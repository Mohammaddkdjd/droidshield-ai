"""
تحليل موارد التطبيق: resources.arsc، ملفات res/ و assets/، و Network Security Config.

كيف تعمل الموارد في Android؟
    resources.arsc جدول مضغوط يربط رقم كل مورد (مثل 0x7F1200D4) بقيمته لكل لغة/جهاز.
    الـ Manifest يشير للموارد بأرقامها (@7F1200D4) لا بأسمائها. لذلك نستخدم ARSCParser
    من Androguard لحلّ هذه المراجع.

لماذا نحلّ مرجع networkSecurityConfig بدل البحث عن res/xml/network_security_config.xml؟
    أدوات البناء الحديثة (R8) تختصر مسارات الموارد: في KDE Connect الملف اسمه res/8G.xml.
    الطريقة الوحيدة الموثوقة هي حلّ الرقم المكتوب في الـ Manifest عبر resources.arsc.
"""
from __future__ import annotations

import logging
from collections import Counter

from androguard.core.axml import AXMLPrinter
from lxml import etree

from ..config import DEFAULT_CONTENT_LIMITS, ContentLimits
from .base import BaseAnalyzer
from .manifest_xml import attr, children, parse_bool

log = logging.getLogger(__name__)


# ------------------------- Network Security Config ------------------------- #
def resolve_resource_path(apk, ref: str | None) -> str | None:
    """'@7F150011' -> 'res/8G.xml' (أول قيمة في الإعداد الافتراضي)."""
    if not ref or not ref.startswith("@"):
        return None
    try:
        configs = apk.apk.get_android_resources().get_resolved_res_configs(int(ref[1:], 16))
    except Exception:
        return None
    return next((v for _, v in configs if isinstance(v, str)), None)


def _trust_anchors(el) -> list[dict]:
    ta = next(iter(children(el, "trust-anchors")), None)
    return [{"src": c.get("src"), "override_pins": parse_bool(c.get("overridePins"))}
            for c in children(ta, "certificates")]


def _domain_config(el) -> dict:
    pin_set = next(iter(children(el, "pin-set")), None)
    return {
        "domains": [{"name": (d.text or "").strip(), "include_subdomains": parse_bool(d.get("includeSubdomains"))}
                    for d in children(el, "domain")],
        "cleartext_permitted": parse_bool(el.get("cleartextTrafficPermitted")),
        "trust_anchors": _trust_anchors(el),
        "pin_set": None if pin_set is None else {
            "expiration": pin_set.get("expiration"),
            "pins": [{"digest": p.get("digest"), "value": (p.text or "").strip()} for p in children(pin_set, "pin")],
        },
        "nested": [_domain_config(c) for c in children(el, "domain-config")],
    }


def parse_network_security_config(root: etree._Element) -> dict:
    """
    يحلل <network-security-config>. النقاط الأمنية المهمة:
        cleartext_permitted -> HTTP غير مشفّر مسموح
        trust user certs    -> التطبيق يثق بشهادات يثبّتها المستخدم (يسهّل اعتراض الاتصال MITM)
        pin_set             -> Certificate Pinning (ممارسة حماية جيدة)
    """
    base = next(iter(children(root, "base-config")), None)
    debug = next(iter(children(root, "debug-overrides")), None)
    domains = [_domain_config(d) for d in children(root, "domain-config")]

    def all_anchors():
        if base is not None:
            yield from _trust_anchors(base)
        for d in domains:
            yield from d["trust_anchors"]

    return {
        "base_config": None if base is None else {
            "cleartext_permitted": parse_bool(base.get("cleartextTrafficPermitted")),
            "trust_anchors": _trust_anchors(base),
        },
        "domain_configs": domains,
        "debug_overrides": None if debug is None else {"trust_anchors": _trust_anchors(debug)},
        "trusts_user_certificates": any(a["src"] == "user" for a in all_anchors()),
        "cleartext_domains": [d["name"] for c in domains if c["cleartext_permitted"] for d in c["domains"]],
        "has_pinning": any(c["pin_set"] for c in domains),
    }


def load_network_security_config(apk) -> dict | None:
    """يجد ملف NSC عبر الـ Manifest ويحلله. None إن لم يوجد."""
    app = next(iter(children(apk.apk.get_android_manifest_xml(), "application")), None)
    ref = attr(app, "networkSecurityConfig") if app is not None else None
    if not ref:
        return None
    path = resolve_resource_path(apk, ref)
    result = {"reference": ref, "path": path, "parsed": None, "error": None}
    if not path or not apk.zip.has(path):
        result["error"] = "تعذّر حلّ مسار الملف"
        return result
    try:
        root = AXMLPrinter(apk.read_entry(path)).get_xml_obj()
        result["parsed"] = parse_network_security_config(root)
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
    return result


# ------------------------------- Inventory ------------------------------- #
def _top_dir(name: str) -> str:
    return name.split("/", 1)[0] + "/" if "/" in name else "(root)"


def _extension(name: str) -> str:
    base = name.rsplit("/", 1)[-1]
    return base.rsplit(".", 1)[-1].lower() if "." in base else "(none)"


class ResourcesAnalyzer(BaseAnalyzer):
    name = "resources"

    def __init__(self, limits: ContentLimits = DEFAULT_CONTENT_LIMITS):
        self.limits = limits

    def analyze(self, apk) -> dict:
        entries = apk.zip.entries
        names = sorted(entries)
        result = {
            "files": {
                "total": len(names),
                "by_top_dir": dict(Counter(_top_dir(n) for n in names).most_common()),
                "by_extension": dict(Counter(_extension(n) for n in names).most_common(30)),
                "largest": [{"name": e.name, "size": e.declared_size} for e in
                            sorted(entries.values(), key=lambda e: e.declared_size, reverse=True)[:20]],
                "res_count": sum(n.startswith("res/") for n in names),
                "assets": [n for n in names if n.startswith("assets/")][: self.limits.max_files_listed],
                "assets_count": sum(n.startswith("assets/") for n in names),
                "raw_resources": [n for n in names if n.startswith("res/raw/")][: self.limits.max_files_listed],
            },
            "arsc": None,
            "network_security_config": load_network_security_config(apk),
        }

        if not apk.zip.has("resources.arsc"):
            return result
        res = apk.apk.get_android_resources()
        arsc = {"packages": [], "error": None}
        try:
            all_strings = res.get_resolved_strings()
            for pkg in res.get_packages_names():
                locales = res.get_locales(pkg)
                default = all_strings.get(pkg, {}).get("DEFAULT", {})
                listed = {}
                for rid, value in list(default.items())[: self.limits.max_resource_strings_listed]:
                    try:
                        key = res.get_resource_xml_name(rid).split("/", 1)[-1]
                    except Exception:
                        key = hex(rid)
                    listed[key] = value
                arsc["packages"].append({
                    "name": pkg,
                    "types": res.get_types(pkg),
                    "locales": sorted("default" if loc in ("\x00\x00", "") else loc for loc in locales),
                    "string_count": len(default),
                    "strings": listed,
                    "strings_truncated": len(default) > len(listed),
                })
        except Exception as e:
            arsc["error"] = f"{type(e).__name__}: {e}"
        result["arsc"] = arsc
        return result
