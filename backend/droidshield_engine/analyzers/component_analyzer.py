"""
تحليل مكوّنات التطبيق: Activities, Activity Aliases, Services, Broadcast Receivers, Content Providers.

أهم ما نحسبه هو "exported" الفعلي، أي هل يستطيع تطبيق آخر تشغيل هذا المكوّن:
    - إذا كُتبت android:exported صراحةً -> نأخذها كما هي.
    - إذا لم تُكتب (القيمة الافتراضية في Android):
        Activity/Service/Receiver: exported إذا كان له intent-filter، وإلا لا.
            (منذ targetSdk 31 يرفض Android تثبيت تطبيق فيه intent-filter بلا exported صريح)
        Provider: exported إذا كان targetSdk أو minSdk <= 16، وإلا لا.
    - إذا كانت مرجعاً لمورد (@7F05...) -> None، لأن قيمتها تحدد وقت التشغيل.

"exposed" = مكوّن exported ومفعّل وبلا إذن يحميه: أي تطبيق على الجهاز يستطيع استدعاءه.
هذه معلومة سطح هجوم (attack surface) وليست دليلاً على أن التطبيق خبيث.
"""
from __future__ import annotations

from collections import Counter

from lxml import etree

from .base import BaseAnalyzer
from .manifest_xml import attr, children, is_resource_ref, parse_bool, parse_int, resolve_class_name

COMPONENT_TAGS = {
    "activity": "activities",
    "activity-alias": "activity_aliases",
    "service": "services",
    "receiver": "receivers",
    "provider": "providers",
}
MAIN, LAUNCHER = "android.intent.action.MAIN", "android.intent.category.LAUNCHER"


def _intent_filters(el: etree._Element) -> list[dict]:
    out = []
    for f in children(el, "intent-filter"):
        out.append({
            "actions": [a for a in (attr(x, "name") for x in children(f, "action")) if a],
            "categories": [c for c in (attr(x, "name") for x in children(f, "category")) if c],
            "data": [{k.split("}")[-1]: v for k, v in d.attrib.items()} for d in children(f, "data")],
            "priority": parse_int(attr(f, "priority")),
            "auto_verify": parse_bool(attr(f, "autoVerify")),
        })
    return out


def _effective_exported(tag: str, raw: str | None, has_filters: bool, target_sdk: int, min_sdk: int):
    if raw is not None:
        return None if is_resource_ref(raw) else parse_bool(raw)
    if tag == "provider":
        return min(target_sdk, min_sdk) <= 16
    return has_filters


def extract_components(manifest: etree._Element, package: str, target_sdk: int, min_sdk: int) -> dict:
    application = next(iter(children(manifest, "application")), None)
    app_permission = attr(application, "permission") if application is not None else None
    app_enabled = parse_bool(attr(application, "enabled")) if application is not None else None

    result: dict[str, list] = {key: [] for key in COMPONENT_TAGS.values()}
    for tag, key in COMPONENT_TAGS.items():
        for el in children(application, tag):
            filters = _intent_filters(el)
            exported_raw = attr(el, "exported")
            enabled = parse_bool(attr(el, "enabled"))
            own_perm = attr(el, "permission")
            comp = {
                "name": resolve_class_name(attr(el, "name"), package),
                "exported_raw": exported_raw,
                "exported": _effective_exported(tag, exported_raw, bool(filters), target_sdk, min_sdk),
                "exported_explicit": exported_raw is not None,
                # المكوّن معطّل إذا عُطّل هو أو عُطّل التطبيق كله
                "enabled": False if app_enabled is False else (enabled if enabled is not None else True),
                "permission": own_perm or app_permission,
                "permission_inherited": own_perm is None and app_permission is not None,
                "process": attr(el, "process"),
                "intent_filters": filters,
            }
            if tag == "activity-alias":
                comp["target_activity"] = resolve_class_name(attr(el, "targetActivity"), package)
            if tag == "service":
                comp["foreground_service_type"] = attr(el, "foregroundServiceType")
                comp["isolated_process"] = parse_bool(attr(el, "isolatedProcess"))
            if tag == "provider":
                comp["authorities"] = [a for a in (attr(el, "authorities") or "").split(";") if a]
                comp["read_permission"] = attr(el, "readPermission")
                comp["write_permission"] = attr(el, "writePermission")
                comp["grant_uri_permissions"] = parse_bool(attr(el, "grantUriPermissions"))
                # Provider محمي إذا وُجد إذن عام أو إذنا القراءة والكتابة معاً
                if not comp["permission"] and comp["read_permission"] and comp["write_permission"]:
                    comp["permission"] = f"read:{comp['read_permission']}|write:{comp['write_permission']}"
            comp["exposed"] = bool(comp["exported"]) and comp["enabled"] is not False and not comp["permission"]
            result[key].append(comp)

    all_comps = [(k, c) for k, items in result.items() for c in items]
    dup = Counter((k, c["name"]) for k, c in all_comps)
    launchers = [c["name"] for k, c in all_comps if k in ("activities", "activity_aliases")
                 and any(MAIN in f["actions"] and LAUNCHER in f["categories"] for f in c["intent_filters"])]
    actions = sorted({a for _, c in all_comps for f in c["intent_filters"] for a in f["actions"]})

    summary = {
        key: {
            "total": len(items),
            "exported": sum(bool(c["exported"]) for c in items),
            "exposed": sum(c["exposed"] for c in items),
            "disabled": sum(c["enabled"] is False for c in items),
        }
        for key, items in result.items()
    }
    return {
        **result,
        "summary": summary,
        "total": len(all_comps),
        "launcher_activities": launchers,
        "intent_actions": actions,
        "exposed_components": [{"type": k, "name": c["name"]} for k, c in all_comps if c["exposed"]],
        "duplicates": sorted(f"{k}:{n}" for (k, n), cnt in dup.items() if cnt > 1),
        "misplaced": sorted({attr(e, "name") or "" for t in COMPONENT_TAGS for e in manifest.iter(t)
                             if e.getparent() is not application} - {""}),
    }


class ComponentAnalyzer(BaseAnalyzer):
    name = "components"

    def analyze(self, apk) -> dict:
        a = apk.apk
        result = extract_components(a.get_android_manifest_xml(), a.get_package(),
                                    int(a.get_effective_target_sdk_version()),
                                    int(a.get_min_sdk_version() or 1))
        result["main_activity"] = a.get_main_activity()
        return result
