"""
مؤشرات الشبكة: عناوين الخوادم المكتوبة في التطبيق، وسياسة الاتصال غير المشفّر (cleartext).

لا يتصل المحرك بأي عنوان. كل شيء من النصوص الثابتة والـ Manifest والـ NSC فقط.

السياسة الفعلية للـ cleartext (بترتيب الأولوية في Android):
    1) Network Security Config موجود -> يحدد هو (base-config، ثم domain-config لكل نطاق)
       وإن لم يذكر base-config قيمة، فالافتراضي حسب targetSdk (مسموح إذا < 28)
    2) وإلا android:usesCleartextTraffic في الـ Manifest
    3) وإلا الافتراضي: مسموح إذا targetSdk < 28

روابط "namespace" مثل http://schemas.android.com ليست اتصالات فعلية بل معرّفات XML؛
نفصلها حتى لا تُحسب مؤشراً على HTTP غير مشفّر.
"""
from __future__ import annotations

import re

from ..config import DEFAULT_CONTENT_LIMITS, ContentLimits
from ..core.budget import TimeBudget
from .base import BaseAnalyzer
from .manifest_xml import attr, children, parse_bool
from .resources_analyzer import load_network_security_config
from .strings_analyzer import IPV4_RE, URL_RE, Findings, add_ip, clean_url, url_host

NAMESPACE_HOSTS = {
    "schemas.android.com", "www.w3.org", "w3.org", "ns.adobe.com", "xml.org", "xmlpull.org", "purl.org",
    "json-schema.org", "java.sun.com", "xml.apache.org", "www.apache.org", "apache.org", "schemas.xmlsoap.org",
    "schemas.microsoft.com", "www.slf4j.org", "javax.xml.xmlconstants",
}
HOST_PORT_RE = re.compile(r"^([a-z0-9.-]+\.[a-z]{2,24}|\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})$", re.I)
DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443, "ftp": 21}


def _port(url: str) -> int | None:
    m = re.match(r"^[a-z]+://(?:[^@/]*@)?[^:/?#]+:(\d{1,5})", url, re.I)
    return int(m.group(1)) if m else None


def effective_cleartext(nsc: dict | None, manifest_flag: bool | None, target_sdk: int) -> dict:
    default = target_sdk < 28
    parsed = (nsc or {}).get("parsed")
    if parsed:
        base = parsed["base_config"]
        value = base["cleartext_permitted"] if base and base["cleartext_permitted"] is not None else default
        return {"permitted": value, "decided_by": "network_security_config",
                "cleartext_domains": parsed["cleartext_domains"]}
    if manifest_flag is not None:
        return {"permitted": manifest_flag, "decided_by": "manifest", "cleartext_domains": []}
    return {"permitted": default, "decided_by": f"default (targetSdk={target_sdk})", "cleartext_domains": []}


class NetworkAnalyzer(BaseAnalyzer):
    name = "network"

    def __init__(self, limits: ContentLimits = DEFAULT_CONTENT_LIMITS):
        self.limits = limits

    def analyze(self, apk) -> dict:
        budget = TimeBudget(self.limits.time_budget_seconds)
        f = Findings(self.limits)
        for source, strings in apk.strings.items():
            if budget.exceeded():
                break
            for s in strings:
                has_url = "://" in s and URL_RE.search(s) is not None
                for raw in (URL_RE.findall(s) if has_url else ()):
                    url = clean_url(raw)
                    host = url_host(url) or ""
                    scheme = url.split(":", 1)[0].lower()
                    if host in NAMESPACE_HOSTS:
                        f.add("namespace_urls", url, source)
                        continue
                    f.add(f"urls_{scheme if scheme in ('http', 'https') else 'other'}", url, source)
                    port = _port(url)
                    f.add("endpoints", f"{scheme}://{host}:{port or DEFAULT_PORTS.get(scheme, '?')}", source,
                          scheme=scheme, host=host, port=port or DEFAULT_PORTS.get(scheme),
                          non_standard_port=port is not None and port != DEFAULT_PORTS.get(scheme))
                    if IPV4_RE.fullmatch(host):
                        add_ip(f, host, source, in_url=True)
                    elif host:
                        f.add("domains", host, source)
                if has_url or "." not in s:
                    continue
                st = s.strip()
                hp = HOST_PORT_RE.match(st)
                if hp:
                    f.add("host_port_strings", st, source, host=hp.group(1).lower(), port=int(hp.group(2)))
                for ip in IPV4_RE.findall(s):
                    add_ip(f, ip, source)

        a = apk.apk
        target = int(a.get_effective_target_sdk_version())
        app = next(iter(children(a.get_android_manifest_xml(), "application")), None)
        manifest_flag = parse_bool(attr(app, "usesCleartextTraffic")) if app is not None else None
        nsc = load_network_security_config(apk)

        ips = f.items("ip_addresses")
        http_urls = f.items("urls_http")
        hardcoded = (
            [{"type": "ip_url", "value": e["value"]} for e in f.items("endpoints") if IPV4_RE.fullmatch(e["host"])]
            + [{"type": "public_ip", "value": i["value"]} for i in ips
               if i["scope"] == "public" and not i["ambiguous"]]
            + [{"type": "host_port", "value": h["value"]} for h in f.items("host_port_strings")]
        )
        return {
            "urls": {"http": http_urls, "https": f.items("urls_https"), "other": f.items("urls_other")},
            "namespace_urls": f.items("namespace_urls"),
            "domains": f.items("domains"),
            "ip_addresses": ips,
            "endpoints": f.items("endpoints"),
            "non_standard_ports": [e["value"] for e in f.items("endpoints") if e["non_standard_port"]],
            "hardcoded_servers": hardcoded,
            "cleartext": {
                "manifest_uses_cleartext_traffic": manifest_flag,
                "network_security_config": nsc,
                "effective": effective_cleartext(nsc, manifest_flag, target),
                "http_url_count": len(http_urls),
            },
            "counts": {
                "http_urls": len(http_urls), "https_urls": len(f.items("urls_https")),
                "domains": len(f.items("domains")),
                "public_ips": sum(i["scope"] == "public" and not i["ambiguous"] for i in ips),
                "ambiguous_ips": sum(i["ambiguous"] for i in ips),
                "endpoints": len(f.items("endpoints")),
            },
            "truncated": {"time_budget": budget.hit, "categories": sorted(f.truncated)},
            "elapsed_seconds": budget.elapsed,
        }
