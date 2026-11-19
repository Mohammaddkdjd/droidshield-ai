"""
أدوات مشتركة لقراءة AndroidManifest.xml بعد أن يحوّله Androguard من Binary XML إلى lxml.

كيف يمثل Androguard الـ Manifest؟
    AndroidManifest.xml داخل الـ APK ليس نصاً بل Binary XML (AXML). Androguard يفكّه إلى
    شجرة lxml عادية. الخصائص التي تبدأ بـ android: تصبح بالشكل:
        {http://schemas.android.com/apk/res/android}exported
    والقيم كلها نصوص: "true" / "false" / "0x00000002" / أو مرجع لمورد "@7F05000A"
    (قيمة تُحدَّد من resources.arsc وقد تختلف حسب الجهاز، فلا نخمّنها).
"""
from __future__ import annotations

import re

from lxml import etree

ANDROID_NS = "http://schemas.android.com/apk/res/android"
_INT_RE = re.compile(r"^-?(0x[0-9a-fA-F]+|\d+)$")


def attr(el: etree._Element, name: str) -> str | None:
    """قيمة خاصية android:name (أو بدون namespace كاحتياط، لأن بعض الأدوات تحذفه)."""
    v = el.get(f"{{{ANDROID_NS}}}{name}")
    return v if v is not None else el.get(name)


def is_resource_ref(value: str | None) -> bool:
    return bool(value) and value.startswith(("@", "?"))


def parse_bool(value: str | None) -> bool | None:
    """'true'/'false' -> bool ؛ مرجع مورد أو قيمة غير مفهومة -> None (غير معروف)."""
    if value is None:
        return None
    v = value.strip().lower()
    if v in ("true", "1", "0xffffffff", "-1"):
        return True
    if v in ("false", "0", "0x0", "0x00000000"):
        return False
    return None


def parse_int(value: str | None) -> int | None:
    if value is None or not _INT_RE.match(value.strip()):
        return None
    return int(value.strip(), 0)


def resolve_class_name(name: str | None, package: str) -> str | None:
    """
    يحوّل اسم المكوّن إلى اسم الصنف الكامل كما يفعل Android:
        ".MainActivity" -> "<package>.MainActivity"
        "MainActivity"  -> "<package>.MainActivity"   (اسم بلا نقاط)
        "a.b.C"         -> "a.b.C"
    """
    if not name:
        return name
    if name.startswith("."):
        return package + name
    if "." not in name:
        return f"{package}.{name}"
    return name


def children(parent: etree._Element | None, tag: str) -> list[etree._Element]:
    """الأبناء المباشرون فقط بهذا الوسم. Android يتجاهل الوسوم الموضوعة في مكان خاطئ."""
    return [] if parent is None else [c for c in parent if c.tag == tag]


def bool_flag(el: etree._Element | None, name: str, default: bool | None) -> dict:
    """
    خاصية منطقية مع القيمة الفعلية التي سيطبقها Android:
        {"raw": "true"|None|"@7F..", "value": True/False/None, "default_used": bool}
    """
    raw = attr(el, name) if el is not None else None
    if raw is None:
        return {"raw": None, "value": default, "default_used": True}
    return {"raw": raw, "value": parse_bool(raw), "default_used": False}
