"""
قاعدة بيانات أذونات Android الرسمية (AOSP) المضمّنة في Androguard.

Androguard يحمل ملفات JSON لكل API level (4 حتى 36) فيها لكل إذن: protectionLevel
و permissionGroup و label و description، مستخرجة من كود Android نفسه.

نستخدمها لشيئين:
    1) تفاصيل الإذن (مستوى الحماية والمجموعة) حسب targetSdk الخاص بالتطبيق.
    2) كشف أذونات تبدو رسمية (android.permission.X) لكنها غير موجودة في القاعدة:
       قد تكون أحدث من القاعدة، أو يعرّفها تطبيق نظام، أو خطأ إملائي، أو اسماً مزيّفاً.
"""
from __future__ import annotations

import os
import re
from functools import lru_cache

from androguard.core import api_specific_resources

_DB_DIR = os.path.join(os.path.dirname(api_specific_resources.__file__), "aosp_permissions")


@lru_cache(maxsize=1)
def available_api_levels() -> tuple[int, ...]:
    files = (f for f in os.listdir(_DB_DIR) if re.match(r"^permissions_\d+\.json$", f))
    return tuple(sorted(int(f[12:-5]) for f in files))


@lru_cache(maxsize=64)
def permissions_for_api(api_level: int) -> dict[str, dict]:
    """التفاصيل حسب API level (Androguard يختار أقرب مستوى متوفر)."""
    return api_specific_resources.load_permissions(int(api_level))


@lru_cache(maxsize=1)
def all_known_permissions() -> frozenset[str]:
    """كل إذن ظهر في أي إصدار Android (لأن أذونات قديمة حُذفت لاحقاً لكنها ما زالت رسمية)."""
    names: set[str] = set()
    for level in available_api_levels():
        names.update(permissions_for_api(level))
    return frozenset(names)


# ----------------------------- Protection Level ----------------------------- #
# من frameworks/base/core/res/res/values/attrs_manifest.xml
_BASE_LEVELS = {0: "normal", 1: "dangerous", 2: "signature", 3: "signatureOrSystem", 4: "internal"}
_FLAGS = {
    0x10: "privileged", 0x20: "development", 0x40: "appop", 0x80: "pre23", 0x100: "installer",
    0x200: "verifier", 0x400: "preinstalled", 0x800: "setup", 0x1000: "instant", 0x2000: "runtime",
    0x4000: "oem", 0x8000: "vendorPrivileged", 0x10000: "textClassifier", 0x20000: "wellbeing",
    0x40000: "documenter", 0x80000: "configurator", 0x100000: "incidentReportApprover",
    0x200000: "appPredictor", 0x400000: "moduleHolder", 0x800000: "companion",
    0x1000000: "retailDemo", 0x2000000: "recents", 0x4000000: "role", 0x8000000: "knownSigner",
}


def decode_protection_level(raw: str | None) -> dict:
    """
    '0x00000012' -> {"base": "signature", "flags": ["privileged"]}
    'signature|privileged' (صيغة نصية) تُفهم أيضاً. القيمة الافتراضية في Android = normal.
    """
    if raw is None:
        return {"raw": None, "base": "normal", "flags": []}
    v = raw.strip()
    if re.match(r"^(0x[0-9a-fA-F]+|\d+)$", v):
        n = int(v, 0)
        flags = [name for bit, name in _FLAGS.items() if n & bit]
        unknown = n & ~0xF & ~sum(_FLAGS)
        if unknown:
            flags.append(hex(unknown))
        return {"raw": raw, "base": _BASE_LEVELS.get(n & 0xF, hex(n & 0xF)), "flags": flags}
    parts = [p for p in v.split("|") if p]
    base = next((p for p in parts if p in _BASE_LEVELS.values()), "normal")
    return {"raw": raw, "base": base, "flags": [p for p in parts if p != base]}
