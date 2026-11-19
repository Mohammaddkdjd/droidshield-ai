"""
تحميل ملفات DEX وتحويلها إلى كائنات Androguard، مرة واحدة لكل APK.

لماذا وحدة مستقلة؟
    dex_analyzer و api_analyzer (وstrings_analyzer لاحقاً) يحتاجون نفس ملفات DEX المحلَّلة.
    تحليل DEX مكلف، فنحلله مرة واحدة ونخزّنه في LoadedApk (lazy: لا يُحلَّل إن لم يطلبه أحد).

لماذا DEX مباشرة وليس AnalyzeAPK؟
    AnalyzeAPK يبني فوق ذلك شبكة كاملة من الإحالات (xrefs) بين كل الـ methods، وهي تستهلك
    ذاكرة ووقتاً كبيرين في التطبيقات الكبيرة. نحن نحتاج فقط: الأصناف، والـ methods،
    واستدعاءات الـ APIs الحساسة، وهذه نستخرجها بمسح التعليمات مباشرة.

كل ملف DEX يُحلَّل مستقلاً: فشل classes2.dex لا يمنع تحليل classes.dex.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from androguard.core.dex import DEX

if TYPE_CHECKING:
    from .apk_loader import LoadedApk

log = logging.getLogger(__name__)
DEX_MAGIC = b"dex\n"


@dataclass
class ParsedDex:
    name: str
    size: int
    version: str | None          # "035" / "037" / "038" / "039" من الـ header
    dex: DEX | None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.dex is not None


def parse_dex_files(apk: LoadedApk) -> list[ParsedDex]:
    out: list[ParsedDex] = []
    for name in apk.zip.dex_files:
        try:
            raw = apk.read_entry(name)  # القراءة الآمنة (حد للحجم)
        except Exception as e:
            out.append(ParsedDex(name, 0, None, None, f"read: {e}"))
            continue
        version = raw[4:7].decode("ascii", "replace") if raw[:4] == DEX_MAGIC else None
        if version is None:
            out.append(ParsedDex(name, len(raw), None, None, "ليس ملف DEX (magic غير صحيح)"))
            continue
        try:
            out.append(ParsedDex(name, len(raw), version, DEX(raw)))
        except Exception as e:
            log.warning("Module error: DEX parse failed for %s: %s", name, type(e).__name__)
            out.append(ParsedDex(name, len(raw), version, None, f"{type(e).__name__}: {e}"))
    return out
