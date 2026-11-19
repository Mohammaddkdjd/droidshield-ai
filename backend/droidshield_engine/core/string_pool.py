"""
تجميع كل النصوص القابلة للفحص من الـ APK، مع مصدر كل نص، مرة واحدة لكل APK.

المصادر:
    classes*.dex    -> جدول النصوص (string_ids) في كل ملف DEX: كل نص ثابت في الكود
    resources.arsc  -> String Resources بكل اللغات (قيم فريدة)
    assets/, res/raw -> ملفات نصية صغيرة (json, txt, js, html, xml...)؛ البرمجيات الخبيثة
                       تخزّن فيها أحياناً عناوين الخوادم أو الإعدادات

لماذا مشترك؟ strings_analyzer و network_analyzer يفحصان نفس النصوص بأنماط مختلفة؛
تجميعها مرتين (خصوصاً من DEX) هدر.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ..config import DEFAULT_CONTENT_LIMITS, ContentLimits

if TYPE_CHECKING:
    from .apk_loader import LoadedApk

log = logging.getLogger(__name__)

TEXT_EXTENSIONS = (".json", ".txt", ".js", ".html", ".htm", ".xml", ".cfg", ".conf", ".ini",
                   ".properties", ".yml", ".yaml", ".csv", ".config", ".dat")
TEXT_DIRS = ("assets/", "res/raw/")


def _is_text_asset(name: str) -> bool:
    return name.startswith(TEXT_DIRS) and name.lower().endswith(TEXT_EXTENSIONS)


def collect_strings(apk: LoadedApk, limits: ContentLimits = DEFAULT_CONTENT_LIMITS) -> dict[str, list[str]]:
    cut = limits.max_string_length
    pool: dict[str, list[str]] = {}

    for pd in apk.dex:
        if pd.ok:
            pool[pd.name] = [s[:cut] for s in pd.dex.get_strings()]

    try:
        res = apk.apk.get_android_resources()
        values: set[str] = set()
        for pkg in res.get_packages_names():
            for strings in res.get_resolved_strings().get(pkg, {}).values():
                values.update(v for v in strings.values() if isinstance(v, str))
        pool["resources.arsc"] = [v[:cut] for v in values]
    except Exception as e:  # بعض التطبيقات بلا resources.arsc أو بملف مشوّه
        log.info("No resource strings: %s", type(e).__name__)

    total = 0
    for name, info in apk.zip.entries.items():
        if not _is_text_asset(name) or info.declared_size > limits.max_text_asset_size:
            continue
        if total + info.declared_size > limits.max_text_assets_total:
            break
        try:
            text = apk.read_entry(name, limits.max_text_asset_size).decode("utf-8", "ignore")
        except Exception:
            continue
        total += len(text)
        pool[name] = [line[:cut] for line in text.splitlines() if line.strip()]
    return pool
