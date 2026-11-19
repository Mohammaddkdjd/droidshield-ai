"""
تحميل ملف APK والتحقق من سلامته قبل أي تحليل.

ترتيب الفحوصات (من الأرخص إلى الأغلى، ويتوقف عند أول خطأ قاتل):
    1) الملف موجود، ملف عادي، غير فارغ، ضمن الحد الأقصى للحجم   (stat فقط)
    2) قراءة الملف مرة واحدة إلى الذاكرة + حساب MD5/SHA1/SHA256
    3) بنية ZIP: Central Directory، عدد الملفات، الأحجام المعلنة، وجود Manifest
    4) فك ضغط الملفات الحرجة فعلياً بحد أقصى (Manifest, resources.arsc, classes*.dex)
       لأن Androguard سيفك ضغطها لاحقاً بلا حد
    5) تمرير نفس البايتات إلى Androguard (raw=True) والتأكد أنه فهم الـ Manifest

لماذا نمرر البايتات وليس المسار إلى Androguard؟
    حتى يكون الملف الذي حسبنا بصمته وفحصناه هو نفسه الذي يُحلَّل، حتى لو تغيّر الملف
    على القرص أثناء التحليل (TOCTOU). ويُقرأ الملف من القرص مرة واحدة فقط.
"""
from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path

from androguard.core.apk import APK
from loguru import logger as _androguard_logger

from ..config import DEFAULT_LIMITS, LoaderLimits
from .dex_loader import ParsedDex, parse_dex_files
from .errors import ApkLoadError, LoadErrorCode
from .string_pool import collect_strings
from .zip_inspector import MANIFEST, RESOURCES, ZipInspection, inspect_zip, read_entry, verify_entry

_androguard_logger.disable("androguard")  # Androguard 4.x يطبع آلاف السطور عبر loguru
log = logging.getLogger(__name__)


@dataclass
class LoadedApk:
    """APK تم التحقق منه وجاهز للتحليل. يُنشأ مرة واحدة لكل ملف ولا يُشارك بين التحليلات."""

    path: Path
    size: int
    hashes: dict[str, str]
    zip: ZipInspection
    apk: APK = field(repr=False)
    load_seconds: float = 0.0
    limits: LoaderLimits = field(default=DEFAULT_LIMITS, repr=False)
    data: bytes = field(default=b"", repr=False)

    @property
    def file_name(self) -> str:
        return self.path.name

    def read_entry(self, name: str, max_bytes: int | None = None) -> bytes:
        """القراءة الآمنة الوحيدة المسموحة للـ analyzers لأي ملف داخل الـ APK."""
        return read_entry(self.data, self.zip, name, max_bytes or self.limits.max_entry_size)[0]

    @cached_property
    def dex(self) -> list[ParsedDex]:
        """ملفات DEX محلَّلة، تُحسب عند أول طلب فقط ثم تُعاد نفسها لكل الـ analyzers."""
        return parse_dex_files(self)

    @cached_property
    def strings(self) -> dict[str, list[str]]:
        """كل النصوص مجمّعة حسب المصدر (DEX، الموارد، ملفات assets النصية)."""
        return collect_strings(self)

    def to_dict(self) -> dict:
        return {
            "file_name": self.file_name,
            "file_size": self.size,
            "hashes": self.hashes,
            "zip": self.zip.to_dict(),
            "load_seconds": round(self.load_seconds, 3),
        }


def _check_file(path: Path, limits: LoaderLimits) -> int:
    if not path.exists():
        raise ApkLoadError(LoadErrorCode.FILE_NOT_FOUND, f"الملف غير موجود: {path.name}")
    if not path.is_file():
        raise ApkLoadError(LoadErrorCode.NOT_A_FILE, f"ليس ملفاً عادياً: {path.name}")
    size = path.stat().st_size
    if size == 0:
        raise ApkLoadError(LoadErrorCode.EMPTY_FILE, "الملف فارغ")
    if size > limits.max_apk_size:
        raise ApkLoadError(LoadErrorCode.FILE_TOO_LARGE,
                           f"حجم الملف {size:,} بايت يتجاوز الحد {limits.max_apk_size:,}")
    return size


def compute_hashes(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def load_apk(path: str | Path, limits: LoaderLimits = DEFAULT_LIMITS) -> LoadedApk:
    """
    يتحقق من الملف ويعيد LoadedApk، أو يرفع ApkLoadError بسبب واضح.

    لا يُنفَّذ أي شيء من الـ APK ولا يُكتب أي ملف على القرص.
    """
    t0 = time.perf_counter()
    path = Path(path)
    size = _check_file(path, limits)
    data = path.read_bytes()
    if len(data) != size:  # تغيّر الملف بين stat والقراءة
        raise ApkLoadError(LoadErrorCode.INVALID_ZIP, "تغيّر حجم الملف أثناء القراءة")
    hashes = compute_hashes(data)
    log.info("Analysis started: %s (sha256=%s, %d bytes)", path.name, hashes["sha256"][:16], size)

    inspection = inspect_zip(data, limits)
    critical = [MANIFEST, *([RESOURCES] if inspection.has(RESOURCES) else []), *inspection.dex_files]
    for name in critical:
        verify_entry(data, inspection, name, limits.max_entry_size)

    try:
        apk = APK(data, raw=True)
    except Exception as e:
        raise ApkLoadError(LoadErrorCode.MANIFEST_PARSE_ERROR,
                           f"تعذّر على Androguard قراءة الـ APK: {type(e).__name__}: {e}") from e
    if not apk.is_valid_APK() or not apk.get_package():
        raise ApkLoadError(LoadErrorCode.MANIFEST_PARSE_ERROR, "الـ Manifest غير صالح أو بلا package name")

    for w in inspection.warnings:
        log.warning("%s: %s %s", w.code.value, w.message, w.entry or "")
    loaded = LoadedApk(path=path, size=size, hashes=hashes, zip=inspection, apk=apk,
                       load_seconds=time.perf_counter() - t0, limits=limits, data=data)
    log.info("APK loaded: %s package=%s dex=%d warnings=%d (%.2fs)", path.name, apk.get_package(),
             len(inspection.dex_files), len(inspection.warnings), loaded.load_seconds)
    return loaded
