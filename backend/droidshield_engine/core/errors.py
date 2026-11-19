"""
أنواع الأخطاء والتحذيرات في مرحلة تحميل APK.

الفرق بين الخطأ والتحذير:
    ApkLoadError  -> لا يمكن تحليل الملف إطلاقاً (ليس ZIP، لا Manifest، Zip Bomb...).
    LoadWarning   -> الملف قابل للتحليل لكن فيه شيء غير طبيعي يستحق التسجيل
                     (مسار مشبوه، ملفات مكررة، ضغط مُتلاعَب به...). هذه معلومات أمنية
                     تُحفظ في raw_analysis.json ولا توقف التحليل.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum


class LoadErrorCode(str, Enum):
    FILE_NOT_FOUND = "FILE_NOT_FOUND"
    NOT_A_FILE = "NOT_A_FILE"
    EMPTY_FILE = "EMPTY_FILE"
    FILE_TOO_LARGE = "FILE_TOO_LARGE"
    INVALID_ZIP = "INVALID_ZIP"
    TOO_MANY_ENTRIES = "TOO_MANY_ENTRIES"
    ZIP_BOMB = "ZIP_BOMB"
    ENTRY_NOT_FOUND = "ENTRY_NOT_FOUND"
    MISSING_MANIFEST = "MISSING_MANIFEST"
    MANIFEST_PARSE_ERROR = "MANIFEST_PARSE_ERROR"


class ApkLoadError(Exception):
    """خطأ يمنع تحليل الـ APK. يحمل code ثابتاً يمكن لـ FastAPI إعادته للواجهة."""

    def __init__(self, code: LoadErrorCode, message: str):
        self.code = code
        self.message = message
        super().__init__(f"[{code.value}] {message}")


class WarningCode(str, Enum):
    UNSAFE_ENTRY_PATH = "UNSAFE_ENTRY_PATH"          # ../ أو مسار مطلق (Path Traversal)
    DUPLICATE_ENTRIES = "DUPLICATE_ENTRIES"          # نفس الاسم أكثر من مرة في ZIP
    ENCRYPTED_FLAG = "ENCRYPTED_FLAG"                # علم تشفير مزيّف لإرباك المحللات
    TAMPERED_COMPRESSION = "TAMPERED_COMPRESSION"    # طريقة ضغط غير صحيحة في الـ header
    LOCAL_HEADER_MISSING = "LOCAL_HEADER_MISSING"    # Central Directory يشير لمكان خاطئ
    CRC_MISMATCH = "CRC_MISMATCH"
    HIGH_COMPRESSION_RATIO = "HIGH_COMPRESSION_RATIO"
    NO_DEX = "NO_DEX"                                # لا يوجد classes.dex (لا كود Java/Kotlin)
    EMBEDDED_CODE = "EMBEDDED_CODE"                  # dex/jar/apk داخل assets أو مكان آخر


@dataclass(frozen=True)
class LoadWarning:
    code: WarningCode
    message: str
    entry: str | None = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["code"] = self.code.value
        return d
