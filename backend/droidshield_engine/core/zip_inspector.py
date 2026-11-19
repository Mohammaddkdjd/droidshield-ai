"""
فحص بنية ZIP للـ APK وقراءة محتوياته بشكل آمن.

لماذا apkInspector وليس zipfile القياسية؟
    Androguard 4.x نفسه يقرأ الـ APK عبر apkInspector. هذه المكتبة تقلّد سلوك Android
    مع ملفات ZIP المشوّهة عمداً (طريقة ضغط مزوّرة، local header خاطئ...) وهي حيلة شائعة
    في البرمجيات الخبيثة: Android يثبّت التطبيق، بينما zipfile ترفضه فيفشل التحليل.
    باستخدام نفس الـ parser نرى الملف كما يراه Androguard و Android.

لماذا قارئ خاص (read_entry) بدل ZipEntry.read من apkInspector؟
    apkInspector يستدعي zlib.decompress بلا حد للحجم الناتج، ويثق بالأحجام المكتوبة في
    الـ headers. ملف يعلن 1KB قد ينفك إلى عدة GB (Zip Bomb). قارئنا يفك الضغط بحد أقصى
    (max_length) ويتوقف فور تجاوزه، مهما كانت القيم المعلنة.

لا يُكتب أي ملف على القرص هنا: كل القراءة من الذاكرة، فلا مجال لـ Path Traversal.
"""
from __future__ import annotations

import io
import logging
import re
import zlib
from dataclasses import dataclass, field

from apkInspector.headers import ZipEntry

from ..config import DEFAULT_LIMITS, LoaderLimits
from .errors import ApkLoadError, LoadErrorCode, LoadWarning, WarningCode

log = logging.getLogger(__name__)

MANIFEST = "AndroidManifest.xml"
RESOURCES = "resources.arsc"
LOCAL_HEADER_SIZE = 30
_DEX_RE = re.compile(r"^classes(\d*)\.dex$")
_EMBEDDED_CODE_EXT = (".dex", ".jar", ".apk", ".odex", ".vdex")


@dataclass(frozen=True)
class ZipEntryInfo:
    """بيانات ملف واحد داخل ZIP كما في الـ Central Directory (الأحجام *معلنة* وقد تكون مزوّرة)."""

    name: str
    compressed_size: int
    declared_size: int
    compression_method: int
    crc32: int
    flags: int
    local_header_offset: int

    @property
    def ratio(self) -> float:
        return self.declared_size / self.compressed_size if self.compressed_size else 0.0


@dataclass
class ZipInspection:
    entries: dict[str, ZipEntryInfo]
    declared_entry_count: int                      # العدد في EOCD (يكشف التكرار)
    dex_files: list[str]                           # classes.dex, classes2.dex... بترتيب Android
    embedded_code: list[str]                       # ملفات كود خارج classes*.dex
    warnings: list[LoadWarning] = field(default_factory=list)
    verified_sizes: dict[str, int] = field(default_factory=dict)  # الحجم الحقيقي بعد فك الضغط
    _parsed: ZipEntry | None = field(default=None, repr=False)

    def has(self, name: str) -> bool:
        return name in self.entries

    def to_dict(self) -> dict:
        return {
            "entry_count": len(self.entries),
            "declared_entry_count": self.declared_entry_count,
            "dex_files": self.dex_files,
            "embedded_code": self.embedded_code,
            "verified_sizes": self.verified_sizes,
            "warnings": [w.to_dict() for w in self.warnings],
        }


# ------------------------------- الفحص ------------------------------- #
def _dex_order(name: str) -> int:
    """classes.dex -> 1 ، classes2.dex -> 2 ... (ترتيب تحميل Android لـ Multi-DEX)."""
    n = _DEX_RE.match(name).group(1)
    return int(n) if n else 1


def _is_unsafe_path(name: str) -> bool:
    parts = name.replace("\\", "/").split("/")
    return name.startswith(("/", "\\")) or ".." in parts or re.match(r"^[A-Za-z]:", name) is not None


def inspect_zip(data: bytes, limits: LoaderLimits = DEFAULT_LIMITS) -> ZipInspection:
    """
    يحلل بنية ZIP (دون فك ضغط أي ملف) ويطبق قواعد الأمان.

    Raises:
        ApkLoadError: INVALID_ZIP / TOO_MANY_ENTRIES / ZIP_BOMB / MISSING_MANIFEST
    """
    try:
        parsed = ZipEntry.parse(io.BytesIO(data), True)
        cd_entries = parsed.central_directory.entries
        declared_count = parsed.eocd.total_number_of_central_directory_records
    except Exception as e:  # apkInspector يرفع أنواعاً مختلفة (struct.error, ValueError, ...)
        raise ApkLoadError(LoadErrorCode.INVALID_ZIP, f"ليس ملف ZIP صالحاً: {type(e).__name__}") from e

    if not cd_entries:
        raise ApkLoadError(LoadErrorCode.INVALID_ZIP, "لا توجد ملفات داخل الـ ZIP")
    if max(len(cd_entries), declared_count) > limits.max_entries:
        raise ApkLoadError(LoadErrorCode.TOO_MANY_ENTRIES,
                           f"{max(len(cd_entries), declared_count)} ملفاً (الحد {limits.max_entries})")

    entries = {
        name: ZipEntryInfo(
            name=name,
            compressed_size=e.compressed_size,
            declared_size=e.uncompressed_size,
            compression_method=e.compression_method,
            crc32=e.crc32_of_uncompressed_data,
            flags=e.general_purpose_bit_flag,
            local_header_offset=e.relative_offset_of_local_file_header,
        )
        for name, e in cd_entries.items()
    }

    declared_total = sum(e.declared_size for e in entries.values())
    if declared_total > limits.max_declared_total:
        raise ApkLoadError(LoadErrorCode.ZIP_BOMB,
                           f"مجموع الأحجام المعلنة {declared_total:,} بايت يتجاوز الحد")

    if MANIFEST not in entries:
        raise ApkLoadError(LoadErrorCode.MISSING_MANIFEST, f"{MANIFEST} غير موجود في جذر الـ APK")

    warnings: list[LoadWarning] = []
    # apkInspector يخزن الـ entries في dict بالاسم، فالمكرر يختفي؛ نكشفه بالمقارنة مع عدد EOCD
    if declared_count != len(entries):
        warnings.append(LoadWarning(WarningCode.DUPLICATE_ENTRIES,
                                    f"EOCD يعلن {declared_count} ملفاً، والأسماء الفريدة {len(entries)}"))
    for e in entries.values():
        if _is_unsafe_path(e.name):
            warnings.append(LoadWarning(WarningCode.UNSAFE_ENTRY_PATH, "مسار يخرج من جذر الـ APK", e.name))
        if e.flags & 0x1:
            warnings.append(LoadWarning(WarningCode.ENCRYPTED_FLAG, "علم التشفير مفعّل", e.name))
        if e.name not in parsed.local_headers:
            warnings.append(LoadWarning(WarningCode.LOCAL_HEADER_MISSING, "local header غير موجود", e.name))
        if e.declared_size >= limits.high_ratio_min_size and e.ratio >= limits.high_ratio_warning:
            warnings.append(LoadWarning(WarningCode.HIGH_COMPRESSION_RATIO,
                                        f"نسبة الضغط {e.ratio:.0f}:1", e.name))

    dex_files = sorted((n for n in entries if _DEX_RE.match(n)), key=_dex_order)
    if not dex_files:
        warnings.append(LoadWarning(WarningCode.NO_DEX, "لا يوجد classes.dex؛ سيُحلَّل الـ Manifest فقط"))
    embedded = sorted(n for n in entries if n.lower().endswith(_EMBEDDED_CODE_EXT) and n not in dex_files)
    for n in embedded:
        warnings.append(LoadWarning(WarningCode.EMBEDDED_CODE, "ملف كود خارج classes*.dex", n))

    return ZipInspection(entries, declared_count, dex_files, embedded, warnings, _parsed=parsed)


# --------------------------- القراءة الآمنة --------------------------- #
def read_entry(data: bytes, inspection: ZipInspection, name: str, max_bytes: int) -> tuple[bytes, str]:
    """
    يقرأ ملفاً واحداً من الـ APK مع حد أقصى للحجم الناتج.

    يتبع نفس منطق apkInspector في الملفات المُتلاعَب بها (حتى نقرأ ما يقرؤه Androguard)،
    لكن مع حد للحجم. يعيد (المحتوى، طريقة القراءة):
        STORED / DEFLATED / STORED_TAMPERED / DEFLATED_TAMPERED

    Raises:
        ApkLoadError(ENTRY_NOT_FOUND): الملف غير موجود.
        ApkLoadError(ZIP_BOMB): الحجم الحقيقي بعد فك الضغط يتجاوز max_bytes.
        ApkLoadError(INVALID_ZIP): بيانات الضغط تالفة.
    """
    info = inspection.entries.get(name)
    local = inspection._parsed.local_headers.get(name) if inspection._parsed else None
    if info is None or local is None:
        raise ApkLoadError(LoadErrorCode.ENTRY_NOT_FOUND, f"الملف غير موجود أو بلا local header: {name}")

    # مثل apkInspector: نأخذ الأحجام من الـ local header إلا إذا كانت أصفاراً
    if local.compressed_size == 0 or local.uncompressed_size == 0:
        csize, usize = info.compressed_size, info.declared_size
    else:
        csize, usize = local.compressed_size, local.uncompressed_size
    start = info.local_header_offset + LOCAL_HEADER_SIZE + local.file_name_length + local.extra_field_length
    method = local.compression_method

    def too_big() -> ApkLoadError:
        return ApkLoadError(LoadErrorCode.ZIP_BOMB, f"{name} يتجاوز {max_bytes:,} بايت بعد فك الضغط")

    def stored(size: int) -> bytes:
        if size > max_bytes:
            raise too_big()
        return data[start:start + size]

    def inflate(strict: bool) -> bytes:
        d = zlib.decompressobj(-15)
        out = d.decompress(data[start:start + csize], max_bytes + 1)
        if len(out) > max_bytes:
            raise too_big()
        if strict and (not d.eof or d.unused_data):
            raise ValueError("deflate stream غير مكتمل")
        return out

    try:
        if method == 0:
            return stored(usize), "STORED"
        if method == 8:
            return inflate(strict=False), "DEFLATED"
        if csize == usize:
            return stored(usize), "STORED_TAMPERED"
        try:
            return inflate(strict=True), "DEFLATED_TAMPERED"
        except zlib.error:
            return stored(usize), "STORED_TAMPERED"
        except ValueError:
            return stored(usize), "STORED_TAMPERED"
    except zlib.error as e:
        raise ApkLoadError(LoadErrorCode.INVALID_ZIP, f"بيانات ضغط تالفة في {name}") from e


def verify_entry(data: bytes, inspection: ZipInspection, name: str, max_bytes: int) -> None:
    """
    يفك ضغط الملف فعلياً (بحد) ليتأكد من حجمه الحقيقي وسلامته، ثم يتخلص من المحتوى.
    يسجل الحجم الحقيقي وتحذيرات التلاعب و CRC في inspection.
    """
    content, how = read_entry(data, inspection, name, max_bytes)
    inspection.verified_sizes[name] = len(content)
    if how.endswith("TAMPERED"):
        inspection.warnings.append(LoadWarning(WarningCode.TAMPERED_COMPRESSION,
                                               f"طريقة الضغط في الـ header غير صحيحة ({how})", name))
    if zlib.crc32(content) != inspection.entries[name].crc32:
        inspection.warnings.append(LoadWarning(WarningCode.CRC_MISMATCH, "CRC32 لا يطابق المحتوى", name))
