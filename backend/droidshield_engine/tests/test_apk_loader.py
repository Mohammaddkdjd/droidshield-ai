"""
اختبارات تحميل APK.

ثلاث مجموعات:
    1) تطبيقات حقيقية من F-Droid: يجب أن تُحمَّل بلا أخطاء ولا تحذيرات.
    2) ملفات تالفة أو خبيثة مصنوعة يدوياً: يجب أن تُرفض برمز الخطأ الصحيح.
    3) حيل التلاعب ببنية ZIP: يجب أن تُكتشف كتحذيرات دون إيقاف التحليل.

لصناعة الحالات الخبيثة نعدّل بايتات الـ headers مباشرة (patch_entry)، لأن zipfile
القياسية لا تسمح بكتابة ملف ZIP مزوّر عن قصد.
"""
import hashlib
import io
import struct
import warnings
import zipfile
from pathlib import Path

import pytest

from droidshield_engine.config import LoaderLimits
from droidshield_engine.core import ApkLoadError, LoadErrorCode, WarningCode, load_apk
from droidshield_engine.core.zip_inspector import inspect_zip, read_entry, verify_entry

APK_DIR = Path("E:/apk_test/dl")
AUTOMATION = APK_DIR / "com.jens.automation2_149.apk"
KDE = APK_DIR / "org.kde.kdeconnect_tp_13702.apk"
needs_real = pytest.mark.skipif(not AUTOMATION.exists(), reason="ملفات APK الحقيقية غير متوفرة")

FAKE_MANIFEST = ("AndroidManifest.xml", b"not a real binary xml")


# ------------------------------- أدوات مساعدة ------------------------------- #
def make_zip(entries, method=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # zipfile تحذّر من الأسماء المكررة، ونحن نريدها عمداً
        with zipfile.ZipFile(buf, "w", method) as z:
            for name, content in entries:
                z.writestr(name, content)
    return buf.getvalue()


# مواضع الحقول (بالبايت) داخل كل header حسب مواصفة ZIP
LOCAL = {"flags": 6, "method": 8, "crc": 14, "csize": 18, "usize": 22}
CENTRAL = {"flags": 8, "method": 10, "crc": 16, "csize": 20, "usize": 24}
SIZES = {"flags": "<H", "method": "<H", "crc": "<I", "csize": "<I", "usize": "<I"}


def patch_entry(data: bytes, name: str, **fields) -> bytes:
    """يعدّل حقولاً في الـ local header والـ central directory لملف معيّن."""
    buf = bytearray(data)
    cd = buf.find(b"PK\x01\x02")
    while cd != -1:
        n_len = struct.unpack_from("<H", buf, cd + 28)[0]
        if buf[cd + 46: cd + 46 + n_len].decode() == name:
            local = struct.unpack_from("<I", buf, cd + 42)[0]
            for f, v in fields.items():
                struct.pack_into(SIZES[f], buf, cd + CENTRAL[f], v)
                struct.pack_into(SIZES[f], buf, local + LOCAL[f], v)
            return bytes(buf)
        cd = buf.find(b"PK\x01\x02", cd + 4)
    raise KeyError(name)


def write(tmp_path, data: bytes, name="t.apk") -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p


def codes(inspection):
    return {w.code for w in inspection.warnings}


# --------------------------- 1) تطبيقات حقيقية --------------------------- #
@needs_real
def test_real_apk_loads_cleanly():
    a = load_apk(AUTOMATION)
    assert a.apk.get_package() == "com.jens.automation2"
    assert a.zip.dex_files == ["classes.dex"]
    assert a.zip.warnings == []


@needs_real
def test_hashes_match_hashlib():
    a = load_apk(AUTOMATION)
    raw = AUTOMATION.read_bytes()
    assert a.hashes == {
        "md5": hashlib.md5(raw).hexdigest(),
        "sha1": hashlib.sha1(raw).hexdigest(),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    assert a.size == len(raw)


@needs_real
def test_multidex_detected_in_android_order():
    a = load_apk(KDE)
    assert a.zip.dex_files == ["classes.dex", "classes2.dex"]
    assert set(a.zip.dex_files) <= set(a.zip.verified_sizes)  # كل DEX فُكّ ضغطه وتم التحقق منه


@needs_real
def test_safe_read_matches_androguard():
    a = load_apk(KDE)
    for name in ("AndroidManifest.xml", "classes2.dex"):
        assert a.read_entry(name) == a.apk.get_file(name)


@needs_real
def test_safe_read_enforces_limit():
    a = load_apk(AUTOMATION)
    with pytest.raises(ApkLoadError) as e:
        a.read_entry("classes.dex", max_bytes=1000)
    assert e.value.code is LoadErrorCode.ZIP_BOMB


@needs_real
def test_read_missing_entry():
    with pytest.raises(ApkLoadError) as e:
        load_apk(AUTOMATION).read_entry("nope.txt")
    assert e.value.code is LoadErrorCode.ENTRY_NOT_FOUND


@needs_real
def test_truncated_apk_rejected(tmp_path):
    raw = AUTOMATION.read_bytes()
    with pytest.raises(ApkLoadError) as e:
        load_apk(write(tmp_path, raw[: len(raw) // 2]))
    assert e.value.code is LoadErrorCode.INVALID_ZIP


@needs_real
def test_real_apk_with_injected_entries_still_loads_with_warnings(tmp_path):
    """تطبيق صالح أُضيف إليه مسار Path Traversal و DEX مخفي: يُحلَّل مع تحذيرات."""
    with zipfile.ZipFile(AUTOMATION) as src:
        entries = [(i.filename, src.read(i)) for i in src.infolist()]
    entries += [("../../evil.so", b"x"), ("assets/payload.dex", b"dex\n035\0")]
    a = load_apk(write(tmp_path, make_zip(entries)))
    assert a.apk.get_package() == "com.jens.automation2"
    assert {WarningCode.UNSAFE_ENTRY_PATH, WarningCode.EMBEDDED_CODE} <= codes(a.zip)
    assert a.zip.embedded_code == ["assets/payload.dex"]
    assert not (tmp_path.parent / "evil.so").exists()  # لم يُكتب شيء على القرص


# --------------------------- 2) ملفات يجب رفضها --------------------------- #
def expect(code, path, limits=LoaderLimits()):
    with pytest.raises(ApkLoadError) as e:
        load_apk(path, limits)
    assert e.value.code is code, e.value


def test_file_not_found(tmp_path):
    expect(LoadErrorCode.FILE_NOT_FOUND, tmp_path / "missing.apk")


def test_directory(tmp_path):
    expect(LoadErrorCode.NOT_A_FILE, tmp_path)


def test_empty_file(tmp_path):
    expect(LoadErrorCode.EMPTY_FILE, write(tmp_path, b""))


def test_too_large(tmp_path):
    expect(LoadErrorCode.FILE_TOO_LARGE, write(tmp_path, b"x" * 100), LoaderLimits(max_apk_size=50))


def test_not_a_zip(tmp_path):
    expect(LoadErrorCode.INVALID_ZIP, write(tmp_path, b"MZ\x90\x00 this is an exe, not an apk" * 10))


def test_missing_manifest(tmp_path):
    expect(LoadErrorCode.MISSING_MANIFEST, write(tmp_path, make_zip([("classes.dex", b"dex")])))


def test_manifest_in_subfolder_does_not_count(tmp_path):
    data = make_zip([("assets/AndroidManifest.xml", b"x"), ("classes.dex", b"dex")])
    expect(LoadErrorCode.MISSING_MANIFEST, write(tmp_path, data))


def test_too_many_entries(tmp_path):
    data = make_zip([FAKE_MANIFEST] + [(f"f{i}", b"") for i in range(10)])
    expect(LoadErrorCode.TOO_MANY_ENTRIES, write(tmp_path, data), LoaderLimits(max_entries=5))


def test_declared_total_too_large(tmp_path):
    data = make_zip([FAKE_MANIFEST, ("assets/big", b"\0" * 10_000)])
    expect(LoadErrorCode.ZIP_BOMB, write(tmp_path, data), LoaderLimits(max_declared_total=5_000))


def test_zip_bomb_in_critical_entry(tmp_path):
    data = make_zip([("AndroidManifest.xml", b"\0" * (5 * 1024**2))])  # 5MB ينضغط إلى ~5KB
    expect(LoadErrorCode.ZIP_BOMB, write(tmp_path, data), LoaderLimits(max_entry_size=1024**2))


def test_zip_bomb_with_forged_sizes(tmp_path):
    """
    الحالة الأخطر: الـ headers تكذب وتعلن أن الحجم 100 بايت فقط، فتمر كل فحوصات الأحجام
    المعلنة. الحماية الوحيدة هنا هي فك الضغط بحد أقصى، وهي التي يجب أن تكشفه.
    """
    data = make_zip([("AndroidManifest.xml", b"\0" * (5 * 1024**2))])
    data = patch_entry(data, "AndroidManifest.xml", usize=100)
    assert inspect_zip(data).entries["AndroidManifest.xml"].declared_size == 100
    expect(LoadErrorCode.ZIP_BOMB, write(tmp_path, data), LoaderLimits(max_entry_size=1024**2))


def test_zip_bomb_in_dex(tmp_path):
    data = make_zip([FAKE_MANIFEST, ("classes2.dex", b"\0" * (3 * 1024**2))])
    expect(LoadErrorCode.ZIP_BOMB, write(tmp_path, data), LoaderLimits(max_entry_size=1024**2))


def test_garbage_manifest(tmp_path):
    expect(LoadErrorCode.MANIFEST_PARSE_ERROR, write(tmp_path, make_zip([FAKE_MANIFEST])))


# ---------------------- 3) حيل التلاعب: تحذيرات لا أخطاء ---------------------- #
def test_path_traversal_and_absolute_paths():
    ins = inspect_zip(make_zip([FAKE_MANIFEST, ("../../x.so", b""), ("/etc/x", b""), ("C:/x", b"")]))
    flagged = {w.entry for w in ins.warnings if w.code is WarningCode.UNSAFE_ENTRY_PATH}
    assert flagged == {"../../x.so", "/etc/x", "C:/x"}


def test_safe_names_not_flagged():
    ins = inspect_zip(make_zip([FAKE_MANIFEST, ("res/a..b.png", b""), ("lib/arm64-v8a/x.so", b"")]))
    assert WarningCode.UNSAFE_ENTRY_PATH not in codes(ins)


def test_duplicate_entries():
    ins = inspect_zip(make_zip([FAKE_MANIFEST, ("classes.dex", b"a"), ("classes.dex", b"b")]))
    assert WarningCode.DUPLICATE_ENTRIES in codes(ins)
    assert ins.declared_entry_count == 3 and len(ins.entries) == 2


def test_fake_encryption_flag():
    data = patch_entry(make_zip([FAKE_MANIFEST, ("classes.dex", b"dex")]), "classes.dex", flags=0x1)
    assert WarningCode.ENCRYPTED_FLAG in codes(inspect_zip(data))


def test_no_dex():
    assert WarningCode.NO_DEX in codes(inspect_zip(make_zip([FAKE_MANIFEST])))


def test_multidex_order_is_numeric():
    names = ["classes10.dex", "classes2.dex", "classes.dex", "classes3.dex"]
    ins = inspect_zip(make_zip([FAKE_MANIFEST] + [(n, b"") for n in names]))
    assert ins.dex_files == ["classes.dex", "classes2.dex", "classes3.dex", "classes10.dex"]


def test_embedded_code_files():
    ins = inspect_zip(make_zip([FAKE_MANIFEST, ("classes.dex", b""), ("assets/a.jar", b""),
                                ("assets/b.apk", b""), ("lib/x.dex", b"")]))
    assert ins.embedded_code == ["assets/a.jar", "assets/b.apk", "lib/x.dex"]


def test_high_compression_ratio_is_warning_only():
    ins = inspect_zip(make_zip([FAKE_MANIFEST, ("assets/zeros.bin", b"\0" * (2 * 1024**2))]))
    assert WarningCode.HIGH_COMPRESSION_RATIO in codes(ins)


def test_tampered_compression_method_read_like_android():
    """طريقة ضغط مزوّرة (99) لملف مخزّن: Android يقرؤه كـ STORED، ونحن كذلك مع تحذير."""
    data = make_zip([FAKE_MANIFEST, ("classes.dex", b"dex\n035\0" * 100)], method=zipfile.ZIP_STORED)
    data = patch_entry(data, "classes.dex", method=99)
    ins = inspect_zip(data)
    content, how = read_entry(data, ins, "classes.dex", 10_000)
    assert (content, how) == (b"dex\n035\0" * 100, "STORED_TAMPERED")
    verify_entry(data, ins, "classes.dex", 10_000)
    assert WarningCode.TAMPERED_COMPRESSION in codes(ins)


def test_tampered_deflate_method():
    payload = b"hello android " * 200
    data = patch_entry(make_zip([FAKE_MANIFEST, ("classes.dex", payload)]), "classes.dex", method=77)
    ins = inspect_zip(data)
    assert read_entry(data, ins, "classes.dex", 10_000) == (payload, "DEFLATED_TAMPERED")


def test_crc_mismatch():
    data = patch_entry(make_zip([FAKE_MANIFEST, ("classes.dex", b"dex")]), "classes.dex", crc=12345)
    ins = inspect_zip(data)
    verify_entry(data, ins, "classes.dex", 1000)
    assert WarningCode.CRC_MISMATCH in codes(ins)
