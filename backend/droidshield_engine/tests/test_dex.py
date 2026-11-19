"""
اختبارات تحليل DEX واستدعاءات الـ APIs.

كيف نتحقق من صحة النتائج دون الاعتماد على الكود نفسه؟
    1) الأعداد: نقرأ header ملف DEX بأنفسنا (struct) ونقارن عدد الأصناف وجدول method_ids.
    2) الـ APIs: نشغّل التحليل الكامل في Androguard (Analysis + create_xref) كمرجع مستقل،
       ونقارن كل API وجدناه: عدد مواضع الاستدعاء، والـ methods التي تستدعيه.
    3) ملفات DEX تالفة داخل APK حقيقي: يجب أن يفشل الملف التالف وحده.
"""
import io
import json
import struct
import zipfile
from pathlib import Path

import pytest

from droidshield_engine.analyzers.api_analyzer import ApiAnalyzer
from droidshield_engine.analyzers.api_catalog import build_index, match
from droidshield_engine.analyzers.dex_analyzer import DexAnalyzer, descriptor_to_java, is_library_class
from droidshield_engine.config import DexLimits
from droidshield_engine.core import load_apk

APK_DIR = Path("E:/apk_test/dl")
AUTOMATION = APK_DIR / "com.jens.automation2_149.apk"
KDE = APK_DIR / "org.kde.kdeconnect_tp_13702.apk"
needs_real = pytest.mark.skipif(not AUTOMATION.exists(), reason="ملفات APK الحقيقية غير متوفرة")


@pytest.fixture(scope="module")
def kde():
    a = load_apk(KDE)
    return a, DexAnalyzer().analyze(a), ApiAnalyzer().analyze(a)


@pytest.fixture(scope="module")
def automation():
    a = load_apk(AUTOMATION)
    return a, DexAnalyzer().analyze(a), ApiAnalyzer().analyze(a)


def dex_header(raw: bytes) -> dict:
    """قراءة مستقلة لـ header ملف DEX حسب مواصفة Android (لا Androguard)."""
    return {
        "version": raw[4:7].decode(),
        "method_ids": struct.unpack_from("<I", raw, 0x58)[0],
        "class_defs": struct.unpack_from("<I", raw, 0x60)[0],
    }


# ============================== DEX structure ============================== #
@needs_real
def test_multidex_all_files_analyzed(kde):
    a, d, _ = kde
    assert [f["name"] for f in d["dex_files"]] == ["classes.dex", "classes2.dex"]
    assert d["multidex"] and all(f["error"] is None for f in d["dex_files"])


@needs_real
@pytest.mark.parametrize("fixture", ["kde", "automation"])
def test_counts_match_dex_header(fixture, request):
    a, d, _ = request.getfixturevalue(fixture)
    with zipfile.ZipFile(a.path) as z:
        for f in d["dex_files"]:
            h = dex_header(z.read(f["name"]))
            assert (f["version"], f["classes"], f["method_ids"]) == (h["version"], h["class_defs"], h["method_ids"])
    assert d["totals"]["classes"] == sum(f["classes"] for f in d["dex_files"])


@needs_real
def test_known_classes_present(kde, automation):
    names = {c["name"] for c in kde[1]["classes"]}
    assert "org.kde.kdeconnect.ui.MainActivity" in names
    assert "com.jens.automation2.ActivityMainTabLayout" in {c["name"] for c in automation[1]["classes"]}


@needs_real
def test_class_details(kde):
    main = next(c for c in kde[1]["classes"] if c["name"] == "org.kde.kdeconnect.ui.MainActivity")
    assert main["library"] is False and main["dex"] == "classes.dex"
    assert main["superclass"] and main["methods"] > 0


@needs_real
def test_native_methods(kde):
    d = kde[1]
    assert d["totals"]["native_methods"] == len(d["native_methods"]) == 8
    natives = {m["signature"] for m in d["methods"] if "native" in m["access"]}
    assert natives <= set(d["native_methods"])  # كل native في القائمة المفصلة موجود في قائمة native


@needs_real
def test_signatures_have_standard_format(kde):
    _, d, api = kde
    for sig in [m["signature"] for m in d["methods"]] + [c["signature"] for c in api["calls"]]:
        assert " " not in sig and "->" in sig and sig.startswith("L")


@needs_real
def test_library_classes_counted_but_not_detailed(kde):
    d = kde[1]
    t = d["totals"]
    assert t["library_classes"] + t["non_library_classes"] == t["classes"]
    assert not any(m["signature"].startswith("Landroidx/") for m in d["methods"])
    assert any(c["name"].startswith("androidx.") for c in d["classes"])  # الأصناف كلها مسرودة


@needs_real
def test_output_size_reasonable(kde):
    assert len(json.dumps(kde[1:], ensure_ascii=False)) < 10_000_000


@pytest.mark.parametrize("desc,java", [("Lcom/a/B;", "com.a.B"), ("Lcom/a/B$C;", "com.a.B$C"), ("I", "I")])
def test_descriptor_to_java(desc, java):
    assert descriptor_to_java(desc) == java


def test_library_detection():
    assert is_library_class("androidx.appcompat.App") and is_library_class("kotlin.Unit")
    assert not is_library_class("a.b.c")          # كود معمّى يبقى ظاهراً
    assert not is_library_class("com.evil.app.Main")


# ============================== API calls ============================== #
def test_catalog_matching():
    idx = build_index()
    assert match(idx, "Landroid/telephony/SmsManager;", "sendTextMessage") == "sms"
    assert match(idx, "Landroid/telephony/SmsManager;", "toString") is None
    # Runtime يتبع فئتين حسب الـ method
    assert match(idx, "Ljava/lang/Runtime;", "exec") == "process_execution"
    assert match(idx, "Ljava/lang/Runtime;", "loadLibrary") == "dynamic_code_loading"
    assert match(idx, "Landroid/app/admin/DevicePolicyManager;", "anything") == "device_admin"
    assert match(idx, "Lcom/evil/SmsManager;", "sendTextMessage") is None  # الاسم الكامل للصنف مطلوب


@needs_real
def test_sms_call_found_with_correct_caller(automation):
    calls = {c["signature"]: c for c in automation[2]["calls"]}
    sig = ("Landroid/telephony/SmsManager;->sendTextMessage(Ljava/lang/String;Ljava/lang/String;"
           "Ljava/lang/String;Landroid/app/PendingIntent;Landroid/app/PendingIntent;)V")
    assert calls[sig]["category"] == "sms"
    assert calls[sig]["callers"] == ["Lcom/jens/automation2/Actions;->sendSmsMessage(Ljava/lang/String;Ljava/lang/String;)V"]


@needs_real
@pytest.mark.slow
def test_api_calls_match_androguard_full_xref(automation):
    """المرجع المستقل: Androguard Analysis الكامل (أبطأ بعدة مرات). يجب تطابق كل API حرفياً."""
    from androguard.core.analysis.analysis import Analysis

    a, _, api = automation
    dx = Analysis()
    for pd in a.dex:
        dx.add(pd.dex)
    dx.create_xref()
    idx = build_index()
    expected = {}
    for m in dx.get_methods():
        if not m.is_external() or not match(idx, m.class_name, m.name):
            continue
        sites = m.get_xref_from()
        if sites:
            sig = f"{m.class_name}->{m.name}{m.descriptor.replace(' ', '')}"
            callers = {f"{c.name}->{mm.name}{mm.descriptor.replace(' ', '')}" for c, mm, _ in sites}
            expected[sig] = (len(sites), callers)

    got = {c["signature"]: (c["call_sites"], set(c["callers"])) for c in api["calls"]}
    assert set(got) == set(expected)
    for sig, (n, callers) in expected.items():
        assert got[sig][0] == n, sig
        if n <= DexLimits().max_callers_per_api:
            assert got[sig][1] == callers, sig


@needs_real
def test_by_category_consistent(automation):
    api = automation[2]
    assert sum(v["call_sites"] for v in api["by_category"].values()) == api["total_call_sites"]
    assert {c["category"] for c in api["calls"]} == set(api["categories_present"])


# ====================== حدود الوقت والملفات التالفة ====================== #
@needs_real
def test_zero_time_budget_returns_partial_result_safely():
    a = load_apk(KDE)
    zero = DexLimits(time_budget_seconds=0)
    d, api = DexAnalyzer(zero).analyze(a), ApiAnalyzer(zero).analyze(a)
    assert d["truncated"]["time_budget"] and api["truncated"]["time_budget"]
    assert d["totals"]["classes"] < 8559
    json.dumps([d, api])


@needs_real
def test_list_caps_mark_truncated():
    a = load_apk(KDE)
    d = DexAnalyzer(DexLimits(max_listed_classes=10, max_listed_methods=5)).analyze(a)
    assert len(d["classes"]) == 10 and len(d["methods"]) == 5
    assert d["truncated"]["classes"] and d["truncated"]["methods"]
    assert d["totals"]["classes"] == 8559  # الأعداد تبقى كاملة


def rebuild(src: Path, replace: dict[str, bytes], tmp_path) -> Path:
    buf = io.BytesIO()
    with zipfile.ZipFile(src) as z, zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as out:
        for i in z.infolist():
            out.writestr(i.filename, replace.get(i.filename, z.read(i)))
    p = tmp_path / "rebuilt.apk"
    p.write_bytes(buf.getvalue())
    return p


@needs_real
@pytest.mark.parametrize("garbage,error_hint", [
    (b"dex\n035\0" + b"\xff" * 200, None),   # magic صحيح لكن المحتوى تالف
    (b"PK not a dex file at all", "magic"),
])
def test_corrupted_secondary_dex_does_not_lose_primary(tmp_path, garbage, error_hint):
    a = load_apk(rebuild(KDE, {"classes2.dex": garbage}, tmp_path))
    d, api = DexAnalyzer().analyze(a), ApiAnalyzer().analyze(a)
    primary, secondary = d["dex_files"]
    assert primary["error"] is None and primary["classes"] == 7775
    assert secondary["error"] is not None
    if error_hint:
        assert error_hint in secondary["error"]
    assert api["total_call_sites"] > 0  # الـ APIs من classes.dex ما زالت موجودة
