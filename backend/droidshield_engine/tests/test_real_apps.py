"""
Phase 9: التحقق من المحرك كاملاً على 12 تطبيقاً حقيقياً متنوعاً من F-Droid.

المرجع المستقل: فهرس F-Droid الرسمي (index-v2.json). F-Droid يبني كل تطبيق من مصدره ويستخرج
بياناته على خوادمه بأدوات Android الرسمية (aapt)، أي دون Androguard ودون كودنا.
من المرجع نقارن: الأذونات، وأذونات uses-permission-sdk-23 منفصلة، و minSdk/targetSdk،
ومعماريات المكتبات الأصلية (nativecode)، وأخيراً المتجه الكامل.

التنوع المختار (فئة لكل تطبيق): uses-permission-sdk-23، targetSdk قديم (16)، مكتبات native
لأربع معماريات، معمارية واحدة، أذونات بـ maxSdkVersion، APK كبير (54MB)، APK صغير جداً،
73 إذناً، صفر أذونات، targetSdk حديث (37)؛ إضافة إلى Automation و KDE Connect.
"""
import json
import time
from functools import lru_cache
from pathlib import Path

import numpy as np
import pytest

from droidshield_engine import config
from droidshield_engine.analyzers import (
    ApiAnalyzer, CertificateAnalyzer, ComponentAnalyzer, DexAnalyzer, HardwareAnalyzer, ManifestAnalyzer,
    MetadataAnalyzer, NativeAnalyzer, NetworkAnalyzer, PermissionAnalyzer, ResourcesAnalyzer, StringsAnalyzer,
)
from droidshield_engine.core import load_apk
from droidshield_engine.core.analysis_result import AnalysisResult, run_module
from droidshield_engine.exporters import export_all
from droidshield_engine.feature_extraction import FeatureMapper, load_feature_schema

ALL = (MetadataAnalyzer, ManifestAnalyzer, PermissionAnalyzer, ComponentAnalyzer, HardwareAnalyzer, DexAnalyzer,
       ApiAnalyzer, ResourcesAnalyzer, StringsAnalyzer, NetworkAnalyzer, NativeAnalyzer, CertificateAnalyzer)
P = "android.permission."
SOURCES = [(Path("E:/apk_test/fdroid_reference.json"), Path("E:/apk_test/dl")),
           (Path("E:/apk_test/phase9_reference.json"), Path("E:/apk_test/phase9_apks"))]


def load_cases() -> list[tuple[str, dict, Path]]:
    cases = []
    for ref, folder in SOURCES:
        if ref.exists():
            for pkg, exp in json.loads(ref.read_text(encoding="utf-8")).items():
                cases.append((pkg, exp, folder / Path(exp["file"]).name))
    return cases


CASES = load_cases()
pytestmark = [pytest.mark.slow, pytest.mark.skipif(not CASES, reason="مراجع F-Droid غير متوفرة")]
IDS = [c[0] for c in CASES]


@lru_cache(maxsize=None)
def analyze(path: Path) -> AnalysisResult:
    t0 = time.perf_counter()
    r = AnalysisResult(path)
    r.loaded = load_apk(path)
    for A in ALL:
        r.modules[A.name] = run_module(A(), r.loaded)
    r.feature_vector = FeatureMapper().map_analysis(r.modules["permissions"].data)
    r.duration_seconds = time.perf_counter() - t0
    return r


@pytest.mark.parametrize("pkg,exp,path", CASES, ids=IDS)
def test_file_is_the_one_described_by_reference(pkg, exp, path):
    r = analyze(path)
    assert r.loaded.hashes["sha256"] == exp["sha256"]
    assert r.package == pkg


@pytest.mark.parametrize("pkg,exp,path", CASES, ids=IDS)
def test_all_modules_succeed(pkg, exp, path):
    r = analyze(path)
    failed = {n: m.error for n, m in r.modules.items() if m.status != "ok"}
    assert failed == {}


@pytest.mark.parametrize("pkg,exp,path", CASES, ids=IDS)
def test_permissions_match_reference_exactly(pkg, exp, path):
    got = set(analyze(path).module_data("permissions")["requested_names"])
    want = set(exp["permissions"])
    assert (sorted(want - got), sorted(got - want)) == ([], [])


@pytest.mark.parametrize("pkg,exp,path", [c for c in CASES if "sdk23" in c[1]], ids=[c[0] for c in CASES if "sdk23" in c[1]])
def test_sdk23_permissions_match_reference(pkg, exp, path):
    reqs = analyze(path).module_data("permissions")["requested"]
    got = {r["name"] for r in reqs if "uses-permission-sdk-23" in r["tags"]}
    assert got == set(exp["sdk23"])


@pytest.mark.parametrize("pkg,exp,path", [c for c in CASES if "target_sdk" in c[1]], ids=[c[0] for c in CASES if "target_sdk" in c[1]])
def test_sdk_levels_match_reference(pkg, exp, path):
    m = analyze(path).module_data("manifest")
    assert (m["min_sdk"], m["target_sdk"]) == (exp["min_sdk"], exp["target_sdk"])


@pytest.mark.parametrize("pkg,exp,path", [c for c in CASES if "nativecode" in c[1]], ids=[c[0] for c in CASES if "nativecode" in c[1]])
def test_native_abis_match_reference(pkg, exp, path):
    native = analyze(path).module_data("native")
    assert native["abis"] == sorted(exp["nativecode"])
    assert native["abi_mismatches"] == [] and native["not_elf"] == []


@pytest.mark.parametrize("pkg,exp,path", CASES, ids=IDS)
def test_vector_matches_vector_built_from_reference(pkg, exp, path):
    schema = load_feature_schema()
    fv = analyze(path).feature_vector
    expected = np.array([int(P + n in set(exp["permissions"])) for n in schema.features], dtype=np.int8)
    assert np.array_equal(fv.values, expected)
    assert fv.validation["passed"] and fv.values.shape == (110,) and fv.values.dtype == np.int8


def test_androguard_builtin_misses_sdk23_but_engine_does_not():
    """الدليل العملي على ثغرة Androguard 4.1.4: تطبيق حقيقي يطلب 17 إذناً عبر sdk-23."""
    case = next((c for c in CASES if c[0] == "be.mygod.vpnhotspot_foss"), None)
    if case is None:
        pytest.skip("vpnhotspot غير متوفر")
    pkg, exp, path = case
    r = analyze(path)
    builtin = set(r.loaded.apk.get_permissions())
    missed = set(exp["sdk23"]) - builtin
    assert len(missed) > 0                                                          # Androguard يفوّتها
    assert missed <= set(r.module_data("permissions")["requested_names"])          # محركنا يلتقطها
    in_schema = {m for m in missed if m.startswith(P) and m[len(P):] in load_feature_schema()}
    assert all(r.feature_vector.as_dict()[m[len(P):]] == 1 for m in in_schema)     # وتصل إلى المتجه


@pytest.mark.parametrize("pkg,exp,path", CASES, ids=IDS)
def test_export_and_reasonable_resources(pkg, exp, path, tmp_path):
    r = analyze(path)
    paths = export_all(r, tmp_path)
    assert np.array_equal(np.load(paths["feature_vector_npy"], allow_pickle=False), r.feature_vector.values)
    assert paths["raw_analysis"].stat().st_size < 30 * 1024 * 1024
    # الوقت المطلق يتغير مع حِمل الجهاز (أثقل تطبيق: ~50s منفرداً، 121s أثناء تشغيل كل الاختبارات)،
    # لذلك نختبر ما يهم تشغيلياً: لم تبلغ أي وحدة ميزانيتها (لا بيانات مقتطعة بسبب الوقت)،
    # والمدة أقل من الحد الصارم الذي يقتل بعده الـ Batch الـ process.
    hit = [n for n, m in r.modules.items() if (m.data or {}).get("truncated", {}).get("time_budget")]
    assert hit == []
    assert r.duration_seconds < config.BATCH_TIMEOUT_SECONDS
