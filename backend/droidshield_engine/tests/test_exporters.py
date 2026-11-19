"""
اختبارات التصدير: raw_analysis.json, feature_vector.npy/.json, analysis_report.txt.

نتحقق من:
    - الملفات الأربعة موجودة، والمتجه المحفوظ = المتجه في الذاكرة (int8، (110,)، نفس القيم).
    - الأرقام في التقرير = الأرقام في نتائج الوحدات (لا تُكتب يدوياً).
    - التقرير لا يذكر Malware/Benign إلا مع نتيجة نموذج.
    - فشل وحدة أو فشل التحميل: تُكتب النتائج المتاحة ويُذكر الفشل بوضوح.
    - اسم المجلد آمن حتى لو كان اسم الحزمة خبيثاً.
"""
import json
from pathlib import Path

import numpy as np
import pytest

from droidshield_engine import config
from droidshield_engine.analyzers import (
    ApiAnalyzer, ComponentAnalyzer, DexAnalyzer, MetadataAnalyzer, NativeAnalyzer, PermissionAnalyzer,
)
from droidshield_engine.analyzers.base import BaseAnalyzer
from droidshield_engine.core import ApkLoadError, load_apk
from droidshield_engine.core.analysis_result import AnalysisResult, run_module
from droidshield_engine.exporters import export_all
from droidshield_engine.exporters.common import ensure_inside, json_default, safe_name
from droidshield_engine.exporters.report_exporter import build_report
from droidshield_engine.feature_extraction import FeatureMapper, load_feature_schema

KDE = Path("E:/apk_test/dl/org.kde.kdeconnect_tp_13702.apk")
needs_real = pytest.mark.skipif(not KDE.exists(), reason="ملفات APK الحقيقية غير متوفرة")
FAST = (MetadataAnalyzer, PermissionAnalyzer, ComponentAnalyzer, DexAnalyzer, ApiAnalyzer, NativeAnalyzer)


class Boom(BaseAnalyzer):
    name = "boom"

    def analyze(self, apk):
        raise RuntimeError("simulated failure")


def analyze(path: Path, analyzers=FAST) -> AnalysisResult:
    r = AnalysisResult(path)
    try:
        r.loaded = load_apk(path)
    except ApkLoadError as e:
        r.load_error = {"code": e.code.value, "message": e.message}
        return r
    for A in analyzers:
        r.modules[A.name] = run_module(A(), r.loaded)
    if r.modules.get("permissions") and r.modules["permissions"].status == "ok":
        r.feature_vector = FeatureMapper().map_analysis(r.modules["permissions"].data)
    return r


@pytest.fixture(scope="module")
def kde_result():
    return analyze(KDE)


# ================================ نجاح كامل ================================ #
@needs_real
def test_four_files_written(kde_result, tmp_path):
    paths = export_all(kde_result, tmp_path)
    folder = paths["folder"]
    assert folder.parent == tmp_path.resolve()
    assert folder.name == "org.kde.kdeconnect_tp_13702_277b31e8e4ff"
    assert sorted(p.name for p in folder.iterdir()) == [
        "analysis_report.txt", "feature_vector.json", "feature_vector.npy", "raw_analysis.json"]
    assert not list(folder.glob("*.tmp"))  # الكتابة الذرية لم تترك ملفات مؤقتة


@needs_real
def test_npy_roundtrip_is_exact(kde_result, tmp_path):
    npy = export_all(kde_result, tmp_path)["feature_vector_npy"]
    v = np.load(npy, allow_pickle=False)
    assert v.shape == (110,) and v.dtype == np.int8
    assert np.array_equal(v, kde_result.feature_vector.values)
    assert set(np.unique(v)).issubset({0, 1})


@needs_real
def test_vector_json_names_and_fingerprint(kde_result, tmp_path):
    doc = json.loads(export_all(kde_result, tmp_path)["feature_vector_json"].read_text(encoding="utf-8"))
    schema = load_feature_schema()
    assert doc["feature_names"] == list(schema.features) == list(doc["vector"])
    assert "Label" not in doc["feature_names"]
    assert doc["schema_fingerprint"] == config.EXPECTED_SCHEMA_SHA256
    assert [doc["vector"][n] for n in schema.features] == kde_result.feature_vector.values.tolist()
    assert doc["validation"]["passed"]


@needs_real
def test_raw_analysis_contains_all_modules_and_no_vector(kde_result, tmp_path):
    raw = json.loads(export_all(kde_result, tmp_path)["raw_analysis"].read_text(encoding="utf-8"))
    assert set(raw["modules"]) == {A.name for A in FAST}
    assert all(m["status"] == "ok" and m["data"] for m in raw["modules"].values())
    assert raw["apk"]["hashes"]["sha256"].startswith("277b31e8")
    assert raw["engine"]["schema_fingerprint"] == config.EXPECTED_SCHEMA_SHA256
    assert "vector" not in raw["feature_mapping"]  # المتجه في ملفاته فقط
    # لا مسارات من جهاز المحلل. نحسب النتيجة أولاً: لو فشل assert على نص حجمه عدة MB
    # لحاول pytest بناء diff كامل له (بطيء جداً)
    text = json.dumps(raw)
    leaks = [p for p in (str(KDE.parent), KDE.parent.as_posix(), str(tmp_path)) if p in text]
    assert leaks == []


@needs_real
def test_report_numbers_come_from_modules(kde_result):
    rep = build_report(kde_result)
    dex = kde_result.module_data("dex")["totals"]
    for line in (f"Classes                            {dex['classes']}",
                 f"Methods                            {dex['methods']}",
                 f"Permissions requested              {kde_result.module_data('permissions')['counts']['requested']}",
                 f"Matched features (=1)              {len(kde_result.feature_vector.matched)}",
                 "Native libraries                   4", "Validation                         PASSED"):
        assert line in rep, line


@needs_real
def test_report_has_no_verdict_without_prediction(kde_result):
    rep = build_report(kde_result)
    assert "Malware" not in rep and "Benign" not in rep


@needs_real
def test_report_shows_prediction_when_given(kde_result):
    kde_result.prediction = {"label": config.MALWARE, "probability": 0.91, "model": "svm"}
    try:
        assert "Model prediction                   Malware" in build_report(kde_result)
        kde_result.prediction["label"] = config.BENIGN
        assert "Model prediction                   Benign" in build_report(kde_result)
    finally:
        kde_result.prediction = None


@needs_real
def test_reexport_overwrites_same_folder(kde_result, tmp_path):
    a, b = export_all(kde_result, tmp_path), export_all(kde_result, tmp_path)
    assert a["folder"] == b["folder"] and len(list(tmp_path.iterdir())) == 1


# ================================ حالات الفشل ================================ #
@needs_real
def test_failed_module_does_not_lose_others(tmp_path):
    r = analyze(KDE, (PermissionAnalyzer, Boom, NativeAnalyzer))
    assert r.modules["boom"].status == "failed" and "simulated failure" in r.modules["boom"].error
    assert r.modules["native"].status == "ok" and r.vector_ok
    paths = export_all(r, tmp_path)
    raw = json.loads(paths["raw_analysis"].read_text(encoding="utf-8"))
    assert raw["status"]["modules_failed"] == ["boom"]
    assert raw["modules"]["boom"]["data"] is None
    assert "[FAIL] boom" in paths["report"].read_text(encoding="utf-8")
    assert "feature_vector_npy" in paths


def test_load_failure_still_exports_raw_and_report(tmp_path):
    bad = tmp_path / "broken.apk"
    bad.write_bytes(b"this is not an apk")
    r = analyze(bad)
    paths = export_all(r, tmp_path / "out")
    assert paths["folder"].name == "FAILED_broken"
    assert "feature_vector_npy" not in paths
    raw = json.loads(paths["raw_analysis"].read_text(encoding="utf-8"))
    assert raw["load_error"]["code"] == "INVALID_ZIP" and raw["status"]["loaded"] is False
    rep = paths["report"].read_text(encoding="utf-8")
    assert "Load FAILED" in rep and "INVALID_ZIP" in rep and "NOT built" in rep


@needs_real
def test_stale_vector_removed_when_mapping_fails(kde_result, tmp_path):
    folder = export_all(kde_result, tmp_path)["folder"]
    vector = kde_result.feature_vector
    try:
        kde_result.feature_vector, kde_result.mapping_error = None, "simulated"
        export_all(kde_result, tmp_path)
        assert not (folder / "feature_vector.npy").exists()  # لا متجه قديم مضلِّل
    finally:
        kde_result.feature_vector, kde_result.mapping_error = vector, None


# ================================ الأمان ================================ #
@pytest.mark.parametrize("raw,expected", [
    ("com.example.app", "com.example.app"), ("../../etc/passwd", "etc_passwd"), ("C:\\Windows", "C_Windows"),
    ("تطبيق", "unknown"), ("", "unknown"), ("a" * 200, "a" * 80), ("..", "unknown"),
])
def test_safe_name(raw, expected):
    assert safe_name(raw) == expected


def test_ensure_inside(tmp_path):
    assert ensure_inside(tmp_path, tmp_path / "x") == (tmp_path / "x").resolve()
    with pytest.raises(ValueError):
        ensure_inside(tmp_path, tmp_path / ".." / "escape")


def test_json_default_types():
    doc = {"i": np.int8(1), "f": np.float32(0.5), "a": np.array([1, 0], dtype=np.int8),
           "s": {"b", "a"}, "p": Path("C:/secret/dir/app.apk"), "by": b"\x01\xff"}
    out = json.loads(json.dumps(doc, default=json_default))
    assert out == {"i": 1, "f": 0.5, "a": [1, 0], "s": ["a", "b"], "p": "app.apk", "by": "01ff"}
