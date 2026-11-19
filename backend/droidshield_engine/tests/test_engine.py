"""
Phase 10: اختبارات التكامل النهائي — AnalysisEngine، الـ Batch المعزول، و CLI.
"""
import csv
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

import numpy as np
import pytest

import batch_helpers
from droidshield_engine import AnalysisEngine, analyze_directory, result_to_dict, run_isolated
from droidshield_engine.analyzers import NativeAnalyzer, PermissionAnalyzer
from droidshield_engine.analyzers.base import BaseAnalyzer
from droidshield_engine.feature_extraction import SchemaValidationError, load_feature_schema

BACKEND = Path(__file__).resolve().parents[2]
P9 = Path("E:/apk_test/phase9_apks")
SMALL = [P9 / "org.jsl.wfwt_17.apk", P9 / "ademar.textlauncher_10.apk", P9 / "S.N.A.K.E_1000001.apk"]
MEDIA = P9 / "ac.robinson.mediaphone_65.apk"
needs_real = pytest.mark.skipif(not MEDIA.exists(), reason="ملفات APK الحقيقية غير متوفرة")


class Boom(BaseAnalyzer):
    name = "boom"

    def analyze(self, apk):
        raise RuntimeError("simulated")


class BrokenPermissions(PermissionAnalyzer):
    def analyze(self, apk):
        raise RuntimeError("permissions broke")


@pytest.fixture(scope="module")
def engine():
    return AnalysisEngine()


# ================================ AnalysisEngine ================================ #
@needs_real
def test_engine_full_analysis(engine):
    r = engine.analyze(MEDIA)
    assert r.loaded_ok and r.vector_ok and r.summary()["modules_failed"] == []
    assert len(r.modules) == 12 and list(r.modules)[0] == "permissions"
    assert r.feature_vector.values.shape == (110,) and r.prediction is None


@needs_real
def test_analyze_and_export_releases_memory(engine, tmp_path):
    r, paths = engine.analyze_and_export(MEDIA, tmp_path)
    assert r.loaded.data == b"" and "dex" not in r.loaded.__dict__ and "strings" not in r.loaded.__dict__
    assert r.package == "ac.robinson.mediaphone"  # ما يحتاجه التقرير باقٍ
    assert np.array_equal(np.load(paths["feature_vector_npy"], allow_pickle=False), r.feature_vector.values)


def test_engine_never_raises_on_bad_file(engine, tmp_path):
    bad = tmp_path / "x.apk"
    bad.write_bytes(b"garbage" * 10)
    r = engine.analyze(bad)
    assert r.load_error["code"] == "INVALID_ZIP" and r.modules == {} and not r.vector_ok


@needs_real
def test_failed_module_isolated(tmp_path):
    r = AnalysisEngine([PermissionAnalyzer(), Boom(), NativeAnalyzer()]).analyze(MEDIA)
    assert r.modules["boom"].status == "failed" and r.modules["native"].status == "ok" and r.vector_ok


@needs_real
def test_permission_failure_means_no_vector_but_other_results_kept():
    r = AnalysisEngine([BrokenPermissions(), NativeAnalyzer()]).analyze(MEDIA)
    assert not r.vector_ok and "permission" in r.mapping_error
    assert r.modules["native"].status == "ok"


def test_duplicate_analyzer_names_rejected():
    with pytest.raises(ValueError):
        AnalysisEngine([PermissionAnalyzer(), PermissionAnalyzer()])


def test_engine_fails_fast_on_changed_dataset(tmp_path):
    """إن تغيّرت أعمدة الـ Dataset، يرفض المحرك العمل عند الإنشاء (لا متجهات بدلالة خاطئة)."""
    src = load_feature_schema().source
    header, *rest = src.read_text(encoding="utf-8").splitlines()[:3]
    cols = header.split(",")
    cols[0], cols[1] = cols[1], cols[0]  # تبديل عمودين فقط
    bad = tmp_path / "ds.csv"
    bad.write_text("\n".join([",".join(cols), *rest]), encoding="utf-8")
    with pytest.raises(SchemaValidationError):
        AnalysisEngine(schema=load_feature_schema(bad))


@needs_real
def test_result_to_dict_is_json(engine):
    doc = result_to_dict(engine.analyze(SMALL[0]))
    s = json.dumps(doc, default=str)
    assert doc["feature_vector"]["length"] == 110 and doc["prediction"] is None and len(s) > 1000


# ================================ Batch المعزول ================================ #
@pytest.fixture
def batch_dir(tmp_path):
    d = tmp_path / "in"
    d.mkdir()
    for f in SMALL:
        shutil.copy(f, d)
    (d / "broken.apk").write_bytes(b"not an apk")
    (d / "empty.apk").write_bytes(b"")
    (d / "notes.txt").write_text("ignored")
    return d


@needs_real
def test_batch_continues_after_failures(batch_dir, tmp_path):
    out = tmp_path / "out"
    s = analyze_directory(batch_dir, out, workers=2, timeout=120)
    assert s["counts"] == {"ok": 3, "partial": 0, "load_failed": 2, "timeout": 0, "crashed": 0}
    by_file = {o.file: o for o in s["outcomes"]}
    assert by_file["broken.apk"].error.startswith("INVALID_ZIP")
    assert by_file["empty.apk"].error.startswith("EMPTY_FILE")
    assert "notes.txt" not in by_file
    # كل تطبيق ناجح له مجلده المستقل بالملفات الأربعة
    for o in s["outcomes"]:
        if o.status == "ok":
            assert len(list((out / o.result_folder).iterdir())) == 4


@needs_real
def test_batch_summary_files(batch_dir, tmp_path):
    s = analyze_directory(batch_dir, tmp_path / "out", workers=1, timeout=120)
    doc = json.loads(s["paths"]["json"].read_text(encoding="utf-8"))
    assert doc["total"] == 5 and doc["engine"]["schema_fingerprint"] == load_feature_schema().fingerprint
    with s["paths"]["csv"].open(encoding="utf-8-sig") as f:
        assert len(list(csv.DictReader(f))) == 5
    with s["paths"]["vectors_csv"].open(encoding="utf-8-sig") as f:
        rows = list(csv.reader(f))
    assert rows[0] == ["file", "sha256", "package", *load_feature_schema().features]  # بلا Label
    assert len(rows) == 4 and all(len(r) == 113 for r in rows)
    assert all(set(r[3:]) <= {"0", "1"} for r in rows[1:])


@needs_real
def test_batch_vectors_equal_single_analysis(batch_dir, tmp_path, engine):
    s = analyze_directory(batch_dir, tmp_path / "out", workers=2, timeout=120)
    for o in s["outcomes"]:
        if o.status == "ok":
            single = engine.analyze(batch_dir / o.file).feature_vector.values.tolist()
            assert o.vector == single, o.file  # العزل في process لا يغيّر النتيجة


def test_hanging_file_is_killed_after_timeout(tmp_path):
    f = tmp_path / "hang.apk"
    f.write_bytes(b"x")
    t0 = time.monotonic()
    o = run_isolated(f, tmp_path, timeout=3, worker=batch_helpers.hanging_worker)
    assert o.status == "timeout" and "3" in o.error
    assert time.monotonic() - t0 < 30


def test_crashing_worker_is_recorded(tmp_path):
    f = tmp_path / "crash.apk"
    f.write_bytes(b"x")
    o = run_isolated(f, tmp_path, timeout=60, worker=batch_helpers.crashing_worker)
    assert o.status == "crashed" and "exit code 3" in o.error


@needs_real
def test_hang_does_not_block_other_files(tmp_path):
    d = tmp_path / "in"
    d.mkdir()
    shutil.copy(SMALL[0], d)
    (d / "zz_hang.apk").write_bytes(b"x")
    s = analyze_directory(d, tmp_path / "out", workers=1, timeout=3, worker=batch_helpers.hanging_worker)
    assert {o.status for o in s["outcomes"]} == {"timeout"} and s["document"]["total"] == 2


def test_empty_directory(tmp_path):
    s = analyze_directory(tmp_path, tmp_path / "out")
    assert s["document"]["total"] == 0 and s["paths"]["json"].exists()


# ==================================== CLI ==================================== #
def cli(*args, tmp_path):
    env = {**__import__("os").environ, "DROIDSHIELD_LOG_DIR": str(tmp_path / "logs")}
    return subprocess.run([sys.executable, "-m", "droidshield_engine", *args], cwd=BACKEND, env=env,
                          capture_output=True, text=True, encoding="utf-8", timeout=300)


def test_cli_schema(tmp_path):
    p = cli("schema", tmp_path=tmp_path)
    assert p.returncode == 0 and "Features     : 110" in p.stdout and "PASSED" in p.stdout


@needs_real
def test_cli_analyze(tmp_path):
    p = cli("analyze", str(SMALL[0]), "--out", str(tmp_path / "res"), tmp_path=tmp_path)
    assert p.returncode == 0, p.stderr
    assert "Modules   : 12 ok" in p.stdout and "(110,) int8" in p.stdout
    assert len(list((tmp_path / "res").iterdir())) == 1
    log = next((tmp_path / "logs").glob("droidshield_*.log")).read_text(encoding="utf-8")
    assert "Schema validation passed" in log and "Analysis completed" in log


@needs_real
def test_cli_analyze_isolated(tmp_path):
    p = cli("analyze", str(SMALL[0]), "--out", str(tmp_path / "res"), "--isolated", "--timeout", "120",
            tmp_path=tmp_path)
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout)["status"] == "ok"


def test_cli_missing_file(tmp_path):
    p = cli("analyze", str(tmp_path / "nope.apk"), tmp_path=tmp_path)
    assert p.returncode == 2


@needs_real
def test_cli_batch_exit_code_reflects_failures(batch_dir, tmp_path):
    p = cli("batch", str(batch_dir), "--out", str(tmp_path / "res"), "--workers", "2", tmp_path=tmp_path)
    assert p.returncode == 1 and "'ok': 3" in p.stdout and "'load_failed': 2" in p.stdout
