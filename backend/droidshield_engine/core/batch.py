"""
تحليل مجموعة ملفات APK، كل ملف في process مستقل.

لماذا process لكل ملف (وليس thread أو حلقة عادية)؟
    1) العزل: لا تُشارَك أي حالة (ذاكرة، كائنات Androguard) بين تطبيقين.
    2) الحد الزمني الصارم: thread عالق لا يمكن إيقافه في Python، أما process فيمكن قتله.
       ملف مصمَّم لإعلاق المحلل (حلقة لا نهائية في parser مثلاً) لا يوقف الدفعة.
    3) الانهيار المعزول: خطأ قاتل في مكتبة native (segfault) يُسقط process ذلك الملف فقط.
    4) الذاكرة: كل process يعيد ذاكرته للنظام عند انتهائه.

نستخدم multiprocessing بنمط "spawn" (الوحيد المتاح على Windows، والأكثر أماناً)، وندير
العمّال بأنفسنا بدل ProcessPoolExecutor لأنه لا يسمح بقتل عامل عالق.

المخرجات الإجمالية في مجلد النتائج:
    batch_<timestamp>.json   -> سجل كامل: لكل ملف status, package, sha256, المدة، الأخطاء، المجلد
    batch_<timestamp>.csv    -> نفس السجل كجدول
    batch_<timestamp>_vectors.csv -> لكل تطبيق ناجح: file, sha256, package + 110 عموداً بترتيب الـ Dataset
                                     (جاهز لتمريره لنموذج التصنيف دفعة واحدة؛ بلا Label)
"""
from __future__ import annotations

import csv
import logging
import multiprocessing as mp
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable

from .. import config
from ..exporters.common import write_json

log = logging.getLogger(__name__)
STATUSES = ("ok", "partial", "load_failed", "timeout", "crashed")


@dataclass
class FileOutcome:
    file: str
    status: str                    # ok | partial (وحدة فشلت) | load_failed | timeout | crashed
    package: str | None = None
    sha256: str | None = None
    duration_seconds: float = 0.0
    vector_built: bool = False
    matched_features: int | None = None
    failed_modules: list[str] = field(default_factory=list)
    error: str | None = None
    result_folder: str | None = None
    vector: list[int] | None = None


def analyze_worker(path: str, results_dir: str, log_dir: str | None, conn) -> None:
    """يعمل داخل process مستقل: يحلل ويصدّر ويرسل ملخصاً صغيراً فقط عبر الـ Pipe."""
    from .analysis_engine import AnalysisEngine
    from .logging_setup import configure_logging

    configure_logging(Path(log_dir) if log_dir else None, console_level=logging.CRITICAL)
    t0 = time.perf_counter()
    try:
        result, paths = AnalysisEngine().analyze_and_export(path, Path(results_dir))
        s = result.summary()
        if not result.loaded_ok:
            status, error = "load_failed", f"{result.load_error['code']}: {result.load_error['message']}"
        else:
            status = "ok" if not s["modules_failed"] and result.vector_ok else "partial"
            error = result.mapping_error
        fv = result.feature_vector
        outcome = FileOutcome(
            file=Path(path).name, status=status, package=result.package,
            sha256=result.loaded.hashes["sha256"] if result.loaded else None,
            duration_seconds=round(time.perf_counter() - t0, 2), vector_built=fv is not None,
            matched_features=len(fv.matched) if fv else None, failed_modules=s["modules_failed"], error=error,
            result_folder=paths["folder"].name, vector=fv.values.tolist() if fv else None,
        )
    except BaseException as e:  # حتى SchemaValidationError: نرسل السبب بدل الصمت
        outcome = FileOutcome(Path(path).name, "crashed", error=f"{type(e).__name__}: {e}",
                              duration_seconds=round(time.perf_counter() - t0, 2))
    conn.send(asdict(outcome))
    conn.close()


def _run_pool(files: list[Path], results_dir: Path, workers: int, timeout: float,
              worker: Callable, log_dir: Path | None) -> list[FileOutcome]:
    ctx = mp.get_context("spawn")
    pending = list(files)
    running: dict[Path, tuple] = {}
    outcomes: dict[Path, FileOutcome] = {}

    while pending or running:
        while pending and len(running) < workers:
            path = pending.pop(0)
            parent, child = ctx.Pipe(duplex=False)
            proc = ctx.Process(target=worker, args=(str(path), str(results_dir), str(log_dir) if log_dir else None,
                                                    child), daemon=True)
            proc.start()
            child.close()
            running[path] = (proc, parent, time.monotonic())
            log.info("Batch: started %s (pid %s)", path.name, proc.pid)

        for path, (proc, conn, started) in list(running.items()):
            elapsed = time.monotonic() - started
            try:
                has_result = conn.poll()
            except (BrokenPipeError, EOFError, OSError):
                # على Windows: موت العامل فجأة يكسر الـ Pipe فيرمي poll() استثناءً.
                # يجب ألا يُسقط ذلك الدفعة كلها؛ نعامله كعامل انتهى بلا نتيجة.
                has_result = False
                proc.join(5)
            if has_result:
                try:
                    outcomes[path] = FileOutcome(**conn.recv())
                except (EOFError, OSError):
                    outcomes[path] = FileOutcome(path.name, "crashed", error="انقطع الاتصال بالعامل",
                                                 duration_seconds=round(elapsed, 2))
                proc.join(5)
            elif not proc.is_alive():
                outcomes[path] = FileOutcome(path.name, "crashed", duration_seconds=round(elapsed, 2),
                                             error=f"انتهى الـ process دون نتيجة (exit code {proc.exitcode})")
            elif elapsed > timeout:
                proc.terminate()
                proc.join(5)
                if proc.is_alive():
                    proc.kill()
                outcomes[path] = FileOutcome(path.name, "timeout", duration_seconds=round(elapsed, 2),
                                             error=f"تجاوز الحد الزمني {timeout:.0f}s فأُوقف")
            else:
                continue
            conn.close()
            del running[path]
            o = outcomes[path]
            (log.info if o.status == "ok" else log.warning)("Batch: %s -> %s %s", path.name, o.status, o.error or "")
        time.sleep(0.05)
    return [outcomes[f] for f in files]


def find_apks(input_dir: Path, recursive: bool = False) -> list[Path]:
    pattern = "**/*.apk" if recursive else "*.apk"
    return sorted(p for p in Path(input_dir).glob(pattern) if p.is_file())


def write_batch_summary(outcomes: list[FileOutcome], results_dir: Path, stamp: str, schema_features) -> dict:
    results_dir.mkdir(parents=True, exist_ok=True)
    counts = {s: sum(o.status == s for o in outcomes) for s in STATUSES}
    doc = {
        "engine": {"name": config.ENGINE_NAME, "version": config.ENGINE_VERSION,
                   "schema_fingerprint": config.EXPECTED_SCHEMA_SHA256},
        "created_at": stamp, "total": len(outcomes), "counts": counts,
        "files": [{k: v for k, v in asdict(o).items() if k != "vector"} for o in outcomes],
    }
    paths = {"json": write_json(results_dir / f"batch_{stamp}.json", doc)}

    paths["csv"] = results_dir / f"batch_{stamp}.csv"
    cols = ["file", "status", "package", "sha256", "duration_seconds", "vector_built", "matched_features",
            "failed_modules", "error", "result_folder"]
    with paths["csv"].open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for o in outcomes:
            d = asdict(o)
            d["failed_modules"] = ";".join(o.failed_modules)
            w.writerow([d[c] for c in cols])

    paths["vectors_csv"] = results_dir / f"batch_{stamp}_vectors.csv"
    with paths["vectors_csv"].open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["file", "sha256", "package", *schema_features])
        for o in outcomes:
            if o.vector is not None:
                w.writerow([o.file, o.sha256, o.package, *o.vector])
    return {"counts": counts, "paths": paths, "document": doc}


def analyze_directory(input_dir: str | Path, results_dir: str | Path | None = None,
                      workers: int = config.BATCH_DEFAULT_WORKERS, timeout: float = config.BATCH_TIMEOUT_SECONDS,
                      recursive: bool = False, worker: Callable = analyze_worker,
                      log_dir: Path | None = None) -> dict:
    """يحلل كل ملفات .apk في مجلد. لا يتوقف عند فشل أي ملف."""
    from ..feature_extraction import load_feature_schema

    schema = load_feature_schema()  # تحقق مبكر في الـ process الرئيسي قبل تشغيل أي عامل
    results_dir = Path(results_dir or config.RESULTS_DIR)
    files = find_apks(Path(input_dir), recursive)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log.info("Batch started: %d files, workers=%d, timeout=%ss", len(files), workers, timeout)
    t0 = time.perf_counter()
    outcomes = _run_pool(files, results_dir, max(1, workers), timeout, worker, log_dir) if files else []
    summary = write_batch_summary(outcomes, results_dir, stamp, schema.features)
    summary["duration_seconds"] = round(time.perf_counter() - t0, 2)
    summary["outcomes"] = outcomes
    log.info("Batch completed: %s in %.1fs", summary["counts"], summary["duration_seconds"])
    return summary


def run_isolated(path: str | Path, results_dir: str | Path | None = None,
                 timeout: float = config.BATCH_TIMEOUT_SECONDS, worker: Callable = analyze_worker,
                 log_dir: Path | None = None) -> FileOutcome:
    """تحليل ملف واحد غير موثوق في process معزول بحد زمني صارم (مناسب لـ FastAPI)."""
    results_dir = Path(results_dir or config.RESULTS_DIR)
    return _run_pool([Path(path)], results_dir, 1, timeout, worker, log_dir)[0]
