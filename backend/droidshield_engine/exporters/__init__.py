"""
حفظ نتائج كل APK في مجلد مستقل:

    <results>/<package>_<versionCode>_<sha256[:12]>/
        raw_analysis.json     -> كل المعلومات المستخرجة (لا تدخل النموذج)
        feature_vector.npy    -> 110 قيمة int8 بترتيب الـ Dataset (مدخل النموذج)
        feature_vector.json   -> نفس المتجه بالأسماء للمراجعة
        analysis_report.txt   -> تقرير مختصر
"""
from __future__ import annotations

import logging
from pathlib import Path

from .. import config
from .common import ensure_inside, result_folder_name
from .json_exporter import export_raw
from .numpy_exporter import export_vector
from .report_exporter import export_report

log = logging.getLogger(__name__)


def export_all(result, results_dir: Path | None = None) -> dict[str, Path]:
    root = Path(results_dir or config.RESULTS_DIR)
    root.mkdir(parents=True, exist_ok=True)
    folder = ensure_inside(root, root / result_folder_name(result))
    folder.mkdir(exist_ok=True)

    paths = {"folder": folder, "raw_analysis": export_raw(result, folder)}
    if result.feature_vector is not None:
        paths["feature_vector_npy"], paths["feature_vector_json"] = export_vector(result.feature_vector, folder)
    else:  # لا نترك متجهاً قديماً من تحليل سابق لنفس الملف
        for stale in ("feature_vector.npy", "feature_vector.json"):
            (folder / stale).unlink(missing_ok=True)
    paths["report"] = export_report(result, folder)
    log.info("Results exported: %s", folder.name)
    return paths


__all__ = ["export_all"]
