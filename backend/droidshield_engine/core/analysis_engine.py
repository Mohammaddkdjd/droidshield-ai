"""
محرك التحليل: نقطة الدخول الموحّدة التي تربط كل الوحدات.

    APK ──► load_apk (فحص أمني) ──► 12 Analyzer (كلٌّ معزول بـ run_module)
                                        │
                                        └─► permissions.requested_names ──► FeatureMapper ──► FeatureVector
                                                                                        │
    AnalysisResult ◄────────────────────────────────────────────────────────────────────┘
          └─► exporters (raw_analysis.json, feature_vector.npy/.json, analysis_report.txt)

الاستخدام من FastAPI لاحقاً:
    engine = AnalysisEngine()            # مرة واحدة عند تشغيل الخادم (تحقق الـ Schema هنا)
    result = engine.analyze(path)        # داخل نفس الـ process (أسرع)
    # أو للملفات غير الموثوقة المرفوعة من مستخدمين:
    summary = run_isolated(path, results_dir, timeout=300)   # core/batch.py: process منفصل وحد زمني صارم

المحرك لا يصنّف التطبيق: result.prediction تبقى None حتى يملأها نموذج التصنيف.
"""
from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Sequence

from .. import config
from ..analyzers import (
    ApiAnalyzer, BaseAnalyzer, CertificateAnalyzer, ComponentAnalyzer, DexAnalyzer, HardwareAnalyzer,
    ManifestAnalyzer, MetadataAnalyzer, NativeAnalyzer, NetworkAnalyzer, PermissionAnalyzer, ResourcesAnalyzer,
    StringsAnalyzer,
)
from ..config import DEFAULT_LIMITS, LoaderLimits
from ..exporters import export_all
from ..exporters.json_exporter import build_raw_document
from ..feature_extraction import FeatureMapper, FeatureSchema, load_feature_schema
from .analysis_result import AnalysisResult, run_module
from .apk_loader import load_apk
from .errors import ApkLoadError

log = logging.getLogger(__name__)


def default_analyzers() -> list[BaseAnalyzer]:
    """الترتيب مقصود: permissions أولاً (المتجه يعتمد عليها)، والوحدات الثقيلة آخراً."""
    return [PermissionAnalyzer(), MetadataAnalyzer(), ManifestAnalyzer(), ComponentAnalyzer(), HardwareAnalyzer(),
            CertificateAnalyzer(), NativeAnalyzer(), ResourcesAnalyzer(), DexAnalyzer(), ApiAnalyzer(),
            StringsAnalyzer(), NetworkAnalyzer()]


class AnalysisEngine:
    def __init__(self, analyzers: Sequence[BaseAnalyzer] | None = None, schema: FeatureSchema | None = None,
                 loader_limits: LoaderLimits = DEFAULT_LIMITS):
        # الـ Schema تُحمَّل ويُتحقق منها هنا: إن تغيّرت الـ Dataset يفشل المحرك فوراً عند التشغيل
        # (SchemaValidationError) بدل أن يُنتج متجهات بدلالة خاطئة لاحقاً
        self.schema = schema or load_feature_schema()
        self.mapper = FeatureMapper(self.schema)
        self.analyzers = list(analyzers) if analyzers is not None else default_analyzers()
        names = [a.name for a in self.analyzers]
        if len(names) != len(set(names)):
            raise ValueError(f"أسماء وحدات مكررة: {names}")
        self.loader_limits = loader_limits
        log.info("Schema validation passed: %d features, fingerprint=%s", len(self.schema), self.schema.fingerprint[:16])

    def analyze(self, path: str | Path) -> AnalysisResult:
        """يحلل APK واحداً. لا يرفع استثناءً بسبب الملف: كل فشل يُسجَّل داخل AnalysisResult."""
        t0 = time.perf_counter()
        result = AnalysisResult(Path(path))
        try:
            result.loaded = load_apk(path, self.loader_limits)
        except ApkLoadError as e:
            result.load_error = {"code": e.code.value, "message": e.message}
        except Exception as e:  # خطأ غير متوقع في المكتبات: نسجّله ولا ننهار
            result.load_error = {"code": "UNEXPECTED", "message": f"{type(e).__name__}: {e}"}
        if result.load_error:
            log.error("Analysis failed: %s (%s)", Path(path).name, result.load_error["code"])
            result.duration_seconds = time.perf_counter() - t0
            return result

        for analyzer in self.analyzers:
            result.modules[analyzer.name] = run_module(analyzer, result.loaded)

        perms = result.modules.get(PermissionAnalyzer.name)
        if perms is None or perms.status != "ok":
            result.mapping_error = "permission_analyzer لم ينجح؛ لا يمكن بناء المتجه"
        else:
            try:
                result.feature_vector = self.mapper.map_analysis(perms.data)
            except Exception as e:
                result.mapping_error = f"{type(e).__name__}: {e}"
        if result.mapping_error:
            log.error("Feature mapping failed: %s: %s", Path(path).name, result.mapping_error)

        result.duration_seconds = time.perf_counter() - t0
        s = result.summary()
        log.info("Analysis completed: %s package=%s modules_ok=%d failed=%s vector=%s (%.1fs)",
                 Path(path).name, result.package, len(s["modules_ok"]), s["modules_failed"] or "none",
                 result.vector_ok, result.duration_seconds)
        return result

    def analyze_and_export(self, path: str | Path, results_dir: Path | None = None) -> tuple[AnalysisResult, dict]:
        result = self.analyze(path)
        paths = export_all(result, results_dir or config.RESULTS_DIR)
        result.release()  # تحرير الذاكرة الثقيلة بعد الحفظ (مهم في الخادم وفي الـ Batch)
        return result, paths


def result_to_dict(result: AnalysisResult) -> dict:
    """تمثيل JSON كامل لنتيجة واحدة (لاستجابة FastAPI): التحليل الخام + المتجه."""
    doc = build_raw_document(result)
    doc["feature_vector"] = result.feature_vector.to_json() if result.feature_vector else None
    doc["prediction"] = result.prediction
    return doc


_default_engine: AnalysisEngine | None = None


def analyze_apk(path: str | Path, export: bool = False, results_dir: Path | None = None) -> AnalysisResult:
    """واجهة مختصرة: محرك افتراضي واحد يُعاد استخدامه (الـ Schema تُقرأ مرة واحدة)."""
    global _default_engine
    if _default_engine is None:
        _default_engine = AnalysisEngine()
    if export:
        return _default_engine.analyze_and_export(path, results_dir)[0]
    return _default_engine.analyze(path)
