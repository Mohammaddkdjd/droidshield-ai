"""
نموذج البيانات لنتيجة تحليل APK واحد: كل ما تنتجه المرحلتان، في كائن واحد.

    AnalysisResult
    ├── load / load_error      -> نجح التحميل أم لا (ولماذا)
    ├── modules: {name: ModuleResult}  -> لكل Analyzer: status + data + error + duration
    ├── feature_vector         -> المتجه (أو None إن تعذّر بناؤه)
    └── prediction             -> None دائماً داخل المحرك؛ يملؤه النموذج لاحقاً (FastAPI)

run_module() هو المكان الوحيد الذي يُشغَّل فيه Analyzer: يلتقط أي استثناء ويحوّله إلى
ModuleResult(status="failed")، فلا يؤدي فشل وحدة إلى فقدان نتائج الوحدات الأخرى.
"""
from __future__ import annotations

import logging
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from ..analyzers.base import BaseAnalyzer
    from ..feature_extraction.feature_vector import FeatureVector
    from .apk_loader import LoadedApk

log = logging.getLogger(__name__)
Status = Literal["ok", "failed", "skipped"]


@dataclass
class ModuleResult:
    name: str
    status: Status
    data: dict | None = None
    error: str | None = None
    duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {"status": self.status, "duration_seconds": round(self.duration_seconds, 3),
                "error": self.error, "data": self.data}


def run_module(analyzer: BaseAnalyzer, apk: LoadedApk) -> ModuleResult:
    t0 = time.perf_counter()
    try:
        data = analyzer.analyze(apk)
        return ModuleResult(analyzer.name, "ok", data, None, time.perf_counter() - t0)
    except Exception as e:
        # نسجّل نوع الخطأ ورسالته وآخر سطر من الـ traceback فقط (لا بيانات حساسة ولا مسارات كاملة)
        where = traceback.extract_tb(e.__traceback__)[-1]
        error = f"{type(e).__name__}: {e} ({Path(where.filename).name}:{where.lineno})"
        log.error("Module error: %s failed: %s", analyzer.name, error)
        return ModuleResult(analyzer.name, "failed", None, error, time.perf_counter() - t0)


@dataclass
class AnalysisResult:
    apk_path: Path
    loaded: LoadedApk | None = None
    load_error: dict | None = None
    modules: dict[str, ModuleResult] = field(default_factory=dict)
    feature_vector: FeatureVector | None = None
    mapping_error: str | None = None
    prediction: dict | None = None
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))
    duration_seconds: float = 0.0

    @property
    def loaded_ok(self) -> bool:
        return self.loaded is not None

    @property
    def vector_ok(self) -> bool:
        return self.feature_vector is not None

    def module_data(self, name: str) -> dict:
        m = self.modules.get(name)
        return m.data if m and m.status == "ok" and m.data else {}

    @property
    def package(self) -> str | None:
        return self.loaded.apk.get_package() if self.loaded else None

    def release(self) -> None:
        """
        يحرر الأجزاء الثقيلة من الذاكرة بعد التصدير: بايتات الـ APK، ملفات DEX المحلّلة،
        ومجمّع النصوص. تبقى نتائج الوحدات والمتجه والبصمات (وكل ما يحتاجه التقرير).
        """
        if self.loaded is not None:
            self.loaded.data = b""
            self.loaded.__dict__.pop("dex", None)      # cached_property
            self.loaded.__dict__.pop("strings", None)

    @property
    def app_name(self) -> str | None:
        return self.module_data("metadata").get("app_name") or self.module_data("manifest").get("app_name")

    def summary(self) -> dict:
        return {
            "loaded": self.loaded_ok,
            "vector_built": self.vector_ok,
            "modules_ok": [n for n, m in self.modules.items() if m.status == "ok"],
            "modules_failed": [n for n, m in self.modules.items() if m.status == "failed"],
            "modules_skipped": [n for n, m in self.modules.items() if m.status == "skipped"],
        }
