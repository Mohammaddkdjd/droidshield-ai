"""
DroidShield AI — Static Analysis & Feature Extraction Engine.

مرحلتان منفصلتان:
    1) Full Static Analysis         -> raw_analysis.json (كل ما يمكن استخراجه)
    2) Schema-Based Feature Mapping -> feature_vector.npy (110 قيمة بترتيب الـ Dataset فقط)

الواجهة العامة (لـ FastAPI وغيره):
    from droidshield_engine import AnalysisEngine, analyze_apk, run_isolated, analyze_directory
"""
from .config import ENGINE_NAME, ENGINE_VERSION

__all__ = ["AnalysisEngine", "analyze_apk", "result_to_dict", "run_isolated", "analyze_directory",
           "ENGINE_NAME", "ENGINE_VERSION"]


def __getattr__(name):
    # استيراد كسول: "import droidshield_engine" لا يحمّل Androguard إلا عند الحاجة
    if name in ("AnalysisEngine", "analyze_apk", "result_to_dict"):
        from .core import analysis_engine
        return getattr(analysis_engine, name)
    if name in ("run_isolated", "analyze_directory"):
        from .core import batch
        return getattr(batch, name)
    raise AttributeError(name)
