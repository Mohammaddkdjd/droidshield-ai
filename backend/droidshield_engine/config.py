"""
الإعدادات المركزية لمحرك DroidShield AI.

كل ثابت يعتمد عليه أكثر من module يُعرَّف هنا مرة واحدة فقط، حتى لا تتباعد القيم بين الملفات.
"""
import os
from dataclasses import dataclass
from pathlib import Path

ENGINE_NAME = "DroidShield AI Static Analysis & Feature Extraction Engine"
ENGINE_VERSION = "1.0.0"
ENGINE_DIR = Path(__file__).resolve().parent
MB, GB = 1024**2, 1024**3

# مجلد النتائج: متغير البيئة أولاً، ثم القرص E: (القرص C: شبه ممتلئ على جهاز التطوير)، ثم داخل المحرك
RESULTS_DIR = Path(os.environ.get("DROIDSHIELD_RESULTS_DIR")
                   or ("E:/DroidShield_results" if Path("E:/").exists() else ENGINE_DIR / "results"))
LOG_DIR = Path(os.environ.get("DROIDSHIELD_LOG_DIR") or RESULTS_DIR / "_logs")

# Batch: كل APK في process مستقل. الحد الزمني صارم (قتل الـ process)، بخلاف الميزانيات
# التعاونية داخل الوحدات. عدد العمّال الافتراضي 1 لأن تحليل تطبيق كبير قد يستهلك ~1GB ذاكرة.
BATCH_TIMEOUT_SECONDS = 300
BATCH_DEFAULT_WORKERS = 1

# ----------------------------- Feature Schema ----------------------------- #
# الـ Dataset هي المصدر الوحيد للـ Schema (لا توجد قائمة مكتوبة يدوياً في أي مكان).
DATASET_PATH = ENGINE_DIR / "dataset" / "Final_Balanced_Three_Datasets.csv"

LABEL_COLUMN = "Label"          # Target Variable، ليس Feature
MALWARE, BENIGN = 1, 0           # ترميز Label المعتمد (للتوثيق والنموذج فقط، لا يدخل المحرك)

EXPECTED_TOTAL_COLUMNS = 111     # 110 Features + Label
EXPECTED_FEATURE_COUNT = 110

# بصمة SHA-256 لأسماء الـ 110 Feature بترتيبها (مفصولة بـ "\n").
# أي تغيير في اسم أو ترتيب أو عدد الأعمدة يغيّر البصمة، فيتوقف المحرك بخطأ واضح
# بدل أن يُنتج متجهاً بدلالة مختلفة عن التي تدرّب عليها النموذج.
# إذا تغيّرت الـ Dataset عن قصد (وأُعيد تدريب النموذج)، تُحدَّث هذه القيمة يدوياً.
EXPECTED_SCHEMA_SHA256 = "b0f737610fbe03c34602221aebb0d5dfd6c9cc61b9d3d0ea54252c3255929be6"

# أسماء Features هي أسماء Android permissions المختصرة: حروف كبيرة وأرقام و _ فقط.
FEATURE_NAME_PATTERN = r"^[A-Z][A-Z0-9_]*$"


# ------------------------------- APK Loading ------------------------------- #
@dataclass(frozen=True)
class LoaderLimits:
    """
    حدود الأمان عند تحميل APK غير موثوق. كل قيمة قابلة للتعديل (مثلاً في الاختبارات).

    لماذا حدود مطلقة للحجم بدل الاعتماد على نسبة الضغط وحدها؟
        نسبة الضغط العالية ليست دليلاً على Zip Bomb؛ ملف أصفار صغير في تطبيق سليم
        قد تصل نسبته إلى 1000. الحماية الحقيقية هي ألا نفك ضغط أي ملف بعد حد معين،
        مهما كانت الأحجام المكتوبة في الـ headers (يمكن تزويرها).
    """

    max_apk_size: int = 500 * MB            # أكبر APK نقبله (يُقرأ كاملاً في الذاكرة)
    max_entries: int = 100_000              # عدد الملفات داخل ZIP
    max_entry_size: int = 256 * MB          # أقصى حجم بعد فك الضغط لأي ملف نقرؤه فعلياً
    max_declared_total: int = 4 * GB        # مجموع الأحجام المعلنة في الـ Central Directory
    high_ratio_warning: float = 100.0       # نسبة ضغط تستحق التنبيه (ليست خطأً)
    high_ratio_min_size: int = 1 * MB       # لا ننبّه على الملفات الصغيرة مهما كانت نسبتها


DEFAULT_LIMITS = LoaderLimits()


# ------------------------------- DEX Analysis ------------------------------- #
@dataclass(frozen=True)
class DexLimits:
    """
    حدود تحليل الكود. تطبيق كبير قد يحوي 300 ألف method؛ حفظها كلها يجعل
    raw_analysis.json بعشرات الـ MB، وتحليلها بلا حد زمني قد يستغرق دقائق.
    عند بلوغ أي حد: نتوقف بأمان، نعيد ما جمعناه، ونسجل truncated=True (لا نُخفي النقص).
    """

    time_budget_seconds: float = 120.0     # لكل وحدة (dex_analyzer و api_analyzer كلٌّ على حدة)
    max_listed_classes: int = 20_000       # العدّ يشمل الكل؛ الحد على القوائم المحفوظة فقط
    # Phase 9: تطبيق حقيقي بـ 7,916 صنفاً خاصاً به أنتج 18MB بحدّ 50 ألفاً؛ 20/15 ألفاً
    # تكفي للمراجعة وتُبقي الملف بحجم معقول لـ FastAPI والواجهة (والنقص يُعلَّم truncated)
    max_listed_methods: int = 20_000
    max_listed_fields: int = 15_000
    max_listed_native: int = 5_000
    max_callers_per_api: int = 20          # مواضع الاستدعاء المحفوظة لكل API حساس


DEFAULT_DEX_LIMITS = DexLimits()


# ---------------------- Strings / Network / Resources / Native ---------------------- #
@dataclass(frozen=True)
class ContentLimits:
    time_budget_seconds: float = 60.0
    max_string_length: int = 8_192          # النص الأطول يُقتطع قبل الفحص (حماية من regex على نص ضخم)
    max_findings_per_category: int = 1_000  # قيم فريدة لكل فئة (urls, ips, ...)
    max_sources_per_finding: int = 10
    max_text_asset_size: int = 1 * MB       # ملفات نصية في assets/ و res/raw نفحصها
    max_text_assets_total: int = 20 * MB
    max_resource_strings_listed: int = 5_000
    max_native_lib_size: int = 64 * MB
    max_symbols_listed: int = 500
    max_files_listed: int = 500


DEFAULT_CONTENT_LIMITS = ContentLimits()
