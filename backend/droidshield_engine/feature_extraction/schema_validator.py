"""
التحقق من سلامة أعمدة الـ Dataset قبل اعتمادها Feature Schema.

لماذا وحدة منفصلة عن schema_loader؟
    القراءة (I/O) شيء والتحقق (قواعد) شيء آخر. فصلهما يسمح باختبار كل قاعدة
    على قائمة أعمدة مصطنعة دون الحاجة إلى ملفات CSV حقيقية.

مبدأ العمل: نجمع *كل* المشاكل ثم نرفع خطأً واحداً يسردها، بدل التوقف عند أول مشكلة،
حتى يرى المستخدم الصورة كاملة من تشغيل واحد.
"""
from __future__ import annotations

import hashlib
import re
from collections import Counter
from collections.abc import Sequence

from .. import config


class SchemaValidationError(ValueError):
    """تُرفع عندما لا تطابق أعمدة الـ Dataset الـ Schema المعتمدة."""

    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__("Feature Schema غير صالحة:\n  - " + "\n  - ".join(problems))


def schema_fingerprint(features: Sequence[str]) -> str:
    """SHA-256 لأسماء الخصائص بترتيبها. الترتيب جزء من البصمة عمداً."""
    return hashlib.sha256("\n".join(features).encode("utf-8")).hexdigest()


def validate_columns(
    columns: Sequence[str],
    label: str = config.LABEL_COLUMN,
    expected_total: int = config.EXPECTED_TOTAL_COLUMNS,
    expected_features: int = config.EXPECTED_FEATURE_COUNT,
    expected_fingerprint: str | None = config.EXPECTED_SCHEMA_SHA256,
) -> list[str]:
    """
    يتحقق من أعمدة الـ Dataset الخام (بما فيها Label) ويعيد قائمة الـ Features بترتيبها الأصلي.

    القواعد:
        1) عدد الأعمدة الكلي = expected_total
        2) لا أسماء فارغة ولا مسافات زائدة في بداية/نهاية الاسم
        3) لا أسماء مكررة
        4) Label موجود مرة واحدة بالضبط
        5) عدد الـ Features بعد استبعاد Label = expected_features
        6) كل اسم Feature يطابق نمط أسماء الأذونات (FEATURE_NAME_PATTERN)
        7) بصمة الأسماء بترتيبها = expected_fingerprint (إن أُعطيت)

    Raises:
        SchemaValidationError: بقائمة كل المشاكل المكتشفة.
    """
    problems: list[str] = []
    columns = list(columns)

    if len(columns) != expected_total:
        problems.append(f"عدد الأعمدة {len(columns)} والمتوقع {expected_total}")

    blank = [i for i, c in enumerate(columns) if not c.strip()]
    if blank:
        problems.append(f"أعمدة بلا اسم في المواضع: {blank}")
    padded = [c for c in columns if c.strip() and c != c.strip()]
    if padded:
        problems.append(f"أسماء فيها مسافات زائدة: {padded}")

    dups = sorted(n for n, k in Counter(columns).items() if k > 1)
    if dups:
        problems.append(f"أعمدة مكررة: {dups}")

    label_count = columns.count(label)
    if label_count != 1:
        problems.append(f"العمود '{label}' موجود {label_count} مرة، والمطلوب مرة واحدة")

    # استبعاد Label بالاسم وليس بالموضع: Label في هذه الـ Dataset هو العمود رقم 14 وليس الأخير.
    features = [c for c in columns if c != label]
    if len(features) != expected_features:
        problems.append(f"عدد الـ Features {len(features)} والمتوقع {expected_features}")

    pattern = re.compile(config.FEATURE_NAME_PATTERN)
    invalid = [c for c in features if c.strip() and not pattern.match(c)]
    if invalid:
        problems.append(f"أسماء لا تطابق نمط أسماء الأذونات: {invalid}")

    # البصمة تُفحص أخيراً، وفقط إن لم توجد مشاكل بنيوية (وإلا فاختلافها نتيجة متوقعة لا معلومة جديدة)
    if not problems and expected_fingerprint is not None:
        actual = schema_fingerprint(features)
        if actual != expected_fingerprint:
            problems.append(
                "تغيّرت أسماء أو ترتيب الـ Features عن الـ Schema المعتمدة "
                f"(البصمة {actual[:16]}… والمتوقعة {expected_fingerprint[:16]}…). "
                "إن كان التغيير مقصوداً وأُعيد تدريب النموذج فحدّث EXPECTED_SCHEMA_SHA256 في config.py"
            )

    if problems:
        raise SchemaValidationError(problems)
    return features
