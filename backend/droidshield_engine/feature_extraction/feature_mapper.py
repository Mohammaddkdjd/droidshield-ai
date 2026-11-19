"""
Schema-Based Feature Mapping: من نتائج التحليل الخام إلى متجه من 110 قيمة.

القاعدة الوحيدة للمطابقة:
    الخاصية F = 1  إذا وفقط إذا طلب التطبيق الإذن "android.permission.F" حرفياً
                    (عبر <uses-permission> أو <uses-permission-sdk-23>)
    وإلا 0.

ما لا يدخل المتجه إطلاقاً (بالتصميم):
    - أذونات مخصصة بنفس الاسم الأخير: com.evil.app.SEND_SMS  ≠  SEND_SMS
    - أذونات يعرّفها التطبيق (<permission>) أو الضمنية (implied): ليست طلباً
    - أي معلومة أخرى من Raw Analysis (APIs, strings, ...): المُطابق لا يستقبلها أصلاً
    - مطابقة تقريبية (Fuzzy): الأسماء الرسمية حساسة لحالة الأحرف وتُطابق حرفياً فقط
    - Label: ليس ضمن الـ Schema (يُستبعد في schema_loader)

لماذا يستقبل map_analysis قاموس الأذونات ويأخذ منه "requested_names" فقط؟
    حتى يكون مستحيلاً بنيوياً أن تتسرب خاصية إضافية من Raw Analysis إلى النموذج.
"""
from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Iterable

import numpy as np

from .feature_vector import DTYPE, FeatureVector
from .schema_loader import FeatureSchema, load_feature_schema

log = logging.getLogger(__name__)
ANDROID_PREFIX = "android.permission."


class FeatureMapper:
    def __init__(self, schema: FeatureSchema | None = None):
        self.schema = schema or load_feature_schema()

    @property
    def feature_names(self) -> tuple[str, ...]:
        return self.schema.features

    def map_permissions(self, requested: Iterable[str]) -> FeatureVector:
        """قائمة أسماء أذونات كاملة (كما في الـ Manifest) -> FeatureVector مُتحقَّق منه."""
        requested = [p for p in requested if isinstance(p, str)]
        counts = Counter(requested)

        values = np.zeros(len(self.schema), dtype=DTYPE)
        unmapped, ignored = set(), set()
        for perm in counts:
            if not perm.startswith(ANDROID_PREFIX):
                ignored.add(perm)
                continue
            short = perm[len(ANDROID_PREFIX):]
            if short in self.schema:
                values[self.schema.index_of(short)] = 1
            else:
                unmapped.add(perm)
        values.flags.writeable = False

        vector = FeatureVector(
            values=values,
            feature_names=self.schema.features,
            schema_fingerprint=self.schema.fingerprint,
            matched=tuple(n for n, v in zip(self.schema.features, values) if v),
            unmapped_android=tuple(sorted(unmapped)),
            ignored_non_android=tuple(sorted(ignored)),
            duplicate_inputs=tuple(sorted(p for p, k in counts.items() if k > 1)),
        )
        report = vector.validate(self.schema)
        object.__setattr__(vector, "validation", report)
        if unmapped:
            log.info("Unknown features (android permissions not in schema): %d", len(unmapped))
        return vector

    def map_analysis(self, permissions_result: dict) -> FeatureVector:
        """يستقبل ناتج PermissionAnalyzer ويأخذ منه requested_names فقط."""
        if "requested_names" not in permissions_result:
            raise KeyError("نتيجة permission_analyzer لا تحوي requested_names")
        return self.map_permissions(permissions_result["requested_names"])

    def empty_vector(self) -> FeatureVector:
        """متجه أصفار صالح (مثلاً لتطبيق لا يطلب أي إذن)."""
        return self.map_permissions([])
