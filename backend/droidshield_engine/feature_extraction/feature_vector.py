"""
FeatureVector: المتجه الذي يدخل نموذج التصنيف، مع كل ما يلزم للتحقق منه ومراجعته.

لماذا كائن وليس np.ndarray فقط؟
    المصفوفة وحدها لا تقول بأي Schema بُنيت. نحمل معها:
        feature_names       -> اسم كل عمود بنفس الترتيب (للمراجعة و SHAP لاحقاً)
        schema_fingerprint  -> بصمة الـ Schema؛ FastAPI يقارنها ببصمة النموذج قبل التنبؤ
        matched/unmapped    -> لماذا أخذ كل عمود قيمته، وما الذي لم يدخل المتجه

المصفوفة للقراءة فقط (writeable=False): لا يستطيع أي كود تعديل قيمة بعد البناء.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from .. import config
from .schema_loader import FeatureSchema

DTYPE = np.int8


class FeatureVectorError(ValueError):
    """المتجه لا يحقق شروط التوافق مع الـ Schema."""


@dataclass(frozen=True)
class FeatureVector:
    values: np.ndarray
    feature_names: tuple[str, ...]
    schema_fingerprint: str
    matched: tuple[str, ...]                 # الخصائص التي قيمتها 1
    unmapped_android: tuple[str, ...] = ()   # android.permission.X موجودة في التطبيق وليست في الـ Schema
    ignored_non_android: tuple[str, ...] = ()  # أذونات خارج namespace النظام (لا تُطابق أبداً)
    duplicate_inputs: tuple[str, ...] = ()
    validation: dict = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.feature_names)

    def as_dict(self) -> dict[str, int]:
        """{"RECORD_AUDIO": 0, ...} بنفس ترتيب أعمدة الـ Dataset."""
        return {name: int(v) for name, v in zip(self.feature_names, self.values)}

    def to_json(self) -> dict:
        return {
            "schema_fingerprint": self.schema_fingerprint,
            "length": len(self),
            "dtype": str(self.values.dtype),
            "ones": int(self.values.sum()),
            "vector": self.as_dict(),
            "matched": list(self.matched),
            "unmapped_android_permissions": list(self.unmapped_android),
            "ignored_non_android_permissions": list(self.ignored_non_android),
            "duplicate_inputs": list(self.duplicate_inputs),
            "validation": self.validation,
        }

    def validate(self, schema: FeatureSchema) -> dict:
        """
        كل شروط التوافق الإلزامية. يرفع FeatureVectorError عند أي مخالفة، ويعيد تقريراً عند النجاح.
        """
        v = self.values
        checks = {
            "shape": v.shape == (len(schema),),
            "dtype_int8": v.dtype == DTYPE,
            "binary": bool(np.isin(v, (0, 1)).all()),
            "length_110": len(schema) == config.EXPECTED_FEATURE_COUNT and v.shape == (config.EXPECTED_FEATURE_COUNT,),
            "names_match_schema_order": self.feature_names == schema.features,
            "label_excluded": config.LABEL_COLUMN not in self.feature_names,
            "fingerprint_matches": self.schema_fingerprint == schema.fingerprint == config.EXPECTED_SCHEMA_SHA256,
            "matched_consistent": set(self.matched) == {n for n, x in zip(self.feature_names, v) if x == 1},
            "read_only": not v.flags.writeable,
        }
        failed = [k for k, ok in checks.items() if not ok]
        if failed:
            raise FeatureVectorError(f"المتجه لا يطابق الـ Schema: {failed}")
        return {"passed": True, "checks": checks}
