"""
تحميل Feature Schema الرسمية من الـ Dataset نفسها.

لماذا من الـ CSV وليس من قائمة مكتوبة يدوياً؟
    القائمة اليدوية نسخة ثانية من الحقيقة، وقد تختلف عن الـ Dataset بحرف أو بترتيب
    دون أن يلاحظ أحد. النموذج تعلّم أن العمود رقم i يعني إذناً معيناً، فأي إزاحة
    تجعل كل تنبؤاته بلا معنى مع أنها ستبدو طبيعية.

كيف نقرأ الـ header؟
    نقرأ أول صف فقط كبيانات خام (header=None, nrows=1, dtype=str).
    لا نستخدم pd.read_csv(nrows=0).columns لأن Pandas يعيد تسمية الأعمدة المكررة
    تلقائياً (SEND_SMS, SEND_SMS.1)، فيُخفي التكرار عن schema_validator.
"""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import pandas as pd

from .. import config
from .schema_validator import schema_fingerprint, validate_columns


@dataclass(frozen=True)
class FeatureSchema:
    """
    الـ Schema المعتمدة: أسماء الـ 110 Feature بترتيب أعمدة الـ Dataset.

    frozen=True و tuple: لا يمكن تعديل الـ Schema بعد تحميلها، لا بالخطأ ولا عمداً.
    """

    features: tuple[str, ...]
    label: str
    source: Path
    fingerprint: str

    def __len__(self) -> int:
        return len(self.features)

    def __iter__(self) -> Iterator[str]:
        return iter(self.features)

    def __contains__(self, name: object) -> bool:
        return name in self._index

    def index_of(self, name: str) -> int:
        """موضع الخاصية في المتجه. KeyError إن لم تكن ضمن الـ Schema."""
        return self._index[name]

    @property
    def _index(self) -> dict[str, int]:
        # يُحسب مرة واحدة ويُخزَّن (الـ dataclass مجمّد، لذلك نكتب عبر object.__setattr__)
        idx = self.__dict__.get("_idx")
        if idx is None:
            idx = {n: i for i, n in enumerate(self.features)}
            object.__setattr__(self, "_idx", idx)
        return idx


def read_dataset_header(path: Path) -> list[str]:
    """يعيد أسماء أعمدة الـ CSV كما هي حرفياً (دون إعادة تسمية المكرر)."""
    if not path.is_file():
        raise FileNotFoundError(f"ملف الـ Dataset غير موجود: {path}")
    header = pd.read_csv(path, header=None, nrows=1, dtype=str, keep_default_na=False)
    if header.empty:
        raise ValueError(f"ملف الـ Dataset فارغ: {path}")
    return header.iloc[0].tolist()


@lru_cache(maxsize=4)
def load_feature_schema(path: Path = config.DATASET_PATH) -> FeatureSchema:
    """
    يقرأ الـ Dataset ويتحقق منها ويعيد FeatureSchema.

    lru_cache: الـ Schema تُقرأ من القرص مرة واحدة لكل مسار، ثم يعاد نفس الكائن
    (مهم لاحقاً في FastAPI و Batch حيث يُبنى آلاف المتجهات).

    Raises:
        FileNotFoundError / ValueError: الملف غير موجود أو فارغ.
        SchemaValidationError: الأعمدة لا تطابق الـ Schema المعتمدة.
    """
    path = Path(path).resolve()
    features = validate_columns(read_dataset_header(path))
    return FeatureSchema(
        features=tuple(features),
        label=config.LABEL_COLUMN,
        source=path,
        fingerprint=schema_fingerprint(features),
    )
