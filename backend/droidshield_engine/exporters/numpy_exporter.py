"""
feature_vector.npy و feature_vector.json: مدخل نموذج التصنيف (المرحلة الثانية).

feature_vector.npy
    مصفوفة NumPy أحادية البعد (110,) من نوع int8، بترتيب أعمدة الـ Dataset.
    تُحفظ بـ allow_pickle=False: ملف .npy عادي يمكن أن يحوي كائنات Python تُنفَّذ عند
    القراءة؛ منع pickle يجعله بيانات أرقام فقط، آمنة للقراءة.
    بعد الحفظ نعيد قراءته ونقارنه بالأصل (لا نفترض أن الكتابة نجحت).

feature_vector.json
    نفس المتجه بصيغة {اسم الخاصية: قيمة} للمراجعة البشرية، مع البصمة ونتائج التحقق.
"""
from __future__ import annotations

import io
from pathlib import Path

import numpy as np

from .common import atomic_write_bytes, write_json

NPY_FILE = "feature_vector.npy"
JSON_FILE = "feature_vector.json"


class ExportVerificationError(RuntimeError):
    pass


def export_vector(fv, folder: Path) -> tuple[Path, Path]:
    buf = io.BytesIO()
    np.save(buf, np.ascontiguousarray(fv.values), allow_pickle=False)
    npy = atomic_write_bytes(folder / NPY_FILE, buf.getvalue())

    loaded = np.load(npy, allow_pickle=False)
    if loaded.shape != fv.values.shape or loaded.dtype != fv.values.dtype or not np.array_equal(loaded, fv.values):
        raise ExportVerificationError("feature_vector.npy لا يطابق المتجه بعد إعادة القراءة")

    doc = {"feature_names": list(fv.feature_names), **fv.to_json()}
    return npy, write_json(folder / JSON_FILE, doc)
