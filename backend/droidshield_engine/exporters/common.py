"""
أدوات مشتركة للتصدير: اسم مجلد آمن لكل تطبيق، كتابة ذرّية، وتحويل آمن إلى JSON.

لماذا لا نستخدم اسم التطبيق (app_name) مجلداً كما هو؟
    الاسم يأتي من ملف غير موثوق: قد يحوي "/" أو ".." (Path Traversal) أو رموزاً لا يقبلها
    Windows، وتطبيقان قد يحملان نفس الاسم. نستخدم:
        <package>_<versionCode>_<أول 12 حرفاً من SHA-256>
    بعد تنقيته من أي رمز غير [A-Za-z0-9._-]، ثم نتأكد أن المسار الناتج داخل مجلد النتائج.

الكتابة الذرّية (atomic): نكتب إلى ملف مؤقت ثم نستبدل به الملف النهائي بخطوة واحدة،
فلا يبقى ملف نصف مكتوب إذا توقف البرنامج أثناء الكتابة.
"""
from __future__ import annotations

import json
import os
import re
from datetime import date, datetime
from enum import Enum
from pathlib import Path

import numpy as np

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


def safe_name(text: str | None, fallback: str = "unknown", max_len: int = 80) -> str:
    cleaned = _UNSAFE.sub("_", text or "").strip("._")
    return (cleaned or fallback)[:max_len]


def result_folder_name(result) -> str:
    sha = result.loaded.hashes["sha256"][:12] if result.loaded else None
    if result.loaded:
        version = result.loaded.apk.get_androidversion_code()
        base = f"{safe_name(result.package)}_{safe_name(version, 'v')}"
    else:
        base = f"FAILED_{safe_name(Path(result.apk_path).stem)}"
    return f"{base}_{sha}" if sha else base


def ensure_inside(root: Path, child: Path) -> Path:
    root, child = root.resolve(), child.resolve()
    if root != child and root not in child.parents:
        raise ValueError(f"مسار خارج مجلد النتائج: {child}")
    return child


def json_default(o):
    """يحوّل الأنواع التي لا يعرفها json (numpy, set, Path, bytes, Enum, datetime)."""
    if isinstance(o, np.integer):
        return int(o)
    if isinstance(o, np.floating):
        return float(o)
    if isinstance(o, np.ndarray):
        return o.tolist()
    if isinstance(o, (set, frozenset, tuple)):
        return sorted(o) if all(isinstance(x, str) for x in o) else list(o)
    if isinstance(o, Path):
        return o.name  # اسم الملف فقط: لا نسرّب مسارات جهاز المحلل
    if isinstance(o, bytes):
        return o.hex()
    if isinstance(o, Enum):
        return o.value
    if isinstance(o, (datetime, date)):
        return o.isoformat()
    raise TypeError(f"نوع غير قابل للتحويل إلى JSON: {type(o).__name__}")


def atomic_write_bytes(path: Path, data: bytes) -> Path:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)
    return path


def atomic_write_text(path: Path, text: str) -> Path:
    return atomic_write_bytes(path, text.encode("utf-8"))


def write_json(path: Path, obj, indent: int | None = 2) -> Path:
    return atomic_write_text(path, json.dumps(obj, ensure_ascii=False, indent=indent, default=json_default))
