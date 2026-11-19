"""
إعداد السجلات (logging) للمحرك.

    - ملف يومي: <LOG_DIR>/droidshield_YYYYMMDD.log  (كل الرسائل من INFO فما فوق)
    - الشاشة: WARNING فما فوق فقط (حتى لا تغرق مخرجات CLI)

لا نسجّل محتوى الملفات ولا المسارات الكاملة: اسم الملف وبصمته المختصرة تكفي للتتبع.
Androguard يستخدم loguru ويُطفأ في apk_loader.
"""
from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path

from .. import config

FORMAT = "%(asctime)s %(levelname)-7s [%(process)d] %(name)s: %(message)s"
_configured: set[str] = set()


def configure_logging(log_dir: Path | None = None, console_level: int = logging.WARNING) -> Path:
    log_dir = Path(log_dir or config.LOG_DIR)
    log_dir.mkdir(parents=True, exist_ok=True)
    path = log_dir / f"droidshield_{datetime.now():%Y%m%d}.log"
    root = logging.getLogger("droidshield_engine")
    if str(path) in _configured:
        return path
    root.setLevel(logging.INFO)
    fh = logging.FileHandler(path, encoding="utf-8")
    fh.setFormatter(logging.Formatter(FORMAT))
    fh.setLevel(logging.INFO)
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    ch.setLevel(console_level)
    root.addHandler(fh)
    root.addHandler(ch)
    root.propagate = False
    _configured.add(str(path))
    return path
