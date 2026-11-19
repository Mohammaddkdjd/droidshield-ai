"""
raw_analysis.json: كل ما استخرجه التحليل الشامل (المرحلة الأولى).

هذا الملف للمراجعة والتطوير المستقبلي فقط، ولا يقرؤه النموذج الحالي إطلاقاً.
البنية:
    engine   -> اسم المحرك وإصداره، بصمة الـ Schema، وقت التحليل
    apk      -> اسم الملف، الحجم، البصمات، فحص ZIP وتحذيراته
    status   -> ملخص: ما نجح وما فشل
    modules  -> لكل وحدة: status, duration, error, data
"""
from __future__ import annotations

from pathlib import Path

from .. import config
from .common import write_json

RAW_FILE = "raw_analysis.json"


def build_raw_document(result) -> dict:
    fv = result.feature_vector
    return {
        "engine": {
            "name": config.ENGINE_NAME,
            "version": config.ENGINE_VERSION,
            "schema_fingerprint": config.EXPECTED_SCHEMA_SHA256,
            "started_at": result.started_at,
            "duration_seconds": round(result.duration_seconds, 3),
        },
        "apk": result.loaded.to_dict() if result.loaded else {"file_name": Path(result.apk_path).name},
        "load_error": result.load_error,
        "status": result.summary(),
        "feature_mapping": None if fv is None else {
            "matched_count": len(fv.matched),
            "unmapped_android_permissions": list(fv.unmapped_android),
            "note": "المتجه الكامل في feature_vector.npy / feature_vector.json",
        },
        "mapping_error": result.mapping_error,
        "modules": {name: m.to_dict() for name, m in result.modules.items()},
    }


def export_raw(result, folder: Path) -> Path:
    return write_json(folder / RAW_FILE, build_raw_document(result))
