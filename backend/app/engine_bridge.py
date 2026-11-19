"""
الجسر بين droidshield_engine و FastAPI.

مسار واحد لكل الطرق: المحرك (داخل الـ process أو معزولاً) يُنتج وثيقتين
    raw   = raw_analysis.json   (كل التحليل الخام)
    fvdoc = feature_vector.json (المتجه + البصمة + التحقق)
وهذا الملف يحوّلهما إلى:
    - متجه NumPy بترتيب الـ Schema (للنموذج)، بعد التحقق من البصمة
    - حقول الاستجابة التي تعرضها الواجهة (app_info, obfuscation, analysis)

لماذا التحليل المعزول افتراضياً؟ الملفات يرفعها مستخدمون مجهولون: ملف مصمَّم لإعلاق المحلل
أو لإسقاطه يُنهى بعد الحد الزمني في process منفصل، والخادم يبقى يعمل.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from droidshield_engine import config as engine_config
from droidshield_engine.exporters.json_exporter import RAW_FILE
from droidshield_engine.exporters.numpy_exporter import JSON_FILE

ISOLATED = os.getenv("DROIDSHIELD_ISOLATED", "1") != "0"
TIMEOUT = float(os.getenv("DROIDSHIELD_TIMEOUT", str(engine_config.BATCH_TIMEOUT_SECONDS)))


class AnalysisFailed(Exception):
    def __init__(self, status: int, message: str, code: str | None = None):
        self.status, self.message, self.code = status, message, code
        super().__init__(message)


@dataclass
class EngineOutput:
    raw: dict
    fvdoc: dict | None


def run_engine(apk_path: Path, engine, results_dir: Path) -> EngineOutput:
    """يحلل الملف ويعيد الوثيقتين، أو يرفع AnalysisFailed برمز HTTP مناسب."""
    if ISOLATED:
        from droidshield_engine.core.batch import run_isolated

        o = run_isolated(apk_path, results_dir, timeout=TIMEOUT)
        if o.status == "timeout":
            raise AnalysisFailed(504, f"تجاوز التحليل الحد الزمني ({TIMEOUT:.0f} ثانية)", "TIMEOUT")
        if o.status == "crashed":
            raise AnalysisFailed(500, "توقف المحلل بشكل غير متوقع أثناء تحليل الملف", "CRASHED")
        folder = results_dir / o.result_folder
        raw = json.loads((folder / RAW_FILE).read_text(encoding="utf-8"))
        fv_path = folder / JSON_FILE
        fvdoc = json.loads(fv_path.read_text(encoding="utf-8")) if fv_path.exists() else None
    else:
        from droidshield_engine.core.analysis_engine import result_to_dict

        result, _ = engine.analyze_and_export(apk_path, results_dir)
        doc = result_to_dict(result)
        raw, fvdoc = doc, doc["feature_vector"]

    if raw.get("load_error"):
        err = raw["load_error"]
        raise AnalysisFailed(422, f"تعذّر تحليل ملف APK: {err['message']}", err["code"])
    if fvdoc is None:
        raise AnalysisFailed(500, f"تعذّر بناء متجه الميزات: {raw.get('mapping_error')}", "MAPPING_FAILED")
    return EngineOutput(raw, fvdoc)


def vector_from_doc(fvdoc: dict, feature_names: list[str]) -> np.ndarray:
    """feature_vector.json -> مصفوفة بترتيب أعمدة النموذج (نرفض أي اختلاف في الأسماء)."""
    if list(fvdoc["vector"]) != list(feature_names):
        raise AnalysisFailed(500, "ترتيب ميزات المحرك لا يطابق النموذج", "SCHEMA_MISMATCH")
    return np.array(list(fvdoc["vector"].values()), dtype=np.float32)


def _data(raw: dict, module: str) -> dict:
    m = raw.get("modules", {}).get(module) or {}
    return m.get("data") or {} if m.get("status") == "ok" else {}


def obfuscation_from_raw(raw: dict) -> dict | None:
    """نفس مؤشرات الواجهة الأربعة، محسوبة من وحدتي dex و strings."""
    dex, strings = _data(raw, "dex"), _data(raw, "strings")
    if not dex and not strings:
        return None
    dex_sources = [v for k, v in strings.get("sources", {}).items() if k.endswith(".dex") and v["strings"]]
    total = sum(v["strings"] for v in dex_sources) or 1
    return {
        "string_entropy_mean": round(sum(v["entropy_mean"] * v["strings"] for v in dex_sources) / total, 4),
        "high_entropy_string_ratio": round(sum(v["high_entropy_ratio"] * v["strings"] for v in dex_sources) / total, 4),
        "single_char_class_ratio": dex.get("naming", {}).get("single_char_class_ratio", 0.0),
        "single_char_method_ratio": dex.get("naming", {}).get("single_char_method_ratio", 0.0),
    }


def app_info_from_raw(raw: dict, file_name: str | None) -> dict:
    meta, perms, net = _data(raw, "metadata"), _data(raw, "permissions"), _data(raw, "network")
    urls = [u["value"] for kind in ("https", "http") for u in net.get("urls", {}).get(kind, [])]
    return {
        "app_name": meta.get("app_name"),
        "package": meta.get("package"),
        "version": meta.get("version_name"),
        "version_code": meta.get("version_code"),
        "min_sdk": meta.get("min_sdk"),
        "target_sdk": meta.get("target_sdk"),
        "permissions": perms.get("requested_names", []),
        "urls": urls[:50],
        "file_name": file_name,
        "sha256": raw["apk"]["hashes"]["sha256"],
        "size_bytes": raw["apk"]["file_size"],
    }


def analysis_summary(raw: dict, fvdoc: dict) -> dict:
    """تفاصيل المحرك الإضافية (لا تدخل النموذج): للعرض والتقارير."""
    perms, comps, api = _data(raw, "permissions"), _data(raw, "components"), _data(raw, "api_calls")
    net, cert, native, strings = _data(raw, "network"), _data(raw, "certificate"), _data(raw, "native"), _data(raw, "strings")
    return {
        "engine_version": raw["engine"]["version"],
        "schema_fingerprint": fvdoc["schema_fingerprint"],
        "schema_validation": fvdoc["validation"],
        "modules": {n: m["status"] for n, m in raw.get("modules", {}).items()},
        "zip_warnings": raw["apk"].get("zip", {}).get("warnings", []),
        "permissions": {
            "counts": perms.get("counts"),
            "outside_model": fvdoc.get("unmapped_android_permissions", []),
            "custom": perms.get("custom", []),
        },
        "sensitive_api_categories": {k: v["call_sites"] for k, v in api.get("by_category", {}).items()},
        "exposed_components": comps.get("exposed_components", []),
        "cleartext": (net.get("cleartext") or {}).get("effective"),
        "hardcoded_servers": net.get("hardcoded_servers", [])[:20],
        "shell_commands": [s["value"] for s in strings.get("shell_commands", [])][:20],
        "native_abis": native.get("abis", []),
        "signing": {"schemes": cert.get("schemes"), "debug_signed": cert.get("debug_signed"),
                    "verified": (cert.get("verification") or {}).get("verified")},
    }
