"""
واجهة FastAPI لفحص ملفات APK.

التشغيل (من داخل مجلد backend):
    uvicorn app.main:app --reload --port 8000

نقاط النهاية:
    GET  /health              حالة الخدمة
    GET  /model/info          معلومات النموذج ومقاييسه
    POST /predict             رفع ملف APK (multipart, field = file) -> droidshield_engine ثم النموذج
    POST /predict/features    إرسال الميزات مباشرة JSON: {"features": {"SEND_SMS": 1, ...}}
"""
import hashlib
import os
import tempfile
import time
from collections import OrderedDict
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from typing import Annotated

from pydantic import BaseModel, Field

from droidshield_engine import AnalysisEngine
from droidshield_engine import config as engine_config
from ml.explainer import MalwareExplainer, SchemaMismatchError

from .engine_bridge import (AnalysisFailed, analysis_summary, app_info_from_raw, obfuscation_from_raw, run_engine,
                            vector_from_doc)

RESULTS_DIR = Path(os.getenv("DROIDSHIELD_RESULTS_DIR") or engine_config.RESULTS_DIR)
UPLOAD_TMP_DIR = os.getenv("UPLOAD_TMP_DIR") or None   # None = مجلد النظام المؤقت
MAX_APK_BYTES = int(os.getenv("MAX_APK_MB", "100")) * 1024 * 1024
CACHE_SIZE = 128
state: dict = {}


class LRUCache(OrderedDict):
    def get_item(self, key):
        if key in self:
            self.move_to_end(key)
            return self[key]
        return None

    def put(self, key, value):
        self[key] = value
        self.move_to_end(key)
        while len(self) > CACHE_SIZE:
            self.popitem(last=False)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    explainer = MalwareExplainer()
    engine = AnalysisEngine()   # يتحقق من الـ Schema عند التشغيل
    # لا نبدأ الخدمة إطلاقاً إن كان النموذج مدرَّباً على Schema مختلفة عن المحرك
    if explainer.schema_fingerprint != engine.schema.fingerprint:
        raise RuntimeError("بصمة Schema النموذج لا تطابق المحرك؛ أعد تدريب النموذج (ml/train_droidshield.py)")
    if explainer.feature_names != list(engine.schema.features):
        raise RuntimeError("ترتيب ميزات النموذج لا يطابق المحرك")
    state.update(explainer=explainer, engine=engine, cache=LRUCache())
    yield
    state.clear()


app = FastAPI(title="DroidShield AI", version=engine_config.ENGINE_VERSION, lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:5173").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


class FeaturesRequest(BaseModel):
    # الميزات ثنائية (الإذن مطلوب أو لا): أي قيمة غير 0/1 تُرفض بـ 422 بدل تنبؤ بلا معنى
    features: dict[str, Annotated[int, Field(ge=0, le=1)]] = Field(
        ..., examples=[{"SEND_SMS": 1, "READ_PHONE_STATE": 1}])
    explain: bool = True


@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": "explainer" in state}


@app.get("/model/info")
def model_info():
    exp: MalwareExplainer = state["explainer"]
    m = exp.metrics
    return {
        "model": "CalibratedClassifierCV(SVC(kernel='rbf'), method='sigmoid')",
        "dataset": exp.card.get("dataset", "unknown"),
        "schema_fingerprint": exp.schema_fingerprint,
        "engine": engine_config.ENGINE_NAME,
        "engine_version": engine_config.ENGINE_VERSION,
        "accuracy": m.get("accuracy"),
        "false_positive_rate": m.get("false_positive_rate"),
        "false_negative_rate": m.get("false_negative_rate"),
        "n_features": len(exp.feature_names),
        "threshold": exp.threshold,
        "best_params": m.get("best_params"),
        "f1": m.get("f1_malware", m.get("f1")),
        "roc_auc": m.get("roc_auc"),
        "confusion_matrix": m.get("confusion_matrix"),
    }


@app.post("/predict/features")
def predict_features(req: FeaturesRequest):
    exp: MalwareExplainer = state["explainer"]
    t0 = time.perf_counter()
    vec, unknown = exp.vector_from_dict(req.features)
    result = exp.predict(vec, explain=req.explain)
    result.update(app_info=None, obfuscation=None, unknown_features=unknown,
                  elapsed_ms=round((time.perf_counter() - t0) * 1000))
    return result


@app.post("/predict")
def predict_apk(file: UploadFile = File(...)):
    # دالة متزامنة (def) -> FastAPI يشغّلها في threadpool فلا تحجب الخادم أثناء التحليل
    exp: MalwareExplainer = state["explainer"]
    t0 = time.perf_counter()

    data = file.file.read(MAX_APK_BYTES + 1)
    if len(data) > MAX_APK_BYTES:
        raise HTTPException(413, f"حجم الملف يتجاوز {MAX_APK_BYTES // (1024 * 1024)} MB")
    if not data.startswith(b"PK"):
        raise HTTPException(400, "الملف ليس APK صالحاً (ليس أرشيف ZIP)")

    sha256 = hashlib.sha256(data).hexdigest()
    cached = state["cache"].get_item(sha256)
    if cached:
        return {**cached, "cached": True, "elapsed_ms": round((time.perf_counter() - t0) * 1000)}

    # اسم ثابت داخل مجلد مؤقت خاص بالطلب: اسم الملف الذي أرسله المستخدم لا يُستخدم كمسار أبداً
    with tempfile.TemporaryDirectory(dir=UPLOAD_TMP_DIR) as tmp:
        path = Path(tmp) / f"{sha256[:16]}.apk"
        path.write_bytes(data)
        try:
            out = run_engine(path, state["engine"], RESULTS_DIR)
        except AnalysisFailed as e:
            raise HTTPException(e.status, e.message, headers={"X-Error-Code": e.code or ""}) from e
    # المجلد المؤقت حُذف هنا: لا نحتفظ بالملف المرفوع أبداً (تبقى نتائج التحليل فقط)

    try:
        vector = vector_from_doc(out.fvdoc, exp.feature_names)
        result = exp.predict(vector, fingerprint=out.fvdoc["schema_fingerprint"])
    except (AnalysisFailed, SchemaMismatchError) as e:
        raise HTTPException(500, str(e)) from e
    result.update(
        app_info=app_info_from_raw(out.raw, file.filename),
        obfuscation=obfuscation_from_raw(out.raw),
        analysis=analysis_summary(out.raw, out.fvdoc),
        unknown_features=[],
        cached=False,
    )
    state["cache"].put(sha256, result)
    return {**result, "elapsed_ms": round((time.perf_counter() - t0) * 1000)}
