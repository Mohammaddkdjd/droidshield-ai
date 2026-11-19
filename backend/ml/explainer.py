"""
طبقة التنبؤ والتفسير: SVM (احتمال الخبث) + SHAP KernelExplainer (أوزان الميزات).

قيم SHAP تُحسب على احتمال الخبث P(malware):
    shap > 0  -> الميزة دفعت القرار نحو "خبيث"
    shap < 0  -> الميزة دفعت القرار نحو "سليم"
    base_value + مجموع قيم SHAP = P(malware) لهذا التطبيق
"""
import json
import threading
import warnings
from pathlib import Path

import joblib
import numpy as np
import shap

MODELS_DIR = Path(__file__).resolve().parents[1] / "models"
DEFAULT_MODEL_DIR = MODELS_DIR / "droidshield"   # نموذج الـ 110 ميزة المتوافق مع droidshield_engine


class SchemaMismatchError(ValueError):
    """المتجه بُني بـ Schema مختلفة عن التي تدرّب عليها النموذج."""


class MalwareExplainer:
    def __init__(self, models_dir: Path = DEFAULT_MODEL_DIR, threshold: float = 0.5,
                 nsamples: int = 500, top_k: int = 15):
        self.model = joblib.load(models_dir / "svm_rbf.joblib")
        self.feature_names: list[str] = json.loads(
            (models_dir / "feature_names.json").read_text(encoding="utf-8"))
        cat_path = models_dir / "feature_categories.json"
        self.categories: dict[str, str] = (
            json.loads(cat_path.read_text(encoding="utf-8")) if cat_path.exists() else {})
        card_path = models_dir / "model_card.json"
        self.card: dict = json.loads(card_path.read_text(encoding="utf-8")) if card_path.exists() else {}
        # بصمة الـ Schema التي تدرّب عليها النموذج (None للنموذج القديم Drebin الذي لا يملك بطاقة)
        self.schema_fingerprint: str | None = self.card.get("schema_fingerprint")
        if self.card and not self.categories:  # كل ميزات هذا النموذج أذونات
            self.categories = dict.fromkeys(self.feature_names, "Manifest Permission")
        metrics_path = models_dir / "metrics.json"
        self.metrics = json.loads(metrics_path.read_text(encoding="utf-8")) if metrics_path.exists() else {}
        self.background = np.load(models_dir / "shap_background.npy")
        self.threshold = threshold
        self.nsamples = nsamples
        self.top_k = top_k
        self._explainer = shap.KernelExplainer(self._malware_proba, self.background)
        self._lock = threading.Lock()

    def _malware_proba(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict_proba(X)[:, 1]

    def vector_from_dict(self, features: dict[str, float]) -> tuple[np.ndarray, list[str]]:
        """يحوّل {'SEND_SMS': 1, ...} إلى متجه بالترتيب الصحيح؛ الميزات غير المذكورة = 0."""
        known = set(self.feature_names)
        unknown = [k for k in features if k not in known]
        vec = np.array([float(features.get(f, 0.0)) for f in self.feature_names], dtype=np.float32)
        return vec, unknown

    def check_fingerprint(self, fingerprint: str | None) -> None:
        if self.schema_fingerprint and fingerprint != self.schema_fingerprint:
            raise SchemaMismatchError(
                f"بصمة المتجه {str(fingerprint)[:16]}… لا تطابق بصمة النموذج {self.schema_fingerprint[:16]}…")

    def predict(self, vector: np.ndarray, explain: bool = True, fingerprint: str | None = None) -> dict:
        if fingerprint is not None:
            self.check_fingerprint(fingerprint)
        x = np.asarray(vector, dtype=np.float32).reshape(1, -1)
        if x.shape[1] != len(self.feature_names):
            raise ValueError(f"عدد الميزات {x.shape[1]} لا يطابق النموذج ({len(self.feature_names)})")

        p_mal = float(self._malware_proba(x)[0])
        is_mal = p_mal >= self.threshold
        result = {
            "label": "malware" if is_mal else "benign",
            "malware_probability": round(p_mal, 4),
            "confidence": round(p_mal if is_mal else 1 - p_mal, 4),
            "safety_score": round((1 - p_mal) * 100, 1),
            "threshold": self.threshold,
            "active_features": int((x[0] != 0).sum()),
            "total_features": len(self.feature_names),
            "detected_features": [
                {"feature": f, "category": self.categories.get(f, "Unknown")}
                for f, v in zip(self.feature_names, x[0]) if v != 0
            ],
        }
        if explain:
            result["explanation"] = self.explain(x)
        return result

    def explain(self, x: np.ndarray) -> dict:
        # KernelExplainer يخزّن حالته الوسيطة على الكائن نفسه، فطلبان متزامنان يُفسدان بعضهما (IndexError)
        with self._lock, warnings.catch_warnings():
            warnings.simplefilter("ignore")
            np.random.seed(0)  # KernelExplainer يأخذ عينات عشوائية؛ بذرة ثابتة = نفس التفسير لنفس الملف
            sv = np.asarray(self._explainer.shap_values(x, nsamples=self.nsamples, silent=True))
        sv = sv.reshape(-1)
        base = float(np.ravel(self._explainer.expected_value)[0])

        order = np.argsort(-np.abs(sv))
        top_idx = [i for i in order[: self.top_k] if sv[i] != 0]
        rest = float(sv.sum() - sv[top_idx].sum())
        return {
            "base_value": round(base, 4),
            "prediction": round(base + float(sv.sum()), 4),
            "top_features": [
                {
                    "feature": self.feature_names[i],
                    "category": self.categories.get(self.feature_names[i], "Unknown"),
                    "value": float(x[0, i]),
                    "shap": round(float(sv[i]), 5),
                    "direction": "malware" if sv[i] > 0 else "benign",
                }
                for i in top_idx
            ],
            "other_features_shap": round(rest, 5),
        }
