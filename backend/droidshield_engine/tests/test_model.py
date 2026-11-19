"""
الربط بين النموذج المدرَّب (models/droidshield) والمحرك: نفس الـ Schema، ونفس صيغة المدخل.
"""
import json
from pathlib import Path

import joblib
import numpy as np
import pytest

from droidshield_engine import config
from droidshield_engine.feature_extraction import FeatureMapper, load_feature_schema

MODEL_DIR = Path(__file__).resolve().parents[2] / "models" / "droidshield"
pytestmark = pytest.mark.skipif(not (MODEL_DIR / "svm_rbf.joblib").exists(), reason="النموذج غير مدرَّب بعد")
P = "android.permission."


@pytest.fixture(scope="module")
def model():
    return joblib.load(MODEL_DIR / "svm_rbf.joblib")


def test_model_card_matches_engine_schema():
    card = json.loads((MODEL_DIR / "model_card.json").read_text(encoding="utf-8"))
    schema = load_feature_schema()
    assert card["schema_fingerprint"] == schema.fingerprint == config.EXPECTED_SCHEMA_SHA256
    assert json.loads((MODEL_DIR / "feature_names.json").read_text()) == list(schema.features)
    assert card["label_encoding"] == {"malware": 1, "benign": 0}


def test_model_accepts_engine_vector(model):
    v = FeatureMapper().map_permissions([P + "SEND_SMS", P + "INTERNET"]).values
    assert model.n_features_in_ == 110
    p = model.predict_proba(v.astype(np.float32).reshape(1, -1))
    assert p.shape == (1, 2) and np.isclose(p.sum(), 1)


def test_shap_background_shape():
    assert np.load(MODEL_DIR / "shap_background.npy").shape[1] == 110


def test_metrics_beat_baselines():
    m = json.loads((MODEL_DIR / "metrics.json").read_text(encoding="utf-8"))
    assert m["data"]["clean_rows"] == 3414                      # تدرّب على البيانات النظيفة لا الأصلية
    assert m["f1_malware"] > m["baselines"]["logistic_regression"]["f1_malware"]
    assert m["roc_auc"] > 0.9
