"""
تدريب نموذج DroidShield على Final_Balanced_Three_Datasets.csv (110 ميزة) — متوافق مع droidshield_engine.

الفرق عن train_svm.py (Drebin-215):
    - الـ Schema تُقرأ من المحرك نفسه (load_feature_schema) لا من أعمدة الملف مباشرة،
      فالنموذج والمحرك يستخدمان نفس الأسماء ونفس الترتيب حتماً.
    - بصمة الـ Schema تُحفظ مع النموذج (model_card.json)؛ FastAPI يرفض أي متجه ببصمة مختلفة.
    - التنظيف (حذف المكرر والمتعارض) يتم قبل التقسيم، وإلا تظهر نفس الصفوف في التدريب
      والاختبار (80% من صفوف هذه الـ Dataset مكررة) فتتضخم النتائج.

المخرجات (backend/models/droidshield/):
    svm_rbf.joblib, feature_names.json, shap_background.npy, metrics.json, model_card.json

الاستخدام (من مجلد backend):
    python ml/train_droidshield.py
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import shap
import sklearn
from sklearn.base import clone
from sklearn.calibration import CalibratedClassifierCV
from sklearn.dummy import DummyClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, balanced_accuracy_score, classification_report, confusion_matrix,
                             f1_score, precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import GridSearchCV, StratifiedKFold, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.svm import SVC

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
from droidshield_engine import config  # noqa: E402
from droidshield_engine.feature_extraction import load_feature_schema  # noqa: E402

OUT_DIR = BACKEND / "models" / "droidshield"
SEED = 42


def load_clean(schema) -> tuple[pd.DataFrame, pd.Series, dict]:
    df = pd.read_csv(schema.source)
    feats = list(schema.features)
    assert list(df.drop(columns=config.LABEL_COLUMN).columns) == feats, "الأعمدة لا تطابق الـ Schema"
    df = df.astype(np.int8)
    stats = {"raw_rows": len(df), "raw_label_counts": df[config.LABEL_COLUMN].value_counts().to_dict()}
    df = df.drop_duplicates()
    stats["after_dedup"] = len(df)
    conflict = df.duplicated(subset=feats, keep=False)
    df = df[~conflict]
    stats["conflicting_rows_removed"] = int(conflict.sum())
    stats["clean_rows"] = len(df)
    stats["clean_label_counts"] = df[config.LABEL_COLUMN].value_counts().to_dict()
    return df[feats], df[config.LABEL_COLUMN].astype(int), stats


def evaluate(y, proba, threshold=0.5) -> dict:
    pred = (proba >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "accuracy": float(accuracy_score(y, pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y, pred)),
        "precision_malware": float(precision_score(y, pred, zero_division=0)),
        "recall_malware": float(recall_score(y, pred)),
        "f1_malware": float(f1_score(y, pred)),
        "roc_auc": float(roc_auc_score(y, proba)),
        "false_positive_rate": float(fp / (fp + tn)),
        "false_negative_rate": float(fn / (fn + tp)),
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=OUT_DIR)
    ap.add_argument("--background", type=int, default=20)
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")

    schema = load_feature_schema()
    X, y, data_stats = load_clean(schema)
    print(f"[+] {data_stats}")
    X_train, X_test, y_train, y_test = train_test_split(
        X.to_numpy(np.float32), y.to_numpy(), test_size=0.2, stratify=y, random_state=SEED)  # مصفوفات: نفس صيغة المحرك
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED)

    # الميزات ثنائية 0/1 فلا حاجة لـ StandardScaler
    grid = GridSearchCV(
        Pipeline([("svm", SVC(kernel="rbf", class_weight="balanced", random_state=SEED))]),
        param_grid={"svm__C": [0.1, 1, 10, 100, 1000], "svm__gamma": ["scale", 0.1, 0.01, 0.001]},
        scoring="f1", cv=cv, n_jobs=-1,
    )
    grid.fit(X_train, y_train)
    print(f"[+] أفضل معاملات: {grid.best_params_} | F1 (CV): {grid.best_score_:.4f}")

    model = CalibratedClassifierCV(clone(grid.best_estimator_), method="sigmoid", cv=cv, ensemble=False)
    model.fit(X_train, y_train)
    proba = model.predict_proba(X_test)[:, 1]
    metrics = evaluate(y_test, proba)

    # خطوط أساس للمقارنة: هل SVM يضيف شيئاً فوق التخمين وفوق نموذج خطي بسيط؟
    baselines = {}
    for name, est in {"majority_class": DummyClassifier(strategy="most_frequent"),
                      "logistic_regression": LogisticRegression(max_iter=2000, class_weight="balanced")}.items():
        est.fit(X_train, y_train)
        baselines[name] = evaluate(y_test, est.predict_proba(X_test)[:, 1])

    print(classification_report(y_test, (proba >= 0.5).astype(int), target_names=["benign", "malware"], digits=4))
    for k in ("accuracy", "f1_malware", "roc_auc", "false_positive_rate", "false_negative_rate"):
        print(f"    {k:22} SVM={metrics[k]:.4f}  LogReg={baselines['logistic_regression'][k]:.4f}  "
              f"Majority={baselines['majority_class'][k]:.4f}")

    args.out.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, args.out / "svm_rbf.joblib")
    np.save(args.out / "shap_background.npy", shap.kmeans(X_train, args.background).data)
    (args.out / "feature_names.json").write_text(json.dumps(list(schema.features), indent=2), encoding="utf-8")
    full = {"best_params": grid.best_params_, "cv_f1": float(grid.best_score_), **metrics,
            "baselines": baselines, "n_train": len(X_train), "n_test": len(X_test),
            "n_features": len(schema), "data": data_stats}
    (args.out / "metrics.json").write_text(json.dumps(full, indent=2, default=str), encoding="utf-8")
    card = {
        "model": "CalibratedClassifierCV(SVC-RBF, sigmoid)",
        "label_encoding": {"malware": config.MALWARE, "benign": config.BENIGN},
        "dataset": schema.source.name,
        "schema_fingerprint": schema.fingerprint,
        "n_features": len(schema),
        "feature_rule": "F=1 iff the APK requests android.permission.F (uses-permission or uses-permission-sdk-23)",
        "input_dtype": "int8 (cast to float32 before predict)",
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sklearn_version": sklearn.__version__,
        "engine_version": config.ENGINE_VERSION,
    }
    (args.out / "model_card.json").write_text(json.dumps(card, indent=2), encoding="utf-8")
    print(f"[+] تم الحفظ في {args.out}")


if __name__ == "__main__":
    main()
