"""
تدريب نموذج SVM (RBF Kernel) على مجموعة بيانات Drebin-215.

المخرجات (في backend/models/):
    svm_rbf.joblib        -> CalibratedClassifierCV( Pipeline[StandardScaler اختياري + SVC-RBF] )
    feature_names.json    -> ترتيب الميزات الذي يجب أن يلتزم به مستخرج Androguard
    shap_background.npy   -> عينة خلفية مُلخّصة (k-means) لـ SHAP KernelExplainer
    metrics.json          -> مقاييس الأداء على بيانات الاختبار

الاستخدام:
    python backend/ml/train_svm.py --data data/drebin-215-dataset-5560malware-9476-benign.csv
    python backend/ml/train_svm.py --data ... --no-scaler      # بدون StandardScaler
"""
import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import shap
from sklearn.base import clone
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    roc_auc_score,
)
from sklearn.model_selection import GridSearchCV, StratifiedKFold, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

ROOT = Path(__file__).resolve().parents[2]
MODELS_DIR = ROOT / "backend" / "models"
LABEL_COL = "class"          # في Drebin-215: S = خبيث (Suspicious) ، B = سليم (Benign)
LABEL_MAP = {"S": 1, "B": 0}


def load_dataset(path: Path):
    df = pd.read_csv(path, low_memory=False)
    # بعض الخلايا في Drebin-215 تحتوي "?" بدل القيمة -> نحذف تلك الصفوف
    df = df.replace("?", np.nan).dropna()
    y = df[LABEL_COL].map(LABEL_MAP)
    if y.isna().any():
        raise ValueError(f"قيم تصنيف غير متوقعة: {df[LABEL_COL].unique()}")
    X = df.drop(columns=[LABEL_COL]).astype(np.float32)
    y = y.astype(int)

    # ~52% من صفوف Drebin-215 مكررة. بدون إزالتها يظهر نفس المتجه في التدريب والاختبار
    # (65% من بيانات الاختبار!) فتتضخم الدقة. نحذف المكرر ونحذف المتجهات التي تحمل التصنيفين معاً.
    d = X.copy()
    d[LABEL_COL] = y.values
    d = d.drop_duplicates()
    conflicting = d.duplicated(subset=list(X.columns), keep=False)
    d = d[~conflicting]
    print(f"[+] بعد إزالة التكرار: {len(d)} من {len(X)} (حُذف {conflicting.sum()} متجه متعارض التصنيف)")
    return d.drop(columns=[LABEL_COL]), d[LABEL_COL]


def build_pipeline(use_scaler: bool) -> Pipeline:
    steps = []
    if use_scaler:
        steps.append(("scaler", StandardScaler()))
    # بدون probability=True (مُهمل منذ sklearn 1.9 ومكلف داخل GridSearch)؛ المعايرة تتم لاحقاً مرة واحدة
    steps.append(("svm", SVC(kernel="rbf", class_weight="balanced", random_state=42)))
    return Pipeline(steps)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, type=Path)
    ap.add_argument("--no-scaler", action="store_true",
                    help="الميزات ثنائية (0/1) فالـ Scaler اختياري؛ يصبح ضرورياً عند إضافة ميزات التعمية")
    ap.add_argument("--background", type=int, default=20,
                    help="عدد مراكز k-means لخلفية SHAP (أقل = أسرع في التفسير)")
    ap.add_argument("--categories", type=Path, default=ROOT / "data" / "dataset-features-categories.csv")
    args = ap.parse_args()

    X, y = load_dataset(args.data)
    print(f"[+] العينات: {len(X)}  | الميزات: {X.shape[1]}  | خبيث: {y.sum()}  | سليم: {(y == 0).sum()}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    grid = GridSearchCV(
        build_pipeline(not args.no_scaler),
        param_grid={
            "svm__C": [1, 10, 100, 1000],   # التشغيل الأول اختار C=100 (حافة الشبكة) فوسّعناها
            "svm__gamma": ["scale", 0.01, 0.001],
        },
        scoring="f1",
        cv=StratifiedKFold(n_splits=5, shuffle=True, random_state=42),
        n_jobs=-1,
        verbose=1,
    )
    grid.fit(X_train, y_train)
    print(f"[+] أفضل معاملات: {grid.best_params_}  | F1 (CV): {grid.best_score_:.4f}")

    # معايرة الاحتمالات (Platt / sigmoid) لأفضل نموذج فقط -> predict_proba موثوق لعداد الأمان
    model = CalibratedClassifierCV(
        clone(grid.best_estimator_), method="sigmoid",
        cv=StratifiedKFold(n_splits=5, shuffle=True, random_state=42), ensemble=False,
    )
    model.fit(X_train, y_train)

    proba = model.predict_proba(X_test)[:, 1]
    pred = (proba >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_test, pred).ravel()
    metrics = {
        "best_params": grid.best_params_,
        "cv_f1": float(grid.best_score_),
        "accuracy": float(accuracy_score(y_test, pred)),
        "f1": float(f1_score(y_test, pred)),
        "roc_auc": float(roc_auc_score(y_test, proba)),
        "false_positive_rate": float(fp / (fp + tn)),   # سليم صُنّف خبيثاً
        "false_negative_rate": float(fn / (fn + tp)),   # خبيث فات النموذج
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
        "report": classification_report(y_test, pred, target_names=["benign", "malware"], output_dict=True),
        "n_train": int(len(X_train)),
        "n_test": int(len(X_test)),
        "n_features": int(X.shape[1]),
        "scaler": not args.no_scaler,
    }
    print(classification_report(y_test, pred, target_names=["benign", "malware"], digits=4))
    print(f"[+] Accuracy: {metrics['accuracy']:.4f} | F1: {metrics['f1']:.4f} | ROC-AUC: {metrics['roc_auc']:.4f}")
    print(f"[+] Confusion [[TN FP] [FN TP]]: {metrics['confusion_matrix']}")
    print(f"[+] FPR: {metrics['false_positive_rate']:.4f} | FNR: {metrics['false_negative_rate']:.4f}")

    # خلفية SHAP: KernelExplainer بطيء، لذلك نلخّص بيانات التدريب إلى عدد صغير من المراكز
    background = shap.kmeans(X_train.values, args.background).data

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODELS_DIR / "svm_rbf.joblib")
    np.save(MODELS_DIR / "shap_background.npy", background)
    (MODELS_DIR / "feature_names.json").write_text(
        json.dumps(list(X.columns), ensure_ascii=False, indent=2), encoding="utf-8"
    )
    if args.categories.exists():  # تصنيف كل ميزة (صلاحية / API / Intent / أمر) للمستخرج والواجهة
        rows = pd.read_csv(args.categories, header=None, names=["feature", "category"])
        cats = dict(zip(rows.feature, rows.category))
        cats.pop(LABEL_COL, None)
        (MODELS_DIR / "feature_categories.json").write_text(
            json.dumps(cats, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    (MODELS_DIR / "metrics.json").write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"[+] تم الحفظ في {MODELS_DIR}")


if __name__ == "__main__":
    main()
