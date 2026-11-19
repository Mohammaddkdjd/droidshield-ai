"""
تنظيف ملف الـ dataset قبل التدريب.

الخطوات:
    1) التحقق: الأعمدة = Feature Schema الخاصة بـ droidshield_engine بنفس الترتيب، والقيم 0/1 فقط، ولا قيم ناقصة.
    2) حذف الصفوف المكررة حرفياً (وإلا تظهر نفس الصفوف في التدريب والاختبار فتُضخَّم الدقة).
    3) المتجهات المتطابقة ذات التصنيف المتعارض (0 و1 معاً):
         drop     (الافتراضي) -> تُحذف كلها
         majority             -> يبقى صف واحد بالتصنيف الأغلب (عند التعادل يُحذف)
    4) (اختياري --drop-empty) حذف الصفوف التي كل أذوناتها 0.

الاستخدام:
    python backend/ml/clean_dataset.py "C:/Users/ali/Desktop/Final_Balanced_Three_Datasets.csv"
    python backend/ml/clean_dataset.py in.csv --out data/clean.csv --conflict majority --drop-empty
"""
import argparse
import json
import sys
import warnings
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from droidshield_engine.feature_extraction import load_feature_schema  # noqa: E402

DEFAULT_OUT = Path(__file__).resolve().parents[2] / "data" / "dataset_clean.csv"
LABEL = "Label"


def counts(df: pd.DataFrame) -> str:
    c = df[LABEL].value_counts().to_dict()
    return f"{len(df):>6} صفاً  (خبيث=1: {c.get(1, 0)} | سليم=0: {c.get(0, 0)})"


def validate(df: pd.DataFrame) -> list[str]:
    schema = load_feature_schema()
    # الأعمدة المتوقعة = ترتيب الـ Dataset الأصلي نفسه (الـ Schema + Label في موضعه)
    expected = [c for c in pd.read_csv(schema.source, nrows=0).columns]
    if list(df.columns) != expected:
        missing = set(expected) - set(df.columns)
        extra = set(df.columns) - set(expected)
        sys.exit(f"[x] الأعمدة لا تطابق Feature Schema\n    ناقص: {sorted(missing)}\n"
                 f"    زائد: {sorted(extra)}\n    (أو الترتيب مختلف)")
    if df.isna().any().any():
        sys.exit(f"[x] توجد قيم ناقصة: {int(df.isna().sum().sum())}")
    bad = ~df.isin([0, 1]).all()
    if bad.any():
        sys.exit(f"[x] قيم غير 0/1 في الأعمدة: {list(bad[bad].index)}")
    return [c for c in df.columns if c != LABEL]


def clean_drop(df: pd.DataFrame, drop_empty: bool = False) -> pd.DataFrame:
    feats = validate(df)
    df = df.astype(int)
    print(f"  الأصل                    : {counts(df)}")

    df = df.drop_duplicates().reset_index(drop=True)
    print(f"  بعد حذف المكرر           : {counts(df)}")

    # بعد حذف المكرر، أي متجه يظهر أكثر من مرة فهو متجه بتصنيفين مختلفين
    dup_mask = df.duplicated(subset=feats, keep=False)
    print(f"  متجهات متعارضة التصنيف    : {df.loc[dup_mask, feats].drop_duplicates().shape[0]}")
    df = df[~dup_mask]
    print(f"  بعد حذف المتعارض         : {counts(df)}")

    if drop_empty:
        df = df[df[feats].sum(axis=1) > 0]
        print(f"  بعد حذف الصفوف الفارغة   : {counts(df)}")
    return df.reset_index(drop=True)


def resolve_majority(raw: pd.DataFrame, feats: list[str]) -> pd.DataFrame:
    """لكل متجه متعارض: التصنيف الأكثر تكراراً في الملف الأصلي، ويُحذف عند التعادل."""
    g = raw.groupby(feats)[LABEL].agg(lambda s: s.mode().tolist())
    g = g[g.map(len) == 1].map(lambda m: m[0])  # استبعاد التعادل
    with warnings.catch_warnings():  # reset_index على 110 مستوى يطلق PerformanceWarning غير مؤثر
        warnings.simplefilter("ignore", pd.errors.PerformanceWarning)
        out = g.reset_index()
    return out[raw.columns].copy()


def main():
    ap = argparse.ArgumentParser(description="تنظيف dataset الأذونات قبل التدريب")
    ap.add_argument("input", type=Path)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--conflict", choices=["drop", "majority"], default="drop")
    ap.add_argument("--drop-empty", action="store_true", help="حذف الصفوف التي كل أذوناتها 0")
    args = ap.parse_args()

    raw = pd.read_csv(args.input)
    print(f"[*] {args.input.name}")
    if args.conflict == "majority":
        feats = validate(raw)
        raw = raw.astype(int)
        # resolve_majority تُرجع صفاً واحداً لكل متجه (متعارض أو لا) -> يشمل حذف المكرر
        print(f"  الأصل                    : {counts(raw)}")
        df = resolve_majority(raw, feats)
        print(f"  بعد حذف المكرر + الأغلبية : {counts(df)}")
        if args.drop_empty:
            df = df[df[feats].sum(axis=1) > 0].reset_index(drop=True)
            print(f"  بعد حذف الصفوف الفارغة   : {counts(df)}")
    else:
        df = clean_drop(raw, args.drop_empty)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(args.out, index=False)
    c = df[LABEL].value_counts()
    print(f"\n[+] حُفظ: {args.out}")
    print(f"    نسبة الخبيث/السليم = {c.get(1, 0)}/{c.get(0, 0)} "
          f"-> استخدم class_weight='balanced' و stratify عند التقسيم")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
