"""
واجهة سطر الأوامر (CLI) للمحرك.

من مجلد backend:
    python -m droidshield_engine analyze app.apk [--out DIR] [--isolated] [--timeout 300]
    python -m droidshield_engine batch  apks_dir [--out DIR] [--workers 2] [--timeout 300] [--recursive]
    python -m droidshield_engine schema

رموز الخروج: 0 نجاح | 1 فشل تحليل ملف أو أكثر | 2 خطأ في الإعداد (Schema، مسار غير موجود)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import config
from .core.logging_setup import configure_logging


def cmd_schema(_args) -> int:
    from .feature_extraction import load_feature_schema

    s = load_feature_schema()
    print(f"Dataset      : {s.source.name}")
    print(f"Features     : {len(s)} (Label excluded)")
    print(f"Fingerprint  : {s.fingerprint}")
    print(f"First / last : {s.features[0]} ... {s.features[-1]}")
    print("Validation   : PASSED")
    return 0


def cmd_analyze(args) -> int:
    path = Path(args.apk)
    if not path.is_file():
        print(f"الملف غير موجود: {path}", file=sys.stderr)
        return 2
    out = Path(args.out) if args.out else config.RESULTS_DIR
    if args.isolated:
        from .core.batch import run_isolated

        o = run_isolated(path, out, timeout=args.timeout)
        print(json.dumps({k: v for k, v in o.__dict__.items() if k != "vector"}, ensure_ascii=False, indent=2))
        return 0 if o.status == "ok" else 1

    from .core.analysis_engine import AnalysisEngine

    result, paths = AnalysisEngine().analyze_and_export(path, out)
    s = result.summary()
    print(f"Package   : {result.package or '-'}")
    print(f"Loaded    : {result.loaded_ok}" + (f"  ({result.load_error['code']})" if result.load_error else ""))
    print(f"Modules   : {len(s['modules_ok'])} ok, failed: {s['modules_failed'] or 'none'}")
    if result.feature_vector is not None:
        print(f"Vector    : {result.feature_vector.values.shape} int8, {len(result.feature_vector.matched)} features = 1")
    print(f"Duration  : {result.duration_seconds:.1f}s")
    print(f"Results   : {paths['folder']}")
    return 0 if result.loaded_ok and result.vector_ok and not s["modules_failed"] else 1


def cmd_batch(args) -> int:
    from .core.batch import analyze_directory

    folder = Path(args.folder)
    if not folder.is_dir():
        print(f"المجلد غير موجود: {folder}", file=sys.stderr)
        return 2
    summary = analyze_directory(folder, args.out, workers=args.workers, timeout=args.timeout,
                                recursive=args.recursive)
    print(f"Files     : {summary['document']['total']}  in {summary['duration_seconds']}s")
    print(f"Status    : {summary['counts']}")
    for name, p in summary["paths"].items():
        print(f"{name:10}: {p}")
    return 0 if summary["counts"]["ok"] == summary["document"]["total"] else 1


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="droidshield_engine", description=config.ENGINE_NAME)
    ap.add_argument("--log-dir", type=Path, default=None)
    sub = ap.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="تحليل ملف APK واحد")
    a.add_argument("apk")
    a.add_argument("--out", help="مجلد النتائج")
    a.add_argument("--isolated", action="store_true", help="التحليل في process معزول بحد زمني")
    a.add_argument("--timeout", type=float, default=config.BATCH_TIMEOUT_SECONDS)
    a.set_defaults(func=cmd_analyze)

    b = sub.add_parser("batch", help="تحليل كل ملفات APK في مجلد")
    b.add_argument("folder")
    b.add_argument("--out")
    b.add_argument("--workers", type=int, default=config.BATCH_DEFAULT_WORKERS)
    b.add_argument("--timeout", type=float, default=config.BATCH_TIMEOUT_SECONDS)
    b.add_argument("--recursive", action="store_true")
    b.set_defaults(func=cmd_batch)

    s = sub.add_parser("schema", help="عرض Feature Schema والتحقق منها")
    s.set_defaults(func=cmd_schema)
    return ap


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):  # الرسائل العربية على طرفية Windows
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    args = build_parser().parse_args(argv)
    configure_logging(args.log_dir)
    try:
        return args.func(args)
    except Exception as e:  # مثل SchemaValidationError عند تغيّر الـ Dataset
        print(f"خطأ: {type(e).__name__}: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
