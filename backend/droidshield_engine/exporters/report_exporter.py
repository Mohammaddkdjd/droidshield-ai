"""
analysis_report.txt: تقرير نصي مختصر يقرؤه الإنسان.

قاعدة مهمة: التقرير لا يذكر Malware أو Benign إلا إذا مُرِّرت إليه نتيجة نموذج التصنيف
(result.prediction). المحرك نفسه لا يعرف التصنيف ولا يخمّنه؛ التحليل الثابت يصف التطبيق فقط.
"""
from __future__ import annotations

from pathlib import Path

from .. import config
from .common import atomic_write_text

REPORT_FILE = "analysis_report.txt"
LINE = "=" * 72
SUB = "-" * 72


def _row(label: str, value) -> str:
    return f"  {label:<34} {value if value not in (None, '') else '-'}"


def build_report(result) -> str:
    md = result.module_data
    meta, perms, comps = md("metadata"), md("permissions"), md("components")
    dex, api, native = md("dex"), md("api_calls"), md("native")
    net, cert, strings = md("network"), md("certificate"), md("strings")
    fv = result.feature_vector

    out = [LINE, f"  {config.ENGINE_NAME}", f"  Version {config.ENGINE_VERSION}   |   {result.started_at}", LINE]

    out += ["", "[1] معلومات التطبيق — Application Info", SUB]
    if not result.loaded_ok:
        err = result.load_error or {}
        out += [_row("File", Path(result.apk_path).name),
                _row("Status", "تعذّر تحميل الـ APK — Load FAILED"),
                _row("Error code", err.get("code")), _row("Reason", err.get("message"))]
    else:
        h = result.loaded.hashes
        out += [
            _row("App name", meta.get("app_name")), _row("Package", result.package),
            _row("Version", f"{meta.get('version_name')} (code {meta.get('version_code')})"),
            _row("SDK (min / target)", f"{meta.get('min_sdk')} / {meta.get('target_sdk')}"),
            _row("File", result.loaded.file_name), _row("Size (bytes)", f"{result.loaded.size:,}"),
            _row("SHA-256", h["sha256"]), _row("SHA-1", h["sha1"]), _row("MD5", h["md5"]),
            _row("ZIP warnings", len(result.loaded.zip.warnings)),
        ]
        for w in result.loaded.zip.warnings[:10]:
            out.append(f"      ! {w.code.value}: {w.message} {w.entry or ''}")

    if result.loaded_ok:
        out += ["", "[2] الأرقام الأساسية — Key Counts", SUB,
                _row("Permissions requested", perms.get("counts", {}).get("requested")),
                _row("  dangerous", perms.get("counts", {}).get("dangerous")),
                _row("  custom (non-system)", perms.get("counts", {}).get("custom")),
                _row("Components (total)", comps.get("total")),
                _row("  exported / exposed", f"{sum(s['exported'] for s in comps.get('summary', {}).values())} / "
                                             f"{len(comps.get('exposed_components', []))}" if comps else None),
                _row("DEX files", dex.get("dex_count")),
                _row("Classes", dex.get("totals", {}).get("classes")),
                _row("Methods", dex.get("totals", {}).get("methods")),
                _row("Sensitive API calls (unique)", api.get("unique_sensitive_apis")),
                _row("  call sites", api.get("total_call_sites")),
                _row("  categories", ", ".join(api.get("categories_present", [])) or None),
                _row("Native libraries", native.get("count")),
                _row("  ABIs", ", ".join(native.get("abis", [])) or None),
                _row("URLs (http / https)", f"{net.get('counts', {}).get('http_urls')} / "
                                            f"{net.get('counts', {}).get('https_urls')}" if net else None),
                _row("Cleartext traffic permitted", (net.get("cleartext", {}).get("effective") or {}).get("permitted")),
                _row("Shell commands found", strings.get("counts", {}).get("shell_commands")),
                _row("Signing schemes", ", ".join(k for k, v in cert.get("schemes", {}).items() if v) or None),
                _row("Signature verified (apksigner)", (cert.get("verification") or {}).get("verified", "not performed"))]

    out += ["", "[3] حالة الوحدات — Module Status", SUB]
    for name, m in result.modules.items():
        mark = {"ok": "OK  ", "failed": "FAIL", "skipped": "SKIP"}[m.status]
        out.append(f"  [{mark}] {name:<14} {m.duration_seconds:7.2f}s  {m.error or ''}")
    if not result.modules:
        out.append("  (لم تُشغَّل أي وحدة)")

    out += ["", "[4] Feature Vector & Schema Validation", SUB]
    if fv is None:
        out += [_row("Vector", "لم يُبنَ — NOT built"), _row("Reason", result.mapping_error or "التحميل فشل")]
    else:
        checks = fv.validation.get("checks", {})
        out += [
            _row("Schema features", len(fv)),
            _row("Matched features (=1)", len(fv.matched)),
            _row("Unmatched features (=0)", len(fv) - len(fv.matched)),
            _row("Android perms outside schema", len(fv.unmapped_android)),
            _row("Non-system perms ignored", len(fv.ignored_non_android)),
            _row("Schema fingerprint", fv.schema_fingerprint[:16] + "…"),
            _row("Validation", "PASSED" if fv.validation.get("passed") else "FAILED"),
            "  " + "  ".join(f"{k}={'✓' if ok else '✗'}" for k, ok in checks.items()),
            "", "  Matched: " + (", ".join(fv.matched) or "-"),
        ]

    out += ["", "[5] التصنيف — Classification", SUB]
    if result.prediction:
        p = result.prediction
        label = "Malware" if p.get("label") == config.MALWARE else "Benign"
        out += [_row("Model prediction", label), _row("Probability (malware)", p.get("probability")),
                _row("Model", p.get("model"))]
    else:
        out.append("  لم يُمرَّر ناتج نموذج التصنيف. هذا التقرير وصفي فقط ولا يحكم على التطبيق.")

    out += ["", LINE]
    return "\n".join(out) + "\n"


def export_report(result, folder: Path) -> Path:
    return atomic_write_text(folder / REPORT_FILE, build_report(result))
