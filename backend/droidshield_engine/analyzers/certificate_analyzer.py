"""
تحليل توقيع الـ APK وشهادات المطوّر.

مخططات التوقيع في Android:
    v1 (JAR signing)   -> ملفات META-INF/*.SF و *.RSA|DSA|EC
    v2 / v3 / v3.1     -> APK Signing Block قبل الـ Central Directory (تحمي الملف كاملاً)
                          v3 يدعم تدوير المفتاح (key rotation)

ماذا نستخرج: الشهادات (Subject, Issuer, Serial, الصلاحية، الخوارزميات) وبصماتها
MD5/SHA1/SHA256 محسوبة على DER الشهادة (نفس ما يعرضه apksigner و keytool).

ما لا نفعله وحده: التحقق التشفيري الكامل من التوقيع (أن المحتوى لم يُعدَّل بعد التوقيع).
Androguard يقرأ الشهادات ولا يتحقق من صحة التوقيع على المحتوى. الأداة المعتمدة لذلك
هي apksigner من Android SDK Build-Tools (تحتاج Java). إن وُجدت على PATH نشغّلها تلقائياً؛
وإلا نسجّل verification.performed = False مع السبب، ولا ندّعي تحققاً لم يحدث.

ملاحظة: كل شهادات Android تقريباً ذاتية التوقيع (self-signed) بطبيعتها؛ هذا ليس مؤشر خبث.
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
from datetime import datetime, timezone

from asn1crypto import x509

from .base import BaseAnalyzer

APKSIGNER_TIMEOUT = 60


def describe_certificate(der: bytes) -> dict:
    cert = x509.Certificate.load(der)
    validity = cert["tbs_certificate"]["validity"]
    not_before, not_after = validity["not_before"].native, validity["not_after"].native
    now = datetime.now(timezone.utc)
    pk = cert.public_key
    subject = cert.subject.human_friendly
    return {
        "subject": subject,
        "issuer": cert.issuer.human_friendly,
        "serial_number": format(cert.serial_number, "x"),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "expired": not_after < now,
        "not_yet_valid": not_before > now,
        "self_signed": cert.self_signed in ("maybe", "yes"),
        "signature_algorithm": cert.signature_algo,
        "hash_algorithm": cert.hash_algo,
        "public_key_algorithm": pk.algorithm,
        "public_key_bits": pk.bit_size,
        "fingerprints": {
            "md5": hashlib.md5(der).hexdigest(),
            "sha1": hashlib.sha1(der).hexdigest(),
            "sha256": hashlib.sha256(der).hexdigest(),
        },
        "debug_certificate": "Android Debug" in subject,
        "weak_hash": cert.hash_algo in ("md5", "sha1"),
        "weak_key": pk.algorithm == "rsa" and (pk.bit_size or 0) < 2048,
    }


def run_apksigner(path: str) -> dict:
    exe = shutil.which("apksigner") or shutil.which("apksigner.bat")
    if not exe:
        return {"performed": False, "tool": None,
                "reason": "apksigner غير مثبّت (Android SDK Build-Tools + Java)؛ الشهادات مستخرجة دون تحقق تشفيري"}
    try:
        p = subprocess.run([exe, "verify", "--verbose", path], capture_output=True, text=True,
                           timeout=APKSIGNER_TIMEOUT, check=False)
        return {"performed": True, "tool": "apksigner", "verified": p.returncode == 0,
                "output": (p.stdout + p.stderr)[-4000:]}
    except subprocess.TimeoutExpired:
        return {"performed": False, "tool": "apksigner", "reason": "timeout"}


class CertificateAnalyzer(BaseAnalyzer):
    name = "certificate"

    def __init__(self, verify_with_apksigner: bool = True):
        self.verify = verify_with_apksigner

    def analyze(self, apk) -> dict:
        a = apk.apk
        schemes = {
            "v1": a.is_signed_v1(),
            "v2": a.is_signed_v2(),
            "v3": a.is_signed_v3(),
            "v31": bool(getattr(a, "is_signed_v31", lambda: False)()),
        }
        ders: dict[str, list[bytes]] = {
            "v1": [c.dump() for c in a.get_certificates_v1()] if schemes["v1"] else [],
            "v2": list(a.get_certificates_der_v2()) if schemes["v2"] else [],
            "v3": list(a.get_certificates_der_v3()) if schemes["v3"] else [],
        }
        certs: dict[str, dict] = {}
        errors = []
        for scheme, items in ders.items():
            for der in items:
                fp = hashlib.sha256(der).hexdigest()
                if fp not in certs:
                    try:
                        certs[fp] = {**describe_certificate(der), "schemes": []}
                    except Exception as e:
                        errors.append(f"{scheme}: {type(e).__name__}")
                        continue
                certs[fp]["schemes"].append(scheme)

        cert_list = list(certs.values())
        return {
            "signed": any(schemes.values()),
            "schemes": schemes,
            "signature_files": a.get_signature_names(),
            "certificates": cert_list,
            "certificate_count": len(cert_list),
            # تطبيق موقّع بشهادات مختلفة في المخططات المختلفة غير طبيعي
            "scheme_certificates_consistent": len(cert_list) <= 1,
            "debug_signed": any(c["debug_certificate"] for c in cert_list),
            "parse_errors": errors,
            "verification": run_apksigner(str(apk.path)) if self.verify else
            {"performed": False, "tool": None, "reason": "معطّل في الإعدادات"},
            "note": "الشهادة الذاتية التوقيع طبيعية في Android وليست دليلاً على أن التطبيق خبيث",
        }
