"""
اختبارات التحليل المتقدم: Strings, Network, Resources (NSC), Hardware, Native, Certificate, Metadata.

المراجع المستقلة المستخدمة:
    - الشهادات: نقرأ ملف التوقيع META-INF/*.RSA بمكتبة cryptography (لا Androguard) ونقارن البصمات.
    - شهادة مصنوعة في الاختبار بخصائص معروفة (مفتاح 1024، Android Debug، منتهية).
    - ELF: معمارية كل مكتبة يجب أن تطابق مجلد الـ ABI الذي وضعها فيه Google/F-Droid.
    - الاتساق بين الوحدات: metadata تحسب أعدادها بنفسها ويجب أن تطابق الوحدات المتخصصة.
"""
import base64
import datetime as dt
import hashlib
import io
import zipfile
from pathlib import Path

import pytest
from lxml import etree

from droidshield_engine.analyzers import (
    CertificateAnalyzer, ComponentAnalyzer, HardwareAnalyzer, MetadataAnalyzer, NativeAnalyzer,
    NetworkAnalyzer, PermissionAnalyzer, ResourcesAnalyzer, StringsAnalyzer,
)
from droidshield_engine.analyzers.certificate_analyzer import describe_certificate
from droidshield_engine.analyzers.hardware_analyzer import extract_features
from droidshield_engine.analyzers.network_analyzer import effective_cleartext
from droidshield_engine.analyzers.resources_analyzer import parse_network_security_config
from droidshield_engine.analyzers.strings_analyzer import (
    Findings, is_ambiguous_ip, is_plausible_domain, looks_like_base64, scan_string,
)
from droidshield_engine.config import ContentLimits
from droidshield_engine.core import load_apk

APK_DIR = Path("E:/apk_test/dl")
AUTOMATION = APK_DIR / "com.jens.automation2_149.apk"
KDE = APK_DIR / "org.kde.kdeconnect_tp_13702.apk"
needs_real = pytest.mark.skipif(not AUTOMATION.exists(), reason="ملفات APK الحقيقية غير متوفرة")
NS = 'xmlns:android="http://schemas.android.com/apk/res/android"'


def scan(*strings, source="classes.dex"):
    f = Findings(ContentLimits())
    for s in strings:
        scan_string(s, source, f)
    return f


def values(f, cat):
    return [i["value"] for i in f.items(cat)]


# =============================== Strings =============================== #
def test_url_domain_and_ip_extraction():
    f = scan("Connecting to https://api.evil-c2.ru/gate.php?id=1).", "http://45.33.32.156:8080/x")
    assert values(f, "urls") == ["http://45.33.32.156:8080/x", "https://api.evil-c2.ru/gate.php?id=1"]
    assert values(f, "domains") == ["api.evil-c2.ru"]
    ip = f.items("ip_addresses")[0]
    assert (ip["value"], ip["scope"], ip["ambiguous"], ip["in_url"]) == ("45.33.32.156", "public", False, True)


@pytest.mark.parametrize("s,ok", [("google.com", True), ("evil-c2.ru", True), ("com.example.app", False),
                                  ("android.intent.action.MAIN", False), ("Hello.World", False), ("a.b", False)])
def test_plausible_domain(s, ok):
    assert is_plausible_domain(s) is ok


@pytest.mark.parametrize("ip,ambiguous", [("2.5.29.14", True), ("1.3.101.112", True), ("1.2.2.1", True),
                                          ("8.8.8.8", False), ("45.33.32.156", False), ("192.168.1.1", False)])
def test_ambiguous_ip(ip, ambiguous):
    assert is_ambiguous_ip(ip) is ambiguous


@pytest.mark.parametrize("s", ["0.0.9.00", "010.1.1.1", "1.2.3.04", "version 0.0.9.00 build"])
def test_leading_zero_octets_are_not_ips_and_do_not_crash(s):
    """من Phase 9: '0.0.9.00' في تطبيق حقيقي أسقط وحدتي strings و network."""
    assert values(scan(s), "ip_addresses") == []


def test_ip_scopes():
    f = scan("127.0.0.1", "10.0.0.5", "224.0.0.1", "45.33.32.156")
    assert {i["value"]: i["scope"] for i in f.items("ip_addresses")} == {
        "127.0.0.1": "loopback", "10.0.0.5": "private", "224.0.0.1": "reserved", "45.33.32.156": "public"}


def test_emails_ignore_image_names():
    f = scan("contact: dev@example.com", "icon@2x.png")
    assert values(f, "emails") == ["dev@example.com"]


def test_shell_commands_vs_prose():
    prose = ("Here you can select a script or an executable that is run as an action. It must be located "
             "in /system/bin/ or similar and you must handle prerequisites yourself.")
    f = scan("su -c id", "pm install -r /data/local/tmp/x.apk", "settings put global airplane_mode_on 1", prose)
    assert set(values(f, "shell_commands")) == {"su -c id", "pm install -r /data/local/tmp/x.apk",
                                                "settings put global airplane_mode_on 1"}
    assert "/system/bin/" in values(f, "file_paths")  # المسار في النص البشري يُرصد كمسار فقط


def test_hidden_url_in_base64():
    payload = base64.b64encode(b"http://hidden-c2.xyz/panel/gate.php").decode()
    f = scan(payload)
    item = f.items("base64_strings")[0]
    assert item["decoded_preview"] == "http://hidden-c2.xyz/panel/gate.php"
    hidden = next(u for u in f.items("urls") if u["value"] == "http://hidden-c2.xyz/panel/gate.php")
    assert hidden["hidden"] and hidden["sources"] == ["classes.dex:base64"]


@pytest.mark.parametrize("s", ["OnCommandResultListener2", "actionBarOnMenuKeyEventPre28",
                               "Elgamal/ECB/PKCS1Padding", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"])
def test_base64_false_positives_rejected(s):
    assert not looks_like_base64(s)


def test_hex_strings_not_base64():
    f = scan("3045AE6FC8422f64ED579528D38120EAE12196D5")
    assert values(f, "hex_strings") and not values(f, "base64_strings")


def test_cipher_and_suspicious():
    f = scan("AES/ECB/PKCS5Padding", "AES/GCM/NoPadding", "/system/xbin/su", "ro.kernel.qemu",
             "content://sms/inbox", "android.telephony.SmsManager")
    ciphers = {i["value"]: i["weak"] for i in f.items("cipher_transformations")}
    assert ciphers == {"AES/ECB/PKCS5Padding": True, "AES/GCM/NoPadding": False}
    groups = {i["value"]: i["group"] for i in f.items("suspicious")}
    assert groups["/system/xbin/su"] == "root_detection"
    assert groups["ro.kernel.qemu"] == "emulator_detection"
    assert groups["content://sms"] == "sensitive_content_uri"
    assert groups["android.telephony.SmsManager"] == "reflection_target"


def test_findings_cap_and_sources():
    f = Findings(ContentLimits(max_findings_per_category=2, max_sources_per_finding=1))
    for i, src in enumerate(["a", "b", "c"]):
        scan_string(f"https://x{i}.com", src, f)
        scan_string("https://x0.com", src, f)
    assert len(f.items("urls")) == 2 and "urls" in f.truncated
    x0 = next(i for i in f.items("urls") if i["value"] == "https://x0.com")
    assert x0["count"] == 4 and x0["sources"] == ["a"]


# ========================= Network Security Config ========================= #
NSC_XML = """<network-security-config>
  <base-config cleartextTrafficPermitted="false">
    <trust-anchors><certificates src="system"/><certificates src="user"/></trust-anchors>
  </base-config>
  <domain-config cleartextTrafficPermitted="true">
    <domain includeSubdomains="true">legacy.example.com</domain>
    <pin-set expiration="2030-01-01"><pin digest="SHA-256">abc=</pin></pin-set>
  </domain-config>
  <debug-overrides><trust-anchors><certificates src="user"/></trust-anchors></debug-overrides>
</network-security-config>"""


def test_parse_network_security_config():
    p = parse_network_security_config(etree.fromstring(NSC_XML))
    assert p["base_config"]["cleartext_permitted"] is False
    assert p["trusts_user_certificates"] is True
    assert p["cleartext_domains"] == ["legacy.example.com"]
    assert p["has_pinning"] and p["domain_configs"][0]["pin_set"]["pins"] == [{"digest": "SHA-256", "value": "abc="}]
    assert p["debug_overrides"]["trust_anchors"] == [{"src": "user", "override_pins": None}]


def test_effective_cleartext_priority():
    nsc = {"parsed": parse_network_security_config(etree.fromstring(NSC_XML))}
    assert effective_cleartext(nsc, True, 30)["permitted"] is False             # NSC يتقدم على الـ Manifest
    assert effective_cleartext(None, True, 30) == {"permitted": True, "decided_by": "manifest", "cleartext_domains": []}
    assert effective_cleartext(None, None, 27)["permitted"] is True             # الافتراضي قبل API 28
    assert effective_cleartext(None, None, 28)["permitted"] is False
    empty_base = {"parsed": parse_network_security_config(etree.fromstring("<network-security-config/>"))}
    assert effective_cleartext(empty_base, None, 27)["permitted"] is True


# =============================== Hardware =============================== #
def test_hardware_features():
    xml = etree.fromstring(f'<manifest {NS}><uses-feature android:name="android.hardware.camera"/>'
                           '<uses-feature android:name="android.hardware.nfc" android:required="false"/>'
                           '<uses-feature android:glEsVersion="0x00020000"/></manifest>')
    r = extract_features(xml)
    assert r["required"] == ["android.hardware.camera"] and r["optional"] == ["android.hardware.nfc"]
    assert r["categories"]["camera"] and r["categories"]["nfc"] and not r["categories"]["gps"]
    assert r["gl_es_version"] == {"version": "0x00020000", "required": True}


# ============================= Certificates ============================= #
def make_cert(cn: str, key_bits: int, days_valid: int, start_offset_days: int = 0) -> bytes:
    from cryptography import x509 as cx509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    name = cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, cn)])
    start = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=start_offset_days)
    cert = (cx509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(0x1234).not_valid_before(start).not_valid_after(start + dt.timedelta(days=days_valid))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


def test_describe_certificate_known_properties():
    der = make_cert("Android Debug", 1024, days_valid=1, start_offset_days=-10)
    c = describe_certificate(der)
    assert c["fingerprints"] == {"md5": hashlib.md5(der).hexdigest(), "sha1": hashlib.sha1(der).hexdigest(),
                                 "sha256": hashlib.sha256(der).hexdigest()}
    assert c["debug_certificate"] and c["weak_key"] and c["expired"] and c["self_signed"]
    assert c["serial_number"] == "1234" and c["public_key_bits"] == 1024


def test_describe_certificate_strong_valid():
    c = describe_certificate(make_cert("Release", 2048, days_valid=3650))
    assert not (c["weak_key"] or c["expired"] or c["not_yet_valid"] or c["debug_certificate"] or c["weak_hash"])


@needs_real
def test_certificate_matches_independent_pkcs7_parse():
    """المرجع: نقرأ META-INF/*.RSA بمكتبة cryptography ونحسب البصمة بأنفسنا."""
    from cryptography.hazmat.primitives.serialization import Encoding, pkcs7

    a = load_apk(KDE)
    r = CertificateAnalyzer().analyze(a)
    with zipfile.ZipFile(KDE) as z:
        certs = pkcs7.load_der_pkcs7_certificates(z.read(r["signature_files"][0]))
    expected = hashlib.sha256(certs[0].public_bytes(Encoding.DER)).hexdigest()
    assert [c["fingerprints"]["sha256"] for c in r["certificates"]] == [expected]
    assert r["schemes"] == {"v1": True, "v2": True, "v3": True, "v31": False}
    assert r["certificates"][0]["schemes"] == ["v1", "v2", "v3"]
    assert r["scheme_certificates_consistent"] and not r["debug_signed"]


@needs_real
def test_verification_not_claimed_without_tool(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: None)
    v = CertificateAnalyzer().analyze(load_apk(KDE))["verification"]
    assert v["performed"] is False and "apksigner" in v["reason"]


# ================================ Native ================================ #
@needs_real
def test_native_libraries_real():
    r = NativeAnalyzer().analyze(load_apk(KDE))
    assert r["count"] == 4 and r["abis"] == ["arm64-v8a", "armeabi-v7a", "x86", "x86_64"]
    machines = {lib["abi"]: lib["elf"]["machine"] for lib in r["libraries"]}
    assert machines == {"arm64-v8a": "EM_AARCH64", "armeabi-v7a": "EM_ARM", "x86": "EM_386", "x86_64": "EM_X86_64"}
    assert r["abi_mismatches"] == [] and "JNI_OnLoad" in r["jni_functions"]
    lib = r["libraries"][0]
    assert "libc.so" in lib["elf"]["needed"] and lib["sha256"] and lib["elf"]["exported_count"] > 0


def rebuild(src: Path, extra: dict[str, bytes], tmp_path) -> Path:
    buf = io.BytesIO()
    with zipfile.ZipFile(src) as z, zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as out:
        for i in z.infolist():
            out.writestr(i.filename, z.read(i))
        for name, data in extra.items():
            out.writestr(name, data)
    p = tmp_path / "rebuilt.apk"
    p.write_bytes(buf.getvalue())
    return p


@needs_real
def test_native_anomalies(tmp_path):
    with zipfile.ZipFile(KDE) as z:
        x86_lib = z.read("lib/x86/libandroidx.graphics.path.so")
    apk = load_apk(rebuild(KDE, {
        "lib/arm64-v8a/libfake.so": x86_lib,               # مكتبة x86 داخل مجلد arm64
        "lib/arm64-v8a/libevil.so": b"MZ\x90\x00 not elf",  # ملف مموّه
        "assets/payload.so": x86_lib,                      # .so خارج lib/
    }, tmp_path))
    r = NativeAnalyzer().analyze(apk)
    assert r["abi_mismatches"] == ["lib/arm64-v8a/libfake.so"]
    assert r["not_elf"] == ["lib/arm64-v8a/libevil.so"]
    assert r["so_outside_lib"] == ["assets/payload.so"]
    assert r["count"] == 6  # فشل مكتبة لا يُسقط البقية


# ========================== Real APKs: content ========================== #
@pytest.fixture(scope="module")
def results():
    out = {}
    for path in (AUTOMATION, KDE):
        a = load_apk(path)
        out[path.name] = {A.name: A().analyze(a) for A in (
            ResourcesAnalyzer, StringsAnalyzer, NetworkAnalyzer, MetadataAnalyzer, PermissionAnalyzer,
            ComponentAnalyzer, HardwareAnalyzer)}
        out[path.name]["_sources"] = list(a.strings)
    return out


@needs_real
def test_nsc_resolved_through_obfuscated_resource_path(results):
    for name in (AUTOMATION.name, KDE.name):
        nsc = results[name]["resources"]["network_security_config"]
        assert nsc["path"] == "res/8G.xml" and nsc["error"] is None  # R8 اختصر المسار
    assert results[AUTOMATION.name]["resources"]["network_security_config"]["parsed"]["trusts_user_certificates"]
    kde_net = results[KDE.name]["network"]["cleartext"]["effective"]
    assert kde_net == {"permitted": True, "decided_by": "network_security_config", "cleartext_domains": []}


@needs_real
def test_resource_strings_and_label(results):
    pkg = results[KDE.name]["resources"]["arsc"]["packages"][0]
    assert pkg["string_count"] == 550 and "KDE Connect" in pkg["strings"].values()
    assert "default" in pkg["locales"] and len(pkg["locales"]) == 92


@needs_real
def test_string_sources(results):
    assert results[KDE.name]["_sources"][:3] == ["classes.dex", "classes2.dex", "resources.arsc"]


@needs_real
def test_real_strings_findings(results):
    auto = results[AUTOMATION.name]["strings"]
    assert "settings put global airplane_mode_on 1" in [i["value"] for i in auto["shell_commands"]]
    assert "Superuser.apk" in [i["value"] for i in auto["suspicious"]]
    kde = results[KDE.name]["strings"]
    assert "https://bugs.kde.org/" in [i["value"] for i in kde["urls"]]
    assert kde["shell_commands"] == [] and kde["base64_strings"] == []


@needs_real
def test_namespace_urls_not_counted_as_cleartext(results):
    net = results[AUTOMATION.name]["network"]
    assert all("schemas.android.com" not in u["value"] for u in net["urls"]["http"])
    assert any("schemas.android.com" in u["value"] for u in net["namespace_urls"])


@needs_real
def test_oids_not_reported_as_servers(results):
    net = results[KDE.name]["network"]
    assert not [h for h in net["hardcoded_servers"] if h["type"] == "public_ip"]
    assert net["counts"]["ambiguous_ips"] > 0


@needs_real
def test_metadata_consistent_with_specialized_analyzers(results):
    for name, r in results.items():
        m = r["metadata"]
        assert m["permission_count"] == r["permissions"]["counts"]["requested"], name
        assert m["component_count"] == r["components"]["total"], name


@needs_real
def test_hardware_real(results):
    hw = results[KDE.name]["hardware"]
    assert hw["required"] == [] and "android.hardware.telephony" in hw["optional"]


@needs_real
def test_text_assets_scanned(tmp_path):
    cfg = b'{"server": "http://45.33.32.156:8080/gate.php", "backup": "c2.evil-domain.ru:4444"}'
    a = load_apk(rebuild(AUTOMATION, {"assets/config.json": cfg}, tmp_path))
    s, n = StringsAnalyzer().analyze(a), NetworkAnalyzer().analyze(a)
    url = next(u for u in s["urls"] if u["value"] == "http://45.33.32.156:8080/gate.php")
    assert url["sources"] == ["assets/config.json"]
    assert "http://45.33.32.156:8080" in n["non_standard_ports"]
    types = {(h["type"], h["value"]) for h in n["hardcoded_servers"]}
    assert ("ip_url", "http://45.33.32.156:8080") in types
