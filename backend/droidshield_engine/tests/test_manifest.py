"""
اختبارات تحليل الـ Manifest (الأذونات، المكوّنات، معلومات التطبيق).

مجموعتان:
    1) XML مكتوب يدوياً: لاختبار كل حالة حدّية بدقة (sdk-23، إذن مزيّف، exported الافتراضي...).
       الدوال extract_* نقية (تأخذ شجرة XML)، لذلك لا نحتاج APK حقيقياً لكل حالة.
    2) تطبيقات حقيقية: نقارن الأذونات مع فهرس F-Droid (مرجع مستقل استخرجه F-Droid على خوادمه).
"""
import json
from pathlib import Path

import pytest
from lxml import etree

from droidshield_engine.analyzers import ComponentAnalyzer, ManifestAnalyzer, PermissionAnalyzer
from droidshield_engine.analyzers.aosp_permissions import decode_protection_level
from droidshield_engine.analyzers.component_analyzer import extract_components
from droidshield_engine.analyzers.manifest_analyzer import extract_manifest_info
from droidshield_engine.analyzers.manifest_xml import resolve_class_name
from droidshield_engine.analyzers.permission_analyzer import extract_permissions
from droidshield_engine.core import load_apk

PKG = "com.example.app"
REF = Path("E:/apk_test/fdroid_reference.json")
needs_real = pytest.mark.skipif(not REF.exists(), reason="مرجع F-Droid غير متوفر")


def manifest(body: str = "", app: str = "", app_attrs: str = "") -> etree._Element:
    return etree.fromstring(
        f'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{PKG}">'
        f'{body}<application {app_attrs}>{app}</application></manifest>'
    )


def perm(name, tag="uses-permission", extra=""):
    return f'<{tag} android:name="{name}" {extra}/>'


def perms(xml, target=30):
    return extract_permissions(xml, PKG, target)


# ============================ Permissions ============================ #
def test_sdk23_permission_is_requested():
    """الثغرة في Androguard 4.1.4: get_permissions() تتجاهل هذا الوسم. نحن لا."""
    r = perms(manifest(perm("android.permission.SEND_SMS", "uses-permission-sdk-23")))
    assert r["requested_names"] == ["android.permission.SEND_SMS"]
    assert r["sdk23_only"] == ["android.permission.SEND_SMS"]


def test_both_tags_merged_and_duplicates_reported():
    xml = manifest(perm("android.permission.CAMERA") + perm("android.permission.CAMERA")
                   + perm("android.permission.CAMERA", "uses-permission-sdk-23"))
    r = perms(xml)
    assert r["requested_names"] == ["android.permission.CAMERA"]       # مرة واحدة فقط
    assert r["requested"][0]["tags"] == ["uses-permission", "uses-permission-sdk-23"]
    assert r["duplicates"] == ["android.permission.CAMERA"]
    assert r["sdk23_only"] == []


def test_custom_permission_with_same_suffix_is_not_android():
    """com.evil.app.SEND_SMS ليس SEND_SMS الحقيقي."""
    r = perms(manifest(perm("com.evil.app.SEND_SMS")))
    assert r["android_permissions"] == []
    assert r["custom"] == ["com.evil.app.SEND_SMS"]


def test_declared_is_not_requested():
    xml = manifest('<permission android:name="com.example.app.MY_PERM" android:protectionLevel="0x2"/>')
    r = perms(xml)
    assert r["requested_names"] == []
    assert r["declared"][0]["name"] == "com.example.app.MY_PERM"
    assert r["declared"][0]["protection_level"]["base"] == "signature"


def test_requesting_own_declared_permission():
    xml = manifest('<permission android:name="com.example.app.P"/>' + perm("com.example.app.P"))
    assert perms(xml)["requested"][0]["category"] == "declared_by_app"


def test_misplaced_permission_ignored():
    """uses-permission داخل <application> يتجاهله Android، فلا نعدّه طلباً."""
    r = perms(manifest(app=perm("android.permission.READ_SMS")))
    assert r["requested_names"] == []
    assert r["misplaced"] == ["android.permission.READ_SMS"]


def test_unrecognized_android_permission():
    r = perms(manifest(perm("android.permission.TOTALLY_FAKE_PERMISSION")))
    assert r["unrecognized_android"] == ["android.permission.TOTALLY_FAKE_PERMISSION"]
    # يبقى إذن android رسمي الصيغة؛ قرار دخوله المتجه يعود للـ Schema وليس لنا
    assert r["android_permissions"] == ["android.permission.TOTALLY_FAKE_PERMISSION"]


def test_legacy_permission_still_recognized():
    """أذونات حُذفت من Android الحديث لكنها في الـ Schema (مثل READ_SOCIAL_STREAM)."""
    r = perms(manifest(perm("android.permission.READ_SOCIAL_STREAM")), target=34)
    assert r["requested"][0]["category"] == "aosp"


def test_protection_level_from_aosp():
    r = perms(manifest(perm("android.permission.SEND_SMS") + perm("android.permission.INTERNET")))
    levels = {x["name"]: x["protection_level"] for x in r["requested"]}
    assert levels["android.permission.SEND_SMS"]["base"] == "dangerous"
    assert levels["android.permission.INTERNET"] == {"raw": "normal|instant", "base": "normal", "flags": ["instant"]}
    assert r["by_protection_level"] == {"dangerous": ["android.permission.SEND_SMS"],
                                        "normal": ["android.permission.INTERNET"]}
    assert r["counts"]["dangerous"] == 1


def test_max_sdk_version_and_empty_name():
    xml = manifest(perm("android.permission.WRITE_EXTERNAL_STORAGE", extra='android:maxSdkVersion="28"')
                   + '<uses-permission android:name=""/>')
    r = perms(xml)
    assert r["requested"][0]["max_sdk_version"] == 28
    assert r["invalid_entries"] == 1


@pytest.mark.parametrize("raw,base,flags", [
    (None, "normal", []),
    ("0x00000001", "dangerous", []),
    ("0x00000012", "signature", ["privileged"]),
    ("signature|privileged", "signature", ["privileged"]),
    ("0x00000062", "signature", ["development", "appop"]),
])
def test_decode_protection_level(raw, base, flags):
    d = decode_protection_level(raw)
    assert (d["base"], d["flags"]) == (base, flags)


# ============================ Components ============================ #
def comps(xml, target=30, min_sdk=21):
    return extract_components(xml, PKG, target, min_sdk)


FILTER = '<intent-filter><action android:name="com.x.ACTION"/></intent-filter>'


@pytest.mark.parametrize("name,expected", [
    (".Main", f"{PKG}.Main"), ("Main", f"{PKG}.Main"), ("a.b.Main", "a.b.Main"), (None, None),
])
def test_resolve_class_name(name, expected):
    assert resolve_class_name(name, PKG) == expected


def test_exported_explicit():
    r = comps(manifest(app='<activity android:name=".A" android:exported="true"/>'
                           '<activity android:name=".B" android:exported="false">' + FILTER + '</activity>'))
    a, b = r["activities"]
    assert (a["exported"], a["exported_explicit"]) == (True, True)
    assert b["exported"] is False  # الصريح يتقدم على وجود intent-filter


def test_exported_default_depends_on_intent_filter():
    r = comps(manifest(app='<service android:name=".WithFilter">' + FILTER + '</service>'
                           '<service android:name=".NoFilter"/>'))
    with_f, no_f = r["services"]
    assert (with_f["exported"], with_f["exported_explicit"]) == (True, False)
    assert no_f["exported"] is False


@pytest.mark.parametrize("target,min_sdk,expected", [(16, 9, True), (30, 21, False), (30, 16, True)])
def test_provider_exported_default(target, min_sdk, expected):
    r = comps(manifest(app='<provider android:name=".P" android:authorities="a;b"/>'), target, min_sdk)
    p = r["providers"][0]
    assert p["exported"] is expected and p["authorities"] == ["a", "b"]


def test_exported_resource_reference_is_unknown():
    r = comps(manifest(app='<receiver android:name=".R" android:exported="@7F050001"/>'))
    assert r["receivers"][0]["exported"] is None


def test_exposed_requires_no_permission_and_enabled():
    app = ('<receiver android:name=".Open" android:exported="true"/>'
           '<receiver android:name=".Guarded" android:exported="true" android:permission="android.permission.BROADCAST_SMS"/>'
           '<receiver android:name=".Off" android:exported="true" android:enabled="false"/>')
    r = comps(manifest(app=app))
    assert [c["name"] for c in r["receivers"] if c["exposed"]] == [f"{PKG}.Open"]
    assert r["summary"]["receivers"] == {"total": 3, "exported": 3, "exposed": 1, "disabled": 1}


def test_application_permission_inherited():
    r = comps(manifest(app='<activity android:name=".A" android:exported="true"/>',
                       app_attrs='android:permission="com.example.app.P"'))
    a = r["activities"][0]
    assert a["permission"] == "com.example.app.P" and a["permission_inherited"] and not a["exposed"]


def test_application_disabled_disables_all():
    r = comps(manifest(app='<activity android:name=".A" android:exported="true"/>',
                       app_attrs='android:enabled="false"'))
    assert r["activities"][0]["enabled"] is False and not r["activities"][0]["exposed"]


def test_provider_protected_by_read_and_write_permissions():
    r = comps(manifest(app='<provider android:name=".P" android:authorities="x" android:exported="true" '
                           'android:readPermission="r.P" android:writePermission="w.P"/>'))
    assert r["providers"][0]["exposed"] is False


def test_launcher_alias_intent_filters_and_actions():
    launcher = ('<intent-filter android:priority="999"><action android:name="android.intent.action.MAIN"/>'
                '<category android:name="android.intent.category.LAUNCHER"/>'
                '<data android:scheme="https" android:host="x.com"/></intent-filter>')
    app = (f'<activity android:name=".Real"/>'
           f'<activity-alias android:name=".Alias" android:targetActivity=".Real">{launcher}</activity-alias>')
    r = comps(manifest(app=app))
    assert r["launcher_activities"] == [f"{PKG}.Alias"]
    alias = r["activity_aliases"][0]
    assert alias["target_activity"] == f"{PKG}.Real"
    assert alias["intent_filters"][0]["priority"] == 999
    assert alias["intent_filters"][0]["data"] == [{"scheme": "https", "host": "x.com"}]
    assert r["intent_actions"] == ["android.intent.action.MAIN"]


def test_duplicate_and_misplaced_components():
    xml = manifest(body='<service android:name=".Outside"/>',
                   app='<service android:name=".S"/><service android:name=".S"/>')
    r = comps(xml)
    assert r["duplicates"] == [f"services:{PKG}.S"]
    assert r["misplaced"] == [".Outside"]
    assert r["summary"]["services"]["total"] == 2  # المكرر يُسجَّل كما في الـ Manifest


# ============================ Application info ============================ #
def test_flag_defaults_when_absent():
    m = extract_manifest_info(manifest(), PKG, 30)
    assert m["flags"]["allow_backup"] == {"raw": None, "value": True, "default_used": True}
    assert m["flags"]["debuggable"]["value"] is False


@pytest.mark.parametrize("target,expected", [(27, True), (28, False)])
def test_cleartext_default_depends_on_target_sdk(target, expected):
    assert extract_manifest_info(manifest(), PKG, target)["flags"]["uses_cleartext_traffic"]["value"] is expected


def test_explicit_flags_and_attributes():
    m = extract_manifest_info(
        manifest(body='<queries><package android:name="com.bank.app"/><intent/></queries>',
                 app='<uses-library android:name="org.apache.http.legacy" android:required="false"/>',
                 app_attrs='android:debuggable="true" android:allowBackup="false" android:name=".App" '
                           'android:networkSecurityConfig="@7F150011"'),
        PKG, 30)
    assert m["flags"]["debuggable"]["value"] is True
    assert m["flags"]["allow_backup"]["value"] is False
    assert m["application"]["class_name"] == f"{PKG}.App"
    assert m["cleartext_note"] is not None
    assert m["queries"] == {"packages": ["com.bank.app"], "intents": 1, "providers": []}
    assert m["uses_libraries"] == [{"name": "org.apache.http.legacy", "required": False}]


@pytest.mark.parametrize("pkg,valid", [("com.example.app", True), ("app", False), ("1com.x", False)])
def test_package_name_validation(pkg, valid):
    assert extract_manifest_info(manifest(), pkg, 30)["package_name_valid"] is valid


# ============================ Real APKs ============================ #
@pytest.fixture(scope="module")
def real():
    ref = json.loads(REF.read_text(encoding="utf-8"))
    out = {}
    for pkg, exp in ref.items():
        apk = load_apk(Path("E:/apk_test/dl") / Path(exp["file"]).name)
        out[pkg] = (exp, {a.name: a.analyze(apk) for a in
                          (PermissionAnalyzer(), ComponentAnalyzer(), ManifestAnalyzer())})
    return out


@needs_real
def test_permissions_match_fdroid_exactly(real):
    for pkg, (exp, r) in real.items():
        assert set(r["permissions"]["requested_names"]) == set(exp["permissions"]), pkg


@needs_real
def test_real_kde_values(real):
    _, r = real["org.kde.kdeconnect_tp"]
    assert r["manifest"]["app_name"] == "KDE Connect"
    assert r["manifest"]["flags"]["allow_backup"]["value"] is False
    assert r["components"]["summary"]["activities"]["total"] == 21
    assert r["components"]["launcher_activities"] == [r["components"]["main_activity"]]
    assert r["permissions"]["declared"][0]["protection_level"]["base"] == "signature"


@needs_real
def test_results_are_json_serializable(real):
    for _, r in real.values():
        json.dumps(r, ensure_ascii=False)
