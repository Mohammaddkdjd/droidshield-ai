"""
اختبارات Feature Mapping — أهم اختبارات المشروع.

ثلاثة مستويات من التحقق:
    1) الاختبارات الإلزامية من المواصفات (الطول، النوع، القيم، Label، الترتيب).
    2) Round-trip على كل صفوف الـ Dataset الفريدة: نحوّل كل صف إلى قائمة أذونات كما
       يكتبها Android، ثم نعيد بناء المتجه؛ يجب أن نحصل على الصف نفسه حرفياً.
       هذا يثبت أن كل عمود في المتجه يحمل نفس دلالة العمود في الـ Dataset.
    3) تطبيقات حقيقية: المتجه المبني من تحليلنا = المتجه المبني من مرجع F-Droid المستقل.
"""
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from droidshield_engine import config
from droidshield_engine.analyzers import PermissionAnalyzer
from droidshield_engine.analyzers.permission_analyzer import extract_permissions
from droidshield_engine.feature_extraction import (
    FeatureMapper, FeatureVectorError, load_feature_schema,
)
from droidshield_engine.core import load_apk
from lxml import etree

P = "android.permission."
REF = Path("E:/apk_test/fdroid_reference.json")
needs_real = pytest.mark.skipif(not REF.exists(), reason="مرجع F-Droid غير متوفر")


@pytest.fixture(scope="module")
def mapper():
    return FeatureMapper()


@pytest.fixture(scope="module")
def schema():
    return load_feature_schema()


# ========================= الاختبارات الإلزامية ========================= #
def test_mandatory_assertions(mapper, schema):
    feature_vector = mapper.map_permissions([P + "RECORD_AUDIO", P + "INTERNET", P + "CAMERA", P + "READ_SMS"]).values
    feature_schema = schema.features
    assert len(feature_schema) == 110
    assert "Label" not in feature_schema
    assert feature_vector.shape == (110,)
    assert feature_vector.dtype == np.int8
    assert set(np.unique(feature_vector)).issubset({0, 1})


def test_spec_example(mapper):
    """المثال من المواصفات حرفياً."""
    fv = mapper.map_permissions([P + "RECORD_AUDIO", P + "INTERNET", P + "CAMERA", P + "READ_SMS"])
    d = fv.as_dict()
    assert {k: d[k] for k in ("RECORD_AUDIO", "INTERNET", "CAMERA", "READ_SMS")} == dict.fromkeys(
        ("RECORD_AUDIO", "INTERNET", "CAMERA", "READ_SMS"), 1)
    assert sum(d.values()) == 4
    assert fv.matched == ("RECORD_AUDIO", "READ_SMS", "CAMERA", "INTERNET")  # بترتيب الـ Schema لا الإدخال


def test_names_follow_dataset_column_order(mapper):
    with config.DATASET_PATH.open(encoding="utf-8") as f:
        header = f.readline().strip().split(",")
    assert list(mapper.feature_names) == [c for c in header if c != "Label"]
    assert list(mapper.map_permissions([]).as_dict()) == list(mapper.feature_names)


def test_each_position_maps_to_its_own_column(mapper, schema):
    """إذن واحد في كل مرة -> الواحد يظهر في موضع عموده بالضبط ولا غيره."""
    for i, name in enumerate(schema.features):
        v = mapper.map_permissions([P + name]).values
        assert v[i] == 1 and v.sum() == 1, name


def test_all_permissions_gives_all_ones(mapper, schema):
    assert mapper.map_permissions([P + n for n in schema.features]).values.sum() == 110


def test_empty_and_zero_vector(mapper):
    fv = mapper.empty_vector()
    assert fv.values.sum() == 0 and fv.matched == () and fv.validation["passed"]


# ========================= حالات المطابقة الحدّية ========================= #
def test_custom_permission_with_same_suffix_not_matched(mapper):
    fv = mapper.map_permissions(["com.evil.app.SEND_SMS", "SEND_SMS", "com.google.android.c2dm.permission.RECEIVE"])
    assert fv.values.sum() == 0
    assert fv.ignored_non_android == ("SEND_SMS", "com.evil.app.SEND_SMS", "com.google.android.c2dm.permission.RECEIVE")


def test_case_sensitive_no_fuzzy(mapper):
    fv = mapper.map_permissions([P + "send_sms", P + "SEND_SMS_", P + "SENDSMS", " " + P + "SEND_SMS"])
    assert fv.values.sum() == 0
    assert set(fv.unmapped_android) == {P + "send_sms", P + "SEND_SMS_", P + "SENDSMS"}


def test_android_permissions_outside_schema_are_reported_not_added(mapper):
    fv = mapper.map_permissions([P + "FOREGROUND_SERVICE", P + "POST_NOTIFICATIONS", P + "CAMERA"])
    assert fv.matched == ("CAMERA",)
    assert fv.unmapped_android == (P + "FOREGROUND_SERVICE", P + "POST_NOTIFICATIONS")
    assert len(fv) == 110  # لا خصائص جديدة مهما كان عدد الأذونات الإضافية


def test_duplicates_counted_once(mapper):
    fv = mapper.map_permissions([P + "CAMERA"] * 3 + [P + "INTERNET"])
    assert fv.values.sum() == 2 and fv.duplicate_inputs == (P + "CAMERA",)


def test_label_cannot_enter_vector(mapper):
    fv = mapper.map_permissions([P + "Label", "Label"])
    assert fv.values.sum() == 0 and "Label" not in fv.feature_names


def test_vector_is_read_only(mapper):
    v = mapper.map_permissions([P + "CAMERA"]).values
    with pytest.raises(ValueError):
        v[0] = 1


def test_map_analysis_uses_only_requested_names(mapper):
    """أي حقل آخر (declared, implied, ...) لا يؤثر على المتجه."""
    result = {"requested_names": [P + "CAMERA"], "declared": [{"name": P + "SEND_SMS"}],
              "implied": [P + "READ_PHONE_STATE"], "android_permissions": [P + "READ_SMS"]}
    assert mapper.map_analysis(result).matched == ("CAMERA",)
    with pytest.raises(KeyError):
        mapper.map_analysis({"android_permissions": [P + "CAMERA"]})


def test_sdk23_permission_reaches_vector(mapper):
    """من الـ XML إلى المتجه: الإذن عبر uses-permission-sdk-23 يجب أن يصبح 1."""
    xml = etree.fromstring('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="a.b">'
                           f'<uses-permission-sdk-23 android:name="{P}SEND_SMS"/>'
                           f'<uses-permission android:name="com.evil.READ_SMS"/>'
                           f'<application><uses-permission android:name="{P}CAMERA"/></application></manifest>')
    fv = mapper.map_analysis(extract_permissions(xml, "a.b", 30))
    assert fv.matched == ("SEND_SMS",)  # sdk-23 نعم؛ المخصص لا؛ الموضوع في مكان خاطئ لا


def test_validation_rejects_tampered_vector(mapper, schema):
    fv = mapper.map_permissions([P + "CAMERA"])
    bad = [
        dict(values=fv.values.astype(np.int64)),
        dict(values=np.append(fv.values, 0)),
        dict(feature_names=tuple(reversed(fv.feature_names))),
        dict(schema_fingerprint="0" * 64),
        dict(matched=("INTERNET",)),
    ]
    for change in bad:
        tampered = type(fv)(**{**fv.__dict__, **change})
        with pytest.raises(FeatureVectorError):
            tampered.validate(schema)


def test_json_output(mapper):
    j = mapper.map_permissions([P + "CAMERA", P + "FOREGROUND_SERVICE"]).to_json()
    json.dumps(j)
    assert j["length"] == 110 and j["dtype"] == "int8" and j["ones"] == 1
    assert j["schema_fingerprint"] == config.EXPECTED_SCHEMA_SHA256
    assert list(j["vector"])[0] == "RECORD_AUDIO" and j["validation"]["passed"]


# ===================== Round-trip على صفوف الـ Dataset ===================== #
def test_roundtrip_every_unique_dataset_row(mapper):
    """
    لكل صف فريد: الأعمدة التي قيمتها 1 -> android.permission.<اسم العمود> -> المتجه.
    يجب أن يطابق المتجه الصف حرفياً، بنفس الترتيب. (3,580 صفاً فريداً)
    """
    df = pd.read_csv(config.DATASET_PATH).drop(columns="Label").drop_duplicates()
    assert list(df.columns) == list(mapper.feature_names)
    rows = df.to_numpy(dtype=np.int8)
    cols = np.array(df.columns)
    for row in rows:
        perms = [P + c for c in cols[row == 1]]
        assert np.array_equal(mapper.map_permissions(perms).values, row)
    assert len(rows) > 3000


# ========================= تطبيقات حقيقية ========================= #
@needs_real
def test_real_apps_vector_matches_fdroid_reference(mapper, schema):
    """
    المتجه من تحليلنا الكامل (APK -> Manifest -> permission_analyzer -> mapper)
    يجب أن يساوي متجهاً مبنياً بكود مستقل بسيط من أذونات فهرس F-Droid.
    """
    ref = json.loads(REF.read_text(encoding="utf-8"))
    for pkg, exp in ref.items():
        apk = load_apk(Path("E:/apk_test/dl") / Path(exp["file"]).name)
        fv = mapper.map_analysis(PermissionAnalyzer().analyze(apk))
        expected = np.array([int(P + name in set(exp["permissions"])) for name in schema.features], dtype=np.int8)
        assert np.array_equal(fv.values, expected), pkg
        assert fv.validation["passed"]


@needs_real
def test_real_apps_known_values(mapper):
    apk = load_apk("E:/apk_test/dl/org.kde.kdeconnect_tp_13702.apk")
    fv = mapper.map_analysis(PermissionAnalyzer().analyze(apk))
    d = fv.as_dict()
    assert d["SEND_SMS"] == d["READ_SMS"] == d["INTERNET"] == 1     # KDE Connect يرسل SMS من الحاسوب
    assert d["INSTALL_PACKAGES"] == d["MASTER_CLEAR"] == 0
    assert P + "FOREGROUND_SERVICE" in fv.unmapped_android         # إذن حديث خارج الـ Dataset
