"""
اختبارات Feature Schema.

الفكرة: نتحقق من الـ Schema بطريقتين مستقلتين:
    - عبر الكود (load_feature_schema)
    - عبر قراءة مستقلة للـ CSV بوحدة csv القياسية (لا Pandas)
فإن اتفقتا فالخطأ لا يمكن أن يكون في طريقة القراءة نفسها.
"""
import csv

import pytest

from droidshield_engine import config
from droidshield_engine.feature_extraction import (
    SchemaValidationError,
    load_feature_schema,
    schema_fingerprint,
    validate_columns,
)


@pytest.fixture(scope="module")
def schema():
    return load_feature_schema()


@pytest.fixture(scope="module")
def raw_header():
    with config.DATASET_PATH.open(newline="", encoding="utf-8") as f:
        return next(csv.reader(f))


def write_csv(tmp_path, columns, name="ds.csv"):
    p = tmp_path / name
    p.write_text(",".join(columns) + "\n" + ",".join("0" for _ in columns) + "\n", encoding="utf-8")
    return p


# ------------------------- الاختبارات الإلزامية ------------------------- #
def test_schema_has_110_features(schema):
    assert len(schema) == 110


def test_label_not_in_schema(schema):
    assert "Label" not in schema
    assert "Label" not in schema.features


def test_order_matches_dataset_exactly(schema, raw_header):
    """الترتيب = أعمدة الـ CSV بعد حذف Label، عنصراً بعنصر."""
    assert list(schema.features) == [c for c in raw_header if c != "Label"]


def test_label_removed_by_name_not_position(schema, raw_header):
    """Label ليس آخر عمود؛ لو حُذف آخر عمود بدلاً منه لضاع PERSISTENT_ACTIVITY."""
    assert raw_header.index("Label") == 13
    assert raw_header[-1] == "PERSISTENT_ACTIVITY" and "PERSISTENT_ACTIVITY" in schema


def test_not_alphabetical(schema):
    assert list(schema.features) != sorted(schema.features)


def test_first_and_last_features(schema):
    assert schema.features[0] == "RECORD_AUDIO"
    assert schema.features[13] == "WRITE_CALL_LOG"  # العمود الذي يلي Label مباشرة
    assert schema.features[-1] == "PERSISTENT_ACTIVITY"


def test_fingerprint_pinned(schema):
    assert schema.fingerprint == config.EXPECTED_SCHEMA_SHA256


def test_index_of(schema):
    assert schema.index_of("RECORD_AUDIO") == 0
    assert schema.index_of("PERSISTENT_ACTIVITY") == 109
    with pytest.raises(KeyError):
        schema.index_of("FOREGROUND_SERVICE")  # إذن حقيقي لكنه خارج الـ Schema


def test_schema_is_immutable(schema):
    with pytest.raises(AttributeError):
        schema.features = ()
    assert isinstance(schema.features, tuple)


def test_loaded_once(schema):
    assert load_feature_schema() is schema


# ------------------------- حالات فشل يجب أن توقف المحرك ------------------------- #
@pytest.fixture
def good_columns(raw_header):
    return list(raw_header)


def test_valid_columns_pass(good_columns):
    assert len(validate_columns(good_columns)) == 110


def test_missing_label(good_columns):
    good_columns.remove("Label")
    with pytest.raises(SchemaValidationError, match="Label"):
        validate_columns(good_columns)


def test_label_twice(good_columns):
    good_columns[-1] = "Label"
    with pytest.raises(SchemaValidationError, match="مرة"):
        validate_columns(good_columns)


def test_duplicate_feature_detected_from_real_csv(tmp_path, good_columns):
    """Pandas يعيد تسمية المكرر إلى SEND_SMS.1؛ يجب أن يكتشف المحرك التكرار رغم ذلك."""
    good_columns[0] = "SEND_SMS"
    path = write_csv(tmp_path, good_columns)
    with pytest.raises(SchemaValidationError, match="مكررة"):
        load_feature_schema(path)


def test_missing_feature(good_columns):
    good_columns.remove("CAMERA")
    with pytest.raises(SchemaValidationError, match="110"):
        validate_columns(good_columns)


def test_extra_feature(good_columns):
    good_columns.append("FOREGROUND_SERVICE")
    with pytest.raises(SchemaValidationError, match="111"):
        validate_columns(good_columns)


def test_renamed_feature_changes_fingerprint(good_columns):
    good_columns[good_columns.index("CAMERA")] = "CAMERA2"
    with pytest.raises(SchemaValidationError, match="البصمة"):
        validate_columns(good_columns)


def test_reordered_features_rejected(good_columns):
    i, j = good_columns.index("SEND_SMS"), good_columns.index("CAMERA")
    good_columns[i], good_columns[j] = good_columns[j], good_columns[i]
    with pytest.raises(SchemaValidationError, match="ترتيب"):
        validate_columns(good_columns)


def test_whitespace_in_name(good_columns):
    good_columns[0] = " RECORD_AUDIO"
    with pytest.raises(SchemaValidationError, match="مسافات"):
        validate_columns(good_columns)


def test_invalid_name(good_columns):
    good_columns[0] = "android.permission.RECORD_AUDIO"
    with pytest.raises(SchemaValidationError, match="نمط"):
        validate_columns(good_columns)


def test_all_problems_reported_together(good_columns):
    good_columns.remove("Label")
    good_columns[0] = "SEND_SMS"
    with pytest.raises(SchemaValidationError) as e:
        validate_columns(good_columns)
    assert len(e.value.problems) >= 3  # العدد + Label + التكرار


def test_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_feature_schema(tmp_path / "nope.csv")


def test_empty_file(tmp_path):
    p = tmp_path / "empty.csv"
    p.write_text("", encoding="utf-8")
    with pytest.raises(Exception):
        load_feature_schema(p)


def test_fingerprint_depends_on_order():
    assert schema_fingerprint(["A", "B"]) != schema_fingerprint(["B", "A"])
