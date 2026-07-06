import json
from pathlib import Path

import pytest

from scopeward.schema import (
    validate,
    validate_document,
    iter_errors,
    load_schema,
    default_schema_path,
    SchemaValidationError,
)


@pytest.fixture(scope="module")
def scope_schema():
    return load_schema()


def _valid_doc():
    return {
        "engagement_id": "E",
        "client": "C",
        "authorized_by": "A",
        "roe": "R",
        "not_before": "2026-01-01T00:00:00Z",
        "not_after": "2026-12-31T00:00:00Z",
        "targets": [{"platform": "android", "app_id": "com.x"}],
        "allowed_modules": ["apkprobe"],
    }


def test_schema_file_exists_and_parses():
    p = default_schema_path()
    assert p.exists()
    data = json.loads(p.read_text(encoding="utf-8"))
    assert data["$schema"].endswith("2020-12/schema")


def test_valid_document_passes(scope_schema):
    assert validate_document(_valid_doc(), scope_schema) == []
    validate(_valid_doc(), scope_schema)  # does not raise


def test_example_file_is_valid():
    example = default_schema_path().parent.parent / "examples" / "engagement.example.json"
    doc = json.loads(example.read_text(encoding="utf-8"))
    assert validate_document(doc) == []


def test_missing_required_field(scope_schema):
    doc = _valid_doc()
    del doc["client"]
    errs = validate_document(doc, scope_schema)
    assert any("client" in e.path and "required" in e.message for e in errs)


def test_wrong_type(scope_schema):
    doc = _valid_doc()
    doc["allow_destructive"] = "yes"
    errs = validate_document(doc, scope_schema)
    assert any("allow_destructive" in e.path for e in errs)


def test_additional_property_rejected(scope_schema):
    doc = _valid_doc()
    doc["sneaky"] = True
    errs = validate_document(doc, scope_schema)
    assert any("sneaky" in e.path and "additional" in e.message for e in errs)


def test_empty_targets_rejected(scope_schema):
    doc = _valid_doc()
    doc["targets"] = []
    errs = validate_document(doc, scope_schema)
    assert any("minItems" in e.message for e in errs)


def test_bad_platform_enum(scope_schema):
    doc = _valid_doc()
    doc["targets"][0]["platform"] = "windows"
    errs = validate_document(doc, scope_schema)
    assert any("enum" in e.message for e in errs)


def test_bad_datetime(scope_schema):
    doc = _valid_doc()
    doc["not_before"] = "yesterday"
    errs = validate_document(doc, scope_schema)
    assert any("date-time" in e.message for e in errs)


def test_empty_string_minlength(scope_schema):
    doc = _valid_doc()
    doc["engagement_id"] = ""
    errs = validate_document(doc, scope_schema)
    assert any("minLength" in e.message for e in errs)


def test_bad_signature_pattern(scope_schema):
    doc = _valid_doc()
    doc["signature"] = "NOTHEX"
    errs = validate_document(doc, scope_schema)
    assert any("pattern" in e.message for e in errs)


def test_good_signature_pattern(scope_schema):
    doc = _valid_doc()
    doc["signature"] = "a" * 64
    assert validate_document(doc, scope_schema) == []


def test_grant_capability_enum(scope_schema):
    doc = _valid_doc()
    doc["grants"] = [{"grant_id": "G", "target": "android:com.x", "capabilities": ["root"]}]
    errs = validate_document(doc, scope_schema)
    assert any("enum" in e.message for e in errs)


def test_valid_grants_and_revocations(scope_schema):
    doc = _valid_doc()
    doc["grants"] = [{"grant_id": "G", "target": "android:com.x", "capabilities": ["read"]}]
    doc["revocations"] = [{"kind": "grant", "value": "G"}]
    assert validate_document(doc, scope_schema) == []


def test_bad_revocation_kind(scope_schema):
    doc = _valid_doc()
    doc["revocations"] = [{"kind": "everything", "value": "x"}]
    errs = validate_document(doc, scope_schema)
    assert any("enum" in e.message for e in errs)


def test_validate_raises_aggregate(scope_schema):
    doc = _valid_doc()
    del doc["client"]
    del doc["roe"]
    with pytest.raises(SchemaValidationError) as ei:
        validate(doc, scope_schema)
    assert len(ei.value.errors) >= 2


def test_bool_not_accepted_as_string(scope_schema):
    doc = _valid_doc()
    doc["engagement_id"] = True
    errs = validate_document(doc, scope_schema)
    assert any("type" in e.message for e in errs)


def test_error_path_points_at_nested_field(scope_schema):
    doc = _valid_doc()
    doc["targets"][0]["app_id"] = ""
    errs = validate_document(doc, scope_schema)
    assert any(e.path.startswith("targets/0/app_id") for e in errs)
