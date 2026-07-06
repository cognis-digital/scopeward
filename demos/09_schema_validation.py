"""Demo: validate scope documents against the shipped JSON Schema."""

from __future__ import annotations

from _common import hr
from scopeward.schema import validate_document, default_schema_path


VALID = {
    "engagement_id": "ENG-1",
    "client": "Acme",
    "authorized_by": "jane@acme.example",
    "roe": "authorized",
    "not_before": "2026-01-01T00:00:00Z",
    "not_after": "2026-12-31T00:00:00Z",
    "targets": [{"platform": "android", "app_id": "com.acme.app"}],
    "allowed_modules": ["apkprobe"],
}

INVALID_DOCS = {
    "missing required field (client)": {k: v for k, v in VALID.items() if k != "client"},
    "unknown platform enum": {**VALID, "targets": [{"platform": "windows", "app_id": "x"}]},
    "empty targets array": {**VALID, "targets": []},
    "additional property": {**VALID, "backdoor": True},
    "bad datetime": {**VALID, "not_before": "sometime"},
    "malformed signature": {**VALID, "signature": "NOT-HEX"},
}


def main() -> int:
    hr("9. JSON Schema validation")
    print(f"schema: {default_schema_path().name} (draft 2020-12)\n")

    errs = validate_document(VALID)
    print(f"valid document -> {len(errs)} error(s)")
    assert errs == []

    print("\ninvalid documents are rejected with a located reason:")
    for label, doc in INVALID_DOCS.items():
        errs = validate_document(doc)
        assert errs, f"{label} should have failed"
        print(f"  [{label}]")
        for e in errs[:2]:
            print(f"     - {e}")

    print("\nOK: the schema accepts good docs and pinpoints bad ones.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
