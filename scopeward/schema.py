"""A focused, stdlib-only JSON Schema (draft 2020-12) validator.

scopeward ships a real JSON Schema for its scope document
(``schema/scope.schema.json``) and validates against it with no third-party
dependency. Rather than pull in ``jsonschema``, this module implements exactly
the keyword subset the scope schema uses, honestly and with structured error
paths. It is deliberately *not* a general validator — unimplemented keywords are
ignored, which is fine because we control the schema.

Supported keywords: ``type``, ``required``, ``properties``,
``additionalProperties`` (bool), ``items``, ``enum``, ``minItems``,
``minLength``, ``pattern`` (Python ``re``), and ``format: date-time``.

Each error is a :class:`SchemaError` carrying a JSON-pointer-ish ``path`` so a
caller can point at the exact offending field.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

_TYPE_CHECKS = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "boolean": lambda v: isinstance(v, bool),
    # note: bool is a subclass of int; exclude it from integer/number.
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "null": lambda v: v is None,
}


@dataclass(frozen=True)
class SchemaError:
    """A single validation failure with a location and message."""

    path: str
    message: str

    def __str__(self) -> str:  # pragma: no cover - trivial
        loc = self.path or "<root>"
        return f"{loc}: {self.message}"


class SchemaValidationError(Exception):
    """Raised by :func:`validate` when ``errors`` is non-empty (aggregate)."""

    def __init__(self, errors: list[SchemaError]) -> None:
        self.errors = errors
        super().__init__(
            f"{len(errors)} schema violation(s): "
            + "; ".join(str(e) for e in errors[:5])
            + (" …" if len(errors) > 5 else "")
        )


def _is_date_time(value: str) -> bool:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        datetime.fromisoformat(text)
        return True
    except ValueError:
        return False


def _join(path: str, key: Any) -> str:
    return f"{path}/{key}" if path else str(key)


def iter_errors(instance: Any, schema: dict[str, Any], path: str = "") -> list[SchemaError]:
    """Return all validation errors of ``instance`` against ``schema``.

    An empty list means the instance is valid.
    """
    errors: list[SchemaError] = []

    # type
    expected_type = schema.get("type")
    if expected_type is not None:
        types = expected_type if isinstance(expected_type, list) else [expected_type]
        if not any(_TYPE_CHECKS.get(t, lambda _v: True)(instance) for t in types):
            errors.append(SchemaError(path, f"expected type {expected_type!r}"))
            return errors  # further keyword checks assume the type matched

    # enum
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(SchemaError(path, f"value {instance!r} not in enum {schema['enum']!r}"))

    # string constraints
    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errors.append(SchemaError(path, f"shorter than minLength {schema['minLength']}"))
        if "pattern" in schema and re.search(schema["pattern"], instance) is None:
            errors.append(SchemaError(path, f"does not match pattern {schema['pattern']!r}"))
        if schema.get("format") == "date-time" and not _is_date_time(instance):
            errors.append(SchemaError(path, "is not a valid date-time"))

    # array constraints
    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errors.append(SchemaError(path, f"fewer than minItems {schema['minItems']}"))
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for i, item in enumerate(instance):
                errors.extend(iter_errors(item, item_schema, _join(path, i)))

    # object constraints
    if isinstance(instance, dict):
        for req in schema.get("required", []):
            if req not in instance:
                errors.append(SchemaError(_join(path, req), "required property is missing"))
        props: dict[str, Any] = schema.get("properties", {})
        for key, value in instance.items():
            if key in props:
                errors.extend(iter_errors(value, props[key], _join(path, key)))
            elif schema.get("additionalProperties") is False:
                errors.append(SchemaError(_join(path, key), "additional property is not allowed"))

    return errors


def load_schema(path: "str | Path | None" = None) -> dict[str, Any]:
    """Load the packaged scope schema (or a schema at ``path``)."""
    if path is None:
        path = default_schema_path()
    return json.loads(Path(path).read_text(encoding="utf-8"))


def default_schema_path() -> Path:
    """Absolute path to the scope JSON Schema.

    Works both from a source clone (``repo_root/schema/``) and from an installed
    wheel, where the schema is bundled at ``scopeward/_schema/`` (see
    ``pyproject.toml`` force-include).
    """
    pkg_dir = Path(__file__).resolve().parent
    bundled = pkg_dir / "_schema" / "scope.schema.json"
    if bundled.exists():
        return bundled
    return pkg_dir.parent / "schema" / "scope.schema.json"


def validate(instance: Any, schema: "dict[str, Any] | None" = None) -> None:
    """Validate ``instance``; raise :class:`SchemaValidationError` if invalid."""
    if schema is None:
        schema = load_schema()
    errors = iter_errors(instance, schema)
    if errors:
        raise SchemaValidationError(errors)


def validate_document(instance: Any, schema: "dict[str, Any] | None" = None) -> list[SchemaError]:
    """Non-raising validation: return the list of errors (empty == valid)."""
    if schema is None:
        schema = load_schema()
    return iter_errors(instance, schema)
