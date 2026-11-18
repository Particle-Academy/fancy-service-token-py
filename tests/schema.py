"""A first-party validator for the keywords envelope.schema.json uses.

type, required, properties, enum, pattern, minLength, maxLength, items,
minItems, minimum, additionalProperties and a local $ref. Any other keyword in
the schema is reported as an error rather than silently ignored, so a schema
that grows a keyword this does not understand fails the suite instead of
passing everything.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

SCHEMA_PATH = Path(__file__).resolve().parent / "fixtures" / "envelope.schema.json"
# Copied unchanged from fancy-http-errors/envelope.schema.json (identical to
# fancy-conformance suites/http/error-envelope/envelope.schema.json).
SCHEMA_SHA256 = "af4fc3e4bbd9dc29fa32cb3a6ea8d7285d84036a7b5e52daa47e29d8e6516509"

MESSAGES_PATH = Path(__file__).resolve().parent.parent / "conformance" / "refusal-messages.json"
# Pinned in the Python and Node legs: the refusal sentences are identical in
# both by test result, not by care.
MESSAGES_SHA256 = "80a951939bd9fcca2e555bbdd337a60481966a0ec3adabed573c46c735e231eb"

UUID_V4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")

_KNOWN = {
    "$schema",
    "$id",
    "$defs",
    "$ref",
    "title",
    "description",
    "type",
    "required",
    "properties",
    "enum",
    "pattern",
    "minLength",
    "maxLength",
    "items",
    "minItems",
    "minimum",
    "additionalProperties",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_schema() -> dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_bytes().decode("utf-8"))


def load_messages() -> dict[str, Any]:
    return json.loads(MESSAGES_PATH.read_bytes().decode("utf-8"))


def _type_of(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, int):
        return "integer"
    if isinstance(v, float):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "array"
    if isinstance(v, dict):
        return "object"
    return type(v).__name__


def validate(value: Any, root: dict[str, Any] | None = None) -> list[str]:
    """Every violation as "path: problem". Empty means valid."""
    schema = root if root is not None else load_schema()
    errors: list[str] = []

    def walk(v: Any, s: dict[str, Any], path: str) -> None:
        errors.extend(f"{path}: schema keyword {k} is not supported" for k in s if k not in _KNOWN)
        ref = s.get("$ref")
        if isinstance(ref, str):
            target = schema.get("$defs", {}).get(ref.removeprefix("#/$defs/"))
            if target is None:
                errors.append(f"{path}: unresolved $ref {ref}")
            else:
                walk(v, target, path)
            return
        want = s.get("type")
        if isinstance(want, str):
            got = _type_of(v)
            if not (want == got or (want == "number" and got in ("number", "integer"))):
                errors.append(f"{path}: expected {want}, got {got}")
                return
        if "enum" in s and v not in s["enum"]:
            errors.append(f"{path}: not in enum")
        if isinstance(v, str):
            if "pattern" in s and re.search(s["pattern"], v) is None:
                errors.append(f"{path}: does not match {s['pattern']}")
            if "minLength" in s and len(v) < s["minLength"]:
                errors.append(f"{path}: shorter than {s['minLength']}")
            if "maxLength" in s and len(v) > s["maxLength"]:
                errors.append(f"{path}: longer than {s['maxLength']}")
        if isinstance(v, int | float) and not isinstance(v, bool) and "minimum" in s and v < s["minimum"]:
            errors.append(f"{path}: below {s['minimum']}")
        if isinstance(v, list):
            if "minItems" in s and len(v) < s["minItems"]:
                errors.append(f"{path}: fewer than {s['minItems']} items")
            if isinstance(s.get("items"), dict):
                for i, item in enumerate(v):
                    walk(item, s["items"], f"{path}[{i}]")
        if isinstance(v, dict):
            props = s.get("properties", {})
            errors.extend(f"{path}: missing {r}" for r in s.get("required", []) if r not in v)
            for k, child in v.items():
                if k in props:
                    walk(child, props[k], f"{path}.{k}")
                elif s.get("additionalProperties") is False:
                    errors.append(f"{path}: unexpected member {k}")

    walk(value, schema, "$")
    return errors
