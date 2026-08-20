"""Small fail-closed JSON Schema subset for the zero-dependency plugin core.

The plugin host only accepts schemas composed from the keywords implemented in
this module.  Rejecting unknown keywords is intentional: accepting a schema we
cannot enforce would turn capability contracts into advisory metadata.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from typing import Any


class PluginSchemaError(ValueError):
    """A capability schema or invocation document is invalid."""


_SUPPORTED_KEYWORDS = frozenset(
    {
        "additionalProperties",
        "enum",
        "items",
        "maxItems",
        "maxLength",
        "maximum",
        "minItems",
        "minLength",
        "minimum",
        "properties",
        "required",
        "type",
    }
)
_JSON_TYPES = frozenset(
    {"array", "boolean", "integer", "null", "number", "object", "string"}
)
_MAX_SCHEMA_DEPTH = 32
_MAX_SCHEMA_PROPERTIES = 256
_MAX_ENUM_ITEMS = 256


def _matches_type(value: Any, schema_type: str) -> bool:
    return {
        "object": lambda item: isinstance(item, Mapping),
        "array": lambda item: isinstance(item, Sequence)
        and not isinstance(item, (str, bytes, bytearray)),
        "string": lambda item: isinstance(item, str),
        "integer": lambda item: type(item) is int,
        "number": lambda item: not isinstance(item, bool)
        and isinstance(item, (int, float))
        and math.isfinite(item),
        "boolean": lambda item: type(item) is bool,
        "null": lambda item: item is None,
    }[schema_type](value)


def validate_schema(
    schema: Mapping[str, Any],
    *,
    path: str = "$schema",
    _depth: int = 0,
) -> None:
    """Validate the supported schema vocabulary before a plugin is installed."""

    if not isinstance(schema, Mapping):
        raise PluginSchemaError(f"{path} must be an object")
    if _depth > _MAX_SCHEMA_DEPTH:
        raise PluginSchemaError(f"{path} exceeds the schema nesting limit")
    unknown = set(schema) - _SUPPORTED_KEYWORDS
    if unknown:
        raise PluginSchemaError(f"{path} has unsupported keywords: {sorted(unknown)}")
    schema_type = schema.get("type")
    if schema_type not in _JSON_TYPES:
        raise PluginSchemaError(f"{path}.type must name one supported JSON type")

    if "enum" in schema:
        enum = schema["enum"]
        if not isinstance(enum, list) or not 0 < len(enum) <= _MAX_ENUM_ITEMS:
            raise PluginSchemaError(
                f"{path}.enum must contain 1..{_MAX_ENUM_ITEMS} scalar values"
            )
        if any(isinstance(item, (Mapping, list, tuple)) for item in enum) or any(
            not _matches_type(item, schema_type) for item in enum
        ):
            raise PluginSchemaError(
                f"{path}.enum values must be scalar values matching the schema type"
            )

    if schema_type == "object":
        properties = schema.get("properties", {})
        if not isinstance(properties, Mapping) or any(
            not isinstance(key, str) for key in properties
        ):
            raise PluginSchemaError(f"{path}.properties must be an object")
        if len(properties) > _MAX_SCHEMA_PROPERTIES:
            raise PluginSchemaError(
                f"{path}.properties exceeds {_MAX_SCHEMA_PROPERTIES} fields"
            )
        if any(not key or len(key.encode("utf-8")) > 128 for key in properties):
            raise PluginSchemaError(f"{path}.properties contains an invalid field name")
        if schema.get("additionalProperties") is not False:
            raise PluginSchemaError(
                f"{path}.additionalProperties must be explicitly false"
            )
        required = schema.get("required", [])
        if not isinstance(required, list) or any(
            not isinstance(item, str) for item in required
        ):
            raise PluginSchemaError(f"{path}.required must be an array of strings")
        if len(required) != len(set(required)) or not set(required) <= set(properties):
            raise PluginSchemaError(
                f"{path}.required must be unique and reference declared properties"
            )
        for key, child in properties.items():
            validate_schema(child, path=f"{path}.properties.{key}", _depth=_depth + 1)
    elif any(key in schema for key in ("properties", "required", "additionalProperties")):
        raise PluginSchemaError(f"{path} uses object keywords for a non-object type")

    if schema_type == "array":
        if "items" not in schema:
            raise PluginSchemaError(f"{path}.items is required for arrays")
        validate_schema(schema["items"], path=f"{path}.items", _depth=_depth + 1)
    elif any(key in schema for key in ("items", "minItems", "maxItems")):
        raise PluginSchemaError(f"{path} uses array keywords for a non-array type")

    for minimum_key, maximum_key, allowed_type in (
        ("minLength", "maxLength", "string"),
        ("minItems", "maxItems", "array"),
    ):
        for key in (minimum_key, maximum_key):
            if key not in schema:
                continue
            if schema_type != allowed_type or type(schema[key]) is not int or schema[key] < 0:
                raise PluginSchemaError(
                    f"{path}.{key} requires a non-negative integer {allowed_type} bound"
                )
        if (
            minimum_key in schema
            and maximum_key in schema
            and schema[minimum_key] > schema[maximum_key]
        ):
            raise PluginSchemaError(f"{path} has an inverted size range")

    for key in ("minimum", "maximum"):
        if key not in schema:
            continue
        if schema_type not in {"integer", "number"} or isinstance(schema[key], bool) or not isinstance(
            schema[key], (int, float)
        ) or not math.isfinite(schema[key]):
            raise PluginSchemaError(f"{path}.{key} requires a numeric schema and value")
    if "minimum" in schema and "maximum" in schema and schema["minimum"] > schema["maximum"]:
        raise PluginSchemaError(f"{path} has an inverted numeric range")


def validate_instance(value: Any, schema: Mapping[str, Any], *, path: str = "$data") -> None:
    """Validate one invocation input or output against a checked schema."""

    schema_type = schema["type"]
    if not _matches_type(value, schema_type):
        raise PluginSchemaError(f"{path} must be {schema_type}")
    if "enum" in schema and value not in schema["enum"]:
        raise PluginSchemaError(f"{path} is outside the allowed enum")

    if schema_type == "object":
        properties = schema.get("properties", {})
        keys = set(value)
        if any(not isinstance(key, str) for key in keys):
            raise PluginSchemaError(f"{path} object keys must be strings")
        missing = set(schema.get("required", [])) - keys
        if missing:
            raise PluginSchemaError(f"{path} is missing required fields: {sorted(missing)}")
        unknown = keys - set(properties)
        if unknown and schema.get("additionalProperties", True) is False:
            raise PluginSchemaError(f"{path} has unknown fields: {sorted(unknown)}")
        for key in keys & set(properties):
            validate_instance(value[key], properties[key], path=f"{path}.{key}")
    elif schema_type == "array":
        length = len(value)
        if "minItems" in schema and length < schema["minItems"]:
            raise PluginSchemaError(f"{path} has too few items")
        if "maxItems" in schema and length > schema["maxItems"]:
            raise PluginSchemaError(f"{path} has too many items")
        for index, item in enumerate(value):
            validate_instance(item, schema["items"], path=f"{path}[{index}]")
    elif schema_type == "string":
        if "minLength" in schema and len(value) < schema["minLength"]:
            raise PluginSchemaError(f"{path} is too short")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            raise PluginSchemaError(f"{path} is too long")
    elif schema_type in {"integer", "number"}:
        if "minimum" in schema and value < schema["minimum"]:
            raise PluginSchemaError(f"{path} is below the minimum")
        if "maximum" in schema and value > schema["maximum"]:
            raise PluginSchemaError(f"{path} exceeds the maximum")


__all__ = ["PluginSchemaError", "validate_instance", "validate_schema"]
