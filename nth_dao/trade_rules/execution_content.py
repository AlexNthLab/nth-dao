"""Content and schema verification for Trade execution claims."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any, Protocol

from nth_dao.trade_rules.canonical import (
    MAX_TRADE_JSON_BYTES,
    TradeCanonicalJSONError,
    parse_trade_json,
)
from nth_dao.trade_rules.package_store import RulePackage

MAX_EXECUTION_CONTENT_BYTES = MAX_TRADE_JSON_BYTES


class TradeExecutionContentRejected(ValueError):
    """Execution content is unavailable, substituted, or schema-invalid."""


class TradeExecutionContentResolver(Protocol):
    """Resolve immutable execution content by its declared digest."""

    def load(self, digest: str, *, max_bytes: int) -> bytes | None:
        """Return exact bytes for ``digest`` without exceeding ``max_bytes``."""


class TradeExecutionSchemaValidator(Protocol):
    """Validate one parsed JSON object against one parsed JSON Schema."""

    def validate(
        self,
        instance: dict[str, Any],
        schema: dict[str, Any],
    ) -> None:
        """Raise TradeExecutionContentRejected when validation fails."""


class MappingTradeExecutionContentResolver:
    """Small immutable resolver for local content-addressed byte mappings."""

    def __init__(self, content: Mapping[str, bytes]) -> None:
        if not isinstance(content, Mapping):
            raise TypeError("content must be a digest-to-bytes mapping")
        normalized: dict[str, bytes] = {}
        for digest, payload in content.items():
            if not isinstance(digest, str) or not digest.startswith("sha256:"):
                raise ValueError("content key must be a sha256 digest")
            if not isinstance(payload, bytes):
                raise TypeError("content values must be bytes")
            actual = "sha256:" + hashlib.sha256(payload).hexdigest()
            if actual != digest:
                raise ValueError(f"content digest mismatch for {digest}")
            normalized[digest] = bytes(payload)
        self._content = normalized

    def load(self, digest: str, *, max_bytes: int) -> bytes | None:
        if (
            isinstance(max_bytes, bool)
            or not isinstance(max_bytes, int)
            or max_bytes < 0
        ):
            raise ValueError("max_bytes must be a non-negative integer")
        payload = self._content.get(digest)
        if payload is None:
            return None
        if len(payload) > max_bytes:
            raise TradeExecutionContentRejected(
                f"content {digest} exceeds the resolver byte limit"
            )
        return bytes(payload)


class JsonSchema202012Validator:
    """Optional ``jsonschema`` adapter; core protocol remains dependency-free."""

    @staticmethod
    def _reject_external_references(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if (
                    key in {"$ref", "$dynamicRef"}
                    and isinstance(item, str)
                    and not item.startswith("#")
                ):
                    raise TradeExecutionContentRejected(
                        "execution Hook schemas must not use external references"
                    )
                JsonSchema202012Validator._reject_external_references(item)
        elif isinstance(value, list):
            for item in value:
                JsonSchema202012Validator._reject_external_references(item)

    def validate(
        self,
        instance: dict[str, Any],
        schema: dict[str, Any],
    ) -> None:
        try:
            from jsonschema import Draft202012Validator
            from jsonschema.exceptions import SchemaError, ValidationError
            from referencing.exceptions import Unresolvable
        except ImportError as exc:
            raise TradeExecutionContentRejected(
                "JSON Schema validation requires nth-dao[trade-validation]"
            ) from exc
        self._reject_external_references(schema)
        try:
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(instance)
        except SchemaError as exc:
            raise TradeExecutionContentRejected(
                f"execution Hook schema is invalid: {exc.message}"
            ) from exc
        except ValidationError as exc:
            location = ".".join(str(item) for item in exc.absolute_path) or "$"
            raise TradeExecutionContentRejected(
                f"execution content violates Hook schema at {location}: "
                f"{exc.message}"
            ) from exc
        except Unresolvable as exc:
            raise TradeExecutionContentRejected(
                f"execution Hook schema reference is unresolved: {exc}"
            ) from exc


def _json_media_type(value: Any, *, label: str) -> None:
    if not isinstance(value, str) or not (
        value == "application/json" or value.endswith("+json")
    ):
        raise TradeExecutionContentRejected(
            f"{label}.media_type must identify JSON"
        )


def _resolve_content(
    descriptor: dict[str, Any],
    resolver: TradeExecutionContentResolver,
    *,
    label: str,
) -> dict[str, Any]:
    _json_media_type(descriptor.get("media_type"), label=label)
    digest = descriptor.get("digest")
    size = descriptor.get("size_bytes")
    if (
        not isinstance(digest, str)
        or not digest.startswith("sha256:")
        or isinstance(size, bool)
        or not isinstance(size, int)
        or not 0 <= size <= MAX_EXECUTION_CONTENT_BYTES
    ):
        raise TradeExecutionContentRejected(
            f"{label} descriptor is invalid or exceeds the byte limit"
        )
    try:
        payload = resolver.load(digest, max_bytes=MAX_EXECUTION_CONTENT_BYTES)
    except TradeExecutionContentRejected:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise TradeExecutionContentRejected(
            f"unable to resolve {label}: {exc}"
        ) from exc
    if payload is None:
        raise TradeExecutionContentRejected(f"{label} content is unavailable")
    if not isinstance(payload, bytes):
        raise TradeExecutionContentRejected(
            f"{label} resolver must return bytes"
        )
    if len(payload) != size:
        raise TradeExecutionContentRejected(f"{label} size mismatch")
    actual = "sha256:" + hashlib.sha256(payload).hexdigest()
    if actual != digest:
        raise TradeExecutionContentRejected(f"{label} digest mismatch")
    try:
        return parse_trade_json(payload)
    except TradeCanonicalJSONError as exc:
        raise TradeExecutionContentRejected(
            f"{label} is not valid NTH Trade JSON: {exc}"
        ) from exc


def _load_schema(
    package: RulePackage,
    digest: str,
    *,
    label: str,
) -> dict[str, Any]:
    try:
        payload = package.resource(digest)
    except KeyError as exc:
        raise TradeExecutionContentRejected(
            f"{label} is not embedded in the operation Rule Package"
        ) from exc
    try:
        return parse_trade_json(payload)
    except TradeCanonicalJSONError as exc:
        raise TradeExecutionContentRejected(
            f"{label} is not valid NTH Trade JSON: {exc}"
        ) from exc


def verify_execution_content(
    *,
    package: RulePackage,
    hook: dict[str, Any],
    operation_input: dict[str, Any],
    outcome: str,
    result: dict[str, Any],
    resolver: TradeExecutionContentResolver,
    schema_validator: TradeExecutionSchemaValidator,
) -> None:
    """Resolve exact bytes and apply the Hook's immutable JSON schemas."""

    if not callable(getattr(resolver, "load", None)):
        raise TypeError("resolver must provide load(digest, max_bytes=...)")
    if not callable(getattr(schema_validator, "validate", None)):
        raise TypeError("schema_validator must provide validate(instance, schema)")
    input_value = _resolve_content(
        operation_input,
        resolver,
        label="operation.input",
    )
    result_value = _resolve_content(result, resolver, label="result")
    input_schema = _load_schema(
        package,
        hook["input_schema_digest"],
        label="input schema",
    )
    try:
        schema_validator.validate(input_value, input_schema)
    except TradeExecutionContentRejected:
        raise
    except (RuntimeError, TypeError, ValueError) as exc:
        raise TradeExecutionContentRejected(
            f"input schema validation failed: {exc}"
        ) from exc
    if outcome != "succeeded":
        return
    output_schema = _load_schema(
        package,
        hook["output_schema_digest"],
        label="output schema",
    )
    try:
        schema_validator.validate(result_value, output_schema)
    except TradeExecutionContentRejected:
        raise
    except (RuntimeError, TypeError, ValueError) as exc:
        raise TradeExecutionContentRejected(
            f"output schema validation failed: {exc}"
        ) from exc


__all__ = [
    "JsonSchema202012Validator",
    "MAX_EXECUTION_CONTENT_BYTES",
    "MappingTradeExecutionContentResolver",
    "TradeExecutionContentRejected",
    "TradeExecutionContentResolver",
    "TradeExecutionSchemaValidator",
    "verify_execution_content",
]
