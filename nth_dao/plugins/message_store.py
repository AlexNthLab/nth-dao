"""Language-neutral contract for bounded collaboration-message storage.

The capability stores opaque canonical-JSON documents. Authorization,
membership, signatures, and message semantics remain host responsibilities;
the store receives an already-authorized local principal from ``PluginHost``.

Version 1 deliberately promises logical deletion only. ``consume`` provides an
atomic, in-process at-most-once read for providers that support it, but it is
not a secure-erasure claim for memory, disks, logs, backups, or remote replicas.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import hashlib
import json
import re
from types import MappingProxyType
from typing import Any, Dict

from nth_dao.canonical_json import canonical_json

from .contracts import CapabilityContract, schema_digest
from .host import PluginInvocationError
from .schema import PluginSchemaError, validate_instance


MESSAGE_STORE_CAPABILITY_ID = "org.nth-dao.message.store"
MESSAGE_STORE_CAPABILITY_VERSION = "1.0.0"
MESSAGE_STORE_MAX_DOCUMENT_BYTES = 1_048_576
MESSAGE_STORE_MAX_MESSAGE_BYTES = 524_288
MESSAGE_STORE_MAX_SAFE_INTEGER = 9_007_199_254_740_991

_MAX_IDENTIFIER_CHARS = 256
_MAX_ITEMS = 256
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_MESSAGE_KEY_RE = re.compile(r"^[\x20-\x7e]{1,256}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

_RETENTION_MODES = ("session", "ttl")
_DELIVERY_MODES = ("consume-on-read", "read-many")

MESSAGE_STORE_ERROR_MODEL: Mapping[str, Mapping[str, Any]] = MappingProxyType({
    "already-applied": {
        "retryable": False,
        "meaning": "the requested destructive generation was already consumed or deleted",
    },
    "conflict": {
        "retryable": False,
        "meaning": "the identifier already binds a different live record",
    },
    "expired": {
        "retryable": False,
        "meaning": "the requested expiry is not in the future",
    },
    "generation-not-found": {
        "retryable": False,
        "meaning": "the requested record generation does not exist",
    },
    "inactive": {
        "retryable": True,
        "meaning": "the provider is not currently active",
    },
    "limit-exceeded": {
        "retryable": False,
        "meaning": "the request exceeds a provider limit",
    },
    "quota-exceeded": {
        "retryable": True,
        "meaning": "temporary provider or principal capacity is exhausted",
    },
    "sequence-exhausted": {
        "retryable": False,
        "meaning": "the provider cannot allocate another portable sequence",
    },
    "stale-generation": {
        "retryable": False,
        "meaning": "the destructive CAS does not match the live record generation",
    },
    "unsupported-delivery-mode": {
        "retryable": False,
        "meaning": "the operation is incompatible with the record delivery mode",
    },
})
MESSAGE_STORE_ERROR_MODEL = MappingProxyType(
    {
        code: MappingProxyType(dict(specification))
        for code, specification in MESSAGE_STORE_ERROR_MODEL.items()
    }
)


class MessageStoreOperationError(PluginInvocationError):
    """Stable provider-domain failure for language-neutral callers."""

    def __init__(self, code: str, detail: str) -> None:
        specification = MESSAGE_STORE_ERROR_MODEL.get(code)
        if specification is None:
            raise ValueError("unsupported message store error code")
        if not isinstance(detail, str) or not detail or len(detail) > 512:
            raise ValueError("message store error detail must be bounded text")
        self.code = code
        self.detail = detail
        self.retryable = bool(specification["retryable"])
        super().__init__(f"{code}: {detail}")

_DESCRIPTOR_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "created_at_ms": {
            "type": "integer",
            "minimum": 0,
            "maximum": MESSAGE_STORE_MAX_SAFE_INTEGER,
        },
        "delivery_mode": {"type": "string", "enum": list(_DELIVERY_MODES)},
        "expires_at_ms": {
            "type": "integer",
            "minimum": 0,
            "maximum": MESSAGE_STORE_MAX_SAFE_INTEGER,
        },
        "message_id": {
            "type": "string",
            "minLength": 1,
            "maxLength": _MAX_IDENTIFIER_CHARS,
        },
        "message_sha256": {"type": "string", "minLength": 64, "maxLength": 64},
        "retention_mode": {"type": "string", "enum": list(_RETENTION_MODES)},
        "sequence": {
            "type": "integer",
            "minimum": 1,
            "maximum": MESSAGE_STORE_MAX_SAFE_INTEGER,
        },
    },
    "required": [
        "created_at_ms",
        "delivery_mode",
        "expires_at_ms",
        "message_id",
        "message_sha256",
        "retention_mode",
        "sequence",
    ],
}

MESSAGE_STORE_INPUT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "after_sequence": {
            "type": "integer",
            "minimum": 0,
            "maximum": MESSAGE_STORE_MAX_SAFE_INTEGER,
        },
        "delivery_mode": {"type": "string", "enum": list(_DELIVERY_MODES)},
        "expires_at_ms": {
            "type": "integer",
            "minimum": 0,
            "maximum": MESSAGE_STORE_MAX_SAFE_INTEGER,
        },
        "expected_message_sha256": {
            "type": "string",
            "minLength": 64,
            "maxLength": 64,
        },
        "expected_sequence": {
            "type": "integer",
            "minimum": 1,
            "maximum": MESSAGE_STORE_MAX_SAFE_INTEGER,
        },
        "limit": {"type": "integer", "minimum": 1, "maximum": _MAX_ITEMS},
        "message_id": {
            "type": "string",
            "minLength": 1,
            "maxLength": _MAX_IDENTIFIER_CHARS,
        },
        "message_json": {
            "type": "string",
            "minLength": 2,
            "maxLength": MESSAGE_STORE_MAX_MESSAGE_BYTES,
        },
        "message_sha256": {"type": "string", "minLength": 64, "maxLength": 64},
        "namespace": {
            "type": "string",
            "minLength": 1,
            "maxLength": _MAX_IDENTIFIER_CHARS,
        },
        "operation": {
            "type": "string",
            "enum": ["consume", "delete", "get", "list", "probe", "put"],
        },
        "retention_mode": {"type": "string", "enum": list(_RETENTION_MODES)},
    },
    "required": ["operation"],
}

MESSAGE_STORE_OUTPUT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "created_at_ms": {
            "type": "integer",
            "minimum": 0,
            "maximum": MESSAGE_STORE_MAX_SAFE_INTEGER,
        },
        "deleted": {"type": "boolean"},
        "deletion_guarantee": {"type": "string", "enum": ["logical-only"]},
        "delivery_mode": {
            "type": "string",
            "enum": ["", *_DELIVERY_MODES],
        },
        "detail": {"type": "string", "maxLength": 2_048},
        "expires_at_ms": {
            "type": "integer",
            "minimum": 0,
            "maximum": MESSAGE_STORE_MAX_SAFE_INTEGER,
        },
        "found": {"type": "boolean"},
        "items": {"type": "array", "maxItems": _MAX_ITEMS, "items": _DESCRIPTOR_SCHEMA},
        "max_message_bytes": {
            "type": "integer",
            "minimum": 1,
            "maximum": MESSAGE_STORE_MAX_SAFE_INTEGER,
        },
        "max_records_per_principal": {
            "type": "integer",
            "minimum": 1,
            "maximum": MESSAGE_STORE_MAX_SAFE_INTEGER,
        },
        "max_ttl_seconds": {
            "type": "integer",
            "minimum": 1,
            "maximum": MESSAGE_STORE_MAX_SAFE_INTEGER,
        },
        "message_id": {"type": "string", "maxLength": _MAX_IDENTIFIER_CHARS},
        "message_json": {"type": "string", "maxLength": MESSAGE_STORE_MAX_MESSAGE_BYTES},
        "message_sha256": {"type": "string", "maxLength": 64},
        "namespace": {"type": "string", "maxLength": _MAX_IDENTIFIER_CHARS},
        "next_sequence": {
            "type": "integer",
            "minimum": 0,
            "maximum": MESSAGE_STORE_MAX_SAFE_INTEGER,
        },
        "operation": {
            "type": "string",
            "enum": ["consume", "delete", "get", "list", "probe", "put"],
        },
        "ready": {"type": "boolean"},
        "replayed": {"type": "boolean"},
        "retention_mode": {
            "type": "string",
            "enum": ["", *_RETENTION_MODES],
        },
        "sequence": {
            "type": "integer",
            "minimum": 0,
            "maximum": MESSAGE_STORE_MAX_SAFE_INTEGER,
        },
        "store_id": {"type": "string", "minLength": 1, "maxLength": 128},
        "supported_delivery_modes": {
            "type": "array",
            "minItems": 1,
            "maxItems": len(_DELIVERY_MODES),
            "items": {"type": "string", "enum": list(_DELIVERY_MODES)},
        },
        "supported_retention_modes": {
            "type": "array",
            "minItems": 1,
            "maxItems": len(_RETENTION_MODES),
            "items": {"type": "string", "enum": list(_RETENTION_MODES)},
        },
    },
    "required": [
        "created_at_ms",
        "deleted",
        "deletion_guarantee",
        "delivery_mode",
        "detail",
        "expires_at_ms",
        "found",
        "items",
        "max_message_bytes",
        "max_records_per_principal",
        "max_ttl_seconds",
        "message_id",
        "message_json",
        "message_sha256",
        "namespace",
        "next_sequence",
        "operation",
        "ready",
        "replayed",
        "retention_mode",
        "sequence",
        "store_id",
        "supported_delivery_modes",
        "supported_retention_modes",
    ],
}

_OPERATION_RULES = {
    "consume": {
        "allowed": (
            "expected_message_sha256",
            "expected_sequence",
            "message_id",
            "namespace",
            "operation",
        ),
        "required": (
            "expected_message_sha256",
            "expected_sequence",
            "message_id",
            "namespace",
            "operation",
        ),
    },
    "delete": {
        "allowed": (
            "expected_message_sha256",
            "expected_sequence",
            "message_id",
            "namespace",
            "operation",
        ),
        "required": (
            "expected_message_sha256",
            "expected_sequence",
            "message_id",
            "namespace",
            "operation",
        ),
    },
    "get": {
        "allowed": ("message_id", "namespace", "operation"),
        "required": ("message_id", "namespace", "operation"),
    },
    "list": {
        "allowed": ("after_sequence", "limit", "namespace", "operation"),
        "required": ("after_sequence", "limit", "namespace", "operation"),
    },
    "probe": {"allowed": ("operation",), "required": ("operation",)},
    "put": {
        "allowed": (
            "delivery_mode",
            "expires_at_ms",
            "message_id",
            "message_json",
            "message_sha256",
            "namespace",
            "operation",
            "retention_mode",
        ),
        "required": (
            "delivery_mode",
            "expires_at_ms",
            "message_id",
            "message_json",
            "message_sha256",
            "namespace",
            "operation",
            "retention_mode",
        ),
    },
}

MESSAGE_STORE_CONTRACT = CapabilityContract(
    capability_id=MESSAGE_STORE_CAPABILITY_ID,
    version=MESSAGE_STORE_CAPABILITY_VERSION,
    input_schema_digest=schema_digest(MESSAGE_STORE_INPUT_SCHEMA),
    output_schema_digest=schema_digest(MESSAGE_STORE_OUTPUT_SCHEMA),
    effects=("none",),
    consistency="C2",
    privacy="confidential",
    security="verified-input",
    cardinality="many",
    deterministic=False,
    retention="ephemeral",
    failure_semantics="at-most-once",
)


def message_store_operation_rule(operation: str) -> tuple[frozenset[str], frozenset[str]]:
    """Return immutable allowed and required fields for an operation."""

    rule = _OPERATION_RULES.get(operation)
    if rule is None:
        raise ValueError("unsupported message store operation")
    return frozenset(rule["allowed"]), frozenset(rule["required"])


def validate_message_store_identifier(value: Any, *, field: str) -> str:
    """Validate portable namespace and message identifiers."""

    if field not in {"namespace", "message_id", "store_id"}:
        raise ValueError("unsupported message store identifier field")
    maximum = 128 if field == "store_id" else _MAX_IDENTIFIER_CHARS
    if (
        not isinstance(value, str)
        or len(value) > maximum
        or _IDENTIFIER_RE.fullmatch(value) is None
        or any(part in {".", ".."} for part in re.split(r"[/:]", value))
        or (
            field == "namespace"
            and (
                value.endswith(("/", ":"))
                or re.search(r"[/:]{2}", value) is not None
                or re.match(r"^[A-Za-z]:/", value) is not None
            )
        )
    ):
        raise ValueError(f"{field} is invalid")
    return value


def canonical_message_document(value: str) -> tuple[Dict[str, Any], bytes]:
    """Parse and verify the canonical object carried by ``message_json``."""

    if not isinstance(value, str):
        raise ValueError("message_json must be text")
    encoded = value.encode("utf-8")
    if len(encoded) > MESSAGE_STORE_MAX_MESSAGE_BYTES:
        raise ValueError("message_json exceeds the UTF-8 byte limit")
    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("message_json must contain valid JSON") from exc
    if not isinstance(parsed, dict):
        raise ValueError("message_json must contain a JSON object")
    _validate_message_keys(parsed)
    _validate_safe_integers(parsed)
    try:
        canonical = canonical_json(parsed)
    except (RecursionError, TypeError, ValueError) as exc:
        raise ValueError("message_json must contain finite canonical JSON") from exc
    if canonical != encoded:
        raise ValueError("message_json must use canonical JSON encoding")
    return parsed, canonical


def message_store_message_digest(message_json: str) -> str:
    """Return lowercase SHA-256 hex for one canonical message document."""

    _, encoded = canonical_message_document(message_json)
    return hashlib.sha256(encoded).hexdigest()


def validate_message_store_input(value: Mapping[str, Any]) -> None:
    """Validate one closed, operation-specific input document."""

    if not isinstance(value, Mapping):
        raise PluginSchemaError("$input must be an object")
    _validate_document_size(value, path="$input")
    validate_instance(value, MESSAGE_STORE_INPUT_SCHEMA, path="$input")
    operation = value.get("operation")
    try:
        allowed, required = message_store_operation_rule(operation)
    except ValueError as exc:
        raise PluginSchemaError("$input.operation is unsupported") from exc
    unexpected = set(value) - allowed
    missing = required - set(value)
    if unexpected:
        raise PluginSchemaError(
            f"$input operation does not accept fields: {sorted(unexpected)}"
        )
    if missing:
        raise PluginSchemaError(f"$input operation requires fields: {sorted(missing)}")
    for field in ("namespace", "message_id"):
        if field not in value:
            continue
        try:
            validate_message_store_identifier(value[field], field=field)
        except ValueError as exc:
            raise PluginSchemaError(f"$input.{field} is invalid") from exc
    if operation in {"consume", "delete"} and _SHA256_RE.fullmatch(
        value["expected_message_sha256"]
    ) is None:
        raise PluginSchemaError(
            "$input.expected_message_sha256 is not lowercase SHA-256 hex"
        )
    if operation != "put":
        return
    try:
        digest = message_store_message_digest(value["message_json"])
    except ValueError as exc:
        raise PluginSchemaError(f"$input.message_json {exc}") from exc
    if _SHA256_RE.fullmatch(value["message_sha256"]) is None:
        raise PluginSchemaError("$input.message_sha256 is not lowercase SHA-256 hex")
    if digest != value["message_sha256"]:
        raise PluginSchemaError("$input.message_sha256 does not bind message_json")
    retention = value["retention_mode"]
    expires_at_ms = value["expires_at_ms"]
    if retention == "session" and expires_at_ms != 0:
        raise PluginSchemaError("$input session retention cannot carry an expiry")
    if retention == "ttl" and expires_at_ms <= 0:
        raise PluginSchemaError("$input ttl retention requires an expiry")


def validate_message_store_output(value: Mapping[str, Any]) -> None:
    """Validate provider output and operation-specific state invariants."""

    if not isinstance(value, Mapping):
        raise PluginSchemaError("$output must be an object")
    _validate_document_size(value, path="$output")
    validate_instance(value, MESSAGE_STORE_OUTPUT_SCHEMA, path="$output")
    try:
        validate_message_store_identifier(value["store_id"], field="store_id")
    except ValueError as exc:
        raise PluginSchemaError("$output.store_id is invalid") from exc
    if not value["ready"]:
        raise PluginSchemaError("$output built-in operation must report ready")
    if value["detail"]:
        raise PluginSchemaError("$output ready operation cannot carry detail")
    if value["max_message_bytes"] > MESSAGE_STORE_MAX_MESSAGE_BYTES:
        raise PluginSchemaError("$output max_message_bytes exceeds the wire limit")
    for key in ("supported_delivery_modes", "supported_retention_modes"):
        items = value[key]
        if items != sorted(set(items)):
            raise PluginSchemaError(f"$output.{key} must be sorted and unique")
    operation = value["operation"]
    if value["replayed"] and operation != "put":
        raise PluginSchemaError("$output.replayed is put-only")
    if value["deleted"] and operation not in {"consume", "delete"}:
        raise PluginSchemaError("$output.deleted is consume/delete-only")

    if operation == "probe":
        _require_empty_record(value)
        if value["found"] or value["items"] or value["next_sequence"]:
            raise PluginSchemaError("$output probe cannot carry record or listing state")
        return
    if operation == "list":
        _require_empty_record(value)
        items = value["items"]
        if value["found"] != bool(items) or value["deleted"] or value["replayed"]:
            raise PluginSchemaError("$output list flags do not match items")
        sequences = [item["sequence"] for item in items]
        message_ids = [item["message_id"] for item in items]
        if sequences != sorted(set(sequences)):
            raise PluginSchemaError("$output list sequences must be increasing and unique")
        if len(message_ids) != len(set(message_ids)):
            raise PluginSchemaError("$output list message ids must be unique")
        if sequences and value["next_sequence"] != sequences[-1]:
            raise PluginSchemaError("$output next_sequence must equal the final item")
        for item in items:
            _validate_descriptor(item, path="$output.items[]")
            if item["delivery_mode"] not in value["supported_delivery_modes"]:
                raise PluginSchemaError("$output list delivery mode is not advertised")
            if item["retention_mode"] not in value["supported_retention_modes"]:
                raise PluginSchemaError("$output list retention mode is not advertised")
        return
    if operation == "delete":
        _require_empty_record(value)
        if value["found"] != value["deleted"] or value["items"]:
            raise PluginSchemaError("$output delete flags are inconsistent")
        if value["next_sequence"] or value["replayed"]:
            raise PluginSchemaError("$output delete carries unrelated state")
        return

    if value["items"] or value["next_sequence"]:
        raise PluginSchemaError(f"$output {operation} cannot carry listing state")
    if not value["found"]:
        if operation == "put":
            raise PluginSchemaError("$output put must identify the stored record")
        _require_empty_record(value)
        if value["deleted"] or value["replayed"]:
            raise PluginSchemaError(f"$output missing {operation} flags are inconsistent")
        return
    _validate_record_fields(value)
    if value["delivery_mode"] not in value["supported_delivery_modes"]:
        raise PluginSchemaError("$output record delivery mode is not advertised")
    if value["retention_mode"] not in value["supported_retention_modes"]:
        raise PluginSchemaError("$output record retention mode is not advertised")
    if operation == "put":
        if value["message_json"] or value["deleted"]:
            raise PluginSchemaError("$output put cannot return content or deletion")
        return
    if value["replayed"]:
        raise PluginSchemaError(f"$output {operation} cannot be replayed")
    if not value["message_json"]:
        raise PluginSchemaError(f"$output {operation} requires message content")
    try:
        digest = message_store_message_digest(value["message_json"])
    except ValueError as exc:
        raise PluginSchemaError(f"$output.message_json {exc}") from exc
    if digest != value["message_sha256"]:
        raise PluginSchemaError("$output.message_sha256 does not bind message_json")
    if operation == "get":
        if value["delivery_mode"] != "read-many" or value["deleted"]:
            raise PluginSchemaError("$output get must be repeatable and non-deleting")
    elif operation == "consume":
        if value["delivery_mode"] != "consume-on-read" or not value["deleted"]:
            raise PluginSchemaError("$output consume must atomically delete one-shot content")


def message_store_protocol_document() -> Dict[str, Any]:
    """Return the complete versioned protocol document for other runtimes."""

    return {
        "capability": MESSAGE_STORE_CONTRACT.to_dict(),
        "canonicalization": {
            "encoding": "utf-8",
            "floats": "forbidden",
            "integer_range": "-(2^53-1)..(2^53-1)",
            "object_keys": "non-empty-printable-ascii-1-to-256-bytes",
            "serialization": "recursive-sorted-keys-compact-json",
        },
        "error_model": {
            code: dict(specification)
            for code, specification in MESSAGE_STORE_ERROR_MODEL.items()
        },
        "input_schema": deepcopy(MESSAGE_STORE_INPUT_SCHEMA),
        "identifier_rules": {
            "grammar": "^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$",
            "namespace_separators": (
                "single slash or colon; no trailing separator or Windows drive prefix"
            ),
            "path_interpretation": (
                "opaque identifier only; providers must hash or encode it before storage"
            ),
            "path_segments": "dot-and-dot-dot-segments-forbidden",
            "principal_scope": (
                "records are isolated by the host-selected local invocation principal; "
                "Host API v1 does not authenticate remote origin"
            ),
        },
        "operation_rules": {
            operation: {
                "allowed": list(rule["allowed"]),
                "required": list(rule["required"]),
            }
            for operation, rule in sorted(_OPERATION_RULES.items())
        },
        "output_schema": deepcopy(MESSAGE_STORE_OUTPUT_SCHEMA),
        "semantics": {
            "consume": "generation-and-hash-cas-atomic-at-most-once-logical-delete",
            "delete": "generation-and-hash-cas-logical-only-not-secure-erasure",
            "get": "read-many-records-only",
            "list": "metadata-only-in-increasing-sequence-order",
            "put": "live-record-immutable-idempotent-by-complete-record",
            "ttl": "absolute-unix-epoch-milliseconds",
        },
        "wire_limits": {
            "max_document_bytes": MESSAGE_STORE_MAX_DOCUMENT_BYTES,
            "max_items": _MAX_ITEMS,
            "max_message_bytes": MESSAGE_STORE_MAX_MESSAGE_BYTES,
            "max_safe_integer": MESSAGE_STORE_MAX_SAFE_INTEGER,
            "size_unit": "canonical-json-utf8-bytes",
        },
    }


def message_store_protocol_digest() -> str:
    document = message_store_protocol_document()
    return f"sha256:{hashlib.sha256(canonical_json(document)).hexdigest()}"


def _validate_descriptor(value: Mapping[str, Any], *, path: str) -> None:
    try:
        validate_message_store_identifier(value["message_id"], field="message_id")
    except ValueError as exc:
        raise PluginSchemaError(f"{path}.message_id is invalid") from exc
    if _SHA256_RE.fullmatch(value["message_sha256"]) is None:
        raise PluginSchemaError(f"{path}.message_sha256 is invalid")
    if value["retention_mode"] == "session" and value["expires_at_ms"] != 0:
        raise PluginSchemaError(f"{path} session retention cannot carry an expiry")
    if value["retention_mode"] == "ttl" and value["expires_at_ms"] <= 0:
        raise PluginSchemaError(f"{path} ttl retention requires an expiry")
    if (
        value["retention_mode"] == "ttl"
        and value["expires_at_ms"] <= value["created_at_ms"]
    ):
        raise PluginSchemaError(f"{path} ttl expiry must follow creation")


def _validate_safe_integers(value: Any, *, path: str = "$") -> None:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, int):
        if not -MESSAGE_STORE_MAX_SAFE_INTEGER <= value <= MESSAGE_STORE_MAX_SAFE_INTEGER:
            raise ValueError(f"integer at {path} exceeds the cross-language safe range")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_safe_integers(item, path=f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _validate_safe_integers(item, path=f"{path}.{key}")
        return


def _validate_message_keys(value: Any, *, path: str = "$") -> None:
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_message_keys(item, path=f"{path}[{index}]")
        return
    if not isinstance(value, dict):
        return
    for key, item in value.items():
        if _MESSAGE_KEY_RE.fullmatch(key) is None:
            raise ValueError(
                f"object key at {path} must be 1-256 printable ASCII bytes"
            )
        _validate_message_keys(item, path=f"{path}.{key}")


def _validate_record_fields(value: Mapping[str, Any]) -> None:
    for field in ("namespace", "message_id"):
        try:
            validate_message_store_identifier(value[field], field=field)
        except ValueError as exc:
            raise PluginSchemaError(f"$output.{field} is invalid") from exc
    _validate_descriptor(value, path="$output")


def _require_empty_record(value: Mapping[str, Any]) -> None:
    if any(
        (
            value["created_at_ms"],
            value["delivery_mode"],
            value["expires_at_ms"],
            value["message_id"],
            value["message_json"],
            value["message_sha256"],
            value["namespace"],
            value["retention_mode"],
            value["sequence"],
        )
    ):
        raise PluginSchemaError("$output operation carries unexpected record fields")


def _validate_document_size(value: Mapping[str, Any], *, path: str) -> None:
    try:
        encoded = canonical_json(dict(value))
    except (RecursionError, TypeError, ValueError) as exc:
        raise PluginSchemaError(f"{path} must be finite canonical JSON") from exc
    if len(encoded) > MESSAGE_STORE_MAX_DOCUMENT_BYTES:
        raise PluginSchemaError(
            f"{path} exceeds {MESSAGE_STORE_MAX_DOCUMENT_BYTES} canonical UTF-8 bytes"
        )


__all__ = [
    "MESSAGE_STORE_CAPABILITY_ID",
    "MESSAGE_STORE_CAPABILITY_VERSION",
    "MESSAGE_STORE_CONTRACT",
    "MESSAGE_STORE_ERROR_MODEL",
    "MESSAGE_STORE_INPUT_SCHEMA",
    "MESSAGE_STORE_MAX_DOCUMENT_BYTES",
    "MESSAGE_STORE_MAX_MESSAGE_BYTES",
    "MESSAGE_STORE_MAX_SAFE_INTEGER",
    "MESSAGE_STORE_OUTPUT_SCHEMA",
    "MessageStoreOperationError",
    "canonical_message_document",
    "message_store_message_digest",
    "message_store_operation_rule",
    "message_store_protocol_digest",
    "message_store_protocol_document",
    "validate_message_store_identifier",
    "validate_message_store_input",
    "validate_message_store_output",
]
