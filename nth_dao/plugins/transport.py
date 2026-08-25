"""Language-neutral contract for bounded protocol-envelope delivery.

Transport providers move opaque canonical-JSON envelopes. They do not decide
membership, verify business signatures, resolve DIDs, or grant authority. The
Host must complete those checks before send and again after receive.

Version 1 provides retry-safe enqueue, leased batch receive, and atomic batch
acknowledgement. A receive lease may be delivered again after it expires, so
consumers must remain idempotent at the protocol-object layer.
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
from .host import InvocationAuthority, PluginAuthorizationError, PluginInvocationError
from .schema import PluginSchemaError, validate_instance


TRANSPORT_CAPABILITY_ID = "org.nth-dao.transport.delivery"
TRANSPORT_CAPABILITY_VERSION = "1.0.0"
TRANSPORT_MAX_DOCUMENT_BYTES = 1_048_576
TRANSPORT_MAX_ENVELOPE_BYTES = 524_288
TRANSPORT_MAX_SAFE_INTEGER = 9_007_199_254_740_991
TRANSPORT_MAX_BATCH_SIZE = 64
TRANSPORT_MAX_LEASE_MS = 300_000

_MAX_IDENTIFIER_CHARS = 256
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_DELIVERY_STATES = ("", "acknowledged", "expired", "leased", "queued")
_DELIVERY_GUARANTEE = "ephemeral-at-least-once-until-ack"

TRANSPORT_ERROR_MODEL: Mapping[str, Mapping[str, Any]] = MappingProxyType(
    {
        "claim-closed": {
            "retryable": False,
            "meaning": "the receive id already names an acknowledged or expired claim",
        },
        "conflict": {
            "retryable": False,
            "meaning": "an id already binds different immutable input",
        },
        "delivery-not-found": {
            "retryable": False,
            "meaning": "the requested delivery is not live in this provider",
        },
        "expired": {
            "retryable": False,
            "meaning": "the envelope expiry is not in the future",
        },
        "inactive": {
            "retryable": True,
            "meaning": "the provider is not currently active",
        },
        "lease-conflict": {
            "retryable": False,
            "meaning": "the acknowledgement does not bind the active receive lease",
        },
        "lease-expired": {
            "retryable": False,
            "meaning": "the receive lease ended before acknowledgement",
        },
        "limit-exceeded": {
            "retryable": False,
            "meaning": "the request exceeds a provider limit",
        },
        "quota-exceeded": {
            "retryable": True,
            "meaning": "temporary provider or principal capacity is exhausted",
        },
    }
)
TRANSPORT_ERROR_MODEL = MappingProxyType(
    {
        code: MappingProxyType(dict(specification))
        for code, specification in TRANSPORT_ERROR_MODEL.items()
    }
)
TRANSPORT_ERROR_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "code": {"type": "string", "enum": sorted(TRANSPORT_ERROR_MODEL)},
        "detail": {"type": "string", "minLength": 1, "maxLength": 512},
        "retryable": {"type": "boolean"},
    },
    "required": ["code", "detail", "retryable"],
}


class TransportOperationError(PluginInvocationError):
    """Stable provider-domain failure for language-neutral callers."""

    def __init__(self, code: str, detail: str) -> None:
        specification = TRANSPORT_ERROR_MODEL.get(code)
        if specification is None:
            raise ValueError("unsupported transport error code")
        if not isinstance(detail, str) or not detail or len(detail) > 512:
            raise ValueError("transport error detail must be bounded text")
        self.code = code
        self.detail = detail
        self.retryable = bool(specification["retryable"])
        super().__init__(f"{code}: {detail}")

    def to_wire(self) -> Dict[str, Any]:
        """Return the closed JSON error envelope used by RPC adapters."""

        return {
            "code": self.code,
            "detail": self.detail,
            "retryable": self.retryable,
        }

    @classmethod
    def from_wire(cls, value: Mapping[str, Any]) -> "TransportOperationError":
        """Rebuild an operation error after validating its wire semantics."""

        validate_transport_error(value)
        return cls(value["code"], value["detail"])


_DELIVERY_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "accepted_at_ms": {
            "type": "integer",
            "minimum": 0,
            "maximum": TRANSPORT_MAX_SAFE_INTEGER,
        },
        "delivery_id": {
            "type": "string",
            "minLength": 1,
            "maxLength": _MAX_IDENTIFIER_CHARS,
        },
        "envelope_json": {
            "type": "string",
            "minLength": 2,
            "maxLength": TRANSPORT_MAX_ENVELOPE_BYTES,
        },
        "envelope_sha256": {"type": "string", "minLength": 64, "maxLength": 64},
        "expires_at_ms": {
            "type": "integer",
            "minimum": 1,
            "maximum": TRANSPORT_MAX_SAFE_INTEGER,
        },
        "transport_delivery_id": {
            "type": "string",
            "minLength": 1,
            "maxLength": _MAX_IDENTIFIER_CHARS,
        },
    },
    "required": [
        "accepted_at_ms",
        "delivery_id",
        "envelope_json",
        "envelope_sha256",
        "expires_at_ms",
        "transport_delivery_id",
    ],
}

TRANSPORT_INPUT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "batch_sha256": {"type": "string", "minLength": 64, "maxLength": 64},
        "delivery_id": {
            "type": "string",
            "minLength": 1,
            "maxLength": _MAX_IDENTIFIER_CHARS,
        },
        "destination_route_id": {
            "type": "string",
            "minLength": 1,
            "maxLength": _MAX_IDENTIFIER_CHARS,
        },
        "envelope_json": {
            "type": "string",
            "minLength": 2,
            "maxLength": TRANSPORT_MAX_ENVELOPE_BYTES,
        },
        "envelope_sha256": {"type": "string", "minLength": 64, "maxLength": 64},
        "expires_at_ms": {
            "type": "integer",
            "minimum": 1,
            "maximum": TRANSPORT_MAX_SAFE_INTEGER,
        },
        "lease_id": {
            "type": "string",
            "minLength": 1,
            "maxLength": _MAX_IDENTIFIER_CHARS,
        },
        "lease_ms": {
            "type": "integer",
            "minimum": 1,
            "maximum": TRANSPORT_MAX_LEASE_MS,
        },
        "limit": {
            "type": "integer",
            "minimum": 1,
            "maximum": TRANSPORT_MAX_BATCH_SIZE,
        },
        "operation": {
            "type": "string",
            "enum": ["ack", "probe", "receive", "send"],
        },
        "receive_id": {
            "type": "string",
            "minLength": 1,
            "maxLength": _MAX_IDENTIFIER_CHARS,
        },
    },
    "required": ["operation"],
}

TRANSPORT_OUTPUT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "accepted": {"type": "boolean"},
        "acknowledged": {"type": "boolean"},
        "acknowledged_count": {
            "type": "integer",
            "minimum": 0,
            "maximum": TRANSPORT_MAX_BATCH_SIZE,
        },
        "batch_sha256": {"type": "string", "maxLength": 64},
        "delivery_guarantee": {
            "type": "string",
            "enum": [_DELIVERY_GUARANTEE],
        },
        "delivery_id": {"type": "string", "maxLength": _MAX_IDENTIFIER_CHARS},
        "detail": {"type": "string", "maxLength": 2_048},
        "expires_at_ms": {
            "type": "integer",
            "minimum": 0,
            "maximum": TRANSPORT_MAX_SAFE_INTEGER,
        },
        "found": {"type": "boolean"},
        "items": {
            "type": "array",
            "maxItems": TRANSPORT_MAX_BATCH_SIZE,
            "items": _DELIVERY_SCHEMA,
        },
        "lease_expires_at_ms": {
            "type": "integer",
            "minimum": 0,
            "maximum": TRANSPORT_MAX_SAFE_INTEGER,
        },
        "lease_id": {"type": "string", "maxLength": _MAX_IDENTIFIER_CHARS},
        "local_route_id": {
            "type": "string",
            "minLength": 1,
            "maxLength": _MAX_IDENTIFIER_CHARS,
        },
        "max_batch_size": {
            "type": "integer",
            "minimum": 1,
            "maximum": TRANSPORT_MAX_BATCH_SIZE,
        },
        "max_envelope_bytes": {
            "type": "integer",
            "minimum": 1,
            "maximum": TRANSPORT_MAX_SAFE_INTEGER,
        },
        "max_lease_ms": {
            "type": "integer",
            "minimum": 1,
            "maximum": TRANSPORT_MAX_LEASE_MS,
        },
        "max_ttl_seconds": {
            "type": "integer",
            "minimum": 1,
            "maximum": TRANSPORT_MAX_SAFE_INTEGER,
        },
        "operation": {
            "type": "string",
            "enum": ["ack", "probe", "receive", "send"],
        },
        "ready": {"type": "boolean"},
        "receive_id": {"type": "string", "maxLength": _MAX_IDENTIFIER_CHARS},
        "replayed": {"type": "boolean"},
        "state": {"type": "string", "enum": list(_DELIVERY_STATES)},
        "supports_ack": {"type": "boolean"},
        "supports_streaming": {"type": "boolean"},
        "transport_id": {"type": "string", "minLength": 1, "maxLength": 128},
        "transport_delivery_id": {
            "type": "string",
            "maxLength": _MAX_IDENTIFIER_CHARS,
        },
    },
    "required": [
        "accepted",
        "acknowledged",
        "acknowledged_count",
        "batch_sha256",
        "delivery_guarantee",
        "delivery_id",
        "detail",
        "expires_at_ms",
        "found",
        "items",
        "lease_expires_at_ms",
        "lease_id",
        "local_route_id",
        "max_batch_size",
        "max_envelope_bytes",
        "max_lease_ms",
        "max_ttl_seconds",
        "operation",
        "ready",
        "receive_id",
        "replayed",
        "state",
        "supports_ack",
        "supports_streaming",
        "transport_id",
        "transport_delivery_id",
    ],
}

_OPERATION_RULES = {
    "ack": {
        "allowed": ("batch_sha256", "lease_id", "operation", "receive_id"),
        "required": ("batch_sha256", "lease_id", "operation", "receive_id"),
    },
    "probe": {"allowed": ("operation",), "required": ("operation",)},
    "receive": {
        "allowed": ("lease_ms", "limit", "operation", "receive_id"),
        "required": ("lease_ms", "limit", "operation", "receive_id"),
    },
    "send": {
        "allowed": (
            "delivery_id",
            "destination_route_id",
            "envelope_json",
            "envelope_sha256",
            "expires_at_ms",
            "operation",
        ),
        "required": (
            "delivery_id",
            "destination_route_id",
            "envelope_json",
            "envelope_sha256",
            "expires_at_ms",
            "operation",
        ),
    },
}

TRANSPORT_LOCAL_CONTRACT = CapabilityContract(
    capability_id=TRANSPORT_CAPABILITY_ID,
    version=TRANSPORT_CAPABILITY_VERSION,
    input_schema_digest=schema_digest(TRANSPORT_INPUT_SCHEMA),
    output_schema_digest=schema_digest(TRANSPORT_OUTPUT_SCHEMA),
    effects=("none",),
    consistency="C2",
    privacy="confidential",
    security="verified-input",
    cardinality="many",
    deterministic=False,
    retention="ephemeral",
    failure_semantics="retry-safe",
)


def transport_operation_rule(operation: str) -> tuple[frozenset[str], frozenset[str]]:
    """Return immutable allowed and required fields for an operation."""

    rule = _OPERATION_RULES.get(operation)
    if rule is None:
        raise ValueError("unsupported transport operation")
    return frozenset(rule["allowed"]), frozenset(rule["required"])


def validate_transport_identifier(value: Any, *, field: str) -> str:
    """Validate portable IDs; route IDs are opaque and never direct URLs."""

    if field not in {
        "delivery_id",
        "destination_route_id",
        "lease_id",
        "local_route_id",
        "receive_id",
        "transport_id",
        "transport_delivery_id",
    }:
        raise ValueError("unsupported transport identifier field")
    maximum = 128 if field == "transport_id" else _MAX_IDENTIFIER_CHARS
    if (
        not isinstance(value, str)
        or len(value) > maximum
        or _IDENTIFIER_RE.fullmatch(value) is None
        or any(part in {".", ".."} for part in re.split(r"[/:]", value))
        or value.endswith(("/", ":"))
        or re.search(r"[/:]{2}", value) is not None
        or re.match(r"^[A-Za-z]:/", value) is not None
    ):
        raise ValueError(f"{field} is invalid")
    return value


def canonical_transport_envelope(value: str) -> tuple[Dict[str, Any], bytes]:
    """Parse one opaque envelope and verify its canonical JSON bytes."""

    if not isinstance(value, str):
        raise ValueError("envelope_json must be text")
    encoded = value.encode("utf-8")
    if len(encoded) > TRANSPORT_MAX_ENVELOPE_BYTES:
        raise ValueError("envelope_json exceeds the UTF-8 byte limit")
    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("envelope_json must contain valid JSON") from exc
    if not isinstance(parsed, dict):
        raise ValueError("envelope_json must contain a JSON object")
    _validate_safe_integers(parsed)
    try:
        encoded_again = canonical_json(parsed)
    except (RecursionError, TypeError, ValueError) as exc:
        raise ValueError("envelope_json must contain finite canonical JSON") from exc
    if encoded_again != encoded:
        raise ValueError("envelope_json must use canonical JSON encoding")
    return parsed, encoded_again


def transport_envelope_digest(envelope_json: str) -> str:
    """Return lowercase SHA-256 hex for one canonical opaque envelope."""

    _, encoded = canonical_transport_envelope(envelope_json)
    return hashlib.sha256(encoded).hexdigest()


def transport_batch_digest(items: list[Mapping[str, Any]]) -> str:
    """Bind every immutable descriptor field in an ordered receive batch."""

    document = {
        "deliveries": [
            {
                "accepted_at_ms": item["accepted_at_ms"],
                "delivery_id": item["delivery_id"],
                "envelope_sha256": item["envelope_sha256"],
                "expires_at_ms": item["expires_at_ms"],
                "transport_delivery_id": item["transport_delivery_id"],
            }
            for item in items
        ]
    }
    return hashlib.sha256(canonical_json(document)).hexdigest()


def validate_transport_input(value: Mapping[str, Any]) -> None:
    """Validate one closed, operation-specific transport input."""

    if not isinstance(value, Mapping):
        raise PluginSchemaError("$input must be an object")
    _validate_document_size(value, path="$input")
    validate_instance(value, TRANSPORT_INPUT_SCHEMA, path="$input")
    operation = value.get("operation")
    try:
        allowed, required = transport_operation_rule(operation)
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
    for field in (
        "delivery_id",
        "destination_route_id",
        "lease_id",
        "receive_id",
    ):
        if field not in value:
            continue
        try:
            validate_transport_identifier(value[field], field=field)
        except ValueError as exc:
            raise PluginSchemaError(f"$input.{field} is invalid") from exc
    for field in ("batch_sha256", "envelope_sha256"):
        if field in value and _SHA256_RE.fullmatch(value[field]) is None:
            raise PluginSchemaError(f"$input.{field} is not lowercase SHA-256 hex")
    if operation != "send":
        return
    try:
        digest = transport_envelope_digest(value["envelope_json"])
    except ValueError as exc:
        raise PluginSchemaError(f"$input.envelope_json {exc}") from exc
    if digest != value["envelope_sha256"]:
        raise PluginSchemaError("$input.envelope_sha256 does not bind envelope_json")


def validate_transport_output(value: Mapping[str, Any]) -> None:
    """Validate provider output and operation-specific state invariants."""

    if not isinstance(value, Mapping):
        raise PluginSchemaError("$output must be an object")
    _validate_document_size(value, path="$output")
    validate_instance(value, TRANSPORT_OUTPUT_SCHEMA, path="$output")
    for field in ("local_route_id", "transport_id"):
        try:
            validate_transport_identifier(value[field], field=field)
        except ValueError as exc:
            raise PluginSchemaError(f"$output.{field} is invalid") from exc
    if not value["ready"]:
        raise PluginSchemaError("$output built-in operation must report ready")
    if value["detail"]:
        raise PluginSchemaError("$output ready operation cannot carry detail")
    if value["max_envelope_bytes"] > TRANSPORT_MAX_ENVELOPE_BYTES:
        raise PluginSchemaError("$output max_envelope_bytes exceeds the wire limit")
    if value["max_batch_size"] > TRANSPORT_MAX_BATCH_SIZE:
        raise PluginSchemaError("$output max_batch_size exceeds the wire limit")
    if value["max_lease_ms"] > TRANSPORT_MAX_LEASE_MS:
        raise PluginSchemaError("$output max_lease_ms exceeds the wire limit")
    if not value["supports_ack"]:
        raise PluginSchemaError("$output v1 provider must support acknowledgement")
    if value["supports_streaming"]:
        raise PluginSchemaError("$output v1 has no streaming operation")

    operation = value["operation"]
    if operation == "probe":
        _require_empty_delivery_state(value)
        return
    if operation == "send":
        _validate_send_output(value)
        return
    if operation == "receive":
        _validate_receive_output(value)
        return
    if operation == "ack":
        _validate_ack_output(value)
        return
    raise PluginSchemaError("$output.operation is unsupported")


def validate_transport_exchange(
    request: Mapping[str, Any],
    response: Mapping[str, Any],
) -> None:
    """Bind one validated provider response to its validated request."""

    operation = request.get("operation")
    if response.get("operation") != operation:
        raise PluginSchemaError("$output.operation does not match $input.operation")
    if operation == "probe":
        return
    if operation == "send":
        for field in ("delivery_id", "expires_at_ms"):
            if response.get(field) != request.get(field):
                raise PluginSchemaError(
                    f"$output.{field} does not match $input.{field}"
                )
        return
    if operation == "receive":
        if response.get("receive_id") != request.get("receive_id"):
            raise PluginSchemaError(
                "$output.receive_id does not match $input.receive_id"
            )
        items = response.get("items")
        if isinstance(items, list) and len(items) > request.get("limit", 0):
            raise PluginSchemaError("$output.items exceed $input.limit")
        return
    if operation == "ack":
        for field in ("receive_id", "lease_id", "batch_sha256"):
            if response.get(field) != request.get(field):
                raise PluginSchemaError(
                    f"$output.{field} does not match $input.{field}"
                )
        return
    raise PluginSchemaError("$input.operation is unsupported")


def validate_transport_authority(
    request: Mapping[str, Any],
    authority: InvocationAuthority,
) -> None:
    """Require Host-derived resource scope before addressing a destination."""

    if not isinstance(authority, InvocationAuthority):
        raise PluginAuthorizationError("transport requires local invocation authority")
    if TRANSPORT_CAPABILITY_ID not in authority.capability_ids:
        raise PluginAuthorizationError("transport authority lacks capability scope")
    if request.get("operation") != "send":
        return
    destination = request.get("destination_route_id")
    if destination not in authority.resource_ids:
        raise PluginAuthorizationError(
            "transport destination is outside the authorized resource scope"
        )


def validate_transport_error(value: Mapping[str, Any]) -> None:
    """Validate a language-neutral transport failure envelope."""

    if not isinstance(value, Mapping):
        raise PluginSchemaError("$error must be an object")
    validate_instance(value, TRANSPORT_ERROR_SCHEMA, path="$error")
    expected = bool(TRANSPORT_ERROR_MODEL[value["code"]]["retryable"])
    if value["retryable"] is not expected:
        raise PluginSchemaError("$error.retryable contradicts the declared error model")


def transport_protocol_document() -> Dict[str, Any]:
    """Return the complete language-neutral v1 protocol document."""

    return {
        "capability": TRANSPORT_LOCAL_CONTRACT.to_dict(),
        "canonicalization": {
            "encoding": "utf-8",
            "floats": "forbidden",
            "integer_range": [
                -TRANSPORT_MAX_SAFE_INTEGER,
                TRANSPORT_MAX_SAFE_INTEGER,
            ],
            "object_keys": "unicode-codepoint-ascending",
            "root": "object",
            "whitespace": "none",
        },
        "error_model": {
            code: dict(specification)
            for code, specification in TRANSPORT_ERROR_MODEL.items()
        },
        "error_schema": deepcopy(TRANSPORT_ERROR_SCHEMA),
        "identifier_rules": {
            "direct_urls": "forbidden",
            "max_chars": _MAX_IDENTIFIER_CHARS,
            "pattern": _IDENTIFIER_RE.pattern,
            "path_segments": ["dot-and-dot-dot-forbidden", "empty-forbidden"],
            "route_semantics": "opaque-provider-route-id-not-authority",
        },
        "input_schema": deepcopy(TRANSPORT_INPUT_SCHEMA),
        "operation_rules": {
            operation: {
                "allowed": list(rule["allowed"]),
                "required": list(rule["required"]),
            }
            for operation, rule in sorted(_OPERATION_RULES.items())
        },
        "output_schema": deepcopy(TRANSPORT_OUTPUT_SCHEMA),
        "semantics": {
            "ack": "atomically-acknowledge-the-entire-leased-batch",
            "authority": "host-owned-never-derived-from-transport-metadata",
            "batch_digest": "ordered-full-descriptor-with-envelope-sha256",
            "delivery": "ephemeral-at-least-once-until-ack-within-provider-lifetime",
            "envelope": "opaque-canonical-json-reverified-after-receive",
            "receive": "caller-principal-inbox-with-expiring-exclusive-lease",
            "response_binding": "host-validates-operation-identifiers-and-request-limits",
            "route_authorization": "explicit-host-resource-scope-before-provider-invocation",
            "retry": "ids-bind-immutable-input-within-provider-retention-window",
            "source": "provider-must-not-accept-a-caller-supplied-source-identity",
        },
        "wire_limits": {
            "max_batch_size": TRANSPORT_MAX_BATCH_SIZE,
            "max_document_bytes": TRANSPORT_MAX_DOCUMENT_BYTES,
            "max_envelope_bytes": TRANSPORT_MAX_ENVELOPE_BYTES,
            "max_lease_ms": TRANSPORT_MAX_LEASE_MS,
            "max_safe_integer": TRANSPORT_MAX_SAFE_INTEGER,
        },
    }


def transport_protocol_digest() -> str:
    """Return the content digest of the full portable protocol document."""

    return f"sha256:{hashlib.sha256(canonical_json(transport_protocol_document())).hexdigest()}"


def transport_contract_vector() -> Dict[str, Any]:
    """Return capability metadata for checked-in conformance artifacts."""

    return {
        "capability": TRANSPORT_LOCAL_CONTRACT.to_dict(),
        "expected_digest": TRANSPORT_LOCAL_CONTRACT.digest,
        "expected_protocol_digest": transport_protocol_digest(),
        "format": "nth-dao-plugin-capability-conformance-v1",
        "input_schema": "transport-input-schema-v1.json",
        "operation_vectors": "transport-wire-cases-v1.json",
        "output_schema": "transport-output-schema-v1.json",
        "profile": "local-ephemeral",
        "schema_version": 1,
    }


def transport_wire_vectors() -> Dict[str, Any]:
    """Return portable examples consumed independently by other runtimes."""

    protocol = transport_protocol_document()
    envelope_document = {
        "id": "message-1",
        "payload": {"body": "hello"},
        "type": "chat.message",
    }
    envelope_json = canonical_json(envelope_document).decode("utf-8")
    item = {
        "accepted_at_ms": 1_750_000_000_000,
        "delivery_id": "delivery-1",
        "envelope_json": envelope_json,
        "envelope_sha256": transport_envelope_digest(envelope_json),
        "expires_at_ms": 1_750_000_060_000,
        "transport_delivery_id": "delivery:sha256:" + "c" * 64,
    }
    return {
        key: deepcopy(protocol[key])
        for key in (
            "canonicalization",
            "error_model",
            "error_schema",
            "identifier_rules",
            "operation_rules",
            "semantics",
            "wire_limits",
        )
    } | {
        "batch_digest_examples": [
            {"items": [item], "sha256": transport_batch_digest([item])}
        ],
        "canonical_examples": [
            {
                "canonical_utf8": envelope_json,
                "document": envelope_document,
                "sha256": transport_envelope_digest(envelope_json),
            }
        ],
        "valid_errors": [
            TransportOperationError(
                "quota-exceeded", "principal capacity is exhausted"
            ).to_wire(),
            TransportOperationError("conflict", "delivery id changed").to_wire(),
        ],
    }


def _validate_send_output(value: Mapping[str, Any]) -> None:
    if (
        not value["accepted"]
        or value["acknowledged"]
        or value["acknowledged_count"]
        or value["found"]
        or value["items"]
        or value["receive_id"]
        or value["lease_id"]
        or value["lease_expires_at_ms"]
        or value["batch_sha256"]
        or value["state"] not in {"queued", "leased", "acknowledged", "expired"}
        or not value["transport_delivery_id"]
    ):
        raise PluginSchemaError("$output send state is inconsistent")
    _validate_delivery_summary(value)
    try:
        validate_transport_identifier(
            value["transport_delivery_id"], field="transport_delivery_id"
        )
    except ValueError as exc:
        raise PluginSchemaError("$output.transport_delivery_id is invalid") from exc


def _validate_receive_output(value: Mapping[str, Any]) -> None:
    if (
        value["accepted"]
        or value["acknowledged"]
        or value["acknowledged_count"]
        or value["delivery_id"]
        or value["expires_at_ms"]
        or value["transport_delivery_id"]
        or not value["receive_id"]
    ):
        raise PluginSchemaError("$output receive state is inconsistent")
    try:
        validate_transport_identifier(value["receive_id"], field="receive_id")
    except ValueError as exc:
        raise PluginSchemaError("$output.receive_id is invalid") from exc
    if not value["found"]:
        if (
            value["items"]
            or value["lease_id"]
            or value["lease_expires_at_ms"]
            or value["batch_sha256"]
            or value["state"]
        ):
            raise PluginSchemaError("$output empty receive state is inconsistent")
        return
    if (
        not value["items"]
        or not value["lease_id"]
        or value["lease_expires_at_ms"] <= 0
        or value["state"] != "leased"
        or _SHA256_RE.fullmatch(value["batch_sha256"]) is None
    ):
        raise PluginSchemaError("$output leased receive state is incomplete")
    if len(value["items"]) > value["max_batch_size"]:
        raise PluginSchemaError("$output items exceed the provider batch limit")
    try:
        validate_transport_identifier(value["lease_id"], field="lease_id")
    except ValueError as exc:
        raise PluginSchemaError("$output.lease_id is invalid") from exc
    transport_delivery_ids: set[str] = set()
    for index, item in enumerate(value["items"]):
        try:
            validate_transport_identifier(item["delivery_id"], field="delivery_id")
            validate_transport_identifier(
                item["transport_delivery_id"], field="transport_delivery_id"
            )
            digest = transport_envelope_digest(item["envelope_json"])
        except ValueError as exc:
            raise PluginSchemaError(f"$output.items[{index}] is invalid") from exc
        if _SHA256_RE.fullmatch(item["envelope_sha256"]) is None:
            raise PluginSchemaError(
                f"$output.items[{index}].envelope_sha256 is invalid"
            )
        if digest != item["envelope_sha256"]:
            raise PluginSchemaError(
                f"$output.items[{index}].envelope_sha256 does not bind envelope_json"
            )
        if item["accepted_at_ms"] > item["expires_at_ms"]:
            raise PluginSchemaError(f"$output.items[{index}] expires before acceptance")
        if value["lease_expires_at_ms"] > item["expires_at_ms"]:
            raise PluginSchemaError(
                f"$output.items[{index}] expires before the receive lease"
            )
        if value["lease_expires_at_ms"] <= item["accepted_at_ms"]:
            raise PluginSchemaError(
                f"$output.items[{index}] lease does not follow acceptance"
            )
        if item["transport_delivery_id"] in transport_delivery_ids:
            raise PluginSchemaError("$output transport delivery ids must be unique")
        transport_delivery_ids.add(item["transport_delivery_id"])
    if transport_batch_digest(value["items"]) != value["batch_sha256"]:
        raise PluginSchemaError("$output.batch_sha256 does not bind items")


def _validate_ack_output(value: Mapping[str, Any]) -> None:
    if (
        value["accepted"]
        or not value["acknowledged"]
        or value["acknowledged_count"] <= 0
        or value["found"]
        or value["items"]
        or value["delivery_id"]
        or value["expires_at_ms"]
        or value["transport_delivery_id"]
        or not value["receive_id"]
        or not value["lease_id"]
        or value["lease_expires_at_ms"]
        or value["state"] != "acknowledged"
        or _SHA256_RE.fullmatch(value["batch_sha256"]) is None
    ):
        raise PluginSchemaError("$output ack state is inconsistent")
    for field in ("receive_id", "lease_id"):
        try:
            validate_transport_identifier(value[field], field=field)
        except ValueError as exc:
            raise PluginSchemaError(f"$output.{field} is invalid") from exc


def _validate_delivery_summary(value: Mapping[str, Any]) -> None:
    try:
        validate_transport_identifier(value["delivery_id"], field="delivery_id")
    except ValueError as exc:
        raise PluginSchemaError("$output.delivery_id is invalid") from exc
    if value["expires_at_ms"] <= 0:
        raise PluginSchemaError("$output.expires_at_ms must identify the delivery")


def _require_empty_delivery_state(value: Mapping[str, Any]) -> None:
    if (
        value["accepted"]
        or value["acknowledged"]
        or value["acknowledged_count"]
        or value["batch_sha256"]
        or value["delivery_id"]
        or value["expires_at_ms"]
        or value["found"]
        or value["items"]
        or value["lease_expires_at_ms"]
        or value["lease_id"]
        or value["receive_id"]
        or value["replayed"]
        or value["state"]
        or value["transport_delivery_id"]
    ):
        raise PluginSchemaError("$output probe state is inconsistent")


def _validate_safe_integers(value: Any, path: str = "$envelope") -> None:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, int):
        if not -TRANSPORT_MAX_SAFE_INTEGER <= value <= TRANSPORT_MAX_SAFE_INTEGER:
            raise ValueError(f"integer at {path} exceeds the portable safe range")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_safe_integers(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _validate_safe_integers(item, f"{path}.{key}")
        return
    if isinstance(value, float):
        raise ValueError(f"float at {path} is not portable canonical JSON")
    raise ValueError(f"unsupported value at {path}")


def _validate_document_size(value: Mapping[str, Any], *, path: str) -> None:
    try:
        encoded = canonical_json(dict(value))
    except (RecursionError, TypeError, ValueError) as exc:
        raise PluginSchemaError(f"{path} is not canonical JSON data") from exc
    if len(encoded) > TRANSPORT_MAX_DOCUMENT_BYTES:
        raise PluginSchemaError(
            f"{path} exceeds {TRANSPORT_MAX_DOCUMENT_BYTES} canonical UTF-8 bytes"
        )


__all__ = [
    "TRANSPORT_CAPABILITY_ID",
    "TRANSPORT_CAPABILITY_VERSION",
    "TRANSPORT_ERROR_MODEL",
    "TRANSPORT_ERROR_SCHEMA",
    "TRANSPORT_INPUT_SCHEMA",
    "TRANSPORT_LOCAL_CONTRACT",
    "TRANSPORT_MAX_BATCH_SIZE",
    "TRANSPORT_MAX_DOCUMENT_BYTES",
    "TRANSPORT_MAX_ENVELOPE_BYTES",
    "TRANSPORT_MAX_LEASE_MS",
    "TRANSPORT_MAX_SAFE_INTEGER",
    "TRANSPORT_OUTPUT_SCHEMA",
    "TransportOperationError",
    "canonical_transport_envelope",
    "transport_batch_digest",
    "transport_contract_vector",
    "transport_envelope_digest",
    "transport_operation_rule",
    "transport_protocol_digest",
    "transport_protocol_document",
    "transport_wire_vectors",
    "validate_transport_identifier",
    "validate_transport_authority",
    "validate_transport_exchange",
    "validate_transport_error",
    "validate_transport_input",
    "validate_transport_output",
]
