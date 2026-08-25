"""Language-neutral agent session capability contract.

The plugin wire contract deliberately excludes commands, environment variables,
working directories, credentials, and arbitrary backend configuration. Those
values belong to the host policy boundary and must never arrive from an
invocation document.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import hashlib
from typing import Any, Dict

from nth_dao.canonical_json import canonical_json

from .contracts import CapabilityContract, schema_digest
from .schema import PluginSchemaError, validate_instance

AGENT_SESSION_CAPABILITY_ID = "org.nth-dao.agent.session"
AGENT_SESSION_CAPABILITY_VERSION = "2.0.0"
AGENT_SESSION_LEGACY_CAPABILITY_VERSION = "1.0.0"
AGENT_SESSION_MAX_DOCUMENT_BYTES = 1_048_576

_MAX_SESSION_ID_CHARS = 128
_MAX_TURN_ID_CHARS = 128
_MAX_GOAL_CHARS = 8_192
_MAX_MODEL_CHARS = 256
_MAX_PROMPT_CHARS = 262_144
_MAX_SYSTEM_PROMPT_CHARS = 65_536
_MAX_RESPONSE_CHARS = 524_288
_MAX_ERROR_CHARS = 4_096
_MAX_TOOL_CALLS = 64

_CAPABILITIES_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "max_context_tokens": {"type": "integer", "minimum": 0},
        "notes": {"type": "string", "maxLength": 2_048},
        "supports_multi_turn": {"type": "boolean"},
        "supports_streaming": {"type": "boolean"},
        "supports_system_prompt": {"type": "boolean"},
        "supports_temperature": {"type": "boolean"},
        "supports_tools": {"type": "boolean"},
    },
    "required": [
        "max_context_tokens",
        "notes",
        "supports_multi_turn",
        "supports_streaming",
        "supports_system_prompt",
        "supports_temperature",
        "supports_tools",
    ],
}

_TOOL_CALL_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "arguments_json": {"type": "string", "maxLength": 65_536},
        "id": {"type": "string", "minLength": 1, "maxLength": 256},
        "name": {"type": "string", "minLength": 1, "maxLength": 256},
    },
    "required": ["arguments_json", "id", "name"],
}

AGENT_SESSION_INPUT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "goal": {"type": "string", "maxLength": _MAX_GOAL_CHARS},
        "max_tokens": {"type": "integer", "minimum": 1, "maximum": 1_000_000},
        "model": {"type": "string", "maxLength": _MAX_MODEL_CHARS},
        "operation": {
            "type": "string",
            "enum": ["cancel", "close", "open", "probe", "status", "turn"],
        },
        "prompt": {"type": "string", "maxLength": _MAX_PROMPT_CHARS},
        "session_id": {
            "type": "string",
            "minLength": 1,
            "maxLength": _MAX_SESSION_ID_CHARS,
        },
        "system_prompt": {
            "type": "string",
            "maxLength": _MAX_SYSTEM_PROMPT_CHARS,
        },
        "temperature_milli": {"type": "integer", "minimum": 0, "maximum": 2_000},
        "timeout_ms": {"type": "integer", "minimum": 100, "maximum": 3_600_000},
        "turn_id": {
            "type": "string",
            "minLength": 1,
            "maxLength": _MAX_TURN_ID_CHARS,
        },
    },
    "required": ["operation"],
}

AGENT_SESSION_OUTPUT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "backend_id": {"type": "string", "minLength": 1, "maxLength": 128},
        "capabilities": _CAPABILITIES_SCHEMA,
        "content": {"type": "string", "maxLength": _MAX_RESPONSE_CHARS},
        "detail": {"type": "string", "maxLength": _MAX_ERROR_CHARS},
        "duration_ms": {"type": "integer", "minimum": 0},
        "error": {"type": "string", "maxLength": _MAX_ERROR_CHARS},
        "finish_reason": {
            "type": "string",
            "enum": ["", "error", "length", "stop", "timeout", "tool_call"],
        },
        "final_status": {
            "type": "string",
            "enum": ["", "completed", "error", "interrupted", "timeout"],
        },
        "input_tokens": {"type": "integer", "minimum": 0},
        "latency_ms": {"type": "integer", "minimum": 0},
        "lease_remaining_ms": {"type": "integer", "minimum": 0},
        "operation": {
            "type": "string",
            "enum": ["cancel", "close", "open", "probe", "status", "turn"],
        },
        "output_tokens": {"type": "integer", "minimum": 0},
        "ready": {"type": "boolean"},
        "receipt_content_hash": {"type": "string", "maxLength": 64},
        "receipt_id": {"type": "string", "maxLength": 256},
        "replayed": {"type": "boolean"},
        "session_id": {"type": "string", "maxLength": _MAX_SESSION_ID_CHARS},
        "state": {
            "type": "string",
            "enum": ["active", "cancelled", "closed", "ready", "unavailable"],
        },
        "tool_calls": {
            "type": "array",
            "maxItems": _MAX_TOOL_CALLS,
            "items": _TOOL_CALL_SCHEMA,
        },
        "total_input_tokens": {"type": "integer", "minimum": 0},
        "total_output_tokens": {"type": "integer", "minimum": 0},
        "total_turns": {"type": "integer", "minimum": 0},
        "turn_id": {"type": "string", "maxLength": _MAX_TURN_ID_CHARS},
    },
    "required": [
        "backend_id",
        "capabilities",
        "content",
        "detail",
        "duration_ms",
        "error",
        "finish_reason",
        "final_status",
        "input_tokens",
        "latency_ms",
        "lease_remaining_ms",
        "operation",
        "output_tokens",
        "ready",
        "receipt_content_hash",
        "receipt_id",
        "replayed",
        "session_id",
        "state",
        "tool_calls",
        "total_input_tokens",
        "total_output_tokens",
        "total_turns",
        "turn_id",
    ],
}

# Version 1 did not advertise temperature support or Receipt references. Keep
# its exact schema and digest available so existing providers remain
# interoperable without making the current schema permissive.
AGENT_SESSION_V1_OUTPUT_SCHEMA: Dict[str, Any] = deepcopy(
    AGENT_SESSION_OUTPUT_SCHEMA
)
_v1_capabilities_schema = AGENT_SESSION_V1_OUTPUT_SCHEMA["properties"][
    "capabilities"
]
del _v1_capabilities_schema["properties"]["supports_temperature"]
_v1_capabilities_schema["required"].remove("supports_temperature")
for _v1_receipt_field in ("receipt_content_hash", "receipt_id"):
    del AGENT_SESSION_V1_OUTPUT_SCHEMA["properties"][_v1_receipt_field]
    AGENT_SESSION_V1_OUTPUT_SCHEMA["required"].remove(_v1_receipt_field)

_AGENT_SESSION_OPERATION_RULES = {
    "cancel": {
        "allowed": ("operation", "session_id"),
        "required": ("operation", "session_id"),
    },
    "close": {
        "allowed": ("operation", "session_id"),
        "required": ("operation", "session_id"),
    },
    "open": {
        "allowed": (
            "goal",
            "max_tokens",
            "model",
            "operation",
            "session_id",
            "temperature_milli",
            "timeout_ms",
        ),
        "required": ("goal", "operation", "session_id"),
    },
    "probe": {
        "allowed": ("operation", "timeout_ms"),
        "required": ("operation",),
    },
    "status": {
        "allowed": ("operation", "session_id"),
        "required": ("operation", "session_id"),
    },
    "turn": {
        "allowed": (
            "operation",
            "prompt",
            "session_id",
            "system_prompt",
            "timeout_ms",
            "turn_id",
        ),
        "required": ("operation", "prompt", "session_id", "turn_id"),
    },
}

_AGENT_SESSION_OUTPUT_RULES_DOCUMENT = {
    "common": {
        "document_max_bytes": AGENT_SESSION_MAX_DOCUMENT_BYTES,
        "max_tokens_semantics": "maximum-output-tokens-per-turn",
        "receipt_references": (
            "v2-turn-only-paired-id-and-lowercase-sha256-content-hash"
        ),
        "replayed_allowed_operations": ["turn"],
        "tool_call_ids": "non-empty-and-unique",
        "turn_tokens_must_not_exceed_totals": True,
    },
    "operations": {
        "cancel": {
            "final_status": ["interrupted"],
            "ready": [True],
            "session_id": "required",
            "state": ["cancelled"],
            "turn_id": "empty",
        },
        "close": {
            "final_status": ["completed", "error", "interrupted", "timeout"],
            "ready": [True],
            "session_id": "required",
            "state": ["closed"],
            "turn_id": "empty",
        },
        "open": {
            "final_status": [""],
            "ready": [True],
            "session_id": "required",
            "state": ["active"],
            "turn_id": "empty",
        },
        "probe": {
            "final_status": [""],
            "ready_state": {"false": "unavailable", "true": "ready"},
            "session_id": "empty",
            "turn_id": "empty",
        },
        "status": {
            "final_status": [""],
            "ready": [True],
            "session_id": "required",
            "state": ["active"],
            "turn_id": "empty",
        },
        "turn": {
            "final_status": [""],
            "finish_reason": ["error", "length", "stop", "timeout", "tool_call"],
            "ready": [True],
            "session_id": "required",
            "state": ["active"],
            "turn_id": "required",
        },
    },
}

AGENT_SESSION_CONTRACT = CapabilityContract(
    capability_id=AGENT_SESSION_CAPABILITY_ID,
    version=AGENT_SESSION_CAPABILITY_VERSION,
    input_schema_digest=schema_digest(AGENT_SESSION_INPUT_SCHEMA),
    output_schema_digest=schema_digest(AGENT_SESSION_OUTPUT_SCHEMA),
    effects=("none",),
    consistency="C0",
    privacy="confidential",
    security="verified-input",
    cardinality="many",
    deterministic=False,
    retention="ephemeral",
    failure_semantics="at-most-once",
)

AGENT_SESSION_SUPERVISED_CONTRACT = CapabilityContract(
    capability_id=AGENT_SESSION_CAPABILITY_ID,
    version=AGENT_SESSION_CAPABILITY_VERSION,
    input_schema_digest=schema_digest(AGENT_SESSION_INPUT_SCHEMA),
    output_schema_digest=schema_digest(AGENT_SESSION_OUTPUT_SCHEMA),
    effects=("network-read", "network-write"),
    consistency="C0",
    privacy="confidential",
    security="verified-input",
    cardinality="many",
    deterministic=False,
    retention="durable",
    failure_semantics="at-most-once",
)

AGENT_SESSION_V1_CONTRACT = CapabilityContract(
    capability_id=AGENT_SESSION_CAPABILITY_ID,
    version=AGENT_SESSION_LEGACY_CAPABILITY_VERSION,
    input_schema_digest=schema_digest(AGENT_SESSION_INPUT_SCHEMA),
    output_schema_digest=schema_digest(AGENT_SESSION_V1_OUTPUT_SCHEMA),
    effects=("none",),
    consistency="C0",
    privacy="confidential",
    security="verified-input",
    cardinality="many",
    deterministic=False,
    retention="ephemeral",
    failure_semantics="at-most-once",
)


def agent_session_operation_rule(operation: str) -> tuple[frozenset[str], frozenset[str]]:
    """Return immutable allowed/required fields for one wire operation."""

    rule = _AGENT_SESSION_OPERATION_RULES.get(operation)
    if rule is None:
        raise ValueError("unsupported agent session operation")
    return frozenset(rule["allowed"]), frozenset(rule["required"])


def agent_session_protocol_document(
    version: str = AGENT_SESSION_CAPABILITY_VERSION,
) -> Dict[str, Any]:
    """Return one complete, versioned language-neutral protocol document."""

    if version == AGENT_SESSION_CAPABILITY_VERSION:
        contract = AGENT_SESSION_CONTRACT
        output_schema = AGENT_SESSION_OUTPUT_SCHEMA
    elif version == AGENT_SESSION_LEGACY_CAPABILITY_VERSION:
        contract = AGENT_SESSION_V1_CONTRACT
        output_schema = AGENT_SESSION_V1_OUTPUT_SCHEMA
    else:
        raise ValueError("unsupported agent session protocol version")
    output_rules = deepcopy(_AGENT_SESSION_OUTPUT_RULES_DOCUMENT)
    if version == AGENT_SESSION_LEGACY_CAPABILITY_VERSION:
        output_rules["common"].pop("receipt_references", None)

    return {
        "capability": contract.to_dict(),
        "input_schema": deepcopy(AGENT_SESSION_INPUT_SCHEMA),
        "identifier_rules": {
            "session_id": {
                "forbidden_codepoints": ["U+0000-U+001F", "U+007F"],
                "max_length": _MAX_SESSION_ID_CHARS,
                "min_length": 1,
                "trimmed": True,
            },
            "turn_id": {
                "forbidden_codepoints": ["U+0000-U+001F", "U+007F"],
                "max_length": _MAX_TURN_ID_CHARS,
                "min_length": 1,
                "trimmed": True,
            },
        },
        "operation_rules": {
            operation: {
                "allowed": list(rule["allowed"]),
                "required": list(rule["required"]),
            }
            for operation, rule in sorted(_AGENT_SESSION_OPERATION_RULES.items())
        },
        "output_rules": output_rules,
        "output_schema": deepcopy(output_schema),
        "wire_limits": {
            "max_document_bytes": AGENT_SESSION_MAX_DOCUMENT_BYTES,
            "size_unit": "canonical-json-utf8-bytes",
        },
    }


def agent_session_protocol_digest(
    version: str = AGENT_SESSION_CAPABILITY_VERSION,
) -> str:
    document = agent_session_protocol_document(version)
    return f"sha256:{hashlib.sha256(canonical_json(document)).hexdigest()}"


def validate_agent_session_identifier(value: Any, *, field: str) -> str:
    """Validate the shared session_id/turn_id lexical policy."""

    if field not in {"session_id", "turn_id"}:
        raise ValueError("unsupported agent session identifier field")
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 128
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)
    ):
        raise ValueError(f"{field} is invalid")
    return value


def validate_agent_session_input(value: Mapping[str, Any]) -> None:
    """Validate schema, operation fields, and shared identifier policy.

    Adapters call this before changing local lifecycle state. The PluginHost
    repeats the schema check at the trust boundary; the duplication is
    intentional because a local validation failure proves that no provider
    side effect could have occurred.
    """

    if not isinstance(value, Mapping):
        raise PluginSchemaError("$input must be an object")
    _validate_agent_session_document_size(value, path="$input")
    validate_instance(value, AGENT_SESSION_INPUT_SCHEMA, path="$input")
    operation = value.get("operation")
    try:
        allowed, required = agent_session_operation_rule(operation)
    except ValueError as exc:
        raise PluginSchemaError("$input.operation is unsupported") from exc
    unexpected = set(value) - allowed
    missing = required - set(value)
    if unexpected:
        raise PluginSchemaError(
            f"$input operation does not accept fields: {sorted(unexpected)}"
        )
    if missing:
        raise PluginSchemaError(
            f"$input operation requires fields: {sorted(missing)}"
        )
    for field in ("session_id", "turn_id"):
        if field not in value:
            continue
        try:
            validate_agent_session_identifier(value[field], field=field)
        except ValueError as exc:
            raise PluginSchemaError(f"$input.{field} is invalid") from exc


def validate_agent_session_output(
    value: Mapping[str, Any],
    *,
    version: str = AGENT_SESSION_CAPABILITY_VERSION,
) -> None:
    """Validate one response including operation-specific state semantics."""

    if not isinstance(value, Mapping):
        raise PluginSchemaError("$output must be an object")
    if version == AGENT_SESSION_CAPABILITY_VERSION:
        output_schema = AGENT_SESSION_OUTPUT_SCHEMA
    elif version == AGENT_SESSION_LEGACY_CAPABILITY_VERSION:
        output_schema = AGENT_SESSION_V1_OUTPUT_SCHEMA
    else:
        raise PluginSchemaError("$output protocol version is unsupported")
    _validate_agent_session_document_size(value, path="$output")
    validate_instance(value, output_schema, path="$output")
    operation = value["operation"]

    session_id = value["session_id"]
    turn_id = value["turn_id"]
    if operation == "probe":
        if session_id or turn_id:
            raise PluginSchemaError("$output probe identifiers must be empty")
    else:
        try:
            validate_agent_session_identifier(session_id, field="session_id")
        except ValueError as exc:
            raise PluginSchemaError("$output.session_id is invalid") from exc
        if operation == "turn":
            try:
                validate_agent_session_identifier(turn_id, field="turn_id")
            except ValueError as exc:
                raise PluginSchemaError("$output.turn_id is invalid") from exc
        elif turn_id:
            raise PluginSchemaError("$output.turn_id is only valid for turn")

    if value["replayed"] and operation != "turn":
        raise PluginSchemaError("$output.replayed is only valid for turn")
    if version == AGENT_SESSION_CAPABILITY_VERSION:
        receipt_id = value["receipt_id"]
        receipt_hash = value["receipt_content_hash"]
        if bool(receipt_id) != bool(receipt_hash):
            raise PluginSchemaError("$output Receipt references must be paired")
        if receipt_id and (
            receipt_id != receipt_id.strip()
            or any(ord(char) < 0x20 or ord(char) == 0x7F for char in receipt_id)
        ):
            raise PluginSchemaError("$output.receipt_id is invalid")
        if receipt_hash and (
            len(receipt_hash) != 64
            or any(char not in "0123456789abcdef" for char in receipt_hash)
        ):
            raise PluginSchemaError(
                "$output.receipt_content_hash is not lowercase SHA-256 hex"
            )
        if operation != "turn" and (receipt_id or receipt_hash):
            raise PluginSchemaError("$output Receipt references are turn-only")
    if value["input_tokens"] > value["total_input_tokens"]:
        raise PluginSchemaError("$output input tokens exceed session total")
    if value["output_tokens"] > value["total_output_tokens"]:
        raise PluginSchemaError("$output output tokens exceed session total")

    tool_calls = value["tool_calls"]
    tool_ids = [item["id"] for item in tool_calls]
    if len(tool_ids) != len(set(tool_ids)):
        raise PluginSchemaError("$output tool call ids must be unique")

    if operation == "probe":
        expected_state = "ready" if value["ready"] else "unavailable"
        if value["state"] != expected_state:
            raise PluginSchemaError("$output probe ready/state mismatch")
        _validate_idle_output(value, require_zero_totals=True)
        return
    if operation in {"open", "status"}:
        if not value["ready"] or value["state"] != "active":
            raise PluginSchemaError(f"$output {operation} must be ready and active")
        _validate_idle_output(value, require_zero_totals=operation == "open")
        if value["lease_remaining_ms"] <= 0:
            raise PluginSchemaError(f"$output {operation} requires an active lease")
        return
    if operation == "turn":
        if not value["ready"] or value["state"] != "active" or value["final_status"]:
            raise PluginSchemaError("$output turn lifecycle state is invalid")
        if value["lease_remaining_ms"] <= 0 or value["total_turns"] < 1:
            raise PluginSchemaError("$output turn requires counters and an active lease")
        reason = value["finish_reason"]
        if not reason:
            raise PluginSchemaError("$output turn requires a finish_reason")
        if (reason == "tool_call") != bool(tool_calls):
            raise PluginSchemaError("$output tool calls do not match finish_reason")
        if reason in {"error", "timeout"}:
            if not value["error"]:
                raise PluginSchemaError("$output failed turn requires error detail")
        elif value["error"]:
            raise PluginSchemaError("$output successful turn cannot carry an error")
        return

    _validate_idle_output(
        value,
        require_zero_totals=False,
        allow_error=True,
        allow_final_status=True,
    )
    if value["lease_remaining_ms"] != 0 or not value["ready"]:
        raise PluginSchemaError(f"$output {operation} terminal state is invalid")
    if operation == "cancel":
        if value["state"] != "cancelled" or value["final_status"] != "interrupted":
            raise PluginSchemaError("$output cancel lifecycle state is invalid")
    elif value["state"] != "closed" or value["final_status"] not in {
        "completed",
        "error",
        "interrupted",
        "timeout",
    }:
        raise PluginSchemaError("$output close lifecycle state is invalid")
    if value["final_status"] in {"error", "timeout"} and not value["error"]:
        raise PluginSchemaError("$output failed close requires error detail")
    if value["final_status"] in {"completed", "interrupted"} and value["error"]:
        raise PluginSchemaError("$output successful close/cancel cannot carry an error")


def _validate_agent_session_document_size(
    value: Mapping[str, Any],
    *,
    path: str,
) -> None:
    try:
        encoded = canonical_json(dict(value))
    except (RecursionError, TypeError, ValueError) as exc:
        raise PluginSchemaError(f"{path} must be finite canonical JSON") from exc
    if len(encoded) > AGENT_SESSION_MAX_DOCUMENT_BYTES:
        raise PluginSchemaError(
            f"{path} exceeds {AGENT_SESSION_MAX_DOCUMENT_BYTES} canonical UTF-8 bytes"
        )


def _validate_idle_output(
    value: Mapping[str, Any],
    *,
    require_zero_totals: bool,
    allow_error: bool = False,
    allow_final_status: bool = False,
) -> None:
    if (
        value["content"]
        or (value["error"] and not allow_error)
        or value["finish_reason"]
        or (value["final_status"] and not allow_final_status)
        or value["input_tokens"]
        or value["output_tokens"]
        or value["latency_ms"]
        or value.get("receipt_content_hash", "")
        or value.get("receipt_id", "")
        or value["replayed"]
        or value["tool_calls"]
    ):
        raise PluginSchemaError("$output idle operation carries turn-only fields")
    if require_zero_totals and (
        value["total_turns"]
        or value["total_input_tokens"]
        or value["total_output_tokens"]
    ):
        raise PluginSchemaError("$output new session/probe totals must be zero")


def capability_document(value: Any) -> Dict[str, Any]:
    """Project backend metadata onto the bounded wire schema."""

    max_context_tokens = getattr(value, "max_context_tokens", None)
    if type(max_context_tokens) is not int or max_context_tokens < 0:
        raise ValueError("max_context_tokens must be a non-negative integer")
    notes = getattr(value, "notes", None)
    if not isinstance(notes, str) or len(notes) > 2_048:
        raise ValueError("capability notes must be bounded text")
    boolean_fields = (
        "supports_multi_turn",
        "supports_streaming",
        "supports_system_prompt",
        "supports_temperature",
        "supports_tools",
    )
    values = {name: getattr(value, name, None) for name in boolean_fields}
    if any(type(item) is not bool for item in values.values()):
        raise ValueError("capability feature flags must be booleans")
    return {
        "max_context_tokens": max_context_tokens,
        "notes": notes,
        **values,
    }


__all__ = [
    "AGENT_SESSION_CAPABILITY_ID",
    "AGENT_SESSION_CAPABILITY_VERSION",
    "AGENT_SESSION_CONTRACT",
    "AGENT_SESSION_INPUT_SCHEMA",
    "AGENT_SESSION_LEGACY_CAPABILITY_VERSION",
    "AGENT_SESSION_MAX_DOCUMENT_BYTES",
    "AGENT_SESSION_OUTPUT_SCHEMA",
    "AGENT_SESSION_SUPERVISED_CONTRACT",
    "AGENT_SESSION_V1_CONTRACT",
    "AGENT_SESSION_V1_OUTPUT_SCHEMA",
    "agent_session_operation_rule",
    "agent_session_protocol_digest",
    "agent_session_protocol_document",
    "capability_document",
    "validate_agent_session_input",
    "validate_agent_session_identifier",
    "validate_agent_session_output",
]
