"""Language-neutral contract for non-authoritative market search indexes.

The host verifies signed Task and Trade Offer source objects before projecting
them into this capability. An index may improve discovery and ranking, but it
never becomes listing, identity, inventory, claim, agreement, or settlement
authority. Callers must resolve and verify the exact content-addressed source
object again before acting on a result.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from copy import deepcopy
import hashlib
import json
import re
from types import MappingProxyType
from typing import Any, Dict
from urllib.parse import urlsplit

from nth_dao.canonical_json import canonical_json
from nth_dao.did_key import is_did_key

from .contracts import CAPABILITY_EFFECTS, CapabilityContract, schema_digest
from .host import PluginInvocationError
from .schema import PluginSchemaError, validate_instance


MARKET_INDEX_CAPABILITY_ID = "org.nth-dao.market.index"
MARKET_INDEX_CAPABILITY_VERSION = "1.0.0"
MARKET_INDEX_MAX_DOCUMENT_BYTES = 1_048_576
MARKET_INDEX_MAX_ENTRY_BYTES = 32_768
MARKET_INDEX_MAX_CURSOR_CHARS = 1_024
MARKET_INDEX_MAX_CURSOR_AGE_MS = 300_000
MARKET_INDEX_MUTATION_REPLAY_WINDOW_MS = 300_000
MARKET_INDEX_STALE_RETENTION_MS = 300_000
MARKET_INDEX_MAX_QUERY_CHARS = 200
MARKET_INDEX_MAX_PAGE_SIZE = 20
MARKET_INDEX_MAX_SAFE_INTEGER = 9_007_199_254_740_991

_MAX_IDENTIFIER_CHARS = 256
_MAX_LIST_ITEMS = 32
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_CATEGORY_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_RAW_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_OBJECT_KEY_RE = re.compile(r"^[\x20-\x7e]{1,256}$")
_INTENTS = ("exchange", "provide", "request")
_ORIGINS = ("federated", "local")


MARKET_INDEX_ERROR_MODEL: Mapping[str, Mapping[str, Any]] = MappingProxyType(
    {
        "conflict": {
            "retryable": False,
            "meaning": "the expected content digest does not match the live entry",
        },
        "expired-entry": {
            "retryable": False,
            "meaning": "the entry is already beyond the index stale-retention horizon",
        },
        "inactive": {
            "retryable": True,
            "meaning": "the provider is not currently active",
        },
        "invalid-cursor": {
            "retryable": False,
            "meaning": "the search cursor is malformed or belongs to another principal",
        },
        "limit-exceeded": {
            "retryable": False,
            "meaning": "the request exceeds a provider or wire limit",
        },
        "quota-exceeded": {
            "retryable": True,
            "meaning": "temporary provider or principal capacity is exhausted",
        },
        "stale-cursor": {
            "retryable": True,
            "meaning": "the index changed after the search page was created",
        },
    }
)
MARKET_INDEX_ERROR_MODEL = MappingProxyType(
    {
        code: MappingProxyType(dict(specification))
        for code, specification in MARKET_INDEX_ERROR_MODEL.items()
    }
)


class MarketIndexOperationError(PluginInvocationError):
    """Stable provider-domain failure for language-neutral callers."""

    def __init__(self, code: str, detail: str) -> None:
        specification = MARKET_INDEX_ERROR_MODEL.get(code)
        if specification is None:
            raise ValueError("unsupported market index error code")
        if not isinstance(detail, str) or not detail or len(detail) > 512:
            raise ValueError("market index error detail must be bounded text")
        self.code = code
        self.detail = detail
        self.retryable = bool(specification["retryable"])
        super().__init__(f"{code}: {detail}")


_ENTRY_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "capabilities": {
            "type": "array",
            "maxItems": _MAX_LIST_ITEMS,
            "items": {"type": "string", "minLength": 1, "maxLength": 256},
        },
        "categories": {
            "type": "array",
            "minItems": 1,
            "maxItems": _MAX_LIST_ITEMS,
            "items": {"type": "string", "minLength": 1, "maxLength": 64},
        },
        "entry_id": {"type": "string", "minLength": 1, "maxLength": 256},
        "intents": {
            "type": "array",
            "minItems": 1,
            "maxItems": len(_INTENTS),
            "items": {"type": "string", "enum": list(_INTENTS)},
        },
        "last_verified_at_ms": {
            "type": "integer",
            "minimum": 0,
            "maximum": MARKET_INDEX_MAX_SAFE_INTEGER,
        },
        "not_after_ms": {
            "type": "integer",
            "minimum": 0,
            "maximum": MARKET_INDEX_MAX_SAFE_INTEGER,
        },
        "origin": {"type": "string", "enum": list(_ORIGINS)},
        "projection_only": {"type": "boolean"},
        "published_at_ms": {
            "type": "integer",
            "minimum": 0,
            "maximum": MARKET_INDEX_MAX_SAFE_INTEGER,
        },
        "publisher_did": {"type": "string", "minLength": 1, "maxLength": 512},
        "source_digest": {"type": "string", "minLength": 71, "maxLength": 71},
        "source_locator": {"type": "string", "maxLength": 1024},
        "source_object_id": {"type": "string", "minLength": 1, "maxLength": 512},
        "source_peer": {"type": "string", "maxLength": 512},
        "source_protocol": {"type": "string", "minLength": 1, "maxLength": 256},
        "stale": {"type": "boolean"},
        "summary": {"type": "string", "maxLength": 2_000},
        "title": {"type": "string", "minLength": 1, "maxLength": 200},
        "version": {"type": "string", "enum": ["1"]},
    },
    "required": [
        "capabilities",
        "categories",
        "entry_id",
        "intents",
        "last_verified_at_ms",
        "not_after_ms",
        "origin",
        "projection_only",
        "published_at_ms",
        "publisher_did",
        "source_digest",
        "source_locator",
        "source_object_id",
        "source_peer",
        "source_protocol",
        "stale",
        "summary",
        "title",
        "version",
    ],
}

_SEARCH_ITEM_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "entry_id": {"type": "string", "minLength": 1, "maxLength": 256},
        "entry_json": {
            "type": "string",
            "minLength": 2,
            "maxLength": MARKET_INDEX_MAX_ENTRY_BYTES,
        },
        "entry_sha256": {"type": "string", "minLength": 64, "maxLength": 64},
        "score": {
            "type": "integer",
            "minimum": 0,
            "maximum": MARKET_INDEX_MAX_SAFE_INTEGER,
        },
    },
    "required": ["entry_id", "entry_json", "entry_sha256", "score"],
}

MARKET_INDEX_INPUT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "categories": {
            "type": "array",
            "maxItems": _MAX_LIST_ITEMS,
            "items": {"type": "string", "minLength": 1, "maxLength": 64},
        },
        "cursor": {"type": "string", "maxLength": MARKET_INDEX_MAX_CURSOR_CHARS},
        "entry_id": {"type": "string", "minLength": 1, "maxLength": 256},
        "entry_json": {
            "type": "string",
            "minLength": 2,
            "maxLength": MARKET_INDEX_MAX_ENTRY_BYTES,
        },
        "entry_sha256": {"type": "string", "minLength": 64, "maxLength": 64},
        "expected_entry_sha256": {"type": "string", "maxLength": 64},
        "include_stale": {"type": "boolean"},
        "intents": {
            "type": "array",
            "maxItems": len(_INTENTS),
            "items": {"type": "string", "enum": list(_INTENTS)},
        },
        "limit": {
            "type": "integer",
            "minimum": 1,
            "maximum": MARKET_INDEX_MAX_PAGE_SIZE,
        },
        "operation": {
            "type": "string",
            "enum": ["get", "probe", "remove", "search", "upsert"],
        },
        "q": {"type": "string", "maxLength": MARKET_INDEX_MAX_QUERY_CHARS},
        "source_protocols": {
            "type": "array",
            "maxItems": _MAX_LIST_ITEMS,
            "items": {"type": "string", "minLength": 1, "maxLength": 256},
        },
    },
    "required": ["operation"],
}

MARKET_INDEX_OUTPUT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "changed": {"type": "boolean"},
        "detail": {"type": "string", "maxLength": 2_048},
        "entry_id": {"type": "string", "maxLength": 256},
        "entry_json": {"type": "string", "maxLength": MARKET_INDEX_MAX_ENTRY_BYTES},
        "entry_sha256": {"type": "string", "maxLength": 64},
        "found": {"type": "boolean"},
        "index_id": {"type": "string", "minLength": 1, "maxLength": 128},
        "items": {
            "type": "array",
            "maxItems": MARKET_INDEX_MAX_PAGE_SIZE,
            "items": _SEARCH_ITEM_SCHEMA,
        },
        "max_entries_per_principal": {
            "type": "integer",
            "minimum": 1,
            "maximum": MARKET_INDEX_MAX_SAFE_INTEGER,
        },
        "max_entry_bytes": {
            "type": "integer",
            "minimum": 1,
            "maximum": MARKET_INDEX_MAX_SAFE_INTEGER,
        },
        "next_cursor": {"type": "string", "maxLength": MARKET_INDEX_MAX_CURSOR_CHARS},
        "operation": {
            "type": "string",
            "enum": ["get", "probe", "remove", "search", "upsert"],
        },
        "ready": {"type": "boolean"},
        "removed": {"type": "boolean"},
        "replayed": {"type": "boolean"},
        "revision": {
            "type": "integer",
            "minimum": 0,
            "maximum": MARKET_INDEX_MAX_SAFE_INTEGER,
        },
    },
    "required": [
        "changed",
        "detail",
        "entry_id",
        "entry_json",
        "entry_sha256",
        "found",
        "index_id",
        "items",
        "max_entries_per_principal",
        "max_entry_bytes",
        "next_cursor",
        "operation",
        "ready",
        "removed",
        "replayed",
        "revision",
    ],
}

_OPERATION_RULES = {
    "get": {
        "allowed": ("entry_id", "operation"),
        "required": ("entry_id", "operation"),
    },
    "probe": {"allowed": ("operation",), "required": ("operation",)},
    "remove": {
        "allowed": ("entry_id", "expected_entry_sha256", "operation"),
        "required": ("entry_id", "expected_entry_sha256", "operation"),
    },
    "search": {
        "allowed": (
            "categories",
            "cursor",
            "include_stale",
            "intents",
            "limit",
            "operation",
            "q",
            "source_protocols",
        ),
        "required": (
            "categories",
            "cursor",
            "include_stale",
            "intents",
            "limit",
            "operation",
            "q",
            "source_protocols",
        ),
    },
    "upsert": {
        "allowed": (
            "entry_id",
            "entry_json",
            "entry_sha256",
            "expected_entry_sha256",
            "operation",
        ),
        "required": (
            "entry_id",
            "entry_json",
            "entry_sha256",
            "expected_entry_sha256",
            "operation",
        ),
    },
}

_MARKET_INDEX_INPUT_SCHEMA_DIGEST = schema_digest(MARKET_INDEX_INPUT_SCHEMA)
_MARKET_INDEX_OUTPUT_SCHEMA_DIGEST = schema_digest(MARKET_INDEX_OUTPUT_SCHEMA)


def is_market_index_wire_compatible_contract(value: Any) -> bool:
    """Return whether a contract speaks the v1 market.index JSON wire shape."""

    return (
        isinstance(value, CapabilityContract)
        and value.capability_id == MARKET_INDEX_CAPABILITY_ID
        and value.major_version == 1
        and value.input_schema_digest == _MARKET_INDEX_INPUT_SCHEMA_DIGEST
        and value.output_schema_digest == _MARKET_INDEX_OUTPUT_SCHEMA_DIGEST
    )


def is_market_index_protocol_contract(value: Any) -> bool:
    """Return whether a wire-compatible profile preserves index semantics."""

    return (
        is_market_index_wire_compatible_contract(value)
        and value.privacy == "public"
        and value.security == "verified-input"
        and value.cardinality == "many"
        and value.failure_semantics == "retry-safe"
    )


def market_index_provider_contract(
    *,
    effects: tuple[str, ...],
    consistency: str = "C2",
    deterministic: bool = False,
    retention: str = "ephemeral",
    version: str = MARKET_INDEX_CAPABILITY_VERSION,
) -> CapabilityContract:
    """Build one exact deployment profile over the stable v1 wire protocol."""

    contract = CapabilityContract(
        capability_id=MARKET_INDEX_CAPABILITY_ID,
        version=version,
        input_schema_digest=_MARKET_INDEX_INPUT_SCHEMA_DIGEST,
        output_schema_digest=_MARKET_INDEX_OUTPUT_SCHEMA_DIGEST,
        effects=effects,
        consistency=consistency,
        privacy="public",
        security="verified-input",
        cardinality="many",
        deterministic=deterministic,
        retention=retention,
        failure_semantics="retry-safe",
    )
    if not is_market_index_protocol_contract(contract):
        raise ValueError("market index provider profile violates v1 protocol semantics")
    return contract


def market_index_provider_allowed(
    contract: Any,
    *,
    allowed_effects: Iterable[str],
) -> bool:
    """Apply explicit Host effect policy after protocol compatibility checks."""

    if isinstance(allowed_effects, (str, bytes)):
        raise TypeError("allowed_effects must be an iterable of effect identifiers")
    try:
        allowed = frozenset(allowed_effects)
    except TypeError as exc:
        raise TypeError("allowed_effects must be an iterable of effect identifiers") from exc
    if any(
        not isinstance(effect, str)
        or effect == "none"
        or effect not in CAPABILITY_EFFECTS
        for effect in allowed
    ):
        raise ValueError("allowed_effects contains an unsupported external effect")
    if not is_market_index_protocol_contract(contract):
        return False
    actual = frozenset(effect for effect in contract.effects if effect != "none")
    return actual.issubset(allowed)


MARKET_INDEX_CONTRACT = market_index_provider_contract(effects=("none",))


def market_index_operation_rule(operation: str) -> tuple[frozenset[str], frozenset[str]]:
    rule = _OPERATION_RULES.get(operation)
    if rule is None:
        raise ValueError("unsupported market index operation")
    return frozenset(rule["allowed"]), frozenset(rule["required"])


def validate_market_index_identifier(value: Any, *, field: str) -> str:
    if field not in {"entry_id", "index_id", "source_protocol"}:
        raise ValueError("unsupported market index identifier field")
    maximum = 128 if field == "index_id" else _MAX_IDENTIFIER_CHARS
    if (
        not isinstance(value, str)
        or len(value) > maximum
        or _IDENTIFIER_RE.fullmatch(value) is None
        or any(part in {".", ".."} for part in re.split(r"[/:]", value))
    ):
        raise ValueError(f"{field} is invalid")
    return value


def canonical_market_index_entry(value: str) -> tuple[Dict[str, Any], bytes]:
    if not isinstance(value, str):
        raise ValueError("entry_json must be text")
    encoded = value.encode("utf-8")
    if len(encoded) > MARKET_INDEX_MAX_ENTRY_BYTES:
        raise ValueError("entry_json exceeds the UTF-8 byte limit")
    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("entry_json must contain valid JSON") from exc
    if not isinstance(parsed, dict):
        raise ValueError("entry_json must contain a JSON object")
    _validate_object_keys(parsed)
    _validate_safe_integers(parsed)
    try:
        validate_instance(parsed, _ENTRY_SCHEMA, path="$entry")
    except PluginSchemaError as exc:
        raise ValueError(str(exc)) from exc
    _validate_entry_semantics(parsed)
    try:
        canonical = canonical_json(parsed)
    except (RecursionError, TypeError, ValueError) as exc:
        raise ValueError("entry_json must contain finite canonical JSON") from exc
    if canonical != encoded:
        raise ValueError("entry_json must use canonical JSON encoding")
    return parsed, canonical


def market_index_entry_digest(entry_json: str) -> str:
    _, encoded = canonical_market_index_entry(entry_json)
    return hashlib.sha256(encoded).hexdigest()


def validate_market_index_input(value: Mapping[str, Any]) -> None:
    if not isinstance(value, Mapping):
        raise PluginSchemaError("$input must be an object")
    _validate_document_size(value, path="$input")
    validate_instance(value, MARKET_INDEX_INPUT_SCHEMA, path="$input")
    operation = value.get("operation")
    try:
        allowed, required = market_index_operation_rule(operation)
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
    if "entry_id" in value:
        try:
            validate_market_index_identifier(value["entry_id"], field="entry_id")
        except ValueError as exc:
            raise PluginSchemaError("$input.entry_id is invalid") from exc
    if "expected_entry_sha256" in value and value["expected_entry_sha256"]:
        if _RAW_SHA256_RE.fullmatch(value["expected_entry_sha256"]) is None:
            raise PluginSchemaError("$input.expected_entry_sha256 is invalid")
    if operation == "remove" and not value["expected_entry_sha256"]:
        raise PluginSchemaError("$input.remove requires a non-empty expected digest")
    if operation == "upsert":
        try:
            entry, _ = canonical_market_index_entry(value["entry_json"])
        except ValueError as exc:
            raise PluginSchemaError(f"$input.entry_json {exc}") from exc
        if _RAW_SHA256_RE.fullmatch(value["entry_sha256"]) is None:
            raise PluginSchemaError("$input.entry_sha256 is invalid")
        if market_index_entry_digest(value["entry_json"]) != value["entry_sha256"]:
            raise PluginSchemaError("$input.entry_sha256 does not bind entry_json")
        if entry["entry_id"] != value["entry_id"]:
            raise PluginSchemaError("$input.entry_id does not bind entry_json")
    if operation == "search":
        _validate_filter_list(value["categories"], category=True, path="$input.categories")
        _validate_filter_list(value["intents"], path="$input.intents")
        _validate_filter_list(
            value["source_protocols"], identifier=True, path="$input.source_protocols"
        )


def validate_market_index_output(value: Mapping[str, Any]) -> None:
    if not isinstance(value, Mapping):
        raise PluginSchemaError("$output must be an object")
    _validate_document_size(value, path="$output")
    validate_instance(value, MARKET_INDEX_OUTPUT_SCHEMA, path="$output")
    try:
        validate_market_index_identifier(value["index_id"], field="index_id")
    except ValueError as exc:
        raise PluginSchemaError("$output.index_id is invalid") from exc
    if not value["ready"] or value["detail"]:
        raise PluginSchemaError("$output built-in operation must be ready without detail")
    if value["max_entry_bytes"] > MARKET_INDEX_MAX_ENTRY_BYTES:
        raise PluginSchemaError("$output max_entry_bytes exceeds the wire limit")
    operation = value["operation"]
    if value["changed"] and operation not in {"remove", "upsert"}:
        raise PluginSchemaError("$output.changed is mutation-only")
    if value["removed"] and operation != "remove":
        raise PluginSchemaError("$output.removed is remove-only")
    if value["replayed"] and operation not in {"remove", "upsert"}:
        raise PluginSchemaError("$output.replayed is mutation-only")
    if operation == "search":
        if value["entry_id"] or value["entry_json"] or value["entry_sha256"]:
            raise PluginSchemaError("$output search cannot carry singular entry state")
        if value["found"] != bool(value["items"]):
            raise PluginSchemaError("$output search found flag does not match items")
        seen: set[str] = set()
        order: list[tuple[int, int, str]] = []
        for item in value["items"]:
            entry = _validate_output_entry(item, path="$output.items[]")
            if item["entry_id"] in seen:
                raise PluginSchemaError("$output search entry ids must be unique")
            seen.add(item["entry_id"])
            order.append((-item["score"], -entry["published_at_ms"], item["entry_id"]))
        if order != sorted(order):
            raise PluginSchemaError("$output search items are not in stable rank order")
        return
    if value["items"] or value["next_cursor"]:
        raise PluginSchemaError(f"$output {operation} cannot carry search state")
    if operation == "probe":
        _require_empty_entry(value)
        if value["found"] or value["changed"] or value["removed"] or value["replayed"]:
            raise PluginSchemaError("$output probe carries entry state")
        return
    if operation == "get":
        if value["changed"] or value["removed"] or value["replayed"]:
            raise PluginSchemaError("$output get carries mutation state")
        if not value["found"]:
            _require_empty_entry(value)
            return
        _validate_output_entry(value, path="$output")
        return
    if value["entry_json"]:
        raise PluginSchemaError(f"$output {operation} cannot return entry content")
    if value["entry_id"]:
        try:
            validate_market_index_identifier(value["entry_id"], field="entry_id")
        except ValueError as exc:
            raise PluginSchemaError("$output.entry_id is invalid") from exc
    if value["entry_sha256"] and _RAW_SHA256_RE.fullmatch(value["entry_sha256"]) is None:
        raise PluginSchemaError("$output.entry_sha256 is invalid")
    if operation == "upsert":
        if not value["found"] or not value["entry_id"] or not value["entry_sha256"]:
            raise PluginSchemaError("$output upsert must identify the live entry")
        if value["removed"] or value["changed"] == value["replayed"]:
            raise PluginSchemaError("$output upsert flags are inconsistent")
    elif operation == "remove":
        if value["found"] or not value["removed"] or not value["entry_id"]:
            raise PluginSchemaError("$output remove flags are inconsistent")
        if value["changed"] == value["replayed"]:
            raise PluginSchemaError("$output remove must be changed or replayed")


def validate_market_index_exchange(
    request: Mapping[str, Any],
    response: Mapping[str, Any],
) -> None:
    """Bind one validated index response to its validated request."""

    operation = request.get("operation")
    if response.get("operation") != operation:
        raise PluginSchemaError("$output.operation does not match $input.operation")
    if operation == "probe":
        return
    if operation == "get":
        if response.get("found") and response.get("entry_id") != request.get("entry_id"):
            raise PluginSchemaError("$output.entry_id does not match $input.entry_id")
        return
    if operation == "search":
        items = response.get("items")
        if isinstance(items, list) and len(items) > request.get("limit", 0):
            raise PluginSchemaError("$output.items exceed $input.limit")
        wanted_categories = set(request.get("categories", ()))
        wanted_intents = set(request.get("intents", ()))
        wanted_protocols = set(request.get("source_protocols", ()))
        include_stale = request.get("include_stale") is True
        for index, item in enumerate(items if isinstance(items, list) else ()):
            try:
                entry, _canonical = canonical_market_index_entry(item["entry_json"])
            except (KeyError, TypeError, ValueError) as exc:
                raise PluginSchemaError(
                    f"$output.items[{index}] is not a valid market entry"
                ) from exc
            if wanted_categories and not wanted_categories.intersection(
                entry["categories"]
            ):
                raise PluginSchemaError(
                    f"$output.items[{index}] does not match $input.categories"
                )
            if wanted_intents and not wanted_intents.intersection(entry["intents"]):
                raise PluginSchemaError(
                    f"$output.items[{index}] does not match $input.intents"
                )
            if wanted_protocols and entry["source_protocol"] not in wanted_protocols:
                raise PluginSchemaError(
                    f"$output.items[{index}] does not match $input.source_protocols"
                )
            if entry["stale"] and not include_stale:
                raise PluginSchemaError(
                    f"$output.items[{index}] is stale but $input.include_stale is false"
                )
        return
    if operation == "upsert":
        expected_digest = request.get("entry_sha256")
    elif operation == "remove":
        expected_digest = request.get("expected_entry_sha256")
    else:
        raise PluginSchemaError("$input.operation is unsupported")
    if response.get("entry_id") != request.get("entry_id"):
        raise PluginSchemaError("$output.entry_id does not match $input.entry_id")
    if response.get("entry_sha256") != expected_digest:
        raise PluginSchemaError(
            "$output.entry_sha256 does not match the requested content digest"
        )


def market_index_protocol_document() -> Dict[str, Any]:
    return {
        "capability": MARKET_INDEX_CONTRACT.to_dict(),
        "canonicalization": {
            "encoding": "utf-8",
            "floats": "forbidden",
            "integer_range": "-(2^53-1)..(2^53-1)",
            "object_keys": "non-empty-printable-ascii-1-to-256-bytes",
            "serialization": "recursive-sorted-keys-compact-json",
        },
        "entry_schema": deepcopy(_ENTRY_SCHEMA),
        "entry_rules": {
            "capabilities": "sorted-unique-portable-identifiers",
            "categories": "sorted-unique-lowercase-slugs",
            "display_text": "title-has-no-controls-summary-allows-only-tab-cr-lf-controls",
            "origin": "local-has-empty-source-peer-federated-has-non-empty-source-peer",
            "projection_only": "must-be-true-and-never-grants-authority",
            "publisher_did": "valid-ed25519-did-key",
            "source_digest": "lowercase-sha256-content-address-with-prefix",
            "source_locator": "opaque-public-hint-no-userinfo-no-automatic-dereference",
            "time": "expiry-follows-publication-and-verification-does-not-precede-it",
        },
        "error_model": {
            code: dict(specification)
            for code, specification in MARKET_INDEX_ERROR_MODEL.items()
        },
        "input_schema": deepcopy(MARKET_INDEX_INPUT_SCHEMA),
        "operation_rules": {
            operation: {
                "allowed": list(rule["allowed"]),
                "required": list(rule["required"]),
            }
            for operation, rule in sorted(_OPERATION_RULES.items())
        },
        "output_schema": deepcopy(MARKET_INDEX_OUTPUT_SCHEMA),
        "provider_profiles": {
            "compatibility": (
                "wire-shape-does-not-imply-contract-substitutability-or-host-authorization"
            ),
            "local_reference_contract_digest": MARKET_INDEX_CONTRACT.digest,
            "selection": "protocol-compatible-then-explicit-effect-policy",
        },
        "semantics": {
            "authority": "search-projection-only-resolve-and-reverify-source-before-action",
            "cursor": "opaque-principal-query-bound-expiring-snapshot-revision-token",
            "remove": "content-digest-cas-idempotent-logical-removal",
            "retry": (
                "identical-mutations-replay-within-the-declared-window-while-provider-is-active"
            ),
            "search": "provider-ranked-with-stable-entry-id-tie-break",
            "stale_retention": (
                "expired-entries-remain-queryable-with-include-stale-until-retention-ends"
            ),
            "upsert": "content-digest-cas-idempotent-replacement",
        },
        "wire_limits": {
            "max_document_bytes": MARKET_INDEX_MAX_DOCUMENT_BYTES,
            "max_cursor_chars": MARKET_INDEX_MAX_CURSOR_CHARS,
            "max_cursor_age_ms": MARKET_INDEX_MAX_CURSOR_AGE_MS,
            "max_entry_bytes": MARKET_INDEX_MAX_ENTRY_BYTES,
            "max_list_items": _MAX_LIST_ITEMS,
            "mutation_replay_window_ms": MARKET_INDEX_MUTATION_REPLAY_WINDOW_MS,
            "stale_retention_ms": MARKET_INDEX_STALE_RETENTION_MS,
            "max_page_size": MARKET_INDEX_MAX_PAGE_SIZE,
            "max_query_chars": MARKET_INDEX_MAX_QUERY_CHARS,
            "max_safe_integer": MARKET_INDEX_MAX_SAFE_INTEGER,
            "size_unit": "canonical-json-utf8-bytes",
        },
    }


def market_index_protocol_digest() -> str:
    return "sha256:" + hashlib.sha256(
        canonical_json(market_index_protocol_document())
    ).hexdigest()


def market_index_contract_vector() -> Dict[str, Any]:
    """Return the checked-in capability vector index."""

    return {
        "capability": MARKET_INDEX_CONTRACT.to_dict(),
        "entry_schema": "market-index-entry-schema-v1.json",
        "expected_digest": MARKET_INDEX_CONTRACT.digest,
        "expected_protocol_digest": market_index_protocol_digest(),
        "format": "nth-dao-plugin-capability-conformance-v1",
        "input_schema": "market-index-input-schema-v1.json",
        "operation_vectors": "market-index-wire-cases-v1.json",
        "output_schema": "market-index-output-schema-v1.json",
        "schema_version": 1,
    }


def market_index_wire_vectors() -> Dict[str, Any]:
    """Return portable positive vectors and closed protocol metadata."""

    entry = {
        "capabilities": ["code.review"],
        "categories": ["tasks"],
        "entry_id": "task:vector-alpha",
        "intents": ["request"],
        "last_verified_at_ms": 1_750_000_000_100,
        "not_after_ms": 1_750_086_400_000,
        "origin": "local",
        "projection_only": True,
        "published_at_ms": 1_750_000_000_000,
        "publisher_did": (
            "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd"
        ),
        "source_digest": "sha256:" + "a" * 64,
        "source_locator": "nth://market/task/vector-alpha",
        "source_object_id": "announcement-vector-alpha",
        "source_peer": "",
        "source_protocol": "org.nth-dao.market.task-announcement.v3",
        "stale": False,
        "summary": "Resolve and verify the signed source before action.",
        "title": "Review vector alpha",
        "version": "1",
    }
    entry_json = canonical_json(entry).decode("utf-8")
    entry_sha256 = hashlib.sha256(entry_json.encode("utf-8")).hexdigest()
    second_entry = deepcopy(entry)
    second_entry.update(
        {
            "entry_id": "task:vector-beta",
            "published_at_ms": entry["published_at_ms"] - 1,
            "source_digest": "sha256:" + "b" * 64,
            "source_locator": "nth://market/task/vector-beta",
            "source_object_id": "announcement-vector-beta",
            "title": "Review vector beta",
        }
    )
    second_entry_json = canonical_json(second_entry).decode("utf-8")
    second_entry_sha256 = hashlib.sha256(
        second_entry_json.encode("utf-8")
    ).hexdigest()

    def base_output(operation: str, *, revision: int = 0) -> Dict[str, Any]:
        return {
            "changed": False,
            "detail": "",
            "entry_id": "",
            "entry_json": "",
            "entry_sha256": "",
            "found": False,
            "index_id": "org.nth-dao.market.memory-index",
            "items": [],
            "max_entries_per_principal": 2_048,
            "max_entry_bytes": MARKET_INDEX_MAX_ENTRY_BYTES,
            "next_cursor": "",
            "operation": operation,
            "ready": True,
            "removed": False,
            "replayed": False,
            "revision": revision,
        }

    probe_input = {"operation": "probe"}
    upsert_input = {
        "entry_id": entry["entry_id"],
        "entry_json": entry_json,
        "entry_sha256": entry_sha256,
        "expected_entry_sha256": "",
        "operation": "upsert",
    }
    get_input = {"entry_id": entry["entry_id"], "operation": "get"}
    search_input = {
        "categories": ["tasks"],
        "cursor": "",
        "include_stale": False,
        "intents": ["request"],
        "limit": 20,
        "operation": "search",
        "q": "review",
        "source_protocols": [entry["source_protocol"]],
    }
    remove_input = {
        "entry_id": entry["entry_id"],
        "expected_entry_sha256": entry_sha256,
        "operation": "remove",
    }
    probe_output = base_output("probe")
    upsert_output = base_output("upsert", revision=1)
    upsert_output.update(
        {
            "changed": True,
            "entry_id": entry["entry_id"],
            "entry_sha256": entry_sha256,
            "found": True,
        }
    )
    get_output = base_output("get", revision=1)
    get_output.update(
        {
            "entry_id": entry["entry_id"],
            "entry_json": entry_json,
            "entry_sha256": entry_sha256,
            "found": True,
        }
    )
    search_output = base_output("search", revision=1)
    search_output.update(
        {
            "found": True,
            "items": [
                {
                    "entry_id": entry["entry_id"],
                    "entry_json": entry_json,
                    "entry_sha256": entry_sha256,
                    "score": 100,
                },
                {
                    "entry_id": second_entry["entry_id"],
                    "entry_json": second_entry_json,
                    "entry_sha256": second_entry_sha256,
                    "score": 90,
                },
            ],
        }
    )
    remove_output = base_output("remove", revision=2)
    remove_output.update(
        {
            "changed": True,
            "entry_id": entry["entry_id"],
            "entry_sha256": entry_sha256,
            "removed": True,
        }
    )

    def search_response_with_entry(mutation: Mapping[str, Any]) -> Dict[str, Any]:
        candidate = deepcopy(entry)
        candidate.update(mutation)
        candidate_json = canonical_json(candidate).decode("utf-8")
        candidate_digest = hashlib.sha256(candidate_json.encode("utf-8")).hexdigest()
        response = base_output("search", revision=1)
        response.update(
            {
                "found": True,
                "items": [
                    {
                        "entry_id": candidate["entry_id"],
                        "entry_json": candidate_json,
                        "entry_sha256": candidate_digest,
                        "score": 100,
                    }
                ],
            }
        )
        return response

    invalid_upsert_flags = deepcopy(upsert_output)
    invalid_upsert_flags["changed"] = False
    invalid_search_found = deepcopy(search_output)
    invalid_search_found["found"] = False
    invalid_get_digest = deepcopy(get_output)
    invalid_get_digest["entry_sha256"] = "0" * 64

    wrong_upsert_binding = deepcopy(upsert_output)
    wrong_upsert_binding["entry_id"] = second_entry["entry_id"]
    limited_search = deepcopy(search_input)
    limited_search["limit"] = 1
    mismatched_category_search = search_response_with_entry(
        {"categories": ["products"]}
    )
    mismatched_intent_search = search_response_with_entry({"intents": ["provide"]})
    mismatched_protocol_search = search_response_with_entry(
        {"source_protocol": "org.nth-dao.market.trade-offer.v1"}
    )
    stale_search = search_response_with_entry({"stale": True})
    replacement_entry = deepcopy(entry)
    replacement_entry.update(
        {
            "source_digest": "sha256:" + "c" * 64,
            "summary": "Replacement generation.",
            "title": "Review vector alpha replacement",
        }
    )
    replacement_entry_json = canonical_json(replacement_entry).decode("utf-8")
    replacement_entry_sha256 = hashlib.sha256(
        replacement_entry_json.encode("utf-8")
    ).hexdigest()
    replacement_upsert = {
        "entry_id": entry["entry_id"],
        "entry_json": replacement_entry_json,
        "entry_sha256": replacement_entry_sha256,
        "expected_entry_sha256": entry_sha256,
        "operation": "upsert",
    }
    recreated_upsert = {**replacement_upsert, "expected_entry_sha256": ""}
    negative_entries = []
    for name, mutation in (
        ("projection-only-required", {"projection_only": False}),
        ("source-digest-needs-prefix", {"source_digest": "a" * 64}),
        ("categories-must-be-unique", {"categories": ["tasks", "tasks"]}),
        (
            "public-locator-forbids-userinfo",
            {"source_locator": "nth://demo-user:demo-pass@peer/item"},
        ),
        (
            "federated-origin-needs-peer",
            {"origin": "federated", "source_peer": ""},
        ),
        ("title-forbids-controls", {"title": "unsafe\u001btitle"}),
    ):
        invalid = deepcopy(entry)
        invalid.update(mutation)
        negative_entries.append(
            {
                "entry_json": canonical_json(invalid).decode("utf-8"),
                "name": name,
            }
        )
    protocol = market_index_protocol_document()
    return {
        "canonicalization": protocol["canonicalization"],
        "entry_rules": protocol["entry_rules"],
        "error_model": protocol["error_model"],
        "identifier_examples": {
            "entry_id": entry["entry_id"],
            "source_protocol": entry["source_protocol"],
        },
        "operation_rules": protocol["operation_rules"],
        "negative_entries": negative_entries,
        "negative_inputs": [
            {
                "input": {
                    "entry_id": entry["entry_id"],
                    "expected_entry_sha256": "",
                    "operation": "remove",
                },
                "name": "remove-needs-cas-digest",
            },
            {
                "input": {
                    "entry_id": entry["entry_id"],
                    "entry_json": entry_json,
                    "entry_sha256": "0" * 64,
                    "expected_entry_sha256": "",
                    "operation": "upsert",
                },
                "name": "upsert-digest-must-bind-entry",
            },
        ],
        "negative_outputs": [
            {
                "expected_error_contains": "upsert flags are inconsistent",
                "name": "upsert-must-change-or-replay",
                "output": invalid_upsert_flags,
            },
            {
                "expected_error_contains": "found flag does not match items",
                "name": "search-found-binds-items",
                "output": invalid_search_found,
            },
            {
                "expected_error_contains": "entry_sha256 does not bind entry_json",
                "name": "get-digest-binds-content",
                "output": invalid_get_digest,
            },
        ],
        "negative_exchanges": [
            {
                "expected_error_contains": "entry_id does not match",
                "name": "upsert-response-binds-entry-id",
                "request": upsert_input,
                "response": wrong_upsert_binding,
            },
            {
                "expected_error_contains": "items exceed",
                "name": "search-response-respects-request-limit",
                "request": limited_search,
                "response": search_output,
            },
            {
                "expected_error_contains": "categories",
                "name": "search-response-binds-categories",
                "request": search_input,
                "response": mismatched_category_search,
            },
            {
                "expected_error_contains": "intents",
                "name": "search-response-binds-intents",
                "request": search_input,
                "response": mismatched_intent_search,
            },
            {
                "expected_error_contains": "source_protocols",
                "name": "search-response-binds-source-protocols",
                "request": search_input,
                "response": mismatched_protocol_search,
            },
            {
                "expected_error_contains": "include_stale",
                "name": "search-response-binds-stale-policy",
                "request": search_input,
                "response": stale_search,
            },
            {
                "expected_error_contains": "operation does not match",
                "name": "response-binds-operation",
                "request": get_input,
                "response": probe_output,
            },
        ],
        "positive_exchanges": [
            {"request": probe_input, "response": probe_output},
            {"request": upsert_input, "response": upsert_output},
            {"request": get_input, "response": get_output},
            {"request": search_input, "response": search_output},
            {"request": remove_input, "response": remove_output},
        ],
        "positive_inputs": [
            probe_input,
            upsert_input,
            get_input,
            search_input,
            remove_input,
        ],
        "positive_outputs": [
            probe_output,
            upsert_output,
            get_output,
            search_output,
            remove_output,
        ],
        "state_cases": [
            {
                "name": "mutation-replay-window",
                "steps": [
                    {
                        "at_ms": 1_750_000_000_200,
                        "expect": {"changed": True, "replayed": False, "revision": 1},
                        "input": upsert_input,
                    },
                    {
                        "at_ms": 1_750_000_000_201,
                        "expect": {"changed": False, "replayed": True, "revision": 1},
                        "input": upsert_input,
                    },
                    {
                        "at_ms": 1_750_000_000_202,
                        "expect": {
                            "changed": True,
                            "removed": True,
                            "replayed": False,
                            "revision": 2,
                        },
                        "input": remove_input,
                    },
                    {
                        "at_ms": 1_750_000_000_203,
                        "expect": {
                            "changed": False,
                            "removed": True,
                            "replayed": True,
                            "revision": 2,
                        },
                        "input": remove_input,
                    },
                    {
                        "at_ms": (
                            1_750_000_000_202
                            + MARKET_INDEX_MUTATION_REPLAY_WINDOW_MS
                            + 1
                        ),
                        "expect_error": "conflict",
                        "input": remove_input,
                    },
                ],
            },
            {
                "name": "upsert-replay-survives-aba",
                "steps": [
                    {
                        "at_ms": 1_750_000_001_000,
                        "expect": {"changed": True, "replayed": False, "revision": 1},
                        "input": upsert_input,
                    },
                    {
                        "at_ms": 1_750_000_001_001,
                        "expect": {"changed": True, "replayed": False, "revision": 2},
                        "input": replacement_upsert,
                    },
                    {
                        "at_ms": 1_750_000_001_002,
                        "expect": {"changed": False, "replayed": True, "revision": 1},
                        "input": upsert_input,
                    },
                    {
                        "at_ms": 1_750_000_001_003,
                        "expect": {
                            "entry_sha256": replacement_entry_sha256,
                            "found": True,
                            "revision": 2,
                        },
                        "input": get_input,
                    },
                ],
            },
            {
                "name": "remove-replay-survives-recreation",
                "steps": [
                    {
                        "at_ms": 1_750_000_002_000,
                        "expect": {"changed": True, "replayed": False, "revision": 1},
                        "input": upsert_input,
                    },
                    {
                        "at_ms": 1_750_000_002_001,
                        "expect": {
                            "changed": True,
                            "removed": True,
                            "replayed": False,
                            "revision": 2,
                        },
                        "input": remove_input,
                    },
                    {
                        "at_ms": 1_750_000_002_002,
                        "expect": {"changed": True, "replayed": False, "revision": 3},
                        "input": recreated_upsert,
                    },
                    {
                        "at_ms": 1_750_000_002_003,
                        "expect": {
                            "changed": False,
                            "removed": True,
                            "replayed": True,
                            "revision": 2,
                        },
                        "input": remove_input,
                    },
                    {
                        "at_ms": 1_750_000_002_004,
                        "expect": {
                            "entry_sha256": replacement_entry_sha256,
                            "found": True,
                            "revision": 3,
                        },
                        "input": get_input,
                    },
                ],
            },
        ],
        "semantics": protocol["semantics"],
        "valid_entry": entry,
        "valid_entry_json": entry_json,
        "valid_entry_sha256": entry_sha256,
        "wire_limits": protocol["wire_limits"],
    }


def market_index_vector_documents() -> Dict[str, Dict[str, Any]]:
    """Return every generated JSON vector keyed by repository filename."""

    protocol = market_index_protocol_document()
    return {
        "market-index-capability-v1.json": market_index_contract_vector(),
        "market-index-entry-schema-v1.json": protocol["entry_schema"],
        "market-index-input-schema-v1.json": protocol["input_schema"],
        "market-index-output-schema-v1.json": protocol["output_schema"],
        "market-index-wire-cases-v1.json": market_index_wire_vectors(),
    }


def _validate_entry_semantics(value: Mapping[str, Any]) -> None:
    try:
        validate_market_index_identifier(value["entry_id"], field="entry_id")
        validate_market_index_identifier(value["source_protocol"], field="source_protocol")
    except ValueError as exc:
        raise ValueError(str(exc)) from exc
    if not is_did_key(value["publisher_did"]):
        raise ValueError("publisher_did must be a valid did:key")
    if _SHA256_RE.fullmatch(value["source_digest"]) is None:
        raise ValueError("source_digest must be lowercase sha256 content address")
    _validate_filter_list(value["categories"], category=True, path="$entry.categories")
    _validate_filter_list(value["intents"], path="$entry.intents")
    _validate_filter_list(
        value["capabilities"], identifier=True, path="$entry.capabilities"
    )
    if value["projection_only"] is not True:
        raise ValueError("projection_only must be true")
    if value["origin"] == "local" and value["source_peer"]:
        raise ValueError("local entries cannot claim a source_peer")
    if value["origin"] == "federated" and not value["source_peer"]:
        raise ValueError("federated entries require source_peer")
    for field in ("source_locator", "source_object_id", "source_peer"):
        if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value[field]):
            raise ValueError(f"{field} cannot contain control characters")
        parsed_locator = urlsplit(value[field])
        if parsed_locator.username is not None or parsed_locator.password is not None:
            raise ValueError(f"{field} cannot contain URI userinfo")
    _validate_display_text(value["title"], field="title", multiline=False)
    _validate_display_text(value["summary"], field="summary", multiline=True)
    if value["not_after_ms"] and value["not_after_ms"] <= value["published_at_ms"]:
        raise ValueError("not_after_ms must follow published_at_ms")
    if (
        value["last_verified_at_ms"]
        and value["last_verified_at_ms"] < value["published_at_ms"]
    ):
        raise ValueError("last_verified_at_ms cannot precede publication")


def _validate_filter_list(
    values: Any,
    *,
    category: bool = False,
    identifier: bool = False,
    path: str,
) -> None:
    if values != sorted(set(values)):
        raise PluginSchemaError(f"{path} must be sorted and unique")
    for item in values:
        if category and _CATEGORY_RE.fullmatch(item) is None:
            raise PluginSchemaError(f"{path} contains an invalid category")
        if identifier:
            try:
                validate_market_index_identifier(item, field="source_protocol")
            except ValueError as exc:
                raise PluginSchemaError(f"{path} contains an invalid identifier") from exc


def _validate_output_entry(value: Mapping[str, Any], *, path: str) -> Dict[str, Any]:
    try:
        entry, _ = canonical_market_index_entry(value["entry_json"])
    except ValueError as exc:
        raise PluginSchemaError(f"{path}.entry_json {exc}") from exc
    if _RAW_SHA256_RE.fullmatch(value["entry_sha256"]) is None:
        raise PluginSchemaError(f"{path}.entry_sha256 is invalid")
    if market_index_entry_digest(value["entry_json"]) != value["entry_sha256"]:
        raise PluginSchemaError(f"{path}.entry_sha256 does not bind entry_json")
    if entry["entry_id"] != value["entry_id"]:
        raise PluginSchemaError(f"{path}.entry_id does not bind entry_json")
    return entry


def _validate_display_text(value: str, *, field: str, multiline: bool) -> None:
    allowed_controls = {0x09, 0x0A, 0x0D} if multiline else set()
    if any(
        (ord(char) < 0x20 and ord(char) not in allowed_controls)
        or ord(char) == 0x7F
        for char in value
    ):
        raise ValueError(f"{field} contains an unsupported control character")


def _require_empty_entry(value: Mapping[str, Any]) -> None:
    if value["entry_id"] or value["entry_json"] or value["entry_sha256"]:
        raise PluginSchemaError("$output operation carries unexpected entry fields")


def _validate_safe_integers(value: Any, *, path: str = "$") -> None:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, int):
        if not -MARKET_INDEX_MAX_SAFE_INTEGER <= value <= MARKET_INDEX_MAX_SAFE_INTEGER:
            raise ValueError(f"integer at {path} exceeds the cross-language safe range")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_safe_integers(item, path=f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _validate_safe_integers(item, path=f"{path}.{key}")


def _validate_object_keys(value: Any, *, path: str = "$") -> None:
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_object_keys(item, path=f"{path}[{index}]")
        return
    if not isinstance(value, dict):
        return
    for key, item in value.items():
        if _OBJECT_KEY_RE.fullmatch(key) is None:
            raise ValueError(f"object key at {path} must be printable bounded ASCII")
        _validate_object_keys(item, path=f"{path}.{key}")


def _validate_document_size(value: Mapping[str, Any], *, path: str) -> None:
    try:
        encoded = canonical_json(dict(value))
    except (RecursionError, TypeError, ValueError) as exc:
        raise PluginSchemaError(f"{path} must be finite canonical JSON") from exc
    if len(encoded) > MARKET_INDEX_MAX_DOCUMENT_BYTES:
        raise PluginSchemaError(
            f"{path} exceeds {MARKET_INDEX_MAX_DOCUMENT_BYTES} canonical UTF-8 bytes"
        )


__all__ = [
    "MARKET_INDEX_CAPABILITY_ID",
    "MARKET_INDEX_CAPABILITY_VERSION",
    "MARKET_INDEX_CONTRACT",
    "MARKET_INDEX_ERROR_MODEL",
    "MARKET_INDEX_INPUT_SCHEMA",
    "MARKET_INDEX_MAX_DOCUMENT_BYTES",
    "MARKET_INDEX_MAX_CURSOR_CHARS",
    "MARKET_INDEX_MAX_CURSOR_AGE_MS",
    "MARKET_INDEX_MAX_ENTRY_BYTES",
    "MARKET_INDEX_MUTATION_REPLAY_WINDOW_MS",
    "MARKET_INDEX_STALE_RETENTION_MS",
    "MARKET_INDEX_MAX_PAGE_SIZE",
    "MARKET_INDEX_MAX_QUERY_CHARS",
    "MARKET_INDEX_MAX_SAFE_INTEGER",
    "MARKET_INDEX_OUTPUT_SCHEMA",
    "MarketIndexOperationError",
    "canonical_market_index_entry",
    "market_index_entry_digest",
    "is_market_index_protocol_contract",
    "is_market_index_wire_compatible_contract",
    "market_index_contract_vector",
    "market_index_operation_rule",
    "market_index_provider_allowed",
    "market_index_provider_contract",
    "market_index_protocol_digest",
    "market_index_protocol_document",
    "market_index_vector_documents",
    "market_index_wire_vectors",
    "validate_market_index_exchange",
    "validate_market_index_identifier",
    "validate_market_index_input",
    "validate_market_index_output",
]
