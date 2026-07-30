"""Signed, content-addressed execution claims for accepted Trade Orders."""

from __future__ import annotations

import copy
import hashlib
import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from nth_dao.did_key import is_did_key
from nth_dao.trade_rules.agreement import DEFAULT_CLOCK_SKEW_SECONDS
from nth_dao.trade_rules.agreement_order import (
    ORDER_ID_PREFIX,
    TradeOrder,
    trade_order_digest,
)
from nth_dao.trade_rules.canonical import (
    MAX_SAFE_INTEGER,
    TradeCanonicalJSONError,
    parse_trade_json,
    trade_canonical_json,
)
from nth_dao.trade_rules.execution_adapter import (
    TradeExecutionAdapterPolicy,
    TradeExecutionAdapterRejected,
    TradeExecutionAdapterResolver,
    resolve_execution_adapter,
)
from nth_dao.trade_rules.execution_content import (
    TradeExecutionContentResolver,
    TradeExecutionSchemaValidator,
    verify_execution_content,
)
from nth_dao.trade_rules.negotiation import (
    RulePackageResolver,
    RuleResolutionPolicy,
)
from nth_dao.trade_rules.order_execution import (
    EXECUTION_READINESS_KIND,
    EXECUTION_READINESS_PROTOCOL_VERSION,
    TradeOrderExecutionReadiness,
    verify_trade_order_execution,
)
from nth_dao.trade_rules.signing import (
    TradeProofError,
    encode_ed25519_signature,
    signed_document_input,
    verification_method_for_did,
    verify_ed25519_did_signature,
)

EXECUTION_RECEIPT_KIND = "nth.dao.trade.execution-receipt"
EXECUTION_RECEIPT_PROTOCOL_VERSION = "1"
EXECUTION_RECEIPT_PROOF_TYPE = "Ed25519Signature2020"
EXECUTION_RECEIPT_PROOF_PURPOSE = "tradeExecution"
EXECUTION_RECEIPT_ID_PREFIX = "nth-trade-execution-sha256:"
EXECUTION_RECEIPT_SIGNING_DOMAIN = b"nth-dao/trade-execution-receipt/v1"
EXECUTION_TERMS_KEY = "org.nthdao.execution/v1"
EXECUTION_OUTCOMES = frozenset({"succeeded", "failed", "cancelled"})
EXECUTOR_ROLES = frozenset({"maker", "taker"})
MAX_EXECUTION_EVIDENCE = 64

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_EXECUTION_ID = re.compile(
    rf"^{re.escape(EXECUTION_RECEIPT_ID_PREFIX)}[0-9a-f]{{64}}$"
)
_ORDER_ID = re.compile(rf"^{re.escape(ORDER_ID_PREFIX)}[0-9a-f]{{64}}$")
_ADAPTER_ID = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+"
    r"(?:/[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?)?$"
)
_VERSION = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
_RULE_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_RULE_ID = re.compile(
    rf"^{_RULE_LABEL}(?:\.{_RULE_LABEL})+"
    r"(?:/[a-z0-9](?:[a-z0-9._-]{0,30}[a-z0-9])?)?$"
)
_MEDIA_TYPE = re.compile(
    r"^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}"
    r"/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$"
)
_EVIDENCE_TYPE = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_TOKEN = re.compile(r"^[a-z0-9][a-z0-9._:/-]{0,159}$")
_OPERATION_ID = re.compile(r"^[a-z][a-z0-9._:-]{0,127}$")
_TIMESTAMP = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?:\.(\d{6}))?Z$"
)
_RECEIPT_FIELDS = frozenset(
    {
        "kind",
        "protocol_version",
        "execution_id",
        "order_id",
        "order_digest",
        "executor_did",
        "executor_role",
        "readiness",
        "readiness_digest",
        "adapter",
        "operation",
        "outcome",
        "result",
        "evidence",
        "started_at",
        "completed_at",
        "proof",
    }
)
_READINESS_FIELDS = frozenset(
    {
        "kind",
        "protocol_version",
        "order_digest",
        "executor_policy_digest",
        "ordered_package_digests",
        "required_capabilities",
        "required_permissions",
        "execution_modes",
        "resolved_resource_bytes",
        "evaluated_at",
    }
)
_ADAPTER_FIELDS = frozenset(
    {"adapter_id", "adapter_version", "adapter_digest", "execution_mode"}
)
_CONTENT_FIELDS = frozenset({"media_type", "digest", "size_bytes"})
_OPERATION_FIELDS = frozenset(
    {
        "operation_id",
        "rule_id",
        "package_digest",
        "hook_name",
        "hook_version",
        "executor_role",
        "input",
        "input_schema_digest",
        "output_schema_digest",
        "side_effect",
    }
)
_GRANT_FIELDS = frozenset(
    {
        "operation_id",
        "rule_id",
        "package_digest",
        "hook_name",
        "hook_version",
        "executor_role",
    }
)
_EXECUTION_TERMS_FIELDS = frozenset({"grants"})
_SIDE_EFFECTS = frozenset({"none", "local", "external", "funds"})
_EVIDENCE_FIELDS = frozenset(
    {"evidence_type", "media_type", "digest", "size_bytes"}
)
_PROOF_FIELDS = frozenset(
    {
        "type",
        "created",
        "verification_method",
        "proof_purpose",
        "proof_value",
    }
)


class TradeExecutionReceiptRejected(ValueError):
    """An execution Receipt is malformed, unbound, or unsigned."""


def _reject(message: str) -> None:
    raise TradeExecutionReceiptRejected(message)


def _exact_fields(
    value: Any,
    expected: frozenset[str],
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        _reject(f"{label} has missing or unknown fields")
    return value


def _digest(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        _reject(f"{label} must be a lowercase sha256 digest")
    return value


def _timestamp(value: Any, *, label: str) -> datetime:
    if not isinstance(value, str) or len(value) > 35:
        _reject(f"{label} must be a UTC RFC3339 timestamp")
    match = _TIMESTAMP.fullmatch(value)
    if match is None:
        _reject(f"{label} must be a UTC RFC3339 timestamp")
    fraction = match.group(2)
    if fraction == "000000":
        _reject(f"{label} must omit zero fractional seconds")
    try:
        base = datetime.strptime(
            match.group(1) + (f".{fraction}" if fraction else ""),
            (
                "%Y-%m-%dT%H:%M:%S.%f"
                if fraction
                else "%Y-%m-%dT%H:%M:%S"
            ),
        ).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise TradeExecutionReceiptRejected(
            f"{label} is not a real timestamp"
        ) from exc
    return base


def _moment(value: Any, *, label: str) -> datetime:
    return _timestamp(value, label=label)


def _time_key(value: Any, *, label: str) -> datetime:
    return _timestamp(value, label=label)


def _utc_now(value: datetime | None) -> datetime:
    moment = value or datetime.now(timezone.utc)
    if (
        not isinstance(moment, datetime)
        or moment.tzinfo is None
        or moment.utcoffset() is None
    ):
        raise TradeExecutionReceiptRejected("now must be timezone-aware")
    return moment.astimezone(timezone.utc)


def _safe_non_negative_int(value: Any, *, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= MAX_SAFE_INTEGER
    ):
        _reject(f"{label} must be a non-negative safe integer")
    return value


def _unique_digests(value: Any, *, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > 256:
        _reject(f"{label} must be a list with at most 256 entries")
    digests = tuple(_digest(item, label=f"{label} item") for item in value)
    if len(set(digests)) != len(digests):
        _reject(f"{label} must be unique")
    return digests


def _sorted_unique_ascii(
    value: Any,
    *,
    label: str,
    maximum: int = 256,
) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > maximum:
        _reject(f"{label} must be a list with at most {maximum} entries")
    output: list[str] = []
    for item in value:
        if (
            not isinstance(item, str)
            or not item
            or len(item) > 128
            or not item.isascii()
            or any(not 0x21 <= ord(char) <= 0x7E for char in item)
        ):
            _reject(f"{label} contains an invalid value")
        output.append(item)
    result = tuple(output)
    if tuple(sorted(set(result))) != result:
        _reject(f"{label} must be sorted and unique")
    return result


def _readiness(value: Any) -> TradeOrderExecutionReadiness:
    document = _exact_fields(value, _READINESS_FIELDS, "readiness")
    if document["kind"] != EXECUTION_READINESS_KIND:
        _reject("readiness has the wrong kind")
    if (
        document["protocol_version"]
        != EXECUTION_READINESS_PROTOCOL_VERSION
    ):
        _reject("readiness has an unsupported protocol version")
    readiness = TradeOrderExecutionReadiness(
        order_digest=_digest(
            document["order_digest"],
            label="readiness.order_digest",
        ),
        executor_policy_digest=_digest(
            document["executor_policy_digest"],
            label="readiness.executor_policy_digest",
        ),
        ordered_package_digests=_unique_digests(
            document["ordered_package_digests"],
            label="readiness.ordered_package_digests",
        ),
        required_capabilities=_sorted_unique_ascii(
            document["required_capabilities"],
            label="readiness.required_capabilities",
        ),
        required_permissions=_sorted_unique_ascii(
            document["required_permissions"],
            label="readiness.required_permissions",
        ),
        execution_modes=_sorted_unique_ascii(
            document["execution_modes"],
            label="readiness.execution_modes",
        ),
        resolved_resource_bytes=_safe_non_negative_int(
            document["resolved_resource_bytes"],
            label="readiness.resolved_resource_bytes",
        ),
        evaluated_at=document["evaluated_at"],
    )
    _timestamp(readiness.evaluated_at, label="readiness.evaluated_at")
    if readiness.to_dict() != document:
        _reject("readiness is not canonical")
    return readiness


def _adapter(value: Any) -> dict[str, Any]:
    document = _exact_fields(value, _ADAPTER_FIELDS, "adapter")
    if (
        not isinstance(document["adapter_id"], str)
        or len(document["adapter_id"]) > 192
        or _ADAPTER_ID.fullmatch(document["adapter_id"]) is None
    ):
        _reject("adapter.adapter_id is invalid")
    if (
        not isinstance(document["adapter_version"], str)
        or len(document["adapter_version"]) > 64
        or _VERSION.fullmatch(document["adapter_version"]) is None
    ):
        _reject("adapter.adapter_version is invalid")
    _digest(document["adapter_digest"], label="adapter.adapter_digest")
    if (
        not isinstance(document["execution_mode"], str)
        or not document["execution_mode"]
        or len(document["execution_mode"]) > 128
        or not document["execution_mode"].isascii()
        or any(
            not 0x21 <= ord(char) <= 0x7E
            for char in document["execution_mode"]
        )
    ):
        _reject("adapter.execution_mode is invalid")
    return document


def _content(value: Any, *, label: str) -> dict[str, Any]:
    document = _exact_fields(value, _CONTENT_FIELDS, label)
    if (
        not isinstance(document["media_type"], str)
        or len(document["media_type"]) > 255
        or _MEDIA_TYPE.fullmatch(document["media_type"]) is None
    ):
        _reject(f"{label}.media_type is invalid")
    _digest(document["digest"], label=f"{label}.digest")
    _safe_non_negative_int(
        document["size_bytes"],
        label=f"{label}.size_bytes",
    )
    return document


def _operation(value: Any) -> dict[str, Any]:
    document = _exact_fields(value, _OPERATION_FIELDS, "operation")
    if (
        not isinstance(document["operation_id"], str)
        or _OPERATION_ID.fullmatch(document["operation_id"]) is None
    ):
        _reject("operation.operation_id is invalid")
    rule_id = document["rule_id"]
    if not isinstance(rule_id, str) or _RULE_ID.fullmatch(rule_id) is None:
        _reject("operation.rule_id is invalid")
    for field in ("hook_name", "hook_version"):
        item = document[field]
        if not isinstance(item, str) or _TOKEN.fullmatch(item) is None:
            _reject(f"operation.{field} is invalid")
    _digest(document["package_digest"], label="operation.package_digest")
    if document["executor_role"] not in EXECUTOR_ROLES:
        _reject("operation.executor_role is invalid")
    _content(document["input"], label="operation.input")
    _digest(
        document["input_schema_digest"],
        label="operation.input_schema_digest",
    )
    _digest(
        document["output_schema_digest"],
        label="operation.output_schema_digest",
    )
    if document["side_effect"] not in _SIDE_EFFECTS:
        _reject("operation.side_effect is invalid")
    if document["side_effect"] == "funds":
        _reject(
            "funds execution requires a separately verified payment mandate"
        )
    return document


def _execution_grants(order_document: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    try:
        terms = order_document["snapshot"]["proposal"]["terms"]
    except (KeyError, TypeError) as exc:
        raise TradeExecutionReceiptRejected(
            "Order proposal terms are unavailable"
        ) from exc
    if not isinstance(terms, dict):
        _reject("Order proposal terms must be an object")
    extension = _exact_fields(
        terms.get(EXECUTION_TERMS_KEY),
        _EXECUTION_TERMS_FIELDS,
        "execution terms",
    )
    grants = extension["grants"]
    if not isinstance(grants, list) or not 1 <= len(grants) <= 256:
        _reject("execution grants must contain 1..256 entries")
    output: list[dict[str, Any]] = []
    previous_id = ""
    seen: set[str] = set()
    for index, raw in enumerate(grants):
        grant = _exact_fields(raw, _GRANT_FIELDS, f"execution grant[{index}]")
        operation_id = grant["operation_id"]
        if (
            not isinstance(operation_id, str)
            or _OPERATION_ID.fullmatch(operation_id) is None
        ):
            _reject(f"execution grant[{index}].operation_id is invalid")
        rule_id = grant["rule_id"]
        if not isinstance(rule_id, str) or _RULE_ID.fullmatch(rule_id) is None:
            _reject(f"execution grant[{index}].rule_id is invalid")
        for field in ("hook_name", "hook_version"):
            item = grant[field]
            if not isinstance(item, str) or _TOKEN.fullmatch(item) is None:
                _reject(f"execution grant[{index}].{field} is invalid")
        _digest(
            grant["package_digest"],
            label=f"execution grant[{index}].package_digest",
        )
        if grant["executor_role"] not in EXECUTOR_ROLES:
            _reject(f"execution grant[{index}].executor_role is invalid")
        if operation_id in seen or operation_id <= previous_id:
            _reject("execution grants must be sorted and unique by operation_id")
        seen.add(operation_id)
        previous_id = operation_id
        output.append(copy.deepcopy(grant))
    return tuple(output)


def _authorized_grant(
    order_document: dict[str, Any],
    operation_id: str,
    executor_role: str,
) -> dict[str, Any]:
    for grant in _execution_grants(order_document):
        if grant["operation_id"] == operation_id:
            if grant["executor_role"] != executor_role:
                _reject("operation grant does not authorize executor_role")
            return grant
    _reject("operation_id is not authorized by the signed Order")


def _operation_contract(
    *,
    package_resolver: RulePackageResolver,
    grant: dict[str, Any],
) -> tuple[Any, dict[str, Any]]:
    try:
        package = package_resolver.load(grant["package_digest"])
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise TradeExecutionReceiptRejected(
            f"unable to load operation Rule Package: {exc}"
        ) from exc
    if package is None:
        _reject("operation Rule Package is unavailable")
    try:
        manifest = package.manifest.to_dict()
    except (AttributeError, TypeError, ValueError) as exc:
        raise TradeExecutionReceiptRejected(
            "operation Rule Package is invalid"
        ) from exc
    if (
        getattr(package, "digest", None) != grant["package_digest"]
        or manifest.get("rule_id") != grant["rule_id"]
    ):
        _reject("operation grant does not match its Rule Package")
    matches = [
        item
        for item in manifest.get("hook_contracts", [])
        if isinstance(item, dict)
        and item.get("name") == grant["hook_name"]
        and item.get("version") == grant["hook_version"]
    ]
    if len(matches) != 1:
        _reject("operation grant does not identify one Rule Hook")
    hook = matches[0]
    if hook.get("side_effect") == "funds":
        _reject(
            "funds execution requires a separately verified payment mandate"
        )
    return package, hook


def _evidence(value: Any) -> tuple[dict[str, Any], ...]:
    if not isinstance(value, list) or len(value) > MAX_EXECUTION_EVIDENCE:
        _reject(
            f"evidence must be a list with at most "
            f"{MAX_EXECUTION_EVIDENCE} entries"
        )
    output: list[dict[str, Any]] = []
    identities: set[tuple[str, str]] = set()
    for index, item in enumerate(value):
        document = _exact_fields(
            item,
            _EVIDENCE_FIELDS,
            f"evidence[{index}]",
        )
        evidence_type = document["evidence_type"]
        if (
            not isinstance(evidence_type, str)
            or _EVIDENCE_TYPE.fullmatch(evidence_type) is None
        ):
            _reject(f"evidence[{index}].evidence_type is invalid")
        content = _content(
            {
                "media_type": document["media_type"],
                "digest": document["digest"],
                "size_bytes": document["size_bytes"],
            },
            label=f"evidence[{index}]",
        )
        normalized = {
            "evidence_type": evidence_type,
            **content,
        }
        identity = (evidence_type, normalized["digest"])
        if identity in identities:
            _reject("evidence contains a duplicate type and digest")
        identities.add(identity)
        output.append(normalized)
    if output != sorted(
        output,
        key=lambda item: (item["evidence_type"], item["digest"]),
    ):
        _reject("evidence must be sorted by evidence_type and digest")
    return tuple(output)


def _proof(value: Any, *, signer_did: str, completed_at: str) -> None:
    document = _exact_fields(value, _PROOF_FIELDS, "proof")
    if document["type"] != EXECUTION_RECEIPT_PROOF_TYPE:
        _reject("proof.type is invalid")
    if document["created"] != completed_at:
        _reject("proof.created must equal completed_at")
    if (
        document["verification_method"]
        != verification_method_for_did(signer_did)
    ):
        _reject("proof.verification_method does not match executor_did")
    if document["proof_purpose"] != EXECUTION_RECEIPT_PROOF_PURPOSE:
        _reject("proof.proof_purpose is invalid")
    _timestamp(document["created"], label="proof.created")


def _execution_id(
    *,
    order_digest: str,
    executor_did: str,
    operation_id: str,
) -> str:
    binding = {
        "executor_did": executor_did,
        "operation_id": operation_id,
        "order_digest": order_digest,
    }
    return EXECUTION_RECEIPT_ID_PREFIX + hashlib.sha256(
        trade_canonical_json(binding)
    ).hexdigest()


def _validate(document: dict[str, Any]) -> None:
    _exact_fields(document, _RECEIPT_FIELDS, "execution receipt")
    if document["kind"] != EXECUTION_RECEIPT_KIND:
        _reject("wrong execution receipt kind")
    if document["protocol_version"] != EXECUTION_RECEIPT_PROTOCOL_VERSION:
        _reject("unsupported execution receipt protocol_version")
    if (
        not isinstance(document["execution_id"], str)
        or _EXECUTION_ID.fullmatch(document["execution_id"]) is None
    ):
        _reject("execution_id is invalid")
    order_digest_value = _digest(
        document["order_digest"],
        label="order_digest",
    )
    if (
        not isinstance(document["order_id"], str)
        or _ORDER_ID.fullmatch(document["order_id"]) is None
    ):
        _reject("order_id is invalid")
    executor_did = document["executor_did"]
    if not isinstance(executor_did, str) or not is_did_key(executor_did):
        _reject("executor_did must be an Ed25519 did:key")
    if document["executor_role"] not in EXECUTOR_ROLES:
        _reject("executor_role is invalid")
    readiness = _readiness(document["readiness"])
    if readiness.order_digest != order_digest_value:
        _reject("readiness is not bound to order_digest")
    if readiness.digest != _digest(
        document["readiness_digest"],
        label="readiness_digest",
    ):
        _reject("readiness_digest does not match readiness")
    adapter = _adapter(document["adapter"])
    if adapter["execution_mode"] not in readiness.execution_modes:
        _reject("adapter execution_mode was not approved by readiness")
    operation = _operation(document["operation"])
    if operation["executor_role"] != document["executor_role"]:
        _reject("operation executor_role does not match receipt")
    if document["outcome"] not in EXECUTION_OUTCOMES:
        _reject("outcome is invalid")
    _content(document["result"], label="result")
    _evidence(document["evidence"])
    started = _time_key(document["started_at"], label="started_at")
    completed = _time_key(document["completed_at"], label="completed_at")
    _time_key(readiness.evaluated_at, label="readiness.evaluated_at")
    if readiness.evaluated_at != document["started_at"]:
        _reject("readiness.evaluated_at must equal started_at")
    if completed < started:
        _reject("completed_at precedes started_at")
    expected_execution_id = _execution_id(
        order_digest=order_digest_value,
        executor_did=executor_did,
        operation_id=operation["operation_id"],
    )
    if document["execution_id"] != expected_execution_id:
        _reject("execution_id binding mismatch")
    _proof(
        document["proof"],
        signer_did=executor_did,
        completed_at=document["completed_at"],
    )


def _verify(document: dict[str, Any]) -> None:
    try:
        signing_input = signed_document_input(
            EXECUTION_RECEIPT_SIGNING_DOMAIN,
            document,
        )
    except TradeProofError as exc:
        raise TradeExecutionReceiptRejected(str(exc)) from exc
    ok, reason = verify_ed25519_did_signature(
        publisher_did=document["executor_did"],
        proof_value=document["proof"]["proof_value"],
        signing_input=signing_input,
    )
    if not ok:
        _reject(reason)


def _verified_order(
    order: TradeOrder | dict[str, Any],
) -> TradeOrder:
    return (
        TradeOrder.from_json(order.canonical_bytes)
        if isinstance(order, TradeOrder)
        else TradeOrder.from_dict(order)
    )


def _resolve_adapter_for_receipt(
    *,
    adapter: dict[str, Any],
    grant: dict[str, Any],
    required_permissions: tuple[str, ...],
    resolver: TradeExecutionAdapterResolver,
    policy: TradeExecutionAdapterPolicy,
) -> None:
    try:
        resolve_execution_adapter(
            adapter_digest=adapter["adapter_digest"],
            adapter_id=adapter["adapter_id"],
            adapter_version=adapter["adapter_version"],
            execution_mode=adapter["execution_mode"],
            rule_id=grant["rule_id"],
            hook_name=grant["hook_name"],
            hook_version=grant["hook_version"],
            rule_permissions=required_permissions,
            resolver=resolver,
            policy=policy,
        )
    except TradeExecutionAdapterRejected as exc:
        raise TradeExecutionReceiptRejected(
            f"execution Adapter rejected: {exc}"
        ) from exc


@dataclass(frozen=True, init=False)
class TradeExecutionReceipt:
    _canonical_bytes: bytes

    @classmethod
    def _create(cls, canonical: bytes) -> "TradeExecutionReceipt":
        value = object.__new__(cls)
        object.__setattr__(value, "_canonical_bytes", bytes(canonical))
        return value

    @classmethod
    def from_dict(
        cls,
        document: dict[str, Any],
        *,
        order: TradeOrder | dict[str, Any],
    ) -> "TradeExecutionReceipt":
        try:
            receipt = _parse_unbound_receipt(document)
            _assert_order_binding(receipt, order)
            return receipt
        except (
            TradeCanonicalJSONError,
            TradeProofError,
            TypeError,
            ValueError,
            UnicodeError,
        ) as exc:
            if isinstance(exc, TradeExecutionReceiptRejected):
                raise
            raise TradeExecutionReceiptRejected(str(exc)) from exc

    @classmethod
    def from_json(
        cls,
        raw: bytes | str,
        *,
        order: TradeOrder | dict[str, Any],
    ) -> "TradeExecutionReceipt":
        try:
            return cls.from_dict(parse_trade_json(raw), order=order)
        except TradeCanonicalJSONError as exc:
            raise TradeExecutionReceiptRejected(str(exc)) from exc

    @property
    def canonical_bytes(self) -> bytes:
        return self._canonical_bytes

    @property
    def execution_id(self) -> str:
        return self.to_dict()["execution_id"]

    def to_dict(self) -> dict[str, Any]:
        return parse_trade_json(self._canonical_bytes)


def _parse_unbound_receipt(
    document: dict[str, Any],
) -> TradeExecutionReceipt:
    canonical = trade_canonical_json(copy.deepcopy(document))
    snapshot = parse_trade_json(canonical)
    _validate(snapshot)
    _verify(snapshot)
    return TradeExecutionReceipt._create(canonical)


def execution_receipt_digest(
    receipt: TradeExecutionReceipt | dict[str, Any],
    *,
    order: TradeOrder | dict[str, Any] | None = None,
) -> str:
    if isinstance(receipt, TradeExecutionReceipt):
        verified = _parse_unbound_receipt(receipt.to_dict())
        if order is not None:
            _assert_order_binding(verified, order)
    else:
        if order is None:
            raise TypeError("order is required when receipt is a dict")
        verified = TradeExecutionReceipt.from_dict(receipt, order=order)
    return "sha256:" + hashlib.sha256(verified.canonical_bytes).hexdigest()


def verify_execution_receipt_order_binding(
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
) -> None:
    verified_receipt = _parse_unbound_receipt(
        receipt.to_dict()
        if isinstance(receipt, TradeExecutionReceipt)
        else receipt
    )
    _assert_order_binding(verified_receipt, order)


def verify_execution_receipt_under_policy(
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
    package_resolver: RulePackageResolver,
    verifier_policy: RuleResolutionPolicy,
    adapter_resolver: TradeExecutionAdapterResolver,
    adapter_policy: TradeExecutionAdapterPolicy,
    content_resolver: TradeExecutionContentResolver,
    schema_validator: TradeExecutionSchemaValidator,
) -> TradeOrderExecutionReadiness:
    """Re-run readiness under the receiver's policy before relying on a claim."""

    verified_receipt = _parse_unbound_receipt(
        receipt.to_dict()
        if isinstance(receipt, TradeExecutionReceipt)
        else receipt
    )
    _assert_order_binding(verified_receipt, order)
    receipt_document = verified_receipt.to_dict()
    claimed = _readiness(receipt_document["readiness"])
    grant = _authorized_grant(
        _verified_order(order).to_dict(),
        receipt_document["operation"]["operation_id"],
        receipt_document["executor_role"],
    )
    package, hook = _operation_contract(
        package_resolver=package_resolver,
        grant=grant,
    )
    operation = receipt_document["operation"]
    expected_operation = {
        **grant,
        "input": operation["input"],
        "input_schema_digest": hook["input_schema_digest"],
        "output_schema_digest": hook["output_schema_digest"],
        "side_effect": hook["side_effect"],
    }
    if operation != expected_operation:
        _reject("execution receipt operation disagrees with Rule Hook")
    verify_execution_content(
        package=package,
        hook=hook,
        operation_input=operation["input"],
        outcome=receipt_document["outcome"],
        result=receipt_document["result"],
        resolver=content_resolver,
        schema_validator=schema_validator,
    )
    _resolve_adapter_for_receipt(
        adapter=receipt_document["adapter"],
        grant=grant,
        required_permissions=tuple(hook["permissions"]),
        resolver=adapter_resolver,
        policy=adapter_policy,
    )
    expected = verify_trade_order_execution(
        _verified_order(order),
        package_resolver,
        verifier_policy,
        at=_moment(receipt_document["started_at"], label="started_at"),
    )
    if (
        claimed.order_digest != expected.order_digest
        or claimed.ordered_package_digests
        != expected.ordered_package_digests
        or claimed.required_capabilities
        != expected.required_capabilities
        or claimed.required_permissions != expected.required_permissions
        or claimed.execution_modes != expected.execution_modes
        or claimed.resolved_resource_bytes
        != expected.resolved_resource_bytes
    ):
        _reject(
            "execution receipt readiness disagrees with verifier policy"
        )
    return expected


def _assert_order_binding(
    verified_receipt: TradeExecutionReceipt,
    order: TradeOrder | dict[str, Any],
) -> None:
    verified_order = _verified_order(order)
    receipt_document = verified_receipt.to_dict()
    order_document = verified_order.to_dict()
    if receipt_document["order_id"] != order_document["order_id"]:
        _reject("execution receipt order_id does not match Order")
    if receipt_document["order_digest"] != trade_order_digest(verified_order):
        _reject("execution receipt order_digest does not match Order")
    role = receipt_document["executor_role"]
    expected_did = order_document[f"{role}_did"]
    if receipt_document["executor_did"] != expected_did:
        _reject("execution receipt signer does not match executor_role")
    expected_packages = {
        item["digest"] for item in order_document["rule_bindings"]
    }
    readiness = _readiness(receipt_document["readiness"])
    if (
        len(readiness.ordered_package_digests) != len(expected_packages)
        or set(readiness.ordered_package_digests) != expected_packages
    ):
        _reject("execution receipt packages do not match Order bindings")
    operation = _operation(receipt_document["operation"])
    grant = _authorized_grant(
        order_document,
        operation["operation_id"],
        receipt_document["executor_role"],
    )
    if any(operation[field] != grant[field] for field in _GRANT_FIELDS):
        _reject("execution receipt operation does not match signed grant")


def _create_trade_execution_receipt(
    identity: Any,
    *,
    order: TradeOrder | dict[str, Any],
    package_resolver: RulePackageResolver,
    executor_policy: RuleResolutionPolicy,
    adapter_resolver: TradeExecutionAdapterResolver,
    adapter_policy: TradeExecutionAdapterPolicy,
    content_resolver: TradeExecutionContentResolver,
    schema_validator: TradeExecutionSchemaValidator,
    executor_role: str,
    adapter_id: str,
    adapter_version: str,
    adapter_digest: str,
    execution_mode: str,
    operation_id: str,
    operation_input: dict[str, Any],
    outcome: str,
    result: dict[str, Any],
    evidence: list[dict[str, Any]] | tuple[dict[str, Any], ...] = (),
    started_at: str,
    completed_at: str,
    now: datetime | None = None,
    clock_skew_seconds: float = DEFAULT_CLOCK_SKEW_SECONDS,
) -> TradeExecutionReceipt:
    """Verify current execution policy, then sign a bounded execution claim."""

    verified_order = _verified_order(order)
    order_document = verified_order.to_dict()
    if executor_role not in EXECUTOR_ROLES:
        _reject("executor_role is invalid")
    executor_did = identity.as_did()
    if executor_did != order_document[f"{executor_role}_did"]:
        _reject("execution signer does not match executor_role")
    started = _moment(started_at, label="started_at")
    completed = _moment(completed_at, label="completed_at")
    if completed < started:
        _reject("completed_at precedes started_at")
    if (
        isinstance(clock_skew_seconds, bool)
        or not isinstance(clock_skew_seconds, (int, float))
        or not math.isfinite(clock_skew_seconds)
        or clock_skew_seconds < 0
    ):
        _reject("clock_skew_seconds must be a finite non-negative number")
    if abs((_utc_now(now) - completed).total_seconds()) > float(
        clock_skew_seconds
    ):
        _reject("completed_at exceeds the local signing clock-skew limit")
    readiness = verify_trade_order_execution(
        verified_order,
        package_resolver,
        executor_policy,
        at=started,
    )
    if readiness.evaluated_at != started_at:
        _reject("started_at is not the canonical execution timestamp")
    grant = _authorized_grant(
        order_document,
        operation_id,
        executor_role,
    )
    if grant["package_digest"] not in readiness.ordered_package_digests:
        _reject("operation Rule Package is outside execution readiness")
    package, hook = _operation_contract(
        package_resolver=package_resolver,
        grant=grant,
    )
    adapter = _adapter({
        "adapter_id": adapter_id,
        "adapter_version": adapter_version,
        "adapter_digest": adapter_digest,
        "execution_mode": execution_mode,
    })
    _resolve_adapter_for_receipt(
        adapter=adapter,
        grant=grant,
        required_permissions=tuple(hook["permissions"]),
        resolver=adapter_resolver,
        policy=adapter_policy,
    )
    verify_execution_content(
        package=package,
        hook=hook,
        operation_input=operation_input,
        outcome=outcome,
        result=result,
        resolver=content_resolver,
        schema_validator=schema_validator,
    )
    order_digest_value = trade_order_digest(verified_order)
    sorted_evidence = sorted(
        copy.deepcopy(list(evidence)),
        key=lambda item: (
            item.get("evidence_type", "") if isinstance(item, dict) else "",
            item.get("digest", "") if isinstance(item, dict) else "",
        ),
    )
    document = {
        "kind": EXECUTION_RECEIPT_KIND,
        "protocol_version": EXECUTION_RECEIPT_PROTOCOL_VERSION,
        "execution_id": _execution_id(
            order_digest=order_digest_value,
            executor_did=executor_did,
            operation_id=operation_id,
        ),
        "order_id": order_document["order_id"],
        "order_digest": order_digest_value,
        "executor_did": executor_did,
        "executor_role": executor_role,
        "readiness": readiness.to_dict(),
        "readiness_digest": readiness.digest,
        "adapter": adapter,
        "operation": {
            **grant,
            "input": copy.deepcopy(operation_input),
            "input_schema_digest": hook["input_schema_digest"],
            "output_schema_digest": hook["output_schema_digest"],
            "side_effect": hook["side_effect"],
        },
        "outcome": outcome,
        "result": copy.deepcopy(result),
        "evidence": sorted_evidence,
        "started_at": started_at,
        "completed_at": completed_at,
        "proof": {
            "type": EXECUTION_RECEIPT_PROOF_TYPE,
            "created": completed_at,
            "verification_method": verification_method_for_did(executor_did),
            "proof_purpose": EXECUTION_RECEIPT_PROOF_PURPOSE,
            "proof_value": "A" * 86,
        },
    }
    _validate(document)
    signing_input = signed_document_input(
        EXECUTION_RECEIPT_SIGNING_DOMAIN,
        document,
    )
    document["proof"]["proof_value"] = encode_ed25519_signature(
        identity.sign(signing_input)
    )
    return TradeExecutionReceipt.from_dict(document, order=verified_order)


__all__ = [
    "EXECUTION_OUTCOMES",
    "EXECUTION_RECEIPT_ID_PREFIX",
    "EXECUTION_RECEIPT_KIND",
    "EXECUTION_RECEIPT_PROOF_PURPOSE",
    "EXECUTION_RECEIPT_PROOF_TYPE",
    "EXECUTION_RECEIPT_PROTOCOL_VERSION",
    "EXECUTION_RECEIPT_SIGNING_DOMAIN",
    "EXECUTION_TERMS_KEY",
    "EXECUTOR_ROLES",
    "MAX_EXECUTION_EVIDENCE",
    "TradeExecutionReceipt",
    "TradeExecutionReceiptRejected",
    "execution_receipt_digest",
    "verify_execution_receipt_order_binding",
    "verify_execution_receipt_under_policy",
]
