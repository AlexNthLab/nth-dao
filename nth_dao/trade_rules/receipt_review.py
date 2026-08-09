"""Counterparty-signed review of a Trade Execution Receipt."""

from __future__ import annotations

import copy
import hashlib
import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from nth_dao.did_key import is_did_key
from nth_dao.identity import AgentIdentity
from nth_dao.trade_rules.agreement import DEFAULT_CLOCK_SKEW_SECONDS
from nth_dao.trade_rules.agreement_order import (
    ORDER_ID_PREFIX,
    TradeOrder,
    trade_order_digest,
)
from nth_dao.trade_rules.canonical import (
    TradeCanonicalJSONError,
    parse_trade_json,
    trade_canonical_json,
)
from nth_dao.trade_rules.execution_adapter import (
    TradeExecutionAdapterPolicy,
    TradeExecutionAdapterResolver,
)
from nth_dao.trade_rules.execution_content import (
    TradeExecutionContentResolver,
    TradeExecutionSchemaValidator,
)
from nth_dao.trade_rules.execution_receipt import (
    EXECUTION_RECEIPT_ID_PREFIX,
    TradeExecutionReceipt,
    execution_receipt_digest,
    verify_execution_receipt_under_policy,
)
from nth_dao.trade_rules.negotiation import (
    RulePackageResolver,
    RuleResolutionPolicy,
)
from nth_dao.trade_rules.signing import (
    TradeProofError,
    encode_ed25519_signature,
    signed_document_input,
    verification_method_for_did,
    verify_ed25519_did_signature,
)

RECEIPT_REVIEW_KIND = "nth.dao.trade.receipt-review"
RECEIPT_REVIEW_PROTOCOL_VERSION = "1"
RECEIPT_REVIEW_PROOF_TYPE = "Ed25519Signature2020"
RECEIPT_REVIEW_PROOF_PURPOSE = "tradeReceiptReview"
RECEIPT_REVIEW_ID_PREFIX = "nth-trade-review-sha256:"
RECEIPT_REVIEW_SIGNING_DOMAIN = b"nth-dao/trade-receipt-review/v1"
RECEIPT_REVIEW_DECISIONS = frozenset({"accepted", "rejected", "disputed"})
MAX_RECEIPT_REVIEW_REASONS = 32

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ORDER_ID = re.compile(rf"^{re.escape(ORDER_ID_PREFIX)}[0-9a-f]{{64}}$")
_EXECUTION_ID = re.compile(
    rf"^{re.escape(EXECUTION_RECEIPT_ID_PREFIX)}[0-9a-f]{{64}}$"
)
_REVIEW_ID = re.compile(
    rf"^{re.escape(RECEIPT_REVIEW_ID_PREFIX)}[0-9a-f]{{64}}$"
)
_REASON = re.compile(r"^[a-z][a-z0-9._:-]{0,127}$")
_TIMESTAMP = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{6}))?Z$"
)
_FIELDS = frozenset(
    {
        "kind",
        "protocol_version",
        "review_id",
        "order_id",
        "order_digest",
        "execution_id",
        "receipt_digest",
        "reviewer_did",
        "reviewer_role",
        "verifier_policy_digest",
        "adapter_policy_digest",
        "decision",
        "reason_codes",
        "reviewed_at",
        "proof",
    }
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
_PARTY_ROLES = frozenset({"maker", "taker"})


class TradeReceiptReviewRejected(ValueError):
    """A Receipt review is malformed, unbound, or unsigned."""


def _reject(message: str) -> None:
    raise TradeReceiptReviewRejected(message)


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
    if match is None or match.group(2) == "000000":
        _reject(f"{label} must be a canonical UTC RFC3339 timestamp")
    fraction = match.group(2)
    try:
        return datetime.strptime(
            match.group(1) + (f".{fraction}" if fraction else ""),
            "%Y-%m-%dT%H:%M:%S.%f" if fraction else "%Y-%m-%dT%H:%M:%S",
        ).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise TradeReceiptReviewRejected(
            f"{label} is not a real timestamp"
        ) from exc


def _utc_now(value: datetime | None) -> datetime:
    moment = value or datetime.now(timezone.utc)
    if (
        not isinstance(moment, datetime)
        or moment.tzinfo is None
        or moment.utcoffset() is None
    ):
        _reject("now must be timezone-aware")
    return moment.astimezone(timezone.utc)


def receipt_review_id(*, receipt_digest: str, reviewer_did: str) -> str:
    """Derive the one stable review identity for a Receipt counterparty."""

    _digest(receipt_digest, label="receipt_digest")
    if not isinstance(reviewer_did, str) or not is_did_key(reviewer_did):
        _reject("reviewer_did must be an Ed25519 did:key")
    binding = {
        "receipt_digest": receipt_digest,
        "reviewer_did": reviewer_did,
    }
    return RECEIPT_REVIEW_ID_PREFIX + hashlib.sha256(
        trade_canonical_json(binding)
    ).hexdigest()


def _validate(document: dict[str, Any]) -> None:
    _exact_fields(document, _FIELDS, "receipt review")
    if document["kind"] != RECEIPT_REVIEW_KIND:
        _reject("wrong receipt review kind")
    if document["protocol_version"] != RECEIPT_REVIEW_PROTOCOL_VERSION:
        _reject("unsupported receipt review protocol_version")
    if (
        not isinstance(document["review_id"], str)
        or _REVIEW_ID.fullmatch(document["review_id"]) is None
    ):
        _reject("review_id is invalid")
    if (
        not isinstance(document["order_id"], str)
        or _ORDER_ID.fullmatch(document["order_id"]) is None
    ):
        _reject("order_id is invalid")
    if (
        not isinstance(document["execution_id"], str)
        or _EXECUTION_ID.fullmatch(document["execution_id"]) is None
    ):
        _reject("execution_id is invalid")
    for field in (
        "order_digest",
        "receipt_digest",
        "verifier_policy_digest",
        "adapter_policy_digest",
    ):
        _digest(document[field], label=field)
    reviewer_did = document["reviewer_did"]
    if not isinstance(reviewer_did, str) or not is_did_key(reviewer_did):
        _reject("reviewer_did must be an Ed25519 did:key")
    if document["reviewer_role"] not in _PARTY_ROLES:
        _reject("reviewer_role is invalid")
    decision = document["decision"]
    if decision not in RECEIPT_REVIEW_DECISIONS:
        _reject("decision is invalid")
    reasons = document["reason_codes"]
    if (
        not isinstance(reasons, list)
        or len(reasons) > MAX_RECEIPT_REVIEW_REASONS
        or any(
            not isinstance(reason, str)
            or _REASON.fullmatch(reason) is None
            for reason in reasons
        )
        or reasons != sorted(set(reasons))
    ):
        _reject("reason_codes must be a bounded sorted unique token list")
    if decision != "accepted" and not reasons:
        _reject("rejected and disputed reviews require a reason code")
    reviewed_at = document["reviewed_at"]
    _timestamp(reviewed_at, label="reviewed_at")
    proof = _exact_fields(document["proof"], _PROOF_FIELDS, "proof")
    if proof["type"] != RECEIPT_REVIEW_PROOF_TYPE:
        _reject("proof.type is invalid")
    if proof["created"] != reviewed_at:
        _reject("proof.created must equal reviewed_at")
    if (
        proof["verification_method"]
        != verification_method_for_did(reviewer_did)
    ):
        _reject("proof.verification_method does not match reviewer_did")
    if proof["proof_purpose"] != RECEIPT_REVIEW_PROOF_PURPOSE:
        _reject("proof.proof_purpose is invalid")


def _verify_signature(document: dict[str, Any]) -> None:
    try:
        signing_input = signed_document_input(
            RECEIPT_REVIEW_SIGNING_DOMAIN,
            document,
        )
    except TradeProofError as exc:
        raise TradeReceiptReviewRejected(str(exc)) from exc
    ok, reason = verify_ed25519_did_signature(
        publisher_did=document["reviewer_did"],
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


def _verified_receipt(
    receipt: TradeExecutionReceipt | dict[str, Any],
    *,
    order: TradeOrder,
) -> TradeExecutionReceipt:
    return (
        TradeExecutionReceipt.from_json(
            receipt.canonical_bytes,
            order=order,
        )
        if isinstance(receipt, TradeExecutionReceipt)
        else TradeExecutionReceipt.from_dict(receipt, order=order)
    )


def _assert_binding(
    review: "TradeReceiptReview",
    *,
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
) -> tuple[TradeExecutionReceipt, TradeOrder]:
    verified_order = _verified_order(order)
    verified_receipt = _verified_receipt(receipt, order=verified_order)
    review_document = review.to_dict()
    order_document = verified_order.to_dict()
    receipt_document = verified_receipt.to_dict()
    expected_receipt_digest = execution_receipt_digest(verified_receipt)
    exact_bindings = {
        "order_id": order_document["order_id"],
        "order_digest": trade_order_digest(verified_order),
        "execution_id": receipt_document["execution_id"],
        "receipt_digest": expected_receipt_digest,
    }
    for field, expected in exact_bindings.items():
        if review_document[field] != expected:
            _reject(f"receipt review {field} binding mismatch")
    expected_role = (
        "taker" if receipt_document["executor_role"] == "maker" else "maker"
    )
    if review_document["reviewer_role"] != expected_role:
        _reject("receipt review must be signed by the counterparty role")
    if review_document["reviewer_did"] != order_document[f"{expected_role}_did"]:
        _reject("receipt review signer does not match reviewer_role")
    if review_document["review_id"] != receipt_review_id(
        receipt_digest=expected_receipt_digest,
        reviewer_did=review_document["reviewer_did"],
    ):
        _reject("review_id binding mismatch")
    if (
        review_document["decision"] == "accepted"
        and receipt_document["outcome"] != "succeeded"
    ):
        _reject("only a succeeded Receipt may be accepted")
    if _timestamp(
        review_document["reviewed_at"],
        label="reviewed_at",
    ) < _timestamp(receipt_document["completed_at"], label="completed_at"):
        _reject("reviewed_at precedes Receipt completion")
    return verified_receipt, verified_order


@dataclass(frozen=True, init=False)
class TradeReceiptReview:
    """Immutable signed counterparty review."""

    _canonical_bytes: bytes

    @classmethod
    def _create(cls, canonical: bytes) -> "TradeReceiptReview":
        value = object.__new__(cls)
        object.__setattr__(value, "_canonical_bytes", bytes(canonical))
        return value

    @classmethod
    def from_dict(
        cls,
        document: dict[str, Any],
        *,
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
    ) -> "TradeReceiptReview":
        try:
            canonical = trade_canonical_json(copy.deepcopy(document))
            snapshot = parse_trade_json(canonical)
            _validate(snapshot)
            _verify_signature(snapshot)
            review = cls._create(canonical)
            _assert_binding(review, receipt=receipt, order=order)
            return review
        except (
            TradeCanonicalJSONError,
            TradeProofError,
            TypeError,
            ValueError,
            UnicodeError,
        ) as exc:
            if isinstance(exc, TradeReceiptReviewRejected):
                raise
            raise TradeReceiptReviewRejected(str(exc)) from exc

    @classmethod
    def from_json(
        cls,
        raw: bytes | str,
        *,
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
    ) -> "TradeReceiptReview":
        try:
            return cls.from_dict(
                parse_trade_json(raw),
                receipt=receipt,
                order=order,
            )
        except TradeCanonicalJSONError as exc:
            raise TradeReceiptReviewRejected(str(exc)) from exc

    @property
    def canonical_bytes(self) -> bytes:
        return self._canonical_bytes

    @property
    def review_id(self) -> str:
        return self.to_dict()["review_id"]

    def to_dict(self) -> dict[str, Any]:
        return parse_trade_json(self._canonical_bytes)


def receipt_review_digest(
    review: TradeReceiptReview | dict[str, Any],
    *,
    receipt: TradeExecutionReceipt | dict[str, Any] | None = None,
    order: TradeOrder | dict[str, Any] | None = None,
) -> str:
    if (receipt is None) != (order is None):
        raise TypeError(
            "receipt and order must be provided together for binding"
        )
    if isinstance(review, TradeReceiptReview):
        verified = TradeReceiptReview._create(review.canonical_bytes)
        _validate(verified.to_dict())
        _verify_signature(verified.to_dict())
        if receipt is not None and order is not None:
            _assert_binding(verified, receipt=receipt, order=order)
    else:
        if receipt is None or order is None:
            raise TypeError(
                "receipt and order are required when review is a dict"
            )
        verified = TradeReceiptReview.from_dict(
            review,
            receipt=receipt,
            order=order,
        )
    return "sha256:" + hashlib.sha256(verified.canonical_bytes).hexdigest()


def verify_trade_receipt_review_under_policy(
    review: TradeReceiptReview | dict[str, Any],
    *,
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
    package_resolver: RulePackageResolver,
    verifier_policy: RuleResolutionPolicy,
    adapter_resolver: TradeExecutionAdapterResolver,
    adapter_policy: TradeExecutionAdapterPolicy,
    content_resolver: TradeExecutionContentResolver,
    schema_validator: TradeExecutionSchemaValidator,
) -> None:
    verified_review = (
        TradeReceiptReview.from_json(
            review.canonical_bytes,
            receipt=receipt,
            order=order,
        )
        if isinstance(review, TradeReceiptReview)
        else TradeReceiptReview.from_dict(
            review,
            receipt=receipt,
            order=order,
        )
    )
    verify_execution_receipt_under_policy(
        receipt,
        order,
        package_resolver,
        verifier_policy,
        adapter_resolver,
        adapter_policy,
        content_resolver,
        schema_validator,
    )
    document = verified_review.to_dict()
    if document["verifier_policy_digest"] != verifier_policy.digest:
        _reject("review verifier_policy_digest does not match local policy")
    if document["adapter_policy_digest"] != adapter_policy.digest:
        _reject("review adapter_policy_digest does not match local policy")


def create_trade_receipt_review(
    identity: AgentIdentity,
    *,
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
    package_resolver: RulePackageResolver,
    verifier_policy: RuleResolutionPolicy,
    adapter_resolver: TradeExecutionAdapterResolver,
    adapter_policy: TradeExecutionAdapterPolicy,
    content_resolver: TradeExecutionContentResolver,
    schema_validator: TradeExecutionSchemaValidator,
    decision: str,
    reason_codes: list[str] | tuple[str, ...] = (),
    reviewed_at: str,
    now: datetime | None = None,
    clock_skew_seconds: float = DEFAULT_CLOCK_SKEW_SECONDS,
) -> TradeReceiptReview:
    """Re-verify a Receipt under local policy, then sign a review claim."""

    if not isinstance(identity, AgentIdentity):
        raise TypeError("identity must be an AgentIdentity")
    verified_order = _verified_order(order)
    verified_receipt = _verified_receipt(receipt, order=verified_order)
    verify_execution_receipt_under_policy(
        verified_receipt,
        verified_order,
        package_resolver,
        verifier_policy,
        adapter_resolver,
        adapter_policy,
        content_resolver,
        schema_validator,
    )
    order_document = verified_order.to_dict()
    receipt_document = verified_receipt.to_dict()
    reviewer_role = (
        "taker" if receipt_document["executor_role"] == "maker" else "maker"
    )
    reviewer_did = identity.as_did()
    if reviewer_did != order_document[f"{reviewer_role}_did"]:
        _reject("receipt review must be signed by the counterparty")
    reviewed = _timestamp(reviewed_at, label="reviewed_at")
    if reviewed < _timestamp(
        receipt_document["completed_at"],
        label="completed_at",
    ):
        _reject("reviewed_at precedes Receipt completion")
    if (
        isinstance(clock_skew_seconds, bool)
        or not isinstance(clock_skew_seconds, (int, float))
        or not math.isfinite(clock_skew_seconds)
        or clock_skew_seconds < 0
    ):
        _reject("clock_skew_seconds must be a finite non-negative number")
    if abs((_utc_now(now) - reviewed).total_seconds()) > float(
        clock_skew_seconds
    ):
        _reject("reviewed_at exceeds the local signing clock-skew limit")
    receipt_digest_value = execution_receipt_digest(verified_receipt)
    document = {
        "kind": RECEIPT_REVIEW_KIND,
        "protocol_version": RECEIPT_REVIEW_PROTOCOL_VERSION,
        "review_id": receipt_review_id(
            receipt_digest=receipt_digest_value,
            reviewer_did=reviewer_did,
        ),
        "order_id": order_document["order_id"],
        "order_digest": trade_order_digest(verified_order),
        "execution_id": receipt_document["execution_id"],
        "receipt_digest": receipt_digest_value,
        "reviewer_did": reviewer_did,
        "reviewer_role": reviewer_role,
        "verifier_policy_digest": verifier_policy.digest,
        "adapter_policy_digest": adapter_policy.digest,
        "decision": decision,
        "reason_codes": sorted(copy.deepcopy(list(reason_codes))),
        "reviewed_at": reviewed_at,
        "proof": {
            "type": RECEIPT_REVIEW_PROOF_TYPE,
            "created": reviewed_at,
            "verification_method": verification_method_for_did(reviewer_did),
            "proof_purpose": RECEIPT_REVIEW_PROOF_PURPOSE,
            "proof_value": "A" * 86,
        },
    }
    _validate(document)
    if decision == "accepted" and receipt_document["outcome"] != "succeeded":
        _reject("only a succeeded Receipt may be accepted")
    signing_input = signed_document_input(
        RECEIPT_REVIEW_SIGNING_DOMAIN,
        document,
    )
    document["proof"]["proof_value"] = encode_ed25519_signature(
        identity.sign(signing_input)
    )
    return TradeReceiptReview.from_dict(
        document,
        receipt=verified_receipt,
        order=verified_order,
    )


__all__ = [
    "MAX_RECEIPT_REVIEW_REASONS",
    "RECEIPT_REVIEW_DECISIONS",
    "RECEIPT_REVIEW_ID_PREFIX",
    "RECEIPT_REVIEW_KIND",
    "RECEIPT_REVIEW_PROOF_PURPOSE",
    "RECEIPT_REVIEW_PROOF_TYPE",
    "RECEIPT_REVIEW_PROTOCOL_VERSION",
    "RECEIPT_REVIEW_SIGNING_DOMAIN",
    "TradeReceiptReview",
    "TradeReceiptReviewRejected",
    "create_trade_receipt_review",
    "receipt_review_digest",
    "receipt_review_id",
    "verify_trade_receipt_review_under_policy",
]
