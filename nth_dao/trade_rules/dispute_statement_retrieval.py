"""Signed bilateral retrieval for an exact Trade Dispute Statement.

This module defines only the wire protocol. Network exposure, replay-journal
persistence, rate limiting, and automatic graph repair belong to the federation
service layer and must not be inferred from these value objects.
"""

from __future__ import annotations

import copy
import hashlib
import re
import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from nth_dao.did_key import is_did_key
from nth_dao.identity import AgentIdentity
from nth_dao.trade_rules.agreement_order import (
    TradeOrder,
    TradeOrderRejected,
    trade_order_digest,
)
from nth_dao.trade_rules.canonical import (
    MAX_TRADE_JSON_BYTES,
    TradeCanonicalJSONError,
    parse_trade_json,
    trade_canonical_json,
)
from nth_dao.trade_rules.dispute_statement import (
    TradeDisputeStatement,
    TradeDisputeStatementRejected,
    UnresolvedTradeDisputeStatement,
    trade_dispute_id,
    trade_dispute_statement_digest,
)
from nth_dao.trade_rules.execution_receipt import (
    TradeExecutionReceipt,
    TradeExecutionReceiptRejected,
    execution_receipt_digest,
)
from nth_dao.trade_rules.receipt_review import (
    TradeReceiptReview,
    TradeReceiptReviewRejected,
    receipt_review_digest,
)
from nth_dao.trade_rules.signing import (
    TradeProofError,
    encode_ed25519_signature,
    signed_document_input,
    verification_method_for_did,
)
from nth_dao.trade_rules.transport_common import (
    bounded_seconds,
    now_ns,
    opposite_party,
    reject,
    timestamp_ns,
    validate_transport_proof,
    verify_transport_signature,
    within_clock_skewed_lifetime,
)

DISPUTE_STATEMENT_FETCH_REQUEST_KIND = "nth.dao.trade.dispute-statement-fetch-request"
DISPUTE_STATEMENT_FETCH_RESPONSE_KIND = "nth.dao.trade.dispute-statement-fetch-response"
DISPUTE_STATEMENT_FETCH_PROTOCOL_VERSION = "1"
DISPUTE_STATEMENT_FETCH_REQUEST_PROOF_PURPOSE = "tradeDisputeStatementFetchRequest"
DISPUTE_STATEMENT_FETCH_RESPONSE_PROOF_PURPOSE = "tradeDisputeStatementFetchResponse"
DISPUTE_STATEMENT_FETCH_PROOF_TYPE = "Ed25519Signature2020"
DISPUTE_STATEMENT_FETCH_REQUEST_SIGNING_DOMAIN = (
    b"nth-dao/trade-dispute-statement-fetch-request/v1"
)
DISPUTE_STATEMENT_FETCH_RESPONSE_SIGNING_DOMAIN = (
    b"nth-dao/trade-dispute-statement-fetch-response/v1"
)
DEFAULT_MAX_DISPUTE_STATEMENT_FETCH_TTL_SECONDS = 300.0
DEFAULT_DISPUTE_STATEMENT_FETCH_CLOCK_SKEW_SECONDS = 300.0
MAX_DISPUTE_STATEMENT_FETCH_SECONDS = 86_400.0
MAX_DISPUTE_STATEMENT_FETCH_REQUEST_BYTES = 16 * 1024
MAX_DISPUTE_STATEMENT_FETCH_RESPONSE_BYTES = MAX_TRADE_JSON_BYTES

_REQUEST_ID_PREFIX = "nth:trade:dispute-statement-fetch-request:sha256:"
_RESPONSE_ID_PREFIX = "nth:trade:dispute-statement-fetch-response:sha256:"
_REQUEST_ID = re.compile(rf"^{re.escape(_REQUEST_ID_PREFIX)}[0-9a-f]{{64}}$")
_RESPONSE_ID = re.compile(rf"^{re.escape(_RESPONSE_ID_PREFIX)}[0-9a-f]{{64}}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_EXECUTION_ID = re.compile(r"^nth-trade-execution-sha256:[0-9a-f]{64}$")
_REVIEW_ID = re.compile(r"^nth-trade-review-sha256:[0-9a-f]{64}$")
_DISPUTE_ID = re.compile(r"^nth-trade-dispute-sha256:[0-9a-f]{64}$")
_NONCE = re.compile(r"^(?:[0-9a-f]{2}){16,64}$")

_REQUEST_FIELDS = frozenset(
    {
        "kind",
        "protocol_version",
        "request_id",
        "nonce",
        "order_digest",
        "execution_id",
        "receipt_digest",
        "review_id",
        "review_digest",
        "dispute_id",
        "statement_digest",
        "requester_did",
        "responder_did",
        "created_at",
        "not_after",
        "proof",
    }
)
_RESPONSE_FIELDS = frozenset(
    {
        "kind",
        "protocol_version",
        "response_id",
        "request_id",
        "request_digest",
        "order_digest",
        "receipt_digest",
        "review_digest",
        "statement_digest",
        "requester_did",
        "responder_did",
        "served_at",
        "statement",
        "proof",
    }
)


class TradeDisputeStatementFetchRequestRejected(ValueError):
    """A fetch request is malformed, stale, unsigned, or unauthorized."""


class TradeDisputeStatementFetchResponseRejected(ValueError):
    """A fetch response is malformed, unsigned, stale, or rebound."""


def _bounded_transport_seconds(
    value: Any,
    *,
    label: str,
    error_type: type[ValueError],
) -> float:
    return bounded_seconds(
        value,
        label=label,
        error_type=error_type,
        maximum=MAX_DISPUTE_STATEMENT_FETCH_SECONDS,
    )


def _verified_context(
    *,
    review: TradeReceiptReview | dict[str, Any],
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
) -> tuple[TradeReceiptReview, TradeExecutionReceipt, TradeOrder]:
    verified_order = (
        TradeOrder.from_json(order.canonical_bytes)
        if isinstance(order, TradeOrder)
        else TradeOrder.from_dict(order)
    )
    verified_receipt = (
        TradeExecutionReceipt.from_json(receipt.canonical_bytes, order=verified_order)
        if isinstance(receipt, TradeExecutionReceipt)
        else TradeExecutionReceipt.from_dict(receipt, order=verified_order)
    )
    verified_review = (
        TradeReceiptReview.from_json(
            review.canonical_bytes,
            receipt=verified_receipt,
            order=verified_order,
        )
        if isinstance(review, TradeReceiptReview)
        else TradeReceiptReview.from_dict(
            review,
            receipt=verified_receipt,
            order=verified_order,
        )
    )
    return verified_review, verified_receipt, verified_order


def _content_binding(
    document: dict[str, Any],
    *,
    identifier_field: str,
) -> dict[str, Any]:
    return {
        key: copy.deepcopy(value)
        for key, value in document.items()
        if key not in {identifier_field, "proof"}
    }


def _content_id(
    document: dict[str, Any],
    *,
    identifier_field: str,
    prefix: str,
) -> str:
    return (
        prefix
        + hashlib.sha256(
            trade_canonical_json(
                _content_binding(document, identifier_field=identifier_field)
            )
        ).hexdigest()
    )


def _request_digest(document: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(trade_canonical_json(document)).hexdigest()


def _validate_request_envelope(document: dict[str, Any]) -> None:
    error_type = TradeDisputeStatementFetchRequestRejected
    if not isinstance(document, dict) or set(document) != _REQUEST_FIELDS:
        reject(error_type, "fetch request has missing or unknown fields")
    if document["kind"] != DISPUTE_STATEMENT_FETCH_REQUEST_KIND:
        reject(error_type, "wrong Dispute Statement fetch request kind")
    if document["protocol_version"] != DISPUTE_STATEMENT_FETCH_PROTOCOL_VERSION:
        reject(error_type, "unsupported fetch request protocol_version")
    if (
        not isinstance(document["request_id"], str)
        or _REQUEST_ID.fullmatch(document["request_id"]) is None
        or document["request_id"]
        != _content_id(
            document,
            identifier_field="request_id",
            prefix=_REQUEST_ID_PREFIX,
        )
    ):
        reject(error_type, "request_id does not match fetch request content")
    if (
        not isinstance(document["nonce"], str)
        or _NONCE.fullmatch(document["nonce"]) is None
    ):
        reject(error_type, "nonce must be 16 to 64 bytes of lowercase hex")
    for field in (
        "order_digest",
        "receipt_digest",
        "review_digest",
        "statement_digest",
    ):
        if (
            not isinstance(document[field], str)
            or _DIGEST.fullmatch(document[field]) is None
        ):
            reject(error_type, f"{field} must be a lowercase sha256 digest")
    if (
        not isinstance(document["execution_id"], str)
        or _EXECUTION_ID.fullmatch(document["execution_id"]) is None
    ):
        reject(error_type, "execution_id is invalid")
    if (
        not isinstance(document["review_id"], str)
        or _REVIEW_ID.fullmatch(document["review_id"]) is None
    ):
        reject(error_type, "review_id is invalid")
    if (
        not isinstance(document["dispute_id"], str)
        or _DISPUTE_ID.fullmatch(document["dispute_id"]) is None
    ):
        reject(error_type, "dispute_id is invalid")
    for field in ("requester_did", "responder_did"):
        if not isinstance(document[field], str) or not is_did_key(document[field]):
            reject(error_type, f"{field} must be an Ed25519 did:key")
    if document["requester_did"] == document["responder_did"]:
        reject(error_type, "fetch request parties must be different principals")

    created_ns = timestamp_ns(
        document["created_at"],
        label="created_at",
        error_type=error_type,
    )
    expiry_ns = timestamp_ns(
        document["not_after"],
        label="not_after",
        error_type=error_type,
    )
    if expiry_ns <= created_ns:
        reject(error_type, "not_after must be later than created_at")
    validate_transport_proof(
        document["proof"],
        signer_did=document["requester_did"],
        purpose=DISPUTE_STATEMENT_FETCH_REQUEST_PROOF_PURPOSE,
        created_at=document["created_at"],
        proof_type=DISPUTE_STATEMENT_FETCH_PROOF_TYPE,
        error_type=error_type,
    )


def _validate_request_static(
    document: dict[str, Any],
    *,
    review: TradeReceiptReview,
    receipt: TradeExecutionReceipt,
    order: TradeOrder,
) -> None:
    error_type = TradeDisputeStatementFetchRequestRejected
    _validate_request_envelope(document)

    order_document = order.to_dict()
    receipt_document = receipt.to_dict()
    review_document = review.to_dict()
    if document["order_digest"] != trade_order_digest(order):
        reject(error_type, "order_digest does not match signed Order")
    if document["execution_id"] != receipt_document["execution_id"]:
        reject(error_type, "execution_id does not match signed Receipt")
    if document["receipt_digest"] != execution_receipt_digest(receipt, order=order):
        reject(error_type, "receipt_digest does not match signed Receipt")
    if document["review_id"] != review_document["review_id"]:
        reject(error_type, "review_id does not match signed Review")
    if document["review_digest"] != receipt_review_digest(
        review,
        receipt=receipt,
        order=order,
    ):
        reject(error_type, "review_digest does not match signed Review")
    if document["dispute_id"] != trade_dispute_id(review_document["review_id"]):
        reject(error_type, "dispute_id does not match signed Review")
    if review_document["decision"] != "disputed":
        reject(error_type, "fetch request requires a disputed Receipt Review")
    if document["requester_did"] not in {
        order_document["maker_did"],
        order_document["taker_did"],
    }:
        reject(error_type, "requester_did is not a party to the signed Order")
    expected_responder = opposite_party(
        order_document,
        document["requester_did"],
        error_type=error_type,
    )
    if document["responder_did"] != expected_responder:
        reject(error_type, "responder_did is not the opposing Order party")


@dataclass(frozen=True, init=False)
class TradeDisputeStatementFetchRequest:
    """Canonical short-lived authorization to fetch one exact Statement."""

    _canonical_bytes: bytes

    @classmethod
    def _create(cls, canonical: bytes) -> "TradeDisputeStatementFetchRequest":
        value = object.__new__(cls)
        object.__setattr__(value, "_canonical_bytes", bytes(canonical))
        return value

    @classmethod
    def from_dict(
        cls,
        document: dict[str, Any],
        *,
        review: TradeReceiptReview | dict[str, Any],
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
    ) -> "TradeDisputeStatementFetchRequest":
        try:
            verified_review, verified_receipt, verified_order = _verified_context(
                review=review,
                receipt=receipt,
                order=order,
            )
            canonical = trade_canonical_json(copy.deepcopy(document))
            if len(canonical) > MAX_DISPUTE_STATEMENT_FETCH_REQUEST_BYTES:
                reject(
                    TradeDisputeStatementFetchRequestRejected,
                    "fetch request exceeds byte limit",
                )
            snapshot = parse_trade_json(canonical)
            _validate_request_static(
                snapshot,
                review=verified_review,
                receipt=verified_receipt,
                order=verified_order,
            )
            verify_transport_signature(
                snapshot,
                signer_field="requester_did",
                domain=DISPUTE_STATEMENT_FETCH_REQUEST_SIGNING_DOMAIN,
                error_type=TradeDisputeStatementFetchRequestRejected,
            )
        except (
            TradeCanonicalJSONError,
            TradeDisputeStatementRejected,
            TradeExecutionReceiptRejected,
            TradeOrderRejected,
            TradeProofError,
            TradeReceiptReviewRejected,
            TypeError,
            ValueError,
            UnicodeError,
        ) as exc:
            if isinstance(exc, TradeDisputeStatementFetchRequestRejected):
                raise
            raise TradeDisputeStatementFetchRequestRejected(str(exc)) from exc
        return cls._create(canonical)

    @classmethod
    def from_json(
        cls,
        raw: bytes | str,
        *,
        review: TradeReceiptReview | dict[str, Any],
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
    ) -> "TradeDisputeStatementFetchRequest":
        try:
            return cls.from_dict(
                parse_trade_json(raw),
                review=review,
                receipt=receipt,
                order=order,
            )
        except TradeCanonicalJSONError as exc:
            raise TradeDisputeStatementFetchRequestRejected(str(exc)) from exc

    @property
    def canonical_bytes(self) -> bytes:
        return self._canonical_bytes

    def to_dict(self) -> dict[str, Any]:
        return parse_trade_json(self._canonical_bytes)

    def assert_observed_at(
        self,
        *,
        at: datetime | None = None,
        max_ttl_seconds: float = DEFAULT_MAX_DISPUTE_STATEMENT_FETCH_TTL_SECONDS,
        clock_skew_seconds: float = DEFAULT_DISPUTE_STATEMENT_FETCH_CLOCK_SKEW_SECONDS,
    ) -> None:
        error_type = TradeDisputeStatementFetchRequestRejected
        max_ttl = _bounded_transport_seconds(
            max_ttl_seconds,
            label="max_ttl_seconds",
            error_type=error_type,
        )
        skew = _bounded_transport_seconds(
            clock_skew_seconds,
            label="clock_skew_seconds",
            error_type=error_type,
        )
        document = self.to_dict()
        created_ns = timestamp_ns(
            document["created_at"], label="created_at", error_type=error_type
        )
        expiry_ns = timestamp_ns(
            document["not_after"], label="not_after", error_type=error_type
        )
        if expiry_ns - created_ns > int(max_ttl * 1_000_000_000):
            reject(error_type, "fetch request lifetime exceeds max_ttl_seconds")
        if not within_clock_skewed_lifetime(
            now_ns(at, error_type=error_type),
            created_ns=created_ns,
            expiry_ns=expiry_ns,
            skew_ns=int(skew * 1_000_000_000),
        ):
            reject(error_type, "fetch request is outside its signed lifetime")


def preflight_trade_dispute_statement_fetch_request(
    raw: bytes | str,
    *,
    order_digest: str,
    execution_id: str,
    review_id: str,
    responder_did: str,
    at: datetime | None = None,
    max_ttl_seconds: float = DEFAULT_MAX_DISPUTE_STATEMENT_FETCH_TTL_SECONDS,
    clock_skew_seconds: float = DEFAULT_DISPUTE_STATEMENT_FETCH_CLOCK_SKEW_SECONDS,
) -> dict[str, Any]:
    """Verify the signed request envelope before loading retained trade state."""

    error_type = TradeDisputeStatementFetchRequestRejected
    try:
        document = parse_trade_json(raw)
        canonical = trade_canonical_json(document)
        if len(canonical) > MAX_DISPUTE_STATEMENT_FETCH_REQUEST_BYTES:
            reject(error_type, "fetch request exceeds byte limit")
        _validate_request_envelope(document)
        expected_path = {
            "order_digest": order_digest,
            "execution_id": execution_id,
            "review_id": review_id,
            "responder_did": responder_did,
        }
        for field, expected in expected_path.items():
            if document[field] != expected:
                reject(error_type, "fetch request does not match its destination")
        verify_transport_signature(
            document,
            signer_field="requester_did",
            domain=DISPUTE_STATEMENT_FETCH_REQUEST_SIGNING_DOMAIN,
            error_type=error_type,
        )
        TradeDisputeStatementFetchRequest._create(canonical).assert_observed_at(
            at=at,
            max_ttl_seconds=max_ttl_seconds,
            clock_skew_seconds=clock_skew_seconds,
        )
    except (
        TradeCanonicalJSONError,
        TradeProofError,
        TypeError,
        ValueError,
        UnicodeError,
    ) as exc:
        if isinstance(exc, error_type):
            raise
        raise error_type(str(exc)) from exc
    return document


def trade_dispute_statement_fetch_request_digest(
    request: TradeDisputeStatementFetchRequest | dict[str, Any],
    *,
    review: TradeReceiptReview | dict[str, Any],
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
) -> str:
    verified = (
        TradeDisputeStatementFetchRequest.from_json(
            request.canonical_bytes,
            review=review,
            receipt=receipt,
            order=order,
        )
        if isinstance(request, TradeDisputeStatementFetchRequest)
        else TradeDisputeStatementFetchRequest.from_dict(
            request,
            review=review,
            receipt=receipt,
            order=order,
        )
    )
    return _request_digest(verified.to_dict())


def create_trade_dispute_statement_fetch_request(
    identity: AgentIdentity,
    *,
    review: TradeReceiptReview | dict[str, Any],
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
    statement_digest: str,
    responder_did: str,
    created_at: str,
    not_after: str,
    nonce: str | None = None,
    now: datetime | None = None,
    max_ttl_seconds: float = DEFAULT_MAX_DISPUTE_STATEMENT_FETCH_TTL_SECONDS,
    clock_skew_seconds: float = DEFAULT_DISPUTE_STATEMENT_FETCH_CLOCK_SKEW_SECONDS,
) -> TradeDisputeStatementFetchRequest:
    """Create one destination-bound fetch authorization without network I/O."""

    if not isinstance(identity, AgentIdentity):
        raise TypeError("identity must be an AgentIdentity")
    verified_review, verified_receipt, verified_order = _verified_context(
        review=review,
        receipt=receipt,
        order=order,
    )
    requester_did = identity.as_did()
    nonce_value = nonce if nonce is not None else secrets.token_hex(16)
    receipt_document = verified_receipt.to_dict()
    review_document = verified_review.to_dict()
    document = {
        "kind": DISPUTE_STATEMENT_FETCH_REQUEST_KIND,
        "protocol_version": DISPUTE_STATEMENT_FETCH_PROTOCOL_VERSION,
        "request_id": _REQUEST_ID_PREFIX + ("0" * 64),
        "nonce": nonce_value,
        "order_digest": trade_order_digest(verified_order),
        "execution_id": receipt_document["execution_id"],
        "receipt_digest": execution_receipt_digest(
            verified_receipt,
            order=verified_order,
        ),
        "review_id": review_document["review_id"],
        "review_digest": receipt_review_digest(
            verified_review,
            receipt=verified_receipt,
            order=verified_order,
        ),
        "dispute_id": trade_dispute_id(review_document["review_id"]),
        "statement_digest": statement_digest,
        "requester_did": requester_did,
        "responder_did": responder_did,
        "created_at": created_at,
        "not_after": not_after,
        "proof": {
            "type": DISPUTE_STATEMENT_FETCH_PROOF_TYPE,
            "created": created_at,
            "verification_method": verification_method_for_did(requester_did),
            "proof_purpose": DISPUTE_STATEMENT_FETCH_REQUEST_PROOF_PURPOSE,
            "proof_value": "A" * 86,
        },
    }
    document["request_id"] = _content_id(
        document,
        identifier_field="request_id",
        prefix=_REQUEST_ID_PREFIX,
    )
    _validate_request_static(
        document,
        review=verified_review,
        receipt=verified_receipt,
        order=verified_order,
    )
    unsigned = TradeDisputeStatementFetchRequest._create(trade_canonical_json(document))
    unsigned.assert_observed_at(
        at=now,
        max_ttl_seconds=max_ttl_seconds,
        clock_skew_seconds=clock_skew_seconds,
    )
    document["proof"]["proof_value"] = encode_ed25519_signature(
        identity.sign(
            signed_document_input(
                DISPUTE_STATEMENT_FETCH_REQUEST_SIGNING_DOMAIN,
                document,
            )
        )
    )
    canonical = trade_canonical_json(document)
    if len(canonical) > MAX_DISPUTE_STATEMENT_FETCH_REQUEST_BYTES:
        raise TradeDisputeStatementFetchRequestRejected(
            "fetch request exceeds byte limit"
        )
    verify_transport_signature(
        document,
        signer_field="requester_did",
        domain=DISPUTE_STATEMENT_FETCH_REQUEST_SIGNING_DOMAIN,
        error_type=TradeDisputeStatementFetchRequestRejected,
    )
    return TradeDisputeStatementFetchRequest._create(canonical)


def _validate_response_static(
    document: dict[str, Any],
    *,
    request: TradeDisputeStatementFetchRequest,
    review: TradeReceiptReview,
    receipt: TradeExecutionReceipt,
    order: TradeOrder,
) -> UnresolvedTradeDisputeStatement:
    error_type = TradeDisputeStatementFetchResponseRejected
    if not isinstance(document, dict) or set(document) != _RESPONSE_FIELDS:
        reject(error_type, "fetch response has missing or unknown fields")
    if document["kind"] != DISPUTE_STATEMENT_FETCH_RESPONSE_KIND:
        reject(error_type, "wrong Dispute Statement fetch response kind")
    if document["protocol_version"] != DISPUTE_STATEMENT_FETCH_PROTOCOL_VERSION:
        reject(error_type, "unsupported fetch response protocol_version")
    if (
        not isinstance(document["response_id"], str)
        or _RESPONSE_ID.fullmatch(document["response_id"]) is None
        or document["response_id"]
        != _content_id(
            document,
            identifier_field="response_id",
            prefix=_RESPONSE_ID_PREFIX,
        )
    ):
        reject(error_type, "response_id does not match fetch response content")
    for field in (
        "request_digest",
        "order_digest",
        "receipt_digest",
        "review_digest",
        "statement_digest",
    ):
        if (
            not isinstance(document[field], str)
            or _DIGEST.fullmatch(document[field]) is None
        ):
            reject(error_type, f"fetch response {field} is invalid")
    if (
        not isinstance(document["request_id"], str)
        or _REQUEST_ID.fullmatch(document["request_id"]) is None
    ):
        reject(error_type, "fetch response request_id is invalid")
    for field in ("requester_did", "responder_did"):
        if not isinstance(document[field], str) or not is_did_key(document[field]):
            reject(error_type, f"fetch response {field} is invalid")

    request_document = request.to_dict()
    expected = {
        "request_id": request_document["request_id"],
        "request_digest": _request_digest(request_document),
        "order_digest": request_document["order_digest"],
        "receipt_digest": request_document["receipt_digest"],
        "review_digest": request_document["review_digest"],
        "statement_digest": request_document["statement_digest"],
        "requester_did": request_document["requester_did"],
        "responder_did": request_document["responder_did"],
    }
    for field, value in expected.items():
        if document[field] != value:
            reject(error_type, f"fetch response {field} does not match request")
    if document["order_digest"] != trade_order_digest(order):
        reject(error_type, "fetch response order_digest does not match signed Order")
    if document["receipt_digest"] != execution_receipt_digest(receipt, order=order):
        reject(
            error_type, "fetch response receipt_digest does not match signed Receipt"
        )
    if document["review_digest"] != receipt_review_digest(
        review,
        receipt=receipt,
        order=order,
    ):
        reject(error_type, "fetch response review_digest does not match signed Review")
    try:
        statement = UnresolvedTradeDisputeStatement.from_dict(
            document["statement"],
            review=review,
            receipt=receipt,
            order=order,
        )
    except (TradeDisputeStatementRejected, TypeError, ValueError) as exc:
        raise error_type(f"fetched Trade Dispute Statement is invalid: {exc}") from exc
    if document["statement_digest"] != trade_dispute_statement_digest(
        statement,
        review=review,
        receipt=receipt,
        order=order,
    ):
        reject(error_type, "statement_digest does not match fetched Statement")
    timestamp_ns(
        document["served_at"],
        label="served_at",
        error_type=error_type,
    )
    validate_transport_proof(
        document["proof"],
        signer_did=document["responder_did"],
        purpose=DISPUTE_STATEMENT_FETCH_RESPONSE_PROOF_PURPOSE,
        created_at=document["served_at"],
        proof_type=DISPUTE_STATEMENT_FETCH_PROOF_TYPE,
        error_type=error_type,
    )
    return statement


def _validate_response_observation(
    document: dict[str, Any],
    request: TradeDisputeStatementFetchRequest,
    *,
    at: datetime | None,
    max_ttl_seconds: float,
    clock_skew_seconds: float,
) -> None:
    """Validate freshness without weakening any signature-verification API."""

    error_type = TradeDisputeStatementFetchResponseRejected
    request.assert_observed_at(
        at=at,
        max_ttl_seconds=max_ttl_seconds,
        clock_skew_seconds=clock_skew_seconds,
    )
    request_document = request.to_dict()
    created_ns = timestamp_ns(
        request_document["created_at"],
        label="request.created_at",
        error_type=error_type,
    )
    expiry_ns = timestamp_ns(
        request_document["not_after"],
        label="request.not_after",
        error_type=error_type,
    )
    skew_ns = int(
        _bounded_transport_seconds(
            clock_skew_seconds,
            label="clock_skew_seconds",
            error_type=error_type,
        )
        * 1_000_000_000
    )
    served_ns = timestamp_ns(
        document["served_at"],
        label="served_at",
        error_type=error_type,
    )
    if not within_clock_skewed_lifetime(
        served_ns,
        created_ns=created_ns,
        expiry_ns=expiry_ns,
        skew_ns=skew_ns,
    ):
        reject(error_type, "fetch response was served outside request lifetime")
    if served_ns > now_ns(at, error_type=error_type) + skew_ns:
        reject(error_type, "fetch response was served too far in the future")


@dataclass(frozen=True, init=False)
class TradeDisputeStatementFetchResponse:
    """Responder-signed return of one author-signed Statement."""

    _canonical_bytes: bytes
    _statement: UnresolvedTradeDisputeStatement

    @classmethod
    def _create(
        cls,
        canonical: bytes,
        statement: UnresolvedTradeDisputeStatement,
    ) -> "TradeDisputeStatementFetchResponse":
        value = object.__new__(cls)
        object.__setattr__(value, "_canonical_bytes", bytes(canonical))
        object.__setattr__(value, "_statement", statement)
        return value

    @classmethod
    def from_dict(
        cls,
        document: dict[str, Any],
        *,
        request: TradeDisputeStatementFetchRequest | dict[str, Any],
        review: TradeReceiptReview | dict[str, Any],
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
    ) -> "TradeDisputeStatementFetchResponse":
        try:
            verified_review, verified_receipt, verified_order = _verified_context(
                review=review,
                receipt=receipt,
                order=order,
            )
            verified_request = (
                TradeDisputeStatementFetchRequest.from_json(
                    request.canonical_bytes,
                    review=verified_review,
                    receipt=verified_receipt,
                    order=verified_order,
                )
                if isinstance(request, TradeDisputeStatementFetchRequest)
                else TradeDisputeStatementFetchRequest.from_dict(
                    request,
                    review=verified_review,
                    receipt=verified_receipt,
                    order=verified_order,
                )
            )
            canonical = trade_canonical_json(copy.deepcopy(document))
            if len(canonical) > MAX_DISPUTE_STATEMENT_FETCH_RESPONSE_BYTES:
                reject(
                    TradeDisputeStatementFetchResponseRejected,
                    "fetch response exceeds byte limit",
                )
            snapshot = parse_trade_json(canonical)
            statement = _validate_response_static(
                snapshot,
                request=verified_request,
                review=verified_review,
                receipt=verified_receipt,
                order=verified_order,
            )
            verify_transport_signature(
                snapshot,
                signer_field="responder_did",
                domain=DISPUTE_STATEMENT_FETCH_RESPONSE_SIGNING_DOMAIN,
                error_type=TradeDisputeStatementFetchResponseRejected,
            )
        except (
            TradeCanonicalJSONError,
            TradeDisputeStatementRejected,
            TradeExecutionReceiptRejected,
            TradeOrderRejected,
            TradeProofError,
            TradeReceiptReviewRejected,
            TypeError,
            ValueError,
            UnicodeError,
        ) as exc:
            if isinstance(exc, TradeDisputeStatementFetchResponseRejected):
                raise
            raise TradeDisputeStatementFetchResponseRejected(str(exc)) from exc
        return cls._create(canonical, statement)

    @classmethod
    def from_json(
        cls,
        raw: bytes | str,
        *,
        request: TradeDisputeStatementFetchRequest | dict[str, Any],
        review: TradeReceiptReview | dict[str, Any],
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
    ) -> "TradeDisputeStatementFetchResponse":
        try:
            return cls.from_dict(
                parse_trade_json(raw),
                request=request,
                review=review,
                receipt=receipt,
                order=order,
            )
        except TradeCanonicalJSONError as exc:
            raise TradeDisputeStatementFetchResponseRejected(str(exc)) from exc

    @property
    def canonical_bytes(self) -> bytes:
        return self._canonical_bytes

    @property
    def statement(self) -> UnresolvedTradeDisputeStatement:
        return self._statement

    def to_dict(self) -> dict[str, Any]:
        return parse_trade_json(self._canonical_bytes)


def trade_dispute_statement_fetch_response_digest(
    response: TradeDisputeStatementFetchResponse | dict[str, Any],
    *,
    request: TradeDisputeStatementFetchRequest | dict[str, Any],
    review: TradeReceiptReview | dict[str, Any],
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
) -> str:
    verified = (
        TradeDisputeStatementFetchResponse.from_json(
            response.canonical_bytes,
            request=request,
            review=review,
            receipt=receipt,
            order=order,
        )
        if isinstance(response, TradeDisputeStatementFetchResponse)
        else TradeDisputeStatementFetchResponse.from_dict(
            response,
            request=request,
            review=review,
            receipt=receipt,
            order=order,
        )
    )
    return "sha256:" + hashlib.sha256(verified.canonical_bytes).hexdigest()


def create_trade_dispute_statement_fetch_response(
    identity: AgentIdentity,
    *,
    request: TradeDisputeStatementFetchRequest | dict[str, Any],
    statement: TradeDisputeStatement | dict[str, Any],
    review: TradeReceiptReview | dict[str, Any],
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
    served_at: str,
    now: datetime | None = None,
    max_ttl_seconds: float = DEFAULT_MAX_DISPUTE_STATEMENT_FETCH_TTL_SECONDS,
    clock_skew_seconds: float = DEFAULT_DISPUTE_STATEMENT_FETCH_CLOCK_SKEW_SECONDS,
) -> TradeDisputeStatementFetchResponse:
    """Return one exact Statement under the responder's signed provenance."""

    if not isinstance(identity, AgentIdentity):
        raise TypeError("identity must be an AgentIdentity")
    verified_review, verified_receipt, verified_order = _verified_context(
        review=review,
        receipt=receipt,
        order=order,
    )
    verified_request = (
        TradeDisputeStatementFetchRequest.from_json(
            request.canonical_bytes,
            review=verified_review,
            receipt=verified_receipt,
            order=verified_order,
        )
        if isinstance(request, TradeDisputeStatementFetchRequest)
        else TradeDisputeStatementFetchRequest.from_dict(
            request,
            review=verified_review,
            receipt=verified_receipt,
            order=verified_order,
        )
    )
    request_document = verified_request.to_dict()
    if identity.as_did() != request_document["responder_did"]:
        raise TradeDisputeStatementFetchResponseRejected(
            "response signer does not match requested responder_did"
        )
    verified_request.assert_observed_at(
        at=now,
        max_ttl_seconds=max_ttl_seconds,
        clock_skew_seconds=clock_skew_seconds,
    )
    unresolved = (
        UnresolvedTradeDisputeStatement.from_json(
            statement.canonical_bytes,
            review=verified_review,
            receipt=verified_receipt,
            order=verified_order,
        )
        if isinstance(statement, TradeDisputeStatement)
        else UnresolvedTradeDisputeStatement.from_dict(
            statement,
            review=verified_review,
            receipt=verified_receipt,
            order=verified_order,
        )
    )
    statement_digest_value = trade_dispute_statement_digest(
        unresolved,
        review=verified_review,
        receipt=verified_receipt,
        order=verified_order,
    )
    if statement_digest_value != request_document["statement_digest"]:
        raise TradeDisputeStatementFetchResponseRejected(
            "fetched Statement does not match requested statement_digest"
        )
    document = {
        "kind": DISPUTE_STATEMENT_FETCH_RESPONSE_KIND,
        "protocol_version": DISPUTE_STATEMENT_FETCH_PROTOCOL_VERSION,
        "response_id": _RESPONSE_ID_PREFIX + ("0" * 64),
        "request_id": request_document["request_id"],
        "request_digest": _request_digest(request_document),
        "order_digest": request_document["order_digest"],
        "receipt_digest": request_document["receipt_digest"],
        "review_digest": request_document["review_digest"],
        "statement_digest": statement_digest_value,
        "requester_did": request_document["requester_did"],
        "responder_did": request_document["responder_did"],
        "served_at": served_at,
        "statement": unresolved.to_dict(),
        "proof": {
            "type": DISPUTE_STATEMENT_FETCH_PROOF_TYPE,
            "created": served_at,
            "verification_method": verification_method_for_did(
                request_document["responder_did"]
            ),
            "proof_purpose": DISPUTE_STATEMENT_FETCH_RESPONSE_PROOF_PURPOSE,
            "proof_value": "A" * 86,
        },
    }
    document["response_id"] = _content_id(
        document,
        identifier_field="response_id",
        prefix=_RESPONSE_ID_PREFIX,
    )
    _validate_response_static(
        document,
        request=verified_request,
        review=verified_review,
        receipt=verified_receipt,
        order=verified_order,
    )
    _validate_response_observation(
        document,
        verified_request,
        at=now,
        max_ttl_seconds=max_ttl_seconds,
        clock_skew_seconds=clock_skew_seconds,
    )
    document["proof"]["proof_value"] = encode_ed25519_signature(
        identity.sign(
            signed_document_input(
                DISPUTE_STATEMENT_FETCH_RESPONSE_SIGNING_DOMAIN,
                document,
            )
        )
    )
    canonical = trade_canonical_json(document)
    verify_transport_signature(
        document,
        signer_field="responder_did",
        domain=DISPUTE_STATEMENT_FETCH_RESPONSE_SIGNING_DOMAIN,
        error_type=TradeDisputeStatementFetchResponseRejected,
    )
    return TradeDisputeStatementFetchResponse._create(canonical, unresolved)


def verify_trade_dispute_statement_fetch_request(
    request: TradeDisputeStatementFetchRequest | dict[str, Any],
    *,
    review: TradeReceiptReview | dict[str, Any],
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
    responder_did: str,
    at: datetime | None = None,
    max_ttl_seconds: float = DEFAULT_MAX_DISPUTE_STATEMENT_FETCH_TTL_SECONDS,
    clock_skew_seconds: float = DEFAULT_DISPUTE_STATEMENT_FETCH_CLOCK_SKEW_SECONDS,
) -> tuple[bool, str]:
    try:
        verified = (
            TradeDisputeStatementFetchRequest.from_json(
                request.canonical_bytes,
                review=review,
                receipt=receipt,
                order=order,
            )
            if isinstance(request, TradeDisputeStatementFetchRequest)
            else TradeDisputeStatementFetchRequest.from_dict(
                request,
                review=review,
                receipt=receipt,
                order=order,
            )
        )
        if verified.to_dict()["responder_did"] != responder_did:
            raise TradeDisputeStatementFetchRequestRejected(
                "fetch request is addressed to another responder"
            )
        verified.assert_observed_at(
            at=at,
            max_ttl_seconds=max_ttl_seconds,
            clock_skew_seconds=clock_skew_seconds,
        )
    except (
        TradeDisputeStatementFetchRequestRejected,
        TypeError,
        ValueError,
        UnicodeError,
    ) as exc:
        return False, str(exc)
    return True, "ok"


def verify_trade_dispute_statement_fetch_response(
    response: TradeDisputeStatementFetchResponse | dict[str, Any],
    *,
    request: TradeDisputeStatementFetchRequest | dict[str, Any],
    review: TradeReceiptReview | dict[str, Any],
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
    at: datetime | None = None,
    max_ttl_seconds: float = DEFAULT_MAX_DISPUTE_STATEMENT_FETCH_TTL_SECONDS,
    clock_skew_seconds: float = DEFAULT_DISPUTE_STATEMENT_FETCH_CLOCK_SKEW_SECONDS,
) -> tuple[bool, str]:
    try:
        verified_review, verified_receipt, verified_order = _verified_context(
            review=review,
            receipt=receipt,
            order=order,
        )
        verified_request = (
            TradeDisputeStatementFetchRequest.from_json(
                request.canonical_bytes,
                review=verified_review,
                receipt=verified_receipt,
                order=verified_order,
            )
            if isinstance(request, TradeDisputeStatementFetchRequest)
            else TradeDisputeStatementFetchRequest.from_dict(
                request,
                review=verified_review,
                receipt=verified_receipt,
                order=verified_order,
            )
        )
        verified = (
            TradeDisputeStatementFetchResponse.from_json(
                response.canonical_bytes,
                request=verified_request,
                review=verified_review,
                receipt=verified_receipt,
                order=verified_order,
            )
            if isinstance(response, TradeDisputeStatementFetchResponse)
            else TradeDisputeStatementFetchResponse.from_dict(
                response,
                request=verified_request,
                review=verified_review,
                receipt=verified_receipt,
                order=verified_order,
            )
        )
        _validate_response_observation(
            verified.to_dict(),
            verified_request,
            at=at,
            max_ttl_seconds=max_ttl_seconds,
            clock_skew_seconds=clock_skew_seconds,
        )
    except (
        TradeCanonicalJSONError,
        TradeDisputeStatementFetchRequestRejected,
        TradeDisputeStatementFetchResponseRejected,
        TradeDisputeStatementRejected,
        TradeExecutionReceiptRejected,
        TradeOrderRejected,
        TradeProofError,
        TradeReceiptReviewRejected,
        TypeError,
        ValueError,
        UnicodeError,
    ) as exc:
        return False, str(exc)
    return True, "ok"


__all__ = [
    "DEFAULT_DISPUTE_STATEMENT_FETCH_CLOCK_SKEW_SECONDS",
    "DEFAULT_MAX_DISPUTE_STATEMENT_FETCH_TTL_SECONDS",
    "DISPUTE_STATEMENT_FETCH_PROTOCOL_VERSION",
    "DISPUTE_STATEMENT_FETCH_PROOF_TYPE",
    "DISPUTE_STATEMENT_FETCH_REQUEST_KIND",
    "DISPUTE_STATEMENT_FETCH_REQUEST_PROOF_PURPOSE",
    "DISPUTE_STATEMENT_FETCH_REQUEST_SIGNING_DOMAIN",
    "DISPUTE_STATEMENT_FETCH_RESPONSE_KIND",
    "DISPUTE_STATEMENT_FETCH_RESPONSE_PROOF_PURPOSE",
    "DISPUTE_STATEMENT_FETCH_RESPONSE_SIGNING_DOMAIN",
    "MAX_DISPUTE_STATEMENT_FETCH_REQUEST_BYTES",
    "MAX_DISPUTE_STATEMENT_FETCH_RESPONSE_BYTES",
    "MAX_DISPUTE_STATEMENT_FETCH_SECONDS",
    "TradeDisputeStatementFetchRequest",
    "TradeDisputeStatementFetchRequestRejected",
    "TradeDisputeStatementFetchResponse",
    "TradeDisputeStatementFetchResponseRejected",
    "create_trade_dispute_statement_fetch_request",
    "create_trade_dispute_statement_fetch_response",
    "trade_dispute_statement_fetch_request_digest",
    "trade_dispute_statement_fetch_response_digest",
    "verify_trade_dispute_statement_fetch_request",
    "verify_trade_dispute_statement_fetch_response",
]
