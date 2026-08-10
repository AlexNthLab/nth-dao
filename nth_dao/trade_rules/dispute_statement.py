"""Signed, content-addressed statements for a disputed Trade Receipt Review."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
from itertools import islice
import math
import re
from typing import Any, Iterable

from nth_dao.did_key import is_did_key
from nth_dao.identity import AgentIdentity
from nth_dao.trade_rules.agreement import DEFAULT_CLOCK_SKEW_SECONDS
from nth_dao.trade_rules.agreement_order import TradeOrder, trade_order_digest
from nth_dao.trade_rules.canonical import (
    TradeCanonicalJSONError,
    parse_trade_json,
    trade_canonical_json,
)
from nth_dao.trade_rules.execution_receipt import (
    TradeExecutionReceipt,
    execution_receipt_digest,
)
from nth_dao.trade_rules.negotiation import RulePackageResolver
from nth_dao.trade_rules.package_store import RulePackage
from nth_dao.trade_rules.receipt_review import (
    RECEIPT_REVIEW_ID_PREFIX,
    TradeReceiptReview,
    receipt_review_digest,
)
from nth_dao.trade_rules.signing import (
    TradeProofError,
    encode_ed25519_signature,
    signed_document_input,
    verification_method_for_did,
    verify_ed25519_did_signature,
)

TRADE_DISPUTE_STATEMENT_KIND = "nth.dao.trade.dispute-statement"
TRADE_DISPUTE_STATEMENT_PROTOCOL_VERSION = "1"
TRADE_DISPUTE_STATEMENT_PROOF_TYPE = "Ed25519Signature2020"
TRADE_DISPUTE_STATEMENT_PROOF_PURPOSE = "tradeDisputeStatement"
TRADE_DISPUTE_STATEMENT_SIGNING_DOMAIN = b"nth-dao/trade-dispute-statement/v1"
TRADE_DISPUTE_ID_PREFIX = "nth-trade-dispute-sha256:"
TRADE_DISPUTE_STATEMENT_ID_PREFIX = "nth-trade-dispute-statement-sha256:"
TRADE_DISPUTE_STATEMENT_TYPES = frozenset(
    {"response", "evidence", "remedy-proposal"}
)
MAX_TRADE_DISPUTE_PARENTS = 64
MAX_TRADE_DISPUTE_REASON_CODES = 32
MAX_TRADE_DISPUTE_EVIDENCE = 32
MAX_TRADE_DISPUTE_STATEMENT_BYTES = 256 * 1024
MAX_TRADE_DISPUTE_CONTENT_BYTES = 16 * 1024 * 1024
MAX_TRADE_DISPUTE_TOTAL_EVIDENCE_BYTES = 64 * 1024 * 1024
MAX_TRADE_DISPUTE_CLOCK_SKEW_SECONDS = 86_400

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_DISPUTE_ID = re.compile(
    rf"^{re.escape(TRADE_DISPUTE_ID_PREFIX)}[0-9a-f]{{64}}$"
)
_REVIEW_ID = re.compile(
    rf"^{re.escape(RECEIPT_REVIEW_ID_PREFIX)}[0-9a-f]{{64}}$"
)
_STATEMENT_ID = re.compile(
    rf"^{re.escape(TRADE_DISPUTE_STATEMENT_ID_PREFIX)}[0-9a-f]{{64}}$"
)
_REASON = re.compile(r"^[a-z][a-z0-9._:-]{0,127}$")
_TOKEN = re.compile(r"^[a-z][a-z0-9._:/-]{0,127}$")
_HOOK_NAME = re.compile(r"^[a-z0-9][a-z0-9._:/-]{0,127}$")
_HOOK_VERSION = re.compile(r"^[a-z0-9][a-z0-9._:/-]{0,31}$")
_MEDIA_TYPE = re.compile(r"^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$")
_RULE_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_RULE_ID = re.compile(
    rf"^{_RULE_LABEL}(?:\.{_RULE_LABEL})+"
    r"(?:/[a-z0-9](?:[a-z0-9._-]{0,30}[a-z0-9])?)?$"
)
_TIMESTAMP = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{6}))?Z$"
)
_FIELDS = frozenset(
    {
        "kind",
        "protocol_version",
        "statement_id",
        "dispute_id",
        "order_digest",
        "receipt_digest",
        "review_digest",
        "review_id",
        "author_did",
        "author_role",
        "statement_type",
        "parent_statement_digests",
        "reason_codes",
        "claim",
        "evidence",
        "rule_action",
        "created_at",
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
_EVIDENCE_FIELDS = frozenset({"purpose", "media_type", "digest", "size"})
_CLAIM_FIELDS = frozenset(
    {"claim_type", "media_type", "digest", "size", "schema_digest"}
)
_RULE_ACTION_FIELDS = frozenset(
    {"rule_id", "digest", "hook", "hook_version"}
)
_PARTY_ROLES = frozenset({"maker", "taker"})


class TradeDisputeStatementRejected(ValueError):
    """A dispute statement is malformed, unsigned, or outside its Order."""


def _reject(message: str) -> None:
    raise TradeDisputeStatementRejected(message)


def _exact_fields(
    value: Any,
    expected: frozenset[str],
    *,
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        _reject(f"{label} has missing or unknown fields")
    return value


def _digest(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        _reject(f"{label} must be a lowercase sha256 digest")
    return value


def _review_id(value: Any) -> str:
    if not isinstance(value, str) or _REVIEW_ID.fullmatch(value) is None:
        _reject("review_id is invalid")
    return value


def _bounded_values(
    values: Iterable[Any],
    *,
    limit: int,
    label: str,
) -> list[Any]:
    if isinstance(values, (str, bytes, bytearray, dict)):
        _reject(f"{label} must be a collection, not a scalar or mapping")
    try:
        bounded = list(islice(iter(values), limit + 1))
    except TypeError as exc:
        raise TradeDisputeStatementRejected(
            f"{label} must be an iterable"
        ) from exc
    if len(bounded) > limit:
        _reject(f"{label} exceeds its item limit")
    return copy.deepcopy(bounded)


def _timestamp(value: Any, *, label: str) -> datetime:
    if not isinstance(value, str) or len(value) > 35:
        _reject(f"{label} must be a canonical UTC RFC3339 timestamp")
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
        raise TradeDisputeStatementRejected(
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


def _clock_skew(value: Any) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
        or value > MAX_TRADE_DISPUTE_CLOCK_SKEW_SECONDS
    ):
        _reject("clock_skew_seconds must be finite and between 0 and 86400")
    return float(value)


def trade_dispute_id(review_id: str) -> str:
    """Derive one stable dispute case identity from a semantic Review ID."""

    binding = {"review_id": _review_id(review_id)}
    return TRADE_DISPUTE_ID_PREFIX + hashlib.sha256(
        trade_canonical_json(binding)
    ).hexdigest()


def _statement_binding(document: dict[str, Any]) -> dict[str, Any]:
    return {
        key: copy.deepcopy(value)
        for key, value in document.items()
        if key not in {"statement_id", "proof"}
    }


def _expected_statement_id(document: dict[str, Any]) -> str:
    return TRADE_DISPUTE_STATEMENT_ID_PREFIX + hashlib.sha256(
        trade_canonical_json(_statement_binding(document))
    ).hexdigest()


def _evidence_binding(
    raw: Any,
    *,
    index: int,
) -> tuple[str, str, str, int]:
    item = _exact_fields(
        raw,
        _EVIDENCE_FIELDS,
        label=f"evidence[{index}]",
    )
    purpose = item["purpose"]
    media_type = item["media_type"]
    if not isinstance(purpose, str) or _TOKEN.fullmatch(purpose) is None:
        _reject(f"evidence[{index}].purpose is invalid")
    if (
        not isinstance(media_type, str)
        or len(media_type) > 127
        or _MEDIA_TYPE.fullmatch(media_type) is None
    ):
        _reject(f"evidence[{index}].media_type is invalid")
    digest = _digest(item["digest"], label=f"evidence[{index}].digest")
    size = item["size"]
    if (
        isinstance(size, bool)
        or not isinstance(size, int)
        or size < 0
        or size > MAX_TRADE_DISPUTE_CONTENT_BYTES
    ):
        _reject(f"evidence[{index}].size is invalid")
    return purpose, digest, media_type, size


def _validate_evidence(value: Any) -> list[tuple[str, str, str, int]]:
    if not isinstance(value, list) or len(value) > MAX_TRADE_DISPUTE_EVIDENCE:
        _reject("evidence must be a bounded list")
    bindings = [
        _evidence_binding(raw, index=index)
        for index, raw in enumerate(value)
    ]
    if bindings != sorted(set(bindings)):
        _reject("evidence must be sorted and contain no duplicate entries")
    metadata_by_digest: dict[str, tuple[str, int]] = {}
    total_size = 0
    for _purpose, digest, media_type, size in bindings:
        total_size += size
        if total_size > MAX_TRADE_DISPUTE_TOTAL_EVIDENCE_BYTES:
            _reject("declared dispute evidence exceeds its total byte limit")
        metadata = (media_type, size)
        existing = metadata_by_digest.setdefault(digest, metadata)
        if existing != metadata:
            _reject("one evidence digest cannot declare conflicting metadata")
    return bindings


def _validate_claim(value: Any, *, statement_type: str) -> tuple[str, str, int] | None:
    if value is None:
        if statement_type != "evidence":
            _reject("response and remedy statements require a typed claim")
        return None
    if statement_type == "evidence":
        _reject("evidence statements cannot contain a claim")
    item = _exact_fields(value, _CLAIM_FIELDS, label="claim")
    claim_type = item["claim_type"]
    media_type = item["media_type"]
    if not isinstance(claim_type, str) or _TOKEN.fullmatch(claim_type) is None:
        _reject("claim.claim_type is invalid")
    if (
        not isinstance(media_type, str)
        or len(media_type) > 127
        or _MEDIA_TYPE.fullmatch(media_type) is None
    ):
        _reject("claim.media_type is invalid")
    digest = _digest(item["digest"], label="claim.digest")
    size = item["size"]
    if (
        isinstance(size, bool)
        or not isinstance(size, int)
        or size < 0
        or size > MAX_TRADE_DISPUTE_CONTENT_BYTES
    ):
        _reject("claim.size is invalid")
    schema_digest = item["schema_digest"]
    if schema_digest is not None:
        _digest(schema_digest, label="claim.schema_digest")
    return digest, media_type, size


def _validate_rule_action(value: Any) -> None:
    if value is None:
        return
    item = _exact_fields(value, _RULE_ACTION_FIELDS, label="rule_action")
    if not isinstance(item["rule_id"], str) or _RULE_ID.fullmatch(
        item["rule_id"]
    ) is None:
        _reject("rule_action.rule_id is invalid")
    _digest(item["digest"], label="rule_action.digest")
    if (
        not isinstance(item["hook"], str)
        or _HOOK_NAME.fullmatch(item["hook"]) is None
    ):
        _reject("rule_action.hook is invalid")
    if (
        not isinstance(item["hook_version"], str)
        or _HOOK_VERSION.fullmatch(item["hook_version"]) is None
    ):
        _reject("rule_action.hook_version is invalid")


def _assert_rule_action_resolves(
    rule_action: dict[str, Any],
    *,
    package_resolver: RulePackageResolver,
) -> None:
    load = getattr(package_resolver, "load", None)
    if not callable(load):
        _reject("rule_action package_resolver must provide load(digest)")
    try:
        package = load(rule_action["digest"])
    except Exception as exc:
        # Resolvers may be local stores, federation adapters, or plugins. Keep
        # their operational failures behind this protocol validation boundary.
        raise TradeDisputeStatementRejected(
            "rule_action package resolution failed"
        ) from exc
    if package is None:
        _reject("rule_action package is unavailable")
    if not isinstance(package, RulePackage):
        _reject("rule_action resolver did not return a verified RulePackage")
    if package.digest != rule_action["digest"]:
        _reject("rule_action package digest mismatch")
    manifest = package.manifest.to_dict()
    if manifest["rule_id"] != rule_action["rule_id"]:
        _reject("rule_action rule_id does not match the resolved package")
    expected_hook = (rule_action["hook"], rule_action["hook_version"])
    available_hooks = {
        (item["name"], item["version"])
        for item in manifest["hook_contracts"]
    }
    if expected_hook not in available_hooks:
        _reject("rule_action hook name/version is absent from the package")


def _validate(document: dict[str, Any]) -> None:
    _exact_fields(document, _FIELDS, label="trade dispute statement")
    if document["kind"] != TRADE_DISPUTE_STATEMENT_KIND:
        _reject("wrong trade dispute statement kind")
    if document["protocol_version"] != TRADE_DISPUTE_STATEMENT_PROTOCOL_VERSION:
        _reject("unsupported trade dispute statement protocol_version")
    if (
        not isinstance(document["statement_id"], str)
        or _STATEMENT_ID.fullmatch(document["statement_id"]) is None
    ):
        _reject("statement_id is invalid")
    if (
        not isinstance(document["dispute_id"], str)
        or _DISPUTE_ID.fullmatch(document["dispute_id"]) is None
    ):
        _reject("dispute_id is invalid")
    for field in ("order_digest", "receipt_digest", "review_digest"):
        _digest(document[field], label=field)
    _review_id(document["review_id"])
    author = document["author_did"]
    if not isinstance(author, str) or not is_did_key(author):
        _reject("author_did must be an Ed25519 did:key")
    if document["author_role"] not in _PARTY_ROLES:
        _reject("author_role is invalid")
    statement_type = document["statement_type"]
    if statement_type not in TRADE_DISPUTE_STATEMENT_TYPES:
        _reject("statement_type is invalid")
    parents = document["parent_statement_digests"]
    if (
        not isinstance(parents, list)
        or len(parents) > MAX_TRADE_DISPUTE_PARENTS
        or any(_DIGEST.fullmatch(item) is None for item in parents if isinstance(item, str))
        or any(not isinstance(item, str) for item in parents)
        or parents != sorted(set(parents))
    ):
        _reject("parent_statement_digests must be bounded, sorted, and unique")
    reasons = document["reason_codes"]
    if (
        not isinstance(reasons, list)
        or len(reasons) > MAX_TRADE_DISPUTE_REASON_CODES
        or any(
            not isinstance(item, str) or _REASON.fullmatch(item) is None
            for item in reasons
        )
        or reasons != sorted(set(reasons))
    ):
        _reject("reason_codes must be bounded, sorted, and unique")
    claim_binding = _validate_claim(
        document["claim"],
        statement_type=statement_type,
    )
    evidence_bindings = _validate_evidence(document["evidence"])
    if statement_type == "evidence" and not document["evidence"]:
        _reject("evidence statements require at least one evidence reference")
    if statement_type != "evidence" and not reasons:
        _reject("response and remedy statements require a reason code")
    if claim_binding is not None:
        claim_digest, claim_media_type, claim_size = claim_binding
        for _purpose, digest, media_type, size in evidence_bindings:
            if digest == claim_digest and (
                media_type != claim_media_type or size != claim_size
            ):
                _reject("claim and evidence metadata conflict for one digest")
    _validate_rule_action(document["rule_action"])
    created_at = document["created_at"]
    _timestamp(created_at, label="created_at")
    proof = _exact_fields(document["proof"], _PROOF_FIELDS, label="proof")
    if proof["type"] != TRADE_DISPUTE_STATEMENT_PROOF_TYPE:
        _reject("proof.type is invalid")
    if proof["created"] != created_at:
        _reject("proof.created must equal created_at")
    if proof["verification_method"] != verification_method_for_did(author):
        _reject("proof.verification_method does not match author_did")
    if proof["proof_purpose"] != TRADE_DISPUTE_STATEMENT_PROOF_PURPOSE:
        _reject("proof.proof_purpose is invalid")
    if not isinstance(proof["proof_value"], str):
        _reject("proof.proof_value is invalid")
    if document["statement_id"] != _expected_statement_id(document):
        _reject("statement_id does not match the statement binding")


def _verify_signature(document: dict[str, Any]) -> None:
    try:
        signing_input = signed_document_input(
            TRADE_DISPUTE_STATEMENT_SIGNING_DOMAIN,
            document,
        )
    except TradeProofError as exc:
        raise TradeDisputeStatementRejected(str(exc)) from exc
    ok, reason = verify_ed25519_did_signature(
        publisher_did=document["author_did"],
        proof_value=document["proof"]["proof_value"],
        signing_input=signing_input,
    )
    if not ok:
        _reject(reason)


def _verified_artifacts(
    review: TradeReceiptReview | dict[str, Any],
    *,
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
) -> tuple[TradeReceiptReview, TradeExecutionReceipt, TradeOrder]:
    verified_order = (
        TradeOrder.from_json(order.canonical_bytes)
        if isinstance(order, TradeOrder)
        else TradeOrder.from_dict(order)
    )
    verified_receipt = (
        TradeExecutionReceipt.from_json(
            receipt.canonical_bytes,
            order=verified_order,
        )
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


def _assert_document_binding(
    document: dict[str, Any],
    *,
    review: TradeReceiptReview | dict[str, Any],
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
    package_resolver: RulePackageResolver | None = None,
) -> None:
    verified_review, verified_receipt, verified_order = _verified_artifacts(
        review,
        receipt=receipt,
        order=order,
    )
    review_document = verified_review.to_dict()
    receipt_document = verified_receipt.to_dict()
    order_document = verified_order.to_dict()
    expected_review_digest = receipt_review_digest(
        verified_review,
        receipt=verified_receipt,
        order=verified_order,
    )
    expected = {
        "dispute_id": trade_dispute_id(review_document["review_id"]),
        "order_digest": trade_order_digest(verified_order),
        "receipt_digest": execution_receipt_digest(verified_receipt),
        "review_digest": expected_review_digest,
        "review_id": review_document["review_id"],
    }
    for field, value in expected.items():
        if document[field] != value:
            _reject(f"trade dispute statement {field} binding mismatch")
    if review_document["decision"] != "disputed":
        _reject("trade dispute statements require a disputed Receipt Review")
    role = document["author_role"]
    if document["author_did"] != order_document[f"{role}_did"]:
        _reject("author_did does not match author_role in the signed Order")
    executor_role = receipt_document["executor_role"]
    if document["statement_type"] == "response" and role != executor_role:
        _reject("a response must be signed by the Receipt executor")
    rule_action = document["rule_action"]
    if rule_action is not None:
        signed_bindings = {
            (item["rule_id"], item["digest"])
            for item in order_document["rule_bindings"]
        }
        if (rule_action["rule_id"], rule_action["digest"]) not in signed_bindings:
            _reject("rule_action is outside the signed Order rule bindings")
        if package_resolver is not None:
            _assert_rule_action_resolves(
                rule_action,
                package_resolver=package_resolver,
            )
    if _timestamp(document["created_at"], label="created_at") < _timestamp(
        review_document["reviewed_at"],
        label="review.reviewed_at",
    ):
        _reject("trade dispute statement predates the disputed Review")


def _validated_canonical_statement(
    document: dict[str, Any],
    *,
    review: TradeReceiptReview | dict[str, Any],
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
    package_resolver: RulePackageResolver | None,
    require_rule_resolution: bool,
) -> bytes:
    canonical = trade_canonical_json(copy.deepcopy(document))
    if len(canonical) > MAX_TRADE_DISPUTE_STATEMENT_BYTES:
        _reject("trade dispute statement exceeds its byte limit")
    snapshot = parse_trade_json(canonical)
    _validate(snapshot)
    _verify_signature(snapshot)
    if (
        require_rule_resolution
        and snapshot["rule_action"] is not None
        and package_resolver is None
    ):
        _reject("rule_action requires an exact-digest package_resolver")
    _assert_document_binding(
        snapshot,
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=package_resolver,
    )
    return canonical


@dataclass(frozen=True, init=False)
class TradeDisputeStatement:
    """Fully verified party statement within a disputed Review case."""

    _canonical_bytes: bytes

    @classmethod
    def _create(cls, canonical: bytes) -> "TradeDisputeStatement":
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
        package_resolver: RulePackageResolver | None = None,
    ) -> "TradeDisputeStatement":
        try:
            canonical = _validated_canonical_statement(
                document,
                review=review,
                receipt=receipt,
                order=order,
                package_resolver=package_resolver,
                require_rule_resolution=True,
            )
            return cls._create(canonical)
        except (
            TradeCanonicalJSONError,
            TradeProofError,
            TypeError,
            ValueError,
            UnicodeError,
        ) as exc:
            if isinstance(exc, TradeDisputeStatementRejected):
                raise
            raise TradeDisputeStatementRejected(str(exc)) from exc

    @classmethod
    def from_json(
        cls,
        raw: bytes | str,
        *,
        review: TradeReceiptReview | dict[str, Any],
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
        package_resolver: RulePackageResolver | None = None,
    ) -> "TradeDisputeStatement":
        try:
            return cls.from_dict(
                parse_trade_json(raw),
                review=review,
                receipt=receipt,
                order=order,
                package_resolver=package_resolver,
            )
        except TradeCanonicalJSONError as exc:
            raise TradeDisputeStatementRejected(str(exc)) from exc

    @property
    def canonical_bytes(self) -> bytes:
        return self._canonical_bytes

    @property
    def statement_id(self) -> str:
        return self.to_dict()["statement_id"]

    @property
    def dispute_id(self) -> str:
        return self.to_dict()["dispute_id"]

    def to_dict(self) -> dict[str, Any]:
        return parse_trade_json(self._canonical_bytes)

    def assert_observed_at(
        self,
        *,
        at: datetime | None = None,
        clock_skew_seconds: float = DEFAULT_CLOCK_SKEW_SECONDS,
    ) -> None:
        """Reject a verified statement observed implausibly before creation."""

        observed = _utc_now(at)
        created = _timestamp(
            self.to_dict()["created_at"],
            label="created_at",
        )
        if created > observed + timedelta(
            seconds=_clock_skew(clock_skew_seconds)
        ):
            _reject("trade dispute statement is too far in the future")


@dataclass(frozen=True, init=False)
class UnresolvedTradeDisputeStatement:
    """Verified signed transport statement with unresolved Rule dependencies."""

    _canonical_bytes: bytes

    @classmethod
    def _create(cls, canonical: bytes) -> "UnresolvedTradeDisputeStatement":
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
    ) -> "UnresolvedTradeDisputeStatement":
        try:
            canonical = _validated_canonical_statement(
                document,
                review=review,
                receipt=receipt,
                order=order,
                package_resolver=None,
                require_rule_resolution=False,
            )
            return cls._create(canonical)
        except (
            TradeCanonicalJSONError,
            TradeProofError,
            TypeError,
            ValueError,
            UnicodeError,
        ) as exc:
            if isinstance(exc, TradeDisputeStatementRejected):
                raise
            raise TradeDisputeStatementRejected(str(exc)) from exc

    @classmethod
    def from_json(
        cls,
        raw: bytes | str,
        *,
        review: TradeReceiptReview | dict[str, Any],
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
    ) -> "UnresolvedTradeDisputeStatement":
        try:
            return cls.from_dict(
                parse_trade_json(raw),
                review=review,
                receipt=receipt,
                order=order,
            )
        except TradeCanonicalJSONError as exc:
            raise TradeDisputeStatementRejected(str(exc)) from exc

    @property
    def canonical_bytes(self) -> bytes:
        return self._canonical_bytes

    @property
    def statement_id(self) -> str:
        return self.to_dict()["statement_id"]

    @property
    def dispute_id(self) -> str:
        return self.to_dict()["dispute_id"]

    def to_dict(self) -> dict[str, Any]:
        return parse_trade_json(self._canonical_bytes)

    def resolve(
        self,
        *,
        review: TradeReceiptReview | dict[str, Any],
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
        package_resolver: RulePackageResolver,
    ) -> TradeDisputeStatement:
        """Resolve exact Rule dependencies into a fully verified statement."""

        return TradeDisputeStatement.from_json(
            self.canonical_bytes,
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=package_resolver,
        )


def create_trade_dispute_statement(
    identity: AgentIdentity,
    *,
    review: TradeReceiptReview | dict[str, Any],
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
    statement_type: str,
    parent_statement_digests: Iterable[str] = (),
    reason_codes: Iterable[str] = (),
    claim: dict[str, Any] | None = None,
    evidence: Iterable[dict[str, Any]] = (),
    rule_action: dict[str, Any] | None = None,
    package_resolver: RulePackageResolver | None = None,
    created_at: str,
    now: datetime | None = None,
    clock_skew_seconds: float = DEFAULT_CLOCK_SKEW_SECONDS,
) -> TradeDisputeStatement:
    """Sign a non-executing party statement for one disputed Review."""

    if not isinstance(identity, AgentIdentity):
        raise TypeError("identity must be an AgentIdentity")
    verified_review, verified_receipt, verified_order = _verified_artifacts(
        review,
        receipt=receipt,
        order=order,
    )
    review_digest = receipt_review_digest(
        verified_review,
        receipt=verified_receipt,
        order=verified_order,
    )
    review_id = verified_review.to_dict()["review_id"]
    order_document = verified_order.to_dict()
    author_did = identity.as_did()
    author_role = next(
        (
            role
            for role in ("maker", "taker")
            if order_document[f"{role}_did"] == author_did
        ),
        "",
    )
    if not author_role:
        _reject("trade dispute statement author is not an Order party")
    parent_values = _bounded_values(
        parent_statement_digests,
        limit=MAX_TRADE_DISPUTE_PARENTS,
        label="parent_statement_digests",
    )
    for index, parent in enumerate(parent_values):
        _digest(parent, label=f"parent_statement_digests[{index}]")
    parent_values.sort()
    reason_values = _bounded_values(
        reason_codes,
        limit=MAX_TRADE_DISPUTE_REASON_CODES,
        label="reason_codes",
    )
    for index, reason in enumerate(reason_values):
        if not isinstance(reason, str) or _REASON.fullmatch(reason) is None:
            _reject(f"reason_codes[{index}] is invalid")
    reason_values.sort()
    unsorted_evidence = _bounded_values(
        evidence,
        limit=MAX_TRADE_DISPUTE_EVIDENCE,
        label="evidence",
    )
    evidence_with_bindings = [
        (_evidence_binding(item, index=index), item)
        for index, item in enumerate(unsorted_evidence)
    ]
    if len({binding for binding, _item in evidence_with_bindings}) != len(
        evidence_with_bindings
    ):
        _reject("evidence must contain no duplicate entries")
    evidence_values = [
        item
        for _binding, item in sorted(
            evidence_with_bindings,
            key=lambda entry: entry[0],
        )
    ]
    document = {
        "kind": TRADE_DISPUTE_STATEMENT_KIND,
        "protocol_version": TRADE_DISPUTE_STATEMENT_PROTOCOL_VERSION,
        "statement_id": TRADE_DISPUTE_STATEMENT_ID_PREFIX + ("0" * 64),
        "dispute_id": trade_dispute_id(review_id),
        "order_digest": trade_order_digest(verified_order),
        "receipt_digest": execution_receipt_digest(verified_receipt),
        "review_digest": review_digest,
        "review_id": review_id,
        "author_did": author_did,
        "author_role": author_role,
        "statement_type": statement_type,
        "parent_statement_digests": parent_values,
        "reason_codes": reason_values,
        "claim": copy.deepcopy(claim),
        "evidence": evidence_values,
        "rule_action": copy.deepcopy(rule_action),
        "created_at": created_at,
        "proof": {
            "type": TRADE_DISPUTE_STATEMENT_PROOF_TYPE,
            "created": created_at,
            "verification_method": verification_method_for_did(author_did),
            "proof_purpose": TRADE_DISPUTE_STATEMENT_PROOF_PURPOSE,
            "proof_value": "A" * 86,
        },
    }
    document["statement_id"] = _expected_statement_id(document)
    _validate(document)
    if document["rule_action"] is not None and package_resolver is None:
        _reject("rule_action requires an exact-digest package_resolver")
    _assert_document_binding(
        document,
        review=verified_review,
        receipt=verified_receipt,
        order=verified_order,
        package_resolver=package_resolver,
    )
    statement_time = _timestamp(created_at, label="created_at")
    if statement_time > _utc_now(now) + timedelta(
        seconds=_clock_skew(clock_skew_seconds)
    ):
        _reject("trade dispute statement is too far in the future")
    signing_input = signed_document_input(
        TRADE_DISPUTE_STATEMENT_SIGNING_DOMAIN,
        document,
    )
    document["proof"]["proof_value"] = encode_ed25519_signature(
        identity.sign(signing_input)
    )
    canonical = trade_canonical_json(document)
    snapshot = parse_trade_json(canonical)
    _validate(snapshot)
    _verify_signature(snapshot)
    return TradeDisputeStatement._create(canonical)


def verify_trade_dispute_statement(
    statement: TradeDisputeStatement | dict[str, Any],
    *,
    review: TradeReceiptReview | dict[str, Any],
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
    package_resolver: RulePackageResolver | None = None,
    at: datetime | None = None,
    clock_skew_seconds: float = DEFAULT_CLOCK_SKEW_SECONDS,
) -> tuple[bool, str]:
    """Verify signature, party bindings, and explicit or local observation time."""

    try:
        verified = (
            TradeDisputeStatement.from_json(
                statement.canonical_bytes,
                review=review,
                receipt=receipt,
                order=order,
                package_resolver=package_resolver,
            )
            if isinstance(statement, TradeDisputeStatement)
            else TradeDisputeStatement.from_dict(
                statement,
                review=review,
                receipt=receipt,
                order=order,
                package_resolver=package_resolver,
            )
        )
        verified.assert_observed_at(
            at=at,
            clock_skew_seconds=clock_skew_seconds,
        )
    except (
        TradeDisputeStatementRejected,
        TradeCanonicalJSONError,
        TradeProofError,
        TypeError,
        ValueError,
        UnicodeError,
    ) as exc:
        return False, str(exc)
    return True, "ok"


def trade_dispute_statement_digest(
    statement: (
        TradeDisputeStatement
        | UnresolvedTradeDisputeStatement
        | dict[str, Any]
    ),
    *,
    review: TradeReceiptReview | dict[str, Any],
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
    package_resolver: RulePackageResolver | None = None,
) -> str:
    if isinstance(
        statement,
        (TradeDisputeStatement, UnresolvedTradeDisputeStatement),
    ):
        canonical = statement.canonical_bytes
    else:
        canonical = TradeDisputeStatement.from_dict(
            statement,
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=package_resolver,
        ).canonical_bytes
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


__all__ = [
    "MAX_TRADE_DISPUTE_EVIDENCE",
    "MAX_TRADE_DISPUTE_CONTENT_BYTES",
    "MAX_TRADE_DISPUTE_CLOCK_SKEW_SECONDS",
    "MAX_TRADE_DISPUTE_PARENTS",
    "MAX_TRADE_DISPUTE_REASON_CODES",
    "MAX_TRADE_DISPUTE_STATEMENT_BYTES",
    "MAX_TRADE_DISPUTE_TOTAL_EVIDENCE_BYTES",
    "TRADE_DISPUTE_ID_PREFIX",
    "TRADE_DISPUTE_STATEMENT_ID_PREFIX",
    "TRADE_DISPUTE_STATEMENT_KIND",
    "TRADE_DISPUTE_STATEMENT_PROTOCOL_VERSION",
    "TRADE_DISPUTE_STATEMENT_TYPES",
    "TradeDisputeStatement",
    "TradeDisputeStatementRejected",
    "UnresolvedTradeDisputeStatement",
    "create_trade_dispute_statement",
    "trade_dispute_id",
    "trade_dispute_statement_digest",
    "verify_trade_dispute_statement",
]
