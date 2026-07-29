"""Signed bilateral agreement statements for Trade Offer v2."""

from __future__ import annotations

import copy
import hashlib
import math
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from nth_dao.did_key import is_did_key
from nth_dao.trade_rules.canonical import (
    TradeCanonicalJSONError,
    parse_trade_json,
    trade_canonical_json,
)
from nth_dao.trade_rules.negotiation import (
    CanonicalOfferResolver,
    CanonicalRuleResolution,
    RuleNegotiationError,
    RuleResolutionPolicy,
    resolve_offer_rules,
)
from nth_dao.trade_rules.offer import (
    TradeOffer,
    offer_digest,
)
from nth_dao.trade_rules.package_store import build_rule_package
from nth_dao.trade_rules.signing import (
    TradeProofError,
    encode_ed25519_signature,
    signed_document_input,
    verification_method_for_did,
    verify_ed25519_did_signature,
)

PROPOSAL_KIND = "nth.dao.trade.proposal"
PROPOSAL_PROTOCOL_VERSION = "1"
PROPOSAL_PROOF_PURPOSE = "tradeProposal"
ACCEPTANCE_KIND = "nth.dao.trade.acceptance"
ACCEPTANCE_PROTOCOL_VERSION = "1"
ACCEPTANCE_PROOF_PURPOSE = "tradeAcceptance"
AGREEMENT_PROOF_TYPE = "Ed25519Signature2020"
DEFAULT_MAX_PROPOSAL_TTL_SECONDS = 7 * 24 * 60 * 60
DEFAULT_CLOCK_SKEW_SECONDS = 5 * 60

_PROPOSAL_DOMAIN = b"nth-dao/trade-proposal/v1"
_ACCEPTANCE_DOMAIN = b"nth-dao/trade-acceptance/v1"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_OFFER_ID = re.compile(
    rf"^{_LABEL}(?:\.{_LABEL})+"
    r"(?:/[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?)?$"
)
_RULE_ID = re.compile(
    rf"^{_LABEL}(?:\.{_LABEL})+"
    r"(?:/[a-z0-9](?:[a-z0-9._-]{0,30}[a-z0-9])?)?$"
)
_TIMESTAMP = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?:\.(\d{1,9}))?Z$"
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
_PROPOSAL_FIELDS = frozenset(
    {
        "kind",
        "protocol_version",
        "offer_publisher_did",
        "offer_id",
        "offer_revision",
        "offer_digest",
        "canonical_chain_digests",
        "maker_did",
        "taker_did",
        "rule_bindings",
        "taker_policy_digest",
        "taker_policy",
        "terms",
        "created_at",
        "not_after",
        "proof",
    }
)
_ACCEPTANCE_FIELDS = frozenset(
    {
        "kind",
        "protocol_version",
        "proposal_digest",
        "offer_digest",
        "maker_did",
        "taker_did",
        "rule_bindings",
        "maker_policy_digest",
        "maker_policy",
        "created_at",
        "proof",
    }
)
_RULE_BINDING_FIELDS = frozenset({"rule_id", "digest"})
_POLICY_FIELDS = frozenset(
    {
        "kind",
        "protocol_version",
        "accepted_publishers",
        "accepted_package_digests",
        "available_capabilities",
        "allowed_permissions",
        "allowed_execution_modes",
        "approved_executable_digests",
        "max_depth",
        "max_packages",
        "max_resource_bytes",
    }
)
_MAX_TERMS_BYTES = 64 * 1024


class _VerifiedPackageResolver:
    def __init__(self, packages: dict[str, Any]) -> None:
        self._packages = dict(packages)

    def load(self, digest: str):
        return self._packages.get(digest)


class TradeAgreementRejected(ValueError):
    """A proposal or acceptance is malformed, unbound, or unsigned."""


def _reject(message: str) -> None:
    raise TradeAgreementRejected(message)


def _exact_fields(
    value: Any,
    expected: frozenset[str],
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        _reject(f"{label} has missing or unknown fields")
    return value


def _timestamp(value: Any, *, label: str) -> tuple[datetime, int]:
    if not isinstance(value, str) or len(value) > 35:
        _reject(f"{label} must be a UTC RFC3339 timestamp")
    match = _TIMESTAMP.fullmatch(value)
    if match is None:
        _reject(f"{label} must be a UTC RFC3339 timestamp")
    try:
        base = datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise TradeAgreementRejected(f"{label} is not a real timestamp") from exc
    nanos = int((match.group(2) or "").ljust(9, "0") or "0")
    return base, nanos


def _utc_now(value: datetime | None) -> datetime:
    moment = value or datetime.now(timezone.utc)
    if (
        not isinstance(moment, datetime)
        or moment.tzinfo is None
        or moment.utcoffset() is None
    ):
        raise TradeAgreementRejected("now must be timezone-aware")
    return moment.astimezone(timezone.utc)


def _duration_seconds(value: Any, *, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
    ):
        _reject(f"{label} must be a finite non-negative number")
    return float(value)


def _assert_local_signing_time(
    created_at: str,
    *,
    now: datetime | None,
    clock_skew_seconds: float,
) -> None:
    skew = _duration_seconds(
        clock_skew_seconds,
        label="clock_skew_seconds",
    )
    created, nanos = _timestamp(created_at, label="created_at")
    created_moment = created + timedelta(microseconds=nanos // 1_000)
    drift = abs((_utc_now(now) - created_moment).total_seconds())
    if drift > skew:
        _reject("created_at exceeds the local signing clock-skew limit")


def _assert_proposal_ttl(
    created_at: str,
    not_after: str,
    *,
    max_ttl_seconds: float,
) -> None:
    limit = _duration_seconds(
        max_ttl_seconds,
        label="max_ttl_seconds",
    )
    created, created_nanos = _timestamp(created_at, label="created_at")
    expiry, expiry_nanos = _timestamp(not_after, label="not_after")
    seconds = (expiry - created).total_seconds()
    seconds += (expiry_nanos - created_nanos) / 1_000_000_000
    if seconds > limit:
        _reject("proposal lifetime exceeds max_ttl_seconds")


def _digest(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        _reject(f"{label} must be a lowercase sha256 digest")
    return value


def _did(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not is_did_key(value):
        _reject(f"{label} must be an Ed25519 did:key")
    return value


def _policy_snapshot(
    value: Any,
    *,
    label: str,
) -> RuleResolutionPolicy:
    document = _exact_fields(value, _POLICY_FIELDS, label)
    try:
        policy = RuleResolutionPolicy.from_dict(document)
    except (TradeCanonicalJSONError, TypeError, ValueError) as exc:
        raise TradeAgreementRejected(
            f"{label} is invalid: {exc}"
        ) from exc
    return policy


def _rule_bindings(value: Any) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, list) or len(value) > 256:
        _reject("rule_bindings must be a list with at most 256 entries")
    output: list[tuple[str, str]] = []
    for index, raw in enumerate(value):
        item = _exact_fields(
            raw,
            _RULE_BINDING_FIELDS,
            f"rule_bindings[{index}]",
        )
        rule_id = item["rule_id"]
        if not isinstance(rule_id, str) or _RULE_ID.fullmatch(rule_id) is None:
            _reject(f"rule_bindings[{index}].rule_id is invalid")
        output.append(
            (rule_id, _digest(item["digest"], label="rule binding digest"))
        )
    if len(set(output)) != len(output):
        _reject("rule_bindings contains duplicate entries")
    rule_ids = [rule_id for rule_id, _digest_value in output]
    if len(set(rule_ids)) != len(rule_ids):
        _reject("rule_bindings binds one rule_id to multiple digests")
    if output != sorted(output):
        _reject("rule_bindings must be sorted by rule_id and digest")
    return tuple(output)


def _proof(
    value: Any,
    *,
    signer_did: str,
    purpose: str,
) -> dict[str, Any]:
    proof = _exact_fields(value, _PROOF_FIELDS, "proof")
    if proof["type"] != AGREEMENT_PROOF_TYPE:
        _reject("proof type is invalid")
    _timestamp(proof["created"], label="proof.created")
    if proof["verification_method"] != verification_method_for_did(signer_did):
        _reject("proof verification_method does not match signer")
    if proof["proof_purpose"] != purpose:
        _reject("proof purpose is invalid")
    if not isinstance(proof["proof_value"], str):
        _reject("proof value is invalid")
    return proof


def _validate_proposal(document: dict[str, Any]) -> None:
    _exact_fields(document, _PROPOSAL_FIELDS, "proposal")
    if document["kind"] != PROPOSAL_KIND:
        _reject("wrong proposal kind")
    if document["protocol_version"] != PROPOSAL_PROTOCOL_VERSION:
        _reject("unsupported proposal protocol_version")
    publisher = _did(
        document["offer_publisher_did"],
        label="offer_publisher_did",
    )
    maker = _did(document["maker_did"], label="maker_did")
    taker = _did(document["taker_did"], label="taker_did")
    if maker != publisher:
        _reject("maker_did must equal the Offer publisher")
    if maker == taker:
        _reject("maker and taker must be different principals")
    offer_id = document["offer_id"]
    if not isinstance(offer_id, str) or _OFFER_ID.fullmatch(offer_id) is None:
        _reject("offer_id is invalid")
    revision = document["offer_revision"]
    if (
        isinstance(revision, bool)
        or not isinstance(revision, int)
        or not 1 <= revision <= 1_000_000
    ):
        _reject("offer_revision is invalid")
    head = _digest(document["offer_digest"], label="offer_digest")
    chain = document["canonical_chain_digests"]
    if (
        not isinstance(chain, list)
        or len(chain) != revision
        or any(
            not isinstance(item, str) or _DIGEST.fullmatch(item) is None
            for item in chain
        )
        or chain[-1] != head
        or len(set(chain)) != len(chain)
    ):
        _reject("canonical_chain_digests is invalid")
    _rule_bindings(document["rule_bindings"])
    taker_policy_digest = _digest(
        document["taker_policy_digest"],
        label="taker_policy_digest",
    )
    if (
        _policy_snapshot(
            document["taker_policy"],
            label="taker_policy",
        ).digest
        != taker_policy_digest
    ):
        _reject("taker_policy_digest does not match taker_policy")
    if not isinstance(document["terms"], dict):
        _reject("terms must be an object")
    try:
        if len(trade_canonical_json(document["terms"])) > _MAX_TERMS_BYTES:
            _reject("terms exceeds the byte limit")
    except TradeCanonicalJSONError as exc:
        raise TradeAgreementRejected(f"terms is invalid: {exc}") from exc
    created = _timestamp(document["created_at"], label="created_at")
    not_after = _timestamp(document["not_after"], label="not_after")
    if not_after <= created:
        _reject("not_after must be later than created_at")
    proof = _proof(
        document["proof"],
        signer_did=taker,
        purpose=PROPOSAL_PROOF_PURPOSE,
    )
    if _timestamp(proof["created"], label="proof.created") != created:
        _reject("proof.created must equal proposal created_at")


def _validate_acceptance(document: dict[str, Any]) -> None:
    _exact_fields(document, _ACCEPTANCE_FIELDS, "acceptance")
    if document["kind"] != ACCEPTANCE_KIND:
        _reject("wrong acceptance kind")
    if document["protocol_version"] != ACCEPTANCE_PROTOCOL_VERSION:
        _reject("unsupported acceptance protocol_version")
    maker = _did(document["maker_did"], label="maker_did")
    taker = _did(document["taker_did"], label="taker_did")
    if maker == taker:
        _reject("maker and taker must be different principals")
    _digest(document["proposal_digest"], label="proposal_digest")
    _digest(document["offer_digest"], label="offer_digest")
    _rule_bindings(document["rule_bindings"])
    maker_policy_digest = _digest(
        document["maker_policy_digest"],
        label="maker_policy_digest",
    )
    if (
        _policy_snapshot(
            document["maker_policy"],
            label="maker_policy",
        ).digest
        != maker_policy_digest
    ):
        _reject("maker_policy_digest does not match maker_policy")
    created = _timestamp(document["created_at"], label="created_at")
    proof = _proof(
        document["proof"],
        signer_did=maker,
        purpose=ACCEPTANCE_PROOF_PURPOSE,
    )
    if _timestamp(proof["created"], label="proof.created") != created:
        _reject("proof.created must equal acceptance created_at")


def _verify_document(
    document: dict[str, Any],
    *,
    signer_did: str,
    domain: bytes,
) -> None:
    try:
        signing_input = signed_document_input(domain, document)
    except TradeProofError as exc:
        raise TradeAgreementRejected(str(exc)) from exc
    ok, reason = verify_ed25519_did_signature(
        publisher_did=signer_did,
        proof_value=document["proof"]["proof_value"],
        signing_input=signing_input,
    )
    if not ok:
        _reject(reason)


@dataclass(frozen=True, init=False)
class TradeProposal:
    _canonical_bytes: bytes

    @classmethod
    def _create(cls, canonical: bytes) -> "TradeProposal":
        value = object.__new__(cls)
        object.__setattr__(value, "_canonical_bytes", bytes(canonical))
        return value

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> "TradeProposal":
        try:
            canonical = trade_canonical_json(copy.deepcopy(document))
            snapshot = parse_trade_json(canonical)
            _validate_proposal(snapshot)
            _verify_document(
                snapshot,
                signer_did=snapshot["taker_did"],
                domain=_PROPOSAL_DOMAIN,
            )
        except (
            TradeCanonicalJSONError,
            TradeProofError,
            TypeError,
            ValueError,
            UnicodeError,
        ) as exc:
            if isinstance(exc, TradeAgreementRejected):
                raise
            raise TradeAgreementRejected(str(exc)) from exc
        return cls._create(canonical)

    @classmethod
    def from_json(cls, raw: bytes | str) -> "TradeProposal":
        try:
            return cls.from_dict(parse_trade_json(raw))
        except TradeCanonicalJSONError as exc:
            raise TradeAgreementRejected(str(exc)) from exc

    @property
    def canonical_bytes(self) -> bytes:
        return self._canonical_bytes

    def to_dict(self) -> dict[str, Any]:
        return parse_trade_json(self._canonical_bytes)


@dataclass(frozen=True, init=False)
class TradeAcceptance:
    _canonical_bytes: bytes

    @classmethod
    def _create(cls, canonical: bytes) -> "TradeAcceptance":
        value = object.__new__(cls)
        object.__setattr__(value, "_canonical_bytes", bytes(canonical))
        return value

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> "TradeAcceptance":
        try:
            canonical = trade_canonical_json(copy.deepcopy(document))
            snapshot = parse_trade_json(canonical)
            _validate_acceptance(snapshot)
            _verify_document(
                snapshot,
                signer_did=snapshot["maker_did"],
                domain=_ACCEPTANCE_DOMAIN,
            )
        except (
            TradeCanonicalJSONError,
            TradeProofError,
            TypeError,
            ValueError,
            UnicodeError,
        ) as exc:
            if isinstance(exc, TradeAgreementRejected):
                raise
            raise TradeAgreementRejected(str(exc)) from exc
        return cls._create(canonical)

    @classmethod
    def from_json(cls, raw: bytes | str) -> "TradeAcceptance":
        try:
            return cls.from_dict(parse_trade_json(raw))
        except TradeCanonicalJSONError as exc:
            raise TradeAgreementRejected(str(exc)) from exc

    @property
    def canonical_bytes(self) -> bytes:
        return self._canonical_bytes

    def to_dict(self) -> dict[str, Any]:
        return parse_trade_json(self._canonical_bytes)


def proposal_digest(proposal: TradeProposal | dict[str, Any]) -> str:
    verified = (
        TradeProposal.from_json(proposal.canonical_bytes)
        if isinstance(proposal, TradeProposal)
        else TradeProposal.from_dict(proposal)
    )
    return "sha256:" + hashlib.sha256(verified.canonical_bytes).hexdigest()


def acceptance_digest(
    acceptance: TradeAcceptance | dict[str, Any],
) -> str:
    verified = (
        TradeAcceptance.from_json(acceptance.canonical_bytes)
        if isinstance(acceptance, TradeAcceptance)
        else TradeAcceptance.from_dict(acceptance)
    )
    return "sha256:" + hashlib.sha256(verified.canonical_bytes).hexdigest()


def _resolution_binding(
    resolution: CanonicalRuleResolution,
    offer: TradeOffer,
    offer_resolver: CanonicalOfferResolver,
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    if not isinstance(resolution, CanonicalRuleResolution):
        raise TypeError("resolution must be a CanonicalRuleResolution")
    if not callable(getattr(offer_resolver, "canonical_snapshot", None)):
        raise TypeError(
            "offer_resolver must provide canonical_snapshot()"
        )
    verified_offer = TradeOffer.from_json(offer.canonical_bytes)
    document = verified_offer.to_dict()
    digest = offer_digest(verified_offer)
    try:
        snapshot = offer_resolver.canonical_snapshot(
            verified_offer.publisher_did,
            verified_offer.offer_id,
        )
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise TradeAgreementRejected(
            f"unable to verify canonical Offer lifecycle: {exc}"
        ) from exc
    if not isinstance(snapshot, tuple) or len(snapshot) != 2:
        _reject("offer resolver returned an invalid canonical snapshot")
    lifecycle, selected = snapshot
    if (
        getattr(lifecycle, "status", None) != "canonical"
        or getattr(lifecycle, "canonical_head_digest", None) != digest
        or getattr(lifecycle, "canonical_digests", None)
        != resolution.canonical_chain_digests
        or not isinstance(selected, TradeOffer)
        or selected.canonical_bytes != verified_offer.canonical_bytes
    ):
        _reject("supplied Offer is not the current canonical lifecycle head")
    if (
        resolution.offer_digest != digest
        or resolution.offer_publisher_did != verified_offer.publisher_did
        or resolution.offer_id != verified_offer.offer_id
        or resolution.offer_revision != document["revision"]
        or len(resolution.canonical_chain_digests) != document["revision"]
        or resolution.canonical_chain_digests[-1] != digest
        or resolution.policy_digest
        != "sha256:"
        + hashlib.sha256(resolution.policy_canonical_bytes).hexdigest()
    ):
        _reject("resolution is not bound to the supplied canonical Offer")
    try:
        policy_document = parse_trade_json(
            resolution.policy_canonical_bytes
        )
        policy = _policy_snapshot(
            policy_document,
            label="resolution policy snapshot",
        )
    except (TradeCanonicalJSONError, TypeError, ValueError) as exc:
        raise TradeAgreementRejected(
            f"resolution policy snapshot is invalid: {exc}"
        ) from exc
    if (
        policy.canonical_bytes != resolution.policy_canonical_bytes
        or policy.digest != resolution.policy_digest
    ):
        _reject("resolution policy digest mismatch")
    rebuilt_bindings: list[dict[str, str]] = []
    verified_packages = {}
    for package in resolution.packages:
        verified_package = build_rule_package(
            package.manifest,
            package.resources,
        )
        if verified_package.digest != package.digest:
            _reject("resolution contains an unverified Rule Package")
        rebuilt_bindings.append(
            {
                "rule_id": verified_package.manifest.rule_id,
                "digest": verified_package.digest,
            }
        )
        verified_packages[verified_package.digest] = verified_package
    resolver = _VerifiedPackageResolver(verified_packages)
    try:
        replayed = resolve_offer_rules(
            verified_offer,
            resolver,
            policy,
            at=datetime.fromisoformat(
                resolution.evaluated_at.replace("Z", "+00:00")
            ),
        )
    except (RuleNegotiationError, TypeError, ValueError) as exc:
        raise TradeAgreementRejected(
            f"resolution replay failed: {exc}"
        ) from exc
    if (
        replayed.root_digests != resolution.root_digests
        or replayed.ordered_digests != resolution.ordered_digests
        or replayed.required_capabilities
        != resolution.required_capabilities
        or replayed.execution_modes != resolution.execution_modes
        or replayed.resolved_resource_bytes
        != resolution.resolved_resource_bytes
    ):
        _reject("resolution replay does not match its claimed result")
    rebuilt_bindings.sort(key=lambda item: (item["rule_id"], item["digest"]))
    if tuple(sorted(item["digest"] for item in rebuilt_bindings)) != tuple(
        sorted(resolution.ordered_digests)
    ):
        _reject("resolution Rule Package bindings are inconsistent")
    return document, rebuilt_bindings


def _proposal_body(
    *,
    resolution: CanonicalRuleResolution,
    offer: TradeOffer,
    offer_resolver: CanonicalOfferResolver,
    taker_did: str,
    terms: dict[str, Any],
    created_at: str,
    not_after: str,
) -> dict[str, Any]:
    offer_document, bindings = _resolution_binding(
        resolution,
        offer,
        offer_resolver,
    )
    if _timestamp(resolution.evaluated_at, label="resolution.evaluated_at") != (
        _timestamp(created_at, label="created_at")
    ):
        _reject("taker resolution time must equal proposal created_at")
    proposal_expiry = _timestamp(not_after, label="not_after")
    offer_expiry_raw = offer_document["not_after"]
    if (
        offer_expiry_raw is not None
        and proposal_expiry
        > _timestamp(offer_expiry_raw, label="offer.not_after")
    ):
        _reject("proposal cannot outlive the signed Offer")
    body = {
        "kind": PROPOSAL_KIND,
        "protocol_version": PROPOSAL_PROTOCOL_VERSION,
        "offer_publisher_did": offer_document["publisher_did"],
        "offer_id": offer_document["offer_id"],
        "offer_revision": offer_document["revision"],
        "offer_digest": resolution.offer_digest,
        "canonical_chain_digests": list(
            resolution.canonical_chain_digests
        ),
        "maker_did": offer_document["publisher_did"],
        "taker_did": taker_did,
        "rule_bindings": bindings,
        "taker_policy_digest": resolution.policy_digest,
        "taker_policy": parse_trade_json(
            resolution.policy_canonical_bytes
        ),
        "terms": copy.deepcopy(terms),
        "created_at": created_at,
        "not_after": not_after,
    }
    placeholder = dict(body)
    placeholder["proof"] = {
        "type": AGREEMENT_PROOF_TYPE,
        "created": created_at,
        "verification_method": verification_method_for_did(taker_did),
        "proof_purpose": PROPOSAL_PROOF_PURPOSE,
        "proof_value": "A" * 86,
    }
    _validate_proposal(placeholder)
    return body


def _sign_proposal_body(
    identity: Any,
    body: dict[str, Any],
) -> TradeProposal:
    document = copy.deepcopy(body)
    if set(document) != _PROPOSAL_FIELDS - {"proof"}:
        _reject("proposal body has missing or unknown fields")
    if identity.as_did() != document.get("taker_did"):
        _reject("proposal signer does not match taker_did")
    document["proof"] = {
        "type": AGREEMENT_PROOF_TYPE,
        "created": document["created_at"],
        "verification_method": verification_method_for_did(
            document["taker_did"]
        ),
        "proof_purpose": PROPOSAL_PROOF_PURPOSE,
        "proof_value": "A" * 86,
    }
    _validate_proposal(document)
    signing_input = signed_document_input(_PROPOSAL_DOMAIN, document)
    document["proof"]["proof_value"] = encode_ed25519_signature(
        identity.sign(signing_input)
    )
    return TradeProposal.from_dict(document)


def create_trade_proposal(
    identity: Any,
    *,
    resolution: CanonicalRuleResolution,
    offer: TradeOffer,
    offer_resolver: CanonicalOfferResolver,
    terms: dict[str, Any],
    created_at: str,
    not_after: str,
    now: datetime | None = None,
    max_ttl_seconds: float = DEFAULT_MAX_PROPOSAL_TTL_SECONDS,
    clock_skew_seconds: float = DEFAULT_CLOCK_SKEW_SECONDS,
) -> TradeProposal:
    """Resolve, validate, and sign one Proposal without a raw-body bypass."""
    _assert_local_signing_time(
        created_at,
        now=now,
        clock_skew_seconds=clock_skew_seconds,
    )
    _assert_proposal_ttl(
        created_at,
        not_after,
        max_ttl_seconds=max_ttl_seconds,
    )
    taker_did = identity.as_did()
    body = _proposal_body(
        resolution=resolution,
        offer=offer,
        offer_resolver=offer_resolver,
        taker_did=taker_did,
        terms=terms,
        created_at=created_at,
        not_after=not_after,
    )
    proposal = _sign_proposal_body(identity, body)
    _resolution_binding(resolution, offer, offer_resolver)
    return proposal


def _acceptance_body(
    *,
    proposal: TradeProposal,
    resolution: CanonicalRuleResolution,
    offer: TradeOffer,
    offer_resolver: CanonicalOfferResolver,
    created_at: str,
) -> dict[str, Any]:
    verified_proposal = TradeProposal.from_json(proposal.canonical_bytes)
    proposal_document = verified_proposal.to_dict()
    offer_document, bindings = _resolution_binding(
        resolution,
        offer,
        offer_resolver,
    )
    if _timestamp(resolution.evaluated_at, label="resolution.evaluated_at") != (
        _timestamp(created_at, label="created_at")
    ):
        _reject("maker resolution time must equal acceptance created_at")
    if (
        proposal_document["offer_digest"] != resolution.offer_digest
        or proposal_document["offer_id"] != offer_document["offer_id"]
        or proposal_document["maker_did"] != offer_document["publisher_did"]
        or proposal_document["rule_bindings"] != bindings
    ):
        _reject("maker resolution does not match the signed proposal")
    if _timestamp(created_at, label="created_at") < _timestamp(
        proposal_document["created_at"],
        label="proposal.created_at",
    ):
        _reject("acceptance cannot predate the signed proposal")
    if _timestamp(created_at, label="created_at") >= _timestamp(
        proposal_document["not_after"],
        label="proposal.not_after",
    ):
        _reject("proposal has expired")
    body = {
        "kind": ACCEPTANCE_KIND,
        "protocol_version": ACCEPTANCE_PROTOCOL_VERSION,
        "proposal_digest": proposal_digest(verified_proposal),
        "offer_digest": resolution.offer_digest,
        "maker_did": proposal_document["maker_did"],
        "taker_did": proposal_document["taker_did"],
        "rule_bindings": bindings,
        "maker_policy_digest": resolution.policy_digest,
        "maker_policy": parse_trade_json(
            resolution.policy_canonical_bytes
        ),
        "created_at": created_at,
    }
    placeholder = dict(body)
    placeholder["proof"] = {
        "type": AGREEMENT_PROOF_TYPE,
        "created": created_at,
        "verification_method": verification_method_for_did(
            body["maker_did"]
        ),
        "proof_purpose": ACCEPTANCE_PROOF_PURPOSE,
        "proof_value": "A" * 86,
    }
    _validate_acceptance(placeholder)
    return body


def _sign_acceptance_body(
    identity: Any,
    body: dict[str, Any],
) -> TradeAcceptance:
    document = copy.deepcopy(body)
    if set(document) != _ACCEPTANCE_FIELDS - {"proof"}:
        _reject("acceptance body has missing or unknown fields")
    if identity.as_did() != document.get("maker_did"):
        _reject("acceptance signer does not match maker_did")
    document["proof"] = {
        "type": AGREEMENT_PROOF_TYPE,
        "created": document["created_at"],
        "verification_method": verification_method_for_did(
            document["maker_did"]
        ),
        "proof_purpose": ACCEPTANCE_PROOF_PURPOSE,
        "proof_value": "A" * 86,
    }
    _validate_acceptance(document)
    signing_input = signed_document_input(_ACCEPTANCE_DOMAIN, document)
    document["proof"]["proof_value"] = encode_ed25519_signature(
        identity.sign(signing_input)
    )
    return TradeAcceptance.from_dict(document)


def create_trade_acceptance(
    identity: Any,
    *,
    proposal: TradeProposal,
    resolution: CanonicalRuleResolution,
    offer: TradeOffer,
    offer_resolver: CanonicalOfferResolver,
    created_at: str,
    now: datetime | None = None,
    clock_skew_seconds: float = DEFAULT_CLOCK_SKEW_SECONDS,
) -> TradeAcceptance:
    """Resolve, validate, and sign one Acceptance without a raw-body bypass."""
    _assert_local_signing_time(
        created_at,
        now=now,
        clock_skew_seconds=clock_skew_seconds,
    )
    body = _acceptance_body(
        proposal=proposal,
        resolution=resolution,
        offer=offer,
        offer_resolver=offer_resolver,
        created_at=created_at,
    )
    acceptance = _sign_acceptance_body(identity, body)
    _resolution_binding(resolution, offer, offer_resolver)
    return acceptance


def verify_acceptance_binding(
    proposal: TradeProposal | dict[str, Any],
    acceptance: TradeAcceptance | dict[str, Any],
) -> tuple[bool, str]:
    try:
        verified_proposal = (
            TradeProposal.from_json(proposal.canonical_bytes)
            if isinstance(proposal, TradeProposal)
            else TradeProposal.from_dict(proposal)
        )
        verified_acceptance = (
            TradeAcceptance.from_json(acceptance.canonical_bytes)
            if isinstance(acceptance, TradeAcceptance)
            else TradeAcceptance.from_dict(acceptance)
        )
        proposal_document = verified_proposal.to_dict()
        acceptance_document = verified_acceptance.to_dict()
        if acceptance_document["proposal_digest"] != proposal_digest(
            verified_proposal
        ):
            return False, "acceptance proposal digest mismatch"
        for field in ("offer_digest", "maker_did", "taker_did", "rule_bindings"):
            if acceptance_document[field] != proposal_document[field]:
                return False, f"acceptance {field} mismatch"
        if _timestamp(
            acceptance_document["created_at"],
            label="acceptance.created_at",
        ) < _timestamp(
            proposal_document["created_at"],
            label="proposal.created_at",
        ):
            return False, "acceptance predates the signed proposal"
        if _timestamp(
            acceptance_document["created_at"],
            label="acceptance.created_at",
        ) >= _timestamp(
            proposal_document["not_after"],
            label="proposal.not_after",
        ):
            return False, "acceptance was created after proposal expiry"
    except (TradeAgreementRejected, TypeError, ValueError) as exc:
        return False, str(exc)
    return True, "ok"


__all__ = [
    "ACCEPTANCE_KIND",
    "ACCEPTANCE_PROOF_PURPOSE",
    "ACCEPTANCE_PROTOCOL_VERSION",
    "AGREEMENT_PROOF_TYPE",
    "DEFAULT_CLOCK_SKEW_SECONDS",
    "DEFAULT_MAX_PROPOSAL_TTL_SECONDS",
    "PROPOSAL_KIND",
    "PROPOSAL_PROOF_PURPOSE",
    "PROPOSAL_PROTOCOL_VERSION",
    "TradeAcceptance",
    "TradeAgreementRejected",
    "TradeProposal",
    "acceptance_digest",
    "create_trade_acceptance",
    "create_trade_proposal",
    "proposal_digest",
    "verify_acceptance_binding",
]
