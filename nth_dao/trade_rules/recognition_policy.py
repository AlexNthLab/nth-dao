"""Signed local trust policy for Trade Rule Recognition statements."""

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
from nth_dao.trade_rules.canonical import (
    TradeCanonicalJSONError,
    parse_trade_json,
    trade_canonical_json,
)
from nth_dao.trade_rules.recognition import (
    MAX_RULE_RECOGNITION_SEQUENCE,
    RuleRecognitionTrustPolicy,
)
from nth_dao.trade_rules.signing import (
    TradeProofError,
    encode_ed25519_signature,
    signed_document_input,
    verification_method_for_did,
    verify_ed25519_did_signature,
)

RULE_RECOGNITION_POLICY_KIND = "nth.dao.trade.rule-recognition-policy"
RULE_RECOGNITION_POLICY_PROTOCOL_VERSION = "1"
RULE_RECOGNITION_POLICY_PROOF_TYPE = "NthEd25519SignatureV1"
RULE_RECOGNITION_POLICY_PROOF_PURPOSE = "tradeRuleRecognitionPolicy"
RULE_RECOGNITION_POLICY_SIGNING_DOMAIN = (
    b"nth-dao/trade-rule-recognition-policy/v1"
)
RULE_RECOGNITION_POLICY_ID_PREFIX = (
    "nth-trade-recognition-policy-sha256:"
)
MAX_RULE_RECOGNITION_POLICY_CONTROLLERS = 64

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_POLICY_ID = re.compile(
    rf"^{re.escape(RULE_RECOGNITION_POLICY_ID_PREFIX)}[0-9a-f]{{64}}$"
)
_TIMESTAMP = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{6}))?Z$"
)
_FIELDS = frozenset(
    {
        "kind",
        "protocol_version",
        "policy_id",
        "node_did",
        "signer_did",
        "controllers",
        "sequence",
        "previous_policy_digest",
        "issued_at",
        "trusted_issuers",
        "threshold",
        "max_statement_ttl_seconds",
        "proof",
    }
)
_ISSUER_FIELDS = frozenset({"issuer_did", "rule_scopes"})
_PROOF_FIELDS = frozenset(
    {
        "type",
        "created",
        "verification_method",
        "proof_purpose",
        "proof_value",
    }
)


class TradeRuleRecognitionPolicyRejected(ValueError):
    """A Recognition policy statement is malformed or unsigned."""


def _reject(message: str) -> None:
    raise TradeRuleRecognitionPolicyRejected(message)


def _exact_fields(
    value: Any,
    expected: frozenset[str],
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        _reject(f"{label} has missing or unknown fields")
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
        raise TradeRuleRecognitionPolicyRejected(
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


def recognition_policy_id(node_did: str) -> str:
    """Derive the stable policy identifier bound to one node namespace."""
    if not isinstance(node_did, str) or not is_did_key(node_did):
        _reject("node_did must be an Ed25519 did:key")
    binding = trade_canonical_json({"node_did": node_did})
    return RULE_RECOGNITION_POLICY_ID_PREFIX + hashlib.sha256(
        binding
    ).hexdigest()


def _validate(document: dict[str, Any]) -> RuleRecognitionTrustPolicy:
    _exact_fields(document, _FIELDS, "Recognition policy")
    if document["kind"] != RULE_RECOGNITION_POLICY_KIND:
        _reject("wrong Recognition policy kind")
    if (
        document["protocol_version"]
        != RULE_RECOGNITION_POLICY_PROTOCOL_VERSION
    ):
        _reject("unsupported Recognition policy protocol_version")
    node_did = document["node_did"]
    signer_did = document["signer_did"]
    if not isinstance(node_did, str) or not is_did_key(node_did):
        _reject("node_did must be an Ed25519 did:key")
    if not isinstance(signer_did, str) or not is_did_key(signer_did):
        _reject("signer_did must be an Ed25519 did:key")
    controllers = document["controllers"]
    if (
        not isinstance(controllers, list)
        or not 1 <= len(controllers) <= MAX_RULE_RECOGNITION_POLICY_CONTROLLERS
        or controllers != sorted(set(controllers))
        or any(
            not isinstance(controller, str) or not is_did_key(controller)
            for controller in controllers
        )
    ):
        _reject("controllers must be a bounded sorted unique DID list")
    policy_id = document["policy_id"]
    if (
        not isinstance(policy_id, str)
        or _POLICY_ID.fullmatch(policy_id) is None
        or policy_id != recognition_policy_id(node_did)
    ):
        _reject("policy_id does not bind node_did")
    sequence = document["sequence"]
    if (
        isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or not 1 <= sequence <= MAX_RULE_RECOGNITION_SEQUENCE
    ):
        _reject("sequence is invalid")
    previous = document["previous_policy_digest"]
    if sequence == 1:
        if previous is not None:
            _reject("sequence 1 must not declare previous_policy_digest")
    elif not isinstance(previous, str) or _DIGEST.fullmatch(previous) is None:
        _reject("successor policy requires previous_policy_digest")
    issued_at = document["issued_at"]
    _timestamp(issued_at, label="issued_at")
    entries = document["trusted_issuers"]
    if not isinstance(entries, list):
        _reject("trusted_issuers must be an array")
    issuers: list[str] = []
    scopes: dict[str, tuple[str, ...]] = {}
    for entry in entries:
        _exact_fields(entry, _ISSUER_FIELDS, "trusted issuer")
        issuer = entry["issuer_did"]
        raw_scopes = entry["rule_scopes"]
        if not isinstance(issuer, str):
            _reject("trusted issuer DID is invalid")
        if not isinstance(raw_scopes, list):
            _reject("trusted issuer rule_scopes must be an array")
        issuers.append(issuer)
        scopes[issuer] = tuple(raw_scopes)
    if issuers != sorted(set(issuers)):
        _reject("trusted_issuers must be sorted and unique")
    try:
        policy = RuleRecognitionTrustPolicy(
            trusted_issuers=frozenset(issuers),
            threshold=document["threshold"],
            max_statement_ttl_seconds=document[
                "max_statement_ttl_seconds"
            ],
            issuer_rule_scopes=scopes,
        )
    except (TypeError, ValueError) as exc:
        raise TradeRuleRecognitionPolicyRejected(str(exc)) from exc
    for entry in entries:
        issuer = entry["issuer_did"]
        if entry["rule_scopes"] != list(policy.issuer_rule_scopes[issuer]):
            _reject("trusted issuer rule_scopes must be sorted and unique")
    proof = _exact_fields(document["proof"], _PROOF_FIELDS, "proof")
    if proof["type"] != RULE_RECOGNITION_POLICY_PROOF_TYPE:
        _reject("proof.type is invalid")
    if proof["created"] != issued_at:
        _reject("proof.created must equal issued_at")
    if (
        proof["verification_method"]
        != verification_method_for_did(signer_did)
    ):
        _reject("proof.verification_method does not match signer_did")
    if proof["proof_purpose"] != RULE_RECOGNITION_POLICY_PROOF_PURPOSE:
        _reject("proof.proof_purpose is invalid")
    return policy


def _verify_signature(document: dict[str, Any]) -> None:
    try:
        signing_input = signed_document_input(
            RULE_RECOGNITION_POLICY_SIGNING_DOMAIN,
            document,
        )
    except TradeProofError as exc:
        raise TradeRuleRecognitionPolicyRejected(str(exc)) from exc
    ok, reason = verify_ed25519_did_signature(
        publisher_did=document["signer_did"],
        proof_value=document["proof"]["proof_value"],
        signing_input=signing_input,
    )
    if not ok:
        _reject(reason)


@dataclass(frozen=True, init=False)
class TradeRuleRecognitionPolicy:
    """Immutable signed local Recognition trust-policy revision."""

    _canonical_bytes: bytes

    @classmethod
    def _create(cls, canonical: bytes) -> "TradeRuleRecognitionPolicy":
        value = object.__new__(cls)
        object.__setattr__(value, "_canonical_bytes", bytes(canonical))
        return value

    @classmethod
    def from_dict(
        cls,
        document: dict[str, Any],
    ) -> "TradeRuleRecognitionPolicy":
        try:
            canonical = trade_canonical_json(copy.deepcopy(document))
            snapshot = parse_trade_json(canonical)
            _validate(snapshot)
            _verify_signature(snapshot)
            return cls._create(canonical)
        except (
            TradeCanonicalJSONError,
            TradeProofError,
            TypeError,
            ValueError,
            UnicodeError,
        ) as exc:
            if isinstance(exc, TradeRuleRecognitionPolicyRejected):
                raise
            raise TradeRuleRecognitionPolicyRejected(str(exc)) from exc

    @classmethod
    def from_json(cls, raw: bytes | str) -> "TradeRuleRecognitionPolicy":
        try:
            return cls.from_dict(parse_trade_json(raw))
        except TradeCanonicalJSONError as exc:
            raise TradeRuleRecognitionPolicyRejected(str(exc)) from exc

    @property
    def canonical_bytes(self) -> bytes:
        return self._canonical_bytes

    @property
    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(self._canonical_bytes).hexdigest()

    @property
    def trust_policy(self) -> RuleRecognitionTrustPolicy:
        return _validate(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return parse_trade_json(self._canonical_bytes)


def verify_rule_recognition_policy_successor(
    previous: TradeRuleRecognitionPolicy | dict[str, Any],
    successor: TradeRuleRecognitionPolicy | dict[str, Any],
) -> None:
    first = (
        TradeRuleRecognitionPolicy.from_json(previous.canonical_bytes)
        if isinstance(previous, TradeRuleRecognitionPolicy)
        else TradeRuleRecognitionPolicy.from_dict(previous)
    )
    second = (
        TradeRuleRecognitionPolicy.from_json(successor.canonical_bytes)
        if isinstance(successor, TradeRuleRecognitionPolicy)
        else TradeRuleRecognitionPolicy.from_dict(successor)
    )
    first_document = first.to_dict()
    second_document = second.to_dict()
    if second_document["node_did"] != first_document["node_did"]:
        _reject("successor policy changes node_did")
    if second_document["policy_id"] != first_document["policy_id"]:
        _reject("successor policy changes policy_id")
    if second_document["sequence"] != first_document["sequence"] + 1:
        _reject("successor policy sequence is not contiguous")
    if second_document["previous_policy_digest"] != first.digest:
        _reject("successor policy predecessor digest mismatch")
    if second_document["signer_did"] not in first_document["controllers"]:
        _reject("successor policy signer is not an authorized controller")
    if _timestamp(
        second_document["issued_at"],
        label="successor issued_at",
    ) < _timestamp(first_document["issued_at"], label="previous issued_at"):
        _reject("successor policy predates previous policy")


def create_rule_recognition_policy(
    identity: AgentIdentity,
    *,
    node_did: str,
    trust_policy: RuleRecognitionTrustPolicy,
    controllers: list[str] | tuple[str, ...] | None = None,
    issued_at: str,
    previous: TradeRuleRecognitionPolicy | dict[str, Any] | None = None,
    now: datetime | None = None,
    clock_skew_seconds: float = DEFAULT_CLOCK_SKEW_SECONDS,
) -> TradeRuleRecognitionPolicy:
    """Sign the first or next local Recognition policy revision."""

    if not isinstance(identity, AgentIdentity) or not identity.can_sign:
        raise TypeError("identity must be a signing AgentIdentity")
    if not isinstance(node_did, str) or not is_did_key(node_did):
        _reject("node_did must be an Ed25519 did:key")
    if not isinstance(trust_policy, RuleRecognitionTrustPolicy):
        raise TypeError("trust_policy must be a RuleRecognitionTrustPolicy")
    if (
        isinstance(clock_skew_seconds, bool)
        or not isinstance(clock_skew_seconds, (int, float))
        or not math.isfinite(clock_skew_seconds)
        or clock_skew_seconds < 0
    ):
        _reject("clock_skew_seconds must be a finite non-negative number")
    issued = _timestamp(issued_at, label="issued_at")
    if abs((_utc_now(now) - issued).total_seconds()) > float(
        clock_skew_seconds
    ):
        _reject("issued_at exceeds the local signing clock-skew limit")
    sequence = 1
    previous_digest: str | None = None
    verified_previous: TradeRuleRecognitionPolicy | None = None
    if previous is not None:
        verified_previous = (
            TradeRuleRecognitionPolicy.from_json(previous.canonical_bytes)
            if isinstance(previous, TradeRuleRecognitionPolicy)
            else TradeRuleRecognitionPolicy.from_dict(previous)
        )
        previous_document = verified_previous.to_dict()
        if previous_document["node_did"] != node_did:
            _reject("previous policy belongs to another node")
        sequence = previous_document["sequence"] + 1
        if sequence > MAX_RULE_RECOGNITION_SEQUENCE:
            _reject("Recognition policy sequence is exhausted")
        previous_digest = verified_previous.digest
    entries = [
        {
            "issuer_did": issuer,
            "rule_scopes": list(trust_policy.issuer_rule_scopes[issuer]),
        }
        for issuer in sorted(trust_policy.trusted_issuers)
    ]
    signer_did = identity.as_did()
    controller_values = (
        [node_did] if controllers is None else copy.deepcopy(list(controllers))
    )
    if verified_previous is None and signer_did != node_did:
        _reject("genesis policy must be signed by node_did")
    document = {
        "kind": RULE_RECOGNITION_POLICY_KIND,
        "protocol_version": RULE_RECOGNITION_POLICY_PROTOCOL_VERSION,
        "policy_id": recognition_policy_id(node_did),
        "node_did": node_did,
        "signer_did": signer_did,
        "controllers": sorted(controller_values),
        "sequence": sequence,
        "previous_policy_digest": previous_digest,
        "issued_at": issued_at,
        "trusted_issuers": entries,
        "threshold": trust_policy.threshold,
        "max_statement_ttl_seconds": (
            trust_policy.max_statement_ttl_seconds
        ),
        "proof": {
            "type": RULE_RECOGNITION_POLICY_PROOF_TYPE,
            "created": issued_at,
            "verification_method": verification_method_for_did(signer_did),
            "proof_purpose": RULE_RECOGNITION_POLICY_PROOF_PURPOSE,
            "proof_value": "A" * 86,
        },
    }
    _validate(document)
    signing_input = signed_document_input(
        RULE_RECOGNITION_POLICY_SIGNING_DOMAIN,
        document,
    )
    document["proof"]["proof_value"] = encode_ed25519_signature(
        identity.sign(signing_input)
    )
    result = TradeRuleRecognitionPolicy.from_dict(document)
    if verified_previous is not None:
        verify_rule_recognition_policy_successor(
            verified_previous,
            result,
        )
    return result


__all__ = [
    "RULE_RECOGNITION_POLICY_ID_PREFIX",
    "RULE_RECOGNITION_POLICY_KIND",
    "RULE_RECOGNITION_POLICY_PROOF_PURPOSE",
    "RULE_RECOGNITION_POLICY_PROOF_TYPE",
    "RULE_RECOGNITION_POLICY_PROTOCOL_VERSION",
    "RULE_RECOGNITION_POLICY_SIGNING_DOMAIN",
    "MAX_RULE_RECOGNITION_POLICY_CONTROLLERS",
    "TradeRuleRecognitionPolicy",
    "TradeRuleRecognitionPolicyRejected",
    "create_rule_recognition_policy",
    "recognition_policy_id",
    "verify_rule_recognition_policy_successor",
]
