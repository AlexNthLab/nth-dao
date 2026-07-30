"""Signed, chained recognition statements for Trade Rule Packages."""

from __future__ import annotations

import copy
import hashlib
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from nth_dao.did_key import is_did_key
from nth_dao.identity import AgentIdentity
from nth_dao.trade_rules.agreement import DEFAULT_CLOCK_SKEW_SECONDS
from nth_dao.trade_rules.canonical import (
    TradeCanonicalJSONError,
    parse_trade_json,
    trade_canonical_json,
)
from nth_dao.trade_rules.package_store import (
    RulePackage,
    RulePackageError,
    build_rule_package,
)
from nth_dao.trade_rules.signing import (
    TradeProofError,
    encode_ed25519_signature,
    signed_document_input,
    verification_method_for_did,
    verify_ed25519_did_signature,
)

RULE_RECOGNITION_KIND = "nth.dao.trade.rule-recognition"
RULE_RECOGNITION_PROTOCOL_VERSION = "1"
RULE_RECOGNITION_PROOF_TYPE = "NthEd25519SignatureV1"
RULE_RECOGNITION_PROOF_PURPOSE = "tradeRuleRecognition"
RULE_RECOGNITION_SIGNING_DOMAIN = b"nth-dao/trade-rule-recognition/v1"
RULE_RECOGNITION_ID_PREFIX = "nth-trade-recognition-sha256:"
RULE_RECOGNITION_DECISIONS = frozenset(
    {"recognized", "deprecated", "revoked"}
)
MAX_RULE_RECOGNITION_REASONS = 32
MAX_RULE_RECOGNITION_STATEMENTS = 16_384
MAX_RULE_RECOGNITION_ISSUERS = 4_096
MAX_RULE_RECOGNITION_SEQUENCE = 2_147_483_647
MAX_RULE_RECOGNITION_SCOPES_PER_ISSUER = 64
DEFAULT_MAX_RULE_RECOGNITION_TTL_SECONDS = 30 * 24 * 60 * 60
MAX_RULE_RECOGNITION_TTL_SECONDS = 366 * 24 * 60 * 60

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_RECOGNITION_ID = re.compile(
    rf"^{re.escape(RULE_RECOGNITION_ID_PREFIX)}[0-9a-f]{{64}}$"
)
_RULE_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_RULE_ID = re.compile(
    rf"^{_RULE_LABEL}(?:\.{_RULE_LABEL})+"
    r"(?:/[a-z0-9](?:[a-z0-9._-]{0,30}[a-z0-9])?)?$"
)
_REASON = re.compile(r"^[a-z][a-z0-9._:-]{0,127}$")
_TIMESTAMP = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{6}))?Z$"
)
_FIELDS = frozenset(
    {
        "kind",
        "protocol_version",
        "recognition_id",
        "rule_id",
        "package_digest",
        "issuer_did",
        "sequence",
        "previous_statement_digest",
        "decision",
        "reason_codes",
        "issued_at",
        "not_after",
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


class TradeRuleRecognitionRejected(ValueError):
    """A recognition statement or projection input is invalid."""


def _reject(message: str) -> None:
    raise TradeRuleRecognitionRejected(message)


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
        raise TradeRuleRecognitionRejected(
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


def _clock_skew(value: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
    ):
        _reject("clock_skew_seconds must be a finite non-negative number")
    return float(value)


def _recognition_id(
    *,
    rule_id: str,
    package_digest: str,
    issuer_did: str,
) -> str:
    binding = {
        "issuer_did": issuer_did,
        "package_digest": package_digest,
        "rule_id": rule_id,
    }
    return RULE_RECOGNITION_ID_PREFIX + hashlib.sha256(
        trade_canonical_json(binding)
    ).hexdigest()


def _reason_codes(values: Iterable[str]) -> list[str]:
    if isinstance(values, (str, bytes)):
        _reject("reason_codes must be an iterable of reason tokens")
    output: list[str] = []
    try:
        for index, value in enumerate(values):
            if index >= MAX_RULE_RECOGNITION_REASONS:
                _reject(
                    "reason_codes exceeds the "
                    f"{MAX_RULE_RECOGNITION_REASONS}-entry limit"
                )
            output.append(value)
    except TypeError as exc:
        raise TradeRuleRecognitionRejected(
            "reason_codes must be an iterable of reason tokens"
        ) from exc
    return sorted(output)


def _validate(document: dict[str, Any]) -> None:
    _exact_fields(document, _FIELDS, "rule recognition")
    if document["kind"] != RULE_RECOGNITION_KIND:
        _reject("wrong rule recognition kind")
    if (
        document["protocol_version"]
        != RULE_RECOGNITION_PROTOCOL_VERSION
    ):
        _reject("unsupported rule recognition protocol_version")
    recognition_id = document["recognition_id"]
    if (
        not isinstance(recognition_id, str)
        or _RECOGNITION_ID.fullmatch(recognition_id) is None
    ):
        _reject("recognition_id is invalid")
    rule_id = document["rule_id"]
    if (
        not isinstance(rule_id, str)
        or len(rule_id) > 160
        or _RULE_ID.fullmatch(rule_id) is None
    ):
        _reject("rule_id is invalid")
    package_digest = _digest(
        document["package_digest"],
        label="package_digest",
    )
    issuer_did = document["issuer_did"]
    if not isinstance(issuer_did, str) or not is_did_key(issuer_did):
        _reject("issuer_did must be an Ed25519 did:key")
    sequence = document["sequence"]
    if (
        isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or not 1 <= sequence <= MAX_RULE_RECOGNITION_SEQUENCE
    ):
        _reject("sequence is invalid")
    previous = document["previous_statement_digest"]
    if sequence == 1:
        if previous is not None:
            _reject("the first recognition statement cannot have a predecessor")
    else:
        _digest(previous, label="previous_statement_digest")
    decision = document["decision"]
    if decision not in RULE_RECOGNITION_DECISIONS:
        _reject("decision is invalid")
    reasons = document["reason_codes"]
    if (
        not isinstance(reasons, list)
        or len(reasons) > MAX_RULE_RECOGNITION_REASONS
        or reasons != sorted(set(reasons))
        or any(
            not isinstance(reason, str)
            or _REASON.fullmatch(reason) is None
            for reason in reasons
        )
    ):
        _reject("reason_codes must be a bounded sorted unique token list")
    if decision != "recognized" and not reasons:
        _reject("deprecated and revoked statements require a reason code")
    issued_at = _timestamp(document["issued_at"], label="issued_at")
    not_after = _timestamp(document["not_after"], label="not_after")
    if not_after <= issued_at:
        _reject("not_after must be later than issued_at")
    expected_id = _recognition_id(
        rule_id=rule_id,
        package_digest=package_digest,
        issuer_did=issuer_did,
    )
    if recognition_id != expected_id:
        _reject("recognition_id binding mismatch")
    proof = _exact_fields(document["proof"], _PROOF_FIELDS, "proof")
    if proof["type"] != RULE_RECOGNITION_PROOF_TYPE:
        _reject("proof.type is invalid")
    if proof["created"] != document["issued_at"]:
        _reject("proof.created must equal issued_at")
    if (
        proof["verification_method"]
        != verification_method_for_did(issuer_did)
    ):
        _reject("proof.verification_method does not match issuer_did")
    if proof["proof_purpose"] != RULE_RECOGNITION_PROOF_PURPOSE:
        _reject("proof.proof_purpose is invalid")


def _verify_signature(document: dict[str, Any]) -> None:
    try:
        signing_input = signed_document_input(
            RULE_RECOGNITION_SIGNING_DOMAIN,
            document,
        )
    except TradeProofError as exc:
        raise TradeRuleRecognitionRejected(str(exc)) from exc
    ok, reason = verify_ed25519_did_signature(
        publisher_did=document["issuer_did"],
        proof_value=document["proof"]["proof_value"],
        signing_input=signing_input,
    )
    if not ok:
        _reject(reason)


def _verified_package(package: RulePackage) -> RulePackage:
    if not isinstance(package, RulePackage):
        raise TypeError("package must be a RulePackage")
    try:
        verified = build_rule_package(
            package.manifest,
            package.resources,
        )
    except (RulePackageError, TypeError, ValueError) as exc:
        raise TradeRuleRecognitionRejected(
            f"Rule Package verification failed: {exc}"
        ) from exc
    if verified.digest != package.digest:
        _reject("Rule Package digest changed during verification")
    return verified


@dataclass(frozen=True, init=False)
class TradeRuleRecognition:
    """Immutable issuer claim about one exact Trade Rule Package."""

    _canonical_bytes: bytes

    @classmethod
    def _create(cls, canonical: bytes) -> "TradeRuleRecognition":
        value = object.__new__(cls)
        object.__setattr__(value, "_canonical_bytes", bytes(canonical))
        return value

    @classmethod
    def from_dict(
        cls,
        document: dict[str, Any],
    ) -> "TradeRuleRecognition":
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
            if isinstance(exc, TradeRuleRecognitionRejected):
                raise
            raise TradeRuleRecognitionRejected(str(exc)) from exc

    @classmethod
    def from_json(cls, raw: bytes | str) -> "TradeRuleRecognition":
        try:
            return cls.from_dict(parse_trade_json(raw))
        except TradeCanonicalJSONError as exc:
            raise TradeRuleRecognitionRejected(str(exc)) from exc

    @property
    def canonical_bytes(self) -> bytes:
        return self._canonical_bytes

    @property
    def recognition_id(self) -> str:
        return self.to_dict()["recognition_id"]

    @property
    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(self._canonical_bytes).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return parse_trade_json(self._canonical_bytes)


def rule_recognition_digest(
    statement: TradeRuleRecognition | dict[str, Any],
) -> str:
    verified = (
        TradeRuleRecognition.from_json(statement.canonical_bytes)
        if isinstance(statement, TradeRuleRecognition)
        else TradeRuleRecognition.from_dict(statement)
    )
    return verified.digest


def _verified_statement(
    statement: TradeRuleRecognition | dict[str, Any],
) -> TradeRuleRecognition:
    return (
        TradeRuleRecognition.from_json(statement.canonical_bytes)
        if isinstance(statement, TradeRuleRecognition)
        else TradeRuleRecognition.from_dict(statement)
    )


def _assert_recognition_binding(
    statement: TradeRuleRecognition,
    package: RulePackage,
) -> None:
    document = statement.to_dict()
    if document["package_digest"] != package.digest:
        _reject("recognition package_digest does not match Rule Package")
    if document["rule_id"] != package.manifest.rule_id:
        _reject("recognition rule_id does not match Rule Package")


def verify_rule_recognition_binding(
    statement: TradeRuleRecognition | dict[str, Any],
    package: RulePackage,
) -> TradeRuleRecognition:
    verified_statement = _verified_statement(statement)
    verified_package = _verified_package(package)
    _assert_recognition_binding(verified_statement, verified_package)
    return verified_statement


def create_rule_recognition(
    identity: AgentIdentity,
    *,
    package: RulePackage,
    decision: str,
    issued_at: str,
    not_after: str,
    previous: TradeRuleRecognition | dict[str, Any] | None = None,
    reason_codes: Iterable[str] = (),
    now: datetime | None = None,
    clock_skew_seconds: float = DEFAULT_CLOCK_SKEW_SECONDS,
) -> TradeRuleRecognition:
    """Sign the next statement in an issuer/package recognition chain."""

    if not isinstance(identity, AgentIdentity):
        raise TypeError("identity must be an AgentIdentity")
    verified_package = _verified_package(package)
    issuer_did = identity.as_did()
    issued = _timestamp(issued_at, label="issued_at")
    if abs((_utc_now(now) - issued).total_seconds()) > _clock_skew(
        clock_skew_seconds
    ):
        _reject("issued_at exceeds the local signing clock-skew limit")
    expires = _timestamp(not_after, label="not_after")
    if expires <= issued:
        _reject("not_after must be later than issued_at")
    sequence = 1
    previous_digest: str | None = None
    if previous is not None:
        verified_previous = _verified_statement(previous)
        _assert_recognition_binding(
            verified_previous,
            verified_package,
        )
        previous_document = verified_previous.to_dict()
        if previous_document["issuer_did"] != issuer_did:
            _reject("recognition predecessor belongs to another issuer")
        if _timestamp(
            previous_document["issued_at"],
            label="previous issued_at",
        ) > issued:
            _reject("recognition issued_at precedes its predecessor")
        sequence = previous_document["sequence"] + 1
        if sequence > MAX_RULE_RECOGNITION_SEQUENCE:
            _reject("recognition sequence is exhausted")
        previous_digest = verified_previous.digest
    reasons = _reason_codes(reason_codes)
    document = {
        "kind": RULE_RECOGNITION_KIND,
        "protocol_version": RULE_RECOGNITION_PROTOCOL_VERSION,
        "recognition_id": _recognition_id(
            rule_id=verified_package.manifest.rule_id,
            package_digest=verified_package.digest,
            issuer_did=issuer_did,
        ),
        "rule_id": verified_package.manifest.rule_id,
        "package_digest": verified_package.digest,
        "issuer_did": issuer_did,
        "sequence": sequence,
        "previous_statement_digest": previous_digest,
        "decision": decision,
        "reason_codes": reasons,
        "issued_at": issued_at,
        "not_after": not_after,
        "proof": {
            "type": RULE_RECOGNITION_PROOF_TYPE,
            "created": issued_at,
            "verification_method": verification_method_for_did(issuer_did),
            "proof_purpose": RULE_RECOGNITION_PROOF_PURPOSE,
            "proof_value": "A" * 86,
        },
    }
    _validate(document)
    document["proof"]["proof_value"] = encode_ed25519_signature(
        identity.sign(
            signed_document_input(
                RULE_RECOGNITION_SIGNING_DOMAIN,
                document,
            )
        )
    )
    statement = TradeRuleRecognition.from_dict(document)
    _assert_recognition_binding(statement, verified_package)
    return statement


@dataclass(frozen=True)
class RuleRecognitionTrustPolicy:
    """Local policy for interpreting third-party recognition claims."""

    trusted_issuers: frozenset[str]
    threshold: int = 1
    max_statement_ttl_seconds: int = (
        DEFAULT_MAX_RULE_RECOGNITION_TTL_SECONDS
    )
    issuer_rule_scopes: Mapping[str, Iterable[str]] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        if isinstance(self.trusted_issuers, (str, bytes)):
            raise ValueError("trusted_issuers must be an iterable of DIDs")
        issuers_set: set[str] = set()
        try:
            for index, issuer in enumerate(self.trusted_issuers):
                if index >= MAX_RULE_RECOGNITION_ISSUERS:
                    raise ValueError(
                        "trusted_issuers exceeds the "
                        f"{MAX_RULE_RECOGNITION_ISSUERS}-entry limit"
                    )
                issuers_set.add(issuer)
        except TypeError as exc:
            raise ValueError(
                "trusted_issuers must be an iterable of DIDs"
            ) from exc
        issuers = frozenset(issuers_set)
        object.__setattr__(self, "trusted_issuers", issuers)
        if not issuers or len(issuers) > MAX_RULE_RECOGNITION_ISSUERS:
            raise ValueError(
                "trusted_issuers must contain 1.."
                f"{MAX_RULE_RECOGNITION_ISSUERS} DIDs"
            )
        if any(
            not isinstance(issuer, str) or not is_did_key(issuer)
            for issuer in issuers
        ):
            raise ValueError("trusted_issuers contains an invalid DID")
        if (
            isinstance(self.threshold, bool)
            or not isinstance(self.threshold, int)
            or not 1 <= self.threshold <= len(issuers)
        ):
            raise ValueError(
                "threshold must be an integer within the trusted issuer set"
            )
        if (
            isinstance(self.max_statement_ttl_seconds, bool)
            or not isinstance(self.max_statement_ttl_seconds, int)
            or not 1
            <= self.max_statement_ttl_seconds
            <= MAX_RULE_RECOGNITION_TTL_SECONDS
        ):
            raise ValueError(
                "max_statement_ttl_seconds must be an integer in 1.."
                f"{MAX_RULE_RECOGNITION_TTL_SECONDS}"
            )
        if not isinstance(self.issuer_rule_scopes, Mapping):
            raise ValueError("issuer_rule_scopes must be a DID-to-scope mapping")
        if set(self.issuer_rule_scopes) != set(issuers):
            raise ValueError(
                "issuer_rule_scopes must define exactly every trusted issuer"
            )
        normalized_scopes: dict[str, tuple[str, ...]] = {}
        for issuer in sorted(issuers):
            raw_scopes = self.issuer_rule_scopes[issuer]
            if isinstance(raw_scopes, (str, bytes)):
                raise ValueError(
                    "each issuer rule scope must be an iterable of prefixes"
                )
            scopes: list[str] = []
            try:
                for index, scope in enumerate(raw_scopes):
                    if index >= MAX_RULE_RECOGNITION_SCOPES_PER_ISSUER:
                        raise ValueError(
                            "issuer rule scopes exceed the "
                            f"{MAX_RULE_RECOGNITION_SCOPES_PER_ISSUER}"
                            "-entry limit"
                        )
                    if (
                        not isinstance(scope, str)
                        or (
                            scope != "*"
                            and (
                                len(scope) > 160
                                or _RULE_ID.fullmatch(scope) is None
                            )
                        )
                    ):
                        raise ValueError(
                            "issuer_rule_scopes contains an invalid rule prefix"
                        )
                    scopes.append(scope)
            except TypeError as exc:
                raise ValueError(
                    "each issuer rule scope must be an iterable of prefixes"
                ) from exc
            canonical_scopes = tuple(sorted(set(scopes)))
            if not canonical_scopes or len(canonical_scopes) != len(scopes):
                raise ValueError(
                    "issuer rule scopes must be non-empty and unique"
                )
            normalized_scopes[issuer] = canonical_scopes
        object.__setattr__(
            self,
            "issuer_rule_scopes",
            MappingProxyType(normalized_scopes),
        )

    def allows(self, issuer_did: str, rule_id: str) -> bool:
        scopes = self.issuer_rule_scopes.get(issuer_did, ())
        return any(
            scope == "*"
            or rule_id == scope
            or rule_id.startswith(scope + ".")
            or rule_id.startswith(scope + "/")
            for scope in scopes
        )


@dataclass(frozen=True)
class RuleRecognitionIssuerState:
    issuer_did: str
    status: str
    decision: str | None
    sequence: int | None
    head_digest: str | None
    expires_at: str | None


@dataclass(frozen=True)
class RuleRecognitionSnapshot:
    package_digest: str
    rule_id: str
    evaluated_at: str
    threshold: int
    observed_quorum_met: bool
    quorum_valid_until: str | None
    recognized_by: tuple[str, ...]
    deprecated_by: tuple[str, ...]
    revoked_by: tuple[str, ...]
    expired_issuers: tuple[str, ...]
    incomplete_issuers: tuple[str, ...]
    conflicted_issuers: tuple[str, ...]
    scope_excluded_issuers: tuple[str, ...]
    quarantined_statement_indexes: tuple[int, ...]
    issuer_states: tuple[RuleRecognitionIssuerState, ...]


def _issuer_state(
    issuer: str,
    statements: list[TradeRuleRecognition],
    *,
    at: datetime,
    max_statement_ttl_seconds: int,
) -> RuleRecognitionIssuerState:
    unique = {statement.digest: statement for statement in statements}
    by_sequence: dict[int, list[TradeRuleRecognition]] = {}
    for statement in unique.values():
        sequence = statement.to_dict()["sequence"]
        by_sequence.setdefault(sequence, []).append(statement)
    if 1 not in by_sequence:
        return RuleRecognitionIssuerState(
            issuer, "incomplete", None, None, None, None
        )
    ordered: list[TradeRuleRecognition] = []
    previous: TradeRuleRecognition | None = None
    for expected_sequence, sequence in enumerate(
        sorted(by_sequence),
        start=1,
    ):
        if sequence != expected_sequence:
            return RuleRecognitionIssuerState(
                issuer, "incomplete", None, None, None, None
            )
        candidates = by_sequence[sequence]
        if len(candidates) != 1:
            return RuleRecognitionIssuerState(
                issuer, "conflicted", None, None, None, None
            )
        current = candidates[0]
        current_document = current.to_dict()
        if previous is None:
            if current_document["previous_statement_digest"] is not None:
                return RuleRecognitionIssuerState(
                    issuer, "conflicted", None, None, None, None
                )
        else:
            previous_document = previous.to_dict()
            if (
                current_document["previous_statement_digest"]
                != previous.digest
                or _timestamp(
                    current_document["issued_at"],
                    label="issued_at",
                )
                < _timestamp(
                    previous_document["issued_at"],
                    label="previous issued_at",
                )
            ):
                return RuleRecognitionIssuerState(
                    issuer, "conflicted", None, None, None, None
                )
        ordered.append(current)
        previous = current
    effective = next(
        (
            statement
            for statement in reversed(ordered)
            if _timestamp(
                statement.to_dict()["issued_at"],
                label="issued_at",
            )
            <= at
        ),
        None,
    )
    if effective is None:
        latest = ordered[-1]
        latest_document = latest.to_dict()
        return RuleRecognitionIssuerState(
            issuer_did=issuer,
            status="not_yet_active",
            decision=latest_document["decision"],
            sequence=latest_document["sequence"],
            head_digest=latest.digest,
            expires_at=latest_document["not_after"],
        )
    head = effective.to_dict()
    issued = _timestamp(head["issued_at"], label="issued_at")
    expires = _timestamp(head["not_after"], label="not_after")
    if (
        expires - issued
    ).total_seconds() > max_statement_ttl_seconds:
        status = "policy_rejected"
    elif expires <= at:
        status = "expired"
    else:
        status = "current"
    return RuleRecognitionIssuerState(
        issuer_did=issuer,
        status=status,
        decision=head["decision"],
        sequence=head["sequence"],
        head_digest=effective.digest,
        expires_at=head["not_after"],
    )


def evaluate_rule_recognition(
    package: RulePackage,
    statements: Iterable[TradeRuleRecognition | dict[str, Any]],
    *,
    policy: RuleRecognitionTrustPolicy,
    at: datetime | None = None,
    strict_invalid: bool = False,
) -> RuleRecognitionSnapshot:
    """Project trusted issuer chains without granting execution authority."""

    if not isinstance(strict_invalid, bool):
        raise TypeError("strict_invalid must be a bool")
    verified_package = _verified_package(package)
    moment = _utc_now(at)
    grouped: dict[str, list[TradeRuleRecognition]] = {}
    quarantined: list[int] = []
    count = 0
    for index, raw in enumerate(statements):
        if count >= MAX_RULE_RECOGNITION_STATEMENTS:
            _reject("recognition statement set exceeds its limit")
        if isinstance(raw, TradeRuleRecognition):
            inspected = raw.to_dict()
        elif isinstance(raw, dict):
            inspected = raw
        else:
            if strict_invalid:
                _reject("recognition statement must be an object")
            quarantined.append(index)
            count += 1
            continue
        count += 1
        if (
            inspected.get("issuer_did") not in policy.trusted_issuers
            or inspected.get("package_digest") != verified_package.digest
        ):
            continue
        if not policy.allows(
            inspected["issuer_did"],
            verified_package.manifest.rule_id,
        ):
            continue
        try:
            statement = _verified_statement(raw)
            _assert_recognition_binding(statement, verified_package)
        except TradeRuleRecognitionRejected:
            if strict_invalid:
                raise
            quarantined.append(index)
            continue
        issuer = statement.to_dict()["issuer_did"]
        grouped.setdefault(issuer, []).append(statement)
    states = tuple(
        _issuer_state(
            issuer,
            grouped.get(issuer, []),
            at=moment,
            max_statement_ttl_seconds=policy.max_statement_ttl_seconds,
        )
        if grouped.get(issuer)
        else RuleRecognitionIssuerState(
            issuer, "out_of_scope", None, None, None, None
        )
        if not policy.allows(
            issuer,
            verified_package.manifest.rule_id,
        )
        else RuleRecognitionIssuerState(
            issuer, "missing", None, None, None, None
        )
        for issuer in sorted(policy.trusted_issuers)
    )

    def issuers_for(*, status: str, decision: str | None = None) -> tuple[str, ...]:
        return tuple(
            state.issuer_did
            for state in states
            if state.status == status
            and (decision is None or state.decision == decision)
        )

    recognized = issuers_for(status="current", decision="recognized")
    recognized_expiries = sorted(
        (
            _timestamp(state.expires_at, label="expires_at")
            for state in states
            if state.status == "current"
            and state.decision == "recognized"
            and state.expires_at is not None
        ),
        reverse=True,
    )
    quorum_met = len(recognized) >= policy.threshold
    quorum_valid_until = (
        recognized_expiries[policy.threshold - 1]
        .isoformat()
        .replace("+00:00", "Z")
        if quorum_met
        else None
    )
    return RuleRecognitionSnapshot(
        package_digest=verified_package.digest,
        rule_id=verified_package.manifest.rule_id,
        evaluated_at=moment.isoformat().replace("+00:00", "Z"),
        threshold=policy.threshold,
        observed_quorum_met=quorum_met,
        quorum_valid_until=quorum_valid_until,
        recognized_by=recognized,
        deprecated_by=issuers_for(
            status="current",
            decision="deprecated",
        ),
        revoked_by=issuers_for(status="current", decision="revoked"),
        expired_issuers=issuers_for(status="expired"),
        incomplete_issuers=tuple(
            state.issuer_did
            for state in states
            if state.status
            in {"incomplete", "not_yet_active", "policy_rejected"}
        ),
        conflicted_issuers=issuers_for(status="conflicted"),
        scope_excluded_issuers=issuers_for(status="out_of_scope"),
        quarantined_statement_indexes=tuple(quarantined),
        issuer_states=states,
    )


__all__ = [
    "MAX_RULE_RECOGNITION_ISSUERS",
    "MAX_RULE_RECOGNITION_REASONS",
    "MAX_RULE_RECOGNITION_SEQUENCE",
    "MAX_RULE_RECOGNITION_SCOPES_PER_ISSUER",
    "MAX_RULE_RECOGNITION_STATEMENTS",
    "DEFAULT_MAX_RULE_RECOGNITION_TTL_SECONDS",
    "MAX_RULE_RECOGNITION_TTL_SECONDS",
    "RULE_RECOGNITION_DECISIONS",
    "RULE_RECOGNITION_ID_PREFIX",
    "RULE_RECOGNITION_KIND",
    "RULE_RECOGNITION_PROOF_PURPOSE",
    "RULE_RECOGNITION_PROOF_TYPE",
    "RULE_RECOGNITION_PROTOCOL_VERSION",
    "RULE_RECOGNITION_SIGNING_DOMAIN",
    "RuleRecognitionIssuerState",
    "RuleRecognitionSnapshot",
    "RuleRecognitionTrustPolicy",
    "TradeRuleRecognition",
    "TradeRuleRecognitionRejected",
    "create_rule_recognition",
    "evaluate_rule_recognition",
    "rule_recognition_digest",
    "verify_rule_recognition_binding",
]
