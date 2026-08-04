"""Bounded federation transport for observed Rule Recognition chains."""

from __future__ import annotations

import copy
import hashlib
import math
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from nth_dao.did_key import is_did_key
from nth_dao.identity import AgentIdentity
from nth_dao.trade_rules.canonical import (
    TradeCanonicalJSONError,
    parse_trade_json,
    trade_canonical_json,
)
from nth_dao.trade_rules.package_binding import (
    OfferPackageBindingRejected,
    SignedOfferPackageBinding,
    require_offer_package_binding,
)
from nth_dao.trade_rules.package_store import (
    RulePackage,
    RulePackageError,
    build_rule_package,
)
from nth_dao.trade_rules.recognition import (
    TradeRuleRecognition,
    TradeRuleRecognitionRejected,
)
from nth_dao.trade_rules.signing import (
    TradeProofError,
    encode_ed25519_signature,
    signed_document_input,
    verification_method_for_did,
    verify_ed25519_did_signature,
)

RULE_RECOGNITION_PROOF_BUNDLE_KIND = (
    "nth.dao.trade.rule-recognition-proof-bundle"
)
RULE_RECOGNITION_PROOF_BUNDLE_PROTOCOL_VERSION = "1"
RULE_RECOGNITION_PROOF_BUNDLE_PROOF_TYPE = "NthEd25519SignatureV1"
RULE_RECOGNITION_PROOF_BUNDLE_PROOF_PURPOSE = (
    "tradeRuleRecognitionObservation"
)
RULE_RECOGNITION_PROOF_BUNDLE_SIGNING_DOMAIN = (
    b"nth-dao/trade-rule-recognition-proof-bundle/v1"
)
MAX_RULE_RECOGNITION_PROOF_BUNDLE_ISSUERS = 64
MAX_RULE_RECOGNITION_PROOF_BUNDLE_STATEMENTS = 256
MAX_RULE_RECOGNITION_PROOF_BUNDLE_TTL_SECONDS = 10 * 60
DEFAULT_RULE_RECOGNITION_PROOF_BUNDLE_TTL_SECONDS = 5 * 60
DEFAULT_RULE_RECOGNITION_PROOF_BUNDLE_CLOCK_SKEW_SECONDS = 60

_BUNDLE_FIELDS = frozenset({
    "kind",
    "protocol_version",
    "offer_digest",
    "offer_package_binding",
    "package_digest",
    "observer_did",
    "observed_at",
    "not_after",
    "observed_heads_digest",
    "issuer_chains",
    "proof",
})
_CHAIN_FIELDS = frozenset({
    "issuer_did",
    "head_digests",
    "statements",
})
_PROOF_FIELDS = frozenset({
    "type",
    "created",
    "verification_method",
    "proof_purpose",
    "proof_value",
})
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TIMESTAMP = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{6}))?Z$"
)


class RuleRecognitionProofBundleRejected(ValueError):
    """An observed Recognition proof bundle is malformed or incomplete."""


def _timestamp(value: Any, *, label: str) -> datetime:
    if not isinstance(value, str) or len(value) > 35:
        raise RuleRecognitionProofBundleRejected(
            f"{label} must be a canonical UTC RFC3339 timestamp"
        )
    match = _TIMESTAMP.fullmatch(value)
    if match is None or match.group(2) == "000000":
        raise RuleRecognitionProofBundleRejected(
            f"{label} must be a canonical UTC RFC3339 timestamp"
        )
    fraction = match.group(2)
    try:
        return datetime.strptime(
            match.group(1) + (f".{fraction}" if fraction else ""),
            "%Y-%m-%dT%H:%M:%S.%f" if fraction else "%Y-%m-%dT%H:%M:%S",
        ).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise RuleRecognitionProofBundleRejected(
            f"{label} is not a real timestamp"
        ) from exc


def _utc_now(value: datetime | None) -> datetime:
    moment = value or datetime.now(timezone.utc)
    if (
        not isinstance(moment, datetime)
        or moment.tzinfo is None
        or moment.utcoffset() is None
    ):
        raise RuleRecognitionProofBundleRejected(
            "now must be timezone-aware"
        )
    return moment.astimezone(timezone.utc)


def _clock_skew(value: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
    ):
        raise RuleRecognitionProofBundleRejected(
            "clock_skew_seconds must be a finite non-negative number"
        )
    return float(value)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")


def _heads_digest(chains: list[dict[str, Any]]) -> str:
    projection = {
        "issuer_heads": [
            {
                "issuer_did": chain["issuer_did"],
                "head_digests": list(chain["head_digests"]),
            }
            for chain in chains
        ]
    }
    return "sha256:" + hashlib.sha256(
        trade_canonical_json(projection)
    ).hexdigest()


def _verify_observer_signature(document: dict[str, Any]) -> None:
    try:
        signing_input = signed_document_input(
            RULE_RECOGNITION_PROOF_BUNDLE_SIGNING_DOMAIN,
            document,
        )
    except TradeProofError as exc:
        raise RuleRecognitionProofBundleRejected(str(exc)) from exc
    ok, reason = verify_ed25519_did_signature(
        publisher_did=document["observer_did"],
        proof_value=document["proof"]["proof_value"],
        signing_input=signing_input,
    )
    if not ok:
        raise RuleRecognitionProofBundleRejected(
            f"Recognition proof bundle observer {reason}"
        )


def _verified_package(package: RulePackage) -> RulePackage:
    if not isinstance(package, RulePackage):
        raise TypeError("package must be a RulePackage")
    try:
        verified = build_rule_package(package.manifest, package.resources)
    except (RulePackageError, TypeError, ValueError) as exc:
        raise RuleRecognitionProofBundleRejected(
            f"Rule Package verification failed: {exc}"
        ) from exc
    if verified.digest != package.digest:
        raise RuleRecognitionProofBundleRejected(
            "Rule Package digest changed during verification"
        )
    return verified


def _verified_statement(
    value: TradeRuleRecognition | dict[str, Any],
    *,
    package: RulePackage,
) -> TradeRuleRecognition:
    try:
        statement = (
            TradeRuleRecognition.from_json(value.canonical_bytes)
            if isinstance(value, TradeRuleRecognition)
            else TradeRuleRecognition.from_dict(value)
        )
    except (TradeRuleRecognitionRejected, TypeError, ValueError) as exc:
        raise RuleRecognitionProofBundleRejected(str(exc)) from exc
    document = statement.to_dict()
    if (
        document["package_digest"] != package.digest
        or document["rule_id"] != package.manifest.rule_id
    ):
        raise RuleRecognitionProofBundleRejected(
            "recognition does not bind the requested Rule Package"
        )
    return statement


def _statement_sort_key(
    statement: TradeRuleRecognition,
) -> tuple[int, str]:
    return statement.to_dict()["sequence"], statement.digest


def _validate_chain(
    value: Any,
    *,
    package: RulePackage,
    max_statements: int = MAX_RULE_RECOGNITION_PROOF_BUNDLE_STATEMENTS,
) -> tuple[TradeRuleRecognition, ...]:
    if (
        isinstance(max_statements, bool)
        or not isinstance(max_statements, int)
        or max_statements <= 0
    ):
        raise ValueError("max_statements must be a positive integer")
    if not isinstance(value, dict) or set(value) != _CHAIN_FIELDS:
        raise RuleRecognitionProofBundleRejected(
            "Recognition issuer chain fields are invalid"
        )
    issuer_did = value["issuer_did"]
    statements_value = value["statements"]
    if (
        not isinstance(issuer_did, str)
        or not isinstance(statements_value, list)
        or not statements_value
        or len(statements_value)
        > max_statements
    ):
        raise RuleRecognitionProofBundleRejected(
            "Recognition issuer chain is invalid"
        )

    statements = tuple(
        _verified_statement(item, package=package)
        for item in statements_value
    )
    if any(
        statement.to_dict()["issuer_did"] != issuer_did
        for statement in statements
    ):
        raise RuleRecognitionProofBundleRejected(
            "Recognition issuer chain contains another issuer"
        )
    if tuple(sorted(statements, key=_statement_sort_key)) != statements:
        raise RuleRecognitionProofBundleRejected(
            "Recognition statements must be sequence/digest sorted"
        )

    by_digest = {statement.digest: statement for statement in statements}
    if len(by_digest) != len(statements):
        raise RuleRecognitionProofBundleRejected(
            "Recognition issuer chain contains duplicate statements"
        )
    referenced: set[str] = set()
    for statement in statements:
        document = statement.to_dict()
        previous_digest = document["previous_statement_digest"]
        if previous_digest is None:
            continue
        previous = by_digest.get(previous_digest)
        if previous is None:
            raise RuleRecognitionProofBundleRejected(
                "Recognition issuer chain is missing a predecessor"
            )
        previous_document = previous.to_dict()
        if previous_document["sequence"] + 1 != document["sequence"]:
            raise RuleRecognitionProofBundleRejected(
                "Recognition issuer chain has a non-contiguous edge"
            )
        if datetime.fromisoformat(
            previous_document["issued_at"].replace("Z", "+00:00")
        ) > datetime.fromisoformat(
            document["issued_at"].replace("Z", "+00:00")
        ):
            raise RuleRecognitionProofBundleRejected(
                "Recognition issuer chain reverses issuance time"
            )
        referenced.add(previous_digest)

    expected_heads = sorted(set(by_digest) - referenced)
    head_digests = value["head_digests"]
    if (
        not isinstance(head_digests, list)
        or head_digests != sorted(set(head_digests))
        or head_digests != expected_heads
    ):
        raise RuleRecognitionProofBundleRejected(
            "Recognition issuer heads do not match the disclosed graph"
        )
    return statements


@dataclass(frozen=True, init=False)
class VerifiedRuleRecognitionProofBundle:
    """Immutable disclosure of observed signed chains, not global freshness."""

    _canonical_bytes: bytes
    _statements: tuple[TradeRuleRecognition, ...]

    @classmethod
    def from_dict(
        cls,
        value: dict[str, Any],
        *,
        package: RulePackage,
        expected_offer_digest: str | None = None,
        expected_offer_publisher_did: str | None = None,
        now: datetime | None = None,
        clock_skew_seconds: float = (
            DEFAULT_RULE_RECOGNITION_PROOF_BUNDLE_CLOCK_SKEW_SECONDS
        ),
    ) -> "VerifiedRuleRecognitionProofBundle":
        verified_package = _verified_package(package)
        if not isinstance(value, dict) or set(value) != _BUNDLE_FIELDS:
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof bundle fields are invalid"
            )
        if value["kind"] != RULE_RECOGNITION_PROOF_BUNDLE_KIND:
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof bundle kind is invalid"
            )
        if (
            value["protocol_version"]
            != RULE_RECOGNITION_PROOF_BUNDLE_PROTOCOL_VERSION
        ):
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof bundle version is unsupported"
            )
        try:
            binding = require_offer_package_binding(
                value["offer_package_binding"],
                expected_offer_digest=(
                    expected_offer_digest or value["offer_digest"]
                ),
                expected_package_digest=verified_package.digest,
                expected_publisher_did=expected_offer_publisher_did,
            )
        except OfferPackageBindingRejected as exc:
            raise RuleRecognitionProofBundleRejected(str(exc)) from exc
        if value["offer_digest"] != binding.offer_digest:
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof bundle Offer binding is inconsistent"
            )
        if value["package_digest"] != verified_package.digest:
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof bundle is for another Rule Package"
            )
        observer_did = value["observer_did"]
        if not isinstance(observer_did, str) or not is_did_key(observer_did):
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof bundle observer_did must be an Ed25519 did:key"
            )
        if observer_did != binding.publisher_did:
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof bundle observer is not the Offer publisher"
            )
        observed_at = _timestamp(value["observed_at"], label="observed_at")
        not_after = _timestamp(value["not_after"], label="not_after")
        if not_after <= observed_at:
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof bundle not_after must follow observed_at"
            )
        if (
            not_after - observed_at
        ).total_seconds() > MAX_RULE_RECOGNITION_PROOF_BUNDLE_TTL_SECONDS:
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof bundle TTL exceeds its limit"
            )
        moment = _utc_now(now)
        skew = _clock_skew(clock_skew_seconds)
        if observed_at > moment + timedelta(seconds=skew):
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof bundle observation is in the future"
            )
        if moment >= not_after:
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof bundle has expired"
            )

        chains = value["issuer_chains"]
        if (
            not isinstance(chains, list)
            or len(chains) > MAX_RULE_RECOGNITION_PROOF_BUNDLE_ISSUERS
        ):
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof bundle issuer count exceeds its limit"
            )
        previous_issuer = ""
        statement_count = 0
        observed_digests: set[str] = set()
        verified_statements: list[TradeRuleRecognition] = []
        for chain in chains:
            if not isinstance(chain, dict) or set(chain) != _CHAIN_FIELDS:
                raise RuleRecognitionProofBundleRejected(
                    "Recognition issuer chain fields are invalid"
                )
            issuer = chain.get("issuer_did")
            if not isinstance(issuer, str) or issuer <= previous_issuer:
                raise RuleRecognitionProofBundleRejected(
                    "Recognition issuer chains must be unique and DID-sorted"
                )
            previous_issuer = issuer
            statement_values = chain["statements"]
            if not isinstance(statement_values, list):
                raise RuleRecognitionProofBundleRejected(
                    "Recognition issuer chain is invalid"
                )
            statement_count += len(statement_values)
            if statement_count > MAX_RULE_RECOGNITION_PROOF_BUNDLE_STATEMENTS:
                raise RuleRecognitionProofBundleRejected(
                    "Recognition proof bundle statement count exceeds its limit"
                )
        for chain in chains:
            statements = _validate_chain(
                chain,
                package=verified_package,
            )
            verified_statements.extend(statements)
            for statement in statements:
                if statement.digest in observed_digests:
                    raise RuleRecognitionProofBundleRejected(
                        "Recognition proof bundle repeats a statement"
                    )
                observed_digests.add(statement.digest)
        expected_heads_digest = _heads_digest(chains)
        if (
            not isinstance(value["observed_heads_digest"], str)
            or _DIGEST.fullmatch(value["observed_heads_digest"]) is None
            or value["observed_heads_digest"] != expected_heads_digest
        ):
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof bundle head-set commitment is invalid"
            )
        proof = value["proof"]
        if not isinstance(proof, dict) or set(proof) != _PROOF_FIELDS:
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof bundle proof fields are invalid"
            )
        if proof["type"] != RULE_RECOGNITION_PROOF_BUNDLE_PROOF_TYPE:
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof bundle proof type is unsupported"
            )
        if proof["created"] != value["observed_at"]:
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof bundle proof.created must equal observed_at"
            )
        if (
            proof["verification_method"]
            != verification_method_for_did(observer_did)
        ):
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof bundle verification method is invalid"
            )
        if (
            proof["proof_purpose"]
            != RULE_RECOGNITION_PROOF_BUNDLE_PROOF_PURPOSE
        ):
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof bundle proof purpose is invalid"
            )
        _verify_observer_signature(value)
        try:
            canonical = trade_canonical_json(value)
        except TradeCanonicalJSONError as exc:
            raise RuleRecognitionProofBundleRejected(str(exc)) from exc
        instance = object.__new__(cls)
        object.__setattr__(instance, "_canonical_bytes", canonical)
        object.__setattr__(instance, "_statements", tuple(verified_statements))
        return instance

    @classmethod
    def from_json(
        cls,
        raw: bytes | str,
        *,
        package: RulePackage,
        expected_offer_digest: str | None = None,
        expected_offer_publisher_did: str | None = None,
        now: datetime | None = None,
        clock_skew_seconds: float = (
            DEFAULT_RULE_RECOGNITION_PROOF_BUNDLE_CLOCK_SKEW_SECONDS
        ),
    ) -> "VerifiedRuleRecognitionProofBundle":
        try:
            value = parse_trade_json(raw)
        except TradeCanonicalJSONError as exc:
            raise RuleRecognitionProofBundleRejected(str(exc)) from exc
        return cls.from_dict(
            value,
            package=package,
            expected_offer_digest=expected_offer_digest,
            expected_offer_publisher_did=expected_offer_publisher_did,
            now=now,
            clock_skew_seconds=clock_skew_seconds,
        )

    @property
    def canonical_bytes(self) -> bytes:
        return self._canonical_bytes

    @property
    def statements(self) -> tuple[TradeRuleRecognition, ...]:
        return self._statements

    @property
    def statement_count(self) -> int:
        return len(self._statements)

    @property
    def package_digest(self) -> str:
        return self.to_dict()["package_digest"]

    @property
    def offer_digest(self) -> str:
        return self.to_dict()["offer_digest"]

    @property
    def observer_did(self) -> str:
        return self.to_dict()["observer_did"]

    @property
    def observed_heads_digest(self) -> str:
        return self.to_dict()["observed_heads_digest"]

    def to_dict(self) -> dict[str, Any]:
        return parse_trade_json(self._canonical_bytes)


def build_rule_recognition_proof_bundle(
    package: RulePackage,
    statements: Iterable[TradeRuleRecognition | dict[str, Any]],
    *,
    offer_package_binding: SignedOfferPackageBinding | dict[str, Any],
    observer_identity: AgentIdentity,
    observed_at: str | None = None,
    not_after: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Sign a complete observed graph without asserting global freshness."""

    if not isinstance(package, RulePackage):
        raise TypeError("package must be a RulePackage")
    if not isinstance(observer_identity, AgentIdentity):
        raise TypeError("observer_identity must be an AgentIdentity")
    if not observer_identity.can_sign:
        raise RuleRecognitionProofBundleRejected(
            "observer_identity has no signing key"
        )
    try:
        binding = require_offer_package_binding(
            offer_package_binding,
            expected_package_digest=package.digest,
            expected_publisher_did=observer_identity.as_did(),
        )
    except OfferPackageBindingRejected as exc:
        raise RuleRecognitionProofBundleRejected(str(exc)) from exc
    grouped: dict[str, list[TradeRuleRecognition]] = {}
    count = 0
    for value in statements:
        count += 1
        if count > MAX_RULE_RECOGNITION_PROOF_BUNDLE_STATEMENTS:
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof bundle statement count exceeds its limit"
            )
        statement = _verified_statement(value, package=package)
        issuer = statement.to_dict()["issuer_did"]
        grouped.setdefault(issuer, []).append(statement)
    if len(grouped) > MAX_RULE_RECOGNITION_PROOF_BUNDLE_ISSUERS:
        raise RuleRecognitionProofBundleRejected(
            "Recognition proof bundle issuer count exceeds its limit"
        )

    chains = []
    for issuer, issuer_statements in sorted(grouped.items()):
        ordered = sorted(issuer_statements, key=_statement_sort_key)
        digests = {statement.digest for statement in ordered}
        referenced = {
            statement.to_dict()["previous_statement_digest"]
            for statement in ordered
            if statement.to_dict()["previous_statement_digest"] is not None
        }
        chains.append({
            "issuer_did": issuer,
            "head_digests": sorted(digests - referenced),
            "statements": [statement.to_dict() for statement in ordered],
        })
    moment = _utc_now(now)
    observed = (
        _format_timestamp(moment)
        if observed_at is None
        else observed_at
    )
    observed_value = _timestamp(observed, label="observed_at")
    expires = (
        _format_timestamp(
            observed_value
            + timedelta(
                seconds=DEFAULT_RULE_RECOGNITION_PROOF_BUNDLE_TTL_SECONDS
            )
        )
        if not_after is None
        else not_after
    )
    wire = {
        "kind": RULE_RECOGNITION_PROOF_BUNDLE_KIND,
        "protocol_version": RULE_RECOGNITION_PROOF_BUNDLE_PROTOCOL_VERSION,
        "offer_digest": binding.offer_digest,
        "offer_package_binding": binding.to_dict(),
        "package_digest": package.digest,
        "observer_did": observer_identity.as_did(),
        "observed_at": observed,
        "not_after": expires,
        "observed_heads_digest": _heads_digest(chains),
        "issuer_chains": chains,
        "proof": {
            "type": RULE_RECOGNITION_PROOF_BUNDLE_PROOF_TYPE,
            "created": observed,
            "verification_method": verification_method_for_did(
                observer_identity.as_did()
            ),
            "proof_purpose": (
                RULE_RECOGNITION_PROOF_BUNDLE_PROOF_PURPOSE
            ),
            "proof_value": "A" * 86,
        },
    }
    try:
        wire["proof"]["proof_value"] = encode_ed25519_signature(
            observer_identity.sign(
                signed_document_input(
                    RULE_RECOGNITION_PROOF_BUNDLE_SIGNING_DOMAIN,
                    copy.deepcopy(wire),
                )
            )
        )
    except TradeProofError as exc:
        raise RuleRecognitionProofBundleRejected(str(exc)) from exc
    return VerifiedRuleRecognitionProofBundle.from_dict(
        wire,
        package=package,
        now=moment,
    ).to_dict()


def parse_rule_recognition_proof_bundle(
    value: dict[str, Any] | bytes | str,
    *,
    package: RulePackage,
    expected_offer_digest: str | None = None,
    expected_offer_publisher_did: str | None = None,
    now: datetime | None = None,
    clock_skew_seconds: float = (
        DEFAULT_RULE_RECOGNITION_PROOF_BUNDLE_CLOCK_SKEW_SECONDS
    ),
) -> VerifiedRuleRecognitionProofBundle:
    """Verify one proof bundle while granting no trust or execution rights."""

    if isinstance(value, (bytes, str)):
        return VerifiedRuleRecognitionProofBundle.from_json(
            value,
            package=package,
            expected_offer_digest=expected_offer_digest,
            expected_offer_publisher_did=expected_offer_publisher_did,
            now=now,
            clock_skew_seconds=clock_skew_seconds,
        )
    if not isinstance(value, dict):
        raise TypeError("Recognition proof bundle must be an object or JSON bytes")
    return VerifiedRuleRecognitionProofBundle.from_dict(
        value,
        package=package,
        expected_offer_digest=expected_offer_digest,
        expected_offer_publisher_did=expected_offer_publisher_did,
        now=now,
        clock_skew_seconds=clock_skew_seconds,
    )


__all__ = [
    "MAX_RULE_RECOGNITION_PROOF_BUNDLE_ISSUERS",
    "MAX_RULE_RECOGNITION_PROOF_BUNDLE_STATEMENTS",
    "MAX_RULE_RECOGNITION_PROOF_BUNDLE_TTL_SECONDS",
    "RULE_RECOGNITION_PROOF_BUNDLE_KIND",
    "RULE_RECOGNITION_PROOF_BUNDLE_PROOF_PURPOSE",
    "RULE_RECOGNITION_PROOF_BUNDLE_PROOF_TYPE",
    "RULE_RECOGNITION_PROOF_BUNDLE_PROTOCOL_VERSION",
    "RuleRecognitionProofBundleRejected",
    "VerifiedRuleRecognitionProofBundle",
    "build_rule_recognition_proof_bundle",
    "parse_rule_recognition_proof_bundle",
]
