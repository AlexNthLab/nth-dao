"""Audited persistence and projection for local Recognition policy."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from nth_dao.did_key import is_did_key
from nth_dao.execution_receipt import now_ms as current_time_ms
from nth_dao.spine import SignedEventLog, SpineEvent
from nth_dao.trade_rules.package_store import RulePackageError, RulePackageStore
from nth_dao.trade_rules.recognition import (
    MAX_RULE_RECOGNITION_SEQUENCE,
    RuleRecognitionSnapshot,
    evaluate_rule_recognition,
)
from nth_dao.trade_rules.recognition_audit import (
    RuleRecognitionAuditCoordinator,
    RuleRecognitionAuditError,
)
from nth_dao.trade_rules.recognition_policy import (
    RULE_RECOGNITION_POLICY_ID_PREFIX,
    TradeRuleRecognitionPolicy,
    recognition_policy_id,
)
from nth_dao.trade_rules.recognition_policy_store import (
    RuleRecognitionPolicyStore,
)

EVENT_TRADE_RULE_RECOGNITION_POLICY_UPDATED = (
    "trade.rule.recognition.policy.updated"
)
RULE_RECOGNITION_POLICY_AUDIT_PROTOCOL_VERSION = "1"
DEFAULT_RULE_RECOGNITION_POLICY_RECONCILE_LIMIT = 100
MAX_RULE_RECOGNITION_POLICY_RECONCILE_LIMIT = 1_000

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TIMESTAMP = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{6}))?Z$"
)
_POLICY_ID = re.compile(
    rf"^{re.escape(RULE_RECOGNITION_POLICY_ID_PREFIX)}[0-9a-f]{{64}}$"
)
_PAYLOAD_FIELDS = frozenset(
    {
        "protocol_version",
        "policy_id",
        "policy_digest",
        "node_did",
        "signer_did",
        "sequence",
        "previous_policy_digest",
        "issued_at",
    }
)


class RuleRecognitionPolicyAuditError(RuntimeError):
    """Recognition policy audit or projection is unavailable."""


class RuleRecognitionPolicyAuditIntegrityError(
    RuleRecognitionPolicyAuditError
):
    """Policy CAS/head and Spine contain conflicting facts."""


def _observed_at_ms(value: Any) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= 9_007_199_254_740_991
    ):
        raise ValueError("observed_at_ms must be a positive safe integer")
    return value


def _audit_timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or len(value) > 35:
        raise RuleRecognitionPolicyAuditError(
            "Recognition policy audit issued_at is invalid"
        )
    match = _TIMESTAMP.fullmatch(value)
    if match is None or match.group(2) == "000000":
        raise RuleRecognitionPolicyAuditError(
            "Recognition policy audit issued_at is not canonical"
        )
    fraction = match.group(2)
    try:
        return datetime.strptime(
            match.group(1) + (f".{fraction}" if fraction else ""),
            "%Y-%m-%dT%H:%M:%S.%f" if fraction else "%Y-%m-%dT%H:%M:%S",
        ).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise RuleRecognitionPolicyAuditError(
            "Recognition policy audit issued_at is not a real timestamp"
        ) from exc


def _projection_time(value: datetime | None) -> datetime:
    moment = datetime.now(timezone.utc) if value is None else value
    if (
        not isinstance(moment, datetime)
        or moment.tzinfo is None
        or moment.utcoffset() is None
    ):
        raise RuleRecognitionPolicyAuditError(
            "Recognition policy projection time must be timezone-aware"
        )
    return moment.astimezone(timezone.utc)


def validate_rule_recognition_policy_audit_payload(
    value: Any,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _PAYLOAD_FIELDS:
        raise RuleRecognitionPolicyAuditError(
            "Recognition policy audit payload has missing or unknown fields"
        )
    if (
        value["protocol_version"]
        != RULE_RECOGNITION_POLICY_AUDIT_PROTOCOL_VERSION
    ):
        raise RuleRecognitionPolicyAuditError(
            "Recognition policy audit protocol version is unsupported"
        )
    if (
        not isinstance(value["policy_id"], str)
        or _POLICY_ID.fullmatch(value["policy_id"]) is None
    ):
        raise RuleRecognitionPolicyAuditError(
            "Recognition policy audit policy_id is invalid"
        )
    if (
        not isinstance(value["policy_digest"], str)
        or _DIGEST.fullmatch(value["policy_digest"]) is None
    ):
        raise RuleRecognitionPolicyAuditError(
            "Recognition policy audit policy_digest is invalid"
        )
    for field in ("node_did", "signer_did"):
        if not isinstance(value[field], str) or not is_did_key(value[field]):
            raise RuleRecognitionPolicyAuditError(
                f"Recognition policy audit {field} is invalid"
            )
    if value["policy_id"] != recognition_policy_id(value["node_did"]):
        raise RuleRecognitionPolicyAuditError(
            "Recognition policy audit policy_id does not bind node_did"
        )
    sequence = value["sequence"]
    if (
        isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or not 1 <= sequence <= MAX_RULE_RECOGNITION_SEQUENCE
    ):
        raise RuleRecognitionPolicyAuditError(
            "Recognition policy audit sequence is invalid"
        )
    previous = value["previous_policy_digest"]
    if sequence == 1:
        if previous is not None:
            raise RuleRecognitionPolicyAuditError(
                "Recognition policy genesis audit binds a predecessor"
            )
    elif not isinstance(previous, str) or _DIGEST.fullmatch(previous) is None:
        raise RuleRecognitionPolicyAuditError(
            "Recognition policy successor audit lacks a predecessor"
        )
    _audit_timestamp(value["issued_at"])
    return dict(value)


def rule_recognition_policy_audit_payload(
    policy: TradeRuleRecognitionPolicy | dict[str, Any],
) -> dict[str, Any]:
    verified = (
        TradeRuleRecognitionPolicy.from_json(policy.canonical_bytes)
        if isinstance(policy, TradeRuleRecognitionPolicy)
        else TradeRuleRecognitionPolicy.from_dict(policy)
    )
    document = verified.to_dict()
    return validate_rule_recognition_policy_audit_payload(
        {
            "protocol_version": (
                RULE_RECOGNITION_POLICY_AUDIT_PROTOCOL_VERSION
            ),
            "policy_id": document["policy_id"],
            "policy_digest": verified.digest,
            "node_did": document["node_did"],
            "signer_did": document["signer_did"],
            "sequence": document["sequence"],
            "previous_policy_digest": document[
                "previous_policy_digest"
            ],
            "issued_at": document["issued_at"],
        }
    )


@dataclass(frozen=True)
class RuleRecognitionPolicyAuditResult:
    policy: TradeRuleRecognitionPolicy
    event: SpineEvent
    store_created: bool
    anchor_created: bool


@dataclass(frozen=True)
class RuleRecognitionPolicyReconciliation:
    scanned: int
    anchored: int
    failed: int
    remaining: int
    blocked_digest: str | None
    error_message: str | None


@dataclass(frozen=True)
class RuleRecognitionPolicyEvaluation:
    policy: TradeRuleRecognitionPolicy
    snapshot: RuleRecognitionSnapshot


class RuleRecognitionPolicyAuditCoordinator:
    """Keep policy CAS/head and exact signed Spine anchors consistent."""

    def __init__(
        self,
        *,
        policy_store: RuleRecognitionPolicyStore,
        package_store: RulePackageStore,
        recognition_audit: RuleRecognitionAuditCoordinator,
        spine: SignedEventLog,
    ) -> None:
        if not isinstance(policy_store, RuleRecognitionPolicyStore):
            raise TypeError("policy_store must be a RuleRecognitionPolicyStore")
        if not isinstance(package_store, RulePackageStore):
            raise TypeError("package_store must be a RulePackageStore")
        if not isinstance(recognition_audit, RuleRecognitionAuditCoordinator):
            raise TypeError(
                "recognition_audit must be a RuleRecognitionAuditCoordinator"
            )
        if not isinstance(spine, SignedEventLog):
            raise TypeError("spine must be a SignedEventLog")
        self.policy_store = policy_store
        self.package_store = package_store
        self.recognition_audit = recognition_audit
        self.spine = spine

    def _anchor_index(self) -> dict[str, SpineEvent]:
        try:
            events = self.spine.verified_snapshot()
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise RuleRecognitionPolicyAuditError(
                f"Spine integrity check failed: {exc}"
            ) from exc
        anchors: dict[str, SpineEvent] = {}
        for event in events:
            if event.type != EVENT_TRADE_RULE_RECOGNITION_POLICY_UPDATED:
                continue
            payload = validate_rule_recognition_policy_audit_payload(
                event.payload
            )
            digest = payload["policy_digest"]
            if digest in anchors:
                raise RuleRecognitionPolicyAuditIntegrityError(
                    "Spine contains duplicate Recognition policy anchors"
                )
            anchors[digest] = event
        return anchors

    @staticmethod
    def _expected_payloads(
        policies: tuple[TradeRuleRecognitionPolicy, ...]
        | list[TradeRuleRecognitionPolicy],
    ) -> dict[str, dict[str, Any]]:
        return {
            policy.digest: rule_recognition_policy_audit_payload(policy)
            for policy in policies
        }

    @staticmethod
    def _assert_cross_log(
        *,
        expected: dict[str, dict[str, Any]],
        anchors: dict[str, SpineEvent],
        node_did: str,
        allow_missing: bool,
    ) -> None:
        relevant = {
            digest: event
            for digest, event in anchors.items()
            if event.payload.get("node_did") == node_did
        }
        extra = sorted(set(relevant) - set(expected))
        if extra:
            raise RuleRecognitionPolicyAuditIntegrityError(
                "Recognition policy rollback evidence: anchor has no "
                f"local statement {extra[0]}"
            )
        for digest, event in relevant.items():
            if event.payload != expected[digest]:
                raise RuleRecognitionPolicyAuditIntegrityError(
                    f"Recognition policy anchor mismatch {digest}"
                )
        if not allow_missing:
            missing = sorted(set(expected) - set(relevant))
            if missing:
                raise RuleRecognitionPolicyAuditIntegrityError(
                    f"missing Recognition policy anchor {missing[0]}"
                )

    def _anchor(
        self,
        policy: TradeRuleRecognitionPolicy,
        *,
        anchors: dict[str, SpineEvent],
        observed_at_ms: int,
    ) -> tuple[SpineEvent, bool]:
        payload = rule_recognition_policy_audit_payload(policy)
        existing = anchors.get(policy.digest)
        if existing is not None:
            if existing.payload != payload:
                raise RuleRecognitionPolicyAuditIntegrityError(
                    "Spine contains a conflicting Recognition policy anchor"
                )
            return existing, False
        try:
            event, created = self.spine.append_unique(
                EVENT_TRADE_RULE_RECOGNITION_POLICY_UPDATED,
                payload,
                unique_payload_fields=("policy_digest",),
                ts_ms=observed_at_ms,
            )
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise RuleRecognitionPolicyAuditError(
                f"unable to anchor Recognition policy: {exc}"
            ) from exc
        if event.payload != payload:
            raise RuleRecognitionPolicyAuditIntegrityError(
                "Spine returned a conflicting Recognition policy anchor"
            )
        anchors[policy.digest] = event
        return event, created

    def record(
        self,
        policy: TradeRuleRecognitionPolicy | dict[str, Any],
        *,
        observed_at_ms: int | None = None,
    ) -> RuleRecognitionPolicyAuditResult:
        verified = (
            TradeRuleRecognitionPolicy.from_json(policy.canonical_bytes)
            if isinstance(policy, TradeRuleRecognitionPolicy)
            else TradeRuleRecognitionPolicy.from_dict(policy)
        )
        moment = _observed_at_ms(
            current_time_ms() if observed_at_ms is None else observed_at_ms
        )
        current = self.policy_store.list_all()
        expected = self._expected_payloads(current)
        expected[verified.digest] = rule_recognition_policy_audit_payload(
            verified
        )
        anchors = self._anchor_index()
        self._assert_cross_log(
            expected=expected,
            anchors=anchors,
            node_did=self.policy_store.node_did,
            allow_missing=True,
        )
        anchored_digests = {
            digest
            for digest, event in anchors.items()
            if event.payload.get("node_did") == self.policy_store.node_did
        }
        unreconciled_predecessors = sorted(
            set(self._expected_payloads(current))
            - anchored_digests
            - {verified.digest}
        )
        if unreconciled_predecessors:
            raise RuleRecognitionPolicyAuditIntegrityError(
                "existing Recognition policy revision lacks a Spine anchor; "
                "reconcile before recording a successor "
                f"({unreconciled_predecessors[0]})"
            )
        stored = self.policy_store.append(verified)
        policies = self.policy_store.list_all()
        anchors = self._anchor_index()
        self._assert_cross_log(
            expected=self._expected_payloads(policies),
            anchors=anchors,
            node_did=self.policy_store.node_did,
            allow_missing=True,
        )
        event, anchor_created = self._anchor(
            stored.policy,
            anchors=anchors,
            observed_at_ms=moment,
        )
        return RuleRecognitionPolicyAuditResult(
            policy=stored.policy,
            event=event,
            store_created=stored.created,
            anchor_created=anchor_created,
        )

    def verify_anchors(self) -> tuple[bool, str]:
        try:
            policies = self.policy_store.list_all()
            self._assert_cross_log(
                expected=self._expected_payloads(policies),
                anchors=self._anchor_index(),
                node_did=self.policy_store.node_did,
                allow_missing=False,
            )
        except (
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
        ) as exc:
            return False, str(exc)
        return True, "ok"

    def verified_policies(
        self,
    ) -> tuple[TradeRuleRecognitionPolicy, ...]:
        """Return one bounded policy snapshot proven against the Spine.

        The second CAS read closes the interval in which a concurrent writer
        could append a store-first revision after verification but before an
        API response is assembled.
        """

        policies = self.policy_store.list_all()
        self._assert_cross_log(
            expected=self._expected_payloads(policies),
            anchors=self._anchor_index(),
            node_did=self.policy_store.node_did,
            allow_missing=False,
        )
        policies_after_verification = self.policy_store.list_all()
        if tuple(policy.digest for policy in policies) != tuple(
            policy.digest for policy in policies_after_verification
        ):
            raise RuleRecognitionPolicyAuditIntegrityError(
                "Recognition trust policy changed during projection"
            )
        return policies

    def reconcile(
        self,
        *,
        limit: int = DEFAULT_RULE_RECOGNITION_POLICY_RECONCILE_LIMIT,
        observed_at_ms: int | None = None,
    ) -> RuleRecognitionPolicyReconciliation:
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_RULE_RECOGNITION_POLICY_RECONCILE_LIMIT
        ):
            raise ValueError(
                "limit must be an integer in 1.."
                f"{MAX_RULE_RECOGNITION_POLICY_RECONCILE_LIMIT}"
            )
        moment = _observed_at_ms(
            current_time_ms() if observed_at_ms is None else observed_at_ms
        )
        policies = self.policy_store.list_all()
        anchors = self._anchor_index()
        expected = self._expected_payloads(policies)
        self._assert_cross_log(
            expected=expected,
            anchors=anchors,
            node_did=self.policy_store.node_did,
            allow_missing=True,
        )
        pending = [policy for policy in policies if policy.digest not in anchors]
        anchored = 0
        failed = 0
        blocked_digest: str | None = None
        error_message: str | None = None
        completed = 0
        for policy in pending[:limit]:
            try:
                _event, created = self._anchor(
                    policy,
                    anchors=anchors,
                    observed_at_ms=moment,
                )
            except RuleRecognitionPolicyAuditError as exc:
                failed = 1
                blocked_digest = policy.digest
                error_message = str(exc)
                break
            anchored += int(created)
            completed += 1
        return RuleRecognitionPolicyReconciliation(
            scanned=completed + failed,
            anchored=anchored,
            failed=failed,
            remaining=len(pending) - completed,
            blocked_digest=blocked_digest,
            error_message=error_message,
        )

    def evaluate(
        self,
        package_digest: str,
        *,
        at: datetime | None = None,
        strict_invalid: bool = False,
    ) -> RuleRecognitionPolicyEvaluation:
        moment = _projection_time(at)
        policies = self.verified_policies()
        if not policies:
            raise RuleRecognitionPolicyAuditError(
                "Recognition trust policy is not configured"
            )
        policy = next(
            (
                candidate
                for candidate in reversed(policies)
                if _audit_timestamp(
                    candidate.to_dict()["issued_at"]
                ) <= moment
            ),
            None,
        )
        if policy is None:
            raise RuleRecognitionPolicyAuditError(
                "Recognition trust policy is not active at the requested time"
            )
        try:
            package = self.package_store.load(package_digest)
        except RulePackageError as exc:
            raise RuleRecognitionPolicyAuditIntegrityError(
                f"Trade Rule Package integrity check failed: {exc}"
            ) from exc
        if package is None:
            raise RuleRecognitionPolicyAuditError(
                "Trade Rule Package is not installed"
            )
        try:
            statements = self.recognition_audit.verified_statements(
                package=package
            )
        except RuleRecognitionAuditError as exc:
            raise RuleRecognitionPolicyAuditIntegrityError(
                str(exc)
            ) from exc
        snapshot = evaluate_rule_recognition(
            package,
            statements,
            policy=policy.trust_policy,
            at=moment,
            strict_invalid=strict_invalid,
        )
        return RuleRecognitionPolicyEvaluation(
            policy=policy,
            snapshot=snapshot,
        )


__all__ = [
    "DEFAULT_RULE_RECOGNITION_POLICY_RECONCILE_LIMIT",
    "EVENT_TRADE_RULE_RECOGNITION_POLICY_UPDATED",
    "MAX_RULE_RECOGNITION_POLICY_RECONCILE_LIMIT",
    "RULE_RECOGNITION_POLICY_AUDIT_PROTOCOL_VERSION",
    "RuleRecognitionPolicyAuditCoordinator",
    "RuleRecognitionPolicyAuditError",
    "RuleRecognitionPolicyAuditIntegrityError",
    "RuleRecognitionPolicyAuditResult",
    "RuleRecognitionPolicyEvaluation",
    "RuleRecognitionPolicyReconciliation",
    "rule_recognition_policy_audit_payload",
    "validate_rule_recognition_policy_audit_payload",
]
