"""Recoverable Spine projection for signed Trade Rule Recognitions."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from nth_dao.did_key import is_did_key
from nth_dao.execution_receipt import now_ms as current_time_ms
from nth_dao.spine import SignedEventLog, SpineEvent
from nth_dao.spine.log import MAX_SPINE_APPEND_BATCH
from nth_dao.trade_rules.package_store import RulePackage
from nth_dao.trade_rules.recognition import (
    MAX_RULE_RECOGNITION_SEQUENCE,
    RULE_RECOGNITION_DECISIONS,
    RULE_RECOGNITION_ID_PREFIX,
    TradeRuleRecognition,
    verify_rule_recognition_binding,
)
from nth_dao.trade_rules.recognition_store import RuleRecognitionStore

EVENT_TRADE_RULE_RECOGNITION_RECORDED = (
    "trade.rule.recognition.recorded"
)
RULE_RECOGNITION_AUDIT_PROTOCOL_VERSION = "1"
DEFAULT_RULE_RECOGNITION_RECONCILE_LIMIT = 100
MAX_RULE_RECOGNITION_RECONCILE_LIMIT = 1_000

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_RECOGNITION_ID = re.compile(
    rf"^{re.escape(RULE_RECOGNITION_ID_PREFIX)}[0-9a-f]{{64}}$"
)
_RULE_ID = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+"
    r"(?:/[a-z0-9](?:[a-z0-9._-]{0,30}[a-z0-9])?)?$"
)
_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d{6})?Z$"
)
_PAYLOAD_FIELDS = frozenset(
    {
        "protocol_version",
        "recognition_id",
        "recognition_digest",
        "rule_id",
        "package_digest",
        "issuer_did",
        "sequence",
        "decision",
        "issued_at",
        "not_after",
    }
)


class RuleRecognitionAuditError(RuntimeError):
    """Recognition audit projection is invalid or unavailable."""


class RuleRecognitionAuditIntegrityError(RuleRecognitionAuditError):
    """CAS and Spine disagree or contain rollback/conflict evidence."""


def _timestamp(value: Any, *, label: str) -> datetime:
    if (
        not isinstance(value, str)
        or len(value) > 35
        or _TIMESTAMP.fullmatch(value) is None
        or ".000000Z" in value
    ):
        raise RuleRecognitionAuditError(
            f"Recognition Spine payload {label} is invalid"
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuleRecognitionAuditError(
            f"Recognition Spine payload {label} is invalid"
        ) from exc
    if parsed.tzinfo != timezone.utc:
        raise RuleRecognitionAuditError(
            f"Recognition Spine payload {label} is invalid"
        )
    return parsed


def _observed_at_ms(value: Any) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= 9_007_199_254_740_991
    ):
        raise ValueError(
            "observed_at_ms must be a positive safe integer"
        )
    return value


def validate_rule_recognition_audit_payload(
    value: Any,
) -> dict[str, Any]:
    """Validate the closed wire shape of a Recognition Spine payload."""

    if not isinstance(value, dict) or set(value) != _PAYLOAD_FIELDS:
        raise RuleRecognitionAuditError(
            "Recognition Spine payload has missing or unknown fields"
        )
    if (
        value["protocol_version"]
        != RULE_RECOGNITION_AUDIT_PROTOCOL_VERSION
    ):
        raise RuleRecognitionAuditError(
            "Recognition Spine payload protocol version is unsupported"
        )
    if (
        not isinstance(value["recognition_id"], str)
        or _RECOGNITION_ID.fullmatch(value["recognition_id"]) is None
    ):
        raise RuleRecognitionAuditError(
            "Recognition Spine payload recognition_id is invalid"
        )
    for field in ("recognition_digest", "package_digest"):
        if (
            not isinstance(value[field], str)
            or _DIGEST.fullmatch(value[field]) is None
        ):
            raise RuleRecognitionAuditError(
                f"Recognition Spine payload {field} is invalid"
            )
    if (
        not isinstance(value["rule_id"], str)
        or _RULE_ID.fullmatch(value["rule_id"]) is None
    ):
        raise RuleRecognitionAuditError(
            "Recognition Spine payload rule_id is invalid"
        )
    if (
        not isinstance(value["issuer_did"], str)
        or not is_did_key(value["issuer_did"])
    ):
        raise RuleRecognitionAuditError(
            "Recognition Spine payload issuer_did is invalid"
        )
    sequence = value["sequence"]
    if (
        isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or not 1 <= sequence <= MAX_RULE_RECOGNITION_SEQUENCE
    ):
        raise RuleRecognitionAuditError(
            "Recognition Spine payload sequence is invalid"
        )
    if value["decision"] not in RULE_RECOGNITION_DECISIONS:
        raise RuleRecognitionAuditError(
            "Recognition Spine payload decision is invalid"
        )
    issued_at = _timestamp(value["issued_at"], label="issued_at")
    not_after = _timestamp(value["not_after"], label="not_after")
    if not_after <= issued_at:
        raise RuleRecognitionAuditError(
            "Recognition Spine payload not_after must follow issued_at"
        )
    return dict(value)


def rule_recognition_audit_payload(
    statement: TradeRuleRecognition | dict[str, Any],
    *,
    package: RulePackage,
) -> dict[str, Any]:
    """Build an exact audit binding for one issuer-signed statement."""

    verified = verify_rule_recognition_binding(statement, package)
    document = verified.to_dict()
    return validate_rule_recognition_audit_payload(
        {
            "protocol_version": (
                RULE_RECOGNITION_AUDIT_PROTOCOL_VERSION
            ),
            "recognition_id": document["recognition_id"],
            "recognition_digest": verified.digest,
            "rule_id": document["rule_id"],
            "package_digest": document["package_digest"],
            "issuer_did": document["issuer_did"],
            "sequence": document["sequence"],
            "decision": document["decision"],
            "issued_at": document["issued_at"],
            "not_after": document["not_after"],
        }
    )


def validate_rule_recognition_audit_binding(
    value: Any,
    *,
    statement: TradeRuleRecognition | dict[str, Any],
    package: RulePackage,
) -> dict[str, Any]:
    """Require an audit payload to bind the exact signed statement."""

    payload = validate_rule_recognition_audit_payload(value)
    expected = rule_recognition_audit_payload(
        statement,
        package=package,
    )
    if payload != expected:
        raise RuleRecognitionAuditError(
            "Recognition Spine payload does not bind the signed statement"
        )
    return payload


@dataclass(frozen=True)
class RuleRecognitionAuditResult:
    statement: TradeRuleRecognition
    event: SpineEvent
    store_created: bool
    anchor_created: bool


@dataclass(frozen=True)
class RuleRecognitionAuditReconciliation:
    scanned: int
    anchored: int
    verified_anchored: int
    failed: int
    remaining: int
    has_more: bool
    blocked_digest: str | None
    error_code: str | None
    error_message: str | None


class RuleRecognitionAuditCoordinator:
    """Persist signed Recognitions before projecting exact Spine anchors."""

    def __init__(
        self,
        *,
        store: RuleRecognitionStore,
        spine: SignedEventLog,
    ) -> None:
        if not isinstance(store, RuleRecognitionStore):
            raise TypeError("store must be a RuleRecognitionStore")
        if not isinstance(spine, SignedEventLog):
            raise TypeError("spine must be a SignedEventLog")
        self.store = store
        self.spine = spine

    def _verified_spine_events(self) -> tuple[SpineEvent, ...]:
        try:
            return self.spine.verified_snapshot()
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise RuleRecognitionAuditError(
                f"Spine integrity check failed: {exc}"
            ) from exc

    def _assert_proof_imports_complete_and_present(
        self,
        events: tuple[SpineEvent, ...],
        *,
        package: RulePackage,
        statement_digests: set[str],
        verify_source_evidence: bool = False,
    ) -> int:
        from nth_dao.trade_rules.recognition_import import (
            EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORT_PROPOSED,
            RULE_RECOGNITION_PROOF_PAGE_IMPORT_PROTOCOL_VERSION,
            RuleRecognitionProofImportError,
            RuleRecognitionProofImportState,
            RuleRecognitionProofStore,
            recognition_proof_import_payload,
            recognition_proof_import_states,
        )
        from nth_dao.trade_rules.recognition_transport import (
            RuleRecognitionProofBundleRejected,
            parse_rule_recognition_proof_bundle,
        )
        from nth_dao.trade_rules.recognition_transport_pages import (
            RULE_RECOGNITION_PROOF_PAGE_KIND,
            VerifiedRuleRecognitionProofPage,
        )
        from nth_dao.trade_rules.canonical import (
            parse_trade_json,
            trade_canonical_json,
        )

        try:
            states = recognition_proof_import_states(
                events,
                package_digest=package.digest,
            )
        except RuleRecognitionProofImportError as exc:
            raise RuleRecognitionAuditIntegrityError(str(exc)) from exc
        pending = [state for state in states if state.completed_event is None]
        if pending:
            raise RuleRecognitionAuditIntegrityError(
                "Recognition proof import is incomplete "
                f"{pending[0].payload['import_id']}"
            )
        page_groups: dict[
            tuple[str, str, str],
            list[RuleRecognitionProofImportState],
        ] = {}
        for state in states:
            payload = state.payload
            if payload["protocol_version"] != (
                RULE_RECOGNITION_PROOF_PAGE_IMPORT_PROTOCOL_VERSION
            ):
                continue
            key = (
                payload["order_digest"],
                payload["source_origin"],
                payload["observation_digest"],
            )
            page_groups.setdefault(key, []).append(state)
        for group in page_groups.values():
            first = group[0].payload
            shared_fields = (
                "offer_digest",
                "package_digest",
                "observer_did",
                "observed_heads_digest",
                "page_count",
                "statement_count",
                "statement_set_digest",
            )
            if any(
                any(
                    state.payload[field] != first[field]
                    for field in shared_fields
                )
                for state in group[1:]
            ):
                raise RuleRecognitionAuditIntegrityError(
                    "Recognition proof page import has conflicting set metadata"
                )
            indexes = sorted(state.payload["page_index"] for state in group)
            if indexes != list(range(first["page_count"])):
                raise RuleRecognitionAuditIntegrityError(
                    "Recognition proof page import set is incomplete or duplicated"
                )
            page_statement_digests = [
                digest
                for state in group
                for digest in state.payload["statement_digests"]
            ]
            if (
                len(page_statement_digests) != first["statement_count"]
                or len(set(page_statement_digests))
                != len(page_statement_digests)
            ):
                raise RuleRecognitionAuditIntegrityError(
                    "Recognition proof page import statement set is incomplete"
                )
            statement_set_digest = "sha256:" + hashlib.sha256(
                trade_canonical_json({
                    "statement_digests": sorted(page_statement_digests)
                })
            ).hexdigest()
            if statement_set_digest != first["statement_set_digest"]:
                raise RuleRecognitionAuditIntegrityError(
                    "Recognition proof page import statement commitment is invalid"
                )
        for state in states:
            missing = sorted(
                set(state.payload["statement_digests"])
                - statement_digests
            )
            if missing:
                raise RuleRecognitionAuditIntegrityError(
                    "completed Recognition proof import is missing local "
                    f"statement {missing[0]}"
                )
        if not verify_source_evidence:
            return len(states)
        for state in states:
            try:
                raw = RuleRecognitionProofStore(
                    self.store.workspace_root
                ).get(state.payload["proof_digest"])
                proposed_at = datetime.fromtimestamp(
                    state.proposed_event.ts_ms / 1000,
                    tz=timezone.utc,
                )
                inspected = parse_trade_json(raw)
                if inspected.get("kind") == RULE_RECOGNITION_PROOF_PAGE_KIND:
                    proof = VerifiedRuleRecognitionProofPage.from_dict(
                        inspected,
                        package=package,
                        expected_offer_digest=state.payload["offer_digest"],
                        expected_offer_publisher_did=state.payload[
                            "observer_did"
                        ],
                        now=proposed_at,
                    )
                else:
                    proof = parse_rule_recognition_proof_bundle(
                        inspected,
                        package=package,
                        expected_offer_digest=state.payload["offer_digest"],
                        expected_offer_publisher_did=state.payload[
                            "observer_did"
                        ],
                        now=proposed_at,
                    )
                expected_payload = recognition_proof_import_payload(
                    proof,
                    event_type=(
                        EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORT_PROPOSED
                    ),
                    order_digest=state.payload["order_digest"],
                    offer_digest=state.payload["offer_digest"],
                    source_origin=state.payload["source_origin"],
                )
            except (
                RuleRecognitionProofBundleRejected,
                RuleRecognitionProofImportError,
                OSError,
                RuntimeError,
                TypeError,
                ValueError,
            ) as exc:
                raise RuleRecognitionAuditIntegrityError(
                    "Recognition proof import source evidence is invalid"
                ) from exc
            if expected_payload != state.payload:
                raise RuleRecognitionAuditIntegrityError(
                    "Recognition proof import source evidence binding mismatch"
                )
        return len(states)

    def verify_proof_import_evidence(
        self,
        *,
        package: RulePackage,
    ) -> int:
        """Deep-audit every retained source envelope for one Package.

        Normal projections verify signed Recognition statements, their local
        CAS files, Spine anchors, and import completion markers. Source proof
        envelopes are immutable provenance evidence, so re-reading every
        historical envelope belongs in an explicit integrity audit rather than
        the public request path.
        """

        statements = self.store.list_for_package(package)
        events = self._verified_spine_events()
        return self._assert_proof_imports_complete_and_present(
            events,
            package=package,
            statement_digests={statement.digest for statement in statements},
            verify_source_evidence=True,
        )

    def _anchor_index(
        self,
        events: tuple[SpineEvent, ...] | None = None,
    ) -> dict[str, SpineEvent]:
        if events is None:
            events = self._verified_spine_events()
        anchors: dict[str, SpineEvent] = {}
        for event in events:
            if event.type != EVENT_TRADE_RULE_RECOGNITION_RECORDED:
                continue
            payload = validate_rule_recognition_audit_payload(event.payload)
            digest = payload["recognition_digest"]
            if digest in anchors:
                raise RuleRecognitionAuditError(
                    "Spine contains duplicate Recognition anchors"
                )
            anchors[digest] = event
        return anchors

    @staticmethod
    def _event_for_payload(
        payload: dict[str, Any],
        anchors: dict[str, SpineEvent],
    ) -> SpineEvent | None:
        event = anchors.get(payload["recognition_digest"])
        if event is not None and event.payload != payload:
            raise RuleRecognitionAuditError(
                "Spine contains a conflicting Recognition anchor"
            )
        return event

    @staticmethod
    def _expected_payloads(
        statements: tuple[TradeRuleRecognition, ...] | list[TradeRuleRecognition],
        *,
        package: RulePackage,
    ) -> dict[str, dict[str, Any]]:
        return {
            statement.digest: rule_recognition_audit_payload(
                statement,
                package=package,
            )
            for statement in statements
        }

    @staticmethod
    def _assert_no_orphan_or_mismatched_anchors(
        *,
        package: RulePackage,
        expected: dict[str, dict[str, Any]],
        anchors: dict[str, SpineEvent],
    ) -> None:
        relevant = {
            digest: event
            for digest, event in anchors.items()
            if event.payload.get("package_digest") == package.digest
        }
        extra = sorted(set(relevant) - set(expected))
        if extra:
            raise RuleRecognitionAuditIntegrityError(
                "Recognition Spine rollback evidence: anchor has no "
                f"local statement {extra[0]}"
            )
        for digest, event in relevant.items():
            if event.payload != expected[digest]:
                raise RuleRecognitionAuditIntegrityError(
                    "Recognition Spine anchor mismatch "
                    f"{digest}"
                )

    def _anchor(
        self,
        statement: TradeRuleRecognition,
        *,
        package: RulePackage,
        anchors: dict[str, SpineEvent],
        observed_at_ms: int,
    ) -> tuple[SpineEvent, bool]:
        payload = rule_recognition_audit_payload(
            statement,
            package=package,
        )
        existing = self._event_for_payload(payload, anchors)
        if existing is not None:
            return existing, False
        try:
            event, created = self.spine.append_unique(
                EVENT_TRADE_RULE_RECOGNITION_RECORDED,
                payload,
                unique_payload_fields=("recognition_digest",),
                ts_ms=observed_at_ms,
            )
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise RuleRecognitionAuditError(
                f"unable to project Recognition into Spine: {exc}"
            ) from exc
        if event.payload != payload:
            raise RuleRecognitionAuditError(
                "Spine returned a conflicting Recognition anchor"
            )
        anchors[payload["recognition_digest"]] = event
        return event, created

    def record(
        self,
        statement: TradeRuleRecognition | dict[str, Any],
        *,
        package: RulePackage,
        observed_at_ms: int | None = None,
    ) -> RuleRecognitionAuditResult:
        verified = verify_rule_recognition_binding(statement, package)
        moment = _observed_at_ms(
            current_time_ms()
            if observed_at_ms is None
            else observed_at_ms
        )
        existing_statements = self.store.list_for_package(package)
        preflight_expected = self._expected_payloads(
            existing_statements,
            package=package,
        )
        preflight_expected[verified.digest] = (
            rule_recognition_audit_payload(
                verified,
                package=package,
            )
        )
        self._assert_no_orphan_or_mismatched_anchors(
            package=package,
            expected=preflight_expected,
            anchors=self._anchor_index(),
        )
        result = self.store.import_json(
            verified.canonical_bytes,
            package=package,
        )
        if not result.accepted or result.statement is None:
            raise RuleRecognitionAuditError(
                "verified Recognition was rejected by its local store"
            )
        anchors = self._anchor_index()
        statements = self.store.list_for_package(package)
        self._assert_no_orphan_or_mismatched_anchors(
            package=package,
            expected=self._expected_payloads(
                statements,
                package=package,
            ),
            anchors=anchors,
        )
        event, anchor_created = self._anchor(
            result.statement,
            package=package,
            anchors=anchors,
            observed_at_ms=moment,
        )
        return RuleRecognitionAuditResult(
            statement=result.statement,
            event=event,
            store_created=not result.duplicate,
            anchor_created=anchor_created,
        )

    def record_batch(
        self,
        statements: tuple[TradeRuleRecognition, ...]
        | list[TradeRuleRecognition],
        *,
        package: RulePackage,
        observed_at_ms: int | None = None,
    ) -> tuple[RuleRecognitionAuditResult, ...]:
        """Persist and anchor one batch with bounded, constant-count scans."""

        if not isinstance(statements, (tuple, list)):
            raise TypeError("statements must be a tuple or list")
        if not statements:
            return ()
        verified = tuple(
            verify_rule_recognition_binding(statement, package)
            for statement in statements
        )
        if len({statement.digest for statement in verified}) != len(verified):
            raise RuleRecognitionAuditError(
                "Recognition audit batch repeats a statement"
            )
        moment = _observed_at_ms(
            current_time_ms()
            if observed_at_ms is None
            else observed_at_ms
        )
        imported = self.store.import_many(verified, package=package)
        all_statements = self.store.list_for_package(package)
        expected = self._expected_payloads(
            all_statements,
            package=package,
        )
        try:
            spine_before = self.spine.verified_snapshot()
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise RuleRecognitionAuditError(
                f"Spine integrity check failed: {exc}"
            ) from exc
        anchors = self._anchor_index(spine_before)
        self._assert_no_orphan_or_mismatched_anchors(
            package=package,
            expected=expected,
            anchors=anchors,
        )
        anchored_by_digest = {
            digest: (event, False) for digest, event in anchors.items()
            if digest in expected
        }
        missing_payloads = tuple(
            expected[digest]
            for digest in sorted(set(expected) - set(anchors))
        )
        try:
            for offset in range(
                0,
                len(missing_payloads),
                MAX_SPINE_APPEND_BATCH,
            ):
                anchored = self.spine.append_unique_many(
                    EVENT_TRADE_RULE_RECOGNITION_RECORDED,
                    missing_payloads[
                        offset:offset + MAX_SPINE_APPEND_BATCH
                    ],
                    unique_payload_fields=("recognition_digest",),
                    ts_ms=moment,
                )
                for event, created in anchored:
                    anchored_by_digest[
                        event.payload["recognition_digest"]
                    ] = (event, created)
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise RuleRecognitionAuditError(
                f"unable to project Recognition batch into Spine: {exc}"
            ) from exc
        if set(anchored_by_digest) != set(expected):
            raise RuleRecognitionAuditError(
                "Spine returned an incomplete Recognition anchor batch"
            )
        statements_after = self.store.list_for_package(package)
        if tuple(item.digest for item in all_statements) != tuple(
            item.digest for item in statements_after
        ):
            raise RuleRecognitionAuditIntegrityError(
                "Recognition statements changed during batch projection"
            )
        results = []
        for store_result in imported:
            statement = store_result.statement
            if statement is None:
                raise RuleRecognitionAuditError(
                    "Recognition batch store returned an empty statement"
                )
            event, anchor_created = anchored_by_digest[statement.digest]
            if event.payload != expected[statement.digest]:
                raise RuleRecognitionAuditIntegrityError(
                    "Recognition batch anchor payload mismatch"
                )
            results.append(
                RuleRecognitionAuditResult(
                    statement=statement,
                    event=event,
                    store_created=not store_result.duplicate,
                    anchor_created=anchor_created,
                )
            )
        return tuple(results)

    def reconcile(
        self,
        *,
        package: RulePackage,
        limit: int = DEFAULT_RULE_RECOGNITION_RECONCILE_LIMIT,
        observed_at_ms: int | None = None,
    ) -> RuleRecognitionAuditReconciliation:
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_RULE_RECOGNITION_RECONCILE_LIMIT
        ):
            raise ValueError(
                "limit must be an integer in 1.."
                f"{MAX_RULE_RECOGNITION_RECONCILE_LIMIT}"
            )
        moment = _observed_at_ms(
            current_time_ms()
            if observed_at_ms is None
            else observed_at_ms
        )
        statements = sorted(
            self.store.list_for_package(package),
            key=lambda item: item.digest,
        )
        spine_events = self._verified_spine_events()
        self._assert_proof_imports_complete_and_present(
            spine_events,
            package=package,
            statement_digests={item.digest for item in statements},
        )
        anchors = self._anchor_index(spine_events)
        expected = self._expected_payloads(
            statements,
            package=package,
        )
        self._assert_no_orphan_or_mismatched_anchors(
            package=package,
            expected=expected,
            anchors=anchors,
        )
        pending = [
            statement
            for statement in statements
            if statement.digest not in anchors
        ]
        batch = pending[:limit]
        anchored = 0
        verified_anchored = len(statements) - len(pending)
        failed = 0
        attempted = 0
        completed = 0
        blocked_digest: str | None = None
        error_code: str | None = None
        error_message: str | None = None
        for statement in batch:
            attempted += 1
            try:
                _event, created = self._anchor(
                    statement,
                    package=package,
                    anchors=anchors,
                    observed_at_ms=moment,
                )
            except RuleRecognitionAuditError as exc:
                failed += 1
                blocked_digest = statement.digest
                error_code = (
                    "integrity-error"
                    if isinstance(
                        exc,
                        RuleRecognitionAuditIntegrityError,
                    )
                    else "spine-anchor-failed"
                )
                error_message = str(exc)
                break
            anchored += int(created)
            verified_anchored += int(not created)
            completed += 1
        remaining = len(pending) - completed
        return RuleRecognitionAuditReconciliation(
            scanned=attempted,
            anchored=anchored,
            verified_anchored=verified_anchored,
            failed=failed,
            remaining=remaining,
            has_more=remaining > 0,
            blocked_digest=blocked_digest,
            error_code=error_code,
            error_message=error_message,
        )

    def verify_anchors(
        self,
        *,
        package: RulePackage,
    ) -> tuple[bool, str]:
        """Cross-check local CAS statements and Spine anchors."""

        try:
            statements = self.store.list_for_package(package)
            expected = self._expected_payloads(
                statements,
                package=package,
            )
            spine_events = self._verified_spine_events()
            self._assert_proof_imports_complete_and_present(
                spine_events,
                package=package,
                statement_digests=set(expected),
            )
            anchors = self._anchor_index(spine_events)
        except (
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
        ) as exc:
            return False, str(exc)
        relevant = {
            digest: event
            for digest, event in anchors.items()
            if event.payload.get("package_digest") == package.digest
        }
        for digest, payload in expected.items():
            event = relevant.get(digest)
            if event is None:
                return False, f"missing Recognition anchor {digest}"
            if event.payload != payload:
                return False, f"Recognition anchor mismatch {digest}"
        extra = sorted(set(relevant) - set(expected))
        if extra:
            return False, f"Recognition anchor has no local statement {extra[0]}"
        return True, "ok"

    def verified_statements(
        self,
        *,
        package: RulePackage,
    ) -> tuple[TradeRuleRecognition, ...]:
        """Return one CAS snapshot proven against one Spine snapshot."""

        statements = self.store.list_for_package(package)
        expected = self._expected_payloads(statements, package=package)
        spine_events = self._verified_spine_events()
        self._assert_proof_imports_complete_and_present(
            spine_events,
            package=package,
            statement_digests=set(expected),
        )
        anchors = self._anchor_index(spine_events)
        self._assert_no_orphan_or_mismatched_anchors(
            package=package,
            expected=expected,
            anchors=anchors,
        )
        relevant = {
            digest: event
            for digest, event in anchors.items()
            if event.payload.get("package_digest") == package.digest
        }
        missing = sorted(set(expected) - set(relevant))
        if missing:
            raise RuleRecognitionAuditIntegrityError(
                f"missing Recognition anchor {missing[0]}"
            )
        statements_after_verification = self.store.list_for_package(package)
        if tuple(item.digest for item in statements) != tuple(
            item.digest for item in statements_after_verification
        ):
            raise RuleRecognitionAuditIntegrityError(
                "Recognition statements changed during projection"
            )
        return statements


__all__ = [
    "DEFAULT_RULE_RECOGNITION_RECONCILE_LIMIT",
    "EVENT_TRADE_RULE_RECOGNITION_RECORDED",
    "MAX_RULE_RECOGNITION_RECONCILE_LIMIT",
    "RULE_RECOGNITION_AUDIT_PROTOCOL_VERSION",
    "RuleRecognitionAuditCoordinator",
    "RuleRecognitionAuditError",
    "RuleRecognitionAuditIntegrityError",
    "RuleRecognitionAuditReconciliation",
    "RuleRecognitionAuditResult",
    "rule_recognition_audit_payload",
    "validate_rule_recognition_audit_binding",
    "validate_rule_recognition_audit_payload",
]
