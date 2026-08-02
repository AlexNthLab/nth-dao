"""Recoverable signed Spine projection for retained Trade Proposals."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Any

from nth_dao.did_key import is_did_key
from nth_dao.spine import SignedEventLog, SpineEvent
from nth_dao.trade_rules.agreement import TradeProposal, proposal_digest
from nth_dao.trade_rules.agreement_inbox import (
    TradeProposalInbox,
    TradeProposalInboxBusy,
    TradeProposalInboxCapacity,
    TradeProposalInboxCorruption,
    TradeProposalInboxEntry,
    TradeProposalInboxRejected,
    TradeProposalInboxResult,
)
from nth_dao.trade_rules.agreement_transport import (
    TradeProposalDelivery,
    TradeProposalDeliveryRejected,
    create_trade_proposal_intake_receipt,
    trade_proposal_intake_receipt_digest,
    verify_trade_proposal_delivery,
    verify_trade_proposal_intake_receipt,
)
from nth_dao.trade_rules.agreement import verify_trade_proposal_under_local_state

EVENT_TRADE_PROPOSAL_RECEIVED = "trade.agreement.proposal.received"
EVENT_TRADE_PROPOSAL_ARCHIVED = "trade.agreement.proposal.archived"
PROPOSAL_RECEIVED_AUDIT_KIND = "nth.dao.trade.proposal-received"
PROPOSAL_RECEIVED_AUDIT_PROTOCOL_VERSION = "1"
_AUDIT_FIELDS = frozenset(
    {
        "kind",
        "protocol_version",
        "proposal_digest",
        "offer_digest",
        "maker_did",
        "taker_did",
        "proposal_created_at",
        "proposal_not_after",
        "status",
    }
)
_ARCHIVE_AUDIT_FIELDS = frozenset(
    {
        "kind",
        "protocol_version",
        "proposal_digest",
        "intake_receipt_digest",
        "receiver_did",
        "archived_at",
        "reason",
    }
)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TIMESTAMP = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?:\.(\d{1,9}))?Z$"
)


class TradeProposalAuditError(RuntimeError):
    """Proposal retention and its signed Spine projection are inconsistent."""


def proposal_received_audit_payload(
    proposal: TradeProposal | dict[str, Any],
) -> dict[str, Any]:
    verified = (
        proposal
        if isinstance(proposal, TradeProposal)
        else TradeProposal.from_dict(proposal)
    )
    document = verified.to_dict()
    return {
        "kind": PROPOSAL_RECEIVED_AUDIT_KIND,
        "protocol_version": PROPOSAL_RECEIVED_AUDIT_PROTOCOL_VERSION,
        "proposal_digest": proposal_digest(verified),
        "offer_digest": document["offer_digest"],
        "maker_did": document["maker_did"],
        "taker_did": document["taker_did"],
        "proposal_created_at": document["created_at"],
        "proposal_not_after": document["not_after"],
        "status": "retained-unaccepted",
    }


def validate_proposal_received_audit_payload(
    payload: Any,
    *,
    proposal: TradeProposal | dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != _AUDIT_FIELDS:
        raise TradeProposalAuditError(
            "Proposal received Spine payload has missing or unknown fields"
        )
    expected_literals = {
        "kind": PROPOSAL_RECEIVED_AUDIT_KIND,
        "protocol_version": PROPOSAL_RECEIVED_AUDIT_PROTOCOL_VERSION,
        "status": "retained-unaccepted",
    }
    for field, expected in expected_literals.items():
        if payload[field] != expected:
            raise TradeProposalAuditError(
                f"Proposal received Spine payload {field} is invalid"
            )
    for field in _AUDIT_FIELDS - expected_literals.keys():
        if not isinstance(payload[field], str) or not payload[field]:
            raise TradeProposalAuditError(
                f"Proposal received Spine payload {field} is invalid"
            )
    for field in ("proposal_digest", "offer_digest"):
        if _DIGEST.fullmatch(payload[field]) is None:
            raise TradeProposalAuditError(
                f"Proposal received Spine payload {field} is invalid"
            )
    for field in ("maker_did", "taker_did"):
        if not is_did_key(payload[field]):
            raise TradeProposalAuditError(
                f"Proposal received Spine payload {field} is invalid"
            )
    if payload["maker_did"] == payload["taker_did"]:
        raise TradeProposalAuditError(
            "Proposal received Spine payload parties are invalid"
        )
    parsed_times: list[tuple[datetime, int]] = []
    for field in ("proposal_created_at", "proposal_not_after"):
        match = _TIMESTAMP.fullmatch(payload[field])
        if match is None:
            raise TradeProposalAuditError(
                f"Proposal received Spine payload {field} is invalid"
            )
        try:
            base = datetime.strptime(
                match.group(1),
                "%Y-%m-%dT%H:%M:%S",
            )
        except ValueError as exc:
            raise TradeProposalAuditError(
                f"Proposal received Spine payload {field} is invalid"
            ) from exc
        parsed_times.append(
            (base, int((match.group(2) or "").ljust(9, "0") or "0"))
        )
    if parsed_times[1] <= parsed_times[0]:
        raise TradeProposalAuditError(
            "Proposal received Spine payload time range is invalid"
        )
    if proposal is not None:
        expected = proposal_received_audit_payload(proposal)
        if payload != expected:
            raise TradeProposalAuditError(
                "Proposal received Spine payload does not bind the Proposal"
            )
    return dict(payload)


@dataclass(frozen=True)
class TradeProposalAuditResult:
    delivery: TradeProposalDelivery
    inbox: TradeProposalInboxResult
    event: SpineEvent
    anchor_created: bool


@dataclass(frozen=True)
class TradeProposalAuditFailure:
    digest: str
    error_code: str
    message: str


@dataclass(frozen=True)
class TradeProposalAuditMetrics:
    active_records: int
    pending_anchors: int
    oldest_pending_age_seconds: float | None
    measured_at: str


@dataclass(frozen=True)
class TradeProposalAuditReconciliation:
    scanned: int
    anchored: int
    verified_anchored: int
    failed: int
    failures: tuple[TradeProposalAuditFailure, ...]
    next_cursor: str | None
    has_more: bool

    @property
    def failure_digests(self) -> tuple[str, ...]:
        """Compatibility projection for pre-structured API consumers."""

        return tuple(failure.digest for failure in self.failures)


@dataclass(frozen=True)
class TradeProposalArchiveResult:
    scanned: int
    archived: int
    already_anchored: int
    failure_digests: tuple[str, ...]


@dataclass(frozen=True)
class TradeProposalAuditView:
    proposal: TradeProposal
    event: SpineEvent | None

    @property
    def audit_verified(self) -> bool:
        return self.event is not None


class TradeProposalAuditCoordinator:
    """Verify delivery, persist Proposal CAS, then project one Spine event."""

    def __init__(
        self,
        inbox: TradeProposalInbox,
        spine: SignedEventLog,
        receiver_identity: Any,
    ) -> None:
        if not isinstance(inbox, TradeProposalInbox):
            raise TypeError("inbox must be a TradeProposalInbox")
        if not isinstance(spine, SignedEventLog):
            raise TypeError("spine must be a SignedEventLog")
        if receiver_identity is None or not getattr(
            receiver_identity, "can_sign", False
        ):
            raise TypeError("receiver_identity must be able to sign")
        receiver_did = receiver_identity.as_did()
        spine_identity = getattr(spine, "_identity", None)
        if spine_identity is None or spine_identity.as_did() != receiver_did:
            raise ValueError(
                "Spine signer must match Proposal intake receiver identity"
            )
        self.inbox = inbox
        self.spine = spine
        self.receiver_identity = receiver_identity
        self.receiver_did = receiver_did

    @staticmethod
    def _failure(
        digest: str,
        exc: BaseException,
    ) -> TradeProposalAuditFailure:
        if isinstance(exc, TradeProposalInboxBusy | TimeoutError):
            code = "inbox-busy"
        elif isinstance(exc, TradeProposalInboxCorruption):
            code = "inbox-corruption"
        elif isinstance(exc, TradeProposalAuditError):
            code = "audit-integrity"
        elif isinstance(exc, OSError):
            code = "io-error"
        elif isinstance(exc, (TypeError, ValueError)):
            code = "validation-error"
        else:
            code = "runtime-error"
        message = str(exc).strip() or type(exc).__name__
        return TradeProposalAuditFailure(
            digest=digest,
            error_code=code,
            message=message[:300],
        )

    def _verified_entry(self, digest: str) -> TradeProposalInboxEntry | None:
        entry = self.inbox.get_entry(digest)
        if entry is None:
            return None
        ok, reason = verify_trade_proposal_intake_receipt(
            entry.intake_receipt,
            delivery=entry.delivery,
            receiver_did=self.receiver_did,
        )
        if not ok:
            raise TradeProposalAuditError(
                f"Proposal intake receipt is not local: {reason}"
            )
        return entry

    def _find_anchor(self, payload: dict[str, Any]) -> SpineEvent | None:
        try:
            events = self.spine.verified_snapshot()
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise TradeProposalAuditError(
                f"Spine integrity check failed: {exc}"
            ) from exc
        matches = [
            event
            for event in events
            if event.type == EVENT_TRADE_PROPOSAL_RECEIVED
            and event.payload.get("proposal_digest")
            == payload["proposal_digest"]
        ]
        if len(matches) > 1:
            raise TradeProposalAuditError(
                "Spine contains duplicate Proposal received anchors"
            )
        if matches and matches[0].payload != payload:
            raise TradeProposalAuditError(
                "Spine contains a conflicting Proposal received anchor"
            )
        return matches[0] if matches else None

    def _anchor_index(self) -> dict[str, SpineEvent]:
        try:
            events = self.spine.verified_snapshot()
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise TradeProposalAuditError(
                f"Spine integrity check failed: {exc}"
            ) from exc
        anchors: dict[str, SpineEvent] = {}
        for event in events:
            if event.type != EVENT_TRADE_PROPOSAL_RECEIVED:
                continue
            digest = event.payload.get("proposal_digest")
            if not isinstance(digest, str) or not digest:
                raise TradeProposalAuditError(
                    "Spine contains an invalid Proposal received anchor"
                )
            if digest in anchors:
                raise TradeProposalAuditError(
                    "Spine contains duplicate Proposal received anchors"
                )
            validate_proposal_received_audit_payload(event.payload)
            anchors[digest] = event
        return anchors

    def _anchor(
        self,
        proposal: TradeProposal,
    ) -> tuple[SpineEvent, bool]:
        payload = proposal_received_audit_payload(proposal)
        validate_proposal_received_audit_payload(
            payload,
            proposal=proposal,
        )
        try:
            return self.spine.append_unique(
                EVENT_TRADE_PROPOSAL_RECEIVED,
                payload,
                unique_payload_fields=("proposal_digest",),
            )
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            # append_unique may have committed before its caller lost the
            # acknowledgement. Re-read the verified chain before reporting a
            # failure so retries remain exactly once.
            try:
                recovered = self._find_anchor(payload)
            except TradeProposalAuditError as recovery_exc:
                raise recovery_exc from exc
            if recovered is not None:
                return recovered, False
            raise TradeProposalAuditError(
                f"unable to project retained Proposal into Spine: {exc}"
            ) from exc

    def receive(
        self,
        delivery: TradeProposalDelivery | dict[str, Any],
        *,
        recipient_did: str,
        offer_resolver: Any,
        rule_resolver: Any,
        at: datetime | None = None,
    ) -> TradeProposalAuditResult:
        verified_delivery = (
            delivery
            if isinstance(delivery, TradeProposalDelivery)
            else TradeProposalDelivery.from_dict(delivery)
        )
        ok, reason = verify_trade_proposal_delivery(
            verified_delivery,
            recipient_did=recipient_did,
            at=at,
        )
        if not ok:
            raise TradeProposalDeliveryRejected(reason)
        delivery_document = verified_delivery.to_dict()
        digest = delivery_document["proposal_digest"]
        existing = self._verified_entry(digest)
        if existing is not None:
            if (
                existing.proposal.canonical_bytes
                != verified_delivery.proposal.canonical_bytes
            ):
                raise TradeProposalAuditError(
                    "committed Proposal content address has conflicting bytes"
                )
            retained = TradeProposalInboxResult(
                digest=digest,
                appended=False,
                proposal=existing.proposal,
                delivery=existing.delivery,
                intake_receipt=existing.intake_receipt,
            )
        else:
            proposal = verified_delivery.proposal
            replay_ok, replay_reason = verify_trade_proposal_under_local_state(
                proposal,
                offer_resolver,
                rule_resolver,
                at=at,
            )
            if not replay_ok:
                # A concurrent receiver may have committed the same Proposal
                # while local Offer state changed. Return that durable result
                # instead of violating retry idempotency.
                concurrent = self._verified_entry(digest)
                if concurrent is None:
                    raise TradeProposalInboxRejected(replay_reason)
                retained = TradeProposalInboxResult(
                    digest=digest,
                    appended=False,
                    proposal=concurrent.proposal,
                    delivery=concurrent.delivery,
                    intake_receipt=concurrent.intake_receipt,
                )
            else:
                received_moment = at or datetime.now(timezone.utc)
                if (
                    received_moment.tzinfo is None
                    or received_moment.utcoffset() is None
                ):
                    raise TradeProposalDeliveryRejected(
                        "receive time must be timezone-aware"
                    )
                received_at = (
                    received_moment.astimezone(timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z")
                )
                intake_receipt = create_trade_proposal_intake_receipt(
                    self.receiver_identity,
                    delivery=verified_delivery,
                    received_at=received_at,
                )
                try:
                    retained = self.inbox.put(
                        verified_delivery, intake_receipt
                    )
                except TradeProposalInboxCapacity:
                    # A bounded active inbox must not become permanently full.
                    # Archive signed expired records and retry exactly once.
                    archive = self.archive_expired(
                        at=received_moment,
                        limit=1_000,
                    )
                    if archive.archived == 0:
                        raise
                    retained = self.inbox.put(
                        verified_delivery, intake_receipt
                    )
        event, anchor_created = self._anchor(retained.proposal)
        return TradeProposalAuditResult(
            delivery=verified_delivery,
            inbox=retained,
            event=event,
            anchor_created=anchor_created,
        )

    def archive_expired(
        self,
        *,
        at: datetime | None = None,
        limit: int = 1_000,
    ) -> TradeProposalArchiveResult:
        """Sign archive tombstones, then remove expired records from active CAS."""

        moment = at or datetime.now(timezone.utc)
        if moment.tzinfo is None or moment.utcoffset() is None:
            raise ValueError("at must be a timezone-aware datetime")
        archived_at = (
            moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        )
        digests = self.inbox.list_expired_digests(at=moment, limit=limit)
        candidates: list[tuple[str, dict[str, Any]]] = []
        failures: list[str] = []
        for digest in digests:
            try:
                entry = self._verified_entry(digest)
                if entry is None:
                    raise TradeProposalAuditError(
                        "Proposal disappeared during archive preparation"
                    )
                payload = {
                    "kind": "nth.dao.trade.proposal-archived",
                    "protocol_version": "1",
                    "proposal_digest": digest,
                    "intake_receipt_digest": (
                        trade_proposal_intake_receipt_digest(
                            entry.intake_receipt
                        )
                    ),
                    "receiver_did": self.receiver_did,
                    "archived_at": archived_at,
                    "reason": "expired",
                }
                if set(payload) != _ARCHIVE_AUDIT_FIELDS:
                    raise TradeProposalAuditError(
                        "Proposal archive payload is malformed"
                    )
                candidates.append((digest, payload))
            except (OSError, RuntimeError, TypeError, ValueError):
                failures.append(digest)
        already_anchored = 0
        if candidates:
            try:
                results = self.spine.append_unique_many(
                    EVENT_TRADE_PROPOSAL_ARCHIVED,
                    tuple(payload for _digest, payload in candidates),
                    unique_payload_fields=("proposal_digest",),
                )
            except (OSError, RuntimeError, TypeError, ValueError):
                failures.extend(digest for digest, _payload in candidates)
                candidates = []
            else:
                already_anchored = sum(
                    1 for _event, created in results if not created
                )
        moved = self.inbox.archive_digests(
            tuple(digest for digest, _payload in candidates)
        )
        moved_set = set(moved)
        failures.extend(
            digest for digest, _payload in candidates if digest not in moved_set
        )
        return TradeProposalArchiveResult(
            scanned=len(digests),
            archived=len(moved),
            already_anchored=already_anchored,
            failure_digests=tuple(failures),
        )

    def list_received(
        self,
        *,
        limit: int = 100,
        after: str | None = None,
    ) -> tuple[tuple[TradeProposalAuditView, ...], str | None]:
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("limit must be an integer")
        if not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        digests = self.inbox.list_digests(limit=limit + 1, after=after)
        page = digests[:limit]
        anchors = self._anchor_index()
        views: list[TradeProposalAuditView] = []
        for digest in page:
            entry = self._verified_entry(digest)
            if entry is None:
                raise TradeProposalAuditError(
                    "Proposal disappeared while building its audit view"
                )
            proposal = entry.proposal
            event = anchors.get(digest)
            if event is not None:
                validate_proposal_received_audit_payload(
                    event.payload,
                    proposal=proposal,
                )
            views.append(TradeProposalAuditView(proposal, event))
        next_cursor = page[-1] if len(digests) > limit and page else None
        return tuple(views), next_cursor

    def get_received(self, digest: str) -> TradeProposalAuditView | None:
        entry = self._verified_entry(digest)
        if entry is None:
            return None
        proposal = entry.proposal
        event = self._anchor_index().get(digest)
        if event is not None:
            validate_proposal_received_audit_payload(
                event.payload,
                proposal=proposal,
            )
        return TradeProposalAuditView(proposal, event)

    def reconcile(
        self,
        *,
        limit: int = 100,
        after: str | None = None,
    ) -> TradeProposalAuditReconciliation:
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("limit must be an integer")
        if not 1 <= limit <= 1_000:
            raise ValueError("limit must be between 1 and 1000")
        digests = self.inbox.list_digests(limit=limit, after=after)
        anchored = 0
        verified_anchored = 0
        failures: list[TradeProposalAuditFailure] = []
        candidates: list[tuple[str, TradeProposal, dict[str, Any]]] = []
        for digest in digests:
            try:
                entry = self._verified_entry(digest)
                if entry is None:
                    raise TradeProposalAuditError(
                        "Proposal disappeared during reconciliation"
                    )
                proposal = entry.proposal
                payload = proposal_received_audit_payload(proposal)
            except (OSError, RuntimeError, TypeError, ValueError) as exc:
                failures.append(self._failure(digest, exc))
            else:
                candidates.append((digest, proposal, payload))
        if candidates:
            try:
                results = self.spine.append_unique_many(
                    EVENT_TRADE_PROPOSAL_RECEIVED,
                    tuple(payload for _digest, _proposal, payload in candidates),
                    unique_payload_fields=("proposal_digest",),
                )
            except (OSError, RuntimeError, TypeError, ValueError) as batch_exc:
                # A failed write may still have committed a valid prefix.
                # Recover it with one verified re-read, never one scan per
                # Proposal.
                try:
                    recovered = self._anchor_index()
                except TradeProposalAuditError as recovery_exc:
                    failures.extend(
                        self._failure(digest, recovery_exc)
                        for digest, _proposal, _payload in candidates
                    )
                else:
                    for digest, proposal, payload in candidates:
                        event = recovered.get(digest)
                        if event is None or event.payload != payload:
                            failures.append(self._failure(digest, batch_exc))
                            continue
                        validate_proposal_received_audit_payload(
                            event.payload,
                            proposal=proposal,
                        )
                        anchored += 1
            else:
                for (_digest, proposal, _payload), (event, created) in zip(
                    candidates,
                    results,
                    strict=True,
                ):
                    validate_proposal_received_audit_payload(
                        event.payload,
                        proposal=proposal,
                    )
                    if created:
                        anchored += 1
                    else:
                        verified_anchored += 1
        next_cursor = digests[-1] if digests else after
        has_more = bool(
            next_cursor
            and self.inbox.list_digests(limit=1, after=next_cursor)
        )
        return TradeProposalAuditReconciliation(
            scanned=len(digests),
            anchored=anchored,
            verified_anchored=verified_anchored,
            failed=len(failures),
            failures=tuple(failures),
            next_cursor=next_cursor,
            has_more=has_more,
        )

    def pending_metrics(
        self,
        *,
        at: datetime | None = None,
    ) -> TradeProposalAuditMetrics:
        """Measure verified active records that still lack a Spine anchor."""

        moment = at or datetime.now(timezone.utc)
        if moment.tzinfo is None or moment.utcoffset() is None:
            raise ValueError("at must be a timezone-aware datetime")
        moment = moment.astimezone(timezone.utc)
        anchors = self._anchor_index()
        active_records = 0
        pending_anchors = 0
        oldest_received: datetime | None = None
        cursor: str | None = None
        while True:
            digests = self.inbox.list_digests(limit=1_000, after=cursor)
            if not digests:
                break
            for digest in digests:
                entry = self._verified_entry(digest)
                if entry is None:
                    raise TradeProposalAuditError(
                        "Proposal disappeared while measuring audit state"
                    )
                active_records += 1
                if digest in anchors:
                    continue
                pending_anchors += 1
                received_text = entry.intake_receipt.to_dict()["received_at"]
                received_at = datetime.fromisoformat(
                    received_text.replace("Z", "+00:00")
                ).astimezone(timezone.utc)
                if oldest_received is None or received_at < oldest_received:
                    oldest_received = received_at
            cursor = digests[-1]
            if len(digests) < 1_000:
                break
        oldest_age = (
            max(0.0, (moment - oldest_received).total_seconds())
            if oldest_received is not None
            else None
        )
        return TradeProposalAuditMetrics(
            active_records=active_records,
            pending_anchors=pending_anchors,
            oldest_pending_age_seconds=oldest_age,
            measured_at=moment.isoformat().replace("+00:00", "Z"),
        )


__all__ = [
    "EVENT_TRADE_PROPOSAL_ARCHIVED",
    "EVENT_TRADE_PROPOSAL_RECEIVED",
    "PROPOSAL_RECEIVED_AUDIT_KIND",
    "PROPOSAL_RECEIVED_AUDIT_PROTOCOL_VERSION",
    "TradeProposalAuditCoordinator",
    "TradeProposalAuditError",
    "TradeProposalAuditFailure",
    "TradeProposalAuditMetrics",
    "TradeProposalAuditReconciliation",
    "TradeProposalAuditResult",
    "TradeProposalAuditView",
    "TradeProposalArchiveResult",
    "proposal_received_audit_payload",
    "validate_proposal_received_audit_payload",
]
