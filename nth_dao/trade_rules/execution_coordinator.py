"""Mandatory CAS issuance path for Trade Execution Receipts."""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, NoReturn

from nth_dao.spine import SignedEventLog, SpineEvent
from nth_dao.trade_rules.agreement import DEFAULT_CLOCK_SKEW_SECONDS
from nth_dao.trade_rules.agreement_order import TradeOrder
from nth_dao.trade_rules.execution_audit import (
    EVENT_TRADE_EXECUTION_RECORDED,
    EXECUTION_AUDIT_ERROR_RECEIPT_CONFLICT,
    EXECUTION_AUDIT_ERROR_RECEIPT_STORE,
    EXECUTION_AUDIT_ERROR_SPINE,
    TradeExecutionAuditBusy,
    TradeExecutionAuditError,
    TradeExecutionAuditOutbox,
    TradeExecutionAuditRecord,
    execution_audit_payload,
    validate_execution_audit_payload,
)
from nth_dao.trade_rules.execution_adapter import (
    TradeExecutionAdapterPolicy,
    TradeExecutionAdapterResolver,
)
from nth_dao.trade_rules.execution_receipt import (
    TradeExecutionReceipt,
    _create_trade_execution_receipt,
    execution_receipt_digest,
)
from nth_dao.trade_rules.execution_receipt_store import (
    TradeExecutionReceiptConflict,
    TradeExecutionReceiptStore,
    TradeExecutionReceiptStoreError,
)
from nth_dao.trade_rules.execution_content import (
    TradeExecutionContentResolver,
    TradeExecutionSchemaValidator,
)
from nth_dao.trade_rules.negotiation import (
    RulePackageResolver,
    RuleResolutionPolicy,
)


@dataclass(frozen=True)
class TradeExecutionAuditResult:
    record: TradeExecutionAuditRecord
    receipt: TradeExecutionReceipt
    prepared_created: bool
    store_created: bool
    anchor_created: bool


@dataclass(frozen=True)
class TradeExecutionAuditReconciliation:
    scanned: int
    anchored: int
    verified_anchored: int
    blocked: int
    verified_blocked: int
    failed: int
    next_cursor: str | None
    has_more: bool


class TradeExecutionCoordinator:
    """Issue through write-ahead audit, Receipt CAS, then signed Spine."""

    def __init__(
        self,
        store: TradeExecutionReceiptStore,
        audit_outbox: TradeExecutionAuditOutbox,
        spine: SignedEventLog,
    ) -> None:
        if not isinstance(store, TradeExecutionReceiptStore):
            raise TypeError("store must be a TradeExecutionReceiptStore")
        if not isinstance(audit_outbox, TradeExecutionAuditOutbox):
            raise TypeError(
                "audit_outbox must be a TradeExecutionAuditOutbox"
            )
        if not isinstance(spine, SignedEventLog):
            raise TypeError("spine must be a SignedEventLog")
        self.store = store
        self.audit_outbox = audit_outbox
        self.spine = spine

    def _anchor_index(
        self,
    ) -> tuple[dict[str, SpineEvent], dict[str, SpineEvent]]:
        try:
            events = self.spine.verified_snapshot()
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise TradeExecutionAuditError(
                f"Spine integrity check failed: {exc}"
            ) from exc
        by_execution_id: dict[str, SpineEvent] = {}
        by_receipt_digest: dict[str, SpineEvent] = {}
        for event in events:
            if event.type != EVENT_TRADE_EXECUTION_RECORDED:
                continue
            payload = validate_execution_audit_payload(event.payload)
            execution_id = payload["execution_id"]
            receipt_digest = payload["receipt_digest"]
            if (
                execution_id in by_execution_id
                or receipt_digest in by_receipt_digest
            ):
                raise TradeExecutionAuditError(
                    "Spine contains duplicate or conflicting execution anchors"
                )
            by_execution_id[execution_id] = event
            by_receipt_digest[receipt_digest] = event
        return by_execution_id, by_receipt_digest

    @staticmethod
    def _find_anchor(
        receipt: TradeExecutionReceipt,
        order: TradeOrder,
        anchor_index: tuple[dict[str, SpineEvent], dict[str, SpineEvent]],
    ) -> SpineEvent | None:
        expected = execution_audit_payload(receipt, order=order)
        by_execution_id, by_receipt_digest = anchor_index
        by_id = by_execution_id.get(receipt.execution_id)
        by_digest = by_receipt_digest.get(expected["receipt_digest"])
        if (
            by_id is not None
            and by_digest is not None
            and by_id != by_digest
        ):
            raise TradeExecutionAuditError(
                "Spine contains a conflicting execution anchor index"
            )
        event = by_id or by_digest
        if event is not None and event.payload != expected:
            raise TradeExecutionAuditError(
                "Spine contains a conflicting execution anchor"
            )
        return event

    @staticmethod
    def _completed_at_ms(receipt: TradeExecutionReceipt) -> int:
        value = receipt.to_dict()["completed_at"]
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (AttributeError, ValueError) as exc:
            raise TradeExecutionAuditError(
                "Receipt completed_at is invalid"
            ) from exc
        return int(parsed.timestamp() * 1000)

    def _verify_blocked_locked(
        self,
        record: TradeExecutionAuditRecord,
        *,
        now_ms: int,
        anchor_index: tuple[dict[str, SpineEvent], dict[str, SpineEvent]],
    ) -> TradeExecutionAuditRecord:
        receipt = record.receipt
        order = record.order
        status = self.store.conflict_status(
            receipt.execution_id,
            order=order,
        )
        if (
            not status.has_conflict
            or status.marker_candidate_digest is None
            or status.marker_candidate_digest == record.receipt_digest
            or record.receipt_digest not in status.retained_receipt_digests
        ):
            raise TradeExecutionAuditError(
                "blocked execution audit has no matching CAS conflict evidence"
            )
        event = self._find_anchor(receipt, order, anchor_index)
        if record.event_id:
            if event is None or event.event_id != record.event_id:
                raise TradeExecutionAuditError(
                    "blocked execution audit event_id does not match Spine"
                )
        elif event is not None:
            record = self.audit_outbox._transition_locked(
                record.execution_id,
                expected=frozenset({"blocked"}),
                status="blocked",
                now_ms=now_ms,
                event_id=event.event_id,
                last_error=EXECUTION_AUDIT_ERROR_RECEIPT_CONFLICT,
            )
        return record

    def _reconcile_locked(
        self,
        execution_id: str,
        *,
        now_ms: int,
        prepared_created: bool,
        anchor_index: tuple[dict[str, SpineEvent], dict[str, SpineEvent]],
    ) -> TradeExecutionAuditResult:
        record = self.audit_outbox._get_locked(execution_id)
        if record is None:
            raise TradeExecutionAuditError(
                "execution audit record disappeared"
            )
        receipt = record.receipt
        order = record.order
        effective_now_ms = max(now_ms, record.updated_at_ms)
        if effective_now_ms < self._completed_at_ms(receipt):
            raise TradeExecutionAuditError(
                "execution audit time precedes Receipt completion"
            )
        store_created = False
        anchor_created = False
        if record.status == "blocked":
            self._verify_blocked_locked(
                record,
                now_ms=now_ms,
                anchor_index=anchor_index,
            )
            raise TradeExecutionReceiptConflict(
                "execution audit is blocked by Receipt equivocation"
            )
        if record.status in {"prepared", "stored", "anchored"}:
            try:
                existing = self.store.get(
                    receipt.execution_id,
                    order=order,
                )
                store_created = existing is None
                stored = self.store.put(receipt, order=order)
                if stored.canonical_bytes != receipt.canonical_bytes:
                    raise TradeExecutionReceiptConflict(
                        "Receipt CAS returned different signed bytes"
                    )
            except TradeExecutionReceiptConflict:
                self.audit_outbox._transition_locked(
                    execution_id,
                    expected=frozenset({record.status}),
                    status="blocked",
                    now_ms=effective_now_ms,
                    last_error=EXECUTION_AUDIT_ERROR_RECEIPT_CONFLICT,
                    increment_attempts=True,
                )
                raise
            except (OSError, RuntimeError, TypeError, ValueError):
                if record.status != "anchored":
                    self.audit_outbox._transition_locked(
                        execution_id,
                        expected=frozenset({record.status}),
                        status=record.status,
                        now_ms=effective_now_ms,
                        last_error=EXECUTION_AUDIT_ERROR_RECEIPT_STORE,
                        increment_attempts=True,
                    )
                raise
        if record.status == "anchored":
            event = self._find_anchor(receipt, order, anchor_index)
            if event is None or event.event_id != record.event_id:
                raise TradeExecutionAuditError(
                    "anchored execution record does not match Spine"
                )
            return TradeExecutionAuditResult(
                record=record,
                receipt=receipt,
                prepared_created=prepared_created,
                store_created=store_created,
                anchor_created=False,
            )
        if record.status == "prepared":
            record = self.audit_outbox._transition_locked(
                execution_id,
                expected=frozenset({"prepared"}),
                status="stored",
                now_ms=effective_now_ms,
            )
        if record.status == "stored":
            try:
                event = self._find_anchor(receipt, order, anchor_index)
                if event is None:
                    event, anchor_created = self.spine.append_unique(
                        EVENT_TRADE_EXECUTION_RECORDED,
                        execution_audit_payload(receipt, order=order),
                        unique_payload_fields=(
                            "execution_id",
                            "receipt_digest",
                        ),
                        ts_ms=effective_now_ms,
                    )
                    anchor_index[0][receipt.execution_id] = event
                    anchor_index[1][record.receipt_digest] = event
            except (OSError, RuntimeError, TypeError, ValueError):
                self.audit_outbox._transition_locked(
                    execution_id,
                    expected=frozenset({"stored"}),
                    status="stored",
                    now_ms=effective_now_ms,
                    last_error=EXECUTION_AUDIT_ERROR_SPINE,
                    increment_attempts=True,
                )
                raise
            record = self.audit_outbox._transition_locked(
                execution_id,
                expected=frozenset({"stored"}),
                status="anchored",
                now_ms=effective_now_ms,
                event_id=event.event_id,
            )
        if record.status != "anchored":
            raise TradeExecutionAuditError(
                f"execution audit stopped in state {record.status!r}"
            )
        return TradeExecutionAuditResult(
            record=record,
            receipt=receipt,
            prepared_created=prepared_created,
            store_created=store_created,
            anchor_created=anchor_created,
        )

    def _retain_and_block_conflict(
        self,
        candidate: TradeExecutionReceipt,
        *,
        order: TradeOrder | dict[str, Any],
        now_ms: int,
    ) -> NoReturn:
        store_error: TradeExecutionReceiptStoreError | None = None
        try:
            self.store.put(candidate, order=order)
        except TradeExecutionReceiptStoreError as exc:
            store_error = exc
        else:
            raise TradeExecutionAuditError(
                "audit conflict disagrees with Receipt CAS"
            )
        if not isinstance(store_error, TradeExecutionReceiptConflict):
            try:
                status = self.store.conflict_status(
                    candidate.execution_id,
                    order=order,
                )
            except TradeExecutionReceiptStoreError as exc:
                raise TradeExecutionAuditError(
                    "Receipt CAS failed before conflict evidence could be "
                    "confirmed"
                ) from exc
            candidate_digest = execution_receipt_digest(
                candidate,
                order=order,
            )
            if (
                not status.has_conflict
                or status.marker_candidate_digest != candidate_digest
            ):
                raise TradeExecutionAuditError(
                    "Receipt CAS failed without retaining conflict evidence"
                ) from store_error
        try:
            with self.audit_outbox.acquire_reconcile():
                current = self.audit_outbox._get_locked(
                    candidate.execution_id
                )
                if current is None:
                    raise TradeExecutionAuditError(
                        "conflicting execution audit record disappeared"
                    )
                if current.status != "blocked":
                    self.audit_outbox._transition_locked(
                        candidate.execution_id,
                        expected=frozenset({current.status}),
                        status="blocked",
                        now_ms=now_ms,
                        last_error=EXECUTION_AUDIT_ERROR_RECEIPT_CONFLICT,
                        increment_attempts=True,
                    )
        except TimeoutError as exc:
            raise TradeExecutionAuditBusy(
                "execution audit reconciliation is busy"
            ) from exc
        raise TradeExecutionReceiptConflict(
            "execution audit ID has different signed bytes; "
            "Receipt CAS retained conflict evidence"
        ) from store_error

    def issue(
        self,
        identity: Any,
        *,
        order: TradeOrder | dict[str, Any],
        package_resolver: RulePackageResolver,
        executor_policy: RuleResolutionPolicy,
        adapter_resolver: TradeExecutionAdapterResolver,
        adapter_policy: TradeExecutionAdapterPolicy,
        content_resolver: TradeExecutionContentResolver,
        schema_validator: TradeExecutionSchemaValidator,
        executor_role: str,
        adapter_id: str,
        adapter_version: str,
        adapter_digest: str,
        execution_mode: str,
        operation_id: str,
        operation_input: dict[str, Any],
        outcome: str,
        result: dict[str, Any],
        evidence: list[dict[str, Any]]
        | tuple[dict[str, Any], ...] = (),
        started_at: str,
        completed_at: str,
        now: datetime | None = None,
        clock_skew_seconds: float = DEFAULT_CLOCK_SKEW_SECONDS,
    ) -> TradeExecutionReceipt:
        candidate = _create_trade_execution_receipt(
            identity,
            order=order,
            package_resolver=package_resolver,
            executor_policy=executor_policy,
            adapter_resolver=adapter_resolver,
            adapter_policy=adapter_policy,
            content_resolver=content_resolver,
            schema_validator=schema_validator,
            executor_role=executor_role,
            adapter_id=adapter_id,
            adapter_version=adapter_version,
            adapter_digest=adapter_digest,
            execution_mode=execution_mode,
            operation_id=operation_id,
            operation_input=operation_input,
            outcome=outcome,
            result=result,
            evidence=evidence,
            started_at=started_at,
            completed_at=completed_at,
            now=now,
            clock_skew_seconds=clock_skew_seconds,
        )
        audit_now_ms = (
            int(now.timestamp() * 1000)
            if isinstance(now, datetime)
            else time.time_ns() // 1_000_000
        )
        try:
            prepared, created = self.audit_outbox.prepare(
                candidate,
                order=order,
                now_ms=audit_now_ms,
            )
        except TradeExecutionReceiptConflict:
            self._retain_and_block_conflict(
                candidate,
                order=order,
                now_ms=audit_now_ms,
            )
        try:
            with self.audit_outbox.acquire_reconcile():
                anchor_index = self._anchor_index()
                result = self._reconcile_locked(
                    prepared.execution_id,
                    now_ms=audit_now_ms,
                    prepared_created=created,
                    anchor_index=anchor_index,
                )
        except TimeoutError as exc:
            raise TradeExecutionAuditBusy(
                "execution audit reconciliation is busy"
            ) from exc
        return result.receipt

    def reconcile(
        self,
        *,
        limit: int = 100,
        now_ms: int | None = None,
        after_execution_id: str | None = None,
    ) -> TradeExecutionAuditReconciliation:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise ValueError("limit must be a positive integer")
        if after_execution_id is not None:
            self.audit_outbox._path(after_execution_id)
        moment = (
            time.time_ns() // 1_000_000
            if now_ms is None
            else now_ms
        )
        if (
            isinstance(moment, bool)
            or not isinstance(moment, int)
            or moment < 0
        ):
            raise ValueError("now_ms must be a non-negative integer")
        scanned = 0
        anchored = 0
        verified_anchored = 0
        blocked = 0
        verified_blocked = 0
        failed = 0
        try:
            with self.audit_outbox.acquire_reconcile():
                anchor_index = self._anchor_index()
                records, has_more = (
                    self.audit_outbox._reconcile_batch_locked(
                        limit=limit,
                        after_execution_id=after_execution_id,
                    )
                )
                for record in records:
                    scanned += 1
                    if record.status in {"prepared", "stored"}:
                        try:
                            self._reconcile_locked(
                                record.execution_id,
                                now_ms=moment,
                                prepared_created=False,
                                anchor_index=anchor_index,
                            )
                            anchored += 1
                        except TradeExecutionReceiptConflict:
                            blocked += 1
                        except (
                            OSError,
                            RuntimeError,
                            TypeError,
                            ValueError,
                        ):
                            failed += 1
                    elif record.status == "anchored":
                        try:
                            self._reconcile_locked(
                                record.execution_id,
                                now_ms=moment,
                                prepared_created=False,
                                anchor_index=anchor_index,
                            )
                            verified_anchored += 1
                        except (
                            OSError,
                            RuntimeError,
                            TypeError,
                            ValueError,
                        ):
                            failed += 1
                    else:
                        try:
                            self._verify_blocked_locked(
                                record,
                                now_ms=moment,
                                anchor_index=anchor_index,
                            )
                            blocked += 1
                            verified_blocked += 1
                        except (
                            OSError,
                            RuntimeError,
                            TypeError,
                            ValueError,
                        ):
                            failed += 1
        except TimeoutError as exc:
            raise TradeExecutionAuditBusy(
                "execution audit reconciliation is busy"
            ) from exc
        return TradeExecutionAuditReconciliation(
            scanned=scanned,
            anchored=anchored,
            verified_anchored=verified_anchored,
            blocked=blocked,
            verified_blocked=verified_blocked,
            failed=failed,
            next_cursor=(
                records[-1].execution_id
                if records and has_more
                else None
            ),
            has_more=has_more,
        )


__all__ = [
    "TradeExecutionAuditReconciliation",
    "TradeExecutionAuditResult",
    "TradeExecutionCoordinator",
]
