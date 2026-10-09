"""Bridge signed delivery envelopes through the governed PluginHost transport.

This is the single control-plane bridge between ``nth_dao.delivery`` and the
language-neutral ``org.nth-dao.transport.delivery`` capability. It preserves
the Host's revocable binding and InvocationAuthority checks while composing
the durable envelope outbox/inbox around a provider's leased transport queue.

Receive ordering is deliberate: valid leased items are accepted into the
durable DeliveryInbox and permanent rejections are durably quarantined before
the complete provider batch is acknowledged. Storage/capacity failure retains
the lease. A crash before acknowledgement redelivers the same lease; exact
retained bytes become idempotent duplicates, not fresh intake.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from nth_dao.canonical_json import canonical_json
from nth_dao.delivery.acknowledgement import DeliveryAck
from nth_dao.delivery.envelope import (
    MAX_ENVELOPE_BYTES,
    TransportEnvelope,
    TransportEnvelopeRejected,
    validate_envelope,
)
from nth_dao.delivery.inbox import (
    DeliveryInbox,
    DeliveryInboxCacheCorrupt,
    DeliveryInboxFull,
    InboxDecision,
)
from nth_dao.delivery.outbox import (
    OUTBOX_ATTEMPT_ERROR,
    OUTBOX_ATTEMPT_REJECTED,
    OUTBOX_ATTEMPT_SENT,
    OUTBOX_STATE_DELIVERED,
    DeliveryOutboxFull,
    DurableOutbox,
    OutboxAttempt,
    OutboxRecord,
)
from nth_dao.delivery.transports.base import SendResult
from nth_dao.plugins.host import (
    InvocationAuthority,
    PluginHostError,
    ProviderBinding,
)
from nth_dao.plugins.schema import PluginSchemaError
from nth_dao.plugins.transport import (
    TRANSPORT_CAPABILITY_ID,
    TRANSPORT_MAX_BATCH_SIZE,
    TRANSPORT_MAX_LEASE_MS,
    TransportOperationError,
    transport_envelope_digest,
    validate_transport_identifier,
)

RouteResolver = Callable[[str], str]
Clock = Callable[[], int]


class PluginDeliveryRuntimeError(RuntimeError):
    """Raised when Host/provider state prevents an honest delivery outcome."""

    def __init__(
        self, message: str, *, partial_result: PluginReceiveResult | None = None,
        error_code: str = "plugin-runtime-failed", retryable: bool = True,
    ) -> None:
        super().__init__(message)
        self.partial_result = partial_result
        self.error_code = error_code
        self.retryable = retryable


@dataclass(frozen=True)
class PluginReceiveResult:
    """One durable receive operation and its provider acknowledgement state."""

    decisions: tuple[InboxDecision, ...]
    found: bool
    transport_acknowledged: bool
    replayed: bool


class PluginDeliveryRuntime:
    """Durable delivery engine over one revocable PluginHost binding."""

    def __init__(
        self,
        *,
        binding: ProviderBinding,
        authority: InvocationAuthority,
        route_resolver: RouteResolver,
        outbox: DurableOutbox,
        inbox: DeliveryInbox | None = None,
        clock: Clock | None = None,
    ) -> None:
        if not isinstance(binding, ProviderBinding):
            raise TypeError("binding must be a PluginHost ProviderBinding")
        if binding.contract.capability_id != TRANSPORT_CAPABILITY_ID:
            raise ValueError("binding does not provide the delivery transport capability")
        if not isinstance(authority, InvocationAuthority):
            raise TypeError("authority must be an InvocationAuthority")
        if TRANSPORT_CAPABILITY_ID not in authority.capability_ids:
            raise ValueError("authority does not include the delivery capability")
        if not callable(route_resolver):
            raise TypeError("route_resolver must be callable")
        if not isinstance(outbox, DurableOutbox):
            raise TypeError("outbox must be a DurableOutbox")
        if inbox is not None and not isinstance(inbox, DeliveryInbox):
            raise TypeError("inbox must be a DeliveryInbox")
        if clock is not None and not callable(clock):
            raise TypeError("clock must be callable")
        self._binding = binding
        self._authority = authority
        self._route_resolver = route_resolver
        self.outbox = outbox
        self.inbox = inbox
        self._clock = clock or (lambda: int(time.time() * 1_000))
        self._transport_name = binding.plugin_id

    @property
    def principal(self) -> str:
        """The locally authorized principal, never provider metadata."""
        return self._authority.principal

    def with_inbox(self, inbox: DeliveryInbox) -> PluginDeliveryRuntime:
        """Bind a different durable intake without mutating a running runtime."""
        return PluginDeliveryRuntime(
            binding=self._binding, authority=self._authority,
            route_resolver=self._route_resolver, outbox=self.outbox,
            inbox=inbox, clock=self._clock,
        )

    def submit(self, envelope: TransportEnvelope) -> SendResult:
        """Durably enqueue and submit one envelope through PluginHost."""

        now_ms = self._now_ms()
        if not isinstance(envelope, TransportEnvelope):
            return SendResult(accepted=False, error_code="invalid-envelope: wrong type")
        try:
            raw = canonical_json(envelope.to_dict())
            if len(raw) > MAX_ENVELOPE_BYTES:
                raise ValueError("envelope exceeds the wire byte limit")
            envelope = TransportEnvelope.from_dict(json.loads(raw))
        except (TypeError, ValueError, OverflowError, RecursionError) as exc:
            return SendResult(accepted=False, error_code=f"invalid-envelope: {exc}")
        ok, reason = validate_envelope(
            envelope,
            now_ms=now_ms,
            require_signature=True,
        )
        if not ok:
            return SendResult(accepted=False, error_code=f"invalid-envelope: {reason}")
        record = self.outbox.enqueue(envelope, now_ms=now_ms)
        if record.is_terminal:
            return SendResult(
                accepted=record.state == OUTBOX_STATE_DELIVERED,
                error_code="" if record.state == OUTBOX_STATE_DELIVERED else "outbox-terminal",
            )
        encoded = record.envelope_json
        queued = TransportEnvelope.from_dict(json.loads(encoded))
        try:
            destination_route = self._route_resolver(queued.recipient)
            validate_transport_identifier(destination_route, field="destination_route_id")
        except (OSError, LookupError, TypeError, ValueError, PluginHostError) as exc:
            raise PluginDeliveryRuntimeError(
                f"delivery route resolution failed: {exc}", error_code="route-resolution-failed",
                retryable=isinstance(exc, (OSError, LookupError, PluginHostError)),
            ) from exc
        try:
            attempt = self.outbox.reserve_attempt(
                record.message_id, transport=self._transport_name, at_ms=self._now_ms(),
            )
        except DeliveryOutboxFull:
            return SendResult(accepted=False, error_code="outbox-attempt-capacity")
        if attempt is None:
            current = self.outbox.get(record.message_id)
            delivered = current is not None and current.state == OUTBOX_STATE_DELIVERED
            return SendResult(accepted=delivered, error_code="" if delivered else "outbox-terminal")
        try:
            response = self._binding.invoke(
                {
                    "operation": "send",
                    "delivery_id": record.message_id,
                    "destination_route_id": destination_route,
                    "envelope_json": encoded,
                    "envelope_sha256": transport_envelope_digest(encoded),
                    "expires_at_ms": record.expires_at_ms,
                },
                authority=self._authority,
            )
        except TransportOperationError as exc:
            outcome = OUTBOX_ATTEMPT_ERROR if exc.retryable else OUTBOX_ATTEMPT_REJECTED
            current = self._complete_attempt(record, attempt, outcome=outcome, error_code=exc.code)
            delivered = current.state == OUTBOX_STATE_DELIVERED
            return SendResult(accepted=delivered, error_code="" if delivered else exc.code)
        except OSError as exc:
            current = self._complete_attempt(record, attempt, outcome=OUTBOX_ATTEMPT_ERROR,
                                             error_code="provider-io-failed")
            if current.state == OUTBOX_STATE_DELIVERED:
                return SendResult(accepted=True)
            raise PluginDeliveryRuntimeError(
                f"delivery provider I/O failed: {exc}", error_code="provider-io-failed",
            ) from exc
        except (PluginHostError, PluginSchemaError, TypeError, ValueError) as exc:
            current = self._complete_attempt(
                record, attempt,
                outcome=OUTBOX_ATTEMPT_ERROR,
                error_code="plugin-invocation-failed",
            )
            if current.state == OUTBOX_STATE_DELIVERED:
                return SendResult(accepted=True)
            raise PluginDeliveryRuntimeError(
                f"delivery transport invocation failed: {exc}"
            ) from exc
        accepted = response.get("accepted") is True
        current = self._complete_attempt(
            record, attempt,
            outcome=OUTBOX_ATTEMPT_SENT if accepted else OUTBOX_ATTEMPT_ERROR,
            error_code="" if accepted else "provider-rejected",
        )
        if current.state == OUTBOX_STATE_DELIVERED:
            return SendResult(accepted=True)
        if current.is_terminal:
            return SendResult(accepted=False, error_code="outbox-terminal")
        return SendResult(
            accepted=accepted,
            error_code="" if accepted else "provider-rejected",
        )

    def receive(
        self,
        *,
        receive_id: str,
        max_items: int = 16,
        lease_ms: int = 30_000,
    ) -> PluginReceiveResult:
        """Lease a batch, persist every decision, then acknowledge the lease."""

        if self.inbox is None:
            raise PluginDeliveryRuntimeError("delivery receive inbox is not configured")
        if isinstance(max_items, bool) or not isinstance(max_items, int):
            raise TypeError("max_items must be an integer")
        if not 1 <= max_items <= TRANSPORT_MAX_BATCH_SIZE:
            raise ValueError(
                f"max_items must be within [1, {TRANSPORT_MAX_BATCH_SIZE}]"
            )
        if isinstance(lease_ms, bool) or not isinstance(lease_ms, int):
            raise TypeError("lease_ms must be an integer")
        if not 1 <= lease_ms <= TRANSPORT_MAX_LEASE_MS:
            raise ValueError(f"lease_ms must be within [1, {TRANSPORT_MAX_LEASE_MS}]")
        decisions: tuple[InboxDecision, ...] = ()
        found = False
        replayed = False
        try:
            response = self._binding.invoke(
                {
                    "operation": "receive",
                    "receive_id": receive_id,
                    "limit": max_items,
                    "lease_ms": lease_ms,
                },
                authority=self._authority,
            )
            found = response["found"] is True
            replayed = bool(response["replayed"])
            if response["found"] is not True:
                return PluginReceiveResult(
                    decisions=(),
                    found=False,
                    transport_acknowledged=False,
                    replayed=bool(response["replayed"]),
                )
            intake_error = None
            for item in response["items"]:
                try:
                    decision = self._persist_transport_item(item)
                except OSError as exc:
                    intake_error = exc
                    decision = InboxDecision(False, "transport intake storage unavailable",
                                             message_id=item["delivery_id"], retryable=True)
                decisions += (decision,)
            if intake_error is not None:
                raise PluginDeliveryRuntimeError(
                    f"delivery intake storage unavailable: {intake_error}",
                    error_code="intake-storage-unavailable",
                    partial_result=PluginReceiveResult(decisions, found, False, replayed),
                ) from intake_error
            if any(
                not decision.accepted
                and not decision.duplicate
                and decision.retryable
                for decision in decisions
            ):
                return PluginReceiveResult(
                    decisions=decisions,
                    found=True,
                    transport_acknowledged=False,
                    replayed=bool(response["replayed"]),
                )
            acknowledgement = self._binding.invoke(
                {
                    "operation": "ack",
                    "receive_id": response["receive_id"],
                    "lease_id": response["lease_id"],
                    "batch_sha256": response["batch_sha256"],
                },
                authority=self._authority,
            )
        except PluginDeliveryRuntimeError as exc:
            if exc.partial_result is None:
                exc.partial_result = PluginReceiveResult(decisions, found, False, replayed)
            raise
        except DeliveryInboxCacheCorrupt as exc:
            raise PluginDeliveryRuntimeError(
                f"delivery intake integrity failed: {exc}",
                error_code="intake-integrity-failed", retryable=False,
                partial_result=PluginReceiveResult(decisions, found, False, replayed),
            ) from exc
        except (TransportOperationError, PluginHostError, PluginSchemaError, OSError) as exc:
            raise PluginDeliveryRuntimeError(
                f"delivery transport receive failed: {exc}",
                error_code=exc.code if isinstance(exc, TransportOperationError) else "provider-receive-failed",
                retryable=exc.retryable if isinstance(exc, TransportOperationError) else True,
                partial_result=PluginReceiveResult(
                    decisions=decisions, found=found, transport_acknowledged=False, replayed=replayed,
                ),
            ) from exc
        if acknowledgement.get("acknowledged") is not True:
            raise PluginDeliveryRuntimeError(
                "delivery transport did not acknowledge the lease",
                partial_result=PluginReceiveResult(
                    decisions=decisions, found=True, transport_acknowledged=False, replayed=replayed,
                ),
            )
        return PluginReceiveResult(
            decisions=decisions,
            found=True,
            transport_acknowledged=True,
            replayed=bool(response["replayed"]),
        )

    def apply_ack(self, ack: DeliveryAck) -> OutboxRecord:
        """Apply a receiver-signed delivery acknowledgement to the outbox."""

        return self.outbox.handle_ack(ack, now_ms=self._now_ms())

    def _persist_transport_item(self, item: Mapping[str, Any]) -> InboxDecision:
        encoded = item["envelope_json"]
        if transport_envelope_digest(encoded) != item["envelope_sha256"]:
            raise PluginDeliveryRuntimeError(
                "provider envelope digest changed after Host validation",
                error_code="transport-integrity-failed", retryable=False,
            )
        try:
            candidate = TransportEnvelope.from_dict(json.loads(encoded))
        except (json.JSONDecodeError, TransportEnvelopeRejected, TypeError, ValueError):
            candidate = None
        if candidate is not None:
            if candidate.message_id != item["delivery_id"]:
                return self._quarantine_rejection(
                    item, InboxDecision(False, "provider delivery_id does not match the signed envelope"),
                )
            if candidate.expires_at_ms != item["expires_at_ms"]:
                return self._quarantine_rejection(
                    item, InboxDecision(False, "provider expiry does not match the signed envelope"),
                )
        if self.inbox is None:
            raise PluginDeliveryRuntimeError("delivery receive inbox is not configured")
        decision = self.inbox.retained_duplicate(encoded)
        if decision is None:
            decision = self.inbox.accept(encoded, now_ms=self._now_ms())
        if (
            decision.envelope_sha256
            and decision.envelope_sha256 != f"sha256:{item['envelope_sha256']}"
        ):
            raise PluginDeliveryRuntimeError(
                "inbox envelope digest does not match provider bytes",
                error_code="transport-integrity-failed", retryable=False,
            )
        if not decision.accepted and not decision.duplicate and not decision.retryable:
            return self._quarantine_rejection(item, decision)
        return decision

    def _quarantine_rejection(self, item: Mapping[str, Any], decision: InboxDecision) -> InboxDecision:
        assert self.inbox is not None
        try:
            self.inbox.quarantine_transport_item(
                item, transport=self._transport_name, reason=decision.reason[:512], at_ms=self._now_ms(),
            )
        except DeliveryInboxFull:
            return InboxDecision(False, "transport quarantine is at capacity",
                                 message_id=decision.message_id, retryable=True)
        return decision

    def _complete_attempt(
        self,
        record: OutboxRecord,
        attempt: OutboxAttempt,
        *,
        outcome: str,
        error_code: str,
    ) -> OutboxRecord:
        return self.outbox.complete_attempt(
            record.message_id, attempt.attempt_id,
            outcome=outcome,
            error_code=error_code,
            at_ms=max(attempt.at_ms, self._now_ms()),
        )

    def _now_ms(self) -> int:
        value = self._clock()
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise PluginDeliveryRuntimeError("delivery clock must return positive integer ms")
        return value


__all__ = [
    "PluginDeliveryRuntime",
    "PluginDeliveryRuntimeError",
    "PluginReceiveResult",
]
