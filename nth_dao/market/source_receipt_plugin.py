"""Explicit PluginHost transport binding for directed source receipt delivery.

Providers carry opaque envelopes. Source evidence, claimant authorization,
durable observations and signed ACKs remain domain responsibilities. Nothing
here installs or enables a provider, resolves a peer, or accepts finished work.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path

from nth_dao.delivery.acknowledgement import DeliveryAck
from nth_dao.delivery.envelope import TransportEnvelope
from nth_dao.delivery.inbox import DeliveryInbox, DeliveryInboxCacheCorrupt
from nth_dao.delivery.outbox import DurableOutbox, OutboxRecord
from nth_dao.delivery.plugin_runtime import (
    PluginDeliveryRuntime,
    PluginDeliveryRuntimeError,
    PluginReceiveResult,
    RouteResolver,
)
from nth_dao.delivery.transports.base import SendResult
from nth_dao.identity import AgentIdentity
from nth_dao.market.source_receipt_delivery import (
    SOURCE_RECEIPT_DELIVERY_KIND,
    SourceReceiptDeliveryReceiver,
    SourceReceiptDeliveryRejected,
    SourceReceiptResumeResult,
    _checked_path,
    acknowledge_source_receipt_delivery,
    open_source_receipt_delivery_outbox,
    require_prepared_source_receipt_delivery,
    source_receipt_delivery_failure,
)
from nth_dao.plugins.host import InvocationAuthority, ProviderBinding
from nth_dao.spine.log import SignedEventLog

MAX_PLUGIN_INGRESS_ENTRIES = 256
MAX_PLUGIN_INGRESS_PENDING_BYTES = 16 * 1024 * 1024


def open_source_receipt_plugin_inbox(receiver: SourceReceiptDeliveryReceiver) -> DeliveryInbox:
    """DID-scoped bounded staging, not claim authorization or work acceptance.

    Other claims and kinds remain durable for their own explicit handlers.
    Signature, direct recipient and intake TTL are still checked before ACK.
    """
    if not isinstance(receiver, SourceReceiptDeliveryReceiver):
        raise TypeError("receiver must be a SourceReceiptDeliveryReceiver")
    did = receiver.identity.as_did()
    relative = Path(".nth/plugin_delivery_ingress") / sha256(did.encode("utf-8")).hexdigest()
    for name in ("inbox.cache.jsonl", "inbox.rejections.jsonl", "inbox.lock"):
        _checked_path(receiver.workspace, relative / name)

    def authorize(envelope: TransportEnvelope) -> tuple[bool, str]:
        return envelope.recipient == did, "direct recipient binding differs"

    return DeliveryInbox(
        _checked_path(receiver.workspace, relative), authorize=authorize,
        clock=receiver.current_time_ms, max_replay_entries=MAX_PLUGIN_INGRESS_ENTRIES,
        reject_links=True, evict_processed=False,
        max_pending_bytes=MAX_PLUGIN_INGRESS_PENDING_BYTES,
    )


@dataclass(frozen=True)
class SourceReceiptTransportFailure:
    """Visible provider failure, separate from independently recoverable domain work."""

    error_code: str
    reason: str
    retryable: bool = True


@dataclass(frozen=True)
class SourceReceiptPluginReceiveResult:
    """Provider lease outcome and domain outcomes are deliberately separate."""

    transport: PluginReceiveResult | None
    domain: SourceReceiptResumeResult
    transport_error: SourceReceiptTransportFailure | None = None
    ack_exports: SourceReceiptResumeResult = field(
        default_factory=lambda: SourceReceiptResumeResult(results=(), failures=()),
    )


class SourceReceiptPluginSender:
    """Send audited source envelopes; the caller owns the Host's lifetime."""

    def __init__(
        self, *, workspace: Path, identity: AgentIdentity, spine: SignedEventLog,
        binding: ProviderBinding, authority: InvocationAuthority,
        route_resolver: RouteResolver, clock: Callable[[], int] | None = None,
    ) -> None:
        if not isinstance(identity, AgentIdentity) or not identity.can_sign:
            raise TypeError("source identity must be a signing AgentIdentity")
        if not isinstance(spine, SignedEventLog) or spine.signer_did != identity.as_did():
            raise SourceReceiptDeliveryRejected("source Spine signer differs from the selected identity")
        if not isinstance(authority, InvocationAuthority) or authority.principal != identity.as_did():
            raise SourceReceiptDeliveryRejected("source transport principal differs from the selected identity")
        if clock is not None and not callable(clock):
            raise TypeError("clock must be callable")
        self._workspace = Path(workspace)
        self._identity = identity
        self._spine = spine
        self._clock = clock
        self._runtime = PluginDeliveryRuntime(
            binding=binding, authority=authority, route_resolver=route_resolver,
            outbox=open_source_receipt_delivery_outbox(self._workspace, clock=clock),
            clock=clock,
        )

    @property
    def outbox(self) -> DurableOutbox:
        return self._runtime.outbox

    def submit(self, envelope: TransportEnvelope) -> SendResult:
        """Preparation evidence is reverified before any provider disclosure."""
        prepared = require_prepared_source_receipt_delivery(
            envelope, workspace=self._workspace, identity=self._identity, spine=self._spine,
        )
        return self._runtime.submit(prepared)

    def acknowledge(self, ack: DeliveryAck) -> OutboxRecord:
        """Apply a separately returned signed ACK using the CLI's domain gate."""
        return acknowledge_source_receipt_delivery(
            ack, workspace=self._workspace, identity=self._identity,
            spine=self._spine, clock=self._clock,
        )


def receive_source_receipt_deliveries(
    *, runtime: PluginDeliveryRuntime, receiver: SourceReceiptDeliveryReceiver,
    receive_id: str, max_items: int = 16, lease_ms: int = 30_000,
) -> SourceReceiptPluginReceiveResult:
    """Retain leased envelopes before domain processing or returning signed ACKs.

    The caller owns provider selection and local authority. ACK return routing
    is explicit and separate: a provider lease ACK never closes a source outbox.
    Previously durable domain work is resumed even when a new lease is empty.
    """
    if not isinstance(runtime, PluginDeliveryRuntime):
        raise TypeError("runtime must be a PluginDeliveryRuntime")
    if not isinstance(receiver, SourceReceiptDeliveryReceiver):
        raise TypeError("receiver must be a SourceReceiptDeliveryReceiver")
    if runtime.inbox is not receiver.inbox:
        raise SourceReceiptDeliveryRejected("plugin runtime must use the receiver's exact durable inbox")
    if runtime.principal != receiver.identity.as_did():
        raise SourceReceiptDeliveryRejected("claimant transport principal differs from the selected identity")
    ingress = None
    transport = None
    transport_error = None
    try:
        ingress = open_source_receipt_plugin_inbox(receiver)
        transport = runtime.with_inbox(ingress).receive(
            receive_id=receive_id, max_items=max_items, lease_ms=lease_ms,
        )
    except PluginDeliveryRuntimeError as exc:
        transport = exc.partial_result
        transport_error = SourceReceiptTransportFailure(
            error_code=exc.error_code, reason=str(exc)[:512], retryable=exc.retryable,
        )
    except OSError as exc:
        transport_error = SourceReceiptTransportFailure(
            error_code="ingress-storage-unavailable", reason=str(exc)[:512],
        )
    except (DeliveryInboxCacheCorrupt, SourceReceiptDeliveryRejected) as exc:
        transport_error = SourceReceiptTransportFailure(
            error_code="ingress-integrity-failed", reason=str(exc)[:512], retryable=False,
        )
    resumed = receiver.resume_pending()
    results = {item.ack.message_id: item for item in resumed.results}
    failures = {item.message_id: item for item in resumed.failures}
    pending = ()
    if ingress is not None:
        try:
            pending = ingress.pending(max_items=MAX_PLUGIN_INGRESS_ENTRIES)
        except OSError as exc:
            transport_error = SourceReceiptTransportFailure(
                error_code="ingress-storage-unavailable", reason=str(exc)[:512],
            )
        except DeliveryInboxCacheCorrupt as exc:
            transport_error = SourceReceiptTransportFailure(
                error_code="ingress-integrity-failed", reason=str(exc)[:512], retryable=False,
            )
    for envelope in pending:
        if (
            envelope.kind != SOURCE_RECEIPT_DELIVERY_KIND
            or envelope.payload.get("source_claim_id") != receiver.source_claim_id
            or envelope.message_id in failures
        ):
            continue
        try:
            result = receiver.receive_retained(ingress, envelope.message_id)
            ingress.mark_processed(envelope.message_id)
            results[envelope.message_id] = result
            failures.pop(envelope.message_id, None)
        except (OSError, TypeError, ValueError, RuntimeError, RecursionError) as exc:
            failures[envelope.message_id] = source_receipt_delivery_failure(envelope.message_id, exc)
    # A durable result may predate a redelivered lease. Recover the exact ACK,
    # rather than reporting a duplicate as though it produced no result.
    for decision in transport.decisions if transport is not None else ():
        if (
            not decision.duplicate or decision.message_id in results or decision.message_id in failures
            or not receiver.inbox.seen(decision.message_id)
        ):
            continue
        try:
            results[decision.message_id] = receiver.get_ack(decision.message_id)
        except (OSError, TypeError, ValueError, RuntimeError, RecursionError) as exc:
            failures[decision.message_id] = source_receipt_delivery_failure(decision.message_id, exc)
    return SourceReceiptPluginReceiveResult(
        transport=transport,
        domain=SourceReceiptResumeResult(results=tuple(results.values()), failures=tuple(failures.values())),
        transport_error=transport_error,
        ack_exports=receiver.export_retained_acks(),
    )


__all__ = [
    "SourceReceiptPluginReceiveResult",
    "SourceReceiptPluginSender",
    "SourceReceiptTransportFailure",
    "open_source_receipt_plugin_inbox",
    "receive_source_receipt_deliveries",
]
