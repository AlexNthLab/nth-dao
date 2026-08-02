"""Verified intake of destination-bound Trade Order deliveries."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from nth_dao.did_key import is_did_key
from nth_dao.trade_rules.order_audit import (
    TradeOrderAuditCoordinator,
    TradeOrderAuditResult,
)
from nth_dao.trade_rules.order_transport import (
    DEFAULT_MAX_ORDER_DELIVERY_TTL_SECONDS,
    DEFAULT_ORDER_DELIVERY_CLOCK_SKEW_SECONDS,
    TradeOrderDelivery,
    TradeOrderDeliveryRejected,
    TradeOrderIntakeReceipt,
    create_trade_order_intake_receipt,
    trade_order_delivery_digest,
    trade_order_intake_receipt_digest,
    verify_trade_order_delivery,
)


def _utc_now(value: datetime | None) -> datetime:
    moment = value or datetime.now(timezone.utc)
    if (
        not isinstance(moment, datetime)
        or moment.tzinfo is None
        or moment.utcoffset() is None
    ):
        raise TradeOrderDeliveryRejected("at must be timezone-aware")
    return moment.astimezone(timezone.utc)


def _timestamp_ms(value: datetime) -> int:
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = value - epoch
    return (
        (delta.days * 86_400 + delta.seconds) * 1_000
        + delta.microseconds // 1_000
    )


@dataclass(frozen=True)
class TradeOrderIntakeResult:
    """One verified delivery and its durable local Order audit result."""

    delivery: TradeOrderDelivery
    delivery_digest: str
    audit: TradeOrderAuditResult
    receipt: TradeOrderIntakeReceipt
    receipt_digest: str


class TradeOrderIntakeCoordinator:
    """Verify an Order delivery before retaining and anchoring its Order."""

    def __init__(
        self,
        order_audit: TradeOrderAuditCoordinator,
        *,
        receiver_identity: Any,
        max_ttl_seconds: float = DEFAULT_MAX_ORDER_DELIVERY_TTL_SECONDS,
        clock_skew_seconds: float = (
            DEFAULT_ORDER_DELIVERY_CLOCK_SKEW_SECONDS
        ),
    ) -> None:
        recipient_did = receiver_identity.as_did()
        if not isinstance(recipient_did, str) or not is_did_key(recipient_did):
            raise ValueError("receiver_identity must expose an Ed25519 did:key")
        if not callable(getattr(receiver_identity, "sign", None)):
            raise ValueError("receiver_identity must support signing")
        self.order_audit = order_audit
        self.receiver_identity = receiver_identity
        self.recipient_did = recipient_did
        self.max_ttl_seconds = max_ttl_seconds
        self.clock_skew_seconds = clock_skew_seconds

    def receive(
        self,
        delivery: TradeOrderDelivery | dict[str, Any],
        *,
        at: datetime | None = None,
    ) -> TradeOrderIntakeResult:
        """Verify, cache, and Spine-anchor one accepted Order idempotently."""

        verified = (
            TradeOrderDelivery.from_json(delivery.canonical_bytes)
            if isinstance(delivery, TradeOrderDelivery)
            else TradeOrderDelivery.from_dict(delivery)
        )
        moment = _utc_now(at)
        ok, reason = verify_trade_order_delivery(
            verified,
            recipient_did=self.recipient_did,
            at=moment,
            max_ttl_seconds=self.max_ttl_seconds,
            clock_skew_seconds=self.clock_skew_seconds,
        )
        if not ok:
            raise TradeOrderDeliveryRejected(reason)
        audit = self.order_audit.accept(
            verified.order,
            now_ms=_timestamp_ms(moment),
        )
        received_at = moment.isoformat().replace("+00:00", "Z")
        receipt = create_trade_order_intake_receipt(
            self.receiver_identity,
            delivery=verified,
            received_at=received_at,
            audit_event_id=audit.record.event_id,
            clock_skew_seconds=self.clock_skew_seconds,
        )
        if not self.order_audit.finalize(audit):
            raise TradeOrderDeliveryRejected(
                "Order audit work disappeared before durable completion"
            )
        return TradeOrderIntakeResult(
            delivery=verified,
            delivery_digest=trade_order_delivery_digest(verified),
            audit=audit,
            receipt=receipt,
            receipt_digest=trade_order_intake_receipt_digest(receipt),
        )


__all__ = [
    "TradeOrderIntakeCoordinator",
    "TradeOrderIntakeResult",
]
