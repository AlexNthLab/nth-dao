"""Policy-verified intake of federated Trade Receipt Reviews."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from nth_dao.did_key import is_did_key
from nth_dao.trade_rules.agreement_order import TradeOrder
from nth_dao.trade_rules.execution_adapter import TradeExecutionAdapterResolver
from nth_dao.trade_rules.execution_content import (
    TradeExecutionContentResolver,
    TradeExecutionSchemaValidator,
)
from nth_dao.trade_rules.execution_receipt import TradeExecutionReceipt
from nth_dao.trade_rules.negotiation import RulePackageResolver
from nth_dao.trade_rules.receipt_review import (
    TradeReceiptReviewRejected,
    verify_trade_receipt_review_under_policy,
)
from nth_dao.trade_rules.receipt_review_audit import (
    TradeReceiptReviewAuditResult,
    TradeReceiptReviewCoordinator,
)
from nth_dao.trade_rules.receipt_review_transport import (
    DEFAULT_MAX_RECEIPT_REVIEW_DELIVERY_TTL_SECONDS,
    DEFAULT_RECEIPT_REVIEW_DELIVERY_CLOCK_SKEW_SECONDS,
    TradeReceiptReviewAcknowledgement,
    TradeReceiptReviewDelivery,
    TradeReceiptReviewDeliveryRejected,
    create_trade_receipt_review_acknowledgement,
    trade_receipt_review_acknowledgement_digest,
    trade_receipt_review_delivery_digest,
    verify_trade_receipt_review_delivery,
)


def _utc_now(value: datetime | None) -> datetime:
    moment = value or datetime.now(timezone.utc)
    if (
        not isinstance(moment, datetime)
        or moment.tzinfo is None
        or moment.utcoffset() is None
    ):
        raise TradeReceiptReviewDeliveryRejected(
            "at must be timezone-aware"
        )
    return moment.astimezone(timezone.utc)


def _format_received_at(
    moment: datetime,
    *,
    delivery: TradeReceiptReviewDelivery,
) -> str:
    created_at = datetime.fromisoformat(
        delivery.to_dict()["created_at"].replace("Z", "+00:00")
    )
    acknowledged_at = max(moment, created_at)
    return acknowledged_at.isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _timestamp_ms(value: datetime) -> int:
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = value - epoch
    return (
        (delta.days * 86_400 + delta.seconds) * 1_000
        + delta.microseconds // 1_000
    )


@dataclass(frozen=True)
class TradeReceiptReviewIntakeResult:
    """Verified Review retention plus receiver-signed acknowledgement."""

    delivery: TradeReceiptReviewDelivery
    delivery_digest: str
    audit: TradeReceiptReviewAuditResult
    acknowledgement: TradeReceiptReviewAcknowledgement
    acknowledgement_digest: str


class TradeReceiptReviewIntakeCoordinator:
    """Re-verify a remote Review before durable local retention."""

    def __init__(
        self,
        review_coordinator: TradeReceiptReviewCoordinator,
        *,
        receiver_identity: Any,
        package_resolver: RulePackageResolver,
        adapter_resolver: TradeExecutionAdapterResolver,
        content_resolver: TradeExecutionContentResolver,
        schema_validator: TradeExecutionSchemaValidator,
        max_ttl_seconds: float = (
            DEFAULT_MAX_RECEIPT_REVIEW_DELIVERY_TTL_SECONDS
        ),
        clock_skew_seconds: float = (
            DEFAULT_RECEIPT_REVIEW_DELIVERY_CLOCK_SKEW_SECONDS
        ),
    ) -> None:
        if not isinstance(
            review_coordinator,
            TradeReceiptReviewCoordinator,
        ):
            raise TypeError(
                "review_coordinator must be a "
                "TradeReceiptReviewCoordinator"
            )
        receiver_did = receiver_identity.as_did()
        if not isinstance(receiver_did, str) or not is_did_key(receiver_did):
            raise ValueError(
                "receiver_identity must expose an Ed25519 did:key"
            )
        if not callable(getattr(receiver_identity, "sign", None)):
            raise ValueError("receiver_identity must support signing")
        self.review_coordinator = review_coordinator
        self.receiver_identity = receiver_identity
        self.receiver_did = receiver_did
        self.package_resolver = package_resolver
        self.adapter_resolver = adapter_resolver
        self.content_resolver = content_resolver
        self.schema_validator = schema_validator
        self.max_ttl_seconds = max_ttl_seconds
        self.clock_skew_seconds = clock_skew_seconds

    def receive(
        self,
        delivery: TradeReceiptReviewDelivery | dict[str, Any],
        *,
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
        at: datetime | None = None,
    ) -> TradeReceiptReviewIntakeResult:
        """Verify policy, retain one Review, and sign the durable ACK."""

        verified_order = (
            TradeOrder.from_json(order.canonical_bytes)
            if isinstance(order, TradeOrder)
            else TradeOrder.from_dict(order)
        )
        verified_receipt = (
            TradeExecutionReceipt.from_json(
                receipt.canonical_bytes,
                order=verified_order,
            )
            if isinstance(receipt, TradeExecutionReceipt)
            else TradeExecutionReceipt.from_dict(
                receipt,
                order=verified_order,
            )
        )
        verified_delivery = (
            TradeReceiptReviewDelivery.from_json(
                delivery.canonical_bytes,
                receipt=verified_receipt,
                order=verified_order,
            )
            if isinstance(delivery, TradeReceiptReviewDelivery)
            else TradeReceiptReviewDelivery.from_dict(
                delivery,
                receipt=verified_receipt,
                order=verified_order,
            )
        )
        moment = _utc_now(at)
        ok, reason = verify_trade_receipt_review_delivery(
            verified_delivery,
            receipt=verified_receipt,
            order=verified_order,
            recipient_did=self.receiver_did,
            at=moment,
            max_ttl_seconds=self.max_ttl_seconds,
            clock_skew_seconds=self.clock_skew_seconds,
        )
        if not ok:
            raise TradeReceiptReviewDeliveryRejected(reason)
        try:
            verify_trade_receipt_review_under_policy(
                verified_delivery.review,
                receipt=verified_receipt,
                order=verified_order,
                package_resolver=self.package_resolver,
                verifier_policy=verified_delivery.verifier_policy,
                adapter_resolver=self.adapter_resolver,
                adapter_policy=verified_delivery.adapter_policy,
                content_resolver=self.content_resolver,
                schema_validator=self.schema_validator,
            )
        except TradeReceiptReviewRejected:
            raise
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise TradeReceiptReviewRejected(
                f"receiver policy verification failed: {exc}"
            ) from exc
        audit = self.review_coordinator.record(
            verified_delivery.review,
            receipt=verified_receipt,
            order=verified_order,
            verifier_policy=verified_delivery.verifier_policy,
            adapter_policy=verified_delivery.adapter_policy,
            observed_at_ms=_timestamp_ms(moment),
        )
        observed_at_ms = self.review_coordinator.observed_at_ms(
            verified_delivery.to_dict()["review_digest"]
        )
        acknowledgement = create_trade_receipt_review_acknowledgement(
            self.receiver_identity,
            delivery=verified_delivery,
            receipt=verified_receipt,
            order=verified_order,
            received_at=_format_received_at(
                datetime.fromtimestamp(
                    observed_at_ms / 1_000,
                    tz=timezone.utc,
                ),
                delivery=verified_delivery,
            ),
            audit_event_id=audit.event.event_id,
            clock_skew_seconds=self.clock_skew_seconds,
        )
        return TradeReceiptReviewIntakeResult(
            delivery=verified_delivery,
            delivery_digest=trade_receipt_review_delivery_digest(
                verified_delivery,
                receipt=verified_receipt,
                order=verified_order,
            ),
            audit=audit,
            acknowledgement=acknowledgement,
            acknowledgement_digest=(
                trade_receipt_review_acknowledgement_digest(
                    acknowledgement
                )
            ),
        )


__all__ = [
    "TradeReceiptReviewIntakeCoordinator",
    "TradeReceiptReviewIntakeResult",
]
