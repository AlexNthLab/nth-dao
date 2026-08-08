"""Policy-verified intake of federated Trade Execution Receipts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from nth_dao.did_key import is_did_key
from nth_dao.trade_rules.agreement_order import TradeOrder
from nth_dao.trade_rules.execution_adapter import (
    TradeExecutionAdapterPolicy,
    TradeExecutionAdapterResolver,
)
from nth_dao.trade_rules.execution_content import (
    TradeExecutionContentResolver,
    TradeExecutionSchemaValidator,
)
from nth_dao.trade_rules.execution_coordinator import (
    TradeExecutionAuditResult,
    TradeExecutionCoordinator,
)
from nth_dao.trade_rules.execution_receipt import (
    TradeExecutionReceiptRejected,
    verify_execution_receipt_under_policy,
)
from nth_dao.trade_rules.execution_transport import (
    DEFAULT_EXECUTION_RECEIPT_DELIVERY_CLOCK_SKEW_SECONDS,
    DEFAULT_MAX_EXECUTION_RECEIPT_DELIVERY_TTL_SECONDS,
    TradeExecutionReceiptAcknowledgement,
    TradeExecutionReceiptDelivery,
    TradeExecutionReceiptDeliveryRejected,
    create_trade_execution_receipt_acknowledgement,
    trade_execution_receipt_acknowledgement_digest,
    trade_execution_receipt_delivery_digest,
    verify_trade_execution_receipt_delivery,
)
from nth_dao.trade_rules.negotiation import (
    RulePackageResolver,
    RuleResolutionPolicy,
)


def _utc_now(value: datetime | None) -> datetime:
    moment = value or datetime.now(timezone.utc)
    if (
        not isinstance(moment, datetime)
        or moment.tzinfo is None
        or moment.utcoffset() is None
    ):
        raise TradeExecutionReceiptDeliveryRejected(
            "at must be timezone-aware"
        )
    return moment.astimezone(timezone.utc)


def _timestamp_ms(value: datetime) -> int:
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = value - epoch
    return (
        (delta.days * 86_400 + delta.seconds) * 1_000
        + delta.microseconds // 1_000
    )


@dataclass(frozen=True)
class TradeExecutionReceiptIntakeResult:
    """Verified Receipt retention plus receiver-signed acknowledgement."""

    delivery: TradeExecutionReceiptDelivery
    delivery_digest: str
    audit: TradeExecutionAuditResult
    acknowledgement: TradeExecutionReceiptAcknowledgement
    acknowledgement_digest: str


class TradeExecutionReceiptIntakeCoordinator:
    """Re-verify a remote execution claim before durable local retention."""

    def __init__(
        self,
        execution_coordinator: TradeExecutionCoordinator,
        *,
        receiver_identity: Any,
        package_resolver: RulePackageResolver,
        verifier_policy: RuleResolutionPolicy,
        adapter_resolver: TradeExecutionAdapterResolver,
        adapter_policy: TradeExecutionAdapterPolicy,
        content_resolver: TradeExecutionContentResolver,
        schema_validator: TradeExecutionSchemaValidator,
        max_ttl_seconds: float = (
            DEFAULT_MAX_EXECUTION_RECEIPT_DELIVERY_TTL_SECONDS
        ),
        clock_skew_seconds: float = (
            DEFAULT_EXECUTION_RECEIPT_DELIVERY_CLOCK_SKEW_SECONDS
        ),
    ) -> None:
        if not isinstance(execution_coordinator, TradeExecutionCoordinator):
            raise TypeError(
                "execution_coordinator must be a TradeExecutionCoordinator"
            )
        receiver_did = receiver_identity.as_did()
        if not isinstance(receiver_did, str) or not is_did_key(receiver_did):
            raise ValueError(
                "receiver_identity must expose an Ed25519 did:key"
            )
        if not callable(getattr(receiver_identity, "sign", None)):
            raise ValueError("receiver_identity must support signing")
        self.execution_coordinator = execution_coordinator
        self.receiver_identity = receiver_identity
        self.receiver_did = receiver_did
        self.package_resolver = package_resolver
        self.verifier_policy = verifier_policy
        self.adapter_resolver = adapter_resolver
        self.adapter_policy = adapter_policy
        self.content_resolver = content_resolver
        self.schema_validator = schema_validator
        self.max_ttl_seconds = max_ttl_seconds
        self.clock_skew_seconds = clock_skew_seconds

    def receive(
        self,
        delivery: TradeExecutionReceiptDelivery | dict[str, Any],
        *,
        order: TradeOrder | dict[str, Any],
        at: datetime | None = None,
    ) -> TradeExecutionReceiptIntakeResult:
        """Verify policy, retain one Receipt, and sign the durable ACK."""

        verified_order = (
            TradeOrder.from_json(order.canonical_bytes)
            if isinstance(order, TradeOrder)
            else TradeOrder.from_dict(order)
        )
        verified_delivery = (
            TradeExecutionReceiptDelivery.from_json(
                delivery.canonical_bytes,
                order=verified_order,
            )
            if isinstance(delivery, TradeExecutionReceiptDelivery)
            else TradeExecutionReceiptDelivery.from_dict(
                delivery,
                order=verified_order,
            )
        )
        moment = _utc_now(at)
        ok, reason = verify_trade_execution_receipt_delivery(
            verified_delivery,
            order=verified_order,
            recipient_did=self.receiver_did,
            at=moment,
            max_ttl_seconds=self.max_ttl_seconds,
            clock_skew_seconds=self.clock_skew_seconds,
        )
        if not ok:
            raise TradeExecutionReceiptDeliveryRejected(reason)
        try:
            verify_execution_receipt_under_policy(
                verified_delivery.receipt,
                verified_order,
                self.package_resolver,
                self.verifier_policy,
                self.adapter_resolver,
                self.adapter_policy,
                self.content_resolver,
                self.schema_validator,
            )
        except TradeExecutionReceiptRejected:
            raise
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise TradeExecutionReceiptRejected(
                f"receiver policy verification failed: {exc}"
            ) from exc
        audit = self.execution_coordinator.record(
            verified_delivery.receipt,
            order=verified_order,
            now_ms=_timestamp_ms(moment),
        )
        delivery_created = datetime.fromisoformat(
            verified_delivery.to_dict()["created_at"].replace(
                "Z", "+00:00"
            )
        )
        acknowledgement_ms = max(
            audit.record.created_at_ms,
            _timestamp_ms(delivery_created),
        )
        received_at = datetime.fromtimestamp(
            acknowledgement_ms / 1_000,
            tz=timezone.utc,
        ).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        acknowledgement = (
            create_trade_execution_receipt_acknowledgement(
                self.receiver_identity,
                delivery=verified_delivery,
                order=verified_order,
                received_at=received_at,
                audit_event_id=audit.record.event_id,
                clock_skew_seconds=self.clock_skew_seconds,
            )
        )
        return TradeExecutionReceiptIntakeResult(
            delivery=verified_delivery,
            delivery_digest=trade_execution_receipt_delivery_digest(
                verified_delivery,
                order=verified_order,
            ),
            audit=audit,
            acknowledgement=acknowledgement,
            acknowledgement_digest=(
                trade_execution_receipt_acknowledgement_digest(
                    acknowledgement
                )
            ),
        )


__all__ = [
    "TradeExecutionReceiptIntakeCoordinator",
    "TradeExecutionReceiptIntakeResult",
]
