"""Mandatory CAS issuance path for Trade Execution Receipts."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from nth_dao.trade_rules.agreement import DEFAULT_CLOCK_SKEW_SECONDS
from nth_dao.trade_rules.agreement_order import TradeOrder
from nth_dao.trade_rules.execution_adapter import (
    TradeExecutionAdapterPolicy,
    TradeExecutionAdapterResolver,
)
from nth_dao.trade_rules.execution_receipt import (
    TradeExecutionReceipt,
    _create_trade_execution_receipt,
)
from nth_dao.trade_rules.execution_receipt_store import (
    TradeExecutionReceiptStore,
)
from nth_dao.trade_rules.execution_content import (
    TradeExecutionContentResolver,
    TradeExecutionSchemaValidator,
)
from nth_dao.trade_rules.negotiation import (
    RulePackageResolver,
    RuleResolutionPolicy,
)


class TradeExecutionCoordinator:
    """Issue signed Receipts only through conflict-retaining CAS storage."""

    def __init__(self, store: TradeExecutionReceiptStore) -> None:
        if not isinstance(store, TradeExecutionReceiptStore):
            raise TypeError("store must be a TradeExecutionReceiptStore")
        self.store = store

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
        return self.store.put(candidate, order=order)


__all__ = ["TradeExecutionCoordinator"]
