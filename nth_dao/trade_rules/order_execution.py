"""Execution-readiness gate for accepted Trade Order Rule Packages."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from nth_dao.trade_rules.canonical import trade_canonical_json
from nth_dao.trade_rules.agreement_order import (
    TradeOrder,
    trade_order_digest,
)
from nth_dao.trade_rules.manifest import evaluate_manifest
from nth_dao.trade_rules.negotiation import (
    RuleNegotiationError,
    RulePackageResolver,
    RuleResolution,
    RuleResolutionPolicy,
    resolve_offer_rules,
)
from nth_dao.trade_rules.offer import TradeOffer

EXECUTION_READINESS_KIND = "nth.dao.trade.execution-readiness"
EXECUTION_READINESS_PROTOCOL_VERSION = "1"


class TradeOrderExecutionRejected(ValueError):
    """The signed Order is not safe to execute under current local policy."""


@dataclass(frozen=True)
class TradeOrderExecutionReadiness:
    order_digest: str
    executor_policy_digest: str
    ordered_package_digests: tuple[str, ...]
    required_capabilities: tuple[str, ...]
    required_permissions: tuple[str, ...]
    execution_modes: tuple[str, ...]
    resolved_resource_bytes: int
    evaluated_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": EXECUTION_READINESS_KIND,
            "protocol_version": EXECUTION_READINESS_PROTOCOL_VERSION,
            "order_digest": self.order_digest,
            "executor_policy_digest": self.executor_policy_digest,
            "ordered_package_digests": list(self.ordered_package_digests),
            "required_capabilities": list(self.required_capabilities),
            "required_permissions": list(self.required_permissions),
            "execution_modes": list(self.execution_modes),
            "resolved_resource_bytes": self.resolved_resource_bytes,
            "evaluated_at": self.evaluated_at,
        }

    @property
    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            trade_canonical_json(self.to_dict())
        ).hexdigest()


def _utc(value: datetime, *, label: str) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _timestamp(value: Any, *, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise TradeOrderExecutionRejected(f"{label} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TradeOrderExecutionRejected(f"{label} is invalid") from exc
    return _utc(parsed, label=label)


def _bindings(resolution: RuleResolution) -> tuple[tuple[str, str], ...]:
    return tuple(
        sorted(
            (
                package.manifest.rule_id,
                package.digest,
            )
            for package in resolution.packages
        )
    )


def _resolve(
    *,
    offer: TradeOffer,
    resolver: RulePackageResolver,
    policy: RuleResolutionPolicy,
    agreement_at: datetime,
    label: str,
) -> RuleResolution:
    try:
        return resolve_offer_rules(
            offer,
            resolver,
            policy,
            at=agreement_at,
        )
    except (
        OSError,
        RuleNegotiationError,
        RuntimeError,
        TypeError,
        ValueError,
    ) as exc:
        raise TradeOrderExecutionRejected(
            f"{label} Rule Package resolution failed: {exc}"
        ) from exc


def verify_trade_order_execution(
    order: TradeOrder | dict[str, Any],
    package_resolver: RulePackageResolver,
    executor_policy: RuleResolutionPolicy,
    *,
    at: datetime,
) -> TradeOrderExecutionReadiness:
    """Re-resolve every transitive Rule dependency before execution.

    The Offer is replayed at the signed acceptance time because expiry of a
    market listing must not erase an already accepted bilateral Order. Every
    resolved Rule manifest is then checked again at the actual execution time.
    The current executor policy is mandatory, so a node can revoke local trust
    or execution permissions after agreement without rewriting signed history.
    """

    verified = (
        TradeOrder.from_json(order.canonical_bytes)
        if isinstance(order, TradeOrder)
        else TradeOrder.from_dict(order)
    )
    if not callable(getattr(package_resolver, "load", None)):
        raise TypeError("package_resolver must provide load(digest)")
    if not isinstance(executor_policy, RuleResolutionPolicy):
        raise TypeError("executor_policy must be a RuleResolutionPolicy")
    execution_at = _utc(at, label="at")
    document = verified.to_dict()
    snapshot = document["snapshot"]
    offer = TradeOffer.from_dict(snapshot["offer"])
    proposal = snapshot["proposal"]
    acceptance = snapshot["acceptance"]
    taker_policy = RuleResolutionPolicy.from_dict(proposal["taker_policy"])
    maker_policy = RuleResolutionPolicy.from_dict(acceptance["maker_policy"])
    if taker_policy.digest != document["policy_digests"]["taker"]:
        raise TradeOrderExecutionRejected(
            "taker policy digest does not match the signed Order"
        )
    if maker_policy.digest != document["policy_digests"]["maker"]:
        raise TradeOrderExecutionRejected(
            "maker policy digest does not match the signed Order"
        )
    agreement_at = _timestamp(
        acceptance["created_at"],
        label="acceptance.created_at",
    )
    if execution_at < agreement_at:
        raise TradeOrderExecutionRejected(
            "execution time precedes the signed Acceptance"
        )
    expected_bindings = tuple(
        (item["rule_id"], item["digest"])
        for item in document["rule_bindings"]
    )
    resolutions = (
        (
            "taker signed policy",
            _resolve(
                offer=offer,
                resolver=package_resolver,
                policy=taker_policy,
                agreement_at=agreement_at,
                label="taker signed policy",
            ),
        ),
        (
            "maker signed policy",
            _resolve(
                offer=offer,
                resolver=package_resolver,
                policy=maker_policy,
                agreement_at=agreement_at,
                label="maker signed policy",
            ),
        ),
        (
            "current executor policy",
            _resolve(
                offer=offer,
                resolver=package_resolver,
                policy=executor_policy,
                agreement_at=agreement_at,
                label="current executor policy",
            ),
        ),
    )
    baseline: RuleResolution | None = None
    for label, resolution in resolutions:
        if _bindings(resolution) != expected_bindings:
            raise TradeOrderExecutionRejected(
                f"{label} resolved bindings do not match the signed Order"
            )
        if baseline is None:
            baseline = resolution
            continue
        if (
            resolution.root_digests != baseline.root_digests
            or resolution.ordered_digests != baseline.ordered_digests
            or resolution.required_capabilities
            != baseline.required_capabilities
            or resolution.required_permissions
            != baseline.required_permissions
            or resolution.execution_modes != baseline.execution_modes
            or resolution.resolved_resource_bytes
            != baseline.resolved_resource_bytes
        ):
            raise TradeOrderExecutionRejected(
                f"{label} resolution disagrees with the bilateral result"
            )
    if baseline is None:  # pragma: no cover - fixed three-policy tuple
        raise TradeOrderExecutionRejected("no Rule resolution was produced")
    for package in baseline.packages:
        active, reason = evaluate_manifest(package.manifest, at=execution_at)
        if not active:
            raise TradeOrderExecutionRejected(
                f"Rule Package {package.digest} is not execution-current: "
                f"{reason}"
            )
    return TradeOrderExecutionReadiness(
        order_digest=trade_order_digest(verified),
        executor_policy_digest=executor_policy.digest,
        ordered_package_digests=baseline.ordered_digests,
        required_capabilities=baseline.required_capabilities,
        required_permissions=baseline.required_permissions,
        execution_modes=baseline.execution_modes,
        resolved_resource_bytes=baseline.resolved_resource_bytes,
        evaluated_at=execution_at.isoformat().replace("+00:00", "Z"),
    )


__all__ = [
    "EXECUTION_READINESS_KIND",
    "EXECUTION_READINESS_PROTOCOL_VERSION",
    "TradeOrderExecutionReadiness",
    "TradeOrderExecutionRejected",
    "verify_trade_order_execution",
]
