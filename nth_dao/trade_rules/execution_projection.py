"""Fail-closed, read-only projection of Agreement execution readiness."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from nth_dao.did_key import is_did_key
from nth_dao.trade_rules.agreement_order import TradeOrder, trade_order_digest
from nth_dao.trade_rules.execution_adapter import TradeExecutionAdapterPolicy
from nth_dao.trade_rules.execution_receipt import trade_order_execution_grants
from nth_dao.trade_rules.manifest import evaluate_manifest
from nth_dao.trade_rules.negotiation import RuleResolutionPolicy
from nth_dao.trade_rules.order_execution import (
    TradeOrderExecutionRejected,
    verify_trade_order_execution,
)
from nth_dao.trade_rules.offer import TradeOffer, offer_digest


class TradeExecutionProjectionError(ValueError):
    """The signed Agreement cannot be projected without ambiguity."""


_RUNTIME_HEALTH_STATUSES = frozenset({
    "healthy",
    "recovering",
    "degraded",
    "unavailable",
})
_ERROR_CODE_RE = re.compile(r"[a-z][a-z0-9-]{0,63}")


@dataclass(frozen=True)
class TradeExecutionRuntimeHealth:
    """Stable, non-sensitive health of the local execution persistence path."""

    status: str
    receipt_persistence_available: bool
    recovery_pending: bool = False
    error_code: str = ""

    def __post_init__(self) -> None:
        if self.status not in _RUNTIME_HEALTH_STATUSES:
            raise ValueError("execution runtime health status is invalid")
        if not isinstance(self.receipt_persistence_available, bool):
            raise TypeError("receipt_persistence_available must be a boolean")
        if not isinstance(self.recovery_pending, bool):
            raise TypeError("recovery_pending must be a boolean")
        if not isinstance(self.error_code, str) or (
            self.error_code and _ERROR_CODE_RE.fullmatch(self.error_code) is None
        ):
            raise ValueError("execution runtime health error_code is invalid")
        if self.status == "healthy" and (
            not self.receipt_persistence_available
            or self.recovery_pending
            or self.error_code
        ):
            raise ValueError("healthy execution runtime has inconsistent fields")
        if self.status != "healthy" and not self.error_code:
            raise ValueError("non-healthy execution runtime requires error_code")
        if self.status == "recovering" and not self.recovery_pending:
            raise ValueError("recovering execution runtime must be pending")
        if self.status == "unavailable" and self.receipt_persistence_available:
            raise ValueError("unavailable execution runtime cannot persist Receipts")

    @property
    def coordinator_available(self) -> bool:
        return self.status != "unavailable"

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.coordinator_available,
            "status": self.status,
            "receipt_persistence_available": self.receipt_persistence_available,
            "recovery_pending": self.recovery_pending,
            "error_code": self.error_code,
            "execution_endpoint_enabled": False,
        }


def _utc(value: datetime | None) -> datetime:
    moment = value or datetime.now(timezone.utc)
    if (
        not isinstance(moment, datetime)
        or moment.tzinfo is None
        or moment.utcoffset() is None
    ):
        raise TradeExecutionProjectionError("at must be timezone-aware")
    return moment.astimezone(timezone.utc)


def _local_role(document: dict[str, Any], local_did: str | None) -> str:
    if not local_did:
        return "unavailable"
    if not is_did_key(local_did):
        raise TradeExecutionProjectionError("local_did must be an Ed25519 did:key")
    if local_did == document["maker_did"]:
        return "maker"
    if local_did == document["taker_did"]:
        return "taker"
    return "observer"


def _load_skill(
    package_resolver: Any,
    package_digest: str,
    *,
    at: datetime,
) -> tuple[dict[str, Any], Any | None]:
    try:
        package = package_resolver.load(package_digest)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        error_type = type(exc).__name__
        return ({
            "package_digest": package_digest,
            "installed": False,
            "current": False,
            "status": "unavailable",
            "reason": f"Rule Package lookup failed ({error_type})",
        }, None)
    if package is None:
        return ({
            "package_digest": package_digest,
            "installed": False,
            "current": False,
            "status": "missing",
            "reason": "Exact signed Rule Package is not installed locally",
        }, None)
    try:
        manifest = package.manifest.to_dict()
        if package.digest != package_digest:
            raise ValueError("resolved package digest differs from Agreement")
        current, reason = evaluate_manifest(package.manifest, at=at)
    except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
        error_type = type(exc).__name__
        return ({
            "package_digest": package_digest,
            "installed": False,
            "current": False,
            "status": "invalid",
            "reason": f"Installed Rule Package is invalid ({error_type})",
        }, None)
    return ({
        "package_digest": package_digest,
        "rule_id": manifest["rule_id"],
        "version": manifest["version"],
        "publisher_did": manifest["publisher_did"],
        "summary": manifest["summary"],
        "execution_mode": manifest["execution"]["mode"],
        "installed": True,
        "current": current,
        "status": "available" if current else "expired",
        "reason": reason,
    }, package)


def project_trade_order_execution(
    order: TradeOrder | dict[str, Any],
    package_resolver: Any,
    *,
    local_did: str | None,
    coordinator_health: TradeExecutionRuntimeHealth,
    executor_policy: RuleResolutionPolicy | None = None,
    adapter_resolver: Any | None = None,
    adapter_policy: TradeExecutionAdapterPolicy | None = None,
    content_resolver: Any | None = None,
    at: datetime | None = None,
) -> dict[str, Any]:
    """Project what is signed, installed, and still missing before execution.

    This function never selects an Adapter, loads execution input, invokes a
    Hook, or issues a Receipt.  A signed bilateral policy is historical input,
    not a substitute for the current local ``executor_policy``.
    """

    if not callable(getattr(package_resolver, "load", None)):
        raise TypeError("package_resolver must provide load(digest)")
    if not isinstance(coordinator_health, TradeExecutionRuntimeHealth):
        raise TypeError(
            "coordinator_health must be a TradeExecutionRuntimeHealth"
        )
    if executor_policy is not None and not isinstance(
        executor_policy, RuleResolutionPolicy
    ):
        raise TypeError("executor_policy must be a RuleResolutionPolicy or None")
    if (adapter_resolver is None) != (adapter_policy is None):
        raise TradeExecutionProjectionError(
            "adapter resolver and policy must be configured together"
        )
    if adapter_policy is not None and not isinstance(
        adapter_policy, TradeExecutionAdapterPolicy
    ):
        raise TypeError("adapter_policy must be a TradeExecutionAdapterPolicy")
    if adapter_resolver is not None and (
        not callable(getattr(adapter_resolver, "load", None))
        or not callable(getattr(adapter_resolver, "load_artifact", None))
    ):
        raise TradeExecutionProjectionError(
            "adapter_resolver must provide load() and load_artifact()"
        )
    if content_resolver is not None and not callable(
        getattr(content_resolver, "load", None)
    ):
        raise TradeExecutionProjectionError(
            "content_resolver must provide load(digest, max_bytes=...)"
        )

    verified = (
        TradeOrder.from_json(order.canonical_bytes)
        if isinstance(order, TradeOrder)
        else TradeOrder.from_dict(order)
    )
    document = verified.to_dict()
    source_offer_digest = offer_digest(
        TradeOffer.from_dict(document["snapshot"]["offer"])
    )
    moment = _utc(at)
    role = _local_role(document, local_did)
    grants = trade_order_execution_grants(verified)

    skills: list[dict[str, Any]] = []
    packages: dict[str, Any | None] = {}
    for binding in document["rule_bindings"]:
        skill, package = _load_skill(
            package_resolver,
            binding["digest"],
            at=moment,
        )
        if skill.get("rule_id") not in {None, binding["rule_id"]}:
            skill.update({
                "installed": False,
                "current": False,
                "status": "invalid",
                "reason": "Rule Package rule_id differs from Agreement binding",
            })
            package = None
        skill.setdefault("rule_id", binding["rule_id"])
        skills.append(skill)
        packages[binding["digest"]] = package

    projected_grants: list[dict[str, Any]] = []
    all_contracts_ready = True
    funds_grants = 0
    for grant in grants:
        package = packages.get(grant["package_digest"])
        hook: dict[str, Any] | None = None
        if package is not None:
            manifest = package.manifest.to_dict()
            matches = [
                candidate
                for candidate in manifest["hook_contracts"]
                if candidate["name"] == grant["hook_name"]
                and candidate["version"] == grant["hook_version"]
            ]
            if len(matches) == 1 and manifest["rule_id"] == grant["rule_id"]:
                hook = matches[0]
        input_available = bool(
            hook is not None
            and hook["input_schema_digest"] in package.resources
        )
        output_available = bool(
            hook is not None
            and hook["output_schema_digest"] in package.resources
        )
        contract_available = (
            hook is not None and input_available and output_available
        )
        all_contracts_ready = all_contracts_ready and contract_available
        side_effect = hook["side_effect"] if hook is not None else "unknown"
        if side_effect == "funds":
            funds_grants += 1
        projected_grants.append({
            **grant,
            "local_executor": role == grant["executor_role"],
            "contract_available": contract_available,
            "input_schema_content_available": input_available,
            "output_schema_content_available": output_available,
            "side_effect": side_effect,
            "permissions": list(hook["permissions"]) if hook is not None else [],
            "funds_execution_enabled": False,
        })

    readiness = None
    policy_status = "not-configured"
    policy_reason = (
        "No current local executor policy is configured; bilateral signed "
        "policies are not trusted as local execution approval"
    )
    if executor_policy is not None:
        try:
            readiness = verify_trade_order_execution(
                verified,
                package_resolver,
                executor_policy,
                at=moment,
            )
        except TradeOrderExecutionRejected:
            policy_status = "blocked"
            policy_reason = "Current local executor policy rejected the Agreement"
        else:
            policy_status = "ready"
            policy_reason = "Current local executor policy revalidated the Agreement"

    adapter_configured = adapter_resolver is not None
    adapter_status = (
        "selection-required" if adapter_configured else "not-configured"
    )
    content_configured = content_resolver is not None
    authorized_operations = sum(
        1 for grant in projected_grants if grant["local_executor"]
    )
    blocking_reasons: list[str] = []
    if not coordinator_health.receipt_persistence_available:
        blocking_reasons.append("TradeExecutionCoordinator is unavailable")
    if role not in {"maker", "taker"}:
        blocking_reasons.append("Local DID is not an Agreement party")
    if not grants:
        blocking_reasons.append("Agreement has no operation grants")
    elif authorized_operations == 0:
        blocking_reasons.append("No operation grant authorizes the local role")
    if any(not skill["installed"] or not skill["current"] for skill in skills):
        blocking_reasons.append("One or more signed Trade Skills are unavailable")
    if not all_contracts_ready:
        blocking_reasons.append(
            "One or more Hook contracts or schema contents are unavailable"
        )
    if policy_status != "ready":
        blocking_reasons.append("Current local executor policy did not approve execution")
    if not adapter_configured:
        blocking_reasons.append("No local Adapter resolver and policy are configured")
    else:
        blocking_reasons.append("An exact approved Adapter must be selected per operation")
    if not content_configured:
        blocking_reasons.append("No runtime content resolver is configured")
    if funds_grants:
        blocking_reasons.append(
            "Funds side effects are disabled and require a separately verified mandate"
        )

    return {
        "order_digest": trade_order_digest(verified),
        "source_offer_digest": source_offer_digest,
        "status": "blocked" if blocking_reasons else "ready",
        "error_code": "",
        "coordinator": coordinator_health.to_dict(),
        "local_executor": {
            "did": local_did or "",
            "role": role,
            "authorized_operation_count": authorized_operations,
        },
        "skills": skills,
        "operation_grants": projected_grants,
        "executor_policy": {
            "configured": executor_policy is not None,
            "status": policy_status,
            "digest": executor_policy.digest if executor_policy is not None else "",
            "reason": policy_reason,
            "readiness": readiness.to_dict() if readiness is not None else None,
        },
        "adapter": {
            "configured": adapter_configured,
            "status": adapter_status,
            "policy_digest": adapter_policy.digest if adapter_policy is not None else "",
            "accepted_adapter_count": (
                len(adapter_policy.accepted_adapter_digests)
                if adapter_policy is not None
                else 0
            ),
        },
        "content": {
            "resolver_configured": content_configured,
            "contract_schema_content_available": (
                all_contracts_ready and bool(grants)
            ),
            "runtime_payloads_ready": False,
            "status": "awaiting-operation-input" if content_configured else "not-configured",
        },
        "funds": {
            "enabled": False,
            "grant_count": funds_grants,
            "reason": (
                "Real-funds execution is disabled by default; a separately "
                "verified payment mandate and explicit runtime are required"
            ),
        },
        "blocking_reasons": blocking_reasons,
        "evaluated_at": moment.isoformat().replace("+00:00", "Z"),
    }


def unavailable_trade_order_execution_projection(
    *,
    order_digest: str,
    local_did: str | None,
    coordinator_health: TradeExecutionRuntimeHealth,
    error_code: str = "projection-failed",
    at: datetime | None = None,
) -> dict[str, Any]:
    """Return a bounded fail-closed view without consulting local plugins.

    The caller supplies the digest from an already verified Agreement audit
    record. No Agreement extension, local resolver, or policy is parsed here,
    so this function is deliberately unable to hide the retained Agreement.
    """

    if not isinstance(coordinator_health, TradeExecutionRuntimeHealth):
        coordinator_health = TradeExecutionRuntimeHealth(
            status="unavailable",
            receipt_persistence_available=False,
            error_code="runtime-health-invalid",
        )
    if not isinstance(error_code, str) or _ERROR_CODE_RE.fullmatch(error_code) is None:
        error_code = "projection-failed"
    if (
        not isinstance(order_digest, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", order_digest) is None
    ):
        order_digest = ""
        error_code = "projection-fallback-invalid-order-digest"
    moment = _utc(at)
    if not isinstance(local_did, str):
        local_did = None
    return {
        "order_digest": order_digest,
        "source_offer_digest": "",
        "status": "unavailable",
        "error_code": error_code,
        "coordinator": coordinator_health.to_dict(),
        "local_executor": {
            "did": local_did or "",
            "role": "unavailable",
            "authorized_operation_count": 0,
        },
        "skills": [],
        "operation_grants": [],
        "executor_policy": {
            "configured": False,
            "status": "unavailable",
            "digest": "",
            "reason": "Execution projection is unavailable on this node",
            "readiness": None,
        },
        "adapter": {
            "configured": False,
            "status": "unavailable",
            "policy_digest": "",
            "accepted_adapter_count": 0,
        },
        "content": {
            "resolver_configured": False,
            "contract_schema_content_available": False,
            "runtime_payloads_ready": False,
            "status": "unavailable",
        },
        "funds": {
            "enabled": False,
            "grant_count": 0,
            "reason": (
                "Real-funds execution is disabled by default; a separately "
                "verified payment mandate and explicit runtime are required"
            ),
        },
        "blocking_reasons": [
            "Execution readiness could not be projected; no operation is authorized"
        ],
        "evaluated_at": moment.isoformat().replace("+00:00", "Z"),
    }


__all__ = [
    "TradeExecutionProjectionError",
    "TradeExecutionRuntimeHealth",
    "project_trade_order_execution",
    "unavailable_trade_order_execution_projection",
]
