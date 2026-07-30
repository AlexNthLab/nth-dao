"""Fail-closed exact-digest resolution for Trade Offer rule references."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Protocol

from nth_dao.did_key import is_did_key
from nth_dao.trade_rules.canonical import (
    TradeCanonicalJSONError,
    trade_canonical_json,
)
from nth_dao.trade_rules.manifest import (
    MANIFEST_EXECUTION_MODES,
    evaluate_manifest,
)
from nth_dao.trade_rules.offer import (
    OfferRejected,
    TradeOffer,
    evaluate_offer,
    offer_digest,
)
from nth_dao.trade_rules.package_store import (
    RulePackage,
    RulePackageError,
    build_rule_package,
)

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[a-z0-9][a-z0-9._:/-]*$")
DEFAULT_MAX_RULE_DEPTH = 32
DEFAULT_MAX_RESOLVED_PACKAGES = 256
DEFAULT_MAX_RESOLVED_RESOURCE_BYTES = 64 * 1024 * 1024


class RuleNegotiationError(ValueError):
    """A required rule set cannot be accepted under explicit local policy."""


class RulePackageResolver(Protocol):
    """Minimal resolver contract for local, Git, or federated package sources."""

    def load(self, digest: str) -> RulePackage | None: ...


class CanonicalOfferResolver(Protocol):
    """Lifecycle projection required before rules can enter an Order."""

    def canonical_snapshot(
        self,
        publisher_did: str,
        offer_id: str,
    ) -> tuple[Any, TradeOffer | None]: ...


def _frozen_strings(
    values: Iterable[str],
    *,
    label: str,
    validator: Any,
    maximum: int,
) -> frozenset[str]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Iterable):
        raise TypeError(f"{label} must be an iterable of strings")
    output: set[str] = set()
    for index, value in enumerate(values):
        if index >= maximum:
            raise ValueError(f"{label} exceeds the {maximum}-entry limit")
        if not isinstance(value, str) or not validator(value):
            raise ValueError(f"{label} contains an invalid value")
        output.add(value)
    return frozenset(output)


@dataclass(frozen=True)
class RuleResolutionPolicy:
    """Local recognition and execution declaration policy.

    Resolution never executes package resources. Non-declarative modes require
    both an allowed mode and an exact approved package digest so publisher-wide
    trust cannot silently grant code execution.
    """

    accepted_publishers: frozenset[str] = frozenset()
    accepted_package_digests: frozenset[str] = frozenset()
    available_capabilities: frozenset[str] = frozenset()
    allowed_permissions: frozenset[str] = frozenset()
    allowed_execution_modes: frozenset[str] = frozenset({"declarative"})
    approved_executable_digests: frozenset[str] = frozenset()
    max_depth: int = DEFAULT_MAX_RULE_DEPTH
    max_packages: int = DEFAULT_MAX_RESOLVED_PACKAGES
    max_resource_bytes: int = DEFAULT_MAX_RESOLVED_RESOURCE_BYTES

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> "RuleResolutionPolicy":
        fields = {
            "kind",
            "protocol_version",
            "accepted_publishers",
            "accepted_package_digests",
            "available_capabilities",
            "allowed_permissions",
            "allowed_execution_modes",
            "approved_executable_digests",
            "max_depth",
            "max_packages",
            "max_resource_bytes",
        }
        if not isinstance(document, dict) or set(document) != fields:
            raise ValueError(
                "rule resolution policy has missing or unknown fields"
            )
        if (
            document["kind"] != "nth.dao.trade.rule-resolution-policy"
            or document["protocol_version"] != "1"
        ):
            raise ValueError("rule resolution policy version is invalid")
        policy = cls(
            accepted_publishers=document["accepted_publishers"],
            accepted_package_digests=document["accepted_package_digests"],
            available_capabilities=document["available_capabilities"],
            allowed_permissions=document["allowed_permissions"],
            allowed_execution_modes=document["allowed_execution_modes"],
            approved_executable_digests=document[
                "approved_executable_digests"
            ],
            max_depth=document["max_depth"],
            max_packages=document["max_packages"],
            max_resource_bytes=document["max_resource_bytes"],
        )
        if policy.canonical_bytes != trade_canonical_json(document):
            raise ValueError("rule resolution policy is not canonical")
        return policy

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "accepted_publishers",
            _frozen_strings(
                self.accepted_publishers,
                label="accepted_publishers",
                validator=is_did_key,
                maximum=4_096,
            ),
        )
        for field_name in (
            "accepted_package_digests",
            "approved_executable_digests",
        ):
            object.__setattr__(
                self,
                field_name,
                _frozen_strings(
                    getattr(self, field_name),
                    label=field_name,
                    validator=lambda value: _DIGEST.fullmatch(value) is not None,
                    maximum=4_096,
                ),
            )
        object.__setattr__(
            self,
            "available_capabilities",
            _frozen_strings(
                self.available_capabilities,
                label="available_capabilities",
                validator=lambda value: (
                    len(value) <= 160 and _TOKEN.fullmatch(value) is not None
                ),
                maximum=1_024,
            ),
        )
        object.__setattr__(
            self,
            "allowed_permissions",
            _frozen_strings(
                self.allowed_permissions,
                label="allowed_permissions",
                validator=lambda value: (
                    len(value) <= 160 and _TOKEN.fullmatch(value) is not None
                ),
                maximum=1_024,
            ),
        )
        object.__setattr__(
            self,
            "allowed_execution_modes",
            _frozen_strings(
                self.allowed_execution_modes,
                label="allowed_execution_modes",
                validator=lambda value: value in MANIFEST_EXECUTION_MODES,
                maximum=len(MANIFEST_EXECUTION_MODES),
            ),
        )
        if "declarative" not in self.allowed_execution_modes:
            raise ValueError(
                "allowed_execution_modes must include declarative"
            )
        for field_name, maximum in (
            ("max_depth", 128),
            ("max_packages", 4_096),
            ("max_resource_bytes", 1024 * 1024 * 1024),
        ):
            value = getattr(self, field_name)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 1 <= value <= maximum
            ):
                raise ValueError(
                    f"{field_name} must be an integer in 1..{maximum}"
                )
        try:
            self.canonical_bytes
        except TradeCanonicalJSONError as exc:
            raise ValueError(
                "rule resolution policy exceeds canonical encoding limits"
            ) from exc

    def accepts(self, package: RulePackage) -> bool:
        return (
            package.digest in self.accepted_package_digests
            or package.digest in self.approved_executable_digests
            or package.manifest.publisher_did in self.accepted_publishers
        )

    @property
    def canonical_bytes(self) -> bytes:
        return trade_canonical_json(
            {
                "kind": "nth.dao.trade.rule-resolution-policy",
                "protocol_version": "1",
                "accepted_publishers": sorted(self.accepted_publishers),
                "accepted_package_digests": sorted(
                    self.accepted_package_digests
                ),
                "available_capabilities": sorted(
                    self.available_capabilities
                ),
                "allowed_permissions": sorted(self.allowed_permissions),
                "allowed_execution_modes": sorted(
                    self.allowed_execution_modes
                ),
                "approved_executable_digests": sorted(
                    self.approved_executable_digests
                ),
                "max_depth": self.max_depth,
                "max_packages": self.max_packages,
                "max_resource_bytes": self.max_resource_bytes,
            }
        )

    @property
    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(self.canonical_bytes).hexdigest()


@dataclass(frozen=True)
class RuleResolution:
    root_digests: tuple[str, ...]
    ordered_digests: tuple[str, ...]
    packages: tuple[RulePackage, ...]
    required_capabilities: tuple[str, ...]
    required_permissions: tuple[str, ...]
    execution_modes: tuple[str, ...]
    resolved_resource_bytes: int

    def bindings(self) -> tuple[dict[str, str], ...]:
        return tuple(
            {
                "rule_id": package.manifest.rule_id,
                "digest": package.digest,
            }
            for package in self.packages
        )


@dataclass(frozen=True)
class CanonicalRuleResolution(RuleResolution):
    offer_publisher_did: str
    offer_id: str
    offer_revision: int
    offer_digest: str
    canonical_chain_digests: tuple[str, ...]
    evaluated_at: str
    policy_digest: str
    policy_canonical_bytes: bytes


def _evaluation_moment(at: datetime | None) -> datetime:
    moment = at or datetime.now(timezone.utc)
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("at must be timezone-aware")
    return moment.astimezone(timezone.utc)


def _rfc3339(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


def _verified_offer(
    value: TradeOffer | dict[str, Any],
) -> TradeOffer:
    try:
        if isinstance(value, TradeOffer):
            return TradeOffer.from_json(value.canonical_bytes)
        if isinstance(value, dict):
            return TradeOffer.from_dict(value)
    except OfferRejected as exc:
        raise RuleNegotiationError(f"offer rejected: {exc}") from exc
    raise TypeError("offer must be a TradeOffer or object")


def resolve_offer_rules(
    offer: TradeOffer | dict[str, Any],
    resolver: RulePackageResolver,
    policy: RuleResolutionPolicy,
    *,
    at: datetime | None = None,
) -> RuleResolution:
    """Resolve rules for one caller-selected exact signed Offer document.

    This low-level primitive does not establish registry lifecycle status.
    Order construction must use ``resolve_canonical_offer_rules``.
    """

    if not callable(getattr(resolver, "load", None)):
        raise TypeError("resolver must provide load(digest)")
    if not isinstance(policy, RuleResolutionPolicy):
        raise TypeError("policy must be a RuleResolutionPolicy")
    verified_offer = _verified_offer(offer)
    moment = _evaluation_moment(at)
    active, reason = evaluate_offer(verified_offer, at=moment)
    if not active:
        raise RuleNegotiationError(f"offer is not active: {reason}")
    offer_document = verified_offer.to_dict()
    root_refs = tuple(
        (reference["rule_id"], reference["digest"])
        for reference in offer_document["rule_refs"]
    )
    if not root_refs:
        return RuleResolution(
            root_digests=(),
            ordered_digests=(),
            packages=(),
            required_capabilities=(),
            required_permissions=(),
            execution_modes=(),
            resolved_resource_bytes=0,
        )

    visiting: set[str] = set()
    loaded: dict[str, RulePackage] = {}
    discovered: set[str] = set()
    rule_ids: dict[str, str] = {}
    ordered: list[RulePackage] = []
    resource_sizes: dict[str, int] = {}
    resolved_resource_bytes = 0

    def visit(rule_id: str, digest: str, *, depth: int) -> None:
        nonlocal resolved_resource_bytes
        if depth > policy.max_depth:
            raise RuleNegotiationError(
                f"rule dependency depth exceeds {policy.max_depth}"
            )
        existing_digest = rule_ids.get(rule_id)
        if existing_digest is not None and existing_digest != digest:
            raise RuleNegotiationError(
                f"rule_id {rule_id} resolves to multiple exact digests"
            )
        if digest in loaded:
            if loaded[digest].manifest.rule_id != rule_id:
                raise RuleNegotiationError(
                    f"package {digest} does not declare rule_id {rule_id}"
                )
            return
        if digest in visiting:
            raise RuleNegotiationError(
                f"dependency cycle detected at package {digest}"
            )
        if digest not in discovered:
            if len(discovered) >= policy.max_packages:
                raise RuleNegotiationError(
                    f"resolved rule set exceeds {policy.max_packages} packages"
                )
            discovered.add(digest)
        package = resolver.load(digest)
        if package is None:
            raise RuleNegotiationError(
                f"required rule package is unavailable: {rule_id} {digest}"
            )
        if not isinstance(package, RulePackage):
            raise RuleNegotiationError(
                f"resolver returned an invalid package for {digest}"
            )
        try:
            verified_package = build_rule_package(
                package.manifest,
                package.resources,
            )
        except (RulePackageError, TypeError, ValueError) as exc:
            raise RuleNegotiationError(
                f"resolver returned an unverified package for {digest}: {exc}"
            ) from exc
        if verified_package.digest != digest:
            raise RuleNegotiationError(
                f"package content digest does not match requested digest {digest}"
            )
        if verified_package.manifest.rule_id != rule_id:
            raise RuleNegotiationError(
                f"package {digest} does not declare rule_id {rule_id}"
            )
        package = verified_package
        new_resources = {
            resource_digest: len(payload)
            for resource_digest, payload in package.resources.items()
            if resource_digest not in resource_sizes
        }
        added_bytes = sum(new_resources.values())
        if (
            resolved_resource_bytes + added_bytes
            > policy.max_resource_bytes
        ):
            raise RuleNegotiationError(
                "resolved rule resources exceed "
                f"{policy.max_resource_bytes} bytes"
            )
        resource_sizes.update(new_resources)
        resolved_resource_bytes += added_bytes
        if not policy.accepts(package):
            raise RuleNegotiationError(
                f"rule package is not accepted by local policy: {digest}"
            )
        current, current_reason = evaluate_manifest(
            package.manifest,
            at=moment,
        )
        if not current:
            raise RuleNegotiationError(
                f"rule package {digest} is not active: {current_reason}"
            )
        document = package.manifest.to_dict()
        missing_capabilities = sorted(
            set(document["required_capabilities"])
            - policy.available_capabilities
        )
        if missing_capabilities:
            raise RuleNegotiationError(
                f"rule package {digest} requires unavailable capabilities: "
                f"{missing_capabilities}"
            )
        mode = document["execution"]["mode"]
        if mode not in policy.allowed_execution_modes:
            raise RuleNegotiationError(
                f"rule package {digest} execution mode is not allowed: {mode}"
            )
        if (
            mode != "declarative"
            and digest not in policy.approved_executable_digests
        ):
            raise RuleNegotiationError(
                f"rule package {digest} lacks exact executable approval"
            )
        missing_permissions = sorted(
            set(document["execution"]["permissions"])
            - policy.allowed_permissions
        )
        if missing_permissions:
            raise RuleNegotiationError(
                f"rule package {digest} requests disallowed permissions: "
                f"{missing_permissions}"
            )

        visiting.add(digest)
        rule_ids[rule_id] = digest
        try:
            for dependency in document["dependencies"]:
                visit(
                    dependency["rule_id"],
                    dependency["digest"],
                    depth=depth + 1,
                )
        finally:
            visiting.remove(digest)
        loaded[digest] = package
        ordered.append(package)

    for root_rule_id, root_digest in root_refs:
        visit(root_rule_id, root_digest, depth=1)

    loaded_digests = set(loaded)
    for package in ordered:
        for conflict in package.manifest.to_dict()["conflicts"]:
            if conflict["digest"] in loaded_digests:
                conflicting = loaded[conflict["digest"]]
                if conflicting.manifest.rule_id == conflict["rule_id"]:
                    raise RuleNegotiationError(
                        f"rule conflict: {package.digest} conflicts with "
                        f"{conflicting.digest}"
                    )

    capabilities = sorted(
        {
            capability
            for package in ordered
            for capability in package.manifest.to_dict()[
                "required_capabilities"
            ]
        }
    )
    modes = sorted(
        {
            package.manifest.to_dict()["execution"]["mode"]
            for package in ordered
        }
    )
    permissions = sorted(
        {
            permission
            for package in ordered
            for permission in package.manifest.to_dict()["execution"][
                "permissions"
            ]
        }
    )
    return RuleResolution(
        root_digests=tuple(digest for _, digest in root_refs),
        ordered_digests=tuple(package.digest for package in ordered),
        packages=tuple(ordered),
        required_capabilities=tuple(capabilities),
        required_permissions=tuple(permissions),
        execution_modes=tuple(modes),
        resolved_resource_bytes=resolved_resource_bytes,
    )


def resolve_canonical_offer_rules(
    publisher_did: str,
    offer_id: str,
    offer_resolver: CanonicalOfferResolver,
    rule_resolver: RulePackageResolver,
    policy: RuleResolutionPolicy,
    *,
    at: datetime | None = None,
) -> CanonicalRuleResolution:
    """Resolve only the canonical lifecycle head selected by an Offer store."""

    if not callable(getattr(offer_resolver, "canonical_snapshot", None)):
        raise TypeError("offer_resolver must provide canonical_snapshot()")
    snapshot = offer_resolver.canonical_snapshot(
        publisher_did, offer_id
    )
    if not isinstance(snapshot, tuple) or len(snapshot) != 2:
        raise RuleNegotiationError(
            "offer resolver returned an invalid canonical snapshot"
        )
    view, selected = snapshot
    status = getattr(view, "status", None)
    head_digest = getattr(view, "canonical_head_digest", None)
    chain_digests = getattr(view, "canonical_digests", None)
    if status != "canonical" or not isinstance(head_digest, str):
        raise RuleNegotiationError(
            f"offer lifecycle is not canonical: {status or 'unknown'}"
        )
    if (
        not isinstance(chain_digests, tuple)
        or not chain_digests
        or any(
            not isinstance(digest, str)
            or _DIGEST.fullmatch(digest) is None
            for digest in chain_digests
        )
        or chain_digests[-1] != head_digest
    ):
        raise RuleNegotiationError(
            "canonical offer lifecycle evidence is invalid"
        )
    if selected is None:
        raise RuleNegotiationError(
            "canonical offer head is missing from its content store"
        )
    if offer_digest(selected) != head_digest:
        raise RuleNegotiationError(
            "canonical offer head digest does not match its lifecycle projection"
        )
    if (
        selected.publisher_did != publisher_did
        or selected.offer_id != offer_id
    ):
        raise RuleNegotiationError(
            "canonical offer head does not match the requested lifecycle"
        )
    moment = _evaluation_moment(at)
    resolution = resolve_offer_rules(
        selected,
        rule_resolver,
        policy,
        at=moment,
    )
    return CanonicalRuleResolution(
        root_digests=resolution.root_digests,
        ordered_digests=resolution.ordered_digests,
        packages=resolution.packages,
        required_capabilities=resolution.required_capabilities,
        required_permissions=resolution.required_permissions,
        execution_modes=resolution.execution_modes,
        resolved_resource_bytes=resolution.resolved_resource_bytes,
        offer_publisher_did=selected.publisher_did,
        offer_id=selected.offer_id,
        offer_revision=selected.to_dict()["revision"],
        offer_digest=head_digest,
        canonical_chain_digests=chain_digests,
        evaluated_at=_rfc3339(moment),
        policy_digest=policy.digest,
        policy_canonical_bytes=policy.canonical_bytes,
    )


__all__ = [
    "CanonicalOfferResolver",
    "CanonicalRuleResolution",
    "DEFAULT_MAX_RESOLVED_PACKAGES",
    "DEFAULT_MAX_RESOLVED_RESOURCE_BYTES",
    "DEFAULT_MAX_RULE_DEPTH",
    "RuleNegotiationError",
    "RulePackageResolver",
    "RuleResolution",
    "RuleResolutionPolicy",
    "resolve_canonical_offer_rules",
    "resolve_offer_rules",
]
