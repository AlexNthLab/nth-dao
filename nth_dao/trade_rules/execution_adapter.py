"""Content-addressed local Adapter descriptors and execution policy."""

from __future__ import annotations

import copy
import hashlib
import re
from dataclasses import dataclass
from typing import Any, Protocol

from nth_dao.trade_rules.canonical import (
    TradeCanonicalJSONError,
    parse_trade_json,
    trade_canonical_json,
)
from nth_dao.trade_rules.manifest import MANIFEST_EXECUTION_MODES

ADAPTER_KIND = "nth.dao.trade.execution-adapter"
ADAPTER_PROTOCOL_VERSION = "1"
MAX_ADAPTER_HOOKS = 256
MAX_ADAPTER_PERMISSIONS = 64
MAX_ADAPTER_ARTIFACT_BYTES = 16 * 1024 * 1024

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_ADAPTER_ID = re.compile(
    rf"^{_LABEL}(?:\.{_LABEL})+"
    r"(?:/[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?)?$"
)
_RULE_ID = re.compile(
    rf"^{_LABEL}(?:\.{_LABEL})+"
    r"(?:/[a-z0-9](?:[a-z0-9._-]{0,30}[a-z0-9])?)?$"
)
_SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
_TOKEN = re.compile(r"^[a-z0-9][a-z0-9._:/-]{0,159}$")
_FIELDS = frozenset(
    {
        "kind",
        "protocol_version",
        "adapter_id",
        "adapter_version",
        "artifact_digest",
        "execution_modes",
        "hooks",
        "permissions",
    }
)
_HOOK_FIELDS = frozenset({"rule_id", "hook_name", "hook_version"})


class TradeExecutionAdapterRejected(ValueError):
    """An Adapter descriptor or local approval is invalid."""


class TradeExecutionAdapterResolver(Protocol):
    def load(self, digest: str) -> "TradeExecutionAdapter | None": ...

    def load_artifact(self, digest: str) -> bytes | None: ...


def _reject(message: str) -> None:
    raise TradeExecutionAdapterRejected(message)


def _digest(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        _reject(f"{label} must be a lowercase sha256 digest")
    return value


def _sorted_tokens(
    value: Any,
    *,
    label: str,
    maximum: int,
) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > maximum:
        _reject(f"{label} must be a list with at most {maximum} entries")
    output: list[str] = []
    for item in value:
        if not isinstance(item, str) or _TOKEN.fullmatch(item) is None:
            _reject(f"{label} contains an invalid token")
        output.append(item)
    result = tuple(output)
    if result != tuple(sorted(set(result))):
        _reject(f"{label} must be sorted and unique")
    return result


def _hooks(value: Any) -> tuple[tuple[str, str, str], ...]:
    if not isinstance(value, list) or len(value) > MAX_ADAPTER_HOOKS:
        _reject(f"hooks must be a list with at most {MAX_ADAPTER_HOOKS} entries")
    output: list[tuple[str, str, str]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict) or set(item) != _HOOK_FIELDS:
            _reject(f"hooks[{index}] has missing or unknown fields")
        rule_id = item["rule_id"]
        if not isinstance(rule_id, str) or _RULE_ID.fullmatch(rule_id) is None:
            _reject(f"hooks[{index}].rule_id is invalid")
        hook_name = item["hook_name"]
        hook_version = item["hook_version"]
        if (
            not isinstance(hook_name, str)
            or _TOKEN.fullmatch(hook_name) is None
            or not isinstance(hook_version, str)
            or _TOKEN.fullmatch(hook_version) is None
        ):
            _reject(f"hooks[{index}] identifies an invalid Hook")
        output.append((rule_id, hook_name, hook_version))
    result = tuple(output)
    if result != tuple(sorted(set(result))):
        _reject("hooks must be sorted and unique")
    return result


@dataclass(frozen=True, init=False)
class TradeExecutionAdapter:
    _canonical_bytes: bytes

    @classmethod
    def _create(cls, canonical: bytes) -> "TradeExecutionAdapter":
        value = object.__new__(cls)
        object.__setattr__(value, "_canonical_bytes", bytes(canonical))
        return value

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> "TradeExecutionAdapter":
        try:
            canonical = trade_canonical_json(copy.deepcopy(document))
            value = parse_trade_json(canonical)
            if set(value) != _FIELDS:
                _reject("Adapter has missing or unknown fields")
            if value["kind"] != ADAPTER_KIND:
                _reject("Adapter has the wrong kind")
            if value["protocol_version"] != ADAPTER_PROTOCOL_VERSION:
                _reject("Adapter has an unsupported protocol version")
            if (
                not isinstance(value["adapter_id"], str)
                or len(value["adapter_id"]) > 192
                or _ADAPTER_ID.fullmatch(value["adapter_id"]) is None
            ):
                _reject("adapter_id is invalid")
            if (
                not isinstance(value["adapter_version"], str)
                or len(value["adapter_version"]) > 64
                or _SEMVER.fullmatch(value["adapter_version"]) is None
            ):
                _reject("adapter_version is not valid SemVer")
            _digest(value["artifact_digest"], label="artifact_digest")
            modes = _sorted_tokens(
                value["execution_modes"],
                label="execution_modes",
                maximum=len(MANIFEST_EXECUTION_MODES),
            )
            if not modes or not set(modes) <= MANIFEST_EXECUTION_MODES:
                _reject("execution_modes contains an unsupported mode")
            _hooks(value["hooks"])
            _sorted_tokens(
                value["permissions"],
                label="permissions",
                maximum=MAX_ADAPTER_PERMISSIONS,
            )
            return cls._create(canonical)
        except (
            TradeCanonicalJSONError,
            TypeError,
            ValueError,
            UnicodeError,
        ) as exc:
            if isinstance(exc, TradeExecutionAdapterRejected):
                raise
            raise TradeExecutionAdapterRejected(str(exc)) from exc

    @property
    def canonical_bytes(self) -> bytes:
        return self._canonical_bytes

    @property
    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(self._canonical_bytes).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return parse_trade_json(self._canonical_bytes)


@dataclass(frozen=True)
class TradeExecutionAdapterPolicy:
    accepted_adapter_digests: frozenset[str]
    allowed_execution_modes: frozenset[str] = frozenset({"declarative"})
    allowed_permissions: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        accepted = frozenset(self.accepted_adapter_digests)
        modes = frozenset(self.allowed_execution_modes)
        permissions = frozenset(self.allowed_permissions)
        object.__setattr__(self, "accepted_adapter_digests", accepted)
        object.__setattr__(self, "allowed_execution_modes", modes)
        object.__setattr__(self, "allowed_permissions", permissions)
        for digest in accepted:
            _digest(digest, label="accepted_adapter_digests item")
        if (
            not modes
            or not modes <= MANIFEST_EXECUTION_MODES
        ):
            _reject("allowed_execution_modes is invalid")
        for permission in permissions:
            if not isinstance(permission, str) or _TOKEN.fullmatch(permission) is None:
                _reject("allowed_permissions contains an invalid token")


def build_execution_adapter(
    *,
    adapter_id: str,
    adapter_version: str,
    artifact_digest: str,
    execution_modes: list[str] | tuple[str, ...],
    hooks: list[dict[str, str]] | tuple[dict[str, str], ...],
    permissions: list[str] | tuple[str, ...] = (),
) -> TradeExecutionAdapter:
    document = {
        "kind": ADAPTER_KIND,
        "protocol_version": ADAPTER_PROTOCOL_VERSION,
        "adapter_id": adapter_id,
        "adapter_version": adapter_version,
        "artifact_digest": artifact_digest,
        "execution_modes": sorted(list(execution_modes)),
        "hooks": sorted(
            [copy.deepcopy(item) for item in hooks],
            key=lambda item: (
                item.get("rule_id", ""),
                item.get("hook_name", ""),
                item.get("hook_version", ""),
            ),
        ),
        "permissions": sorted(list(permissions)),
    }
    return TradeExecutionAdapter.from_dict(document)


def resolve_execution_adapter(
    *,
    adapter_digest: str,
    adapter_id: str,
    adapter_version: str,
    execution_mode: str,
    rule_id: str,
    hook_name: str,
    hook_version: str,
    rule_permissions: tuple[str, ...],
    resolver: TradeExecutionAdapterResolver,
    policy: TradeExecutionAdapterPolicy,
) -> TradeExecutionAdapter:
    if not callable(getattr(resolver, "load", None)):
        raise TypeError("adapter resolver must provide load(digest)")
    if not callable(getattr(resolver, "load_artifact", None)):
        raise TypeError(
            "adapter resolver must provide load_artifact(digest)"
        )
    if not isinstance(policy, TradeExecutionAdapterPolicy):
        raise TypeError("adapter_policy must be a TradeExecutionAdapterPolicy")
    _digest(adapter_digest, label="adapter_digest")
    if adapter_digest not in policy.accepted_adapter_digests:
        _reject("Adapter digest is not accepted by local policy")
    try:
        candidate = resolver.load(adapter_digest)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise TradeExecutionAdapterRejected(
            f"unable to load Adapter: {exc}"
        ) from exc
    if candidate is None:
        _reject("Adapter is unavailable")
    if not isinstance(candidate, TradeExecutionAdapter):
        _reject("Adapter resolver returned an invalid object")
    adapter = TradeExecutionAdapter.from_dict(candidate.to_dict())
    if adapter.digest != adapter_digest:
        _reject("Adapter content digest mismatch")
    document = adapter.to_dict()
    if (
        document["adapter_id"] != adapter_id
        or document["adapter_version"] != adapter_version
    ):
        _reject("Adapter identity does not match Receipt")
    if (
        execution_mode not in document["execution_modes"]
        or execution_mode not in policy.allowed_execution_modes
    ):
        _reject("Adapter execution mode is not locally allowed")
    hook = {
        "rule_id": rule_id,
        "hook_name": hook_name,
        "hook_version": hook_version,
    }
    if hook not in document["hooks"]:
        _reject("Adapter does not support the authorized Rule Hook")
    adapter_permissions = tuple(document["permissions"])
    if adapter_permissions != tuple(rule_permissions):
        _reject("Adapter permissions do not exactly match the Rule")
    if not set(adapter_permissions) <= policy.allowed_permissions:
        _reject("Adapter permissions exceed local policy")
    try:
        artifact = resolver.load_artifact(document["artifact_digest"])
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise TradeExecutionAdapterRejected(
            f"unable to load Adapter artifact: {exc}"
        ) from exc
    if artifact is None:
        _reject("Adapter artifact is unavailable")
    if not isinstance(artifact, bytes):
        _reject("Adapter resolver returned an invalid artifact")
    if len(artifact) > MAX_ADAPTER_ARTIFACT_BYTES:
        _reject("Adapter artifact exceeds the byte limit")
    actual_artifact_digest = (
        "sha256:" + hashlib.sha256(artifact).hexdigest()
    )
    if actual_artifact_digest != document["artifact_digest"]:
        _reject("Adapter artifact content digest mismatch")
    return adapter


__all__ = [
    "ADAPTER_KIND",
    "ADAPTER_PROTOCOL_VERSION",
    "MAX_ADAPTER_HOOKS",
    "MAX_ADAPTER_PERMISSIONS",
    "MAX_ADAPTER_ARTIFACT_BYTES",
    "TradeExecutionAdapter",
    "TradeExecutionAdapterPolicy",
    "TradeExecutionAdapterRejected",
    "TradeExecutionAdapterResolver",
    "build_execution_adapter",
    "resolve_execution_adapter",
]
