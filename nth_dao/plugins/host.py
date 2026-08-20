"""Default-deny lifecycle host for reviewed NTH DAO built-in plugins."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import secrets
import threading
import time
from typing import Any, Dict, Protocol, Tuple
import weakref

from nth_dao.canonical_json import canonical_json
from nth_dao.util.io import InterProcessLock

from .contracts import (
    PLUGIN_HOST_API_VERSION,
    PLUGIN_PERMISSIONS,
    CapabilityContract,
    CapabilityRequirement,
    PluginContractError,
    PluginManifest,
    ensure_host_api_compatible,
    schema_digest,
)
from .schema import PluginSchemaError, validate_instance, validate_schema
from .audit import PluginAuditError, PluginAuditLog


class PluginHostError(RuntimeError):
    """Base error for plugin host operations."""


class PluginAuthorizationError(PluginHostError):
    """A plugin lacks an explicit host permission grant."""


class PluginDependencyError(PluginHostError):
    """A required capability cannot be resolved safely."""


class PluginLifecycleError(PluginHostError):
    """A plugin failed while starting or stopping."""


class PluginConflictError(PluginHostError):
    """A plugin or single-provider capability conflicts with host state."""


class PluginInvocationError(PluginHostError):
    """A capability invocation failed a host boundary check."""


_MAX_INVOCATION_DOCUMENT_BYTES = 1024 * 1024


def _json_boundary_copy(value: Mapping[str, Any], *, label: str) -> Dict[str, Any]:
    try:
        encoded = canonical_json(dict(value))
    except (RecursionError, TypeError, ValueError) as exc:
        raise PluginSchemaError(f"{label} must be finite JSON data") from exc
    if len(encoded) > _MAX_INVOCATION_DOCUMENT_BYTES:
        raise PluginSchemaError(
            f"{label} exceeds {_MAX_INVOCATION_DOCUMENT_BYTES} bytes"
        )
    decoded = json.loads(encoded)
    if not isinstance(decoded, dict):
        raise PluginSchemaError(f"{label} must be an object")
    return decoded


@dataclass(frozen=True)
class PluginHostPolicy:
    """Local security ceiling; plugin manifests can only narrow it."""

    allowed_permissions: frozenset[str] = frozenset()
    max_risk_tier: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.allowed_permissions, frozenset):
            object.__setattr__(self, "allowed_permissions", frozenset(self.allowed_permissions))
        if any(item not in PLUGIN_PERMISSIONS for item in self.allowed_permissions):
            raise ValueError("host policy contains an unsupported plugin permission")
        if type(self.max_risk_tier) is not int or not 0 <= self.max_risk_tier <= 4:
            raise ValueError("host max_risk_tier must be an integer from 0 through 4")


@dataclass(frozen=True)
class PluginContext:
    plugin_id: str
    host_api: str
    granted_permissions: frozenset[str]
    workspace_root: Path | None


@dataclass(frozen=True)
class InvocationAuthority:
    """Local authority presented for one capability invocation.

    This is not a remote signature container.  The caller must derive it from
    an already verified local session, mandate, or governance decision.
    """

    principal: str
    capability_ids: frozenset[str]
    mandate_digest: str = ""
    idempotency_key: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.principal, str) or not self.principal.strip():
            raise ValueError("invocation principal must be non-empty text")
        if len(self.principal.encode("utf-8")) > 512:
            raise ValueError("invocation principal is too long")
        if not isinstance(self.capability_ids, frozenset):
            object.__setattr__(self, "capability_ids", frozenset(self.capability_ids))
        if not self.capability_ids or any(
            not isinstance(item, str) or not item for item in self.capability_ids
        ):
            raise ValueError("invocation capability_ids must contain non-empty text")
        for label, value in (
            ("mandate_digest", self.mandate_digest),
            ("idempotency_key", self.idempotency_key),
        ):
            if not isinstance(value, str) or len(value.encode("utf-8")) > 512:
                raise ValueError(f"invocation {label} must be bounded text")


@dataclass(frozen=True)
class PluginInvocationContext:
    plugin_id: str
    capability_id: str
    invocation_id: str
    authority: InvocationAuthority
    granted_permissions: frozenset[str]
    workspace_root: Path | None


class CapabilityProvider(Protocol):
    """The only provider surface callable by PluginHost."""

    def invoke(
        self,
        payload: Mapping[str, Any],
        context: PluginInvocationContext,
    ) -> Mapping[str, Any]: ...


class CapabilitySchemas:
    """Owned input/output schema copies bound to one capability contract."""

    def __init__(
        self,
        input_schema: Mapping[str, Any],
        output_schema: Mapping[str, Any],
    ) -> None:
        validate_schema(input_schema, path="$input_schema")
        validate_schema(output_schema, path="$output_schema")
        self._input_schema = deepcopy(dict(input_schema))
        self._output_schema = deepcopy(dict(output_schema))

    @property
    def input_schema(self) -> Dict[str, Any]:
        return deepcopy(self._input_schema)

    @property
    def output_schema(self) -> Dict[str, Any]:
        return deepcopy(self._output_schema)


class PluginRuntime(Protocol):
    """A reviewed built-in runtime with explicit start/stop effects."""

    def start(self, context: PluginContext) -> Mapping[str, object]: ...

    def stop(self) -> None: ...


PluginFactory = Callable[[], PluginRuntime]


@dataclass(frozen=True)
class ProviderBinding:
    """Revocable capability handle; the provider object never leaves Host."""

    plugin_id: str
    contract: CapabilityContract
    generation: str
    _host_ref: weakref.ReferenceType["PluginHost"] = field(
        repr=False,
        compare=False,
    )

    def invoke(
        self,
        payload: Mapping[str, Any],
        *,
        authority: InvocationAuthority,
    ) -> Dict[str, Any]:
        host = self._host_ref()
        if host is None:
            raise PluginInvocationError("plugin host is no longer available")
        return host.invoke(self, payload, authority=authority)


@dataclass(frozen=True)
class PluginStatus:
    plugin_id: str
    state: str
    declared_permissions: Tuple[str, ...]
    authorized_permissions: Tuple[str, ...]
    provided_capabilities: Tuple[str, ...]
    risk_tier: int
    desired_enabled: bool = False
    last_error: str = ""


@dataclass
class _StopOperation:
    done: threading.Event = field(default_factory=threading.Event)
    errors: list[BaseException] = field(default_factory=list)


@dataclass
class _PluginRecord:
    manifest: PluginManifest
    factory: PluginFactory
    state: str = "installed"
    grants: frozenset[str] = frozenset()
    runtime: PluginRuntime | None = None
    bindings: Dict[str, ProviderBinding] = field(default_factory=dict)
    providers: Dict[str, CapabilityProvider] = field(default_factory=dict)
    schemas: Dict[str, CapabilitySchemas] = field(default_factory=dict)
    audited_capabilities: frozenset[str] = frozenset()
    generation: str = ""
    active_calls: int = 0
    stop_operation: _StopOperation | None = None
    desired_enabled: bool = False
    last_error: str = ""


class PluginHost:
    """Atomic registry and lifecycle manager for trusted built-ins.

    This class enforces host policy and dependency semantics, but it is not a
    Python sandbox. The deliberately named ``register_builtin`` method is the
    only installation path in host API v1.
    """

    def __init__(
        self,
        *,
        policy: PluginHostPolicy | None = None,
        host_api: str = PLUGIN_HOST_API_VERSION,
        workspace_root: Path | None = None,
        lifecycle_timeout_s: float = 2.0,
    ) -> None:
        self.policy = policy or PluginHostPolicy()
        self.host_api = host_api
        ensure_host_api_compatible(host_api, PLUGIN_HOST_API_VERSION)
        ensure_host_api_compatible(PLUGIN_HOST_API_VERSION, host_api)
        self.workspace_root = (
            Path(workspace_root).resolve() if workspace_root is not None else None
        )
        if (
            isinstance(lifecycle_timeout_s, bool)
            or not isinstance(lifecycle_timeout_s, (int, float))
            or not 0.1 <= float(lifecycle_timeout_s) <= 30.0
        ):
            raise ValueError("lifecycle_timeout_s must be between 0.1 and 30 seconds")
        self.lifecycle_timeout_s = float(lifecycle_timeout_s)
        self._records: Dict[str, _PluginRecord] = {}
        self._providers: Dict[str, Dict[str, ProviderBinding]] = {}
        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)
        self._audit_log = (
            PluginAuditLog(self.workspace_root / ".nth" / "plugin-host" / "audit.jsonl")
            if self.workspace_root is not None
            else None
        )
        self._refresh_execution_dir = (
            self.workspace_root / ".nth" / "plugin-host" / "refresh-executions"
            if self.workspace_root is not None
            else None
        )
        self._persisted = (
            self._audit_log.projection() if self._audit_log is not None else {}
        )

    def register_builtin(
        self,
        manifest: PluginManifest,
        factory: PluginFactory,
        *,
        schemas: Mapping[str, CapabilitySchemas],
        allow_manifest_upgrade: bool = False,
        audited_capabilities: frozenset[str] | set[str] = frozenset(),
    ) -> None:
        if not isinstance(manifest, PluginManifest):
            raise TypeError("manifest must be a PluginManifest")
        if not callable(factory):
            raise TypeError("plugin factory must be callable")
        if type(allow_manifest_upgrade) is not bool:
            raise TypeError("allow_manifest_upgrade must be a boolean")
        audited = frozenset(audited_capabilities)
        if any(not isinstance(item, str) or not item for item in audited):
            raise TypeError("audited capability ids must be non-empty strings")
        provided_ids = frozenset(item.capability_id for item in manifest.provides)
        if not audited <= provided_ids:
            raise PluginContractError(
                "audited capabilities must be provided by the plugin manifest"
            )
        if audited and self._audit_log is None:
            raise PluginAuthorizationError(
                "audited capabilities require a host-bound workspace audit"
            )
        if manifest.runtime != "builtin":
            raise PluginContractError("only builtin manifests may be registered")
        if manifest.publisher_did or manifest.proof:
            raise PluginContractError(
                "host API v1 does not verify signed external plugin manifests"
            )
        if any(item.security == "irreversible" for item in manifest.provides):
            raise PluginAuthorizationError(
                "host API v1 does not execute irreversible capabilities"
            )
        ensure_host_api_compatible(manifest.host_api, self.host_api)
        checked_schemas = self._validate_schemas(manifest, schemas)
        with self._lock:
            existing = self._records.get(manifest.plugin_id)
            if existing is not None:
                if existing.manifest.digest == manifest.digest and existing.factory is factory:
                    return
                raise PluginConflictError(
                    f"plugin {manifest.plugin_id!r} is already installed"
                )
            persisted = self._persisted.get(manifest.plugin_id)
            if persisted is not None and persisted.get("manifest_digest") != manifest.digest:
                if not allow_manifest_upgrade:
                    raise PluginConflictError(
                        f"persisted plugin {manifest.plugin_id!r} has a different manifest"
                    )
                previous_digest = persisted["manifest_digest"]
                self._audit(
                    "plugin.upgraded",
                    manifest.plugin_id,
                    {
                        "previous_manifest_digest": previous_digest,
                        "manifest_digest": manifest.digest,
                    },
                )
                persisted = {
                    "manifest_digest": manifest.digest,
                    "grants": [],
                    "desired_enabled": False,
                }
                self._persisted[manifest.plugin_id] = persisted
            restored_grants = frozenset(persisted.get("grants", ())) if persisted else frozenset()
            if not (
                restored_grants <= frozenset(manifest.permissions)
                and restored_grants <= self.policy.allowed_permissions
            ):
                restored_grants = frozenset()
            if persisted is None:
                self._audit(
                    "plugin.registered",
                    manifest.plugin_id,
                    {"manifest_digest": manifest.digest},
                )
                self._persisted[manifest.plugin_id] = {
                    "manifest_digest": manifest.digest,
                    "grants": [],
                    "desired_enabled": False,
                }
            self._records[manifest.plugin_id] = _PluginRecord(
                manifest=manifest,
                factory=factory,
                state="authorized" if restored_grants else "installed",
                grants=restored_grants,
                schemas=checked_schemas,
                audited_capabilities=audited,
                desired_enabled=bool(persisted and persisted.get("desired_enabled")),
            )

    def authorize(
        self,
        plugin_id: str,
        permissions: frozenset[str] | set[str],
        *,
        operator: Mapping[str, str] | None = None,
    ) -> None:
        grants = frozenset(permissions)
        if any(not isinstance(item, str) for item in grants):
            raise TypeError("plugin permission grants must be strings")
        with self._lock:
            record = self._require_record(plugin_id)
            if record.state in {
                "cleanup-failed",
                "enabling",
                "enabled",
                "disabling",
            }:
                raise PluginLifecycleError("disable the plugin before changing grants")
            undeclared = grants - frozenset(record.manifest.permissions)
            if undeclared:
                raise PluginAuthorizationError(
                    f"cannot grant undeclared permissions: {sorted(undeclared)}"
                )
            forbidden = grants - self.policy.allowed_permissions
            if forbidden:
                raise PluginAuthorizationError(
                    f"host policy forbids permissions: {sorted(forbidden)}"
                )
            workspace_permissions = {
                "filesystem.read.workspace",
                "filesystem.write.workspace",
            }
            if grants & workspace_permissions and self.workspace_root is None:
                raise PluginAuthorizationError(
                    "workspace permissions require a host-bound workspace_root"
                )
            self._audit(
                "plugin.authorized",
                plugin_id,
                self._operator_details({"grants": sorted(grants)}, operator),
            )
            record.grants = grants
            record.state = "authorized" if grants else "installed"
            self._persisted[plugin_id]["grants"] = sorted(grants)
            record.last_error = ""

    def enable(
        self,
        plugin_id: str,
        *,
        operator: Mapping[str, str] | None = None,
    ) -> Tuple[ProviderBinding, ...]:
        deadline = time.monotonic() + self.lifecycle_timeout_s
        with self._condition:
            record = self._require_record(plugin_id)
            while record.state in {"enabling", "disabling"}:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise PluginLifecycleError(
                        f"plugin {plugin_id!r} lifecycle transition timed out"
                    )
                self._condition.wait(remaining)
            if record.state == "enabled":
                return tuple(record.bindings[key] for key in sorted(record.bindings))
            if record.state == "cleanup-failed":
                raise PluginLifecycleError(
                    f"plugin {plugin_id!r} is currently {record.state}"
                )
            required_grants = frozenset(record.manifest.permissions)
            missing = required_grants - record.grants
            if missing:
                raise PluginAuthorizationError(
                    f"plugin lacks required grants: {sorted(missing)}"
                )
            if record.manifest.risk_tier > self.policy.max_risk_tier:
                raise PluginAuthorizationError(
                    f"plugin risk tier T{record.manifest.risk_tier} exceeds "
                    f"host ceiling T{self.policy.max_risk_tier}"
                )
            self._validate_dependencies(record.manifest.requires)
            self._validate_cardinality(record.manifest.provides, plugin_id)
            record.state = "enabling"
            factory = record.factory
            context = PluginContext(
                plugin_id=plugin_id,
                host_api=self.host_api,
                granted_permissions=record.grants,
                workspace_root=self.workspace_root,
            )
        runtime: PluginRuntime | None = None
        start_invoked = False
        try:
            runtime = factory()
            if not callable(getattr(runtime, "start", None)) or not callable(
                getattr(runtime, "stop", None)
            ):
                raise TypeError("plugin factory did not return a PluginRuntime")
            start_invoked = True
            providers = runtime.start(context)
            generation = secrets.token_hex(16)
            bindings, checked_providers = self._build_bindings(
                record.manifest,
                providers,
                generation=generation,
            )
            with self._condition:
                if record.state != "enabling":
                    raise PluginLifecycleError("plugin enable was superseded")
                self._validate_cardinality(record.manifest.provides, plugin_id)
                self._audit(
                    "plugin.enable.succeeded",
                    plugin_id,
                    self._operator_details(
                        {"manifest_digest": record.manifest.digest},
                        operator,
                    ),
                )
                for capability_id, binding in bindings.items():
                    self._providers.setdefault(capability_id, {})[plugin_id] = binding
                record.runtime = runtime
                record.bindings = bindings
                record.providers = checked_providers
                record.generation = generation
                record.state = "enabled"
                record.desired_enabled = True
                self._persisted[plugin_id]["desired_enabled"] = True
                record.last_error = ""
                self._condition.notify_all()
                return tuple(bindings[key] for key in sorted(bindings))
        except Exception as exc:
            cleanup_error = ""
            cleanup_operation: _StopOperation | None = None
            if runtime is not None and start_invoked:
                try:
                    cleanup_operation = self._begin_stop(runtime)
                    self._await_stop(cleanup_operation)
                except Exception as cleanup_exc:  # noqa: BLE001
                    cleanup_error = (
                        f"; cleanup failed: {type(cleanup_exc).__name__}: {cleanup_exc}"
                    )
            with self._condition:
                record.runtime = runtime if cleanup_error else None
                record.bindings.clear()
                record.providers.clear()
                record.generation = ""
                record.stop_operation = (
                    cleanup_operation
                    if cleanup_operation is not None and not cleanup_operation.done.is_set()
                    else None
                )
                record.state = "cleanup-failed" if cleanup_error else "failed"
                record.last_error = (
                    f"{type(exc).__name__}: {exc}{cleanup_error}"
                )[:1000]
                try:
                    self._audit(
                        "plugin.enable.failed",
                        plugin_id,
                        self._operator_details(
                            {
                                "error_type": type(exc).__name__,
                                "cleanup_failed": bool(cleanup_error),
                            },
                            operator,
                        ),
                    )
                except PluginAuditError as audit_exc:
                    record.last_error = f"{record.last_error}; audit failed: {audit_exc}"[:1000]
                self._condition.notify_all()
            raise PluginLifecycleError(
                f"plugin {plugin_id!r} failed to start: {record.last_error}"
            ) from exc

    def disable(
        self,
        plugin_id: str,
        *,
        operator: Mapping[str, str] | None = None,
    ) -> bool:
        deadline = time.monotonic() + self.lifecycle_timeout_s
        with self._condition:
            record = self._require_record(plugin_id)
            while record.state in {"enabling", "disabling"}:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise PluginLifecycleError(
                        f"plugin {plugin_id!r} lifecycle transition timed out"
                    )
                self._condition.wait(remaining)
            if record.state not in {"enabled", "cleanup-failed"}:
                return False
            dependents = (
                self._dependent_plugins(plugin_id)
                if record.state == "enabled"
                else frozenset()
            )
            if dependents:
                raise PluginDependencyError(
                    f"enabled plugins depend on {plugin_id!r}: {sorted(dependents)}"
                )
            runtime = record.runtime
            pending_stop = record.stop_operation
            record.state = "disabling"
            for capability_id in tuple(record.bindings):
                providers = self._providers.get(capability_id)
                if providers is None:
                    continue
                providers.pop(plugin_id, None)
                if not providers:
                    self._providers.pop(capability_id, None)
            record.bindings.clear()
            record.providers.clear()
            record.generation = ""
            self._condition.notify_all()
        cleanup_error: Exception | None = None
        stop_operation = pending_stop
        try:
            if runtime is not None:
                if stop_operation is None:
                    stop_operation = self._begin_stop(runtime)
                elif stop_operation.done.is_set() and stop_operation.errors:
                    stop_operation = self._begin_stop(runtime)
                self._await_stop(stop_operation)
        except Exception as exc:  # noqa: BLE001
            cleanup_error = exc
        with self._condition:
            while record.active_calls:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    cleanup_error = TimeoutError(
                        f"{record.active_calls} capability invocation(s) did not stop"
                    )
                    break
                self._condition.wait(remaining)
            record.desired_enabled = False
            self._persisted[plugin_id]["desired_enabled"] = False
            if cleanup_error is not None:
                record.runtime = runtime
                record.stop_operation = stop_operation
                record.state = "cleanup-failed"
                record.last_error = (
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )[:1000]
                try:
                    self._audit(
                        "plugin.disable.failed",
                        plugin_id,
                        self._operator_details(
                            {"error_type": type(cleanup_error).__name__},
                            operator,
                        ),
                    )
                except PluginAuditError as audit_exc:
                    record.last_error = (
                        f"{record.last_error}; audit failed: {audit_exc}"
                    )[:1000]
                self._condition.notify_all()
                raise PluginLifecycleError(
                    f"plugin {plugin_id!r} cleanup failed: {record.last_error}"
                ) from cleanup_error
            record.runtime = None
            record.stop_operation = None
            try:
                self._audit(
                    "plugin.disable.succeeded",
                    plugin_id,
                    self._operator_details({}, operator),
                )
            except PluginAuditError as exc:
                record.state = "failed"
                record.last_error = f"PluginAuditError: {exc}"[:1000]
                self._condition.notify_all()
                raise PluginLifecycleError(
                    f"plugin {plugin_id!r} stopped but audit commit failed"
                ) from exc
            record.state = "authorized" if record.grants else "installed"
            record.last_error = ""
            self._condition.notify_all()
            return True

    def revoke(self, plugin_id: str) -> None:
        while True:
            with self._condition:
                record = self._require_record(plugin_id)
                if record.state in {"enabling", "disabling"}:
                    self._condition.wait(self.lifecycle_timeout_s)
                    continue
                if record.state not in {"enabled", "cleanup-failed"}:
                    self._audit("plugin.revoked", plugin_id, {})
                    record.grants = frozenset()
                    record.state = "installed"
                    record.desired_enabled = False
                    self._persisted[plugin_id]["grants"] = []
                    self._persisted[plugin_id]["desired_enabled"] = False
                    record.last_error = ""
                    return
            self.disable(plugin_id)

    def uninstall(self, plugin_id: str) -> None:
        with self._lock:
            record = self._require_record(plugin_id)
            if record.state in {
                "cleanup-failed",
                "enabled",
                "enabling",
                "disabling",
            }:
                raise PluginLifecycleError("disable the plugin before uninstalling it")
            self._audit("plugin.uninstalled", plugin_id, {})
            self._records.pop(plugin_id)
            self._persisted.pop(plugin_id, None)

    def resolve(self, capability_id: str, *, major_version: int | None = None) -> Tuple[ProviderBinding, ...]:
        with self._lock:
            bindings = self._providers.get(capability_id, {})
            values = tuple(
                binding
                for plugin_id, binding in sorted(bindings.items())
                if major_version is None or binding.contract.major_version == major_version
            )
        return values

    def resolve_one(self, capability_id: str, *, major_version: int | None = None) -> ProviderBinding:
        values = self.resolve(capability_id, major_version=major_version)
        if not values:
            raise PluginDependencyError(f"capability {capability_id!r} is unavailable")
        if len(values) != 1:
            raise PluginConflictError(
                f"capability {capability_id!r} has {len(values)} providers"
            )
        return values[0]

    def invoke(
        self,
        binding: ProviderBinding,
        payload: Mapping[str, Any],
        *,
        authority: InvocationAuthority,
        _refresh_invocation_id: str = "",
    ) -> Dict[str, Any]:
        """Invoke one capability through the revocable Trust Kernel boundary."""

        if not isinstance(binding, ProviderBinding) or binding._host_ref() is not self:
            raise PluginInvocationError("provider binding does not belong to this host")
        if not isinstance(payload, Mapping):
            raise PluginSchemaError("capability input must be an object")
        if not isinstance(authority, InvocationAuthority):
            raise PluginAuthorizationError("capability invocation requires local authority")
        with self._lock:
            record = self._require_record(binding.plugin_id)
            current = record.bindings.get(binding.contract.capability_id)
            if (
                record.state != "enabled"
                or current is not binding
                or not record.generation
                or binding.generation != record.generation
            ):
                raise PluginInvocationError("provider binding is disabled or stale")
            capability_id = binding.contract.capability_id
            if capability_id not in authority.capability_ids:
                raise PluginAuthorizationError(
                    f"principal is not authorized for capability {capability_id!r}"
                )
            if capability_id in record.audited_capabilities:
                if not _refresh_invocation_id:
                    raise PluginAuthorizationError(
                        "capability requires an audited refresh invocation"
                    )
                pending = {
                    item["invocation_id"]: item
                    for item in self.incomplete_refreshes(binding.plugin_id)
                }
                intent = pending.get(_refresh_invocation_id)
                if intent is None:
                    raise PluginAuthorizationError(
                        "audited refresh intent is missing or already terminal"
                    )
            required = binding.contract.required_permissions
            if not required <= record.grants or not required <= self.policy.allowed_permissions:
                raise PluginAuthorizationError("capability grants are no longer effective")
            provider = record.providers[capability_id]
            schemas = record.schemas[capability_id]
            record.active_calls += 1
            context = PluginInvocationContext(
                plugin_id=binding.plugin_id,
                capability_id=capability_id,
                invocation_id=secrets.token_hex(16),
                authority=authority,
                granted_permissions=record.grants,
                workspace_root=self.workspace_root,
            )
        try:
            request_body = _json_boundary_copy(payload, label="capability input")
            validate_instance(request_body, schemas._input_schema, path="$input")
            response = provider.invoke(request_body, context)
            if not isinstance(response, Mapping):
                raise PluginSchemaError("capability output must be an object")
            response_body = _json_boundary_copy(response, label="capability output")
            validate_instance(response_body, schemas._output_schema, path="$output")
            return response_body
        finally:
            with self._condition:
                record.active_calls = max(0, record.active_calls - 1)
                self._condition.notify_all()

    def invoke_audited_refresh(
        self,
        binding: ProviderBinding,
        payload: Mapping[str, Any],
        *,
        authority: InvocationAuthority,
        operator: Mapping[str, str],
    ) -> Dict[str, Any]:
        """Invoke an audited capability with durable intent and terminal state."""

        invocation_id = self.begin_refresh(binding.plugin_id, operator=operator)
        execution_lock = self._refresh_execution_lock(invocation_id)
        try:
            execution_lock.acquire()
        except (OSError, TimeoutError) as exc:
            try:
                self.record_refresh(
                    binding.plugin_id,
                    operator=operator,
                    error_type="RefreshExecutionLeaseUnavailable",
                    invocation_id=invocation_id,
                )
            except PluginAuditError as audit_exc:
                raise audit_exc from exc
            raise PluginLifecycleError(
                "audited refresh execution lease is unavailable"
            ) from exc
        try:
            try:
                result = self.invoke(
                    binding,
                    payload,
                    authority=authority,
                    _refresh_invocation_id=invocation_id,
                )
            except Exception as exc:
                try:
                    self.record_refresh(
                        binding.plugin_id,
                        operator=operator,
                        error_type=type(exc).__name__,
                        invocation_id=invocation_id,
                    )
                except PluginAuditError as audit_exc:
                    raise audit_exc from exc
                raise
            result_items = result.get("verified_peers", [])
            result_count = len(result_items) if isinstance(result_items, list) else 0
            result_digest = (
                "sha256:" + hashlib.sha256(canonical_json(result)).hexdigest()
            )
            self.record_refresh(
                binding.plugin_id,
                operator=operator,
                invocation_id=invocation_id,
                result_digest=result_digest,
                result_count=result_count,
            )
            return result
        finally:
            execution_lock.release()

    def status(self, plugin_id: str) -> PluginStatus:
        with self._lock:
            record = self._require_record(plugin_id)
            return PluginStatus(
                plugin_id=plugin_id,
                state=record.state,
                declared_permissions=record.manifest.permissions,
                authorized_permissions=tuple(sorted(record.grants)),
                provided_capabilities=tuple(sorted(record.bindings)),
                risk_tier=record.manifest.risk_tier,
                desired_enabled=record.desired_enabled,
                last_error=record.last_error,
            )

    def list_status(self) -> Tuple[PluginStatus, ...]:
        with self._lock:
            return tuple(
                PluginStatus(
                    plugin_id=plugin_id,
                    state=record.state,
                    declared_permissions=record.manifest.permissions,
                    authorized_permissions=tuple(sorted(record.grants)),
                    provided_capabilities=tuple(sorted(record.bindings)),
                    risk_tier=record.manifest.risk_tier,
                    desired_enabled=record.desired_enabled,
                    last_error=record.last_error,
                )
                for plugin_id, record in sorted(self._records.items())
            )

    def verify_audit(self) -> tuple[bool, str]:
        if self._audit_log is None:
            return True, "audit-disabled-without-workspace"
        try:
            self._audit_log.read_verified()
        except PluginAuditError as exc:
            return False, str(exc)
        return True, "ok"

    def record_refresh(
        self,
        plugin_id: str,
        *,
        operator: Mapping[str, str],
        error_type: str = "",
        invocation_id: str = "",
        result_digest: str = "",
        result_count: int = 0,
    ) -> None:
        """Commit operator attribution for a manual provider refresh."""
        with self._lock:
            self._require_record(plugin_id)
            if invocation_id:
                event_type = (
                    "plugin.refresh.aborted"
                    if error_type
                    else "plugin.refresh.completed"
                )
                details: Dict[str, Any] = {"invocation_id": invocation_id}
                if error_type:
                    details["error_type"] = error_type
                else:
                    details["result_digest"] = result_digest
                    details["result_count"] = result_count
            else:
                event_type = (
                    "plugin.refresh.failed"
                    if error_type
                    else "plugin.refresh.succeeded"
                )
                details = {"error_type": error_type} if error_type else {}
            self._audit(
                event_type,
                plugin_id,
                self._operator_details(details, operator),
            )

    def begin_refresh(
        self,
        plugin_id: str,
        *,
        operator: Mapping[str, str],
    ) -> str:
        """Durably record refresh intent before any provider side effect."""

        invocation_id = secrets.token_hex(16)
        with self._lock:
            record = self._require_record(plugin_id)
            if record.state != "enabled" or not record.generation:
                raise PluginInvocationError(
                    "plugin refresh intent requires an enabled provider"
                )
            self._audit(
                "plugin.refresh.started",
                plugin_id,
                self._operator_details(
                    {"invocation_id": invocation_id}, operator,
                ),
            )
        return invocation_id

    def incomplete_refreshes(self, plugin_id: str = "") -> tuple[Dict[str, str], ...]:
        if self._audit_log is None:
            return ()
        pending = self._audit_log.incomplete_refreshes()
        if not plugin_id:
            return pending
        return tuple(item for item in pending if item["plugin_id"] == plugin_id)

    def abort_incomplete_refresh(
        self,
        plugin_id: str,
        invocation_id: str,
        *,
        operator: Mapping[str, str],
    ) -> None:
        """Close one crash-left intent as outcome-unknown; never forge success."""

        if (
            not isinstance(invocation_id, str)
            or len(invocation_id) != 32
            or any(char not in "0123456789abcdef" for char in invocation_id)
        ):
            raise ValueError("refresh invocation_id is invalid")
        with self._lock:
            self._require_record(plugin_id)
        execution_lock = self._refresh_execution_lock(invocation_id)
        try:
            execution_lock.acquire()
        except (OSError, TimeoutError) as exc:
            raise PluginLifecycleError("refresh invocation is still active") from exc
        try:
            with self._lock:
                self._require_record(plugin_id)
                pending = {
                    item["invocation_id"]: item
                    for item in self.incomplete_refreshes(plugin_id)
                }
                if invocation_id not in pending:
                    raise PluginInvocationError("refresh intent is not pending")
                self.record_refresh(
                    plugin_id,
                    operator=operator,
                    error_type="OperatorReconciledOutcomeUnknown",
                    invocation_id=invocation_id,
                )
        finally:
            execution_lock.release()

    def _refresh_execution_lock(self, invocation_id: str) -> InterProcessLock:
        if self._refresh_execution_dir is None:
            raise PluginAuthorizationError(
                "audited refresh execution requires a workspace"
            )
        return InterProcessLock(
            self._refresh_execution_dir / invocation_id,
            timeout=0.1,
            poll=0.02,
        )

    @staticmethod
    def _operator_details(
        details: Mapping[str, Any],
        operator: Mapping[str, str] | None,
    ) -> Dict[str, Any]:
        result = dict(details)
        if operator is not None:
            result["operator"] = dict(operator)
        return result

    def _audit(
        self,
        event_type: str,
        plugin_id: str,
        details: Mapping[str, Any],
    ) -> None:
        if self._audit_log is not None:
            self._audit_log.append(event_type, plugin_id, details)

    @staticmethod
    def _begin_stop(runtime: PluginRuntime) -> _StopOperation:
        operation = _StopOperation()
        def stop_runtime() -> None:
            try:
                runtime.stop()
            except BaseException as exc:  # noqa: BLE001
                operation.errors.append(exc)
            finally:
                operation.done.set()

        thread = threading.Thread(
            target=stop_runtime,
            name="nth-plugin-stop",
            daemon=True,
        )
        thread.start()
        return operation

    def _await_stop(self, operation: _StopOperation) -> None:
        if not operation.done.wait(self.lifecycle_timeout_s):
            raise TimeoutError("plugin stop exceeded its lifecycle deadline")
        if operation.errors:
            raise operation.errors[0]

    def _require_record(self, plugin_id: str) -> _PluginRecord:
        if not isinstance(plugin_id, str) or plugin_id not in self._records:
            raise KeyError(f"plugin {plugin_id!r} is not installed")
        return self._records[plugin_id]

    def _validate_dependencies(
        self, requirements: Tuple[CapabilityRequirement, ...]
    ) -> None:
        for requirement in requirements:
            matches = self.resolve(
                requirement.capability_id,
                major_version=requirement.major_version,
            )
            matches = tuple(
                item
                for item in matches
                if item.contract.digest == requirement.contract_digest
            )
            if not matches and not requirement.optional:
                raise PluginDependencyError(
                    f"required capability {requirement.capability_id!r} "
                    f"major {requirement.major_version} is unavailable"
                )

    def _validate_cardinality(
        self,
        contracts: Tuple[CapabilityContract, ...],
        plugin_id: str,
    ) -> None:
        for contract in contracts:
            existing = tuple(
                binding
                for owner, binding in self._providers.get(
                    contract.capability_id, {}
                ).items()
                if owner != plugin_id
            )
            if not existing:
                continue
            if contract.cardinality == "one" or any(
                item.contract.cardinality == "one" for item in existing
            ):
                raise PluginConflictError(
                    f"capability {contract.capability_id!r} allows one provider"
                )

    def _build_bindings(
        self,
        manifest: PluginManifest,
        providers: Mapping[str, object],
        *,
        generation: str,
    ) -> tuple[Dict[str, ProviderBinding], Dict[str, CapabilityProvider]]:
        if not isinstance(providers, Mapping):
            raise TypeError("plugin start() must return a provider mapping")
        expected = {item.capability_id: item for item in manifest.provides}
        actual = set(providers)
        if actual != set(expected):
            raise PluginConflictError(
                "plugin provider mapping does not match its manifest: "
                f"missing={sorted(set(expected) - actual)}, "
                f"unknown={sorted(actual - set(expected))}"
            )
        bindings: Dict[str, ProviderBinding] = {}
        checked_providers: Dict[str, CapabilityProvider] = {}
        for capability_id in sorted(expected):
            provider = providers[capability_id]
            if provider is None or not callable(getattr(provider, "invoke", None)):
                raise PluginConflictError(
                    f"plugin returned no invocable provider for {capability_id!r}"
                )
            bindings[capability_id] = ProviderBinding(
                plugin_id=manifest.plugin_id,
                contract=expected[capability_id],
                generation=generation,
                _host_ref=weakref.ref(self),
            )
            checked_providers[capability_id] = provider
        return bindings, checked_providers

    @staticmethod
    def _validate_schemas(
        manifest: PluginManifest,
        schemas: Mapping[str, CapabilitySchemas],
    ) -> Dict[str, CapabilitySchemas]:
        if not isinstance(schemas, Mapping):
            raise TypeError("plugin schemas must be a capability mapping")
        expected = {item.capability_id: item for item in manifest.provides}
        if set(schemas) != set(expected):
            raise PluginContractError(
                "plugin schema mapping does not match provided capabilities"
            )
        checked: Dict[str, CapabilitySchemas] = {}
        for capability_id, contract in expected.items():
            item = schemas[capability_id]
            if not isinstance(item, CapabilitySchemas):
                raise TypeError("plugin schema entries must be CapabilitySchemas")
            if schema_digest(item._input_schema) != contract.input_schema_digest:
                raise PluginContractError(
                    f"input schema digest mismatch for {capability_id!r}"
                )
            if schema_digest(item._output_schema) != contract.output_schema_digest:
                raise PluginContractError(
                    f"output schema digest mismatch for {capability_id!r}"
                )
            checked[capability_id] = item
        return checked

    def _dependent_plugins(self, plugin_id: str) -> frozenset[str]:
        record = self._records[plugin_id]
        removed_capabilities = frozenset(record.bindings)
        dependents = set()
        for candidate_id, candidate in self._records.items():
            if candidate_id == plugin_id or candidate.state != "enabled":
                continue
            for requirement in candidate.manifest.requires:
                if requirement.optional or requirement.capability_id not in removed_capabilities:
                    continue
                alternatives = tuple(
                    binding
                    for binding in self.resolve(
                        requirement.capability_id,
                        major_version=requirement.major_version,
                    )
                    if binding.plugin_id != plugin_id
                    and binding.contract.digest == requirement.contract_digest
                )
                if not alternatives:
                    dependents.add(candidate_id)
        return frozenset(dependents)


__all__ = [
    "CapabilityProvider",
    "CapabilitySchemas",
    "InvocationAuthority",
    "PluginAuthorizationError",
    "PluginConflictError",
    "PluginContext",
    "PluginDependencyError",
    "PluginFactory",
    "PluginHost",
    "PluginHostError",
    "PluginHostPolicy",
    "PluginInvocationContext",
    "PluginInvocationError",
    "PluginLifecycleError",
    "PluginRuntime",
    "PluginStatus",
    "ProviderBinding",
]
