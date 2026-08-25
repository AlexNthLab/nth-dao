"""Security and lifecycle tests for the NTH DAO plugin kernel."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import threading
import time

import pytest

from nth_dao.plugins import (
    CapabilityContract,
    CapabilityRequirement,
    CapabilitySchemas,
    InvocationAuthority,
    PluginAuthorizationError,
    PluginAuditError,
    PluginConflictError,
    PluginContractError,
    PluginDependencyError,
    PluginHost,
    PluginHostPolicy,
    PluginInvocationError,
    PluginLifecycleError,
    PluginManifest,
    PluginSchemaError,
    ensure_host_api_compatible,
    schema_digest,
)
from nth_dao.canonical_json import canonical_json
from nth_dao.plugins.audit import PluginAuditLog
from nth_dao.util.io import InterProcessLock


EMPTY_SCHEMA_BODY = {
    "type": "object",
    "additionalProperties": False,
    "properties": {},
}
EMPTY_SCHEMA = schema_digest(EMPTY_SCHEMA_BODY)
ARTIFACT_DIGEST = f"sha256:{hashlib.sha256(b'test-plugin').hexdigest()}"
VECTOR_PATH = (
    Path(__file__).parents[1]
    / "nth_dao"
    / "plugins"
    / "vectors"
    / "manifest-v1.json"
)


def capability(
    capability_id: str = "org.nth-dao.test.echo",
    *,
    effects: tuple[str, ...] = ("none",),
    consistency: str = "C1",
    privacy: str = "workspace",
    security: str = "verified-input",
    cardinality: str = "one",
    failure_semantics: str = "retry-safe",
) -> CapabilityContract:
    return CapabilityContract(
        capability_id=capability_id,
        version="1.0.0",
        input_schema_digest=EMPTY_SCHEMA,
        output_schema_digest=EMPTY_SCHEMA,
        effects=effects,
        consistency=consistency,
        privacy=privacy,
        security=security,
        cardinality=cardinality,
        deterministic=True,
        retention="none",
        failure_semantics=failure_semantics,
    )


def manifest(
    plugin_id: str = "org.nth-dao.test.echo",
    *,
    provides: tuple[CapabilityContract, ...] | None = None,
    requires: tuple[CapabilityRequirement, ...] = (),
    permissions: tuple[str, ...] = (),
) -> PluginManifest:
    return PluginManifest(
        manifest_version=1,
        plugin_id=plugin_id,
        version="1.0.0",
        host_api="1.0",
        kind="discovery.provider",
        runtime="builtin",
        provides=provides or (capability(),),
        requires=requires,
        permissions=permissions,
        artifact_digest=ARTIFACT_DIGEST,
    )


class Runtime:
    def __init__(
        self,
        providers: dict[str, object],
        *,
        start_error: Exception | None = None,
        stop_error: Exception | None = None,
    ) -> None:
        self.providers = providers
        self.start_error = start_error
        self.stop_error = stop_error
        self.started = 0
        self.stopped = 0
        self.context = None

    def start(self, context):
        self.started += 1
        self.context = context
        if self.start_error is not None:
            raise self.start_error
        return self.providers

    def stop(self) -> None:
        self.stopped += 1
        if self.stop_error is not None:
            raise self.stop_error


class Provider:
    def __init__(self, response: dict | None = None) -> None:
        self.response = response or {}
        self.calls = []

    def invoke(self, payload, context):
        self.calls.append((payload, context))
        return dict(self.response)


def plugin_schemas(item: PluginManifest) -> dict[str, CapabilitySchemas]:
    return {
        contract.capability_id: CapabilitySchemas(
            EMPTY_SCHEMA_BODY,
            EMPTY_SCHEMA_BODY,
        )
        for contract in item.provides
    }


def register(host: PluginHost, item: PluginManifest, factory) -> None:
    host.register_builtin(item, factory, schemas=plugin_schemas(item))


def authority(capability_id: str) -> InvocationAuthority:
    return InvocationAuthority(
        principal="test-suite",
        capability_ids=frozenset({capability_id}),
    )


def test_manifest_round_trip_and_content_digest_are_stable() -> None:
    original = manifest()
    restored = PluginManifest.from_dict(original.to_dict())
    assert restored == original
    assert restored.digest == original.digest
    assert schema_digest({"b": 2, "a": 1}) == schema_digest({"a": 1, "b": 2})


def test_checked_in_manifest_conformance_vector() -> None:
    vector = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    assert vector["format"] == "nth-dao-plugin-manifest-conformance-v1"
    positive = vector["positive"]
    parsed = PluginManifest.from_dict(positive["manifest"])
    assert schema_digest(positive["schema"]) == positive["schema_digest"]
    assert parsed.provides[0].digest == positive["capability_digest"]
    assert parsed.digest == positive["manifest_digest"]
    assert canonical_json(parsed.to_dict()).hex() == positive["expected_canonical_hex"]

    for case in vector["negative"]:
        body = deepcopy(positive["manifest"])
        body[case["path"]] = case["value"]
        with pytest.raises(PluginContractError, match=case["expected_error"]):
            PluginManifest.from_dict(body)
    for case in vector["schema_negative"]:
        with pytest.raises(PluginSchemaError, match=case["expected_error"]):
            CapabilitySchemas(case["schema"], positive["schema"])


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (lambda body: body.update(extra=True), "fields are invalid"),
        (lambda body: body.update(runtime="python"), "builtin plugins only"),
        (lambda body: body.update(plugin_id="../escape"), "namespaced identifier"),
        (lambda body: body.update(plugin_id="org.nth-dao.bad-"), "namespaced identifier"),
        (lambda body: body.update(version="1.0.0-01"), "semantic version"),
        (
            lambda body: body.update(permissions=["network.client", "artifact.read"]),
            "sorted and unique",
        ),
        (lambda body: body.update(artifact_digest="sha256:ABC"), "lowercase sha256"),
    ],
)
def test_manifest_parser_rejects_noncanonical_or_unsafe_input(mutate, match) -> None:
    body = manifest().to_dict()
    mutate(body)
    with pytest.raises(PluginContractError, match=match):
        PluginManifest.from_dict(body)


def test_capability_effect_requires_matching_manifest_permission() -> None:
    network_capability = capability(effects=("network-read",))
    with pytest.raises(PluginContractError, match="undeclared permissions"):
        manifest(provides=(network_capability,))


def test_manifest_rejects_permission_without_declared_effect() -> None:
    with pytest.raises(PluginContractError, match="not declared by capability effects"):
        manifest(permissions=("network.client",))


def test_high_consistency_capability_cannot_be_best_effort() -> None:
    with pytest.raises(PluginContractError, match="C3/C4"):
        capability(consistency="C3", failure_semantics="best-effort")


def test_irreversible_capability_must_declare_an_effect() -> None:
    with pytest.raises(PluginContractError, match="external effect"):
        capability(security="irreversible")


def test_host_api_rejects_newer_minor_or_different_major() -> None:
    ensure_host_api_compatible("1.0", "1.1")
    with pytest.raises(PluginContractError):
        ensure_host_api_compatible("1.2", "1.1")
    with pytest.raises(PluginContractError):
        ensure_host_api_compatible("2.0", "1.9")


def test_default_host_policy_denies_effectful_plugin() -> None:
    cap = capability(effects=("network-read",))
    item = manifest(provides=(cap,), permissions=("network.client",))
    runtime = Runtime({cap.capability_id: Provider()})
    host = PluginHost()
    register(host, item, lambda: runtime)
    with pytest.raises(PluginAuthorizationError, match="host policy forbids"):
        host.authorize(item.plugin_id, {"network.client"})
    with pytest.raises(PluginAuthorizationError, match="lacks required grants"):
        host.enable(item.plugin_id)
    assert runtime.started == 0


def test_workspace_permission_requires_host_bound_root(tmp_path: Path) -> None:
    cap = capability(effects=("filesystem-read",))
    item = manifest(
        provides=(cap,),
        permissions=("filesystem.read.workspace",),
    )
    policy = PluginHostPolicy(
        allowed_permissions=frozenset({"filesystem.read.workspace"}),
        max_risk_tier=2,
    )
    unbound = PluginHost(policy=policy)
    register(unbound, item, lambda: Runtime({cap.capability_id: Provider()}))
    with pytest.raises(PluginAuthorizationError, match="workspace_root"):
        unbound.authorize(item.plugin_id, {"filesystem.read.workspace"})

    bound = PluginHost(policy=policy, workspace_root=tmp_path)
    runtime = Runtime({cap.capability_id: Provider()})
    register(bound, item, lambda: runtime)
    bound.authorize(item.plugin_id, {"filesystem.read.workspace"})
    bound.enable(item.plugin_id)
    assert runtime.context.workspace_root == tmp_path.resolve()


def test_builtin_registration_rejects_unverified_signature_metadata() -> None:
    body = manifest().to_dict()
    body["publisher_did"] = (
        "did:key:z6MkiTBz1ym7DYJi7e3oHrf2bgPUC3nLGQYVhn4rJmZQ6V1r"
    )
    body["proof"] = "unverified-shape-only-proof"
    item = PluginManifest.from_dict(body)
    with pytest.raises(PluginContractError, match="does not verify"):
        register(PluginHost(), item, lambda: Runtime({}))


def test_install_authorize_enable_resolve_disable_are_distinct() -> None:
    cap = capability(effects=("network-read",))
    item = manifest(provides=(cap,), permissions=("network.client",))
    provider = Provider()
    runtime = Runtime({cap.capability_id: provider})
    host = PluginHost(
        policy=PluginHostPolicy(
            allowed_permissions=frozenset({"network.client"}),
            max_risk_tier=3,
        )
    )
    register(host, item, lambda: runtime)
    assert host.status(item.plugin_id).state == "installed"
    assert host.resolve(cap.capability_id) == ()

    host.authorize(item.plugin_id, {"network.client"})
    assert host.status(item.plugin_id).state == "authorized"
    binding = host.enable(item.plugin_id)[0]
    assert not hasattr(binding, "provider")
    assert runtime.context.granted_permissions == frozenset({"network.client"})
    assert host.resolve_one(cap.capability_id) is binding
    assert binding.invoke({}, authority=authority(cap.capability_id)) == {}
    assert provider.calls

    assert host.disable(item.plugin_id) is True
    assert runtime.stopped == 1
    assert host.resolve(cap.capability_id) == ()
    assert host.status(item.plugin_id).state == "authorized"
    with pytest.raises(PluginInvocationError, match="disabled or stale"):
        binding.invoke({}, authority=authority(cap.capability_id))


def test_invocation_enforces_schema_and_authority_at_call_boundary() -> None:
    input_schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {"value": {"type": "integer", "minimum": 0}},
        "required": ["value"],
    }
    output_schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {"result": {"type": "string", "minLength": 1}},
        "required": ["result"],
    }
    cap = CapabilityContract(
        capability_id="org.nth-dao.test.typed",
        version="1.0.0",
        input_schema_digest=schema_digest(input_schema),
        output_schema_digest=schema_digest(output_schema),
        effects=("none",),
        consistency="C1",
        privacy="workspace",
        security="verified-input",
        cardinality="one",
        deterministic=True,
        retention="none",
        failure_semantics="retry-safe",
    )
    item = manifest(provides=(cap,))
    provider = Provider({"result": "ok"})
    host = PluginHost()
    host.register_builtin(
        item,
        lambda: Runtime({cap.capability_id: provider}),
        schemas={cap.capability_id: CapabilitySchemas(input_schema, output_schema)},
    )
    binding = host.enable(item.plugin_id)[0]

    with pytest.raises(PluginAuthorizationError, match="not authorized"):
        binding.invoke(
            {"value": 1},
            authority=InvocationAuthority(
                principal="test-suite",
                capability_ids=frozenset({"org.nth-dao.test.other"}),
            ),
        )
    with pytest.raises(PluginSchemaError, match="must be integer"):
        binding.invoke({"value": True}, authority=authority(cap.capability_id))
    assert binding.invoke(
        {"value": 1},
        authority=authority(cap.capability_id),
    ) == {"result": "ok"}
    provider.response = {"result": ""}
    with pytest.raises(PluginSchemaError, match="too short"):
        binding.invoke({"value": 1}, authority=authority(cap.capability_id))


def test_registration_rejects_schema_digest_mismatch_and_unknown_keywords() -> None:
    item = manifest()
    with pytest.raises(PluginSchemaError, match="unsupported keywords"):
        CapabilitySchemas(
            {"type": "object", "unevaluatedProperties": False},
            EMPTY_SCHEMA_BODY,
        )
    with pytest.raises(PluginContractError, match="input schema digest mismatch"):
        PluginHost().register_builtin(
            item,
            lambda: Runtime({item.provides[0].capability_id: Provider()}),
            schemas={
                item.provides[0].capability_id: CapabilitySchemas(
                    {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {"changed": {"type": "boolean"}},
                    },
                    EMPTY_SCHEMA_BODY,
                )
            },
        )


def test_c2_registration_requires_semantic_validators_and_operation_echo() -> None:
    operation_schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "operation": {"type": "string", "enum": ["read", "write"]}
        },
        "required": ["operation"],
    }
    cap = CapabilityContract(
        capability_id="org.nth-dao.test.c2-operation",
        version="1.0.0",
        input_schema_digest=schema_digest(operation_schema),
        output_schema_digest=schema_digest(operation_schema),
        effects=("none",),
        consistency="C2",
        privacy="workspace",
        security="verified-input",
        cardinality="one",
        deterministic=True,
        retention="none",
        failure_semantics="at-most-once",
    )
    item = manifest(provides=(cap,))

    with pytest.raises(PluginContractError, match="requires input and output"):
        PluginHost().register_builtin(
            item,
            lambda: Runtime({cap.capability_id: Provider()}),
            schemas={
                cap.capability_id: CapabilitySchemas(
                    operation_schema,
                    operation_schema,
                )
            },
        )

    provider = Provider({"operation": "write"})
    host = PluginHost()
    host.register_builtin(
        item,
        lambda: Runtime({cap.capability_id: provider}),
        schemas={
            cap.capability_id: CapabilitySchemas(
                operation_schema,
                operation_schema,
                input_validator=lambda value: None,
                output_validator=lambda value: None,
            )
        },
    )
    binding = host.enable(item.plugin_id)[0]
    with pytest.raises(PluginSchemaError, match="does not match"):
        binding.invoke(
            {"operation": "read"},
            authority=authority(cap.capability_id),
        )


def test_host_runs_exchange_validator_after_output_validation() -> None:
    token_schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {"token": {"type": "string", "minLength": 1}},
        "required": ["token"],
    }
    cap = CapabilityContract(
        capability_id="org.nth-dao.test.exchange-binding",
        version="1.0.0",
        input_schema_digest=schema_digest(token_schema),
        output_schema_digest=schema_digest(token_schema),
        effects=("none",),
        consistency="C1",
        privacy="workspace",
        security="verified-input",
        cardinality="one",
        deterministic=True,
        retention="none",
        failure_semantics="retry-safe",
    )
    item = manifest(provides=(cap,))
    provider = Provider({"token": "substituted"})

    def bind_exchange(request, response) -> None:
        if response["token"] != request["token"]:
            raise PluginSchemaError("exchange token mismatch")

    host = PluginHost()
    host.register_builtin(
        item,
        lambda: Runtime({cap.capability_id: provider}),
        schemas={
            cap.capability_id: CapabilitySchemas(
                token_schema,
                token_schema,
                exchange_validator=bind_exchange,
            )
        },
    )
    binding = host.enable(item.plugin_id)[0]
    with pytest.raises(PluginSchemaError, match="exchange token mismatch"):
        binding.invoke(
            {"token": "original"},
            authority=authority(cap.capability_id),
        )


def test_schema_rejects_unbounded_objects_and_regex_patterns() -> None:
    with pytest.raises(PluginSchemaError, match="explicitly false"):
        CapabilitySchemas(
            {"type": "object", "additionalProperties": True, "properties": {}},
            EMPTY_SCHEMA_BODY,
        )
    with pytest.raises(PluginSchemaError, match="unsupported keywords"):
        CapabilitySchemas(
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "value": {"type": "string", "pattern": "(a+)+$"},
                },
            },
            EMPTY_SCHEMA_BODY,
        )


def test_invocation_rejects_oversized_and_non_finite_json() -> None:
    cap = capability()
    item = manifest(provides=(cap,))
    host = PluginHost()
    register(host, item, lambda: Runtime({cap.capability_id: Provider()}))
    binding = host.enable(item.plugin_id)[0]

    with pytest.raises(PluginSchemaError, match="exceeds"):
        binding.invoke(
            {"unexpected": "x" * (1024 * 1024)},
            authority=authority(cap.capability_id),
        )
    with pytest.raises(PluginSchemaError, match="finite JSON"):
        binding.invoke(
            {"unexpected": float("nan")},
            authority=authority(cap.capability_id),
        )


def test_host_v1_refuses_irreversible_capability_execution() -> None:
    cap = capability(effects=("network-write",), security="irreversible")
    item = manifest(provides=(cap,), permissions=("network.client",))
    host = PluginHost(
        policy=PluginHostPolicy(
            allowed_permissions=frozenset({"network.client"}),
            max_risk_tier=4,
        )
    )
    with pytest.raises(PluginAuthorizationError, match="does not execute irreversible"):
        register(host, item, lambda: Runtime({cap.capability_id: Provider()}))


def test_host_rejects_undeclared_grant_and_risk_above_ceiling() -> None:
    cap = capability(effects=("network-read",))
    item = manifest(provides=(cap,), permissions=("network.client",))
    host = PluginHost(
        policy=PluginHostPolicy(
            allowed_permissions=frozenset({"network.client"}),
            max_risk_tier=2,
        )
    )
    register(host, item, lambda: Runtime({cap.capability_id: Provider()}))
    with pytest.raises(PluginAuthorizationError, match="undeclared"):
        host.authorize(item.plugin_id, {"artifact.read"})
    host.authorize(item.plugin_id, {"network.client"})
    with pytest.raises(PluginAuthorizationError, match="risk tier T3"):
        host.enable(item.plugin_id)


def test_failed_start_is_cleaned_and_never_publishes_capability() -> None:
    item = manifest()
    runtime = Runtime(
        {item.provides[0].capability_id: Provider()},
        start_error=RuntimeError("partial start"),
    )
    host = PluginHost()
    register(host, item, lambda: runtime)
    with pytest.raises(PluginLifecycleError, match="partial start"):
        host.enable(item.plugin_id)
    assert runtime.started == 1
    assert runtime.stopped == 1
    assert host.resolve(item.provides[0].capability_id) == ()
    assert host.status(item.plugin_id).state == "failed"


def test_provider_manifest_mismatch_is_cleaned_atomically() -> None:
    item = manifest()
    runtime = Runtime({"org.nth-dao.test.undeclared": Provider()})
    host = PluginHost()
    register(host, item, lambda: runtime)
    with pytest.raises(PluginLifecycleError, match="does not match"):
        host.enable(item.plugin_id)
    assert runtime.stopped == 1
    assert host.resolve(item.provides[0].capability_id) == ()


def test_cleanup_failure_still_removes_routing() -> None:
    item = manifest()
    runtime = Runtime(
        {item.provides[0].capability_id: Provider()},
        stop_error=RuntimeError("cannot stop"),
    )
    host = PluginHost()
    register(host, item, lambda: runtime)
    host.enable(item.plugin_id)
    with pytest.raises(PluginLifecycleError, match="cannot stop"):
        host.disable(item.plugin_id)
    assert host.resolve(item.provides[0].capability_id) == ()
    assert host.status(item.plugin_id).state == "cleanup-failed"
    with pytest.raises(PluginLifecycleError, match="disable the plugin"):
        host.uninstall(item.plugin_id)
    with pytest.raises(PluginLifecycleError, match="currently cleanup-failed"):
        host.enable(item.plugin_id)
    runtime.stop_error = None
    assert host.disable(item.plugin_id) is True
    assert runtime.stopped == 2
    host.uninstall(item.plugin_id)


def test_single_provider_capability_conflict_fails_before_second_start() -> None:
    cap = capability()
    first = manifest("org.nth-dao.test.first", provides=(cap,))
    second = manifest("org.nth-dao.test.second", provides=(cap,))
    first_runtime = Runtime({cap.capability_id: Provider()})
    second_runtime = Runtime({cap.capability_id: Provider()})
    host = PluginHost()
    register(host, first, lambda: first_runtime)
    register(host, second, lambda: second_runtime)
    host.enable(first.plugin_id)
    with pytest.raises(PluginConflictError, match="allows one provider"):
        host.enable(second.plugin_id)
    assert second_runtime.started == 0


def test_required_dependency_controls_enable_and_disable_order() -> None:
    source_cap = capability("org.nth-dao.test.source")
    sink_cap = capability("org.nth-dao.test.sink")
    source = manifest("org.nth-dao.test.source-plugin", provides=(source_cap,))
    sink = manifest(
        "org.nth-dao.test.sink-plugin",
        provides=(sink_cap,),
        requires=(
            CapabilityRequirement(
                capability_id=source_cap.capability_id,
                major_version=1,
                contract_digest=source_cap.digest,
            ),
        ),
    )
    host = PluginHost()
    register(host, source, lambda: Runtime({source_cap.capability_id: Provider()}))
    register(host, sink, lambda: Runtime({sink_cap.capability_id: Provider()}))
    with pytest.raises(PluginDependencyError, match="unavailable"):
        host.enable(sink.plugin_id)
    host.enable(source.plugin_id)
    host.enable(sink.plugin_id)
    with pytest.raises(PluginDependencyError, match="depend"):
        host.disable(source.plugin_id)
    assert host.disable(sink.plugin_id) is True
    assert host.disable(source.plugin_id) is True


def test_dependency_rejects_same_name_and_major_with_different_contract() -> None:
    actual = capability("org.nth-dao.test.source", privacy="workspace")
    # Build a semantically different contract with the same name and version.
    expected = CapabilityContract(
        **{
            **actual.to_dict(),
            "effects": tuple(actual.effects),
            "privacy": "confidential",
        }
    )
    sink_cap = capability("org.nth-dao.test.sink")
    source = manifest("org.nth-dao.test.source-plugin", provides=(actual,))
    sink = manifest(
        "org.nth-dao.test.sink-plugin",
        provides=(sink_cap,),
        requires=(
            CapabilityRequirement(
                capability_id=actual.capability_id,
                major_version=1,
                contract_digest=expected.digest,
            ),
        ),
    )
    host = PluginHost()
    register(host, source, lambda: Runtime({actual.capability_id: Provider()}))
    register(host, sink, lambda: Runtime({sink_cap.capability_id: Provider()}))
    host.enable(source.plugin_id)
    with pytest.raises(PluginDependencyError, match="unavailable"):
        host.enable(sink.plugin_id)


def test_concurrent_enable_starts_a_plugin_once() -> None:
    item = manifest()
    counter_lock = threading.Lock()
    created = 0
    runtime = Runtime({item.provides[0].capability_id: Provider()})

    def factory():
        nonlocal created
        with counter_lock:
            created += 1
        return runtime

    host = PluginHost()
    register(host, item, factory)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: host.enable(item.plugin_id), range(16)))
    assert all(result[0] is results[0][0] for result in results)
    assert created == 1
    assert runtime.started == 1


def test_duplicate_registration_is_idempotent_only_for_same_manifest_and_factory() -> None:
    item = manifest()
    runtime = Runtime({item.provides[0].capability_id: Provider()})

    def factory():
        return runtime

    host = PluginHost()
    register(host, item, factory)
    register(host, item, factory)
    with pytest.raises(PluginConflictError, match="already installed"):
        register(host, item, lambda: runtime)


def test_plugin_code_runs_outside_host_lock() -> None:
    slow_item = manifest("org.nth-dao.test.slow")
    other_item = manifest("org.nth-dao.test.other")
    entered = threading.Event()
    release = threading.Event()

    class SlowRuntime(Runtime):
        def start(self, context):
            entered.set()
            assert release.wait(2.0)
            return super().start(context)

    host = PluginHost()
    register(
        host,
        slow_item,
        lambda: SlowRuntime({slow_item.provides[0].capability_id: Provider()}),
    )
    register(
        host,
        other_item,
        lambda: Runtime({other_item.provides[0].capability_id: Provider()}),
    )
    thread = threading.Thread(target=host.enable, args=(slow_item.plugin_id,))
    thread.start()
    assert entered.wait(1.0)
    started = time.monotonic()
    assert host.status(other_item.plugin_id).state == "installed"
    assert time.monotonic() - started < 0.2
    release.set()
    thread.join(timeout=2.0)
    assert not thread.is_alive()


def test_stop_timeout_quarantines_plugin_and_revokes_binding() -> None:
    item = manifest()
    release = threading.Event()

    class SlowStopRuntime(Runtime):
        def stop(self):
            self.stopped += 1
            release.wait(1.0)

    runtime = SlowStopRuntime({item.provides[0].capability_id: Provider()})
    host = PluginHost(lifecycle_timeout_s=0.1)
    register(host, item, lambda: runtime)
    binding = host.enable(item.plugin_id)[0]
    started = time.monotonic()
    with pytest.raises(PluginLifecycleError, match="deadline"):
        host.disable(item.plugin_id)
    assert time.monotonic() - started < 0.5
    assert host.status(item.plugin_id).state == "cleanup-failed"
    with pytest.raises(PluginInvocationError, match="disabled or stale"):
        binding.invoke({}, authority=authority(item.provides[0].capability_id))
    release.set()
    deadline = time.monotonic() + 1.0
    while runtime.stopped != 1 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert host.disable(item.plugin_id) is True
    assert runtime.stopped == 1
    assert host.status(item.plugin_id).state == "installed"


def test_audit_restores_grants_and_desired_state_without_auto_enable(
    tmp_path: Path,
) -> None:
    item = manifest()
    provider = Provider()
    first = PluginHost(workspace_root=tmp_path)
    register(first, item, lambda: Runtime({item.provides[0].capability_id: provider}))
    first.authorize(item.plugin_id, set())
    first.enable(item.plugin_id)
    assert first.verify_audit() == (True, "ok")

    restarted = PluginHost(workspace_root=tmp_path)
    register(
        restarted,
        item,
        lambda: Runtime({item.provides[0].capability_id: Provider()}),
    )
    status = restarted.status(item.plugin_id)
    assert status.state == "installed"
    assert status.desired_enabled is True
    assert restarted.resolve(item.provides[0].capability_id) == ()


def test_builtin_manifest_upgrade_is_explicit_audited_and_clears_authority(
    tmp_path: Path,
) -> None:
    item = manifest()
    first = PluginHost(workspace_root=tmp_path)
    register(first, item, lambda: Runtime({item.provides[0].capability_id: Provider()}))
    first.enable(item.plugin_id)

    changed_body = item.to_dict()
    changed_body["artifact_digest"] = f"sha256:{hashlib.sha256(b'upgrade').hexdigest()}"
    changed = PluginManifest.from_dict(changed_body)
    refused = PluginHost(workspace_root=tmp_path)
    with pytest.raises(PluginConflictError, match="different manifest"):
        refused.register_builtin(
            changed,
            lambda: Runtime({changed.provides[0].capability_id: Provider()}),
            schemas=plugin_schemas(changed),
        )

    upgraded = PluginHost(workspace_root=tmp_path)
    upgraded.register_builtin(
        changed,
        lambda: Runtime({changed.provides[0].capability_id: Provider()}),
        schemas=plugin_schemas(changed),
        allow_manifest_upgrade=True,
    )
    status = upgraded.status(changed.plugin_id)
    assert status.state == "installed"
    assert status.authorized_permissions == ()
    assert status.desired_enabled is False
    assert upgraded.resolve(changed.provides[0].capability_id) == ()
    assert any(
        event["event_type"] == "plugin.upgraded"
        for event in upgraded._audit_log.read_verified()
    )


def test_corrupt_plugin_audit_fails_closed(tmp_path: Path) -> None:
    item = manifest()
    host = PluginHost(workspace_root=tmp_path)
    register(host, item, lambda: Runtime({item.provides[0].capability_id: Provider()}))
    audit_path = tmp_path / ".nth" / "plugin-host" / "audit.jsonl"
    body = bytearray(audit_path.read_bytes())
    body[-3] = ord("0") if body[-3] != ord("0") else ord("1")
    audit_path.write_bytes(body)
    with pytest.raises(
        PluginAuditError,
        match="chain breaks|hash mismatch|invalid JSON",
    ):
        PluginHost(workspace_root=tmp_path)


def test_plugin_audit_reader_waits_for_cross_process_writer_lock(
    tmp_path: Path,
) -> None:
    audit_path = tmp_path / "audit.jsonl"
    log = PluginAuditLog(audit_path)
    log.append(
        "plugin.registered",
        "org.nth-dao.test",
        {"manifest_digest": ARTIFACT_DIGEST},
    )
    external_writer = InterProcessLock(audit_path, timeout=2.0)
    external_writer.acquire()
    entered = threading.Event()
    finished = threading.Event()
    records = []

    def read_snapshot() -> None:
        entered.set()
        records.extend(log.read_verified())
        finished.set()

    reader = threading.Thread(target=read_snapshot, daemon=True)
    reader.start()
    assert entered.wait(1.0)
    assert finished.wait(0.15) is False
    external_writer.release()
    reader.join(2.0)

    assert finished.is_set()
    assert len(records) == 1


def test_plugin_audit_lock_timeout_is_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    log = PluginAuditLog(tmp_path / "audit.jsonl")
    monkeypatch.setattr(
        log.lock,
        "acquire",
        lambda: (_ for _ in ()).throw(TimeoutError("busy")),
    )

    with pytest.raises(PluginAuditError, match="lock timed out"):
        log.read_verified()


def test_plugin_audit_lock_io_failure_is_normalized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    log = PluginAuditLog(tmp_path / "audit.jsonl")
    monkeypatch.setattr(
        log.lock,
        "acquire",
        lambda: (_ for _ in ()).throw(OSError("permission denied")),
    )

    with pytest.raises(PluginAuditError, match="lock is unavailable"):
        log.read_verified()


def test_plugin_audit_append_directory_failure_is_normalized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    log = PluginAuditLog(tmp_path / "missing" / "audit.jsonl")
    monkeypatch.setattr(log.lock, "acquire", lambda: True)
    monkeypatch.setattr(log.lock, "release", lambda: None)
    original_mkdir = Path.mkdir

    def fail_audit_mkdir(path: Path, *args, **kwargs):
        if path == log.path.parent:
            raise OSError("read-only filesystem")
        return original_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", fail_audit_mkdir)

    with pytest.raises(PluginAuditError, match="cannot append plugin audit"):
        log.append(
            "plugin.registered",
            "org.nth-dao.test",
            {"manifest_digest": ARTIFACT_DIGEST},
        )


def test_hash_valid_plugin_audit_with_invalid_event_details_fails_closed(
    tmp_path: Path,
) -> None:
    item = manifest()
    host = PluginHost(workspace_root=tmp_path)
    register(host, item, lambda: Runtime({item.provides[0].capability_id: Provider()}))
    audit_path = tmp_path / ".nth" / "plugin-host" / "audit.jsonl"
    first = json.loads(audit_path.read_text(encoding="utf-8").splitlines()[0])
    core = {
        "seq": 1,
        "recorded_at": "2026-08-20T00:00:00+00:00",
        "event_type": "plugin.authorized",
        "plugin_id": item.plugin_id,
        "details": {},
        "previous_hash": first["event_hash"],
    }
    forged = {
        **core,
        "event_hash": hashlib.sha256(canonical_json(core)).hexdigest(),
    }
    with audit_path.open("ab") as stream:
        stream.write(canonical_json(forged) + b"\n")

    with pytest.raises(PluginAuditError, match="event details are invalid"):
        PluginHost(workspace_root=tmp_path)


def test_plugin_audit_rejects_invalid_operator_attribution(tmp_path: Path) -> None:
    item = manifest()
    host = PluginHost(workspace_root=tmp_path)
    register(host, item, lambda: Runtime({item.provides[0].capability_id: Provider()}))
    audit_path = tmp_path / ".nth" / "plugin-host" / "audit.jsonl"
    first = json.loads(audit_path.read_text(encoding="utf-8").splitlines()[0])
    core = {
        "seq": 1,
        "recorded_at": "2026-08-20T00:00:00+00:00",
        "event_type": "plugin.authorized",
        "plugin_id": item.plugin_id,
        "details": {
            "grants": [],
            "operator": {"actor_id": "admin"},
        },
        "previous_hash": first["event_hash"],
    }
    forged = {
        **core,
        "event_hash": hashlib.sha256(canonical_json(core)).hexdigest(),
    }
    with audit_path.open("ab") as stream:
        stream.write(canonical_json(forged) + b"\n")

    with pytest.raises(PluginAuditError, match="operator is invalid"):
        PluginHost(workspace_root=tmp_path)


def test_hash_valid_plugin_audit_cannot_skip_registration(tmp_path: Path) -> None:
    audit_path = tmp_path / ".nth" / "plugin-host" / "audit.jsonl"
    audit_path.parent.mkdir(parents=True)
    core = {
        "seq": 0,
        "recorded_at": "2026-08-20T00:00:00+00:00",
        "event_type": "plugin.authorized",
        "plugin_id": "org.nth-dao.test.echo",
        "details": {"grants": []},
        "previous_hash": "",
    }
    forged = {
        **core,
        "event_hash": hashlib.sha256(canonical_json(core)).hexdigest(),
    }
    audit_path.write_bytes(canonical_json(forged) + b"\n")

    with pytest.raises(PluginAuditError, match="precedes registration"):
        PluginHost(workspace_root=tmp_path)


def test_disable_audit_failure_cannot_forge_clean_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    item = manifest()
    host = PluginHost(workspace_root=tmp_path)
    register(host, item, lambda: Runtime({item.provides[0].capability_id: Provider()}))
    binding = host.enable(item.plugin_id)[0]
    assert host._audit_log is not None
    monkeypatch.setattr(
        host._audit_log,
        "append",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            PluginAuditError("injected audit outage")
        ),
    )
    with pytest.raises(PluginLifecycleError, match="audit commit failed"):
        host.disable(item.plugin_id)
    assert host.status(item.plugin_id).state == "failed"
    assert host.resolve(item.provides[0].capability_id) == ()
    with pytest.raises(PluginInvocationError, match="disabled or stale"):
        binding.invoke({}, authority=authority(item.provides[0].capability_id))
