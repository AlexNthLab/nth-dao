"""Adversarial tests for the reviewed subprocess plugin boundary."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

import pytest

import nth_dao.plugins.subprocess_runtime as subprocess_runtime_module
from nth_dao.plugins import (
    CapabilityContract,
    CapabilitySchemas,
    InvocationAuthority,
    PluginContractError,
    PluginHost,
    PluginHostPolicy,
    PluginInvocationError,
    PluginLifecycleError,
    PluginManifest,
    PluginSchemaError,
    ReviewedSubprocessSpec,
    SubprocessPluginError,
    SubprocessRemoteError,
    schema_digest,
    subprocess_artifact_digest,
    subprocess_canonical_json,
    subprocess_rpc_protocol_digest,
    subprocess_rpc_protocol_document,
    subprocess_rpc_wire_vectors,
)


WORKER = Path(__file__).parent / "fixtures" / "plugin_rpc_worker.py"
VECTOR = (
    Path(__file__).parents[1]
    / "nth_dao"
    / "plugins"
    / "vectors"
    / "subprocess-rpc-v1.json"
)
INPUT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {"value": {"type": "string", "maxLength": 256}},
    "required": ["value"],
}
OUTPUT_SCHEMA = INPUT_SCHEMA
CAPABILITY_ID = "org.nth-dao.test.subprocess-echo"


def test_checked_in_subprocess_rpc_vector_matches_protocol_code() -> None:
    vector = json.loads(VECTOR.read_text(encoding="utf-8"))
    assert vector == subprocess_rpc_wire_vectors()
    assert vector["protocol_digest"] == subprocess_rpc_protocol_digest()
    protocol = subprocess_rpc_protocol_document()
    assert protocol["trust_boundary"]["os_sandbox"] == "not-provided"
    assert protocol["trust_boundary"]["irreversible_capabilities"] == "unsupported"


def test_subprocess_canonical_json_rejects_unsafe_integers() -> None:
    with pytest.raises(ValueError, match="safe range"):
        subprocess_canonical_json({"value": 9_007_199_254_740_992})


def test_node_matches_subprocess_rpc_canonical_vectors() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is unavailable for cross-language conformance")
    script = r"""
const crypto = require("crypto");
const fs = require("fs");
function canonical(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error("unsafe integer");
    return String(value);
  }
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (typeof value === "object") {
    return "{" + Object.keys(value).sort().map(
      key => JSON.stringify(key) + ":" + canonical(value[key])
    ).join(",") + "}";
  }
  throw new Error("unsupported JSON value");
}
const vectors = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
for (const item of [...vectors.canonical_examples, ...vectors.examples]) {
  const encoded = canonical(item.document);
  if (encoded !== item.canonical_utf8) throw new Error("canonical bytes mismatch: " + item.name);
  const digest = "sha256:" + crypto.createHash("sha256").update(encoded, "utf8").digest("hex");
  if (digest !== item.sha256) throw new Error("canonical digest mismatch: " + item.name);
}
"""
    result = subprocess.run(
        [node, "-e", script, str(VECTOR)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout


def make_manifest(
    artifact: Path = WORKER,
    *,
    runtime: str = "subprocess",
    input_schema: dict = INPUT_SCHEMA,
    output_schema: dict = OUTPUT_SCHEMA,
) -> PluginManifest:
    contract = CapabilityContract(
        capability_id=CAPABILITY_ID,
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
    return PluginManifest(
        manifest_version=1,
        plugin_id="org.nth-dao.test.subprocess",
        version="1.0.0",
        host_api="1.1",
        kind="agent.provider",
        runtime=runtime,
        provides=(contract,),
        requires=(),
        permissions=(),
        artifact_digest=subprocess_artifact_digest(artifact),
    )


def make_spec(tmp_path: Path, mode: str = "normal", **overrides) -> ReviewedSubprocessSpec:
    values = {
        "launcher": Path(sys.executable),
        "artifact": WORKER,
        "working_directory": tmp_path,
        "arguments": (mode,),
        "startup_timeout_s": 1.0,
        "invocation_timeout_s": 1.0,
        "shutdown_timeout_s": 0.5,
    }
    values.update(overrides)
    return ReviewedSubprocessSpec(**values)


def register_and_enable(tmp_path: Path, mode: str = "normal", **overrides):
    manifest = make_manifest()
    host = PluginHost(workspace_root=tmp_path, lifecycle_timeout_s=2.0)
    host.register_reviewed_subprocess(
        manifest,
        make_spec(tmp_path, mode, **overrides),
        schemas={
            CAPABILITY_ID: CapabilitySchemas(INPUT_SCHEMA, OUTPUT_SCHEMA),
        },
    )
    binding = host.enable(manifest.plugin_id)[0]
    authority = InvocationAuthority(
        principal="did:key:test-principal",
        capability_ids=frozenset({CAPABILITY_ID}),
    )
    return host, manifest, binding, authority


def test_subprocess_manifest_requires_explicit_registration_path(tmp_path: Path) -> None:
    manifest = make_manifest()
    spec = make_spec(tmp_path)
    with pytest.raises(PluginContractError, match="builtin"):
        PluginHost().register_builtin(
            manifest,
            lambda: object(),
            schemas={CAPABILITY_ID: CapabilitySchemas(INPUT_SCHEMA, OUTPUT_SCHEMA)},
        )
    builtin_body = manifest.to_dict()
    builtin_body["runtime"] = "builtin"
    with pytest.raises(PluginContractError, match="runtime=subprocess"):
        PluginHost().register_reviewed_subprocess(
            PluginManifest.from_dict(builtin_body),
            spec,
            schemas={CAPABILITY_ID: CapabilitySchemas(INPUT_SCHEMA, OUTPUT_SCHEMA)},
        )


def test_reviewed_subprocess_round_trip_and_clean_shutdown(tmp_path: Path) -> None:
    host, manifest, binding, authority = register_and_enable(tmp_path)
    assert binding.invoke({"value": "hello"}, authority=authority) == {
        "value": "hello"
    }
    assert host.disable(manifest.plugin_id) is True
    assert host.status(manifest.plugin_id).state == "installed"


def test_repeated_reviewed_registration_is_idempotent_for_same_spec(
    tmp_path: Path,
) -> None:
    manifest = make_manifest()
    spec = make_spec(tmp_path)
    schemas = {CAPABILITY_ID: CapabilitySchemas(INPUT_SCHEMA, OUTPUT_SCHEMA)}
    host = PluginHost(workspace_root=tmp_path)
    host.register_reviewed_subprocess(manifest, spec, schemas=schemas)
    host.register_reviewed_subprocess(manifest, spec, schemas=schemas)
    assert host.status(manifest.plugin_id).state == "installed"


def test_subprocess_environment_is_explicit_and_does_not_inherit_secrets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NTH_SECRET_SHOULD_NOT_LEAK", "top-secret")
    host, manifest, binding, authority = register_and_enable(
        tmp_path,
        "environment",
        environment=(("EXPLICIT_VALUE", "present"),),
    )
    assert binding.invoke({"value": "ignored"}, authority=authority) == {
        "value": "present|clean"
    }
    host.disable(manifest.plugin_id)


def test_worker_artifact_is_checked_at_registration_and_again_at_start(
    tmp_path: Path,
) -> None:
    copied = tmp_path / "worker.py"
    shutil.copyfile(WORKER, copied)
    manifest = make_manifest(copied)
    spec = ReviewedSubprocessSpec(
        launcher=Path(sys.executable),
        artifact=copied,
        working_directory=tmp_path,
    )
    copied.write_text(copied.read_text(encoding="utf-8") + "\n# changed\n", encoding="utf-8")
    host = PluginHost(workspace_root=tmp_path)
    with pytest.raises(SubprocessPluginError, match="artifact_digest"):
        host.register_reviewed_subprocess(
            manifest,
            spec,
            schemas={CAPABILITY_ID: CapabilitySchemas(INPUT_SCHEMA, OUTPUT_SCHEMA)},
        )

    copied.write_bytes(WORKER.read_bytes())
    host.register_reviewed_subprocess(
        manifest,
        spec,
        schemas={CAPABILITY_ID: CapabilitySchemas(INPUT_SCHEMA, OUTPUT_SCHEMA)},
    )
    copied.write_text(copied.read_text(encoding="utf-8") + "\n# raced\n", encoding="utf-8")
    with pytest.raises(PluginLifecycleError, match="artifact"):
        host.enable(manifest.plugin_id)
    assert host.status(manifest.plugin_id).state == "failed"


def test_launcher_is_resolved_and_rejects_symlink(tmp_path: Path) -> None:
    link = tmp_path / "launcher-link"
    try:
        link.symlink_to(Path(sys.executable))
    except OSError:
        pytest.skip("launcher symlink creation is unavailable")

    with pytest.raises(SubprocessPluginError, match="launcher must not be a symlink"):
        ReviewedSubprocessSpec(
            launcher=link,
            artifact=WORKER,
            working_directory=tmp_path,
        )


def test_launcher_bytes_are_checked_at_registration_and_again_at_start(
    tmp_path: Path,
) -> None:
    launcher = tmp_path / "reviewed-launcher.bin"
    reviewed_bytes = b"reviewed launcher bytes"
    launcher.write_bytes(reviewed_bytes)
    manifest = make_manifest()
    spec = ReviewedSubprocessSpec(
        launcher=launcher,
        artifact=WORKER,
        working_directory=tmp_path,
    )
    schemas = {CAPABILITY_ID: CapabilitySchemas(INPUT_SCHEMA, OUTPUT_SCHEMA)}

    launcher.write_bytes(b"replaced before registration")
    with pytest.raises(SubprocessPluginError, match="launcher changed"):
        PluginHost(workspace_root=tmp_path).register_reviewed_subprocess(
            manifest,
            spec,
            schemas=schemas,
        )

    launcher.write_bytes(reviewed_bytes)
    host = PluginHost(workspace_root=tmp_path)
    host.register_reviewed_subprocess(manifest, spec, schemas=schemas)
    launcher.write_bytes(b"replaced before startup")
    with pytest.raises(PluginLifecycleError, match="launcher changed"):
        host.enable(manifest.plugin_id)
    assert host.status(manifest.plugin_id).state == "failed"


def test_worker_executes_verified_private_snapshot_not_mutable_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    copied = tmp_path / "reviewed-worker.py"
    shutil.copyfile(WORKER, copied)
    manifest = make_manifest(copied)
    spec = ReviewedSubprocessSpec(
        launcher=Path(sys.executable),
        artifact=copied,
        working_directory=tmp_path,
        startup_timeout_s=1.0,
        invocation_timeout_s=1.0,
        shutdown_timeout_s=0.5,
    )
    real_popen = subprocess_runtime_module.subprocess.Popen
    launched: list[Path] = []

    def racing_popen(command, **kwargs):
        snapshot = Path(command[1])
        launched.append(snapshot)
        copied.write_text("raise RuntimeError('mutated source')\n", encoding="utf-8")
        return real_popen(command, **kwargs)

    monkeypatch.setattr(subprocess_runtime_module.subprocess, "Popen", racing_popen)
    host = PluginHost(workspace_root=tmp_path)
    host.register_reviewed_subprocess(
        manifest,
        spec,
        schemas={CAPABILITY_ID: CapabilitySchemas(INPUT_SCHEMA, OUTPUT_SCHEMA)},
    )
    binding = host.enable(manifest.plugin_id)[0]
    authority = InvocationAuthority(
        principal="test",
        capability_ids=frozenset({CAPABILITY_ID}),
    )
    assert binding.invoke({"value": "snapshot"}, authority=authority) == {
        "value": "snapshot"
    }
    assert launched and launched[0] != copied
    assert launched[0].is_file()
    snapshot_directory = launched[0].parent
    assert snapshot_directory.is_relative_to(
        tmp_path / ".nth" / "plugin-host" / "snapshots"
    )
    host.disable(manifest.plugin_id)
    assert not snapshot_directory.exists()


def test_registration_cleans_only_inactive_owned_snapshot_generations(
    tmp_path: Path,
) -> None:
    manifest = make_manifest()
    spec = make_spec(tmp_path)
    snapshot_root = tmp_path / ".nth" / "plugin-host" / "snapshots"
    directory, _snapshot, lease = spec.snapshot_artifact(
        manifest.artifact_digest,
        snapshot_root=snapshot_root,
        plugin_id=manifest.plugin_id,
    )
    lease.release()

    host = PluginHost(workspace_root=tmp_path)
    host.register_reviewed_subprocess(
        manifest,
        spec,
        schemas={CAPABILITY_ID: CapabilitySchemas(INPUT_SCHEMA, OUTPUT_SCHEMA)},
    )

    assert not directory.exists()
    cleanup_events = [
        event
        for event in host._audit_log.read_verified()
        if event["event_type"] == "plugin.snapshot.orphans-cleaned"
    ]
    assert cleanup_events[-1]["details"] == {"count": 1}


def test_registration_audits_orphan_snapshot_cleanup_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = make_manifest()
    spec = make_spec(tmp_path)
    snapshot_root = tmp_path / ".nth" / "plugin-host" / "snapshots"
    _directory, _snapshot, lease = spec.snapshot_artifact(
        manifest.artifact_digest,
        snapshot_root=snapshot_root,
        plugin_id=manifest.plugin_id,
    )
    lease.release()

    def fail_remove(_directory: Path) -> None:
        raise OSError("simulated cleanup failure")

    monkeypatch.setattr(subprocess_runtime_module, "_remove_private_tree", fail_remove)
    host = PluginHost(workspace_root=tmp_path)
    with pytest.raises(PluginLifecycleError, match="snapshot cleanup failed"):
        host.register_reviewed_subprocess(
            manifest,
            spec,
            schemas={CAPABILITY_ID: CapabilitySchemas(INPUT_SCHEMA, OUTPUT_SCHEMA)},
        )
    assert host._audit_log.read_verified()[-1]["event_type"] == (
        "plugin.snapshot.cleanup.failed"
    )


def test_snapshot_janitor_refuses_redirected_root(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    snapshot_parent = workspace / ".nth" / "plugin-host"
    snapshot_parent.mkdir(parents=True)
    outside = tmp_path / "outside"
    generation = outside / ("generation-" + "a" * 32)
    generation.mkdir(parents=True)
    sentinel = generation / "must-remain.txt"
    sentinel.write_text("owned by another path", encoding="utf-8")
    redirected = snapshot_parent / "snapshots"
    try:
        redirected.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink creation is unavailable")

    with pytest.raises(SubprocessPluginError, match="path redirection"):
        subprocess_runtime_module.cleanup_orphaned_subprocess_snapshots(redirected)
    assert sentinel.read_text(encoding="utf-8") == "owned by another path"


def test_disable_surfaces_snapshot_cleanup_failure_and_can_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host, manifest, _binding, _authority = register_and_enable(tmp_path)
    real_remove = subprocess_runtime_module._remove_private_tree

    def fail_remove(_directory: Path) -> None:
        raise OSError("simulated cleanup failure")

    monkeypatch.setattr(subprocess_runtime_module, "_remove_private_tree", fail_remove)
    with pytest.raises(PluginLifecycleError, match="cleanup failed"):
        host.disable(manifest.plugin_id)
    assert host.status(manifest.plugin_id).state == "cleanup-failed"

    monkeypatch.setattr(subprocess_runtime_module, "_remove_private_tree", real_remove)
    assert host.disable(manifest.plugin_id) is True
    assert host.status(manifest.plugin_id).state == "installed"


def test_launch_profile_change_clears_persisted_grants(
    tmp_path: Path,
) -> None:
    contract = CapabilityContract(
        capability_id=CAPABILITY_ID,
        version="1.0.0",
        input_schema_digest=schema_digest(INPUT_SCHEMA),
        output_schema_digest=schema_digest(OUTPUT_SCHEMA),
        effects=("network-read",),
        consistency="C1",
        privacy="workspace",
        security="verified-input",
        cardinality="one",
        deterministic=False,
        retention="none",
        failure_semantics="retry-safe",
    )
    manifest = PluginManifest(
        manifest_version=1,
        plugin_id="org.nth-dao.test.subprocess-profile",
        version="1.0.0",
        host_api="1.1",
        kind="agent.provider",
        runtime="subprocess",
        provides=(contract,),
        requires=(),
        permissions=("network.client",),
        artifact_digest=subprocess_artifact_digest(WORKER),
    )
    schemas = {CAPABILITY_ID: CapabilitySchemas(INPUT_SCHEMA, OUTPUT_SCHEMA)}
    policy = PluginHostPolicy(
        allowed_permissions=frozenset({"network.client"}),
        max_risk_tier=3,
    )
    reviewed = make_spec(tmp_path)
    first = PluginHost(workspace_root=tmp_path, policy=policy)
    first.register_reviewed_subprocess(manifest, reviewed, schemas=schemas)
    first.authorize(manifest.plugin_id, {"network.client"})

    unchanged = PluginHost(workspace_root=tmp_path, policy=policy)
    unchanged.register_reviewed_subprocess(
        manifest,
        make_spec(tmp_path),
        schemas=schemas,
    )
    assert unchanged.status(manifest.plugin_id).authorized_permissions == (
        "network.client",
    )

    changed = make_spec(
        tmp_path,
        mode="environment",
    )
    restarted = PluginHost(workspace_root=tmp_path, policy=policy)
    restarted.register_reviewed_subprocess(manifest, changed, schemas=schemas)
    status = restarted.status(manifest.plugin_id)
    assert status.authorized_permissions == ()
    assert status.desired_enabled is False
    assert restarted._audit_log.read_verified()[-1]["event_type"] == (
        "plugin.launch-profile.changed"
    )


def test_explicit_environment_requires_fresh_authorization_without_commitment_leak(
    tmp_path: Path,
) -> None:
    contract = CapabilityContract(
        capability_id=CAPABILITY_ID,
        version="1.0.0",
        input_schema_digest=schema_digest(INPUT_SCHEMA),
        output_schema_digest=schema_digest(OUTPUT_SCHEMA),
        effects=("network-read",),
        consistency="C1",
        privacy="workspace",
        security="verified-input",
        cardinality="one",
        deterministic=False,
        retention="none",
        failure_semantics="retry-safe",
    )
    manifest = PluginManifest(
        manifest_version=1,
        plugin_id="org.nth-dao.test.subprocess-environment-profile",
        version="1.0.0",
        host_api="1.1",
        kind="agent.provider",
        runtime="subprocess",
        provides=(contract,),
        requires=(),
        permissions=("network.client",),
        artifact_digest=subprocess_artifact_digest(WORKER),
    )
    schemas = {CAPABILITY_ID: CapabilitySchemas(INPUT_SCHEMA, OUTPUT_SCHEMA)}
    policy = PluginHostPolicy(
        allowed_permissions=frozenset({"network.client"}),
        max_risk_tier=3,
    )
    secret = "1234"
    reviewed = make_spec(
        tmp_path,
        environment=(("EXPLICIT_VALUE", secret),),
    )
    reconstructed = make_spec(
        tmp_path,
        environment=(("EXPLICIT_VALUE", secret),),
    )
    assert reviewed.launch_profile_digest != reconstructed.launch_profile_digest

    first = PluginHost(workspace_root=tmp_path, policy=policy)
    first.register_reviewed_subprocess(manifest, reviewed, schemas=schemas)
    first.authorize(manifest.plugin_id, {"network.client"})

    restarted = PluginHost(workspace_root=tmp_path, policy=policy)
    restarted.register_reviewed_subprocess(
        manifest,
        reconstructed,
        schemas=schemas,
    )
    assert restarted.status(manifest.plugin_id).authorized_permissions == ()
    audit_text = restarted._audit_log.path.read_text(encoding="utf-8")
    assert secret not in audit_text


@pytest.mark.parametrize("mode", ["bad-ready", "handshake-hang"])
def test_bad_handshake_never_publishes_capability(tmp_path: Path, mode: str) -> None:
    manifest = make_manifest()
    host = PluginHost(workspace_root=tmp_path, lifecycle_timeout_s=1.0)
    host.register_reviewed_subprocess(
        manifest,
        make_spec(tmp_path, mode, startup_timeout_s=0.2),
        schemas={CAPABILITY_ID: CapabilitySchemas(INPUT_SCHEMA, OUTPUT_SCHEMA)},
    )
    started = time.monotonic()
    with pytest.raises(PluginLifecycleError, match="handshake"):
        host.enable(manifest.plugin_id)
    assert time.monotonic() - started < 3.0
    assert host.resolve(CAPABILITY_ID) == ()
    assert host.status(manifest.plugin_id).state == "failed"


@pytest.mark.parametrize(
    "mode",
    [
        "wrong-id",
        "malformed",
        "noncanonical",
        "oversize",
        "crash",
        "hang",
        "flood",
        "stderr-flood",
        "invalid-output",
    ],
)
def test_protocol_or_availability_failure_quarantines_generation(
    tmp_path: Path,
    mode: str,
) -> None:
    timeout = 0.2 if mode == "hang" else 1.0
    host, manifest, binding, authority = register_and_enable(
        tmp_path,
        mode,
        invocation_timeout_s=timeout,
    )
    started = time.monotonic()
    with pytest.raises(PluginInvocationError):
        binding.invoke({"value": "hello"}, authority=authority)
    assert time.monotonic() - started < 3.0
    assert host.status(manifest.plugin_id).state == "failed"
    assert host.status(manifest.plugin_id).desired_enabled is False
    assert host.resolve(CAPABILITY_ID) == ()
    with pytest.raises(PluginInvocationError, match="disabled or stale"):
        binding.invoke({"value": "again"}, authority=authority)
    events = host._audit_log.read_verified()
    assert events[-1]["event_type"] == "plugin.runtime.failed"


def test_remote_business_error_does_not_quarantine_worker(tmp_path: Path) -> None:
    host, manifest, binding, authority = register_and_enable(tmp_path, "remote-error")
    with pytest.raises(SubprocessRemoteError, match="warming up") as raised:
        binding.invoke({"value": "hello"}, authority=authority)
    assert raised.value.code == "not-ready"
    assert raised.value.retryable is True
    assert host.status(manifest.plugin_id).state == "enabled"
    assert host.resolve_one(CAPABILITY_ID) is binding
    host.disable(manifest.plugin_id)


def test_worker_cannot_mark_at_most_once_failure_as_retryable(tmp_path: Path) -> None:
    contract = CapabilityContract(
        capability_id=CAPABILITY_ID,
        version="1.0.0",
        input_schema_digest=schema_digest(INPUT_SCHEMA),
        output_schema_digest=schema_digest(OUTPUT_SCHEMA),
        effects=("none",),
        consistency="C2",
        privacy="workspace",
        security="verified-input",
        cardinality="one",
        deterministic=False,
        retention="none",
        failure_semantics="at-most-once",
    )
    manifest = PluginManifest(
        manifest_version=1,
        plugin_id="org.nth-dao.test.subprocess-at-most-once",
        version="1.0.0",
        host_api="1.1",
        kind="agent.provider",
        runtime="subprocess",
        provides=(contract,),
        requires=(),
        permissions=(),
        artifact_digest=subprocess_artifact_digest(WORKER),
    )
    def no_op(*_args) -> None:
        return None
    host = PluginHost(workspace_root=tmp_path)
    host.register_reviewed_subprocess(
        manifest,
        make_spec(tmp_path, "remote-error"),
        schemas={
            CAPABILITY_ID: CapabilitySchemas(
                INPUT_SCHEMA,
                OUTPUT_SCHEMA,
                input_validator=no_op,
                output_validator=no_op,
                exchange_validator=no_op,
            )
        },
    )
    binding = host.enable(manifest.plugin_id)[0]
    authority = InvocationAuthority(
        principal="test",
        capability_ids=frozenset({CAPABILITY_ID}),
    )
    with pytest.raises(PluginInvocationError, match="retryability"):
        binding.invoke({"value": "hello"}, authority=authority)
    assert host.status(manifest.plugin_id).state == "failed"
    assert host.resolve(CAPABILITY_ID) == ()


def test_idle_protocol_failure_proactively_quarantines_generation(
    tmp_path: Path,
) -> None:
    host, manifest, _binding, _authority = register_and_enable(
        tmp_path,
        "single-unsolicited",
    )
    deadline = time.monotonic() + 3.0
    while host.status(manifest.plugin_id).state in {"enabled", "disabling"}:
        if time.monotonic() >= deadline:
            pytest.fail("idle protocol failure did not quarantine the provider")
        time.sleep(0.02)
    status = host.status(manifest.plugin_id)
    assert status.state == "failed"
    assert status.desired_enabled is False
    assert host.resolve(CAPABILITY_ID) == ()
    assert host._audit_log.read_verified()[-1]["event_type"] == (
        "plugin.runtime.failed"
    )


def test_stderr_content_is_never_reflected_into_host_diagnostics(tmp_path: Path) -> None:
    host, manifest, binding, authority = register_and_enable(tmp_path, "stderr-secret")
    with pytest.raises(PluginInvocationError) as raised:
        binding.invoke({"value": "hello"}, authority=authority)
    status = host.status(manifest.plugin_id)
    combined = f"{raised.value} {status.last_error}"
    assert "secret-token-must-not-surface" not in combined
    assert "stderr" in combined


def test_runtime_failure_projection_remains_disabled_after_restart(tmp_path: Path) -> None:
    host, manifest, binding, authority = register_and_enable(tmp_path, "wrong-id")
    with pytest.raises(PluginInvocationError):
        binding.invoke({"value": "hello"}, authority=authority)

    restarted = PluginHost(workspace_root=tmp_path)
    restarted.register_reviewed_subprocess(
        manifest,
        make_spec(tmp_path, "normal"),
        schemas={CAPABILITY_ID: CapabilitySchemas(INPUT_SCHEMA, OUTPUT_SCHEMA)},
    )
    status = restarted.status(manifest.plugin_id)
    assert status.state == "installed"
    assert status.desired_enabled is False
    assert restarted.resolve(CAPABILITY_ID) == ()


def test_host_sized_payload_fits_inside_rpc_envelope(tmp_path: Path) -> None:
    large_schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {"value": {"type": "string", "maxLength": 1_040_000}},
        "required": ["value"],
    }
    contract = CapabilityContract(
        capability_id=CAPABILITY_ID,
        version="1.0.0",
        input_schema_digest=schema_digest(large_schema),
        output_schema_digest=schema_digest(large_schema),
        effects=("none",),
        consistency="C1",
        privacy="workspace",
        security="verified-input",
        cardinality="one",
        deterministic=True,
        retention="none",
        failure_semantics="retry-safe",
    )
    manifest = PluginManifest(
        manifest_version=1,
        plugin_id="org.nth-dao.test.subprocess",
        version="1.0.0",
        host_api="1.1",
        kind="agent.provider",
        runtime="subprocess",
        provides=(contract,),
        requires=(),
        permissions=(),
        artifact_digest=subprocess_artifact_digest(WORKER),
    )
    host = PluginHost(workspace_root=tmp_path)
    host.register_reviewed_subprocess(
        manifest,
        make_spec(tmp_path, invocation_timeout_s=15.0),
        schemas={CAPABILITY_ID: CapabilitySchemas(large_schema, large_schema)},
    )
    binding = host.enable(manifest.plugin_id)[0]
    authority = InvocationAuthority(
        principal="test",
        capability_ids=frozenset({CAPABILITY_ID}),
    )
    value = "x" * 1_040_000
    assert binding.invoke({"value": value}, authority=authority)["value"] == value
    host.disable(manifest.plugin_id)


def test_unrepresentable_input_does_not_quarantine_healthy_worker(
    tmp_path: Path,
) -> None:
    numeric_schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {"value": {"type": "number"}},
        "required": ["value"],
    }
    manifest = make_manifest(
        input_schema=numeric_schema,
        output_schema=numeric_schema,
    )
    host = PluginHost(workspace_root=tmp_path)
    host.register_reviewed_subprocess(
        manifest,
        make_spec(tmp_path),
        schemas={
            CAPABILITY_ID: CapabilitySchemas(numeric_schema, numeric_schema),
        },
    )
    binding = host.enable(manifest.plugin_id)[0]
    authority = InvocationAuthority(
        principal="test",
        capability_ids=frozenset({CAPABILITY_ID}),
    )

    with pytest.raises(PluginSchemaError, match="finite JSON"):
        binding.invoke({"value": 1.5}, authority=authority)
    with pytest.raises(PluginInvocationError, match="not representable"):
        binding.invoke(
            {"value": 9_007_199_254_740_992},
            authority=authority,
        )

    assert host.status(manifest.plugin_id).state == "enabled"
    assert binding.invoke({"value": 1}, authority=authority) == {"value": 1}
    host.disable(manifest.plugin_id)


def test_validator_cannot_push_unrepresentable_input_into_worker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = make_manifest()
    host = PluginHost(workspace_root=tmp_path)

    def inject_float(payload: dict) -> None:
        payload["value"] = 1.5

    host.register_reviewed_subprocess(
        manifest,
        make_spec(tmp_path),
        schemas={
            CAPABILITY_ID: CapabilitySchemas(
                INPUT_SCHEMA,
                OUTPUT_SCHEMA,
                input_validator=inject_float,
            ),
        },
    )
    binding = host.enable(manifest.plugin_id)[0]
    authority = InvocationAuthority(
        principal="test",
        capability_ids=frozenset({CAPABILITY_ID}),
    )

    def unexpected_dispatch(*args, **kwargs):
        pytest.fail("mutated validator input reached the subprocess provider")

    monkeypatch.setattr(
        subprocess_runtime_module._SubprocessCapabilityProvider,
        "invoke",
        unexpected_dispatch,
    )
    try:
        with pytest.raises(PluginSchemaError, match="input validator must not mutate"):
            binding.invoke({"value": "valid-before-validator"}, authority=authority)
        assert host.status(manifest.plugin_id).state == "enabled"
    finally:
        host.disable(manifest.plugin_id)


def test_oversized_request_does_not_quarantine_healthy_worker(
    tmp_path: Path,
) -> None:
    bounded_schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {"value": {"type": "string", "maxLength": 4096}},
        "required": ["value"],
    }
    manifest = make_manifest(
        input_schema=bounded_schema,
        output_schema=bounded_schema,
    )
    host = PluginHost(workspace_root=tmp_path)
    host.register_reviewed_subprocess(
        manifest,
        make_spec(tmp_path, max_frame_bytes=1024),
        schemas={
            CAPABILITY_ID: CapabilitySchemas(bounded_schema, bounded_schema),
        },
    )
    binding = host.enable(manifest.plugin_id)[0]
    authority = InvocationAuthority(
        principal="test",
        capability_ids=frozenset({CAPABILITY_ID}),
    )

    with pytest.raises(PluginInvocationError, match="frame limit"):
        binding.invoke({"value": "x" * 2048}, authority=authority)

    assert host.status(manifest.plugin_id).state == "enabled"
    assert binding.invoke({"value": "small"}, authority=authority) == {
        "value": "small"
    }
    host.disable(manifest.plugin_id)


def test_subprocess_invocations_are_serialized_without_response_mixup(tmp_path: Path) -> None:
    host, manifest, binding, authority = register_and_enable(tmp_path)
    values = [f"value-{index}" for index in range(20)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(
            pool.map(
                lambda value: binding.invoke({"value": value}, authority=authority)["value"],
                values,
            )
        )
    assert results == values
    host.disable(manifest.plugin_id)


def test_disable_interrupts_a_hung_invocation_and_reaches_clean_state(
    tmp_path: Path,
) -> None:
    host, manifest, binding, authority = register_and_enable(
        tmp_path,
        "hang",
        invocation_timeout_s=30.0,
    )

    def invoke():
        with pytest.raises(PluginInvocationError):
            binding.invoke({"value": "blocked"}, authority=authority)

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(invoke)
        time.sleep(0.1)
        started = time.monotonic()
        assert host.disable(manifest.plugin_id) is True
        assert time.monotonic() - started < 3.0
        future.result(timeout=3.0)
    assert host.status(manifest.plugin_id).state == "installed"
    assert host.resolve(CAPABILITY_ID) == ()


def test_spec_rejects_ambient_loader_overrides_and_symlink_artifacts(
    tmp_path: Path,
) -> None:
    with pytest.raises(SubprocessPluginError, match="host-reserved"):
        make_spec(tmp_path, environment=(("PYTHONPATH", "attacker"),))
    link = tmp_path / "worker-link.py"
    try:
        link.symlink_to(WORKER)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(SubprocessPluginError, match="symlink"):
        ReviewedSubprocessSpec(
            launcher=Path(sys.executable),
            artifact=link,
            working_directory=tmp_path,
        )
