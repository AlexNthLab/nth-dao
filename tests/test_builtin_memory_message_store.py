"""Lifecycle, isolation, retention, and concurrency tests for message.store."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import threading

import pytest

from nth_dao.canonical_json import canonical_json
from nth_dao.plugins import (
    InvocationAuthority,
    MessageStoreOperationError,
    PluginHost,
    PluginHostPolicy,
    PluginInvocationContext,
    PluginInvocationError,
    PluginSchemaError,
)
from nth_dao.plugins.builtin.memory_message_store import (
    MEMORY_MESSAGE_STORE_PLUGIN_ID,
    MemoryMessageStoreProvider,
    memory_message_store_manifest,
    register_memory_message_store,
)
from nth_dao.plugins.message_store import (
    MESSAGE_STORE_CAPABILITY_ID,
    MESSAGE_STORE_MAX_DOCUMENT_BYTES,
    message_store_message_digest,
)
from nth_dao.web import create_app


VECTOR_PATH = (
    Path(__file__).parents[1]
    / "nth_dao"
    / "plugins"
    / "vectors"
    / "message-store-wire-cases-v1.json"
)


def _authority(principal: str = "group:alpha") -> InvocationAuthority:
    return InvocationAuthority(
        principal=principal,
        capability_ids=frozenset({MESSAGE_STORE_CAPABILITY_ID}),
    )


def _enabled_binding(tmp_path: Path):
    host = PluginHost(policy=PluginHostPolicy(), workspace_root=tmp_path)
    item = register_memory_message_store(host)
    host.authorize(item.plugin_id, set())
    binding = host.enable(item.plugin_id)[0]
    return host, item, binding


def _context(principal: str = "group:alpha") -> PluginInvocationContext:
    return PluginInvocationContext(
        plugin_id=MEMORY_MESSAGE_STORE_PLUGIN_ID,
        capability_id=MESSAGE_STORE_CAPABILITY_ID,
        invocation_id="test-invocation",
        authority=_authority(principal),
        granted_permissions=frozenset(),
        workspace_root=None,
    )


def _put(
    *,
    message_id: str = "message-1",
    body: str = "hello",
    retention_mode: str = "session",
    delivery_mode: str = "read-many",
    expires_at_ms: int = 0,
) -> dict:
    message_json = canonical_json({"body": body, "kind": "chat"}).decode("utf-8")
    return {
        "operation": "put",
        "namespace": "group:alpha/channel:general",
        "message_id": message_id,
        "message_json": message_json,
        "message_sha256": message_store_message_digest(message_json),
        "retention_mode": retention_mode,
        "delivery_mode": delivery_mode,
        "expires_at_ms": expires_at_ms,
    }


def _lookup(
    operation: str,
    message_id: str = "message-1",
    *,
    expected: dict | None = None,
) -> dict:
    result = {
        "operation": operation,
        "namespace": "group:alpha/channel:general",
        "message_id": message_id,
    }
    if operation in {"consume", "delete"}:
        if expected is None:
            raise ValueError("destructive lookup requires an expected record")
        result["expected_message_sha256"] = expected["message_sha256"]
        result["expected_sequence"] = expected["sequence"]
    return result


def test_memory_store_is_installed_but_disabled_by_default(tmp_path: Path) -> None:
    host = PluginHost(policy=PluginHostPolicy(), workspace_root=tmp_path)
    item = register_memory_message_store(host)
    status = host.status(item.plugin_id)
    assert status.state == "installed"
    assert status.risk_tier == 0
    assert status.declared_permissions == ()
    assert host.resolve(MESSAGE_STORE_CAPABILITY_ID) == ()


def test_web_registers_memory_store_without_enabling_it(tmp_path: Path) -> None:
    app = create_app(tmp_path)
    status = app.state.nth.plugin_host.status(MEMORY_MESSAGE_STORE_PLUGIN_ID)
    assert status.state == "installed"
    assert status.desired_enabled is False
    assert app.state.nth.plugin_host.resolve(MESSAGE_STORE_CAPABILITY_ID) == ()


def test_memory_store_manifest_is_exact_and_self_contained() -> None:
    item = memory_message_store_manifest()
    assert item.plugin_id == MEMORY_MESSAGE_STORE_PLUGIN_ID
    assert item.kind == "message.store"
    assert item.permissions == ()
    assert item.provides[0].capability_id == MESSAGE_STORE_CAPABILITY_ID
    assert item.provides[0].effects == ("none",)


def test_memory_store_put_get_list_delete_round_trip(tmp_path: Path) -> None:
    host, _, binding = _enabled_binding(tmp_path)
    put = binding.invoke(_put(), authority=_authority())
    assert put["found"] is True
    assert put["replayed"] is False
    assert put["message_json"] == ""

    replay = binding.invoke(_put(), authority=_authority())
    assert replay["replayed"] is True
    assert replay["sequence"] == put["sequence"]

    listed = binding.invoke(
        {
            "operation": "list",
            "namespace": "group:alpha/channel:general",
            "after_sequence": 0,
            "limit": 10,
        },
        authority=_authority(),
    )
    assert listed["found"] is True
    assert [item["message_id"] for item in listed["items"]] == ["message-1"]
    assert "message_json" not in listed["items"][0]

    fetched = binding.invoke(_lookup("get"), authority=_authority())
    assert fetched["message_json"] == _put()["message_json"]
    assert fetched["deleted"] is False

    deleted = binding.invoke(_lookup("delete", expected=put), authority=_authority())
    assert deleted["found"] is deleted["deleted"] is True
    assert binding.invoke(_lookup("get"), authority=_authority())["found"] is False
    assert host.status(MEMORY_MESSAGE_STORE_PLUGIN_ID).state == "enabled"


def test_memory_store_message_ids_are_immutable(tmp_path: Path) -> None:
    host, _, binding = _enabled_binding(tmp_path)
    binding.invoke(_put(body="first"), authority=_authority())
    with pytest.raises(MessageStoreOperationError) as caught:
        binding.invoke(_put(body="replacement"), authority=_authority())
    assert caught.value.code == "conflict"
    assert caught.value.retryable is False
    assert (
        binding.invoke(_lookup("get"), authority=_authority())["message_json"]
        == _put(body="first")["message_json"]
    )
    assert host.status(MEMORY_MESSAGE_STORE_PLUGIN_ID).state == "enabled"


@pytest.mark.parametrize("delivery_mode", ["read-many", "consume-on-read"])
def test_memory_store_rejects_records_that_cannot_fit_retrieval_envelope(
    delivery_mode: str,
) -> None:
    provider = MemoryMessageStoreProvider()
    payload = _put(body="\\" * 262_000, delivery_mode=delivery_mode)
    assert len(canonical_json(payload)) <= MESSAGE_STORE_MAX_DOCUMENT_BYTES

    with pytest.raises(MessageStoreOperationError) as caught:
        provider.invoke(payload, _context())

    assert caught.value.code == "limit-exceeded"
    assert provider.invoke(_lookup("get"), _context())["found"] is False
    assert provider.invoke(_put(body="small"), _context())["sequence"] == 1


def test_memory_store_stale_delete_cannot_remove_replacement(tmp_path: Path) -> None:
    host, _, binding = _enabled_binding(tmp_path)
    original = binding.invoke(_put(body="original"), authority=_authority())
    binding.invoke(_lookup("delete", expected=original), authority=_authority())
    replacement = binding.invoke(_put(body="replacement"), authority=_authority())

    with pytest.raises(MessageStoreOperationError) as caught:
        binding.invoke(_lookup("delete", expected=original), authority=_authority())
    assert caught.value.code == "stale-generation"
    assert caught.value.retryable is False

    current = binding.invoke(_lookup("get"), authority=_authority())
    assert current["found"] is True
    assert current["sequence"] == replacement["sequence"]
    assert current["message_json"] == _put(body="replacement")["message_json"]
    assert host.status(MEMORY_MESSAGE_STORE_PLUGIN_ID).state == "enabled"


def test_memory_store_tombstone_identifies_already_applied_delete(tmp_path: Path) -> None:
    host, _, binding = _enabled_binding(tmp_path)
    stored = binding.invoke(_put(), authority=_authority())
    request = _lookup("delete", expected=stored)
    binding.invoke(request, authority=_authority())
    with pytest.raises(MessageStoreOperationError) as caught:
        binding.invoke(request, authority=_authority())
    assert caught.value.code == "already-applied"
    assert host.status(MEMORY_MESSAGE_STORE_PLUGIN_ID).state == "enabled"


def test_memory_store_executes_checked_in_state_transition_vectors() -> None:
    vectors = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    for scenario in vectors["state_transition_vectors"]:
        provider = MemoryMessageStoreProvider(clock=lambda: 1_750_000_000.0)
        for step in scenario["steps"]:
            expected_error = step.get("expected_error")
            if expected_error:
                assert expected_error in vectors["error_model"]
                with pytest.raises(MessageStoreOperationError) as caught:
                    provider.invoke(step["input"], _context(scenario["principal"]))
                assert caught.value.code == expected_error
                continue
            response = provider.invoke(step["input"], _context(scenario["principal"]))
            assert {
                key: response[key] for key in step["expected_fields"]
            } == step["expected_fields"]


def test_memory_store_does_not_mutate_sequence_before_output_is_validated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nth_dao.plugins.builtin.memory_message_store as store_module

    provider = MemoryMessageStoreProvider()
    original = store_module.MEMORY_MESSAGE_STORE_MAX_TTL_SECONDS
    monkeypatch.setattr(store_module, "MEMORY_MESSAGE_STORE_MAX_TTL_SECONDS", 0)
    with pytest.raises(PluginSchemaError, match="max_ttl_seconds"):
        provider.invoke(_put(), _context())
    monkeypatch.setattr(store_module, "MEMORY_MESSAGE_STORE_MAX_TTL_SECONDS", original)
    assert provider.invoke(_put(), _context())["sequence"] == 1


def test_memory_store_partitions_records_by_host_selected_principal(
    tmp_path: Path,
) -> None:
    host, _, binding = _enabled_binding(tmp_path)
    binding.invoke(_put(), authority=_authority("group:alpha"))
    assert binding.invoke(
        _lookup("get"), authority=_authority("group:beta")
    )["found"] is False
    binding.invoke(_put(body="beta"), authority=_authority("group:beta"))
    assert binding.invoke(
        _lookup("get"), authority=_authority("group:alpha")
    )["message_json"] == _put()["message_json"]
    assert binding.invoke(
        _lookup("get"), authority=_authority("group:beta")
    )["message_json"] == _put(body="beta")["message_json"]
    assert host.status(MEMORY_MESSAGE_STORE_PLUGIN_ID).state == "enabled"


def test_memory_store_ttl_expires_and_releases_identifier() -> None:
    now = [1_750_000_000.0]
    provider = MemoryMessageStoreProvider(clock=lambda: now[0])
    payload = _put(
        retention_mode="ttl",
        expires_at_ms=int(now[0] * 1_000) + 10_000,
    )
    first = provider.invoke(payload, _context())
    now[0] += 11
    assert provider.invoke(_lookup("get"), _context())["found"] is False
    replacement = provider.invoke(
        _put(body="after-expiry", retention_mode="session"),
        _context(),
    )
    assert replacement["sequence"] > first["sequence"]


def test_memory_store_rejects_expired_and_excessive_ttl() -> None:
    now = 1_750_000_000.0
    provider = MemoryMessageStoreProvider(clock=lambda: now)
    with pytest.raises(MessageStoreOperationError) as expired:
        provider.invoke(
            _put(retention_mode="ttl", expires_at_ms=int(now * 1_000)),
            _context(),
        )
    assert expired.value.code == "expired"
    with pytest.raises(MessageStoreOperationError) as excessive:
        provider.invoke(
            _put(
                retention_mode="ttl",
                expires_at_ms=int(now * 1_000) + 2_592_001_000,
            ),
            _context(),
        )
    assert excessive.value.code == "limit-exceeded"


def test_memory_store_clock_is_finite_and_never_moves_backward() -> None:
    now = [1_750_000_000.0]
    provider = MemoryMessageStoreProvider(clock=lambda: now[0])
    first = provider.invoke(_put(), _context())
    now[0] -= 10
    second = provider.invoke(_put(message_id="message-2"), _context())
    assert second["created_at_ms"] == first["created_at_ms"]
    now[0] = float("nan")
    with pytest.raises(RuntimeError, match="invalid timestamp"):
        provider.invoke({"operation": "probe"}, _context())
    now[0] = 1e308
    with pytest.raises(RuntimeError, match="invalid timestamp"):
        provider.invoke({"operation": "probe"}, _context())


def test_memory_store_direct_call_enforces_authority_scope() -> None:
    provider = MemoryMessageStoreProvider()
    context = PluginInvocationContext(
        plugin_id=MEMORY_MESSAGE_STORE_PLUGIN_ID,
        capability_id=MESSAGE_STORE_CAPABILITY_ID,
        invocation_id="test-invocation",
        authority=InvocationAuthority(
            principal="group:alpha",
            capability_ids=frozenset({"org.nth-dao.agent.session"}),
        ),
        granted_permissions=frozenset(),
        workspace_root=None,
    )
    with pytest.raises(PluginInvocationError, match="lacks capability scope"):
        provider.invoke({"operation": "probe"}, context)


def test_memory_store_consume_is_atomic_under_concurrency(tmp_path: Path) -> None:
    host, _, binding = _enabled_binding(tmp_path)
    stored = binding.invoke(
        _put(delivery_mode="consume-on-read"),
        authority=_authority(),
    )
    barrier = threading.Barrier(16)

    def consume() -> tuple[str, dict | str]:
        barrier.wait()
        try:
            return (
                "ok",
                binding.invoke(
                    _lookup("consume", expected=stored),
                    authority=_authority(),
                ),
            )
        except MessageStoreOperationError as exc:
            return "error", exc.code

    with ThreadPoolExecutor(max_workers=16) as executor:
        results = list(executor.map(lambda _: consume(), range(16)))
    consumed = [item for status, item in results if status == "ok"]
    errors = [item for status, item in results if status == "error"]
    assert len(consumed) == 1
    assert consumed[0]["deleted"] is True
    assert consumed[0]["message_json"] == _put()["message_json"]
    assert errors == ["already-applied"] * 15
    assert host.status(MEMORY_MESSAGE_STORE_PLUGIN_ID).state == "enabled"


def test_memory_store_concurrent_identical_puts_are_idempotent(tmp_path: Path) -> None:
    host, _, binding = _enabled_binding(tmp_path)
    barrier = threading.Barrier(16)

    def put() -> dict:
        barrier.wait()
        return binding.invoke(_put(), authority=_authority())

    with ThreadPoolExecutor(max_workers=16) as executor:
        results = list(executor.map(lambda _: put(), range(16)))
    assert sum(not item["replayed"] for item in results) == 1
    assert len({item["sequence"] for item in results}) == 1
    assert host.status(MEMORY_MESSAGE_STORE_PLUGIN_ID).state == "enabled"


def test_memory_store_read_validation_does_not_hold_global_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = MemoryMessageStoreProvider()
    provider.invoke(_put(), _context("group:alpha"))
    validation_started = threading.Event()
    release_validation = threading.Event()
    original_checked = provider._checked

    def delayed_checked(response: dict) -> dict:
        if response["operation"] == "get":
            validation_started.set()
            assert release_validation.wait(timeout=2)
        return original_checked(response)

    monkeypatch.setattr(provider, "_checked", delayed_checked)
    with ThreadPoolExecutor(max_workers=2) as executor:
        read = executor.submit(
            provider.invoke,
            _lookup("get"),
            _context("group:alpha"),
        )
        assert validation_started.wait(timeout=1)
        write = executor.submit(
            provider.invoke,
            _put(message_id="message-2"),
            _context("group:beta"),
        )
        try:
            assert write.result(timeout=1)["found"] is True
        finally:
            release_validation.set()
        assert read.result(timeout=1)["found"] is True


def test_memory_store_enforces_principal_record_quota(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nth_dao.plugins.builtin.memory_message_store as store_module

    monkeypatch.setattr(store_module, "MEMORY_MESSAGE_STORE_MAX_RECORDS_PER_PRINCIPAL", 2)
    provider = MemoryMessageStoreProvider()
    provider.invoke(_put(message_id="message-1"), _context())
    provider.invoke(_put(message_id="message-2"), _context())
    with pytest.raises(MessageStoreOperationError) as caught:
        provider.invoke(_put(message_id="message-3"), _context())
    assert caught.value.code == "quota-exceeded"
    assert caught.value.retryable is True
    provider.invoke(_put(message_id="message-1"), _context("group:beta"))


def test_memory_store_list_cursor_is_stable_across_deletion(tmp_path: Path) -> None:
    host, _, binding = _enabled_binding(tmp_path)
    stored = {}
    for index in range(1, 4):
        stored[index] = binding.invoke(
            _put(message_id=f"message-{index}", body=str(index)),
            authority=_authority(),
        )
    first = binding.invoke(
        {
            "operation": "list",
            "namespace": "group:alpha/channel:general",
            "after_sequence": 0,
            "limit": 2,
        },
        authority=_authority(),
    )
    binding.invoke(
        _lookup("delete", "message-1", expected=stored[1]),
        authority=_authority(),
    )
    second = binding.invoke(
        {
            "operation": "list",
            "namespace": "group:alpha/channel:general",
            "after_sequence": first["next_sequence"],
            "limit": 2,
        },
        authority=_authority(),
    )
    assert [item["message_id"] for item in first["items"]] == ["message-1", "message-2"]
    assert [item["message_id"] for item in second["items"]] == ["message-3"]
    assert host.status(MEMORY_MESSAGE_STORE_PLUGIN_ID).state == "enabled"


def test_memory_store_delivery_modes_cannot_be_bypassed(tmp_path: Path) -> None:
    host, _, binding = _enabled_binding(tmp_path)
    one_shot = binding.invoke(
        _put(delivery_mode="consume-on-read"), authority=_authority()
    )
    with pytest.raises(MessageStoreOperationError) as get_error:
        binding.invoke(_lookup("get"), authority=_authority())
    assert get_error.value.code == "unsupported-delivery-mode"
    binding.invoke(_lookup("delete", expected=one_shot), authority=_authority())
    repeatable = binding.invoke(
        _put(delivery_mode="read-many"), authority=_authority()
    )
    with pytest.raises(MessageStoreOperationError) as consume_error:
        binding.invoke(
            _lookup("consume", expected=repeatable), authority=_authority()
        )
    assert consume_error.value.code == "unsupported-delivery-mode"
    assert host.status(MEMORY_MESSAGE_STORE_PLUGIN_ID).state == "enabled"


def test_memory_store_disable_invalidates_binding_and_clears_provider(tmp_path: Path) -> None:
    host, item, binding = _enabled_binding(tmp_path)
    binding.invoke(_put(), authority=_authority())
    host.disable(item.plugin_id)
    with pytest.raises(PluginInvocationError, match="disabled or stale"):
        binding.invoke(_lookup("get"), authority=_authority())
