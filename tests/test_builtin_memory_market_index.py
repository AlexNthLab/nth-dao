"""Lifecycle, isolation, CAS, pagination, and concurrency tests for market.index."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from nth_dao.canonical_json import canonical_json
from nth_dao.plugins import (
    InvocationAuthority,
    MARKET_INDEX_CAPABILITY_ID,
    MarketIndexOperationError,
    PluginHost,
    PluginHostPolicy,
    PluginInvocationContext,
)
from nth_dao.plugins.builtin.memory_market_index import (
    MEMORY_MARKET_INDEX_PLUGIN_ID,
    MemoryMarketIndexProvider,
    memory_market_index_manifest,
    register_memory_market_index,
)
from nth_dao.plugins.market_index import market_index_entry_digest
from nth_dao.plugins.market_index import (
    MARKET_INDEX_MUTATION_REPLAY_WINDOW_MS,
    MARKET_INDEX_STALE_RETENTION_MS,
    market_index_wire_vectors,
)
from nth_dao.web import create_app


PUBLISHER_DID = "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd"


def _authority(principal: str = "workspace:alpha") -> InvocationAuthority:
    return InvocationAuthority(
        principal=principal,
        capability_ids=frozenset({MARKET_INDEX_CAPABILITY_ID}),
    )


def _context(principal: str = "workspace:alpha") -> PluginInvocationContext:
    return PluginInvocationContext(
        plugin_id=MEMORY_MARKET_INDEX_PLUGIN_ID,
        capability_id=MARKET_INDEX_CAPABILITY_ID,
        invocation_id="test-invocation",
        authority=_authority(principal),
        granted_permissions=frozenset(),
        workspace_root=None,
    )


def _entry(
    entry_id: str,
    *,
    title: str,
    published_at_ms: int,
    categories: list[str] | None = None,
    stale: bool = False,
    not_after_ms: int = 0,
) -> dict:
    return {
        "capabilities": ["code.review"],
        "categories": categories or ["tasks"],
        "entry_id": entry_id,
        "intents": ["request"],
        "last_verified_at_ms": published_at_ms,
        "not_after_ms": not_after_ms,
        "origin": "local",
        "projection_only": True,
        "published_at_ms": published_at_ms,
        "publisher_did": PUBLISHER_DID,
        "source_digest": "sha256:" + "a" * 64,
        "source_locator": f"nth://market/{entry_id}",
        "source_object_id": f"source-{entry_id}",
        "source_peer": "",
        "source_protocol": "org.nth-dao.market.task-announcement.v3",
        "stale": stale,
        "summary": "Signed discovery claim; reverify before action.",
        "title": title,
        "version": "1",
    }


def _upsert(entry: dict, expected: str = "") -> dict:
    text = canonical_json(entry).decode("utf-8")
    return {
        "operation": "upsert",
        "entry_id": entry["entry_id"],
        "entry_json": text,
        "entry_sha256": market_index_entry_digest(text),
        "expected_entry_sha256": expected,
    }


def _search(**overrides) -> dict:
    value = {
        "operation": "search",
        "q": "",
        "categories": [],
        "intents": [],
        "source_protocols": [],
        "include_stale": False,
        "cursor": "",
        "limit": 20,
    }
    value.update(overrides)
    return value


def _enabled_binding(tmp_path: Path):
    host = PluginHost(policy=PluginHostPolicy(), workspace_root=tmp_path)
    item = register_memory_market_index(host)
    host.authorize(item.plugin_id, set())
    binding = host.enable(item.plugin_id)[0]
    return host, item, binding


def test_memory_market_index_is_installed_but_disabled_by_default(tmp_path: Path) -> None:
    host = PluginHost(policy=PluginHostPolicy(), workspace_root=tmp_path)
    item = register_memory_market_index(host)
    assert host.status(item.plugin_id).state == "installed"
    assert host.status(item.plugin_id).risk_tier == 0
    assert host.resolve(MARKET_INDEX_CAPABILITY_ID) == ()


def test_web_registers_memory_market_index_without_enabling_it(tmp_path: Path) -> None:
    app = create_app(tmp_path)
    status = app.state.nth.plugin_host.status(MEMORY_MARKET_INDEX_PLUGIN_ID)
    assert status.state == "installed"
    assert status.desired_enabled is False
    assert app.state.nth.plugin_host.resolve(MARKET_INDEX_CAPABILITY_ID) == ()


def test_memory_market_index_manifest_is_non_authoritative() -> None:
    item = memory_market_index_manifest()
    assert item.kind == "market.index"
    assert item.permissions == ()
    assert item.provides[0].effects == ("none",)
    assert item.provides[0].security == "verified-input"


@pytest.mark.parametrize(
    "dependency",
    ("canonical_json.py", "did_key.py"),
)
def test_memory_market_index_artifact_digest_binds_wire_dependencies(
    monkeypatch: pytest.MonkeyPatch,
    dependency: str,
) -> None:
    import nth_dao.plugins.builtin.memory_market_index as index_module

    assert f"nth_dao/{dependency}" in index_module._REVIEWED_ARTIFACT_PATHS
    original_digest = index_module._reviewed_artifact_digest()
    original_read_bytes = Path.read_bytes

    def altered_read_bytes(path: Path) -> bytes:
        content = original_read_bytes(path)
        if path.name == dependency:
            return content + b"\n#audit-dependency-change\n"
        return content

    monkeypatch.setattr(Path, "read_bytes", altered_read_bytes)
    assert index_module._reviewed_artifact_digest() != original_digest


def test_memory_market_index_upsert_get_update_remove_round_trip(tmp_path: Path) -> None:
    host, _, binding = _enabled_binding(tmp_path)
    first_request = _upsert(
        _entry("task:alpha", title="Alpha review", published_at_ms=1_750_000_000_000)
    )
    first = binding.invoke(first_request, authority=_authority())
    assert first["changed"] is True
    assert first["revision"] == 1

    replay = binding.invoke(first_request, authority=_authority())
    assert replay["replayed"] is True
    assert replay["revision"] == 1

    fetched = binding.invoke(
        {"operation": "get", "entry_id": "task:alpha"}, authority=_authority()
    )
    assert fetched["entry_sha256"] == first_request["entry_sha256"]

    update_request = _upsert(
        _entry("task:alpha", title="Alpha fixed", published_at_ms=1_750_000_000_001),
        expected=first_request["entry_sha256"],
    )
    updated = binding.invoke(update_request, authority=_authority())
    assert updated["revision"] == 2
    old_retry = binding.invoke(first_request, authority=_authority())
    assert old_retry["replayed"] is True
    assert old_retry["revision"] == first["revision"]
    assert binding.invoke(
        {"operation": "get", "entry_id": "task:alpha"},
        authority=_authority(),
    )["entry_sha256"] == update_request["entry_sha256"]

    remove_request = {
        "operation": "remove",
        "entry_id": "task:alpha",
        "expected_entry_sha256": update_request["entry_sha256"],
    }
    removed = binding.invoke(remove_request, authority=_authority())
    assert removed["changed"] is removed["removed"] is True
    assert removed["revision"] == 3
    replayed_remove = binding.invoke(remove_request, authority=_authority())
    assert replayed_remove["replayed"] is replayed_remove["removed"] is True
    assert replayed_remove["revision"] == 3
    assert host.status(MEMORY_MARKET_INDEX_PLUGIN_ID).state == "enabled"


def test_memory_market_index_upsert_retry_is_generation_safe_after_aba() -> None:
    provider = MemoryMarketIndexProvider(
        clock=lambda: 1_750_000_100.0,
        cursor_secret=b"x" * 32,
    )
    original = _upsert(
        _entry("task:aba", title="A", published_at_ms=1_750_000_000_000)
    )
    replacement = _upsert(
        _entry("task:aba", title="B", published_at_ms=1_750_000_000_001),
        expected=original["entry_sha256"],
    )
    provider.invoke(original, _context())
    first_replacement = provider.invoke(replacement, _context())
    revert = _upsert(
        _entry("task:aba", title="A", published_at_ms=1_750_000_000_000),
        expected=replacement["entry_sha256"],
    )
    provider.invoke(revert, _context())

    replay = provider.invoke(replacement, _context())
    assert replay["changed"] is False
    assert replay["replayed"] is True
    assert replay["revision"] == first_replacement["revision"]
    assert replay["entry_sha256"] == first_replacement["entry_sha256"]
    current = provider.invoke(
        {"operation": "get", "entry_id": "task:aba"},
        _context(),
    )
    assert current["entry_sha256"] == original["entry_sha256"]


def test_memory_market_index_remove_retry_survives_same_id_recreation() -> None:
    provider = MemoryMarketIndexProvider(
        clock=lambda: 1_750_000_100.0,
        cursor_secret=b"x" * 32,
    )
    original = _upsert(
        _entry("task:recreated", title="A", published_at_ms=1_750_000_000_000)
    )
    replacement = _upsert(
        _entry("task:recreated", title="B", published_at_ms=1_750_000_000_001)
    )
    provider.invoke(original, _context())
    removal = {
        "operation": "remove",
        "entry_id": original["entry_id"],
        "expected_entry_sha256": original["entry_sha256"],
    }
    first_removal = provider.invoke(removal, _context())
    provider.invoke(replacement, _context())

    replay = provider.invoke(removal, _context())
    assert replay["changed"] is False
    assert replay["replayed"] is True
    assert replay["revision"] == first_removal["revision"]
    current = provider.invoke(
        {"operation": "get", "entry_id": original["entry_id"]},
        _context(),
    )
    assert current["entry_sha256"] == replacement["entry_sha256"]


def test_memory_market_index_replay_preserves_original_revision() -> None:
    provider = MemoryMarketIndexProvider(
        clock=lambda: 1_750_000_100.0,
        cursor_secret=b"x" * 32,
    )
    alpha = _upsert(
        _entry("task:a", title="A", published_at_ms=1_750_000_000_000)
    )
    beta = _upsert(
        _entry("task:b", title="B", published_at_ms=1_750_000_000_001)
    )
    first = provider.invoke(alpha, _context())
    provider.invoke(beta, _context())

    replay = provider.invoke(alpha, _context())
    assert replay["changed"] is False
    assert replay["replayed"] is True
    assert replay["revision"] == first["revision"]


def test_memory_market_index_isolates_principals(tmp_path: Path) -> None:
    host, _, binding = _enabled_binding(tmp_path)
    request = _upsert(
        _entry("task:secret", title="Private projection", published_at_ms=1_750_000_000_000)
    )
    binding.invoke(request, authority=_authority("workspace:alpha"))
    assert binding.invoke(
        {"operation": "get", "entry_id": "task:secret"},
        authority=_authority("workspace:beta"),
    )["found"] is False
    assert binding.invoke(
        _search(), authority=_authority("workspace:beta")
    )["items"] == []
    assert host.status(MEMORY_MARKET_INDEX_PLUGIN_ID).state == "enabled"


def test_memory_market_index_search_ranks_filters_and_pages(tmp_path: Path) -> None:
    host, _, binding = _enabled_binding(tmp_path)
    for entry in (
        _entry("task:a", title="Review", published_at_ms=1_750_000_000_001),
        _entry("task:b", title="Review beta", published_at_ms=1_750_000_000_003),
        _entry("task:c", title="Gamma review", published_at_ms=1_750_000_000_002),
        _entry(
            "service:d",
            title="Review service",
            published_at_ms=1_750_000_000_004,
            categories=["services"],
        ),
    ):
        binding.invoke(_upsert(entry), authority=_authority())

    first = binding.invoke(
        _search(q="review", categories=["tasks"], limit=2), authority=_authority()
    )
    assert [item["entry_id"] for item in first["items"]] == ["task:a", "task:b"]
    assert first["next_cursor"]
    second = binding.invoke(
        _search(q="review", categories=["tasks"], limit=2, cursor=first["next_cursor"]),
        authority=_authority(),
    )
    assert [item["entry_id"] for item in second["items"]] == ["task:c"]
    assert second["next_cursor"] == ""
    assert host.status(MEMORY_MARKET_INDEX_PLUGIN_ID).state == "enabled"


def test_memory_market_index_cursor_is_principal_bound_and_tamper_evident() -> None:
    provider = MemoryMarketIndexProvider(cursor_secret=b"x" * 32)
    for index in range(2):
        provider.invoke(
            _upsert(
                _entry(
                    f"task:{index}",
                    title=f"Task {index}",
                    published_at_ms=1_750_000_000_000 + index,
                )
            ),
            _context(),
        )
    cursor = provider.invoke(_search(limit=1), _context())["next_cursor"]
    with pytest.raises(MarketIndexOperationError) as cross_principal:
        provider.invoke(_search(limit=1, cursor=cursor), _context("workspace:beta"))
    assert cross_principal.value.code == "invalid-cursor"
    replacement = "A" if cursor[-1] != "A" else "B"
    with pytest.raises(MarketIndexOperationError) as tampered:
        provider.invoke(_search(limit=1, cursor=cursor[:-1] + replacement), _context())
    assert tampered.value.code == "invalid-cursor"


def test_memory_market_index_maximum_entry_id_still_produces_valid_cursor() -> None:
    provider = MemoryMarketIndexProvider(cursor_secret=b"x" * 32)
    long_id = "a" * 256
    for entry in (
        _entry(long_id, title="First", published_at_ms=1_750_000_000_001),
        _entry("task:second", title="Second", published_at_ms=1_750_000_000_000),
    ):
        provider.invoke(_upsert(entry), _context())
    first = provider.invoke(_search(limit=1), _context())
    assert first["next_cursor"]
    second = provider.invoke(_search(limit=1, cursor=first["next_cursor"]), _context())
    assert len(second["items"]) == 1


def test_memory_market_index_rejects_cursor_after_mutation() -> None:
    provider = MemoryMarketIndexProvider(cursor_secret=b"x" * 32)
    for index in range(2):
        provider.invoke(
            _upsert(
                _entry(
                    f"task:{index}",
                    title=f"Task {index}",
                    published_at_ms=1_750_000_000_000 + index,
                )
            ),
            _context(),
        )
    cursor = provider.invoke(_search(limit=1), _context())["next_cursor"]
    provider.invoke(
        _upsert(_entry("task:3", title="Task 3", published_at_ms=1_750_000_000_003)),
        _context(),
    )
    with pytest.raises(MarketIndexOperationError) as caught:
        provider.invoke(_search(limit=1, cursor=cursor), _context())
    assert caught.value.code == "stale-cursor"
    assert caught.value.retryable is True


def test_memory_market_index_cursor_cannot_change_query_semantics() -> None:
    provider = MemoryMarketIndexProvider(cursor_secret=b"x" * 32)
    for index in range(2):
        provider.invoke(
            _upsert(
                _entry(
                    f"task:{index}",
                    title=f"Review {index}",
                    published_at_ms=1_750_000_000_000 + index,
                )
            ),
            _context(),
        )
    cursor = provider.invoke(_search(q="review", limit=1), _context())["next_cursor"]
    with pytest.raises(MarketIndexOperationError) as caught:
        provider.invoke(_search(q="", limit=1, cursor=cursor), _context())
    assert caught.value.code == "invalid-cursor"


def test_memory_market_index_cursor_expires_without_mutating_index() -> None:
    now = [1_750_000_100.0]
    provider = MemoryMarketIndexProvider(
        clock=lambda: now[0],
        cursor_secret=b"x" * 32,
    )
    for index in range(2):
        provider.invoke(
            _upsert(
                _entry(
                    f"task:{index}",
                    title=f"Task {index}",
                    published_at_ms=1_750_000_000_000 + index,
                )
            ),
            _context(),
        )
    cursor = provider.invoke(_search(limit=1), _context())["next_cursor"]
    now[0] += 301
    with pytest.raises(MarketIndexOperationError) as caught:
        provider.invoke(_search(limit=1, cursor=cursor), _context())
    assert caught.value.code == "invalid-cursor"


def test_memory_market_index_filters_static_and_expired_stale_entries() -> None:
    provider = MemoryMarketIndexProvider(clock=lambda: 1_750_000_100.0)
    provider.invoke(
        _upsert(
            _entry(
                "task:static-stale",
                title="Stale",
                published_at_ms=1_750_000_000_000,
                stale=True,
            )
        ),
        _context(),
    )
    provider.invoke(
        _upsert(
            _entry(
                "task:expired",
                title="Expired",
                published_at_ms=1_750_000_000_000,
                not_after_ms=1_750_000_050_000,
            )
        ),
        _context(),
    )
    assert provider.invoke(_search(), _context())["items"] == []
    visible = provider.invoke(_search(include_stale=True), _context())
    assert {item["entry_id"] for item in visible["items"]} == {
        "task:expired",
        "task:static-stale",
    }


def test_memory_market_index_rejects_already_purged_entry_without_phantom_write() -> None:
    not_after_ms = 1_750_000_050_000
    payload = _upsert(
        _entry(
            "task:already-purged",
            title="Already purged",
            published_at_ms=1_750_000_000_000,
            not_after_ms=not_after_ms,
        )
    )
    rejected = MemoryMarketIndexProvider(
        clock=lambda: (not_after_ms + MARKET_INDEX_STALE_RETENTION_MS) / 1_000
    )

    with pytest.raises(MarketIndexOperationError) as caught:
        rejected.invoke(payload, _context())

    assert caught.value.code == "expired-entry"
    assert rejected.invoke(
        {"operation": "get", "entry_id": payload["entry_id"]},
        _context(),
    )["found"] is False
    assert rejected._principal_revisions == {}
    assert rejected._mutation_receipts == {}

    accepted = MemoryMarketIndexProvider(
        clock=lambda: (
            not_after_ms + MARKET_INDEX_STALE_RETENTION_MS - 1
        )
        / 1_000
    )
    assert accepted.invoke(payload, _context())["changed"] is True


def test_memory_market_index_expired_retention_reclaims_quota(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nth_dao.plugins.builtin.memory_market_index as index_module

    monkeypatch.setattr(index_module, "MEMORY_MARKET_INDEX_MAX_ENTRIES", 1)
    monkeypatch.setattr(
        index_module,
        "MEMORY_MARKET_INDEX_MAX_ENTRIES_PER_PRINCIPAL",
        1,
    )
    now = [1_750_000_100.0]
    provider = MemoryMarketIndexProvider(clock=lambda: now[0])
    expired = _upsert(
        _entry(
            "task:expired",
            title="Expired",
            published_at_ms=1_750_000_000_000,
            not_after_ms=1_750_000_050_000,
        )
    )
    replacement = _upsert(
        _entry(
            "task:replacement",
            title="Replacement",
            published_at_ms=1_750_000_100_000,
        )
    )
    provider.invoke(expired, _context())

    with pytest.raises(MarketIndexOperationError) as retained:
        provider.invoke(replacement, _context())
    assert retained.value.code == "quota-exceeded"
    assert provider.invoke(_search(include_stale=True), _context())["found"] is True

    now[0] = (
        1_750_000_050_000 + MARKET_INDEX_STALE_RETENTION_MS + 1
    ) / 1_000
    created = provider.invoke(replacement, _context())

    assert created["changed"] is True
    assert provider.invoke(
        {"operation": "get", "entry_id": expired["entry_id"]},
        _context(),
    )["found"] is False
    assert provider._principal_counts["workspace:alpha"] == 1
    assert provider._total_bytes == provider._principal_bytes["workspace:alpha"]


def test_memory_market_index_expiry_gc_invalidates_cursor_but_keeps_static_stale() -> None:
    now = [1_750_000_100.0]
    provider = MemoryMarketIndexProvider(
        clock=lambda: now[0],
        cursor_secret=b"x" * 32,
    )
    for entry in (
        _entry(
            "task:expired-a",
            title="Expired A",
            published_at_ms=1_750_000_000_002,
            not_after_ms=1_750_000_050_000,
        ),
        _entry(
            "task:expired-b",
            title="Expired B",
            published_at_ms=1_750_000_000_001,
            not_after_ms=1_750_000_050_000,
        ),
        _entry(
            "task:static-stale",
            title="Static stale",
            published_at_ms=1_750_000_000_000,
            stale=True,
        ),
    ):
        provider.invoke(_upsert(entry), _context())
    now[0] = 1_750_000_349.0
    first = provider.invoke(_search(include_stale=True, limit=1), _context())
    assert first["next_cursor"]

    now[0] = 1_750_000_351.0
    with pytest.raises(MarketIndexOperationError) as changed:
        provider.invoke(
            _search(include_stale=True, limit=1, cursor=first["next_cursor"]),
            _context(),
        )
    assert changed.value.code == "stale-cursor"
    remaining = provider.invoke(_search(include_stale=True), _context())
    assert [item["entry_id"] for item in remaining["items"]] == [
        "task:static-stale"
    ]


def test_memory_market_index_concurrent_cas_allows_one_replacement() -> None:
    provider = MemoryMarketIndexProvider()
    original = _upsert(
        _entry("task:race", title="Original", published_at_ms=1_750_000_000_000)
    )
    provider.invoke(original, _context())
    requests = [
        _upsert(
            _entry(
                "task:race",
                title=f"Replacement {index}",
                published_at_ms=1_750_000_000_001 + index,
            ),
            expected=original["entry_sha256"],
        )
        for index in range(8)
    ]

    def attempt(request: dict) -> str:
        try:
            provider.invoke(request, _context())
            return "updated"
        except MarketIndexOperationError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(attempt, requests))
    assert outcomes.count("updated") == 1
    assert outcomes.count("conflict") == 7


def test_memory_market_index_deactivation_revokes_provider() -> None:
    provider = MemoryMarketIndexProvider()
    provider.deactivate()
    with pytest.raises(MarketIndexOperationError) as caught:
        provider.invoke({"operation": "probe"}, _context())
    assert caught.value.code == "inactive"


def test_memory_market_index_never_evicts_live_mutation_receipts_for_capacity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nth_dao.plugins.builtin.memory_market_index as index_module

    monkeypatch.setattr(index_module, "MEMORY_MARKET_INDEX_MAX_MUTATION_RECEIPTS", 1)
    now = [1_750_000_100.0]
    provider = MemoryMarketIndexProvider(clock=lambda: now[0])
    alpha = _upsert(
        _entry(
            "task:a",
            title="Alpha",
            published_at_ms=1_750_000_000_000,
        )
    )
    beta = _upsert(
        _entry(
            "task:b",
            title="Beta",
            published_at_ms=1_750_000_000_000,
        )
    )
    provider.invoke(alpha, _context("workspace:alpha"))
    now[0] += MARKET_INDEX_MUTATION_REPLAY_WINDOW_MS / 1_000 + 1
    provider.invoke(beta, _context("workspace:beta"))
    now[0] += MARKET_INDEX_MUTATION_REPLAY_WINDOW_MS / 1_000 + 1
    provider.invoke({"operation": "probe"}, _context("workspace:beta"))
    alpha_remove = {
        "operation": "remove",
        "entry_id": alpha["entry_id"],
        "expected_entry_sha256": alpha["entry_sha256"],
    }
    beta_remove = {
        "operation": "remove",
        "entry_id": beta["entry_id"],
        "expected_entry_sha256": beta["entry_sha256"],
    }
    provider.invoke(alpha_remove, _context("workspace:alpha"))

    with pytest.raises(MarketIndexOperationError) as full:
        provider.invoke(beta_remove, _context("workspace:beta"))
    assert full.value.code == "quota-exceeded"
    assert provider.invoke(
        alpha_remove,
        _context("workspace:alpha"),
    )["replayed"] is True
    assert provider.invoke(
        {"operation": "get", "entry_id": beta["entry_id"]},
        _context("workspace:beta"),
    )["found"] is True

    now[0] += MARKET_INDEX_MUTATION_REPLAY_WINDOW_MS / 1_000 + 1
    provider.invoke(beta_remove, _context("workspace:beta"))
    assert "workspace:alpha" not in provider._principal_revisions
    assert "workspace:alpha" not in provider._principal_counts
    assert "workspace:alpha" not in provider._principal_bytes
    assert "workspace:alpha" not in provider._principal_mutation_receipt_counts


def test_memory_market_index_executes_portable_state_vectors() -> None:
    for case in market_index_wire_vectors()["state_cases"]:
        now_ms = [0]
        provider = MemoryMarketIndexProvider(clock=lambda: now_ms[0] / 1_000)
        for step in case["steps"]:
            now_ms[0] = step["at_ms"]
            if "expect_error" in step:
                with pytest.raises(MarketIndexOperationError) as caught:
                    provider.invoke(step["input"], _context())
                assert caught.value.code == step["expect_error"], case["name"]
                continue
            response = provider.invoke(step["input"], _context())
            for field, expected in step["expect"].items():
                assert response[field] == expected, (case["name"], field)
