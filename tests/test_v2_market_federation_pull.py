"""FED-2:任务市场联邦拉取侧 + market/open 合并(跨节点发现)。

不起真 socket:用可注入的 http_get 把"对端 hub"路由到第二个 TestClient
节点。验证 PC-A 看不到 PC-B 任务的根因被解决 —— B 发任务,A 经联邦拉到。
"""
from __future__ import annotations

from pathlib import Path
import time
from urllib.parse import urlsplit

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from nth_dao.identity import AgentIdentity, crypto_available
from nth_dao.commerce.listing import (
    ListingStore, SignedListing, listing_digest, sign_listing,
)
from nth_dao.commerce.listing_announcement import (
    listing_offer_uri, publish_listing_announcement,
)
from nth_dao.b64u import b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.market.announcement import sign_announcement, verify_announcement
from nth_dao.market.feed import MarketFeed
from nth_dao.market.federation import FeedDigest
from nth_dao.web import create_app
from nth_dao.web.market_federation_poll import (
    FederationCache, FederationCacheCapacityError, FederationCycleReport,
    _verify_pulled_listing, federate_once, pull_from_peer,
)
from nth_dao.util.io import atomic_write_json

pytestmark = pytest.mark.skipif(
    not crypto_available(), reason="PyNaCl needed (digest/announcement signing)"
)


def _http_get_via(client: TestClient):
    """把 http_get(url) 路由到一个 TestClient(模拟对端 hub)。"""
    def get(url: str):
        u = urlsplit(url)
        full = u.path + (f"?{u.query}" if u.query else "")
        return client.get(full).json()
    return get


def _node_did(client: TestClient) -> str:
    return client.app.state.nth.node_identity.as_did()


def test_pull_from_peer_returns_verified(tmp_path: Path) -> None:
    b = TestClient(create_app(tmp_path / "b", require_console_auth=False))
    an = b.post(
        "/api/v2/market/announce",
        json={"title": "B task", "capability_set": ["code_review"], "reward_minor": 7},
    )
    aid = an.json()["announcement_id"]

    anns = pull_from_peer(
        "https://peer-b.example",
        _http_get_via(b),
        expected_source_did=_node_did(b),
    )
    got = [a for a in anns if a.announcement_id == aid]
    assert got, "联邦拉取应拿到 B 的公告"
    assert verify_announcement(got[0])[0]  # 全文 publisher_sig 验过


def test_pull_from_peer_uses_verified_incremental_cursor(tmp_path: Path) -> None:
    peer = TestClient(create_app(tmp_path / "peer", require_console_auth=False))
    first_id = peer.post(
        "/api/v2/market/announce",
        json={"title": "first", "capability_set": ["review"]},
    ).json()["announcement_id"]
    first_cursor: dict[str, int] = {}
    first = pull_from_peer(
        "https://peer.example",
        _http_get_via(peer),
        expected_source_did=_node_did(peer),
        _cursor_out=first_cursor,
    )
    second_id = peer.post(
        "/api/v2/market/announce",
        json={"title": "second", "capability_set": ["review"]},
    ).json()["announcement_id"]
    second_cursor: dict[str, int] = {}
    delta = pull_from_peer(
        "https://peer.example",
        _http_get_via(peer),
        expected_source_did=_node_did(peer),
        _since_seq=first_cursor["high_seq"],
        _cursor_out=second_cursor,
    )

    assert [item.announcement_id for item in first] == [first_id]
    assert [item.announcement_id for item in delta] == [second_id]
    assert second_cursor["high_seq"] > first_cursor["high_seq"]


def test_pull_from_peer_resolves_and_binds_full_commerce_listing(
    tmp_path: Path,
) -> None:
    root = tmp_path / "b"
    app = create_app(root, require_console_auth=False)
    b = TestClient(app)
    seller = app.state.nth.node_identity
    listing = sign_listing(
        seller,
        SignedListing(
            listing_id="remote-review",
            listing_type="service",
            seller_did=seller.as_did(),
            title="Remote review",
            description="One review",
            price_value="2",
            price_currency="USDC",
            settlement_methods=["x402:usdc"],
            published_at_ms=1_000,
            not_after_ms=9_999_999_999_999,
        ),
    )
    ann = publish_listing_announcement(
        ListingStore(root),
        MarketFeed(root),
        seller=seller,
        listing=listing,
        capability_set=["code_review"],
    )

    pulled = pull_from_peer(
        "https://peer-b.example",
        _http_get_via(b),
        expected_source_did=seller.as_did(),
    )

    assert [item.announcement_id for item in pulled] == [ann.announcement_id]


def test_listing_cache_rebinds_every_signed_announcement(tmp_path: Path) -> None:
    seller = AgentIdentity.generate(label="seller")
    listing = sign_listing(
        seller,
        SignedListing(
            listing_id="cached-offer",
            listing_type="service",
            seller_did=seller.as_did(),
            title="Review",
            description="One review",
            price_value="2",
            price_currency="USDC",
            settlement_methods=["x402:usdc"],
            published_at_ms=1_000,
            not_after_ms=9_999_999_999_999,
        ),
    )
    digest = listing_digest(listing)

    def commerce_announcement(price_minor: int):
        return sign_announcement(
            publisher=seller,
            title=listing.title,
            description=listing.description,
            kind="nth-task-announcement-v3",
            listing_type=listing.listing_type,
            offer_digest=digest,
            offer_uri=listing_offer_uri(digest),
            reward_minor=price_minor,
            reward_asset="USDC",
            price_minor=price_minor,
            price_asset="USDC",
            published_at_ms=listing.published_at_ms,
            not_after=listing.not_after_ms,
        )

    valid = commerce_announcement(2_000_000)
    mismatched = commerce_announcement(3_000_000)
    cache = {}
    fetches = 0

    def fetch_listing(_url: str):
        nonlocal fetches
        fetches += 1
        return listing.to_dict()

    assert _verify_pulled_listing(
        "https://seller.example", valid, fetch_listing, cache,
    )
    assert not _verify_pulled_listing(
        "https://seller.example", mismatched, fetch_listing, cache,
    )
    assert fetches == 1


def test_market_open_merges_federated_from_peer(tmp_path: Path) -> None:
    # 节点 B 发任务。
    b = TestClient(create_app(tmp_path / "b", require_console_auth=False))
    aid = b.post(
        "/api/v2/market/announce",
        json={"title": "cross-node task", "capability_set": []},
    ).json()["announcement_id"]

    # 节点 A —— 自己一条活都没发。
    a_app = create_app(tmp_path / "a", require_console_auth=False)
    a = TestClient(a_app)
    assert a.get("/api/v2/market/open").json() == []  # 联邦前:空

    # 经 B 的 client 拉一轮,灌进 A 的联邦缓存(模拟 poller 一次循环)。
    entries = federate_once(
        ["https://peer-b.example"],
        _http_get_via(b),
        verify_seed_peer=lambda _url: _node_did(b),
    )
    assert any(
        entry["ann"].announcement_id == aid for entry in entries.values()
    )
    cache = FederationCache()
    cache.replace_all(entries)
    a_app.state.market_fed_cache = cache

    # 关键:A 现在能在 market/open 里看到 B 的任务,标记 federated + source。
    open_list = a.get("/api/v2/market/open").json()
    fed = [x for x in open_list if x.get("announcement_id") == aid]
    assert fed, "PC-A 应能看到 PC-B 发布的任务(联邦发现)"
    assert fed[0]["federated"] is True
    assert fed[0]["source_peer"] == "https://peer-b.example"
    assert fed[0]["claimed"] is False


def test_market_open_merges_federated_product_listing_from_peer(
    tmp_path: Path,
) -> None:
    b = TestClient(create_app(tmp_path / "b", require_console_auth=False))
    legacy = sign_announcement(
        publisher=b.app.state.nth.node_identity,
        title="remote DAO service pack",
        input_schema={"__nth_listing_type": "service"},
        capability_set=["debug"],
        reward_minor=500,
    )
    MarketFeed(tmp_path / "b", spine=b.app.state.nth.spine).publish(legacy)
    aid = legacy.announcement_id

    a_app = create_app(tmp_path / "a", require_console_auth=False)
    a = TestClient(a_app)
    entries = federate_once(
        ["https://peer-b.example"],
        _http_get_via(b),
        verify_seed_peer=lambda _url: _node_did(b),
    )
    cache = FederationCache()
    cache.replace_all(entries)
    a_app.state.market_fed_cache = cache

    rows = a.get("/api/v2/market/open", params={"listing_type": "service"}).json()
    hit = next((x for x in rows if x.get("announcement_id") == aid), None)
    assert hit is not None
    assert hit["federated"] is True
    assert hit["listing_type"] == "service"
    assert hit["source_peer"] == "https://peer-b.example"


def test_digest_pagination_covers_whole_feed(tmp_path: Path, monkeypatch) -> None:
    # FED-1 审查修复:digest serve 侧封顶 + 拉方翻页。把每页设 2、发 5 条,
    # 翻页须覆盖全部(否则只会拿到前 2 条)。
    import nth_dao.web.v2_api as v2_api
    monkeypatch.setattr(v2_api, "_FED_DIGEST_PAGE", 2)

    b = TestClient(create_app(tmp_path / "b", require_console_auth=False))
    ids = [
        b.post(
            "/api/v2/market/announce",
            json={"title": f"task {i}", "capability_set": []},
        ).json()["announcement_id"]
        for i in range(5)
    ]
    # 单次 digest 确实被截到 2 条(证明 serve 侧封顶生效)。
    page = b.get("/api/v2/market/federation/digest?since=-1").json()
    assert len(page["refs"]) == 2

    # 但 federate_once 翻页 → 5 条全收。
    entries = federate_once(
        ["https://peer-b.example"],
        _http_get_via(b),
        verify_seed_peer=lambda _url: _node_did(b),
    )
    discovered_ids = {entry["ann"].announcement_id for entry in entries.values()}
    for aid in ids:
        assert aid in discovered_ids, f"翻页应覆盖 {aid}"
    assert len(entries) == 5


def test_equal_local_ids_from_different_daos_do_not_shadow(
    tmp_path: Path,
) -> None:
    from nth_dao.market import MarketFeed

    b_app = create_app(tmp_path / "b", require_console_auth=False)
    c_app = create_app(tmp_path / "c", require_console_auth=False)
    b = TestClient(b_app)
    c = TestClient(c_app)
    for app, root, title in (
        (b_app, tmp_path / "b", "B shared id"),
        (c_app, tmp_path / "c", "C shared id"),
    ):
        identity = app.state.nth.node_identity
        MarketFeed(root).publish(sign_announcement(
            publisher=identity,
            authority_did=identity.as_did(),
            title=title,
            announcement_id="shared-local-id",
        ))

    def routed_get(url: str):
        parsed = urlsplit(url)
        client = b if parsed.netloc == "peer-b.example" else c
        path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        return client.get(path).json()

    dids = {
        "https://peer-b.example": _node_did(b),
        "https://peer-c.example": _node_did(c),
    }
    entries = federate_once(
        list(dids),
        routed_get,
        verify_seed_peer=lambda url: dids[url],
    )

    assert len(entries) == 2
    assert len(set(entries)) == 2
    assert {
        entry["ann"].title for entry in entries.values()
    } == {"B shared id", "C shared id"}

    a_app = create_app(tmp_path / "a", require_console_auth=False)
    cache = FederationCache()
    cache.replace_all(entries)
    a_app.state.market_fed_cache = cache
    rows = TestClient(a_app).get("/api/v2/market/open").json()
    shared = [row for row in rows if row["announcement_id"] == "shared-local-id"]
    assert len(shared) == 2
    assert len({row["federation_key"] for row in shared}) == 2


def test_remote_claim_removes_task_from_next_signed_snapshot(
    tmp_path: Path,
) -> None:
    b_root = tmp_path / "b"
    b = TestClient(create_app(b_root, require_console_auth=False))
    aid = b.post(
        "/api/v2/market/announce",
        json={"title": "claim lifecycle", "capability_set": []},
    ).json()["announcement_id"]
    peer = "https://peer-b.example"
    before = federate_once(
        [peer],
        _http_get_via(b),
        verify_seed_peer=lambda _url: _node_did(b),
    )
    assert any(
        entry["ann"].announcement_id == aid for entry in before.values()
    )

    atomic_write_json(
        b_root / "market_claims" / f"{aid}.json",
        {"announcement_id": aid, "status": "claimed"},
    )
    # A previously cached digest id must not resurrect the task through the
    # authoritative full-record endpoint after the claim wins.
    assert b.get(
        "/api/v2/market/federation/pull", params={"ids": aid},
    ).json() == []
    after = federate_once(
        [peer],
        _http_get_via(b),
        verify_seed_peer=lambda _url: _node_did(b),
    )

    assert not any(
        entry["ann"].announcement_id == aid for entry in after.values()
    )


def test_federation_cache_error_retains_bounded_non_actionable_hint() -> None:
    identity = AgentIdentity.generate(label="remote")
    ann = sign_announcement(
        publisher=identity,
        authority_did=identity.as_did(),
        title="stale task",
    )
    cache = FederationCache()
    cache.replace_all({
        "legacy-key": {
            "ann": ann,
            "source": "https://remote.example",
            "source_did": identity.as_did(),
        },
    })
    assert cache.snapshot()

    cache.mark_error("refresh failed", peer_count=1)

    snapshot = cache.snapshot()
    assert len(snapshot) == 1
    assert next(iter(snapshot.values()))["stale"] is True
    status = cache.status()
    assert status["cached_announcements"] == 1
    assert status["stale_announcements"] == 1
    assert status["last_error"] == "refresh failed"


def test_federation_cache_isolates_input_and_snapshot_mutations() -> None:
    identity = AgentIdentity.generate(label="remote")
    ann = sign_announcement(
        publisher=identity,
        authority_did=identity.as_did(),
        title="immutable verified task",
        capability_set=["review"],
        input_schema={"properties": {"diff": {"type": "string"}}},
    )
    source_entry = {
        "ann": ann,
        "source": "https://remote.example/",
        "source_did": identity.as_did(),
        "untrusted_extra": {"mutable": True},
    }
    cache = FederationCache()
    cache.replace_all({"caller-key": source_entry})

    ann.title = "tampered after cache write"
    ann.capability_set.append("admin")
    source_entry["source"] = "https://attacker.example"

    first = next(iter(cache.snapshot().values()))
    assert first["ann"].title == "immutable verified task"
    assert first["ann"].capability_set == ["review"]
    assert first["source"] == "https://remote.example"
    assert "untrusted_extra" not in first

    first["ann"].title = "tampered snapshot"
    first["ann"].input_schema["properties"]["diff"]["type"] = "integer"
    first["source"] = "https://snapshot-attacker.example"

    second = next(iter(cache.snapshot().values()))
    assert second["ann"].title == "immutable verified task"
    assert second["ann"].input_schema["properties"]["diff"]["type"] == "string"
    assert second["source"] == "https://remote.example"


def test_partial_cycle_replaces_only_completed_sources() -> None:
    first = AgentIdentity.generate(label="first")
    second = AgentIdentity.generate(label="second")
    first_ann = sign_announcement(
        publisher=first, authority_did=first.as_did(), title="first old",
    )
    second_ann = sign_announcement(
        publisher=second, authority_did=second.as_did(), title="second stable",
    )
    first_url = "https://first.example"
    second_url = "https://second.example"
    cache = FederationCache(stale_ttl_ms=60_000)
    cache.replace_all({
        "first": {"ann": first_ann, "source": first_url},
        "second": {"ann": second_ann, "source": second_url},
    })

    cache.apply_cycle({}, completed_sources={first_url}, peer_count=2)

    snapshot = cache.snapshot()
    assert len(snapshot) == 1
    retained = next(iter(snapshot.values()))
    assert retained["source"] == second_url
    assert retained["stale"] is True


def test_incremental_cycle_merges_then_periodic_full_reconcile_removes_absent() -> None:
    identity = AgentIdentity.generate(label="remote")
    source = "https://remote.example"
    first = sign_announcement(
        publisher=identity,
        authority_did=identity.as_did(),
        title="first",
    )
    second = sign_announcement(
        publisher=identity,
        authority_did=identity.as_did(),
        title="second",
    )
    cache = FederationCache(stale_ttl_ms=1_000)
    cache.apply_cycle(
        {"first": {"ann": first, "source": source}},
        completed_sources={source},
        full_sources={source},
        source_high_seq={source: 0},
        source_dids={source: identity.as_did()},
        now_ms_override=1_000,
    )
    assert cache.since_for_source(
        source,
        identity.as_did(),
        now_ms_override=1_050,
        full_reconcile_ms=100,
    ) == 0

    cache.apply_cycle(
        {"second": {"ann": second, "source": source}},
        completed_sources={source},
        full_sources=set(),
        source_high_seq={source: 1},
        source_dids={source: identity.as_did()},
        now_ms_override=1_050,
    )
    titles = {
        item["ann"].title
        for item in cache.snapshot(now_ms_override=1_050).values()
    }
    assert titles == {"first", "second"}
    assert cache.since_for_source(
        source,
        identity.as_did(),
        now_ms_override=1_100,
        full_reconcile_ms=100,
    ) == -1

    cache.apply_cycle(
        {"second": {"ann": second, "source": source}},
        completed_sources={source},
        full_sources={source},
        source_high_seq={source: 1},
        source_dids={source: identity.as_did()},
        now_ms_override=1_100,
    )
    remaining = cache.snapshot(now_ms_override=1_100)
    assert [item["ann"].title for item in remaining.values()] == ["second"]


def test_incremental_cursor_fails_closed_on_identity_rotation() -> None:
    first = AgentIdentity.generate(label="first")
    second = AgentIdentity.generate(label="second")
    source = "https://remote.example"
    cache = FederationCache(stale_ttl_ms=1_000)
    cache.apply_cycle(
        {},
        completed_sources={source},
        full_sources={source},
        source_high_seq={source: 9},
        source_dids={source: first.as_did()},
        now_ms_override=1_000,
    )

    assert cache.since_for_source(
        source,
        second.as_did(),
        now_ms_override=1_010,
        full_reconcile_ms=100,
    ) == -1


def test_stale_source_is_evicted_after_ttl() -> None:
    identity = AgentIdentity.generate(label="remote")
    announcement = sign_announcement(
        publisher=identity,
        authority_did=identity.as_did(),
        title="bounded stale task",
    )
    source = "https://remote.example"
    cache = FederationCache(stale_ttl_ms=100)
    cache.replace_all({"one": {"ann": announcement, "source": source}})
    verified_at = next(iter(cache.snapshot().values()))["last_verified_ms"]

    cache.apply_cycle(
        {}, completed_sources=set(), now_ms_override=verified_at + 101,
    )

    assert cache.snapshot() == {}


def test_snapshot_enforces_ttl_without_waiting_for_another_poll_cycle() -> None:
    identity = AgentIdentity.generate(label="remote")
    announcement = sign_announcement(
        publisher=identity,
        authority_did=identity.as_did(),
        title="read-time stale task",
    )
    cache = FederationCache(stale_ttl_ms=100)
    cache.replace_all({
        "one": {
            "ann": announcement,
            "source": "https://remote.example",
        },
    })
    verified_at = next(iter(cache.snapshot().values()))["last_verified_ms"]

    assert cache.snapshot(now_ms_override=verified_at + 100)
    assert cache.snapshot(now_ms_override=verified_at + 101) == {}


def test_snapshot_fails_closed_when_wall_clock_moves_before_verification() -> None:
    identity = AgentIdentity.generate(label="remote")
    announcement = sign_announcement(
        publisher=identity,
        authority_did=identity.as_did(),
        title="clock rollback task",
    )
    cache = FederationCache(stale_ttl_ms=100)
    cache.replace_all({
        "one": {
            "ann": announcement,
            "source": "https://remote.example",
        },
    })
    verified_at = next(iter(cache.snapshot().values()))["last_verified_ms"]

    assert cache.snapshot(now_ms_override=verified_at - 1) == {}


def test_cache_capacity_rejection_is_atomic() -> None:
    first = AgentIdentity.generate(label="first")
    second = AgentIdentity.generate(label="second")
    first_ann = sign_announcement(
        publisher=first, authority_did=first.as_did(), title="first",
    )
    second_ann = sign_announcement(
        publisher=second, authority_did=second.as_did(), title="second",
    )
    cache = FederationCache(max_records=1)
    cache.replace_all({
        "first": {"ann": first_ann, "source": "https://first.example"},
    })

    with pytest.raises(FederationCacheCapacityError, match="global"):
        cache.replace_all({
            "first": {"ann": first_ann, "source": "https://first.example"},
            "second": {"ann": second_ann, "source": "https://second.example"},
        })

    snapshot = cache.snapshot()
    assert len(snapshot) == 1
    assert next(iter(snapshot.values()))["ann"].title == "first"


def test_cache_enforces_per_source_and_byte_limits() -> None:
    identity = AgentIdentity.generate(label="source")
    announcements = [
        sign_announcement(
            publisher=identity,
            authority_did=identity.as_did(),
            title=f"record {index}",
        )
        for index in range(2)
    ]
    entries = {
        str(index): {
            "ann": announcement,
            "source": "https://source.example",
        }
        for index, announcement in enumerate(announcements)
    }

    with pytest.raises(FederationCacheCapacityError, match="per-source"):
        FederationCache(max_records_per_source=1).replace_all(entries)
    with pytest.raises(FederationCacheCapacityError, match="byte"):
        FederationCache(max_bytes=1).replace_all({"one": entries["0"]})


def test_federation_cycle_rejects_global_record_overflow(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)
    for title in ("first", "second"):
        assert client.post(
            "/api/v2/market/announce",
            json={"title": title, "capability_set": ["review"]},
        ).status_code == 200

    with pytest.raises(FederationCacheCapacityError, match="global"):
        federate_once(
            ["https://source.example"],
            _http_get_via(client),
            verify_seed_peer=lambda _url: _node_did(client),
            max_records=1,
        )


def test_seed_rotation_lets_healthy_peer_run_after_slow_peer_budget() -> None:
    slow = AgentIdentity.generate(label="slow")
    healthy = AgentIdentity.generate(label="healthy")
    healthy_ann = sign_announcement(
        publisher=healthy,
        authority_did=healthy.as_did(),
        title="healthy task",
    )
    slow_url = "https://slow.example"
    healthy_url = "https://healthy.example"

    def routed_get(url: str):
        if url.startswith(slow_url):
            time.sleep(0.2)
            raise TimeoutError("slow peer")
        if "since=-1" in url:
            raw = healthy_ann.to_dict()
            ref_fields = (
                "announcement_id", "publisher_did", "authority_did",
                "capability_set", "context", "reward_minor", "reward_asset",
                "published_at_ms", "not_after",
            )
            digest = FeedDigest(
                source_did=healthy.as_did(), generated_at_ms=1, high_seq=0,
                refs=[{key: raw.get(key) for key in ref_fields}],
            )
            digest.digest_sig = b64u_encode(
                healthy.sign(canonical_json(digest.signing_body()))
            )
            return digest.to_dict()
        if "/digest?" in url:
            terminal = FeedDigest(
                source_did=healthy.as_did(), generated_at_ms=2, high_seq=0,
                refs=[],
            )
            terminal.digest_sig = b64u_encode(
                healthy.sign(canonical_json(terminal.signing_body()))
            )
            return terminal.to_dict()
        if "/pull?" in url:
            return [healthy_ann.to_dict()]
        if url.endswith("/peers"):
            return {"peers": []}
        raise AssertionError(url)

    dids = {slow_url: slow.as_did(), healthy_url: healthy.as_did()}
    first_report = FederationCycleReport()
    first = federate_once(
        [slow_url, healthy_url], routed_get,
        verify_seed_peer=lambda url: dids[url],
        max_duration_s=0.1,
        cycle_report=first_report,
        start_offset=0,
    )
    assert first == {}
    assert healthy_url not in first_report.completed_sources

    second_report = FederationCycleReport()
    second = federate_once(
        [slow_url, healthy_url], routed_get,
        verify_seed_peer=lambda url: dids[url],
        max_duration_s=0.1,
        cycle_report=second_report,
        start_offset=1,
    )
    assert any(entry["ann"].title == "healthy task" for entry in second.values())
    assert healthy_url in second_report.completed_sources


def test_unsigned_or_bad_peer_yields_nothing(tmp_path: Path) -> None:
    # 对端返回垃圾(验签失败)→ 一条都不收(fail-closed)。
    def bad_get(url: str):
        if url.endswith("/digest"):
            return {"source_did": "did:key:zBOGUS", "refs": [], "digest_sig": "AA"}
        return []
    expected_did = AgentIdentity.generate(label="expected").as_did()
    assert pull_from_peer(
        "https://evil.example", bad_get, expected_source_did=expected_did,
    ) == []
    assert federate_once(
        ["https://evil.example"],
        bad_get,
        verify_seed_peer=lambda _url: expected_did,
    ) == {}


def test_signed_malformed_digest_and_announcement_fail_closed() -> None:
    source = AgentIdentity.generate(label="source")
    ann = sign_announcement(
        publisher=source,
        authority_did=source.as_did(),
        title="unsafe full record",
    )
    raw = ann.to_dict()
    ref_fields = (
        "announcement_id", "publisher_did", "authority_did",
        "capability_set", "context", "reward_minor", "reward_asset",
        "published_at_ms", "not_after",
    )
    digest = FeedDigest(
        source_did=source.as_did(),
        generated_at_ms=1,
        high_seq=0,
        refs=[{key: raw.get(key) for key in ref_fields}],
    )
    digest.digest_sig = b64u_encode(
        source.sign(canonical_json(digest.signing_body()))
    )

    malformed_digest = FeedDigest.from_dict(digest.to_dict())
    malformed_digest.high_seq = "bad"  # type: ignore[assignment]
    malformed_digest.digest_sig = b64u_encode(
        source.sign(canonical_json(malformed_digest.signing_body()))
    )

    def bad_digest_get(url: str):
        assert "/digest?" in url
        return malformed_digest.to_dict()

    assert pull_from_peer(
        "https://source.example",
        bad_digest_get,
        expected_source_did=source.as_did(),
    ) == []

    malformed_ann = sign_announcement(
        publisher=source,
        authority_did=source.as_did(),
        title="unsafe full record",
        announcement_id=ann.announcement_id,
    )
    malformed_ann.not_after = "never"  # type: ignore[assignment]
    malformed_ann.publisher_sig = b64u_encode(
        source.sign(canonical_json(malformed_ann.signing_body()))
    )

    def bad_announcement_get(url: str):
        if "/digest?" in url:
            return digest.to_dict()
        if "/pull?" in url:
            return [malformed_ann.to_dict()]
        raise AssertionError(url)

    assert pull_from_peer(
        "https://source.example",
        bad_announcement_get,
        expected_source_did=source.as_did(),
    ) == []


@pytest.mark.parametrize("response_kind", ["empty", "subset", "duplicate"])
def test_pull_rejects_incomplete_or_duplicate_signed_digest_batch(
    response_kind: str,
) -> None:
    source = AgentIdentity.generate(label="source")
    announcements = [
        sign_announcement(
            publisher=source,
            authority_did=source.as_did(),
            title=f"declared record {index}",
        )
        for index in range(2)
    ]
    ref_fields = (
        "announcement_id", "publisher_did", "authority_did",
        "capability_set", "context", "reward_minor", "reward_asset",
        "published_at_ms", "not_after",
    )
    digest = FeedDigest(
        source_did=source.as_did(),
        generated_at_ms=1,
        high_seq=1,
        refs=[
            {key: announcement.to_dict().get(key) for key in ref_fields}
            for announcement in announcements
        ],
    )
    digest.digest_sig = b64u_encode(
        source.sign(canonical_json(digest.signing_body()))
    )
    responses = {
        "empty": [],
        "subset": [announcements[0].to_dict()],
        "duplicate": [
            announcements[0].to_dict(),
            announcements[0].to_dict(),
        ],
    }

    def inconsistent_get(url: str):
        if "/digest?" in url:
            return digest.to_dict()
        if "/pull?" in url:
            return responses[response_kind]
        raise AssertionError(url)

    completion: dict[str, bool] = {}
    assert pull_from_peer(
        "https://source.example",
        inconsistent_get,
        expected_source_did=source.as_did(),
        _completion=completion,
    ) == []
    assert completion == {"complete": False}


def test_pull_rejects_peer_snapshot_above_local_record_limit() -> None:
    source = AgentIdentity.generate(label="source")
    announcements = [
        sign_announcement(
            publisher=source,
            authority_did=source.as_did(),
            title=f"record {index}",
        )
        for index in range(2)
    ]
    ref_fields = (
        "announcement_id", "publisher_did", "authority_did",
        "capability_set", "context", "reward_minor", "reward_asset",
        "published_at_ms", "not_after",
    )
    digest = FeedDigest(
        source_did=source.as_did(),
        generated_at_ms=1,
        high_seq=1,
        refs=[
            {key: announcement.to_dict().get(key) for key in ref_fields}
            for announcement in announcements
        ],
    )
    digest.digest_sig = b64u_encode(
        source.sign(canonical_json(digest.signing_body()))
    )

    def oversized_get(url: str):
        if "/digest?" in url:
            return digest.to_dict()
        raise AssertionError("oversized digest must fail before pull")

    completion: dict[str, bool] = {}
    assert pull_from_peer(
        "https://source.example",
        oversized_get,
        expected_source_did=source.as_did(),
        _completion=completion,
        _max_records=1,
    ) == []
    assert completion == {"complete": False}


@pytest.mark.parametrize("bad_limit", [True, 1.5, 0, -1])
def test_federation_record_limits_require_positive_integers(bad_limit) -> None:
    with pytest.raises(ValueError, match="positive integer"):
        federate_once([], max_records=bad_limit)


def test_later_digest_page_failure_discards_partial_snapshot() -> None:
    source = AgentIdentity.generate(label="source")
    announcement = sign_announcement(
        publisher=source,
        authority_did=source.as_did(),
        title="must not leak from a partial snapshot",
    )
    raw = announcement.to_dict()
    ref_fields = (
        "announcement_id", "publisher_did", "authority_did",
        "capability_set", "context", "reward_minor", "reward_asset",
        "published_at_ms", "not_after",
    )
    first_page = FeedDigest(
        source_did=source.as_did(),
        generated_at_ms=1,
        high_seq=0,
        refs=[{key: raw.get(key) for key in ref_fields}],
    )
    first_page.digest_sig = b64u_encode(
        source.sign(canonical_json(first_page.signing_body()))
    )
    requested: list[str] = []

    def interrupted_get(url: str):
        requested.append(url)
        if "since=-1" in url:
            return first_page.to_dict()
        if "/digest?" in url:
            raise TimeoutError("second page timed out")
        if "/pull?" in url:
            return [announcement.to_dict()]
        raise AssertionError(url)

    assert pull_from_peer(
        "https://source.example",
        interrupted_get,
        expected_source_did=source.as_did(),
    ) == []
    assert not any("/pull?" in url for url in requested)


def test_peer_cannot_replay_another_daos_signed_feed() -> None:
    origin = AgentIdentity.generate(label="origin")
    mirror = AgentIdentity.generate(label="mirror")
    announcement = sign_announcement(
        publisher=origin,
        authority_did=origin.as_did(),
        title="origin-only task",
    )
    raw = announcement.to_dict()
    ref_fields = (
        "announcement_id",
        "publisher_did",
        "authority_did",
        "capability_set",
        "context",
        "reward_minor",
        "reward_asset",
        "published_at_ms",
        "not_after",
    )
    digest = FeedDigest(
        source_did=origin.as_did(),
        generated_at_ms=1,
        high_seq=0,
        refs=[{key: raw.get(key) for key in ref_fields}],
    )
    digest.digest_sig = b64u_encode(
        origin.sign(canonical_json(digest.signing_body()))
    )

    def replaying_mirror(url: str):
        if "/digest?" in url:
            return digest.to_dict()
        if "/pull?" in url:
            return [raw]
        raise AssertionError(url)

    assert pull_from_peer(
        "https://mirror.example",
        replaying_mirror,
        expected_source_did=mirror.as_did(),
    ) == []
