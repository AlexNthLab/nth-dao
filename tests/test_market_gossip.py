"""FED-B:gossip 传递发现 —— 节点只配几个 peer,经它们的 peer 列表逐跳
发现整张可达网络的任务。

链路 A→B→C:A 只把 B 当 seed,B 配了 C,C 发了任务。A 应经 gossip 传递发现
C 的活(任务仍直连 C 拉 + 双层验签,gossip 只扩大「连谁」)。不起真 socket:
多路复用 http_get 按 host 路由到各节点 TestClient。
"""
from __future__ import annotations

import json
import socket
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("nacl")

from fastapi.testclient import TestClient

from nth_dao.did_key import encode_ed25519_did_key
from nth_dao.web import create_app
from nth_dao.web.market_federation_poll import (
    _urllib_request_bytes_pinned,
    fetch_peer_list,
    federate_once,
)

C_URL = "https://node-c.example"
B_URL = "https://node-b.example"
A_URL = "https://node-a.example"
NEW_NODE_DID = encode_ed25519_did_key(bytes.fromhex("34" * 32))
NODE_A_DID = encode_ed25519_did_key(bytes.fromhex("56" * 32))


def test_pinned_http_has_absolute_response_deadline(monkeypatch) -> None:
    client, server = socket.socketpair()
    monkeypatch.setattr(
        "nth_dao.web.market_federation_poll.socket.create_connection",
        lambda *args, **kwargs: client,
    )

    def slow_drip() -> None:
        try:
            server.recv(4096)
            server.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n"
            )
            while True:
                server.sendall(b"x")
                time.sleep(0.02)
        except OSError:
            pass
        finally:
            server.close()

    worker = threading.Thread(target=slow_drip, daemon=True)
    worker.start()
    started = time.monotonic()
    with pytest.raises(TimeoutError, match="absolute deadline"):
        _urllib_request_bytes_pinned(
            "http://peer.example/data",
            "93.184.216.34",
            method="GET",
            timeout_s=0.05,
        )
    assert time.monotonic() - started < 0.5
    worker.join(timeout=0.5)


def _resolve_public(host, *a, **k):
    """测试用 DNS:把 *.example 假域名映射到一个公网 IP(过 SSRF 校验);
    含 'internal' 的域名映射到内网 IP(被 SSRF 拒)。不起真 DNS。"""
    ip = "10.0.0.9" if "internal" in host else "93.184.216.34"
    return [(2, 1, 6, "", (ip, 0))]


def _resolve_never(host, *a, **k):  # 断言:原始 IP/localhost 分支不该触发解析
    raise AssertionError(f"不应解析 {host}(原始 IP/localhost 应短路)")


def _write_verified_seed_metadata(
    workspace: Path, peer_url: str, peer_client: TestClient,
) -> None:
    identity = peer_client.app.state.nth.node_identity
    payload = {
        peer_url: {
            "peer_url": peer_url,
            "identity_url": f"{peer_url}/.well-known/nth-dao/identity.json",
            "did": identity.as_did(),
            "pubkey_hex": identity.pubkey_hex,
            "verified_at": "2026-07-15T00:00:00+00:00",
            "card_kind": "nth-dao-identity-card-v1",
            "federation_protocol": "nth-dao-federation-v1",
        },
    }
    path = workspace / "federation" / "peers_meta.json"
    path.write_text(json.dumps(payload), encoding="utf-8")


def _node_did(client: TestClient) -> str:
    return client.app.state.nth.node_identity.as_did()


def test_gossip_transitive_discovery(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("NTH_FED_PEERS", raising=False)

    # C:发一个任务,自己没配 peer。
    c_app = create_app(tmp_path / "c", require_console_auth=False)
    c = TestClient(c_app)
    aid = c.post(
        "/api/v2/market/announce",
        json={"title": "deep task", "capability_set": ["code_review"], "reward_minor": 8},
    ).json()["announcement_id"]

    # B:没任务,但**配置了 C 为 peer**(经 workspace peers.json)。
    b_ws = tmp_path / "b"
    (b_ws / "federation").mkdir(parents=True, exist_ok=True)
    (b_ws / "federation" / "peers.json").write_text(
        json.dumps([C_URL]), encoding="utf-8")
    _write_verified_seed_metadata(b_ws, C_URL, c)
    b_app = create_app(b_ws, require_console_auth=False)
    b = TestClient(b_app)

    # 多路复用:按 host 把 http_get 路由到对应节点的 TestClient。
    def http_get(url: str):
        u = urlsplit(url)
        full = u.path + (f"?{u.query}" if u.query else "")
        if "node-c" in u.netloc:
            return c.get(full).json()
        if "node-b" in u.netloc:
            return b.get(full).json()
        raise RuntimeError(f"unexpected url {url}")

    # 健全性:B 公开的 peer 列表确实含 C。
    assert fetch_peer_list(B_URL, http_get) == [C_URL]

    # A 只把 B 当 seed → BFS 经 B 的 peer 列表传递发现 C → 拉到 C 的任务。
    entries = federate_once(
        [B_URL],
        http_get,
        resolve=_resolve_public,
        verify_seed_peer=lambda _url: _node_did(b),
        verify_gossip_peer=lambda url, _ip: _node_did(c) if url == C_URL else None,
    )
    matches = [
        entry for entry in entries.values()
        if entry["ann"].announcement_id == aid
    ]
    assert len(matches) == 1, "应经 B 传递发现(gossip)到 C 的任务"
    assert matches[0]["source"].rstrip("/") == C_URL


def test_gossip_bounded_and_loop_safe(tmp_path: Path, monkeypatch) -> None:
    # 环:B 配 C,C 配回 B。BFS 的 seen 去重 + max_peers 应让它收敛、不死循环。
    monkeypatch.delenv("NTH_FED_PEERS", raising=False)
    b_ws = tmp_path / "b"
    c_ws = tmp_path / "c"
    for ws, peer in ((b_ws, C_URL), (c_ws, B_URL)):
        (ws / "federation").mkdir(parents=True, exist_ok=True)
        (ws / "federation" / "peers.json").write_text(
            json.dumps([peer]), encoding="utf-8")
    b = TestClient(create_app(b_ws, require_console_auth=False))
    c = TestClient(create_app(c_ws, require_console_auth=False))
    _write_verified_seed_metadata(b_ws, C_URL, c)
    _write_verified_seed_metadata(c_ws, B_URL, b)
    # C 发个任务。
    aid = c.post(
        "/api/v2/market/announce",
        json={"title": "t", "capability_set": []},
    ).json()["announcement_id"]

    def http_get(url: str):
        u = urlsplit(url)
        full = u.path + (f"?{u.query}" if u.query else "")
        return (c if "node-c" in u.netloc else b).get(full).json()

    entries = federate_once(
        [B_URL],
        http_get,
        max_peers=8,
        resolve=_resolve_public,
        verify_seed_peer=lambda _url: _node_did(b),
        verify_gossip_peer=lambda url, _ip: (
            _node_did(c) if url == C_URL else _node_did(b)
        ),
    )  # 有环也必须收敛
    assert any(
        entry["ann"].announcement_id == aid for entry in entries.values()
    )


def test_gossip_rejects_internal_urls_ssrf(tmp_path: Path, monkeypatch) -> None:
    # 恶意 peer 在 peer 列表里塞内网/云元数据地址 → BFS 绝不能去连(防 SSRF)。
    monkeypatch.delenv("NTH_FED_PEERS", raising=False)
    b_ws = tmp_path / "b"
    (b_ws / "federation").mkdir(parents=True, exist_ok=True)
    bad = [
        "http://169.254.169.254/",       # 云元数据
        "https://localhost/",
        "http://10.0.0.5:6379",          # 内网 redis
        "https://127.0.0.1/",
    ]
    (b_ws / "federation" / "peers.json").write_text(
        json.dumps(bad), encoding="utf-8")
    b = TestClient(create_app(b_ws, require_console_auth=False))

    fetched: list = []

    def http_get(url: str):
        fetched.append(url)
        u = urlsplit(url)
        full = u.path + (f"?{u.query}" if u.query else "")
        if "node-b" in u.netloc:
            return b.get(full).json()
        raise AssertionError(f"SSRF:poller 连了被禁地址 {url}")

    # 原始 IP/localhost 必须在解析前短路:_resolve_never 被调到就炸。
    entries = federate_once(
        [B_URL], http_get, resolve=_resolve_never,
        verify_seed_peer=lambda _url: _node_did(b),
    )
    assert entries == {}  # B 没任务,且坏 peer 一个都没被连
    assert all("node-b" in urlsplit(u).netloc for u in fetched)


def test_gossip_rejects_domain_resolving_to_internal(tmp_path: Path, monkeypatch) -> None:
    # Option A 核心:peer 报一个**域名**,但它解析到内网 IP → BFS 必须不连。
    monkeypatch.delenv("NTH_FED_PEERS", raising=False)
    b_ws = tmp_path / "b"
    (b_ws / "federation").mkdir(parents=True, exist_ok=True)
    # 域名本身看起来无害(https + 非 localhost),但 _resolve_public 把含
    # 'internal' 的域名解析到 10.0.0.9 → 应被拒。
    (b_ws / "federation" / "peers.json").write_text(
        json.dumps(["https://db-internal.example"]), encoding="utf-8")
    b = TestClient(create_app(b_ws, require_console_auth=False))

    fetched: list = []

    def http_get(url: str):
        fetched.append(url)
        u = urlsplit(url)
        if "node-b" in u.netloc:
            return b.get(u.path + (f"?{u.query}" if u.query else "")).json()
        raise AssertionError(f"SSRF:连了解析到内网的域名 {url}")

    entries = federate_once(
        [B_URL], http_get, resolve=_resolve_public,
        verify_seed_peer=lambda _url: _node_did(b),
    )
    assert entries == {}
    assert all("node-b" in urlsplit(u).netloc for u in fetched)


def test_is_safe_gossip_url_unit() -> None:
    from nth_dao.web.market_federation_poll import _is_safe_gossip_url as ok
    # 公网:域名解析到公网 IP / 原始公网 IP → 放行。
    assert ok("https://node-pub.example", resolve=_resolve_public)
    assert ok("https://1.2.3.4/")             # 原始公网 IP,不解析
    # 域名解析到内网 → 拒(Option A 新增防护)。
    assert not ok("https://db-internal.example", resolve=_resolve_public)
    # 解析失败 → fail-closed。
    assert not ok("https://nx.example", resolve=_resolve_never)
    # 非 https / localhost / 原始内网 IP → 解析前即拒。
    assert not ok("http://node-pub.example", resolve=_resolve_never)
    assert not ok("https://localhost/", resolve=_resolve_never)
    assert not ok("https://127.0.0.1/", resolve=_resolve_never)
    assert not ok("http://169.254.169.254/", resolve=_resolve_never)
    assert not ok("https://10.0.0.5/", resolve=_resolve_never)
    assert not ok("https://192.168.1.1/", resolve=_resolve_never)
    assert not ok("https://[::1]/", resolve=_resolve_never)   # ipv6 loopback
    assert not ok("not a url at all", resolve=_resolve_never)


def test_gossip_identity_preflight_can_drop_unverified_peer(monkeypatch) -> None:
    import nth_dao.web.market_federation_poll as poll

    monkeypatch.setattr(
        poll, "pull_from_peer", lambda peer, http_get, **kwargs: [],
    )
    monkeypatch.setattr(
        poll,
        "fetch_peer_list",
        lambda peer, http_get: [C_URL] if peer == B_URL else [],
    )
    checked: list[str] = []

    entries = poll.federate_once(
        [B_URL],
        lambda _url: {},
        resolve=_resolve_public,
        verify_gossip_peer=lambda url, resolved_ip: checked.append(url) or False,
        verify_seed_peer=lambda _url: NODE_A_DID,
    )

    assert entries == {}
    assert checked == [C_URL]


def test_gossip_candidate_limit_precedes_identity_preflight(monkeypatch) -> None:
    import nth_dao.web.market_federation_poll as poll

    candidates = [f"https://node-{idx}.example" for idx in range(100)]
    monkeypatch.setattr(
        poll, "pull_from_peer", lambda peer, http_get, **kwargs: [],
    )
    monkeypatch.setattr(
        poll,
        "fetch_peer_list",
        lambda peer, http_get: candidates if peer == B_URL else [],
    )
    checked: list[str] = []

    poll.federate_once(
        [B_URL],
        lambda _url: {},
        resolve=_resolve_public,
        max_peers=2,
        verify_gossip_peer=lambda url, resolved_ip: checked.append(url) or False,
        verify_seed_peer=lambda _url: NODE_A_DID,
    )

    assert len(checked) == 1


def test_gossip_cycle_obeys_total_time_budget(monkeypatch) -> None:
    import time
    import nth_dao.web.market_federation_poll as poll

    candidates = [f"https://node-{idx}.example" for idx in range(10)]
    monkeypatch.setattr(
        poll, "pull_from_peer", lambda peer, http_get, **kwargs: [],
    )
    monkeypatch.setattr(
        poll,
        "fetch_peer_list",
        lambda peer, http_get: candidates if peer == B_URL else [],
    )
    checked: list[str] = []

    def slow_reject(url: str, resolved_ip: str) -> bool:
        checked.append(url)
        time.sleep(0.01)
        return False

    started = time.monotonic()
    entries = poll.federate_once(
        [B_URL],
        lambda _url: {},
        resolve=_resolve_public,
        verify_gossip_peer=slow_reject,
        verify_seed_peer=lambda _url: NODE_A_DID,
        max_duration_s=0.001,
    )

    assert entries == {}
    assert len(checked) <= 1
    assert time.monotonic() - started < 0.2


def test_gossip_cycle_honours_cancellation_before_network_io() -> None:
    requested: list[str] = []

    entries = federate_once(
        [B_URL],
        lambda url: requested.append(url) or {},
        cancelled=lambda: True,
    )

    assert entries == {}
    assert requested == []


def test_gossip_market_fetch_uses_resolved_ip(monkeypatch) -> None:
    import nth_dao.web.market_federation_poll as poll

    pinned_calls: list[tuple[str, str]] = []

    def pinned_json(url: str, resolved_ip: str):
        pinned_calls.append((url, resolved_ip))
        return {}

    monkeypatch.setattr(poll, "_urllib_get_json_pinned", pinned_json)
    monkeypatch.setattr(
        poll,
        "pull_from_peer",
        lambda peer, http_get, **kwargs: (
            http_get(f"{C_URL}/api/v2/market/federation/digest")
            if peer == C_URL else {}
        ) and [],
    )
    monkeypatch.setattr(
        poll,
        "fetch_peer_list",
        lambda peer, http_get: [C_URL] if peer == B_URL else [],
    )

    entries = poll.federate_once(
        [B_URL],
        resolve=_resolve_public,
        verify_gossip_peer=lambda url, resolved_ip: NODE_A_DID,
        verify_seed_peer=lambda _url: NODE_A_DID,
    )

    assert entries == {}
    assert pinned_calls == [
        (f"{C_URL}/api/v2/market/federation/digest", "93.184.216.34")
    ]


def test_gossip_identity_preflight_failure_is_fail_closed(monkeypatch) -> None:
    import nth_dao.web.market_federation_poll as poll

    monkeypatch.setattr(
        poll, "pull_from_peer", lambda peer, http_get, **kwargs: [],
    )
    monkeypatch.setattr(
        poll,
        "fetch_peer_list",
        lambda peer, http_get: [C_URL] if peer == B_URL else [],
    )

    def unavailable(_url: str, _resolved_ip: str):
        raise RuntimeError("identity service unavailable")

    entries = poll.federate_once(
        [B_URL],
        lambda _url: {},
        resolve=_resolve_public,
        verify_gossip_peer=unavailable,
        verify_seed_peer=lambda _url: NODE_A_DID,
    )

    assert entries == {}


def test_configured_seed_identity_preflight_can_fail_closed(monkeypatch) -> None:
    import nth_dao.web.market_federation_poll as poll

    pulled: list[str] = []

    def pull(peer, http_get, **kwargs):
        pulled.append(peer)
        return []

    monkeypatch.setattr(poll, "pull_from_peer", pull)
    monkeypatch.setattr(poll, "fetch_peer_list", lambda peer, http_get: [])

    entries = poll.federate_once(
        [B_URL],
        lambda _url: {},
        verify_seed_peer=lambda _url: None,
    )

    assert entries == {}
    assert pulled == []


def test_learned_initial_peer_is_revalidated_and_ip_pinned(monkeypatch) -> None:
    import nth_dao.web.market_federation_poll as poll

    pinned_calls: list[tuple[str, str]] = []
    verified: list[tuple[str, str]] = []

    def pinned_json(url: str, resolved_ip: str):
        pinned_calls.append((url, resolved_ip))
        return {}

    def pull(peer, http_get, **kwargs):
        http_get(f"{peer}/api/v2/market/federation/digest")
        return []

    monkeypatch.setattr(poll, "_urllib_get_json_pinned", pinned_json)
    monkeypatch.setattr(poll, "pull_from_peer", pull)
    monkeypatch.setattr(poll, "fetch_peer_list", lambda peer, http_get: [])

    entries = poll.federate_once(
        [],
        untrusted_peers=[C_URL],
        resolve=_resolve_public,
        verify_gossip_peer=lambda url, ip: verified.append((url, ip)) or NODE_A_DID,
    )

    assert entries == {}
    assert verified == [(C_URL, "93.184.216.34")]
    assert pinned_calls == [
        (f"{C_URL}/api/v2/market/federation/digest", "93.184.216.34")
    ]


def test_learned_initial_peer_never_inherits_operator_seed_trust(monkeypatch) -> None:
    import nth_dao.web.market_federation_poll as poll

    pulled: list[str] = []
    monkeypatch.setattr(
        poll,
        "pull_from_peer",
        lambda peer, http_get: pulled.append(peer) or [],
    )
    monkeypatch.setattr(poll, "fetch_peer_list", lambda peer, http_get: [])

    entries = poll.federate_once(
        [],
        untrusted_peers=["https://10.0.0.8"],
        resolve=_resolve_never,
        verify_gossip_peer=lambda url, ip: NODE_A_DID,
    )

    assert entries == {}
    assert pulled == []


def test_peer_hello_announces_only_bounded_identity_hint() -> None:
    from nth_dao.web.market_federation_poll import announce_peer_hello

    calls: list[tuple[str, dict]] = []

    def post(url: str, payload: dict):
        calls.append((url, payload))
        return {"learned": True}

    result = announce_peer_hello(
        [B_URL, B_URL],
        peer_url="https://new-node.example/",
        did=NEW_NODE_DID,
        http_post=post,
    )

    assert result == {B_URL: ""}
    assert calls == [(
        f"{B_URL}/api/v2/market/federation/hello",
        {"peer_url": "https://new-node.example", "did": NEW_NODE_DID},
    )]


def test_peer_hello_failure_is_isolated_per_seed() -> None:
    from nth_dao.web.market_federation_poll import announce_peer_hello

    def post(url: str, payload: dict):
        if "node-b" in url:
            raise TimeoutError("offline")
        return {"learned": True}

    result = announce_peer_hello(
        [B_URL, C_URL],
        peer_url="https://new-node.example",
        did=NEW_NODE_DID,
        http_post=post,
    )

    assert result[B_URL].startswith("TimeoutError:")
    assert result[C_URL] == ""


def test_poller_stop_event_interrupts_long_sleep() -> None:
    from nth_dao.web.market_federation_poll import FederationCache, start_poller

    stop_event = threading.Event()
    thread = start_poller(
        lambda: [],
        FederationCache(),
        stop_event=stop_event,
        interval_s=60.0,
    )

    stop_event.set()
    thread.join(timeout=1.0)

    assert not thread.is_alive()


def test_poller_self_terminates_when_peer_set_becomes_empty() -> None:
    from nth_dao.web.market_federation_poll import FederationCache, start_poller

    peers = ["https://peer.example"]
    stop_event = threading.Event()
    thread = start_poller(
        lambda: list(peers),
        FederationCache(),
        stop_event=stop_event,
        interval_s=0.01,
        verify_seed_peer=lambda _url: None,
    )
    peers.clear()

    thread.join(timeout=1.0)

    assert stop_event.is_set()
    assert not thread.is_alive()


def test_poller_wires_incremental_cursor_and_cycle_progress(
    monkeypatch,
) -> None:
    from nth_dao.web import market_federation_poll as poll

    source = "https://peer.example"
    source_did = "did:key:zIncrementalTest"
    cache = poll.FederationCache(stale_ttl_ms=60_000)
    stop_event = threading.Event()
    seen_since: list[int] = []

    def fake_federate(*_args, **kwargs):
        report = kwargs["cycle_report"]
        seen_since.append(kwargs["source_since"](source, source_did))
        report.completed_sources.add(source)
        report.full_sources.add(source)
        report.source_high_seq[source] = 3
        report.source_dids[source] = source_did
        stop_event.set()
        return {}

    monkeypatch.setattr(poll, "federate_once", fake_federate)
    thread = poll.start_poller(
        lambda: [source],
        cache,
        stop_event=stop_event,
        interval_s=0.01,
    )
    thread.join(timeout=1.0)

    assert seen_since == [-1]
    assert cache.status()["incremental_source_cursors"] == 1


@pytest.mark.parametrize("interval", [-1.0, 0.0, float("nan"), float("inf")])
def test_poller_rejects_non_positive_or_non_finite_interval(interval: float) -> None:
    from nth_dao.web.market_federation_poll import FederationCache, start_poller

    with pytest.raises(ValueError, match="positive finite"):
        start_poller(lambda: [], FederationCache(), interval_s=interval)


def test_reverse_hello_makes_new_nodes_tasks_transitively_discoverable(
    tmp_path: Path, monkeypatch,
) -> None:
    """A knows B; after hello, a third node can discover A through B."""
    import nth_dao.web.v2_api as v2_api

    a = TestClient(create_app(tmp_path / "a", require_console_auth=False))
    announcement_id = a.post(
        "/api/v2/market/announce",
        json={"title": "newcomer task", "capability_set": ["review"]},
    ).json()["announcement_id"]

    b = TestClient(create_app(tmp_path / "b", require_console_auth=True))
    a_identity = a.app.state.nth.node_identity
    metadata = {
        "peer_url": A_URL,
        "identity_url": f"{A_URL}/.well-known/nth-dao/identity.json",
        "did": a_identity.as_did(),
        "pubkey_hex": a_identity.pubkey_hex,
    }
    monkeypatch.setattr(
        "nth_dao.web.market_federation_poll._resolve_safe_gossip_ip",
        lambda url, **kwargs: "93.184.216.34",
    )
    monkeypatch.setattr(
        v2_api,
        "_fetch_and_verify_federation_identity",
        lambda *args, **kwargs: (metadata, ""),
    )
    monkeypatch.setattr(
        "nth_dao.web.market_federation_poll.start_poller",
        lambda *args, **kwargs: None,
    )

    hello = b.post(
        "/api/v2/market/federation/hello",
        json={"peer_url": A_URL, "did": NODE_A_DID},
    )
    assert hello.status_code == 200, hello.text

    def http_get(url: str):
        parsed = urlsplit(url)
        path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        if "node-a" in parsed.netloc:
            return a.get(path).json()
        if "node-b" in parsed.netloc:
            return b.get(path).json()
        raise RuntimeError(f"unexpected federation URL {url}")

    entries = federate_once(
        [B_URL],
        http_get,
        resolve=_resolve_public,
        verify_seed_peer=lambda _url: _node_did(b),
        verify_gossip_peer=lambda url, ip: (
            _node_did(a) if url == A_URL and bool(ip) else None
        ),
    )

    matches = [
        entry for entry in entries.values()
        if entry["ann"].announcement_id == announcement_id
    ]
    assert len(matches) == 1
    assert matches[0]["source"] == A_URL
