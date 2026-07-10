"""FED-B:gossip 传递发现 —— 节点只配几个 peer,经它们的 peer 列表逐跳
发现整张可达网络的任务。

链路 A→B→C:A 只把 B 当 seed,B 配了 C,C 发了任务。A 应经 gossip 传递发现
C 的活(任务仍直连 C 拉 + 双层验签,gossip 只扩大「连谁」)。不起真 socket:
多路复用 http_get 按 host 路由到各节点 TestClient。
"""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("nacl")

from fastapi.testclient import TestClient

from nth_dao.web import create_app
from nth_dao.web.market_federation_poll import fetch_peer_list, federate_once

C_URL = "https://node-c.example"
B_URL = "https://node-b.example"


def _resolve_public(host, *a, **k):
    """测试用 DNS:把 *.example 假域名映射到一个公网 IP(过 SSRF 校验);
    含 'internal' 的域名映射到内网 IP(被 SSRF 拒)。不起真 DNS。"""
    ip = "10.0.0.9" if "internal" in host else "93.184.216.34"
    return [(2, 1, 6, "", (ip, 0))]


def _resolve_never(host, *a, **k):  # 断言:原始 IP/localhost 分支不该触发解析
    raise AssertionError(f"不应解析 {host}(原始 IP/localhost 应短路)")


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
    entries = federate_once([B_URL], http_get, resolve=_resolve_public)
    assert aid in entries, "应经 B 传递发现(gossip)到 C 的任务"
    assert entries[aid]["source"].rstrip("/") == C_URL


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
        [B_URL], http_get, max_peers=8, resolve=_resolve_public)  # 有环也必须收敛
    assert aid in entries


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
    entries = federate_once([B_URL], http_get, resolve=_resolve_never)
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

    entries = federate_once([B_URL], http_get, resolve=_resolve_public)
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

    monkeypatch.setattr(poll, "pull_from_peer", lambda peer, http_get: [])
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
    )

    assert entries == {}
    assert checked == [C_URL]


def test_gossip_candidate_limit_precedes_identity_preflight(monkeypatch) -> None:
    import nth_dao.web.market_federation_poll as poll

    candidates = [f"https://node-{idx}.example" for idx in range(100)]
    monkeypatch.setattr(poll, "pull_from_peer", lambda peer, http_get: [])
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
    )

    assert len(checked) == 1


def test_gossip_cycle_obeys_total_time_budget(monkeypatch) -> None:
    import time
    import nth_dao.web.market_federation_poll as poll

    candidates = [f"https://node-{idx}.example" for idx in range(10)]
    monkeypatch.setattr(poll, "pull_from_peer", lambda peer, http_get: [])
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
        max_duration_s=0.001,
    )

    assert entries == {}
    assert len(checked) <= 1
    assert time.monotonic() - started < 0.2


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
        lambda peer, http_get: (
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
        verify_gossip_peer=lambda url, resolved_ip: True,
    )

    assert entries == {}
    assert pinned_calls == [
        (f"{C_URL}/api/v2/market/federation/digest", "93.184.216.34")
    ]


def test_gossip_identity_preflight_failure_is_fail_closed(monkeypatch) -> None:
    import nth_dao.web.market_federation_poll as poll

    monkeypatch.setattr(poll, "pull_from_peer", lambda peer, http_get: [])
    monkeypatch.setattr(
        poll,
        "fetch_peer_list",
        lambda peer, http_get: [C_URL] if peer == B_URL else [],
    )

    def unavailable(_url: str, _resolved_ip: str) -> bool:
        raise RuntimeError("identity service unavailable")

    entries = poll.federate_once(
        [B_URL],
        lambda _url: {},
        resolve=_resolve_public,
        verify_gossip_peer=unavailable,
    )

    assert entries == {}


def test_configured_seed_identity_preflight_can_fail_closed(monkeypatch) -> None:
    import nth_dao.web.market_federation_poll as poll

    pulled: list[str] = []

    def pull(peer, http_get):
        pulled.append(peer)
        return []

    monkeypatch.setattr(poll, "pull_from_peer", pull)
    monkeypatch.setattr(poll, "fetch_peer_list", lambda peer, http_get: [])

    entries = poll.federate_once(
        [B_URL],
        lambda _url: {},
        verify_seed_peer=lambda _url: False,
    )

    assert entries == {}
    assert pulled == []
