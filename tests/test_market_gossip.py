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
    entries = federate_once([B_URL], http_get)
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

    entries = federate_once([B_URL], http_get, max_peers=8)  # 有环也必须收敛
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

    entries = federate_once([B_URL], http_get)
    assert entries == {}  # B 没任务,且坏 peer 一个都没被连
    assert all("node-b" in urlsplit(u).netloc for u in fetched)


def test_is_safe_gossip_url_unit() -> None:
    from nth_dao.web.market_federation_poll import _is_safe_gossip_url as ok
    assert ok("https://nodeC.trycloudflare.com")
    assert ok("https://1.2.3.4/")            # 公网 IP
    assert not ok("http://nodeC.example")    # 非 https
    assert not ok("https://localhost/")
    assert not ok("https://127.0.0.1/")
    assert not ok("http://169.254.169.254/")  # 链路本地 + http
    assert not ok("https://10.0.0.5/")        # 私网
    assert not ok("https://192.168.1.1/")
    assert not ok("https://[::1]/")           # ipv6 loopback
    assert not ok("not a url at all")
