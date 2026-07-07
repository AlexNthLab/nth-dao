"""FED-2:任务市场联邦拉取侧 + market/open 合并(跨节点发现)。

不起真 socket:用可注入的 http_get 把"对端 hub"路由到第二个 TestClient
节点。验证 PC-A 看不到 PC-B 任务的根因被解决 —— B 发任务,A 经联邦拉到。
"""
from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from nth_dao.identity import crypto_available
from nth_dao.market.announcement import verify_announcement
from nth_dao.web import create_app
from nth_dao.web.market_federation_poll import (
    FederationCache, federate_once, pull_from_peer,
)

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


def test_pull_from_peer_returns_verified(tmp_path: Path) -> None:
    b = TestClient(create_app(tmp_path / "b", require_console_auth=False))
    an = b.post(
        "/api/v2/market/announce",
        json={"title": "B task", "capability_set": ["code_review"], "reward_minor": 7},
    )
    aid = an.json()["announcement_id"]

    anns = pull_from_peer("https://peer-b.example", _http_get_via(b))
    got = [a for a in anns if a.announcement_id == aid]
    assert got, "联邦拉取应拿到 B 的公告"
    assert verify_announcement(got[0])[0]  # 全文 publisher_sig 验过


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
    entries = federate_once(["https://peer-b.example"], _http_get_via(b))
    assert aid in entries
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
    aid = b.post(
        "/api/v2/market/announce",
        json={
            "title": "remote DAO service pack",
            "listing_type": "service",
            "capability_set": ["debug"],
            "reward_minor": 500,
        },
    ).json()["announcement_id"]

    a_app = create_app(tmp_path / "a", require_console_auth=False)
    a = TestClient(a_app)
    entries = federate_once(["https://peer-b.example"], _http_get_via(b))
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
    entries = federate_once(["https://peer-b.example"], _http_get_via(b))
    for aid in ids:
        assert aid in entries, f"翻页应覆盖 {aid}"
    assert len(entries) == 5


def test_unsigned_or_bad_peer_yields_nothing(tmp_path: Path) -> None:
    # 对端返回垃圾(验签失败)→ 一条都不收(fail-closed)。
    def bad_get(url: str):
        if url.endswith("/digest"):
            return {"source_did": "did:key:zBOGUS", "refs": [], "digest_sig": "AA"}
        return []
    assert pull_from_peer("https://evil.example", bad_get) == []
    assert federate_once(["https://evil.example"], bad_get) == {}
