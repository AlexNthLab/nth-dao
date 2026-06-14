"""FED-1:任务市场联邦传输层(serve 侧 HTTP 端点)。

federation.py 的数据模型/验签已有 test_market_federation.py 覆盖;本文件
只测把它包成 HTTP 的两个 serve 端点 —— digest(签名摘要)+ pull(全文)。
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from nth_dao.identity import crypto_available
from nth_dao.market.announcement import TaskAnnouncement, verify_announcement
from nth_dao.market.federation import FeedDigest, verify_digest
from nth_dao.web import create_app

pytestmark = pytest.mark.skipif(
    not crypto_available(), reason="PyNaCl needed (digest/announcement signing)"
)

from fastapi.testclient import TestClient


def test_empty_node_digest_is_signed(tmp_path: Path) -> None:
    # 从不发活的节点被对端轮询 digest:返回签名的空 digest,且不造 market_feed/。
    c = TestClient(create_app(tmp_path, require_console_auth=False))
    d = FeedDigest.from_dict(c.get("/api/v2/market/federation/digest").json())
    ok, why = verify_digest(d)
    assert ok, why
    assert d.refs == []
    assert not (tmp_path / "market_feed").exists()  # 无副作用


def test_digest_and_pull_roundtrip(tmp_path: Path) -> None:
    c = TestClient(create_app(tmp_path, require_console_auth=False))
    an = c.post(
        "/api/v2/market/announce",
        json={"title": "fed task", "capability_set": ["code_review"], "reward_minor": 10},
    )
    assert an.status_code == 200, an.text
    aid = an.json()["announcement_id"]

    # digest:provenance 验签通过,且含该公告的 ref。
    d = FeedDigest.from_dict(c.get("/api/v2/market/federation/digest").json())
    ok, why = verify_digest(d)
    assert ok, why
    assert any(r.get("announcement_id") == aid for r in d.refs)
    # ref 是"不可信提示",不带 publisher_sig。
    ref = next(r for r in d.refs if r["announcement_id"] == aid)
    assert "publisher_sig" not in ref

    # 按 id 拉全文:返回完整且 publisher_sig 自验通过的公告(信任真相层)。
    full = c.get(f"/api/v2/market/federation/pull?ids={aid}").json()
    assert len(full) == 1
    ann = TaskAnnouncement.from_dict(full[0])
    vok, vwhy = verify_announcement(ann)
    assert vok, vwhy
    assert ann.announcement_id == aid


def test_pull_unknown_id_skipped(tmp_path: Path) -> None:
    c = TestClient(create_app(tmp_path, require_console_auth=False))
    c.post("/api/v2/market/announce", json={"title": "x", "capability_set": []})
    # 不存在的 id 静默略过 → 空列表(拉方据此丢弃对应 ref)。
    assert c.get("/api/v2/market/federation/pull?ids=deadbeef").json() == []
    # 空 ids → []。
    assert c.get("/api/v2/market/federation/pull").json() == []
