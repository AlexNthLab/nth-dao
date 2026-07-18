"""Phase 2d:/market/open 事实源切换(feed↔spine)的等价性 + reconcile 端点。"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("nacl")

from fastapi.testclient import TestClient

from nth_dao.web import create_app
from nth_dao.market.claim import ClaimStore
from nth_dao.util.io import atomic_write_json


def _open_ids(client: TestClient) -> set:
    return {a["announcement_id"] for a in client.get("/api/v2/market/open").json()}


def test_open_identical_feed_vs_spine_and_reconcile(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("NTH_MARKET_READ_SOURCE", raising=False)
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)

    want = set()
    for title in ("t1", "t2", "t3"):
        r = client.post("/api/v2/market/announce", json={
            "title": title, "capability_set": ["code_review"], "reward_minor": 2})
        assert r.status_code == 200, r.text
        want.add(r.json()["announcement_id"])

    # 默认 feed 源。
    assert _open_ids(client) == want

    # 切 spine 源 → **同一结果**(双写保证一致)。
    monkeypatch.setenv("NTH_MARKET_READ_SOURCE", "spine")
    assert _open_ids(client) == want

    # 对账 in_sync。
    rec = client.get("/api/v2/market/reconcile").json()
    assert rec["available"] is True
    assert rec["active_source"] == "spine"
    assert rec["in_sync"] is True, rec
    assert rec["feed_open"] == rec["spine_open"] == 3


def test_reconcile_unavailable_without_market(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("NTH_MARKET_READ_SOURCE", raising=False)
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)
    rec = client.get("/api/v2/market/reconcile").json()
    assert rec["available"] is False   # 还没发过任务,无 feed 文件


def test_spine_source_fails_safe_to_feed(tmp_path: Path, monkeypatch) -> None:
    # spine 缺失时 source=spine 仍 fail-safe 回退 feed,绝不中断市场。
    monkeypatch.delenv("NTH_MARKET_READ_SOURCE", raising=False)
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)
    r = client.post("/api/v2/market/announce", json={
        "title": "t", "capability_set": ["x"], "reward_minor": 0})
    aid = r.json()["announcement_id"]

    app.state.nth.spine = None              # 模拟 spine 缺失
    monkeypatch.setenv("NTH_MARKET_READ_SOURCE", "spine")
    assert aid in _open_ids(client)         # 回退 feed,照常可见


def test_corrupt_claim_slot_is_hidden_by_both_sources_and_breaks_reconcile(
    tmp_path: Path, monkeypatch,
) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)
    response = client.post(
        "/api/v2/market/announce",
        json={"title": "claimed?", "capability_set": []},
    )
    aid = response.json()["announcement_id"]
    store = ClaimStore(tmp_path)
    atomic_write_json(store._path(aid), {
        "announcement_id": aid,
        "status": "claimed",
        "claimant_did": "did:key:forged",
    })

    monkeypatch.delenv("NTH_MARKET_READ_SOURCE", raising=False)
    assert aid not in _open_ids(client)
    monkeypatch.setenv("NTH_MARKET_READ_SOURCE", "spine")
    assert aid not in _open_ids(client)
    report = client.get("/api/v2/market/reconcile").json()
    assert report["in_sync"] is False
    assert report["corrupt_claim_slots"] == [aid]
