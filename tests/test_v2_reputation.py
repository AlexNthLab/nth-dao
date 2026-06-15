"""信誉端点:/api/v2/reputation 从 spine 派生(发布计入 publisher)。"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("nacl")

from fastapi.testclient import TestClient

from nth_dao.web import create_app


def test_reputation_endpoint(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)
    for title in ("t1", "t2"):
        r = client.post("/api/v2/market/announce", json={
            "title": title, "capability_set": ["x"], "reward_minor": 0})
        assert r.status_code == 200, r.text

    lst = client.get("/api/v2/reputation").json()
    # 发布者 = 本节点身份 → tasks_published == 2。
    assert any(x["tasks_published"] == 2 for x in lst)
    assert all("score" in x for x in lst)

    one = client.get("/api/v2/reputation/did:key:zNobody").json()
    assert one["score"] == 0 and one["tasks_claimed"] == 0


def test_reputation_empty(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)
    assert client.get("/api/v2/reputation").json() == []
