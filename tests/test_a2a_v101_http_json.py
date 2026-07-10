"""A2A v1.0.1 HTTP+JSON conformance smoke tests."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from nth_dao.identity import crypto_available
from nth_dao.web import create_app


pytestmark = pytest.mark.skipif(
    not crypto_available(),
    reason="A2A v1.0.1 HTTP+JSON tests require PyNaCl-backed identity",
)


def _client(tmp_path, monkeypatch, *, require_auth: bool = False) -> TestClient:
    monkeypatch.setenv("NTH_LAN_PUBLISH", "0")
    return TestClient(create_app(tmp_path, require_console_auth=require_auth))


def _message(text: str = "hello") -> dict:
    return {
        "message": {
            "role": "ROLE_USER",
            "parts": [{"text": text, "mediaType": "text/plain"}],
        },
        "configuration": {"returnImmediately": True},
    }


def test_agent_card_v101_alias_declares_http_json_first(tmp_path, monkeypatch) -> None:
    client = _client(tmp_path, monkeypatch)
    resp = client.get("/.well-known/agent-card.json")
    assert resp.status_code == 200
    assert resp.headers["A2A-Version"] == "1.0.1"
    body = resp.json()
    assert "supportedInterfaces" in body
    assert "supported_interfaces" not in body
    first = body["supportedInterfaces"][0]
    assert first["protocolBinding"] == "HTTP+JSON"
    assert first["protocolVersion"] == "1.0.1"
    assert first["url"].startswith("http://")
    assert any(
        iface["protocolBinding"] == "JSONRPC"
        and iface["url"].endswith("/api/a2a/rpc")
        for iface in body["supportedInterfaces"]
    )


def test_http_json_message_send_get_list_cancel_roundtrip(tmp_path, monkeypatch) -> None:
    client = _client(tmp_path, monkeypatch)
    headers = {"A2A-Version": "1.0.1", "Content-Type": "application/a2a+json"}

    sent = client.post("/message:send", json=_message("start"), headers=headers)
    assert sent.status_code == 200, sent.text
    assert sent.headers["A2A-Version"] == "1.0.1"
    assert sent.headers["content-type"].startswith("application/a2a+json")
    task = sent.json()["task"]
    task_id = task["id"]
    assert task["status"]["state"] == "TASK_STATE_SUBMITTED"

    got = client.get(f"/tasks/{task_id}?historyLength=0", headers={"A2A-Version": "1.0.1"})
    assert got.status_code == 200, got.text
    got_task = got.json()
    assert got_task["id"] == task_id
    assert got_task["history"] == []

    listed = client.get("/tasks?pageSize=10", headers={"A2A-Version": "1.0.1"})
    assert listed.status_code == 200, listed.text
    listed_body = listed.json()
    assert listed_body["totalSize"] >= 1
    assert any(t["id"] == task_id for t in listed_body["tasks"])
    assert "nextPageToken" in listed_body

    canceled = client.post(f"/tasks/{task_id}:cancel", json={}, headers=headers)
    assert canceled.status_code == 200, canceled.text
    assert canceled.json()["status"]["state"] == "TASK_STATE_CANCELED"


def test_http_json_rejects_incompatible_major_version(tmp_path, monkeypatch) -> None:
    client = _client(tmp_path, monkeypatch)
    resp = client.post("/message:send", json=_message(), headers={"A2A-Version": "2.0"})
    assert resp.status_code == 400
    body = resp.json()
    assert body["error"]["data"] == {"requested": "2.0", "supported": "1.0.1"}


def test_http_json_root_actions_share_console_auth_gate(tmp_path, monkeypatch) -> None:
    client = _client(tmp_path, monkeypatch, require_auth=True)
    assert client.get("/.well-known/agent-card.json").status_code == 200
    assert client.post("/message:send", json=_message()).status_code == 401
