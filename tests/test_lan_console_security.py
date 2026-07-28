"""LAN federation must not leak the operator console token."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from nth_dao.web import create_app


def test_remote_console_html_does_not_embed_operator_token(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.setenv("NTH_CONSOLE_TOKEN_DIR", str(tmp_path / "token"))
    app = create_app(tmp_path / "workspace", require_console_auth=True)
    token = app.state.nth_console_token
    client = TestClient(
        app,
        base_url="http://192.168.50.20",
        client=("192.168.50.30", 50000),
    )

    response = client.get("/v2.html")

    assert response.status_code == 200
    assert token not in response.text
    assert "nth_console_token" in response.text


def test_loopback_console_html_keeps_local_operator_convenience(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.setenv("NTH_CONSOLE_TOKEN_DIR", str(tmp_path / "token"))
    app = create_app(tmp_path / "workspace", require_console_auth=True)
    token = app.state.nth_console_token
    client = TestClient(
        app,
        base_url="http://127.0.0.1",
        client=("127.0.0.1", 50000),
    )

    response = client.get("/v2.html")

    assert response.status_code == 200
    assert token in response.text


def test_reverse_proxy_does_not_receive_embedded_operator_token(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.setenv("NTH_CONSOLE_TOKEN_DIR", str(tmp_path / "token"))
    app = create_app(tmp_path / "workspace", require_console_auth=True)
    token = app.state.nth_console_token
    client = TestClient(
        app,
        base_url="https://dao.example",
        client=("127.0.0.1", 55000),
    )

    response = client.get(
        "/v2.html",
        headers={
            "X-Forwarded-For": "203.0.113.44",
            "X-Forwarded-Host": "dao.example",
            "X-Forwarded-Proto": "https",
        },
    )

    assert response.status_code == 200
    assert token not in response.text
    assert "nth_console_token" in response.text


@pytest.mark.parametrize(
    "header",
    ["X-Real-IP", "Via", "CF-Connecting-IP", "True-Client-IP"],
)
def test_common_proxy_headers_disable_console_token_embedding(
    tmp_path: Path, monkeypatch, header: str,
) -> None:
    monkeypatch.setenv("NTH_CONSOLE_TOKEN_DIR", str(tmp_path / "token"))
    app = create_app(tmp_path / "workspace", require_console_auth=True)
    client = TestClient(
        app,
        base_url="http://127.0.0.1",
        client=("127.0.0.1", 55000),
    )

    response = client.get("/v2.html", headers={header: "203.0.113.8"})

    assert response.status_code == 200
    assert app.state.nth_console_token not in response.text


def test_non_loopback_host_never_gets_token_even_from_loopback_peer(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.setenv("NTH_CONSOLE_TOKEN_DIR", str(tmp_path / "token"))
    app = create_app(tmp_path / "workspace", require_console_auth=True)
    client = TestClient(
        app,
        base_url="https://dao.example",
        client=("127.0.0.1", 55000),
    )

    response = client.get("/v2.html")

    assert response.status_code == 200
    assert app.state.nth_console_token not in response.text


def test_remote_console_reads_require_bearer_token(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.setenv("NTH_CONSOLE_TOKEN_DIR", str(tmp_path / "token"))
    app = create_app(tmp_path / "workspace", require_console_auth=True)
    client = TestClient(
        app,
        base_url="http://192.168.50.20",
        client=("192.168.50.30", 50000),
    )

    for path in (
        "/api/v2/channels",
        "/api/v2/decisions",
        "/api/v2/missions",
        "/api/v2/cap_tokens",
        "/api/v2/agents",
    ):
        assert client.get(path).status_code == 401, path

    headers = {"Authorization": f"Bearer {app.state.nth_console_token}"}
    assert client.get("/api/v2/channels", headers=headers).status_code == 200
    assert client.get("/api/v2/decisions", headers=headers).status_code == 200


def test_remote_federation_reads_remain_public(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.setenv("NTH_CONSOLE_TOKEN_DIR", str(tmp_path / "token"))
    app = create_app(tmp_path / "workspace", require_console_auth=True)
    client = TestClient(
        app,
        base_url="http://192.168.50.20",
        client=("192.168.50.30", 50000),
    )

    for path in (
        "/api/v2/health",
        "/api/v2/market/open",
        "/api/v2/market/categories",
        "/api/v2/market/federation/digest",
        "/api/v2/market/federation/pull",
        "/api/v2/market/federation/peers",
        "/api/v2/social/federation/pull",
    ):
        response = client.get(path)
        assert response.status_code == 200, (path, response.text)


def test_remote_channel_messages_are_not_anonymous(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.setenv("NTH_CONSOLE_TOKEN_DIR", str(tmp_path / "token"))
    app = create_app(tmp_path / "workspace", require_console_auth=True)
    client = TestClient(
        app,
        base_url="http://192.168.50.20",
        client=("192.168.50.30", 50000),
    )
    headers = {"Authorization": f"Bearer {app.state.nth_console_token}"}
    channels = client.get("/api/v2/channels", headers=headers).json()
    channel_id = channels[0]["channel_id"]
    posted = client.post(
        f"/api/v2/channels/{channel_id}/messages",
        headers=headers,
        json={"agent_id": "admin", "body": "private marker"},
    )
    assert posted.status_code == 200, posted.text

    assert client.get(f"/api/v2/channels/{channel_id}/messages").status_code == 401
    private = client.get(
        f"/api/v2/channels/{channel_id}/messages", headers=headers,
    )
    assert private.status_code == 200
    assert any(row["body"] == "private marker" for row in private.json())
