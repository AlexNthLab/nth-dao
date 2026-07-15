from pathlib import Path

from fastapi.testclient import TestClient

from nth_dao.web import create_app


def _auth_headers(app) -> dict[str, str]:
    return {"Authorization": f"Bearer {app.state.nth_console_token}"}


def _assert_supervisor_stopped(app) -> None:
    supervisor = getattr(app.state, "v2_supervisor", None)
    if supervisor is not None:
        assert all(not agent.alive for agent in supervisor.list_agents())


def test_api_requires_console_bearer_token(tmp_path: Path):
    app = create_app(tmp_path, require_console_auth=True)
    with TestClient(app) as client:
        missing = client.get("/api/summary", params={"actor_id": "admin"})
        assert missing.status_code == 401

        wrong = client.get(
            "/api/summary",
            params={"actor_id": "admin"},
            headers={"Authorization": "Bearer wrong"},
        )
        assert wrong.status_code == 401

        ok = client.get(
            "/api/summary",
            params={"actor_id": "admin"},
            headers=_auth_headers(app),
        )
        assert ok.status_code == 200


def test_actor_id_remains_authorization_not_authentication(tmp_path: Path):
    app = create_app(tmp_path, require_console_auth=True)
    with TestClient(app) as client:
        response = client.get(
            "/api/build_id",
            params={"actor_id": "stranger"},
            headers=_auth_headers(app),
        )
        assert response.status_code == 403


def test_frontend_html_injects_console_token(tmp_path: Path):
    app = create_app(tmp_path, require_console_auth=True)
    with TestClient(app) as client:
        response = client.get("/")
        assert response.status_code == 200
        assert "window.__NTH_CONSOLE_TOKEN__" in response.text
        assert app.state.nth_console_token in response.text


def test_frontend_html_omits_token_when_disabled(tmp_path: Path, monkeypatch):
    """Disabled page embedding must not weaken API authentication."""
    monkeypatch.setenv("NTH_CONSOLE_TOKEN", "secret-write-token-xyz")
    monkeypatch.setenv("NTH_CONSOLE_TOKEN_IN_PAGE", "0")
    app = create_app(tmp_path, require_console_auth=True)

    with TestClient(app) as client:
        response = client.get("/")
        assert response.status_code == 200
        assert "secret-write-token-xyz" not in response.text
        assert "nth_console_token" in response.text
        assert "nthSetToken" in response.text

        no_token = client.post(
            "/api/v2/agents/spawn",
            json={"kind": "mock", "label": "x", "capabilities": []},
        )
        assert no_token.status_code == 401, no_token.text

        with_token = client.post(
            "/api/v2/agents/spawn",
            json={"kind": "mock", "label": "y", "capabilities": []},
            headers={"Authorization": "Bearer secret-write-token-xyz"},
        )
        assert with_token.status_code != 401, with_token.text

    _assert_supervisor_stopped(app)


def test_render_console_html_embed_flag(tmp_path: Path):
    from nth_dao.web import _render_console_html

    html = tmp_path / "index.html"
    html.write_text("<html><head></head><body></body></html>", encoding="utf-8")

    embedded = _render_console_html(html, "TOK123", embed_token=True)
    assert "TOK123" in embedded
    assert "__NTH_CONSOLE_TOKEN__" in embedded

    omitted = _render_console_html(html, "TOK123", embed_token=False)
    assert "TOK123" not in omitted
    assert "nth_console_token" in omitted
    assert "nthSetToken" in omitted


def test_v2_read_open_but_action_gated_under_auth(tmp_path: Path):
    """Anonymous reads stay open while every agent-driving action is gated."""
    app = create_app(tmp_path, require_console_auth=True)

    with TestClient(app) as client:
        read = client.get("/api/v2/agents")
        assert read.status_code == 200, read.text

        no_token = client.post(
            "/api/v2/agents/spawn",
            json={"kind": "mock", "label": "x", "capabilities": []},
        )
        assert no_token.status_code == 401, no_token.text

        ask_without_token = client.post(
            "/api/v2/agents/did:key:zStranger/ask-stream",
            json={"prompt": "drive me for free"},
        )
        assert ask_without_token.status_code == 401, ask_without_token.text

        with_token = client.post(
            "/api/v2/agents/spawn",
            json={"kind": "mock", "label": "y", "capabilities": []},
            headers=_auth_headers(app),
        )
        assert with_token.status_code != 401, with_token.text

    _assert_supervisor_stopped(app)
