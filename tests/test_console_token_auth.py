from pathlib import Path

from fastapi.testclient import TestClient

from nth_dao.web import create_app


def _auth_headers(app) -> dict[str, str]:
    return {"Authorization": f"Bearer {app.state.nth_console_token}"}


def test_api_requires_console_bearer_token(tmp_path: Path):
    app = create_app(tmp_path, require_console_auth=True)
    client = TestClient(app)

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
    client = TestClient(app)

    response = client.get(
        "/api/build_id",
        params={"actor_id": "stranger"},
        headers=_auth_headers(app),
    )
    assert response.status_code == 403


def test_frontend_html_injects_console_token(tmp_path: Path):
    app = create_app(tmp_path, require_console_auth=True)
    client = TestClient(app)

    response = client.get("/")
    assert response.status_code == 200
    assert "window.__NTH_CONSOLE_TOKEN__" in response.text
    assert app.state.nth_console_token in response.text


def test_v2_read_open_but_action_gated_under_auth(tmp_path: Path):
    """2026-06-13 hardening regression: under console auth, the v2
    READ surface (GET) stays anonymous-open, but v2 ACTION endpoints
    (POST spawn / stop / ask) must NOT ride the anonymous bypass —
    an unauthenticated caller (incl. a CSRF POST) must not be able to
    drive a spawned agent under its delegated cap_token authority.
    """
    app = create_app(tmp_path, require_console_auth=True)
    client = TestClient(app)

    # READ: anonymous-open even with no token.
    read = client.get("/api/v2/agents")
    assert read.status_code == 200, read.text

    # ACTION without token: rejected at the auth middleware (401),
    # BEFORE reaching the handler — so it never spawns / drives.
    no_tok = client.post(
        "/api/v2/agents/spawn",
        json={"kind": "mock", "label": "x", "capabilities": []},
    )
    assert no_tok.status_code == 401, no_tok.text

    ask_no_tok = client.post(
        "/api/v2/agents/did:key:zStranger/ask-stream",
        json={"prompt": "drive me for free"},
    )
    assert ask_no_tok.status_code == 401, ask_no_tok.text

    # ACTION with the operator's console token: passes the auth gate
    # (status is no longer 401 — handler-level result may vary).
    with_tok = client.post(
        "/api/v2/agents/spawn",
        json={"kind": "mock", "label": "y", "capabilities": []},
        headers=_auth_headers(app),
    )
    assert with_tok.status_code != 401, with_tok.text
