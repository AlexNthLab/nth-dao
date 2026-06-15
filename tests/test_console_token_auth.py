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


def test_frontend_html_omits_token_when_disabled(tmp_path: Path, monkeypatch):
    """方案 D:NTH_CONSOLE_TOKEN_IN_PAGE=0 → 页面**不含**明文 token,改用引导
    脚本(localStorage + 角落按钮)。写接口仍受同一 token 鉴权(带外分发)。"""
    monkeypatch.setenv("NTH_CONSOLE_TOKEN", "secret-write-token-xyz")
    monkeypatch.setenv("NTH_CONSOLE_TOKEN_IN_PAGE", "0")
    app = create_app(tmp_path, require_console_auth=True)
    client = TestClient(app)

    r = client.get("/")
    assert r.status_code == 200
    # 关键:明文 token 绝不出现在页面。
    assert "secret-write-token-xyz" not in r.text
    # 引导脚本在位(从 localStorage 取 + 设置/清除按钮)。
    assert "nth_console_token" in r.text
    assert "nthSetToken" in r.text

    # 写接口仍受同一 token 鉴权:无 token 401,带外拿到 token 后照常用。
    no_tok = client.post(
        "/api/v2/agents/spawn",
        json={"kind": "mock", "label": "x", "capabilities": []},
    )
    assert no_tok.status_code == 401, no_tok.text
    with_tok = client.post(
        "/api/v2/agents/spawn",
        json={"kind": "mock", "label": "y", "capabilities": []},
        headers={"Authorization": "Bearer secret-write-token-xyz"},
    )
    assert with_tok.status_code != 401, with_tok.text


def test_render_console_html_embed_flag(tmp_path: Path):
    """单元:embed_token 控制是否内嵌 token。"""
    from nth_dao.web import _render_console_html
    f = tmp_path / "i.html"
    f.write_text("<html><head></head><body></body></html>", encoding="utf-8")

    on = _render_console_html(f, "TOK123", embed_token=True)
    assert "TOK123" in on and "__NTH_CONSOLE_TOKEN__" in on

    off = _render_console_html(f, "TOK123", embed_token=False)
    assert "TOK123" not in off                       # 不内嵌明文 token
    assert "nth_console_token" in off and "nthSetToken" in off


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
