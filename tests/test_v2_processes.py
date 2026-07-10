from pathlib import Path

from fastapi.testclient import TestClient

from nth_dao.web import create_app


def _auth_headers(app) -> dict[str, str]:
    return {"Authorization": f"Bearer {app.state.nth_console_token}"}


def test_v2_create_process_persists_to_blackboard(tmp_path: Path):
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)

    created = client.post(
        "/api/v2/processes",
        json={
            "title": "  Debug checkout flow  ",
            "workflow": "engineering",
            "subtitle": "Reproduce, patch, verify.",
            "current_agent": "codex",
        },
    )
    assert created.status_code == 200, created.text
    body = created.json()
    assert body["id"]
    assert not body["id"].startswith("p-local-")
    assert body["title"] == "Debug checkout flow"
    assert body["workflow"] == "engineering"
    assert body["subtitle"] == "Reproduce, patch, verify."
    assert body["current_agent"] == "codex"
    assert body["stage"] == "received"

    entry = app.state.nth.blackboard.get(body["id"], "shared")
    assert entry is not None
    assert entry.author == "admin"
    assert entry.metadata["current_agent"] == "codex"
    assert entry.metadata["created_by"] == "admin"

    listed = client.get("/api/v2/processes")
    assert listed.status_code == 200, listed.text
    rows = listed.json()
    assert any(row["id"] == body["id"] for row in rows)


def test_v2_create_process_rejects_unknown_stage(tmp_path: Path):
    client = TestClient(create_app(tmp_path, require_console_auth=False))

    response = client.post(
        "/api/v2/processes",
        json={
            "title": "Bad stage",
            "workflow": "qa",
            "current_agent": "codex",
            "stage": "mystery",
        },
    )
    assert response.status_code == 422


def test_v2_create_process_rejects_unknown_fields(tmp_path: Path):
    client = TestClient(create_app(tmp_path, require_console_auth=False))

    response = client.post(
        "/api/v2/processes",
        json={
            "title": "Extra field",
            "workflow": "qa",
            "current_agent": "codex",
            "unexpected": "should not be accepted",
        },
    )
    assert response.status_code == 422


def test_v2_create_process_respects_console_auth(tmp_path: Path):
    app = create_app(tmp_path, require_console_auth=True)
    client = TestClient(app)

    no_token = client.post(
        "/api/v2/processes",
        json={"title": "Secret work", "workflow": "ops", "current_agent": "admin"},
    )
    assert no_token.status_code == 401, no_token.text

    with_token = client.post(
        "/api/v2/processes",
        headers=_auth_headers(app),
        json={"title": "Secret work", "workflow": "ops", "current_agent": "admin"},
    )
    assert with_token.status_code == 200, with_token.text
