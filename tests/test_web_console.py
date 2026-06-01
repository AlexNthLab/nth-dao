from fastapi.testclient import TestClient

from nth_dao.web import create_app


def test_web_console_serves_typescript_frontend(tmp_path):
    client = TestClient(create_app(tmp_path))

    response = client.get("/")
    assert response.status_code == 200
    assert "NTH DAO Console" in response.text
    assert "/assets/" in response.text


def test_web_console_promotes_default_admin_for_existing_local_workspace(tmp_path):
    (tmp_path / "team.json").write_text(
        '{"team_name":"Existing DAO","join_policy":"open","admin_ids":[],"member_ids":["admin"],"roles":{"admin":"member"}}',
        encoding="utf-8",
    )
    client = TestClient(create_app(tmp_path))

    state = client.get("/api/state", params={"agent_id": "admin"})

    assert state.status_code == 200
    assert state.json()["actor"]["role"] == "owner"


def test_web_console_bootstraps_open_team_and_allows_member_message(tmp_path):
    client = TestClient(create_app(tmp_path))

    state = client.get("/api/state", params={"agent_id": "alice"})
    assert state.status_code == 200
    assert state.json()["actor"]["role"] == "member"

    sent = client.post(
        "/api/messages",
        json={"agent_id": "alice", "channel_id": "general", "body": "hello dao"},
    )
    assert sent.status_code == 200
    assert sent.json()["body"] == "hello dao"


def test_web_console_rejects_non_admin_announcement(tmp_path):
    client = TestClient(create_app(tmp_path))
    client.post("/api/join", json={"agent_id": "alice"})

    denied = client.post(
        "/api/announcements",
        json={
            "author_id": "alice",
            "channel_id": "general",
            "title": "Not allowed",
            "body": "members cannot post announcements",
        },
    )
    assert denied.status_code == 403

    allowed = client.post(
        "/api/announcements",
        json={
            "author_id": "admin",
            "channel_id": "general",
            "title": "Allowed",
            "body": "admins can post announcements",
        },
    )
    assert allowed.status_code == 200
    assert allowed.json()["title"] == "Allowed"


def test_web_console_rejects_task_update_from_unrelated_member(tmp_path):
    client = TestClient(create_app(tmp_path))
    client.post("/api/join", json={"agent_id": "alice"})
    client.post("/api/join", json={"agent_id": "bob"})

    created = client.post(
        "/api/tasks",
        json={
            "created_by": "alice",
            "channel_id": "general",
            "title": "Review protocol",
            "assignee_id": "alice",
        },
    )
    assert created.status_code == 200
    task_id = created.json()["task_id"]

    denied = client.patch(
        f"/api/tasks/{task_id}",
        json={"actor_id": "bob", "status": "completed"},
    )
    assert denied.status_code == 403

    allowed = client.patch(
        f"/api/tasks/{task_id}",
        json={"actor_id": "alice", "status": "completed"},
    )
    assert allowed.status_code == 200
    assert allowed.json()["status"] == "completed"
