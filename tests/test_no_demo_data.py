"""Production web surfaces must never synthesize demonstration records."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from nth_dao.web import create_app
from nth_dao.web.agent_roster import AgentRoster
from nth_dao.web.legacy_demo_cleanup import purge_legacy_demo_state


SEED_DID = "did:key:z6MkpQ8eF1xRzL3tJyN5sWvD9XbA2C7uYkP4hM8kT6f3B"


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_fresh_workspace_has_no_synthetic_operational_records(tmp_path: Path) -> None:
    client = TestClient(create_app(tmp_path, require_console_auth=False))

    for endpoint in (
        "/api/v2/decisions",
        "/api/v2/missions",
        "/api/v2/processes",
        "/api/v2/receipts",
        "/api/v2/rules",
        "/api/v2/agents",
        "/api/v2/cap_tokens",
        "/api/v2/conversations",
        "/api/v2/messages/anything",
    ):
        response = client.get(endpoint)
        assert response.status_code == 200, (endpoint, response.text)
        assert response.json() == [], endpoint


def test_v2_identity_is_the_real_workspace_identity(tmp_path: Path) -> None:
    client = TestClient(create_app(tmp_path, require_console_auth=False))

    legacy = client.get("/api/identity", params={"actor_id": "admin"})
    current = client.get("/api/v2/identity")

    assert legacy.status_code == current.status_code == 200
    assert current.json()["did"] == legacy.json()["did"]
    assert current.json()["code"] == legacy.json()["code"]
    assert current.json()["did"] != (
        "did:key:z6MkmRxmBi9p9ziBz2JzBwd8Y5iMzzhPXAi95MPZiLEJJqjL"
    )


def test_mock_backend_is_hidden_without_explicit_test_mode(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.delenv("NTH_ENABLE_TEST_BACKENDS", raising=False)
    client = TestClient(create_app(tmp_path, require_console_auth=False))
    response = client.get("/api/v2/agents/backends/status")

    assert response.status_code == 200
    assert "mock" not in response.json()["backends"]


def test_cleanup_removes_only_exact_legacy_records(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    state = app.state.nth

    seed_identity = tmp_path / "team_agents" / "1f9c-44de" / "identity.json"
    _write_json(seed_identity, {"did": SEED_DID, "label": "code-helper"})
    lookalike = tmp_path / "team_agents" / "user-copy" / "identity.json"
    _write_json(lookalike, {"did": SEED_DID, "label": "user-owned"})

    roster = AgentRoster(tmp_path)
    mock_identity = Path(roster.allocate_identity_file())
    _write_json(mock_identity, {"agent_id": "test-only"})
    roster.add(
        identity_file=str(mock_identity),
        kind="mock",
        label="test-only",
        capabilities=[],
        did="did:key:zMock",
    )
    real_identity = Path(roster.allocate_identity_file())
    _write_json(real_identity, {"agent_id": "codex-real"})
    roster.add(
        identity_file=str(real_identity),
        kind="codex",
        label="codex-real",
        capabilities=["code"],
        did="did:key:zReal",
    )
    state.membership.ensure_member("echo-agent")

    marker = tmp_path / "migrations" / "legacy-demo-cleanup-v2.json"
    marker.unlink(missing_ok=True)
    first = purge_legacy_demo_state(state)
    second = purge_legacy_demo_state(state)

    assert not seed_identity.exists()
    quarantined_seed = (
        tmp_path
        / "migrations"
        / "legacy-demo-cleanup-v2"
        / "quarantine"
        / "team_agents"
        / "1f9c-44de"
        / "identity.json"
    )
    assert quarantined_seed.exists()
    assert lookalike.exists()
    assert mock_identity.exists()
    assert real_identity.exists()
    assert [row["kind"] for row in roster.all()] == ["mock", "codex"]
    assert "echo-agent" in state.membership.load_config().member_ids
    assert first["quarantined_count"] == 1
    assert second == first


def test_cleanup_does_not_follow_seed_path_symlink(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    state = app.state.nth
    external = tmp_path.parent / f"{tmp_path.name}-external-identity.json"
    _write_json(external, {"did": SEED_DID, "label": "code-helper"})
    seed_identity = tmp_path / "team_agents" / "1f9c-44de" / "identity.json"
    seed_identity.parent.mkdir(parents=True)
    try:
        seed_identity.symlink_to(external)
    except (OSError, NotImplementedError):
        return

    marker = tmp_path / "migrations" / "legacy-demo-cleanup-v2.json"
    marker.unlink(missing_ok=True)
    result = purge_legacy_demo_state(state)

    assert external.exists()
    assert seed_identity.is_symlink()
    assert result["quarantined_count"] == 0


def test_cleanup_failure_is_not_marked_complete_and_retries(
    tmp_path: Path,
) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    state = app.state.nth
    source = tmp_path / "team_agents" / "1f9c-44de" / "identity.json"
    _write_json(source, {"did": SEED_DID, "label": "code-helper"})
    target = (
        tmp_path
        / "migrations"
        / "legacy-demo-cleanup-v2"
        / "quarantine"
        / "team_agents"
        / "1f9c-44de"
        / "identity.json"
    )
    _write_json(target, {"different": True})
    marker = tmp_path / "migrations" / "legacy-demo-cleanup-v2.json"
    marker.unlink(missing_ok=True)

    first = purge_legacy_demo_state(state)

    assert first["completed"] is False
    assert first["failures"] == ["team_agents/1f9c-44de/identity.json"]
    assert source.exists()
    assert not marker.exists()

    target.unlink()
    second = purge_legacy_demo_state(state)

    assert second["completed"] is True
    assert second["failures"] == []
    assert not source.exists()
    assert marker.exists()


def test_workspace_readers_do_not_resurrect_repository_fixtures(
    tmp_path: Path,
) -> None:
    from nth_dao.web import v2_api

    assert v2_api._candidate_dirs(tmp_path / "workspace", "team_agents") == [
        tmp_path / "workspace" / "team_agents"
    ]


def test_agent_startup_does_not_raise_operator_decision() -> None:
    import inspect
    from nth_dao.web import dummy_agent

    assert "Acknowledge agent" not in inspect.getsource(dummy_agent.main)


def test_public_agent_listing_redacts_local_workspace_path(tmp_path: Path) -> None:
    class _Record:
        kind = "codex"
        cap_token_id = None

        @staticmethod
        def to_agent_entry() -> dict[str, object]:
            return {
                "agent_id": "local-worker",
                "did": "did:key:zLocalWorker",
                "code": "LOCALWORK",
                "label": "local worker",
                "source": "local",
                "capabilities": [],
                "has_active_cap": False,
                "supervised": True,
                "alive": True,
                "kind": "codex",
                "work_scope_id": "scope-a1",
                "work_scope_root": r"X:\synthetic-fixture\secret-project",
                "work_access": "read-only",
                "work_revision": "abc123",
            }

    class _Supervisor:
        @staticmethod
        def list_agents() -> list[_Record]:
            return [_Record()]

    app = create_app(tmp_path, require_console_auth=False)
    app.state.v2_supervisor = _Supervisor()
    client = TestClient(app)

    public_row = client.get("/api/v2/agents").json()[0]
    assert "work_scope_root" not in public_row
    assert public_row["work_scope_id"] == "scope-a1"

    token = app.state.nth_console_token
    private_row = client.get(
        "/api/v2/agents",
        headers={"Authorization": f"Bearer {token}"},
    ).json()[0]
    assert private_row["work_scope_root"] == (
        r"X:\synthetic-fixture\secret-project"
    )
