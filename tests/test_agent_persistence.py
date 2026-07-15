"""Persistent supervised-agent identities and roster behavior."""
from __future__ import annotations
import json

from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient


def test_roster_add_all_remove_roundtrip(tmp_path: Path) -> None:
    from nth_dao.web.agent_roster import AgentRoster

    roster = AgentRoster(tmp_path)
    assert roster.all() == []
    identity_file = roster.allocate_identity_file()
    assert identity_file.endswith("identity.json")
    assert roster.is_owned_identity_file(identity_file)

    roster.add(
        identity_file=identity_file,
        kind="mock",
        label="worker-one",
        capabilities=["nth-dao.chat"],
        did="did:key:zAAA",
        project_workdir=str(tmp_path),
        work_access="read-only",
        work_revision="abc123",
    )

    again = AgentRoster(tmp_path)
    rows = again.all()
    assert len(rows) == 1
    assert rows[0]["did"] == "did:key:zAAA"
    assert rows[0]["kind"] == "mock"
    assert rows[0]["identity_file"] == identity_file
    assert rows[0]["project_workdir"] == str(tmp_path)
    assert rows[0]["work_access"] == "read-only"
    assert rows[0]["work_revision"] == "abc123"
    assert rows[0]["enabled"] is True
    assert rows[0]["slot_id"]

    identity_path = Path(identity_file)
    identity_path.parent.mkdir(parents=True, exist_ok=True)
    identity_path.write_text("private identity stays", encoding="utf-8")
    disabled = again.disable_by_did("did:key:zAAA")
    assert disabled is not None
    assert disabled["enabled"] is False
    assert identity_path.read_text(encoding="utf-8") == "private identity stays"
    assert AgentRoster(tmp_path).all()[0]["enabled"] is False

    removed = again.remove_by_did("did:key:zAAA")
    assert removed is not None
    assert removed["identity_file"] == identity_file
    assert AgentRoster(tmp_path).all() == []


def test_roster_add_dedups_by_identity_file(tmp_path: Path) -> None:
    from nth_dao.web.agent_roster import AgentRoster

    roster = AgentRoster(tmp_path)
    identity_file = roster.allocate_identity_file()
    roster.add(identity_file=identity_file, kind="mock", label="a", capabilities=[], did="d1")
    roster.add(identity_file=identity_file, kind="mock", label="b", capabilities=[], did="d1")
    assert len(roster.all()) == 1


def test_roster_corrupt_file_is_failsafe(tmp_path: Path) -> None:
    from nth_dao.web.agent_roster import AgentRoster

    agents_dir = tmp_path / "agents"
    agents_dir.mkdir(parents=True)
    (agents_dir / "roster.json").write_text("{ not json", encoding="utf-8")
    assert AgentRoster(tmp_path).all() == []


def test_roster_rejects_identity_file_outside_owned_tree(tmp_path: Path) -> None:
    from nth_dao.web.agent_roster import AgentRoster

    roster = AgentRoster(tmp_path)
    outside = tmp_path / "outside" / "identity.json"
    outside.parent.mkdir()
    outside.write_text("not a real key", encoding="utf-8")

    assert not roster.is_owned_identity_file(str(outside))
    with pytest.raises(ValueError, match="agents/identities"):
        roster.add(
            identity_file=str(outside),
            kind="mock",
            label="bad",
            capabilities=[],
            did="did:key:zBAD",
        )


def test_roster_cleanup_only_removes_owned_identity_dir(tmp_path: Path) -> None:
    from nth_dao.web.agent_roster import AgentRoster

    roster = AgentRoster(tmp_path)
    outside = tmp_path / "keep" / "identity.json"
    outside.parent.mkdir()
    outside.write_text("not a real key", encoding="utf-8")

    assert roster.cleanup_identity_dir(str(outside)) is False
    assert outside.exists()

    owned = Path(roster.allocate_identity_file())
    owned.parent.mkdir(parents=True)
    owned.write_text("not a real key", encoding="utf-8")
    assert roster.cleanup_identity_dir(str(owned)) is True
    assert not owned.parent.exists()


def test_restore_all_enabled_persistent_slots_even_for_same_backend(tmp_path: Path) -> None:
    from nth_dao.web.agent_roster import AgentRoster
    from nth_dao.web.v2_api import _restore_persistent_agents

    roster = AgentRoster(tmp_path)
    for kind, label, did in (
        ("hermes", "old-hermes", "did:key:zOldHermes"),
        ("codex", "codex", "did:key:zCodex"),
        ("hermes", "new-hermes", "did:key:zNewHermes"),
    ):
        identity_file = Path(roster.allocate_identity_file())
        identity_file.parent.mkdir(parents=True)
        identity_file.write_text("placeholder", encoding="utf-8")
        roster.add(
            identity_file=str(identity_file),
            kind=kind,
            label=label,
            capabilities=[],
            did=did,
        )

    spawned: list[dict] = []

    class FakeSupervisor:
        def spawn(self, **kwargs):
            spawned.append(kwargs)

    nth = SimpleNamespace(
        workspace=tmp_path,
        node_identity=SimpleNamespace(can_sign=True),
        cap_tokens=object(),
    )
    request = SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(nth=nth)),
    )

    _restore_persistent_agents(request, FakeSupervisor())

    assert {(row["kind"], row["label"]) for row in spawned} == {
        ("hermes", "old-hermes"),
        ("codex", "codex"),
        ("hermes", "new-hermes"),
    }


def test_restore_skips_disabled_slot_without_deleting_identity(tmp_path: Path) -> None:
    from nth_dao.web.agent_roster import AgentRoster
    from nth_dao.web.v2_api import _restore_persistent_agents

    roster = AgentRoster(tmp_path)
    identity_file = Path(roster.allocate_identity_file())
    identity_file.parent.mkdir(parents=True)
    identity_file.write_text("placeholder", encoding="utf-8")
    roster.add(
        identity_file=str(identity_file), kind="hermes", label="stopped",
        capabilities=[], did="did:key:zStopped",
    )
    roster.disable_by_did("did:key:zStopped")
    spawned: list[dict] = []

    class FakeSupervisor:
        def spawn(self, **kwargs):
            spawned.append(kwargs)

    nth = SimpleNamespace(
        workspace=tmp_path,
        node_identity=SimpleNamespace(can_sign=True),
        cap_tokens=object(),
    )
    request = SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(nth=nth)),
    )

    _restore_persistent_agents(request, FakeSupervisor())

    assert spawned == []
    assert identity_file.exists()


def test_legacy_duplicate_backend_rows_migrate_once_to_explicit_slots(
    tmp_path: Path,
) -> None:
    from nth_dao.web.agent_roster import AgentRoster

    agents_dir = tmp_path / "agents"
    agents_dir.mkdir(parents=True)
    rows = [
        {"kind": "hermes", "did": "did:key:zOld", "identity_file": "old"},
        {"kind": "hermes", "did": "did:key:zNew", "identity_file": "new"},
    ]
    (agents_dir / "roster.json").write_text(
        json.dumps({"agents": rows}), encoding="utf-8",
    )

    roster = AgentRoster(tmp_path)
    migrated = roster.migrate_legacy_slots()

    assert all(row.get("slot_id") for row in migrated)
    assert migrated[0]["enabled"] is False
    assert migrated[0]["disabled_reason"] == "legacy-kind-dedup-migration"
    assert migrated[1]["enabled"] is True
    assert roster.migrate_legacy_slots() == migrated


def test_stop_endpoint_disables_persistent_slot_instead_of_removing_it(
    tmp_path: Path,
) -> None:
    from nth_dao.web import create_app
    from nth_dao.web.agent_roster import AgentRoster
    from nth_dao.web.agent_supervisor import AgentSupervisor, InMemoryRunner

    app = create_app(tmp_path, require_console_auth=False)
    app.state.v2_supervisor = AgentSupervisor(InMemoryRunner())
    client = TestClient(app)
    spawned = client.post(
        "/api/v2/agents/spawn",
        json={"kind": "mock", "label": "durable", "persist": True},
    )
    assert spawned.status_code == 201, spawned.text
    body = spawned.json()

    stopped = client.post(f"/api/v2/agents/{body['agent_id']}/stop")

    assert stopped.status_code == 200, stopped.text
    rows = AgentRoster(tmp_path).all()
    assert len(rows) == 1
    assert rows[0]["did"] == body["did"]
    assert rows[0]["enabled"] is False
    assert rows[0]["disabled_reason"] == "operator-stop"


def test_subprocess_stable_did_across_restart(tmp_path: Path) -> None:
    pytest.importorskip("nacl")
    from nth_dao.web.agent_supervisor import SubprocessRunner

    identity_file = str(tmp_path / "agent_identity.json")
    first = SubprocessRunner()
    _, did1 = first.start("agent-1", "mock", identity_file=identity_file)
    try:
        assert did1
        assert Path(identity_file).exists()
    finally:
        first.stop("agent-1")

    second = SubprocessRunner()
    _, did2 = second.start("agent-2", "mock", identity_file=identity_file)
    try:
        assert did2 == did1
    finally:
        second.stop("agent-2")


def test_subprocess_no_identity_file_is_ephemeral(tmp_path: Path) -> None:
    pytest.importorskip("nacl")
    from nth_dao.web.agent_supervisor import SubprocessRunner

    runner = SubprocessRunner()
    _, did1 = runner.start("e1", "mock")
    runner.stop("e1")
    _, did2 = runner.start("e2", "mock")
    runner.stop("e2")
    assert did1 and did2 and did1 != did2
