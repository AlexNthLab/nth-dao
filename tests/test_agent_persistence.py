"""Persistent supervised-agent identities and roster behavior."""
from __future__ import annotations

from pathlib import Path

import pytest


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
    )

    again = AgentRoster(tmp_path)
    rows = again.all()
    assert len(rows) == 1
    assert rows[0]["did"] == "did:key:zAAA"
    assert rows[0]["kind"] == "mock"
    assert rows[0]["identity_file"] == identity_file

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
