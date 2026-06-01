"""v0.9.4 — Forward-compat: older on-disk artifacts MUST load under current code.

For each fixture under tests/migration_fixtures/<version>/, the runner
calls the appropriate `from_dict()` on the current implementation and
asserts the load succeeds without raising and preserves the fields
the older version DID set.

This is the canonical anti-regression for the migration contract documented
in docs/MIGRATIONS.md.
"""

import json
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "migration_fixtures"


def _load_json(path: Path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.mark.parametrize("version", ["0.9.0", "0.9.2", "0.9.3"])
def test_v090_mission_loads_under_current_code(version):
    """A pre-current mission file must parse cleanly via Mission.from_dict."""
    fixture = FIXTURES_DIR / version / "mission.json"
    if not fixture.exists():
        pytest.skip(f"no mission fixture for {version}")
    data = _load_json(fixture)
    from nth_dao.orchestration import Mission
    m = Mission.from_dict(data)
    # Preserved fields from older version
    assert m.id == data["id"]
    assert m.title == data["title"]
    assert m.goal == data["goal"]
    assert m.owner == data["owner"]
    assert m.status == data["status"]
    # New-in-v0.9.3 fields must default-init when absent
    if "template_id" not in data:
        assert m.template_id is None
    if "template_lock" not in data:
        assert m.template_lock == {}
    if "owner_did" not in data:
        assert m.owner_did == ""


@pytest.mark.parametrize("version", ["0.9.0", "0.9.2", "0.9.3"])
def test_v090_team_loads_under_current_code(version):
    """A pre-current team.json must parse cleanly via TeamConfig.from_dict."""
    fixture = FIXTURES_DIR / version / "team.json"
    if not fixture.exists():
        pytest.skip(f"no team fixture for {version}")
    data = _load_json(fixture)
    from nth_dao.membership import TeamConfig
    cfg = TeamConfig.from_dict(data)
    assert cfg.team_id == data["team_id"]
    assert cfg.team_name == data["team_name"]
    assert cfg.admin_ids == data["admin_ids"]
    # owner_pubkey/owner_sig new in 0.9.3 — must default to empty
    assert cfg.owner_pubkey == data.get("owner_pubkey", "")
    assert cfg.owner_sig == data.get("owner_sig", "")


def test_round_trip_through_current_code_is_idempotent(tmp_path):
    """Loading a 0.9.0 mission, re-saving via current code, then re-loading
    preserves the immutable identity fields."""
    src = FIXTURES_DIR / "0.9.0" / "mission.json"
    data = _load_json(src)
    from nth_dao.orchestration import Mission, MissionStore
    m = Mission.from_dict(data)
    store = MissionStore(str(tmp_path / "missions"))
    store.create(m)
    reloaded = store.get(m.id)
    assert reloaded is not None
    assert reloaded.id == data["id"]
    assert reloaded.title == data["title"]
    assert reloaded.owner == data["owner"]


def test_unknown_fields_in_future_format_are_tolerated(tmp_path):
    """If a fixture contains fields we don't recognize, we drop them but don't crash."""
    data = _load_json(FIXTURES_DIR / "0.9.0" / "mission.json")
    data["future_field_xyz_42"] = {"this": "doesn't exist yet"}
    from nth_dao.orchestration import Mission
    m = Mission.from_dict(data)  # MUST NOT raise
    assert m.id == data["id"]
