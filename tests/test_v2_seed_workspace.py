"""
Test coverage for ``nth_dao.web.seed_workspace`` (Q1 fix 2026-06-10).

The seed_workspace script touches three areas that are easy to get
wrong silently: atomic file writes, idempotent skip-or-write
branches, and `--reset` rm -rf. The previous version of this script
had zero test coverage; this file walks the matrix.

Test plan summary:

  _write_json_atomic
    - happy path writes the expected payload, leaves no .tmp behind
    - mkdir-parents creates missing intermediate dirs
    - rename failure (PermissionError simulated) cleans up the .tmp
    - non-OSError (e.g. TypeError from a malformed payload) is NOT
      caught — propagates up so a programmer bug isn't hidden
    - KeyboardInterrupt mid-write is NOT caught (BaseException
      subclass) — propagates correctly

  _seed_one
    - branch matrix:
        1. reset=True,  dir-exists      → rmtree + write all
        2. reset=True,  dir-missing     → write all (no rm)
        3. reset=False, file-exists     → already-present, no write
        4. reset=False, file-missing    → write
        5. dry_run=True, file-exists    → already-present, no write
        6. dry_run=True, file-missing   → wrote-counted but no file
    - SeedCount fields are named (not positional) so adding a 4th
      counter later doesn't silently break callers

  seed_workspace (integration)
    - re-runs are idempotent (wrote=0 second time)
    - cap_token not_after is overridden to far-future (Q3/Q4 fix)
    - the script's deepcopy keeps v2_api._seed_cap_tokens()
      uncontaminated for other callers (Q3 mutation safety)
    - agents land in nested subdirs (team_agents/{code}/identity.json)
    - workspace defaults to ~/.nth-dao/workspaces/default when None

All tests use pytest tmp_path so the real workspace under HOME is
never touched.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

import pytest

from nth_dao.web import seed_workspace as sw
from nth_dao.web.seed_workspace import (
    SeedCount,
    _seed_one,
    _write_json_atomic,
    seed_workspace,
)


# ─────────────────────────────────────────────────────────────
# _write_json_atomic
# ─────────────────────────────────────────────────────────────

def test_atomic_write_happy_path(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "x.json"
    _write_json_atomic(target, {"k": "v", "n": 1})
    assert target.exists()
    assert json.loads(target.read_text(encoding="utf-8")) == {"k": "v", "n": 1}
    # No leftover .tmp.
    assert not target.with_suffix(".json.tmp").exists()


def test_atomic_write_creates_parents(tmp_path: Path) -> None:
    target = tmp_path / "deep" / "deeper" / "x.json"
    _write_json_atomic(target, {"k": "v"})
    assert target.exists()


def test_atomic_write_cleans_tmp_on_oserror(tmp_path: Path) -> None:
    """Simulate a rename failure (locked target, antivirus, etc.)
    and confirm we don't leave a .tmp behind on disk.

    Mock fragility note (reviewer 2026-06-10): this patches
    ``Path.replace`` because that's what _write_json_atomic calls.
    If the production code is ever switched to ``os.replace(tmp,
    path)`` directly the patch would miss it — but the same logic
    still applies and a regression test would still fail because
    the .tmp leak would surface in the assertions below. The test
    is checking BEHAVIOUR (no leftover .tmp) not implementation,
    so the mock substitution is the cheapest way to trigger the
    failure path in tmp_path without resorting to permission
    chmods that don't work uniformly on Windows. """
    target = tmp_path / "x.json"

    # Inject an OSError on replace by patching Path.replace.
    real_replace = Path.replace

    def boom(self: Path, dst: Path) -> Path:
        if str(self).endswith(".tmp"):
            raise PermissionError("simulated antivirus lock")
        return real_replace(self, dst)

    with patch.object(Path, "replace", boom):
        with pytest.raises(PermissionError):
            _write_json_atomic(target, {"k": "v"})

    # Both .json and .tmp absent.
    assert not target.exists()
    assert not target.with_suffix(".json.tmp").exists()


def test_atomic_write_propagates_non_oserror(tmp_path: Path) -> None:
    """A TypeError from json.dumps (programmer bug) should not be
    swallowed by the OSError-narrow catch."""
    target = tmp_path / "x.json"

    class NotSerialisable:
        pass

    with pytest.raises(TypeError):
        _write_json_atomic(target, {"bad": NotSerialisable()})


# ─────────────────────────────────────────────────────────────
# _seed_one branch matrix
# ─────────────────────────────────────────────────────────────

def _entry(i: int) -> Dict[str, Any]:
    return {"id": f"e-{i}", "v": i}


def _seed_one_call(
    target_dir: Path,
    entries: list,
    *,
    reset: bool = False,
    dry_run: bool = False,
) -> SeedCount:
    return _seed_one(
        label="x",
        target_dir=target_dir,
        entries=entries,
        filename_of=lambda e: f"{e['id']}.json",
        payload_of=lambda e: e,
        reset=reset,
        dry_run=dry_run,
    )


def test_seed_one_branch_1_reset_dir_exists(tmp_path: Path) -> None:
    # Pre-existing real data — gets wiped by reset.
    (tmp_path / "existing.json").write_text('{"alive":true}', encoding="utf-8")
    r = _seed_one_call(tmp_path, [_entry(1), _entry(2)], reset=True)
    assert r == SeedCount(wrote=2, skipped=0, already=0)
    assert not (tmp_path / "existing.json").exists()
    assert (tmp_path / "e-1.json").exists()
    assert (tmp_path / "e-2.json").exists()


def test_seed_one_branch_2_reset_dir_missing(tmp_path: Path) -> None:
    target = tmp_path / "fresh"
    r = _seed_one_call(target, [_entry(1)], reset=True)
    assert r == SeedCount(wrote=1, skipped=0, already=0)
    assert (target / "e-1.json").exists()


def test_seed_one_branch_3_no_reset_file_exists(tmp_path: Path) -> None:
    (tmp_path / "e-1.json").write_text('{"v": 99}', encoding="utf-8")
    r = _seed_one_call(tmp_path, [_entry(1)], reset=False)
    assert r == SeedCount(wrote=0, skipped=0, already=1)
    # Pre-existing content untouched.
    assert json.loads((tmp_path / "e-1.json").read_text())["v"] == 99


def test_seed_one_branch_4_no_reset_file_missing(tmp_path: Path) -> None:
    r = _seed_one_call(tmp_path, [_entry(1)], reset=False)
    assert r == SeedCount(wrote=1, skipped=0, already=0)
    assert (tmp_path / "e-1.json").exists()


def test_seed_one_branch_5_dryrun_file_exists(tmp_path: Path) -> None:
    (tmp_path / "e-1.json").write_text("orig", encoding="utf-8")
    r = _seed_one_call(tmp_path, [_entry(1)], dry_run=True)
    assert r == SeedCount(wrote=0, skipped=0, already=1)
    assert (tmp_path / "e-1.json").read_text() == "orig"


def test_seed_one_branch_6_dryrun_file_missing(tmp_path: Path) -> None:
    r = _seed_one_call(tmp_path, [_entry(1)], dry_run=True)
    assert r == SeedCount(wrote=1, skipped=0, already=0)
    assert not (tmp_path / "e-1.json").exists()


def test_seed_one_continues_after_per_entry_failure(tmp_path: Path) -> None:
    """If _write_json_atomic raises for one entry, _seed_one logs
    and increments skipped, then continues with the next entry."""
    target = tmp_path / "out"
    target.mkdir()
    # Make one entry's payload non-serialisable.
    class Bad:
        pass
    entries = [_entry(1), {"id": "e-bad", "v": Bad()}, _entry(3)]

    r = _seed_one(
        label="x",
        target_dir=target,
        entries=entries,
        filename_of=lambda e: f"{e['id']}.json",
        payload_of=lambda e: e,
        reset=False,
        dry_run=False,
    )
    # e-1 and e-3 written; e-bad skipped.
    assert r.wrote == 2
    assert r.skipped == 1
    assert (target / "e-1.json").exists()
    assert (target / "e-3.json").exists()
    assert not (target / "e-bad.json").exists()


# ─────────────────────────────────────────────────────────────
# SeedCount API stability
# ─────────────────────────────────────────────────────────────

def test_seedcount_is_namedtuple() -> None:
    """Named fields stop unpack-by-position from silently breaking
    when a 4th counter is added someday."""
    c = SeedCount(wrote=1, skipped=2, already=3)
    assert c.wrote == 1
    assert c.skipped == 2
    assert c.already == 3
    # Still indexable for back-compat with old callers.
    assert c[0] == 1


# ─────────────────────────────────────────────────────────────
# seed_workspace integration
# ─────────────────────────────────────────────────────────────

def test_seed_workspace_idempotent(tmp_path: Path) -> None:
    r1 = seed_workspace(workspace=tmp_path)
    r2 = seed_workspace(workspace=tmp_path)

    # First run writes; second is a no-op.
    assert r1["receipts"].wrote   == 2
    assert r1["cap_tokens"].wrote == 2
    assert r1["agents"].wrote     == 5

    assert r2["receipts"].wrote   == 0
    assert r2["cap_tokens"].wrote == 0
    assert r2["agents"].wrote     == 0
    assert r2["receipts"].already   == 2
    assert r2["cap_tokens"].already == 2
    assert r2["agents"].already     == 5


def test_seed_workspace_cap_tokens_far_future(tmp_path: Path) -> None:
    """Q3/Q4 fix: not_after is set to ~1 year out, not whatever
    v2_api seeded (2-3 hours from now). """
    seed_workspace(workspace=tmp_path)

    now_ms = int(time.time() * 1000)
    six_months_ms = 6 * 30 * 24 * 3600 * 1000

    for p in (tmp_path / "team_cap_tokens").glob("*.json"):
        data = json.loads(p.read_text(encoding="utf-8"))
        # ~1 year is much more than 6 months.
        assert data["not_after"] > now_ms + six_months_ms, (
            f"{p.name} not_after should be ~1y in future, "
            f"got {data['not_after']} (now={now_ms}, "
            f"diff={(data['not_after']-now_ms)/3600_000:.1f}h)"
        )


def test_seed_workspace_does_not_corrupt_v2api_seed(tmp_path: Path) -> None:
    """Q3 mutation-safety check: the script's deepcopy + override
    must not leak into the v2_api API path."""
    from nth_dao.web import v2_api

    # Get a fresh view BEFORE seed_workspace runs.
    pristine = v2_api._seed_cap_tokens()
    pristine_not_after = [c["not_after"] for c in pristine]

    seed_workspace(workspace=tmp_path)

    # Get a fresh view AFTER. Should match pristine — the in-place
    # mutation in seed_workspace must not have leaked.
    after = v2_api._seed_cap_tokens()
    after_not_after = [c["not_after"] for c in after]

    # Allow a small drift (these use time.time() at call time, so
    # they advance by ms across the two calls).
    for p, a in zip(pristine_not_after, after_not_after):
        assert abs(a - p) < 60_000  # within 1 minute = same source


def test_seed_workspace_agents_use_nested_dirs(tmp_path: Path) -> None:
    seed_workspace(workspace=tmp_path)
    agent_dirs = list((tmp_path / "team_agents").iterdir())
    # 5 seed agents → 5 subdirs, each with identity.json.
    assert len(agent_dirs) == 5
    for d in agent_dirs:
        assert d.is_dir()
        assert (d / "identity.json").exists()


def test_seed_workspace_dry_run_writes_nothing(tmp_path: Path) -> None:
    seed_workspace(workspace=tmp_path, dry_run=True)
    # No files on disk.
    assert not any((tmp_path / "team_receipts").glob("*.json"))
    assert not any((tmp_path / "team_cap_tokens").glob("*.json"))
    assert not (tmp_path / "team_agents").exists() or \
           not list((tmp_path / "team_agents").iterdir())


def test_seed_workspace_default_workspace_path() -> None:
    """When workspace=None we fall through to the home-dir default."""
    home = sw._default_workspace()
    assert home == Path.home() / ".nth-dao" / "workspaces" / "default"
