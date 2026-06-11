"""
Phase 3a tests — supervised agent runtime.

Covers:
  AgentSupervisor + InMemoryRunner unit tests (fast)
    - spawn returns a record with fresh did + agent_id
    - spawn twice → two distinct dids + records
    - stop removes from registry + returns True; second stop False
    - list_agents reflects registry; alive flag follows runner
    - on_event(heartbeat) bumps last_seen
    - shutdown stops everything best-effort

  FastAPI integration via TestClient (uses InMemoryRunner injected)
    - POST /api/v2/agents/spawn returns 201 + AgentEntry shape
    - GET /api/v2/agents merges supervised first
    - POST /api/v2/agents/{id}/stop returns 200, agent disappears
    - POST /api/v2/agents/{unknown}/stop returns 404
    - Spawned agents are deduped by did against the disk/seed list

  Real subprocess smoke (kept fast)
    - SubprocessRunner.start spawns nth_dao.web.dummy_agent
    - The child writes an "agent_started" line to stdout within 5s
    - stop terminates the child cleanly

Run: pytest tests/test_v2_agent_supervisor.py -q
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from nth_dao.web.agent_supervisor import (
    AgentSupervisor,
    InMemoryRunner,
    SubprocessRunner,
)


# ─────────────────────────────────────────────────────────────
# Unit tests — InMemoryRunner
# ─────────────────────────────────────────────────────────────

def test_spawn_returns_record_with_fresh_did() -> None:
    sup = AgentSupervisor(InMemoryRunner())
    r = sup.spawn(kind="mock", label="test-1", capabilities=["nth-dao.chat"])
    assert r.agent_id
    assert r.did.startswith("did:nth-hub-stub:")
    assert r.kind == "mock"
    assert r.label == "test-1"
    assert r.capabilities == ["nth-dao.chat"]
    assert r.alive is True
    assert r.pid is not None


def test_spawn_twice_distinct() -> None:
    sup = AgentSupervisor(InMemoryRunner())
    a = sup.spawn(kind="mock", label="a")
    b = sup.spawn(kind="mock", label="b")
    assert a.agent_id != b.agent_id
    assert a.did != b.did


def test_stop_removes_and_is_idempotent() -> None:
    sup = AgentSupervisor(InMemoryRunner())
    r = sup.spawn(kind="mock", label="x")
    assert sup.stop(r.agent_id) is True
    assert sup.stop(r.agent_id) is False
    assert sup.get(r.agent_id) is None


def test_list_agents_reflects_alive_flag() -> None:
    runner = InMemoryRunner()
    sup = AgentSupervisor(runner)
    a = sup.spawn(kind="mock", label="a")
    b = sup.spawn(kind="mock", label="b")

    listed = sup.list_agents()
    assert {x.agent_id for x in listed} == {a.agent_id, b.agent_id}
    assert all(x.alive for x in listed)

    # Manually stop one via the runner (simulates an external kill)
    runner._alive[a.agent_id] = False  # type: ignore[attr-defined]
    listed = sup.list_agents()
    by_id = {x.agent_id: x for x in listed}
    assert by_id[a.agent_id].alive is False
    assert by_id[b.agent_id].alive is True


def test_on_event_heartbeat_bumps_last_seen() -> None:
    sup = AgentSupervisor(InMemoryRunner())
    r = sup.spawn(kind="mock", label="x")
    earlier = r.last_seen
    time.sleep(0.01)
    sup.on_event(r.agent_id, {"event": "heartbeat", "ts": 1})
    refreshed = sup.get(r.agent_id)
    assert refreshed is not None
    assert refreshed.last_seen > earlier


def test_shutdown_stops_all() -> None:
    sup = AgentSupervisor(InMemoryRunner())
    a = sup.spawn(kind="mock", label="a")
    b = sup.spawn(kind="mock", label="b")
    sup.shutdown()
    assert sup.get(a.agent_id) is None
    assert sup.get(b.agent_id) is None


# ─────────────────────────────────────────────────────────────
# FastAPI integration
# ─────────────────────────────────────────────────────────────

@pytest.fixture
def hub_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> TestClient:
    """FastAPI client with the supervisor swapped for InMemoryRunner
    so tests don't spawn real processes. """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("NTH_V2_WORKSPACE_ONLY", "true")

    from nth_dao.web import create_app
    app = create_app(
        workspace=tmp_path / ".nth-dao" / "workspaces" / "default",
        require_console_auth=False,
    )
    # Pre-seat the in-memory supervisor so v2_api skips the
    # subprocess factory path.
    app.state.v2_supervisor = AgentSupervisor(InMemoryRunner())
    return TestClient(app)


def test_spawn_endpoint_returns_201(hub_client: TestClient) -> None:
    r = hub_client.post("/api/v2/agents/spawn", json={
        "kind": "mock",
        "label": "test-agent",
        "capabilities": ["nth-dao.chat"],
    })
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["did"].startswith("did:nth-hub-stub:")
    assert body["kind"] == "mock"
    assert body["label"] == "test-agent"
    entry = body["agent"]
    assert entry["source"] == "local"
    assert entry["supervised"] is True
    assert entry["alive"] is True
    assert entry["capabilities"] == ["nth-dao.chat"]


def test_supervised_agents_appear_in_get(hub_client: TestClient) -> None:
    # Spawn 2 agents.
    spawned = []
    for label in ("alpha", "beta"):
        r = hub_client.post("/api/v2/agents/spawn", json={
            "kind": "mock", "label": label, "capabilities": [],
        })
        assert r.status_code == 201
        spawned.append(r.json()["did"])

    listing = hub_client.get("/api/v2/agents").json()
    dids = {a["did"] for a in listing}
    assert set(spawned).issubset(dids)
    # Supervised agents come FIRST in the merged list.
    assert all(listing[i]["supervised"] for i in range(2))


def test_stop_endpoint_removes_agent(hub_client: TestClient) -> None:
    r = hub_client.post("/api/v2/agents/spawn", json={
        "kind": "mock", "label": "to-stop", "capabilities": [],
    })
    aid = r.json()["agent_id"]

    r2 = hub_client.post(f"/api/v2/agents/{aid}/stop")
    assert r2.status_code == 200
    assert r2.json()["stopped"] is True

    listing = hub_client.get("/api/v2/agents").json()
    dids = {a["did"] for a in listing}
    assert r.json()["did"] not in dids


def test_stop_unknown_id_404(hub_client: TestClient) -> None:
    r = hub_client.post("/api/v2/agents/does-not-exist/stop")
    assert r.status_code == 404


def test_seed_has_no_internal_duplicates(hub_client: TestClient) -> None:
    """Sanity guard: the v2_api seed agents must not contain
    duplicate DIDs amongst themselves. """
    listing = hub_client.get("/api/v2/agents").json()
    dids = [a["did"] for a in listing]
    assert len(set(dids)) == len(dids)


def test_supervisor_wins_dedup_against_seed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Review fix #3 (2026-06-11): the previous test only checked
    the seed baseline; the actual dedup logic in v2_api.py at the
    GET /agents handler was never exercised. Inject a supervised
    agent whose DID exactly matches a seed entry, then assert the
    merged response shows that DID exactly once and that the
    supervised version (with `supervised: True`) wins. """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("NTH_V2_WORKSPACE_ONLY", "true")

    from nth_dao.web import create_app
    from nth_dao.web.agent_supervisor import AgentRecord, InMemoryRunner

    app = create_app(
        workspace=tmp_path / ".nth-dao" / "workspaces" / "default",
        require_console_auth=False,
    )
    client = TestClient(app)

    # Get the first seed DID to use as the collision target.
    seed_listing = client.get("/api/v2/agents").json()
    target_did = seed_listing[0]["did"]
    assert target_did

    # Seat a supervisor pre-loaded with a record whose DID matches.
    sup = AgentSupervisor(InMemoryRunner())
    forged = AgentRecord(
        agent_id="collision-001",
        kind="mock",
        label="forced-collision",
        did=target_did,  # SAME as seed entry
        capabilities=["x"],
        started_at="2026-06-11T00:00:00+00:00",
        last_seen="2026-06-11T00:00:00+00:00",
        alive=True,
    )
    with sup._lock:  # type: ignore[attr-defined]
        sup._agents[forged.agent_id] = forged  # type: ignore[attr-defined]
    app.state.v2_supervisor = sup

    merged = client.get("/api/v2/agents").json()
    matching = [a for a in merged if a["did"] == target_did]
    assert len(matching) == 1, (
        f"expected dedup to 1, got {len(matching)} entries for "
        f"did {target_did}"
    )
    # The supervised version must win — supervised flag set + the
    # forged label visible.
    assert matching[0].get("supervised") is True
    assert matching[0]["label"] == "forced-collision"


def test_supervisor_thread_safety_smoke() -> None:
    """Polish: concurrency smoke for the supervisor lock. Spawns
    from one thread while another reads list_agents in a loop —
    proves the cross-thread read/write doesn't crash, doesn't lose
    records, and produces consistent listings.

    Doesn't aim to detect every race — that's what reasoning is
    for — but a noticeable regression in lock semantics would
    surface here (assertion error on count mismatch). """
    import threading

    sup = AgentSupervisor(InMemoryRunner())
    SPAWN_COUNT = 30
    spawned_ids: list[str] = []
    spawned_lock = threading.Lock()
    stop_event = threading.Event()

    def spawner() -> None:
        for i in range(SPAWN_COUNT):
            r = sup.spawn(kind="mock", label=f"t-{i}")
            with spawned_lock:
                spawned_ids.append(r.agent_id)
        stop_event.set()

    def lister() -> None:
        # Loop reading while the spawner mutates.
        while not stop_event.is_set():
            listed = sup.list_agents()
            # The set of agent_ids must be a subset of what's
            # been spawned so far — never see a phantom id.
            ids = {a.agent_id for a in listed}
            with spawned_lock:
                known = set(spawned_ids)
            phantom = ids - known
            assert not phantom, f"saw unknown id(s): {phantom}"

    threads = [
        threading.Thread(target=spawner, name="spawner"),
        threading.Thread(target=lister, name="lister"),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)
        assert not t.is_alive(), f"{t.name} did not terminate"

    final = sup.list_agents()
    assert len(final) == SPAWN_COUNT
    assert {a.agent_id for a in final} == set(spawned_ids)


# ─────────────────────────────────────────────────────────────
# Real subprocess smoke
# ─────────────────────────────────────────────────────────────

# Smoke test timeout — polish 2026-06-11: extracted from a magic
# literal so a slower CI can bump it without a code rebrowse.
_SMOKE_TIMEOUT = 5.0


def test_subprocess_runner_smoke() -> None:
    """One end-to-end check that SubprocessRunner can spawn
    nth_dao.web.dummy_agent, that the child prints its
    "agent_started" line, and that stop() terminates it cleanly.

    Skipped on platforms where subprocess.Popen with stdout=PIPE
    is unreliable in pytest's stdout capture (rare). """
    import uuid
    events: list[dict] = []
    runner = SubprocessRunner(on_event=lambda _id, e: events.append(e))
    # N-6 fix (2026-06-11): random agent_id so pytest-xdist parallel
    # workers don't collide on the same SubprocessRunner key when
    # someone someday runs `pytest -n auto`.
    agent_id = f"smoke-{uuid.uuid4().hex[:12]}"
    pid = runner.start(agent_id, kind="mock")
    if pid is None:
        pytest.skip("subprocess could not start (CI sandboxing?)")
    try:
        # Wait up to _SMOKE_TIMEOUT seconds for the "agent_started" event.
        deadline = time.time() + _SMOKE_TIMEOUT
        while time.time() < deadline:
            if any(e.get("event") == "agent_started" for e in events):
                break
            time.sleep(0.1)
        kinds = {e.get("event") for e in events}
        assert "agent_started" in kinds, f"events seen: {kinds!r}"
        assert runner.is_alive(agent_id), "agent should be alive"
    finally:
        runner.stop(agent_id)
        # L-5 fix (2026-06-11): no magic sleep — runner.stop()
        # already wait()s with a 2s+1s timeout, so by the time it
        # returns the process is guaranteed to have exited (or
        # been kill()ed). The previous time.sleep(0.3) was racing
        # an event already settled.
        assert not runner.is_alive(agent_id), "agent should be dead after stop"
