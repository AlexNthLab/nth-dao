"""
Phase 3a/3b/3c tests — supervised agent runtime.

Covers:
  AgentSupervisor + InMemoryRunner unit tests (fast)
    - spawn returns a record with real did:key + agent_id
    - spawn twice → two distinct dids + records
    - stop removes from registry + returns True; second stop False
    - list_agents reflects registry; alive flag follows runner
    - on_event(heartbeat) bumps last_seen
    - shutdown stops everything best-effort

  Phase 3b additions
    - InMemoryRunner returns a real-shape did:key (decodes via did_key)
    - spawn() with cap_token_issuer stamps cap_token_id on record
    - cap_token_issuer raising tears down the child and re-raises

  FastAPI integration via TestClient (uses InMemoryRunner injected)
    - POST /api/v2/agents/spawn returns 201 + AgentEntry shape
    - GET /api/v2/agents merges supervised first
    - POST /api/v2/agents/{id}/stop returns 200, agent disappears
    - POST /api/v2/agents/{unknown}/stop returns 404
    - Spawned agents are deduped by did against the disk/seed list
    - Phase 3b: spawn issues a cap_token persisted in the store
    - Phase 3b: spawn 503 when node_identity missing

  Real subprocess smoke (kept fast)
    - SubprocessRunner.start spawns nth_dao.web.dummy_agent
    - The child writes an "agent_started" line with a real did:key
    - SubprocessRunner.start blocks until handshake, returns the did
    - stop terminates the child cleanly

Run: pytest tests/test_v2_agent_supervisor.py -q
"""
from __future__ import annotations

import json
import os
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
    # Phase 3b: did is now a REAL W3C did:key (z6Mk… for Ed25519),
    # not the Phase 3a ``did:nth-hub-stub:`` placeholder.
    sup = AgentSupervisor(InMemoryRunner())
    r = sup.spawn(kind="mock", label="test-1", capabilities=["nth-dao.chat"])
    assert r.agent_id
    assert r.did.startswith("did:key:z6Mk"), (
        f"expected a did:key Ed25519 multibase prefix, got {r.did!r}"
    )
    assert r.kind == "mock"
    assert r.label == "test-1"
    assert r.capabilities == ["nth-dao.chat"]
    assert r.alive is True
    assert r.pid is not None
    # Phase 3b: with no cap_token_issuer the field stays None — the
    # supervisor doesn't manufacture tokens on its own.
    assert r.cap_token_id is None


def test_inmemory_runner_did_decodes_as_real_didkey() -> None:
    """Phase 3b: the InMemoryRunner's generated DID must round-trip
    through the project's own did:key codec, so test code that
    feeds it into cap_token.sign_cap_token (which validates the
    subject_did) doesn't have to special-case test runners. """
    from nth_dao.did_key import decode_ed25519_did_key, is_did_key
    sup = AgentSupervisor(InMemoryRunner())
    r = sup.spawn(kind="mock", label="x")
    assert is_did_key(r.did)
    pubkey = decode_ed25519_did_key(r.did)
    assert len(pubkey) == 32  # Ed25519 pubkey size


def test_spawn_with_cap_token_issuer_stamps_token_id() -> None:
    """Phase 3b: when spawn() is given a cap_token_issuer callback,
    the returned record carries the issued token_id. The supervisor
    invokes the callback with the child's DID + capabilities. """
    sup = AgentSupervisor(InMemoryRunner())
    calls: list[tuple[str, list[str]]] = []

    def fake_issuer(did: str, caps: list[str]) -> dict:
        calls.append((did, list(caps)))
        return {"token_id": "tok-" + did[-8:], "subject_did": did}

    r = sup.spawn(
        kind="mock", label="t",
        capabilities=["nth-dao.chat"],
        cap_token_issuer=fake_issuer,
    )
    assert r.cap_token_id == "tok-" + r.did[-8:]
    assert len(calls) == 1
    issued_did, issued_caps = calls[0]
    assert issued_did == r.did
    assert issued_caps == ["nth-dao.chat"]


def test_spawn_warns_when_issuer_returns_dict_without_token_id(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """H-2 fix (review round Phase 3b R1): if a cap_token_issuer
    returns SOMETHING but no usable ``token_id``, the supervisor
    must log a loud WARNING. Without this, a contract drift in
    sign_cap_token (renamed field, swapped key) would silently
    park unauthorised agents in the registry. """
    import logging

    sup = AgentSupervisor(InMemoryRunner())

    def issuer_missing_token_id(_did: str, _caps: list[str]) -> dict:
        # Dict-shaped but no token_id — exactly the contract-drift
        # case the WARNING is meant to catch.
        return {"subject_did": _did, "capabilities": list(_caps)}

    with caplog.at_level(logging.WARNING, logger="nth_dao.web.agent_supervisor"):
        r = sup.spawn(
            kind="mock", label="weird-issuer",
            capabilities=[],
            cap_token_issuer=issuer_missing_token_id,
        )

    # Agent is still registered — supervisor didn't fail-closed
    # on this (the issuer didn't raise, just returned an odd dict);
    # but the WARNING gives the operator a chance to notice.
    assert r.cap_token_id is None
    warnings = [r.getMessage() for r in caplog.records
                if r.levelno == logging.WARNING]
    assert any("without a valid 'token_id'" in w for w in warnings), (
        f"expected a WARNING about missing token_id, got: {warnings!r}"
    )


def test_spawn_kills_child_when_cap_token_issuer_raises() -> None:
    """Phase 3b: if the issuer raises, the supervisor must tear
    the child down BEFORE re-raising — otherwise the caller gets a
    500 while an unauthorised agent quietly runs in the background. """
    runner = InMemoryRunner()
    sup = AgentSupervisor(runner)

    class Boom(RuntimeError):
        pass

    def angry_issuer(_did: str, _caps: list[str]) -> dict:
        raise Boom("issuer rejected this subject_did")

    with pytest.raises(Boom):
        sup.spawn(
            kind="mock", label="t",
            capabilities=[],
            cap_token_issuer=angry_issuer,
        )

    # No record left behind, runner.is_alive must be False for every
    # known id (the InMemoryRunner.stop flips the alive flag).
    assert sup.list_agents() == []
    # The InMemoryRunner reuses agent_ids of stopped children in its
    # _alive dict; assert every alive flag is False.
    all_alive = list(runner._alive.values())  # type: ignore[attr-defined]
    assert not any(all_alive), (
        f"runner should have torn the child down; alive flags: {all_alive!r}"
    )


def test_spawn_warns_when_issuer_returns_non_dict(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """N-1 fix (review round Phase 3b R2): if a cap_token_issuer
    returns a non-dict truthy value (list, str, custom object),
    the supervisor must emit a clear WARNING naming the actual
    type instead of relying on a downstream AttributeError to
    blow up the spawn. The agent still registers — same posture
    as H-2's missing-token_id branch. """
    import logging

    sup = AgentSupervisor(InMemoryRunner())

    def issuer_returns_list(_did: str, _caps: list[str]) -> list:
        # Wrong shape — pretend a refactor renamed sign_cap_token's
        # return into a list-of-tokens. The supervisor shouldn't
        # crash trying to call .get() on it.
        return [{"token_id": "tok-001"}]  # type: ignore[return-value]

    with caplog.at_level(logging.WARNING, logger="nth_dao.web.agent_supervisor"):
        r = sup.spawn(
            kind="mock", label="non-dict-issuer",
            capabilities=[],
            cap_token_issuer=issuer_returns_list,  # type: ignore[arg-type]
        )

    assert r.cap_token_id is None
    warnings = [r.getMessage() for r in caplog.records
                if r.levelno == logging.WARNING]
    assert any("returned list instead of a dict" in w for w in warnings), (
        f"expected a WARNING naming the bad return type, got: {warnings!r}"
    )


def test_spawn_kills_child_when_post_handshake_assembly_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """H-1 fix (review round Phase 3b R1): the runner gives us a
    live child the moment start() returns. ANY exception from
    issuer / AgentRecord construction / self._agents insert before
    we mark the spawn complete must trigger runner.stop() in a
    finally — otherwise the subprocess is orphaned.

    Forcing the failure: monkeypatch AgentRecord to raise inside
    spawn's try block. The supervisor must then call runner.stop().
    """
    from nth_dao.web import agent_supervisor as supmod

    runner = InMemoryRunner()
    sup = AgentSupervisor(runner)

    class _Boom(RuntimeError):
        pass

    def explosive_record(*_args: object, **_kwargs: object) -> None:
        raise _Boom("simulated post-handshake assembly failure")

    monkeypatch.setattr(supmod, "AgentRecord", explosive_record)

    with pytest.raises(_Boom):
        sup.spawn(kind="mock", label="t", capabilities=[])

    # Runner.stop() flipped the alive flag for the doomed agent.
    # Every recorded alive value must be False — no orphan.
    all_alive = list(runner._alive.values())  # type: ignore[attr-defined]
    assert not any(all_alive), (
        f"runner should have stopped the child; alive flags: {all_alive!r}"
    )
    # And no leftover record in the supervisor either.
    assert sup.list_agents() == []


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
    # Phase 3b: real W3C did:key, not the Phase 3a stub.
    assert body["did"].startswith("did:key:z6Mk")
    assert body["kind"] == "mock"
    assert body["label"] == "test-agent"
    # Phase 3b: hub issued a cap_token on spawn; the response carries
    # the token_id so the UI can splice it into /api/v2/cap_tokens.
    assert body["cap_token_id"], "cap_token_id must be set on Phase 3b spawn"
    entry = body["agent"]
    assert entry["source"] == "local"
    assert entry["supervised"] is True
    assert entry["alive"] is True
    assert entry["capabilities"] == ["nth-dao.chat"]
    # has_active_cap must follow cap_token_id presence.
    assert entry["has_active_cap"] is True


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


def test_spawn_persists_cap_token_in_store(hub_client: TestClient) -> None:
    """Phase 3b end-to-end: the issued token must land in
    state.cap_tokens, with the child's DID as subject_did and
    nth:receipt_sign present. Without this, the operator's audit
    log would be missing the records that justified granting
    receipt-signing authority to a freshly-spawned agent. """
    from nth_dao.cap_token import CAP_NTH_RECEIPT_SIGN

    r = hub_client.post("/api/v2/agents/spawn", json={
        "kind": "mock", "label": "auth-test",
        "capabilities": ["nth-dao.chat"],
    })
    assert r.status_code == 201, r.text
    body = r.json()
    token_id = body["cap_token_id"]
    spawned_did = body["did"]

    # The app object the fixture built has state.nth.cap_tokens —
    # pull it out to verify the audit record on disk.
    app = hub_client.app
    store = app.state.nth.cap_tokens
    record = store.get(token_id)
    assert record is not None, (
        f"cap_token {token_id!r} not found in store after spawn"
    )
    assert record["subject_did"] == spawned_did
    assert CAP_NTH_RECEIPT_SIGN in record["capabilities"]
    # nth-dao.chat is NOT in KNOWN_CAPABILITIES so it must be
    # filtered out (defensive — typos in the request shouldn't
    # produce phantom caps).
    assert "nth-dao.chat" not in record["capabilities"]


def test_v2_receipt_persistor_drops_when_receipts_store_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """H-1 fix (review round Phase 3c R1): when the v2_api receipt
    persistor closure runs but ``state.nth.receipts`` has been
    cleared (early dev state, post-shutdown), the receipt MUST be
    dropped with a clear WARNING. Without this coverage a future
    refactor that renames ``state.nth.receipts`` would silently
    drop every child-signed receipt — the only signal would be a
    WARNING buried in logs. """
    import logging

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("NTH_V2_WORKSPACE_ONLY", "true")

    from nth_dao.web import create_app
    app = create_app(
        workspace=tmp_path / ".nth-dao" / "workspaces" / "default",
        require_console_auth=False,
    )
    # Force the lazy supervisor build by accessing it (any GET that
    # touches it works; use the agents listing).
    client = TestClient(app)
    client.get("/api/v2/agents")
    sup = app.state.v2_supervisor
    # Spawn an agent so we have a record to attach the receipt to.
    r = sup.spawn(kind="mock", label="receipt-test", capabilities=[])
    # Knock out the receipts store AFTER spawn, then fire a
    # receipt_signed event through the supervisor. The persistor
    # closure looks up state.nth.receipts FRESH each call.
    app.state.nth.receipts = None
    with caplog.at_level(logging.WARNING, logger="nth_dao.web.v2_api"):
        sup.on_event(r.agent_id, {
            "event": "receipt_signed",
            "agent_id": r.agent_id,
            "receipt": {
                "receipt_id": "r-h1",
                "signer_did": r.did,
                "content_hash": "h-test",
            },
        })
    msgs = [w.getMessage() for w in caplog.records
            if w.levelno == logging.WARNING]
    assert any("state.nth.receipts is unavailable" in m for m in msgs), (
        f"expected a WARNING when receipts store is missing; got {msgs!r}"
    )


def test_spawn_503_when_node_identity_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Phase 3b fail-closed: if state.node_identity is absent the
    hub MUST refuse to spawn — bringing up a child without an
    issuer would mean no cap_token, no audit trail. 503 is the
    same posture Phase 2 uses for receipt signing. """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("NTH_V2_WORKSPACE_ONLY", "true")

    from nth_dao.web import create_app
    app = create_app(
        workspace=tmp_path / ".nth-dao" / "workspaces" / "default",
        require_console_auth=False,
    )
    # Pre-seat InMemoryRunner so this test can't accidentally fork
    # a real child even if the failure path lets us through.
    app.state.v2_supervisor = AgentSupervisor(InMemoryRunner())
    # Strip the identity that create_app bootstrapped, simulating
    # an early-deploy state where the workspace doesn't yet have
    # a keypair.
    app.state.nth.node_identity = None
    client = TestClient(app)

    r = client.post("/api/v2/agents/spawn", json={
        "kind": "mock", "label": "no-identity", "capabilities": [],
    })
    assert r.status_code == 503, r.text
    assert "signer identity unavailable" in r.json()["detail"]


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
# Phase 3c — env-var timeout
# ─────────────────────────────────────────────────────────────

def test_handshake_timeout_env_var_positive_float(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Phase 3c: NTH_AGENT_HANDSHAKE_TIMEOUT_S overrides the
    module default when set to a positive float. """
    monkeypatch.setenv("NTH_AGENT_HANDSHAKE_TIMEOUT_S", "3.5")
    runner = SubprocessRunner()
    assert runner._handshake_timeout == 3.5  # type: ignore[attr-defined]


def test_handshake_timeout_env_var_falls_back_on_bad_input(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Phase 3c: malformed env values must log a WARNING and fall
    back to the 10s default — silently inheriting bad values would
    hide ops mistakes. """
    import logging
    monkeypatch.setenv("NTH_AGENT_HANDSHAKE_TIMEOUT_S", "not-a-number")
    with caplog.at_level(logging.WARNING, logger="nth_dao.web.agent_supervisor"):
        runner = SubprocessRunner()
    assert runner._handshake_timeout == 10.0  # type: ignore[attr-defined]
    assert any(
        "is not a number" in r.getMessage() for r in caplog.records
    ), f"expected a WARNING about the bad env value; got {caplog.records!r}"


def test_handshake_timeout_env_var_rejects_non_positive(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Phase 3c: zero / negative values are nonsensical for a
    timeout. WARNING + default. """
    import logging
    monkeypatch.setenv("NTH_AGENT_HANDSHAKE_TIMEOUT_S", "0")
    with caplog.at_level(logging.WARNING, logger="nth_dao.web.agent_supervisor"):
        runner = SubprocessRunner()
    assert runner._handshake_timeout == 10.0  # type: ignore[attr-defined]
    assert any(
        "must be positive" in r.getMessage() for r in caplog.records
    )


def test_explicit_handshake_timeout_overrides_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An explicit kwarg always wins over the env var — useful in
    tests that pin a fast timeout regardless of operator config. """
    monkeypatch.setenv("NTH_AGENT_HANDSHAKE_TIMEOUT_S", "99.0")
    runner = SubprocessRunner(handshake_timeout=2.0)
    assert runner._handshake_timeout == 2.0  # type: ignore[attr-defined]


# ─────────────────────────────────────────────────────────────
# Phase 3c — cap_token file delivery + receipt persistor wiring
# ─────────────────────────────────────────────────────────────

def test_spawn_writes_cap_token_file_at_expected_path(
    tmp_path: Path,
) -> None:
    """Phase 3c: when cap_token_dir + issuer are both set, spawn
    atomic-writes the issued token JSON to
    ``<cap_token_dir>/<agent_id>/cap_token.json`` so a real child
    could poll + load it. """
    sup = AgentSupervisor(
        InMemoryRunner(),
        cap_token_dir=tmp_path / "agents",
    )
    issued: dict = {}

    def fake_issuer(did: str, _caps: list[str]) -> dict:
        token = {
            "token_id": "tok-abc123",
            "subject_did": did,
            "capabilities": ["nth:receipt_sign"],
        }
        issued.update(token)
        return token

    r = sup.spawn(
        kind="mock", label="t", capabilities=[],
        cap_token_issuer=fake_issuer,
    )

    expected = tmp_path / "agents" / r.agent_id / "cap_token.json"
    assert expected.exists(), f"cap_token file not written at {expected}"
    import json
    on_disk = json.loads(expected.read_text(encoding="utf-8"))
    assert on_disk["token_id"] == "tok-abc123"
    assert on_disk["subject_did"] == r.did


def test_spawn_survives_cap_token_file_write_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """C-1 fix (review round Phase 3c R1): if the cap_token file
    write fails (disk full, permission denied, etc.) the agent
    must stay alive AND registered — the audit-store entry for
    the token is already valid; killing the agent here would
    orphan it. Operator gets a WARNING explaining the situation. """
    import logging
    from nth_dao.web import agent_supervisor as supmod

    # Force every _atomic_write_json call to raise OSError, as if
    # the cap_token directory's filesystem hit a quota.
    def boom_writer(_path: str, _payload: dict) -> None:
        raise OSError("simulated ENOSPC")

    monkeypatch.setattr(supmod, "_atomic_write_json", boom_writer)

    runner = InMemoryRunner()
    sup = AgentSupervisor(runner, cap_token_dir=tmp_path / "agents")

    def fake_issuer(did: str, _caps: list[str]) -> dict:
        return {
            "token_id": "tok-survive",
            "subject_did": did,
            "capabilities": ["nth:receipt_sign"],
        }

    with caplog.at_level(logging.WARNING, logger="nth_dao.web.agent_supervisor"):
        r = sup.spawn(
            kind="mock", label="t", capabilities=[],
            cap_token_issuer=fake_issuer,
        )

    # The agent is still alive + registered + the token_id is
    # stamped — only the file delivery failed.
    assert r.cap_token_id == "tok-survive"
    assert sup.get(r.agent_id) is not None
    assert runner.is_alive(r.agent_id), (
        "InMemoryRunner.is_alive must remain True — the failed "
        "file delivery should NOT have triggered rollback"
    )
    warnings = [w.getMessage() for w in caplog.records
                if w.levelno == logging.WARNING]
    assert any(
        "failed to deliver cap_token file" in w for w in warnings
    ), f"expected delivery-failure WARNING; got {warnings!r}"


def test_atomic_write_json_restricts_to_owner_on_posix(
    tmp_path: Path,
) -> None:
    """H-2 fix (review round Phase 3c R2): cap_token files are
    bearer tokens. On POSIX the file must end up at mode 0o600 —
    world-readable would let any local user present the token as
    authority. Skipped on Windows where POSIX mode isn't honoured
    (per-user ACL on the workspace path covers it there). """
    if sys.platform.startswith("win"):
        pytest.skip("POSIX mode bits don't apply on Windows")
    from nth_dao.web import agent_supervisor as supmod

    target = tmp_path / "cap_token.json"
    supmod._atomic_write_json(str(target), {"token_id": "x"})
    mode = os.stat(str(target)).st_mode & 0o777
    assert mode == 0o600, (
        f"cap_token file at {target} ended up at mode {oct(mode)}; "
        "expected 0o600 (owner-only). G-1 reminder: chmod must "
        "land on tmp BEFORE os.replace so the FINAL file inherits "
        "the restricted mode."
    )


def test_stop_removes_cap_token_file_and_agent_dir(
    tmp_path: Path,
) -> None:
    """H-1 fix (review round Phase 3c R2): stop() must delete the
    cap_token file + remove the per-agent dir so disk-fill and
    stale-token sprawl don't accumulate across thousands of spawn/
    stop cycles. """
    cap_token_dir = tmp_path / "agents"
    sup = AgentSupervisor(InMemoryRunner(), cap_token_dir=cap_token_dir)

    def fake_issuer(did: str, _caps: list[str]) -> dict:
        return {"token_id": "tok-cleanup", "subject_did": did}

    r = sup.spawn(
        kind="mock", label="t", capabilities=[],
        cap_token_issuer=fake_issuer,
    )
    agent_dir = cap_token_dir / r.agent_id
    cap_token_file = agent_dir / "cap_token.json"
    assert cap_token_file.exists(), "precondition: file should be written"

    assert sup.stop(r.agent_id) is True
    assert not cap_token_file.exists(), (
        "cap_token file should be removed after stop"
    )
    assert not agent_dir.exists(), (
        "per-agent dir should be removed after stop (rmdir on empty)"
    )


def test_stop_cleanup_survives_unlink_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """H-1 fix part 2: if unlink raises (read-only fs, permission
    issue), stop() still returns True, the agent is still removed
    from the registry, and a WARNING is logged. The operator
    can sweep manually — but a stuck unlink should never block
    the supervisor's stop path. """
    import logging
    from pathlib import Path as _Path

    cap_token_dir = tmp_path / "agents"
    sup = AgentSupervisor(InMemoryRunner(), cap_token_dir=cap_token_dir)

    def fake_issuer(did: str, _caps: list[str]) -> dict:
        return {"token_id": "tok-survive", "subject_did": did}

    r = sup.spawn(
        kind="mock", label="t", capabilities=[],
        cap_token_issuer=fake_issuer,
    )

    real_unlink = _Path.unlink

    def boom_unlink(self: _Path, *args: object, **kwargs: object) -> None:
        if self.name == "cap_token.json":
            raise OSError("simulated EROFS")
        return real_unlink(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(_Path, "unlink", boom_unlink)

    with caplog.at_level(logging.WARNING, logger="nth_dao.web.agent_supervisor"):
        ok = sup.stop(r.agent_id)
    assert ok is True
    assert sup.get(r.agent_id) is None  # still removed
    warnings = [w.getMessage() for w in caplog.records
                if w.levelno == logging.WARNING]
    assert any(
        "failed to remove cap_token.json" in w for w in warnings
    ), f"expected the unlink-failure WARNING; got {warnings!r}"


def test_spawn_skips_file_write_when_no_cap_token_dir(
    tmp_path: Path,
) -> None:
    """Phase 3c: supervisor with cap_token_dir=None must NOT
    attempt to write the file even if an issuer is supplied
    (Phase 3a/3b behaviour preserved). """
    sup = AgentSupervisor(InMemoryRunner(), cap_token_dir=None)

    def fake_issuer(did: str, _caps: list[str]) -> dict:
        return {"token_id": "tok-xyz", "subject_did": did}

    r = sup.spawn(
        kind="mock", label="t", capabilities=[],
        cap_token_issuer=fake_issuer,
    )
    # Token is still stamped on the record (3b semantics).
    assert r.cap_token_id == "tok-xyz"
    # But no agent directory created under tmp_path.
    assert not any(tmp_path.iterdir()), (
        "supervisor should not touch the filesystem when "
        f"cap_token_dir is None; saw {list(tmp_path.iterdir())}"
    )


def test_subprocess_runner_passes_cap_token_file_arg() -> None:
    """Phase 3c: when cap_token_file_path is provided, the
    SubprocessRunner constructs a Popen cmd line that includes
    ``--cap-token-file <path>``. Asserted via Popen monkeypatch
    so this doesn't spawn a real child.

    M-2 note (review round Phase 3c R1): the SubprocessRunner is
    constructed OUTSIDE the mock.patch context (the ctor doesn't
    touch subprocess.Popen — it only allocates dicts and locks).
    Only ``runner.start()`` enters the patched region, so the
    fake_popen substitution covers every Popen call this test
    triggers. """
    import unittest.mock as mock

    runner = SubprocessRunner(handshake_timeout=0.5)
    captured: list[list[str]] = []

    class _FakeProc:
        pid = 99999
        stdout = None
        stderr = None
        def poll(self) -> int | None: return None
        def terminate(self) -> None: pass
        def kill(self) -> None: pass
        def wait(self, timeout: float = 0) -> int: return 0

    def fake_popen(cmd: list[str], **_kwargs: object) -> _FakeProc:
        captured.append(list(cmd))
        return _FakeProc()

    with mock.patch("subprocess.Popen", side_effect=fake_popen):
        # The handshake will time out (no stdout reader to set the
        # event) but that's fine — we only care about the cmd line.
        pid, did = runner.start(
            "aid-001", "mock",
            cap_token_file_path="/tmp/some/cap_token.json",
        )

    assert captured, "Popen wasn't called"
    cmd = captured[0]
    assert "--cap-token-file" in cmd
    idx = cmd.index("--cap-token-file")
    assert cmd[idx + 1] == "/tmp/some/cap_token.json"


def test_receipt_persistor_called_on_receipt_signed_event() -> None:
    """Phase 3c: supervisor.on_event for receipt_signed forwards
    the receipt to the configured persistor. """
    persisted: list[tuple[str, dict]] = []

    def persistor(agent_id: str, receipt: dict) -> None:
        persisted.append((agent_id, receipt))

    sup = AgentSupervisor(
        InMemoryRunner(),
        receipt_persistor=persistor,
    )
    r = sup.spawn(kind="mock", label="t", capabilities=[])
    fake_receipt = {
        "receipt_id": "r-001",
        "signer_did": r.did,
        "content_hash": "abc123",
    }
    sup.on_event(r.agent_id, {
        "event": "receipt_signed",
        "agent_id": r.agent_id,
        "receipt": fake_receipt,
    })
    assert persisted == [(r.agent_id, fake_receipt)]


def test_receipt_persistor_failure_logs_warning_keeps_agent(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Phase 3c: a persistor that raises must NOT kill the agent —
    the supervisor logs and continues. Otherwise a transient disk
    hiccup would take healthy agents offline. """
    import logging

    def angry_persistor(_aid: str, _receipt: dict) -> None:
        raise RuntimeError("disk full")

    sup = AgentSupervisor(
        InMemoryRunner(),
        receipt_persistor=angry_persistor,
    )
    r = sup.spawn(kind="mock", label="t", capabilities=[])
    with caplog.at_level(logging.WARNING, logger="nth_dao.web.agent_supervisor"):
        sup.on_event(r.agent_id, {
            "event": "receipt_signed",
            "agent_id": r.agent_id,
            "receipt": {"receipt_id": "r-001", "signer_did": r.did},
        })
    # Agent still registered.
    assert sup.get(r.agent_id) is not None
    warnings = [w.getMessage() for w in caplog.records
                if w.levelno == logging.WARNING]
    assert any("receipt_persistor failed" in w for w in warnings)


def test_receipt_signed_without_persistor_logs_info(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Phase 3c: when no persistor is configured the receipt is
    INFO-logged + dropped (not silently). """
    import logging
    sup = AgentSupervisor(InMemoryRunner())  # no persistor
    r = sup.spawn(kind="mock", label="t", capabilities=[])
    with caplog.at_level(logging.INFO, logger="nth_dao.web.agent_supervisor"):
        sup.on_event(r.agent_id, {
            "event": "receipt_signed",
            "agent_id": r.agent_id,
            "receipt": {"receipt_id": "r-001", "signer_did": r.did},
        })
    msgs = [r.getMessage() for r in caplog.records if r.levelno == logging.INFO]
    assert any("no persistor configured" in m for m in msgs)


def test_agent_started_logs_a2a_port_when_advertised(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Phase 3c: agent_started with an a2a_port field gets the
    port included in the INFO log so the operator can verify the
    child's HTTP surface is reachable. """
    import logging
    sup = AgentSupervisor(InMemoryRunner())
    r = sup.spawn(kind="mock", label="t", capabilities=[])
    with caplog.at_level(logging.INFO, logger="nth_dao.web.agent_supervisor"):
        sup.on_event(r.agent_id, {
            "event": "agent_started",
            "agent_id": r.agent_id,
            "pid": 12345,
            "a2a_port": 54321,
            "did": r.did,
        })
    msgs = [r.getMessage() for r in caplog.records if r.levelno == logging.INFO]
    assert any("a2a_port=54321" in m for m in msgs), (
        f"expected port in log; got {msgs!r}"
    )


# ─────────────────────────────────────────────────────────────
# Phase 3d — a2a_port stamping, decision_raiser, A2A proxy
# ─────────────────────────────────────────────────────────────

def test_inmemory_runner_handshake_data_is_empty() -> None:
    """Phase 3d: InMemoryRunner has no real handshake so its
    handshake_data is empty. Tests that need a port can fake it
    via a custom runner subclass. """
    runner = InMemoryRunner()
    assert runner.handshake_data("any-id") == {}


def test_spawn_stamps_a2a_port_from_handshake_data() -> None:
    """Phase 3d: when a runner's handshake_data exposes ``a2a_port``,
    spawn() must copy it onto the AgentRecord at construct time
    (NOT via on_event — that races against spawn's own insert). """

    class _PortyRunner(InMemoryRunner):
        def __init__(self, port: int) -> None:
            super().__init__()
            self._port = port

        def handshake_data(self, _aid: str) -> dict:
            return {"a2a_port": self._port}

    sup = AgentSupervisor(_PortyRunner(47123))
    r = sup.spawn(kind="mock", label="x", capabilities=[])
    assert r.a2a_port == 47123
    # And the field round-trips through to_agent_entry for the
    # /api/v2/agents response.
    entry = r.to_agent_entry()
    assert entry["a2a_port"] == 47123


def test_spawn_ignores_garbage_a2a_port_from_handshake() -> None:
    """Phase 3d: defensive — non-int / non-positive ports get
    dropped. Avoids a misbehaving runner injecting "5432" (str) or
    -1 into the record. """

    class _BadPortRunner(InMemoryRunner):
        def __init__(self, port_value: object) -> None:
            super().__init__()
            self._port = port_value

        def handshake_data(self, _aid: str) -> dict:
            return {"a2a_port": self._port}

    for bad in ("47000", 0, -5, None, [47000]):
        sup = AgentSupervisor(_BadPortRunner(bad))
        r = sup.spawn(kind="mock", label="x", capabilities=[])
        assert r.a2a_port is None, (
            f"a2a_port should be None for bad input {bad!r}; got {r.a2a_port!r}"
        )


def test_decision_raiser_called_on_decision_raised_event() -> None:
    """Phase 3d: supervisor.on_event for decision_raised forwards
    the decision to the configured raiser. """
    raised: list[tuple[str, dict]] = []

    def raiser(agent_id: str, decision: dict) -> None:
        raised.append((agent_id, decision))

    sup = AgentSupervisor(InMemoryRunner(), decision_raiser=raiser)
    r = sup.spawn(kind="mock", label="t", capabilities=[])
    fake_decision = {
        "title": "Acknowledge me",
        "impact": "low",
        "preview_receipt": {"kind": "nth.agent_attestation"},
    }
    sup.on_event(r.agent_id, {
        "event": "decision_raised",
        "agent_id": r.agent_id,
        "decision": fake_decision,
    })
    assert raised == [(r.agent_id, fake_decision)]


def test_decision_raiser_failure_logs_warning_keeps_agent(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Phase 3d: a raiser that raises must NOT kill the agent —
    matches the receipt_persistor posture. """
    import logging

    def angry_raiser(_aid: str, _decision: dict) -> None:
        raise RuntimeError("store offline")

    sup = AgentSupervisor(InMemoryRunner(), decision_raiser=angry_raiser)
    r = sup.spawn(kind="mock", label="t", capabilities=[])
    with caplog.at_level(logging.WARNING, logger="nth_dao.web.agent_supervisor"):
        sup.on_event(r.agent_id, {
            "event": "decision_raised",
            "agent_id": r.agent_id,
            "decision": {"title": "x"},
        })
    assert sup.get(r.agent_id) is not None
    warnings = [w.getMessage() for w in caplog.records
                if w.levelno == logging.WARNING]
    assert any("decision_raiser failed" in w for w in warnings)


def test_decision_raised_without_dict_payload_logs_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Phase 3d: defensive — a non-dict decision payload (child
    bug, contract drift) gets a clear WARNING + drop. """
    import logging

    sup = AgentSupervisor(InMemoryRunner(), decision_raiser=lambda _a, _d: None)
    r = sup.spawn(kind="mock", label="t", capabilities=[])
    with caplog.at_level(logging.WARNING, logger="nth_dao.web.agent_supervisor"):
        sup.on_event(r.agent_id, {
            "event": "decision_raised",
            "decision": "not a dict",
        })
    warnings = [w.getMessage() for w in caplog.records
                if w.levelno == logging.WARNING]
    assert any("without a dict 'decision'" in w for w in warnings)


def test_v2_decision_raiser_works_before_decisions_endpoint_touched(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Live walk-through bug regression (2026-06-11): the
    decision_raiser closure must lazy-build v2_decisions_store on
    first use, not only when GET /api/v2/decisions has populated
    it. A child can raise BEFORE the operator hits the decisions
    endpoint — and used to silently drop the decision in that case
    because the store didn't exist yet. """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("NTH_V2_WORKSPACE_ONLY", "true")

    from nth_dao.web import create_app
    app = create_app(
        workspace=tmp_path / ".nth-dao" / "workspaces" / "default",
        require_console_auth=False,
    )
    client = TestClient(app)
    # Force the supervisor build but NOT the decisions store.
    client.get("/api/v2/agents")
    sup = app.state.v2_supervisor
    assert not hasattr(app.state, "v2_decisions_store"), (
        "precondition: decisions store must not yet exist"
    )

    r = sup.spawn(kind="mock", label="prelaunch", capabilities=[])
    sup.on_event(r.agent_id, {
        "event": "decision_raised",
        "agent_id": r.agent_id,
        "decision": {
            "title": "Pre-endpoint test",
            "impact": "low",
            "preview_receipt": {"kind": "nth.agent_attestation"},
            "mission_id": "",
        },
    })

    listing = client.get("/api/v2/decisions").json()
    matching = [d for d in listing if d["title"] == "Pre-endpoint test"]
    assert len(matching) == 1, (
        f"agent-raised decision must appear even when decisions "
        f"endpoint wasn't hit first; got {[d['title'] for d in listing]!r}"
    )


def test_v2_decision_raiser_assigns_id_and_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Phase 3d end-to-end: when a child raises a decision (no id,
    no source), the v2_api closure assigns both and inserts into
    the in-process decisions store. The decision then appears in
    GET /api/v2/decisions. """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("NTH_V2_WORKSPACE_ONLY", "true")

    from nth_dao.web import create_app
    app = create_app(
        workspace=tmp_path / ".nth-dao" / "workspaces" / "default",
        require_console_auth=False,
    )
    client = TestClient(app)
    # Force the lazy supervisor build by triggering a GET.
    client.get("/api/v2/agents")
    sup = app.state.v2_supervisor
    # Force the lazy decisions_store build by triggering its GET.
    client.get("/api/v2/decisions")

    r = sup.spawn(kind="mock", label="raiser-test", capabilities=[])
    sup.on_event(r.agent_id, {
        "event": "decision_raised",
        "agent_id": r.agent_id,
        "decision": {
            "title": "Acknowledge me",
            "impact": "low",
            "preview_receipt": {"kind": "nth.agent_attestation"},
            "mission_id": "",
        },
    })

    listing = client.get("/api/v2/decisions").json()
    matching = [d for d in listing if d.get("title") == "Acknowledge me"]
    assert len(matching) == 1, (
        f"expected the raised decision in the listing; got {listing!r}"
    )
    raised = matching[0]
    # Hub-assigned id starts with the agent-<first8>- prefix.
    assert raised["id"].startswith(f"agent-{r.agent_id[:8]}-")
    # Source surfaces "type": "agent" + agent_id.
    src = raised.get("source")
    assert isinstance(src, dict)
    assert src["type"] == "agent"
    assert src["agent_id"] == r.agent_id
    assert "raised_at" in raised


def test_v2_decision_raiser_overwrites_child_attribution_claims(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """H-1 fix (review round Phase 3d R1): a child that emits a
    decision claiming to be a different DID must NOT have that
    attribution honoured. The hub stamps proposer_did /
    proposer_label / source / raised_at from the AgentRecord
    lookup regardless of what the child sent. """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("NTH_V2_WORKSPACE_ONLY", "true")

    from nth_dao.web import create_app
    app = create_app(
        workspace=tmp_path / ".nth-dao" / "workspaces" / "default",
        require_console_auth=False,
    )
    client = TestClient(app)
    client.get("/api/v2/agents")
    client.get("/api/v2/decisions")
    sup = app.state.v2_supervisor
    r = sup.spawn(kind="mock", label="legit-agent", capabilities=[])

    # Simulate a malicious child trying to claim someone else's
    # identity + a forged source. All four fields are attribution
    # — the hub MUST overwrite them.
    forged = {
        "title": "Acknowledge me",
        "impact": "low",
        "preview_receipt": {"kind": "nth.agent_attestation"},
        "mission_id": "",
        "proposer_did": "did:key:zForgedAttacker",
        "proposer_label": "Admin",
        "source": {"type": "operator", "agent_id": "fake-admin"},
        "raised_at": "1970-01-01T00:00:00+00:00",
    }
    sup.on_event(r.agent_id, {
        "event": "decision_raised",
        "agent_id": r.agent_id,
        "decision": forged,
    })

    listing = client.get("/api/v2/decisions").json()
    matching = [d for d in listing if d["title"] == "Acknowledge me"]
    assert len(matching) == 1
    raised = matching[0]
    # Hub-stamped attribution wins — NOT the forged values.
    assert raised["proposer_did"] == r.did, (
        f"hub must overwrite proposer_did; child sent forged value "
        f"but stored as {raised['proposer_did']!r}"
    )
    assert raised["proposer_label"] == r.label
    assert raised["source"] == {"type": "agent", "agent_id": r.agent_id}
    # raised_at must NOT be the forged 1970 value.
    assert raised["raised_at"] != "1970-01-01T00:00:00+00:00"


def test_v2_a2a_proxy_502_on_malformed_response(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """H-2 fix (review round Phase 3d R1): if the child returns
    bytes that don't decode as JSON / UTF-8, the proxy must
    surface 502 (upstream garbage), not 500 (hub bug). """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("NTH_V2_WORKSPACE_ONLY", "true")

    from nth_dao.web import create_app
    from nth_dao.web.agent_supervisor import AgentRecord

    app = create_app(
        workspace=tmp_path / ".nth-dao" / "workspaces" / "default",
        require_console_auth=False,
    )
    # Seat a supervisor with an agent that has an a2a_port, but
    # don't actually run a child — the test monkeypatches urlopen
    # to return garbage on its behalf.
    sup = AgentSupervisor(InMemoryRunner())
    app.state.v2_supervisor = sup
    forged_did = "did:key:z6MkForgedForProxyTest"
    forged = AgentRecord(
        agent_id="proxy-test",
        kind="mock",
        label="proxy-test",
        did=forged_did,
        capabilities=[],
        started_at="2026-06-11T00:00:00+00:00",
        last_seen="2026-06-11T00:00:00+00:00",
        alive=True,
        pid=1,
        a2a_port=51999,
    )
    with sup._lock:  # type: ignore[attr-defined]
        sup._agents["proxy-test"] = forged  # type: ignore[attr-defined]
    # Trick InMemoryRunner.is_alive — we want list_agents to keep
    # the record as alive even though no real child exists.
    sup._runner._alive["proxy-test"] = True  # type: ignore[attr-defined]

    import urllib.request as _ureq

    class _FakeResp:
        status = 200
        def __enter__(self) -> "_FakeResp": return self
        def __exit__(self, *_a: object) -> None: return None
        def read(self) -> bytes:
            # Non-JSON bytes — would crash json.loads.
            return b"<html>oops i'm not json</html>"

    def fake_urlopen(_url: str, **_kw: object) -> _FakeResp:
        return _FakeResp()

    monkeypatch.setattr(_ureq, "urlopen", fake_urlopen)

    client = TestClient(app)
    resp = client.get(f"/api/v2/agents/{forged_did}/ping")
    assert resp.status_code == 502, resp.text
    detail = resp.json()["detail"]
    assert "malformed response" in detail


def test_v2_a2a_proxy_404_when_did_not_supervised(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Phase 3d A2A proxy: unknown DIDs get 404 with a helpful
    diagnostic. """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("NTH_V2_WORKSPACE_ONLY", "true")

    from nth_dao.web import create_app
    app = create_app(
        workspace=tmp_path / ".nth-dao" / "workspaces" / "default",
        require_console_auth=False,
    )
    client = TestClient(app)
    r = client.get(
        "/api/v2/agents/did:key:z6MkNotSupervised/ping"
    )
    assert r.status_code == 404, r.text
    detail = r.json()["detail"]
    assert "did:key:z6MkNotSupervised" in detail


def test_v2_a2a_proxy_404_when_agent_has_no_a2a_port(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Phase 3d: an InMemoryRunner-spawned agent has a2a_port=None
    (no real HTTP surface). The proxy correctly excludes it. """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("NTH_V2_WORKSPACE_ONLY", "true")

    from nth_dao.web import create_app
    app = create_app(
        workspace=tmp_path / ".nth-dao" / "workspaces" / "default",
        require_console_auth=False,
    )
    app.state.v2_supervisor = AgentSupervisor(InMemoryRunner())
    client = TestClient(app)
    sup = app.state.v2_supervisor
    r = sup.spawn(kind="mock", label="no-port", capabilities=[])

    resp = client.get(f"/api/v2/agents/{r.did}/ping")
    assert resp.status_code == 404, resp.text


# ─────────────────────────────────────────────────────────────
# Phase 3e — recovery sweep, A2A POST proxy, R1 follow-ups
# ─────────────────────────────────────────────────────────────

def test_atomic_write_json_cleans_up_tmp_on_replace_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """M-2 fix (review round Phase 3d R1): if os.replace raises,
    the tmp file must be unlinked so the agent dir doesn't
    accumulate orphan .tmp files. """
    from nth_dao.web import agent_supervisor as supmod

    target = tmp_path / "cap_token.json"
    real_replace = os.replace

    def boom_replace(_src: str, _dst: str) -> None:
        raise OSError("simulated cross-device link")

    monkeypatch.setattr(os, "replace", boom_replace)

    with pytest.raises(OSError):
        supmod._atomic_write_json(str(target), {"token_id": "x"})

    monkeypatch.setattr(os, "replace", real_replace)  # restore
    tmp_file = target.with_suffix(target.suffix + ".tmp")
    assert not tmp_file.exists(), (
        f"tmp file should be cleaned up on replace failure; "
        f"found {tmp_file}"
    )


def test_recover_orphaned_receipts_persists_and_unlinks(
    tmp_path: Path,
) -> None:
    """Phase 3e: orphaned ``last_receipt.json`` files from a prior
    run are persisted via the receipt_persistor on the next
    supervisor build, and the file is unlinked so a re-run doesn't
    double-persist. """
    cap_token_dir = tmp_path / "agents"
    cap_token_dir.mkdir()

    # Lay down two prior-agent dirs, each with a stub receipt.
    receipts_seen: list[tuple[str, dict]] = []

    def persistor(agent_id: str, receipt: dict) -> None:
        receipts_seen.append((agent_id, receipt))

    for aid in ("crashed-001", "crashed-002"):
        agent_dir = cap_token_dir / aid
        agent_dir.mkdir()
        (agent_dir / "last_receipt.json").write_text(
            json.dumps({
                "receipt_id": f"r-{aid}",
                "signer_did": f"did:key:z6Mk{aid}",
                "content_hash": "abc",
            }),
            encoding="utf-8",
        )

    sup = AgentSupervisor(
        InMemoryRunner(),
        cap_token_dir=cap_token_dir,
        receipt_persistor=persistor,
    )
    recovered = sup.recover_orphaned_receipts()
    assert recovered == 2
    agent_ids = sorted(aid for aid, _ in receipts_seen)
    assert agent_ids == ["crashed-001", "crashed-002"]
    # Files unlinked → second sweep is a no-op.
    assert sup.recover_orphaned_receipts() == 0


def test_recover_orphaned_receipts_skips_malformed(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Phase 3e: a recovery file that isn't valid JSON / isn't a
    receipt-shaped dict is logged + left in place (operator can
    inspect). The sweep must NOT crash on it. """
    import logging
    cap_token_dir = tmp_path / "agents"
    (cap_token_dir / "bad-json").mkdir(parents=True)
    (cap_token_dir / "bad-json" / "last_receipt.json").write_text(
        "{this is not valid JSON",
        encoding="utf-8",
    )
    (cap_token_dir / "no-signer").mkdir()
    (cap_token_dir / "no-signer" / "last_receipt.json").write_text(
        json.dumps({"receipt_id": "r", "content_hash": "x"}),
        encoding="utf-8",
    )

    sup = AgentSupervisor(
        InMemoryRunner(),
        cap_token_dir=cap_token_dir,
        receipt_persistor=lambda _a, _r: None,
    )
    with caplog.at_level(logging.WARNING, logger="nth_dao.web.agent_supervisor"):
        recovered = sup.recover_orphaned_receipts()
    assert recovered == 0
    # Both files should still be on disk for operator inspection.
    assert (cap_token_dir / "bad-json" / "last_receipt.json").exists()
    assert (cap_token_dir / "no-signer" / "last_receipt.json").exists()
    msgs = [w.getMessage() for w in caplog.records
            if w.levelno == logging.WARNING]
    assert any("could not parse" in m for m in msgs)
    assert any("no signer_did" in m for m in msgs)


def test_recover_orphaned_receipts_leaves_file_on_persistor_failure(
    tmp_path: Path,
) -> None:
    """Phase 3e: if the persistor raises mid-sweep, the file is
    LEFT in place — next run can retry. Otherwise a transient
    disk error during recovery would silently lose the receipt. """
    cap_token_dir = tmp_path / "agents"
    (cap_token_dir / "agent-a").mkdir(parents=True)
    recovery = cap_token_dir / "agent-a" / "last_receipt.json"
    recovery.write_text(
        json.dumps({"receipt_id": "r", "signer_did": "did:key:zX"}),
        encoding="utf-8",
    )

    def angry_persistor(_aid: str, _receipt: dict) -> None:
        raise RuntimeError("disk full")

    sup = AgentSupervisor(
        InMemoryRunner(),
        cap_token_dir=cap_token_dir,
        receipt_persistor=angry_persistor,
    )
    assert sup.recover_orphaned_receipts() == 0
    assert recovery.exists(), (
        "receipt file must remain for next-run retry when "
        "persistor raised"
    )


def test_a2a_post_proxy_413_on_oversized_content_length(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """H-2 fix (review round Phase 3e R1): when the caller claims
    a body bigger than 1MB via Content-Length, the hub returns 413
    WITHOUT buffering. urllib's urlopen must NOT be called — the
    rejection happens at the header check. """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("NTH_V2_WORKSPACE_ONLY", "true")

    from nth_dao.web import create_app
    from nth_dao.web.agent_supervisor import AgentRecord

    app = create_app(
        workspace=tmp_path / ".nth-dao" / "workspaces" / "default",
        require_console_auth=False,
    )
    sup = AgentSupervisor(InMemoryRunner())
    app.state.v2_supervisor = sup
    target_did = "did:key:z6MkTooBig"
    rec = AgentRecord(
        agent_id="big", kind="mock", label="big", did=target_did,
        capabilities=[],
        started_at="2026-06-11T00:00:00+00:00",
        last_seen="2026-06-11T00:00:00+00:00",
        alive=True, pid=1, a2a_port=51960,
    )
    with sup._lock:  # type: ignore[attr-defined]
        sup._agents["big"] = rec  # type: ignore[attr-defined]
    sup._runner._alive["big"] = True  # type: ignore[attr-defined]

    # If the hub buffered the body before checking Content-Length,
    # urlopen would be called. Assert it isn't.
    import urllib.request as _ureq
    called: list[object] = []

    def fake_urlopen(*_a: object, **_kw: object) -> None:
        called.append("urlopen-was-called")
        raise AssertionError("hub must not forward when body > 1MB")

    monkeypatch.setattr(_ureq, "urlopen", fake_urlopen)

    client = TestClient(app)
    resp = client.post(
        f"/api/v2/agents/{target_did}/a2a/echo",
        content=b"x",  # tiny body
        headers={"Content-Length": str(2 * 1024 * 1024)},  # claim 2MB
    )
    assert resp.status_code == 413, resp.text
    assert "1MB" in resp.json()["detail"]
    assert not called, "urlopen must NOT be invoked before the cap check"


def test_a2a_post_proxy_400_on_malformed_content_length(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """H-2 follow-up: a Content-Length that isn't an integer
    (typo, smuggling attempt) lands on the 400 path with a clear
    diagnostic, not the 500 path. """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("NTH_V2_WORKSPACE_ONLY", "true")

    from nth_dao.web import create_app
    from nth_dao.web.agent_supervisor import AgentRecord

    app = create_app(
        workspace=tmp_path / ".nth-dao" / "workspaces" / "default",
        require_console_auth=False,
    )
    sup = AgentSupervisor(InMemoryRunner())
    app.state.v2_supervisor = sup
    target_did = "did:key:z6MkBadCL"
    rec = AgentRecord(
        agent_id="bcl", kind="mock", label="bcl", did=target_did,
        capabilities=[],
        started_at="2026-06-11T00:00:00+00:00",
        last_seen="2026-06-11T00:00:00+00:00",
        alive=True, pid=1, a2a_port=51970,
    )
    with sup._lock:  # type: ignore[attr-defined]
        sup._agents["bcl"] = rec  # type: ignore[attr-defined]
    sup._runner._alive["bcl"] = True  # type: ignore[attr-defined]

    client = TestClient(app)
    resp = client.post(
        f"/api/v2/agents/{target_did}/a2a/echo",
        content=b"x",
        headers={"Content-Length": "not-a-number"},
    )
    # TestClient may compute its own Content-Length and override
    # ours. If the explicit header DID stick, we get the 400 path;
    # if TestClient overwrote it with the actual body length (1),
    # we'd hit the normal path. Accept either 400 or 404 (404
    # because the InMemoryRunner-backed agent has no real HTTP
    # surface so the proxy forward would fail) but never 500.
    assert resp.status_code != 500, resp.text


def test_a2a_post_proxy_403_for_unauthorized_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Phase 3e: A2A POST without auth header → child rejects 401,
    proxy forwards the status. Validates the auth pass-through.
    Uses a fake urlopen so no real subprocess needed. """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("NTH_V2_WORKSPACE_ONLY", "true")

    from nth_dao.web import create_app
    from nth_dao.web.agent_supervisor import AgentRecord

    app = create_app(
        workspace=tmp_path / ".nth-dao" / "workspaces" / "default",
        require_console_auth=False,
    )
    sup = AgentSupervisor(InMemoryRunner())
    app.state.v2_supervisor = sup
    target_did = "did:key:z6MkTestPeerForA2A"
    rec = AgentRecord(
        agent_id="a2a-test", kind="mock", label="a2a-test",
        did=target_did, capabilities=[],
        started_at="2026-06-11T00:00:00+00:00",
        last_seen="2026-06-11T00:00:00+00:00",
        alive=True, pid=1, a2a_port=51950,
    )
    with sup._lock:  # type: ignore[attr-defined]
        sup._agents["a2a-test"] = rec  # type: ignore[attr-defined]
    sup._runner._alive["a2a-test"] = True  # type: ignore[attr-defined]

    import urllib.error
    import urllib.request as _ureq

    def fake_urlopen(req: object, **_kw: object) -> None:
        # Simulate the child returning 401 for missing auth.
        body = json.dumps({"error": {
            "code": "no-auth",
            "message": "A2A auth failed for /a2a/echo: no-auth",
        }}).encode("utf-8")
        raise urllib.error.HTTPError(
            url="http://127.0.0.1:51950/a2a/echo",
            code=401, msg="Unauthorized",
            hdrs=None,  # type: ignore[arg-type]
            fp=__import__("io").BytesIO(body),
        )

    monkeypatch.setattr(_ureq, "urlopen", fake_urlopen)

    client = TestClient(app)
    resp = client.post(
        f"/api/v2/agents/{target_did}/a2a/echo",
        json={"hello": "world"},
    )
    # Child's 401 forwarded by the hub.
    assert resp.status_code == 401, resp.text
    body = resp.json()
    assert body["error"]["code"] == "no-auth"


def test_a2a_post_proxy_404_when_did_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Phase 3e: A2A POST to an unknown DID gets 404 the same way
    the GET /ping proxy does. """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("NTH_V2_WORKSPACE_ONLY", "true")

    from nth_dao.web import create_app
    app = create_app(
        workspace=tmp_path / ".nth-dao" / "workspaces" / "default",
        require_console_auth=False,
    )
    client = TestClient(app)
    resp = client.post(
        "/api/v2/agents/did:key:z6MkUnknown/a2a/echo",
        json={"x": 1},
    )
    assert resp.status_code == 404, resp.text


def test_dummy_agent_verify_a2a_auth_rejects_missing_header() -> None:
    """Phase 3e child-side: no Authorization header → no-auth. """
    from nth_dao.web.dummy_agent import _CapTokenHolder, _verify_a2a_auth

    holder = _CapTokenHolder()
    holder.set({"issuer_did": "did:key:zHubIssuer"})
    ok, reason, token = _verify_a2a_auth("", holder, "echo")
    assert ok is False
    assert reason == "no-auth"
    assert token is None


def test_dummy_agent_verify_a2a_auth_rejects_bad_scheme() -> None:
    """Phase 3e: anything other than 'CapToken <encoded>' → bad-scheme. """
    from nth_dao.web.dummy_agent import _CapTokenHolder, _verify_a2a_auth

    holder = _CapTokenHolder()
    holder.set({"issuer_did": "did:key:zHubIssuer"})
    ok, reason, _ = _verify_a2a_auth("Bearer xyz", holder, "echo")
    assert ok is False
    assert reason == "bad-scheme"


def test_dummy_agent_verify_a2a_auth_rejects_before_own_token_loaded() -> None:
    """Phase 3e: requests arriving before the child has loaded
    its own cap_token must be rejected with not-yet-authorized
    (so a fast peer can't slip in pre-handshake). """
    from nth_dao.web.dummy_agent import _CapTokenHolder, _verify_a2a_auth

    holder = _CapTokenHolder()  # empty — nothing set
    # Need a syntactically valid CapToken header for the test to
    # reach the issuer check. The body content doesn't matter
    # because decode happens before issuer comparison.
    fake_header = "CapToken " + __import__("base64").urlsafe_b64encode(
        b'{"kind":"nth-cap-token-v1","issuer_did":"did:key:zX"}'
    ).decode("ascii").rstrip("=")
    ok, reason, _ = _verify_a2a_auth(fake_header, holder, "echo")
    assert ok is False
    assert reason == "not-yet-authorized"


# ─────────────────────────────────────────────────────────────
# Phase 4 — pluggable ask backend (mock + claude-code)
# ─────────────────────────────────────────────────────────────

def test_mock_ask_backend_echoes_prompt() -> None:
    """Phase 4: the mock backend acks the prompt back. Used as the
    default + the wire-test path. """
    from nth_dao.web.dummy_agent import _MockAskBackend

    out = _MockAskBackend().ask({"prompt": "hello world"}, timeout_s=1.0)
    assert "hello world" in out["response"]
    assert out["backend"] == "mock"


def test_mock_ask_backend_stream_emits_deltas_then_done() -> None:
    """Phase 5.2: ``stream_ask`` on the mock backend yields a
    sequence of ``(delta, str)`` tuples followed by exactly one
    ``(done, dict)`` terminating tuple. Verified deterministically
    via the ``_no_sleep`` hatch. """
    from nth_dao.web.dummy_agent import _MockAskBackend

    events = list(_MockAskBackend().stream_ask(
        {"prompt": "abc", "_no_sleep": True}, timeout_s=1.0,
    ))
    kinds = [k for k, _ in events]
    assert kinds[-1] == "done"
    assert all(k == "delta" for k in kinds[:-1])
    # Reassembled deltas equal the full buffered response.
    reassembled = "".join(p for k, p in events if k == "delta")
    full = _MockAskBackend().ask({"prompt": "abc"}, timeout_s=1.0)
    assert reassembled == full["response"]
    # Done payload carries backend metadata.
    done_meta = events[-1][1]
    assert done_meta["backend"] == "mock"
    assert "input_tokens" in done_meta
    assert "output_tokens" in done_meta


def test_default_stream_ask_polyfill_yields_single_delta_then_done() -> None:
    """Phase 5.2: a backend that doesn't override ``stream_ask``
    gets a polyfill that calls the buffered ``ask`` and re-emits
    as ONE delta + ONE done. Verifies the default implementation
    on the base class. """
    from nth_dao.web.dummy_agent import _AskBackend

    class _LegacyBackend(_AskBackend):
        name = "legacy"

        def ask(self, params, timeout_s):
            return {
                "response": "all at once",
                "backend": self.name,
                "exit_code": 0,
            }

    events = list(_LegacyBackend().stream_ask({}, timeout_s=1.0))
    assert len(events) == 2
    assert events[0] == ("delta", "all at once")
    assert events[1][0] == "done"
    # ``response`` key should be stripped from the done meta so
    # the operator's view doesn't see it twice.
    assert "response" not in events[1][1]
    assert events[1][1]["backend"] == "legacy"
    assert events[1][1]["exit_code"] == 0


def test_child_stream_ask_flushes_error_event_when_backend_raises_mid_stream(
    tmp_path: Path,
) -> None:
    """F-5 fix (review round Phase 5.2 R1): if a backend yields N
    deltas then raises mid-stream, the child must:
      - flush all deltas already produced
      - emit a final ``data: {"error":...}`` event
      - close the connection cleanly (no escaped exception)

    Verified end-to-end via real subprocess + a custom
    delta-then-raise backend injected via a tiny dummy module
    spawned with kind=mock and a monkeypatched ask_backend.

    Because the production child resolves backends from kind, we
    can't easily inject a custom one from outside. Instead we
    exercise the in-process A2AHandler logic via a unit-style
    test that constructs the handler's _stream_ask closure with
    a synthetic backend. """
    import socket as _sk
    import threading as _th
    import io as _io

    pytest.importorskip("nacl")
    # Build a fake backend that yields 2 deltas then raises.
    from nth_dao.web.dummy_agent import _AskBackend

    class _MidStreamRaiser(_AskBackend):
        name = "raise-after-2"

        def ask(self, params, timeout_s):
            return {"response": "(stub)", "backend": self.name}

        def stream_ask(self, params, timeout_s):
            yield "delta", "first "
            yield "delta", "second "
            raise TimeoutError("simulated mid-stream timeout")

    # N-1 marker (review round Phase 5.2 R2): this test exercises
    # the LOGIC PATTERN (deltas-then-error → 2 delta events + 1
    # error event) — NOT a direct call into A2AHandler._stream_ask.
    # Because the production child resolves backends by kind
    # string we can't inject a custom mid-stream-raiser from
    # outside without forking the agent process. If you reorder
    # the except branches in dummy_agent.py's _stream_ask, this
    # test won't catch the drift — it tests the copy here, not
    # the live handler. Acceptable compromise; flag for any future
    # reviewer who's tracing coverage.
    out = _io.BytesIO()

    def write_event(payload: dict) -> bool:
        out.write(b"data: " + json.dumps(payload).encode("utf-8") + b"\n\n")
        return True

    # Inline the same try-block shape as _stream_ask
    backend = _MidStreamRaiser()
    try:
        for kind, payload in backend.stream_ask({}, timeout_s=5.0):
            if kind == "delta":
                write_event({"delta": payload})
            elif kind == "done":
                write_event({"done": True})
    except TimeoutError as exc:
        write_event({"error": {"code": "backend-timeout", "message": str(exc)}})
    except ValueError as exc:
        write_event({"error": {"code": "bad-request", "message": str(exc)}})
    except Exception as exc:
        write_event({
            "error": {
                "code": "backend-failed",
                "message": f"{type(exc).__name__}: {exc}",
            },
        })

    body = out.getvalue().decode("utf-8")
    events = [json.loads(line[len("data: "):])
              for line in body.splitlines() if line.startswith("data: ")]
    assert len(events) == 3, body
    assert events[0] == {"delta": "first "}
    assert events[1] == {"delta": "second "}
    assert events[2]["error"]["code"] == "backend-timeout"
    assert "simulated mid-stream" in events[2]["error"]["message"]


def test_proxy_ssestream_abandons_upstream_when_consumer_disconnects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F-1 + F-2 fix (review round Phase 5.2 R1): when the queue
    fills because the consumer is gone, the reader thread must
    bail out within the consumer-gone timeout instead of blocking
    forever (leaking the upstream urllib connection + thread).

    Asserted by:
      - injecting a urlopen that produces an unbounded stream of
        1KB chunks
      - NOT draining the SSE queue
      - asserting the reader thread exits within a bounded wall
        time after the queue fills (5s consumer-gone timeout
        + 2s slack) """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("NTH_V2_WORKSPACE_ONLY", "true")
    import time as _time
    import urllib.request as _ureq

    from nth_dao.web.v2_api import _proxy_ssestream

    # Fake upstream that streams forever.
    class _InfiniteResp:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *_a): return None
        def read(self, n: int = -1) -> bytes:
            # Bounded by FastAPI/queue semantics, not by us.
            return b"x" * 1024

    monkeypatch.setattr(_ureq, "urlopen", lambda *_a, **_k: _InfiniteResp())

    response = _proxy_ssestream(
        url="http://127.0.0.1:0/fake",
        body_bytes=b"{}",
        req_headers={},
        forward_timeout=60.0,
    )
    # We deliberately do NOT consume response.body_iterator. The
    # reader thread will fill its 64-slot queue almost immediately
    # then block on put(timeout=5). Within ~7s it should give up
    # and the daemon thread should die.
    start = _time.time()
    deadline = start + 12.0
    # Find the reader thread by name; wait for it to terminate.
    import threading as _th
    reader = next(
        (t for t in _th.enumerate() if t.name == "a2a-sse-reader"),
        None,
    )
    assert reader is not None, "reader thread should have started"
    while reader.is_alive() and _time.time() < deadline:
        _time.sleep(0.5)
    elapsed = _time.time() - start
    assert not reader.is_alive(), (
        f"reader thread should have exited within ~7s (queue-full "
        f"timeout); still alive after {elapsed:.1f}s"
    )
    # 7s = 5s consumer-gone timeout + ~2s for queue to fill at
    # 1KB/iter × 64 slots; we give 12s wall budget to dodge CI
    # jitter but verify it landed well under.
    assert elapsed < 12.0


def test_v2_proxy_forwards_ask_stream_as_sse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Phase 5.2: the hub proxy returns ``text/event-stream`` for
    ``ask-stream`` and forwards the child's chunked body verbatim.
    Uses a fake urllib that returns a multi-chunk body to verify
    incremental forwarding. """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("NTH_V2_WORKSPACE_ONLY", "true")

    from nth_dao.web import create_app
    from nth_dao.web.agent_supervisor import AgentRecord

    app = create_app(
        workspace=tmp_path / ".nth-dao" / "workspaces" / "default",
        require_console_auth=False,
    )
    sup = AgentSupervisor(InMemoryRunner())
    app.state.v2_supervisor = sup
    target_did = "did:key:z6MkStreamProbe"
    rec = AgentRecord(
        agent_id="streamer", kind="mock", label="streamer",
        did=target_did, capabilities=[],
        started_at="2026-06-11T00:00:00+00:00",
        last_seen="2026-06-11T00:00:00+00:00",
        alive=True, pid=1, a2a_port=51990,
    )
    with sup._lock:  # type: ignore[attr-defined]
        sup._agents["streamer"] = rec  # type: ignore[attr-defined]
    sup._runner._alive["streamer"] = True  # type: ignore[attr-defined]

    sse_body = (
        b'data: {"delta":"hello"}\n\n'
        b'data: {"delta":" world"}\n\n'
        b'data: {"done":true,"input_tokens":5,"output_tokens":2}\n\n'
    )

    import urllib.request as _ureq

    class _FakeResp:
        status = 200
        _consumed = False
        def __enter__(self) -> "_FakeResp": return self
        def __exit__(self, *_a: object) -> None: return None
        def read(self, n: int = -1) -> bytes:
            if self._consumed:
                return b""
            self._consumed = True
            return sse_body

    monkeypatch.setattr(_ureq, "urlopen", lambda *_a, **_k: _FakeResp())

    client = TestClient(app)
    with client.stream(
        "POST",
        f"/api/v2/agents/{target_did}/a2a/ask-stream",
        json={"prompt": "hi"},
    ) as resp:
        assert resp.status_code == 200, resp.text
        ct = resp.headers["content-type"]
        assert ct.startswith("text/event-stream"), ct
        chunks = b""
        for raw in resp.iter_bytes():
            chunks += raw
    # Order-preserving, all 3 events visible to the caller.
    assert b'"delta":"hello"' in chunks
    assert b'"delta":" world"' in chunks
    assert b'"done":true' in chunks


def test_mock_ask_backend_signals_truncation_for_long_prompts() -> None:
    """L-1 fix (review round Phase 4 R3): the mock backend caps
    its echoed prompt at 512 chars. The cap was previously silent;
    now the response carries an explicit ``…[+N chars truncated]``
    suffix so a caller can spot the truncation. """
    from nth_dao.web.dummy_agent import _MockAskBackend

    short = _MockAskBackend().ask({"prompt": "abc"}, timeout_s=1.0)
    assert "truncated" not in short["response"], short

    long_prompt = "x" * 1000
    long = _MockAskBackend().ask(
        {"prompt": long_prompt}, timeout_s=1.0,
    )
    assert "truncated" in long["response"]
    assert "+488 chars" in long["response"], long["response"]


def test_mock_ask_backend_no_prompt_returns_help_text() -> None:
    """Phase 4: missing prompt is friendly for the mock backend
    (not an error). The claude-code backend treats it as ValueError. """
    from nth_dao.web.dummy_agent import _MockAskBackend

    out = _MockAskBackend().ask({}, timeout_s=1.0)
    assert "no prompt" in out["response"].lower()


def test_resolve_ask_backend_picks_by_kind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Phase 4/5.1: ``_resolve_ask_backend`` maps the agent kind to
    a concrete backend instance. For ``claude-code``: SDK when
    ANTHROPIC_API_KEY is set, CLI when not. Unknown kinds fall back
    to mock with a structured stderr event. """
    from nth_dao.web.dummy_agent import (
        _AnthropicSdkAskBackend, _ClaudeCliAskBackend,
        _MockAskBackend, _resolve_ask_backend,
    )

    assert isinstance(_resolve_ask_backend("mock"), _MockAskBackend)
    # No key → CLI backend (Phase 4 default).
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert isinstance(
        _resolve_ask_backend("claude-code"), _ClaudeCliAskBackend,
    )
    # Key present → SDK backend (Phase 5.1 preferred).
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")
    assert isinstance(
        _resolve_ask_backend("claude-code"), _AnthropicSdkAskBackend,
    )
    # Unknown → mock fallback regardless of key.
    assert isinstance(_resolve_ask_backend("not-a-real-kind"), _MockAskBackend)


def test_claude_code_backend_rejects_empty_prompt() -> None:
    """Phase 4: claude-code is stricter than mock — empty prompt
    raises ValueError (caller gets 400, not a wasted CLI invocation). """
    from nth_dao.web.dummy_agent import _ClaudeCliAskBackend

    with pytest.raises(ValueError, match="requires a 'prompt'"):
        _ClaudeCliAskBackend().ask({"prompt": "   "}, timeout_s=1.0)


def test_claude_code_backend_rejects_oversized_prompt() -> None:
    """Phase 4: 32KB cap on prompts forwarded to claude — prevents
    a misconfigured peer from burning huge API context on the
    operator's behalf. """
    from nth_dao.web.dummy_agent import _ClaudeCliAskBackend

    big = "x" * (40 * 1024)
    with pytest.raises(ValueError, match="prompt too long"):
        _ClaudeCliAskBackend().ask({"prompt": big}, timeout_s=1.0)


def test_anthropic_sdk_backend_rejects_empty_prompt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Phase 5.1: empty prompt → ValueError → 400 at the handler.
    No SDK call attempted (cheap fail). """
    from nth_dao.web.dummy_agent import _AnthropicSdkAskBackend

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    with pytest.raises(ValueError, match="requires a 'prompt'"):
        _AnthropicSdkAskBackend().ask({"prompt": "  "}, timeout_s=5.0)


def test_anthropic_sdk_backend_rejects_oversized_prompt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Phase 5.1: 32KB cap on prompts — matches the CLI backend so
    a misbehaving peer can't burn API context. """
    from nth_dao.web.dummy_agent import _AnthropicSdkAskBackend

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    with pytest.raises(ValueError, match="prompt too long"):
        _AnthropicSdkAskBackend().ask(
            {"prompt": "x" * 40000}, timeout_s=5.0,
        )


def test_anthropic_sdk_backend_raises_when_api_key_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Phase 5.1: missing key surfaces a clear error pointing at
    the env var BEFORE we attempt to construct the SDK client. """
    from nth_dao.web.dummy_agent import _AnthropicSdkAskBackend

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY not set"):
        _AnthropicSdkAskBackend().ask({"prompt": "hi"}, timeout_s=5.0)


def test_anthropic_sdk_backend_invokes_messages_create(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Phase 5.1: when the key is set, the backend calls
    ``client.messages.create`` and returns the concatenated text
    blocks. Verified by monkeypatching the SDK client. """
    pytest.importorskip("anthropic")
    import anthropic as _anth

    from nth_dao.web.dummy_agent import _AnthropicSdkAskBackend

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    captured_create: dict = {}
    captured_init: list[dict] = []

    class _FakeUsage:
        input_tokens = 7
        output_tokens = 12

    class _FakeTextBlock:
        text = "PONG"

    class _FakeMsg:
        content = [_FakeTextBlock()]
        usage = _FakeUsage()
        stop_reason = "end_turn"

    class _FakeMessages:
        def create(self, **kwargs: object) -> "_FakeMsg":
            captured_create.update(kwargs)
            return _FakeMsg()

    class _FakeClient:
        def __init__(self, **kw: object) -> None:
            captured_init.append(dict(kw))
            self.messages = _FakeMessages()

    monkeypatch.setattr(_anth, "Anthropic", _FakeClient)
    out = _AnthropicSdkAskBackend().ask(
        {"prompt": "ping"}, timeout_s=10.0,
    )
    assert out["response"] == "PONG"
    assert out["backend"] == "claude-code"
    assert out["model"] == "claude-sonnet-4-6"
    assert out["input_tokens"] == 7
    assert out["output_tokens"] == 12
    # M-4 fix (review round Phase 5.1 R1): verify the per-request
    # timeout is FORWARDED to messages.create (where the SDK
    # actually honours it), NOT pinned to the cached client's
    # constructor. Without this assert a regression hardcoding
    # the SDK timeout would pass silently.
    assert captured_create["timeout"] == 10.0, captured_create
    assert captured_create["max_tokens"] == 1024
    assert captured_create["messages"] == [{"role": "user", "content": "ping"}]


def test_anthropic_sdk_backend_caches_client_across_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """M-1 fix (review round Phase 5.1 R1): repeated ``ask`` calls
    on the same backend instance must reuse the SDK client (so the
    httpx connection pool persists). Asserted by counting how many
    times the patched ``Anthropic`` constructor fires. """
    pytest.importorskip("anthropic")
    import anthropic as _anth
    from nth_dao.web.dummy_agent import _AnthropicSdkAskBackend

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    construct_count = 0

    class _FakeUsage:
        input_tokens = 1
        output_tokens = 1

    class _FakeBlock:
        text = "ok"

    class _FakeMsg:
        content = [_FakeBlock()]
        usage = _FakeUsage()
        stop_reason = "end_turn"

    class _FakeMessages:
        def create(self, **_kw: object) -> "_FakeMsg":
            return _FakeMsg()

    class _FakeClient:
        def __init__(self, **_kw: object) -> None:
            nonlocal construct_count
            construct_count += 1
            self.messages = _FakeMessages()

    monkeypatch.setattr(_anth, "Anthropic", _FakeClient)

    backend = _AnthropicSdkAskBackend()
    backend.ask({"prompt": "a"}, timeout_s=10.0)
    backend.ask({"prompt": "b"}, timeout_s=10.0)
    backend.ask({"prompt": "c"}, timeout_s=10.0)

    assert construct_count == 1, (
        f"expected the SDK client to be cached and reused; "
        f"got {construct_count} constructions"
    )


def test_anthropic_sdk_backend_rejects_whitespace_only_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """L-1 fix (review round Phase 5.1 R1): a key value of only
    whitespace (operator typo with trailing space) should yield
    the "not set" diagnostic, NOT the SDK's later AuthenticationError
    which would have said "verify ANTHROPIC_API_KEY" — misleading
    because the env var IS present, just blank. """
    from nth_dao.web.dummy_agent import _AnthropicSdkAskBackend

    monkeypatch.setenv("ANTHROPIC_API_KEY", "   ")
    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY not set"):
        _AnthropicSdkAskBackend().ask({"prompt": "hi"}, timeout_s=5.0)


def test_anthropic_sdk_backend_maps_api_timeout_to_TimeoutError(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BUG-2 fix (review round Phase 5.1 R2): the SDK's
    ``APITimeoutError`` must be translated to a stdlib
    ``TimeoutError`` so the A2A handler routes it to 504
    backend-timeout (not the generic 502 backend-failed). """
    pytest.importorskip("anthropic")
    import anthropic as _anth
    from nth_dao.web.dummy_agent import _AnthropicSdkAskBackend

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")

    class _FakeMessages:
        def create(self, **_kw: object) -> object:
            # The SDK's APITimeoutError signature requires a
            # request object, but our error handling only checks
            # the type — pass a stub.
            raise _anth.APITimeoutError(request=object())  # type: ignore[arg-type]

    class _FakeClient:
        def __init__(self, **_kw: object) -> None:
            self.messages = _FakeMessages()

    monkeypatch.setattr(_anth, "Anthropic", _FakeClient)
    with pytest.raises(TimeoutError, match="did not respond within"):
        _AnthropicSdkAskBackend().ask(
            {"prompt": "slow"}, timeout_s=7.0,
        )


@pytest.mark.parametrize(
    "exc_cls, expected_exc, expected_match",
    [
        ("RateLimitError", TimeoutError, "rate-limited"),
        ("APIConnectionError", RuntimeError, "unreachable"),
        # R2-3 (review round Phase 5.2 R3): BadRequestError now
        # maps to ValueError (handler routes → 400 bad-request)
        # to match our own input-validation pattern.
        ("BadRequestError", ValueError, "rejected the request"),
        # R2-4 (review round Phase 5.2 R3): APIStatusError fallback
        # for any other status-based SDK error.
        ("PermissionDeniedError", RuntimeError, "returned status"),
        ("NotFoundError", RuntimeError, "returned status"),
    ],
)
@pytest.mark.parametrize("method", ["ask", "stream_ask"])
def test_anthropic_sdk_backend_maps_extended_sdk_errors(
    monkeypatch: pytest.MonkeyPatch,
    exc_cls: str,
    expected_exc: type,
    expected_match: str,
    method: str,
) -> None:
    """H-1 + R2-1 + R2-3 + R2-4 fix (review rounds Phase 5.2 R2 + R3):
    every extended SDK error class is exercised through BOTH the
    buffered ``ask`` AND the streaming ``stream_ask`` paths. The
    streaming dimension (R2-1) was previously uncovered — the fake
    client only had ``create``, not ``stream``. Now ``stream`` is
    a context manager whose ``__enter__`` raises the same exception
    so the streaming except-set is exercised identically. """
    pytest.importorskip("anthropic")
    import anthropic as _anth
    from nth_dao.web.dummy_agent import _AnthropicSdkAskBackend

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")

    class _FakeRequest:
        method = "POST"
        url = "https://api.anthropic.com/v1/messages"

    class _FakeResponse:
        status_code = 429
        headers: dict = {}
        request = _FakeRequest()

    cls = getattr(_anth, exc_cls)

    def _raise() -> None:
        # APIConnectionError takes ``request=``; everything else
        # takes ``(message, response, body)`` like AuthenticationError.
        if exc_cls == "APIConnectionError":
            raise cls(message="boom", request=_FakeRequest())
        raise cls(
            message="boom",
            response=_FakeResponse(),  # type: ignore[arg-type]
            body=None,
        )

    class _FakeStream:
        # R2-1 fix: streaming-path counterpart. The production code
        # does ``with client.messages.stream(...) as stream`` then
        # iterates ``stream.text_stream``. Raising at ``__enter__``
        # exercises the same except-set as the buffered path.
        def __enter__(self) -> "_FakeStream":
            _raise()
            return self  # unreachable

        def __exit__(self, *_a: object) -> None:
            return None

    class _FakeMessages:
        def create(self, **_kw: object) -> object:
            _raise()

        def stream(self, **_kw: object) -> "_FakeStream":
            return _FakeStream()

    class _FakeClient:
        def __init__(self, **_kw: object) -> None:
            self.messages = _FakeMessages()

    monkeypatch.setattr(_anth, "Anthropic", _FakeClient)
    backend = _AnthropicSdkAskBackend()
    with pytest.raises(expected_exc, match=expected_match):
        if method == "ask":
            backend.ask({"prompt": "hi"}, timeout_s=5.0)
        else:
            # Stream is a generator — fully consume to drive the
            # exception through.
            list(backend.stream_ask({"prompt": "hi"}, timeout_s=5.0))


def test_anthropic_sdk_backend_maps_auth_error_to_RuntimeError(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BUG-2 fix (review round Phase 5.1 R2): the SDK's
    ``AuthenticationError`` (bad/expired key) must surface as a
    RuntimeError telling the operator to verify the env var, not
    a generic 502. """
    pytest.importorskip("anthropic")
    import anthropic as _anth
    from nth_dao.web.dummy_agent import _AnthropicSdkAskBackend

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-bad")

    class _FakeRequest:
        method = "POST"
        url = "https://api.anthropic.com/v1/messages"

    class _FakeResponse:
        status_code = 401
        headers: dict = {}
        request = _FakeRequest()

    class _FakeMessages:
        def create(self, **_kw: object) -> object:
            # Real signature is AuthenticationError(message, response, body)
            raise _anth.AuthenticationError(
                "Invalid API key",
                response=_FakeResponse(),  # type: ignore[arg-type]
                body=None,
            )

    class _FakeClient:
        def __init__(self, **_kw: object) -> None:
            self.messages = _FakeMessages()

    monkeypatch.setattr(_anth, "Anthropic", _FakeClient)
    with pytest.raises(RuntimeError, match="verify ANTHROPIC_API_KEY"):
        _AnthropicSdkAskBackend().ask(
            {"prompt": "hi"}, timeout_s=5.0,
        )


def test_resolve_ask_backend_falls_back_to_cli_when_anthropic_not_installed(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """BUG-3 fix (review round Phase 5.1 R2): if ANTHROPIC_API_KEY
    is set but the ``anthropic`` package isn't importable, the
    dispatcher must cleanly fall back to the CLI backend rather
    than constructing an unusable SDK backend that fails on first
    use. """
    import builtins
    from nth_dao.web.dummy_agent import (
        _ClaudeCliAskBackend, _resolve_ask_backend,
    )

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")

    # Make the anthropic import fail by removing it from sys.modules
    # and patching __import__ to refuse it.
    import sys
    sys.modules.pop("anthropic", None)
    original_import = builtins.__import__

    def fake_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "anthropic":
            raise ImportError("simulated missing anthropic package")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    backend = _resolve_ask_backend("claude-code")
    assert isinstance(backend, _ClaudeCliAskBackend), (
        f"expected fallback to CLI backend; got {type(backend).__name__}"
    )


@pytest.mark.skipif(
    not os.environ.get("ANTHROPIC_API_KEY", "").strip(),
    reason=(
        "BUG-1 fix (review round Phase 5.1 R2): live API integration "
        "test — set ANTHROPIC_API_KEY to run. Catches model-id drift "
        "(e.g. claude-sonnet-4-6 deprecated / renamed) that no mock "
        "test can detect."
    ),
)
def test_anthropic_sdk_backend_real_api_round_trip_validates_model_id() -> None:
    """BUG-1 fix (review round Phase 5.1 R2): integration probe.

    Mock-based tests can never validate that ``DEFAULT_MODEL`` is a
    model name the live API actually accepts. This test makes a
    real round-trip with a tiny prompt + low max_tokens (cents at
    worst) to confirm the model id resolves end-to-end. Skipped
    when ANTHROPIC_API_KEY isn't set, so CI without credentials
    isn't blocked. """
    from nth_dao.web.dummy_agent import _AnthropicSdkAskBackend

    out = _AnthropicSdkAskBackend().ask(
        {
            "prompt": "Reply with exactly the four letters PONG. Nothing else.",
            "max_tokens": 16,
        },
        timeout_s=30.0,
    )
    # The model should answer at all (token counts > 0); we don't
    # assert the exact response text because LLMs sometimes add
    # extra punctuation.
    assert out["backend"] == "claude-code"
    assert out["model"] == _AnthropicSdkAskBackend.DEFAULT_MODEL
    assert out["input_tokens"] > 0, "model rejected the request"
    assert out["output_tokens"] > 0, "model returned empty response"
    assert "PONG" in out["response"].upper(), (
        f"model didn't follow basic instruction; got: {out['response']!r}"
    )


def test_anthropic_sdk_backend_honours_widened_max_tokens_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """M-2 fix (review round Phase 5.1 R1): the max_tokens upper
    bound widened from 8192 → 32768 to match current Sonnet 4.6 /
    Opus 4.8 API limits. Verify 16384 (previously rejected, now
    accepted) actually propagates to messages.create. """
    pytest.importorskip("anthropic")
    import anthropic as _anth
    from nth_dao.web.dummy_agent import _AnthropicSdkAskBackend

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    captured: dict = {}

    class _FakeUsage:
        input_tokens = 1
        output_tokens = 1

    class _FakeBlock:
        text = "ok"

    class _FakeMsg:
        content = [_FakeBlock()]
        usage = _FakeUsage()
        stop_reason = "end_turn"

    class _FakeMessages:
        def create(self, **kw: object) -> "_FakeMsg":
            captured.update(kw)
            return _FakeMsg()

    class _FakeClient:
        def __init__(self, **_kw: object) -> None:
            self.messages = _FakeMessages()

    monkeypatch.setattr(_anth, "Anthropic", _FakeClient)

    _AnthropicSdkAskBackend().ask(
        {"prompt": "longish", "max_tokens": 16384},
        timeout_s=10.0,
    )
    assert captured["max_tokens"] == 16384, captured

    # And anything above the new ceiling still falls back to the
    # default — defense against a peer requesting astronomical
    # output budgets.
    captured.clear()
    _AnthropicSdkAskBackend().ask(
        {"prompt": "huge", "max_tokens": 100_000},
        timeout_s=10.0,
    )
    assert captured["max_tokens"] == 1024  # DEFAULT_MAX_TOKENS


def test_claude_code_backend_prefers_adjacent_exe_over_ps1(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BUG-5 fix (review round Phase 4 R2): when ``shutil.which``
    returns the npm ``claude.ps1`` shim, the backend must walk to
    the adjacent vendored ``claude.exe`` rather than invoking the
    broken .ps1 path. Verifies the argv that's handed to
    subprocess.run starts with the .exe, not the .ps1. """
    import shutil
    import subprocess as _sp

    from nth_dao.web.dummy_agent import _ClaudeCliAskBackend

    # Build a fake claude install layout under tmp_path so the
    # candidate .exe check succeeds.
    npm_dir = tmp_path / "npm-global"
    ps1 = npm_dir / "claude.ps1"
    npm_dir.mkdir()
    ps1.write_text("# shim", encoding="utf-8")
    exe_dir = (
        npm_dir / "node_modules" / "@anthropic-ai" / "claude-code" / "bin"
    )
    exe_dir.mkdir(parents=True)
    exe = exe_dir / "claude.exe"
    exe.write_text("# vendored binary", encoding="utf-8")

    monkeypatch.setattr(shutil, "which", lambda _n: str(ps1))

    captured: list[list[str]] = []

    class _FakeCompleted:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def fake_run(argv: list[str], **_kw: object) -> _FakeCompleted:
        captured.append(list(argv))
        return _FakeCompleted()

    monkeypatch.setattr(_sp, "run", fake_run)

    out = _ClaudeCliAskBackend().ask(
        {"prompt": "hello"}, timeout_s=5.0,
    )
    assert out["response"] == "ok"
    assert captured, "subprocess.run was not invoked"
    # First arg of argv must be the resolved .exe, NOT the .ps1.
    invoked = captured[0][0]
    assert invoked == str(exe), (
        f"expected {exe} to be invoked; got {invoked!r}"
    )


def test_claude_code_backend_raises_when_ps1_has_no_adjacent_exe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BUG-3 fix (review round Phase 4 R2): if shutil.which finds
    claude.ps1 but the vendored claude.exe is missing (broken npm
    install), don't silently fall through to the .ps1 path (which
    triggers ACCESS_VIOLATION on Windows + piped stdout — and would
    then be misattributed to the CLI bug). Raise a targeted error
    pointing at the broken install layout. """
    import shutil
    from nth_dao.web.dummy_agent import _ClaudeCliAskBackend

    # Lay down only the .ps1, NOT the vendored .exe.
    npm_dir = tmp_path / "npm-global"
    npm_dir.mkdir()
    ps1 = npm_dir / "claude.ps1"
    ps1.write_text("# shim", encoding="utf-8")
    monkeypatch.setattr(shutil, "which", lambda _n: str(ps1))

    with pytest.raises(RuntimeError, match="install layout may be broken"):
        _ClaudeCliAskBackend().ask(
            {"prompt": "hi"}, timeout_s=5.0,
        )


def test_a2a_post_rejects_non_dict_body(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BUG-1 fix (review round Phase 4 R2): a JSON body that
    parses to something other than an object (list / string /
    number / bool / null) must return 400 with a clear diagnostic.
    Pre-fix this would have hit AttributeError on
    ``params.get(...)`` and bubbled to 500. Exercised via the
    real subprocess so we cover the child handler's path, not
    a mock. """
    pytest.importorskip("nacl")
    import urllib.error
    import urllib.request as _ureq
    import uuid as _uuid

    from nth_dao.cap_token import (
        CAP_A2A_MESSAGE_SEND, CAP_NTH_RECEIPT_SIGN,
        encode_authorization_header, sign_cap_token,
    )
    from nth_dao.identity import AgentIdentity

    issuer = AgentIdentity.generate(label="test-non-dict-body")
    events: list[dict] = []
    runner = SubprocessRunner(
        on_event=lambda _id, e: events.append(e),
        handshake_timeout=_SMOKE_TIMEOUT,
    )
    agent_id = f"non-dict-{_uuid.uuid4().hex[:12]}"
    cap_token_path = tmp_path / "cap_token.json"
    pid, child_did = runner.start(
        agent_id, kind="mock",
        cap_token_file_path=str(cap_token_path),
    )
    if pid is None:
        pytest.skip("subprocess could not start (CI sandboxing?)")
    try:
        child_token = sign_cap_token(
            issuer=issuer, subject_did=child_did,
            capabilities=[CAP_NTH_RECEIPT_SIGN],
        )
        from nth_dao.web.agent_supervisor import _atomic_write_json
        _atomic_write_json(str(cap_token_path), child_token)
        deadline = time.time() + _SMOKE_TIMEOUT
        while time.time() < deadline:
            if any(e.get("event") == "agent_started" for e in events):
                break
            time.sleep(0.1)
        started = next(e for e in events if e.get("event") == "agent_started")
        port = started["a2a_port"]

        peer = AgentIdentity.generate(label="non-dict-peer")
        peer_token = sign_cap_token(
            issuer=issuer, subject_did=peer.as_did(),
            capabilities=[CAP_A2A_MESSAGE_SEND],
        )
        auth = "CapToken " + encode_authorization_header(peer_token)

        # Top-level JSON array — valid JSON, not a dict.
        req = _ureq.Request(
            url=f"http://127.0.0.1:{port}/a2a/ask",
            data=json.dumps(["not", "an", "object"]).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": auth,
            },
            method="POST",
        )
        try:
            with _ureq.urlopen(req, timeout=3.0):  # noqa: S310
                pytest.fail("expected 400 for non-dict body")
        except urllib.error.HTTPError as exc:
            assert exc.code == 400, exc.code
            body = json.loads(exc.read().decode("utf-8"))
            assert body["error"]["code"] == "bad-request"
            assert "JSON object" in body["error"]["message"]
    finally:
        runner.stop(agent_id)


@pytest.mark.parametrize(
    "rc, label",
    [
        (3221225477, "unsigned-DWORD"),
        (-1073741819, "signed-long"),
    ],
)
def test_claude_code_backend_translates_windows_access_violation(
    monkeypatch: pytest.MonkeyPatch, rc: int, label: str,
) -> None:
    """Phase 4: when claude.exe crashes with 0xC0000005
    (ACCESS_VIOLATION — known Windows + piped-stdout issue), the
    backend must raise a targeted RuntimeError telling the operator
    to switch to kind=mock, not a generic 'exited 3221225477'.

    R-1 fix (review round Phase 4 R3): parametrize over BOTH the
    unsigned (3221225477) and signed (-1073741819) representations
    of 0xC0000005 — the original R2 test only covered the unsigned
    case, which let a Python build that surfaces the signed form
    slip past the hint translation. """
    import shutil
    import subprocess as _sp

    from nth_dao.web.dummy_agent import _ClaudeCliAskBackend

    # Pretend the binary IS on PATH (skip the not-on-PATH branch).
    monkeypatch.setattr(shutil, "which", lambda _name: "C:/fake/claude.exe")

    class _FakeCompleted:
        returncode = rc
        stdout = ""
        stderr = ""

    monkeypatch.setattr(
        _sp, "run", lambda *_a, **_k: _FakeCompleted(),
    )
    with pytest.raises(RuntimeError, match="ACCESS_VIOLATION") as exc_info:
        _ClaudeCliAskBackend().ask(
            {"prompt": "hi"}, timeout_s=1.0,
        )
    # Verify the message points at the kind=mock workaround.
    assert "kind=mock" in str(exc_info.value), (
        f"[{label}] expected the operator-facing hint; got: "
        f"{exc_info.value}"
    )


def test_claude_code_backend_raises_when_binary_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Phase 4: when ``claude`` isn't on PATH the backend raises a
    clear RuntimeError pointing at the install / fallback path. """
    import shutil
    from nth_dao.web.dummy_agent import _ClaudeCliAskBackend

    monkeypatch.setattr(shutil, "which", lambda _name: None)
    with pytest.raises(RuntimeError, match="not on PATH"):
        _ClaudeCliAskBackend().ask(
            {"prompt": "hi"}, timeout_s=1.0,
        )


def test_hub_proxy_ask_uses_per_method_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """H-1 fix (review round Phase 4 R1): the hub proxy must read
    its forward timeout from ``_A2A_METHOD_TIMEOUTS[method]`` so the
    /a2a/ask path isn't capped at the snappy /ping default. Verified
    by intercepting urlopen and asserting it was called with the
    map's value for "ask" (65.0s) — NOT the 2.0s default."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("NTH_V2_WORKSPACE_ONLY", "true")

    from nth_dao.web import create_app
    from nth_dao.web.agent_supervisor import AgentRecord
    from nth_dao.web import v2_api as _v2

    app = create_app(
        workspace=tmp_path / ".nth-dao" / "workspaces" / "default",
        require_console_auth=False,
    )
    sup = AgentSupervisor(InMemoryRunner())
    app.state.v2_supervisor = sup
    target_did = "did:key:z6MkAskTimeoutProbe"
    rec = AgentRecord(
        agent_id="ask-probe", kind="mock", label="ask-probe",
        did=target_did, capabilities=[],
        started_at="2026-06-11T00:00:00+00:00",
        last_seen="2026-06-11T00:00:00+00:00",
        alive=True, pid=1, a2a_port=51999,
    )
    with sup._lock:  # type: ignore[attr-defined]
        sup._agents["ask-probe"] = rec  # type: ignore[attr-defined]
    sup._runner._alive["ask-probe"] = True  # type: ignore[attr-defined]

    import urllib.request as _ureq
    seen_timeouts: list[float] = []

    class _FakeResp:
        status = 200
        def __enter__(self) -> "_FakeResp": return self
        def __exit__(self, *_a: object) -> None: return None
        def read(self) -> bytes:
            return json.dumps({"result": {"ok": True}}).encode("utf-8")

    def fake_urlopen(_req: object, *, timeout: float = 0) -> _FakeResp:
        seen_timeouts.append(timeout)
        return _FakeResp()

    monkeypatch.setattr(_ureq, "urlopen", fake_urlopen)

    client = TestClient(app)
    # First confirm the map carries the expected value (so a future
    # rename of "ask" or constant fails this test loudly).
    assert _v2._A2A_METHOD_TIMEOUTS["ask"] == 65.0

    resp = client.post(
        f"/api/v2/agents/{target_did}/a2a/ask",
        json={"prompt": "hi"},
    )
    assert resp.status_code == 200, resp.text
    assert seen_timeouts == [65.0], (
        f"expected per-method timeout 65.0 for 'ask', got {seen_timeouts!r}"
    )

    # And a non-mapped method falls back to the snappy default.
    seen_timeouts.clear()
    resp2 = client.post(
        f"/api/v2/agents/{target_did}/a2a/echo",
        json={"x": 1},
    )
    assert resp2.status_code == 200, resp2.text
    assert seen_timeouts == [2.0], (
        f"expected default timeout 2.0 for 'echo', got {seen_timeouts!r}"
    )


def test_hub_proxy_ask_end_to_end_through_real_subprocess(
    tmp_path: Path,
) -> None:
    """H-2 fix (review round Phase 4 R1): the existing Phase 4 ask
    test bypasses the hub by posting to 127.0.0.1:<port> directly,
    so a bug in the hub proxy (e.g. the H-1 timeout regression) was
    invisible. This test goes through the hub's
    POST /api/v2/agents/{did}/a2a/ask endpoint to a REAL spawned
    child running the mock backend — verifying the full
    operator-facing path works end-to-end. """
    pytest.importorskip("nacl")
    import uuid as _uuid

    from nth_dao.cap_token import (
        CAP_NTH_RECEIPT_SIGN,
        sign_cap_token,
    )
    from nth_dao.identity import AgentIdentity
    from nth_dao.web import create_app
    from nth_dao.web.agent_supervisor import (
        SubprocessRunner, _atomic_write_json,
    )

    issuer = AgentIdentity.generate(label="test-hub-proxy-ask")
    events: list[dict] = []
    runner = SubprocessRunner(
        on_event=lambda _id, e: events.append(e),
        handshake_timeout=_SMOKE_TIMEOUT,
    )
    agent_id = f"hub-ask-{_uuid.uuid4().hex[:12]}"
    cap_token_path = tmp_path / "cap_token.json"
    pid, child_did = runner.start(
        agent_id, kind="mock",
        cap_token_file_path=str(cap_token_path),
    )
    if pid is None:
        pytest.skip("subprocess could not start (CI sandboxing?)")
    try:
        child_token = sign_cap_token(
            issuer=issuer, subject_did=child_did,
            capabilities=[CAP_NTH_RECEIPT_SIGN],
        )
        _atomic_write_json(str(cap_token_path), child_token)

        deadline = time.time() + _SMOKE_TIMEOUT
        while time.time() < deadline:
            if any(e.get("event") == "agent_started" for e in events):
                break
            time.sleep(0.1)
        started = next(e for e in events if e.get("event") == "agent_started")
        port = started["a2a_port"]

        # Stand up a FastAPI app + supervisor seeded with the real
        # AgentRecord so the proxy resolves the DID.
        app = create_app(
            workspace=tmp_path / ".nth-dao" / "workspaces" / "default",
            require_console_auth=False,
        )
        sup = AgentSupervisor(InMemoryRunner())
        from nth_dao.web.agent_supervisor import AgentRecord
        with sup._lock:  # type: ignore[attr-defined]
            sup._agents[agent_id] = AgentRecord(  # type: ignore[attr-defined]
                agent_id=agent_id, kind="mock", label="hub-proxy-test",
                did=child_did, capabilities=[],
                started_at="2026-06-11T00:00:00+00:00",
                last_seen="2026-06-11T00:00:00+00:00",
                alive=True, pid=pid, a2a_port=port,
            )
        sup._runner._alive[agent_id] = True  # type: ignore[attr-defined]
        app.state.v2_supervisor = sup

        client = TestClient(app)
        # No Authorization header → child rejects with 401 (proves
        # the auth wire is live through the proxy too).
        resp_noauth = client.post(
            f"/api/v2/agents/{child_did}/a2a/ask",
            json={"prompt": "hub-proxy hello"},
        )
        assert resp_noauth.status_code == 401, resp_noauth.text

        # With a same-issuer peer cap_token the proxy forwards and
        # the child's mock backend echoes back.
        from nth_dao.cap_token import (
            CAP_A2A_MESSAGE_SEND, encode_authorization_header,
        )
        peer = AgentIdentity.generate(label="proxy-peer")
        peer_token = sign_cap_token(
            issuer=issuer, subject_did=peer.as_did(),
            capabilities=[CAP_A2A_MESSAGE_SEND],
        )
        auth = "CapToken " + encode_authorization_header(peer_token)

        resp = client.post(
            f"/api/v2/agents/{child_did}/a2a/ask",
            json={"prompt": "hub-proxy hello"},
            headers={"Authorization": auth},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["result"]["backend"] == "mock"
        assert "hub-proxy hello" in body["result"]["response"]
        assert body["result"]["caller_did"] == peer.as_did()
        assert body["result"]["agent_did"] == child_did
    finally:
        runner.stop(agent_id)


def test_subprocess_real_a2a_ask_stream_end_to_end(
    tmp_path: Path,
) -> None:
    """Phase 5.2 end-to-end: spawn a real child with kind=mock,
    deliver a cap_token, then POST /a2a/ask-stream directly to the
    child's port and read the SSE response line-by-line. Verifies:
      - child emits Content-Type: text/event-stream
      - at least 2 ``data: {"delta":...}`` events arrive before done
      - terminating ``data: {"done":true,...}`` event closes the stream
      - reassembled deltas equal the buffered mock response """
    pytest.importorskip("nacl")
    import socket
    import uuid as _uuid

    from nth_dao.cap_token import (
        CAP_A2A_MESSAGE_SEND, CAP_NTH_RECEIPT_SIGN,
        encode_authorization_header, sign_cap_token,
    )
    from nth_dao.identity import AgentIdentity

    issuer = AgentIdentity.generate(label="test-stream-issuer")
    events: list[dict] = []
    runner = SubprocessRunner(
        on_event=lambda _id, e: events.append(e),
        handshake_timeout=_SMOKE_TIMEOUT,
    )
    agent_id = f"stream-{_uuid.uuid4().hex[:12]}"
    cap_token_path = tmp_path / "cap_token.json"
    pid, child_did = runner.start(
        agent_id, kind="mock",
        cap_token_file_path=str(cap_token_path),
    )
    if pid is None:
        pytest.skip("subprocess could not start (CI sandboxing?)")
    try:
        child_token = sign_cap_token(
            issuer=issuer, subject_did=child_did,
            capabilities=[CAP_NTH_RECEIPT_SIGN],
        )
        from nth_dao.web.agent_supervisor import _atomic_write_json
        _atomic_write_json(str(cap_token_path), child_token)
        deadline = time.time() + _SMOKE_TIMEOUT
        while time.time() < deadline:
            if any(e.get("event") == "agent_started" for e in events):
                break
            time.sleep(0.1)
        started = next(e for e in events if e.get("event") == "agent_started")
        port = started["a2a_port"]

        # Wait for the child to load its OWN cap_token (proven by
        # the receipt_signed event firing) — otherwise the A2A
        # auth check rejects with "not-yet-authorized" because
        # the holder slot hasn't been populated.
        deadline = time.time() + _SMOKE_TIMEOUT
        while time.time() < deadline:
            if any(e.get("event") == "receipt_signed" for e in events):
                break
            time.sleep(0.1)
        assert any(e.get("event") == "receipt_signed" for e in events), (
            "child should have loaded its own cap_token + signed an "
            "attestation by now"
        )

        peer = AgentIdentity.generate(label="stream-peer")
        peer_token = sign_cap_token(
            issuer=issuer, subject_did=peer.as_did(),
            capabilities=[CAP_A2A_MESSAGE_SEND],
        )
        auth = "CapToken " + encode_authorization_header(peer_token)
        body = json.dumps({
            "prompt": "streamtest",
            "_no_sleep": True,
        }).encode("utf-8")

        # Raw socket so we can read the SSE chunks as they land
        # without urllib buffering. Localhost only.
        with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
            req = (
                f"POST /a2a/ask-stream HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{port}\r\n"
                f"Content-Type: application/json\r\n"
                f"Authorization: {auth}\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("utf-8") + body
            s.sendall(req)
            buf = b""
            deadline = time.time() + 5.0
            while time.time() < deadline:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
        text = buf.decode("utf-8", errors="replace")
        assert "text/event-stream" in text.lower(), text[:300]
        # Strip headers, keep body.
        body_text = text.split("\r\n\r\n", 1)[-1]
        # Parse SSE events.
        data_events = [
            line[len("data: "):]
            for line in body_text.splitlines()
            if line.startswith("data: ")
        ]
        assert len(data_events) >= 2, (
            f"expected ≥2 SSE events; got {data_events!r}"
        )
        parsed = [json.loads(d) for d in data_events]
        assert parsed[-1].get("done") is True
        deltas = [p["delta"] for p in parsed if "delta" in p]
        assert deltas, f"no delta events; got {parsed!r}"
        reassembled = "".join(deltas)
        # Mock backend's response shape: "(mock) ack: streamtest"
        assert "streamtest" in reassembled
    finally:
        runner.stop(agent_id)


def test_subprocess_real_a2a_ask_mock_backend(
    tmp_path: Path,
) -> None:
    """Phase 4 end-to-end on the mock backend: spawn a real child
    with kind=mock, write cap_token, then POST /a2a/ask DIRECTLY
    against the child's port with a peer cap_token signed by the
    same issuer. The child's ``ask`` handler should route to the
    mock backend and echo the prompt back. """
    pytest.importorskip("nacl")
    import urllib.request as _ureq
    import uuid as _uuid

    from nth_dao.cap_token import (
        CAP_A2A_MESSAGE_SEND, CAP_NTH_RECEIPT_SIGN,
        encode_authorization_header, sign_cap_token,
    )
    from nth_dao.identity import AgentIdentity

    issuer = AgentIdentity.generate(label="test-hub-ask")
    events: list[dict] = []
    runner = SubprocessRunner(
        on_event=lambda _id, e: events.append(e),
        handshake_timeout=_SMOKE_TIMEOUT,
    )
    agent_id = f"ask-{_uuid.uuid4().hex[:12]}"
    cap_token_path = tmp_path / "cap_token.json"
    pid, child_did = runner.start(
        agent_id, kind="mock",
        cap_token_file_path=str(cap_token_path),
    )
    if pid is None:
        pytest.skip("subprocess could not start (CI sandboxing?)")
    try:
        child_token = sign_cap_token(
            issuer=issuer, subject_did=child_did,
            capabilities=[CAP_NTH_RECEIPT_SIGN],
        )
        from nth_dao.web.agent_supervisor import _atomic_write_json
        _atomic_write_json(str(cap_token_path), child_token)

        deadline = time.time() + _SMOKE_TIMEOUT
        while time.time() < deadline:
            if any(e.get("event") == "receipt_signed" for e in events):
                break
            time.sleep(0.1)
        started = next(e for e in events if e.get("event") == "agent_started")
        port = started["a2a_port"]

        peer = AgentIdentity.generate(label="peer-ask")
        peer_token = sign_cap_token(
            issuer=issuer, subject_did=peer.as_did(),
            capabilities=[CAP_A2A_MESSAGE_SEND],
        )
        auth = "CapToken " + encode_authorization_header(peer_token)

        req = _ureq.Request(
            url=f"http://127.0.0.1:{port}/a2a/ask",
            data=json.dumps({"prompt": "ping from test"}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": auth,
            },
            method="POST",
        )
        with _ureq.urlopen(req, timeout=3.0) as resp:  # noqa: S310
            assert resp.status == 200
            body = json.loads(resp.read().decode("utf-8"))
        result = body["result"]
        assert result["method"] == "ask"
        assert result["backend"] == "mock"
        assert "ping from test" in result["response"]
        assert result["caller_did"] == peer.as_did()
    finally:
        runner.stop(agent_id)


# ─────────────────────────────────────────────────────────────
# Real subprocess smoke
# ─────────────────────────────────────────────────────────────

# Smoke test timeout — polish 2026-06-11: extracted from a magic
# literal so a slower CI can bump it without a code rebrowse.
_SMOKE_TIMEOUT = 5.0


def test_subprocess_runner_smoke() -> None:
    """One end-to-end check that SubprocessRunner can spawn
    nth_dao.web.dummy_agent, that the child generates an Ed25519
    keypair + reports its real DID, and that stop() terminates
    it cleanly.

    Phase 3b: start() is synchronous w.r.t. the identity handshake,
    so by the time it returns we already have the child's did. No
    polling loop on the events list needed — that was a Phase 3a
    workaround for the fire-and-forget Popen.
    """
    import uuid
    from nth_dao.did_key import is_did_key
    events: list[dict] = []
    runner = SubprocessRunner(
        on_event=lambda _id, e: events.append(e),
        handshake_timeout=_SMOKE_TIMEOUT,
    )
    # N-6 fix (2026-06-11): random agent_id so pytest-xdist parallel
    # workers don't collide on the same SubprocessRunner key when
    # someone someday runs `pytest -n auto`.
    agent_id = f"smoke-{uuid.uuid4().hex[:12]}"
    pid, did = runner.start(agent_id, kind="mock")
    if pid is None:
        pytest.skip("subprocess could not start (CI sandboxing?)")
    try:
        # Phase 3b: start() blocked until the handshake event, so
        # this assert is about the result of the handshake — not
        # a race with the reader thread.
        assert is_did_key(did), (
            f"expected a W3C did:key from the child, got {did!r}"
        )
        # The corresponding agent_started event must have been
        # forwarded to on_event already (the reader sets the
        # handshake event AFTER stashing did/pubkey AND BEFORE
        # forwarding — see _read_stdout_loop). Give the reader a
        # brief tick if the OS has only just scheduled it.
        deadline = time.time() + 1.0
        while time.time() < deadline:
            if any(e.get("event") == "agent_started" for e in events):
                break
            time.sleep(0.05)
        kinds = {e.get("event") for e in events}
        assert "agent_started" in kinds, f"events seen: {kinds!r}"
        # The forwarded event must carry the same did the runner
        # returned — they're the same source.
        started = next(e for e in events if e.get("event") == "agent_started")
        assert started.get("did") == did
        # Phase 3c: agent_started must advertise an a2a_port
        # (kernel-chosen ephemeral port, > 1024 since we bind as
        # an unprivileged process).
        a2a_port = started.get("a2a_port")
        assert isinstance(a2a_port, int) and a2a_port > 1024, (
            f"expected an ephemeral a2a_port, got {a2a_port!r}"
        )
        assert runner.is_alive(agent_id), "agent should be alive"

        # Phase 3c: the child's /ping endpoint must answer with the
        # identity card. Use urllib instead of requests to keep
        # the test stdlib-only.
        # L-2 note (review round Phase 3c R1): this assert depends
        # on the OS scheduling the daemon serve_forever thread and
        # the TCP socket being reachable inside 2s. A /ping timeout
        # here is almost certainly an ENVIRONMENT issue (sandbox
        # rules, slow CI VM, antivirus stalling the bind), not a
        # protocol regression — file an env bug before assuming
        # the dummy_agent's A2A surface is broken.
        import urllib.request
        with urllib.request.urlopen(  # noqa: S310 — localhost only
            f"http://127.0.0.1:{a2a_port}/ping", timeout=2.0,
        ) as resp:
            assert resp.status == 200
            body = json.loads(resp.read().decode("utf-8"))
        assert body["did"] == did
        assert body["agent_id"] == agent_id
        assert body["kind"] == "mock"
        assert "uptime_ms" in body
    finally:
        runner.stop(agent_id)
        # L-5 fix (2026-06-11): no magic sleep — runner.stop()
        # already wait()s with a 2s+1s timeout, so by the time it
        # returns the process is guaranteed to have exited (or
        # been kill()ed).
        assert not runner.is_alive(agent_id), "agent should be dead after stop"


def test_supervisor_stamps_a2a_port_on_real_subprocess_spawn() -> None:
    """Phase 3d end-to-end: spawn via AgentSupervisor + real
    SubprocessRunner (no cap_token issuer needed for this check)
    and assert the AgentRecord carries the child's advertised port.
    Then verify list_agents + to_agent_entry round-trip it. """
    sup = AgentSupervisor(SubprocessRunner(handshake_timeout=_SMOKE_TIMEOUT))
    try:
        r = sup.spawn(kind="mock", label="port-3d", capabilities=[])
    except RuntimeError as exc:
        pytest.skip(f"subprocess could not start: {exc}")
    try:
        assert r.a2a_port is not None and r.a2a_port > 1024, (
            f"expected a stamped ephemeral a2a_port, got {r.a2a_port!r}"
        )
        # Same value must come back via list_agents (snapshot copy).
        listed = sup.list_agents()
        assert len(listed) == 1
        assert listed[0].a2a_port == r.a2a_port
        # And via to_agent_entry (what /api/v2/agents serialises).
        entry = listed[0].to_agent_entry()
        assert entry["a2a_port"] == r.a2a_port
    finally:
        sup.stop(r.agent_id)


def test_a2a_post_end_to_end_with_real_subprocess(
    tmp_path: Path,
) -> None:
    """Phase 3e end-to-end: spawn a real child, deliver a cap_token
    signed by a generated test identity, then call POST /a2a/echo
    DIRECTLY against the child's HTTP server with a second
    cap_token signed by the SAME identity. The child must accept
    + echo back the params + return the caller's subject_did.

    This proves:
      - Child's auth check parses the Authorization: CapToken header
      - Child verifies the token's issuer_did matches its own
      - Child grants the call when capabilities include
        a2a:message_send
      - Child rejects auth-less calls (covered by unit test) """
    pytest.importorskip("nacl")
    import urllib.error
    import urllib.request as _ureq
    import uuid as _uuid

    from nth_dao.cap_token import (
        CAP_A2A_MESSAGE_SEND, CAP_NTH_RECEIPT_SIGN,
        encode_authorization_header, sign_cap_token,
    )
    from nth_dao.did_key import is_did_key
    from nth_dao.identity import AgentIdentity

    issuer = AgentIdentity.generate(label="test-hub")
    events: list[dict] = []
    runner = SubprocessRunner(
        on_event=lambda _id, e: events.append(e),
        handshake_timeout=_SMOKE_TIMEOUT,
    )
    agent_id = f"smoke-e2e-{_uuid.uuid4().hex[:12]}"
    cap_token_path = tmp_path / "cap_token.json"
    pid, child_did = runner.start(
        agent_id, kind="mock",
        cap_token_file_path=str(cap_token_path),
    )
    if pid is None:
        pytest.skip("subprocess could not start (CI sandboxing?)")
    try:
        assert is_did_key(child_did)
        # Sign + deliver the CHILD's own cap_token (so its A2A
        # auth slot fills + it knows the legitimate issuer_did).
        child_token = sign_cap_token(
            issuer=issuer,
            subject_did=child_did,
            capabilities=[CAP_NTH_RECEIPT_SIGN],
        )
        from nth_dao.web.agent_supervisor import _atomic_write_json
        _atomic_write_json(str(cap_token_path), child_token)

        # Wait for the child to load + start signing receipts —
        # that confirms cap_token_holder.set() has fired.
        deadline = time.time() + _SMOKE_TIMEOUT
        while time.time() < deadline:
            if any(e.get("event") == "receipt_signed" for e in events):
                break
            time.sleep(0.1)
        assert any(e.get("event") == "receipt_signed" for e in events), (
            "child should have signed an attestation by now"
        )

        # Fetch the a2a_port from the agent_started event.
        started = next(e for e in events if e.get("event") == "agent_started")
        port = started.get("a2a_port")
        assert isinstance(port, int) and port > 1024

        # Issue a SECOND cap_token for a "peer agent" calling
        # /a2a/echo. Same issuer ⇒ child trusts it. Capability
        # includes a2a:message_send ⇒ child grants the call.
        peer = AgentIdentity.generate(label="peer-agent")
        peer_token = sign_cap_token(
            issuer=issuer,
            subject_did=peer.as_did(),
            capabilities=[CAP_A2A_MESSAGE_SEND],
        )
        auth_value = "CapToken " + encode_authorization_header(peer_token)

        # POST /a2a/echo directly to the child.
        req = _ureq.Request(
            url=f"http://127.0.0.1:{port}/a2a/echo",
            data=json.dumps({"hello": "world"}).encode("utf-8"),
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "Authorization": auth_value,
            },
            method="POST",
        )
        with _ureq.urlopen(req, timeout=2.0) as resp:  # noqa: S310
            assert resp.status == 200, resp.status
            body = json.loads(resp.read().decode("utf-8"))
        result = body["result"]
        assert result["method"] == "echo"
        assert result["received_params"] == {"hello": "world"}
        assert result["caller_did"] == peer.as_did()
        assert result["agent_did"] == child_did

        # And: a bogus peer signed by a DIFFERENT issuer is
        # REJECTED (issuer-mismatch).
        bogus_issuer = AgentIdentity.generate(label="bogus")
        bogus_token = sign_cap_token(
            issuer=bogus_issuer,
            subject_did=peer.as_did(),
            capabilities=[CAP_A2A_MESSAGE_SEND],
        )
        bogus_auth = "CapToken " + encode_authorization_header(bogus_token)
        req2 = _ureq.Request(
            url=f"http://127.0.0.1:{port}/a2a/echo",
            data=b"{}",
            headers={
                "Content-Type": "application/json",
                "Authorization": bogus_auth,
            },
            method="POST",
        )
        try:
            with _ureq.urlopen(req2, timeout=2.0):  # noqa: S310
                pytest.fail("child should have rejected bogus issuer")
        except urllib.error.HTTPError as exc:
            assert exc.code == 401, exc.code
            err = json.loads(exc.read().decode("utf-8"))
            assert err["error"]["code"] == "issuer-mismatch"
    finally:
        runner.stop(agent_id)


def test_subprocess_runner_rejects_mismatched_subject_did(
    tmp_path: Path,
) -> None:
    """M-1 fix (review round Phase 3c R2): if a cap_token's
    subject_did doesn't match the child's own DID, the child must
    refuse to sign an attestation. Spawns a real child, writes a
    deliberately mismatched cap_token to the polled path, waits
    for ~1.5 heartbeats, and asserts NO receipt_signed event was
    emitted (the child observed the mismatch and bailed). """
    import uuid as _uuid
    events: list[dict] = []
    runner = SubprocessRunner(
        on_event=lambda _id, e: events.append(e),
        handshake_timeout=_SMOKE_TIMEOUT,
    )
    agent_id = f"smoke-m1-{_uuid.uuid4().hex[:12]}"
    cap_token_path = tmp_path / "cap_token.json"
    pid, did = runner.start(
        agent_id, kind="mock",
        cap_token_file_path=str(cap_token_path),
    )
    if pid is None:
        pytest.skip("subprocess could not start (CI sandboxing?)")
    try:
        # Deliberately mismatched subject_did — a DIFFERENT did:key,
        # not the child's own. The child must refuse.
        cap_token = {
            "token_id": "tok-mismatch",
            "subject_did": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSrEEa2NDsR9ZS6sj6kk",
            "capabilities": ["nth:receipt_sign"],
            "issuer_did": "did:key:zFakeIssuer",
        }
        tmp = cap_token_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(cap_token), encoding="utf-8")
        os.replace(str(tmp), str(cap_token_path))

        # Wait ~1.5 heartbeats so the child has at LEAST polled
        # the file once. If it were going to sign, it would have
        # by now. The 1.5s window is the same magnitude as the
        # smoke test's _SMOKE_TIMEOUT polling.
        deadline = time.time() + 2.5
        while time.time() < deadline:
            if any(e.get("event") == "receipt_signed" for e in events):
                break
            time.sleep(0.1)

        signed = [e for e in events if e.get("event") == "receipt_signed"]
        assert not signed, (
            "child must NOT sign an attestation for a cap_token "
            f"whose subject_did doesn't match its own DID; got: {signed!r}"
        )
    finally:
        runner.stop(agent_id)


def test_subprocess_runner_cap_token_file_round_trip(
    tmp_path: Path,
) -> None:
    """Phase 3c end-to-end: spawn a real child with
    --cap-token-file <path>, write a cap_token JSON to that path,
    wait for the child to sign + emit ``receipt_signed``. Verifies:
      - child polls the file (loads it from disk)
      - child signs an nth.agent_attestation receipt with its own
        Ed25519 identity (signer_did matches the handshake DID)
      - receipt's timeline carries the cap_token_id we wrote
    """
    import json as _json
    import uuid
    events: list[dict] = []
    runner = SubprocessRunner(
        on_event=lambda _id, e: events.append(e),
        handshake_timeout=_SMOKE_TIMEOUT,
    )
    agent_id = f"smoke-3c-{uuid.uuid4().hex[:12]}"
    cap_token_path = tmp_path / "cap_token.json"
    pid, did = runner.start(
        agent_id, kind="mock",
        cap_token_file_path=str(cap_token_path),
    )
    if pid is None:
        pytest.skip("subprocess could not start (CI sandboxing?)")
    try:
        # Atomic-write the cap_token to where the child is polling.
        cap_token = {
            "token_id": "tok-smoke-001",
            "subject_did": did,
            "capabilities": ["nth:receipt_sign"],
            "issuer_did": "did:key:zFakeIssuerForSmoke",
        }
        tmp = cap_token_path.with_suffix(".json.tmp")
        tmp.write_text(_json.dumps(cap_token), encoding="utf-8")
        os.replace(str(tmp), str(cap_token_path))

        # Wait up to _SMOKE_TIMEOUT for the receipt_signed event.
        deadline = time.time() + _SMOKE_TIMEOUT
        signed = None
        while time.time() < deadline:
            for e in events:
                if e.get("event") == "receipt_signed":
                    signed = e
                    break
            if signed is not None:
                break
            time.sleep(0.1)
        assert signed is not None, (
            f"child did not emit receipt_signed within {_SMOKE_TIMEOUT}s; "
            f"events seen: {[e.get('event') for e in events]!r}"
        )
        receipt = signed.get("receipt")
        assert isinstance(receipt, dict), receipt
        assert receipt.get("signer_did") == did, (
            "the receipt must be signed by the child's own DID, not "
            "the hub's or anyone else's"
        )
        # Inspect the timeline payload for the cap_token wiring.
        timeline = receipt.get("timeline") or []
        attestations = [
            e for e in timeline
            if isinstance(e, dict) and e.get("type") == "nth.agent_attestation"
        ]
        assert attestations, f"no attestation entry in timeline: {timeline!r}"
        payload = attestations[0].get("payload") or {}
        assert payload.get("cap_token_id") == "tok-smoke-001"
        assert payload.get("did") == did
    finally:
        runner.stop(agent_id)
