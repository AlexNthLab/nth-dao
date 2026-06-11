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
    assert any("failed to remove cap_token file" in w for w in warnings)


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
