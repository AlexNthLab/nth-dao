"""
Tests for Phase 2 POST endpoints:

  POST /api/v2/decisions/{id}/approve   → signs + persists receipt
  POST /api/v2/decisions/{id}/reject    → drops from queue
  POST /api/v2/decisions/{id}/defer     → drops from queue

End-to-end: spin up a FastAPI TestClient that uses a real WebState
with a tmp_path workspace (so the bootstrap creates a fresh Ed25519
identity), then walk:
  - GET /decisions returns 3 explicit test fixtures
  - POST /approve/dec-001 returns a signed receipt, queue shrinks
  - Receipt is on disk in team_receipts/
  - Subsequent approve of dec-002 chains to the first (prev_content_hash
    matches the first receipt's content_hash)
  - POST a missing id → 404
  - POST reject → drops without signing
  - POST defer → drops without signing

Run: pytest tests/test_v2_decision_approve.py -q
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Dict

import pytest
from fastapi.testclient import TestClient


def _test_decisions() -> Dict[str, Dict[str, Any]]:
    """Return explicit queue fixtures; production starts with an empty queue."""
    return {
        f"dec-00{index}": {
            "id": f"dec-00{index}",
            "title": f"Test decision {index}",
            "rationale": "Exercise the signed decision resolution path.",
            "impact": "low",
            "proposer_did": "did:key:zTestProposer",
            "proposer_label": "test-proposer",
            "preview_receipt": {
                "kind": "nth-test-preview-v1",
                "sequence": index,
            },
            "raised_at": f"2026-06-09T10:0{index}:00Z",
        }
        for index in range(1, 4)
    }


def _install_test_decisions(app: Any) -> None:
    app.state.v2_decisions_store = _test_decisions()


def _signed_decision_events(client: TestClient) -> list[Any]:
    return [
        event
        for event in client.app.state.nth.spine.read_all()
        if event.type.startswith("decision.")
    ]


@pytest.fixture
def hub_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """A FastAPI client with a fresh workspace and identity bootstrap.

    Uses monkeypatch on HOME so the WebState's default workspace path
    resolves under tmp_path — no chance of touching the real one. """
    monkeypatch.setenv("NTH_V2_WORKSPACE_ONLY", "true")  # skip repo fixtures
    # Point HOME at tmp_path so ~/.nth-dao/... resolves locally.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))  # Windows

    from nth_dao.web import create_app
    # require_console_auth=False so we can POST without a token
    # (v2 routes are anonymous on the local-only bind anyway).
    app = create_app(
        workspace=tmp_path / ".nth-dao" / "workspaces" / "default",
        require_console_auth=False,
    )
    _install_test_decisions(app)
    return TestClient(app)


def test_get_decisions_initially_three(hub_client: TestClient) -> None:
    r = hub_client.get("/api/v2/decisions")
    assert r.status_code == 200
    ids = [d["id"] for d in r.json()]
    assert sorted(ids) == ["dec-001", "dec-002", "dec-003"]


def test_pending_decision_survives_hub_restart(tmp_path: Path) -> None:
    from nth_dao.web import create_app
    from nth_dao.web.decision_store import DecisionStore

    workspace = tmp_path / "workspace"
    DecisionStore(workspace).put(_test_decisions()["dec-001"])

    first = TestClient(create_app(workspace, require_console_auth=False))
    assert [row["id"] for row in first.get("/api/v2/decisions").json()] == [
        "dec-001"
    ]

    restarted = TestClient(create_app(workspace, require_console_auth=False))
    assert [row["id"] for row in restarted.get("/api/v2/decisions").json()] == [
        "dec-001"
    ]


def test_concurrent_approve_creates_exactly_one_receipt(tmp_path: Path) -> None:
    from nth_dao.web import create_app
    from nth_dao.web.decision_store import DecisionStore

    workspace = tmp_path / "workspace"
    store = DecisionStore(workspace)
    store.put(_test_decisions()["dec-001"])
    app = create_app(workspace, require_console_auth=False)
    barrier = threading.Barrier(2)
    statuses: list[int] = []

    def approve() -> None:
        with TestClient(app) as client:
            barrier.wait()
            statuses.append(
                client.post("/api/v2/decisions/dec-001/approve").status_code
            )

    threads = [threading.Thread(target=approve) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)

    assert all(not thread.is_alive() for thread in threads)
    assert sorted(statuses) == [200, 404]
    assert len(list((workspace / "team_receipts").glob("*.json"))) == 1
    assert [event["event_kind"] for event in store.events()] == [
        "decision.raised",
        "decision.approved",
    ]


def test_concurrent_distinct_approvals_keep_one_receipt_chain(
    tmp_path: Path,
) -> None:
    from nth_dao.web import create_app
    from nth_dao.web.decision_store import DecisionStore

    workspace = tmp_path / "workspace"
    store = DecisionStore(workspace)
    store.put(_test_decisions()["dec-001"])
    store.put(_test_decisions()["dec-002"])
    app = create_app(workspace, require_console_auth=False)
    barrier = threading.Barrier(2)
    responses: list[dict] = []

    def approve(decision_id: str) -> None:
        with TestClient(app) as client:
            barrier.wait()
            response = client.post(f"/api/v2/decisions/{decision_id}/approve")
            assert response.status_code == 200, response.text
            responses.append(response.json())

    threads = [
        threading.Thread(target=approve, args=("dec-001",)),
        threading.Thread(target=approve, args=("dec-002",)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)

    assert all(not thread.is_alive() for thread in threads)
    assert len(responses) == 2
    summaries = [response["receipt"] for response in responses]
    genesis = [
        summary for summary in summaries if not summary["prev_content_hash"]
    ]
    chained = [
        summary for summary in summaries if summary["prev_content_hash"]
    ]
    assert len(genesis) == len(chained) == 1
    assert chained[0]["prev_content_hash"] == genesis[0]["content_hash"]


def test_approve_retry_recovers_receipt_saved_before_queue_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.web import create_app
    from nth_dao.web.decision_store import DecisionStore

    workspace = tmp_path / "workspace"
    store = DecisionStore(workspace)
    store.put(_test_decisions()["dec-001"])
    app = create_app(workspace, require_console_auth=False)
    app.state.v2_decisions_store = store
    original_complete = store.complete
    calls = 0

    def fail_first_complete(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("simulated SQLite completion failure")
        return original_complete(*args, **kwargs)

    monkeypatch.setattr(store, "complete", fail_first_complete)
    client = TestClient(app)

    first = client.post("/api/v2/decisions/dec-001/approve")

    assert first.status_code == 500
    assert store.get("dec-001") is not None
    assert len(list((workspace / "team_receipts").glob("*.json"))) == 1

    second = client.post("/api/v2/decisions/dec-001/approve")

    assert second.status_code == 200, second.text
    assert second.json()["recovered"] is True
    assert store.get("dec-001") is None
    assert len(list((workspace / "team_receipts").glob("*.json"))) == 1
    events = _signed_decision_events(client)
    assert [event.type for event in events] == ["decision.approved"]


def test_approve_signs_and_persists(hub_client: TestClient, tmp_path: Path) -> None:
    r = hub_client.post("/api/v2/decisions/dec-001/approve")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["decision_id"] == "dec-001"
    assert body["removed"] is True
    assert body["signed"] is True
    assert body["audit_signed"] is True
    assert body["audit_event_id"]

    rcpt = body["receipt"]
    assert rcpt["content_hash"]
    # Genesis (no prior receipt by this signer) → empty prev.
    assert rcpt["prev_content_hash"] == ""
    assert rcpt["summary"]
    assert rcpt["signer_did"].startswith("did:key:")

    # Receipt on disk.
    receipts_dir = tmp_path / ".nth-dao" / "workspaces" / "default" / "team_receipts"
    files = list(receipts_dir.glob("*.json"))
    assert len(files) == 1
    on_disk = json.loads(files[0].read_text(encoding="utf-8"))
    assert on_disk["content_hash"] == rcpt["content_hash"]
    events = _signed_decision_events(hub_client)
    assert len(events) == 1
    event = events[0]
    assert event.type == "decision.approved"
    assert event.event_id == body["audit_event_id"]
    assert event.payload["decision_id"] == "dec-001"
    assert event.payload["receipt_id"] == rcpt["id"]
    assert event.payload["receipt_content_hash"] == rcpt["content_hash"]
    assert hub_client.app.state.nth.spine.verify_chain() == (True, "ok")


def test_approve_chains_subsequent_receipt(hub_client: TestClient) -> None:
    """Second approve carries the first's content_hash as
    prev_content_hash — Phase B chain link working end-to-end. """
    r1 = hub_client.post("/api/v2/decisions/dec-001/approve")
    assert r1.status_code == 200
    first_hash = r1.json()["receipt"]["content_hash"]

    r2 = hub_client.post("/api/v2/decisions/dec-002/approve")
    assert r2.status_code == 200, r2.text
    second = r2.json()["receipt"]
    assert second["prev_content_hash"] == first_hash
    # And the two content hashes differ.
    assert second["content_hash"] != first_hash


def test_approve_removes_decision_from_queue(hub_client: TestClient) -> None:
    pre = hub_client.get("/api/v2/decisions").json()
    assert any(d["id"] == "dec-001" for d in pre)

    hub_client.post("/api/v2/decisions/dec-001/approve")

    post = hub_client.get("/api/v2/decisions").json()
    assert all(d["id"] != "dec-001" for d in post)
    assert len(post) == 2


def test_approve_unknown_id_404(hub_client: TestClient) -> None:
    r = hub_client.post("/api/v2/decisions/does-not-exist/approve")
    assert r.status_code == 404
    assert "not found" in r.json()["detail"]


def test_approve_already_resolved_404(hub_client: TestClient) -> None:
    """Idempotent guard — second approve of the same id gets 404. """
    r1 = hub_client.post("/api/v2/decisions/dec-001/approve")
    assert r1.status_code == 200
    r2 = hub_client.post("/api/v2/decisions/dec-001/approve")
    assert r2.status_code == 404


def test_reject_drops_without_signing(hub_client: TestClient, tmp_path: Path) -> None:
    r = hub_client.post("/api/v2/decisions/dec-001/reject")
    assert r.status_code == 200
    body = r.json()
    assert body["removed"] is True
    assert body["signed"] is False
    assert body["audit_signed"] is True
    assert body["audit_event_id"]
    assert "receipt" not in body

    # No receipt was written.
    receipts_dir = tmp_path / ".nth-dao" / "workspaces" / "default" / "team_receipts"
    if receipts_dir.exists():
        assert list(receipts_dir.glob("*.json")) == []
    events = _signed_decision_events(hub_client)
    assert [event.type for event in events] == ["decision.rejected"]
    assert events[0].event_id == body["audit_event_id"]
    assert events[0].payload["receipt_id"] == ""


def test_defer_drops_without_signing(hub_client: TestClient) -> None:
    r = hub_client.post("/api/v2/decisions/dec-001/defer")
    assert r.status_code == 200
    body = r.json()
    assert body["removed"] is True
    assert body["signed"] is False
    assert body["audit_signed"] is True
    events = _signed_decision_events(hub_client)
    assert [event.type for event in events] == ["decision.deferred"]
    assert events[0].event_id == body["audit_event_id"]


def test_missing_spine_keeps_rejection_pending(hub_client: TestClient) -> None:
    hub_client.app.state.nth.spine = None

    response = hub_client.post("/api/v2/decisions/dec-001/reject")

    assert response.status_code == 503
    pending = hub_client.get("/api/v2/decisions").json()
    assert any(row["id"] == "dec-001" for row in pending)


def test_cached_spine_view_cannot_hide_disk_tampering(
    hub_client: TestClient,
) -> None:
    spine = hub_client.app.state.nth.spine
    spine.append("test.preexisting", {"value": "original"})
    cached_events = list(spine.read_all())
    spine._v2_verified_cache = (spine.head_hash, cached_events)
    lines = spine._path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[-1])
    tampered["payload"]["value"] = "tampered"
    lines[-1] = json.dumps(tampered, separators=(",", ":"), sort_keys=True)
    spine._path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    response = hub_client.post("/api/v2/decisions/dec-001/reject")

    assert response.status_code == 503
    assert "integrity" in response.json()["detail"].lower()
    pending = hub_client.get("/api/v2/decisions").json()
    assert any(row["id"] == "dec-001" for row in pending)


def test_conflicting_signed_outcome_blocks_approval_before_receipt(
    hub_client: TestClient,
) -> None:
    spine = hub_client.app.state.nth.spine
    spine.append(
        "decision.rejected",
        {
            "decision_id": "dec-001",
            "decision_payload_hash": "0" * 64,
            "proposer_did": "",
            "mission_id": "",
            "decided_by_did": hub_client.app.state.nth.node_identity.as_did(),
            "receipt_id": "",
            "receipt_content_hash": "",
        },
    )

    response = hub_client.post("/api/v2/decisions/dec-001/approve")

    assert response.status_code == 409
    assert hub_client.app.state.nth.receipts.list_ids() == []
    pending = hub_client.get("/api/v2/decisions").json()
    assert any(row["id"] == "dec-001" for row in pending)


def test_no_signer_503(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """If state.node_identity is unset the endpoint MUST fail
    closed (503), not return an unsigned receipt. """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))

    from nth_dao.web import create_app
    app = create_app(
        workspace=tmp_path / ".nth-dao" / "workspaces" / "default",
        require_console_auth=False,
    )
    _install_test_decisions(app)
    # Wipe the identity AFTER startup so the v2 routes see None.
    app.state.nth.node_identity = None

    client = TestClient(app)
    r = client.post("/api/v2/decisions/dec-001/approve")
    assert r.status_code == 503
    assert "signer" in r.json()["detail"].lower()


def test_no_receipts_store_503(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """If state.receipts is unset the endpoint MUST fail closed
    (503) BEFORE signing. Review fix #4 2026-06-10: previously
    the code would sign + silently discard, returning signed=True
    to the UI with no on-disk receipt. """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))

    from nth_dao.web import create_app
    app = create_app(
        workspace=tmp_path / ".nth-dao" / "workspaces" / "default",
        require_console_auth=False,
    )
    _install_test_decisions(app)
    # Wipe the receipts store but leave identity intact — confirms
    # the receipts-store guard fires independently of the signer.
    app.state.nth.receipts = None

    client = TestClient(app)
    r = client.post("/api/v2/decisions/dec-001/approve")
    assert r.status_code == 503
    detail = r.json()["detail"].lower()
    assert "receipt" in detail and "store" in detail

    # The decision MUST still be in the queue (we failed before
    # signing or removing).
    queue = client.get("/api/v2/decisions").json()
    assert any(d["id"] == "dec-001" for d in queue)


def test_receipt_verifies_via_existing_verifier(hub_client: TestClient) -> None:
    """The signed receipt should satisfy nth_dao.execution_receipt.
    verify_receipt — proves the signature is real, not stubbed. """
    r = hub_client.post("/api/v2/decisions/dec-001/approve")
    assert r.status_code == 200

    # Pull the on-disk receipt — the API summary doesn't carry sig.
    state = hub_client.app.state.nth
    rid = r.json()["receipt"]["id"]
    full = state.receipts.load(rid)
    assert full is not None

    from nth_dao.execution_receipt import verify_receipt
    result = verify_receipt(full)
    # verify_receipt returns bool in this version; some forks return
    # (ok, reason). Handle both.
    ok = result[0] if isinstance(result, tuple) else result
    assert ok, f"verify_receipt failed: {result!r}"


def test_receipts_endpoint_returns_chronological_order(tmp_path: Path) -> None:
    """Bug discovered during Phase 2 browser walk-through 2026-06-11:
    ``_read_receipts_from_disk`` returned filename-ASCII order, so a
    mix of uuid-hex receipt ids (from Phase 2 POST /approve) and
    rcpt-aaa* names (from Phase 1.5 seed_workspace) put the newest
    signed receipt in the middle of the list. StatusBar's chain head
    computation (``receipts[-1].content_hash``) silently showed stale
    data. The disk reader now sorts by issued_at ascending.

    Test does NOT spin up the FastAPI app — calls the disk reader
    directly to keep it focused on the sort guarantee. """
    from nth_dao.web.v2_api import _read_receipts_from_disk

    rdir = tmp_path / "team_receipts"
    rdir.mkdir()

    # Three receipts, deliberately ordered so filename-ASCII sort
    # would produce a WRONG chronological tail.
    fixtures = [
        # filename                  issued_at                    content_hash
        ("rcpt-aaa1.json",          "2026-06-09T11:20:00Z",      "aaaa0001"),  # OLDEST
        ("zzz-newest-receipt.json", "2026-06-11T15:00:00Z",      "ffff9999"),  # NEWEST chronologically
        ("rcpt-aaa2.json",          "2026-06-09T13:45:00Z",      "bbbb0002"),  # MIDDLE
    ]
    for fn, ts, ch in fixtures:
        (rdir / fn).write_text(json.dumps({
            "id": fn[:-5],
            "content_hash": ch,
            "issued_at": ts,
            "signer_did": "did:key:test",
            "goal_id": "g",
            "prev_content_hash": "",
            "summary": "s",
        }), encoding="utf-8")

    # Filename ASCII sort would put "rcpt-aaa2.json" last (the
    # MIDDLE receipt). Verify our chronological sort puts the
    # NEWEST receipt last.
    result = _read_receipts_from_disk(tmp_path)
    assert len(result) == 3
    assert result[0]["content_hash"] == "aaaa0001", "oldest should be first"
    assert result[1]["content_hash"] == "bbbb0002", "middle should be middle"
    assert result[2]["content_hash"] == "ffff9999", (
        "newest should be LAST; "
        "regression: ASCII filename sort would put 'rcpt-aaa2' here"
    )


def test_receipts_sort_tie_breaks_on_content_hash(tmp_path: Path) -> None:
    """When two receipts share an issued_at (sub-ms collision or
    seed dup), break the tie on content_hash ascending so the
    LEX-GREATEST hash ends up at receipts[-1] — matching
    ReceiptStore.head_content_hash's documented convention. """
    from nth_dao.web.v2_api import _read_receipts_from_disk

    rdir = tmp_path / "team_receipts"
    rdir.mkdir()

    # Two receipts at the same instant — only content_hash distinguishes.
    for fn, ts, ch in [
        ("z.json", "2026-06-11T15:00:00Z", "ffff"),
        ("a.json", "2026-06-11T15:00:00Z", "0000"),
    ]:
        (rdir / fn).write_text(json.dumps({
            "id": fn[:-5], "content_hash": ch, "issued_at": ts,
            "signer_did": "x", "goal_id": "g",
            "prev_content_hash": "", "summary": "s",
        }), encoding="utf-8")

    result = _read_receipts_from_disk(tmp_path)
    assert [r["content_hash"] for r in result] == ["0000", "ffff"]
    # The chain head shown by the frontend is result[-1] — must be
    # the lex-greatest hash to match head_content_hash.
    assert result[-1]["content_hash"] == "ffff"


def test_receipts_sort_mixed_timezone_offsets(tmp_path: Path) -> None:
    """Review fix 2026-06-11: lex sort on ISO strings silently
    LIES when offset suffixes differ. Worked example where lex
    and true-UTC ordering DISAGREE:

      R1: "2026-06-11T05:00:00+00:00" → UTC 05:00
      R2: "2026-06-11T20:00:00+08:00" → UTC 12:00  (20 - 8 = 12)
      R3: "2026-06-11T18:00:00+00:00" → UTC 18:00

      Lex order (broken):  R1(05) < R3(18) < R2(20)   → tail = R2 wrong
      UTC order (correct): R1(05) < R2(12) < R3(18)   → tail = R3 right

    _parse_issued_at normalises to UTC so the sort key reflects
    true instants. """
    from nth_dao.web.v2_api import _read_receipts_from_disk

    rdir = tmp_path / "team_receipts"
    rdir.mkdir()

    for fn, ts, ch in [
        ("R3.json", "2026-06-11T18:00:00+00:00", "ccc"),  # UTC 18:00 — newest
        ("R2.json", "2026-06-11T20:00:00+08:00", "bbb"),  # UTC 12:00 — middle
        ("R1.json", "2026-06-11T05:00:00+00:00", "aaa"),  # UTC 05:00 — oldest
    ]:
        (rdir / fn).write_text(json.dumps({
            "id": fn[:-5], "content_hash": ch, "issued_at": ts,
            "signer_did": "x", "goal_id": "g",
            "prev_content_hash": "", "summary": "s",
        }), encoding="utf-8")

    result = _read_receipts_from_disk(tmp_path)
    hashes = [r["content_hash"] for r in result]
    # UTC chronology: 05:00 < 12:00 < 18:00 → aaa, bbb, ccc.
    # Naive lex sort would put bbb LAST (because "20:00..." > "18:00...").
    assert hashes == ["aaa", "bbb", "ccc"], (
        f"timezone normalisation failed: got {hashes} "
        "(naive lex would put 'bbb' last because '20' > '18')"
    )
    # Specifically, the tail MUST be R3 (UTC 18:00) — the
    # StatusBar's chain head must show R3, not R2.
    assert result[-1]["content_hash"] == "ccc"


def test_receipts_sort_empty_issued_at_lands_at_front(tmp_path: Path) -> None:
    """Empty / malformed issued_at sorts to the FRONT (not the
    middle of the lex order, which would corrupt receipts[-1]).
    Aligns with ReceiptStore.head_content_hash which effectively
    skips un-timestamped entries. """
    from nth_dao.web.v2_api import _read_receipts_from_disk

    rdir = tmp_path / "team_receipts"
    rdir.mkdir()

    for fn, ts, ch in [
        ("good.json",    "2026-06-11T15:00:00Z", "good"),
        ("nots.json",    "",                     "nots"),  # missing
        ("malformed.json", "not-a-date",         "malf"),
    ]:
        (rdir / fn).write_text(json.dumps({
            "id": fn[:-5], "content_hash": ch, "issued_at": ts,
            "signer_did": "x", "goal_id": "g",
            "prev_content_hash": "", "summary": "s",
        }), encoding="utf-8")

    result = _read_receipts_from_disk(tmp_path)
    # The good one MUST be at the tail so the StatusBar chain head
    # picks it up. Order of the bad ones at the front is
    # implementation-defined but they MUST NOT be at the tail.
    assert result[-1]["content_hash"] == "good"
    front_hashes = {r["content_hash"] for r in result[:-1]}
    assert front_hashes == {"nots", "malf"}
