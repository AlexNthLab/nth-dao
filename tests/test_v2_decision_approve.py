"""
Tests for Phase 2 POST endpoints:

  POST /api/v2/decisions/{id}/approve   → signs + persists receipt
  POST /api/v2/decisions/{id}/reject    → drops from queue
  POST /api/v2/decisions/{id}/defer     → drops from queue

End-to-end: spin up a FastAPI TestClient that uses a real WebState
with a tmp_path workspace (so the bootstrap creates a fresh Ed25519
identity), then walk:
  - GET /decisions returns 3 seeded
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
from pathlib import Path
from typing import Any, Dict

import pytest
from fastapi.testclient import TestClient


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
    return TestClient(app)


def test_get_decisions_initially_three(hub_client: TestClient) -> None:
    r = hub_client.get("/api/v2/decisions")
    assert r.status_code == 200
    ids = [d["id"] for d in r.json()]
    assert sorted(ids) == ["dec-001", "dec-002", "dec-003"]


def test_approve_signs_and_persists(hub_client: TestClient, tmp_path: Path) -> None:
    r = hub_client.post("/api/v2/decisions/dec-001/approve")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["decision_id"] == "dec-001"
    assert body["removed"] is True
    assert body["signed"] is True

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
    assert "receipt" not in body

    # No receipt was written.
    receipts_dir = tmp_path / ".nth-dao" / "workspaces" / "default" / "team_receipts"
    if receipts_dir.exists():
        assert list(receipts_dir.glob("*.json")) == []


def test_defer_drops_without_signing(hub_client: TestClient) -> None:
    r = hub_client.post("/api/v2/decisions/dec-001/defer")
    assert r.status_code == 200
    body = r.json()
    assert body["removed"] is True
    assert body["signed"] is False


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
