"""v2 handoff endpoints persist only pre-signed capsules/responses."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("nacl")

from fastapi.testclient import TestClient

from nth_dao.execution_receipt import TimelineEntry, now_ms, sign_receipt
from nth_dao.identity import AgentIdentity
from nth_dao.runtime import (
    sign_handoff_capsule,
    sign_handoff_response,
    source_evidence_from_git,
)
from nth_dao.web import create_app


def _source_evidence() -> dict:
    return {
        "kind": "source_span",
        "commit": "c" * 40,
        "path": "nth_dao/web/v2_api.py",
        "symbol": "v2_handoff_record",
        "line_hint": 3900,
        "content_hash": "sha256:" + "d" * 64,
    }


def _client(tmp_path: Path) -> TestClient:
    return TestClient(create_app(tmp_path, require_console_auth=False))


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _handoff_response_receipt(
    signer: AgentIdentity,
    *,
    mission_id: str,
    response_type: str,
    target_capsule_hash: str,
    replacement_capsule_hash: str = "",
    receipt_id: str = "receipt-handoff-1",
) -> dict:
    return sign_receipt(
        [TimelineEntry(
            timestamp=now_ms(),
            type="nth.handoff_response",
            payload={
                "mission_id": mission_id,
                "response_type": response_type,
                "target_capsule_hash": target_capsule_hash,
                "replacement_capsule_hash": replacement_capsule_hash,
            },
        )],
        signer,
        goal_id=mission_id,
        receipt_id=receipt_id,
    )


def test_handoff_endpoint_records_and_lists_capsule(tmp_path: Path) -> None:
    client = _client(tmp_path)
    author = AgentIdentity.generate()
    capsule = sign_handoff_capsule(
        signer=author,
        mission_id="mission-http",
        finding="Mission handoff should be visible in the spine projection.",
        root_cause_hypothesis="No endpoint existed to persist signed handoffs.",
        evidence=[_source_evidence()],
        next_actions=["Post a refutation if another agent disagrees."],
        risks=["Signature does not make the diagnosis true."],
    )

    r = client.post("/api/v2/handoffs", json={"statement": capsule})
    assert r.status_code == 200, r.text
    assert r.json()["capsule_hash"] == capsule["capsule_hash"]

    rows = client.get("/api/v2/handoffs", params={"mission_id": "mission-http"}).json()
    assert len(rows) == 1
    assert rows[0]["status"] == "proposed"
    assert rows[0]["finding"] == capsule["finding"]
    assert rows[0]["evidence_count"] == 1
    assert "evidence" not in rows[0]
    assert "review_packet" not in rows[0]

    detailed = client.get(
        "/api/v2/handoffs",
        params={"mission_id": "mission-http", "include_details": True},
    ).json()
    assert detailed[0]["evidence"][0]["content_hash"] == _source_evidence()["content_hash"]
    assert detailed[0]["evidence_verification"][0]["status"] in {
        "unreachable",
        "unavailable",
    }
    packet = detailed[0]["review_packet"]
    assert packet["packet_kind"] == "nth-handoff-review-packet-v1"
    assert packet["packet_version"] == 1
    assert packet["packet_is_signed"] is False
    assert packet["is_truth_verdict"] is False
    assert packet["warning"] == "Signed handoff is a claim, not a verified fact."
    assert "least context needed" in packet["goal"]
    assert packet["capsule_hash"] == capsule["capsule_hash"]
    assert packet["finding"] == capsule["finding"]
    assert packet["evidence_summary"]["total"] == 1
    assert sum(
        packet["evidence_summary"].get(status, 0)
        for status in ("unreachable", "unavailable")
    ) == 1
    assert packet["evidence_verification"] == detailed[0]["evidence_verification"]
    assert packet["next_actions"] == ["Post a refutation if another agent disagrees."]
    assert packet["risks"] == ["Signature does not make the diagnosis true."]
    assert any(
        "refutation or superseding handoff" in step
        for step in packet["required_review_steps"]
    )


def test_handoff_endpoint_records_refutation(tmp_path: Path) -> None:
    client = _client(tmp_path)
    capsule = sign_handoff_capsule(
        signer=AgentIdentity.generate(),
        mission_id="mission-http",
        finding="A claimed root cause.",
        root_cause_hypothesis="The first agent may be wrong.",
        evidence=[_source_evidence()],
    )
    assert client.post("/api/v2/handoffs", json={"statement": capsule}).status_code == 200

    response = sign_handoff_response(
        signer=AgentIdentity.generate(),
        response_type="refuted",
        target_capsule_hash=capsule["capsule_hash"],
        mission_id="mission-http",
        reason="The pinned evidence contradicts this root-cause hypothesis.",
        counter_evidence=[_source_evidence()],
    )
    rr = client.post("/api/v2/handoffs/responses", json={"statement": response})
    assert rr.status_code == 200, rr.text
    assert rr.json()["response_type"] == "refuted"

    row = client.get(
        "/api/v2/handoffs",
        params={"mission_id": "mission-http", "include_details": True},
    ).json()[0]
    assert row["status"] == "contested"
    assert row["refutations"][0]["response_hash"] == response["response_hash"]
    assert row["refutations"][0]["authorized"] is False


def test_handoff_response_rejects_unknown_target(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = sign_handoff_response(
        signer=AgentIdentity.generate(),
        response_type="refuted",
        target_capsule_hash="sha256:" + "e" * 64,
        mission_id="mission-http",
        reason="No capsule exists for this hash.",
    )
    rr = client.post("/api/v2/handoffs/responses", json={"statement": response})
    assert rr.status_code == 404
    assert "target handoff capsule not found" in rr.text


def test_superseded_response_requires_existing_bound_receipt(tmp_path: Path) -> None:
    client = _client(tmp_path)
    author = AgentIdentity.generate()
    original = sign_handoff_capsule(
        signer=author,
        mission_id="mission-http",
        finding="Original diagnosis.",
        root_cause_hypothesis="This should be replaced.",
        evidence=[_source_evidence()],
    )
    replacement = sign_handoff_capsule(
        signer=author,
        mission_id="mission-http",
        finding="Corrected diagnosis.",
        root_cause_hypothesis="This one is backed by a receipt.",
        evidence=[_source_evidence()],
        parent_capsule_hash=original["capsule_hash"],
    )
    assert client.post("/api/v2/handoffs", json={"statement": original}).status_code == 200
    assert client.post("/api/v2/handoffs", json={"statement": replacement}).status_code == 200

    missing_receipt = sign_handoff_response(
        signer=author,
        response_type="superseded",
        target_capsule_hash=original["capsule_hash"],
        replacement_capsule_hash=replacement["capsule_hash"],
        mission_id="mission-http",
        reason="Replace with a corrected capsule.",
        receipt_id="receipt-missing",
        receipt_content_hash="a" * 64,
    )
    rr = client.post("/api/v2/handoffs/responses", json={"statement": missing_receipt})
    assert rr.status_code == 400
    assert "receipt not found" in rr.text

    wrong_payload = _handoff_response_receipt(
        author,
        mission_id="mission-http",
        response_type="superseded",
        target_capsule_hash="sha256:" + "f" * 64,
        replacement_capsule_hash=replacement["capsule_hash"],
        receipt_id="receipt-wrong-payload",
    )
    client.app.state.nth.receipts.save(wrong_payload)
    unbound = sign_handoff_response(
        signer=author,
        response_type="superseded",
        target_capsule_hash=original["capsule_hash"],
        replacement_capsule_hash=replacement["capsule_hash"],
        mission_id="mission-http",
        reason="Receipt payload points at the wrong target.",
        receipt_id=wrong_payload["receipt_id"],
        receipt_content_hash=wrong_payload["content_hash"],
    )
    rr = client.post("/api/v2/handoffs/responses", json={"statement": unbound})
    assert rr.status_code == 400
    assert "does not bind target/replacement" in rr.text

    receipt = _handoff_response_receipt(
        author,
        mission_id="mission-http",
        response_type="superseded",
        target_capsule_hash=original["capsule_hash"],
        replacement_capsule_hash=replacement["capsule_hash"],
        receipt_id="receipt-bound",
    )
    client.app.state.nth.receipts.save(receipt)
    response = sign_handoff_response(
        signer=author,
        response_type="superseded",
        target_capsule_hash=original["capsule_hash"],
        replacement_capsule_hash=replacement["capsule_hash"],
        mission_id="mission-http",
        reason="Receipt proves the replacement work was executed.",
        receipt_id=receipt["receipt_id"],
        receipt_content_hash=receipt["content_hash"],
    )
    rr = client.post("/api/v2/handoffs/responses", json={"statement": response})
    assert rr.status_code == 200, rr.text
    row = client.get(
        "/api/v2/handoffs",
        params={"mission_id": "mission-http", "include_details": True},
    ).json()[0]
    assert row["status"] == "superseded"
    assert row["supersessions"][0]["receipt_id"] == "receipt-bound"


def test_handoff_endpoint_rejects_invalid_signature(tmp_path: Path) -> None:
    client = _client(tmp_path)
    capsule = sign_handoff_capsule(
        signer=AgentIdentity.generate(),
        mission_id="mission-http",
        finding="A signed claim.",
        root_cause_hypothesis="Tampering must fail closed.",
        evidence=[_source_evidence()],
    )
    capsule["sig"] = "tampered"
    r = client.post("/api/v2/handoffs", json={"statement": capsule})
    assert r.status_code == 400
    assert "invalid handoff capsule" in r.text


def test_handoff_details_verify_evidence_via_repo_mapping(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "source-repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "nth-test.invalid")
    _git(repo, "config", "user.name", "NTH Test")
    src = repo / "pkg"
    src.mkdir()
    (src / "bug.py").write_text("def bug():\n    return 'fixed'\n", encoding="utf-8")
    _git(repo, "add", "pkg/bug.py")
    _git(repo, "commit", "-m", "add bug evidence")

    evidence = source_evidence_from_git(
        repo,
        "pkg/bug.py",
        repo_id="github.com/nth-dao/source-repo",
        repo_url="https://github.com/nth-dao/source-repo.git",
    )
    monkeypatch.setenv(
        "NTH_SOURCE_REPOS",
        f"github.com/nth-dao/source-repo={repo}",
    )
    client = _client(tmp_path / "hub")
    capsule = sign_handoff_capsule(
        signer=AgentIdentity.generate(),
        mission_id="mission-http",
        finding="Mapped repo evidence should verify.",
        root_cause_hypothesis="The receiving node has the matching checkout.",
        evidence=[evidence],
    )
    assert client.post("/api/v2/handoffs", json={"statement": capsule}).status_code == 200

    row = client.get(
        "/api/v2/handoffs",
        params={"mission_id": "mission-http", "include_details": True},
    ).json()[0]
    report = row["evidence_verification"][0]
    assert report["status"] == "verified"
    assert report["commit_reachable"] is True
    assert report["blob_reachable"] is True
    assert report["content_match"] is True
    assert report["resolver"]["matched_by"] == "github.com/nth-dao/source-repo"
    assert "repo_root" not in report["resolver"]


def test_handoff_details_bad_repo_mapping_does_not_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "source-repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "nth-test.invalid")
    _git(repo, "config", "user.name", "NTH Test")
    (repo / "bug.py").write_text("print('fixed')\n", encoding="utf-8")
    _git(repo, "add", "bug.py")
    _git(repo, "commit", "-m", "add evidence")

    evidence = source_evidence_from_git(
        repo,
        "bug.py",
        repo_id="github.com/nth-dao/source-repo",
    )
    not_git = tmp_path / "not-git"
    not_git.mkdir()
    monkeypatch.setenv(
        "NTH_SOURCE_REPOS",
        f"github.com/nth-dao/source-repo={not_git}",
    )
    monkeypatch.setenv("NTH_SOURCE_REPO", str(repo))
    client = _client(tmp_path / "hub")
    capsule = sign_handoff_capsule(
        signer=AgentIdentity.generate(),
        mission_id="mission-http",
        finding="Bad mapping must not silently fall back.",
        root_cause_hypothesis="The configured source repo is invalid.",
        evidence=[evidence],
    )
    assert client.post("/api/v2/handoffs", json={"statement": capsule}).status_code == 200

    row = client.get(
        "/api/v2/handoffs",
        params={"mission_id": "mission-http", "include_details": True},
    ).json()[0]
    report = row["evidence_verification"][0]
    assert report["status"] == "unavailable"
    assert report["resolver"]["matched_by"] == "github.com/nth-dao/source-repo"
    assert report["commit_reachable"] is False
    assert report["blob_reachable"] is False
    assert "not a git checkout" in report["reason"]
    assert str(not_git) not in report["reason"]


def test_mission_timeline_includes_signed_handoffs(tmp_path: Path) -> None:
    client = _client(tmp_path)
    created = client.post(
        "/api/v2/missions",
        json={
            "title": "Handoff-visible debug",
            "goal": "Show agent handoff in Mission timeline",
            "steps": [{"description": "triage the bug"}],
        },
    )
    assert created.status_code == 200, created.text
    mission_id = created.json()["id"]

    capsule = sign_handoff_capsule(
        signer=AgentIdentity.generate(),
        mission_id=mission_id,
        finding="First agent found a likely branch.",
        root_cause_hypothesis="The channel dispatch branch is suspicious.",
        evidence=[_source_evidence()],
    )
    assert client.post("/api/v2/handoffs", json={"statement": capsule}).status_code == 200

    rows = client.get("/api/v2/missions").json()
    row = next(item for item in rows if item["id"] == mission_id)
    handoffs = [event for event in row["timeline"] if event["kind"] == "handoff"]
    assert handoffs, row["timeline"]
    assert handoffs[0]["label"].startswith("Handoff proposed:")
    assert handoffs[0]["capsule_hash"] == capsule["capsule_hash"]
    assert handoffs[0]["status"] == "proposed"

    response = sign_handoff_response(
        signer=AgentIdentity.generate(),
        response_type="refuted",
        target_capsule_hash=capsule["capsule_hash"],
        mission_id=mission_id,
        reason="The pinned branch was not on the execution path.",
    )
    assert client.post("/api/v2/handoffs/responses", json={"statement": response}).status_code == 200

    rows = client.get("/api/v2/missions").json()
    row = next(item for item in rows if item["id"] == mission_id)
    handoff = next(event for event in row["timeline"] if event["kind"] == "handoff")
    assert handoff["status"] == "contested"
    assert handoff["label"].startswith("Handoff contested:")
    assert handoff["refutation_count"] == 1


def test_mission_participant_refutation_is_authorized(tmp_path: Path) -> None:
    client = _client(tmp_path)
    reviewer = AgentIdentity.generate()
    created = client.post(
        "/api/v2/missions",
        json={
            "title": "Participant-reviewed handoff",
            "goal": "Only a mission participant may close this as refuted",
            "driver": "reviewer",
            "driver_did": reviewer.as_did(),
            "steps": [{"description": "review pinned evidence"}],
        },
    )
    assert created.status_code == 200, created.text
    mission_id = created.json()["id"]
    capsule = sign_handoff_capsule(
        signer=AgentIdentity.generate(),
        mission_id=mission_id,
        finding="A suspicious root cause.",
        root_cause_hypothesis="The first diagnosis may be wrong.",
        evidence=[_source_evidence()],
    )
    assert client.post("/api/v2/handoffs", json={"statement": capsule}).status_code == 200
    response = sign_handoff_response(
        signer=reviewer,
        response_type="refuted",
        target_capsule_hash=capsule["capsule_hash"],
        mission_id=mission_id,
        reason="The assigned reviewer checked the pinned evidence.",
        counter_evidence=[_source_evidence()],
    )
    assert client.post("/api/v2/handoffs/responses", json={"statement": response}).status_code == 200

    row = client.get(
        "/api/v2/handoffs",
        params={"mission_id": mission_id, "include_details": True},
    ).json()[0]
    assert row["status"] == "refuted"
    assert row["refutations"][0]["authorized"] is True
    assert row["refutations"][0]["authorization_reason"] == "mission_participant"
