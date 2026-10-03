"""A confirmed intent alone is not a verification-grade claim chain."""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

import pytest

pytest.importorskip("nacl")

from nth_dao.cap_token import CAP_NTH_RECEIPT_SIGN, sign_cap_token
from nth_dao.identity import AgentIdentity
from nth_dao.execution_receipt import TimelineEntry, sign_receipt
from nth_dao.market.announcement import (
    TaskAnnouncement,
    announcement_federation_key,
    sign_announcement,
)
from nth_dao.market.claim import sign_claim_receipt
from nth_dao.market.claim_ack import AuthorityClaimAckStore, sign_authority_claim_ack
from nth_dao.market import (
    ClaimEvidenceUnavailable,
    resolve_confirmed_claim_evidence,
)
from nth_dao.market.claim_intent import (
    IntentTracker,
    IntentTrackerCorrupt,
    sign_claim_intent,
)
from nth_dao.market import claim_intent as claim_intent_module
from nth_dao.market.mission_completion import (
    sign_mission_completion,
    verify_confirmed_mission_completion,
)


def _prepared_claim(
    workspace: Path, *, max_intents: int = 4096, include_signer: bool = False,
    mission_id: str = "",
):
    authority = AgentIdentity.generate(label="authority")
    claimant = AgentIdentity.generate(label="claimant")
    ann = sign_announcement(
        publisher=authority,
        authority_did=authority.as_did(),
        title="work",
        mission_id=mission_id,
    )
    token = sign_cap_token(
        issuer=claimant,
        subject_did=claimant.as_did(),
        capabilities=[CAP_NTH_RECEIPT_SIGN],
        scope_task_id=f"market:claim:{ann.announcement_id}",
    )
    receipt = sign_claim_receipt(ann, claimant, token)
    intent = sign_claim_intent(
        claimant,
        announcement_id=ann.announcement_id,
        cap_token=token,
    )
    tracker = IntentTracker(
        workspace / "federation" / "claim_intents",
        max_intents=max_intents,
    )
    tracker.record_sent(
        intent,
        receipt=receipt,
        announcement=ann,
        cap_token=token,
        source_peer="https://source.example",
        source_did=authority.as_did(),
        federation_key=announcement_federation_key(ann),
    )
    claim_record = {
        "announcement_id": ann.announcement_id,
        "status": "claimed",
        "claimant_did": claimant.as_did(),
        "publisher_did": authority.as_did(),
        "cap_token_id": token["token_id"],
        "claimed_at_ms": receipt["timeline"][0]["timestamp"],
        "receipt_id": receipt["receipt_id"],
        "receipt": receipt,
    }
    ack = sign_authority_claim_ack(
        authority=authority,
        announcement=ann,
        claim_record=claim_record,
    )
    result = (tracker, intent, receipt, ack)
    return (*result, claimant, ann) if include_signer else result


def _signed_completion(workspace: Path, *, claimed_mission_id: str = ""):
    tracker, intent, receipt, ack, claimant, ann = _prepared_claim(
        workspace, include_signer=True, mission_id=claimed_mission_id,
    )
    tracker.mark(intent, "confirmed")
    execution = sign_receipt(
        [TimelineEntry(
            timestamp=int(time.time() * 1000), type="nth.task_completed",
            payload={"mission_id": "mission-1"},
        )],
        claimant, goal_id="mission:mission-1",
    )
    completion = sign_mission_completion(
        claimant,
        announcement_id=ann.announcement_id,
        mission_id="mission-1",
        claim_receipt=receipt,
        authority_ack=ack,
        execution_receipt=execution,
    )
    return tracker, intent, ack, completion, execution


def test_completion_verification_uses_confirmed_local_claim(tmp_path: Path) -> None:
    _tracker, intent, ack, completion, execution = _signed_completion(tmp_path)
    with pytest.raises(ClaimEvidenceUnavailable, match="acknowledgement is missing"):
        verify_confirmed_mission_completion(
            tmp_path, intent["nonce"], completion, execution,
        )
    AuthorityClaimAckStore(tmp_path).save(ack)
    assert verify_confirmed_mission_completion(
        tmp_path, intent["nonce"], completion, execution,
    ) == (True, "ok")
    assert verify_confirmed_mission_completion(
        tmp_path, intent["nonce"], completion, {**execution, "goal_id": "wrong"},
    )[0] is False


def test_completion_rejects_a_different_signed_claim_mission(tmp_path: Path) -> None:
    _tracker, intent, ack, completion, execution = _signed_completion(
        tmp_path, claimed_mission_id="mission-original",
    )
    AuthorityClaimAckStore(tmp_path).save(ack)
    verified, reason = verify_confirmed_mission_completion(
        tmp_path, intent["nonce"], completion, execution,
    )
    assert not verified
    assert "mission" in reason


def test_completion_verification_is_wired_to_rest_endpoint(tmp_path: Path) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from nth_dao.web import create_app

    _tracker, intent, ack, completion, execution = _signed_completion(tmp_path)
    client = TestClient(create_app(tmp_path, require_console_auth=False))
    url = f"/api/v2/market/claim-intents/{intent['nonce']}/completion/verify"
    payload = {"completion_record": completion, "execution_receipt": execution}
    assert client.post(url, json=payload).status_code == 409
    AuthorityClaimAckStore(tmp_path).save(ack)
    response = client.post(url, json=payload)
    assert response.status_code == 200, response.text
    assert response.json() == {
        "nonce": intent["nonce"], "verified": True, "reason": "ok",
        "verification_scope": "signed_evidence_only",
    }
    assert client.post(
        "/api/v2/market/claim-intents/invalid!/completion/verify",
        json=payload,
    ).status_code == 422
    noncanonical = {
        **payload,
        "completion_record": {**completion, "fractional": 1.5},
    }
    assert client.post(url, json=noncanonical).status_code == 422


def test_completion_verification_requires_console_authorization(
    tmp_path: Path,
) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from nth_dao.web import create_app

    client = TestClient(create_app(tmp_path, require_console_auth=True))
    url = "/api/v2/market/claim-intents/1234567890123456/completion/verify"
    response = client.post(url, json={
        "completion_record": {}, "execution_receipt": {},
    })
    assert response.status_code in (401, 403)


def test_claim_evidence_summary_requires_complete_signed_chain(
    tmp_path: Path,
) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from nth_dao.web import create_app

    tracker, intent, receipt, ack, _claimant, _ann = _prepared_claim(
        tmp_path, include_signer=True, mission_id="mission-1",
    )
    client = TestClient(create_app(tmp_path, require_console_auth=False))
    url = f"/api/v2/market/claim-intents/{intent['nonce']}/evidence"
    assert client.get(url).status_code == 409
    tracker.mark(intent, "confirmed")
    assert client.get(url).status_code == 409
    path = AuthorityClaimAckStore(tmp_path).save(ack)
    response = client.get(url)
    assert response.status_code == 200, response.text
    assert response.json() == {
        "nonce": intent["nonce"],
        "evidence_verified": True,
        "verification_scope": "signed_claim_only",
        "claim_receipt_id": receipt["receipt_id"],
        "authority_ack_id": ack["ack_id"],
        "claimant_did": intent["claimant_did"],
        "source_did": ack["authority_did"],
        "mission_id": "mission-1",
    }
    assert client.get(
        "/api/v2/market/claim-intents/invalid!/evidence"
    ).status_code == 422
    path.write_text("{}", encoding="utf-8")
    assert client.get(url).status_code == 503


def test_claim_evidence_summary_requires_console_authorization(
    tmp_path: Path,
) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from nth_dao.web import create_app

    client = TestClient(create_app(tmp_path, require_console_auth=True))
    response = client.get(
        "/api/v2/market/claim-intents/1234567890123456/evidence"
    )
    assert response.status_code in (401, 403)


def test_claim_evidence_summary_accepts_maximum_mission_id(
    tmp_path: Path,
) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from nth_dao.web import create_app

    mission_id = "m" * 256
    tracker, intent, _receipt, ack = _prepared_claim(
        tmp_path, mission_id=mission_id,
    )
    tracker.mark(intent, "confirmed")
    AuthorityClaimAckStore(tmp_path).save(ack)
    with TestClient(create_app(tmp_path, require_console_auth=False)) as client:
        response = client.get(
            f"/api/v2/market/claim-intents/{intent['nonce']}/evidence"
        )
    assert response.status_code == 200, response.text
    assert response.json()["mission_id"] == mission_id


def test_confirmed_claim_evidence_requires_retained_receipt_and_source_ack(
    tmp_path: Path,
) -> None:
    tracker, intent, receipt, ack = _prepared_claim(tmp_path)
    nonce = intent["nonce"]
    with pytest.raises(ClaimEvidenceUnavailable, match="not locally confirmed"):
        resolve_confirmed_claim_evidence(tmp_path, nonce)
    tracker.mark(intent, "confirmed")
    with pytest.raises(ClaimEvidenceUnavailable, match="acknowledgement is missing"):
        resolve_confirmed_claim_evidence(tmp_path, nonce)
    AuthorityClaimAckStore(tmp_path).save(ack)
    evidence = resolve_confirmed_claim_evidence(tmp_path, nonce)
    assert evidence["intent"] == intent
    assert evidence["claim_receipt"] == receipt
    assert evidence["authority_ack"] == ack
    assert evidence["source_did"] == ack["authority_did"]


def test_confirmed_claim_evidence_rejects_tampered_ack(tmp_path: Path) -> None:
    tracker, intent, _receipt, ack = _prepared_claim(tmp_path)
    tracker.mark(intent, "confirmed")
    path = AuthorityClaimAckStore(tmp_path).save(ack)
    path.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="malformed record"):
        resolve_confirmed_claim_evidence(tmp_path, intent["nonce"])


def test_confirmed_claim_evidence_rejects_corrupt_ack_after_cold_start(
    tmp_path: Path,
) -> None:
    tracker, intent, _receipt, ack = _prepared_claim(tmp_path)
    tracker.mark(intent, "confirmed")
    path = AuthorityClaimAckStore(tmp_path).save(ack)
    path.write_text("{}", encoding="utf-8")
    AuthorityClaimAckStore._directory_cache.clear()
    with pytest.raises(ValueError, match="unreadable record"):
        resolve_confirmed_claim_evidence(tmp_path, intent["nonce"])


def test_confirmed_claim_evidence_rejects_missing_retained_receipt(
    tmp_path: Path,
) -> None:
    tracker, intent, _receipt, ack = _prepared_claim(tmp_path)
    tracker.mark(intent, "confirmed")
    AuthorityClaimAckStore(tmp_path).save(ack)
    receipt_hash = tracker.record(intent["nonce"])["receipt_hash"]
    (
        tmp_path
        / "federation"
        / "claim_intents"
        / "claim-receipts"
        / f"{receipt_hash}.json"
    ).unlink()
    with pytest.raises(
        IntentTrackerCorrupt,
        match="committed claim receipt evidence is missing",
    ):
        resolve_confirmed_claim_evidence(tmp_path, intent["nonce"])


def test_confirmed_claim_evidence_rejects_rewritten_source(tmp_path: Path) -> None:
    tracker, intent, _receipt, ack = _prepared_claim(tmp_path)
    tracker.mark(intent, "confirmed")
    AuthorityClaimAckStore(tmp_path).save(ack)
    journal = tmp_path / "federation" / "claim_intents" / "claim-intents.jsonl"
    events = [
        json.loads(line) for line in journal.read_text(encoding="utf-8").splitlines()
    ]
    events[0]["source_did"] = AgentIdentity.generate(label="attacker").as_did()
    journal.write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )
    with pytest.raises(IntentTrackerCorrupt, match="announcement binding"):
        resolve_confirmed_claim_evidence(tmp_path, intent["nonce"])


def test_confirmed_claim_evidence_survives_archival_and_index_migration(
    tmp_path: Path,
) -> None:
    tracker, intent, _receipt, ack = _prepared_claim(tmp_path, max_intents=1)
    tracker.mark(intent, "confirmed")
    AuthorityClaimAckStore(tmp_path).save(ack)
    _prepared_claim(tmp_path, max_intents=1)
    assert tracker.archived_record(intent["nonce"])["state"] == "confirmed"
    index = (
        tmp_path
        / "federation"
        / "claim_intents"
        / "claim-intents-archive"
        / "index.sqlite3"
    )
    with sqlite3.connect(index) as database:
        database.execute("UPDATE bindings SET segment_name = NULL")
    assert (
        resolve_confirmed_claim_evidence(tmp_path, intent["nonce"])["authority_ack"]
        == ack
    )


def test_legacy_source_record_without_announcement_fails_closed(tmp_path: Path) -> None:
    tracker, intent, _receipt, ack = _prepared_claim(tmp_path)
    tracker.mark(intent, "confirmed")
    AuthorityClaimAckStore(tmp_path).save(ack)
    journal = tmp_path / "federation" / "claim_intents" / "claim-intents.jsonl"
    events = [
        json.loads(line) for line in journal.read_text(encoding="utf-8").splitlines()
    ]
    del events[0]["announcement"]
    journal.write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )
    with pytest.raises(
        ClaimEvidenceUnavailable, match="no retained signed announcement"
    ):
        resolve_confirmed_claim_evidence(tmp_path, intent["nonce"])


def test_colliding_attacker_announcement_cannot_rebind_claim(tmp_path: Path) -> None:
    tracker, intent, receipt, _ack = _prepared_claim(tmp_path)
    tracker.mark(intent, "confirmed")
    attacker = AgentIdentity.generate(label="attacker")
    original = TaskAnnouncement.from_dict(
        tracker.record(intent["nonce"])["announcement"]
    )
    forged = sign_announcement(
        publisher=attacker,
        authority_did=attacker.as_did(),
        announcement_id=original.announcement_id,
        title="colliding task",
    )
    claim_record = {
        "announcement_id": forged.announcement_id,
        "status": "claimed",
        "claimant_did": intent["claimant_did"],
        "publisher_did": attacker.as_did(),
        "cap_token_id": intent["cap_token_id"],
        "claimed_at_ms": receipt["timeline"][0]["timestamp"],
        "receipt_id": receipt["receipt_id"],
        "receipt": receipt,
    }
    AuthorityClaimAckStore(tmp_path).save(
        sign_authority_claim_ack(
            authority=attacker,
            announcement=forged,
            claim_record=claim_record,
        )
    )
    journal = tmp_path / "federation" / "claim_intents" / "claim-intents.jsonl"
    events = [
        json.loads(line) for line in journal.read_text(encoding="utf-8").splitlines()
    ]
    events[0]["announcement"] = forged.to_dict()
    events[0]["source_did"] = attacker.as_did()
    events[0]["federation_key"] = announcement_federation_key(forged)
    journal.write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )
    with pytest.raises(ClaimEvidenceUnavailable, match="signed claim event differs"):
        resolve_confirmed_claim_evidence(tmp_path, intent["nonce"])


def test_archive_segment_reader_is_bounded_after_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "segment.jsonl"
    path.write_bytes(b"short")
    assert claim_intent_module._read_archive_segment(path) == b"short"
    with monkeypatch.context() as patcher:
        patcher.setattr(claim_intent_module, "MAX_TRACKER_JOURNAL_BYTES", 32)
        patcher.setattr(claim_intent_module.os, "read", lambda _fd, _limit: b"x" * 33)
        with pytest.raises(IntentTrackerCorrupt, match="exceeds size limit"):
            claim_intent_module._read_archive_segment(path)


def test_retained_receipt_uses_bounded_descriptor_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    tracker, intent, receipt, _ack = _prepared_claim(tmp_path)
    receipt_hash = tracker.record(intent["nonce"])["receipt_hash"]
    receipt_path = (
        tmp_path / "federation" / "claim_intents" / "claim-receipts"
        / f"{receipt_hash}.json"
    )
    original_read = Path.read_bytes

    def refuse_receipt_path_read(path: Path) -> bytes:
        if path == receipt_path:
            pytest.fail("retained receipt was read without a descriptor bound")
        return original_read(path)

    monkeypatch.setattr(Path, "read_bytes", refuse_receipt_path_read)
    assert tracker.load_receipt_by_hash(receipt_hash) == receipt


def test_retained_receipt_rejects_growth_after_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    tracker, intent, _receipt, _ack = _prepared_claim(tmp_path)
    receipt_hash = tracker.record(intent["nonce"])["receipt_hash"]
    with monkeypatch.context() as patcher:
        patcher.setattr(
            claim_intent_module.os, "read",
            lambda _fd, limit: b"x" * limit,
        )
        with pytest.raises(IntentTrackerCorrupt, match="exceeds size limit"):
            tracker.load_receipt_by_hash(receipt_hash)


def test_archive_binding_audit_rechecks_signed_source(tmp_path: Path) -> None:
    tracker, _intent, _receipt, _ack = _prepared_claim(tmp_path)
    journal = tmp_path / "federation" / "claim_intents" / "claim-intents.jsonl"
    event = json.loads(journal.read_text(encoding="utf-8").splitlines()[0])
    event["source_did"] = AgentIdentity.generate(label="other").as_did()
    archived = json.dumps(event).encode("utf-8") + b"\n"
    with pytest.raises(IntentTrackerCorrupt, match="announcement binding"):
        tracker._archive_sent_bindings(tmp_path / "segment.jsonl", archived)
