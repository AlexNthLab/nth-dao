"""A confirmed intent alone is not a verification-grade claim chain."""

from __future__ import annotations

import json
import hashlib
import multiprocessing
import sqlite3
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import pytest

pytest.importorskip("nacl")

from nth_dao.cap_token import CAP_NTH_RECEIPT_SIGN, sign_cap_token
from nth_dao.canonical_json import canonical_json
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
    MissionCompletionRejected,
    receipt_digest,
    sign_mission_completion,
    verify_confirmed_mission_completion,
)
from nth_dao.market.completion_store import (
    ClaimCompletionStore,
    CompletionEvidenceConflict,
    CompletionEvidenceCorrupt,
    CompletionEvidenceRejected,
)
from nth_dao.market.completion_flow import (
    build_portable_completion_proof,
    record_local_mission_completion,
    verify_portable_completion_proof,
)
from nth_dao.orchestration.mission import Mission, MissionStatus, StepStatus
from nth_dao.orchestration.mission_store import MissionStore


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


def _record_completion_in_process(
    args: tuple[Path, str, dict, dict],
) -> bool:
    workspace, nonce, completion, execution = args
    _value, created = ClaimCompletionStore(workspace).record(
        nonce, completion, execution,
    )
    return created


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


def test_completion_store_is_durable_and_idempotent(tmp_path: Path) -> None:
    _tracker, intent, ack, completion, execution = _signed_completion(tmp_path)
    AuthorityClaimAckStore(tmp_path).save(ack)
    store = ClaimCompletionStore(tmp_path)
    saved, created = store.record(intent["nonce"], completion, execution)
    assert created is True
    assert saved["completion_record"] == completion
    assert not (store.root / intent["nonce"] / "_slot.lock").exists()
    assert ClaimCompletionStore(tmp_path).load(intent["nonce"]) == saved
    repeated, created = ClaimCompletionStore(tmp_path).record(
        intent["nonce"], completion, execution,
    )
    assert created is False
    assert repeated == saved


def test_completion_store_cross_process_exactly_once(tmp_path: Path) -> None:
    _tracker, intent, ack, completion, execution = _signed_completion(tmp_path)
    AuthorityClaimAckStore(tmp_path).save(ack)
    args = [(tmp_path, intent["nonce"], completion, execution)] * 3
    with ProcessPoolExecutor(
        max_workers=3, mp_context=multiprocessing.get_context("spawn"),
    ) as pool:
        results = list(pool.map(_record_completion_in_process, args))
    assert sorted(results) == [False, False, True]


def test_completion_store_requires_confirmed_source_ack(tmp_path: Path) -> None:
    _tracker, intent, _ack, completion, execution = _signed_completion(tmp_path)
    store = ClaimCompletionStore(tmp_path)
    with pytest.raises(ClaimEvidenceUnavailable, match="acknowledgement is missing"):
        store.record(intent["nonce"], completion, execution)
    assert store.load(intent["nonce"]) is None


def test_completion_store_rejects_invalid_submission(tmp_path: Path) -> None:
    _tracker, intent, ack, completion, execution = _signed_completion(tmp_path)
    AuthorityClaimAckStore(tmp_path).save(ack)
    with pytest.raises(CompletionEvidenceRejected, match="signature"):
        ClaimCompletionStore(tmp_path).record(
            intent["nonce"], {**completion, "outcome": "failed"}, execution,
        )


def test_completion_store_fails_closed_on_tamper(tmp_path: Path) -> None:
    _tracker, intent, ack, completion, execution = _signed_completion(tmp_path)
    AuthorityClaimAckStore(tmp_path).save(ack)
    store = ClaimCompletionStore(tmp_path)
    store.record(intent["nonce"], completion, execution)
    path = next((store.root / intent["nonce"]).glob("*.json"))
    path.write_text("{}", encoding="utf-8")
    with pytest.raises(CompletionEvidenceCorrupt, match="content hash changed"):
        ClaimCompletionStore(tmp_path).load(intent["nonce"])
    with pytest.raises(CompletionEvidenceCorrupt, match="content hash changed"):
        store.record(intent["nonce"], completion, execution)


def test_completion_write_failure_leaves_no_slot_residue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _tracker, intent, ack, completion, execution = _signed_completion(tmp_path)
    AuthorityClaimAckStore(tmp_path).save(ack)
    store = ClaimCompletionStore(tmp_path)
    original_replace = store._replace_durable

    def fail_replace(_source: Path, _target: Path) -> None:
        raise OSError("simulated durable rename failure")

    monkeypatch.setattr(store, "_replace_durable", fail_replace)
    with pytest.raises(OSError, match="simulated"):
        store.record(intent["nonce"], completion, execution)
    slot = store.root / intent["nonce"]
    assert list(slot.iterdir()) == []
    stage = tmp_path / ".nth" / "staging" / "claim_completions"
    assert list(stage.iterdir()) == []
    (stage / "abandoned-by-crashed-process.tmp").write_bytes(b"incomplete")
    monkeypatch.setattr(store, "_replace_durable", original_replace)
    saved, created = store.record(intent["nonce"], completion, execution)
    assert created and ClaimCompletionStore(tmp_path).load(intent["nonce"]) == saved


def test_completion_store_rejects_symlinked_federation_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ClaimCompletionStore(tmp_path)
    original_is_symlink = Path.is_symlink
    monkeypatch.setattr(
        Path, "is_symlink",
        lambda path: path == store.root.parent or original_is_symlink(path),
    )
    with pytest.raises(CompletionEvidenceCorrupt, match="symlink"):
        store.load("a" * 24)


def test_completion_store_rejects_symlinked_private_lock_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _tracker, intent, ack, completion, execution = _signed_completion(tmp_path)
    AuthorityClaimAckStore(tmp_path).save(ack)
    store = ClaimCompletionStore(tmp_path)
    original_is_symlink = Path.is_symlink
    private_root = tmp_path / ".nth"
    monkeypatch.setattr(
        Path, "is_symlink",
        lambda path: path == private_root or original_is_symlink(path),
    )
    with pytest.raises(CompletionEvidenceCorrupt, match="lock directory"):
        store.record(intent["nonce"], completion, execution)


def test_completion_store_rejects_conflicting_signed_claim(tmp_path: Path) -> None:
    tracker, intent, claim_receipt, ack, claimant, ann = _prepared_claim(
        tmp_path, include_signer=True,
    )
    tracker.mark(intent, "confirmed")
    AuthorityClaimAckStore(tmp_path).save(ack)
    execution = sign_receipt(
        [TimelineEntry(
            timestamp=int(time.time() * 1000), type="nth.task_completed",
            payload={"mission_id": "mission-1"},
        )],
        claimant, goal_id="mission:mission-1",
    )
    first = sign_mission_completion(
        claimant, announcement_id=ann.announcement_id, mission_id="mission-1",
        claim_receipt=claim_receipt, authority_ack=ack,
        execution_receipt=execution, completed_at_ms=int(time.time() * 1000),
    )
    second = sign_mission_completion(
        claimant, announcement_id=ann.announcement_id, mission_id="mission-1",
        claim_receipt=claim_receipt, authority_ack=ack,
        execution_receipt=execution, completed_at_ms=first["completed_at_ms"] + 1,
    )
    store = ClaimCompletionStore(tmp_path)
    store.record(intent["nonce"], first, execution)
    with pytest.raises(CompletionEvidenceConflict):
        store.record(intent["nonce"], second, execution)
    imported = {
        "version": 1, "nonce": intent["nonce"],
        "completion_record": second, "execution_receipt": execution,
    }
    raw = canonical_json(imported)
    (store.root / intent["nonce"] / f"{hashlib.sha256(raw).hexdigest()}.json").write_bytes(raw)
    with pytest.raises(CompletionEvidenceConflict):
        ClaimCompletionStore(tmp_path).load(intent["nonce"])


def test_completion_store_appends_failed_then_succeeded_revision(tmp_path: Path) -> None:
    tracker, intent, claim_receipt, ack, claimant, ann = _prepared_claim(
        tmp_path, include_signer=True,
    )
    tracker.mark(intent, "confirmed")
    AuthorityClaimAckStore(tmp_path).save(ack)
    claim_at = claim_receipt["timeline"][0]["timestamp"]

    def completion(outcome: str, offset: int, *, revision: int = 0,
                   supersedes_digest: str = "") -> tuple[dict, dict]:
        event_type = "nth.task_completed" if outcome == "succeeded" else "nth.task_failed"
        execution = sign_receipt(
            [TimelineEntry(
                timestamp=claim_at + offset,
                type=event_type,
                payload={"mission_id": "mission-1"},
            )], claimant, goal_id="mission:mission-1",
        )
        record = sign_mission_completion(
            claimant, announcement_id=ann.announcement_id,
            mission_id="mission-1", claim_receipt=claim_receipt,
            authority_ack=ack, execution_receipt=execution,
            outcome=outcome, completed_at_ms=claim_at + offset + 1,
            revision=revision, supersedes_digest=supersedes_digest,
        )
        return record, execution

    store = ClaimCompletionStore(tmp_path)
    failed, failed_execution = completion("failed", 1)
    store.record(intent["nonce"], failed, failed_execution)
    first_path = next((store.root / intent["nonce"]).glob("*.json"))
    first_digest = f"sha256:{first_path.stem}"
    succeeded, succeeded_execution = completion(
        "succeeded", 2, revision=1, supersedes_digest=first_digest,
    )
    latest, created = store.record(intent["nonce"], succeeded, succeeded_execution)
    assert created is True
    assert latest["completion_record"]["outcome"] == "succeeded"
    assert ClaimCompletionStore(tmp_path).load(intent["nonce"]) == latest
    assert len(list((store.root / intent["nonce"]).glob("*.json"))) == 2
    proof = build_portable_completion_proof(tmp_path, intent["nonce"])
    assert proof is not None and len(proof["completion_chain"]) == 2
    assert verify_portable_completion_proof(
        proof, expected_source_did=ack["authority_did"],
        expected_federation_key=ack["federation_key"],
    ) == (True, "ok")
    missing_predecessor = {**proof, "completion_chain": proof["completion_chain"][1:]}
    assert verify_portable_completion_proof(
        missing_predecessor, expected_source_did=ack["authority_did"],
        expected_federation_key=ack["federation_key"],
    )[0] is False
    repeated, created = store.record(intent["nonce"], failed, failed_execution)
    assert created is False and repeated == latest

    fork, fork_execution = completion(
        "succeeded", 3, revision=1, supersedes_digest=first_digest,
    )
    with pytest.raises(CompletionEvidenceConflict, match="current head"):
        store.record(intent["nonce"], fork, fork_execution)
    imported = {
        "version": 1, "nonce": intent["nonce"],
        "completion_record": fork, "execution_receipt": fork_execution,
    }
    raw = canonical_json(imported)
    (store.root / intent["nonce"] / f"{hashlib.sha256(raw).hexdigest()}.json").write_bytes(raw)
    with pytest.raises(CompletionEvidenceConflict, match="forked"):
        ClaimCompletionStore(tmp_path).load(intent["nonce"])


def test_claimant_signed_merge_recovers_synced_completion_fork(tmp_path: Path) -> None:
    tracker, intent, claim_receipt, ack, claimant, ann = _prepared_claim(
        tmp_path, include_signer=True,
    )
    tracker.mark(intent, "confirmed")
    AuthorityClaimAckStore(tmp_path).save(ack)
    claim_at = claim_receipt["timeline"][0]["timestamp"]

    def statement(outcome: str, offset: int, **lineage):
        event = "nth.task_completed" if outcome == "succeeded" else "nth.task_failed"
        execution = sign_receipt(
            [TimelineEntry(timestamp=claim_at + offset, type=event,
                           payload={"mission_id": "mission-1"})],
            claimant, goal_id="mission:mission-1",
        )
        record = sign_mission_completion(
            claimant, announcement_id=ann.announcement_id,
            mission_id="mission-1", claim_receipt=claim_receipt,
            authority_ack=ack, execution_receipt=execution, outcome=outcome,
            completed_at_ms=claim_at + offset + 1, **lineage,
        )
        return {"version": 1, "nonce": intent["nonce"],
                "completion_record": record, "execution_receipt": execution}

    store = ClaimCompletionStore(tmp_path)
    first = statement("failed", 1)
    second = statement("succeeded", 3)
    store.record(intent["nonce"], first["completion_record"], first["execution_receipt"])
    sibling_bytes = canonical_json(second)
    sibling_path = store.root / intent["nonce"] / (
        hashlib.sha256(sibling_bytes).hexdigest() + ".json"
    )
    sibling_path.write_bytes(sibling_bytes)  # A legitimate offline Git merge.
    with pytest.raises(CompletionEvidenceConflict):
        store.load(intent["nonce"])

    parents = sorted([receipt_digest(first), receipt_digest(second)])
    merged = statement("succeeded", 5, revision=1, supersedes_digests=parents)
    result, created = store.record(
        intent["nonce"], merged["completion_record"], merged["execution_receipt"],
    )
    assert created and result == merged
    assert store.load(intent["nonce"]) == merged
    assert len(list((store.root / intent["nonce"]).glob("*.json"))) == 3

    proof = build_portable_completion_proof(tmp_path, intent["nonce"])
    assert proof is not None and proof["version"] == 2
    assert len(proof["completion_chain"]) == 3
    source = {"expected_source_did": ack["authority_did"],
              "expected_federation_key": ack["federation_key"]}
    assert verify_portable_completion_proof(proof, **source) == (True, "ok")
    without_branch = json.loads(json.dumps(proof))
    without_branch["completion_chain"] = [first, merged]
    assert not verify_portable_completion_proof(without_branch, **source)[0]


def test_portable_proof_can_export_all_retained_bounded_revisions(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    tracker, intent, claim_receipt, ack, claimant, ann = _prepared_claim(
        tmp_path, include_signer=True,
    )
    tracker.mark(intent, "confirmed")
    AuthorityClaimAckStore(tmp_path).save(ack)
    store = ClaimCompletionStore(tmp_path)
    claimed_at = claim_receipt["timeline"][0]["timestamp"]
    predecessor = ""
    for revision in range(4):
        execution = sign_receipt(
            [TimelineEntry(
                timestamp=claimed_at + revision + 1,
                type="nth.task_completed",
                payload={"mission_id": "mission-1", "result": "x" * 275_000},
            )],
            claimant, goal_id="mission:mission-1",
        )
        record = sign_mission_completion(
            claimant, announcement_id=ann.announcement_id,
            mission_id="mission-1", claim_receipt=claim_receipt,
            authority_ack=ack, execution_receipt=execution,
            completed_at_ms=claimed_at + revision + 2,
            revision=revision, supersedes_digest=predecessor,
        )
        envelope, created = store.record(intent["nonce"], record, execution)
        assert created
        predecessor = receipt_digest(envelope)

    proof = build_portable_completion_proof(tmp_path, intent["nonce"])
    assert proof is not None and len(canonical_json(proof)) > 1024 * 1024
    assert verify_portable_completion_proof(
        proof, expected_source_did=ack["authority_did"],
        expected_federation_key=ack["federation_key"],
    ) == (True, "ok")
    from nth_dao.cli.claim_completion import main as completion_cli

    path = tmp_path / "portable-completion.json"
    path.write_bytes(canonical_json(proof))
    assert completion_cli([
        "verify", "--proof-file", str(path),
        "--source-did", ack["authority_did"],
        "--federation-key", ack["federation_key"],
    ]) == 0
    assert json.loads(capsys.readouterr().out)["source_claim_id"] == ack["ack_id"]


def test_fork_resolution_requires_explicit_claimant_cli_action(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    tracker, intent, receipt, ack, claimant, ann = _prepared_claim(
        tmp_path, include_signer=True,
    )
    tracker.mark(intent, "confirmed")
    AuthorityClaimAckStore(tmp_path).save(ack)
    mission = Mission.new(
        title="Work", goal="Deliver", owner=claimant.as_did(),
        owner_did=claimant.as_did(), steps=[{"description": "Deliver"}],
    )
    mission.metadata["source_announcement_id"] = ann.announcement_id
    mission.status = MissionStatus.COMPLETED.value
    mission.steps[0].status = StepStatus.DONE.value
    MissionStore(str(tmp_path / "missions")).create(mission)
    first, created = record_local_mission_completion(
        tmp_path, intent["nonce"], mission.id, claimant,
    )
    assert created
    completed_at = first["completion_record"]["completed_at_ms"]
    second_execution = sign_receipt(
        [TimelineEntry(timestamp=completed_at, type="nth.task_completed",
                       payload={"mission_id": mission.id, "independent": True})],
        claimant, goal_id=f"mission:{mission.id}",
    )
    second_record = sign_mission_completion(
        claimant, announcement_id=ann.announcement_id, mission_id=mission.id,
        claim_receipt=receipt, authority_ack=ack,
        execution_receipt=second_execution, completed_at_ms=completed_at,
    )
    sibling = {"version": 1, "nonce": intent["nonce"],
               "completion_record": second_record,
               "execution_receipt": second_execution}
    raw = canonical_json(sibling)
    slot = ClaimCompletionStore(tmp_path).root / intent["nonce"]
    (slot / f"{hashlib.sha256(raw).hexdigest()}.json").write_bytes(raw)

    from nth_dao.cli.claim_completion import main

    identity_path = tmp_path / "claimant-private.json"
    claimant.save(identity_path)
    args = ["record", "--workspace", str(tmp_path),
            "--identity-file", str(identity_path),
            "--nonce", intent["nonce"], "--mission-id", mission.id]
    assert main(args) == 1
    assert "explicit claimant resolution" in capsys.readouterr().err
    assert main([*args, "--resolve-fork"]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["created"] is True
    assert summary["revision"] == 1
    chain = ClaimCompletionStore(tmp_path).load_chain(intent["nonce"])
    assert len(chain) == 3
    assert chain[-1]["completion_record"]["version"] == 3


def test_claimant_process_records_finished_local_mission(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    tracker, intent, _receipt, ack, claimant, ann = _prepared_claim(
        tmp_path, include_signer=True,
    )
    tracker.mark(intent, "confirmed")
    AuthorityClaimAckStore(tmp_path).save(ack)
    mission = Mission.new(
        title="Work", goal="Deliver", owner=claimant.as_did(),
        owner_did=claimant.as_did(), steps=[{"description": "Deliver"}],
    )
    mission.id = "mission-1"
    mission.metadata["source_announcement_id"] = ann.announcement_id
    mission.status = MissionStatus.COMPLETED.value
    mission.steps[0].status = StepStatus.DONE.value
    MissionStore(str(tmp_path / "missions")).create(mission)

    saved, created = record_local_mission_completion(
        tmp_path, intent["nonce"], mission.id, claimant,
    )
    assert created and saved["completion_record"]["outcome"] == "succeeded"
    assert ClaimCompletionStore(tmp_path).load(intent["nonce"]) == saved
    repeated, created = record_local_mission_completion(
        tmp_path, intent["nonce"], mission.id, claimant,
    )
    assert not created and repeated == saved
    from nth_dao.cli.claim_completion import main

    identity_path = tmp_path / "claimant-private.json"
    claimant.save(identity_path)
    assert main([
        "record", "--workspace", str(tmp_path), "--identity-file", str(identity_path),
        "--nonce", intent["nonce"], "--mission-id", mission.id,
    ]) == 0
    cli_response = json.loads(capsys.readouterr().out)
    assert cli_response["created"] is False
    assert "private_key" not in cli_response
    with pytest.raises(MissionCompletionRejected, match="not the confirmed claimant"):
        record_local_mission_completion(
            tmp_path, intent["nonce"], mission.id,
            AgentIdentity.generate(label="unrelated"),
        )
    mission.status = MissionStatus.ACTIVE.value
    MissionStore(str(tmp_path / "missions")).save(mission)
    with pytest.raises(MissionCompletionRejected, match="no terminal result"):
        record_local_mission_completion(tmp_path, intent["nonce"], mission.id, claimant)


def test_handed_off_mission_is_not_a_successful_market_completion(tmp_path: Path) -> None:
    tracker, intent, _receipt, ack, claimant, ann = _prepared_claim(
        tmp_path, include_signer=True,
    )
    tracker.mark(intent, "confirmed")
    AuthorityClaimAckStore(tmp_path).save(ack)
    mission = Mission.new(
        title="Work", goal="Deliver", owner=claimant.as_did(),
        owner_did=claimant.as_did(), steps=[{"description": "Deliver"}],
    )
    mission.metadata["source_announcement_id"] = ann.announcement_id
    store = MissionStore(str(tmp_path / "missions"))
    store.create(mission)
    step_id = mission.steps[0].id

    store.update_step(mission.id, step_id, status=StepStatus.HANDED_OFF.value)
    assert store.get(mission.id).status != MissionStatus.COMPLETED.value
    with pytest.raises(MissionCompletionRejected, match="no terminal result"):
        record_local_mission_completion(tmp_path, intent["nonce"], mission.id, claimant)

    # Old workspaces can contain a completed parent with a handed-off step.
    legacy = store.get(mission.id)
    legacy.status = MissionStatus.COMPLETED.value
    store.save(legacy)
    with pytest.raises(MissionCompletionRejected, match="no terminal result"):
        record_local_mission_completion(tmp_path, intent["nonce"], mission.id, claimant)

    store.try_claim(mission.id, step_id, "next-agent")
    resumed = store.get(mission.id)
    assert resumed.status == MissionStatus.ACTIVE.value
    assert resumed.completed_at is None
    store.update_step(mission.id, step_id, status=StepStatus.DONE.value)
    assert store.get(mission.id).status == MissionStatus.COMPLETED.value


def test_portable_completion_proof_requires_external_source_pins(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    _tracker, intent, ack, completion, execution = _signed_completion(tmp_path)
    AuthorityClaimAckStore(tmp_path).save(ack)
    ClaimCompletionStore(tmp_path).record(intent["nonce"], completion, execution)
    proof = build_portable_completion_proof(tmp_path, intent["nonce"])
    assert proof is not None
    assert proof["source_claim_id"] == ack["ack_id"]
    source_did = ack["authority_did"]
    federation_key = ack["federation_key"]
    assert verify_portable_completion_proof(
        proof, expected_source_did=source_did,
        expected_federation_key=federation_key,
    ) == (True, "ok")
    from nth_dao.cli.claim_completion import main

    proof_path = tmp_path / "portable-proof.json"
    proof_path.write_bytes(canonical_json(proof))
    assert main([
        "verify", "--proof-file", str(proof_path),
        "--source-did", source_did, "--federation-key", federation_key,
    ]) == 0
    cli_result = json.loads(capsys.readouterr().out)
    assert cli_result["verified"] is True
    assert cli_result["source_claim_id"] == ack["ack_id"]
    assert cli_result["nonce_authenticated"] is False
    proof_path.write_text("[" * 1100 + "0" + "]" * 1100, encoding="utf-8")
    assert main([
        "verify", "--proof-file", str(proof_path),
        "--source-did", source_did, "--federation-key", federation_key,
    ]) == 1
    assert verify_portable_completion_proof(
        proof, expected_source_did=AgentIdentity.generate().as_did(),
        expected_federation_key=federation_key,
    )[0] is False
    assert verify_portable_completion_proof(
        proof, expected_source_did="", expected_federation_key=federation_key,
    )[0] is False
    tampered = json.loads(json.dumps(proof))
    tampered["completion_chain"][0]["completion_record"]["outcome"] = "failed"
    assert verify_portable_completion_proof(
        tampered, expected_source_did=source_did,
        expected_federation_key=federation_key,
    )[0] is False
    wrong_binding = {**proof, "source_claim_id": "0" * 64}
    assert verify_portable_completion_proof(
        wrong_binding, expected_source_did=source_did,
        expected_federation_key=federation_key,
    )[0] is False


def test_rewrapped_local_nonce_keeps_the_same_source_claim_identity(tmp_path: Path) -> None:
    tracker, intent, receipt, ack, claimant, ann = _prepared_claim(
        tmp_path, include_signer=True,
    )
    tracker.mark(intent, "confirmed")
    AuthorityClaimAckStore(tmp_path).save(ack)
    completed_at = receipt["timeline"][0]["timestamp"] + 1
    execution = sign_receipt(
        [TimelineEntry(timestamp=completed_at, type="nth.task_completed",
                       payload={"mission_id": "mission-1"})],
        claimant, goal_id="mission:mission-1",
    )
    completion = sign_mission_completion(
        claimant, announcement_id=ann.announcement_id,
        mission_id="mission-1", claim_receipt=receipt,
        authority_ack=ack, execution_receipt=execution,
        completed_at_ms=completed_at,
    )
    ClaimCompletionStore(tmp_path).record(intent["nonce"], completion, execution)
    proof = build_portable_completion_proof(tmp_path, intent["nonce"])
    assert proof is not None
    rebound = json.loads(json.dumps(proof))
    fresh_intent = sign_claim_intent(
        claimant, announcement_id=ann.announcement_id,
        cap_token=receipt["authorizing_cap_token"],
    )
    rebound["intent"] = fresh_intent
    rebound["nonce"] = fresh_intent["nonce"]
    for envelope in rebound["completion_chain"]:
        envelope["nonce"] = fresh_intent["nonce"]
    pins = {"expected_source_did": ack["authority_did"],
            "expected_federation_key": ack["federation_key"]}
    assert verify_portable_completion_proof(proof, **pins) == (True, "ok")
    assert verify_portable_completion_proof(rebound, **pins) == (True, "ok")
    assert rebound["nonce"] != proof["nonce"]
    assert rebound["source_claim_id"] == proof["source_claim_id"] == ack["ack_id"]


def test_completion_proof_export_is_operator_only(tmp_path: Path) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from nth_dao.web import create_app

    _tracker, intent, ack, completion, execution = _signed_completion(tmp_path)
    AuthorityClaimAckStore(tmp_path).save(ack)
    ClaimCompletionStore(tmp_path).record(intent["nonce"], completion, execution)
    url = f"/api/v2/market/claim-intents/{intent['nonce']}/completion/proof"
    authorized = TestClient(create_app(tmp_path, require_console_auth=False))
    response = authorized.get(url)
    assert response.status_code == 200, response.text
    assert verify_portable_completion_proof(
        response.json(), expected_source_did=ack["authority_did"],
        expected_federation_key=ack["federation_key"],
    ) == (True, "ok")
    locked = TestClient(create_app(tmp_path, require_console_auth=True))
    assert locked.get(url).status_code in (401, 403)


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


def test_completion_record_endpoint_is_idempotent_and_read_only_on_get(
    tmp_path: Path,
) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from nth_dao.web import create_app

    _tracker, intent, ack, completion, execution = _signed_completion(tmp_path)
    client = TestClient(create_app(tmp_path, require_console_auth=False))
    base = f"/api/v2/market/claim-intents/{intent['nonce']}/completion"
    payload = {"completion_record": completion, "execution_receipt": execution}
    assert client.get(base).status_code == 404
    assert client.post(base + "/record", json=payload).status_code == 409
    AuthorityClaimAckStore(tmp_path).save(ack)
    first = client.post(base + "/record", json=payload)
    assert first.status_code == 200, first.text
    assert first.json()["recorded"] is True
    assert first.json()["already_recorded"] is False
    assert first.json()["verification_scope"] == "signed_evidence_only"
    assert first.json()["outcome"] == "succeeded"
    assert first.json()["evidence_digest"].startswith("sha256:")
    assert first.json()["source_claim_id"] == ack["ack_id"]
    assert first.json()["nonce_authenticated"] is False
    second = client.post(base + "/record", json=payload)
    assert second.status_code == 200
    assert second.json()["already_recorded"] is True
    assert client.get(base).json() == {
        key: value for key, value in first.json().items() if key != "already_recorded"
    }
    assert client.post(base + "/record", json={
        **payload, "completion_record": {**completion, "outcome": "failed"},
    }).status_code == 422
    assert client.post(base + "/record", json={
        **payload, "unexpected": "ignored?",
    }).status_code == 422


def test_completion_record_endpoint_fails_closed_on_tamper(tmp_path: Path) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from nth_dao.web import create_app

    _tracker, intent, ack, completion, execution = _signed_completion(tmp_path)
    AuthorityClaimAckStore(tmp_path).save(ack)
    client = TestClient(create_app(tmp_path, require_console_auth=False))
    base = f"/api/v2/market/claim-intents/{intent['nonce']}/completion"
    payload = {"completion_record": completion, "execution_receipt": execution}
    assert client.post(base + "/record", json=payload).status_code == 200
    slot = ClaimCompletionStore(tmp_path).root / intent["nonce"]
    next(slot.glob("*.json")).write_text("{}", encoding="utf-8")
    assert client.get(base).status_code == 503
    assert client.post(base + "/record", json=payload).status_code == 503


def test_completion_record_request_is_bounded_before_json_parsing(
    tmp_path: Path,
) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from nth_dao.web import create_app

    client = TestClient(create_app(tmp_path, require_console_auth=False))
    path = "/api/v2/market/claim-intents/1234567890123456/completion/record"
    assert client.post(path, json={"padding": "x" * (512 * 1024)}).status_code == 413
    assert client.post(path.replace("/record", "/verify"), json={
        "padding": "x" * (512 * 1024),
    }).status_code == 413


def test_completion_record_endpoints_require_console_authorization(
    tmp_path: Path,
) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from nth_dao.web import create_app

    client = TestClient(create_app(tmp_path, require_console_auth=True))
    base = "/api/v2/market/claim-intents/1234567890123456/completion"
    assert client.get(base).status_code in (401, 403)
    assert client.post(base + "/record", json={
        "completion_record": {}, "execution_receipt": {},
    }).status_code in (401, 403)


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
