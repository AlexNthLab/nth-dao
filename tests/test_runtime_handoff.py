"""Signed handoff capsules: source-authenticated, evidence-pinned, refutable."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

pytest.importorskip("nacl")

from nth_dao.identity import AgentIdentity
from nth_dao.runtime import (
    HandoffProjection,
    record_handoff,
    record_handoff_response,
    sign_handoff_capsule,
    sign_handoff_response,
    source_evidence_from_git,
    verify_handoff_capsule,
    verify_handoff_response,
    verify_source_evidence,
    verify_source_evidence_report,
)
from nth_dao.spine import SignedEventLog, replay


def _id() -> AgentIdentity:
    return AgentIdentity.generate()


def _source_evidence() -> dict:
    return {
        "kind": "source_span",
        "commit": "a" * 40,
        "path": "nth_dao/web/v2_api.py",
        "symbol": "_channel_ask_and_reply",
        "line_hint": 2848,
        "content_hash": "sha256:" + "b" * 64,
    }


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _capsule(signer: AgentIdentity | None = None) -> dict:
    signer = signer or _id()
    return sign_handoff_capsule(
        signer=signer,
        mission_id="mission-1",
        step_id="scan",
        finding="Channel dispatch can emit repeated backend errors.",
        root_cause_hypothesis="The previous implementation lacked per-agent cooldown.",
        evidence=[_source_evidence()],
        changed_files=["nth_dao/web/v2_api.py"],
        tests=[{"name": "test_v2_channel_dispatch", "status": "passed"}],
        current_status="candidate fix ready",
        next_actions=["Re-run channel dispatch tests."],
        risks=["Signature proves source, not root-cause truth."],
    )


def test_handoff_capsule_sign_verify_and_tamper() -> None:
    stmt = _capsule()
    assert stmt["capsule_hash"].startswith("sha256:")
    ok, why = verify_handoff_capsule(stmt)
    assert ok, why

    tampered = dict(stmt)
    tampered["root_cause_hypothesis"] = "A different story."
    ok, why = verify_handoff_capsule(tampered)
    assert not ok
    assert "capsule_hash mismatch" in why


def test_verification_is_not_a_truth_oracle() -> None:
    stmt = sign_handoff_capsule(
        signer=_id(),
        mission_id="mission-2",
        finding="The sky is green.",
        root_cause_hypothesis="This is intentionally false but signed.",
        evidence=[_source_evidence()],
    )
    ok, why = verify_handoff_capsule(stmt)
    assert ok, why


def test_source_evidence_requires_content_addressing() -> None:
    evidence = _source_evidence()
    evidence.pop("content_hash")
    with pytest.raises(ValueError, match="content_hash"):
        sign_handoff_capsule(
            signer=_id(),
            mission_id="mission-1",
            finding="x",
            root_cause_hypothesis="y",
            evidence=[evidence],
        )

    absolute = _source_evidence()
    absolute["path"] = "Z:/private.py"
    with pytest.raises(ValueError, match="repository-relative"):
        sign_handoff_capsule(
            signer=_id(),
            mission_id="mission-1",
            finding="x",
            root_cause_hypothesis="y",
            evidence=[absolute],
        )


def test_source_evidence_from_git_verifies_real_blob(tmp_path: Path) -> None:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "nth-test.invalid")
    _git(tmp_path, "config", "user.name", "NTH Test")
    src = tmp_path / "src"
    src.mkdir()
    (src / "demo.py").write_text("print('hello')\n", encoding="utf-8")
    _git(tmp_path, "add", "src/demo.py")
    _git(tmp_path, "commit", "-m", "add demo")

    evidence = source_evidence_from_git(
        tmp_path,
        "src/demo.py",
        symbol="demo",
        line_hint=1,
        repo_url="https://github.com/nth-dao/example.git",
        repo_id="github.com/nth-dao/example",
    )
    assert evidence["commit"]
    assert evidence["content_hash"].startswith("sha256:")
    assert evidence["source"]["repo_url"] == "https://github.com/nth-dao/example.git"
    ok, why = verify_source_evidence(tmp_path, evidence)
    assert ok, why
    report = verify_source_evidence_report(tmp_path, evidence)
    assert report["status"] == "verified"
    assert report["local_reachable"] is True
    assert report["content_match"] is True

    tampered = dict(evidence)
    tampered["source"] = dict(evidence["source"])
    tampered["content_hash"] = "sha256:" + "0" * 64
    tampered["source"]["content_hash"] = tampered["content_hash"]
    ok, why = verify_source_evidence(tmp_path, tampered)
    assert not ok
    assert "content_hash mismatch" in why


def test_source_evidence_rejects_tokenized_repo_url(tmp_path: Path) -> None:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "nth-test.invalid")
    _git(tmp_path, "config", "user.name", "NTH Test")
    (tmp_path / "demo.py").write_text("print('hello')\n", encoding="utf-8")
    _git(tmp_path, "add", "demo.py")
    _git(tmp_path, "commit", "-m", "add demo")

    with pytest.raises(ValueError, match="userinfo|tokens"):
        source_evidence_from_git(
            tmp_path,
            "demo.py",
            repo_url="https://userinfo@github.invalid/nth-dao/example.git",
        )


def test_untrusted_refutation_contests_capsule(tmp_path: Path) -> None:
    spine = SignedEventLog(tmp_path / "spine.jsonl", _id())
    capsule = _capsule()
    record_handoff(spine, capsule)
    response = sign_handoff_response(
        signer=_id(),
        response_type="refuted",
        target_capsule_hash=capsule["capsule_hash"],
        mission_id="mission-1",
        reason="Evidence points to a different failing branch.",
        counter_evidence=[_source_evidence()],
    )
    ok, why = verify_handoff_response(response)
    assert ok, why
    record_handoff_response(spine, response)

    proj = HandoffProjection()
    replay(spine.read_all(), proj)
    rec = proj.get(capsule["capsule_hash"])
    assert rec is not None
    assert rec.status == "contested"
    assert rec.refutations[0]["response_hash"] == response["response_hash"]


def test_trusted_refutation_can_refute_capsule(tmp_path: Path) -> None:
    spine = SignedEventLog(tmp_path / "spine.jsonl", _id())
    capsule = _capsule()
    reviewer = _id()
    record_handoff(spine, capsule)
    response = sign_handoff_response(
        signer=reviewer,
        response_type="refuted",
        target_capsule_hash=capsule["capsule_hash"],
        mission_id="mission-1",
        reason="Trusted reviewer confirmed the claim is wrong.",
        counter_evidence=[_source_evidence()],
    )
    record_handoff_response(spine, response)

    proj = HandoffProjection(trusted_responders={reviewer.as_did()})
    replay(spine.read_all(), proj)
    rec = proj.get(capsule["capsule_hash"])
    assert rec is not None
    assert rec.status == "refuted"
    assert rec.refutations[0]["authorized"] is True
    assert rec.refutations[0]["authorization_reason"] == "trusted_responder"


def test_custom_responder_authorizer_controls_terminal_status(tmp_path: Path) -> None:
    spine = SignedEventLog(tmp_path / "spine.jsonl", _id())
    capsule = _capsule()
    reviewer = _id()
    record_handoff(spine, capsule)
    response = sign_handoff_response(
        signer=reviewer,
        response_type="refuted",
        target_capsule_hash=capsule["capsule_hash"],
        mission_id="mission-1",
        reason="Mission participant reviewed pinned evidence.",
        counter_evidence=[_source_evidence()],
    )
    record_handoff_response(spine, response)

    def authorize(_rec, stmt):
        assert stmt["author_did"] == reviewer.as_did()
        return True, "mission_participant"

    proj = HandoffProjection(responder_authorizer=authorize)
    replay(spine.read_all(), proj)
    rec = proj.get(capsule["capsule_hash"])
    assert rec is not None
    assert rec.status == "refuted"
    assert rec.refutations[0]["authorization_reason"] == "mission_participant"


def test_superseded_response_requires_replacement_hash() -> None:
    capsule = _capsule()
    with pytest.raises(ValueError, match="replacement_capsule_hash"):
        sign_handoff_response(
            signer=_id(),
            response_type="superseded",
            target_capsule_hash=capsule["capsule_hash"],
            mission_id="mission-1",
            reason="A corrected capsule should replace this one.",
        )


def test_supersession_waits_for_existing_replacement(tmp_path: Path) -> None:
    spine = SignedEventLog(tmp_path / "spine.jsonl", _id())
    author = _id()
    original = _capsule(author)
    replacement = sign_handoff_capsule(
        signer=author,
        mission_id="mission-1",
        finding="Corrected finding.",
        root_cause_hypothesis="Corrected hypothesis.",
        evidence=[_source_evidence()],
        parent_capsule_hash=original["capsule_hash"],
    )
    response = sign_handoff_response(
        signer=author,
        response_type="superseded",
        target_capsule_hash=original["capsule_hash"],
        replacement_capsule_hash=replacement["capsule_hash"],
        mission_id="mission-1",
        reason="Replacing the earlier capsule with a corrected one.",
    )
    record_handoff(spine, original)
    record_handoff_response(spine, response)

    proj = HandoffProjection()
    replay(spine.read_all(), proj)
    rec = proj.get(original["capsule_hash"])
    assert rec is not None
    assert rec.status == "supersession_proposed"

    record_handoff(spine, replacement)
    proj = HandoffProjection()
    replay(spine.read_all(), proj)
    rec = proj.get(original["capsule_hash"])
    assert rec is not None
    assert rec.status == "superseded"


def test_statement_size_cap_rejects_payload_bloat() -> None:
    with pytest.raises(ValueError, match="too large"):
        sign_handoff_capsule(
            signer=_id(),
            mission_id="mission-1",
            finding="x",
            root_cause_hypothesis="y",
            evidence=[_source_evidence()],
            tests=[{"blob": "x" * 5000}],
        )


def test_record_rejects_invalid_capsule(tmp_path: Path) -> None:
    spine = SignedEventLog(tmp_path / "spine.jsonl", _id())
    stmt = _capsule()
    stmt["sig"] = "tampered"
    with pytest.raises(ValueError, match="invalid handoff capsule"):
        record_handoff(spine, stmt)
