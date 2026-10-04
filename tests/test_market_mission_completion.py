"""Tests for mission completion records — binding claim + execution chains."""

from __future__ import annotations

import time
from copy import deepcopy

import pytest

pytest.importorskip("nacl")

from nth_dao.b64u import b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.cap_token import CAP_NTH_RECEIPT_SIGN, sign_cap_token
from nth_dao.execution_receipt import TimelineEntry, sign_receipt
from nth_dao.identity import AgentIdentity
from nth_dao.market import (
    ClaimStore,
    MarketFeed,
    sign_announcement,
    sign_claim_receipt,
)
from nth_dao.market.announcement import announcement_federation_key
from nth_dao.market.claim_ack import sign_authority_claim_ack
from nth_dao.market.claim_intent import (
    admit_claim_intent,
    sign_claim_intent,
)
from nth_dao.market.mission_completion import (
    MissionCompletionRejected,
    receipt_digest,
    sign_mission_completion,
    verify_mission_completion,
)

NOW_MS = int(time.time() * 1000)


def _selfissue(agent, caps):
    return sign_cap_token(
        issuer=agent,
        subject_did=agent.as_did(),
        capabilities=[*caps, CAP_NTH_RECEIPT_SIGN],
    )


@pytest.fixture()
def claimed_task(tmp_path, monkeypatch):
    """A claimed announcement: agent claims via the intent path, returns
    everything needed to complete it."""

    feed = MarketFeed(tmp_path / "feed")
    store = ClaimStore(tmp_path / "claims")
    pub = AgentIdentity.generate(label="pub")
    agent = AgentIdentity.generate(label="agent")
    ann = sign_announcement(
        publisher=pub,
        title="task",
        capability_set=["code_review"],
        reward_minor=5,
    )
    feed.publish(ann)
    token = _selfissue(agent, ["code_review"])
    # the cap_token is signed at the REAL wall clock; admitting at a
    # collection-time constant (NOW_MS) lands before the token's
    # not-before and fails — admit at the real clock instead
    now = int(time.time() * 1000)
    monkeypatch.setitem(globals(), "NOW_MS", now)
    intent = sign_claim_intent(
        agent,
        announcement_id=ann.announcement_id,
        cap_token=token,
        created_at_ms=now,
    )
    claim_receipt = sign_claim_receipt(ann, agent, token)
    claim_outcome = admit_claim_intent(
        feed,
        store,
        intent,
        claim_receipt,
        cap_token=token,
        now_ms_override=now + 1_000,
    )
    authority_ack = sign_authority_claim_ack(
        authority=pub,
        announcement=ann,
        claim_record=claim_outcome.claim_record,
    )
    return agent, ann, claim_receipt, authority_ack


def _exec_receipt(agent, mission_id="mission-1", outcome="succeeded"):
    from nth_dao.execution_receipt import TimelineEntry

    return sign_receipt(
        [
            TimelineEntry(
                timestamp=NOW_MS + 2_000,
                type=(
                    "nth.task_completed"
                    if outcome == "succeeded"
                    else "nth.task_failed"
                ),
                payload={"mission_id": mission_id, "result": outcome},
            )
        ],
        agent,
        goal_id=f"mission:{mission_id}",
    )


def _verify_with_evidence(
    record,
    ann,
    claim_receipt,
    authority_ack,
    execution_receipt,
    **kwargs,
):
    return verify_mission_completion(
        record,
        claim_receipt=claim_receipt,
        authority_ack=authority_ack,
        execution_receipt=execution_receipt,
        expected_authority_did=ann.effective_authority_did(),
        expected_federation_key=announcement_federation_key(ann),
        **kwargs,
    )


class TestSignAndVerify:
    def test_merge_signer_rejects_unhashable_predecessors(self, claimed_task):
        agent, ann, claim_receipt, authority_ack = claimed_task
        with pytest.raises(MissionCompletionRejected, match="revision link"):
            sign_mission_completion(
                agent, announcement_id=ann.announcement_id,
                mission_id="mission-1", claim_receipt=claim_receipt,
                authority_ack=authority_ack,
                execution_receipt=_exec_receipt(agent),
                completed_at_ms=NOW_MS + 3_000, revision=1,
                supersedes_digests=[{"not": "a digest"}, "sha256:" + "0" * 64],
            )

    def test_statement_only_verification_must_be_explicit(self, claimed_task):
        agent, ann, claim_receipt, authority_ack = claimed_task
        exec_receipt = _exec_receipt(agent)
        record = sign_mission_completion(
            agent,
            announcement_id=ann.announcement_id,
            mission_id="mission-1",
            claim_receipt=claim_receipt,
            authority_ack=authority_ack,
            execution_receipt=exec_receipt,
            completed_at_ms=NOW_MS + 3_000,
        )
        assert verify_mission_completion(record, now_ms=NOW_MS + 4_000) == (
            False,
            "completion evidence is required",
        )
        assert verify_mission_completion(
            record,
            now_ms=NOW_MS + 4_000,
            require_evidence=False,
        ) == (True, "ok")

    def test_verifier_accepts_full_announcement_id_contract(self, claimed_task):
        agent, ann, claim_receipt, authority_ack = claimed_task
        record = sign_mission_completion(
            agent,
            announcement_id=ann.announcement_id,
            mission_id="mission-1",
            claim_receipt=claim_receipt,
            authority_ack=authority_ack,
            execution_receipt=_exec_receipt(agent),
            completed_at_ms=NOW_MS + 3_000,
        )
        record = deepcopy(record)
        record["announcement_id"] = "dao:" + "a" * 252
        body = canonical_json(
            {key: value for key, value in record.items() if key != "signature"}
        )
        record["signature"] = b64u_encode(agent.sign(body))

        assert len(record["announcement_id"]) == 256
        assert verify_mission_completion(
            record, now_ms=NOW_MS + 4_000, require_evidence=False
        ) == (True, "ok")

    def test_roundtrip_with_receipts_verification_grade(self, claimed_task):
        agent, ann, claim_receipt, authority_ack = claimed_task
        exec_receipt = _exec_receipt(agent)
        record = sign_mission_completion(
            agent,
            announcement_id=ann.announcement_id,
            mission_id="mission-1",
            claim_receipt=claim_receipt,
            authority_ack=authority_ack,
            execution_receipt=exec_receipt,
            completed_at_ms=NOW_MS + 3_000,
        )
        ok, reason = _verify_with_evidence(
            record,
            ann,
            claim_receipt,
            authority_ack,
            exec_receipt,
            now_ms=NOW_MS + 4_000,
        )
        assert ok, reason

    def test_tampered_outcome_breaks_signature(self, claimed_task):
        agent, ann, claim_receipt, authority_ack = claimed_task
        exec_receipt = _exec_receipt(agent, outcome="failed")
        record = sign_mission_completion(
            agent,
            announcement_id=ann.announcement_id,
            mission_id="mission-1",
            claim_receipt=claim_receipt,
            authority_ack=authority_ack,
            execution_receipt=exec_receipt,
            outcome="failed",
            completed_at_ms=NOW_MS + 3_000,
        )
        record["outcome"] = "succeeded"
        ok, reason = verify_mission_completion(record, now_ms=NOW_MS + 4_000)
        assert not ok and "signature" in reason

    def test_claimant_mismatch_rejected_at_sign(self, claimed_task):
        """A completion record cannot cite an execution receipt signed by
        someone else — the chain must run through the claimant."""

        agent, ann, claim_receipt, authority_ack = claimed_task
        other = AgentIdentity.generate(label="other")
        other_exec = _exec_receipt(other)
        with pytest.raises(
            MissionCompletionRejected, match="does not match the claimant"
        ):
            sign_mission_completion(
                agent,
                announcement_id=ann.announcement_id,
                mission_id="mission-1",
                claim_receipt=claim_receipt,
                authority_ack=authority_ack,
                execution_receipt=other_exec,
            )

    def test_wrong_claim_receipt_rejected_at_verify(self, claimed_task):
        agent, ann, claim_receipt, authority_ack = claimed_task
        exec_receipt = _exec_receipt(agent)
        record = sign_mission_completion(
            agent,
            announcement_id=ann.announcement_id,
            mission_id="mission-1",
            claim_receipt=claim_receipt,
            authority_ack=authority_ack,
            execution_receipt=exec_receipt,
            completed_at_ms=NOW_MS + 3_000,
        )
        other_claim = sign_claim_receipt(
            ann,
            agent,
            _selfissue(agent, ["code_review"]),
        )
        ok, reason = _verify_with_evidence(
            record,
            ann,
            other_claim,
            authority_ack,
            exec_receipt,
            now_ms=NOW_MS + 4_000,
        )
        assert not ok and "claim receipt digest" in reason

    def test_failed_outcome_is_recordable(self, claimed_task):
        """Honest failures are recorded, not hidden — the market sees them."""

        agent, ann, claim_receipt, authority_ack = claimed_task
        exec_receipt = _exec_receipt(agent, outcome="failed")
        record = sign_mission_completion(
            agent,
            announcement_id=ann.announcement_id,
            mission_id="mission-1",
            claim_receipt=claim_receipt,
            authority_ack=authority_ack,
            execution_receipt=exec_receipt,
            outcome="failed",
            completed_at_ms=NOW_MS + 3_000,
        )
        ok, _ = _verify_with_evidence(
            record,
            ann,
            claim_receipt,
            authority_ack,
            exec_receipt,
            now_ms=NOW_MS + 4_000,
        )
        assert ok and record["outcome"] == "failed"

    def test_preclaim_execution_event_is_rejected_at_sign_and_verify(self, claimed_task):
        agent, ann, claim_receipt, authority_ack = claimed_task
        claim_at = claim_receipt["timeline"][0]["timestamp"]
        old_execution = sign_receipt(
            [TimelineEntry(
                timestamp=claim_at - 86_400_000,
                type="nth.task_completed",
                payload={"mission_id": "mission-1"},
            )],
            agent, goal_id="mission:mission-1",
        )
        with pytest.raises(MissionCompletionRejected, match="chronology"):
            sign_mission_completion(
                agent, announcement_id=ann.announcement_id,
                mission_id="mission-1", claim_receipt=claim_receipt,
                authority_ack=authority_ack, execution_receipt=old_execution,
                completed_at_ms=claim_at + 3_000,
            )

        current_execution = sign_receipt(
            [TimelineEntry(
                timestamp=claim_at + 2_000,
                type="nth.task_completed",
                payload={"mission_id": "mission-1"},
            )],
            agent, goal_id="mission:mission-1",
        )
        record = sign_mission_completion(
            agent, announcement_id=ann.announcement_id,
            mission_id="mission-1", claim_receipt=claim_receipt,
            authority_ack=authority_ack, execution_receipt=current_execution,
            completed_at_ms=claim_at + 3_000,
        )
        record["execution_receipt_digest"] = receipt_digest(old_execution)
        record["signature"] = b64u_encode(agent.sign(canonical_json({
            key: value for key, value in record.items() if key != "signature"
        })))
        ok, reason = _verify_with_evidence(
            record, ann, claim_receipt, authority_ack, old_execution,
            now_ms=claim_at + 4_000,
        )
        assert not ok and "chronology" in reason

    def test_boolean_revision_is_not_a_v1_root(self, claimed_task):
        agent, ann, claim_receipt, authority_ack = claimed_task
        with pytest.raises(MissionCompletionRejected, match="revision link"):
            sign_mission_completion(
                agent, announcement_id=ann.announcement_id,
                mission_id="mission-1", claim_receipt=claim_receipt,
                authority_ack=authority_ack, execution_receipt=_exec_receipt(agent),
                revision=False,
            )

    def test_unknown_field_rejected(self, claimed_task):
        agent, ann, claim_receipt, authority_ack = claimed_task
        exec_receipt = _exec_receipt(agent)
        record = sign_mission_completion(
            agent,
            announcement_id=ann.announcement_id,
            mission_id="mission-1",
            claim_receipt=claim_receipt,
            authority_ack=authority_ack,
            execution_receipt=exec_receipt,
            completed_at_ms=NOW_MS + 3_000,
        )
        record["sneaky"] = 1
        ok, reason = verify_mission_completion(record, now_ms=NOW_MS + 4_000)
        assert not ok and "missing or unknown" in reason

    def test_future_completion_rejected(self, claimed_task):
        agent, ann, claim_receipt, authority_ack = claimed_task
        exec_receipt = _exec_receipt(agent)
        record = sign_mission_completion(
            agent,
            announcement_id=ann.announcement_id,
            mission_id="mission-1",
            claim_receipt=claim_receipt,
            authority_ack=authority_ack,
            execution_receipt=exec_receipt,
            completed_at_ms=NOW_MS + 10 * 60 * 1000,
        )
        ok, reason = verify_mission_completion(record, now_ms=NOW_MS + 4_000)
        assert not ok and "future" in reason

    def test_unverified_receipt_objects_cannot_be_wrapped(self, claimed_task):
        agent, ann, _claim_receipt, authority_ack = claimed_task
        execution_receipt = _exec_receipt(agent)
        with pytest.raises(MissionCompletionRejected, match="claim receipt signature"):
            sign_mission_completion(
                agent,
                announcement_id=ann.announcement_id,
                mission_id="mission-1",
                claim_receipt={"signer_did": agent.as_did()},
                authority_ack=authority_ack,
                execution_receipt=execution_receipt,
            )

    def test_authority_ack_is_required_as_signed_cas_evidence(self, claimed_task):
        agent, ann, claim_receipt, authority_ack = claimed_task
        execution_receipt = _exec_receipt(agent)
        tampered_ack = dict(authority_ack)
        tampered_ack["announcement_id"] = "different-announcement"
        with pytest.raises(
            MissionCompletionRejected,
            match="authority claim acknowledgement is invalid",
        ):
            sign_mission_completion(
                agent,
                announcement_id=ann.announcement_id,
                mission_id="mission-1",
                claim_receipt=claim_receipt,
                authority_ack=tampered_ack,
                execution_receipt=execution_receipt,
            )

    @pytest.mark.parametrize(
        ("mission_id", "execution_outcome", "record_outcome"),
        [
            ("different-mission", "succeeded", "succeeded"),
            ("mission-1", "succeeded", "failed"),
        ],
    )
    def test_execution_receipt_binds_mission_and_outcome(
        self,
        claimed_task,
        mission_id,
        execution_outcome,
        record_outcome,
    ):
        agent, ann, claim_receipt, authority_ack = claimed_task
        execution_receipt = _exec_receipt(
            agent, mission_id=mission_id, outcome=execution_outcome
        )
        with pytest.raises(MissionCompletionRejected, match="execution receipt"):
            sign_mission_completion(
                agent,
                announcement_id=ann.announcement_id,
                mission_id="mission-1",
                claim_receipt=claim_receipt,
                authority_ack=authority_ack,
                execution_receipt=execution_receipt,
                outcome=record_outcome,
            )

    def test_partial_verification_evidence_is_rejected(self, claimed_task):
        agent, ann, claim_receipt, authority_ack = claimed_task
        execution_receipt = _exec_receipt(agent)
        record = sign_mission_completion(
            agent,
            announcement_id=ann.announcement_id,
            mission_id="mission-1",
            claim_receipt=claim_receipt,
            authority_ack=authority_ack,
            execution_receipt=execution_receipt,
            completed_at_ms=NOW_MS + 3_000,
        )
        ok, reason = verify_mission_completion(
            record,
            claim_receipt=claim_receipt,
            now_ms=NOW_MS + 4_000,
        )
        assert not ok and "all three evidence" in reason

    def test_verification_grade_checks_expected_authority(self, claimed_task):
        agent, ann, claim_receipt, authority_ack = claimed_task
        execution_receipt = _exec_receipt(agent)
        record = sign_mission_completion(
            agent,
            announcement_id=ann.announcement_id,
            mission_id="mission-1",
            claim_receipt=claim_receipt,
            authority_ack=authority_ack,
            execution_receipt=execution_receipt,
            completed_at_ms=NOW_MS + 3_000,
        )
        wrong_authority = AgentIdentity.generate(label="wrong-authority")
        ok, reason = verify_mission_completion(
            record,
            claim_receipt=claim_receipt,
            authority_ack=authority_ack,
            execution_receipt=execution_receipt,
            expected_authority_did=wrong_authority.as_did(),
            expected_federation_key=announcement_federation_key(ann),
            now_ms=NOW_MS + 4_000,
        )
        assert not ok and "authority does not match" in reason

    def test_verification_grade_requires_trusted_announcement_context(
        self, claimed_task
    ):
        agent, ann, claim_receipt, authority_ack = claimed_task
        execution_receipt = _exec_receipt(agent)
        record = sign_mission_completion(
            agent,
            announcement_id=ann.announcement_id,
            mission_id="mission-1",
            claim_receipt=claim_receipt,
            authority_ack=authority_ack,
            execution_receipt=execution_receipt,
            completed_at_ms=NOW_MS + 3_000,
        )

        ok, reason = verify_mission_completion(
            record,
            claim_receipt=claim_receipt,
            authority_ack=authority_ack,
            execution_receipt=execution_receipt,
            now_ms=NOW_MS + 4_000,
        )

        assert not ok
        assert reason == "trusted announcement authority context is required"

    def test_signed_history_does_not_expire_by_default(self, claimed_task):
        agent, ann, claim_receipt, authority_ack = claimed_task
        execution_receipt = _exec_receipt(agent)
        record = sign_mission_completion(
            agent,
            announcement_id=ann.announcement_id,
            mission_id="mission-1",
            claim_receipt=claim_receipt,
            authority_ack=authority_ack,
            execution_receipt=execution_receipt,
            completed_at_ms=NOW_MS + 3_000,
        )
        much_later = NOW_MS + 2 * 365 * 24 * 3600 * 1000
        assert _verify_with_evidence(
            record,
            ann,
            claim_receipt,
            authority_ack,
            execution_receipt,
            now_ms=much_later,
        ) == (True, "ok")
        ok, reason = _verify_with_evidence(
            record,
            ann,
            claim_receipt,
            authority_ack,
            execution_receipt,
            now_ms=much_later,
            max_age_ms=24 * 3600 * 1000,
        )
        assert not ok and "older" in reason

    def test_malformed_root_and_bool_version_fail_without_exception(self, claimed_task):
        assert verify_mission_completion([], now_ms=NOW_MS) == (
            False,
            "completion record must be an object",
        )
        agent, ann, claim_receipt, authority_ack = claimed_task
        record = sign_mission_completion(
            agent,
            announcement_id=ann.announcement_id,
            mission_id="mission-1",
            claim_receipt=claim_receipt,
            authority_ack=authority_ack,
            execution_receipt=_exec_receipt(agent),
            completed_at_ms=NOW_MS + 3_000,
        )
        record["version"] = True
        ok, reason = verify_mission_completion(record, now_ms=NOW_MS + 4_000)
        assert not ok and reason == "wrong kind or version"
