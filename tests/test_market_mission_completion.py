"""Tests for mission completion records — binding claim + execution chains."""

from __future__ import annotations

import time

import pytest

pytest.importorskip("nacl")

from nth_dao.cap_token import CAP_NTH_RECEIPT_SIGN, sign_cap_token  # noqa: E402
from nth_dao.execution_receipt import sign_receipt  # noqa: E402
from nth_dao.identity import AgentIdentity  # noqa: E402
from nth_dao.market import (  # noqa: E402
    ClaimStore,
    MarketFeed,
    sign_announcement,
    sign_claim_receipt,
)
from nth_dao.market.claim_intent import (
    admit_claim_intent,  # noqa: E402
    sign_claim_intent,  # noqa: E402
)
from nth_dao.market.mission_completion import (  # noqa: E402
    MissionCompletionRejected,
    sign_mission_completion,
    verify_mission_completion,
)

NOW_MS = int(time.time() * 1000)


def _selfissue(agent, caps):
    return sign_cap_token(
        issuer=agent, subject_did=agent.as_did(),
        capabilities=[*caps, CAP_NTH_RECEIPT_SIGN],
    )


@pytest.fixture()
def claimed_task(tmp_path):
    """A claimed announcement: agent claims via the intent path, returns
    everything needed to complete it."""

    feed = MarketFeed(tmp_path / "feed")
    store = ClaimStore(tmp_path / "claims")
    pub = AgentIdentity.generate(label="pub")
    agent = AgentIdentity.generate(label="agent")
    ann = sign_announcement(
        publisher=pub, title="task", capability_set=["code_review"],
        reward_minor=5,
    )
    feed.publish(ann)
    token = _selfissue(agent, ["code_review"])
    intent = sign_claim_intent(
        agent, announcement_id=ann.announcement_id, cap_token=token,
        created_at_ms=NOW_MS,
    )
    claim_receipt = sign_claim_receipt(ann, agent, token)
    admit_claim_intent(
        feed, store, intent, claim_receipt, cap_token=token,
        now_ms_override=NOW_MS + 1_000,
    )
    return agent, ann, claim_receipt


def _exec_receipt(agent, mission_id="mission-1"):
    from nth_dao.execution_receipt import TimelineEntry

    return sign_receipt(
        [
            TimelineEntry(
                timestamp=NOW_MS + 2_000,
                type="nth.task_completed",
                payload={"mission_id": mission_id, "result": "ok"},
            )
        ],
        agent,
        goal_id=f"mission:{mission_id}",
    )


class TestSignAndVerify:
    def test_roundtrip_without_receipts(self, claimed_task):
        agent, ann, claim_receipt = claimed_task
        exec_receipt = _exec_receipt(agent)
        record = sign_mission_completion(
            agent,
            announcement_id=ann.announcement_id,
            mission_id="mission-1",
            claim_receipt=claim_receipt,
            execution_receipt=exec_receipt,
            completed_at_ms=NOW_MS + 3_000,
        )
        ok, reason = verify_mission_completion(record, now_ms=NOW_MS + 4_000)
        assert ok, reason

    def test_roundtrip_with_receipts_verification_grade(self, claimed_task):
        agent, ann, claim_receipt = claimed_task
        exec_receipt = _exec_receipt(agent)
        record = sign_mission_completion(
            agent,
            announcement_id=ann.announcement_id,
            mission_id="mission-1",
            claim_receipt=claim_receipt,
            execution_receipt=exec_receipt,
            completed_at_ms=NOW_MS + 3_000,
        )
        ok, reason = verify_mission_completion(
            record,
            claim_receipt=claim_receipt,
            execution_receipt=exec_receipt,
            now_ms=NOW_MS + 4_000,
        )
        assert ok, reason

    def test_tampered_outcome_breaks_signature(self, claimed_task):
        agent, ann, claim_receipt = claimed_task
        exec_receipt = _exec_receipt(agent)
        record = sign_mission_completion(
            agent,
            announcement_id=ann.announcement_id,
            mission_id="mission-1",
            claim_receipt=claim_receipt,
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

        agent, ann, claim_receipt = claimed_task
        other = AgentIdentity.generate(label="other")
        other_exec = _exec_receipt(other)
        with pytest.raises(MissionCompletionRejected, match="does not match the claimant"):
            sign_mission_completion(
                agent,
                announcement_id=ann.announcement_id,
                mission_id="mission-1",
                claim_receipt=claim_receipt,
                execution_receipt=other_exec,
            )

    def test_wrong_claim_receipt_rejected_at_verify(self, claimed_task):
        agent, ann, claim_receipt = claimed_task
        exec_receipt = _exec_receipt(agent)
        record = sign_mission_completion(
            agent,
            announcement_id=ann.announcement_id,
            mission_id="mission-1",
            claim_receipt=claim_receipt,
            execution_receipt=exec_receipt,
            completed_at_ms=NOW_MS + 3_000,
        )
        other_claim = sign_claim_receipt(
            ann, agent, _selfissue(agent, ["code_review"]),
        )
        ok, reason = verify_mission_completion(
            record, claim_receipt=other_claim, now_ms=NOW_MS + 4_000,
        )
        assert not ok and "claim receipt digest" in reason

    def test_failed_outcome_is_recordable(self, claimed_task):
        """Honest failures are recorded, not hidden — the market sees them."""

        agent, ann, claim_receipt = claimed_task
        exec_receipt = _exec_receipt(agent)
        record = sign_mission_completion(
            agent,
            announcement_id=ann.announcement_id,
            mission_id="mission-1",
            claim_receipt=claim_receipt,
            execution_receipt=exec_receipt,
            outcome="failed",
            completed_at_ms=NOW_MS + 3_000,
        )
        ok, _ = verify_mission_completion(record, now_ms=NOW_MS + 4_000)
        assert ok and record["outcome"] == "failed"

    def test_unknown_field_rejected(self, claimed_task):
        agent, ann, claim_receipt = claimed_task
        exec_receipt = _exec_receipt(agent)
        record = sign_mission_completion(
            agent,
            announcement_id=ann.announcement_id,
            mission_id="mission-1",
            claim_receipt=claim_receipt,
            execution_receipt=exec_receipt,
            completed_at_ms=NOW_MS + 3_000,
        )
        record["sneaky"] = 1
        ok, reason = verify_mission_completion(record, now_ms=NOW_MS + 4_000)
        assert not ok and "missing or unknown" in reason

    def test_future_completion_rejected(self, claimed_task):
        agent, ann, claim_receipt = claimed_task
        exec_receipt = _exec_receipt(agent)
        record = sign_mission_completion(
            agent,
            announcement_id=ann.announcement_id,
            mission_id="mission-1",
            claim_receipt=claim_receipt,
            execution_receipt=exec_receipt,
            completed_at_ms=NOW_MS + 10 * 60 * 1000,
        )
        ok, reason = verify_mission_completion(record, now_ms=NOW_MS + 4_000)
        assert not ok and "future" in reason
