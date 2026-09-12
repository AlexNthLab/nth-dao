"""Claim intent lifecycle tests (design doc §7.1).

Offline intent ≠ authority: an intent reserves nothing, expires on its own
clock, and the UI must distinguish pending from confirmed. The authority
side (admit_claim_intent) cross-binds the intent to the pre-signed receipt
and delegates to the borrowed CAS.
"""

from __future__ import annotations

import time

import pytest

pytest.importorskip("nacl")

from nth_dao.cap_token import CAP_NTH_RECEIPT_SIGN, sign_cap_token
from nth_dao.identity import AgentIdentity
from nth_dao.market import (
    ClaimConflict,
    ClaimStore,
    MarketFeed,
    sign_announcement,
    sign_claim_receipt,
)
from nth_dao.market.claim_intent import (
    DEFAULT_INTENT_TTL_MS,
    MAX_INTENT_TTL_MS,
    REJECT_INTENT_BINDING,
    REJECT_INTENT_EXPIRED,
    REJECT_INTENT_FUTURE,
    REJECT_INTENT_MALFORMED,
    REJECT_INTENT_SIGNATURE,
    ClaimIntentRejected,
    IntentTracker,
    admit_claim_intent,
    sign_claim_intent,
    verify_claim_intent,
)

NOW_MS = int(time.time() * 1000)


def _selfissue(agent, caps):
    return sign_cap_token(
        issuer=agent, subject_did=agent.as_did(),
        capabilities=[*caps, CAP_NTH_RECEIPT_SIGN],
    )


def _setup(tmp_path, caps=("code_review",)):
    feed = MarketFeed(tmp_path)
    store = ClaimStore(tmp_path)
    pub = AgentIdentity.generate(label="pub")
    agent = AgentIdentity.generate(label="agent")
    ann = sign_announcement(
        publisher=pub, title="task", capability_set=list(caps), reward_minor=5,
    )
    feed.publish(ann)
    return feed, store, pub, agent, ann


class TestSignAndVerify:
    def test_roundtrip(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        intent = sign_claim_intent(
            agent,
            announcement_id=ann.announcement_id,
            cap_token=token,
            created_at_ms=NOW_MS,
        )
        ok, reason = verify_claim_intent(intent, now_ms=NOW_MS + 1_000)
        assert ok, reason

    def test_tampered_field_breaks_signature(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        intent = sign_claim_intent(
            agent, announcement_id=ann.announcement_id, cap_token=token,
            created_at_ms=NOW_MS,
        )
        intent["announcement_id"] = "other-task"
        ok, reason = verify_claim_intent(intent, now_ms=NOW_MS)
        assert not ok and reason == REJECT_INTENT_SIGNATURE

    def test_expired_intent(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        intent = sign_claim_intent(
            agent, announcement_id=ann.announcement_id, cap_token=token,
            created_at_ms=NOW_MS, ttl_ms=1_000,
        )
        ok, reason = verify_claim_intent(intent, now_ms=NOW_MS + 2_000)
        assert not ok and reason == REJECT_INTENT_EXPIRED

    def test_future_creation_rejected(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        intent = sign_claim_intent(
            agent, announcement_id=ann.announcement_id, cap_token=token,
            created_at_ms=NOW_MS + 10 * 60 * 1000,  # 10 min future
        )
        ok, reason = verify_claim_intent(intent, now_ms=NOW_MS)
        assert not ok and reason == REJECT_INTENT_FUTURE

    def test_wrong_claimant_did_rejected(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        intent = sign_claim_intent(
            agent, announcement_id=ann.announcement_id, cap_token=token,
            created_at_ms=NOW_MS,
        )
        mallory = AgentIdentity.generate(label="mallory")
        intent["claimant_did"] = mallory.as_did()
        ok, reason = verify_claim_intent(intent, now_ms=NOW_MS)
        assert not ok and reason == REJECT_INTENT_SIGNATURE

    def test_field_set_tamper(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        intent = sign_claim_intent(
            agent, announcement_id=ann.announcement_id, cap_token=token,
            created_at_ms=NOW_MS,
        )
        hostile = dict(intent)
        hostile["extra"] = True
        ok, reason = verify_claim_intent(hostile, now_ms=NOW_MS)
        assert not ok and reason == REJECT_INTENT_MALFORMED

    def test_cap_token_subject_mismatch_early_fail(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        other = AgentIdentity.generate(label="other")
        token = _selfissue(other, ["code_review"])  # subject is `other`
        with pytest.raises(ClaimIntentRejected, match="subject"):
            sign_claim_intent(
                agent, announcement_id=ann.announcement_id, cap_token=token,
            )

    def test_ttl_bounds_enforced(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        with pytest.raises(ClaimIntentRejected):
            sign_claim_intent(
                agent, announcement_id=ann.announcement_id, cap_token=token,
                ttl_ms=MAX_INTENT_TTL_MS + 1,
            )


class TestAdmit:
    def test_happy_path_delegates_to_cas(self, tmp_path):
        feed, store, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        intent = sign_claim_intent(
            agent, announcement_id=ann.announcement_id, cap_token=token,
            created_at_ms=NOW_MS,
        )
        receipt = sign_claim_receipt(ann, agent, token)
        out = admit_claim_intent(
            feed, store, intent, receipt, cap_token=token,
            now_ms_override=int(time.time() * 1000),
        )
        assert out.claim_record["claimant_did"] == agent.as_did()
        assert store.is_claimed(ann.announcement_id)

    def test_cross_binding_wrong_announcement(self, tmp_path):
        feed, store, _, agent, ann = _setup(tmp_path)
        # a second announcement on the same feed
        pub2 = AgentIdentity.generate(label="pub2")
        ann2 = sign_announcement(
            publisher=pub2, title="other", capability_set=["code_review"],
            reward_minor=1,
        )
        feed.publish(ann2)
        token = _selfissue(agent, ["code_review"])
        intent = sign_claim_intent(
            agent, announcement_id=ann.announcement_id, cap_token=token,
            created_at_ms=NOW_MS,
        )
        # receipt binds ann2 while the intent binds ann
        receipt = sign_claim_receipt(ann2, agent, token)
        with pytest.raises(ClaimIntentRejected, match=REJECT_INTENT_BINDING):
            admit_claim_intent(
                feed, store, intent, receipt, cap_token=token,
                now_ms_override=int(time.time() * 1000),
            )

    def test_cross_binding_wrong_claimant(self, tmp_path):
        feed, store, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        intent = sign_claim_intent(
            agent, announcement_id=ann.announcement_id, cap_token=token,
            created_at_ms=NOW_MS,
        )
        # receipt signed by a different agent
        mallory = AgentIdentity.generate(label="mallory")
        mallory_token = _selfissue(mallory, ["code_review"])
        receipt = sign_claim_receipt(ann, mallory, mallory_token)
        with pytest.raises(ClaimIntentRejected, match=REJECT_INTENT_BINDING):
            admit_claim_intent(
                feed, store, intent, receipt, cap_token=token,
                now_ms_override=int(time.time() * 1000),
            )

    def test_expired_intent_never_reaches_cas(self, tmp_path):
        feed, store, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        intent = sign_claim_intent(
            agent, announcement_id=ann.announcement_id, cap_token=token,
            created_at_ms=NOW_MS, ttl_ms=1_000,
        )
        receipt = sign_claim_receipt(ann, agent, token)
        with pytest.raises(ClaimIntentRejected, match=REJECT_INTENT_EXPIRED):
            admit_claim_intent(
                feed, store, intent, receipt, cap_token=token,
                now_ms_override=NOW_MS + 2_000,
            )
        assert not store.is_claimed(ann.announcement_id)  # CAS untouched

    def test_two_intents_one_winner(self, tmp_path):
        """Two offline intents race at the authority: CAS picks exactly one
        winner; the loser sees ClaimConflict — the design doc's mandate that
        intents never reserve anything."""

        feed, store, _, agentA, ann = _setup(tmp_path)
        agentB = AgentIdentity.generate(label="B")
        tokenA = _selfissue(agentA, ["code_review"])
        tokenB = _selfissue(agentB, ["code_review"])
        intentA = sign_claim_intent(
            agentA, announcement_id=ann.announcement_id, cap_token=tokenA,
            created_at_ms=NOW_MS,
        )
        intentB = sign_claim_intent(
            agentB, announcement_id=ann.announcement_id, cap_token=tokenB,
            created_at_ms=NOW_MS,
        )
        receiptA = sign_claim_receipt(ann, agentA, tokenA)
        receiptB = sign_claim_receipt(ann, agentB, tokenB)
        admit_claim_intent(
            feed, store, intentA, receiptA, cap_token=tokenA,
            now_ms_override=int(time.time() * 1000),
        )
        with pytest.raises(ClaimConflict):
            admit_claim_intent(
                feed, store, intentB, receiptB, cap_token=tokenB,
                now_ms_override=int(time.time() * 1000),
            )
        assert store.is_claimed(ann.announcement_id)


class TestIntentTracker:
    def _intent(self, agent, announcement_id, token, nonce=None, ttl=DEFAULT_INTENT_TTL_MS, created_at_ms=None):
        return sign_claim_intent(
            agent, announcement_id=announcement_id, cap_token=token,
            created_at_ms=created_at_ms if created_at_ms is not None else NOW_MS,
            ttl_ms=ttl, nonce=nonce,
        )

    def test_pending_then_confirmed(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        intent = self._intent(agent, ann.announcement_id, token, nonce="a" * 16)
        tracker = IntentTracker(tmp_path / "tracker")
        tracker.record_sent(intent)
        assert len(tracker.pending(now_ms=NOW_MS + 1)) == 1
        tracker.mark(intent, "confirmed")
        assert tracker.pending(now_ms=NOW_MS + 1) == []
        assert tracker.stats()["confirmed"] == 1

    def test_sweep_expired(self, tmp_path):
        """Uses the real clock: record_sent self-verifies against the wall
        clock, so a module-constant NOW_MS would be stale by the time the
        full suite reaches this file (round-25 flake fix)."""

        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        now = int(time.time() * 1000)
        intent = self._intent(
            agent, ann.announcement_id, token, nonce="b" * 16, ttl=1_000,
            created_at_ms=now,
        )
        tracker = IntentTracker(tmp_path / "tracker")
        tracker.record_sent(intent)
        assert tracker.sweep_expired(now_ms=now + 2_000) == 1
        assert tracker.stats()["expired"] == 1

    def test_restart_preserves_state(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        intent = self._intent(agent, ann.announcement_id, token, nonce="c" * 16)
        tracker = IntentTracker(tmp_path / "tracker")
        tracker.record_sent(intent)
        tracker.mark(intent, "rejected")
        reloaded = IntentTracker(tmp_path / "tracker")
        assert reloaded.stats()["rejected"] == 1

    def test_idempotent_resend(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        intent = self._intent(agent, ann.announcement_id, token, nonce="d" * 16)
        tracker = IntentTracker(tmp_path / "tracker")
        tracker.record_sent(intent)
        tracker.record_sent(intent)  # no double count
        assert len(tracker.pending(now_ms=NOW_MS + 1)) == 1

    def test_invalid_intent_refused(self, tmp_path):
        tracker = IntentTracker(tmp_path / "tracker")
        with pytest.raises(ClaimIntentRejected):
            tracker.record_sent({"kind": "garbage"})

    def test_torn_tail_tolerated(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        intent = self._intent(agent, ann.announcement_id, token, nonce="e" * 16)
        tracker = IntentTracker(tmp_path / "tracker")
        tracker.record_sent(intent)
        journal = tmp_path / "tracker" / "claim-intents.jsonl"
        with open(journal, "ab") as handle:
            handle.write(b'{"event":"sen')
        reloaded = IntentTracker(tmp_path / "tracker")
        assert reloaded.stats()["pending"] == 1

    def test_corruption_fails_closed(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        intent = self._intent(agent, ann.announcement_id, token, nonce="f" * 16)
        tracker = IntentTracker(tmp_path / "tracker")
        tracker.record_sent(intent)
        journal = tmp_path / "tracker" / "claim-intents.jsonl"
        lines = journal.read_bytes().split(b"\n")
        lines[0] = b"{busted"
        journal.write_bytes(b"\n".join(lines))
        with pytest.raises(RuntimeError, match="corrupt"):
            IntentTracker(tmp_path / "tracker")


class TestOfflineStory:
    def test_full_offline_flow(self, tmp_path):
        """The design doc §7.1 story: sign intent+receipt offline → carry →
        authority admits → claimant's tracker flips to confirmed."""

        feed, store, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        # offline: sign both, track as pending
        now = int(time.time() * 1000)  # real clock: tracker self-verifies
        intent = sign_claim_intent(
            agent, announcement_id=ann.announcement_id, cap_token=token,
            created_at_ms=now,
        )
        receipt = sign_claim_receipt(ann, agent, token)
        tracker = IntentTracker(tmp_path / "tracker")
        tracker.record_sent(intent)
        assert len(tracker.pending(now_ms=now + 1)) == 1  # UI: pending

        # later, at the authority (any transport carried the pair)
        out = admit_claim_intent(
            feed, store, intent, receipt, cap_token=token,
            now_ms_override=now + 60_000,
        )
        assert out.claim_record["claimant_did"] == agent.as_did()

        # the response comes back; the tracker flips pending → confirmed
        tracker.mark(intent, "confirmed")
        assert tracker.pending(now_ms=now + 61_000) == []
        assert tracker.stats()["confirmed"] == 1  # UI: confirmed


# ─────────────────── adversarial review round 24 (LL-2) ───────────────────


class TestCapTokenBinding:
    def test_intent_citing_different_token_rejected(self, tmp_path):
        """Bug LL-2: an intent self-describing token X cannot be admitted
        with token Y — the audit trail would diverge from the claim."""

        feed, store, _, agent, ann = _setup(tmp_path)
        cited_token = _selfissue(agent, ["code_review"])
        other_token = _selfissue(agent, ["code_review"])  # different token_id
        assert cited_token["token_id"] != other_token["token_id"]
        intent = sign_claim_intent(
            agent, announcement_id=ann.announcement_id, cap_token=cited_token,
            created_at_ms=NOW_MS,
        )
        receipt = sign_claim_receipt(ann, agent, other_token)
        with pytest.raises(ClaimIntentRejected, match="different cap_token"):
            admit_claim_intent(
                feed, store, intent, receipt, cap_token=other_token,
                now_ms_override=int(time.time() * 1000),
            )
        assert not store.is_claimed(ann.announcement_id)

    def test_matching_token_still_admitted(self, tmp_path):
        feed, store, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        intent = sign_claim_intent(
            agent, announcement_id=ann.announcement_id, cap_token=token,
            created_at_ms=NOW_MS,
        )
        receipt = sign_claim_receipt(ann, agent, token)
        out = admit_claim_intent(
            feed, store, intent, receipt, cap_token=token,
            now_ms_override=int(time.time() * 1000),
        )
        assert out.claim_record["claimant_did"] == agent.as_did()
