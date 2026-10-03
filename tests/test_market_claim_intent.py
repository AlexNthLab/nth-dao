"""Claim intent lifecycle tests (design doc §7.1).

Offline intent ≠ authority: an intent reserves nothing, expires on its own
clock, and the UI must distinguish pending from confirmed. The authority
side (admit_claim_intent) cross-binds the intent to the pre-signed receipt
and delegates to the borrowed CAS.
"""

from __future__ import annotations

import hashlib
import json
import multiprocessing as mp
import os
import sqlite3
import time
from contextlib import closing
from pathlib import Path

import pytest

pytest.importorskip("nacl")

from nth_dao.b64u import b64u_encode
from nth_dao.canonical_json import canonical_json
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
    IntentTrackerCorrupt,
    IntentTrackerFull,
    admit_claim_intent,
    sign_claim_intent,
    verify_claim_intent,
)

NOW_MS = int(time.time() * 1000)


def _confirm_receipt_worker(directory, receipt_id, receipt_hash, start, results):
    try:
        from nth_dao.market.claim_intent import IntentTracker

        if not start.wait(timeout=10):
            raise TimeoutError("worker start signal timed out")
        nonce = IntentTracker(directory).confirm_by_receipt(receipt_id, receipt_hash)
        results.put(("confirmed", nonce))
    except Exception as exc:
        results.put(("error", repr(exc)))


def _reconcile_retry_worker(
    directory, retry_intent, receipt_id, receipt_hash, start, results,
):
    try:
        from nth_dao.market.claim_intent import ClaimIntentRejected, IntentTracker

        if not start.wait(timeout=10):
            raise TimeoutError("worker start signal timed out")
        try:
            result = IntentTracker(directory).reconcile_retry(
                retry_intent, receipt_id, receipt_hash,
            )
            results.put(("reconciled", result))
        except ClaimIntentRejected as exc:
            results.put(("terminal", str(exc)))
    except Exception as exc:
        results.put(("error", repr(exc)))


def _resign_intent(intent, signer):
    intent["signature"] = b64u_encode(
        signer.sign(
            canonical_json({k: v for k, v in intent.items() if k != "signature"})
        )
    )
    return intent


def _selfissue(agent, caps):
    return sign_cap_token(
        issuer=agent,
        subject_did=agent.as_did(),
        capabilities=[*caps, CAP_NTH_RECEIPT_SIGN],
    )


def _setup(tmp_path, caps=("code_review",)):
    feed = MarketFeed(tmp_path)
    store = ClaimStore(tmp_path)
    pub = AgentIdentity.generate(label="pub")
    agent = AgentIdentity.generate(label="agent")
    ann = sign_announcement(
        publisher=pub,
        title="task",
        capability_set=list(caps),
        reward_minor=5,
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

    def test_accepts_full_announcement_id_alphabet_and_length(self, tmp_path):
        _, _, _, agent, _ = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        announcement_id = "dao:" + "a" * 252
        intent = sign_claim_intent(
            agent,
            announcement_id=announcement_id,
            cap_token=token,
            created_at_ms=NOW_MS,
        )

        assert len(announcement_id) == 256
        assert verify_claim_intent(intent, now_ms=NOW_MS + 1_000) == (True, "ok")

    def test_tampered_field_breaks_signature(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        intent = sign_claim_intent(
            agent,
            announcement_id=ann.announcement_id,
            cap_token=token,
            created_at_ms=NOW_MS,
        )
        intent["announcement_id"] = "other-task"
        ok, reason = verify_claim_intent(intent, now_ms=NOW_MS)
        assert not ok and reason == REJECT_INTENT_SIGNATURE

    def test_expired_intent(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        intent = sign_claim_intent(
            agent,
            announcement_id=ann.announcement_id,
            cap_token=token,
            created_at_ms=NOW_MS,
            ttl_ms=1_000,
        )
        ok, reason = verify_claim_intent(intent, now_ms=NOW_MS + 2_000)
        assert not ok and reason == REJECT_INTENT_EXPIRED

    def test_future_creation_rejected(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        intent = sign_claim_intent(
            agent,
            announcement_id=ann.announcement_id,
            cap_token=token,
            created_at_ms=NOW_MS + 10 * 60 * 1000,  # 10 min future
        )
        ok, reason = verify_claim_intent(intent, now_ms=NOW_MS)
        assert not ok and reason == REJECT_INTENT_FUTURE

    def test_wrong_claimant_did_rejected(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        intent = sign_claim_intent(
            agent,
            announcement_id=ann.announcement_id,
            cap_token=token,
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
            agent,
            announcement_id=ann.announcement_id,
            cap_token=token,
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
                agent,
                announcement_id=ann.announcement_id,
                cap_token=token,
            )

    def test_ttl_bounds_enforced(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        with pytest.raises(ClaimIntentRejected):
            sign_claim_intent(
                agent,
                announcement_id=ann.announcement_id,
                cap_token=token,
                ttl_ms=MAX_INTENT_TTL_MS + 1,
            )

    def test_empty_cap_token_id_is_never_an_unbound_wildcard(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        invalid_token = dict(token)
        invalid_token["token_id"] = ""
        with pytest.raises(ClaimIntentRejected, match="token_id"):
            sign_claim_intent(
                agent, announcement_id=ann.announcement_id, cap_token=invalid_token
            )

        intent = sign_claim_intent(
            agent,
            announcement_id=ann.announcement_id,
            cap_token=token,
            created_at_ms=NOW_MS,
        )
        intent["cap_token_id"] = ""
        _resign_intent(intent, agent)
        assert verify_claim_intent(intent, now_ms=NOW_MS) == (
            False,
            REJECT_INTENT_MALFORMED,
        )

    def test_bool_version_and_clock_are_not_integers(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        intent = sign_claim_intent(
            agent,
            announcement_id=ann.announcement_id,
            cap_token=token,
            created_at_ms=NOW_MS,
        )
        intent["version"] = True
        _resign_intent(intent, agent)
        assert verify_claim_intent(intent, now_ms=NOW_MS)[0] is False
        assert verify_claim_intent(
            sign_claim_intent(
                agent,
                announcement_id=ann.announcement_id,
                cap_token=token,
                created_at_ms=NOW_MS,
            ),
            now_ms=True,
        ) == (False, REJECT_INTENT_MALFORMED)

    def test_noncanonical_signature_encoding_is_rejected(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        intent = sign_claim_intent(
            agent,
            announcement_id=ann.announcement_id,
            cap_token=token,
            created_at_ms=NOW_MS,
        )
        intent["signature"] += "="
        assert verify_claim_intent(intent, now_ms=NOW_MS) == (
            False,
            REJECT_INTENT_SIGNATURE,
        )

    def test_non_object_cap_token_has_protocol_error(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        with pytest.raises(ClaimIntentRejected, match="must be an object"):
            sign_claim_intent(
                agent,
                announcement_id=ann.announcement_id,
                cap_token=None,
            )


class TestAdmit:
    def test_happy_path_delegates_to_cas(self, tmp_path):
        feed, store, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        intent = sign_claim_intent(
            agent,
            announcement_id=ann.announcement_id,
            cap_token=token,
            created_at_ms=NOW_MS,
        )
        receipt = sign_claim_receipt(ann, agent, token)
        out = admit_claim_intent(
            feed,
            store,
            intent,
            receipt,
            cap_token=token,
            now_ms_override=int(time.time() * 1000),
        )
        assert out.claim_record["claimant_did"] == agent.as_did()
        assert store.is_claimed(ann.announcement_id)

    def test_cross_binding_wrong_announcement(self, tmp_path):
        feed, store, _, agent, ann = _setup(tmp_path)
        # a second announcement on the same feed
        pub2 = AgentIdentity.generate(label="pub2")
        ann2 = sign_announcement(
            publisher=pub2,
            title="other",
            capability_set=["code_review"],
            reward_minor=1,
        )
        feed.publish(ann2)
        token = _selfissue(agent, ["code_review"])
        intent = sign_claim_intent(
            agent,
            announcement_id=ann.announcement_id,
            cap_token=token,
            created_at_ms=NOW_MS,
        )
        # receipt binds ann2 while the intent binds ann
        receipt = sign_claim_receipt(ann2, agent, token)
        with pytest.raises(ClaimIntentRejected, match=REJECT_INTENT_BINDING):
            admit_claim_intent(
                feed,
                store,
                intent,
                receipt,
                cap_token=token,
                now_ms_override=int(time.time() * 1000),
            )

    def test_cross_binding_wrong_claimant(self, tmp_path):
        feed, store, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        intent = sign_claim_intent(
            agent,
            announcement_id=ann.announcement_id,
            cap_token=token,
            created_at_ms=NOW_MS,
        )
        # receipt signed by a different agent
        mallory = AgentIdentity.generate(label="mallory")
        mallory_token = _selfissue(mallory, ["code_review"])
        receipt = sign_claim_receipt(ann, mallory, mallory_token)
        with pytest.raises(ClaimIntentRejected, match=REJECT_INTENT_BINDING):
            admit_claim_intent(
                feed,
                store,
                intent,
                receipt,
                cap_token=token,
                now_ms_override=int(time.time() * 1000),
            )

    def test_expired_intent_never_reaches_cas(self, tmp_path):
        feed, store, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        intent = sign_claim_intent(
            agent,
            announcement_id=ann.announcement_id,
            cap_token=token,
            created_at_ms=NOW_MS,
            ttl_ms=1_000,
        )
        receipt = sign_claim_receipt(ann, agent, token)
        with pytest.raises(ClaimIntentRejected, match=REJECT_INTENT_EXPIRED):
            admit_claim_intent(
                feed,
                store,
                intent,
                receipt,
                cap_token=token,
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
            agentA,
            announcement_id=ann.announcement_id,
            cap_token=tokenA,
            created_at_ms=NOW_MS,
        )
        intentB = sign_claim_intent(
            agentB,
            announcement_id=ann.announcement_id,
            cap_token=tokenB,
            created_at_ms=NOW_MS,
        )
        receiptA = sign_claim_receipt(ann, agentA, tokenA)
        receiptB = sign_claim_receipt(ann, agentB, tokenB)
        admit_claim_intent(
            feed,
            store,
            intentA,
            receiptA,
            cap_token=tokenA,
            now_ms_override=int(time.time() * 1000),
        )
        with pytest.raises(ClaimConflict):
            admit_claim_intent(
                feed,
                store,
                intentB,
                receiptB,
                cap_token=tokenB,
                now_ms_override=int(time.time() * 1000),
            )
        assert store.is_claimed(ann.announcement_id)

    def test_invalid_authority_clock_fails_before_cas(self, tmp_path):
        feed, store, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        intent = sign_claim_intent(
            agent,
            announcement_id=ann.announcement_id,
            cap_token=token,
        )
        receipt = sign_claim_receipt(ann, agent, token)
        with pytest.raises(ClaimIntentRejected, match="authority clock"):
            admit_claim_intent(
                feed,
                store,
                intent,
                receipt,
                cap_token=token,
                now_ms_override=True,
            )
        assert not store.is_claimed(ann.announcement_id)


class TestIntentTracker:
    def _intent(
        self,
        agent,
        announcement_id,
        token,
        nonce=None,
        ttl=DEFAULT_INTENT_TTL_MS,
        created_at_ms=None,
    ):
        return sign_claim_intent(
            agent,
            announcement_id=announcement_id,
            cap_token=token,
            created_at_ms=created_at_ms if created_at_ms is not None else NOW_MS,
            ttl_ms=ttl,
            nonce=nonce,
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
            agent,
            ann.announcement_id,
            token,
            nonce="b" * 16,
            ttl=1_000,
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

    def test_tracker_detaches_input_and_pending_projection(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        intent = self._intent(agent, ann.announcement_id, token, nonce="x" * 16)
        original_announcement_id = intent["announcement_id"]
        tracker = IntentTracker(tmp_path / "tracker")
        tracker.record_sent(intent)

        intent["announcement_id"] = "caller-mutated"
        projected = tracker.pending(now_ms=NOW_MS + 1)
        assert projected[0]["announcement_id"] == original_announcement_id
        projected[0]["announcement_id"] = "reader-mutated"
        assert tracker.pending(now_ms=NOW_MS + 1)[0][
            "announcement_id"
        ] == original_announcement_id

    def test_terminal_replay_is_idempotent_but_conflict_is_rejected(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        intent = self._intent(agent, ann.announcement_id, token, nonce="m" * 16)
        tracker = IntentTracker(tmp_path / "tracker")
        tracker.record_sent(intent)
        tracker.mark(intent, "confirmed")
        tracker.mark(intent, "confirmed")

        with pytest.raises(ClaimIntentRejected, match="already terminal as confirmed"):
            tracker.mark(intent, "rejected")
        assert tracker.stats() == {"confirmed": 1}

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
        second = self._intent(agent, ann.announcement_id, token, nonce="l" * 16)
        reloaded.record_sent(second)

        restarted = IntentTracker(tmp_path / "tracker")
        assert restarted.pending(now_ms=NOW_MS + 1) == [intent, second]
        assert journal.read_bytes().endswith(b"\n")

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

    def test_stale_instances_refresh_before_read_and_write(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        intent = self._intent(agent, ann.announcement_id, token, nonce="g" * 16)
        directory = tmp_path / "tracker"
        first = IntentTracker(directory)
        stale = IntentTracker(directory)

        first.record_sent(intent)
        assert stale.pending(now_ms=NOW_MS + 1) == [intent]
        stale.mark(intent, "confirmed")
        assert first.stats() == {"confirmed": 1}

    def test_nonce_collision_cannot_rebind_existing_intent(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        first_token = _selfissue(agent, ["code_review"])
        second_token = _selfissue(agent, ["code_review"])
        first = self._intent(agent, ann.announcement_id, first_token, nonce="h" * 16)
        collision = self._intent(
            agent, ann.announcement_id, second_token, nonce="h" * 16
        )
        tracker = IntentTracker(tmp_path / "tracker")
        tracker.record_sent(first)

        with pytest.raises(ClaimIntentRejected, match="different intent"):
            tracker.record_sent(collision)
        assert tracker.pending(now_ms=NOW_MS + 1) == [first]

    def test_capacity_fails_closed_without_growing_journal(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        tracker = IntentTracker(tmp_path / "tracker", max_intents=1)
        tracker.record_sent(
            self._intent(agent, ann.announcement_id, token, nonce="i" * 16)
        )
        before = (tmp_path / "tracker" / "claim-intents.jsonl").read_bytes()

        with pytest.raises(IntentTrackerFull, match="capacity"):
            tracker.record_sent(
                self._intent(agent, ann.announcement_id, token, nonce="j" * 16)
            )
        assert (tmp_path / "tracker" / "claim-intents.jsonl").read_bytes() == before

    def test_capacity_archives_old_terminal_records_and_keeps_pending(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        directory = tmp_path / "tracker"
        tracker = IntentTracker(directory, max_intents=4)
        intents = [
            self._intent(
                agent,
                ann.announcement_id,
                token,
                nonce=character * 16,
                created_at_ms=NOW_MS + index,
            )
            for index, character in enumerate("ijklq")
        ]
        for intent, state in zip(intents[:3], ("confirmed", "rejected", "expired")):
            tracker.record_sent(intent)
            tracker.mark(intent, state)
        tracker.record_sent(intents[3])
        original = (directory / "claim-intents.jsonl").read_bytes()

        tracker.record_sent(intents[4])

        assert tracker.stats() == {
            "rejected": 1,
            "expired": 1,
            "pending": 2,
        }
        assert {item["nonce"] for item in tracker.pending(now_ms=NOW_MS + 10)} == {
            intents[3]["nonce"],
            intents[4]["nonce"],
        }
        archives = list((directory / "claim-intents-archive").glob("*.jsonl"))
        assert len(archives) == 1
        archived = archives[0].read_bytes()
        assert archived in original
        assert len(archived) < len(original)
        assert all(
            event["nonce"] == intents[0]["nonce"]
            for event in (json.loads(line) for line in archived.splitlines())
        )
        restarted = IntentTracker(directory, max_intents=4)
        assert restarted.stats() == tracker.stats()
        with pytest.raises(ClaimIntentRejected, match="archived intent"):
            restarted.record_sent(intents[0])

    def test_compaction_rewrite_failure_leaves_active_journal_usable(
        self,
        tmp_path,
        monkeypatch,
    ):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        directory = tmp_path / "tracker"
        tracker = IntentTracker(directory, max_intents=2)
        terminal = self._intent(agent, ann.announcement_id, token, nonce="u" * 16)
        pending = self._intent(agent, ann.announcement_id, token, nonce="v" * 16)
        replacement = self._intent(agent, ann.announcement_id, token, nonce="w" * 16)
        tracker.record_sent(terminal)
        tracker.mark(terminal, "confirmed")
        tracker.record_sent(pending)
        journal = directory / "claim-intents.jsonl"
        original = journal.read_bytes()

        from nth_dao.market import claim_intent as claim_intent_module

        real_atomic_write = claim_intent_module.atomic_write_bytes

        def fail_active_rewrite(path, content):
            if path == journal:
                raise OSError("simulated active journal rewrite failure")
            real_atomic_write(path, content)

        monkeypatch.setattr(
            claim_intent_module,
            "atomic_write_bytes",
            fail_active_rewrite,
        )
        with pytest.raises(OSError, match="simulated"):
            tracker.record_sent(replacement)

        assert journal.read_bytes() == original
        assert IntentTracker(directory, max_intents=2).stats() == {
            "confirmed": 1,
            "pending": 1,
        }
        monkeypatch.setattr(
            claim_intent_module, "atomic_write_bytes", real_atomic_write,
        )
        tracker.record_sent(replacement)
        assert IntentTracker(directory, max_intents=2).stats() == {
            "pending": 2,
        }

    def test_archive_index_rebuild_and_warm_start_do_not_reparse_history(
        self, tmp_path, monkeypatch,
    ):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        directory = tmp_path / "tracker"
        tracker = IntentTracker(directory, max_intents=3)
        pending = self._intent(agent, ann.announcement_id, token, nonce="p" * 16)
        tracker.record_sent(pending)
        for index in range(30):
            intent = self._intent(
                agent, ann.announcement_id, token, nonce=f"{index:016d}",
            )
            if index == 0:
                first_receipt = sign_claim_receipt(ann, agent, token)
                tracker.record_sent(intent, receipt=first_receipt)
            else:
                tracker.record_sent(intent)
            tracker.mark(intent, "confirmed")

        archive_dir = directory / "claim-intents-archive"
        archives = list(archive_dir.glob("claim-intents-*.jsonl"))
        assert len(archives) >= 20
        index_path = archive_dir / "index.sqlite3"
        with closing(sqlite3.connect(index_path)) as database:
            archived_count = database.execute(
                "SELECT COUNT(*) FROM bindings"
            ).fetchone()[0]
        assert archived_count >= 20

        original_read_bytes = Path.read_bytes

        def refuse_archive_content_read(path):
            if path.parent == archive_dir and path.suffix == ".jsonl":
                raise AssertionError("warm startup reparsed an old archive segment")
            return original_read_bytes(path)

        with monkeypatch.context() as patcher:
            patcher.setattr(Path, "read_bytes", refuse_archive_content_read)
            restarted = IntentTracker(directory, max_intents=3)
            assert len(restarted.pending(now_ms=NOW_MS + 1)) == 1
        with pytest.raises(ClaimIntentRejected, match="archived intent"):
            restarted.record_sent(self._intent(
                agent, ann.announcement_id, token, nonce="0000000000000000",
            ))
        with pytest.raises(ClaimIntentRejected, match="archived intent"):
            restarted.record_sent(
                self._intent(agent, ann.announcement_id, token, nonce="x" * 16),
                receipt=first_receipt,
            )
        assert restarted.verify_archive_integrity() == archived_count

        index_path.rename(archive_dir / "index.sqlite3.backup")
        rebuilt = IntentTracker(directory, max_intents=3)
        with pytest.raises(ClaimIntentRejected, match="archived intent"):
            rebuilt.record_sent(self._intent(
                agent, ann.announcement_id, token, nonce="0000000000000000",
            ))
        assert (archive_dir / "index.sqlite3").is_file()
        assert rebuilt.verify_archive_integrity() == archived_count

    def test_changed_archive_segment_fails_closed(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        directory = tmp_path / "tracker"
        tracker = IntentTracker(directory, max_intents=1)
        old = self._intent(agent, ann.announcement_id, token, nonce="r" * 16)
        tracker.record_sent(old)
        tracker.mark(old, "confirmed")
        tracker.record_sent(self._intent(
            agent, ann.announcement_id, token, nonce="s" * 16,
        ))
        archive = next((directory / "claim-intents-archive").glob("*.jsonl"))
        archive.write_bytes(archive.read_bytes() + b"corrupt\n")

        with pytest.raises(IntentTrackerCorrupt, match="content hash"):
            IntentTracker(directory, max_intents=1)

    def test_full_audit_detects_same_size_tamper_with_restored_mtime(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        directory = tmp_path / "tracker"
        tracker = IntentTracker(directory, max_intents=1)
        old = self._intent(agent, ann.announcement_id, token, nonce="a" * 16)
        tracker.record_sent(old)
        tracker.mark(old, "confirmed")
        tracker.record_sent(self._intent(
            agent, ann.announcement_id, token, nonce="b" * 16,
        ))
        archive = next((directory / "claim-intents-archive").glob("*.jsonl"))
        stat = archive.stat()
        original = archive.read_bytes()
        archive.write_bytes(b"[" + original[1:])
        os.utime(archive, ns=(stat.st_atime_ns, stat.st_mtime_ns))
        assert archive.stat().st_size == stat.st_size

        with pytest.raises(IntentTrackerCorrupt, match="content hash"):
            tracker.verify_archive_integrity()

    def test_full_audit_detects_missing_archive_index_binding(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        directory = tmp_path / "tracker"
        tracker = IntentTracker(directory, max_intents=1)
        old = self._intent(agent, ann.announcement_id, token, nonce="c" * 16)
        tracker.record_sent(old)
        tracker.mark(old, "confirmed")
        tracker.record_sent(self._intent(
            agent, ann.announcement_id, token, nonce="d" * 16,
        ))

        index_path = directory / "claim-intents-archive" / "index.sqlite3"
        with closing(sqlite3.connect(index_path)) as database, database:
            database.execute("DELETE FROM bindings WHERE nonce = ?", (old["nonce"],))

        with pytest.raises(IntentTrackerCorrupt, match="does not match"):
            tracker.verify_archive_integrity()

    def test_byte_cap_compaction_keeps_inflight_confirmation(self, tmp_path, monkeypatch):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        directory = tmp_path / "tracker"
        tracker = IntentTracker(directory, max_intents=4)
        old = self._intent(agent, ann.announcement_id, token, nonce="s" * 16)
        current = self._intent(agent, ann.announcement_id, token, nonce="t" * 16)
        receipt = sign_claim_receipt(ann, agent, token)
        receipt_hash = hashlib.sha256(canonical_json(receipt)).hexdigest()
        tracker.record_sent(old)
        tracker.mark(old, "rejected")
        tracker.record_sent(current, receipt=receipt)

        from nth_dao.market import claim_intent as claim_intent_module

        journal = directory / "claim-intents.jsonl"
        monkeypatch.setattr(
            claim_intent_module, "MAX_TRACKER_JOURNAL_BYTES", journal.stat().st_size,
        )
        assert tracker.confirm_by_receipt(receipt["receipt_id"], receipt_hash) == (
            current["nonce"]
        )
        assert tracker.stats() == {"confirmed": 1}
        assert IntentTracker(directory, max_intents=4).stats() == {"confirmed": 1}

    def test_compaction_preserves_unrelated_reconciliation_event(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        directory = tmp_path / "tracker"
        tracker = IntentTracker(directory, max_intents=4)
        intents = [
            self._intent(
                agent, ann.announcement_id, token,
                nonce=character * 16, created_at_ms=NOW_MS + index,
            )
            for index, character in enumerate("abcde")
        ]
        receipt = sign_claim_receipt(ann, agent, token)
        receipt_hash = hashlib.sha256(canonical_json(receipt)).hexdigest()
        tracker.record_sent(intents[0])
        tracker.mark(intents[0], "rejected")
        tracker.record_sent(intents[1], receipt=receipt)
        tracker.record_sent(intents[2])
        tracker.reconcile_retry(intents[2], receipt["receipt_id"], receipt_hash)
        tracker.record_sent(intents[3])
        before = (directory / "claim-intents.jsonl").read_bytes()
        reconciled_line = next(
            line for line in before.splitlines(keepends=True)
            if b'"event":"reconciled"' in line
        )

        tracker.record_sent(intents[4])

        active = (directory / "claim-intents.jsonl").read_bytes()
        assert reconciled_line in active
        assert tracker.stats() == {"confirmed": 1, "rejected": 1, "pending": 2}
        assert IntentTracker(directory, max_intents=4).stats() == tracker.stats()

    @pytest.mark.parametrize("archive_prior", [True, False])
    def test_compaction_preserves_cross_boundary_reconciliation(
        self, tmp_path, archive_prior,
    ):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        directory = tmp_path / "tracker"
        tracker = IntentTracker(directory, max_intents=3)
        prior = self._intent(
            agent, ann.announcement_id, token, nonce="k" * 16,
            created_at_ms=NOW_MS + (0 if archive_prior else 1),
        )
        retry = self._intent(
            agent, ann.announcement_id, token, nonce="l" * 16,
            created_at_ms=NOW_MS + (1 if archive_prior else 0),
        )
        pending = self._intent(
            agent, ann.announcement_id, token,
            nonce="m" * 16, created_at_ms=NOW_MS + 2,
        )
        next_intent = self._intent(
            agent, ann.announcement_id, token,
            nonce="n" * 16, created_at_ms=NOW_MS + 3,
        )
        receipt = sign_claim_receipt(ann, agent, token)
        receipt_hash = hashlib.sha256(canonical_json(receipt)).hexdigest()
        tracker.record_sent(prior, receipt=receipt)
        tracker.record_sent(retry)
        tracker.reconcile_retry(retry, receipt["receipt_id"], receipt_hash)
        tracker.record_sent(pending)

        tracker.record_sent(next_intent)

        active = (directory / "claim-intents.jsonl").read_bytes()
        archive = next((directory / "claim-intents-archive").glob("*.jsonl"))
        assert b'"event":"reconciled"' not in active
        assert b'"event":"reconciled"' in archive.read_bytes()
        assert tracker.stats() == (
            {"rejected": 1, "pending": 2}
            if archive_prior else {"confirmed": 1, "pending": 2}
        )
        restarted = IntentTracker(directory, max_intents=3)
        assert restarted.stats() == tracker.stats()
        assert restarted.verify_archive_integrity() == 1

    def test_unknown_terminal_transition_fails_closed(self, tmp_path):
        directory = tmp_path / "tracker"
        directory.mkdir()
        journal = directory / "claim-intents.jsonl"
        journal.write_text(
            '{"event":"confirmed","nonce":"kkkkkkkkkkkkkkkk"}\n',
            encoding="utf-8",
        )

        with pytest.raises(IntentTrackerCorrupt, match="unknown intent"):
            IntentTracker(directory)

    def test_records_are_detached_sorted_and_project_expiry(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        now = int(time.time() * 1000)
        older = self._intent(
            agent,
            ann.announcement_id,
            token,
            nonce="n" * 16,
            ttl=1_000,
            created_at_ms=now,
        )
        newer = self._intent(
            agent,
            ann.announcement_id,
            token,
            nonce="o" * 16,
            ttl=5_000,
            created_at_ms=now + 1,
        )
        tracker = IntentTracker(tmp_path / "tracker")
        tracker.record_sent(older)
        tracker.record_sent(newer)

        records = tracker.records(now_ms=now + 2_000)

        assert [item["intent"]["nonce"] for item in records] == [
            newer["nonce"],
            older["nonce"],
        ]
        assert [item["state"] for item in records] == ["pending", "expired"]
        records[0]["intent"]["announcement_id"] = "mutated"
        assert tracker.records(now_ms=now + 2_000)[0]["intent"] == newer
        assert tracker.stats() == {"pending": 2}

    def test_records_validate_limit_and_clock(self, tmp_path):
        tracker = IntentTracker(tmp_path / "tracker")
        with pytest.raises(ValueError, match="limit"):
            tracker.records(limit=0)
        with pytest.raises(ValueError, match="now_ms"):
            tracker.records(now_ms=True)

    def test_authority_ack_receipt_binding_confirms_exact_pending(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        first = self._intent(agent, ann.announcement_id, token, nonce="p" * 16)
        second = self._intent(agent, ann.announcement_id, token, nonce="q" * 16)
        receipt = sign_claim_receipt(ann, agent, token)
        tracker = IntentTracker(tmp_path / "tracker")
        tracker.record_sent(first, receipt=receipt)
        tracker.record_sent(second)
        receipt_hash = hashlib.sha256(canonical_json(receipt)).hexdigest()

        assert tracker.confirm_by_receipt(receipt["receipt_id"], receipt_hash) == first["nonce"]
        assert tracker.stats() == {"confirmed": 1, "pending": 1}
        assert tracker.confirm_by_receipt("unknown", receipt_hash) is None

    def test_signed_ack_can_correct_a_locally_expired_intent(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        now = int(time.time() * 1000)
        intent = self._intent(
            agent,
            ann.announcement_id,
            token,
            nonce="s" * 16,
            ttl=1_000,
            created_at_ms=now,
        )
        receipt = sign_claim_receipt(ann, agent, token)
        directory = tmp_path / "tracker"
        tracker = IntentTracker(directory)
        tracker.record_sent(intent, receipt=receipt)
        tracker.sweep_expired(now_ms=now + 2_000)
        assert tracker.stats() == {"expired": 1}

        receipt_hash = hashlib.sha256(canonical_json(receipt)).hexdigest()
        assert tracker.confirm_by_receipt(
            receipt["receipt_id"], receipt_hash,
        ) == intent["nonce"]
        assert tracker.stats() == {"confirmed": 1}
        assert IntentTracker(directory).stats() == {"confirmed": 1}

    def test_reconcile_retry_is_atomic_and_no_match_is_a_noop(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        prior = self._intent(agent, ann.announcement_id, token, nonce="t" * 16)
        retry = self._intent(agent, ann.announcement_id, token, nonce="u" * 16)
        receipt = sign_claim_receipt(ann, agent, token)
        receipt_hash = hashlib.sha256(canonical_json(receipt)).hexdigest()
        directory = tmp_path / "tracker"
        tracker = IntentTracker(directory)
        tracker.record_sent(prior, receipt=receipt)
        tracker.record_sent(retry)

        assert tracker.reconcile_retry(retry, "missing", receipt_hash) is None
        assert tracker.stats() == {"pending": 2}
        assert tracker.reconcile_retry(
            retry, receipt["receipt_id"], receipt_hash,
        ) == (prior["nonce"], True)
        assert tracker.stats() == {"confirmed": 1, "rejected": 1}
        assert IntentTracker(directory).stats() == {
            "confirmed": 1,
            "rejected": 1,
        }

    def test_reconcile_retry_distinguishes_already_confirmed(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        prior = self._intent(agent, ann.announcement_id, token, nonce="v" * 16)
        retry = self._intent(agent, ann.announcement_id, token, nonce="w" * 16)
        receipt = sign_claim_receipt(ann, agent, token)
        receipt_hash = hashlib.sha256(canonical_json(receipt)).hexdigest()
        tracker = IntentTracker(tmp_path / "tracker")
        tracker.record_sent(prior, receipt=receipt)
        tracker.confirm_by_receipt(receipt["receipt_id"], receipt_hash)
        tracker.record_sent(retry)

        assert tracker.reconcile_retry(
            retry, receipt["receipt_id"], receipt_hash,
        ) == (prior["nonce"], False)
        assert tracker.stats() == {"confirmed": 1, "rejected": 1}

    def test_receipt_confirmation_is_idempotent_across_spawned_processes(
        self, tmp_path,
    ):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        intent = self._intent(agent, ann.announcement_id, token, nonce="d" * 16)
        receipt = sign_claim_receipt(ann, agent, token)
        receipt_hash = hashlib.sha256(canonical_json(receipt)).hexdigest()
        directory = tmp_path / "tracker"
        IntentTracker(directory).record_sent(intent, receipt=receipt)

        ctx = mp.get_context("spawn")
        start = ctx.Event()
        results = ctx.Queue()
        processes = [
            ctx.Process(
                target=_confirm_receipt_worker,
                args=(str(directory), receipt["receipt_id"], receipt_hash, start, results),
            )
            for _ in range(4)
        ]
        for process in processes:
            process.start()
        start.set()
        responses = [results.get(timeout=30) for _ in processes]
        for process in processes:
            process.join(timeout=10)
            assert process.exitcode == 0

        assert responses == [("confirmed", intent["nonce"])] * len(processes)
        assert IntentTracker(directory).stats() == {"confirmed": 1}
        journal = (directory / "claim-intents.jsonl").read_text(encoding="utf-8")
        assert journal.count('"event":"confirmed"') == 1

    def test_retry_reconciliation_has_one_winner_across_spawned_processes(
        self, tmp_path,
    ):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        prior = self._intent(agent, ann.announcement_id, token, nonce="e" * 16)
        retry = self._intent(agent, ann.announcement_id, token, nonce="f" * 16)
        receipt = sign_claim_receipt(ann, agent, token)
        receipt_hash = hashlib.sha256(canonical_json(receipt)).hexdigest()
        directory = tmp_path / "tracker"
        tracker = IntentTracker(directory)
        tracker.record_sent(prior, receipt=receipt)
        tracker.record_sent(retry)

        ctx = mp.get_context("spawn")
        start = ctx.Event()
        results = ctx.Queue()
        processes = [
            ctx.Process(
                target=_reconcile_retry_worker,
                args=(
                    str(directory), retry, receipt["receipt_id"], receipt_hash,
                    start, results,
                ),
            )
            for _ in range(4)
        ]
        for process in processes:
            process.start()
        start.set()
        responses = [results.get(timeout=30) for _ in processes]
        for process in processes:
            process.join(timeout=10)
            assert process.exitcode == 0

        assert responses.count(("reconciled", (prior["nonce"], True))) == 1
        assert sum(kind == "terminal" for kind, _ in responses) == 3
        assert IntentTracker(directory).stats() == {"confirmed": 1, "rejected": 1}
        journal = (directory / "claim-intents.jsonl").read_text(encoding="utf-8")
        assert journal.count('"event":"reconciled"') == 1

    def test_receipt_binding_survives_restart_and_rejects_mismatch(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        intent = self._intent(agent, ann.announcement_id, token, nonce="r" * 16)
        receipt = sign_claim_receipt(ann, agent, token)
        directory = tmp_path / "tracker"
        IntentTracker(directory).record_sent(intent, receipt=receipt)
        reloaded = IntentTracker(directory)

        record = reloaded.records(now_ms=NOW_MS + 1)[0]
        assert record["receipt_id"] == receipt["receipt_id"]
        assert reloaded.confirm_by_receipt(receipt["receipt_id"], "0" * 64) is None

        wrong_agent = AgentIdentity.generate(label="wrong")
        wrong_token = _selfissue(wrong_agent, ["code_review"])
        wrong_receipt = sign_claim_receipt(ann, wrong_agent, wrong_token)
        with pytest.raises(ClaimIntentRejected, match="does not bind"):
            IntentTracker(tmp_path / "other").record_sent(
                intent,
                receipt=wrong_receipt,
            )

    def test_record_sent_rejects_shallow_unsigned_receipt(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        intent = self._intent(agent, ann.announcement_id, token, nonce="a" * 16)
        fake_receipt = {
            "receipt_id": "not-a-signed-receipt",
            "signer_did": agent.as_did(),
            "goal_id": f"market:claim:{ann.announcement_id}",
        }

        with pytest.raises(ClaimIntentRejected, match="signature or authorization"):
            IntentTracker(tmp_path / "tracker").record_sent(
                intent,
                receipt=fake_receipt,
            )

    def test_record_sent_rejects_tampered_receipt_token(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        intent = self._intent(agent, ann.announcement_id, token, nonce="b" * 16)
        receipt = sign_claim_receipt(ann, agent, token)
        receipt["authorizing_cap_token"] = dict(receipt["authorizing_cap_token"])
        receipt["authorizing_cap_token"]["token_id"] = "tampered-token"

        with pytest.raises(ClaimIntentRejected, match="signature or authorization"):
            IntentTracker(tmp_path / "tracker").record_sent(
                intent,
                receipt=receipt,
            )

    def test_record_sent_rejects_valid_receipt_for_different_token(self, tmp_path):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        other_token = _selfissue(agent, ["code_review"])
        intent = self._intent(agent, ann.announcement_id, token, nonce="c" * 16)
        receipt = sign_claim_receipt(ann, agent, other_token)

        with pytest.raises(ClaimIntentRejected, match="does not bind"):
            IntentTracker(tmp_path / "tracker").record_sent(
                intent,
                receipt=receipt,
            )

    def test_source_binding_survives_restart_and_is_detached(self, tmp_path):
        _, _, publisher, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        intent = self._intent(agent, ann.announcement_id, token, nonce="y" * 16)
        receipt = sign_claim_receipt(ann, agent, token)
        directory = tmp_path / "tracker"
        IntentTracker(directory).record_sent(
            intent,
            receipt=receipt,
            source_peer="https://source.example",
            source_did=publisher.as_did(),
            federation_key="nth-ann-sha256:" + "a" * 64,
        )
        tracker = IntentTracker(directory)

        record = tracker.record(intent["nonce"])
        assert record is not None
        assert record["source_peer"] == "https://source.example"
        assert record["source_did"] == publisher.as_did()
        assert record["receipt_hash"] == hashlib.sha256(
            canonical_json(receipt)
        ).hexdigest()
        record["source_peer"] = "https://mutated.example"
        assert tracker.record(intent["nonce"])["source_peer"] == (
            "https://source.example"
        )
        assert tracker.records()[0]["federation_key"] == (
            "nth-ann-sha256:" + "a" * 64
        )

    @pytest.mark.parametrize(
        ("source_peer", "source_did", "federation_key"),
        [
            (0, "", ""),
            ("", None, ""),
            ("", "", False),
        ],
    )
    def test_source_binding_rejects_non_string_values(
        self,
        tmp_path,
        source_peer,
        source_did,
        federation_key,
    ):
        _, _, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        intent = self._intent(agent, ann.announcement_id, token, nonce="z" * 16)

        with pytest.raises(ClaimIntentRejected, match="must contain strings"):
            IntentTracker(tmp_path / "tracker").record_sent(
                intent,
                source_peer=source_peer,
                source_did=source_did,
                federation_key=federation_key,
            )


class TestOfflineStory:
    def test_full_offline_flow(self, tmp_path):
        """The design doc §7.1 story: sign intent+receipt offline → carry →
        authority admits → claimant's tracker flips to confirmed."""

        feed, store, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        # offline: sign both, track as pending
        now = int(time.time() * 1000)  # real clock: tracker self-verifies
        intent = sign_claim_intent(
            agent,
            announcement_id=ann.announcement_id,
            cap_token=token,
            created_at_ms=now,
        )
        receipt = sign_claim_receipt(ann, agent, token)
        tracker = IntentTracker(tmp_path / "tracker")
        tracker.record_sent(intent)
        assert len(tracker.pending(now_ms=now + 1)) == 1  # UI: pending

        # later, at the authority (any transport carried the pair)
        out = admit_claim_intent(
            feed,
            store,
            intent,
            receipt,
            cap_token=token,
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
            agent,
            announcement_id=ann.announcement_id,
            cap_token=cited_token,
            created_at_ms=NOW_MS,
        )
        receipt = sign_claim_receipt(ann, agent, other_token)
        with pytest.raises(ClaimIntentRejected, match="different cap_token"):
            admit_claim_intent(
                feed,
                store,
                intent,
                receipt,
                cap_token=other_token,
                now_ms_override=int(time.time() * 1000),
            )
        assert not store.is_claimed(ann.announcement_id)

    def test_matching_token_still_admitted(self, tmp_path):
        feed, store, _, agent, ann = _setup(tmp_path)
        token = _selfissue(agent, ["code_review"])
        intent = sign_claim_intent(
            agent,
            announcement_id=ann.announcement_id,
            cap_token=token,
            created_at_ms=NOW_MS,
        )
        receipt = sign_claim_receipt(ann, agent, token)
        out = admit_claim_intent(
            feed,
            store,
            intent,
            receipt,
            cap_token=token,
            now_ms_override=int(time.time() * 1000),
        )
        assert out.claim_record["claimant_did"] == agent.as_did()
