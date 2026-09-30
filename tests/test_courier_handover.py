"""End-to-end courier handover: seal → carry → drain → open → inbox → ACK.

Pins the design doc §九 success scenario: Alice seals for Bob, the
courier (Carol's store) carries it, Bob drains/opens/validates/accepts,
signs an ACK, and the carrier pool is only mutated after success.
"""

from __future__ import annotations

import time

import pytest

pytest.importorskip("nacl")

from nacl.signing import SigningKey

from nth_dao.delivery.acknowledgement import validate_ack
from nth_dao.delivery.courier import seal_courier_envelope
from nth_dao.delivery.courier_handover import (
    ack_envelopes_from_report,
    process_handover,
)
from nth_dao.delivery.courier_store import CourierStore
from nth_dao.delivery.envelope import sign_envelope
from nth_dao.delivery.inbox import DeliveryInbox
from nth_dao.delivery.outbox import DurableOutbox
from nth_dao.did_key import encode_ed25519_did_key
from nth_dao.identity import AgentIdentity

NOW_MS = int(time.time() * 1000)


def _make_recipient():
    """Build a recipient whose Ed25519 key and did match, exposing the
    sign/as_did surface that sign_ack needs (duck-typed proxy)."""

    from nth_dao.did_key import encode_ed25519_did_key

    signing = SigningKey(b"\x05" * 32)
    did = encode_ed25519_did_key(signing.verify_key.encode())

    class _Recipient:
        def as_did(self):
            return did

        def sign(self, payload: bytes) -> bytes:
            return signing.sign(payload).signature

        pubkey_hex = signing.verify_key.encode().hex()

    return _Recipient(), signing, did


@pytest.fixture()
def alice():
    return AgentIdentity.generate(label="alice")


@pytest.fixture()
def bob():
    signing = SigningKey(b"\x01" * 32)
    did = encode_ed25519_did_key(signing.verify_key.encode())
    return {"signing": signing, "did": did}


@pytest.fixture()
def carrier(tmp_path):
    return CourierStore(tmp_path / "carrier")


@pytest.fixture()
def bob_inbox(tmp_path):
    return DeliveryInbox(tmp_path / "bob-inbox", clock=lambda: NOW_MS + 1_000)


@pytest.fixture()
def ack_outbox(tmp_path):
    return DurableOutbox(tmp_path / "ack-outbox", clock=lambda: NOW_MS + 2_000)


def _envelope(alice, payload=None, recipient="dao:core", ttl_ms=3_600_000):
    return sign_envelope(
        alice,
        kind="channel.message",
        recipient=recipient,
        payload={"body": "carry me"} if payload is None else payload,
        created_at_ms=NOW_MS,
        expires_at_ms=NOW_MS + ttl_ms,
    )


class TestFullFlowWithRealKeys:
    """The complete flow using controllable recipient keys."""

    def test_seal_carry_open_inbox_ack(
        self, tmp_path, alice, carrier, bob_inbox, ack_outbox
    ):
        recipient, signing, did = _make_recipient()
        envelope = _envelope(alice, payload={"mission": "sealed delivery"})
        courier = seal_courier_envelope(envelope, recipient_did=did)
        carrier.seal_into(courier)

        report = process_handover(
            carrier,
            recipient=recipient,
            identity_private=signing,
            inbox=bob_inbox,
            ack_outbox=ack_outbox,
            now_ms=NOW_MS + 2_000,
        )

        assert len(report["accepted"]) == 1
        assert len(report["opened"]) == 1
        assert report["opened"][0].payload == {"mission": "sealed delivery"}
        assert report["rejected"] == []
        # carrier is emptied after successful handover
        assert carrier.stats()["envelopes"] == 0
        # inbox holds the envelope
        assert bob_inbox.seen(envelope.message_id)
        # the ACK verifies and binds the envelope
        ack = report["accepted"][0]
        ok, reason = validate_ack(ack, now_ms=NOW_MS + 3_000)
        assert ok, reason
        assert len(ack_outbox.pending(now_ms=NOW_MS + 3_000)) == 1

    def test_ack_envelopes_addressed_to_sender(
        self, tmp_path, alice, carrier, bob_inbox, ack_outbox
    ):
        recipient, signing, did = _make_recipient()
        envelope = _envelope(alice)
        courier = seal_courier_envelope(envelope, recipient_did=did)
        carrier.seal_into(courier)
        report = process_handover(
            carrier, recipient=recipient, identity_private=signing,
            inbox=bob_inbox, ack_outbox=ack_outbox, now_ms=NOW_MS + 2_000,
        )
        ack_envelopes = ack_envelopes_from_report(
            report, recipient=recipient, sender_did=alice.as_did(),
            now_ms=NOW_MS + 3_000,
        )
        assert len(ack_envelopes) == 1
        ack_env = ack_envelopes[0]
        assert ack_env.recipient == alice.as_did()
        assert ack_env.kind == "delivery.ack"
        assert ack_env.payload["ack"]["message_id"] == envelope.message_id

    def test_ack_is_durable_before_carrier_removal(
        self, tmp_path, alice, carrier, bob_inbox, ack_outbox, monkeypatch
    ):
        recipient, signing, did = _make_recipient()
        courier = seal_courier_envelope(
            _envelope(alice, ttl_ms=3 * 3_600_000), recipient_did=did
        )
        carrier.seal_into(courier)

        def fail_handover(_courier):
            raise OSError("simulated carrier failure")

        monkeypatch.setattr(carrier, "hand_over", fail_handover)
        with pytest.raises(OSError, match="simulated carrier failure"):
            process_handover(
                carrier,
                recipient=recipient,
                identity_private=signing,
                inbox=bob_inbox,
                ack_outbox=ack_outbox,
                now_ms=NOW_MS + 2_000,
            )
        with pytest.raises(OSError, match="simulated carrier failure"):
            process_handover(
                carrier,
                recipient=recipient,
                identity_private=signing,
                inbox=bob_inbox,
                ack_outbox=ack_outbox,
                now_ms=NOW_MS + 2 * 3_600_000,
            )

        assert len(ack_outbox.pending(now_ms=NOW_MS + 2 * 3_600_000 + 1)) == 1
        assert carrier.stats()["envelopes"] == 1

    def test_handover_rejects_non_positive_batch_size(
        self, carrier, bob_inbox, ack_outbox
    ):
        recipient, signing, _did = _make_recipient()
        with pytest.raises(ValueError, match="max_items"):
            process_handover(
                carrier,
                recipient=recipient,
                identity_private=signing,
                inbox=bob_inbox,
                ack_outbox=ack_outbox,
                max_items=0,
            )


class TestHostileCarrier:
    def test_hostile_envelope_rejected_but_batch_survives(
        self, tmp_path, alice, carrier, bob_inbox, ack_outbox
    ):
        """One hostile envelope in a multi-envelope batch must not poison
        the rest — per-envelope isolation."""

        recipient, signing, did = _make_recipient()
        good = seal_courier_envelope(
            _envelope(alice, payload={"n": 1}), recipient_did=did
        )
        # Hostile but wire-valid: ciphertext was sealed to another key while
        # the plaintext routing DID claims Bob. Public integrity still
        # passes at the carrier; Bob must isolate the decryption failure.
        mallory_signing = SigningKey(b"\x09" * 32)
        mallory_did = encode_ed25519_did_key(mallory_signing.verify_key.encode())
        bad = seal_courier_envelope(
            _envelope(alice, payload={"n": 2}), recipient_did=mallory_did
        )
        bad["recipient_did"] = did
        carrier.seal_into(good)
        carrier.seal_into(bad)

        report = process_handover(
            carrier, recipient=recipient, identity_private=signing,
            inbox=bob_inbox, ack_outbox=ack_outbox, now_ms=NOW_MS + 2_000,
        )
        assert len(report["accepted"]) == 1
        assert len(report["rejected"]) == 1
        assert "decryption" in report["rejected"][0]["reason"]
        # the rejected one stays on the carrier for host inspection
        assert carrier.stats()["envelopes"] == 1

    def test_expired_envelope_rejected_and_retained(
        self, tmp_path, alice, carrier, bob_inbox, ack_outbox
    ):
        from nth_dao.delivery.envelope import sign_envelope as _sign

        recipient, signing, did = _make_recipient()
        stale = _sign(
            alice,
            kind="channel.message",
            recipient="dao:core",
            payload={"old": True},
            created_at_ms=NOW_MS - 10_000,
            expires_at_ms=NOW_MS - 5_000,  # already expired
        )
        courier = seal_courier_envelope(stale, recipient_did=did)
        carrier.seal_into(courier)
        report = process_handover(
            carrier, recipient=recipient, identity_private=signing,
            inbox=bob_inbox, ack_outbox=ack_outbox, now_ms=NOW_MS + 2_000,
        )
        assert report["accepted"] == []
        assert len(report["rejected"]) == 1
        assert "expired" in report["rejected"][0]["reason"]
        assert carrier.stats()["envelopes"] == 1  # retained for inspection

    def test_duplicate_envelope_is_ack_but_not_double_accepted(
        self, tmp_path, alice, carrier, bob_inbox, ack_outbox
    ):
        """A courier re-delivering an already-accepted envelope still gets
        its ACK (idempotent) — but the inbox only counts it once."""

        recipient, signing, did = _make_recipient()
        envelope = _envelope(alice)
        courier = seal_courier_envelope(envelope, recipient_did=did)
        carrier.seal_into(courier)
        first = process_handover(
            carrier, recipient=recipient, identity_private=signing,
            inbox=bob_inbox, ack_outbox=ack_outbox, now_ms=NOW_MS + 2_000,
        )
        assert len(first["accepted"]) == 1
        # same envelope carried again (a second carrier copy)
        carrier.seal_into(courier)
        second = process_handover(
            carrier, recipient=recipient, identity_private=signing,
            inbox=bob_inbox, ack_outbox=ack_outbox, now_ms=NOW_MS + 3_000,
        )
        assert len(second["accepted"]) == 1  # still ACKed (duplicate)
        assert second["accepted"][0].message_id == envelope.message_id
        # inbox entry count stays 1
        assert bob_inbox.entry_count() == 1

    def test_unauthorized_sender_rejected_and_retained(
        self, tmp_path, alice, bob_inbox, ack_outbox
    ):
        """The inbox authorize hook rejects a sender that is not allowlisted;
        the envelope stays on the carrier for host inspection."""

        from nth_dao.identity import AgentIdentity

        mallory = AgentIdentity.generate(label="mallory")
        recipient, signing, did = _make_recipient()
        hostile = sign_envelope(
            mallory,
            kind="channel.message",
            recipient="dao:core",
            payload={"spoof": True},
            created_at_ms=NOW_MS,
            expires_at_ms=NOW_MS + 60_000,
        )
        courier = seal_courier_envelope(hostile, recipient_did=did)
        store = CourierStore(tmp_path / "carrier")
        store.seal_into(courier)

        def only_alice(envelope):
            return envelope.sender_did == alice.as_did(), "sender not allowlisted"

        strict_inbox = DeliveryInbox(
            tmp_path / "strict", clock=lambda: NOW_MS + 1_000, authorize=only_alice
        )
        report = process_handover(
            store, recipient=recipient, identity_private=signing,
            inbox=strict_inbox, ack_outbox=ack_outbox, now_ms=NOW_MS + 2_000,
        )
        assert report["accepted"] == []
        assert len(report["rejected"]) == 1
        assert "not allowlisted" in report["rejected"][0]["reason"]
        assert store.stats()["envelopes"] == 1


# ─────────────────── adversarial review round 21 (bug HH-1) ───────────────────


class TestClockDefault:
    def test_no_now_ms_defaults_to_wall_clock_not_skipped(
        self, tmp_path, alice, ack_outbox
    ):
        """Bug HH-1: process_handover without now_ms must default to the
        wall clock — a skipped TTL check let stale envelopes through when
        the host inbox also lacked a clock."""

        from nth_dao.delivery.courier import seal_courier_envelope
        from nth_dao.delivery.courier_store import CourierStore
        from nth_dao.delivery.envelope import sign_envelope as _sign
        from nth_dao.delivery.inbox import DeliveryInbox

        recipient, signing, did = _make_recipient()
        stale = _sign(
            alice,
            kind="channel.message",
            recipient="dao:core",
            payload={"old": True},
            created_at_ms=int(time.time() * 1000) - 100_000,
            expires_at_ms=int(time.time() * 1000) - 50_000,
        )
        courier = seal_courier_envelope(stale, recipient_did=did)
        store = CourierStore(tmp_path / "carrier")
        store.seal_into(courier)
        # the host inbox has NO clock override (real wall clock) — the
        # open-stage gate must still independently reject
        inbox = DeliveryInbox(tmp_path / "inbox")
        report = process_handover(
            store, recipient=recipient, identity_private=signing, inbox=inbox,
            ack_outbox=ack_outbox,
            now_ms=None,
        )
        assert report["accepted"] == []
        assert len(report["rejected"]) == 1
        assert "expired" in report["rejected"][0]["reason"]
