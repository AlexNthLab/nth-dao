"""End-to-end courier handover: seal → carry → drain → open → inbox → ACK.

Pins the design doc §九 success scenario: Alice seals for Bob, the
courier (Carol's store) carries it, Bob drains/opens/validates/accepts,
signs an ACK, and the carrier pool is only mutated after success.
"""

from __future__ import annotations

import time

import pytest

pytest.importorskip("nacl")

from nacl.signing import SigningKey  # noqa: E402

from nth_dao.delivery.acknowledgement import validate_ack  # noqa: E402
from nth_dao.delivery.courier import seal_courier_envelope  # noqa: E402
from nth_dao.delivery.courier_handover import (  # noqa: E402
    ack_envelopes_from_report,
    process_handover,
)
from nth_dao.delivery.courier_store import CourierStore  # noqa: E402
from nth_dao.delivery.envelope import sign_envelope  # noqa: E402
from nth_dao.delivery.inbox import DeliveryInbox  # noqa: E402
from nth_dao.did_key import encode_ed25519_did_key  # noqa: E402
from nth_dao.identity import AgentIdentity  # noqa: E402

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


def _envelope(alice, payload=None, recipient="dao:core"):
    return sign_envelope(
        alice,
        kind="channel.message",
        recipient=recipient,
        payload={"body": "carry me"} if payload is None else payload,
        created_at_ms=NOW_MS,
        expires_at_ms=NOW_MS + 3_600_000,
    )


class TestFullFlowWithRealKeys:
    """The complete flow using controllable recipient keys."""

    def test_seal_carry_open_inbox_ack(self, tmp_path, alice, carrier, bob_inbox):
        recipient, signing, did = _make_recipient()
        envelope = _envelope(alice, payload={"mission": "sealed delivery"})
        courier = seal_courier_envelope(envelope, recipient_did=did)
        carrier.seal_into(courier)

        report = process_handover(
            carrier,
            recipient=recipient,
            identity_private=signing,
            inbox=bob_inbox,
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

    def test_ack_envelopes_addressed_to_sender(self, tmp_path, alice, carrier, bob_inbox):
        recipient, signing, did = _make_recipient()
        envelope = _envelope(alice)
        courier = seal_courier_envelope(envelope, recipient_did=did)
        carrier.seal_into(courier)
        report = process_handover(
            carrier, recipient=recipient, identity_private=signing,
            inbox=bob_inbox, now_ms=NOW_MS + 2_000,
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


class TestHostileCarrier:
    def test_hostile_envelope_rejected_but_batch_survives(
        self, tmp_path, alice, carrier, bob_inbox
    ):
        """One hostile envelope in a multi-envelope batch must not poison
        the rest — per-envelope isolation."""

        recipient, signing, did = _make_recipient()
        good = seal_courier_envelope(
            _envelope(alice, payload={"n": 1}), recipient_did=did
        )
        # hostile: a tampered ciphertext (integrity fails)
        bad = seal_courier_envelope(
            _envelope(alice, payload={"n": 2}), recipient_did=did
        )
        bad["ciphertext"] = bad["ciphertext"][:-4] + "AAAA"
        carrier.seal_into(good)
        carrier.seal_into(bad)

        report = process_handover(
            carrier, recipient=recipient, identity_private=signing,
            inbox=bob_inbox, now_ms=NOW_MS + 2_000,
        )
        assert len(report["accepted"]) == 1
        assert len(report["rejected"]) == 1
        assert "integrity" in report["rejected"][0]["reason"]
        # the rejected one stays on the carrier for host inspection
        assert carrier.stats()["envelopes"] == 1

    def test_expired_envelope_rejected_and_retained(
        self, tmp_path, alice, carrier, bob_inbox
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
            inbox=bob_inbox, now_ms=NOW_MS + 2_000,
        )
        assert report["accepted"] == []
        assert len(report["rejected"]) == 1
        assert "expired" in report["rejected"][0]["reason"]
        assert carrier.stats()["envelopes"] == 1  # retained for inspection

    def test_duplicate_envelope_is_ack_but_not_double_accepted(
        self, tmp_path, alice, carrier, bob_inbox
    ):
        """A courier re-delivering an already-accepted envelope still gets
        its ACK (idempotent) — but the inbox only counts it once."""

        recipient, signing, did = _make_recipient()
        envelope = _envelope(alice)
        courier = seal_courier_envelope(envelope, recipient_did=did)
        carrier.seal_into(courier)
        first = process_handover(
            carrier, recipient=recipient, identity_private=signing,
            inbox=bob_inbox, now_ms=NOW_MS + 2_000,
        )
        assert len(first["accepted"]) == 1
        # same envelope carried again (a second carrier copy)
        carrier.seal_into(courier)
        second = process_handover(
            carrier, recipient=recipient, identity_private=signing,
            inbox=bob_inbox, now_ms=NOW_MS + 3_000,
        )
        assert len(second["accepted"]) == 1  # still ACKed (duplicate)
        assert second["accepted"][0].message_id == envelope.message_id
        # inbox entry count stays 1
        assert bob_inbox.entry_count() == 1

    def test_unauthorized_sender_rejected_and_retained(self, tmp_path, alice, bob_inbox):
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
            inbox=strict_inbox, now_ms=NOW_MS + 2_000,
        )
        assert report["accepted"] == []
        assert len(report["rejected"]) == 1
        assert "not allowlisted" in report["rejected"][0]["reason"]
        assert store.stats()["envelopes"] == 1
