"""Tests for the Courier envelope (Phase 4) — sealed X25519 store-and-carry."""

from __future__ import annotations

import time

import pytest

pytest.importorskip("nacl")

from nacl.signing import SigningKey  # noqa: E402

from nth_dao.delivery.courier import (  # noqa: E402
    CourierEnvelopeRejected,
    courier_envelope_digest,
    open_courier_envelope,
    seal_courier_envelope,
)
from nth_dao.delivery.envelope import sign_envelope  # noqa: E402
from nth_dao.identity import AgentIdentity  # noqa: E402

NOW_MS = int(time.time() * 1000)


@pytest.fixture()
def alice():
    return AgentIdentity.generate(label="alice")


@pytest.fixture()
def bob():
    return AgentIdentity.generate(label="bob")


@pytest.fixture()
def bob_signing(bob):
    return bob  # AgentIdentity wraps a SigningKey internally


def _envelope(alice, payload=None):
    return sign_envelope(
        alice,
        kind="channel.message",
        recipient="dao:core",
        payload={"body": "carry me"} if payload is None else payload,
        created_at_ms=NOW_MS,
        expires_at_ms=NOW_MS + 3_600_000,
    )


class TestSeal:
    def test_seal_produces_wire_shape(self, alice, bob):
        envelope = _envelope(alice)
        courier = seal_courier_envelope(
            envelope, recipient_did=bob.as_did(), courier_id="usb-1"
        )
        assert courier["protocol"] == "nth-courier-envelope"
        assert courier["version"] == 1
        assert courier["recipient_did"] == bob.as_did()
        assert courier["courier_id"] == "usb-1"
        assert len(courier["ciphertext"]) > 0
        assert courier["integrity"].startswith("sha256:")

    def test_ciphertext_differs_per_seal(self, alice, bob):
        """SealedBox uses ephemeral X25519 per seal — same inputs produce
        different ciphertexts (semantic security)."""

        envelope = _envelope(alice)
        first = seal_courier_envelope(envelope, recipient_did=bob.as_did())
        second = seal_courier_envelope(envelope, recipient_did=bob.as_did())
        assert first["ciphertext"] != second["ciphertext"]
        # digests differ too — tracing a courier by content is not possible
        assert courier_envelope_digest(first) != courier_envelope_digest(second)

    def test_unsigned_envelope_rejected(self, alice, bob):
        envelope = _envelope(alice)
        envelope.signature = ""
        with pytest.raises(Exception, match="signature"):
            seal_courier_envelope(envelope, recipient_did=bob.as_did())

    def test_private_recipient_required(self, alice):
        with pytest.raises(Exception, match="did:key"):
            seal_courier_envelope(
                _envelope(alice), recipient_did="dao:core"
            )


class TestOpen:
    def test_roundtrip_via_dedicated_signing_key(self, alice):
        """The cleanest contract: the recipient's courier key pair is derived
        from the same Ed25519 seed that forms their NTH identity."""


        recipient_seed = b"\x01" * 32

        recipient_signing = SigningKey(recipient_seed)
        from nth_dao.did_key import encode_ed25519_did_key

        recipient_pub = recipient_signing.verify_key.encode()
        recipient_did = encode_ed25519_did_key(recipient_pub)

        envelope = _envelope(alice)
        courier = seal_courier_envelope(envelope, recipient_did=recipient_did)

        opened = open_courier_envelope(
            courier,
            recipient_did=recipient_did,
            identity_private=recipient_signing,
            now_ms=NOW_MS + 1_000,
        )
        assert opened.message_id == envelope.message_id
        assert opened.payload == envelope.payload

    def test_wrong_recipient_cannot_open(self, alice):
        """Mallory (a different key holder) cannot open bob's courier."""

        from nth_dao.did_key import encode_ed25519_did_key

        mallory_signing = SigningKey(b"\x02" * 32)
        mallory_pub = mallory_signing.verify_key.encode()
        mallory_did = encode_ed25519_did_key(mallory_pub)
        mallory_courier = seal_courier_envelope(
            _envelope(alice), recipient_did=mallory_did
        )

        # bob's key cannot open mallory's courier
        bob_signing = SigningKey(b"\x01" * 32)
        bob_pub = bob_signing.verify_key.encode()
        bob_did = encode_ed25519_did_key(bob_pub)
        bob_courier = seal_courier_envelope(
            _envelope(alice), recipient_did=bob_did
        )
        with pytest.raises(CourierEnvelopeRejected, match="different recipient"):
            open_courier_envelope(
                mallory_courier,
                recipient_did=bob_did,
                identity_private=bob_signing,
            )
        # and bob CAN open his own
        opened = open_courier_envelope(
            bob_courier, recipient_did=bob_did, identity_private=bob_signing,
            now_ms=NOW_MS,
        )
        assert opened.payload == {"body": "carry me"}

    def test_tampered_ciphertext_rejected_by_integrity(self, alice):
        from nth_dao.did_key import encode_ed25519_did_key

        recipient = SigningKey(b"\x01" * 32)
        recipient_did = encode_ed25519_did_key(recipient.verify_key.encode())
        courier = seal_courier_envelope(
            _envelope(alice), recipient_did=recipient_did
        )
        courier["ciphertext"] = courier["ciphertext"][:-4] + "AAAA"
        with pytest.raises(CourierEnvelopeRejected, match="integrity"):
            open_courier_envelope(
                courier,
                recipient_did=recipient_did,
                identity_private=recipient,
            )

    def test_unknown_field_rejected(self, alice):
        from nth_dao.did_key import encode_ed25519_did_key

        recipient = SigningKey(b"\x01" * 32)
        recipient_did = encode_ed25519_did_key(recipient.verify_key.encode())
        courier = seal_courier_envelope(
            _envelope(alice), recipient_did=recipient_did
        )
        courier["sneaky"] = True
        with pytest.raises(CourierEnvelopeRejected, match="unknown fields"):
            open_courier_envelope(
                courier,
                recipient_did=recipient_did,
                identity_private=recipient,
            )

    def test_expired_envelope_rejected_after_open(self, alice):
        from nth_dao.did_key import encode_ed25519_did_key

        recipient = SigningKey(b"\x01" * 32)
        recipient_did = encode_ed25519_did_key(recipient.verify_key.encode())
        envelope = sign_envelope(
            alice,
            kind="channel.message",
            recipient="dao:core",
            payload={"n": 1},
            created_at_ms=NOW_MS,
            expires_at_ms=NOW_MS + 1_000,
        )
        courier = seal_courier_envelope(envelope, recipient_did=recipient_did)
        # the courier arrives AFTER the envelope expired
        with pytest.raises(CourierEnvelopeRejected, match="expired"):
            open_courier_envelope(
                courier,
                recipient_did=recipient_did,
                identity_private=recipient,
                now_ms=NOW_MS + 2_000,
            )
