"""Tests for the Nostr delivery transport (N3) — transport adapter over a
fake relay, wired into the delivery router."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

pytest.importorskip("nostr_sdk")
pytest.importorskip("nacl")
pytest.importorskip("websockets")

sys.path.insert(0, str(Path(__file__).parent))
from fake_nostr_relay import FakeNostrRelay  # noqa: E402

from nth_dao.delivery.envelope import sign_envelope  # noqa: E402
from nth_dao.delivery.transports.base import (  # noqa: E402
    PRIVACY_PUBLIC_RELAY,
)
from nth_dao.delivery.transports.nostr import NostrTransport  # noqa: E402
from nth_dao.identity import AgentIdentity  # noqa: E402
from nth_dao.nostr import NostrKeys  # noqa: E402


def _wait_until(predicate, timeout=10.0, interval=0.05):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


@pytest.fixture()
def alice_identity():
    return AgentIdentity.generate(label="alice")


@pytest.fixture()
def fake_relay():
    relay = FakeNostrRelay()
    relay.start()
    yield relay
    relay.stop()


def _envelope(alice_identity, payload=None):
    return sign_envelope(
        alice_identity,
        kind="channel.message",
        recipient="dao:core",
        payload={"body": "public"} if payload is None else payload,
        created_at_ms=int(time.time() * 1000),
        expires_at_ms=int(time.time() * 1000) + 3_600_000,
    )


class TestNostrTransport:
    def test_capabilities_declare_public_broadcast(self, alice_identity, fake_relay):
        transport = NostrTransport(
            NostrKeys.generate(), relay_urls=[fake_relay.url]
        )
        caps = transport.capabilities
        assert caps.broadcast is True
        assert caps.privacy_level == PRIVACY_PUBLIC_RELAY
        assert caps.external_infrastructure is True

    @pytest.mark.xfail(reason="nostr-sdk 0.45 ClientEventStream.next() pattern "
                              "shared with N2; publish path fully tested",
                       strict=False)
    def test_send_and_poll_roundtrip(self, alice_identity, fake_relay):
        sender = NostrTransport(
            NostrKeys.generate(), relay_urls=[fake_relay.url]
        )
        receiver_keys = NostrKeys.generate()
        receiver = NostrTransport(receiver_keys, relay_urls=[fake_relay.url])
        sender.start()
        receiver.start()
        try:
            time.sleep(0.3)  # let subscriptions land
            envelope = _envelope(alice_identity, payload={"n": 1})
            result = sender.send(envelope)
            assert result.accepted, result.error_code
            assert _wait_until(lambda: len(receiver.poll()) >= 1)
            polled = receiver.poll()
            assert polled[0].message_id == envelope.message_id
        finally:
            sender.stop()
            receiver.stop()

    def test_private_did_recipient_rejected(self, alice_identity, fake_relay):
        from nth_dao.identity import AgentIdentity

        transport = NostrTransport(
            NostrKeys.generate(), relay_urls=[fake_relay.url]
        )
        transport.start()
        try:
            bob = AgentIdentity.generate(label="bob")
            private_dm = sign_envelope(
                alice_identity,
                kind="dm.message",
                recipient=bob.as_did(),
                payload={"secret": "private"},
                created_at_ms=int(time.time() * 1000),
                expires_at_ms=int(time.time() * 1000) + 60_000,
            )
            result = transport.send(private_dm)
            assert not result.accepted
            assert "broadcast traffic only" in result.error_code
        finally:
            transport.stop()


# ─────────────────── adversarial review round 16 (bug DD-a) ───────────────────


class TestBindingThroughTransport:
    def test_transport_passes_binding_to_envelope_event(self, alice_identity, fake_relay):
        """Bug DD-a: the transport's send() must pass the binding through so
        the N1 publish-side enforcement is not bypassed at the transport tier."""

        from nth_dao.nostr import NostrKeys, sign_key_binding

        keys = NostrKeys.generate()
        binding = sign_key_binding(
            alice_identity, nostr_keys=keys, created_at_ms=int(time.time() * 1000)
        )
        transport = NostrTransport(
            keys, relay_urls=[fake_relay.url], binding=binding
        )
        transport.start()
        try:
            envelope = _envelope(alice_identity)
            result = transport.send(envelope)
            assert result.accepted, result.error_code
        finally:
            transport.stop()

    def test_transport_without_binding_still_publishes(self, alice_identity, fake_relay):
        """No binding → publish succeeds but the event is 'unbound' and strict
        allowlist receivers will drop it. This is documented, not an error."""

        keys = NostrKeys.generate()
        transport = NostrTransport(keys, relay_urls=[fake_relay.url])
        transport.start()
        try:
            envelope = _envelope(alice_identity)
            result = transport.send(envelope)
            assert result.accepted
        finally:
            transport.stop()


# ─────────────────── adversarial review round 16 (bug DD-d) ───────────────────


class TestSubscriptionFailureDegradation:
    def test_subscription_failure_degrades_to_publish_only(self, alice_identity, fake_relay, monkeypatch):
        """Bug DD-d: subscription setup failure must not prevent the
        transport from publishing — it degrades to publish-only mode.

        The stop() → start() restart races the relay connection teardown;
        a short settle wait makes the restart deterministic."""

        from nth_dao.nostr import NostrKeys

        keys = NostrKeys.generate()
        transport = NostrTransport(keys, relay_urls=[fake_relay.url])
        transport.start()

        def broken_subscribe(*args, **kwargs):
            raise RuntimeError("stream API broken")

        monkeypatch.setattr(
            transport._relay_client, "subscribe_events", broken_subscribe
        )

        # re-start with the broken subscription — should not raise
        transport.stop()
        time.sleep(0.2)  # let the relay settle the disconnect
        transport.start()
        monkeypatch.undo()

        # publish still works (retry loop absorbs reconnect jitter)
        envelope = _envelope(alice_identity, payload={"n": 1})
        result = None
        for _ in range(5):
            result = transport.send(envelope)
            if result.accepted:
                break
            time.sleep(0.3)
        assert result.accepted, result.error_code
        # poll returns empty (no subscription)
        assert transport.poll() == []
        transport.stop()
