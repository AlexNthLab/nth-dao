"""Tests for the HTTPS federation transport and stdlib ingest server."""

from __future__ import annotations

import json

import pytest

from nth_dao.canonical_json import canonical_json
from nth_dao.delivery.acknowledgement import sign_ack
from nth_dao.delivery.envelope import (
    envelope_digest,
    sign_envelope,
)
from nth_dao.delivery.inbox import DeliveryInbox
from nth_dao.delivery.transports.federation import (
    FederationIngestServer,
    FederationTransport,
    FederationTransportError,
    ack_from_envelope,
    validate_peer_url,
)

pytest.importorskip("nacl")

NOW_MS = 1_750_000_000_000


@pytest.fixture()
def alice_identity():
    from nth_dao.identity import AgentIdentity

    return AgentIdentity.generate(label="alice")


@pytest.fixture()
def bob_identity():
    from nth_dao.identity import AgentIdentity

    return AgentIdentity.generate(label="bob")


def _envelope(alice_identity, payload=None):
    return sign_envelope(
        alice_identity,
        kind="channel.message",
        recipient="dao:core",
        payload={"body": "hi"} if payload is None else payload,
        created_at_ms=NOW_MS,
        expires_at_ms=NOW_MS + 120_000,
    )


@pytest.fixture()
def server(tmp_path, bob_identity):
    inbox = DeliveryInbox(tmp_path / "bob", clock=lambda: NOW_MS + 1_000)
    server = FederationIngestServer(inbox, host="127.0.0.1", port=0)
    server.start()
    yield server, inbox
    server.stop()


class TestPeerUrlValidation:
    def test_https_anywhere(self):
        assert validate_peer_url("https://peer.example.com") == "https://peer.example.com"
        assert validate_peer_url("https://1.2.3.4:8443/x") == "https://1.2.3.4:8443/x"

    def test_http_loopback_allowed(self):
        assert validate_peer_url("http://127.0.0.1:8080") == "http://127.0.0.1:8080"
        assert validate_peer_url("http://localhost:9000/") == "http://localhost:9000"

    def test_http_non_loopback_rejected(self):
        with pytest.raises(FederationTransportError, match="https"):
            validate_peer_url("http://peer.example.com")

    def test_credentials_rejected(self):
        with pytest.raises(FederationTransportError):
            validate_peer_url("https://user:pass@peer.example.com")

    def test_query_and_fragment_rejected(self):
        with pytest.raises(FederationTransportError):
            validate_peer_url("https://peer.example.com/?x=1")
        with pytest.raises(FederationTransportError):
            validate_peer_url("https://peer.example.com/#frag")

    def test_whitespace_and_empty_rejected(self):
        with pytest.raises(FederationTransportError):
            validate_peer_url("  ")
        with pytest.raises(FederationTransportError):
            validate_peer_url("")
        with pytest.raises(FederationTransportError):
            validate_peer_url("https://peer .example.com")


class TestFederationTransport:
    def test_requires_peers(self):
        with pytest.raises(ValueError, match="peer_urls"):
            FederationTransport(peer_urls=[])

    def test_rejects_duplicate_peers(self):
        with pytest.raises(ValueError, match="duplicates"):
            FederationTransport(peer_urls=["https://a.example.com", "https://a.example.com"])

    def test_unreachable_peers_fail_closed(self, alice_identity):
        transport = FederationTransport(peer_urls=["http://127.0.0.1:59999"])
        result = transport.send(_envelope(alice_identity))
        assert not result.accepted
        assert result.error_code == "peers-unreachable"

    def test_capabilities_declare_broadcast_push(self):
        transport = FederationTransport(peer_urls=["https://a.example.com"])
        caps = transport.capabilities
        assert caps.broadcast is True
        assert caps.realtime is False
        assert caps.privacy_level == 1
        assert transport.poll() == []


class TestIngestServer:

    def test_roundtrip_accepts_valid_envelope(self, server, alice_identity):
        httpd, inbox = server
        transport = FederationTransport(peer_urls=[httpd.url])
        envelope = _envelope(alice_identity)
        result = transport.send(envelope)
        assert result.accepted, result.error_code
        assert inbox.entry_count() == 1
        assert inbox.seen(envelope.message_id)

    def test_duplicate_delivery_is_idempotent_success(self, server, alice_identity):
        httpd, inbox = server
        transport = FederationTransport(peer_urls=[httpd.url])
        envelope = _envelope(alice_identity)
        assert transport.send(envelope).accepted
        # redelivering the same envelope still answers 200
        assert transport.send(envelope).accepted
        assert inbox.entry_count() == 1

    def test_two_transports_one_server(self, server, alice_identity):
        """Federated broadcast: two senders, one ingest point, both land."""

        httpd, inbox = server
        first = FederationTransport(peer_urls=[httpd.url], name="fed-1")
        second = FederationTransport(peer_urls=[httpd.url], name="fed-2")
        assert first.send(_envelope(alice_identity, payload={"n": 1})).accepted
        assert second.send(_envelope(alice_identity, payload={"n": 2})).accepted
        assert inbox.entry_count() == 2

    def test_malformed_body_returns_400(self, server):
        import urllib.error
        import urllib.request

        httpd, _ = server
        request = urllib.request.Request(
            httpd.ingest_url, data=b"{not json", method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            urllib.request.urlopen(request, timeout=5)
            raise AssertionError("expected HTTP 400")
        except urllib.error.HTTPError as exc:
            assert exc.code == 400

    def test_unknown_path_404(self, server):
        import urllib.error
        import urllib.request

        httpd, _ = server
        request = urllib.request.Request(
            httpd.url + "/elsewhere", data=b"{}", method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            urllib.request.urlopen(request, timeout=5)
            raise AssertionError("expected HTTP 404")
        except urllib.error.HTTPError as exc:
            assert exc.code == 404

    def test_oversized_body_413(self, server):
        import urllib.error
        import urllib.request

        httpd, _ = server
        # raw oversized body: the Content-Length gate fires before parsing
        body = b"x" * 600_000
        request = urllib.request.Request(
            httpd.ingest_url, data=body, method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            urllib.request.urlopen(request, timeout=10)
            raise AssertionError("expected HTTP 413")
        except urllib.error.HTTPError as exc:
            assert exc.code == 413

    def test_expired_envelope_422(self, server, alice_identity):
        import urllib.error
        import urllib.request

        httpd, _ = server
        envelope = sign_envelope(
            alice_identity,
            kind="channel.message",
            recipient="dao:core",
            payload={"n": 1},
            created_at_ms=NOW_MS,
            expires_at_ms=NOW_MS + 1_000,
        )
        body = canonical_json(envelope.to_dict())
        request = urllib.request.Request(
            httpd.ingest_url, data=body, method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            urllib.request.urlopen(request, timeout=5)
            raise AssertionError("expected HTTP 422")
        except urllib.error.HTTPError as exc:
            assert exc.code == 422
            payload = json.loads(exc.read())
            assert "expired" in payload["reason"]


class TestAckEnvelope:
    def test_ack_roundtrip_through_envelope(self, tmp_path, alice_identity, bob_identity):
        """The ACK travels back as a signed envelope; only the receiver's
        identity can vouch for it."""

        alice_inbox = DeliveryInbox(tmp_path / "alice", clock=lambda: NOW_MS)
        envelope = _envelope(alice_identity)
        ack = sign_ack(
            bob_identity,
            message_id=envelope.message_id,
            envelope_sha256=envelope_digest(envelope),
            received_at_ms=NOW_MS + 1_000,
        )
        ack_envelope = sign_envelope(
            bob_identity,
            kind="delivery.ack",
            recipient=alice_identity.as_did(),
            payload={"ack": ack.to_dict()},
            created_at_ms=NOW_MS + 1_100,
            expires_at_ms=NOW_MS + 61_100,
        )
        # bob's own inbox accepts his outgoing ack envelope in real flows via
        # loopback; here we validate the unwrap on alice's side
        assert alice_inbox.accept(ack_envelope, now_ms=NOW_MS + 1_500).accepted
        unwrapped = ack_from_envelope(ack_envelope)
        assert unwrapped.message_id == envelope.message_id

    def test_wrong_kind_rejected(self, alice_identity, bob_identity):
        envelope = _envelope(alice_identity)
        with pytest.raises(ValueError, match="not a delivery.ack"):
            ack_from_envelope(envelope)

    def test_author_must_be_the_ack_receiver(self, alice_identity, bob_identity):
        ack = sign_ack(
            bob_identity,
            message_id="sha256:" + "3" * 64,
            envelope_sha256="sha256:" + "4" * 64,
            received_at_ms=NOW_MS,
        )
        # envelope authored by alice but the ack claims bob is the receiver
        forged = sign_envelope(
            alice_identity,
            kind="delivery.ack",
            recipient=alice_identity.as_did(),
            payload={"ack": ack.to_dict()},
            created_at_ms=NOW_MS,
            expires_at_ms=NOW_MS + 60_000,
        )
        with pytest.raises(ValueError, match="does not match the envelope author"):
            ack_from_envelope(forged)

    def test_payload_shape_strict(self, alice_identity, bob_identity):
        ack = sign_ack(
            bob_identity,
            message_id="sha256:" + "1" * 64,
            envelope_sha256="sha256:" + "2" * 64,
            received_at_ms=NOW_MS,
        )
        envelope = sign_envelope(
            bob_identity,
            kind="delivery.ack",
            recipient=alice_identity.as_did(),
            payload={"ack": ack.to_dict(), "extra": 1},
            created_at_ms=NOW_MS,
            expires_at_ms=NOW_MS + 60_000,
        )
        with pytest.raises(ValueError, match="exactly one"):
            ack_from_envelope(envelope)


class TestClientSideValidation:
    def test_send_unsigned_envelope_rejected_client_side(self, alice_identity):
        transport = FederationTransport(peer_urls=["https://a.example.com"])
        envelope = _envelope(alice_identity)
        envelope.signature = ""
        result = transport.send(envelope)
        assert not result.accepted
        assert "invalid-envelope" in result.error_code


# ─────────────────── adversarial review round 8 (bug AJ) ───────────────────


class TestContentLengthStrictness:
    def test_unicode_content_length_returns_400_not_crash(self, server):
        """Bug AJ: '²'.isdigit() is True but int('²') explodes — a hostile
        Content-Length header must get a clean 400, never kill the thread.
        Raw sockets (urllib's own header handling would obscure the server
        behavior under test)."""

        import socket

        httpd, _ = server
        port = httpd._httpd.server_address[1]
        for hostile in ("²", "１２３", "-5", "1e3", ""):
            sock = socket.create_connection(("127.0.0.1", port), timeout=5)
            header_value = hostile.encode("latin-1", "replace")
            request = (
                b"POST /delivery/ingest HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: " + header_value + b"\r\n"
                b"\r\n{}"
            )
            sock.sendall(request)
            response = sock.recv(4096)
            sock.close()
            status = int(response.split(b"\r\n", 1)[0].split()[1])
            assert status == 400, (hostile, response[:60])

        # the server is still alive afterwards
        transport = FederationTransport(peer_urls=[httpd.url])
        from nth_dao.identity import AgentIdentity

        ident = AgentIdentity.generate(label="still-alive")
        envelope = _envelope(ident)
        assert transport.send(envelope).accepted
