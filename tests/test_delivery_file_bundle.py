"""Tests for the file-bundle transport — the offline carry baseline."""

from __future__ import annotations

import json

import pytest

from nth_dao.canonical_json import canonical_json
from nth_dao.delivery.envelope import MAX_SAFE_INTEGER, sign_envelope
from nth_dao.delivery.inbox import DeliveryInbox
import nth_dao.delivery.transports.file_bundle as file_bundle_module
from nth_dao.delivery.transports.file_bundle import (
    BUNDLE_SUFFIX,
    DEFAULT_IMPORT_LEASE_MS,
    FileBundleRejected,
    FileBundleTransport,
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
        expires_at_ms=NOW_MS + 60_000,
    )


@pytest.fixture()
def exchange(tmp_path):
    return tmp_path / "exchange"


@pytest.fixture()
def sender_transport(exchange, alice_identity):
    return FileBundleTransport(
        exchange, alice_identity, state_dir=exchange / ".state-alice",
        clock=lambda: NOW_MS,
    )


class TestBundleRoundtrip:
    def test_send_serializes_snapshot_validated_before_caller_mutation(
        self, exchange, alice_identity, monkeypatch
    ):
        sender = sender_transport_factory(exchange, alice_identity)
        envelope = _envelope(alice_identity, payload={"body": "original"})
        real_validate = file_bundle_module.validate_envelope

        def mutate_caller_after_validation(candidate, **kwargs):
            result = real_validate(candidate, **kwargs)
            envelope.payload["body"] = "forged-after-validation"
            return result

        monkeypatch.setattr(
            file_bundle_module,
            "validate_envelope",
            mutate_caller_after_validation,
        )

        assert sender.send(envelope).accepted is True
        bundle_path = next(exchange.glob(f"*{BUNDLE_SUFFIX}"))
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        wire_envelope = json.loads(bundle["envelopes"][0])

        assert envelope.payload["body"] == "forged-after-validation"
        assert wire_envelope["payload"]["body"] == "original"

    def test_send_then_poll_delivers(self, exchange, alice_identity, bob_identity):
        sender = sender_transport_factory(exchange, alice_identity)
        receiver = FileBundleTransport(
            exchange, bob_identity, state_dir=exchange / ".state-bob",
            clock=lambda: NOW_MS,
        )
        envelope = _envelope(alice_identity)
        assert sender.send(envelope).accepted
        received = receiver.poll()
        assert len(received) == 1
        assert received[0].message_id == envelope.message_id
        assert receiver.commit_import(received[0].message_id) is True

    def test_repoll_does_not_double_deliver(self, exchange, alice_identity, bob_identity):
        sender = sender_transport_factory(exchange, alice_identity)
        receiver = FileBundleTransport(
            exchange, bob_identity, state_dir=exchange / ".state-bob",
            clock=lambda: NOW_MS,
        )
        sender.send(_envelope(alice_identity))
        received = receiver.poll()
        assert len(received) == 1
        assert receiver.commit_import(received[0].message_id) is True
        assert receiver.poll() == []

    def test_receiver_restart_does_not_double_deliver(self, exchange, alice_identity, bob_identity):
        sender = sender_transport_factory(exchange, alice_identity)
        sender.send(_envelope(alice_identity))
        first = FileBundleTransport(
            exchange, bob_identity, state_dir=exchange / ".state-bob", clock=lambda: NOW_MS
        )
        received = first.poll()
        assert len(received) == 1
        assert first.commit_import(received[0].message_id) is True
        second = FileBundleTransport(
            exchange, bob_identity, state_dir=exchange / ".state-bob", clock=lambda: NOW_MS
        )
        assert second.poll() == []

    def test_bundle_file_is_signed_canonical_json(self, exchange, alice_identity):
        sender = sender_transport_factory(exchange, alice_identity)
        sender.send(_envelope(alice_identity))
        bundles = list(exchange.glob(f"*{BUNDLE_SUFFIX}"))
        assert len(bundles) == 1
        data = json.loads(bundles[0].read_text())
        assert data["protocol"] == "nth-delivery-file-bundle"
        assert data["version"] == 1
        assert data["sender_did"] == alice_identity.as_did()
        assert data["signature"]
        # canonical bytes on disk: re-encoding matches
        assert canonical_json(data) == bundles[0].read_bytes()

    def test_partial_poll_does_not_discard_bundle_tail(
        self, exchange, alice_identity, bob_identity
    ):
        sender = sender_transport_factory(exchange, alice_identity)
        originals = [
            _envelope(alice_identity, payload={"n": index}) for index in range(3)
        ]
        sender._write_bundle(sender._build_bundle(originals))
        receiver = FileBundleTransport(
            exchange,
            bob_identity,
            state_dir=exchange / ".state-bob",
            clock=lambda: NOW_MS,
        )

        first = receiver.poll(max_items=1)
        assert receiver.commit_import(first[0].message_id) is True
        remainder = receiver.poll(max_items=10)
        for envelope in remainder:
            assert receiver.commit_import(envelope.message_id) is True

        assert [item.message_id for item in first] == [originals[0].message_id]
        assert [item.message_id for item in remainder] == [
            item.message_id for item in originals[1:]
        ]

    def test_crash_after_inbox_persist_redelivers_then_commits_duplicate(
        self, exchange, alice_identity, bob_identity, tmp_path
    ):
        now_ms = [NOW_MS]
        sender = sender_transport_factory(exchange, alice_identity)
        envelope = _envelope(alice_identity)
        assert sender.send(envelope).accepted is True
        state_dir = exchange / ".state-bob"
        receiver = FileBundleTransport(
            exchange,
            bob_identity,
            state_dir=state_dir,
            clock=lambda: now_ms[0],
        )
        leased = receiver.poll(lease_ms=10)
        assert [item.message_id for item in leased] == [envelope.message_id]

        inbox = DeliveryInbox(tmp_path / "durable-inbox", clock=lambda: now_ms[0])
        assert inbox.accept(leased[0], now_ms=now_ms[0]).accepted is True
        # Simulate a crash before commit_import. After lease expiry, a new
        # process sees the item; Inbox identifies it as already durable.
        now_ms[0] += 11
        recovered = FileBundleTransport(
            exchange,
            bob_identity,
            state_dir=state_dir,
            clock=lambda: now_ms[0],
        )
        decisions = recovered.poll_into(inbox, lease_ms=10)

        assert len(decisions) == 1
        assert decisions[0].duplicate is True
        assert recovered.poll() == []

        now_ms[0] += DEFAULT_IMPORT_LEASE_MS + 1
        restarted = FileBundleTransport(
            exchange,
            bob_identity,
            state_dir=state_dir,
            clock=lambda: now_ms[0],
        )
        assert restarted.poll() == []

    @pytest.mark.parametrize("clock_value", [True, 0, -1, MAX_SAFE_INTEGER + 1])
    def test_poll_rejects_invalid_clock_values(
        self, exchange, bob_identity, clock_value
    ):
        receiver = FileBundleTransport(
            exchange,
            bob_identity,
            state_dir=exchange / ".state-bob",
            clock=lambda: clock_value,
        )

        with pytest.raises(FileBundleRejected, match="clock"):
            receiver.poll()

    def test_poll_rejects_lease_deadline_overflow(self, exchange, bob_identity):
        receiver = FileBundleTransport(
            exchange,
            bob_identity,
            state_dir=exchange / ".state-bob",
            clock=lambda: MAX_SAFE_INTEGER,
        )

        with pytest.raises(FileBundleRejected, match="lease expiry"):
            receiver.poll(lease_ms=1)

    def test_expired_lease_cannot_be_committed(
        self, exchange, alice_identity, bob_identity
    ):
        now_ms = [NOW_MS]
        sender = sender_transport_factory(exchange, alice_identity)
        envelope = _envelope(alice_identity)
        assert sender.send(envelope).accepted is True
        receiver = FileBundleTransport(
            exchange,
            bob_identity,
            state_dir=exchange / ".state-bob",
            clock=lambda: now_ms[0],
        )
        assert len(receiver.poll(lease_ms=10)) == 1
        now_ms[0] += 11

        with pytest.raises(FileBundleRejected, match="expired import lease"):
            receiver.commit_import(envelope.message_id)

        assert receiver.poll(lease_ms=10)[0].message_id == envelope.message_id

    def test_compaction_drops_expired_orphan_leases(
        self, exchange, alice_identity, bob_identity, monkeypatch
    ):
        import nth_dao.delivery.transports.file_bundle as file_bundle_module

        now_ms = [NOW_MS]
        sender = sender_transport_factory(exchange, alice_identity)
        orphan = _envelope(alice_identity, payload={"n": "orphan"})
        assert sender.send(orphan).accepted is True
        receiver = FileBundleTransport(
            exchange,
            bob_identity,
            state_dir=exchange / ".state-bob",
            clock=lambda: now_ms[0],
        )
        assert len(receiver.poll(lease_ms=10)) == 1
        for path in exchange.glob("*.nthbundle"):
            path.unlink()

        now_ms[0] += 11
        monkeypatch.setattr(file_bundle_module, "_IMPORTED_JOURNAL_CAP", 1)
        current = _envelope(alice_identity, payload={"n": "current"})
        assert sender.send(current).accepted is True
        assert receiver.poll(lease_ms=10)[0].message_id == current.message_id

        journal = (exchange / ".state-bob" / "imported.jsonl").read_text()
        assert orphan.message_id not in journal
        assert current.message_id in journal


class TestBundleHostility:
    def test_bundle_reader_never_uses_unbounded_read_bytes(
        self, exchange, alice_identity, bob_identity, monkeypatch
    ):
        sender = sender_transport_factory(exchange, alice_identity)
        envelope = _envelope(alice_identity)
        assert sender.send(envelope).accepted is True
        bundle_path = next(exchange.glob(f"*{BUNDLE_SUFFIX}"))
        original_read_bytes = type(bundle_path).read_bytes

        def forbidden_read_bytes(path):
            if path == bundle_path:
                raise AssertionError("bundle loading must use a bounded read")
            return original_read_bytes(path)

        monkeypatch.setattr(type(bundle_path), "read_bytes", forbidden_read_bytes)
        receiver = FileBundleTransport(
            exchange,
            bob_identity,
            state_dir=exchange / ".state-bob",
            clock=lambda: NOW_MS,
        )
        assert receiver.poll()[0].message_id == envelope.message_id

    def test_tampered_bundle_rejected(self, exchange, alice_identity, bob_identity):
        sender = sender_transport_factory(exchange, alice_identity)
        sender.send(_envelope(alice_identity))
        bundle_path = next(exchange.glob(f"*{BUNDLE_SUFFIX}"))
        data = json.loads(bundle_path.read_text())
        data["created_at_ms"] += 1  # any body change breaks the signature
        bundle_path.write_bytes(canonical_json(data))
        receiver = FileBundleTransport(
            exchange, bob_identity, state_dir=exchange / ".state-bob", clock=lambda: NOW_MS
        )
        assert receiver.poll() == []

    def test_corrupt_json_skipped_not_fatal(self, exchange, alice_identity, bob_identity):
        sender = sender_transport_factory(exchange, alice_identity)
        sender.send(_envelope(alice_identity))
        junk = exchange / "junk.nthbundle"
        junk.write_bytes(b"{not json")
        receiver = FileBundleTransport(
            exchange, bob_identity, state_dir=exchange / ".state-bob", clock=lambda: NOW_MS
        )
        received = receiver.poll()
        assert len(received) == 1  # the good bundle survives the bad one

    def test_unknown_fields_rejected(self, exchange, alice_identity, bob_identity):
        sender = sender_transport_factory(exchange, alice_identity)
        sender.send(_envelope(alice_identity))
        bundle_path = next(exchange.glob(f"*{BUNDLE_SUFFIX}"))
        data = json.loads(bundle_path.read_text())
        data["surprise"] = True
        bundle_path.write_bytes(canonical_json(data))
        receiver = FileBundleTransport(
            exchange, bob_identity, state_dir=exchange / ".state-bob", clock=lambda: NOW_MS
        )
        assert receiver.poll() == []

    def test_wrong_version_rejected(self, exchange, alice_identity, bob_identity):
        sender = sender_transport_factory(exchange, alice_identity)
        sender.send(_envelope(alice_identity))
        bundle_path = next(exchange.glob(f"*{BUNDLE_SUFFIX}"))
        data = json.loads(bundle_path.read_text())
        # re-sign as v99 with bob's key over the modified body
        data["version"] = 99
        data["sender_did"] = bob_identity.as_did()
        from nth_dao.b64u import b64u_encode

        data["signature"] = b64u_encode(
            bob_identity.sign(canonical_json(
                {k: v for k, v in data.items() if k != "signature"}
            ))
        )
        bundle_path.write_bytes(canonical_json(data))
        receiver = FileBundleTransport(
            exchange, bob_identity, state_dir=exchange / ".state-bob", clock=lambda: NOW_MS
        )
        assert receiver.poll() == []

    def test_unsigned_envelope_not_sendable(self, exchange, alice_identity):
        sender = sender_transport_factory(exchange, alice_identity)
        envelope = _envelope(alice_identity)
        envelope.signature = ""
        result = sender.send(envelope)
        assert not result.accepted and "invalid-envelope" in result.error_code


class TestBundleCaps:
    def test_crypto_required(self, exchange, monkeypatch):
        import nth_dao.delivery.transports.file_bundle as fb

        monkeypatch.setattr(fb, "_NACL_AVAILABLE", False)
        from nth_dao.identity import AgentIdentity

        with pytest.raises(FileBundleRejected, match="crypto unavailable"):
            FileBundleTransport(exchange, AgentIdentity.generate(label="x"))

    def test_capabilities_declare_offline_broadcast(self, sender_transport):
        caps = sender_transport.capabilities
        assert caps.realtime is False
        assert caps.broadcast is True
        assert caps.privacy_level == 2
        assert caps.external_infrastructure is False

    def test_bundle_directory_over_limit_fails_closed_without_importing(
        self, exchange, alice_identity, bob_identity, monkeypatch
    ):
        import nth_dao.delivery.transports.file_bundle as fb

        monkeypatch.setattr(fb, "BUNDLE_MAX_BUNDLES_PER_DIR", 2)
        monkeypatch.setattr(fb, "BUNDLE_MAX_DIRECTORY_ENTRIES", 4)
        sender = sender_transport_factory(exchange, alice_identity)
        for index in range(3):
            assert sender.send(
                _envelope(alice_identity, payload={"n": index})
            ).accepted
        receiver = FileBundleTransport(
            exchange,
            bob_identity,
            state_dir=exchange / ".state-bob",
            clock=lambda: NOW_MS,
        )

        assert receiver.poll() == []
        assert not (exchange / ".state-bob" / "imported.jsonl").exists()


def sender_transport_factory(exchange, identity):
    return FileBundleTransport(
        exchange, identity, state_dir=exchange / ".state-alice", clock=lambda: NOW_MS
    )


# ──────────────── adversarial review round 2 (bugs E + F + G) ────────────────


class TestReviewRoundTwo:
    def test_oversized_bundle_skipped_before_read(self, exchange, alice_identity, bob_identity, monkeypatch):
        """Bug E: a hostile courier drops a huge file — poll must stat-and-
        skip it without ever reading it into memory."""

        import nth_dao.delivery.transports.file_bundle as fb

        sender = FileBundleTransport(
            exchange, alice_identity, state_dir=exchange / ".state-alice", clock=lambda: NOW_MS
        )
        sender.send(_envelope(alice_identity))
        # hostile: a 64 KB junk bundle while the cap is patched down to 4 KB
        # (a legitimate single-envelope bundle is well under 4 KB)
        junk = exchange / "junk-big.nthbundle"
        junk.write_bytes(b"x" * 65_536)
        monkeypatch.setattr(fb, "BUNDLE_MAX_FILE_BYTES", 4_096)

        receiver = FileBundleTransport(
            exchange, bob_identity, state_dir=exchange / ".state-bob", clock=lambda: NOW_MS
        )
        received = receiver.poll()
        assert len(received) == 1  # good bundle survives, big junk skipped

    def test_no_tmp_leftovers_after_send(self, exchange, alice_identity):
        """Bug F: the atomic write must use a unique temp name and clean up —
        no .tmp-* files may linger after a send."""

        sender = FileBundleTransport(
            exchange, alice_identity, state_dir=exchange / ".state-alice", clock=lambda: NOW_MS
        )
        sender.send(_envelope(alice_identity))
        sender.send(_envelope(alice_identity, payload={"n": 2}))
        leftovers = list(exchange.glob(".tmp-*"))
        assert leftovers == []
        bundles = list(exchange.glob(f"*{BUNDLE_SUFFIX}"))
        assert len(bundles) == 2

    def test_version_bool_rejected(self, exchange, alice_identity, bob_identity):
        """Bug G: JSON `true` equals Python 1 — a bundle claiming
        version=true must be rejected by a strict type check."""

        from nth_dao.b64u import b64u_encode
        from nth_dao.delivery.transports.file_bundle import _bundle_body

        envelope = _envelope(alice_identity)
        envelope_json = canonical_json(envelope.to_dict()).decode("utf-8")
        import hashlib as _hashlib

        digest = "sha256:" + _hashlib.sha256(
            (envelope_json + "\n").encode("utf-8")
        ).hexdigest()
        bundle = {
            "protocol": "nth-delivery-file-bundle",
            "version": True,  # hostile: bool sneaks past `== 1`
            "sender_did": alice_identity.as_did(),
            "created_at_ms": NOW_MS,
            "envelopes": [envelope_json],
            "envelopes_sha256": digest,
        }
        bundle["signature"] = b64u_encode(
            alice_identity.sign(canonical_json(_bundle_body(bundle)))
        )
        # the exchange dir is created by the transports; receiver first so the
        # directory exists before the hostile bundle is dropped
        receiver = FileBundleTransport(
            exchange, bob_identity, state_dir=exchange / ".state-bob", clock=lambda: NOW_MS
        )
        path = exchange / "bundle-bool-version.nthbundle"
        path.write_bytes(canonical_json(bundle))
        assert receiver.poll() == []


# ──────────────── adversarial review round 3 (bug K) ────────────────


class TestImportJournalCrossProcess:
    def test_import_journal_loader_streams_bounded_lines(
        self, exchange, alice_identity, bob_identity, monkeypatch
    ):
        sender = sender_transport_factory(exchange, alice_identity)
        envelope = _envelope(alice_identity)
        assert sender.send(envelope).accepted is True
        state_dir = exchange / ".state-shared"
        first = FileBundleTransport(
            exchange, bob_identity, state_dir=state_dir, clock=lambda: NOW_MS
        )
        leased = first.poll()
        assert first.commit_import(leased[0].message_id) is True
        journal_path = state_dir / "imported.jsonl"
        original_read_bytes = type(journal_path).read_bytes

        def forbidden_read_bytes(path):
            if path == journal_path:
                raise AssertionError("import journal loading must stream bounded lines")
            return original_read_bytes(path)

        monkeypatch.setattr(type(journal_path), "read_bytes", forbidden_read_bytes)
        second = FileBundleTransport(
            exchange, bob_identity, state_dir=state_dir, clock=lambda: NOW_MS
        )
        assert second.poll() == []

    def test_import_journal_rejects_oversized_or_unknown_events(
        self, exchange, bob_identity
    ):
        state_dir = exchange / ".state-bob"
        state_dir.mkdir(parents=True)
        journal_path = state_dir / "imported.jsonl"
        journal_path.write_bytes(b"{" + b"x" * 5000 + b"}\n")

        with pytest.raises(FileBundleRejected, match="byte limit"):
            FileBundleTransport(
                exchange, bob_identity, state_dir=state_dir, clock=lambda: NOW_MS
            )

    def test_shared_state_dir_dedups_across_instances(self, exchange, alice_identity, bob_identity):
        """Bug K: two receiver processes sharing one state dir must dedup
        imports through the (now lock-protected) journal — a bundle imported
        by one is not re-imported by the other."""

        sender = FileBundleTransport(
            exchange, alice_identity, state_dir=exchange / ".state-alice", clock=lambda: NOW_MS
        )
        sender.send(_envelope(alice_identity))
        receiver_one = FileBundleTransport(
            exchange, bob_identity, state_dir=exchange / ".state-shared", clock=lambda: NOW_MS
        )
        receiver_two = FileBundleTransport(
            exchange, bob_identity, state_dir=exchange / ".state-shared", clock=lambda: NOW_MS
        )
        assert len(receiver_one.poll()) == 1
        # the second process folds the same journal: no double delivery
        import time as _t

        _t.sleep(0.02)
        assert receiver_two.poll() == []
