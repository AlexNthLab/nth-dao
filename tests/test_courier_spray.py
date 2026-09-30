"""Tests for Courier spray-and-wait replication bookkeeping."""

from __future__ import annotations

import time

import pytest

pytest.importorskip("nacl")

from nacl.signing import SigningKey

from nth_dao.delivery.courier import seal_courier_envelope
from nth_dao.delivery.courier_spray import CourierSpray, CourierSprayError
from nth_dao.delivery.courier_store import CourierStore
from nth_dao.delivery.envelope import sign_envelope
from nth_dao.did_key import encode_ed25519_did_key
from nth_dao.identity import AgentIdentity

NOW_MS = int(time.time() * 1000)


@pytest.fixture()
def alice():
    return AgentIdentity.generate(label="alice")


def _make_recipient():
    signing = SigningKey(b"\x06" * 32)
    did = encode_ed25519_did_key(signing.verify_key.encode())
    return signing, did


def _spray_copies(alice, did, count):
    """Seal one envelope per carrier (distinct ciphertexts per seal)."""

    envelope = sign_envelope(
        alice,
        kind="channel.message",
        recipient="dao:core",
        payload={"spray": True},
        created_at_ms=NOW_MS,
        expires_at_ms=NOW_MS + 3_600_000,
    )
    copies = {}
    for i in range(count):
        copies[f"carrier-{i}"] = seal_courier_envelope(envelope, recipient_did=did)
    return envelope, copies


class TestRegister:
    def test_register_returns_spray_id(self, tmp_path, alice):
        _signing, did = _make_recipient()
        _, copies = _spray_copies(alice, did, 3)
        spray = CourierSpray(tmp_path / "spray")
        spray_id = spray.register(message_id="sha256:" + "a" * 64, carrier_copies=copies)
        assert spray_id.startswith("spray-")
        assert len(spray.pending_sprays()) == 1
        assert set(spray.pending_sprays()[0]["carriers"]) == set(copies)

    def test_empty_copies_rejected(self, tmp_path):
        spray = CourierSpray(tmp_path / "spray")
        with pytest.raises(CourierSprayError, match="non-empty"):
            spray.register(message_id="m", carrier_copies={})

    def test_carrier_cap_enforced(self, tmp_path, alice):
        _signing, did = _make_recipient()
        _, copies = _spray_copies(alice, did, 4)
        spray = CourierSpray(tmp_path / "spray", max_carriers=3)
        with pytest.raises(CourierSprayError, match="at most 3"):
            spray.register(message_id="m", carrier_copies=copies)

    def test_pending_spray_cap_is_cross_instance(self, tmp_path, alice):
        _signing, did = _make_recipient()
        _, first_copy = _spray_copies(alice, did, 1)
        _, second_copy = _spray_copies(alice, did, 1)
        directory = tmp_path / "spray"
        first = CourierSpray(directory, max_sprays=1)
        stale = CourierSpray(directory, max_sprays=1)

        first.register(message_id="m1", carrier_copies=first_copy)

        with pytest.raises(CourierSprayError, match="pending-spray quota"):
            stale.register(message_id="m2", carrier_copies=second_copy)

    @pytest.mark.parametrize(
        ("message_id", "carrier_copies", "match"),
        [
            ("m" * 257, {"carrier": {}}, "message_id"),
            ("m", {"c" * 129: {}}, "carrier name"),
            ("m", {"bad\ncarrier": {}}, "carrier name"),
        ],
    )
    def test_metadata_bounds(self, tmp_path, message_id, carrier_copies, match):
        spray = CourierSpray(tmp_path / "spray")
        with pytest.raises(CourierSprayError, match=match):
            spray.register(message_id=message_id, carrier_copies=carrier_copies)

    def test_non_courier_copy_rejected(self, tmp_path):
        spray = CourierSpray(tmp_path / "spray")
        with pytest.raises(CourierSprayError, match="carrier copy"):
            spray.register(message_id="m", carrier_copies={"carrier": {}})

    def test_ciphertexts_differ_per_carrier(self, tmp_path, alice):
        """Each carrier gets its own ephemeral seal — carriers cannot tell
        they are carrying the same logical message."""

        _signing, did = _make_recipient()
        _, copies = _spray_copies(alice, did, 3)
        cts = [c["ciphertext"] for c in copies.values()]
        assert len(set(cts)) == len(cts)


class TestCancelSiblings:
    def test_one_delivery_cancels_all_others(self, tmp_path, alice):
        _signing, did = _make_recipient()
        _, copies = _spray_copies(alice, did, 3)
        spray = CourierSpray(tmp_path / "spray")
        spray_id = spray.register(message_id="m1", carrier_copies=copies)

        stores = {}
        for name, courier in copies.items():
            store = CourierStore(tmp_path / name)
            store.seal_into(courier)
            stores[name] = store

        cancelled = spray.cancel_siblings(
            spray_id, delivering_carrier="carrier-0", carrier_stores=stores
        )
        assert cancelled == 2
        # carrier-0 still holds its copy; the others are emptied
        assert stores["carrier-0"].stats()["envelopes"] == 1
        assert stores["carrier-1"].stats()["envelopes"] == 0
        assert stores["carrier-2"].stats()["envelopes"] == 0
        assert spray.pending_sprays() == []

    def test_double_completion_is_noop(self, tmp_path, alice):
        _signing, did = _make_recipient()
        _, copies = _spray_copies(alice, did, 2)
        spray = CourierSpray(tmp_path / "spray")
        spray_id = spray.register(message_id="m", carrier_copies=copies)
        stores = {
            name: CourierStore(tmp_path / name) for name in copies
        }
        for name, courier in copies.items():
            stores[name].seal_into(courier)
        first = spray.cancel_siblings(
            spray_id, delivering_carrier="carrier-0", carrier_stores=stores
        )
        second = spray.cancel_siblings(
            spray_id, delivering_carrier="carrier-0", carrier_stores=stores
        )
        assert first == 1 and second == 0

    def test_unknown_store_remains_pending(self, tmp_path, alice):
        """An unreachable carrier must not be reported as cancelled."""

        _signing, did = _make_recipient()
        _, copies = _spray_copies(alice, did, 2)
        spray = CourierSpray(tmp_path / "spray")
        spray_id = spray.register(message_id="m", carrier_copies=copies)
        cancelled = spray.cancel_siblings(
            spray_id, delivering_carrier="carrier-0", carrier_stores={}
        )
        assert cancelled == 0
        pending = spray.pending_sprays()
        assert len(pending) == 1
        assert pending[0]["carriers"] == ["carrier-1"]

    def test_unknown_spray_rejected(self, tmp_path):
        spray = CourierSpray(tmp_path / "spray")
        with pytest.raises(CourierSprayError, match="unknown spray"):
            spray.cancel_siblings("spray-nope", delivering_carrier="x", carrier_stores={})


class TestPersistence:
    def test_sprays_survive_restart(self, tmp_path, alice):
        _signing, did = _make_recipient()
        _, copies = _spray_copies(alice, did, 2)
        spray = CourierSpray(tmp_path / "spray")
        spray.register(message_id="m", carrier_copies=copies)
        reloaded = CourierSpray(tmp_path / "spray")
        assert len(reloaded.pending_sprays()) == 1

    def test_completion_survives_restart(self, tmp_path, alice):
        _signing, did = _make_recipient()
        _, copies = _spray_copies(alice, did, 2)
        spray = CourierSpray(tmp_path / "spray")
        spray_id = spray.register(message_id="m", carrier_copies=copies)
        stores = {name: CourierStore(tmp_path / name) for name in copies}
        for name, courier in copies.items():
            stores[name].seal_into(courier)
        spray.cancel_siblings(
            spray_id, delivering_carrier="carrier-0", carrier_stores=stores
        )
        reloaded = CourierSpray(tmp_path / "spray")
        assert reloaded.pending_sprays() == []
        assert reloaded.stats()["sprays"] == 1

    def test_torn_tail_ignored(self, tmp_path, alice):
        _signing, did = _make_recipient()
        _, copies = _spray_copies(alice, did, 1)
        spray = CourierSpray(tmp_path / "spray")
        spray.register(message_id="m", carrier_copies=copies)
        journal = tmp_path / "spray" / "spray.journal.jsonl"
        with open(journal, "ab") as handle:
            handle.write(b'{"event":"reg')
        reloaded = CourierSpray(tmp_path / "spray")
        assert len(reloaded.pending_sprays()) == 1

    def test_corrupt_journal_fails_closed(self, tmp_path, alice):
        _signing, did = _make_recipient()
        _, copies = _spray_copies(alice, did, 1)
        spray = CourierSpray(tmp_path / "spray")
        spray.register(message_id="m", carrier_copies=copies)
        journal = tmp_path / "spray" / "spray.journal.jsonl"
        lines = journal.read_bytes().split(b"\n")
        lines[0] = b"{busted"
        journal.write_bytes(b"\n".join(lines))
        with pytest.raises(CourierSprayError, match="corrupt"):
            CourierSpray(tmp_path / "spray")

    def test_non_object_event_fails_closed(self, tmp_path):
        directory = tmp_path / "spray"
        directory.mkdir()
        (directory / "spray.journal.jsonl").write_bytes(b"[]\n")

        with pytest.raises(CourierSprayError, match="not an object"):
            CourierSpray(directory)

    def test_oversized_journal_is_bounded_before_read(self, tmp_path, monkeypatch):
        import nth_dao.delivery.courier_spray as spray_module

        directory = tmp_path / "spray"
        directory.mkdir()
        monkeypatch.setattr(spray_module, "_JOURNAL_MAX_BYTES", 64)
        monkeypatch.setattr(spray_module, "_JOURNAL_RECOVERY_SLACK_BYTES", 16)
        (directory / "spray.journal.jsonl").write_bytes(b"x" * 81)

        with pytest.raises(CourierSprayError, match="bounded.*limit"):
            CourierSpray(directory)

    def test_registered_event_schema_is_validated(self, tmp_path):
        from nth_dao.canonical_json import canonical_json

        directory = tmp_path / "spray"
        directory.mkdir()
        event = {
            "event": "registered",
            "spray_id": "not-a-spray-id",
            "message_id": "m",
            "carrier_digests": {"carrier": "not-a-digest"},
            "created_at_ms": NOW_MS,
        }
        (directory / "spray.journal.jsonl").write_bytes(
            canonical_json(event) + b"\n"
        )

        with pytest.raises(CourierSprayError, match="registered event"):
            CourierSpray(directory)

    def test_long_lived_instance_observes_external_registration(
        self, tmp_path, alice
    ):
        _signing, did = _make_recipient()
        _, copies = _spray_copies(alice, did, 1)
        directory = tmp_path / "spray"
        reader = CourierSpray(directory)
        writer = CourierSpray(directory)

        spray_id = writer.register(message_id="m", carrier_copies=copies)

        assert reader.stats() == {"sprays": 1, "pending": 1}
        assert reader.pending_sprays()[0]["spray_id"] == spray_id

    def test_completed_history_is_bounded_and_compacted(self, tmp_path, alice):
        _signing, did = _make_recipient()
        directory = tmp_path / "spray"
        spray = CourierSpray(directory, max_sprays=1, max_history=2)
        completed_ids = []
        for index in range(4):
            _, copies = _spray_copies(alice, did, 1)
            spray_id = spray.register(
                message_id=f"m-{index}", carrier_copies=copies
            )
            spray.cancel_siblings(
                spray_id,
                delivering_carrier="carrier-0",
                carrier_stores={},
            )
            completed_ids.append(spray_id)

        reloaded = CourierSpray(directory, max_sprays=1, max_history=2)

        assert reloaded.stats() == {"sprays": 2, "pending": 0}
        with pytest.raises(CourierSprayError, match="unknown spray"):
            reloaded.cancel_siblings(
                completed_ids[0],
                delivering_carrier="carrier-0",
                carrier_stores={},
            )

    def test_compaction_preserves_pending_digest_state(self, tmp_path, alice):
        _signing, did = _make_recipient()
        _, copies = _spray_copies(alice, did, 2)
        directory = tmp_path / "spray"
        spray = CourierSpray(directory)
        spray_id = spray.register(message_id="m", carrier_copies=copies)

        spray.compact()
        reloaded = CourierSpray(directory)

        assert reloaded.pending_sprays() == [{
            "spray_id": spray_id,
            "message_id": "m",
            "carriers": ["carrier-0", "carrier-1"],
            "created_at_ms": spray.pending_sprays()[0]["created_at_ms"],
        }]


# ─────────────────── adversarial review round 22 (JJ-1) ───────────────────


class TestJournalDigestOnly:
    def test_journal_holds_no_ciphertext(self, tmp_path, alice):
        """Bug JJ-1: the spray journal must not persist courier ciphertexts
        (digests only) — no sensitive-material multiplication on disk."""

        _signing, did = _make_recipient()
        _, copies = _spray_copies(alice, did, 2)
        spray = CourierSpray(tmp_path / "spray")
        spray.register(message_id="m", carrier_copies=copies)
        journal = (tmp_path / "spray" / "spray.journal.jsonl").read_text()
        for courier in copies.values():
            assert courier["ciphertext"][:40] not in journal
        assert "carrier_digests" in journal

    def test_restart_semantics_cancel_removes_persisted_copy(self, tmp_path, alice):
        """Persisted digests let a restarted spray delete exact siblings."""

        _signing, did = _make_recipient()
        _, copies = _spray_copies(alice, did, 2)
        spray = CourierSpray(tmp_path / "spray")
        spray_id = spray.register(message_id="m", carrier_copies=copies)
        stores = {name: CourierStore(tmp_path / name) for name in copies}
        for name, courier in copies.items():
            stores[name].seal_into(courier)
        reloaded = CourierSpray(tmp_path / "spray")  # restart: memory lost
        cancelled = reloaded.cancel_siblings(
            spray_id, delivering_carrier="carrier-0", carrier_stores=stores
        )
        assert cancelled == 1
        assert stores["carrier-1"].stats()["envelopes"] == 0
        assert reloaded.pending_sprays() == []
