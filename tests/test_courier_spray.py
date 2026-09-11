"""Tests for Courier spray-and-wait replication bookkeeping."""

from __future__ import annotations

import time

import pytest

pytest.importorskip("nacl")

from nacl.signing import SigningKey  # noqa: E402

from nth_dao.delivery.courier import seal_courier_envelope  # noqa: E402
from nth_dao.delivery.courier_spray import CourierSpray, CourierSprayError  # noqa: E402
from nth_dao.delivery.courier_store import CourierStore  # noqa: E402
from nth_dao.delivery.envelope import sign_envelope  # noqa: E402
from nth_dao.did_key import encode_ed25519_did_key  # noqa: E402
from nth_dao.identity import AgentIdentity  # noqa: E402

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
        signing, did = _make_recipient()
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
        signing, did = _make_recipient()
        _, copies = _spray_copies(alice, did, 4)
        spray = CourierSpray(tmp_path / "spray", max_carriers=3)
        with pytest.raises(CourierSprayError, match="at most 3"):
            spray.register(message_id="m", carrier_copies=copies)

    def test_ciphertexts_differ_per_carrier(self, tmp_path, alice):
        """Each carrier gets its own ephemeral seal — carriers cannot tell
        they are carrying the same logical message."""

        signing, did = _make_recipient()
        _, copies = _spray_copies(alice, did, 3)
        cts = [c["ciphertext"] for c in copies.values()]
        assert len(set(cts)) == len(cts)


class TestCancelSiblings:
    def test_one_delivery_cancels_all_others(self, tmp_path, alice):
        signing, did = _make_recipient()
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
        signing, did = _make_recipient()
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

    def test_unknown_store_still_records_cancellation(self, tmp_path, alice):
        """A carrier absent from carrier_stores is cancelled in bookkeeping
        (the host could not reach the store, but the spray must not hang)."""

        signing, did = _make_recipient()
        _, copies = _spray_copies(alice, did, 2)
        spray = CourierSpray(tmp_path / "spray")
        spray_id = spray.register(message_id="m", carrier_copies=copies)
        cancelled = spray.cancel_siblings(
            spray_id, delivering_carrier="carrier-0", carrier_stores={}
        )
        assert cancelled == 1
        assert spray.pending_sprays() == []

    def test_unknown_spray_rejected(self, tmp_path):
        spray = CourierSpray(tmp_path / "spray")
        with pytest.raises(CourierSprayError, match="unknown spray"):
            spray.cancel_siblings("spray-nope", delivering_carrier="x", carrier_stores={})


class TestPersistence:
    def test_sprays_survive_restart(self, tmp_path, alice):
        signing, did = _make_recipient()
        _, copies = _spray_copies(alice, did, 2)
        spray = CourierSpray(tmp_path / "spray")
        spray.register(message_id="m", carrier_copies=copies)
        reloaded = CourierSpray(tmp_path / "spray")
        assert len(reloaded.pending_sprays()) == 1

    def test_completion_survives_restart(self, tmp_path, alice):
        signing, did = _make_recipient()
        _, copies = _spray_copies(alice, did, 2)
        spray = CourierSpray(tmp_path / "spray")
        spray_id = spray.register(message_id="m", carrier_copies=copies)
        spray.cancel_siblings(
            spray_id, delivering_carrier="carrier-0", carrier_stores={}
        )
        reloaded = CourierSpray(tmp_path / "spray")
        assert reloaded.pending_sprays() == []
        assert reloaded.stats()["sprays"] == 1

    def test_torn_tail_ignored(self, tmp_path, alice):
        signing, did = _make_recipient()
        _, copies = _spray_copies(alice, did, 1)
        spray = CourierSpray(tmp_path / "spray")
        spray.register(message_id="m", carrier_copies=copies)
        journal = tmp_path / "spray" / "spray.journal.jsonl"
        with open(journal, "ab") as handle:
            handle.write(b'{"event":"reg')
        reloaded = CourierSpray(tmp_path / "spray")
        assert len(reloaded.pending_sprays()) == 1

    def test_corrupt_journal_fails_closed(self, tmp_path, alice):
        signing, did = _make_recipient()
        _, copies = _spray_copies(alice, did, 1)
        spray = CourierSpray(tmp_path / "spray")
        spray.register(message_id="m", carrier_copies=copies)
        journal = tmp_path / "spray" / "spray.journal.jsonl"
        lines = journal.read_bytes().split(b"\n")
        lines[0] = b"{busted"
        journal.write_bytes(b"\n".join(lines))
        with pytest.raises(CourierSprayError, match="corrupt"):
            CourierSpray(tmp_path / "spray")


# ─────────────────── adversarial review round 22 (JJ-1) ───────────────────


class TestJournalDigestOnly:
    def test_journal_holds_no_ciphertext(self, tmp_path, alice):
        """Bug JJ-1: the spray journal must not persist courier ciphertexts
        (digests only) — no sensitive-material multiplication on disk."""

        signing, did = _make_recipient()
        _, copies = _spray_copies(alice, did, 2)
        spray = CourierSpray(tmp_path / "spray")
        spray.register(message_id="m", carrier_copies=copies)
        journal = (tmp_path / "spray" / "spray.journal.jsonl").read_text()
        for courier in copies.values():
            assert courier["ciphertext"][:40] not in journal
        assert "carrier_digests" in journal

    def test_restart_semantics_cancel_still_works(self, tmp_path, alice):
        """After a restart the in-memory carriers are gone (digest-only
        journal); cancel_siblings still records cancellations and completes
        the spray — the stores drop their copies via their own lifecycle."""

        signing, did = _make_recipient()
        _, copies = _spray_copies(alice, did, 2)
        spray = CourierSpray(tmp_path / "spray")
        spray_id = spray.register(message_id="m", carrier_copies=copies)
        reloaded = CourierSpray(tmp_path / "spray")  # restart: memory lost
        cancelled = reloaded.cancel_siblings(
            spray_id, delivering_carrier="carrier-0", carrier_stores={}
        )
        assert cancelled == 1
        assert reloaded.pending_sprays() == []
