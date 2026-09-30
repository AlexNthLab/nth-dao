"""Tests for the Courier store — quota-bounded sealed envelope pool."""

from __future__ import annotations

import time

import pytest

pytest.importorskip("nacl")

from nacl.signing import SigningKey

from nth_dao.delivery.courier import (
    seal_courier_envelope,
)
from nth_dao.delivery.courier_store import (
    CourierStore,
    CourierStoreError,
    CourierStoreFull,
)
from nth_dao.delivery.envelope import sign_envelope
from nth_dao.did_key import encode_ed25519_did_key
from nth_dao.identity import AgentIdentity

NOW_MS = int(time.time() * 1000)


@pytest.fixture()
def alice():
    return AgentIdentity.generate(label="alice")


@pytest.fixture()
def bob_keys():
    signing = SigningKey(b"\x01" * 32)
    did = encode_ed25519_did_key(signing.verify_key.encode())
    return signing, did


def _courier(alice, bob_did, n=0):
    envelope = sign_envelope(
        alice,
        kind="channel.message",
        recipient="dao:core",
        payload={"n": n},
        created_at_ms=NOW_MS,
        expires_at_ms=NOW_MS + 3_600_000,
    )
    return seal_courier_envelope(envelope, recipient_did=bob_did)


class TestQuotas:
    def test_seal_into_and_drain(self, tmp_path, alice, bob_keys):
        _signing, did = bob_keys
        store = CourierStore(tmp_path / "carrier")
        digest = store.seal_into(_courier(alice, did))
        assert digest.startswith("sha256:")
        drained = store.drain_for(did)
        assert len(drained) == 1
        assert store.stats()["envelopes"] == 1

    def test_total_bytes_quota_fail_closed(self, tmp_path, alice, bob_keys):
        _signing, did = bob_keys
        store = CourierStore(tmp_path / "carrier", max_total_bytes=1)
        with pytest.raises(CourierStoreFull, match="total-bytes"):
            store.seal_into(_courier(alice, did))

    def test_envelope_count_quota(self, tmp_path, alice, bob_keys):
        _signing, did = bob_keys
        store = CourierStore(tmp_path / "carrier", max_envelopes=2)
        store.seal_into(_courier(alice, did, n=1))
        store.seal_into(_courier(alice, did, n=2))
        with pytest.raises(CourierStoreFull, match="envelope-count"):
            store.seal_into(_courier(alice, did, n=3))

    def test_per_recipient_quota(self, tmp_path, alice, bob_keys):
        _signing, did = bob_keys
        store = CourierStore(tmp_path / "carrier", max_per_recipient=2, max_envelopes=100)
        store.seal_into(_courier(alice, did, n=1))
        store.seal_into(_courier(alice, did, n=2))
        with pytest.raises(CourierStoreFull, match="per-recipient"):
            store.seal_into(_courier(alice, did, n=3))

    def test_oversized_metadata_is_rejected_before_persistence(
        self, tmp_path, alice, bob_keys
    ):
        _signing, did = bob_keys
        directory = tmp_path / "carrier"
        store = CourierStore(directory)
        courier = _courier(alice, did)
        courier["courier_id"] = "x" * 100_000

        with pytest.raises(CourierStoreError, match="courier_id"):
            store.seal_into(courier)
        assert not (directory / "courier.journal.jsonl").exists()

    def test_corrupt_ciphertext_integrity_is_rejected_before_persistence(
        self, tmp_path, alice, bob_keys
    ):
        _signing, did = bob_keys
        store = CourierStore(tmp_path / "carrier")
        courier = _courier(alice, did)
        replacement = "A" if courier["ciphertext"][0] != "A" else "B"
        courier["ciphertext"] = replacement + courier["ciphertext"][1:]

        with pytest.raises(CourierStoreError, match="integrity"):
            store.seal_into(courier)

    def test_seal_time_must_be_positive_integer(self, tmp_path, alice, bob_keys):
        _signing, did = bob_keys
        store = CourierStore(tmp_path / "carrier")
        with pytest.raises(CourierStoreError, match="now_ms"):
            store.seal_into(_courier(alice, did), now_ms=False)


class TestHandover:
    def test_handover_removes_envelope(self, tmp_path, alice, bob_keys):
        _signing, did = bob_keys
        store = CourierStore(tmp_path / "carrier")
        courier = _courier(alice, did)
        store.seal_into(courier)
        store.hand_over(courier)
        assert store.drain_for(did) == []
        assert store.stats()["envelopes"] == 0

    def test_handover_unknown_rejected(self, tmp_path, alice, bob_keys):
        _signing, did = bob_keys
        store = CourierStore(tmp_path / "carrier")
        with pytest.raises(CourierStoreError, match="not in pool"):
            store.hand_over(_courier(alice, did))

    def test_discard_digest_is_idempotent(self, tmp_path, alice, bob_keys):
        _signing, did = bob_keys
        store = CourierStore(tmp_path / "carrier")
        digest = store.seal_into(_courier(alice, did))

        assert store.discard_digest(digest) is True
        assert store.discard_digest(digest) is False
        assert store.stats()["envelopes"] == 0

    def test_discard_rejects_malformed_digest(self, tmp_path):
        store = CourierStore(tmp_path / "carrier")
        with pytest.raises(CourierStoreError, match="digest"):
            store.discard_digest("sha256:not-a-digest")

    def test_drain_isolates_recipients(self, tmp_path, alice, bob_keys):
        _signing_bob, bob_did = bob_keys
        carol_signing = SigningKey(b"\x02" * 32)
        carol_did = encode_ed25519_did_key(carol_signing.verify_key.encode())
        store = CourierStore(tmp_path / "carrier")
        store.seal_into(_courier(alice, bob_did))
        store.seal_into(_courier(alice, carol_did))
        assert len(store.drain_for(bob_did)) == 1
        assert len(store.drain_for(carol_did)) == 1

    def test_drain_requires_positive_max_items(self, tmp_path, bob_keys):
        _signing, did = bob_keys
        store = CourierStore(tmp_path / "carrier")
        with pytest.raises(CourierStoreError, match="max_items"):
            store.drain_for(did, max_items=0)


class TestPersistence:
    def test_pool_survives_restart(self, tmp_path, alice, bob_keys):
        _signing, did = bob_keys
        store = CourierStore(tmp_path / "carrier")
        courier = _courier(alice, did)
        store.seal_into(courier)
        reloaded = CourierStore(tmp_path / "carrier")
        assert len(reloaded.drain_for(did)) == 1
        assert reloaded.stats()["envelopes"] == 1

    def test_handover_survives_restart(self, tmp_path, alice, bob_keys):
        _signing, did = bob_keys
        store = CourierStore(tmp_path / "carrier")
        courier = _courier(alice, did)
        store.seal_into(courier)
        store.hand_over(courier)
        reloaded = CourierStore(tmp_path / "carrier")
        assert reloaded.drain_for(did) == []

    def test_idempotent_reseal(self, tmp_path, alice, bob_keys):
        _signing, did = bob_keys
        store = CourierStore(tmp_path / "carrier")
        courier = _courier(alice, did)
        first = store.seal_into(courier)
        second = store.seal_into(courier)
        assert first == second
        assert store.stats()["envelopes"] == 1

    def test_torn_tail_ignored(self, tmp_path, alice, bob_keys):
        _signing, did = bob_keys
        store = CourierStore(tmp_path / "carrier")
        store.seal_into(_courier(alice, did))
        journal = tmp_path / "carrier" / "courier.journal.jsonl"
        with open(journal, "ab") as handle:
            handle.write(b'{"event":"seal')
        reloaded = CourierStore(tmp_path / "carrier")
        assert reloaded.stats()["envelopes"] == 1

    def test_corrupt_journal_fails_closed(self, tmp_path, alice, bob_keys):
        _signing, did = bob_keys
        store = CourierStore(tmp_path / "carrier")
        store.seal_into(_courier(alice, did))
        journal = tmp_path / "carrier" / "courier.journal.jsonl"
        lines = journal.read_bytes().split(b"\n")
        lines[0] = b"{busted"
        journal.write_bytes(b"\n".join(lines))
        with pytest.raises(CourierStoreError, match="corrupt"):
            CourierStore(tmp_path / "carrier")

    def test_non_object_journal_event_fails_closed(self, tmp_path):
        directory = tmp_path / "carrier"
        directory.mkdir()
        (directory / "courier.journal.jsonl").write_bytes(b"[]\n")

        with pytest.raises(CourierStoreError, match="not an object"):
            CourierStore(directory)

    def test_sealed_digest_mismatch_fails_closed(
        self, tmp_path, alice, bob_keys
    ):
        from nth_dao.canonical_json import canonical_json

        _signing, did = bob_keys
        directory = tmp_path / "carrier"
        directory.mkdir()
        event = {
            "event": "sealed",
            "digest": "sha256:" + "0" * 64,
            "envelope": _courier(alice, did),
            "sealed_at_ms": NOW_MS,
        }
        (directory / "courier.journal.jsonl").write_bytes(
            canonical_json(event) + b"\n"
        )

        with pytest.raises(CourierStoreError, match="digest mismatch"):
            CourierStore(directory)


class TestRotationSafety:
    def test_oversized_restart_compacts_without_losing_live_entries(
        self, tmp_path, alice, bob_keys, monkeypatch
    ):
        import nth_dao.delivery.courier_store as store_module
        from nth_dao.canonical_json import canonical_json

        _signing, did = bob_keys
        directory = tmp_path / "carrier"
        store = CourierStore(directory)
        store.seal_into(_courier(alice, did))
        journal = directory / "courier.journal.jsonl"
        live_size = journal.stat().st_size
        with open(journal, "ab") as handle:
            handle.write(canonical_json({
                "event": "handed_over",
                "digest": "sha256:" + "0" * 64,
            }) + b"\n")
        assert journal.stat().st_size > live_size
        monkeypatch.setattr(store_module, "_JOURNAL_MAX_BYTES", live_size + 1)

        reloaded = CourierStore(directory)

        assert reloaded.stats()["envelopes"] == 1
        assert journal.stat().st_size <= live_size + 1

    def test_stale_instance_rotation_preserves_other_process_append(
        self, tmp_path, alice, bob_keys
    ):
        _signing, did = bob_keys
        directory = tmp_path / "carrier"
        stale = CourierStore(directory)
        stale.seal_into(_courier(alice, did, n=1))
        concurrent = CourierStore(directory)
        concurrent.seal_into(_courier(alice, did, n=2))

        stale._rotate_from_memory()

        assert CourierStore(directory).stats()["envelopes"] == 2


# ─────────────────── adversarial review round 23 (KK-9) ───────────────────


class TestCrossProcessQuota:
    def test_two_processes_cannot_bypass_quota(self, tmp_path):
        """Bug KK-9: two processes sealing into the same directory each saw
        only their own memory state and both passed the quota. seal_into now
        re-parses the journal under the file lock before checking."""

        import subprocess
        import sys

        directory = tmp_path / "carrier"
        code = (
            "import sys\n"
            "from nth_dao.delivery.courier_store import CourierStore, CourierStoreFull\n"
            f"store = CourierStore({str(directory)!r}, max_envelopes=1)\n"
            "from nth_dao.identity import AgentIdentity\n"
            "from nth_dao.delivery.envelope import sign_envelope\n"
            "from nth_dao.delivery.courier import seal_courier_envelope\n"
            "import time\n"
            "NOW = int(time.time()*1000)\n"
            "ident = AgentIdentity.generate(label=sys.argv[1])\n"
            "env = sign_envelope(ident, kind='k.a', recipient='dao:c', payload={'n':1},\n"
            "    created_at_ms=NOW, expires_at_ms=NOW+60000)\n"
            "try:\n"
            "    store.seal_into(seal_courier_envelope(env, recipient_did=ident.as_did()))\n"
            "    print('sealed')\n"
            "except CourierStoreFull:\n"
            "    print('rejected')\n"
        )
        procs = [
            subprocess.Popen(
                [sys.executable, "-c", code, name],
                stdout=subprocess.PIPE, text=True,
            )
            for name in ("A", "B")
        ]
        outputs = [proc.communicate(timeout=30)[0].strip() for proc in procs]
        outcomes = sorted(outputs)
        assert outcomes == ["rejected", "sealed"], outputs
        journal = directory / "courier.journal.jsonl"
        lines = [line for line in journal.read_bytes().split(b"\n") if line.strip()]
        assert len(lines) == 1  # quota=1 held across processes


class TestCrossProcessVisibility:
    def test_long_lived_reader_observes_and_removes_external_append(
        self, tmp_path, alice, bob_keys
    ):
        _signing, did = bob_keys
        directory = tmp_path / "carrier"
        reader = CourierStore(directory)
        writer = CourierStore(directory)
        courier = _courier(alice, did)

        writer.seal_into(courier)

        assert reader.stats()["envelopes"] == 1
        assert reader.drain_for(did) == [courier]
        reader.hand_over(courier)
        assert CourierStore(directory).stats()["envelopes"] == 0
