"""Tests for the Courier store — quota-bounded sealed envelope pool."""

from __future__ import annotations

import time

import pytest

pytest.importorskip("nacl")

from nacl.signing import SigningKey  # noqa: E402

from nth_dao.delivery.courier import (  # noqa: E402
    seal_courier_envelope,
)
from nth_dao.delivery.courier_store import (  # noqa: E402
    CourierStore,
    CourierStoreError,
    CourierStoreFull,
)
from nth_dao.delivery.envelope import sign_envelope  # noqa: E402
from nth_dao.did_key import encode_ed25519_did_key  # noqa: E402
from nth_dao.identity import AgentIdentity  # noqa: E402

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
        signing, did = bob_keys
        store = CourierStore(tmp_path / "carrier")
        digest = store.seal_into(_courier(alice, did))
        assert digest.startswith("sha256:")
        drained = store.drain_for(did)
        assert len(drained) == 1
        assert store.stats()["envelopes"] == 1

    def test_total_bytes_quota_fail_closed(self, tmp_path, alice, bob_keys):
        signing, did = bob_keys
        store = CourierStore(tmp_path / "carrier", max_total_bytes=1)
        with pytest.raises(CourierStoreFull, match="total-bytes"):
            store.seal_into(_courier(alice, did))

    def test_envelope_count_quota(self, tmp_path, alice, bob_keys):
        signing, did = bob_keys
        store = CourierStore(tmp_path / "carrier", max_envelopes=2)
        store.seal_into(_courier(alice, did, n=1))
        store.seal_into(_courier(alice, did, n=2))
        with pytest.raises(CourierStoreFull, match="envelope-count"):
            store.seal_into(_courier(alice, did, n=3))

    def test_per_recipient_quota(self, tmp_path, alice, bob_keys):
        signing, did = bob_keys
        store = CourierStore(tmp_path / "carrier", max_per_recipient=2, max_envelopes=100)
        store.seal_into(_courier(alice, did, n=1))
        store.seal_into(_courier(alice, did, n=2))
        with pytest.raises(CourierStoreFull, match="per-recipient"):
            store.seal_into(_courier(alice, did, n=3))


class TestHandover:
    def test_handover_removes_envelope(self, tmp_path, alice, bob_keys):
        signing, did = bob_keys
        store = CourierStore(tmp_path / "carrier")
        courier = _courier(alice, did)
        store.seal_into(courier)
        store.hand_over(courier)
        assert store.drain_for(did) == []
        assert store.stats()["envelopes"] == 0

    def test_handover_unknown_rejected(self, tmp_path, alice, bob_keys):
        signing, did = bob_keys
        store = CourierStore(tmp_path / "carrier")
        with pytest.raises(CourierStoreError, match="not in pool"):
            store.hand_over(_courier(alice, did))

    def test_drain_isolates_recipients(self, tmp_path, alice, bob_keys):
        signing_bob, bob_did = bob_keys
        carol_signing = SigningKey(b"\x02" * 32)
        carol_did = encode_ed25519_did_key(carol_signing.verify_key.encode())
        store = CourierStore(tmp_path / "carrier")
        store.seal_into(_courier(alice, bob_did))
        store.seal_into(_courier(alice, carol_did))
        assert len(store.drain_for(bob_did)) == 1
        assert len(store.drain_for(carol_did)) == 1


class TestPersistence:
    def test_pool_survives_restart(self, tmp_path, alice, bob_keys):
        signing, did = bob_keys
        store = CourierStore(tmp_path / "carrier")
        courier = _courier(alice, did)
        store.seal_into(courier)
        reloaded = CourierStore(tmp_path / "carrier")
        assert len(reloaded.drain_for(did)) == 1
        assert reloaded.stats()["envelopes"] == 1

    def test_handover_survives_restart(self, tmp_path, alice, bob_keys):
        signing, did = bob_keys
        store = CourierStore(tmp_path / "carrier")
        courier = _courier(alice, did)
        store.seal_into(courier)
        store.hand_over(courier)
        reloaded = CourierStore(tmp_path / "carrier")
        assert reloaded.drain_for(did) == []

    def test_idempotent_reseal(self, tmp_path, alice, bob_keys):
        signing, did = bob_keys
        store = CourierStore(tmp_path / "carrier")
        courier = _courier(alice, did)
        first = store.seal_into(courier)
        second = store.seal_into(courier)
        assert first == second
        assert store.stats()["envelopes"] == 1

    def test_torn_tail_ignored(self, tmp_path, alice, bob_keys):
        signing, did = bob_keys
        store = CourierStore(tmp_path / "carrier")
        store.seal_into(_courier(alice, did))
        journal = tmp_path / "carrier" / "courier.journal.jsonl"
        with open(journal, "ab") as handle:
            handle.write(b'{"event":"seal')
        reloaded = CourierStore(tmp_path / "carrier")
        assert reloaded.stats()["envelopes"] == 1

    def test_corrupt_journal_fails_closed(self, tmp_path, alice, bob_keys):
        signing, did = bob_keys
        store = CourierStore(tmp_path / "carrier")
        store.seal_into(_courier(alice, did))
        journal = tmp_path / "carrier" / "courier.journal.jsonl"
        lines = journal.read_bytes().split(b"\n")
        lines[0] = b"{busted"
        journal.write_bytes(b"\n".join(lines))
        with pytest.raises(CourierStoreError, match="corrupt"):
            CourierStore(tmp_path / "carrier")


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
