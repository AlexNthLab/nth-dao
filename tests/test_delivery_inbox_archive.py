"""Completed history must not consume active queue slots or lose replay safety."""

from __future__ import annotations

import json
import multiprocessing
import os

import pytest

from nth_dao.canonical_json import canonical_json
from nth_dao.delivery.envelope import sign_envelope
from nth_dao.delivery.inbox import DeliveryInbox, DeliveryInboxCacheCorrupt
from nth_dao.identity import AgentIdentity

pytest.importorskip("nacl")
NOW = 1_750_000_000_000


def _archive_writer(directory, index, start, output):
    try:
        identity = AgentIdentity.generate(label=f"archive-worker-{index}")
        inbox = DeliveryInbox(directory, clock=lambda: NOW, max_replay_entries=4,
                              archive_processed=True, reject_links=True)
        if not start.wait(20):
            raise RuntimeError("archive test start timed out")
        packets = []
        for counter in range(4):
            packet = sign_envelope(identity, kind="chat.message", recipient=identity.as_did(),
                                   payload={"worker": index, "counter": counter},
                                   created_at_ms=NOW, expires_at_ms=NOW + 60_000)
            if not inbox.accept(packet).accepted:
                raise RuntimeError("archive test intake failed")
            inbox.mark_processed(packet.message_id)
            packets.append(packet.to_dict())
        output.put((True, packets))
    except (OSError, TypeError, ValueError, RuntimeError) as exc:
        output.put((False, f"{type(exc).__name__}: {exc}"))


def test_completed_archive_bounds_active_cache_and_preserves_nonce_after_restart(tmp_path):
    identity = AgentIdentity.generate(label="archive-test")
    directory = tmp_path / "inbox"
    inbox = DeliveryInbox(directory, clock=lambda: NOW, max_replay_entries=2,
                          archive_processed=True, reject_links=True)
    first = None
    for index in range(5):
        envelope = sign_envelope(identity, kind="chat.message", recipient=identity.as_did(),
                                 payload={"index": index}, created_at_ms=NOW, expires_at_ms=NOW + 60_000)
        first = first or envelope
        assert inbox.accept(envelope).accepted
        inbox.mark_processed(envelope.message_id)
    assert inbox.entry_count() == 2 and inbox.pending() == []
    restarted = DeliveryInbox(directory, clock=lambda: NOW, max_replay_entries=2,
                              archive_processed=True, reject_links=True)
    assert restarted.accept(first).duplicate
    assert restarted.retained_duplicate(canonical_json(first.to_dict()).decode()).duplicate
    changed = sign_envelope(identity, kind="chat.message", recipient=identity.as_did(),
                            payload={"different": True}, nonce=first.nonce,
                            created_at_ms=NOW, expires_at_ms=NOW + 60_000)
    assert restarted.accept(changed).replayed
    assert restarted.retained_entry(first.message_id).envelope.to_dict() == first.to_dict()


def test_archive_still_applies_backpressure_to_pending_work(tmp_path):
    identity = AgentIdentity.generate(label="pending-test")
    inbox = DeliveryInbox(tmp_path, clock=lambda: NOW, max_replay_entries=1, archive_processed=True)
    def packet(index):
        return sign_envelope(identity, kind="chat.message", recipient=identity.as_did(),
                             payload={"index": index}, created_at_ms=NOW, expires_at_ms=NOW + 60_000)
    first, second = packet(1), packet(2)
    assert inbox.accept(first).accepted
    decision = inbox.accept(second)
    assert not decision.accepted and decision.retryable
    assert inbox.pending()[0].message_id == first.message_id


def test_archive_crash_before_nonce_pointer_keeps_pending_and_exact_retry_repairs(tmp_path, monkeypatch):
    identity = AgentIdentity.generate(label="archive-crash")
    inbox = DeliveryInbox(tmp_path, clock=lambda: NOW, max_replay_entries=1, archive_processed=True)
    envelope = sign_envelope(identity, kind="chat.message", recipient=identity.as_did(),
                             payload={}, created_at_ms=NOW, expires_at_ms=NOW + 60_000)
    assert inbox.accept(envelope).accepted
    retain = inbox._archive._retain
    def fail_nonce(path, raw):
        if "nonces" in path.parts:
            raise OSError("injected nonce pointer failure")
        retain(path, raw)
    with monkeypatch.context() as patch:
        patch.setattr(inbox._archive, "_retain", fail_nonce)
        with pytest.raises(OSError, match="pointer failure"):
            inbox.mark_processed(envelope.message_id)
    assert inbox.pending()[0].message_id == envelope.message_id
    assert inbox.mark_processed(envelope.message_id)
    assert inbox.retained_entry(envelope.message_id).accepted_at_ms == NOW


def test_archived_nonce_corruption_fails_closed_after_eviction(tmp_path):
    identity = AgentIdentity.generate(label="archive-corrupt")
    inbox = DeliveryInbox(tmp_path, clock=lambda: NOW, max_replay_entries=1, archive_processed=True)
    packets = [sign_envelope(identity, kind="chat.message", recipient=identity.as_did(),
                            payload={"index": index}, created_at_ms=NOW, expires_at_ms=NOW + 60_000)
               for index in range(2)]
    for packet in packets:
        assert inbox.accept(packet).accepted
        inbox.mark_processed(packet.message_id)
    inbox._archive._nonce_path(identity.as_did(), packets[0].nonce).write_bytes(b"{}")
    with pytest.raises(DeliveryInboxCacheCorrupt, match="pointer"):
        inbox.accept(packets[0])


@pytest.mark.parametrize("restart", [False, True])
def test_missing_archived_nonce_pointer_never_makes_reused_nonce_fresh(tmp_path, restart):
    identity = AgentIdentity.generate(label="lost-nonce-index")
    inbox = DeliveryInbox(tmp_path, clock=lambda: NOW, max_replay_entries=1,
                          archive_processed=True, reject_links=True)
    packets = [sign_envelope(identity, kind="chat.message", recipient=identity.as_did(),
                            payload={"index": index}, created_at_ms=NOW, expires_at_ms=NOW + 60_000)
               for index in range(2)]
    for packet in packets:
        assert inbox.accept(packet).accepted
        inbox.mark_processed(packet.message_id)
    pointer = inbox._archive._nonce_path(identity.as_did(), packets[0].nonce)
    pointer.rename(pointer.with_suffix(".test-backup"))
    if restart:
        inbox = DeliveryInbox(tmp_path, clock=lambda: NOW, max_replay_entries=1,
                              archive_processed=True, reject_links=True)
    changed = sign_envelope(identity, kind="chat.message", recipient=identity.as_did(),
                            payload={"changed": True}, nonce=packets[0].nonce,
                            created_at_ms=NOW, expires_at_ms=NOW + 60_000)
    for _ in range(2):
        with pytest.raises(DeliveryInboxCacheCorrupt, match="nonce pointer"):
            inbox.accept(changed)


@pytest.mark.parametrize("corruption", ["missing", "invalid"])
def test_archive_catalog_loss_is_not_silently_rebuilt(tmp_path, corruption):
    inbox = DeliveryInbox(tmp_path, archive_processed=True, reject_links=True)
    path = inbox._archive.catalog_path
    if corruption == "missing":
        path.rename(path.with_suffix(".test-backup"))
    else:
        path.write_bytes(b"invalid database")
    for _ in range(2):
        with pytest.raises(DeliveryInboxCacheCorrupt, match="catalog"):
            DeliveryInbox(tmp_path, archive_processed=True, reject_links=True)


def test_archive_catalog_commit_failure_keeps_pending_and_retry_repairs(tmp_path, monkeypatch):
    identity = AgentIdentity.generate(label="catalog-crash")
    inbox = DeliveryInbox(tmp_path, clock=lambda: NOW, archive_processed=True)
    packet = sign_envelope(identity, kind="chat.message", recipient=identity.as_did(), payload={},
                           created_at_ms=NOW, expires_at_ms=NOW + 60_000)
    assert inbox.accept(packet).accepted
    def unavailable(*_args):
        raise OSError("injected catalog commit failure")
    with monkeypatch.context() as patch:
        patch.setattr(inbox._archive, "_catalog_retain", unavailable)
        with pytest.raises(OSError, match="catalog commit failure"):
            inbox.mark_processed(packet.message_id)
    restarted = DeliveryInbox(tmp_path, clock=lambda: NOW, archive_processed=True)
    assert restarted.retained_entry(packet.message_id).envelope.to_dict() == packet.to_dict()
    assert restarted.mark_processed(packet.message_id)
    assert restarted.pending() == [] and restarted.accept(packet).duplicate


def test_legacy_json_archive_upgrade_retains_all_nonce_bindings(tmp_path):
    identity = AgentIdentity.generate(label="legacy-json-archive")
    inbox = DeliveryInbox(tmp_path, clock=lambda: NOW, max_replay_entries=1, archive_processed=True)
    packets = [sign_envelope(identity, kind="chat.message", recipient=identity.as_did(),
                            payload={"index": index}, created_at_ms=NOW, expires_at_ms=NOW + 60_000)
               for index in range(3)]
    for packet in packets:
        assert inbox.accept(packet).accepted
        inbox.mark_processed(packet.message_id)
    catalog = inbox._archive.catalog_path
    catalog.rename(catalog.with_suffix(".test-backup"))
    journal = tmp_path / "inbox.cache.jsonl"
    events = [json.loads(line) for line in journal.read_bytes().splitlines()]
    for event in events:
        if event["event"] == "archive_enabled":
            event.pop("catalog_version")
    journal.write_bytes(b"".join(canonical_json(event) + b"\n" for event in events))
    upgraded = DeliveryInbox(tmp_path, clock=lambda: NOW, max_replay_entries=1, archive_processed=True)
    assert all(upgraded.retained_entry(packet.message_id) for packet in packets)
    changed = sign_envelope(identity, kind="chat.message", recipient=identity.as_did(),
                            payload={"changed": True}, nonce=packets[0].nonce,
                            created_at_ms=NOW, expires_at_ms=NOW + 60_000)
    assert upgraded.accept(changed).replayed


def test_distinct_concurrent_processes_preserve_archived_history(tmp_path):
    context = multiprocessing.get_context("spawn")
    start, output = context.Event(), context.Queue()
    workers = [context.Process(target=_archive_writer, args=(str(tmp_path), index, start, output))
               for index in range(3)]
    for worker in workers:
        worker.start()
    start.set()
    results = [output.get(timeout=40) for _ in workers]
    for worker in workers:
        worker.join(timeout=10)
        assert worker.exitcode == 0
    assert all(ok for ok, _ in results), results
    inbox = DeliveryInbox(tmp_path, clock=lambda: NOW, max_replay_entries=4,
                          archive_processed=True, reject_links=True)
    assert inbox.entry_count() == 4 and inbox.pending() == []
    for _ok, packets in results:
        for packet in packets:
            assert inbox.accept(packet).duplicate
            assert inbox.retained_entry(packet["message_id"]).envelope.to_dict() == packet


def test_legacy_compacted_tombstone_is_archived_without_inventing_wire_evidence(tmp_path):
    identity = AgentIdentity.generate(label="legacy-archive")
    packet = sign_envelope(identity, kind="chat.message", recipient=identity.as_did(),
                           payload={}, created_at_ms=NOW, expires_at_ms=NOW + 60_000)
    old = DeliveryInbox(tmp_path, clock=lambda: NOW, max_replay_entries=1, evict_processed=False)
    assert old.accept(packet).accepted
    old.mark_processed(packet.message_id)
    with old._process_lock():
        old._compact_cache_journal_locked()
    new = DeliveryInbox(tmp_path, clock=lambda: NOW, max_replay_entries=1, archive_processed=True)
    different = sign_envelope(identity, kind="chat.message", recipient=identity.as_did(),
                              payload={"new": True}, created_at_ms=NOW, expires_at_ms=NOW + 60_000)
    assert new.accept(different).accepted
    assert new.accept(packet).duplicate
    assert new.retained_duplicate(canonical_json(packet.to_dict()).decode()).duplicate
    assert new.retained_entry(packet.message_id) is None


def test_completed_archive_cannot_be_silently_disabled_after_compaction(tmp_path):
    inbox = DeliveryInbox(tmp_path, archive_processed=True)
    with inbox._process_lock():
        inbox._compact_cache_journal_locked()
    with pytest.raises(DeliveryInboxCacheCorrupt, match="archive.*enabled"):
        DeliveryInbox(tmp_path)


def test_removed_archive_marker_is_integrity_failure_not_fresh_intake(tmp_path):
    identity = AgentIdentity.generate(label="missing-marker")
    inbox = DeliveryInbox(tmp_path, clock=lambda: NOW, archive_processed=True)
    packet = sign_envelope(identity, kind="chat.message", recipient=identity.as_did(),
                           payload={}, created_at_ms=NOW, expires_at_ms=NOW + 60_000)
    assert inbox.accept(packet).accepted
    inbox.mark_processed(packet.message_id)
    journal = tmp_path / "inbox.cache.jsonl"
    journal.write_bytes(b"".join(line + b"\n" for line in journal.read_bytes().splitlines()
                                 if json.loads(line)["event"] != "archive_enabled"))
    with pytest.raises(DeliveryInboxCacheCorrupt, match="marker is missing"):
        DeliveryInbox(tmp_path, archive_processed=True)


def test_missing_marker_without_archive_files_fails_closed_on_every_retry(tmp_path):
    identity = AgentIdentity.generate(label="empty-marker-retry")
    inbox = DeliveryInbox(tmp_path, clock=lambda: NOW, archive_processed=True)
    packet = sign_envelope(identity, kind="chat.message", recipient=identity.as_did(),
                           payload={}, created_at_ms=NOW, expires_at_ms=NOW + 60_000)
    (tmp_path / "inbox.cache.jsonl").write_bytes(b"")
    for _ in range(2):
        with pytest.raises(DeliveryInboxCacheCorrupt, match="marker is missing"):
            inbox.accept(packet)


def test_reused_source_outbox_requires_exact_directory_and_retention_policy(tmp_path):
    from nth_dao.delivery.outbox import DurableOutbox
    source = tmp_path / "source"
    box = DurableOutbox(source, retain_terminal_records=True, reject_links=True)
    box.require_retained_independent_storage(source)
    with pytest.raises(ValueError, match="exact selected directory"):
        box.require_retained_independent_storage(tmp_path / "other")
    unsafe = DurableOutbox(tmp_path / "unsafe")
    with pytest.raises(ValueError, match="independent evidence"):
        unsafe.require_retained_independent_storage(tmp_path / "unsafe")


@pytest.mark.parametrize("linked_part", ["message", "nonce", "catalog"])
def test_linked_archive_evidence_is_classified_as_integrity_failure(tmp_path, linked_part):
    identity = AgentIdentity.generate(label="linked-archive")
    inbox = DeliveryInbox(tmp_path, clock=lambda: NOW, archive_processed=True)
    packet = sign_envelope(identity, kind="chat.message", recipient=identity.as_did(),
                           payload={}, created_at_ms=NOW, expires_at_ms=NOW + 60_000)
    assert inbox.accept(packet).accepted
    inbox.mark_processed(packet.message_id)
    path = {"message": inbox._archive._message_path(packet.message_id),
            "nonce": inbox._archive._nonce_path(identity.as_did(), packet.nonce),
            "catalog": inbox._archive.catalog_path}[linked_part]
    try:
        os.link(path, tmp_path / "archive-alias.json")
    except OSError as exc:
        pytest.skip(f"hardlinks unavailable: {type(exc).__name__}")
    with pytest.raises(DeliveryInboxCacheCorrupt, match="unsafe"):
        inbox.retained_entry(packet.message_id)
