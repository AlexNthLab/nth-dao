"""Read views preserve storage while retaining validation and write guards."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("nacl")

from nth_dao.delivery.acknowledgement import sign_ack
from nth_dao.delivery.envelope import envelope_digest, sign_envelope
from nth_dao.delivery.inbox import DeliveryInbox, DeliveryInboxCacheCorrupt
from nth_dao.delivery.outbox import DurableOutbox
from nth_dao.identity import AgentIdentity
from nth_dao.market.claim_intent import (
    IntentTracker,
    IntentTrackerCorrupt,
    sign_claim_intent,
)

NOW = 1_750_000_000_000


def _envelope(identity):
    return sign_envelope(
        identity,
        kind="test.message",
        recipient=identity.as_did(),
        payload={"text": "test"},
        created_at_ms=NOW,
        expires_at_ms=NOW + 60_000,
    )


def _snapshot(directory: Path) -> dict[str, bytes]:
    return {
        path.relative_to(directory).as_posix(): path.read_bytes()
        for path in directory.rglob("*")
        if path.is_file() and not path.name.endswith(".lock")
    }


def test_read_only_inbox_refold_preserves_tail_and_blocks_all_actions(tmp_path):
    identity = AgentIdentity.generate(label="reader")
    envelope = _envelope(identity)
    writer = DeliveryInbox(tmp_path, clock=lambda: NOW, reject_links=True)
    assert writer.accept(envelope).accepted
    view = DeliveryInbox(tmp_path, clock=lambda: NOW, reject_links=True, read_only=True)
    with writer._cache_path.open("ab") as stream:
        stream.write(b'{"event":"partial"')
    before = _snapshot(tmp_path)
    assert view.pending()[0].message_id == envelope.message_id
    actions = [
        lambda: view.accept(envelope),
        lambda: view.accept({}),
        lambda: view.mark_processed(envelope.message_id),
        lambda: view.retained_duplicate("{}"),
        lambda: view.compact_rejections(),
        lambda: view.quarantine_transport_item(
            {}, transport="test", reason="test", at_ms=NOW
        ),
    ]
    for action in actions:
        with pytest.raises(PermissionError, match="read-only"):
            action()
    assert _snapshot(tmp_path) == before
    recovered = DeliveryInbox(tmp_path, clock=lambda: NOW, reject_links=True)
    assert recovered.pending()[0].message_id == envelope.message_id
    assert list(tmp_path.glob("inbox.cache.jsonl.torn.*"))


def test_read_only_outbox_refold_and_expiry_never_write(tmp_path):
    identity = AgentIdentity.generate(label="reader")
    envelope = _envelope(identity)
    writer = DurableOutbox(tmp_path, clock=lambda: NOW, reject_links=True)
    writer.enqueue(envelope)
    view = DurableOutbox(tmp_path, clock=lambda: NOW, reject_links=True, read_only=True)
    with writer._journal_path.open("ab") as stream:
        stream.write(b'{"event":"partial"')
    before = _snapshot(tmp_path)
    assert view.get(envelope.message_id).state == "queued"
    assert view.pending(now_ms=NOW + 60_001) == []
    assert view.get(envelope.message_id).state == "queued"
    ack = sign_ack(
        identity,
        message_id=envelope.message_id,
        envelope_sha256=envelope_digest(envelope),
        received_at_ms=NOW,
    )
    actions = [
        lambda: view.enqueue(envelope),
        lambda: view.compact(),
        lambda: view.handle_ack(ack),
        lambda: view.record_attempt(
            envelope.message_id, transport="test", outcome="sent"
        ),
        lambda: view.reserve_attempt(envelope.message_id, transport="test"),
        lambda: view.complete_attempt(envelope.message_id, "unused", outcome="sent"),
    ]
    for action in actions:
        with pytest.raises(PermissionError, match="read-only"):
            action()
    assert _snapshot(tmp_path) == before


def test_read_only_archive_reads_existing_catalog_without_migration(tmp_path):
    identity = AgentIdentity.generate(label="reader")
    first, second = _envelope(identity), _envelope(identity)
    writer = DeliveryInbox(
        tmp_path, clock=lambda: NOW, max_replay_entries=1, archive_processed=True
    )
    writer.accept(first)
    writer.mark_processed(first.message_id)
    writer.accept(second)
    writer.mark_processed(second.message_id)
    before = _snapshot(tmp_path)
    view = DeliveryInbox(
        tmp_path,
        clock=lambda: NOW,
        max_replay_entries=1,
        archive_processed=True,
        read_only=True,
    )
    assert view.seen(first.message_id) and view.accepted_at(first.message_id) == NOW
    assert _snapshot(tmp_path) == before
    catalog = writer._archive.catalog_path
    catalog.rename(catalog.with_name("preserved-catalog.sqlite3"))
    before = _snapshot(tmp_path)
    with pytest.raises(DeliveryInboxCacheCorrupt):
        DeliveryInbox(tmp_path, archive_processed=True, read_only=True)
    assert _snapshot(tmp_path) == before


def test_read_only_inbox_never_initializes_archive(tmp_path):
    with pytest.raises(DeliveryInboxCacheCorrupt, match="explicit initialization"):
        DeliveryInbox(tmp_path, archive_processed=True, read_only=True)
    assert _snapshot(tmp_path) == {}


def test_read_only_claim_tracker_preserves_archive_and_refuses_rebuild(tmp_path):
    from test_market_claim_intent import _selfissue, _setup

    _, _, _, identity, announcement = _setup(tmp_path / "market")
    token = _selfissue(identity, ["code_review"])

    def intent(nonce):
        return sign_claim_intent(
            identity,
            announcement_id=announcement.announcement_id,
            cap_token=token,
            nonce=nonce * 16,
        )

    old, current = intent("a"), intent("b")
    directory = tmp_path / "tracker"
    writer = IntentTracker(directory, max_intents=1)
    writer.record_sent(old)
    writer.mark(old, "confirmed")
    writer.record_sent(current)
    before = _snapshot(directory)
    view = IntentTracker(directory, read_only=True)
    assert view.archived_record(old["nonce"])["state"] == "confirmed"
    assert view.record(current["nonce"])["state"] == "pending"
    with pytest.raises(PermissionError, match="read-only"):
        view.mark(current, "rejected")
    assert _snapshot(directory) == before
    index = directory / "claim-intents-archive/index.sqlite3"
    index.rename(index.with_name("preserved-index.sqlite3"))
    before = _snapshot(directory)
    with pytest.raises(IntentTrackerCorrupt):
        IntentTracker(directory, read_only=True)
    assert _snapshot(directory) == before


@pytest.mark.parametrize("factory", [DeliveryInbox, DurableOutbox, IntentTracker])
def test_read_only_mode_is_strictly_boolean(tmp_path, factory):
    with pytest.raises(ValueError, match="read_only"):
        factory(tmp_path, read_only="false")
