"""Actual lock paths and opened-file checks for directed delivery stores."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from nth_dao.delivery.inbox import DeliveryInbox
from nth_dao.delivery.outbox import DurableOutbox
from nth_dao.util.io import InterProcessLock, atomic_write_bytes, open_independent_file


@pytest.mark.parametrize("component", ["inbox", "outbox", "intake", "preparation", "spine"])
def test_actual_lock_hardlink_is_rejected(tmp_path: Path, component: str) -> None:
    target = tmp_path / "unrelated.txt"
    target.write_bytes(b"test-owned unrelated bytes")
    directory = tmp_path / "delivery"
    directory.mkdir()
    name = "events.jsonl" if component == "spine" else component + ".lock"
    lock = InterProcessLock(directory / name, reject_links=True)
    os.link(target, lock.lock_path)
    with pytest.raises(ValueError, match="independent regular"):
        if component == "inbox":
            DeliveryInbox(directory, reject_links=True)
        elif component == "outbox":
            DurableOutbox(directory, reject_links=True)
        elif component == "spine":
            from nth_dao.cli.source_receipt_delivery import _spine
            from nth_dao.identity import AgentIdentity

            _spine(tmp_path, Path("delivery/events.jsonl"), AgentIdentity.generate())
        else:
            with lock:
                pytest.fail("unsafe lock was acquired")
    assert target.read_bytes() == b"test-owned unrelated bytes"


def test_actual_lock_symlink_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "unrelated.txt"
    target.write_bytes(b"test-owned bytes")
    lock = InterProcessLock(tmp_path / "inbox.lock", reject_links=True)
    try:
        lock.lock_path.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"OS does not permit test-owned symlinks: {exc}")
    with pytest.raises(ValueError, match="traverses a link"), lock:
        pytest.fail("unsafe lock was acquired")
    assert target.read_bytes() == b"test-owned bytes"


def test_opened_lock_identity_mismatch_closes_descriptor(tmp_path: Path, monkeypatch) -> None:
    lock = InterProcessLock(tmp_path / "intake.lock", reject_links=True)
    original_stat = Path.stat
    original_open = os.open
    descriptors = []

    def capture_open(*args, **kwargs):
        descriptor = original_open(*args, **kwargs)
        descriptors.append(descriptor)
        return descriptor

    def swapped_stat(path, *args, **kwargs):
        info = original_stat(path, *args, **kwargs)
        if path == lock.lock_path:
            return SimpleNamespace(st_mode=info.st_mode, st_nlink=info.st_nlink,
                                   st_dev=info.st_dev, st_ino=info.st_ino + 1)
        return info

    monkeypatch.setattr(os, "open", capture_open)
    monkeypatch.setattr(Path, "stat", swapped_stat)
    with pytest.raises(ValueError, match="changed during open"), lock:
        pytest.fail("changed lock was acquired")
    assert len(descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(descriptors[0])


@pytest.mark.parametrize("mode", ["rb", "ab", "wb", "r+b", "atomic"])
def test_independent_data_io_rejects_hardlinks_before_writing(tmp_path: Path, mode: str) -> None:
    target = tmp_path / "test-owned-unrelated.bin"
    original = b"test-owned bytes"
    target.write_bytes(original)
    path = tmp_path / "record.bin"
    os.link(target, path)
    with pytest.raises(ValueError, match="independent regular"):
        if mode == "atomic":
            atomic_write_bytes(path, b"replacement", reject_links=True)
        else:
            with open_independent_file(path, mode) as stream:
                if mode != "rb":
                    stream.write(b"replacement")
    assert target.read_bytes() == original


def test_independent_append_checks_opened_inode_before_write(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "record.bin"
    target.write_bytes(b"original")
    original_stat = Path.stat

    def replaced(path, *args, **kwargs):
        info = original_stat(path, *args, **kwargs)
        if path == target:
            return SimpleNamespace(st_mode=info.st_mode, st_nlink=info.st_nlink,
                                   st_dev=info.st_dev, st_ino=info.st_ino + 1)
        return info

    monkeypatch.setattr(Path, "stat", replaced)
    with pytest.raises(ValueError, match="changed during open"):
        open_independent_file(target, "ab")
    assert target.read_bytes() == b"original"


def test_atomic_publication_rejects_replaced_temp_without_deleting_it(tmp_path: Path, monkeypatch) -> None:
    import nth_dao.util.io as module

    target = tmp_path / "record.bin"
    target.write_bytes(b"original")
    checked = module.check_independent_file
    replacements = []

    def replaced(path, **kwargs):
        if path.name.endswith(".tmp") and not replacements:
            path.rename(path.with_suffix(".test-saved"))
            path.write_bytes(b"foreign replacement")
            replacements.append(path)
        return checked(path, **kwargs)

    monkeypatch.setattr(module, "check_independent_file", replaced)
    with pytest.raises(ValueError, match="temporary file changed"):
        module.atomic_write_bytes(target, b"new content", reject_links=True)
    assert target.read_bytes() == b"original"
    assert replacements[0].read_bytes() == b"foreign replacement"


@pytest.mark.parametrize("filename", ["inbox.cache.jsonl", "inbox.rejections.jsonl", "outbox.journal.jsonl"])
def test_linked_journal_is_rejected_before_store_initialization(tmp_path: Path, filename: str) -> None:
    target = tmp_path / "test-owned-unrelated.bin"
    original = b"test-owned bytes"
    target.write_bytes(original)
    directory = tmp_path / "delivery"
    directory.mkdir()
    os.link(target, directory / filename)
    store = DurableOutbox if filename.startswith("outbox") else DeliveryInbox
    with pytest.raises(ValueError, match="independent regular"):
        store(directory, reject_links=True)
    assert target.read_bytes() == original


@pytest.mark.parametrize("store", [DeliveryInbox, DurableOutbox])
def test_linked_journal_inserted_after_initialization_is_not_written(tmp_path: Path, store) -> None:
    from nth_dao.delivery.envelope import sign_envelope
    from nth_dao.identity import AgentIdentity

    now = 1_750_000_000_000
    directory = tmp_path / "delivery"
    instance = store(directory, reject_links=True, clock=lambda: now)
    filename = "outbox.journal.jsonl" if store is DurableOutbox else "inbox.cache.jsonl"
    target = tmp_path / "test-owned-unrelated.bin"
    target.write_bytes(b"")
    os.link(target, directory / filename)
    envelope = sign_envelope(AgentIdentity.generate(), kind="chat.message", recipient="dao:core",
                             payload={"text": "test"}, created_at_ms=now, expires_at_ms=now + 60_000)
    with pytest.raises(ValueError, match="independent regular"):
        instance.enqueue(envelope) if store is DurableOutbox else instance.accept(envelope)
    assert target.read_bytes() == b""


@pytest.mark.parametrize("store", [DeliveryInbox, DurableOutbox])
def test_same_size_and_mtime_journal_replacement_is_refolded(tmp_path: Path, store) -> None:
    from nth_dao.delivery.envelope import sign_envelope
    from nth_dao.identity import AgentIdentity

    now = 1_750_000_000_000
    instance = store(tmp_path / "delivery", clock=lambda: now, reject_links=True)
    envelope = sign_envelope(AgentIdentity.generate(), kind="chat.message", recipient="dao:core",
                             payload={"text": "test"}, created_at_ms=now, expires_at_ms=now + 60_000)
    if store is DurableOutbox:
        instance.enqueue(envelope)
        path = instance._journal_path
    else:
        assert instance.accept(envelope).accepted
        path = instance._cache_path
    metadata = path.stat()
    path.rename(path.with_suffix(".test-saved"))
    path.write_bytes(b" " * (metadata.st_size - 1) + b"\n")
    os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    if store is DurableOutbox:
        assert instance.get(envelope.message_id) is None
    else:
        assert instance.accepted_at(envelope.message_id) is None


@pytest.mark.parametrize("store", [DeliveryInbox, DurableOutbox])
def test_failed_torn_tail_quarantine_preserves_original_journal(tmp_path: Path, monkeypatch, store) -> None:
    directory = tmp_path / "delivery"
    directory.mkdir()
    name = "inbox.cache.jsonl" if store is DeliveryInbox else "outbox.journal.jsonl"
    path = directory / name
    tail = b'{"unfinished":'
    path.write_bytes(tail)

    def fail(*_args, **_kwargs):
        raise OSError("injected quarantine write failure")

    with monkeypatch.context() as patch:
        patch.setattr("nth_dao.delivery._journal.atomic_write_bytes", fail)
        with pytest.raises(OSError, match="quarantine"):
            store(directory)
    assert path.read_bytes() == tail
    store(directory)
    assert path.read_bytes() == b""
    assert [entry.read_bytes() for entry in directory.glob("*.torn.*")] == [tail]
