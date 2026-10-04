"""Immutable, locally retained evidence for a claimant's completion claim."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any

from nth_dao.canonical_json import canonical_json
from nth_dao.market.mission_completion import (
    COMPLETION_MERGE_VERSION, COMPLETION_REVISION_VERSION,
    CompletionLineageError, resolve_completion_lineage,
    verify_confirmed_mission_completion,
)
from nth_dao.util.io import InterProcessLock

_NONCE_RE = re.compile(r"[A-Za-z0-9]{16,64}\Z")
_DIGEST_FILE_RE = re.compile(r"[0-9a-f]{64}\.json\Z")
_MAX_RECORD_BYTES = 512 * 1024
_MAX_DIRECTORY_ENTRIES = 32


class CompletionEvidenceRejected(ValueError):
    """Submitted signatures or bindings do not establish completion evidence."""


class CompletionEvidenceConflict(ValueError):
    """This nonce already has a different retained completion claim."""


class CompletionEvidenceCorrupt(ValueError):
    """Retained completion evidence cannot be trusted."""


class ClaimCompletionStore:
    """One append-only, claimant-signed completion chain per claim nonce.

    Separate files for conflicting writes make Git merges visible rather than
    silently selecting one node's claim. A verified record proves signed
    provenance and binding, not that the work was accepted or paid for.
    """

    def __init__(self, workspace: Path) -> None:
        self.workspace = Path(workspace)
        self.root = self.workspace / "federation" / "claim_completions"

    def _directory(self, nonce: str) -> Path:
        if not isinstance(nonce, str) or _NONCE_RE.fullmatch(nonce) is None:
            raise CompletionEvidenceRejected("claim nonce format is invalid")
        return self.root / nonce

    def _lock_target(self, nonce: str) -> Path:
        private_root = self.workspace / ".nth"
        lock_root = private_root / "locks"
        completion_locks = lock_root / "claim_completions"
        if any(path.is_symlink() for path in (
            private_root, lock_root, completion_locks,
        )):
            raise CompletionEvidenceCorrupt("completion lock directory is a symlink")
        return completion_locks / nonce

    def _stage_root(self) -> Path:
        private_root = self.workspace / ".nth"
        stage_parent = private_root / "staging"
        stage = stage_parent / "claim_completions"
        if any(path.is_symlink() for path in (private_root, stage_parent, stage)):
            raise CompletionEvidenceCorrupt("completion staging directory is a symlink")
        stage.mkdir(parents=True, exist_ok=True)
        return stage

    @staticmethod
    def _replace_durable(source: Path, target: Path) -> None:
        if os.name == "nt":
            import ctypes

            move = ctypes.WinDLL("kernel32", use_last_error=True).MoveFileExW
            move.argtypes = (ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_ulong)
            move.restype = ctypes.c_int
            if not move(str(source), str(target), 0x1 | 0x8):
                raise OSError(ctypes.get_last_error(), "durable completion rename failed")
        else:
            os.replace(source, target)
            directory_fd = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)

    def _write_immutable(self, target: Path, raw: bytes, nonce: str) -> None:
        stage = self._stage_root()
        fd, temporary = tempfile.mkstemp(prefix=f"{nonce}-", suffix=".tmp", dir=stage)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            self._replace_durable(Path(temporary), target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _check_directory(self, directory: Path) -> None:
        if (
            self.root.parent.is_symlink()
            or self.root.is_symlink()
            or directory.is_symlink()
        ):
            raise CompletionEvidenceCorrupt("completion store directory is a symlink")

    def _entries(self, directory: Path, nonce: str) -> list[Path]:
        self._check_directory(directory)
        if not directory.exists():
            return []
        found: list[Path] = []
        with os.scandir(directory) as entries:
            for count, entry in enumerate(entries, start=1):
                if count > _MAX_DIRECTORY_ENTRIES:
                    raise CompletionEvidenceCorrupt("completion slot exceeds entry limit")
                if _DIGEST_FILE_RE.fullmatch(entry.name) is None:
                    raise CompletionEvidenceCorrupt("completion slot has an unknown entry")
                found.append(directory / entry.name)
        return found

    def _graph(
        self, entries: list[Path], nonce: str,
    ) -> tuple[list[tuple[Path, dict[str, Any]]], list[str]]:
        records = {f"sha256:{path.stem}": (path, self._read(path, nonce))
                   for path in entries}
        try:
            order, heads = resolve_completion_lineage(
                {digest: value for digest, (_, value) in records.items()},
            )
        except CompletionLineageError as exc:
            raise CompletionEvidenceCorrupt(str(exc)) from exc
        return [records[digest] for digest in order], heads

    def _ordered(self, entries: list[Path], nonce: str) -> list[tuple[Path, dict[str, Any]]]:
        ordered, heads = self._graph(entries, nonce)
        if len(heads) != 1:
            raise CompletionEvidenceConflict("claim has forked completion revisions")
        return ordered

    def _head(self, entries: list[Path], nonce: str) -> tuple[Path, dict[str, Any]]:
        return self._ordered(entries, nonce)[-1]

    def _read(self, path: Path, nonce: str) -> dict[str, Any]:
        if path.is_symlink():
            raise CompletionEvidenceCorrupt("completion evidence is a symlink")
        before = os.stat(path, follow_symlinks=False)
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            after = os.stat(path, follow_symlinks=False)
            if (
                not stat.S_ISREG(opened.st_mode)
                or not stat.S_ISREG(before.st_mode)
                or not stat.S_ISREG(after.st_mode)
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
                or (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
                or opened.st_size > _MAX_RECORD_BYTES
            ):
                raise CompletionEvidenceCorrupt("completion evidence file is unsafe")
            chunks: list[bytes] = []
            remaining = _MAX_RECORD_BYTES + 1
            while remaining:
                chunk = os.read(fd, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
        finally:
            os.close(fd)
        if len(raw) > _MAX_RECORD_BYTES:
            raise CompletionEvidenceCorrupt("completion evidence is oversized")
        if path.stem != hashlib.sha256(raw).hexdigest():
            raise CompletionEvidenceCorrupt("completion evidence content hash changed")
        try:
            value = json.loads(raw.decode("utf-8"))
            if canonical_json(value) != raw:
                raise ValueError("completion evidence is not canonical JSON")
        except (UnicodeError, ValueError, RecursionError, OverflowError) as exc:
            raise CompletionEvidenceCorrupt("completion evidence encoding is invalid") from exc
        if (
            not isinstance(value, dict)
            or set(value) != {"version", "nonce", "completion_record", "execution_receipt"}
            or type(value["version"]) is not int
            or value["version"] != 1
            or value["nonce"] != nonce
        ):
            raise CompletionEvidenceCorrupt("completion evidence envelope is invalid")
        verified, reason = verify_confirmed_mission_completion(
            self.workspace, nonce, value["completion_record"], value["execution_receipt"]
        )
        if not verified:
            raise CompletionEvidenceCorrupt(f"retained completion is invalid: {reason}")
        return value

    def load(self, nonce: str) -> dict[str, Any] | None:
        directory = self._directory(nonce)
        self._check_directory(directory)
        if not directory.exists():
            return None
        with InterProcessLock(self._lock_target(nonce)):
            entries = self._entries(directory, nonce)
            return self._head(entries, nonce)[1] if entries else None

    def load_chain(self, nonce: str) -> list[dict[str, Any]]:
        """Return every verified branch only when they have one resolved head."""
        directory = self._directory(nonce)
        self._check_directory(directory)
        if not directory.exists():
            return []
        with InterProcessLock(self._lock_target(nonce)):
            entries = self._entries(directory, nonce)
            return [value for _, value in self._ordered(entries, nonce)] if entries else []

    def heads(self, nonce: str) -> list[tuple[str, dict[str, Any]]]:
        """Expose verified conflicting heads to the claimant for explicit resolution."""
        directory = self._directory(nonce)
        self._check_directory(directory)
        if not directory.exists():
            return []
        with InterProcessLock(self._lock_target(nonce)):
            entries = self._entries(directory, nonce)
            ordered, heads = self._graph(entries, nonce)
            by_digest = {f"sha256:{path.stem}": value for path, value in ordered}
            return [(digest, by_digest[digest]) for digest in heads]

    def record(
        self, nonce: str, completion_record: dict[str, Any],
        execution_receipt: dict[str, Any],
    ) -> tuple[dict[str, Any], bool]:
        directory = self._directory(nonce)
        self._check_directory(directory)
        value = {
            "version": 1,
            "nonce": nonce,
            "completion_record": completion_record,
            "execution_receipt": execution_receipt,
        }
        try:
            raw = canonical_json(value)
        except (TypeError, ValueError, OverflowError, RecursionError) as exc:
            raise CompletionEvidenceRejected("completion evidence is not canonical JSON") from exc
        if len(raw) > _MAX_RECORD_BYTES:
            raise CompletionEvidenceRejected("completion evidence is too large")
        value = json.loads(raw)
        verified, reason = verify_confirmed_mission_completion(
            self.workspace, nonce, value["completion_record"], value["execution_receipt"]
        )
        if not verified:
            raise CompletionEvidenceRejected(reason)
        digest = hashlib.sha256(raw).hexdigest()
        directory.mkdir(parents=True, exist_ok=True)
        with InterProcessLock(self._lock_target(nonce)):
            entries = self._entries(directory, nonce)
            if entries:
                ordered, heads = self._graph(entries, nonce)
                if any(path.stem == digest for path in entries):
                    if len(heads) != 1:
                        raise CompletionEvidenceConflict("claim has forked completion revisions")
                    return ordered[-1][1], False
                record = value["completion_record"]
                by_digest = {f"sha256:{path.stem}": item for path, item in ordered}
                head_records = [by_digest[head]["completion_record"] for head in heads]
                expected_revision = max(head.get("revision", 0) for head in head_records) + 1
                if (
                    record.get("revision", 0) != expected_revision
                    or any(record["completed_at_ms"] < head["completed_at_ms"]
                           for head in head_records)
                    or (len(heads) == 1 and (
                        record["version"] != COMPLETION_REVISION_VERSION
                        or record["supersedes_digest"] != heads[0]
                    ))
                    or (len(heads) > 1 and (
                        record["version"] != COMPLETION_MERGE_VERSION
                        or record["supersedes_digests"] != sorted(heads)
                    ))
                ):
                    raise CompletionEvidenceConflict("completion does not extend the current head")
            elif value["completion_record"]["version"] != 1:
                raise CompletionEvidenceConflict("completion revision has no predecessor")
            if len(entries) >= _MAX_DIRECTORY_ENTRIES:
                raise CompletionEvidenceConflict("completion slot reached its revision limit")
            self._write_immutable(directory / f"{digest}.json", raw, nonce)
        return json.loads(raw), True


__all__ = [
    "ClaimCompletionStore", "CompletionEvidenceRejected",
    "CompletionEvidenceConflict", "CompletionEvidenceCorrupt",
]
