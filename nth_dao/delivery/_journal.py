"""Recovery of a validated JSONL prefix under the caller's process lock."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from nth_dao.util.io import atomic_write_bytes, open_independent_file
from nth_dao.util.path_security import path_is_linklike


def journal_fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    """Include file identity so a same-size/mtime replacement is refolded."""
    return (metadata.st_mtime_ns, metadata.st_size, metadata.st_dev,
            metadata.st_ino, metadata.st_ctime_ns)


def recover_torn_tail(path: Path, raw: bytes) -> None:
    """Preserve an uncommitted tail before atomically restoring the valid prefix.

    Call only after validating every newline-terminated record while holding
    the same lock used for append. A failed recovery must prohibit append.
    """
    if not raw or raw.endswith(b"\n"):
        return
    boundary = raw.rfind(b"\n") + 1
    tail = raw[boundary:]
    quarantine = path.with_name(path.name + ".torn." + hashlib.sha256(tail).hexdigest())
    for candidate in (path, quarantine):
        if any(path_is_linklike(parent) for parent in (candidate, *candidate.parents)):
            raise ValueError("journal recovery path traverses a link")
    if quarantine.exists():
        metadata = quarantine.stat(follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size != len(tail):
            raise ValueError("journal recovery tail is not a bounded regular file")
        with open_independent_file(quarantine, "rb") as handle:
            retained = handle.read(len(tail) + 1)
        if retained != tail:
            raise ValueError("journal recovery tail differs from its retained digest")
    else:
        atomic_write_bytes(quarantine, tail, reject_links=True)
    atomic_write_bytes(path, raw[:boundary], reject_links=True)
