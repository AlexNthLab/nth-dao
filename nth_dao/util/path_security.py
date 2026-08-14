"""Small path checks shared by local durable stores."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Protocol


class _PathLike(Protocol):
    def is_symlink(self) -> bool: ...

    def is_junction(self) -> bool: ...


def path_is_linklike(path: Path | _PathLike) -> bool:
    """Return whether *path* is a link/reparse point without an exists race."""

    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    if is_junction and is_junction():
        return True
    if os.name != "nt":
        return False
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        # SQLite can remove -wal/-shm files between adjacent path checks.
        return False
    return bool(
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


__all__ = ["path_is_linklike"]
