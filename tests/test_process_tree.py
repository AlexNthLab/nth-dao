from __future__ import annotations

import pytest

from nth_dao.util.process_tree import ProcessTreeGuard


class _Process:
    pid = 4321

    @staticmethod
    def poll():
        return None


class _Kernel32:
    def __init__(self) -> None:
        self.close_calls = 0

    def CloseHandle(self, handle):
        self.close_calls += 1
        return self.close_calls > 1


def test_windows_handle_close_failure_remains_retryable(monkeypatch) -> None:
    from nth_dao.util import process_tree

    kernel32 = _Kernel32()
    guard = ProcessTreeGuard(
        _Process(), kernel32=kernel32, windows_handle=1234,
    )
    monkeypatch.setattr(process_tree.os, "name", "nt")

    with pytest.raises(OSError, match="CloseHandle failed"):
        guard.close()

    guard.close()
    guard.close()
    assert kernel32.close_calls == 2
