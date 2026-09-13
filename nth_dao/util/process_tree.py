"""Cross-platform lifetime ownership for one subprocess tree.

This is resource containment, not a security sandbox. Callers must create
POSIX children with ``start_new_session=True``. On Windows a Job Object keeps
descendants addressable even after the direct child exits.
"""

from __future__ import annotations

import os
import signal
import subprocess
import threading
from typing import Any

_WINDOWS_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_WINDOWS_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
WINDOWS_CREATE_SUSPENDED = 0x00000004
_WINDOWS_THREAD_SUSPEND_RESUME = 0x0002
_WINDOWS_TH32CS_SNAPTHREAD = 0x00000004
_WINDOWS_ERROR_NO_MORE_FILES = 18


class ProcessTreeGuard:
    """Own and terminate the process group/job containing one child."""

    def __init__(
        self,
        process: subprocess.Popen,
        *,
        kernel32: Any = None,
        windows_handle: Any = None,
    ) -> None:
        self._process = process
        self._kernel32 = kernel32
        self._windows_handle = windows_handle
        self._closed = False
        self._lock = threading.Lock()

    def terminate(self, *, force: bool = True) -> bool:
        """Signal the entire owned tree, falling back to the direct child."""

        with self._lock:
            if self._closed:
                return self._process.poll() is not None
            if os.name == "nt" and self._windows_handle is not None:
                if self._kernel32.TerminateJobObject(self._windows_handle, 1):
                    return True
            elif os.name != "nt":
                try:
                    os.killpg(
                        self._process.pid,
                        signal.SIGKILL if force else signal.SIGTERM,
                    )
                    return True
                except (OSError, ProcessLookupError):
                    pass
            if self._process.poll() is not None:
                return True
            try:
                self._process.kill() if force else self._process.terminate()
            except OSError:
                return self._process.poll() is not None
            return True

    def close(self) -> None:
        """Release ownership; kill descendants that outlived the direct child."""

        with self._lock:
            if self._closed:
                return
            if os.name == "nt" and self._windows_handle is not None:
                handle = self._windows_handle
                if not self._kernel32.CloseHandle(handle):
                    import ctypes

                    raise OSError(ctypes.get_last_error(), "CloseHandle failed")
                self._windows_handle = None
                self._closed = True
                return
            if os.name != "nt":
                try:
                    os.killpg(self._process.pid, signal.SIGKILL)
                except (OSError, ProcessLookupError):
                    pass
            self._closed = True


def attach_process_tree_guard(process: subprocess.Popen) -> ProcessTreeGuard:
    """Create durable process-tree ownership for an already spawned child."""

    if os.name != "nt":
        return ProcessTreeGuard(process)

    import ctypes
    from ctypes import wintypes

    class _JobObjectBasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _IoCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class _JobObjectExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _JobObjectBasicLimitInformation),
            ("IoInfo", _IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    handle = kernel32.CreateJobObjectW(None, None)
    if not handle:
        raise OSError(ctypes.get_last_error(), "CreateJobObjectW failed")
    try:
        limits = _JobObjectExtendedLimitInformation()
        limits.BasicLimitInformation.LimitFlags = (
            _WINDOWS_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        )
        if not kernel32.SetInformationJobObject(
            handle,
            _WINDOWS_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            raise OSError(
                ctypes.get_last_error(), "SetInformationJobObject failed"
            )
        process_handle = getattr(process, "_handle", None)
        if process_handle is None or not kernel32.AssignProcessToJobObject(
            handle, wintypes.HANDLE(int(process_handle))
        ):
            raise OSError(ctypes.get_last_error(), "AssignProcessToJobObject failed")
    except BaseException:
        kernel32.CloseHandle(handle)
        raise
    return ProcessTreeGuard(
        process,
        kernel32=kernel32,
        windows_handle=handle,
    )


def resume_suspended_process(process: subprocess.Popen) -> None:
    """Resume every initial thread of a suspended Windows child.

    CPython closes the primary thread handle before ``Popen`` returns. Reopen
    it by thread id only after the process has entered its Job Object, closing
    the spawn-before-containment race. Non-Windows callers are a no-op.
    """

    if os.name != "nt":
        return
    if process.poll() is not None:
        raise OSError("suspended child exited before it could be resumed")

    import ctypes
    from ctypes import wintypes

    class _ThreadEntry32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ThreadID", wintypes.DWORD),
            ("th32OwnerProcessID", wintypes.DWORD),
            ("tpBasePri", wintypes.LONG),
            ("tpDeltaPri", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ThreadEntry32)]
    kernel32.Thread32First.restype = wintypes.BOOL
    kernel32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ThreadEntry32)]
    kernel32.Thread32Next.restype = wintypes.BOOL
    kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenThread.restype = wintypes.HANDLE
    kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel32.ResumeThread.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    snapshot = kernel32.CreateToolhelp32Snapshot(_WINDOWS_TH32CS_SNAPTHREAD, 0)
    invalid_handle = ctypes.c_void_p(-1).value
    if not snapshot or int(snapshot) == invalid_handle:
        raise OSError(ctypes.get_last_error(), "CreateToolhelp32Snapshot failed")
    thread_ids: list[int] = []
    try:
        entry = _ThreadEntry32()
        entry.dwSize = ctypes.sizeof(entry)
        if not kernel32.Thread32First(snapshot, ctypes.byref(entry)):
            raise OSError(ctypes.get_last_error(), "Thread32First failed")
        while True:
            if int(entry.th32OwnerProcessID) == int(process.pid):
                thread_ids.append(int(entry.th32ThreadID))
            entry.dwSize = ctypes.sizeof(entry)
            if kernel32.Thread32Next(snapshot, ctypes.byref(entry)):
                continue
            error = ctypes.get_last_error()
            if error not in (0, _WINDOWS_ERROR_NO_MORE_FILES):
                raise OSError(error, "Thread32Next failed")
            break
    finally:
        kernel32.CloseHandle(snapshot)

    if not thread_ids:
        raise OSError("suspended child has no resumable thread")
    resumed = 0
    for thread_id in thread_ids:
        thread_handle = kernel32.OpenThread(
            _WINDOWS_THREAD_SUSPEND_RESUME, False, thread_id,
        )
        if not thread_handle:
            raise OSError(ctypes.get_last_error(), "OpenThread failed")
        try:
            if kernel32.ResumeThread(thread_handle) == 0xFFFFFFFF:
                raise OSError(ctypes.get_last_error(), "ResumeThread failed")
            resumed += 1
        finally:
            kernel32.CloseHandle(thread_handle)
    if resumed != len(thread_ids):
        raise OSError("not every suspended child thread was resumed")


__all__ = [
    "WINDOWS_CREATE_SUSPENDED",
    "ProcessTreeGuard",
    "attach_process_tree_guard",
    "resume_suspended_process",
]
