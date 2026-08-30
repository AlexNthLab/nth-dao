"""Bounded RPC runtime for statically reviewed subprocess plugins.

This boundary contains crashes, hangs, stdout protocol pollution, and ambient
environment inheritance. It is deliberately not described as an OS sandbox:
without WASI, containers, or platform policy, the child process still has the
operating-system authority of the NTH DAO user account.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
from pathlib import Path
import queue
import re
import secrets
import shutil
import signal
import stat
import subprocess
import threading
import time
from typing import Any, BinaryIO, Callable, Dict, Mapping, Tuple

from nth_dao.canonical_json import canonical_json
from nth_dao.util.io import InterProcessLock

from .contracts import PluginManifest
from .host import (
    CapabilityProvider,
    PluginContext,
    PluginInvocationContext,
    PluginInvocationError,
    PluginProviderUnavailable,
)


SUBPROCESS_RPC_PROTOCOL = "nth-dao-plugin-rpc"
SUBPROCESS_RPC_VERSION = 1
SUBPROCESS_MAX_FRAME_BYTES = 2 * 1024 * 1024
SUBPROCESS_MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
SUBPROCESS_MAX_LAUNCHER_BYTES = 256 * 1024 * 1024
SUBPROCESS_MAX_STDERR_BYTES = 64 * 1024
SUBPROCESS_MAX_SAFE_INTEGER = 9_007_199_254_740_991

_ENV_KEY_RE = re.compile(r"^[A-Z_][A-Z0-9_]{0,63}$")
_ERROR_CODE_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_SNAPSHOT_GENERATION_RE = re.compile(r"^generation-[0-9a-f]{32}$")
_RESERVED_ENV = frozenset(
    {
        "NTH_PLUGIN_ID",
        "NTH_PLUGIN_MANIFEST_DIGEST",
        "NTH_PLUGIN_RPC",
        "NTH_PLUGIN_RPC_VERSION",
        "COMSPEC",
        "DYLD_INSERT_LIBRARIES",
        "LD_PRELOAD",
        "PYTHONINSPECT",
        "PYTHONIOENCODING",
        "PYTHONNOUSERSITE",
        "PYTHONPATH",
        "PYTHONSAFEPATH",
        "PYTHONSTARTUP",
        "PYTHONUNBUFFERED",
        "SYSTEMROOT",
        "WINDIR",
    }
)


def _windows_taskkill_path() -> Path | None:
    """Resolve the Windows system directory without trusting environment text."""

    if os.name != "nt":
        return None
    try:
        import ctypes

        buffer = ctypes.create_unicode_buffer(32_768)
        length = ctypes.windll.kernel32.GetWindowsDirectoryW(  # type: ignore[attr-defined]
            buffer, len(buffer)
        )
    except (AttributeError, OSError):
        return None
    if not 0 < length < len(buffer):
        return None
    candidate = Path(buffer.value) / "System32" / "taskkill.exe"
    return candidate if candidate.is_file() else None


def _remove_private_tree(directory: Path) -> None:
    def make_writable_and_retry(function, path, _error) -> None:
        try:
            os.chmod(path, stat.S_IWRITE)
            function(path)
        except OSError:
            return

    shutil.rmtree(directory, ignore_errors=False, onerror=make_writable_and_retry)


def _snapshot_lease(snapshot_root: Path, generation: str) -> InterProcessLock:
    return InterProcessLock(
        snapshot_root / ".leases" / generation,
        timeout=0.02,
        poll=0.005,
    )


def _prepare_snapshot_root(snapshot_root: Path) -> Path:
    root = Path(os.path.abspath(snapshot_root))
    try:
        resolved = root.resolve(strict=False)
    except OSError as exc:
        raise SubprocessPluginError(
            "cannot resolve subprocess snapshot storage"
        ) from exc
    if os.path.normcase(str(root)) != os.path.normcase(str(resolved)):
        raise SubprocessPluginError(
            "subprocess snapshot storage must not use path redirection"
        )
    root.mkdir(parents=True, exist_ok=True)
    leases = root / ".leases"
    if leases.is_symlink():
        raise SubprocessPluginError(
            "subprocess snapshot lease storage must not be a symlink"
        )
    leases.mkdir(mode=0o700, exist_ok=True)
    if leases.resolve(strict=True) != leases:
        raise SubprocessPluginError(
            "subprocess snapshot lease storage must not use path redirection"
        )
    try:
        os.chmod(root, 0o700)
        os.chmod(leases, 0o700)
    except OSError as exc:
        raise SubprocessPluginError(
            "cannot make subprocess snapshot storage private"
        ) from exc
    return root


def cleanup_orphaned_subprocess_snapshots(snapshot_root: Path) -> int:
    """Remove only inactive Host-owned generations under one private root."""

    root = _prepare_snapshot_root(snapshot_root)
    janitor = InterProcessLock(root / ".janitor", timeout=2.0, poll=0.01)
    try:
        janitor.acquire()
    except (OSError, TimeoutError) as exc:
        raise SubprocessPluginError("subprocess snapshot janitor is busy") from exc
    removed = 0
    try:
        for candidate in sorted(root.iterdir(), key=lambda item: item.name):
            if _SNAPSHOT_GENERATION_RE.fullmatch(candidate.name) is None:
                continue
            if candidate.is_symlink() or not candidate.is_dir():
                raise SubprocessPluginError(
                    "subprocess snapshot generation has an unsafe file type"
                )
            lease = _snapshot_lease(root, candidate.name)
            try:
                lease.acquire()
            except TimeoutError:
                continue
            except OSError as exc:
                raise SubprocessPluginError(
                    "cannot inspect subprocess snapshot generation lease"
                ) from exc
            try:
                _remove_private_tree(candidate)
                removed += 1
            except OSError as exc:
                raise SubprocessPluginError(
                    "cannot remove orphaned subprocess snapshot"
                ) from exc
            finally:
                lease.release()
            try:
                lease.lock_path.unlink(missing_ok=True)
            except OSError as exc:
                raise SubprocessPluginError(
                    "cannot remove orphaned subprocess snapshot lease"
                ) from exc
    finally:
        janitor.release()
    return removed


class SubprocessPluginError(RuntimeError):
    """A reviewed subprocess specification or lifecycle operation is invalid."""


class SubprocessRemoteError(PluginInvocationError):
    """The worker returned a bounded, non-fatal capability error."""

    def __init__(self, code: str, message: str, *, retryable: bool) -> None:
        super().__init__(f"subprocess plugin error {code!r}: {message}")
        self.code = code
        self.retryable = retryable


def subprocess_canonical_json(document: Dict[str, Any]) -> bytes:
    """Encode the RPC JSON subset with RFC 8785-compatible key ordering."""

    if not isinstance(document, dict):
        raise TypeError("subprocess canonical JSON root must be an object")

    def encode(value: Any, *, depth: int) -> bytes:
        if depth > 64:
            raise ValueError("subprocess canonical JSON exceeds its depth limit")
        if value is None:
            return b"null"
        if type(value) is bool:
            return b"true" if value else b"false"
        if type(value) is int:
            if not -SUBPROCESS_MAX_SAFE_INTEGER <= value <= SUBPROCESS_MAX_SAFE_INTEGER:
                raise ValueError(
                    "subprocess canonical JSON integer exceeds the safe range"
                )
            return str(value).encode("ascii")
        if isinstance(value, str):
            try:
                return json.dumps(
                    value,
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ValueError(
                    "subprocess canonical JSON contains invalid Unicode"
                ) from exc
        if isinstance(value, list):
            return b"[" + b",".join(
                encode(item, depth=depth + 1) for item in value
            ) + b"]"
        if isinstance(value, dict):
            if any(not isinstance(key, str) for key in value):
                raise TypeError("subprocess canonical JSON keys must be strings")
            try:
                keys = sorted(value, key=lambda item: item.encode("utf-16-be"))
            except UnicodeEncodeError as exc:
                raise ValueError(
                    "subprocess canonical JSON key contains invalid Unicode"
                ) from exc
            members = []
            for key in keys:
                members.append(
                    encode(key, depth=depth + 1)
                    + b":"
                    + encode(value[key], depth=depth + 1)
                )
            return b"{" + b",".join(members) + b"}"
        raise TypeError(
            f"subprocess canonical JSON rejects {type(value).__name__}"
        )

    return encode(document, depth=0)


def _parse_safe_rpc_integer(value: str) -> int:
    parsed = int(value)
    if not -SUBPROCESS_MAX_SAFE_INTEGER <= parsed <= SUBPROCESS_MAX_SAFE_INTEGER:
        raise ValueError("subprocess RPC integer exceeds the safe range")
    return parsed


def subprocess_artifact_digest(path: Path) -> str:
    """Hash one reviewed worker artifact with a hard size ceiling."""

    candidate = Path(path)
    if candidate.is_symlink():
        raise SubprocessPluginError("subprocess worker artifact must not be a symlink")
    try:
        resolved = candidate.resolve(strict=True)
        stat = resolved.stat()
    except OSError as exc:
        raise SubprocessPluginError("subprocess worker artifact is unavailable") from exc
    if not resolved.is_file():
        raise SubprocessPluginError("subprocess worker artifact must be a file")
    if stat.st_size > SUBPROCESS_MAX_ARTIFACT_BYTES:
        raise SubprocessPluginError("subprocess worker artifact exceeds 64 MiB")
    digest = hashlib.sha256()
    total = 0
    try:
        with resolved.open("rb") as stream:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > SUBPROCESS_MAX_ARTIFACT_BYTES:
                    raise SubprocessPluginError(
                        "subprocess worker artifact changed beyond 64 MiB while hashing"
                    )
                digest.update(chunk)
    except OSError as exc:
        raise SubprocessPluginError("cannot read subprocess worker artifact") from exc
    return f"sha256:{digest.hexdigest()}"


def _subprocess_launcher_digest(path: Path) -> str:
    """Hash one resolved launcher without following a final symlink."""

    candidate = Path(path)
    if candidate.is_symlink():
        raise SubprocessPluginError("subprocess launcher must not be a symlink")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise SubprocessPluginError("subprocess launcher is unavailable") from exc
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    digest = hashlib.sha256()
    total = 0
    try:
        descriptor = os.open(resolved, flags)
        try:
            file_stat = os.fstat(descriptor)
            if not stat.S_ISREG(file_stat.st_mode):
                raise SubprocessPluginError("subprocess launcher must be a file")
            if file_stat.st_size > SUBPROCESS_MAX_LAUNCHER_BYTES:
                raise SubprocessPluginError("subprocess launcher exceeds 256 MiB")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                while True:
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > SUBPROCESS_MAX_LAUNCHER_BYTES:
                        raise SubprocessPluginError(
                            "subprocess launcher changed beyond 256 MiB while hashing"
                        )
                    digest.update(chunk)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise SubprocessPluginError("cannot read subprocess launcher") from exc
    return f"sha256:{digest.hexdigest()}"


@dataclass(frozen=True)
class ReviewedSubprocessSpec:
    """Trusted local launch data; never populate this from a remote manifest."""

    launcher: Path
    artifact: Path
    working_directory: Path
    arguments: Tuple[str, ...] = ()
    environment: Tuple[Tuple[str, str], ...] = ()
    startup_timeout_s: float = 3.0
    invocation_timeout_s: float = 30.0
    shutdown_timeout_s: float = 2.0
    max_frame_bytes: int = SUBPROCESS_MAX_FRAME_BYTES
    max_stderr_bytes: int = SUBPROCESS_MAX_STDERR_BYTES
    launcher_digest: str = field(init=False, repr=False)
    environment_profile_nonce: str = field(
        default_factory=lambda: secrets.token_hex(16),
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        launcher = Path(self.launcher)
        artifact = Path(self.artifact)
        working_directory = Path(self.working_directory)
        if launcher.is_symlink():
            raise SubprocessPluginError("subprocess launcher must not be a symlink")
        if artifact.is_symlink():
            raise SubprocessPluginError("subprocess worker artifact must not be a symlink")
        try:
            launcher_target = launcher.resolve(strict=True)
            artifact = artifact.resolve(strict=True)
            working_directory = working_directory.resolve(strict=True)
        except OSError as exc:
            raise SubprocessPluginError("subprocess launch paths must already exist") from exc
        if not launcher_target.is_file():
            raise SubprocessPluginError("subprocess launcher must be a file")
        if not artifact.is_file():
            raise SubprocessPluginError("subprocess worker artifact must be a file")
        if not working_directory.is_dir():
            raise SubprocessPluginError("subprocess working_directory must be a directory")
        object.__setattr__(self, "launcher", launcher_target)
        object.__setattr__(self, "artifact", artifact)
        object.__setattr__(self, "working_directory", working_directory)
        object.__setattr__(
            self,
            "launcher_digest",
            _subprocess_launcher_digest(launcher_target),
        )

        arguments = tuple(self.arguments)
        if len(arguments) > 32:
            raise SubprocessPluginError("subprocess arguments exceed 32 items")
        if any(
            not isinstance(item, str)
            or "\x00" in item
            or len(item.encode("utf-8")) > 4096
            or any(ord(char) < 0x20 or ord(char) == 0x7F for char in item)
            for item in arguments
        ):
            raise SubprocessPluginError("subprocess arguments must be bounded text")
        if sum(len(item.encode("utf-8")) for item in arguments) > 16 * 1024:
            raise SubprocessPluginError("subprocess arguments exceed 16 KiB")
        object.__setattr__(self, "arguments", arguments)

        environment = tuple(self.environment)
        keys = tuple(item[0] for item in environment if isinstance(item, tuple) and len(item) == 2)
        if len(keys) != len(environment) or keys != tuple(sorted(set(keys))):
            raise SubprocessPluginError("subprocess environment must be sorted and unique")
        for key, value in environment:
            if not isinstance(key, str) or not _ENV_KEY_RE.fullmatch(key):
                raise SubprocessPluginError("subprocess environment key is invalid")
            if key in _RESERVED_ENV or key.startswith("PYTHON"):
                raise SubprocessPluginError(
                    f"subprocess environment key {key!r} is host-reserved"
                )
            if (
                not isinstance(value, str)
                or "\x00" in value
                or len(value.encode("utf-8")) > 4096
                or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)
            ):
                raise SubprocessPluginError("subprocess environment value is invalid")
        if sum(len(key) + len(value.encode("utf-8")) for key, value in environment) > 32 * 1024:
            raise SubprocessPluginError("subprocess environment exceeds 32 KiB")
        object.__setattr__(self, "environment", environment)

        for label, value, minimum, maximum in (
            ("startup_timeout_s", self.startup_timeout_s, 0.1, 30.0),
            ("invocation_timeout_s", self.invocation_timeout_s, 0.1, 300.0),
            ("shutdown_timeout_s", self.shutdown_timeout_s, 0.1, 10.0),
        ):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise SubprocessPluginError(f"{label} must be numeric")
            if not minimum <= float(value) <= maximum:
                raise SubprocessPluginError(
                    f"{label} must be between {minimum} and {maximum} seconds"
                )
            object.__setattr__(self, label, float(value))
        if type(self.max_frame_bytes) is not int or not 1024 <= self.max_frame_bytes <= SUBPROCESS_MAX_FRAME_BYTES:
            raise SubprocessPluginError("max_frame_bytes must be between 1 KiB and 2 MiB")
        if type(self.max_stderr_bytes) is not int or not 0 <= self.max_stderr_bytes <= SUBPROCESS_MAX_STDERR_BYTES:
            raise SubprocessPluginError("max_stderr_bytes must be between 0 and 64 KiB")

    def verify_artifact(self, expected_digest: str) -> None:
        if subprocess_artifact_digest(self.artifact) != expected_digest:
            raise SubprocessPluginError(
                "subprocess worker artifact does not match manifest artifact_digest"
            )

    def verify_launcher(self) -> None:
        actual_digest = _subprocess_launcher_digest(self.launcher)
        if not hmac.compare_digest(actual_digest, self.launcher_digest):
            raise SubprocessPluginError(
                "subprocess launcher changed after review"
            )

    def snapshot_artifact(
        self,
        expected_digest: str,
        *,
        snapshot_root: Path,
        plugin_id: str,
    ) -> tuple[Path, Path, InterProcessLock]:
        """Copy verified bytes into one private immutable launch generation."""

        root = _prepare_snapshot_root(snapshot_root)
        generation = f"generation-{secrets.token_hex(16)}"
        directory = root / generation
        target = directory / f"worker{self.artifact.suffix}"
        marker = directory / "owner.json"
        digest = hashlib.sha256()
        total = 0
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        janitor = InterProcessLock(root / ".janitor", timeout=2.0, poll=0.01)
        lease = _snapshot_lease(root, generation)
        cleanup_error: OSError | None = None
        try:
            try:
                janitor.acquire()
                directory.mkdir(mode=0o700)
                os.chmod(directory, 0o700)
                lease.acquire()
                marker_bytes = canonical_json(
                    {
                        "artifact_digest": expected_digest,
                        "plugin_id": plugin_id,
                        "snapshot_version": 1,
                    }
                )
                with marker.open("xb") as marker_stream:
                    marker_stream.write(marker_bytes)
                    marker_stream.flush()
                    os.fsync(marker_stream.fileno())
                source_fd = os.open(self.artifact, flags)
            except (OSError, TimeoutError) as exc:
                raise SubprocessPluginError(
                    "cannot open subprocess worker artifact for snapshot"
                ) from exc
            finally:
                janitor.release()
            try:
                source_stat = os.fstat(source_fd)
                if not stat.S_ISREG(source_stat.st_mode):
                    raise SubprocessPluginError(
                        "subprocess worker artifact snapshot source is not a file"
                    )
                with os.fdopen(source_fd, "rb", closefd=False) as source, target.open(
                    "xb"
                ) as destination:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > SUBPROCESS_MAX_ARTIFACT_BYTES:
                            raise SubprocessPluginError(
                                "subprocess worker artifact exceeds 64 MiB"
                            )
                        digest.update(chunk)
                        destination.write(chunk)
                    destination.flush()
                    os.fsync(destination.fileno())
            finally:
                os.close(source_fd)
            actual_digest = f"sha256:{digest.hexdigest()}"
            if not hmac.compare_digest(actual_digest, expected_digest):
                raise SubprocessPluginError(
                    "subprocess worker artifact changed before snapshot"
                )
            os.chmod(target, 0o500)
            return directory, target, lease
        except BaseException as exc:
            lease.release()
            try:
                if directory.exists():
                    _remove_private_tree(directory)
                lease.lock_path.unlink(missing_ok=True)
            except OSError as remove_exc:
                cleanup_error = remove_exc
            if cleanup_error is not None:
                raise SubprocessPluginError(
                    "subprocess snapshot setup failed and cleanup was incomplete"
                ) from exc
            raise

    @property
    def launch_profile_digest(self) -> str:
        """Bind every reviewed local launch choice without persisting its text."""

        document = {
            "arguments": list(self.arguments),
            "artifact": os.path.normcase(str(self.artifact)),
            "environment_keys": [key for key, _value in self.environment],
            "environment_profile_nonce": (
                self.environment_profile_nonce if self.environment else ""
            ),
            "invocation_timeout_s": format(self.invocation_timeout_s, ".17g"),
            "launcher": os.path.normcase(str(self.launcher)),
            "launcher_digest": self.launcher_digest,
            "max_frame_bytes": self.max_frame_bytes,
            "max_stderr_bytes": self.max_stderr_bytes,
            "profile_version": 2,
            "shutdown_timeout_s": format(self.shutdown_timeout_s, ".17g"),
            "startup_timeout_s": format(self.startup_timeout_s, ".17g"),
            "working_directory": os.path.normcase(str(self.working_directory)),
        }
        return "sha256:" + hashlib.sha256(canonical_json(document)).hexdigest()

    @property
    def command(self) -> Tuple[str, ...]:
        prefix = (str(self.launcher),)
        if self.launcher != self.artifact:
            prefix += (str(self.artifact),)
        return prefix + self.arguments

    def command_for_snapshot(self, snapshot: Path) -> Tuple[str, ...]:
        if self.launcher == self.artifact:
            return (str(snapshot),) + self.arguments
        return (str(self.launcher), str(snapshot)) + self.arguments


class _StdoutReader:
    def __init__(self, stream: BinaryIO, *, maximum: int) -> None:
        self.stream = stream
        self.maximum = maximum
        self.frames: queue.Queue[bytes] = queue.Queue(maxsize=8)
        self.error = ""
        self.closed = threading.Event()
        self.thread = threading.Thread(
            target=self._run,
            name="nth-plugin-rpc-stdout",
            daemon=True,
        )

    def start(self) -> None:
        self.thread.start()

    def _run(self) -> None:
        try:
            while True:
                line = self.stream.readline(self.maximum + 2)
                if not line:
                    return
                if not line.endswith(b"\n") or len(line.rstrip(b"\r\n")) > self.maximum:
                    self.error = "worker emitted an oversized or unterminated RPC frame"
                    return
                frame = line.rstrip(b"\r\n")
                try:
                    self.frames.put_nowait(frame)
                except queue.Full:
                    self.error = "worker emitted unsolicited RPC frames"
                    return
        except (OSError, ValueError) as exc:
            self.error = f"worker stdout reader failed: {type(exc).__name__}"
        finally:
            self.closed.set()


class _StderrReader:
    def __init__(self, stream: BinaryIO, *, maximum: int) -> None:
        self.stream = stream
        self.maximum = maximum
        self.total = 0
        self.digest = hmac.new(secrets.token_bytes(32), digestmod=hashlib.sha256)
        self.error = ""
        self.lock = threading.Lock()
        self.thread = threading.Thread(
            target=self._run,
            name="nth-plugin-rpc-stderr",
            daemon=True,
        )

    def start(self) -> None:
        self.thread.start()

    def _run(self) -> None:
        try:
            while True:
                chunk = self.stream.read(4096)
                if not chunk:
                    return
                with self.lock:
                    self.total += len(chunk)
                    self.digest.update(chunk)
                    if self.total > self.maximum:
                        self.error = "worker stderr exceeded its byte limit"
                        return
        except (OSError, ValueError):
            return

    def summary(self) -> str:
        with self.lock:
            if not self.total:
                return "stderr-bytes=0"
            return (
                f"stderr-bytes={self.total},"
                f"stderr-hmac-sha256={self.digest.hexdigest()}"
            )


class _SubprocessCapabilityProvider(CapabilityProvider):
    def __init__(self, runtime: "ReviewedSubprocessRuntime", capability_id: str) -> None:
        self.runtime = runtime
        self.capability_id = capability_id

    def invoke(
        self,
        payload: Mapping[str, Any],
        context: PluginInvocationContext,
    ) -> Mapping[str, Any]:
        if context.capability_id != self.capability_id:
            raise PluginProviderUnavailable("subprocess provider capability binding changed")
        return self.runtime.invoke(payload, context)


class ReviewedSubprocessRuntime:
    """One serialized, fail-closed RPC connection to a reviewed worker."""

    def __init__(self, manifest: PluginManifest, spec: ReviewedSubprocessSpec) -> None:
        if manifest.runtime != "subprocess":
            raise SubprocessPluginError("reviewed subprocess runtime requires runtime=subprocess")
        self.manifest = manifest
        self.spec = spec
        self._process: subprocess.Popen[bytes] | None = None
        self._stdout: _StdoutReader | None = None
        self._stderr: _StderrReader | None = None
        self._io_lock = threading.RLock()
        self._state_lock = threading.RLock()
        self._failure = ""
        self._started = False
        self._stopping = False
        self._failure_handler: Callable[[PluginProviderUnavailable], None] | None = None
        self._failure_notified = False
        self._monitor_thread: threading.Thread | None = None
        self._snapshot_directory: Path | None = None
        self._snapshot_lease: InterProcessLock | None = None
        self._snapshot_root: Path | None = None
        self._awaiting_response = False

    def start(self, context: PluginContext) -> Mapping[str, object]:
        with self._io_lock:
            if self._started or self._process is not None:
                raise SubprocessPluginError("subprocess plugin runtime is already started")
            if context.plugin_id != self.manifest.plugin_id:
                raise SubprocessPluginError("subprocess plugin context does not match manifest")
            if context.workspace_root is None:
                raise SubprocessPluginError(
                    "reviewed subprocess runtime requires a workspace root"
                )
            self.spec.verify_launcher()
            snapshot_root = (
                context.workspace_root / ".nth" / "plugin-host" / "snapshots"
            )
            snapshot_directory, snapshot_artifact, snapshot_lease = (
                self.spec.snapshot_artifact(
                    self.manifest.artifact_digest,
                    snapshot_root=snapshot_root,
                    plugin_id=self.manifest.plugin_id,
                )
            )
            self._snapshot_directory = snapshot_directory
            self._snapshot_lease = snapshot_lease
            self._snapshot_root = snapshot_root
            environment = self._environment()
            kwargs: Dict[str, Any] = {
                "stdin": subprocess.PIPE,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
                "cwd": str(self.spec.working_directory),
                "env": environment,
                "shell": False,
                "text": False,
                "bufsize": 0,
                "close_fds": True,
            }
            if os.name == "nt":
                kwargs["creationflags"] = (
                    getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                    | getattr(subprocess, "CREATE_NO_WINDOW", 0)
                )
            else:
                kwargs["start_new_session"] = True
            try:
                self.spec.verify_launcher()
            except SubprocessPluginError:
                self._remove_snapshot()
                raise
            try:
                process = subprocess.Popen(
                    list(self.spec.command_for_snapshot(snapshot_artifact)),
                    **kwargs,
                )
            except OSError as exc:
                self._remove_snapshot()
                raise SubprocessPluginError("cannot start reviewed subprocess worker") from exc
            self._process = process
            if process.stdin is None or process.stdout is None or process.stderr is None:
                self._break("subprocess worker pipes are unavailable")
                raise SubprocessPluginError(self._failure)
            self._stdout = _StdoutReader(process.stdout, maximum=self.spec.max_frame_bytes)
            self._stderr = _StderrReader(process.stderr, maximum=self.spec.max_stderr_bytes)
            self._stdout.start()
            self._stderr.start()
            nonce = secrets.token_hex(16)
            hello = {
                "protocol": SUBPROCESS_RPC_PROTOCOL,
                "version": SUBPROCESS_RPC_VERSION,
                "type": "hello",
                "plugin_id": self.manifest.plugin_id,
                "manifest_digest": self.manifest.digest,
                "nonce": nonce,
                "capability_ids": sorted(
                    item.capability_id for item in self.manifest.provides
                ),
            }
            try:
                ready = self._exchange(hello, self.spec.startup_timeout_s)
                self._validate_ready(ready, hello)
            except Exception as exc:
                self._break(f"subprocess worker handshake failed: {type(exc).__name__}")
                raise SubprocessPluginError(self._failure) from exc
            self._started = True
            self._stopping = False
            self._monitor_thread = threading.Thread(
                target=self._monitor,
                name="nth-plugin-rpc-monitor",
                daemon=True,
            )
            self._monitor_thread.start()
            return {
                item.capability_id: _SubprocessCapabilityProvider(
                    self, item.capability_id
                )
                for item in self.manifest.provides
            }

    def invoke(
        self,
        payload: Mapping[str, Any],
        context: PluginInvocationContext,
    ) -> Mapping[str, Any]:
        with self._io_lock:
            if self._failure:
                raise PluginProviderUnavailable(self._failure)
            if not self._started or self._process is None:
                raise PluginProviderUnavailable("subprocess plugin is not running")
            if self._process.poll() is not None:
                self._break("subprocess worker exited before invocation")
                raise PluginProviderUnavailable(self._failure)
            request = {
                "protocol": SUBPROCESS_RPC_PROTOCOL,
                "version": SUBPROCESS_RPC_VERSION,
                "type": "invoke",
                "invocation_id": context.invocation_id,
                "capability_id": context.capability_id,
                "payload": dict(payload),
                "context": {
                    "principal": context.authority.principal,
                    "capability_ids": sorted(context.authority.capability_ids),
                    "mandate_digest": context.authority.mandate_digest,
                    "idempotency_key": context.authority.idempotency_key,
                    "resource_ids": sorted(context.authority.resource_ids),
                    "granted_permissions": sorted(context.granted_permissions),
                },
            }
            try:
                encoded_request = subprocess_canonical_json(request)
            except (RecursionError, TypeError, ValueError) as exc:
                raise PluginInvocationError(
                    "subprocess RPC request is not representable by the wire protocol"
                ) from exc
            if len(encoded_request) > self.spec.max_frame_bytes:
                raise PluginInvocationError(
                    "subprocess RPC request exceeds the configured frame limit"
                )
            try:
                response = self._exchange(
                    request,
                    self.spec.invocation_timeout_s,
                )
                return self._validate_result(
                    response,
                    context.invocation_id,
                    context.capability_id,
                )
            except SubprocessRemoteError:
                raise
            except Exception as exc:
                detail = (
                    str(exc)
                    if isinstance(exc, SubprocessPluginError)
                    else type(exc).__name__
                )
                self._break(f"subprocess worker invocation failed: {detail}")
                raise PluginProviderUnavailable(self._failure) from exc

    def stop(self) -> None:
        with self._state_lock:
            self._stopping = True
        acquired = self._io_lock.acquire(timeout=0.05)
        if not acquired:
            with self._state_lock:
                if not self._failure:
                    self._failure = "subprocess worker was stopped during invocation"
                self._terminate_tree(force=True)
                self._close()
            return
        try:
            process = self._process
            if process is None:
                return
            if process.poll() is None and not self._failure:
                request_id = secrets.token_hex(16)
                try:
                    response = self._exchange(
                        {
                            "protocol": SUBPROCESS_RPC_PROTOCOL,
                            "version": SUBPROCESS_RPC_VERSION,
                            "type": "shutdown",
                            "request_id": request_id,
                        },
                        self.spec.shutdown_timeout_s,
                    )
                    if set(response) != {
                        "protocol",
                        "version",
                        "type",
                        "request_id",
                    } or response != {
                        "protocol": SUBPROCESS_RPC_PROTOCOL,
                        "version": SUBPROCESS_RPC_VERSION,
                        "type": "stopped",
                        "request_id": request_id,
                    }:
                        raise SubprocessPluginError("invalid shutdown acknowledgement")
                except Exception:
                    self._terminate_tree(force=True)
            if process.poll() is None:
                try:
                    process.wait(timeout=self.spec.shutdown_timeout_s)
                except subprocess.TimeoutExpired:
                    self._terminate_tree(force=True)
            self._close()
            if process.poll() is None:
                raise SubprocessPluginError("subprocess worker could not be terminated")
        finally:
            self._io_lock.release()

    def set_failure_handler(
        self,
        handler: Callable[[PluginProviderUnavailable], None],
    ) -> None:
        """Arm one Host callback for an asynchronous generation failure."""

        if not callable(handler):
            raise TypeError("subprocess failure handler must be callable")
        pending: PluginProviderUnavailable | None = None
        with self._state_lock:
            if self._failure_handler is not None:
                raise SubprocessPluginError("subprocess failure handler is already set")
            self._failure_handler = handler
            if self._failure and not self._failure_notified:
                self._failure_notified = True
                pending = PluginProviderUnavailable(self._failure)
        if pending is not None:
            handler(pending)

    def _monitor(self) -> None:
        while True:
            time.sleep(0.05)
            with self._state_lock:
                process = self._process
                if self._stopping or not self._started or self._failure:
                    return
                stdout_error = self._stdout.error if self._stdout is not None else ""
                stderr_error = self._stderr.error if self._stderr is not None else ""
                unsolicited = bool(
                    self._stdout is not None
                    and not self._awaiting_response
                    and not self._stdout.frames.empty()
                )
                exited = process is None or process.poll() is not None
            reason = stdout_error or stderr_error
            if not reason and unsolicited:
                reason = "worker emitted an unsolicited RPC frame"
            if not reason and exited:
                reason = "subprocess worker exited while idle"
            if reason:
                self._break(reason)
                self._notify_failure()
                return

    def _notify_failure(self) -> None:
        handler: Callable[[PluginProviderUnavailable], None] | None = None
        error: PluginProviderUnavailable | None = None
        with self._state_lock:
            if (
                self._failure
                and not self._failure_notified
                and self._failure_handler is not None
            ):
                self._failure_notified = True
                handler = self._failure_handler
                error = PluginProviderUnavailable(self._failure)
        if handler is not None and error is not None:
            handler(error)

    def _environment(self) -> Dict[str, str]:
        environment: Dict[str, str] = {}
        if os.name == "nt":
            for key in ("SYSTEMROOT", "WINDIR", "COMSPEC"):
                value = os.environ.get(key)
                if value:
                    environment[key] = value
        environment.update(
            {
                "NTH_PLUGIN_ID": self.manifest.plugin_id,
                "NTH_PLUGIN_MANIFEST_DIGEST": self.manifest.digest,
                "NTH_PLUGIN_RPC": SUBPROCESS_RPC_PROTOCOL,
                "NTH_PLUGIN_RPC_VERSION": str(SUBPROCESS_RPC_VERSION),
                "PYTHONIOENCODING": "utf-8",
                "PYTHONNOUSERSITE": "1",
                "PYTHONSAFEPATH": "1",
                "PYTHONUNBUFFERED": "1",
            }
        )
        environment.update(dict(self.spec.environment))
        return environment

    def _send(self, document: Dict[str, Any]) -> None:
        process = self._process
        if process is None or process.stdin is None or process.poll() is not None:
            raise EOFError("subprocess worker is not writable")
        encoded = subprocess_canonical_json(document)
        if len(encoded) > self.spec.max_frame_bytes:
            raise SubprocessPluginError("subprocess RPC request exceeds frame limit")
        try:
            process.stdin.write(encoded + b"\n")
            process.stdin.flush()
        except (BrokenPipeError, OSError, ValueError) as exc:
            raise EOFError("subprocess worker pipe closed") from exc

    def _exchange(self, document: Dict[str, Any], timeout_s: float) -> Dict[str, Any]:
        with self._state_lock:
            if self._awaiting_response:
                raise SubprocessPluginError(
                    "subprocess worker already has an in-flight request"
                )
            self._awaiting_response = True
        try:
            self._send(document)
            return self._receive(timeout_s)
        finally:
            with self._state_lock:
                self._awaiting_response = False

    def _receive(self, timeout_s: float) -> Dict[str, Any]:
        reader = self._stdout
        process = self._process
        if reader is None or process is None:
            raise EOFError("subprocess worker is not readable")
        deadline = time.monotonic() + timeout_s
        while True:
            if reader.error:
                raise SubprocessPluginError(reader.error)
            if self._stderr is not None and self._stderr.error:
                raise SubprocessPluginError(self._stderr.error)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("subprocess worker response timed out")
            try:
                raw = reader.frames.get(timeout=min(0.05, remaining))
                break
            except queue.Empty:
                if process.poll() is not None and reader.closed.is_set():
                    raise EOFError(
                        f"subprocess worker exited ({self._stderr_summary()})"
                    )
        def reject_duplicate_keys(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate JSON key")
                result[key] = value
            return result
        try:
            document = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=reject_duplicate_keys,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    ValueError(f"invalid JSON constant {value}")
                ),
                parse_int=lambda value: _parse_safe_rpc_integer(value),
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise SubprocessPluginError("subprocess worker emitted invalid JSON") from exc
        if not isinstance(document, dict):
            raise SubprocessPluginError("subprocess RPC response must be an object")
        try:
            if subprocess_canonical_json(document) != raw:
                raise SubprocessPluginError(
                    "subprocess worker response is not canonical JSON"
                )
        except (RecursionError, TypeError, ValueError) as exc:
            raise SubprocessPluginError(
                "subprocess worker response is not canonical JSON"
            ) from exc
        return document

    @staticmethod
    def _validate_ready(response: Dict[str, Any], request: Dict[str, Any]) -> None:
        expected_fields = {
            "protocol",
            "version",
            "type",
            "plugin_id",
            "manifest_digest",
            "nonce",
            "capability_ids",
        }
        if set(response) != expected_fields:
            raise SubprocessPluginError("subprocess ready fields are invalid")
        expected = {**request, "type": "ready"}
        if response != expected:
            raise SubprocessPluginError("subprocess ready binding does not match hello")

    def _validate_result(
        self,
        response: Dict[str, Any],
        invocation_id: str,
        capability_id: str,
    ) -> Mapping[str, Any]:
        common = {"protocol", "version", "type", "invocation_id", "ok"}
        if response.get("protocol") != SUBPROCESS_RPC_PROTOCOL or response.get("version") != SUBPROCESS_RPC_VERSION:
            raise SubprocessPluginError("subprocess result protocol is invalid")
        if response.get("type") != "result" or response.get("invocation_id") != invocation_id:
            raise SubprocessPluginError("subprocess result invocation binding is invalid")
        if type(response.get("ok")) is not bool:
            raise SubprocessPluginError("subprocess result ok flag is invalid")
        if response["ok"]:
            if set(response) != common | {"output"} or not isinstance(response.get("output"), dict):
                raise SubprocessPluginError("subprocess success result is invalid")
            return response["output"]
        if set(response) != common | {"error"} or not isinstance(response.get("error"), dict):
            raise SubprocessPluginError("subprocess error result is invalid")
        error = response["error"]
        if set(error) != {"code", "message", "retryable"}:
            raise SubprocessPluginError("subprocess error fields are invalid")
        code = error.get("code")
        message = error.get("message")
        retryable = error.get("retryable")
        if not isinstance(code, str) or not _ERROR_CODE_RE.fullmatch(code):
            raise SubprocessPluginError("subprocess error code is invalid")
        if (
            not isinstance(message, str)
            or not message
            or len(message.encode("utf-8")) > 512
            or any(ord(char) < 0x20 or ord(char) == 0x7F for char in message)
        ):
            raise SubprocessPluginError("subprocess error message is invalid")
        if type(retryable) is not bool:
            raise SubprocessPluginError("subprocess retryable flag is invalid")
        contract = next(
            (
                item
                for item in self.manifest.provides
                if item.capability_id == capability_id
            ),
            None,
        )
        if contract is None:
            raise SubprocessPluginError("subprocess capability contract is unavailable")
        if retryable and contract.failure_semantics not in {
            "best-effort",
            "retry-safe",
        }:
            raise SubprocessPluginError(
                "subprocess error retryability contradicts capability contract"
            )
        raise SubprocessRemoteError(code, message, retryable=retryable)

    def _break(self, reason: str) -> None:
        with self._state_lock:
            if not self._failure:
                self._failure = f"{reason}; {self._stderr_summary()}"[:1000]
            self._terminate_tree(force=True)
            try:
                self._close()
            except SubprocessPluginError:
                self._failure = f"{self._failure}; snapshot cleanup failed"[:1000]

    def _stderr_summary(self) -> str:
        return self._stderr.summary() if self._stderr is not None else "stderr-unavailable"

    def _terminate_tree(self, *, force: bool) -> None:
        process = self._process
        if process is None or process.poll() is not None:
            return
        try:
            if os.name == "nt":
                taskkill = _windows_taskkill_path()
                if taskkill is not None:
                    subprocess.run(
                        [str(taskkill), "/PID", str(process.pid), "/T", "/F"],
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=2.0,
                        check=False,
                        shell=False,
                        env={
                            "SYSTEMROOT": str(taskkill.parents[1]),
                            "WINDIR": str(taskkill.parents[1]),
                        },
                    )
                else:
                    process.kill() if force else process.terminate()
            else:
                os.killpg(process.pid, signal.SIGKILL if force else signal.SIGTERM)
        except (OSError, ProcessLookupError, subprocess.TimeoutExpired):
            try:
                process.kill() if force else process.terminate()
            except OSError:
                pass
        try:
            process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
            except OSError:
                pass

    def _close(self) -> None:
        process = self._process
        if process is not None:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass
        for reader in (self._stdout, self._stderr):
            if reader is not None and reader.thread is not threading.current_thread():
                reader.thread.join(timeout=0.2)
        monitor = self._monitor_thread
        if monitor is not None and monitor is not threading.current_thread():
            monitor.join(timeout=0.2)
        self._started = False
        self._remove_snapshot()

    def _remove_snapshot(self) -> None:
        directory = self._snapshot_directory
        lease = self._snapshot_lease
        root = self._snapshot_root
        if directory is None:
            return
        if lease is None or root is None:
            raise SubprocessPluginError("subprocess snapshot lease state is invalid")
        janitor = InterProcessLock(root / ".janitor", timeout=2.0, poll=0.01)
        try:
            janitor.acquire()
            if directory.exists():
                _remove_private_tree(directory)
            lease.release()
            lease.lock_path.unlink(missing_ok=True)
        except (OSError, TimeoutError) as exc:
            raise SubprocessPluginError(
                "subprocess snapshot cleanup failed"
            ) from exc
        finally:
            janitor.release()
        self._snapshot_directory = None
        self._snapshot_lease = None
        self._snapshot_root = None


def subprocess_rpc_protocol_document() -> Dict[str, Any]:
    """Return the language-neutral RPC v1 contract for other host runtimes."""

    return {
        "canonicalization": {
            "encoding": "utf-8",
            "floats": "forbidden",
            "framing": "one-canonical-json-object-per-line",
            "integer_range": "-(2^53-1)..(2^53-1)",
            "object_keys": "utf-16-code-unit-ascending-rfc8785",
            "root": "object",
            "whitespace": "none",
        },
        "limits": {
            "artifact_bytes": SUBPROCESS_MAX_ARTIFACT_BYTES,
            "frame_bytes": SUBPROCESS_MAX_FRAME_BYTES,
            "stderr_bytes": SUBPROCESS_MAX_STDERR_BYTES,
        },
        "messages": {
            "hello": [
                "protocol",
                "version",
                "type",
                "plugin_id",
                "manifest_digest",
                "nonce",
                "capability_ids",
            ],
            "invoke": [
                "protocol",
                "version",
                "type",
                "invocation_id",
                "capability_id",
                "payload",
                "context",
            ],
            "ready": [
                "protocol",
                "version",
                "type",
                "plugin_id",
                "manifest_digest",
                "nonce",
                "capability_ids",
            ],
            "result-error": [
                "protocol",
                "version",
                "type",
                "invocation_id",
                "ok",
                "error",
            ],
            "result-success": [
                "protocol",
                "version",
                "type",
                "invocation_id",
                "ok",
                "output",
            ],
            "shutdown": ["protocol", "version", "type", "request_id"],
            "stopped": ["protocol", "version", "type", "request_id"],
        },
        "protocol": SUBPROCESS_RPC_PROTOCOL,
        "semantics": {
            "authority": "host-verified-context-never-worker-derived",
            "business_error": "bounded-error-does-not-revoke-generation",
            "fatal_error": "timeout-crash-or-protocol-failure-revokes-generation",
            "handshake": "exact-echo-binds-nonce-plugin-manifest-and-capabilities",
            "invocation": "one-in-flight-request-per-worker",
            "stderr": "bounded-byte-count-and-process-local-keyed-fingerprint",
        },
        "trust_boundary": {
            "artifact": "private-entry-snapshot-sha256-verified-before-each-start",
            "environment": "minimal-host-baseline-plus-explicit-reviewed-values",
            "external_packages": "unsupported",
            "irreversible_capabilities": "unsupported",
            "os_sandbox": "not-provided",
            "publisher_signatures": "not-verified",
            "resource_quotas": "not-provided",
        },
        "version": SUBPROCESS_RPC_VERSION,
    }


def subprocess_rpc_protocol_digest() -> str:
    return "sha256:" + hashlib.sha256(
        subprocess_canonical_json(subprocess_rpc_protocol_document())
    ).hexdigest()


def subprocess_rpc_wire_vectors() -> Dict[str, Any]:
    """Return deterministic handshake and invocation examples for ports."""

    manifest_digest = "sha256:" + "a" * 64
    invocation_id = "b" * 32
    request_id = "c" * 32
    nonce = "d" * 32
    capability_id = "org.nth-dao.example.echo"
    plugin_id = "org.nth-dao.example.worker"
    hello = {
        "protocol": SUBPROCESS_RPC_PROTOCOL,
        "version": SUBPROCESS_RPC_VERSION,
        "type": "hello",
        "plugin_id": plugin_id,
        "manifest_digest": manifest_digest,
        "nonce": nonce,
        "capability_ids": [capability_id],
    }
    records = [
        ("hello", hello),
        ("ready", {**hello, "type": "ready"}),
        (
            "invoke",
            {
                "protocol": SUBPROCESS_RPC_PROTOCOL,
                "version": SUBPROCESS_RPC_VERSION,
                "type": "invoke",
                "invocation_id": invocation_id,
                "capability_id": capability_id,
                "payload": {"value": "hello"},
                "context": {
                    "principal": "did:key:example",
                    "capability_ids": [capability_id],
                    "mandate_digest": "",
                    "idempotency_key": "request-1",
                    "resource_ids": [],
                    "granted_permissions": [],
                },
            },
        ),
        (
            "result-success",
            {
                "protocol": SUBPROCESS_RPC_PROTOCOL,
                "version": SUBPROCESS_RPC_VERSION,
                "type": "result",
                "invocation_id": invocation_id,
                "ok": True,
                "output": {"value": "hello"},
            },
        ),
        (
            "result-error",
            {
                "protocol": SUBPROCESS_RPC_PROTOCOL,
                "version": SUBPROCESS_RPC_VERSION,
                "type": "result",
                "invocation_id": invocation_id,
                "ok": False,
                "error": {
                    "code": "not-ready",
                    "message": "worker is warming up",
                    "retryable": True,
                },
            },
        ),
        (
            "shutdown",
            {
                "protocol": SUBPROCESS_RPC_PROTOCOL,
                "version": SUBPROCESS_RPC_VERSION,
                "type": "shutdown",
                "request_id": request_id,
            },
        ),
        (
            "stopped",
            {
                "protocol": SUBPROCESS_RPC_PROTOCOL,
                "version": SUBPROCESS_RPC_VERSION,
                "type": "stopped",
                "request_id": request_id,
            },
        ),
    ]
    examples = []
    for name, document in records:
        encoded = subprocess_canonical_json(document)
        examples.append(
            {
                "canonical_utf8": encoded.decode("utf-8"),
                "document": document,
                "name": name,
                "sha256": "sha256:" + hashlib.sha256(encoded).hexdigest(),
            }
        )
    unicode_document = {"\ue000": 1, "\U00010000": SUBPROCESS_MAX_SAFE_INTEGER}
    unicode_encoded = subprocess_canonical_json(unicode_document)
    return {
        "canonical_examples": [
            {
                "canonical_utf8": unicode_encoded.decode("utf-8"),
                "document": unicode_document,
                "name": "non-bmp-key-order-and-safe-integer",
                "sha256": "sha256:"
                + hashlib.sha256(unicode_encoded).hexdigest(),
            }
        ],
        "examples": examples,
        "format": "nth-dao-plugin-subprocess-rpc-v1",
        "protocol_digest": subprocess_rpc_protocol_digest(),
        "schema_version": 1,
    }


__all__ = [
    "ReviewedSubprocessRuntime",
    "ReviewedSubprocessSpec",
    "SUBPROCESS_MAX_ARTIFACT_BYTES",
    "SUBPROCESS_MAX_FRAME_BYTES",
    "SUBPROCESS_MAX_STDERR_BYTES",
    "SUBPROCESS_MAX_SAFE_INTEGER",
    "SUBPROCESS_RPC_PROTOCOL",
    "SUBPROCESS_RPC_VERSION",
    "SubprocessPluginError",
    "SubprocessRemoteError",
    "subprocess_canonical_json",
    "subprocess_artifact_digest",
    "subprocess_rpc_protocol_digest",
    "subprocess_rpc_protocol_document",
    "subprocess_rpc_wire_vectors",
]
