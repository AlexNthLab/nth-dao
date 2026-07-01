"""
Agent supervisor — Phase 3a/3b/3c of the local-hub plan.

The supervisor is a per-app singleton (on ``app.state.v2_supervisor``)
that holds a registry of live agents and a runner-strategy that
knows how to actually start / stop them.

  Supervisor      ── owns the agent registry (dict by agent_id)
       │
       └── Runner ── strategy for the OS-level lifecycle
           ├── InMemoryRunner   — tests; tracks alive flag only
           └── SubprocessRunner — production; spawns
                                 nth_dao.web.dummy_agent as a child

Phase 3a scope:
  - Spawn / stop / list / liveness check
  - Threading: a reader thread per subprocess agent drains stdout
    JSON events; the supervisor updates ``last_seen`` on heartbeat
  - Graceful stop: terminate(); fall back to kill() after a timeout

Phase 3b (2026-06-11):
  - Runner.start() now returns (pid, did) and is synchronous:
    SubprocessRunner blocks until the child emits its first
    ``agent_started`` NDJSON event with a ``did`` field.
  - InMemoryRunner generates a real-shape did:key from random
    bytes (no signing key needed — tests never actually sign).
  - Supervisor.spawn() takes an optional ``cap_token_issuer``
    callback. After the child reports its DID, the supervisor
    calls the issuer with (did, capabilities) and stamps the
    returned token's ``token_id`` on the AgentRecord. Issuer
    raising → kill child before re-raise.

Phase 3c (2026-06-11):
  - Cap_token tempfile delivery: after issuance the supervisor
    atomic-writes the signed token JSON to
    ``<cap_token_dir>/<agent_id>/cap_token.json``; the runner
    passes that path to the child via ``--cap-token-file``.
    Child polls and loads on next tick, then signs its own
    ``nth.agent_attestation`` receipt and emits ``receipt_signed``.
  - Receipt persistor: AgentSupervisor accepts a callback that
    forwards ``receipt_signed`` events to the hub's ReceiptStore.
    Without it the receipt is logged at INFO and dropped.
  - A2A localhost port: the child opens a stdlib HTTP server on
    a random port and advertises it in ``agent_started.a2a_port``.
    Phase 3c only LOGS the port; Phase 3d will stamp it on
    AgentRecord + AgentEntryM for the routing layer to consume.
  - Handshake timeout is environment-configurable via
    ``NTH_AGENT_HANDSHAKE_TIMEOUT_S`` (float seconds, positive).
    Falls back to the 10s module default if absent / malformed.

Phase 3d will add:
  - a2a_port stamping + a hub-side A2A RPC router that uses it.
  - Decision raising from agent → /api/v2/decisions/raise

Thread safety: the supervisor's ``_lock`` serialises mutations.
The runner instances are individually responsible for their own
process state. Tests use InMemoryRunner so they don't pay the
subprocess cost.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Protocol, Tuple

logger = logging.getLogger(__name__)


# 运行态 agent 数量天花板(2026-06-14 审查补:项目反复强调 auto/scale 路径
# 必须有显式上限,而 spawn 之前没有任何上限——跑飞的循环/误用/带 token 的
# CSRF 可无限拉起子进程耗尽机器)。默认 32,可由 NTH_MAX_LIVE_AGENTS 覆盖;
# <=0 视为"不限"(回到旧行为,但需显式选择)。
def _default_max_live_agents() -> int:
    try:
        return int(os.environ.get("NTH_MAX_LIVE_AGENTS", "32"))
    except (TypeError, ValueError):
        return 32


class AgentCapacityExceeded(RuntimeError):
    """spawn 时存活 agent 数已达上限。端点应映射为 HTTP 429。"""



# ─────────────────────────────────────────────────────────────
# Data
# ─────────────────────────────────────────────────────────────


@dataclass
class AgentRecord:
    """One supervised agent's hub-side state.

    Mirrors the v2 ``AgentEntry`` shape used by /api/v2/agents
    so the supervisor can be merged with the disk reader without
    a translation layer. """
    agent_id: str
    kind: str
    label: str
    did: str
    capabilities: List[str]
    started_at: str
    last_seen: str
    pid: Optional[int] = None
    alive: bool = True
    # Reserved for Phase 3b — populated when the hub issues a
    # cap_token on spawn.
    cap_token_id: Optional[str] = None
    # Phase 3d (2026-06-11): the child's localhost A2A HTTP port,
    # advertised on agent_started.a2a_port and stamped by the
    # supervisor's on_event handler. None when the child didn't
    # bind (degraded state) or for InMemoryRunner where no real
    # server exists. The hub's A2A proxy uses this to route a
    # request to the child.
    a2a_port: Optional[int] = None

    def to_agent_entry(self) -> Dict[str, Any]:
        """Translate to the dict shape /api/v2/agents returns.

        M-5 fix (2026-06-11): ``capabilities`` is shallow-copied
        so a caller mutating the returned list can't poison the
        record's internal state. Other fields are immutable (str/
        int/bool/None) so no further copy needed. """
        return {
            "agent_id": self.agent_id,
            "did": self.did,
            "code": self.agent_id[:9],
            "label": self.label,
            "source": "local",
            "capabilities": list(self.capabilities),
            "last_seen": self.last_seen,
            "has_active_cap": self.cap_token_id is not None,
            # Surfaces hub-supervised origin so the UI can show a
            # "live" badge distinct from a contact / LAN peer.
            "supervised": True,
            "alive": self.alive,
            "kind": self.kind,
            # Phase 3d: surface the A2A port so the v2 console can
            # show a "reachable on :PORT" badge / call the proxy.
            "a2a_port": self.a2a_port,
        }


# ─────────────────────────────────────────────────────────────
# Runner strategies
# ─────────────────────────────────────────────────────────────


class AgentRunner(Protocol):
    """OS-lifecycle strategy. Methods are simple and synchronous;
    threading concerns live in the supervisor, not here.

    Phase 3b: ``start()`` is synchronous w.r.t. the DID handshake —
    it blocks until the agent has reported its W3C did:key, so
    callers can register the AgentRecord under the real DID.
    Note that ``on_event`` forwarding for that same ``agent_started``
    line happens AFTER start() unblocks, on the reader thread. The
    handshake is a result of ``start()``; the event-stream emission
    is not — they're concurrent. Callers waiting to OBSERVE the
    ``agent_started`` event via ``on_event`` still need a brief
    grace period (see SubprocessRunner._read_stdout_loop and the
    smoke test's polling window).

    Phase 3c: ``cap_token_file_path`` lets the supervisor pre-
    declare where the child should look for its issued cap_token.
    InMemoryRunner ignores it (tests don't deliver tokens).
    SubprocessRunner appends ``--cap-token-file <path>`` so the
    child polls that path on each tick. """

    def start(
        self,
        agent_id: str,
        kind: str,
        *,
        cap_token_file_path: Optional[str] = None,
        identity_file: Optional[str] = None,
    ) -> Tuple[Optional[int], str]:
        """Start the agent process and wait for its DID handshake.

        Returns ``(pid, did)``. On failure (spawn error, handshake
        timeout, missing DID in the first event) returns
        ``(None, "")`` and ensures any partially-started child is
        cleaned up before returning. """
        ...

    def stop(self, agent_id: str) -> None:
        """Request graceful stop; block until terminated or
        timeout, then force-kill. Idempotent. """
        ...

    def is_alive(self, agent_id: str) -> bool:
        ...

    def handshake_data(self, agent_id: str) -> Dict[str, Any]:
        """Return a shallow copy of any structured handshake
        metadata captured at start() time (Phase 3d). At minimum
        the SubprocessRunner stores ``did``, ``pubkey_hex``, and
        ``a2a_port`` if the child advertised one. InMemoryRunner
        returns an empty dict since there's no real handshake.

        Contract (A-1 doc, review round Phase 3d R1):
          - Must be ready by the time ``start()`` returns with a
            non-empty DID. The supervisor reads this immediately
            after ``start()`` and expects the data to be populated.
          - Must be safe to call concurrently with other methods.
          - Must NOT raise except for ``AttributeError`` on legacy
            runners that don't implement the method — the
            supervisor relies on that one allowed exception type
            to provide a forward-compatible fallback. Any other
            exception is treated as a bug. """
        ...


# Phase 3b: how long SubprocessRunner waits for the child's first
# ``agent_started`` event before assuming the spawn failed. Python
# startup + AgentIdentity.generate() takes ~200ms on a warm cache,
# up to a few seconds on first-ever import. 10s is conservative.
_DEFAULT_HANDSHAKE_TIMEOUT_S = 10.0

# Phase 3c: env-var override. Production hubs on slow filesystems
# (network-mounted workspaces, Windows AV scanning) may need a
# bigger window; CI shards may want a smaller one to fail fast on
# stuck children.
_HANDSHAKE_TIMEOUT_ENV_VAR = "NTH_AGENT_HANDSHAKE_TIMEOUT_S"


def _read_handshake_timeout_from_env() -> float:
    """Resolve the handshake timeout from the environment.

    Returns the module default if the var is absent, empty, not a
    valid float, or non-positive. Logs a WARNING in the malformed
    cases so the operator notices instead of silently falling back. """
    raw = os.environ.get(_HANDSHAKE_TIMEOUT_ENV_VAR, "").strip()
    if not raw:
        return _DEFAULT_HANDSHAKE_TIMEOUT_S
    try:
        value = float(raw)
    except ValueError:
        logger.warning(
            "agent_supervisor: %s=%r is not a number; using default %.1fs",
            _HANDSHAKE_TIMEOUT_ENV_VAR, raw, _DEFAULT_HANDSHAKE_TIMEOUT_S,
        )
        return _DEFAULT_HANDSHAKE_TIMEOUT_S
    if value <= 0:
        logger.warning(
            "agent_supervisor: %s=%r must be positive; using default %.1fs",
            _HANDSHAKE_TIMEOUT_ENV_VAR, raw, _DEFAULT_HANDSHAKE_TIMEOUT_S,
        )
        return _DEFAULT_HANDSHAKE_TIMEOUT_S
    return value


class InMemoryRunner:
    """Test runner — no OS process. Spawn flips an alive flag and
    mints a real-shape ``did:key`` for the agent.

    Phase 3b: the DID is encoded from 32 random bytes via the
    project's own W3C codec, so it round-trips through
    ``is_did_key`` / ``decode_ed25519_did_key`` without needing
    PyNaCl. Tests that call ``cap_token.sign_cap_token`` with this
    DID as ``subject_did`` will pass the shape check; verification
    against a real signing key isn't possible because we never
    generated one, but Phase 3b's InMemoryRunner doesn't sign. """

    def __init__(self) -> None:
        self._alive: Dict[str, bool] = {}
        self._counter = 0
        self._lock = threading.Lock()

    def start(
        self,
        agent_id: str,
        kind: str,
        *,
        cap_token_file_path: Optional[str] = None,  # noqa: ARG002 — ignored
        identity_file: Optional[str] = None,  # noqa: ARG002 — ignored (no child)
    ) -> Tuple[Optional[int], str]:
        # Phase 3c: ``cap_token_file_path`` is accepted for protocol
        # parity but ignored — InMemoryRunner has no child to read
        # from disk. Tests that exercise the file-delivery path use
        # SubprocessRunner with a tmp_path-scoped cap_token_dir.
        #
        # Lazy local import — keeps ``did_key`` off the module-load
        # path for the production hub, which only ever instantiates
        # SubprocessRunner via build_default_supervisor(). Tests pay
        # the import cost on first spawn (it's cached by sys.modules
        # for subsequent calls, so the per-spawn overhead is a dict
        # lookup, not a re-parse).
        from nth_dao.did_key import encode_ed25519_did_key
        did = encode_ed25519_did_key(os.urandom(32))
        with self._lock:
            self._counter += 1
            self._alive[agent_id] = True
        return 10_000 + self._counter, did

    def stop(self, agent_id: str) -> None:
        with self._lock:
            self._alive[agent_id] = False

    def is_alive(self, agent_id: str) -> bool:
        return self._alive.get(agent_id, False)

    def handshake_data(self, agent_id: str) -> Dict[str, Any]:
        # No real handshake happens for the in-memory runner —
        # tests that need a port can construct a custom subclass.
        return {}


class SubprocessRunner:
    """Production runner — spawns nth_dao.web.dummy_agent as a
    child python process. One reader thread per child drains its
    stdout JSON events and forwards heartbeats to the supervisor
    via the ``on_event`` callback.

    Process death detection: poll() each time is_alive is asked.
    The reader thread also notices EOF on stdout and stops. """

    def __init__(
        self,
        on_event: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        handshake_timeout: Optional[float] = None,
        workspace: Optional[Path] = None,
    ) -> None:
        # Phase 3c: env-var override is consulted ONCE at runner
        # construction. Per-spawn override would let one wild test
        # poison another; this way the operator sets the env once at
        # hub launch and every spawn under that supervisor honours it.
        if handshake_timeout is None:
            handshake_timeout = _read_handshake_timeout_from_env()
        # 切片B:共享 workspace,spawn 时作为 --workspace 传给子 agent,让它
        # 够得到市场 feed/claim store 去认领。None → 子进程拿不到,claim 方法
        # 返回 no-workspace(认领禁用,其余功能不受影响)。
        self._workspace = workspace
        self._procs: Dict[str, subprocess.Popen] = {}
        # N-1 fix (2026-06-11): track BOTH stdout and stderr reader
        # threads so a future shutdown / health check can iterate
        # them symmetrically. The previous version registered only
        # stdout, leaving stderr as a fire-and-forget daemon that
        # was invisible to any future ``for t in self._readers``
        # introspection.
        self._stdout_readers: Dict[str, threading.Thread] = {}
        self._stderr_readers: Dict[str, threading.Thread] = {}
        # Phase 3b: each spawn allocates a per-agent Event + result
        # slot. The reader thread sets the event when the first
        # ``agent_started`` line arrives; start() blocks on it
        # for at most ``handshake_timeout`` seconds.
        self._handshake_events: Dict[str, threading.Event] = {}
        self._handshake_data: Dict[str, Dict[str, Any]] = {}
        self._handshake_timeout = handshake_timeout
        self._on_event = on_event
        self._lock = threading.Lock()

    def start(
        self,
        agent_id: str,
        kind: str,
        *,
        cap_token_file_path: Optional[str] = None,
        identity_file: Optional[str] = None,
    ) -> Tuple[Optional[int], str]:
        # Spawn `python -m nth_dao.web.dummy_agent --id … --kind …`.
        # Using sys.executable keeps the child on the same interpreter
        # as the hub — important on Windows where multiple Pythons
        # may be installed.
        cmd = [
            sys.executable, "-m", "nth_dao.web.dummy_agent",
            "--id", agent_id,
            "--kind", kind,
        ]
        if cap_token_file_path:
            # Phase 3c: child polls this path each tick; appears
            # AFTER the supervisor receives the DID handshake and
            # invokes the cap_token_issuer.
            cmd.extend(["--cap-token-file", cap_token_file_path])
        if identity_file:
            # 持久身份:子进程载入已存密钥 → 重启后同一 DID(持久化恢复用)。
            cmd.extend(["--identity-file", identity_file])
        if self._workspace is not None:
            # 切片B:共享 workspace,让子 agent 的 claim 方法够到市场文件。
            cmd.extend(["--workspace", str(self._workspace)])
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                # H-1 fix (2026-06-11): stderr piped, NOT DEVNULL.
                # The previous DEVNULL silently swallowed every
                # child traceback / ImportError / dependency
                # failure — operators saw "spawn returned 201,
                # agent dies immediately" with zero diagnostic.
                # Now a dedicated reader thread logs each stderr
                # line at WARNING level so the operator sees the
                # actual child-side failure.
                stderr=subprocess.PIPE,
                text=True,
                # On Windows, CREATE_NEW_PROCESS_GROUP lets us send
                # CTRL_BREAK_EVENT to terminate gracefully. POSIX
                # ignores the flag.
                creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("agent_supervisor: spawn failed for %s: %s",
                           agent_id, exc)
            return None, ""

        # H-2 fix (2026-06-11): both proc and reader thread are
        # registered inside a SINGLE lock acquisition. Two locks
        # had a gap during which stop() could pop _readers (no-op)
        # before we wrote it; the post-stop write then leaked.
        # Starting the thread inside the lock is safe — t.start()
        # only schedules the OS thread; the reader's first work is
        # reading proc.stdout which is independent of supervisor
        # state.
        # M-1 fix (2026-06-11): str() coerce defends against a
        # None agent_id sneaking in from a misuse of the Protocol.
        stdout_thread = threading.Thread(
            target=self._read_stdout_loop,
            args=(agent_id, proc),
            name=f"agent-reader-{str(agent_id or '')[:8]}",
            daemon=True,
        )
        stderr_thread = threading.Thread(
            target=self._read_stderr_loop,
            args=(agent_id, proc),
            name=f"agent-stderr-{str(agent_id or '')[:8]}",
            daemon=True,
        )
        handshake_event = threading.Event()
        with self._lock:
            self._procs[agent_id] = proc
            self._stdout_readers[agent_id] = stdout_thread
            self._stderr_readers[agent_id] = stderr_thread
            self._handshake_events[agent_id] = handshake_event
            self._handshake_data[agent_id] = {}
        stdout_thread.start()
        stderr_thread.start()

        # Phase 3b: block until the child has emitted ``agent_started``
        # with a ``did`` field. We do NOT hold the lock during wait —
        # the reader thread needs to acquire it to record the
        # handshake data. Timeout → tear the child down before
        # returning so we don't leak a half-started process.
        if not handshake_event.wait(timeout=self._handshake_timeout):
            logger.warning(
                "agent_supervisor: %s did not report DID within %.1fs — "
                "killing child", agent_id, self._handshake_timeout,
            )
            self.stop(agent_id)
            return None, ""
        with self._lock:
            data = dict(self._handshake_data.get(agent_id, {}))
        did = str(data.get("did") or "")
        if not did:
            logger.warning(
                "agent_supervisor: %s agent_started event missing 'did' — "
                "killing child", agent_id,
            )
            self.stop(agent_id)
            return None, ""
        return proc.pid, did

    def stop(self, agent_id: str) -> None:
        with self._lock:
            proc = self._procs.get(agent_id)
        if proc is None:
            return
        try:
            # Review fix #4 (2026-06-11): wrap terminate() in
            # OSError catch — if the process already exited
            # between the dict fetch above and this call, Windows
            # raises PermissionError / OSError on TerminateProcess.
            # We're already cleaning up the registry in finally;
            # propagating the exception to the HTTP layer was
            # giving the user a misleading 500.
            try:
                proc.terminate()
            except OSError as exc:
                logger.debug(
                    "agent_supervisor: terminate %s raced with exit: %s",
                    agent_id, exc,
                )
            # Give the child a chance to print its goodbye event.
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                except OSError as exc:
                    logger.debug(
                        "agent_supervisor: kill %s raced with exit: %s",
                        agent_id, exc,
                    )
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass
        finally:
            with self._lock:
                self._procs.pop(agent_id, None)
                self._stdout_readers.pop(agent_id, None)
                self._stderr_readers.pop(agent_id, None)
                # Phase 3b: free the handshake slots. If start() is
                # still blocking on the event (handshake_timeout
                # hasn't fired yet), set it now so the waiter wakes
                # up and falls through to the "" return on a missing
                # did — far better than the caller hanging until
                # timeout when we already know the child is gone.
                self._handshake_data.pop(agent_id, None)
                ev = self._handshake_events.pop(agent_id, None)
            if ev is not None:
                ev.set()

    def is_alive(self, agent_id: str) -> bool:
        with self._lock:
            proc = self._procs.get(agent_id)
        if proc is None:
            return False
        return proc.poll() is None

    def handshake_data(self, agent_id: str) -> Dict[str, Any]:
        # Phase 3d: return a copy so callers can mutate freely
        # without poisoning the runner's internal slot.
        with self._lock:
            return dict(self._handshake_data.get(agent_id, {}))

    def _read_stdout_loop(self, agent_id: str, proc: subprocess.Popen) -> None:
        """Drain the child's stdout, forwarding parsed JSON events
        to the supervisor's callback. Quietly exits on EOF.

        L-4 fix (2026-06-11): non-JSON lines from stdout now log
        at WARNING (was DEBUG, which production rarely shows). If
        the child accidentally print()s a stray line, the operator
        sees it. """
        stdout = proc.stdout
        if stdout is None:
            return
        try:
            for line in stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    logger.warning(
                        "agent_supervisor: non-JSON stdout from %s: %r",
                        agent_id, line[:120],
                    )
                    continue
                # Phase 3b: when the first ``agent_started`` lands,
                # stash the did/pubkey for start()'s waiter and set
                # the handshake event. Doing this BEFORE on_event
                # forwarding so an on_event callback that raises
                # can't deadlock start(). Multiple agent_started
                # lines (shouldn't happen but defensive) only honor
                # the first — once handshake_data has a did we leave
                # it alone.
                if event.get("event") == "agent_started":
                    with self._lock:
                        slot = self._handshake_data.get(agent_id)
                        ev = self._handshake_events.get(agent_id)
                        if slot is not None and not slot.get("did"):
                            slot["did"] = str(event.get("did") or "")
                            slot["pubkey_hex"] = str(
                                event.get("pubkey_hex") or ""
                            )
                            # Phase 3d: stash a2a_port here so spawn()
                            # can stamp it on the AgentRecord at
                            # construct time — avoids the race that
                            # would otherwise exist between this
                            # reader thread firing on_event and
                            # spawn() inserting the record.
                            port = event.get("a2a_port")
                            if isinstance(port, int) and port > 0:
                                slot["a2a_port"] = port
                    if ev is not None:
                        ev.set()
                if self._on_event is not None:
                    try:
                        self._on_event(agent_id, event)
                    except Exception as exc:  # noqa: BLE001
                        logger.warning(
                            "agent_supervisor: on_event raised for %s: %s",
                            agent_id, exc,
                        )
        except Exception as exc:  # noqa: BLE001
            # The child may have been killed mid-read; that's fine.
            logger.debug("agent reader %s loop ended: %s", agent_id, exc)

    def _read_stderr_loop(self, agent_id: str, proc: subprocess.Popen) -> None:
        """H-1 fix (2026-06-11): drain the child's stderr to the
        hub log. Every line is surfaced at WARNING level so a
        traceback from the child (ImportError, missing dependency,
        crash) lands in the operator's log instead of /dev/null.
        Empty lines are skipped to avoid log noise. """
        stderr = proc.stderr
        if stderr is None:
            return
        try:
            for line in stderr:
                line = line.strip()
                if not line:
                    continue
                logger.warning("agent[%s] stderr: %s", agent_id, line[:200])
        except Exception as exc:  # noqa: BLE001
            logger.debug("agent stderr reader %s loop ended: %s", agent_id, exc)


# ─────────────────────────────────────────────────────────────
# Supervisor
# ─────────────────────────────────────────────────────────────


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _atomic_write_json(path: str, payload: Dict[str, Any]) -> None:
    """Write ``payload`` as JSON to ``path`` atomically + restrictively.

    Used by the supervisor to land cap_token files where the child
    is polling. Atomic via tmp + os.replace, so the child cannot
    see a partial / truncated file even if the writer crashes
    mid-flight.

    H-2 fix (review round Phase 3c R2): cap_token files are bearer
    tokens, so we ``chmod 0o600`` BEFORE the os.replace. POSIX
    ``os.replace`` preserves the REPLACING file's permissions
    (the tmp), not the replaced file's — G-1 detail from the
    meta-review. Setting 0o600 on the final path AFTER replace
    would leave a small window where the file inherited the tmp's
    umask-defaulted mode. Windows ignores POSIX bits but raises
    no error, and the workspace path is per-user-ACL'd there
    anyway. chmod failures (FAT, network mounts without POSIX
    mode) are best-effort logged + survived rather than aborting
    the delivery — the alternative is no token file at all. """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    try:
        os.chmod(str(tmp), 0o600)
    except OSError as exc:
        logger.debug(
            "agent_supervisor: chmod 0o600 on %s not supported (%s); "
            "delivery proceeds with default permissions",
            tmp, exc,
        )
    # M-2 fix (review round Phase 3d R1): if os.replace raises
    # (cross-device, perm flip, transient EBUSY on Windows), the
    # tmp file is left behind and would never be cleaned up
    # because stop()'s cleanup loop only knows about cap_token.json
    # / last_receipt.json. Try/finally that unlinks the tmp on
    # replace-failure keeps the agent dir tidy.
    try:
        os.replace(str(tmp), str(p))
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


# Phase 3b: signature of the optional ``cap_token_issuer`` callback
# the supervisor invokes after a child has reported its DID. The
# callback receives ``(subject_did, capabilities)`` and returns a
# signed token dict (must have ``token_id``) or None to skip
# issuance. Any exception is treated as fatal — the spawned agent
# is stopped and the exception re-raised.
CapTokenIssuer = Callable[[str, List[str]], Optional[Dict[str, Any]]]


class AgentSupervisor:
    """Per-app singleton holding the registry of supervised agents.

    Methods are thread-safe; mutations go through ``_lock``. Reads
    of the registry (list_agents, get) make a shallow copy so
    callers can iterate without holding the lock.

    Phase 3c additions:
      cap_token_dir   — where per-agent cap_token files live. After
                        the issuer signs a token, ``spawn`` atomic-
                        writes it under ``<dir>/<agent_id>/cap_token.json``
                        so the child can read it. None disables the
                        file-delivery path entirely (Phase 3b semantics).
      receipt_persistor — invoked with ``(agent_id, receipt_dict)``
                        whenever a child emits a ``receipt_signed``
                        event. None → the receipt is INFO-logged and
                        dropped. Errors from the persistor are caught
                        + WARNING-logged; they do NOT kill the agent
                        (a single failed persist shouldn't take an
                        otherwise healthy agent offline). """

    def __init__(
        self,
        runner: AgentRunner,
        *,
        cap_token_dir: Optional[Path] = None,
        receipt_persistor: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        decision_raiser: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        max_live_agents: Optional[int] = None,
    ) -> None:
        self._runner = runner
        self._agents: Dict[str, AgentRecord] = {}
        self._lock = threading.Lock()
        # 运行态上限:None → 取 NTH_MAX_LIVE_AGENTS / 默认 32;<=0 表示不限。
        self._max_live_agents = (
            _default_max_live_agents() if max_live_agents is None
            else max_live_agents
        )
        self._cap_token_dir = cap_token_dir
        self._receipt_persistor = receipt_persistor
        # Phase 3d: invoked when a child emits ``decision_raised``.
        # v2_api wires this to insert the decision into the v2
        # decisions store (and assign an id if the child didn't).
        # None → INFO-log + drop, same pattern as receipt_persistor.
        self._decision_raiser = decision_raiser

    def spawn(
        self,
        *,
        kind: str,
        label: str,
        capabilities: Optional[List[str]] = None,
        cap_token_issuer: Optional[CapTokenIssuer] = None,
        identity_file: Optional[str] = None,
    ) -> AgentRecord:
        """Spawn a new supervised agent.

        ``identity_file``(持久化):非空时透传给子进程 ``--identity-file`` —— 存在则
        载入(重启后同一 DID),否则生成并保存到此路径供下次复用。空 = 临时身份。

        Phase 3b: ``start()`` blocks until the child has reported its
        W3C did:key, so by the time this method returns the AgentRecord
        carries the child's REAL identity (not a stub). If
        ``cap_token_issuer`` is provided the supervisor calls it with
        ``(did, capabilities)`` after the handshake; the returned
        token's ``token_id`` is stamped on the record. If the issuer
        raises, the freshly-started child is stopped before re-raising
        so the caller never sees an agent running without authority.

        Raises:
            RuntimeError if the runner could not start the agent or
                the child failed to report a DID within the handshake
                timeout.
            Any exception from ``cap_token_issuer`` (after killing
                the child).
            AgentCapacityExceeded if the live-agent ceiling is reached
                (checked BEFORE starting any subprocess, fail-closed).
        """
        # 容量闸:达上限即拒,绝不再起子进程。stop() 会从 _agents.pop,
        # 故 len(_agents) 即当前在册(已起未停)数。并发下可能轻微超额
        # (检查与最终插入之间锁已释放),但这是防"跑飞",非精确配额,
        # 操作员触发频率低,可接受。
        if self._max_live_agents > 0:
            with self._lock:
                live = len(self._agents)
            if live >= self._max_live_agents:
                raise AgentCapacityExceeded(
                    f"live agent ceiling reached: "
                    f"{live}/{self._max_live_agents} "
                    f"(raise NTH_MAX_LIVE_AGENTS to allow more)"
                )

        agent_id = uuid.uuid4().hex
        # Phase 3b note (race): the reader thread starts inside
        # runner.start() and emits on_event(agent_started) before
        # this method finishes registering the AgentRecord. The
        # gap between start() returning and our self._agents insert
        # is dominated by ``cap_token_issuer`` — in the production
        # path that's ``sign_cap_token()`` + ``CapTokenStore.record()``
        # + ``cap_token.json`` write (Phase 3c), tens to a few
        # hundred milliseconds. The child emits heartbeats every ~1s
        # so it's plausible the first heartbeat lands in this gap —
        # N-2 fix (review round Phase 3b R2). ``on_event`` handles
        # that case via ``self._agents.get(agent_id)`` which is
        # None-safe; the dropped bump is forgiven the moment the
        # next heartbeat arrives.
        # C-1 fix (review round Phase 3b R1): no try/except around
        # runner.start() — the runner is responsible for its own
        # cleanup on internal failure (SubprocessRunner.start kills
        # the child + clears its dicts before returning ("", None)),
        # and an exception escaping start() is one we can't sensibly
        # recover from at this layer, so we let it propagate
        # untouched. The previous bare try/except: raise was a
        # refactor leftover that gave a false impression of cleanup.

        # Phase 3c: pre-compute the cap_token file path BEFORE
        # spawning so the runner can pass it to the child via
        # ``--cap-token-file``. Only meaningful when both a
        # cap_token_dir and an issuer are configured; otherwise
        # the child runs without an authority file (Phase 3b
        # semantics — informational, no signing).
        cap_token_file_path: Optional[str] = None
        if cap_token_issuer is not None and self._cap_token_dir is not None:
            agent_dir = self._cap_token_dir / agent_id
            agent_dir.mkdir(parents=True, exist_ok=True)
            cap_token_file_path = str(agent_dir / "cap_token.json")

        pid, did = self._runner.start(
            agent_id, kind,
            cap_token_file_path=cap_token_file_path,
            identity_file=identity_file,
        )
        # Phase 3d: pull post-handshake metadata BEFORE checking
        # success — the runner's handshake_data is populated atomically
        # with the DID, so a non-empty ``did`` implies the data is
        # ready. handshake_data() returns {} for InMemoryRunner / for
        # runners that don't implement the protocol method (the dict
        # default keeps the access safe in both cases).
        try:
            handshake_meta = self._runner.handshake_data(agent_id)
        except AttributeError:
            # M-3 fix (review round Phase 3d R1): only AttributeError
            # is the legitimate fall-through (a legacy runner that
            # predates the Protocol method). Real bugs (TypeError,
            # threading violations) should surface as 500, not get
            # swallowed into "no metadata".
            logger.debug(
                "agent_supervisor: runner %s does not implement "
                "handshake_data — proceeding without metadata",
                type(self._runner).__name__,
            )
            handshake_meta = {}
        raw_port = handshake_meta.get("a2a_port")
        a2a_port: Optional[int] = (
            raw_port if isinstance(raw_port, int) and raw_port > 0 else None
        )
        if not did:
            # Runner already cleaned up; nothing for us to undo.
            raise RuntimeError(
                f"agent {agent_id!r} did not complete identity "
                "handshake (child failed to start, crashed before "
                "emitting agent_started, or returned no DID)."
            )

        # H-1 fix (review round Phase 3b R1): once the runner has
        # given us a live child, EVERY exception path from here to
        # the final self._agents insert must call runner.stop()
        # before re-raising — otherwise the subprocess is orphaned
        # (parent has no record of it, reader thread keeps draining,
        # heartbeats hit a None record and are silently dropped, and
        # the only thing that can kill the child is an external
        # signal). The outer try/finally wraps issuance + record
        # construction + dict insert; cleanup_needed flips off only
        # after the record is safely in self._agents.
        cleanup_needed = True
        # Phase 3c C-1 fix (review round Phase 3c R1): hoist
        # ``issued_token`` so we can perform the cap_token file
        # delivery AFTER the agent is safely registered. The
        # delivery is ancillary — the audit store already has the
        # token after the issuer returned. A disk-full at delivery
        # time used to roll back the spawn (cleanup_needed=True →
        # runner.stop), orphaning the just-recorded audit entry.
        # Now: delivery happens outside the try/finally, failures
        # log WARNING and the agent stays alive without its file.
        issued_token: Optional[Dict[str, Any]] = None
        try:
            cap_token_id: Optional[str] = None
            if cap_token_issuer is not None:
                try:
                    token = cap_token_issuer(did, list(capabilities or []))
                except Exception as exc:
                    logger.warning(
                        "agent_supervisor: cap_token issuance failed "
                        "for %s (did=%s): %s — stopping child",
                        agent_id, did[:24] + "…", exc,
                    )
                    raise
                if token is not None:
                    # N-1 fix (review round Phase 3b R2): defensive
                    # isinstance check BEFORE calling .get(). An
                    # issuer that returns a list/str/custom object
                    # would otherwise raise AttributeError here,
                    # which the outer try/finally still cleans up
                    # safely — but the operator log would show a
                    # generic "'list' has no attribute 'get'"
                    # instead of a clear contract-violation
                    # message. WARN-then-continue gives them the
                    # type and the agent still gets registered
                    # (without a token_id, same posture as the
                    # missing-token_id branch below).
                    if not isinstance(token, dict):
                        logger.warning(
                            "agent_supervisor: cap_token_issuer for "
                            "%s (did=%s) returned %s instead of a "
                            "dict; agent will be recorded without "
                            "a cap_token_id.",
                            agent_id, did[:24] + "…",
                            type(token).__name__,
                        )
                    else:
                        tid = token.get("token_id")
                        if isinstance(tid, str) and tid:
                            cap_token_id = tid
                            # File delivery deferred to after the
                            # try/finally — see C-1 note above.
                            issued_token = token
                        else:
                            # H-2 fix (review round Phase 3b R1):
                            # the issuer returned a dict but no
                            # usable token_id — likely contract
                            # drift (sign_cap_token renamed the
                            # field) or a custom issuer that
                            # botched its return. The agent runs
                            # but loses its audit handle, so a
                            # loud WARNING is mandatory.
                            logger.warning(
                                "agent_supervisor: cap_token_issuer "
                                "for %s (did=%s) returned a dict "
                                "without a valid 'token_id' string; "
                                "agent will be recorded without a "
                                "cap_token_id. Returned keys: %s",
                                agent_id, did[:24] + "…",
                                sorted(token.keys()),
                            )

            record = AgentRecord(
                agent_id=agent_id,
                kind=kind,
                label=label or kind,
                did=did,
                capabilities=capabilities or [],
                started_at=_now_iso(),
                last_seen=_now_iso(),
                alive=True,
                pid=pid,
                cap_token_id=cap_token_id,
                a2a_port=a2a_port,
            )
            with self._lock:
                self._agents[agent_id] = record
            cleanup_needed = False
        finally:
            if cleanup_needed:
                try:
                    self._runner.stop(agent_id)
                except Exception as stop_exc:  # noqa: BLE001
                    logger.warning(
                        "agent_supervisor: rollback stop also failed "
                        "for %s: %s", agent_id, stop_exc,
                    )

        # Phase 3c: deliver the cap_token to the child via the
        # pre-declared file path. The agent is already registered
        # in self._agents at this point, so a failure here is
        # logged + survived rather than killing a healthy spawn
        # (C-1 fix — review round Phase 3c R1). The audit-store
        # token remains valid; operator can revoke + re-issue if
        # the file ever needs to be re-delivered.
        if issued_token is not None and cap_token_file_path is not None:
            try:
                _atomic_write_json(cap_token_file_path, issued_token)
            except OSError as exc:
                logger.warning(
                    "agent_supervisor: failed to deliver cap_token "
                    "file for %s at %s (token_id=%s is valid and "
                    "recorded in the audit store, but the child "
                    "cannot load it — consider revoke + re-issue): "
                    "%s",
                    agent_id, cap_token_file_path,
                    cap_token_id, exc,
                )

        logger.info(
            "agent_supervisor: spawned %s (kind=%s, pid=%s, did=%s, cap_token=%s)",
            agent_id, kind, pid, did[:24] + "…", cap_token_id or "none",
        )
        return record

    def stop(self, agent_id: str) -> bool:
        """Stop and remove an agent. Returns True if the id was
        known AT CALL TIME. Repeated single-threaded stops return
        False on the second call.

        Concurrency semantic (N-2 note 2026-06-11): two threads
        calling stop() on the same id simultaneously may BOTH
        observe ``in self._agents`` and BOTH return True. The
        underlying runner.stop() is idempotent (SubprocessRunner
        early-returns when proc is gone, InMemoryRunner just
        flips a bool), so the double-True is harmless — no zombie
        process, no double-pop crash. Callers that need strict
        once-only semantics must coordinate at a higher layer.

        M-3 fix (2026-06-11): runner.stop() is called BEFORE
        popping the record. The previous order would have orphaned
        the registry entry if a future runner implementation
        raised — the agent stayed running but supervisor lost
        track. Now the pop happens only after stop() completes.
        We still hold no lock across runner.stop() so a long-
        running stop doesn't block other supervisor ops. """
        with self._lock:
            present = agent_id in self._agents
        if not present:
            return False
        self._runner.stop(agent_id)
        with self._lock:
            self._agents.pop(agent_id, None)
        # H-1 fix (review round Phase 3c R2): remove the cap_token
        # file + per-agent dir. cap_tokens are bearer authority;
        # leaving them on disk past the agent's lifetime is an
        # audit + security gap. Best-effort: filesystem failures
        # log WARNING but don't propagate (we already stopped the
        # child — the operator should be able to call stop() and
        # have it return). rmdir only succeeds on an empty dir, so
        # if a future phase puts other files alongside cap_token.json
        # we won't accidentally nuke them.
        if self._cap_token_dir is not None:
            agent_dir = self._cap_token_dir / agent_id
            # Phase 3d: also remove last_receipt.json — the child's
            # crash-recovery copy written before emitting
            # receipt_signed (M-3 fix). Without this the per-agent
            # dir would never be empty enough for rmdir to succeed.
            for fname in ("cap_token.json", "last_receipt.json"):
                fpath = agent_dir / fname
                try:
                    if fpath.exists():
                        fpath.unlink()
                except OSError as exc:
                    logger.warning(
                        "agent_supervisor: failed to remove %s for "
                        "stopped agent %s: %s",
                        fname, agent_id, exc,
                    )
            try:
                if agent_dir.exists():
                    agent_dir.rmdir()
            except OSError:
                # Non-empty (future phases) or transient — leave
                # the empty dir for an operator sweep.
                pass
        logger.info("agent_supervisor: stopped %s", agent_id)
        return True

    def list_agents(self) -> List[AgentRecord]:
        # Review fix #2 (2026-06-11): the previous version copied
        # references out under the lock then mutated `a.alive`
        # outside it. on_event() concurrently mutates `last_seen`
        # on the SAME object via the supervisor lock, producing a
        # read-write race (CPython's GIL prevents corruption but
        # the cross-field ordering is undefined).
        #
        # Fix: snapshot the (id, alive) pairs first while holding
        # the lock, then return shallow COPIES of the records with
        # the refreshed alive value applied. Callers get an
        # immutable view of the state at one instant. We don't
        # call is_alive() under the lock to keep the critical
        # section short — is_alive could touch subprocess.poll
        # which on Windows can block briefly.
        with self._lock:
            records = list(self._agents.values())
        # M-4 transient note (2026-06-11): a record inserted by a
        # concurrent spawn that's still inside runner.start() can
        # show alive=False in this listing because is_alive checks
        # before the runner's internal proc dict is populated. The
        # NEXT GET /agents converges to the truth. Phase 3b might
        # close this by waiting for agent_started before responding.
        alive_map = {r.agent_id: self._runner.is_alive(r.agent_id)
                     for r in records}
        out: List[AgentRecord] = []
        with self._lock:
            for r in records:
                # Pick the current record from the dict in case
                # another writer landed during the is_alive scan.
                current = self._agents.get(r.agent_id)
                if current is None:
                    continue  # was stopped between the two reads
                snap = AgentRecord(
                    agent_id=current.agent_id,
                    kind=current.kind,
                    label=current.label,
                    did=current.did,
                    capabilities=list(current.capabilities),
                    started_at=current.started_at,
                    last_seen=current.last_seen,
                    pid=current.pid,
                    alive=alive_map.get(current.agent_id, False),
                    cap_token_id=current.cap_token_id,
                    a2a_port=current.a2a_port,
                )
                out.append(snap)
        return out

    def get(self, agent_id: str) -> Optional[AgentRecord]:
        with self._lock:
            return self._agents.get(agent_id)

    def on_event(self, agent_id: str, event: Dict[str, Any]) -> None:
        """Callback bound to SubprocessRunner so heartbeats from
        the child update ``last_seen`` in the registry.

        L-3 fix (2026-06-11): also log ``agent_started`` and
        ``agent_stopping`` at INFO so the operator sees lifecycle
        transitions in the hub log. We deliberately do NOT trust
        the event's reported pid / agent_id for routing — the
        supervisor stamps agent_id from its own side via the
        runner callback. Phase 3b can use these events for richer
        state transitions (alive → stopping etc).

        A-1 TODO (Phase 3b): if last_seen drifts past N*heartbeat
        without an update, mark alive=False even though proc.poll
        says the process is up — catches dead-locked children. """
        kind = event.get("event")
        if kind == "heartbeat":
            with self._lock:
                record = self._agents.get(agent_id)
                if record is not None:
                    record.last_seen = _now_iso()
        elif kind == "agent_started":
            # Phase 3d: a2a_port stamping happens at spawn time
            # (pulled from runner.handshake_data) — race-free
            # because the reader populates the slot BEFORE setting
            # the handshake event that unblocks start(). This
            # branch only logs.
            a2a_port = event.get("a2a_port")
            if isinstance(a2a_port, int) and a2a_port > 0:
                logger.info(
                    "agent_supervisor: %s reported started "
                    "(child pid=%s, a2a_port=%d)",
                    agent_id, event.get("pid"), a2a_port,
                )
            else:
                logger.info(
                    "agent_supervisor: %s reported started (child pid=%s)",
                    agent_id, event.get("pid"),
                )
        elif kind == "agent_stopping":
            logger.info("agent_supervisor: %s reported stopping", agent_id)
        elif kind == "decision_raised":
            # Phase 3d: child is asking the operator to act on
            # something. Validate shape, then forward to the
            # configured raiser (v2_api wires it into the decisions
            # store). Failure → WARNING + survive, same posture as
            # receipt_persistor: a transient store failure shouldn't
            # take an otherwise healthy agent offline.
            decision = event.get("decision")
            if not isinstance(decision, dict):
                logger.warning(
                    "agent_supervisor: %s emitted decision_raised "
                    "without a dict 'decision' field — dropping. "
                    "Payload type: %s",
                    agent_id, type(decision).__name__,
                )
            elif self._decision_raiser is None:
                logger.info(
                    "agent_supervisor: %s emitted decision_raised "
                    "(title=%r) but no raiser configured — dropping",
                    agent_id, decision.get("title", "?"),
                )
            else:
                try:
                    self._decision_raiser(agent_id, decision)
                    logger.info(
                        "agent_supervisor: %s raised decision "
                        "(title=%r)",
                        agent_id, decision.get("title", "?"),
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "agent_supervisor: decision_raiser failed "
                        "for %s (title=%r): %s",
                        agent_id, decision.get("title", "?"), exc,
                    )
        elif kind == "receipt_signed":
            # Phase 3c: child has signed a receipt with its own
            # AgentIdentity (typically the nth.agent_attestation
            # receipt minted on cap_token load). Forward to the
            # persistor; failure here is logged + swallowed so a
            # transient disk hiccup doesn't kill an otherwise
            # healthy agent.
            receipt = event.get("receipt")
            if not isinstance(receipt, dict):
                logger.warning(
                    "agent_supervisor: %s emitted receipt_signed "
                    "without a dict 'receipt' field — dropping. "
                    "Payload type: %s",
                    agent_id, type(receipt).__name__,
                )
            elif self._receipt_persistor is None:
                logger.info(
                    "agent_supervisor: %s emitted receipt_signed "
                    "(id=%s, signer=%s) but no persistor configured "
                    "— dropping",
                    agent_id,
                    receipt.get("receipt_id", "?"),
                    str(receipt.get("signer_did", ""))[:24] + "…",
                )
            else:
                try:
                    self._receipt_persistor(agent_id, receipt)
                    logger.info(
                        "agent_supervisor: %s persisted receipt "
                        "(id=%s)",
                        agent_id, receipt.get("receipt_id", "?"),
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "agent_supervisor: receipt_persistor failed "
                        "for %s (id=%s): %s",
                        agent_id,
                        receipt.get("receipt_id", "?"),
                        exc,
                    )
        else:
            # N-4 fix (2026-06-11): unknown event types are debug-
            # logged rather than silently dropped. Phase 3b will
            # add agent_error / cap_used / decision_raised etc;
            # surfacing them early helps catch the protocol drift.
            logger.debug(
                "agent_supervisor: %s emitted unknown event kind=%r",
                agent_id, kind,
            )

    def shutdown(self) -> None:
        """Stop every supervised agent. Called on hub teardown.
        Best-effort: failures during stop are logged but not
        re-raised so a hung agent doesn't block clean shutdown. """
        with self._lock:
            ids = list(self._agents.keys())
        for aid in ids:
            try:
                self.stop(aid)
            except Exception as exc:  # noqa: BLE001
                logger.warning("shutdown stop failed for %s: %s", aid, exc)

    def recover_orphaned_receipts(self) -> int:
        """Phase 3e: scan ``cap_token_dir`` for ``last_receipt.json``
        files left behind by agents that crashed (or that the hub
        was killed before reading their pipe). For each one:

          1. Parse as JSON. Malformed → log + skip + leave in
             place (operator can inspect).
          2. Validate it looks like a receipt dict (has
             ``signer_did``). If not, log + skip + leave.
          3. Forward to ``receipt_persistor`` if configured;
             otherwise log + skip.
          4. On successful persistence, unlink the file so the
             next sweep doesn't re-process it.

        Returns the count of receipts successfully recovered.
        Idempotent — running the sweep twice is a no-op on the
        second call (already-recovered files are gone).

        No-op if ``cap_token_dir`` is None or doesn't exist. """
        if self._cap_token_dir is None or not self._cap_token_dir.exists():
            return 0
        if self._receipt_persistor is None:
            logger.info(
                "agent_supervisor: recovery sweep skipped — no "
                "receipt_persistor configured (workspace not "
                "bootstrapped?)",
            )
            return 0

        recovered = 0
        for agent_dir in self._cap_token_dir.iterdir():
            if not agent_dir.is_dir():
                continue
            recovery_path = agent_dir / "last_receipt.json"
            if not recovery_path.exists():
                continue
            try:
                raw = recovery_path.read_text(encoding="utf-8")
                receipt = json.loads(raw)
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning(
                    "agent_supervisor: recovery sweep could not "
                    "parse %s: %s — leaving in place",
                    recovery_path, exc,
                )
                continue
            if not isinstance(receipt, dict) or not receipt.get("signer_did"):
                logger.warning(
                    "agent_supervisor: recovery file %s doesn't "
                    "look like a receipt (no signer_did) — leaving",
                    recovery_path,
                )
                continue
            cap_token_path = agent_dir / "cap_token.json"
            if cap_token_path.exists():
                try:
                    cap_token = json.loads(cap_token_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as exc:
                    logger.warning(
                        "agent_supervisor: recovery sweep could not "
                        "parse %s: %s — leaving receipt in place",
                        cap_token_path, exc,
                    )
                    continue
                expected_did = str(cap_token.get("subject_did", "") or "")
                signer_did = str(receipt.get("signer_did", "") or "")
                if expected_did and signer_did != expected_did:
                    logger.warning(
                        "agent_supervisor: recovery receipt signer_did "
                        "does not match cap_token subject for %s "
                        "(receipt_id=%s) — leaving file",
                        agent_dir.name, receipt.get("receipt_id", "?"),
                    )
                    continue

            try:
                # agent_dir.name IS the agent_id the supervisor
                # used to create the dir, so forward that as the
                # routing key even though the agent itself is
                # already gone.
                self._receipt_persistor(agent_dir.name, receipt)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "agent_supervisor: recovery persistor failed "
                    "for %s (receipt_id=%s): %s — leaving file",
                    agent_dir.name,
                    receipt.get("receipt_id", "?"), exc,
                )
                continue
            try:
                recovery_path.unlink()
            except OSError as exc:
                logger.warning(
                    "agent_supervisor: persisted receipt %s but "
                    "could not remove the recovery file: %s",
                    recovery_path, exc,
                )
                # Don't decrement — the receipt IS persisted; the
                # file lingering is a cleanup issue, not a recovery
                # failure. Operator can sweep manually if needed.
            recovered += 1
            logger.info(
                "agent_supervisor: recovered orphaned receipt "
                "(id=%s) for stopped agent %s",
                receipt.get("receipt_id", "?"), agent_dir.name,
            )
        return recovered


# ─────────────────────────────────────────────────────────────
# Convenience factory used by the hub bootstrap
# ─────────────────────────────────────────────────────────────


def build_default_supervisor(
    *,
    cap_token_dir: Optional[Path] = None,
    receipt_persistor: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    decision_raiser: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    workspace: Optional[Path] = None,
) -> AgentSupervisor:
    """Production supervisor — uses SubprocessRunner. Tests
    construct their own with InMemoryRunner.

    Phase 3c (2026-06-11):
      cap_token_dir       — when set, ``spawn`` writes per-agent
                            cap_token.json files here and tells the
                            runner to pass the path to the child.
                            v2_api typically passes
                            ``<workspace>/sandbox/agents``.
      receipt_persistor   — forwarded into the supervisor for
                            ``receipt_signed`` events. v2_api wires
                            this to ``state.receipts.save``.

    Phase 3d (2026-06-11):
      decision_raiser     — forwarded into the supervisor for
                            ``decision_raised`` events. v2_api
                            wires this to insert into the v2
                            decisions store with hub-stamped
                            attribution (the child can propose a
                            decision but cannot claim a foreign
                            proposer_did).

    M-2 fix (2026-06-11): the previous version relied on Python's
    closure late-binding (``supervisor`` captured by name, not by
    value, and assigned AFTER ``_on_event`` was defined). It was
    safe today only because reader threads can't fire on_event
    until the supervisor is constructed and start() runs, but a
    refactor that broke that ordering would have triggered an
    UnboundLocalError. The mutable-container pattern makes the
    forward-reference explicit and reorder-tolerant. """
    holder: List[AgentSupervisor] = []

    def _on_event(agent_id: str, event: Dict[str, Any]) -> None:
        if holder:
            holder[0].on_event(agent_id, event)
        else:
            # N-3 fix (2026-06-11): defensive log so a refactor
            # that reorders construction surfaces immediately
            # instead of silently dropping the first events.
            logger.warning(
                "agent_supervisor: _on_event before supervisor ready, "
                "dropping event=%s for %s",
                event.get("event"), agent_id,
            )

    runner = SubprocessRunner(on_event=_on_event, workspace=workspace)
    supervisor = AgentSupervisor(
        runner,
        cap_token_dir=cap_token_dir,
        receipt_persistor=receipt_persistor,
        decision_raiser=decision_raiser,
    )
    holder.append(supervisor)
    return supervisor
