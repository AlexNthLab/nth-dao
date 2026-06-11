"""
Agent supervisor — Phase 3a/3b of the local-hub plan.

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
    ``agent_started`` NDJSON event with a ``did`` field; the hub
    registers the AgentRecord under that real W3C did:key.
  - InMemoryRunner generates a real-shape did:key from random
    bytes (no signing key needed — tests never actually sign).
  - Supervisor.spawn() takes an optional ``cap_token_issuer``
    callback. After the child reports its DID, the supervisor
    calls the issuer with (did, capabilities) and stamps the
    returned token's ``token_id`` on the AgentRecord. If issuance
    raises, the just-started agent is killed before re-raising
    so the caller never sees a child running without authority.

Phase 3c/d will add:
  - Cap_token delivered to the child via tempfile / IPC so it can
    sign receipts on its own.
  - A2A localhost HTTP endpoint per agent (random port, advertised)
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
from typing import Any, Callable, Dict, List, Optional, Protocol, Tuple

logger = logging.getLogger(__name__)


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

    def to_agent_entry(self) -> Dict[str, Any]:
        """Translate to the dict shape /api/v2/agents returns.

        M-5 fix (2026-06-11): ``capabilities`` is shallow-copied
        so a caller mutating the returned list can't poison the
        record's internal state. Other fields are immutable (str/
        int/bool/None) so no further copy needed. """
        return {
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
    smoke test's polling window). """

    def start(self, agent_id: str, kind: str) -> Tuple[Optional[int], str]:
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


# Phase 3b: how long SubprocessRunner waits for the child's first
# ``agent_started`` event before assuming the spawn failed. Python
# startup + AgentIdentity.generate() takes ~200ms on a warm cache,
# up to a few seconds on first-ever import. 10s is conservative.
_DEFAULT_HANDSHAKE_TIMEOUT_S = 10.0


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

    def start(self, agent_id: str, kind: str) -> Tuple[Optional[int], str]:
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
        handshake_timeout: float = _DEFAULT_HANDSHAKE_TIMEOUT_S,
    ) -> None:
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

    def start(self, agent_id: str, kind: str) -> Tuple[Optional[int], str]:
        # Spawn `python -m nth_dao.web.dummy_agent --id … --kind …`.
        # Using sys.executable keeps the child on the same interpreter
        # as the hub — important on Windows where multiple Pythons
        # may be installed.
        cmd = [
            sys.executable, "-m", "nth_dao.web.dummy_agent",
            "--id", agent_id,
            "--kind", kind,
        ]
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
    callers can iterate without holding the lock. """

    def __init__(self, runner: AgentRunner) -> None:
        self._runner = runner
        self._agents: Dict[str, AgentRecord] = {}
        self._lock = threading.Lock()

    def spawn(
        self,
        *,
        kind: str,
        label: str,
        capabilities: Optional[List[str]] = None,
        cap_token_issuer: Optional[CapTokenIssuer] = None,
    ) -> AgentRecord:
        """Spawn a new supervised agent.

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
        """
        agent_id = uuid.uuid4().hex
        # Phase 3b note (race): the reader thread starts inside
        # runner.start() and emits on_event(agent_started) before
        # this method finishes registering the AgentRecord. The
        # gap between start() returning and our self._agents insert
        # is dominated by ``cap_token_issuer`` — in the production
        # path that's ``sign_cap_token()`` + ``CapTokenStore.record()``
        # (one file write), tens to a few hundred milliseconds. The
        # child emits heartbeats every ~1s, so it's plausible the
        # first heartbeat lands in this gap — N-2 fix (review round
        # Phase 3b R2). ``on_event`` handles that case via
        # ``self._agents.get(agent_id)`` which is None-safe; the
        # dropped bump is forgiven the moment the next heartbeat
        # arrives.
        # C-1 fix (review round Phase 3b R1): no try/except around
        # runner.start() — the runner is responsible for its own
        # cleanup on internal failure (SubprocessRunner.start kills
        # the child + clears its dicts before returning ("", None)),
        # and an exception escaping start() is one we can't sensibly
        # recover from at this layer, so we let it propagate
        # untouched. The previous bare try/except: raise was a
        # refactor leftover that gave a false impression of cleanup.
        pid, did = self._runner.start(agent_id, kind)
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
            logger.info(
                "agent_supervisor: %s reported started (child pid=%s)",
                agent_id, event.get("pid"),
            )
        elif kind == "agent_stopping":
            logger.info("agent_supervisor: %s reported stopping", agent_id)
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


# ─────────────────────────────────────────────────────────────
# Convenience factory used by the hub bootstrap
# ─────────────────────────────────────────────────────────────


def build_default_supervisor() -> AgentSupervisor:
    """Production supervisor — uses SubprocessRunner. Tests
    construct their own with InMemoryRunner.

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

    runner = SubprocessRunner(on_event=_on_event)
    supervisor = AgentSupervisor(runner)
    holder.append(supervisor)
    return supervisor
