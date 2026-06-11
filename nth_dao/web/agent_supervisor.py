"""
Agent supervisor — Phase 3a of the local-hub plan.

The supervisor is a per-app singleton (on ``app.state.v2_supervisor``)
that holds a registry of live agents and a runner-strategy that
knows how to actually start / stop them.

  Supervisor      ── owns the agent registry (dict by agent_id)
       │
       └── Runner ── strategy for the OS-level lifecycle
           ├── InMemoryRunner   — tests; tracks alive flag only
           └── SubprocessRunner — production; spawns
                                 nth_dao.web.dummy_agent as a child

Phase 3a scope (this file):
  - Spawn / stop / list / liveness check
  - Each agent gets a fresh did:key on spawn (placeholder pubkey
    derived from os.urandom — Phase 3b swaps this for a real
    Ed25519 keypair from nth_dao.identity)
  - Threading: a reader thread per subprocess agent drains stdout
    JSON events; the supervisor updates ``last_seen`` on heartbeat
  - Graceful stop: terminate(); fall back to kill() after a timeout

Phase 3b/c/d will add:
  - Cap_token issued by the hub on spawn (subject_did = agent's did)
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
from typing import Any, Callable, Dict, List, Optional, Protocol

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
    threading concerns live in the supervisor, not here. """

    def start(self, agent_id: str, kind: str) -> Optional[int]:
        """Start the agent process. Returns pid (real or fake). """
        ...

    def stop(self, agent_id: str) -> None:
        """Request graceful stop; block until terminated or
        timeout, then force-kill. Idempotent. """
        ...

    def is_alive(self, agent_id: str) -> bool:
        ...


class InMemoryRunner:
    """Test runner — no OS process. Spawn flips an alive flag. """

    def __init__(self) -> None:
        self._alive: Dict[str, bool] = {}
        self._counter = 0
        self._lock = threading.Lock()

    def start(self, agent_id: str, kind: str) -> Optional[int]:
        with self._lock:
            self._counter += 1
            self._alive[agent_id] = True
            return 10_000 + self._counter  # fake pid

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
        self._on_event = on_event
        self._lock = threading.Lock()

    def start(self, agent_id: str, kind: str) -> Optional[int]:
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
            return None

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
        with self._lock:
            self._procs[agent_id] = proc
            self._stdout_readers[agent_id] = stdout_thread
            self._stderr_readers[agent_id] = stderr_thread
        stdout_thread.start()
        stderr_thread.start()
        return proc.pid

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


def _generate_did() -> str:
    """Placeholder DID for Phase 3a — Phase 3b swaps for a real
    Ed25519 pubkey via nth_dao.identity.Identity.fresh().

    Review fix #7 (2026-06-11): use the dedicated method prefix
    ``did:nth-hub-stub:`` so any consumer that does a
    ``did.startswith("did:key:")`` check rejects this loudly
    instead of silently treating uuid hex as a real pubkey.
    Once Phase 3b lands real keys the prefix flips back to
    ``did:key:`` and the consumer's check starts succeeding. """
    suffix = uuid.uuid4().hex
    return f"did:nth-hub-stub:{suffix}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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
    ) -> AgentRecord:
        agent_id = uuid.uuid4().hex
        record = AgentRecord(
            agent_id=agent_id,
            kind=kind,
            label=label or kind,
            did=_generate_did(),
            capabilities=capabilities or [],
            started_at=_now_iso(),
            last_seen=_now_iso(),
            alive=True,
        )
        # Review fix #1 (2026-06-11): register BEFORE start so a
        # reader thread that fires on_event before start() returns
        # finds the record. The pid is filled in after start since
        # the runner returns it; on_event for heartbeats doesn't
        # read pid so the brief None window is harmless.
        with self._lock:
            self._agents[agent_id] = record
        try:
            pid = self._runner.start(agent_id, kind)
        except Exception:
            # start failed — drop the record we pre-inserted so
            # list_agents doesn't show a ghost entry.
            with self._lock:
                self._agents.pop(agent_id, None)
            raise
        record.pid = pid
        # A-2 TODO (Phase 3b): wait (with timeout) for the child's
        # agent_started event before returning. Today spawn returns
        # as soon as Popen is constructed — if the child crashes on
        # import the caller still gets a "success" response and the
        # death only surfaces later via stderr log lines.
        logger.info(
            "agent_supervisor: spawned %s (kind=%s, pid=%s, did=%s)",
            agent_id, kind, pid, record.did[:24] + "…",
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
