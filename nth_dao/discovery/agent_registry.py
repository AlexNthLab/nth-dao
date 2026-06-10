"""
AgentRegistry - file-backed peer registry for cross-process / cross-terminal agent discovery.

Design:
    - Each agent writes its own record to team_agents/{agent_id}.json
    - File name is the safe_id-normalized agent_id
    - Record holds: capabilities, backend, status, hostname, pid, last_seen, ...
    - register() spawns a heartbeat thread that re-touches the file every
      heartbeat_interval seconds
    - Use Git (via PR 5 git_sync) to sync team_agents/ across hosts

Notes:
    - PR 5 log_collector style: append-only when desired
    - Listing uses last_seen freshness, not Git history
    - cleanup() is opt-in and not called automatically
"""

from __future__ import annotations

import atexit
import logging
import socket
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import os

from ..util import atomic_write_json, safe_load_json, safe_id as _safe_id

logger = logging.getLogger("nth_dao.discovery")

# repo_root/team_agents/
DEFAULT_AGENTS_DIR = "team_agents"

# C2: clock-skew tolerance - two machines sharing a filesystem may have
# clocks that differ by up to 30 s.  Without this buffer, agent B may
# incorrectly mark agent A as dead simply because B's clock is ahead.
CLOCK_SKEW_TOLERANCE_SECONDS = 30
# Upper bound on future timestamps - anything more than 5 minutes in the
# future is treated as invalid (tampered / misconfigured clock).
FUTURE_STALE_SECONDS = 300


@dataclass
class AgentRecord:
    """One agent's discovery record (persisted as team_agents/{agent_id}.json)."""
    agent_id: str
    hostname: str
    pid: int
    backend_id: str = "unknown"        # mock / hermes / claude_code / ...
    capabilities: List[str] = field(default_factory=list)  # e.g. ["python", "web", "codegen"]
    groups: List[str] = field(default_factory=list)        # e.g. ["frontend", "ops"]
    status: str = "idle"                # idle / busy / blocked / offline
    current_mission: Optional[str] = None
    # -- v0.9.8: Agent discovery enhancement --
    seeking: List[str] = field(default_factory=list)          # capabilities this agent is looking for
    accepting_tasks: bool = False                               # actively accepting marketplace tasks
    available_for: List[str] = field(default_factory=list)     # action types accepted (e.g. code_review, deploy)
                                                               # NOTE: distinct from capabilities - used by
                                                               # consumers for routing, NOT by find_complements
    metadata: Dict[str, Any] = field(default_factory=dict)
    registered_at: str = field(default_factory=lambda: datetime.now().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    instance_token: str = field(default_factory=lambda: uuid.uuid4().hex[:8])

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "AgentRecord":
        # Tolerant: drop unknown fields so older / newer records still load.
        fields = {f for f in cls.__dataclass_fields__}
        unknown = set(data.keys()) - fields
        if unknown:
            logger.debug("AgentRecord.from_dict: ignoring unknown fields %s", unknown)
        return cls(**{k: v for k, v in data.items() if k in fields})

    def is_alive(self, max_stale_seconds: int = 90) -> bool:
        """True iff last_seen is within max_stale_seconds of now.

        Applies CLOCK_SKEW_TOLERANCE_SECONDS buffer for multi-machine
        clock drift, and rejects timestamps more than FUTURE_STALE_SECONDS
        in the future (tampered / misconfigured clock).
        """
        try:
            last = datetime.fromisoformat(self.last_seen)
            delta = (datetime.now() - last).total_seconds()
            # CRIT-2 fix 2026-06-10: clock skew is asymmetric. It exists
            # to forgive FUTURE timestamps caused by remote-clock drift
            # (delta < 0), NOT to widen the stale window. The previous
            # ``effective = max_stale + SKEW`` meant a heartbeat 119s old
            # passed when max_stale=90s and SKEW=30s — the agent was
            # actually dead by the policy.
            #   Accepted window: [-SKEW, max_stale)
            #   delta < -SKEW       → future beyond tolerance → reject
            #   delta >= max_stale  → too old → reject
            # Note: FUTURE_STALE_SECONDS (300s) is strictly looser than
            # the SKEW check (30s) so its old purpose — distinguishing
            # tampered from skewed — is subsumed here. Constant kept
            # for any external callers that import it.
            if delta < -CLOCK_SKEW_TOLERANCE_SECONDS:
                return False
            return delta < max_stale_seconds
        except Exception:
            return False

    def short(self) -> str:
        marker = "*" if self.is_alive() else "-"
        cap_str = ",".join(self.capabilities[:3]) or "-"
        extra = ""
        if self.seeking:
            extra += f" seek=[{','.join(self.seeking[:2])}]"
        if self.accepting_tasks:
            extra += " accept"
        return (
            f"{marker} {self.agent_id:20s} backend={self.backend_id:12s} "
            f"caps=[{cap_str}] status={self.status}{extra}"
        )


class AgentRegistry:
    """File-backed agent registry with heartbeat thread + freshness filter."""

    DEFAULT_HEARTBEAT_INTERVAL = 30
    STALE_THRESHOLD_SECONDS = 90  # last_seen older than 90s = not alive

    def __init__(
        self,
        agents_dir: str = DEFAULT_AGENTS_DIR,
        heartbeat_interval: int = DEFAULT_HEARTBEAT_INTERVAL,
    ):
        """
        Args:
            agents_dir: default ./team_agents/, aligned with the git_sync path
            heartbeat_interval: heartbeat interval in seconds
        """
        self.agents_dir = Path(agents_dir)
        self.agents_dir.mkdir(parents=True, exist_ok=True)
        self.heartbeat_interval = heartbeat_interval

        self._record: Optional[AgentRecord] = None
        self._record_lock = threading.RLock()  # C3: protect _record R/W across threads
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._heartbeat_stop = threading.Event()
        # M-8: repeated register() calls no longer stack atexit callbacks
        self._atexit_registered = False

    #   /  /

    def register(
        self,
        agent_id: str,
        backend_id: str = "unknown",
        capabilities: Optional[List[str]] = None,
        groups: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        seeking: Optional[List[str]] = None,
        accepting_tasks: bool = False,
        available_for: Optional[List[str]] = None,
        start_heartbeat: bool = True,
    ) -> AgentRecord:
        """Register this agent and (optionally) start a heartbeat thread."""
        # CRIT-3 fix 2026-06-10: stop the heartbeat thread BEFORE we
        # take _record_lock. unregister() also stops the heartbeat,
        # but calling it from inside the lock makes _stop_heartbeat's
        # join(timeout=2) wait while the heartbeat thread is itself
        # trying to acquire _record_lock — net 2s of wasted time on
        # every re-register. _stop_heartbeat is idempotent (None-safe)
        # so this is safe to call unconditionally.
        self._stop_heartbeat()
        # Re-registering replaces the prior record (idempotent).
        with self._record_lock:
            if self._record is not None:
                self.unregister()

            self._record = AgentRecord(
                agent_id=agent_id,
                hostname=socket.gethostname(),
                pid=os.getpid(),
                backend_id=backend_id,
                capabilities=capabilities or [],
                groups=groups or [],
                seeking=seeking or [],
                accepting_tasks=accepting_tasks,
                available_for=available_for or [],
                metadata=metadata or {},
            )
            self._write(self._record)

        if start_heartbeat:
            self._start_heartbeat()

        # Register atexit only once to avoid repeated attach/detach accumulation
        if not self._atexit_registered:
            atexit.register(self.unregister)
            self._atexit_registered = True

        return self._record

    def update_status(
        self,
        status: Optional[str] = None,
        current_mission: Optional[str] = None,
        metadata_patch: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Patch this agent's record fields + bump last_seen."""
        with self._record_lock:
            if self._record is None:
                raise RuntimeError("call register() first")
            if status is not None:
                self._record.status = status
            if current_mission is not None:
                self._record.current_mission = current_mission
            if metadata_patch:
                self._record.metadata.update(metadata_patch)
            self._record.last_seen = datetime.now().isoformat()
            self._write(self._record)

    def heartbeat(self) -> None:
        """Just bump last_seen; called from the heartbeat thread."""
        with self._record_lock:
            if self._record is None:
                return
            self._record.last_seen = datetime.now().isoformat()
            self._write(self._record)

    def unregister(self) -> None:
        """Stop heartbeat and mark this agent offline.

        Note: leaves the JSON file in place as a tombstone (status=offline).
        Run cleanup() to remove stale tombstones.
        """
        self._stop_heartbeat()
        with self._record_lock:
            if self._record is None:
                return
            target = self._path_for(self._record.agent_id)
            try:
                if target.exists():
                    # Write status=offline rather than unlinking, to preserve audit
                    # trail. Use cleanup() to purge old tombstones.
                    self._record.status = "offline"
                    self._record.last_seen = datetime.now().isoformat()
                    self._write(self._record)
            except Exception:
                logger.exception("unregister: failed to write offline tombstone for %s",
                                 self._record.agent_id)
            self._record = None

    #   /

    def list_all(self) -> List[AgentRecord]:
        """All registered agent records, including offline tombstones."""
        records = []
        for f in sorted(self.agents_dir.glob("*.json")):
            data = safe_load_json(f, fallback=None)
            if data is None:
                continue
            try:
                records.append(AgentRecord.from_dict(data))
            except Exception:
                continue
        return records

    def list_alive(self, max_stale: int = STALE_THRESHOLD_SECONDS) -> List[AgentRecord]:
        """Records whose last_seen is within max_stale seconds of now."""
        return [r for r in self.list_all() if r.is_alive(max_stale)]

    def get(self, agent_id: str) -> Optional[AgentRecord]:
        path = self._path_for(agent_id)
        data = safe_load_json(path, fallback=None)
        if data is None:
            return None
        try:
            return AgentRecord.from_dict(data)
        except Exception:
            return None

    @property
    def my_record(self) -> Optional[AgentRecord]:
        with self._record_lock:
            return self._record

    #

    def cleanup(self, max_stale: int = 86400) -> int:
        """Remove tombstones older than max_stale seconds (default 1 day)."""
        removed = 0
        for f in self.agents_dir.glob("*.json"):
            data = safe_load_json(f, fallback=None)
            if data is None:
                continue
            try:
                rec = AgentRecord.from_dict(data)
            except Exception:
                continue
            if not rec.is_alive(max_stale):
                try:
                    f.unlink()
                    removed += 1
                except OSError as e:
                    logger.warning("cleanup unlink %s failed: %s", f, e)
        return removed

    #

    def _path_for(self, agent_id: str) -> Path:
        return self.agents_dir / f"{_safe_id(agent_id)}.json"

    def _write(self, record: AgentRecord) -> None:
        path = self._path_for(record.agent_id)
        atomic_write_json(path, record.to_dict())

    def _start_heartbeat(self) -> None:
        if self._heartbeat_thread is not None:
            return
        self._heartbeat_stop.clear()

        def _loop():
            while not self._heartbeat_stop.wait(self.heartbeat_interval):
                try:
                    self.heartbeat()
                except Exception as e:
                    # Best-effort: a transient FS error shouldn't kill the agent.
                    logger.debug("heartbeat tick failed: %s", e)

        self._heartbeat_thread = threading.Thread(
            target=_loop, daemon=True, name=f"AgentHeartbeat-{self._record.agent_id}"
        )
        self._heartbeat_thread.start()

    def _stop_heartbeat(self) -> None:
        if self._heartbeat_thread is None:
            return
        self._heartbeat_stop.set()
        self._heartbeat_thread.join(timeout=2)
        self._heartbeat_thread = None
