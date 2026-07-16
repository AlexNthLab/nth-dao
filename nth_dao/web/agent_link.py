"""Bot-style local AgentLink inbox.

The link deliberately separates delivery from provider execution:

    submit -> accepted -> processing -> completed/failed
                              -> delivery_unknown (restart/shutdown)

This is the useful part of a Telegram bot architecture. A caller does not
hold an HTTP request open while Hermes or another provider is working. Each
agent gets one serial worker and a bounded inbox, so messages are ordered and
backpressure is explicit. Job metadata is persisted without storing prompts.
"""
from __future__ import annotations

import queue
import logging
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, Optional, Tuple

from nth_dao.util.io import (
    InterProcessLock,
    atomic_write_json,
    safe_id,
    safe_load_json,
)


LinkWorker = Callable[[], Any]
UNCERTAIN_STATES = frozenset({"delivery_unknown"})
TERMINAL_STATES = frozenset({"completed", "completed_unverified", "failed"}) | UNCERTAIN_STATES
MAX_AGENT_LINK_RESPONSE_BYTES = 100_000
logger = logging.getLogger("nth_dao.web.agent_link")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def bound_agent_response(
    value: Any, *, max_bytes: int = MAX_AGENT_LINK_RESPONSE_BYTES,
) -> Tuple[str, bool]:
    """Return a UTF-8-safe bounded projection and an explicit truncation bit."""
    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")
    text = str(value or "")
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text, False
    return encoded[:max_bytes].decode("utf-8", errors="ignore"), True


@dataclass(frozen=True)
class LinkJob:
    job_id: str
    agent_id: str
    agent_did: str
    state: str
    created_at: str
    updated_at: str
    idempotency_key: str = ""
    request_hash: str = ""
    prompt_sha256: str = ""
    channel_id: str = ""
    request_message_id: str = ""
    error: str = ""
    response: str = ""
    response_truncated: bool = False
    receipt_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "job_id": self.job_id,
            "agent_id": self.agent_id,
            "agent_did": self.agent_did,
            "state": self.state,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "idempotency_key": self.idempotency_key,
            "request_hash": self.request_hash,
            "prompt_sha256": self.prompt_sha256,
            "channel_id": self.channel_id,
            "request_message_id": self.request_message_id,
            "error": self.error,
            "response": self.response,
            "response_truncated": self.response_truncated,
            "receipt_id": self.receipt_id,
        }


class IdempotencyConflict(ValueError):
    """The same idempotency key was reused for a different request."""


class AgentLinkConflict(ValueError):
    """A recovery attempt conflicts with the already recorded outcome."""


_ALLOWED_TRANSITIONS = {
    "accepted": frozenset({"processing", "failed", "delivery_unknown"}),
    "processing": frozenset({
        "completed", "completed_unverified", "failed", "delivery_unknown",
    }),
    "completed": frozenset({"completed"}),
    "completed_unverified": frozenset({"completed_unverified"}),
    "failed": frozenset({"failed"}),
    "delivery_unknown": frozenset({"delivery_unknown"}),
}


class AgentLinkStore:
    """Small file-backed job store owned by one hub workspace.

    The prompt is intentionally absent. The channel or caller keeps the
    request content; the link store keeps only routing and outcome metadata.
    """

    def __init__(self, root: Optional[Path] = None, *, max_jobs: int = 1000) -> None:
        if max_jobs < 1:
            raise ValueError("max_jobs must be positive")
        self.root = Path(root) if root is not None else None
        self.max_jobs = int(max_jobs)
        self._lock = threading.RLock()
        self._jobs: Dict[str, LinkJob] = {}
        self._by_idempotency: Dict[Tuple[str, str], str] = {}
        if self.root is not None:
            self._load()

    @contextmanager
    def _process_lock(self) -> Iterator[None]:
        if self.root is None:
            yield
            return
        with InterProcessLock(self.root / "agent_links" / "jobs"):
            yield

    def create(
        self,
        *,
        agent_id: str,
        agent_did: str,
        idempotency_key: str = "",
        request_hash: str = "",
        prompt_sha256: str = "",
        channel_id: str = "",
        request_message_id: str = "",
    ) -> LinkJob:
        with self._lock:
            with self._process_lock():
                self._refresh_from_disk()
                lookup = (str(agent_did), str(idempotency_key))
                if idempotency_key and lookup in self._by_idempotency:
                    existing = self._jobs.get(self._by_idempotency[lookup])
                    if existing is not None:
                        if (
                            request_hash
                            and existing.request_hash
                            and existing.request_hash != str(request_hash)
                        ):
                            raise IdempotencyConflict(
                                "idempotency key was already used for a different "
                                "AgentLink request"
                            )
                        if request_hash and not existing.request_hash:
                            raise IdempotencyConflict(
                                "idempotency key belongs to a legacy request "
                                "without a request hash"
                            )
                        if (
                            prompt_sha256
                            and existing.prompt_sha256
                            and existing.prompt_sha256 != str(prompt_sha256)
                        ):
                            raise IdempotencyConflict(
                                "idempotency key was already used for a different "
                                "prompt"
                            )
                        if prompt_sha256 and not existing.prompt_sha256:
                            raise IdempotencyConflict(
                                "idempotency key belongs to a legacy request "
                                "without a prompt hash"
                            )
                        return existing
                if len(self._jobs) >= self.max_jobs:
                    raise AgentLinkStoreFull(
                        "AgentLink history is full; archive or purge old jobs "
                        "before retrying"
                    )
                timestamp = _now()
                job = LinkJob(
                    job_id=uuid.uuid4().hex,
                    agent_id=str(agent_id),
                    agent_did=str(agent_did),
                    state="accepted",
                    created_at=timestamp,
                    updated_at=timestamp,
                    idempotency_key=str(idempotency_key),
                    request_hash=str(request_hash or ""),
                    prompt_sha256=str(prompt_sha256 or ""),
                    channel_id=str(channel_id or "")[:200],
                    request_message_id=str(request_message_id or "")[:200],
                )
                self._jobs[job.job_id] = job
                if idempotency_key:
                    self._by_idempotency[lookup] = job.job_id
                self._save(job)
                return job

    def get(self, job_id: str) -> Optional[LinkJob]:
        with self._lock:
            with self._process_lock():
                self._refresh_from_disk()
                return self._jobs.get(str(job_id))

    def transition(
        self,
        job_id: str,
        state: str,
        *,
        error: str = "",
        response: str = "",
        response_truncated: bool = False,
        receipt_id: str = "",
    ) -> LinkJob:
        if state not in {"accepted", "processing", *TERMINAL_STATES}:
            raise ValueError(f"invalid AgentLink state: {state!r}")
        with self._lock:
            with self._process_lock():
                self._refresh_from_disk()
                current = self._jobs.get(str(job_id))
                if current is None:
                    raise KeyError(f"unknown AgentLink job: {job_id!r}")
                if state == current.state:
                    return current
                if state not in _ALLOWED_TRANSITIONS.get(current.state, frozenset()):
                    raise ValueError(
                        f"invalid AgentLink transition {current.state!r} -> {state!r} "
                        f"for {job_id!r}"
                    )
                normalized_response, was_truncated = bound_agent_response(response)
                updated = LinkJob(
                    job_id=current.job_id,
                    agent_id=current.agent_id,
                    agent_did=current.agent_did,
                    state=state,
                    created_at=current.created_at,
                    updated_at=_now(),
                    idempotency_key=current.idempotency_key,
                    request_hash=current.request_hash,
                    prompt_sha256=current.prompt_sha256,
                    channel_id=current.channel_id,
                    request_message_id=current.request_message_id,
                    error=str(error or "")[:2000],
                    response=normalized_response,
                    response_truncated=bool(response_truncated or was_truncated),
                    receipt_id=str(receipt_id or "")[:200],
                )
                self._jobs[updated.job_id] = updated
                self._save(updated)
                return updated

    def _path(self, job_id: str) -> Optional[Path]:
        if self.root is None:
            return None
        return self.root / "agent_links" / "jobs" / f"{safe_id(job_id)}.json"

    def _save(self, job: LinkJob) -> None:
        path = self._path(job.job_id)
        if path is not None:
            atomic_write_json(path, job.to_dict())

    def _job_from_data(self, data: Any) -> Optional[LinkJob]:
        if not isinstance(data, dict):
            return None
        try:
            response, was_truncated = bound_agent_response(data.get("response", ""))
            job = LinkJob(
                job_id=str(data["job_id"]),
                agent_id=str(data["agent_id"]),
                agent_did=str(data["agent_did"]),
                state=str(data["state"]),
                created_at=str(data["created_at"]),
                updated_at=str(data["updated_at"]),
                idempotency_key=str(data.get("idempotency_key", "")),
                request_hash=str(data.get("request_hash", "")),
                prompt_sha256=str(data.get("prompt_sha256", "")),
                channel_id=str(data.get("channel_id", "")),
                request_message_id=str(data.get("request_message_id", "")),
                error=str(data.get("error", "")),
                response=response,
                response_truncated=bool(
                    data.get("response_truncated", False) or was_truncated
                ),
                receipt_id=str(data.get("receipt_id", "")),
            )
        except (KeyError, TypeError, ValueError):
            return None
        valid_states = {"accepted", "processing", *TERMINAL_STATES}
        return job if job.state in valid_states else None

    def _read_disk_jobs(self) -> Dict[str, LinkJob]:
        path = self.root / "agent_links" / "jobs" if self.root else None
        if path is None or not path.exists():
            return {}
        jobs: Dict[str, LinkJob] = {}
        for item in path.glob("*.json"):
            job = self._job_from_data(safe_load_json(item, fallback=None))
            if job is not None:
                jobs[job.job_id] = job
        return jobs

    def _rebuild_idempotency_index(self) -> None:
        self._by_idempotency.clear()
        for job in self._jobs.values():
            if job.idempotency_key:
                self._by_idempotency[(job.agent_did, job.idempotency_key)] = job.job_id

    def all(self) -> Tuple[LinkJob, ...]:
        """Return a stable snapshot of durable jobs without exposing internals."""

        with self._lock:
            with self._process_lock():
                self._refresh_from_disk()
                return tuple(
                    sorted(self._jobs.values(), key=lambda job: (job.created_at, job.job_id))
                )

    def _refresh_from_disk(self) -> None:
        if self.root is None:
            return
        disk_jobs = self._read_disk_jobs()
        self._jobs = disk_jobs
        self._rebuild_idempotency_index()

    def _load(self) -> None:
        with self._lock:
            with self._process_lock():
                self._refresh_from_disk()
                recovered: Dict[str, LinkJob] = {}
                for job in self._jobs.values():
                    if job.state not in {"accepted", "processing"}:
                        continue
                    recovered[job.job_id] = LinkJob(
                        job_id=job.job_id,
                        agent_id=job.agent_id,
                        agent_did=job.agent_did,
                        state="delivery_unknown",
                        created_at=job.created_at,
                        updated_at=_now(),
                        idempotency_key=job.idempotency_key,
                        request_hash=job.request_hash,
                        prompt_sha256=job.prompt_sha256,
                        channel_id=job.channel_id,
                        request_message_id=job.request_message_id,
                        error=(
                            "Hub restarted before the AgentLink job completed; "
                            "the remote execution outcome is unknown."
                        ),
                        response="",
                        receipt_id="",
                    )
                for job_id, job in recovered.items():
                    self._jobs[job_id] = job
                    self._save(job)
                self._rebuild_idempotency_index()

    def reconcile_completed(
        self,
        job_id: str,
        *,
        response: str,
        receipt_id: str,
        persist_receipt: Optional[Callable[[], Any]] = None,
    ) -> LinkJob:
        """Close an uncertain delivery only after explicit evidence checks.

        ``delivery_unknown`` is intentionally not part of the normal state
        transition table. Recovery callers must use this method after they
        have verified a signed receipt and bound it to this job.
        """
        with self._lock:
            with self._process_lock():
                self._refresh_from_disk()
                current = self._jobs.get(str(job_id))
                if current is None:
                    raise KeyError(f"unknown AgentLink job: {job_id!r}")
                if current.state == "completed":
                    normalized_response, _ = bound_agent_response(response)
                    if (
                        current.receipt_id == str(receipt_id or "")
                        and current.response == normalized_response
                    ):
                        return current
                    raise AgentLinkConflict(
                        "AgentLink job already completed with a different outcome"
                    )
                if current.state not in {"delivery_unknown", "completed_unverified"}:
                    raise ValueError(
                        "only uncertain AgentLink jobs can be reconciled"
                    )
                if not current.prompt_sha256:
                    raise ValueError(
                        "AgentLink job has no prompt hash and cannot be reconciled"
                    )
                normalized_response, response_truncated = bound_agent_response(response)
                if (
                    current.state == "completed_unverified"
                    and current.response != normalized_response
                ):
                    raise AgentLinkConflict(
                        "unverified AgentLink response does not match recovery"
                    )
                if not str(receipt_id or ""):
                    raise ValueError("AgentLink reconciliation requires receipt_id")
                if persist_receipt is not None:
                    persist_receipt()
                updated = LinkJob(
                    job_id=current.job_id,
                    agent_id=current.agent_id,
                    agent_did=current.agent_did,
                    state="completed",
                    created_at=current.created_at,
                    updated_at=_now(),
                    idempotency_key=current.idempotency_key,
                    request_hash=current.request_hash,
                    prompt_sha256=current.prompt_sha256,
                    channel_id=current.channel_id,
                    request_message_id=current.request_message_id,
                    response=normalized_response,
                    response_truncated=response_truncated,
                    receipt_id=str(receipt_id or "")[:200],
                )
                self._jobs[updated.job_id] = updated
                self._save(updated)
                return updated


class AgentLinkBusy(RuntimeError):
    """The per-agent inbox has reached its configured bound."""


class AgentLinkStoreFull(RuntimeError):
    """The durable job history reached its configured safety bound."""


class AgentLinkManager:
    """Manage one serial, bounded worker inbox per supervised agent."""

    def __init__(
        self,
        store: Optional[AgentLinkStore] = None,
        *,
        max_pending_per_agent: int = 4,
        max_jobs: int = 1000,
    ) -> None:
        if max_pending_per_agent < 1:
            raise ValueError("max_pending_per_agent must be positive")
        if max_jobs < 1:
            raise ValueError("max_jobs must be positive")
        self.store = store or AgentLinkStore(max_jobs=max_jobs)
        if store is not None:
            self.store.max_jobs = int(max_jobs)
        self.max_pending_per_agent = int(max_pending_per_agent)
        self.max_jobs = int(max_jobs)
        self._lock = threading.RLock()
        self._queues: Dict[
            str, "queue.Queue[Optional[Tuple[LinkJob, LinkWorker]]]"
        ] = {}
        self._threads: Dict[str, threading.Thread] = {}
        self._queued_job_ids: set[str] = set()
        self._closed = False

    def submit(
        self,
        *,
        agent_id: str,
        agent_did: str,
        worker: LinkWorker,
        idempotency_key: str = "",
        request_hash: str = "",
        prompt_sha256: str = "",
        channel_id: str = "",
        request_message_id: str = "",
        autostart: bool = True,
    ) -> LinkJob:
        if not callable(worker):
            raise TypeError("AgentLink worker must be callable")
        with self._lock:
            if self._closed:
                raise RuntimeError("AgentLinkManager is closed")
            job = self.store.create(
                agent_id=agent_id,
                agent_did=agent_did,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                prompt_sha256=prompt_sha256,
                channel_id=channel_id,
                request_message_id=request_message_id,
            )
            if job.state != "accepted" or job.job_id in self._queued_job_ids:
                return job
            key = str(agent_did)
            q = self._queues.get(key)
            if q is None:
                q = queue.Queue(maxsize=self.max_pending_per_agent)
                self._queues[key] = q
                thread = threading.Thread(
                    target=self._worker_loop,
                    args=(q,),
                    name=f"nth-agent-link-{safe_id(agent_id, fallback='agent')[:24]}",
                    daemon=True,
                )
                self._threads[key] = thread
            try:
                q.put_nowait((job, worker))
            except queue.Full as exc:
                self.store.transition(
                    job.job_id,
                    "failed",
                    error="Agent inbox is full; retry later.",
                )
                raise AgentLinkBusy(
                    f"agent {agent_did!r} inbox is full"
                ) from exc
            self._queued_job_ids.add(job.job_id)
            if autostart:
                self._start_thread_locked(key)
            return job

    def _start_thread_locked(self, agent_did: str) -> None:
        thread = self._threads.get(str(agent_did))
        if thread is None or thread.ident is not None:
            return
        thread.start()

    def start(self, agent_did: str) -> None:
        """Start a deferred inbox after its accepted status is durable."""
        with self._lock:
            if self._closed:
                raise RuntimeError("AgentLinkManager is closed")
            self._start_thread_locked(str(agent_did))

    def get(self, job_id: str) -> Optional[LinkJob]:
        return self.store.get(job_id)

    def reconcile_completed(
        self,
        job_id: str,
        *,
        response: str,
        receipt_id: str,
        persist_receipt: Optional[Callable[[], Any]] = None,
    ) -> LinkJob:
        return self.store.reconcile_completed(
            job_id,
            response=response,
            receipt_id=receipt_id,
            persist_receipt=persist_receipt,
        )

    def close(self, timeout: float = 1.0) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            queues = list(self._queues.values())
            threads = list(self._threads.values())
            for q in queues:
                # Do not execute queued provider calls during shutdown. They
                # have not been delivered yet, so preserve the uncertainty in
                # the durable job state and let the next hub reconcile it.
                while True:
                    try:
                        item = q.get_nowait()
                    except queue.Empty:
                        break
                    try:
                        if item is not None:
                            job, _worker = item
                            self._queued_job_ids.discard(job.job_id)
                            self.store.transition(
                                job.job_id,
                                "delivery_unknown",
                                error=(
                                    "Hub shut down before the AgentLink job "
                                    "was delivered; execution outcome is unknown."
                                ),
                            )
                    finally:
                        q.task_done()
                try:
                    q.put_nowait(None)
                except queue.Full:
                    logger.warning("could not enqueue AgentLink shutdown sentinel")
        for thread in threads:
            if thread.ident is not None:
                thread.join(timeout=max(0.0, timeout))

    def _worker_loop(
        self,
        q: "queue.Queue[Optional[Tuple[LinkJob, LinkWorker]]]",
    ) -> None:
        while True:
            item = q.get()
            try:
                if item is None:
                    return
                job, worker = item
                with self._lock:
                    self._queued_job_ids.discard(job.job_id)
                try:
                    self.store.transition(job.job_id, "processing")
                    outcome = worker()
                    if outcome is False:
                        fields: Dict[str, Any] = {
                            "error": "AgentLink worker returned failure without a reason"
                        }
                    elif not isinstance(outcome, dict):
                        fields = {
                            "error": (
                                "AgentLink worker returned an invalid result type: "
                                f"{type(outcome).__name__}"
                            )
                        }
                    else:
                        fields = outcome
                    error = str(fields.get("error", "") or "")
                    receipt_id = str(fields.get("receipt_id", "") or "")
                    terminal_state = (
                        "failed"
                        if error
                        else ("completed" if receipt_id else "completed_unverified")
                    )
                    self.store.transition(
                        job.job_id,
                        terminal_state,
                        error=error,
                        response=str(fields.get("response", "")),
                        response_truncated=bool(
                            fields.get("response_truncated", False)
                        ),
                        receipt_id=receipt_id,
                    )
                except Exception as exc:  # noqa: BLE001
                    error = f"{type(exc).__name__}: {exc}"
                    try:
                        self.store.transition(
                            job.job_id,
                            "failed",
                            error=error,
                        )
                    except Exception as persist_exc:  # noqa: BLE001
                        logger.error(
                            "AgentLink job %s failed and failure state could "
                            "not be persisted: %s",
                            job.job_id,
                            persist_exc,
                        )
            finally:
                q.task_done()
