"""Lifecycle-owned delivery retries for the durable commerce outbox."""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from dataclasses import asdict, dataclass
from typing import Any, Callable, Dict

from nth_dao.commerce.outbox import (
    OUTBOX_ERROR_DISPATCH_CONTRACT,
    OUTBOX_ERROR_LEASE_SUPERSEDED,
    OUTBOX_ERROR_PERSISTENCE,
    OUTBOX_ERROR_RECORD_MISSING,
    OUTBOX_ERROR_RUNTIME,
    CommerceEnvelopeRejected,
    CommerceOutbox,
    OutboxRecord,
    normalize_outbox_error,
)

logger = logging.getLogger(__name__)

DispatchRecord = Callable[[OutboxRecord, int], Dict[str, Any]]
MaintenanceCycle = Callable[[int, int], Dict[str, int]]


@dataclass(frozen=True)
class ReconcilerConfig:
    poll_interval_s: float = 2.0
    lease_ms: int = 30_000
    batch_limit: int = 25
    base_backoff_ms: int = 1_000
    max_backoff_ms: int = 300_000
    jitter_ratio: float = 0.2
    archive_after_s: int = 0
    orphan_after_s: int = 7 * 86_400

    def __post_init__(self) -> None:
        if isinstance(self.poll_interval_s, bool) or not isinstance(self.poll_interval_s, (int, float)):
            raise ValueError("poll_interval_s must be numeric")
        if not 0.1 <= float(self.poll_interval_s) <= 300.0:
            raise ValueError("poll_interval_s must be between 0.1 and 300")
        if isinstance(self.lease_ms, bool) or not isinstance(self.lease_ms, int) or not 1_000 <= self.lease_ms <= 300_000:
            raise ValueError("lease_ms must be between 1000 and 300000")
        if isinstance(self.batch_limit, bool) or not isinstance(self.batch_limit, int) or not 1 <= self.batch_limit <= 1_000:
            raise ValueError("batch_limit must be between 1 and 1000")
        if isinstance(self.base_backoff_ms, bool) or not isinstance(self.base_backoff_ms, int) or self.base_backoff_ms < 1:
            raise ValueError("base_backoff_ms must be a positive integer")
        if isinstance(self.max_backoff_ms, bool) or not isinstance(self.max_backoff_ms, int) or not self.base_backoff_ms <= self.max_backoff_ms <= 86_400_000:
            raise ValueError("max_backoff_ms must be between base_backoff_ms and 86400000")
        if isinstance(self.jitter_ratio, bool) or not isinstance(self.jitter_ratio, (int, float)) or not 0.0 <= float(self.jitter_ratio) <= 0.5:
            raise ValueError("jitter_ratio must be between 0 and 0.5")
        if (
            isinstance(self.archive_after_s, bool)
            or not isinstance(self.archive_after_s, int)
            or (self.archive_after_s != 0 and self.archive_after_s < 86_400)
        ):
            raise ValueError("archive_after_s must be 0 or at least 86400")
        if (
            isinstance(self.orphan_after_s, bool)
            or not isinstance(self.orphan_after_s, int)
            or self.orphan_after_s < 86_400
        ):
            raise ValueError("orphan_after_s must be at least 86400")


class CommerceReconciler:
    """Poll an outbox without weakening its lease and idempotency guarantees.

    The dispatcher receives the leased record and the delay to persist if the
    attempt fails. It must finalize the lease through ``record_attempt``. A
    raised exception is treated as a failed attempt and finalized here so a
    faulty adapter cannot strand work until lease expiry.
    """

    def __init__(
        self,
        outbox: CommerceOutbox,
        dispatch: DispatchRecord,
        *,
        config: ReconcilerConfig | None = None,
        maintenance: MaintenanceCycle | None = None,
    ) -> None:
        if not callable(dispatch):
            raise TypeError("dispatch must be callable")
        self.outbox = outbox
        self.dispatch = dispatch
        self.config = config or ReconcilerConfig()
        if maintenance is not None and not callable(maintenance):
            raise TypeError("maintenance must be callable")
        self.maintenance = maintenance
        self._stop_event = threading.Event()
        self._run_lock = threading.Lock()
        self._state_lock = threading.RLock()
        self._thread: threading.Thread | None = None
        self._started_at_ms = 0
        self._last_run_at_ms = 0
        self._last_success_at_ms = 0
        self._last_error = ""
        self._claimed_total = 0
        self._acknowledged_total = 0
        self._failed_total = 0
        self._maintenance_total = 0
        self._quarantined_total = 0
        self._maintenance_error = ""

    def retry_delay_ms(self, prior_attempts: int, message_id: str = "") -> int:
        if isinstance(prior_attempts, bool) or not isinstance(prior_attempts, int) or prior_attempts < 0:
            raise ValueError("prior_attempts must be a non-negative integer")
        exponent = min(prior_attempts, 30)
        base_delay = min(
            self.config.max_backoff_ms,
            self.config.base_backoff_ms * (2 ** exponent),
        )
        jitter_window = int(base_delay * float(self.config.jitter_ratio))
        if not message_id or jitter_window <= 0 or base_delay >= self.config.max_backoff_ms:
            return base_delay
        jitter = int.from_bytes(
            hashlib.sha256(message_id.encode("utf-8")).digest()[:8],
            "big",
        ) % (jitter_window + 1)
        return min(self.config.max_backoff_ms, base_delay + jitter)

    def run_once(self, *, now_ms_override: int = 0) -> Dict[str, Any]:
        if not self._run_lock.acquire(blocking=False):
            return {"busy": True, "claimed": 0, "acknowledged": 0, "failed": 0}
        claimed = 0
        acknowledged = 0
        failed = 0
        last_error = ""
        try:
            candidates = self.outbox.pending(limit=self.config.batch_limit)
            for candidate in candidates:
                if self._stop_event.is_set():
                    break
                candidate_id = str(candidate.envelope.get("message_id", ""))
                try:
                    record = self.outbox.claim(
                        candidate_id,
                        lease_ms=self.config.lease_ms,
                        now_ms_override=now_ms_override,
                    )
                except CommerceEnvelopeRejected as exc:
                    logger.warning("skipping invalid commerce outbox candidate %s: %s", candidate_id, exc)
                    continue
                if record is None:
                    continue
                claimed += 1
                message_id = str(record.envelope.get("message_id", ""))
                retry_after_ms = self.retry_delay_ms(record.attempts, message_id)
                previous_error = last_error
                try:
                    result = self.dispatch(record, retry_after_ms)
                    if not isinstance(result, dict):
                        raise TypeError("commerce dispatcher returned a non-object result")
                    current = self.outbox.get(message_id)
                    if current is not None and current.status == "acknowledged":
                        acknowledged += 1
                        continue
                    if (
                        current is not None
                        and current.status == "inflight"
                        and current.lease_id == record.lease_id
                    ):
                        last_error = OUTBOX_ERROR_DISPATCH_CONTRACT
                        current = self.outbox.record_attempt(
                            message_id,
                            error=last_error,
                            lease_id=record.lease_id,
                            retry_after_ms=retry_after_ms,
                            now_ms_override=now_ms_override,
                        )
                    if current is None:
                        last_error = OUTBOX_ERROR_RECORD_MISSING
                    elif current.status == "inflight":
                        last_error = OUTBOX_ERROR_LEASE_SUPERSEDED
                    else:
                        last_error = normalize_outbox_error(
                            result.get("error") or current.last_error,
                            retryable=current.status != "blocked",
                        )
                    failed += 1
                except Exception as exc:  # noqa: BLE001 - worker boundary must release its lease
                    last_error = OUTBOX_ERROR_RUNTIME
                    logger.warning(
                        "commerce dispatcher failed for %s (%s)",
                        message_id,
                        type(exc).__name__,
                    )
                    try:
                        current = self.outbox.get(message_id)
                        if current is not None and current.status == "acknowledged":
                            acknowledged += 1
                            last_error = previous_error
                            continue
                        if (
                            current is not None
                            and current.status == "inflight"
                            and current.lease_id == record.lease_id
                        ):
                            self.outbox.record_attempt(
                                message_id,
                                error=last_error,
                                lease_id=record.lease_id,
                                retry_after_ms=retry_after_ms,
                                now_ms_override=now_ms_override,
                            )
                    except (CommerceEnvelopeRejected, OSError, RuntimeError, TypeError, ValueError) as persist_exc:
                        last_error = OUTBOX_ERROR_PERSISTENCE
                        logger.error(
                            "commerce reconciler could not finalize %s (%s)",
                            message_id,
                            type(persist_exc).__name__,
                        )
                    failed += 1
            if self.config.archive_after_s:
                current_ms = now_ms_override or time.time_ns() // 1_000_000
                self.outbox.archive_acknowledged(
                    before_ms=current_ms - self.config.archive_after_s * 1_000,
                    limit=self.config.batch_limit,
                )
            if self.maintenance is not None:
                current_ms = now_ms_override or time.time_ns() // 1_000_000
                try:
                    maintenance = self.maintenance(
                        current_ms,
                        self.config.batch_limit,
                    )
                    with self._state_lock:
                        self._maintenance_total += int(
                            maintenance.get("scanned", 0)
                        )
                        self._quarantined_total += int(
                            maintenance.get("quarantined", 0)
                        )
                        self._maintenance_error = ""
                except Exception as exc:  # noqa: BLE001 - maintenance is isolated
                    with self._state_lock:
                        self._maintenance_error = OUTBOX_ERROR_RUNTIME
                    logger.error(
                        "commerce import maintenance failed (%s)",
                        type(exc).__name__,
                    )
            return {
                "busy": False,
                "claimed": claimed,
                "acknowledged": acknowledged,
                "failed": failed,
            }
        except Exception as exc:
            last_error = OUTBOX_ERROR_RUNTIME
            logger.warning(
                "commerce reconciliation cycle failed (%s)",
                type(exc).__name__,
            )
            raise
        finally:
            current_ms = now_ms_override or time.time_ns() // 1_000_000
            with self._state_lock:
                self._last_run_at_ms = current_ms
                self._claimed_total += claimed
                self._acknowledged_total += acknowledged
                self._failed_total += failed
                if acknowledged:
                    self._last_success_at_ms = current_ms
                if last_error:
                    self._last_error = last_error
                elif acknowledged:
                    self._last_error = ""
            self._run_lock.release()

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.run_once()
            except Exception as exc:  # noqa: BLE001 - keep lifecycle worker alive
                with self._state_lock:
                    self._last_error = OUTBOX_ERROR_RUNTIME
                logger.error(
                    "commerce reconciliation cycle failed (%s)",
                    type(exc).__name__,
                )
            self._stop_event.wait(float(self.config.poll_interval_s))

    def start(self) -> bool:
        with self._state_lock:
            if self._thread is not None and self._thread.is_alive():
                return False
            self._stop_event.clear()
            self._started_at_ms = time.time_ns() // 1_000_000
            self._thread = threading.Thread(
                target=self._run,
                name="nth-commerce-reconciler",
                daemon=True,
            )
            self._thread.start()
            return True

    def stop(self, *, timeout_s: float = 10.0) -> bool:
        if isinstance(timeout_s, bool) or not isinstance(timeout_s, (int, float)) or timeout_s < 0:
            raise ValueError("timeout_s must be a non-negative number")
        self._stop_event.set()
        with self._state_lock:
            thread = self._thread
        if thread is not None:
            thread.join(timeout=float(timeout_s))
        stopped = thread is None or not thread.is_alive()
        if stopped:
            with self._state_lock:
                self._thread = None
        return stopped

    def status(self) -> Dict[str, Any]:
        with self._state_lock:
            thread = self._thread
            return {
                "running": bool(thread is not None and thread.is_alive()),
                "started_at_ms": self._started_at_ms,
                "last_run_at_ms": self._last_run_at_ms,
                "last_success_at_ms": self._last_success_at_ms,
                "last_error": self._last_error,
                "claimed_total": self._claimed_total,
                "acknowledged_total": self._acknowledged_total,
                "failed_total": self._failed_total,
                "maintenance_total": self._maintenance_total,
                "quarantined_total": self._quarantined_total,
                "maintenance_error": self._maintenance_error,
                "config": asdict(self.config),
            }
