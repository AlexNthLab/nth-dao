"""Bounded targeted recovery tests for retained Dispute Statement ACKs."""

from __future__ import annotations

from types import SimpleNamespace
import threading
import time

import pytest

from nth_dao.web import (
    _TRADE_DISPUTE_URGENT_MAX_ATTEMPTS,
    _TRADE_DISPUTE_URGENT_MAX_TARGETS,
    _TradeDisputeStatementRecoveryWorker,
    _recover_trade_dispute_statement_dispatch_acknowledgement,
)


def digest(index: int) -> str:
    return f"sha256:{index:064x}"


def state(dispatch=None):
    return SimpleNamespace(
        spine=object(),
        trade_dispute_statement_audit=None,
        trade_dispute_statement_dispatch=dispatch or object(),
        trade_dispute_statement_recovery_lock=threading.Lock(),
    )


def test_target_queue_deduplicates_and_is_capacity_bounded() -> None:
    worker = _TradeDisputeStatementRecoveryWorker(state())
    target = digest(1)
    assert worker.wake(target, urgent_for_s=5.0) is True
    assert worker.wake(target, urgent_for_s=5.0) is True
    assert len(worker._urgent_targets) == 1
    for index in range(2, _TRADE_DISPUTE_URGENT_MAX_TARGETS + 1):
        assert worker.wake(digest(index), urgent_for_s=5.0) is True
    assert len(worker._urgent_targets) == _TRADE_DISPUTE_URGENT_MAX_TARGETS
    assert worker.wake(digest(_TRADE_DISPUTE_URGENT_MAX_TARGETS + 1)) is False


def test_duplicate_wake_does_not_reset_backoff_or_extend_deadline() -> None:
    worker = _TradeDisputeStatementRecoveryWorker(state())
    target = digest(1)
    assert worker.wake(target, urgent_for_s=2.0) is True
    queued = worker._urgent_targets[target]
    queued["attempts"] = 3
    queued["next_at"] = time.monotonic() + 0.75
    original = dict(queued)

    assert worker.wake(target, urgent_for_s=30.0) is True

    assert worker._urgent_targets[target] == original


def test_inflight_duplicate_cannot_reduce_retry_budget_or_extend_deadline() -> None:
    worker = _TradeDisputeStatementRecoveryWorker(state())
    target = digest(1)
    now = time.monotonic()
    inflight = {
        "attempts": 2,
        "next_at": now,
        "expires_at": now + 2.0,
    }
    worker._urgent_targets[target] = {
        "attempts": 0,
        "next_at": now,
        "expires_at": now + 30.0,
    }

    worker._retry_target(target, inflight)

    queued = worker._urgent_targets[target]
    assert queued["attempts"] == 3
    assert float(queued["next_at"]) > now
    assert queued["expires_at"] == inflight["expires_at"]


def test_target_retry_is_bounded_and_backed_off() -> None:
    worker = _TradeDisputeStatementRecoveryWorker(state())
    target = digest(1)
    item = {
        "attempts": 0,
        "next_at": time.monotonic(),
        "expires_at": time.monotonic() + 10.0,
    }
    previous_next = float(item["next_at"])
    for expected_attempt in range(1, _TRADE_DISPUTE_URGENT_MAX_ATTEMPTS + 1):
        worker._retry_target(target, item)
        queued = worker._urgent_targets.pop(target, None)
        if expected_attempt == _TRADE_DISPUTE_URGENT_MAX_ATTEMPTS:
            assert queued is None
            break
        assert queued is item
        assert item["attempts"] == expected_attempt
        assert float(item["next_at"]) > previous_next
        previous_next = float(item["next_at"])


def test_specific_recovery_calls_only_requested_digest() -> None:
    calls = []

    class Dispatch:
        def recover_acknowledgement(self, statement_digest):
            calls.append(statement_digest)
            return SimpleNamespace(anchor_event_id="a" * 64)

    target = digest(7)
    assert _recover_trade_dispute_statement_dispatch_acknowledgement(
        state(Dispatch()),
        target,
    ) is True
    assert calls == [target]


def test_worker_prioritizes_target_without_global_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = _TradeDisputeStatementRecoveryWorker(state())
    target = digest(9)
    calls = []
    recovered = threading.Event()

    def recover(_state, statement_digest):
        calls.append(statement_digest)
        recovered.set()
        worker._cancel.set()
        return True

    monkeypatch.setattr(
        "nth_dao.web._recover_trade_dispute_statement_dispatch_acknowledgement",
        recover,
    )
    monkeypatch.setattr(
        "nth_dao.web._recover_trade_dispute_statement_dispatch_acknowledgements",
        lambda _state: (_ for _ in ()).throw(AssertionError("unexpected global scan")),
    )
    assert worker.wake(target, urgent_for_s=5.0) is True
    worker.start()
    assert recovered.wait(1.0)
    worker.stop()
    assert calls == [target]


def test_target_queue_rejects_malformed_digest() -> None:
    worker = _TradeDisputeStatementRecoveryWorker(state())
    with pytest.raises(ValueError, match="statement_digest"):
        worker.wake("../not-a-digest", urgent_for_s=5.0)
