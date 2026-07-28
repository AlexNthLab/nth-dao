from __future__ import annotations

import threading
from pathlib import Path

import pytest

from nth_dao.web.decision_store import (
    DecisionConflict,
    DecisionNotFound,
    DecisionStore,
)


def _decision(decision_id: str, title: str = "Review change") -> dict:
    return {
        "id": decision_id,
        "title": title,
        "rationale": "A durable operator decision.",
        "raised_at": "2026-07-28T00:00:00+00:00",
    }


def test_decision_survives_store_recreation(tmp_path: Path) -> None:
    DecisionStore(tmp_path).put(_decision("d-1"))

    reopened = DecisionStore(tmp_path)

    assert reopened.get("d-1") == _decision("d-1")
    assert reopened.events()[0]["event_kind"] == "decision.raised"


def test_same_id_is_idempotent_but_cannot_overwrite(tmp_path: Path) -> None:
    store = DecisionStore(tmp_path)
    store.put(_decision("d-1"))
    store.put(_decision("d-1"))

    with pytest.raises(DecisionConflict):
        store.put(_decision("d-1", title="Different action"))

    assert len(store.events()) == 1
    assert store.get("d-1")["title"] == "Review change"


@pytest.mark.parametrize(
    "decision",
    [
        {"id": "x" * 201, "title": "oversized id"},
        {"id": "d-large", "title": "x" * (256 * 1024)},
        {"id": "d-nan", "title": float("nan")},
    ],
)
def test_rejects_unbounded_or_non_json_decisions(
    tmp_path: Path, decision: dict,
) -> None:
    store = DecisionStore(tmp_path)

    with pytest.raises(ValueError):
        store.put(decision)

    assert store.values() == []


def test_concurrent_writers_do_not_lose_decisions(tmp_path: Path) -> None:
    barrier = threading.Barrier(12)
    errors: list[BaseException] = []

    def write(index: int) -> None:
        try:
            store = DecisionStore(tmp_path)
            barrier.wait()
            store.put(_decision(f"d-{index:02d}"))
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=write, args=(i,)) for i in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert not errors
    assert all(not thread.is_alive() for thread in threads)
    assert len(DecisionStore(tmp_path).values()) == 12


def test_resolution_rolls_back_on_failure(tmp_path: Path) -> None:
    store = DecisionStore(tmp_path)
    store.put(_decision("d-1"))

    with pytest.raises(RuntimeError):
        with store.resolution("d-1"):
            raise RuntimeError("receipt persistence failed")

    assert store.get("d-1") is not None
    assert [event["event_kind"] for event in store.events()] == [
        "decision.raised"
    ]


def test_only_one_concurrent_resolution_succeeds(tmp_path: Path) -> None:
    DecisionStore(tmp_path).put(_decision("d-1"))
    barrier = threading.Barrier(2)
    resolved: list[str] = []
    missing: list[str] = []

    def resolve() -> None:
        store = DecisionStore(tmp_path)
        barrier.wait()
        try:
            with store.resolution("d-1") as transaction:
                transaction.complete("approved", receipt_id="receipt-1")
            resolved.append("ok")
        except DecisionNotFound:
            missing.append("missing")

    threads = [threading.Thread(target=resolve) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert resolved == ["ok"]
    assert missing == ["missing"]
    store = DecisionStore(tmp_path)
    assert store.get("d-1") is None
    assert [event["event_kind"] for event in store.events()] == [
        "decision.raised",
        "decision.approved",
    ]
    assert store.events()[-1]["receipt_id"] == "receipt-1"
