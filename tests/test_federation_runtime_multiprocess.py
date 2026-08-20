"""Process-level regression tests for federation runtime ownership."""

from __future__ import annotations

import multiprocessing
from pathlib import Path
from types import SimpleNamespace


def _hold_federation_owner(
    workspace: str,
    ready,
    release,
    result,
) -> None:
    from nth_dao.web import v2_api

    state = SimpleNamespace()
    acquired = v2_api._claim_market_fed_runtime_owner(
        state,
        Path(workspace),
        timeout_s=2.0,
    )
    result.put(acquired)
    ready.set()
    try:
        release.wait(10.0)
    finally:
        v2_api._release_market_fed_runtime_owner(state)


def _persist_federation_preference(workspace: str, mode: str, result) -> None:
    from nth_dao.web import v2_api

    try:
        v2_api._write_fed_runtime_preference(Path(workspace), mode)
    except Exception as exc:  # pragma: no cover - relayed to parent assertion
        result.put((False, type(exc).__name__, str(exc)))
    else:
        result.put((True, "", ""))


def test_only_one_process_can_own_federation_runtime(tmp_path: Path) -> None:
    from nth_dao.web import v2_api

    context = multiprocessing.get_context("spawn")
    ready = context.Event()
    release = context.Event()
    result = context.Queue()
    worker = context.Process(
        target=_hold_federation_owner,
        args=(str(tmp_path), ready, release, result),
    )
    worker.start()
    parent_state = SimpleNamespace()
    try:
        assert ready.wait(10.0), "owner process did not become ready"
        assert result.get(timeout=2.0) is True
        assert (
            v2_api._claim_market_fed_runtime_owner(
                parent_state,
                tmp_path,
                timeout_s=0.2,
            )
            is False
        )
    finally:
        release.set()
        worker.join(timeout=10.0)
        if worker.is_alive():
            worker.terminate()
            worker.join(timeout=5.0)
        v2_api._release_market_fed_runtime_owner(parent_state)
    assert worker.exitcode == 0

    assert v2_api._claim_market_fed_runtime_owner(
        parent_state,
        tmp_path,
        timeout_s=1.0,
    )
    v2_api._release_market_fed_runtime_owner(parent_state)


def test_process_written_suspension_invalidates_parent_cache(tmp_path: Path) -> None:
    from nth_dao.web import v2_api

    state = SimpleNamespace(
        market_fed_runtime_preference="legacy",
        market_fed_plugin_suspended=False,
    )
    context = multiprocessing.get_context("spawn")
    result = context.Queue()
    worker = context.Process(
        target=_persist_federation_preference,
        args=(str(tmp_path), "suspended", result),
    )
    worker.start()
    worker.join(timeout=10.0)
    if worker.is_alive():
        worker.terminate()
        worker.join(timeout=5.0)
    assert worker.exitcode == 0
    assert result.get(timeout=2.0) == (True, "", "")

    assert v2_api._initialize_fed_runtime_preference(state, tmp_path) == "suspended"
    assert state.market_fed_runtime_preference == "suspended"
    assert state.market_fed_plugin_suspended is True
