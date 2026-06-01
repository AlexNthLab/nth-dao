"""跨进程 claim 竞态测试。

C-3 的本质修复是：两个独立进程同时 try_claim 同一个 step，
只有一个能成功；另一个必须收到 ClaimConflict（而不是 silent overwrite）。

如果文件锁工作正确，run N 个 worker 抢 1 个 step → 只有 1 个 winner。
"""

import multiprocessing as mp
import os
import sys
from pathlib import Path


def _worker(workspace: str, mission_id: str, step_id: str, agent_id: str,
            result_queue) -> None:
    """子进程入口。"""
    # 把项目根加入 sys.path，以便 import nth_dao
    project_root = str(Path(__file__).parent.parent)
    sys.path.insert(0, project_root)

    try:
        from nth_dao.orchestration.mission_store import MissionStore, ClaimConflict
        store = MissionStore(str(Path(workspace) / "missions"))
        try:
            step = store.try_claim(
                mission_id, step_id,
                agent_id=agent_id, capabilities=["python"],
            )
            if step is not None and step.assignee == agent_id:
                result_queue.put(("won", agent_id))
                return
            result_queue.put(("lost", agent_id))
        except ClaimConflict as e:
            result_queue.put(("conflict", agent_id, str(e)))
    except Exception as e:
        result_queue.put(("error", agent_id, repr(e)))


def _create_worker(workspace: str, mission_id: str, agent_id: str, result_queue) -> None:
    project_root = str(Path(__file__).parent.parent)
    sys.path.insert(0, project_root)
    try:
        from nth_dao.orchestration import Mission
        from nth_dao.orchestration.mission_store import MissionStore
        store = MissionStore(str(Path(workspace) / "missions"))
        mission = Mission.new(
            title="create-race",
            goal="g",
            owner=agent_id,
            steps=[{"id": "s1", "description": "x"}],
        )
        mission.id = mission_id
        try:
            store.create(mission)
            result_queue.put(("created", agent_id))
        except FileExistsError:
            result_queue.put(("exists", agent_id))
    except Exception as e:
        result_queue.put(("error", agent_id, repr(e)))


def test_exactly_one_winner_across_processes(tmp_path):
    """启动 N 个独立进程抢同一个 step —— 恰好 1 个赢，其它都收到 ClaimConflict。"""
    # 准备 mission
    from nth_dao.orchestration import Mission
    from nth_dao.orchestration.mission_store import MissionStore

    store = MissionStore(str(tmp_path / "missions"))
    m = Mission.new(
        title="race", goal="g", owner="orchestrator",
        steps=[{
            "id": "the_step", "description": "x",
            "required_capabilities": ["python"],
        }],
    )
    store.create(m)

    # 启动 N 个 worker
    n_workers = 6
    ctx = mp.get_context("spawn")
    q = ctx.Queue()
    procs = [
        ctx.Process(
            target=_worker,
            args=(str(tmp_path), m.id, "the_step", f"agent-{i}", q),
        )
        for i in range(n_workers)
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=30)

    results = []
    while not q.empty():
        results.append(q.get_nowait())

    won = [r for r in results if r[0] == "won"]
    conflict = [r for r in results if r[0] == "conflict"]
    error = [r for r in results if r[0] == "error"]

    assert len(error) == 0, f"unexpected errors: {error}"
    assert len(won) == 1, (
        f"expected exactly 1 winner, got {len(won)}; "
        f"results={results}"
    )
    # 其余应该都是 conflict（不是 silent lost）
    assert len(conflict) == n_workers - 1, (
        f"expected {n_workers - 1} conflicts, got {len(conflict)}; "
        f"results={results}"
    )


def test_exactly_one_create_across_processes(tmp_path):
    n_workers = 6
    ctx = mp.get_context("spawn")
    q = ctx.Queue()
    procs = [
        ctx.Process(
            target=_create_worker,
            args=(str(tmp_path), "same-mission", f"agent-{i}", q),
        )
        for i in range(n_workers)
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=30)

    results = []
    while not q.empty():
        results.append(q.get_nowait())

    created = [r for r in results if r[0] == "created"]
    exists = [r for r in results if r[0] == "exists"]
    error = [r for r in results if r[0] == "error"]

    assert len(error) == 0, f"unexpected errors: {error}"
    assert len(created) == 1, f"expected exactly 1 creator; results={results}"
    assert len(exists) == n_workers - 1, f"expected duplicate creates to fail; results={results}"
