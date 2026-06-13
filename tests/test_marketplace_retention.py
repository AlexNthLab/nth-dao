"""终态订单按保留期老化清理(2026-06-14)。

存储膨胀的正解不是给开放订单设上限(那是待办的真实工作),而是清理永
不消失的终态订单。开放订单不设上限;终态订单过保留期由 prune_finished
清掉(签名证据在 receipt/reputation store 里持久,清的只是操作态文件)。
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

from nth_dao.marketplace import TaskMarketplace


def _age_to(mp: TaskMarketplace, order_id: str, when: datetime) -> None:
    """把一个订单的时间戳改老,模拟它在很久以前进入终态。"""
    o = mp.get_order(order_id)
    assert o is not None
    ts = when.isoformat()
    o.created_at = ts
    o.timeline = [{"action": o.status.value, "actor": mp.agent_id, "timestamp": ts}]
    mp._save(o)


def test_open_orders_are_not_capped(tmp_path: Path) -> None:
    # 开放订单不设上限:20 个全部创建成功。
    mp = TaskMarketplace(agent_id="bob", workspace=tmp_path)
    for i in range(20):
        mp.create_order(title=f"t{i}")
    assert len(mp.list_open()) == 20


def test_prune_finished_removes_only_aged_terminal_orders(tmp_path: Path) -> None:
    mp = TaskMarketplace(agent_id="alice", workspace=tmp_path)

    still_open = mp.create_order(title="still-open")

    old = mp.create_order(title="old-done")
    mp.cancel(old.order_id)                       # → CANCELLED(终态)
    _age_to(mp, old.order_id, datetime.now() - timedelta(days=40))

    fresh = mp.create_order(title="fresh-done")
    mp.cancel(fresh.order_id)                      # 终态但时间戳=now

    pruned = mp.prune_finished(older_than_days=30)

    assert pruned == 1
    assert mp.get_order(old.order_id) is None          # 旧终态被清
    assert mp.get_order(fresh.order_id) is not None     # 新终态保留
    assert mp.get_order(still_open.order_id) is not None  # 开放单永不被清


def test_prune_retention_zero_is_noop(tmp_path: Path) -> None:
    mp = TaskMarketplace(
        agent_id="carol", workspace=tmp_path, finished_retention_days=0,
    )
    o = mp.create_order(title="x")
    mp.cancel(o.order_id)
    _age_to(mp, o.order_id, datetime.now() - timedelta(days=999))
    assert mp.prune_finished() == 0
    assert mp.get_order(o.order_id) is not None
