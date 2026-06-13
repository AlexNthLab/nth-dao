"""单个 creator 的开放订单上限(2026-06-14 审查补:auto/scale 显式上限)。

防止一个 agent 无界堆开放订单撑爆 marketplace 目录。达上限 create_order
抛 ValueError;完成/取消腾出名额后可再开;<=0 表示不限。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nth_dao.marketplace import TaskMarketplace


def test_open_order_ceiling_blocks_then_reopens(tmp_path: Path) -> None:
    mp = TaskMarketplace(agent_id="alice", workspace=tmp_path, max_open_orders=2)
    o1 = mp.create_order(title="t1")
    mp.create_order(title="t2")
    # 第三个超限 → 拒。
    with pytest.raises(ValueError, match="ceiling"):
        mp.create_order(title="t3")
    # 取消一个腾出名额 → 又能开。
    mp.cancel(o1.order_id)
    mp.create_order(title="t3-again")  # 不再抛


def test_open_order_ceiling_zero_means_unlimited(tmp_path: Path) -> None:
    mp = TaskMarketplace(agent_id="bob", workspace=tmp_path, max_open_orders=0)
    for i in range(5):
        mp.create_order(title=f"t{i}")
    assert len(mp.list_open()) == 5
