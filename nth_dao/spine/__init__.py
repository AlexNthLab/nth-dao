"""Nth DAO 统一签名因果日志 spine(Phase 1)。

愿景基石#1:整个节点的事实源收敛成**一条 per-DAO 的签名 hash 链事件日志**;
market / ledger / 审计 / 信誉 / 争议都是它的物化视图(``Projection``)。

本包当前**非破坏式新增**,与现有各 feed 并存;后续 Phase 再把旧 feed 逐个迁成
投影(双写 → 切读),不做 big-bang。
"""
from nth_dao.spine.event import (
    GENESIS_PREV,
    SpineEvent,
    event_content_hash,
    sign_event,
    verify_event,
)
from nth_dao.spine.log import SignedEventLog
from nth_dao.spine.projection import Projection, replay

__all__ = [
    "GENESIS_PREV",
    "SpineEvent",
    "event_content_hash",
    "sign_event",
    "verify_event",
    "SignedEventLog",
    "Projection",
    "replay",
]
