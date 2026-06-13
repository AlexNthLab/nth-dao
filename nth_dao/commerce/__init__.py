"""Nth DAO commerce —— 交易状态机（claim → 执行 → 交付 → 验收 → 结算）。

主动市场（``nth_dao.market``）负责"谁来干"（discover→match→claim）。
commerce 负责"干得怎样、钱怎么付"（execute→deliver→verify→settle）。
接缝：``open_trade`` 吃一条市场 claim_record 开局。

设计见桌面 ``A2A交易演进路线图-2026-06-12-重锚定当前代码.md``。

里程碑：
  CS1 ✅  签名 trade 状态机（无真钱，manual 结算）
  CS2 ⏳  DeterministicTestVerifier（复用 sandbox + execution receipt）
  CS3 ⏳  争议处理（DISPUTED → REFUNDED / 部分结算）
  CS4 ⏳  x402 testnet 真钱结算 adapter
"""

from nth_dao.commerce.trade import (
    # 状态
    STATE_EXECUTING,
    STATE_DELIVERED,
    STATE_VERIFIED,
    STATE_FAILED,
    STATE_SETTLED,
    TERMINAL_STATES,
    # 事件类型 / verdict
    EVENT_TRADE_OPENED,
    EVENT_DELIVERY_SUBMITTED,
    EVENT_VERIFICATION_RECORDED,
    EVENT_SETTLEMENT_RECORDED,
    VERDICT_PASS,
    VERDICT_FAIL,
    # 对象 + 存储
    TradeEvent,
    TradeStore,
    sign_trade_event,
    verify_trade_event,
    # 转移函数
    open_trade,
    submit_delivery,
    record_verification,
    record_settlement,
    # 查询 + 验证
    trade_state,
    verify_trade,
    # 异常
    TradeRejected,
    TradeConflict,
    # reject reasons
    REJECT_TRADE_NOT_FOUND,
    REJECT_TRADE_EXISTS,
    REJECT_ILLEGAL_TRANSITION,
    REJECT_WRONG_ACTOR,
    REJECT_BAD_VERDICT,
    REJECT_EVENT_SIG_INVALID,
    REJECT_CHAIN_BROKEN,
)

__all__ = [
    "STATE_EXECUTING",
    "STATE_DELIVERED",
    "STATE_VERIFIED",
    "STATE_FAILED",
    "STATE_SETTLED",
    "TERMINAL_STATES",
    "EVENT_TRADE_OPENED",
    "EVENT_DELIVERY_SUBMITTED",
    "EVENT_VERIFICATION_RECORDED",
    "EVENT_SETTLEMENT_RECORDED",
    "VERDICT_PASS",
    "VERDICT_FAIL",
    "TradeEvent",
    "TradeStore",
    "sign_trade_event",
    "verify_trade_event",
    "open_trade",
    "submit_delivery",
    "record_verification",
    "record_settlement",
    "trade_state",
    "verify_trade",
    "TradeRejected",
    "TradeConflict",
    "REJECT_TRADE_NOT_FOUND",
    "REJECT_TRADE_EXISTS",
    "REJECT_ILLEGAL_TRANSITION",
    "REJECT_WRONG_ACTOR",
    "REJECT_BAD_VERDICT",
    "REJECT_EVENT_SIG_INVALID",
    "REJECT_CHAIN_BROKEN",
]
