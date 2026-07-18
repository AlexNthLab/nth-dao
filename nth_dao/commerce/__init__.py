"""Nth DAO commerce —— 交易状态机（claim → 执行 → 交付 → 验收 → 结算）。

主动市场（``nth_dao.market``）负责"谁来干"（discover→match→claim）。
commerce 负责"干得怎样、钱怎么付"（execute→deliver→verify→settle）。
接缝：``open_trade`` 吃一条市场 claim_record 开局。

设计见桌面 ``A2A交易演进路线图-2026-06-12-重锚定当前代码.md``。

里程碑：
  CS1 ✅  签名 trade 状态机（无真钱，manual 结算）
  CS2 ✅  commerce↔market 绑定校验 + DeterministicTestVerifier（首个 SKU）
  CS3 ✅  争议处理（DISPUTED → SETTLED / REFUNDED / SPLIT_SETTLED）
  CS4 ✅  结算 adapter（manual + x402 testnet，PaymentRail 注入）+ 校验
"""

from nth_dao.commerce.trade import (
    # 状态
    STATE_EXECUTING,
    STATE_DELIVERED,
    STATE_VERIFIED,
    STATE_FAILED,
    STATE_SETTLED,
    STATE_DISPUTED,
    STATE_REFUNDED,
    STATE_SPLIT_SETTLED,
    TERMINAL_STATES,
    # 事件类型 / verdict / resolution
    EVENT_TRADE_OPENED,
    EVENT_DELIVERY_SUBMITTED,
    EVENT_VERIFICATION_RECORDED,
    EVENT_SETTLEMENT_RECORDED,
    EVENT_DISPUTE_OPENED,
    EVENT_DISPUTE_RESOLVED,
    VERDICT_PASS,
    VERDICT_FAIL,
    RESOLUTION_SETTLE,
    RESOLUTION_REFUND,
    RESOLUTION_SPLIT,
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
    open_dispute,
    resolve_dispute,
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
    REJECT_BAD_RESOLUTION,
    REJECT_EVENT_SIG_INVALID,
    REJECT_CHAIN_BROKEN,
)

__all__ = [
    "STATE_EXECUTING",
    "STATE_DELIVERED",
    "STATE_VERIFIED",
    "STATE_FAILED",
    "STATE_SETTLED",
    "STATE_DISPUTED",
    "STATE_REFUNDED",
    "STATE_SPLIT_SETTLED",
    "TERMINAL_STATES",
    "EVENT_TRADE_OPENED",
    "EVENT_DELIVERY_SUBMITTED",
    "EVENT_VERIFICATION_RECORDED",
    "EVENT_SETTLEMENT_RECORDED",
    "EVENT_DISPUTE_OPENED",
    "EVENT_DISPUTE_RESOLVED",
    "VERDICT_PASS",
    "VERDICT_FAIL",
    "RESOLUTION_SETTLE",
    "RESOLUTION_REFUND",
    "RESOLUTION_SPLIT",
    "TradeEvent",
    "TradeStore",
    "sign_trade_event",
    "verify_trade_event",
    "open_trade",
    "submit_delivery",
    "record_verification",
    "record_settlement",
    "open_dispute",
    "resolve_dispute",
    "trade_state",
    "verify_trade",
    "TradeRejected",
    "TradeConflict",
    "REJECT_TRADE_NOT_FOUND",
    "REJECT_TRADE_EXISTS",
    "REJECT_ILLEGAL_TRANSITION",
    "REJECT_WRONG_ACTOR",
    "REJECT_BAD_VERDICT",
    "REJECT_BAD_RESOLUTION",
    "REJECT_EVENT_SIG_INVALID",
    "REJECT_CHAIN_BROKEN",
    # CS2a binding
    "verify_trade_binding",
    # CS2b verifier
    "DeterministicTestVerifier",
    "VerificationOutcome",
    "sign_test_execution_receipt",
    "SKU_TEST_EXECUTION",
    # CS4 settlement adapters
    "SettlementIntent",
    "SettlementResult",
    "SettlementAdapter",
    "ManualSettlementAdapter",
    "X402SettlementAdapter",
    "PaymentRail",
    "RailReceipt",
    "FakePaymentRail",
    "SettlementFailed",
    "settlement_payload",
    "settle_trade",
    "verify_settlement",
    "ADAPTER_MANUAL",
    "ADAPTER_X402_TESTNET",
    "KNOWN_ADAPTERS",
    "SUPPORTED_CURRENCIES",
    "REJECT_UNKNOWN_ADAPTER",
    "REJECT_AMOUNT_INVALID",
    "REJECT_AMOUNT_MISMATCH",
    "REJECT_CURRENCY_UNSUPPORTED",
    "REJECT_CURRENCY_MISMATCH",
    "REJECT_PAYEE_MISMATCH",
    "REJECT_PAYER_MISMATCH",
    "REJECT_TX_REF_MISSING",
    "REJECT_NETWORK_MISSING",
    "REJECT_PROOF_MISSING",
]

from nth_dao.commerce.binding import (
    verify_trade_binding,
    REJECT_NO_OPENED,
    REJECT_ANN_ID_MISMATCH,
    REJECT_ANN_SIG_INVALID,
    REJECT_PUBLISHER_MISMATCH,
    REJECT_CLAIM_RECEIPT_INVALID,
    REJECT_CLAIMANT_MISMATCH,
    REJECT_CLAIM_ANN_MISMATCH,
    REJECT_CLAIM_RECEIPT_ID_MISMATCH,
)
from nth_dao.commerce.verifier import (
    DeterministicTestVerifier,
    VerificationOutcome,
    sign_test_execution_receipt,
    SKU_TEST_EXECUTION,
)
from nth_dao.commerce.settlement import (
    SettlementIntent,
    SettlementResult,
    SettlementAdapter,
    ManualSettlementAdapter,
    X402SettlementAdapter,
    PaymentRail,
    RailReceipt,
    FakePaymentRail,
    SettlementFailed,
    settlement_payload,
    settle_trade,
    verify_settlement,
    ADAPTER_MANUAL,
    ADAPTER_X402_TESTNET,
    KNOWN_ADAPTERS,
    SUPPORTED_CURRENCIES,
    REJECT_UNKNOWN_ADAPTER,
    REJECT_AMOUNT_INVALID,
    REJECT_AMOUNT_MISMATCH,
    REJECT_CURRENCY_UNSUPPORTED,
    REJECT_CURRENCY_MISMATCH,
    REJECT_PAYEE_MISMATCH,
    REJECT_PAYER_MISMATCH,
    REJECT_TX_REF_MISSING,
    REJECT_NETWORK_MISSING,
    REJECT_PROOF_MISSING,
)

# Signed commerce catalog and authorised ordering.
from nth_dao.commerce.money import (
    ASSET_DECIMALS,
    MoneyRejected,
    decimal_to_minor,
    minor_to_decimal,
)
from nth_dao.commerce.listing import (
    LISTING_PRODUCT,
    LISTING_SERVICE,
    LISTING_TYPES,
    ListingRejected,
    ListingStore,
    SignedListing,
    listing_digest,
    sign_listing,
    verify_listing,
)
from nth_dao.commerce.listing_announcement import (
    listing_offer_uri,
    publish_listing_announcement,
    verify_listing_announcement_binding,
)
from nth_dao.commerce.order import (
    EVENT_ORDER_CREATED,
    STATE_CREATED,
    OrderConflict,
    OrderEvent,
    OrderRejected,
    OrderStore,
    create_order,
    order_id_for_payment,
    verify_order,
    verify_order_event,
)
from nth_dao.commerce.checkout import CheckoutRejected, create_order_from_mandates
from nth_dao.commerce.order_trade import (
    OrderTradeRejected,
    open_commerce_trade,
    verify_order_trade_binding,
)

__all__ += [
    "verify_trade_binding", "REJECT_NO_OPENED", "REJECT_ANN_ID_MISMATCH",
    "REJECT_ANN_SIG_INVALID", "REJECT_PUBLISHER_MISMATCH",
    "REJECT_CLAIM_RECEIPT_INVALID", "REJECT_CLAIMANT_MISMATCH",
    "REJECT_CLAIM_ANN_MISMATCH", "REJECT_CLAIM_RECEIPT_ID_MISMATCH",
    "ASSET_DECIMALS", "MoneyRejected", "decimal_to_minor", "minor_to_decimal",
    "LISTING_PRODUCT", "LISTING_SERVICE", "LISTING_TYPES", "ListingRejected",
    "ListingStore", "SignedListing", "listing_digest", "sign_listing",
    "verify_listing", "listing_offer_uri", "publish_listing_announcement",
    "verify_listing_announcement_binding",
    "EVENT_ORDER_CREATED", "STATE_CREATED", "OrderConflict",
    "OrderEvent", "OrderRejected", "OrderStore", "create_order",
    "order_id_for_payment", "verify_order", "verify_order_event",
    "CheckoutRejected", "create_order_from_mandates",
    "OrderTradeRejected", "open_commerce_trade", "verify_order_trade_binding",
]
