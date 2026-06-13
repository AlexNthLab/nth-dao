"""Commerce CS4 —— 结算 adapter（manual + x402 testnet 真钱）。

CS1-CS3 里 ``settlement`` 是一个**自由字典**，调用方手搓
``{"adapter_id": "manual", "amount_minor": 10}`` 直接喂给
``record_settlement`` / ``resolve_dispute``。能跑，但有两个缺口：

  1. 没有"按约定金额真去付钱"的执行路径 —— manual 是一句话记录。
  2. 没有"这条 settlement 配不配得上这笔 trade"的校验 —— 一个
     settler 可以签一条 ``amount_minor=1`` 的结算，把该付 1000 的活
     白嫖了，verify_trade 也发现不了（它只验链/签名，不验金额）。

CS4 把 settlement 形式化成 **adapter**：

  SettlementIntent（该付多少、付给谁）
        │  adapter.settle(intent)
        ▼
  SettlementResult ──.to_payload()──► 嵌进签名事件的 settlement dict
        │
        ▼
  verify_settlement(settlement, 期望金额/币种/收款方)  ← 闭合缺口 2

为什么这样建（中out）：
  - 中：``SettlementAdapter`` ABC + ``SettlementResult``。和 verifier/
    binding 同构（产出可独立校验的结构化记录）。
  - 上：``settlement_payload`` / ``settle_trade`` 把 adapter 接到既有
    record_settlement / resolve_dispute 上，**不改它们的签名**（CS1-CS3
    既有调用零破坏）。
  - 下：``PaymentRail`` 协议 + ``FakePaymentRail``（确定性、无真钱）。

⚠️ 真钱边界（重要）：x402 testnet 也是在动链上资产。本模块**只实现
协议/结构/校验**，真正的签名+广播交给注入进来的 ``PaymentRail`` ——
``X402SettlementAdapter`` 不持有私钥、不直接广播。带私钥的真实 rail
由运维方自行接（见 PaymentRail 协议）。测试一律走 FakePaymentRail。

设计见桌面 ``A2A交易演进路线图-2026-06-12-重锚定当前代码.md``。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Protocol, Tuple, runtime_checkable

from nth_dao.execution_receipt import now_ms

# ── adapter id ──
ADAPTER_MANUAL = "manual"
ADAPTER_X402_TESTNET = "x402-testnet"
KNOWN_ADAPTERS = frozenset({ADAPTER_MANUAL, ADAPTER_X402_TESTNET})

# ── 支持的币种（minor units，整数）──
#   USDC: 6 位小数，amount_minor 以 1e-6 USDC 计（x402 真钱）。
#   NTH-TEST: 内部测试记账单位（manual 用）。
#   credit: 市场层默认计价单位（announcement.reward_asset 默认值）——
#     收录进来，让有偿"credit"任务可经 manual adapter 内部结算；否则
#     binding 要求 terms.currency==reward_asset 后，credit 任务无币可结。
SUPPORTED_CURRENCIES = frozenset({"USDC", "NTH-TEST", "credit"})

# ── reject reasons ──
REJECT_UNKNOWN_ADAPTER = "settlement-unknown-adapter"
REJECT_AMOUNT_INVALID = "settlement-amount-invalid"
REJECT_AMOUNT_MISMATCH = "settlement-amount-mismatch"
REJECT_CURRENCY_UNSUPPORTED = "settlement-currency-unsupported"
REJECT_CURRENCY_MISMATCH = "settlement-currency-mismatch"
REJECT_PAYEE_MISMATCH = "settlement-payee-mismatch"
REJECT_PAYER_MISMATCH = "settlement-payer-mismatch"
REJECT_TX_REF_MISSING = "settlement-tx-ref-missing"
REJECT_NETWORK_MISSING = "settlement-network-missing"
REJECT_PROOF_MISSING = "settlement-proof-missing"
REJECT_TRADE_MISMATCH = "settlement-trade-mismatch"
REJECT_TRADE_NOT_FOUND = "settlement-trade-not-found"
REJECT_BAD_STATE = "settlement-bad-state"
REJECT_WRONG_SETTLER = "settlement-wrong-settler"


class SettlementFailed(Exception):
    """adapter 结算失败（rail 拒绝 / 配置缺失 / 入参非法）。"""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


# ── 类型安全强转（不信任外部 settlement 字段；bool 不算 int）──


def _safe_int(value: Any) -> Optional[int]:
    """非 bool 的整数才接受（Python bool 是 int 子类，必须排除）。"""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


def _safe_str(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _positive_amount(value: Any) -> Optional[int]:
    """正整数金额才接受（>0、非 bool）。"""
    iv = _safe_int(value)
    if iv is None or iv <= 0:
        return None
    return iv


# ── 意图 + 结果 ──


@dataclass
class SettlementIntent:
    """该付什么（由 trade 约定的条款驱动，不由 settlement 自身决定）。

    amount_minor：minor units 正整数（如 USDC 以 1e-6 计）。
    """

    trade_id: str
    amount_minor: int
    currency: str
    payee_did: str
    payer_did: str = ""
    memo: str = ""

    def validate(self) -> None:
        if _positive_amount(self.amount_minor) is None:
            raise SettlementFailed(
                REJECT_AMOUNT_INVALID,
                f"amount_minor 必须正整数，实际 {self.amount_minor!r}",
            )
        if self.currency not in SUPPORTED_CURRENCIES:
            raise SettlementFailed(
                REJECT_CURRENCY_UNSUPPORTED,
                f"currency={self.currency!r}，支持 {sorted(SUPPORTED_CURRENCIES)}",
            )
        if not self.payee_did:
            raise SettlementFailed(
                REJECT_PAYEE_MISMATCH, "payee_did 为空"
            )


@dataclass
class SettlementResult:
    """adapter 产出 —— 即将嵌进签名事件的 settlement dict 的结构化形态。"""

    adapter_id: str
    amount_minor: int
    currency: str
    payee_did: str
    payer_did: str = ""
    tx_ref: str = ""          # 链上/外部交易引用（manual 为空）
    network: str = ""         # 如 "base-sepolia"（manual 为空）
    proof: Dict[str, Any] = field(default_factory=dict)
    settled_at_ms: int = 0

    def to_payload(self) -> Dict[str, Any]:
        """嵌进 ``record_settlement(settlement=...)`` 的字典。"""
        return {
            "adapter_id": self.adapter_id,
            "amount_minor": self.amount_minor,
            "currency": self.currency,
            "payee_did": self.payee_did,
            "payer_did": self.payer_did,
            "tx_ref": self.tx_ref,
            "network": self.network,
            "proof": dict(self.proof),
            "settled_at_ms": self.settled_at_ms,
        }


# ── 支付通道（rail）──


@dataclass
class RailReceipt:
    """rail 付款回执。tx_ref 是链上/外部交易引用；proof 是 rail 特定证据。"""

    tx_ref: str
    proof: Dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class PaymentRail(Protocol):
    """付款通道协议。真实实现持有私钥、签名并广播交易 —— 那部分由
    运维方接入，**本模块不提供带私钥的实现**。adapter 只调 ``pay`` 拿
    回执，不碰密钥。"""

    rail_id: str
    network: str

    def pay(
        self,
        *,
        payee_did: str,
        amount_minor: int,
        currency: str,
        memo: str,
    ) -> RailReceipt:
        ...


class FakePaymentRail:
    """确定性假 rail（测试用，无真钱、无密钥、无广播）。

    tx_ref 由入参确定性派生，便于断言。``fail`` 模式模拟 rail 拒绝。
    记录每次调用到 ``calls`` 供测试核对（金额/收款方传对了没）。
    """

    rail_id = "fake"
    network = "fake-net"

    def __init__(self, *, fail: bool = False) -> None:
        self._fail = fail
        self.calls: list[Dict[str, Any]] = []

    def pay(
        self,
        *,
        payee_did: str,
        amount_minor: int,
        currency: str,
        memo: str,
    ) -> RailReceipt:
        self.calls.append({
            "payee_did": payee_did,
            "amount_minor": amount_minor,
            "currency": currency,
            "memo": memo,
        })
        if self._fail:
            raise SettlementFailed("rail-declined", "FakePaymentRail fail 模式")
        import hashlib
        h = hashlib.sha256(
            f"{payee_did}|{amount_minor}|{currency}|{memo}".encode("utf-8")
        ).hexdigest()[:16]
        return RailReceipt(
            tx_ref=f"fake:{h}",
            proof={"facilitator": "fake", "settled": True},
        )


# ── adapter ──


class SettlementAdapter(Protocol):
    """结算 adapter 协议：按意图付款，产出可独立校验的结果。"""

    adapter_id: str

    def settle(self, intent: SettlementIntent) -> SettlementResult:
        ...


class ManualSettlementAdapter:
    """无真钱：把意图原样记成签名 settlement（adapter_id="manual"）。

    形式化 CS1-CS3 的手搓 manual 字典 —— 产出多带几个字段（tx_ref=""、
    network=""），但 record_settlement 吃自由字典，向后兼容。
    """

    adapter_id = ADAPTER_MANUAL

    def settle(self, intent: SettlementIntent) -> SettlementResult:
        intent.validate()
        return SettlementResult(
            adapter_id=ADAPTER_MANUAL,
            amount_minor=intent.amount_minor,
            currency=intent.currency,
            payee_did=intent.payee_did,
            payer_did=intent.payer_did,
            tx_ref="",
            network="",
            proof={},
            settled_at_ms=now_ms(),
        )


class X402SettlementAdapter:
    """x402 真钱结算：把意图交给注入的 ``PaymentRail`` 付，拿回执签结果。

    本类**不持私钥、不广播** —— 真正动资产的是 rail。rail 返回的 tx_ref
    必须非空，否则视为"声称付了但没链上引用"= 假钱，拒绝。
    """

    adapter_id = ADAPTER_X402_TESTNET

    def __init__(self, rail: PaymentRail) -> None:
        self._rail = rail

    def settle(self, intent: SettlementIntent) -> SettlementResult:
        intent.validate()
        receipt = self._rail.pay(
            payee_did=intent.payee_did,
            amount_minor=intent.amount_minor,
            currency=intent.currency,
            memo=intent.memo,
        )
        tx_ref = _safe_str(receipt.tx_ref)
        if not tx_ref:
            # rail 没给链上引用 —— 不能凭一句"付了"就记结算。
            raise SettlementFailed(
                REJECT_TX_REF_MISSING,
                "rail 未返回 tx_ref；拒绝记录无凭据的真钱结算",
            )
        network = _safe_str(getattr(self._rail, "network", "")) or ""
        if not network:
            raise SettlementFailed(
                REJECT_NETWORK_MISSING, "rail 未声明 network"
            )
        return SettlementResult(
            adapter_id=ADAPTER_X402_TESTNET,
            amount_minor=intent.amount_minor,
            currency=intent.currency,
            payee_did=intent.payee_did,
            payer_did=intent.payer_did,
            tx_ref=tx_ref,
            network=network,
            proof=dict(receipt.proof) if isinstance(receipt.proof, dict) else {},
            settled_at_ms=now_ms(),
        )


def settlement_payload(
    adapter: SettlementAdapter, intent: SettlementIntent
) -> Dict[str, Any]:
    """跑 adapter 并返回可直接喂给 record_settlement/resolve_dispute 的
    settlement dict。"""
    return adapter.settle(intent).to_payload()


def settle_trade(
    store: Any,
    trade_id: str,
    *,
    settler: Any,
    adapter: SettlementAdapter,
    intent: SettlementIntent,
    now_ms_override: int = 0,
) -> Any:
    """闭环便捷函数：跑 adapter 付款 → 把结果记成签名结算事件
    （VERIFIED → SETTLED）。

    把 CS4 的 adapter 接到 CS1 的 ``record_settlement`` 上，不改后者签名。

    付款前预检（防双付）：x402 的 ``adapter.settle`` 会真的广播交易，所以
    必须在付款**之前**确认 trade 能接受这笔结算 —— 否则若 record_settlement
    因状态/角色被拒，钱已付出去却没记事件，重试就双付了。预检：
      - intent.trade_id 与目标一致（防把 A 单付款记到 B 单）；
      - trade 存在且处于 VERIFIED（唯一能直接结算的前置态）；
      - settler 是 open 时绑定的结算方。
    预检通过后才付款。残留 TOCTOU（预检与落账之间另有写入）由
    record_settlement 的原子状态守卫兜底：那种情况下第二个写入会被拒，
    但钱可能已付 —— 真钱生产应上两阶段提交（CS4 testnet 范围内以预检
    覆盖常见 foot-gun 为度）。
    """
    # 延迟 import 避免与 __init__ 的导入次序耦合（trade 不依赖本模块）。
    from nth_dao.commerce.trade import (
        record_settlement, trade_state, _parties, STATE_VERIFIED,
    )

    if intent.trade_id != trade_id:
        raise SettlementFailed(
            REJECT_TRADE_MISMATCH,
            f"intent.trade_id={intent.trade_id!r} != trade_id={trade_id!r}",
        )
    events = store.get_events(trade_id)
    if not events:
        raise SettlementFailed(REJECT_TRADE_NOT_FOUND, trade_id)
    state = trade_state(store, trade_id)
    if state != STATE_VERIFIED:
        raise SettlementFailed(
            REJECT_BAD_STATE,
            f"trade 须在 {STATE_VERIFIED!r} 才能结算，实际 {state!r}（付款前置守卫）",
        )
    parties = _parties(events)
    if settler.as_did() != parties.get("settler_did"):
        raise SettlementFailed(
            REJECT_WRONG_SETTLER,
            f"settler {settler.as_did()!r} 非绑定结算方 "
            f"{parties.get('settler_did')!r}",
        )

    # 预检通过 → 付款（adapter 可能广播）→ 落账。
    payload = adapter.settle(intent).to_payload()
    return record_settlement(
        store, trade_id, settler=settler, settlement=payload,
        now_ms_override=now_ms_override,
    )


# ── 校验：这条 settlement 配不配得上 trade 的约定 ──


def verify_settlement(
    settlement: Dict[str, Any],
    *,
    expected_amount_minor: int,
    expected_currency: str,
    expected_payee_did: str,
    expected_payer_did: str = "",
) -> Tuple[bool, str]:
    """校验一条 settlement dict 是否匹配 trade 的约定条款。

    关键：**期望值来自 trade 的约定**（announcement reward / claim），
    不来自 settlement 自身 —— 不信任攻击者可控字段。一个 settler 把
    amount_minor 写成 1 想白嫖 1000 的活，这里挡下（amount-mismatch）。

    所有字段做类型安全强转（bool 不算 int，缺字段不崩）。
    """
    adapter_id = _safe_str(settlement.get("adapter_id"))
    if adapter_id not in KNOWN_ADAPTERS:
        return False, REJECT_UNKNOWN_ADAPTER

    amount = _positive_amount(settlement.get("amount_minor"))
    if amount is None:
        return False, REJECT_AMOUNT_INVALID
    if amount != expected_amount_minor:
        return False, REJECT_AMOUNT_MISMATCH

    currency = _safe_str(settlement.get("currency"))
    if currency not in SUPPORTED_CURRENCIES:
        return False, REJECT_CURRENCY_UNSUPPORTED
    if currency != expected_currency:
        return False, REJECT_CURRENCY_MISMATCH

    payee = _safe_str(settlement.get("payee_did"))
    if payee != expected_payee_did:
        return False, REJECT_PAYEE_MISMATCH

    if expected_payer_did:
        payer = _safe_str(settlement.get("payer_did"))
        if payer != expected_payer_did:
            return False, REJECT_PAYER_MISMATCH

    # 真钱 adapter 必须带链上凭据：tx_ref + network + proof。
    if adapter_id == ADAPTER_X402_TESTNET:
        if not _safe_str(settlement.get("tx_ref")):
            return False, REJECT_TX_REF_MISSING
        if not _safe_str(settlement.get("network")):
            return False, REJECT_NETWORK_MISSING
        proof = settlement.get("proof")
        if not isinstance(proof, dict) or not proof:
            return False, REJECT_PROOF_MISSING

    return True, "ok"
