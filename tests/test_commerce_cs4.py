"""CS4 测试 —— 结算 adapter（manual + x402 testnet）+ 结算校验。

退出门槛（CS4）：
  - manual 与 x402 两种 adapter 都能把"按约定付款"产出成可嵌进签名
    事件的结算记录；
  - x402 adapter 不持私钥、把付款委托给注入的 PaymentRail；rail 失败
    时不留半条结算；rail 不给 tx_ref 时拒绝记录"无凭据真钱"；
  - settle_trade 闭环：adapter 付款 → record_settlement → SETTLED，整链
    仍可 verify_trade；
  - verify_settlement 用 **trade 约定的金额/币种/收款方** 校验，挡下
    settler 改小金额白嫖（amount-mismatch）等攻击。
"""

from __future__ import annotations

import pytest

from nth_dao.identity import AgentIdentity
from nth_dao.commerce import (
    TradeStore,
    open_trade,
    submit_delivery,
    record_verification,
    trade_state,
    verify_trade,
    STATE_VERIFIED,
    STATE_SETTLED,
    VERDICT_PASS,
    # CS4
    SettlementIntent,
    ManualSettlementAdapter,
    X402SettlementAdapter,
    FakePaymentRail,
    SettlementFailed,
    settle_trade,
    settlement_payload,
    verify_settlement,
    ADAPTER_MANUAL,
    ADAPTER_X402_TESTNET,
    REJECT_AMOUNT_MISMATCH,
    REJECT_AMOUNT_INVALID,
    REJECT_CURRENCY_MISMATCH,
    REJECT_PAYEE_MISMATCH,
    REJECT_UNKNOWN_ADAPTER,
    REJECT_TX_REF_MISSING,
    REJECT_NETWORK_MISSING,
    REJECT_PROOF_MISSING,
)

pytest.importorskip("nacl")


def _claim(ann_id, claimant, publisher):
    return {
        "announcement_id": ann_id,
        "claimant_did": claimant.as_did(),
        "publisher_did": publisher.as_did(),
        "receipt_id": "rcpt-" + ann_id,
    }


def _to_verified(store, ann_id, *, claimant, publisher, verifier, settler):
    """把一笔 trade 推到 VERIFIED（结算前置态）。"""
    open_trade(store, authority=publisher, claim_record=_claim(ann_id, claimant, publisher),
               verifier_did=verifier.as_did(), settler_did=settler.as_did())
    submit_delivery(store, ann_id, claimant=claimant,
                    delivery={"artifact_sha256": "abc", "execution_receipt_id": "x"})
    record_verification(store, ann_id, verifier=verifier, verdict=VERDICT_PASS,
                        result={"checks": "ok"})
    assert trade_state(store, ann_id) == STATE_VERIFIED


# ─── manual adapter ──────────────────────────────────────────────


def test_manual_adapter_settle_trade_to_settled(tmp_path) -> None:
    """manual adapter 经 settle_trade 闭环到 SETTLED，整链可验。"""
    store = TradeStore(tmp_path)
    pub = AgentIdentity.generate(label="pub")
    claimant = AgentIdentity.generate(label="worker")
    verifier = AgentIdentity.generate(label="ver")
    settler = AgentIdentity.generate(label="settler")
    _to_verified(store, "ann-1", claimant=claimant, publisher=pub,
                 verifier=verifier, settler=settler)

    intent = SettlementIntent(trade_id="ann-1", amount_minor=10,
                              currency="NTH-TEST", payee_did=claimant.as_did(),
                              payer_did=pub.as_did())
    settle_trade(store, "ann-1", settler=settler,
                 adapter=ManualSettlementAdapter(), intent=intent)
    assert trade_state(store, "ann-1") == STATE_SETTLED
    ok, reason = verify_trade(store, "ann-1")
    assert ok, reason


# ─── x402 adapter（注入 FakePaymentRail，无真钱）─────────────────


def test_x402_adapter_pays_via_rail_and_settles(tmp_path) -> None:
    """x402 adapter 把付款委托给 rail，结果带 tx_ref/network/proof，
    且 rail 收到的金额/收款方正确。"""
    store = TradeStore(tmp_path)
    pub = AgentIdentity.generate(label="pub")
    claimant = AgentIdentity.generate(label="worker")
    verifier = AgentIdentity.generate(label="ver")
    settler = AgentIdentity.generate(label="settler")
    _to_verified(store, "ann-2", claimant=claimant, publisher=pub,
                 verifier=verifier, settler=settler)

    rail = FakePaymentRail()
    intent = SettlementIntent(trade_id="ann-2", amount_minor=1_000_000,
                              currency="USDC", payee_did=claimant.as_did(),
                              payer_did=pub.as_did(), memo="ann-2")
    settle_trade(store, "ann-2", settler=settler,
                 adapter=X402SettlementAdapter(rail), intent=intent)

    assert trade_state(store, "ann-2") == STATE_SETTLED
    # rail 收到正确金额 + 收款方（adapter 没篡改意图）
    assert rail.calls == [{
        "payee_did": claimant.as_did(), "amount_minor": 1_000_000,
        "currency": "USDC", "memo": "ann-2",
    }]
    # 结算事件里带链上凭据
    events = store.get_events("ann-2")
    settle_ev = events[-1]
    s = settle_ev["payload"]["settlement"]
    assert s["adapter_id"] == ADAPTER_X402_TESTNET
    assert s["tx_ref"].startswith("fake:")
    assert s["network"] == "fake-net"
    assert s["proof"]["settled"] is True
    ok, reason = verify_trade(store, "ann-2")
    assert ok, reason


def test_x402_rail_failure_leaves_no_settlement(tmp_path) -> None:
    """rail 拒付 → SettlementFailed 上抛，trade 停在 VERIFIED（不留半条）。"""
    store = TradeStore(tmp_path)
    pub = AgentIdentity.generate(label="pub")
    claimant = AgentIdentity.generate(label="worker")
    verifier = AgentIdentity.generate(label="ver")
    settler = AgentIdentity.generate(label="settler")
    _to_verified(store, "ann-3", claimant=claimant, publisher=pub,
                 verifier=verifier, settler=settler)

    rail = FakePaymentRail(fail=True)
    intent = SettlementIntent(trade_id="ann-3", amount_minor=5,
                              currency="USDC", payee_did=claimant.as_did())
    with pytest.raises(SettlementFailed):
        settle_trade(store, "ann-3", settler=settler,
                     adapter=X402SettlementAdapter(rail), intent=intent)
    assert trade_state(store, "ann-3") == STATE_VERIFIED  # 未推进


def test_x402_empty_tx_ref_rejected(tmp_path) -> None:
    """rail 返回空 tx_ref（声称付了但无链上引用）→ 拒绝记录假钱。"""
    class _NoRefRail:
        rail_id = "noref"
        network = "base-sepolia"

        def pay(self, **_):
            from nth_dao.commerce import RailReceipt
            return RailReceipt(tx_ref="", proof={"x": 1})

    intent = SettlementIntent(trade_id="t", amount_minor=5,
                              currency="USDC", payee_did="did:key:zPayee")
    with pytest.raises(SettlementFailed) as ei:
        X402SettlementAdapter(_NoRefRail()).settle(intent)
    assert ei.value.reason == REJECT_TX_REF_MISSING


def test_settle_trade_rejects_trade_id_mismatch(tmp_path) -> None:
    """intent.trade_id 与目标 trade_id 不符 → 拒（防把 A 单付款记到 B 单）。"""
    store = TradeStore(tmp_path)
    settler = AgentIdentity.generate(label="settler")
    intent = SettlementIntent(trade_id="OTHER", amount_minor=5,
                              currency="USDC", payee_did="did:key:zPayee")
    with pytest.raises(SettlementFailed):
        settle_trade(store, "ann-X", settler=settler,
                     adapter=ManualSettlementAdapter(), intent=intent)


# ─── verify_settlement：用约定条款挡攻击 ─────────────────────────


def _good_x402_settlement():
    rail = FakePaymentRail()
    intent = SettlementIntent(trade_id="t", amount_minor=1000,
                              currency="USDC", payee_did="did:key:zPayee",
                              payer_did="did:key:zPayer")
    return settlement_payload(X402SettlementAdapter(rail), intent)


def test_verify_settlement_happy(tmp_path) -> None:
    s = _good_x402_settlement()
    ok, reason = verify_settlement(
        s, expected_amount_minor=1000, expected_currency="USDC",
        expected_payee_did="did:key:zPayee", expected_payer_did="did:key:zPayer")
    assert ok, reason


def test_verify_settlement_amount_mismatch_blocks_freeride(tmp_path) -> None:
    """settler 把金额改小想白嫖 → amount-mismatch 挡下。"""
    s = _good_x402_settlement()
    s["amount_minor"] = 1  # 篡改：该付 1000 只记 1
    ok, reason = verify_settlement(
        s, expected_amount_minor=1000, expected_currency="USDC",
        expected_payee_did="did:key:zPayee")
    assert not ok and reason == REJECT_AMOUNT_MISMATCH


def test_verify_settlement_bool_amount_rejected(tmp_path) -> None:
    """amount_minor=True 不能当 1 用（bool 不算 int）。"""
    s = _good_x402_settlement()
    s["amount_minor"] = True
    ok, reason = verify_settlement(
        s, expected_amount_minor=1, expected_currency="USDC",
        expected_payee_did="did:key:zPayee")
    assert not ok and reason == REJECT_AMOUNT_INVALID


def test_verify_settlement_currency_and_payee_and_adapter(tmp_path) -> None:
    base = _good_x402_settlement()

    s = dict(base); s["currency"] = "NTH-TEST"
    ok, reason = verify_settlement(
        s, expected_amount_minor=1000, expected_currency="USDC",
        expected_payee_did="did:key:zPayee")
    assert not ok and reason == REJECT_CURRENCY_MISMATCH

    s = dict(base); s["payee_did"] = "did:key:zAttacker"
    ok, reason = verify_settlement(
        s, expected_amount_minor=1000, expected_currency="USDC",
        expected_payee_did="did:key:zPayee")
    assert not ok and reason == REJECT_PAYEE_MISMATCH

    s = dict(base); s["adapter_id"] = "bribe"
    ok, reason = verify_settlement(
        s, expected_amount_minor=1000, expected_currency="USDC",
        expected_payee_did="did:key:zPayee")
    assert not ok and reason == REJECT_UNKNOWN_ADAPTER


def test_verify_settlement_x402_requires_onchain_proof(tmp_path) -> None:
    """x402 必须带 tx_ref + network + 非空 proof，缺一不可。"""
    base = _good_x402_settlement()

    s = dict(base); s["tx_ref"] = ""
    ok, reason = verify_settlement(
        s, expected_amount_minor=1000, expected_currency="USDC",
        expected_payee_did="did:key:zPayee")
    assert not ok and reason == REJECT_TX_REF_MISSING

    s = dict(base); s["network"] = ""
    ok, reason = verify_settlement(
        s, expected_amount_minor=1000, expected_currency="USDC",
        expected_payee_did="did:key:zPayee")
    assert not ok and reason == REJECT_NETWORK_MISSING

    s = dict(base); s["proof"] = {}
    ok, reason = verify_settlement(
        s, expected_amount_minor=1000, expected_currency="USDC",
        expected_payee_did="did:key:zPayee")
    assert not ok and reason == REJECT_PROOF_MISSING


def test_verify_settlement_payer_mismatch(tmp_path) -> None:
    """给了期望 payer 时，payer 不符也挡（payer-mismatch）。"""
    from nth_dao.commerce import REJECT_PAYER_MISMATCH
    s = _good_x402_settlement()
    ok, reason = verify_settlement(
        s, expected_amount_minor=1000, expected_currency="USDC",
        expected_payee_did="did:key:zPayee",
        expected_payer_did="did:key:zSomeoneElse")
    assert not ok and reason == REJECT_PAYER_MISMATCH


# ─── 审查修复 A：terms 让 verify_trade 自动核对结算金额 ──────────


def test_terms_make_verify_trade_catch_freeride(tmp_path) -> None:
    """开局签 terms(1000) 后，settler 记一条 amount=1 的结算想白嫖 ——
    record_settlement 仍会写入（它不验金额），但 verify_trade 自动用
    terms 核对，挡下（amount-mismatch）。这才真正闭合缺口。"""
    from nth_dao.commerce import record_settlement
    store = TradeStore(tmp_path)
    pub = AgentIdentity.generate(label="pub")
    claimant = AgentIdentity.generate(label="worker")
    verifier = AgentIdentity.generate(label="ver")
    settler = AgentIdentity.generate(label="settler")
    open_trade(store, authority=pub,
               claim_record=_claim("ann-t", claimant, pub),
               verifier_did=verifier.as_did(), settler_did=settler.as_did(),
               terms={"amount_minor": 1000, "currency": "USDC"})
    submit_delivery(store, "ann-t", claimant=claimant,
                    delivery={"artifact_sha256": "a", "execution_receipt_id": "x"})
    record_verification(store, "ann-t", verifier=verifier, verdict=VERDICT_PASS,
                        result={"ok": 1})
    # settler 手搓一条改小金额的结算（绕过 settle_trade 的 adapter）
    record_settlement(store, "ann-t", settler=settler, settlement={
        "adapter_id": ADAPTER_X402_TESTNET, "amount_minor": 1,
        "currency": "USDC", "payee_did": claimant.as_did(),
        "tx_ref": "fake:deadbeef", "network": "base-sepolia",
        "proof": {"settled": True},
    })
    assert trade_state(store, "ann-t") == STATE_SETTLED
    ok, reason = verify_trade(store, "ann-t")
    assert not ok and reason == REJECT_AMOUNT_MISMATCH


def test_terms_honest_settlement_passes_verify_trade(tmp_path) -> None:
    """开局签 terms 后，诚实按约定金额经 settle_trade 结算，verify_trade 过。"""
    store = TradeStore(tmp_path)
    pub = AgentIdentity.generate(label="pub")
    claimant = AgentIdentity.generate(label="worker")
    verifier = AgentIdentity.generate(label="ver")
    settler = AgentIdentity.generate(label="settler")
    open_trade(store, authority=pub,
               claim_record=_claim("ann-h", claimant, pub),
               verifier_did=verifier.as_did(), settler_did=settler.as_did(),
               terms={"amount_minor": 1000, "currency": "USDC"})
    submit_delivery(store, "ann-h", claimant=claimant,
                    delivery={"artifact_sha256": "a", "execution_receipt_id": "x"})
    record_verification(store, "ann-h", verifier=verifier, verdict=VERDICT_PASS,
                        result={"ok": 1})
    intent = SettlementIntent(trade_id="ann-h", amount_minor=1000,
                              currency="USDC", payee_did=claimant.as_did())
    settle_trade(store, "ann-h", settler=settler,
                 adapter=X402SettlementAdapter(FakePaymentRail()), intent=intent)
    ok, reason = verify_trade(store, "ann-h")
    assert ok, reason


# ─── 审查修复 B：settle_trade 付款前预检（防双付）──────────────


def test_settle_trade_rejects_before_paying_when_not_verified(tmp_path) -> None:
    """trade 不在 VERIFIED 时，settle_trade 在**付款前**就拒 —— rail 没被
    调用（无双付风险）。"""
    store = TradeStore(tmp_path)
    pub = AgentIdentity.generate(label="pub")
    claimant = AgentIdentity.generate(label="worker")
    verifier = AgentIdentity.generate(label="ver")
    settler = AgentIdentity.generate(label="settler")
    # 只开到 EXECUTING（未交付未验收）
    open_trade(store, authority=pub,
               claim_record=_claim("ann-b", claimant, pub),
               verifier_did=verifier.as_did(), settler_did=settler.as_did())
    rail = FakePaymentRail()
    intent = SettlementIntent(trade_id="ann-b", amount_minor=5,
                              currency="USDC", payee_did=claimant.as_did())
    with pytest.raises(SettlementFailed):
        settle_trade(store, "ann-b", settler=settler,
                     adapter=X402SettlementAdapter(rail), intent=intent)
    assert rail.calls == []  # 关键：付款前就拦下，rail 未被调


def test_settle_trade_rejects_wrong_settler_before_paying(tmp_path) -> None:
    """非绑定 settler 调 settle_trade → 付款前拒，rail 未被调。"""
    store = TradeStore(tmp_path)
    pub = AgentIdentity.generate(label="pub")
    claimant = AgentIdentity.generate(label="worker")
    verifier = AgentIdentity.generate(label="ver")
    settler = AgentIdentity.generate(label="settler")
    intruder = AgentIdentity.generate(label="intruder")
    _to_verified(store, "ann-w", claimant=claimant, publisher=pub,
                 verifier=verifier, settler=settler)
    rail = FakePaymentRail()
    intent = SettlementIntent(trade_id="ann-w", amount_minor=5,
                              currency="USDC", payee_did=claimant.as_did())
    with pytest.raises(SettlementFailed):
        settle_trade(store, "ann-w", settler=intruder,
                     adapter=X402SettlementAdapter(rail), intent=intent)
    assert rail.calls == []


def test_verify_settlement_manual_needs_no_txref(tmp_path) -> None:
    """manual（无真钱）不要求 tx_ref/network/proof。"""
    intent = SettlementIntent(trade_id="t", amount_minor=10,
                              currency="NTH-TEST", payee_did="did:key:zPayee")
    s = settlement_payload(ManualSettlementAdapter(), intent)
    assert s["adapter_id"] == ADAPTER_MANUAL and s["tx_ref"] == ""
    ok, reason = verify_settlement(
        s, expected_amount_minor=10, expected_currency="NTH-TEST",
        expected_payee_did="did:key:zPayee")
    assert ok, reason
