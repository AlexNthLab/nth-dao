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

from nth_dao.cap_token import sign_cap_token, CAP_NTH_RECEIPT_SIGN
from nth_dao.identity import AgentIdentity
from nth_dao.market import (
    MarketFeed, ClaimStore, claim_announcement, sign_announcement,
)
from nth_dao.commerce import (
    TradeStore,
    open_trade,
    submit_delivery,
    record_verification,
    trade_state,
    verify_trade,
    verify_trade_binding,
    TradeRejected,
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


# ─── 二轮审查修复：terms 必须钉死在签名公告 reward 上 ──────────


def _real_claim(tmp_path, *, reward_minor=1000, reward_asset="USDC"):
    """造一条真实市场链（公告 publisher 签 + 认领 claimant 签）。"""
    feed = MarketFeed(tmp_path)
    cstore = ClaimStore(tmp_path)
    issuer = AgentIdentity.generate(label="issuer")
    publisher = AgentIdentity.generate(label="publisher")
    worker = AgentIdentity.generate(label="worker")
    ann = sign_announcement(
        publisher=publisher, title="do work",
        capability_set=["test_execution"], reward_minor=reward_minor,
        reward_asset=reward_asset,
    )
    feed.publish(ann)
    out = claim_announcement(
        feed, cstore, ann.announcement_id, claimant=worker,
        cap_token=sign_cap_token(issuer=issuer, subject_did=worker.as_did(),
                                 capabilities=["test_execution", CAP_NTH_RECEIPT_SIGN]))
    return {"publisher": publisher, "worker": worker, "ann": ann,
            "claim_record": out.claim_record}


def test_binding_passes_when_terms_match_announcement_reward(tmp_path) -> None:
    s = _real_claim(tmp_path, reward_minor=1000, reward_asset="USDC")
    tstore = TradeStore(tmp_path)
    open_trade(tstore, authority=s["publisher"], claim_record=s["claim_record"],
               terms={"amount_minor": 1000, "currency": "USDC"})
    events = tstore.get_events(s["ann"].announcement_id)
    ok, reason = verify_trade_binding(events, announcement=s["ann"],
                                      claim_record=s["claim_record"])
    assert ok, reason


def test_binding_catches_opener_underpay_terms(tmp_path) -> None:
    """恶意开局方把 terms 压成 1（公告 reward=1000）—— verify_trade 会被
    骗过（terms 自洽），但 verify_trade_binding 把 terms 钉死在签名公告
    reward 上，识破（terms-reward-mismatch）。这才端到端闭合白嫖。"""
    from nth_dao.commerce.binding import REJECT_TERMS_REWARD_MISMATCH
    s = _real_claim(tmp_path, reward_minor=1000, reward_asset="USDC")
    tstore = TradeStore(tmp_path)
    open_trade(tstore, authority=s["publisher"], claim_record=s["claim_record"],
               terms={"amount_minor": 1, "currency": "USDC"})  # 压价
    events = tstore.get_events(s["ann"].announcement_id)
    ok, reason = verify_trade_binding(events, announcement=s["ann"],
                                      claim_record=s["claim_record"])
    assert not ok and reason == REJECT_TERMS_REWARD_MISMATCH


def test_binding_catches_terms_asset_swap(tmp_path) -> None:
    """terms 币种与公告 reward_asset 不符（公告 USDC、terms NTH-TEST）→ 拒。"""
    from nth_dao.commerce.binding import REJECT_TERMS_ASSET_MISMATCH
    s = _real_claim(tmp_path, reward_minor=1000, reward_asset="USDC")
    tstore = TradeStore(tmp_path)
    open_trade(tstore, authority=s["publisher"], claim_record=s["claim_record"],
               terms={"amount_minor": 1000, "currency": "NTH-TEST"})
    events = tstore.get_events(s["ann"].announcement_id)
    ok, reason = verify_trade_binding(events, announcement=s["ann"],
                                      claim_record=s["claim_record"])
    assert not ok and reason == REJECT_TERMS_ASSET_MISMATCH


# ─── 三轮审查修复：payee 绑 claimant / terms 不可选规避 / credit ──


def test_binding_catches_payee_redirect(tmp_path) -> None:
    """开局方把 terms.payee 指到第三方（非 claimant）—— 钱不进 worker
    口袋。verify_trade 只核对 settlement.payee==terms.payee（自洽）会被骗，
    binding 把 payee 钉到真 claimant 上识破（terms-payee-mismatch）。"""
    from nth_dao.commerce.binding import REJECT_TERMS_PAYEE_MISMATCH
    s = _real_claim(tmp_path, reward_minor=1000, reward_asset="USDC")
    attacker = AgentIdentity.generate(label="attacker")
    tstore = TradeStore(tmp_path)
    open_trade(tstore, authority=s["publisher"], claim_record=s["claim_record"],
               terms={"amount_minor": 1000, "currency": "USDC",
                      "payee_did": attacker.as_did()})  # 改收款方
    events = tstore.get_events(s["ann"].announcement_id)
    ok, reason = verify_trade_binding(events, announcement=s["ann"],
                                      claim_record=s["claim_record"])
    assert not ok and reason == REJECT_TERMS_PAYEE_MISMATCH


def test_require_terms_blocks_paid_task_without_terms(tmp_path) -> None:
    """有偿任务不签 terms 想规避金额约束 —— require_terms=True 时硬失败。
    默认（require_terms=False）保留旧 provenance-only 语义不破坏 CS2。"""
    from nth_dao.commerce.binding import REJECT_TERMS_REQUIRED
    s = _real_claim(tmp_path, reward_minor=1000, reward_asset="USDC")
    tstore = TradeStore(tmp_path)
    open_trade(tstore, authority=s["publisher"], claim_record=s["claim_record"])  # 无 terms
    events = tstore.get_events(s["ann"].announcement_id)
    # 默认：仍通过（provenance-only，向后兼容）
    ok, _ = verify_trade_binding(events, announcement=s["ann"],
                                 claim_record=s["claim_record"])
    assert ok
    # 严格：有偿无 terms → 拒
    ok, reason = verify_trade_binding(events, announcement=s["ann"],
                                      claim_record=s["claim_record"],
                                      require_terms=True)
    assert not ok and reason == REJECT_TERMS_REQUIRED


def test_require_terms_allows_free_task_without_terms(tmp_path) -> None:
    """免费任务（reward_minor=0）即便 require_terms=True 也无需 terms。"""
    s = _real_claim(tmp_path, reward_minor=0, reward_asset="credit")
    tstore = TradeStore(tmp_path)
    open_trade(tstore, authority=s["publisher"], claim_record=s["claim_record"])
    events = tstore.get_events(s["ann"].announcement_id)
    ok, reason = verify_trade_binding(events, announcement=s["ann"],
                                      claim_record=s["claim_record"],
                                      require_terms=True)
    assert ok, reason


def test_credit_task_settles_via_manual(tmp_path) -> None:
    """credit 计价任务可经 manual adapter 结算（credit ∈ SUPPORTED）。"""
    intent = SettlementIntent(trade_id="t", amount_minor=10,
                              currency="credit", payee_did="did:key:zPayee")
    s = settlement_payload(ManualSettlementAdapter(), intent)
    ok, reason = verify_settlement(
        s, expected_amount_minor=10, expected_currency="credit",
        expected_payee_did="did:key:zPayee")
    assert ok, reason


def test_open_trade_rejects_malformed_terms(tmp_path) -> None:
    """terms 给了但畸形（空/零/负/bool 金额、空币种）→ 开局当场拒，
    不签进链（防 -1 哨兵静默 brick 这笔 trade）。"""
    store = TradeStore(tmp_path)
    pub = AgentIdentity.generate(label="pub")
    claimant = AgentIdentity.generate(label="worker")
    for bad in ({}, {"amount_minor": 0, "currency": "USDC"},
                {"amount_minor": -5, "currency": "USDC"},
                {"amount_minor": True, "currency": "USDC"},
                {"amount_minor": 10, "currency": ""}):
        with pytest.raises(TradeRejected):
            open_trade(store, authority=pub,
                       claim_record=_claim("ann-bad-" + str(id(bad)), claimant, pub),
                       terms=bad)


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
