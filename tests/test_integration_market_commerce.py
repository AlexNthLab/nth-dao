"""端到端联调 —— market → commerce 整链组合验证。

各模块都有自己的单元测试；本文件验证它们**拼起来**仍成立：一笔活从
公告发布，到认领、开单、交付、确定性验收、x402 结算，再到链自洽校验、
锚定校验、信誉投影，全程一条流水线跑通；并且把"白嫖"等攻击放到整链
里，证明 **verify_trade ∧ verify_trade_binding** 组合才真正闭合（任一单
独都不够）。

覆盖的层：
  M1 公告(sign_announcement)→ M3 认领(claim_announcement)
  CS1 open_trade(带 terms)→ 交付 → CS2b 确定性验收 → CS4 x402 结算
  CS1 verify_trade（链自洽 + terms 核对金额）
  CS2a verify_trade_binding（锚定真公告 + terms==reward + payee==claimant）
  M5 compute_reputation（从签名 claim 记录投影信誉）
"""

from __future__ import annotations

import pytest

from nth_dao.cap_token import sign_cap_token, CAP_NTH_RECEIPT_SIGN
from nth_dao.identity import AgentIdentity
from nth_dao.market import (
    MarketFeed, ClaimStore, claim_announcement, sign_announcement,
    compute_reputation,
)
from nth_dao.commerce import (
    TradeStore, open_trade, submit_delivery, record_verification,
    trade_state, verify_trade, verify_trade_binding,
    DeterministicTestVerifier, sign_test_execution_receipt,
    SettlementIntent, X402SettlementAdapter, FakePaymentRail, settle_trade,
    VERDICT_FAIL, STATE_SETTLED, STATE_FAILED,
)

pytest.importorskip("nacl")

REPO = "https://example.com/r"
COMMIT = "a" * 40
COMMAND = "pytest -q"
REWARD = 1_000_000          # 1 USDC（minor units）
ASSET = "USDC"


def _market_chain(tmp_path):
    """造完整市场链：公告（带 SKU input_schema + USDC reward）→ 认领。"""
    feed = MarketFeed(tmp_path)
    cstore = ClaimStore(tmp_path)
    issuer = AgentIdentity.generate(label="issuer")
    publisher = AgentIdentity.generate(label="publisher")
    worker = AgentIdentity.generate(label="worker")
    ann = sign_announcement(
        publisher=publisher, title="run tests on commit",
        capability_set=["test_execution"], reward_minor=REWARD,
        reward_asset=ASSET,
        input_schema={"repository_url": REPO, "commit": COMMIT,
                      "commands": [COMMAND]},
        acceptance={"accept_exit_codes": [0]},
    )
    feed.publish(ann)
    out = claim_announcement(
        feed, cstore, ann.announcement_id, claimant=worker,
        cap_token=sign_cap_token(issuer=issuer, subject_did=worker.as_did(),
                                 capabilities=["test_execution", CAP_NTH_RECEIPT_SIGN]))
    return {
        "feed": feed, "cstore": cstore, "publisher": publisher,
        "worker": worker, "ann": ann, "claim_record": out.claim_record,
    }


def _drive_to_verified(tstore, s, *, verifier, settler, exit_code=0, terms=None):
    """开单(带 terms) → 交付(带 execution receipt) → 确定性验收 → record。
    返回 (ann_id, outcome)。"""
    ann_id = s["ann"].announcement_id
    open_trade(tstore, authority=s["publisher"], claim_record=s["claim_record"],
               verifier_did=verifier.as_did(), settler_did=settler.as_did(),
               terms=terms)
    exec_receipt = sign_test_execution_receipt(
        s["worker"], repository_url=REPO, commit=COMMIT, command=COMMAND,
        exit_code=exit_code, announcement_id=ann_id)
    submit_delivery(tstore, ann_id, claimant=s["worker"],
                    delivery={"execution_receipt": exec_receipt})
    outcome = DeterministicTestVerifier().verify(
        announcement=s["ann"], execution_receipt=exec_receipt,
        expected_signer_did=s["worker"].as_did())
    record_verification(tstore, ann_id, verifier=verifier,
                        verdict=outcome.verdict, result=outcome.checks)
    return ann_id, outcome


# ─── happy path：整链跑通 ───────────────────────────────────────


def test_full_chain_market_to_x402_settled_with_reputation(tmp_path) -> None:
    """一笔活全程：公告 → 认领 → 开单(terms=reward) → 交付 → 验收(pass)
    → x402 结算 → 链自洽 ∧ 锚定(strict) 双过 → worker 信誉 +1。"""
    s = _market_chain(tmp_path)
    tstore = TradeStore(tmp_path)
    verifier = AgentIdentity.generate(label="verifier")
    settler = AgentIdentity.generate(label="settler")

    ann_id, outcome = _drive_to_verified(
        tstore, s, verifier=verifier, settler=settler,
        terms={"amount_minor": REWARD, "currency": ASSET})
    assert outcome.passed

    # CS4：x402 经 FakePaymentRail 结算（无真钱，确定性）
    rail = FakePaymentRail()
    settle_trade(
        tstore, ann_id, settler=settler,
        adapter=X402SettlementAdapter(rail),
        intent=SettlementIntent(trade_id=ann_id, amount_minor=REWARD,
                                currency=ASSET, payee_did=s["worker"].as_did(),
                                payer_did=s["publisher"].as_did(), memo=ann_id))
    assert trade_state(tstore, ann_id) == STATE_SETTLED
    # rail 收到正确金额 + 收款方（worker）
    assert rail.calls == [{
        "payee_did": s["worker"].as_did(), "amount_minor": REWARD,
        "currency": ASSET, "memo": ann_id,
    }]

    # CS1 链自洽（含 terms 自动核对结算金额）
    ok, reason = verify_trade(tstore, ann_id)
    assert ok, reason
    # CS2a + 三轮加固：锚定真公告 + terms==reward + payee==claimant，且严格
    # 要求有偿任务必须带 terms
    ok, reason = verify_trade_binding(
        tstore.get_events(ann_id), announcement=s["ann"],
        claim_record=s["claim_record"], require_terms=True)
    assert ok, reason

    # M5 信誉：worker 这笔认领计入（签名可验）
    prof = compute_reputation(s["worker"].as_did(), s["cstore"].all_records())
    assert prof.claims_count == 1
    assert prof.distinct_publishers == 1
    assert prof.total_reward_minor == REWARD


# ─── 整链负路径：验收失败不结算 ─────────────────────────────────


def test_full_chain_failing_verification_blocks_settlement(tmp_path) -> None:
    """测试不过 → verdict=fail → 状态 FAILED → settle 在付款前被拒，
    rail 从未被调（无真钱外流）。信誉仍记这次认领（认领确实发生过）。"""
    s = _market_chain(tmp_path)
    tstore = TradeStore(tmp_path)
    verifier = AgentIdentity.generate(label="verifier")
    settler = AgentIdentity.generate(label="settler")

    ann_id, outcome = _drive_to_verified(
        tstore, s, verifier=verifier, settler=settler, exit_code=1,
        terms={"amount_minor": REWARD, "currency": ASSET})
    assert outcome.verdict == VERDICT_FAIL
    assert trade_state(tstore, ann_id) == STATE_FAILED

    from nth_dao.commerce import SettlementFailed
    rail = FakePaymentRail()
    with pytest.raises(SettlementFailed):
        settle_trade(
            tstore, ann_id, settler=settler,
            adapter=X402SettlementAdapter(rail),
            intent=SettlementIntent(trade_id=ann_id, amount_minor=REWARD,
                                    currency=ASSET, payee_did=s["worker"].as_did()))
    assert rail.calls == []  # 付款前就被状态守卫拦下
    assert trade_state(tstore, ann_id) == STATE_FAILED

    # 认领本身有效 → 信誉仍计入
    prof = compute_reputation(s["worker"].as_did(), s["cstore"].all_records())
    assert prof.claims_count == 1


# ─── 整链对抗：白嫖只有 verify_trade ∧ binding 组合才闭合 ────────


def test_full_chain_underpay_passes_chain_but_caught_by_binding(tmp_path) -> None:
    """恶意开局方把 terms 压成 1（公告 reward=1_000_000）、结算也付 1。

    关键：单看 verify_trade 会**通过** —— 结算金额(1)与 terms(1)自洽。只有
    回锚到签名公告的 verify_trade_binding 才识破（terms != reward）。证明
    整链可信必须 verify_trade ∧ verify_trade_binding，任一单独都不够。"""
    s = _market_chain(tmp_path)
    tstore = TradeStore(tmp_path)
    verifier = AgentIdentity.generate(label="verifier")
    # 开局方自任 settler，把 terms 压成 1
    ann_id, outcome = _drive_to_verified(
        tstore, s, verifier=verifier, settler=s["publisher"],
        terms={"amount_minor": 1, "currency": ASSET})
    assert outcome.passed

    rail = FakePaymentRail()
    settle_trade(
        tstore, ann_id, settler=s["publisher"],
        adapter=X402SettlementAdapter(rail),
        intent=SettlementIntent(trade_id=ann_id, amount_minor=1,
                                currency=ASSET, payee_did=s["worker"].as_did()))
    assert trade_state(tstore, ann_id) == STATE_SETTLED

    # 链自洽：通过（结算 1 == terms 1）—— 单独不足以发现白嫖
    ok, _ = verify_trade(tstore, ann_id)
    assert ok
    # 锚定：识破（terms 1 != 公告 reward 1_000_000）
    from nth_dao.commerce.binding import REJECT_TERMS_REWARD_MISMATCH
    ok, reason = verify_trade_binding(
        tstore.get_events(ann_id), announcement=s["ann"],
        claim_record=s["claim_record"], require_terms=True)
    assert not ok and reason == REJECT_TERMS_REWARD_MISMATCH
