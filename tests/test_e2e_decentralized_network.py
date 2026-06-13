"""端到端全链路 capstone:去中心 agent 网络从发现到结算。

把根本方案四平面串成一条链,一个 worker 用**同一个 DID** 贯穿:

  发现 → 握手(证明掌握 DID 私钥)→ announce(协调者只发活)→ 原子认领
  (worker 自治拉活)→ 签名工作(signer+内容三绑)→ commerce 结算(x402)
  → verify_trade ∧ binding(锚定签名公告 reward)→ reputation。

证明四平面**可组合**:身份在发现/握手/认领/工作/结算间一致流动,每一跳
都有签名证据,冲突由 CAS 消解,无中心 relay。
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("nacl")

from nth_dao.cap_token import (
    sign_cap_token, CAP_NTH_RECEIPT_SIGN, CAP_A2A_MESSAGE_SEND,
)
from nth_dao.identity import AgentIdentity
from nth_dao.execution_receipt import now_ms
from nth_dao.web.dummy_agent import _build_a2a_ask_receipt
from nth_dao.market import MarketFeed, ClaimStore, compute_reputation
from nth_dao.orchestration.a2a_coordinator import PeerResponse
from nth_dao.orchestration.market_coordinator import announce_step, MarketWorker
from nth_dao.discovery.a2a_resolve import resolve_a2a_peers
from nth_dao.commerce import (
    TradeStore, open_trade, submit_delivery, record_verification,
    trade_state, verify_trade, verify_trade_binding,
    SettlementIntent, X402SettlementAdapter, FakePaymentRail, settle_trade,
    VERDICT_PASS, STATE_SETTLED,
)

REWARD = 1_000_000
ASSET = "USDC"
SKILL = "solo"


class _Step:
    def __init__(self, sid, caps, desc=""):
        self.id = sid
        self.required_capabilities = caps
        self.description = desc


class _FakePeer:
    def __init__(self, did, capabilities, label=""):
        self.did = did
        self.capabilities = capabilities
        self.label = label


def _signing_dispatch(identity, cap_token):
    """worker 自己执行 + 亲签工作 receipt 的 dispatch(发现握手与干活共用:
    它对任何 prompt 都签一张 signer==自己、绑定该 prompt/response 的 receipt)。"""
    def dispatch(prompt: str) -> PeerResponse:
        resp = f"done: {prompt[:30]}"
        t0 = now_ms()
        receipt, reason = _build_a2a_ask_receipt(
            identity=identity, method="ask", backend_name="local",
            token=cap_token, agent_did=identity.as_did(),
            params={"prompt": prompt}, result={"response": resp},
            started_at_ms=t0, ended_at_ms=now_ms())
        assert receipt is not None, reason
        return PeerResponse(text=resp, receipt=receipt, agent_did=identity.as_did())
    return dispatch


def test_full_chain_discovery_to_settlement(tmp_path: Path) -> None:
    issuer = AgentIdentity.generate(label="issuer")
    publisher = AgentIdentity.generate(label="publisher")
    worker = AgentIdentity.generate(label="worker")
    verifier = AgentIdentity.generate(label="verifier")
    settler = AgentIdentity.generate(label="settler")

    worker_cap = sign_cap_token(
        issuer=issuer, subject_did=worker.as_did(),
        capabilities=[SKILL, CAP_NTH_RECEIPT_SIGN, CAP_A2A_MESSAGE_SEND])
    dispatch = _signing_dispatch(worker, worker_cap)

    # ── 平面1+2:发现 + 身份握手 ──
    discovered = [_FakePeer(worker.as_did(), [SKILL], "w")]
    peers = resolve_a2a_peers(
        discovered, dispatch_for=lambda _p: dispatch, verify_identity=True)
    assert [p.did for p in peers] == [worker.as_did()], "worker 须过握手入组"

    # ── 平面4:协调者只 announce(不派活)──
    feed = MarketFeed(tmp_path)
    claim_store = ClaimStore(tmp_path)
    ann = announce_step(feed, _Step("s1", [SKILL], "修一个 bug"),
                        publisher=publisher, mission_id="m1",
                        reward_minor=REWARD, reward_asset=ASSET)

    # ── worker 自治:pull → 原子认领 → 执行 → 工作 receipt 校验 ──
    w = MarketWorker(feed, claim_store, worker, worker_cap, dispatch)
    out = w.claim_and_execute(ann.announcement_id, prompt="处理 s1")
    assert out is not None and out.verified, f"工作未通过校验: {out and out.reason}"

    # ── commerce:从认领闭合到 x402 结算 ──
    tstore = TradeStore(tmp_path)
    open_trade(tstore, authority=publisher, claim_record=out.claim_record,
               verifier_did=verifier.as_did(), settler_did=settler.as_did(),
               terms={"amount_minor": REWARD, "currency": ASSET})
    submit_delivery(tstore, ann.announcement_id, claimant=worker,
                    delivery={"work": out.response[:20]})
    record_verification(tstore, ann.announcement_id, verifier=verifier,
                        verdict=VERDICT_PASS, result={"ok": 1})
    rail = FakePaymentRail()
    settle_trade(tstore, ann.announcement_id, settler=settler,
                 adapter=X402SettlementAdapter(rail),
                 intent=SettlementIntent(trade_id=ann.announcement_id,
                                         amount_minor=REWARD, currency=ASSET,
                                         payee_did=worker.as_did()))
    assert trade_state(tstore, ann.announcement_id) == STATE_SETTLED
    assert rail.calls and rail.calls[0]["payee_did"] == worker.as_did()

    # ── 离线复核:链自洽 ∧ 锚定签名公告 reward(strict)──
    assert verify_trade(tstore, ann.announcement_id)[0]
    ok, why = verify_trade_binding(
        tstore.get_events(ann.announcement_id), announcement=ann,
        claim_record=out.claim_record, require_terms=True)
    assert ok, why

    # ── reputation:worker 这笔认领计入(签名可验)──
    prof = compute_reputation(worker.as_did(), claim_store.all_records())
    assert prof.claims_count == 1
    assert prof.total_reward_minor == REWARD
