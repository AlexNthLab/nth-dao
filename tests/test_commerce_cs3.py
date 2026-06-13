"""CS3 测试 —— 争议处理（DISPUTED → SETTLED|REFUNDED|SPLIT_SETTLED）。

退出门槛（CS3）：
  - 交付后任一方可提争议；resolver 裁决三种结局；
  - 争议事件链每步签名可验、verify_trade 复核通过；
  - 非法：旁人裁决 / 错前置 / 伪造 resolution-state 被拒。

覆盖：
  - 三种入口（DELIVERED/VERIFIED/FAILED → DISPUTED）
  - publisher 与 claimant 都可提争议；旁人不可
  - 三种裁决：settle / refund / split → 对应终态
  - 只有绑定 resolver 能裁决
  - resolve 前必须先 dispute（非法前置）
  - 伪造 resolution-state（settle 但 new_state=refunded）被 verify_trade 拒
"""

from __future__ import annotations

import json

import pytest

from nth_dao.identity import AgentIdentity
from nth_dao.commerce import (
    TradeStore, open_trade, submit_delivery, record_verification,
    open_dispute, resolve_dispute, trade_state, verify_trade,
    TradeRejected,
    STATE_DELIVERED, STATE_DISPUTED, STATE_SETTLED, STATE_REFUNDED,
    STATE_SPLIT_SETTLED, STATE_FAILED,
    VERDICT_PASS, VERDICT_FAIL,
    RESOLUTION_SETTLE, RESOLUTION_REFUND, RESOLUTION_SPLIT,
    REJECT_WRONG_ACTOR, REJECT_ILLEGAL_TRANSITION, REJECT_BAD_RESOLUTION,
)

pytest.importorskip("nacl")


def _claim(ann_id, claimant, publisher):
    return {"announcement_id": ann_id, "claimant_did": claimant.as_did(),
            "publisher_did": publisher.as_did(), "receipt_id": "r-" + ann_id}


def _open(tmp_path, ann_id, *, resolver=None):
    store = TradeStore(tmp_path)
    auth = AgentIdentity.generate(label="dao")
    pub = AgentIdentity.generate(label="pub")
    worker = AgentIdentity.generate(label="worker")
    resolver = resolver or AgentIdentity.generate(label="arbiter")
    open_trade(store, authority=auth, claim_record=_claim(ann_id, worker, pub),
               verifier_did=pub.as_did(), settler_did=pub.as_did(),
               resolver_did=resolver.as_did())
    return store, pub, worker, resolver


# ─── 入口：交付后三态都可提争议 ─────────────────────────────────


def test_dispute_from_delivered(tmp_path) -> None:
    store, pub, worker, resolver = _open(tmp_path, "d1")
    submit_delivery(store, "d1", claimant=worker, delivery={"x": 1})
    open_dispute(store, "d1", disputant=pub, reason="delivery doesn't match spec")
    assert trade_state(store, "d1") == STATE_DISPUTED
    assert verify_trade(store, "d1")[0]


def test_dispute_from_verified(tmp_path) -> None:
    """已 VERIFIED 仍可提争议（publisher 质疑验收方）。"""
    store, pub, worker, resolver = _open(tmp_path, "d2")
    submit_delivery(store, "d2", claimant=worker, delivery={})
    record_verification(store, "d2", verifier=pub, verdict=VERDICT_PASS, result={})
    open_dispute(store, "d2", disputant=pub, reason="verifier colluded")
    assert trade_state(store, "d2") == STATE_DISPUTED


def test_dispute_from_failed_by_claimant(tmp_path) -> None:
    """FAILED 后 claimant 可申诉（认为 fail 不公）。"""
    store, pub, worker, resolver = _open(tmp_path, "d3")
    submit_delivery(store, "d3", claimant=worker, delivery={})
    record_verification(store, "d3", verifier=pub, verdict=VERDICT_FAIL, result={})
    assert trade_state(store, "d3") == STATE_FAILED
    open_dispute(store, "d3", disputant=worker, reason="my tests actually pass")
    assert trade_state(store, "d3") == STATE_DISPUTED


def test_outsider_cannot_dispute(tmp_path) -> None:
    store, pub, worker, resolver = _open(tmp_path, "d4")
    submit_delivery(store, "d4", claimant=worker, delivery={})
    intruder = AgentIdentity.generate(label="intruder")
    with pytest.raises(TradeRejected) as exc:
        open_dispute(store, "d4", disputant=intruder, reason="meddling")
    assert exc.value.reason == REJECT_WRONG_ACTOR


def test_cannot_dispute_before_delivery(tmp_path) -> None:
    store, pub, worker, resolver = _open(tmp_path, "d5")
    # 还在 EXECUTING（未交付）就提争议 → 非法前置
    with pytest.raises(TradeRejected) as exc:
        open_dispute(store, "d5", disputant=pub, reason="too early")
    assert exc.value.reason == REJECT_ILLEGAL_TRANSITION


# ─── 裁决：三种结局 ──────────────────────────────────────────────


def test_resolve_settle(tmp_path) -> None:
    store, pub, worker, resolver = _open(tmp_path, "r1")
    submit_delivery(store, "r1", claimant=worker, delivery={})
    open_dispute(store, "r1", disputant=pub, reason="x")
    resolve_dispute(store, "r1", resolver=resolver, resolution=RESOLUTION_SETTLE,
                    settlement={"adapter_id": "manual", "amount_minor": 10},
                    rationale="work is fine")
    assert trade_state(store, "r1") == STATE_SETTLED
    assert verify_trade(store, "r1")[0]


def test_resolve_refund(tmp_path) -> None:
    store, pub, worker, resolver = _open(tmp_path, "r2")
    submit_delivery(store, "r2", claimant=worker, delivery={})
    open_dispute(store, "r2", disputant=pub, reason="bad work")
    resolve_dispute(store, "r2", resolver=resolver, resolution=RESOLUTION_REFUND,
                    settlement={"adapter_id": "manual", "refund_minor": 10})
    assert trade_state(store, "r2") == STATE_REFUNDED
    assert verify_trade(store, "r2")[0]


def test_resolve_split(tmp_path) -> None:
    store, pub, worker, resolver = _open(tmp_path, "r3")
    submit_delivery(store, "r3", claimant=worker, delivery={})
    open_dispute(store, "r3", disputant=worker, reason="partial")
    resolve_dispute(store, "r3", resolver=resolver, resolution=RESOLUTION_SPLIT,
                    settlement={"adapter_id": "manual", "claimant_minor": 6,
                                "refund_minor": 4})
    assert trade_state(store, "r3") == STATE_SPLIT_SETTLED
    assert verify_trade(store, "r3")[0]


def test_only_resolver_can_resolve(tmp_path) -> None:
    store, pub, worker, resolver = _open(tmp_path, "r4")
    submit_delivery(store, "r4", claimant=worker, delivery={})
    open_dispute(store, "r4", disputant=pub, reason="x")
    # publisher 想自己裁决（不是绑定的 resolver）→ 拒
    with pytest.raises(TradeRejected) as exc:
        resolve_dispute(store, "r4", resolver=pub, resolution=RESOLUTION_REFUND,
                        settlement={})
    assert exc.value.reason == REJECT_WRONG_ACTOR


def test_bad_resolution_rejected(tmp_path) -> None:
    store, pub, worker, resolver = _open(tmp_path, "r5")
    submit_delivery(store, "r5", claimant=worker, delivery={})
    open_dispute(store, "r5", disputant=pub, reason="x")
    with pytest.raises(TradeRejected) as exc:
        resolve_dispute(store, "r5", resolver=resolver, resolution="bribe",
                        settlement={})
    assert exc.value.reason == REJECT_BAD_RESOLUTION


def test_cannot_resolve_without_dispute(tmp_path) -> None:
    store, pub, worker, resolver = _open(tmp_path, "r6")
    submit_delivery(store, "r6", claimant=worker, delivery={})
    # DELIVERED 直接裁决（没争议）→ 非法前置
    with pytest.raises(TradeRejected) as exc:
        resolve_dispute(store, "r6", resolver=resolver, resolution=RESOLUTION_SETTLE,
                        settlement={})
    assert exc.value.reason == REJECT_ILLEGAL_TRANSITION


# ─── 伪造 resolution-state 被 verify_trade 拒 ────────────────────


def test_cannot_dispute_after_settled(tmp_path) -> None:
    """已结清的交易不能再被翻出来争议（终态不可重开）。"""
    store, pub, worker, resolver = _open(tmp_path, "t1")
    submit_delivery(store, "t1", claimant=worker, delivery={})
    record_verification(store, "t1", verifier=pub, verdict=VERDICT_PASS, result={})
    from nth_dao.commerce import record_settlement
    record_settlement(store, "t1", settler=pub, settlement={"adapter_id": "manual"})
    assert trade_state(store, "t1") == STATE_SETTLED
    with pytest.raises(TradeRejected) as exc:
        open_dispute(store, "t1", disputant=worker, reason="buyer's remorse")
    assert exc.value.reason == REJECT_ILLEGAL_TRANSITION


def test_cannot_settle_behind_open_dispute(tmp_path) -> None:
    """争议开启后，普通结算被挡（只能走 resolve_dispute）—— 防绕过争议偷结算。"""
    store, pub, worker, resolver = _open(tmp_path, "t2")
    submit_delivery(store, "t2", claimant=worker, delivery={})
    record_verification(store, "t2", verifier=pub, verdict=VERDICT_PASS, result={})
    open_dispute(store, "t2", disputant=pub, reason="wait")
    from nth_dao.commerce import record_settlement
    with pytest.raises(TradeRejected) as exc:
        record_settlement(store, "t2", settler=pub, settlement={})
    assert exc.value.reason == REJECT_ILLEGAL_TRANSITION


def test_verify_rejects_forged_resolution_state(tmp_path) -> None:
    """resolver 裁 resolution=settle 却把 new_state 伪造成 refunded（想偷改
    资金去向）→ verify_trade 按 resolution 算期望态，判非法。"""
    from nth_dao.commerce.trade import (
        TradeEvent, sign_trade_event, EVENT_DISPUTE_RESOLVED,
    )
    store, pub, worker, resolver = _open(tmp_path, "f1")
    submit_delivery(store, "f1", claimant=worker, delivery={})
    open_dispute(store, "f1", disputant=pub, reason="x")
    path = store._path("f1")
    data = json.loads(path.read_text(encoding="utf-8"))
    # resolution=settle 但 new_state 伪造成 refunded
    ev = TradeEvent(trade_id="f1", seq=len(data["events"]),
                    type=EVENT_DISPUTE_RESOLVED, actor_did=resolver.as_did(),
                    prev_state=STATE_DISPUTED, new_state=STATE_REFUNDED,
                    payload={"resolution": RESOLUTION_SETTLE, "settlement": {}},
                    created_at_ms=1)
    sign_trade_event(resolver, ev)
    data["events"].append(ev.to_dict())
    path.write_text(json.dumps(data), encoding="utf-8")
    ok, reason = verify_trade(store, "f1")
    assert not ok
    assert reason == REJECT_ILLEGAL_TRANSITION
