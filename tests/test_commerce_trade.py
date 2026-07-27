"""CS1 测试 —— 交易状态机（无真钱，从市场认领闭合到结算）。

退出门槛（CS1）：
  - 一笔从市场 claim 开局的交易，走完 执行→交付→验收→结算 全程，
    每步签名可独立验证；
  - 非法转移（跳步/重复/错前置）被拒；
  - 错误角色（非 claimant 交付、非 verifier 验收）被拒；
  - verify_trade 能离线复核整条链。

覆盖：
  - happy path EXECUTING→DELIVERED→VERIFIED→SETTLED
  - verify(fail) → FAILED 终态，不能再结算
  - 非法转移：未交付先验收 / 未验收先结算 / 重复 open
  - 错误角色：旁人交付 / 旁人验收 / 旁人结算
  - verify_trade 整链复核 + 篡改检测
  - 并发 open 恰好一胜
"""

from __future__ import annotations

import json
import multiprocessing as mp
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from nth_dao.identity import AgentIdentity
from nth_dao.util.io import atomic_write_json
from nth_dao.commerce import (
    TradeStore,
    open_trade,
    submit_delivery,
    record_verification,
    record_settlement,
    trade_state,
    verify_trade,
    TradeConflict,
    TradeRejected,
    STATE_EXECUTING,
    STATE_DELIVERED,
    STATE_VERIFIED,
    STATE_FAILED,
    STATE_SETTLED,
    VERDICT_PASS,
    VERDICT_FAIL,
    REJECT_ILLEGAL_TRANSITION,
    REJECT_WRONG_ACTOR,
    REJECT_TRADE_EXISTS,
    REJECT_BAD_VERDICT,
    REJECT_CHAIN_BROKEN,
)

pytest.importorskip("nacl")


def _claim(ann_id, claimant, publisher):
    """构造一条 market claim_record 的最小形状（commerce 只需这几字段）。"""
    return {
        "announcement_id": ann_id,
        "claimant_did": claimant.as_did(),
        "publisher_did": publisher.as_did(),
        "receipt_id": "rcpt-" + ann_id,
    }


# ─── happy path ──────────────────────────────────────────────────


def test_full_lifecycle_to_settled(tmp_path) -> None:
    """退出门槛：claim → 执行 → 交付 → 验收(pass) → 结算，整链可验。"""
    store = TradeStore(tmp_path)
    authority = AgentIdentity.generate(label="dao")      # 主 DAO（开局 + 默认 verifier/settler 但这里显式给）
    publisher = AgentIdentity.generate(label="pub")
    claimant = AgentIdentity.generate(label="worker")
    verifier = AgentIdentity.generate(label="verifier")
    settler = AgentIdentity.generate(label="settler")

    claim = _claim("ann-1", claimant, publisher)
    open_trade(store, authority=authority, claim_record=claim,
               verifier_did=verifier.as_did(), settler_did=settler.as_did())
    assert trade_state(store, "ann-1") == STATE_EXECUTING

    submit_delivery(store, "ann-1", claimant=claimant,
                    delivery={"artifact_sha256": "abc", "execution_receipt_id": "x"})
    assert trade_state(store, "ann-1") == STATE_DELIVERED

    record_verification(store, "ann-1", verifier=verifier, verdict=VERDICT_PASS,
                        result={"checks": "all-green"})
    assert trade_state(store, "ann-1") == STATE_VERIFIED

    record_settlement(store, "ann-1", settler=settler,
                      settlement={"adapter_id": "manual", "amount_minor": 10})
    assert trade_state(store, "ann-1") == STATE_SETTLED

    # 整链离线可验
    ok, reason = verify_trade(store, "ann-1")
    assert ok, reason


def test_verify_fail_goes_to_failed_terminal(tmp_path) -> None:
    store = TradeStore(tmp_path)
    auth = AgentIdentity.generate(label="dao")
    pub = AgentIdentity.generate(label="pub")
    worker = AgentIdentity.generate(label="worker")
    claim = _claim("ann-2", worker, pub)
    # 默认 verifier/settler = publisher
    open_trade(store, authority=auth, claim_record=claim)
    submit_delivery(store, "ann-2", claimant=worker, delivery={"x": 1})
    record_verification(store, "ann-2", verifier=pub, verdict=VERDICT_FAIL,
                        result={"reason": "tests failed"})
    assert trade_state(store, "ann-2") == STATE_FAILED
    # FAILED 是终态：不能再结算
    with pytest.raises(TradeRejected) as exc:
        record_settlement(store, "ann-2", settler=pub, settlement={"adapter_id": "manual"})
    assert exc.value.reason == REJECT_ILLEGAL_TRANSITION
    assert verify_trade(store, "ann-2")[0]


def test_verify_trade_binds_every_event_to_requested_trade_id(tmp_path) -> None:
    store = TradeStore(tmp_path)
    authority = AgentIdentity.generate(label="dao")
    publisher = AgentIdentity.generate(label="publisher")
    claimant = AgentIdentity.generate(label="claimant")
    open_trade(
        store,
        authority=authority,
        claim_record=_claim("bound-trade", claimant, publisher),
    )
    events = store.get_events("bound-trade")

    mismatched_store = SimpleNamespace(get_events=lambda _trade_id: events)
    assert verify_trade(mismatched_store, "different-trade") == (
        False,
        REJECT_CHAIN_BROKEN,
    )


def test_import_refuses_to_overwrite_empty_corrupt_trade(tmp_path) -> None:
    source = TradeStore(tmp_path / "source")
    target = TradeStore(tmp_path / "target")
    authority = AgentIdentity.generate(label="dao")
    publisher = AgentIdentity.generate(label="publisher")
    claimant = AgentIdentity.generate(label="claimant")
    open_trade(
        source,
        authority=authority,
        claim_record=_claim("corrupt-trade", claimant, publisher),
    )
    events = source.get_events("corrupt-trade")
    target_path = target._path("corrupt-trade")
    atomic_write_json(
        target_path,
        {"trade_id": "corrupt-trade", "events": []},
    )

    with pytest.raises(TradeConflict, match="unreadable"):
        target.import_verified_events("corrupt-trade", events)

    assert target.get_events("corrupt-trade") == []


# ─── 非法转移 ────────────────────────────────────────────────────


def test_cannot_verify_before_delivery(tmp_path) -> None:
    store = TradeStore(tmp_path)
    auth = AgentIdentity.generate(label="dao")
    pub = AgentIdentity.generate(label="pub")
    worker = AgentIdentity.generate(label="worker")
    open_trade(store, authority=auth, claim_record=_claim("a3", worker, pub))
    # 跳过交付直接验收 → 拒
    with pytest.raises(TradeRejected) as exc:
        record_verification(store, "a3", verifier=pub, verdict=VERDICT_PASS, result={})
    assert exc.value.reason == REJECT_ILLEGAL_TRANSITION


def test_cannot_settle_before_verification(tmp_path) -> None:
    store = TradeStore(tmp_path)
    auth = AgentIdentity.generate(label="dao")
    pub = AgentIdentity.generate(label="pub")
    worker = AgentIdentity.generate(label="worker")
    open_trade(store, authority=auth, claim_record=_claim("a4", worker, pub))
    submit_delivery(store, "a4", claimant=worker, delivery={})
    # DELIVERED 直接结算（跳过验收）→ 拒
    with pytest.raises(TradeRejected) as exc:
        record_settlement(store, "a4", settler=pub, settlement={})
    assert exc.value.reason == REJECT_ILLEGAL_TRANSITION


def test_duplicate_open_rejected(tmp_path) -> None:
    store = TradeStore(tmp_path)
    auth = AgentIdentity.generate(label="dao")
    pub = AgentIdentity.generate(label="pub")
    worker = AgentIdentity.generate(label="worker")
    claim = _claim("a5", worker, pub)
    open_trade(store, authority=auth, claim_record=claim)
    with pytest.raises(TradeRejected) as exc:
        open_trade(store, authority=auth, claim_record=claim)
    assert exc.value.reason == REJECT_TRADE_EXISTS


def test_bad_verdict_rejected(tmp_path) -> None:
    store = TradeStore(tmp_path)
    auth = AgentIdentity.generate(label="dao")
    pub = AgentIdentity.generate(label="pub")
    worker = AgentIdentity.generate(label="worker")
    open_trade(store, authority=auth, claim_record=_claim("a6", worker, pub))
    submit_delivery(store, "a6", claimant=worker, delivery={})
    with pytest.raises(TradeRejected) as exc:
        record_verification(store, "a6", verifier=pub, verdict="maybe", result={})
    assert exc.value.reason == REJECT_BAD_VERDICT


# ─── 错误角色 ────────────────────────────────────────────────────


def test_wrong_actor_delivery_rejected(tmp_path) -> None:
    store = TradeStore(tmp_path)
    auth = AgentIdentity.generate(label="dao")
    pub = AgentIdentity.generate(label="pub")
    worker = AgentIdentity.generate(label="worker")
    intruder = AgentIdentity.generate(label="intruder")
    open_trade(store, authority=auth, claim_record=_claim("a7", worker, pub))
    # 旁人冒充 claimant 交付 → 拒
    with pytest.raises(TradeRejected) as exc:
        submit_delivery(store, "a7", claimant=intruder, delivery={})
    assert exc.value.reason == REJECT_WRONG_ACTOR


def test_wrong_actor_verification_rejected(tmp_path) -> None:
    store = TradeStore(tmp_path)
    auth = AgentIdentity.generate(label="dao")
    pub = AgentIdentity.generate(label="pub")
    worker = AgentIdentity.generate(label="worker")
    verifier = AgentIdentity.generate(label="verifier")
    intruder = AgentIdentity.generate(label="intruder")
    open_trade(store, authority=auth, claim_record=_claim("a8", worker, pub),
               verifier_did=verifier.as_did())
    submit_delivery(store, "a8", claimant=worker, delivery={})
    with pytest.raises(TradeRejected) as exc:
        record_verification(store, "a8", verifier=intruder, verdict=VERDICT_PASS, result={})
    assert exc.value.reason == REJECT_WRONG_ACTOR


# ─── verify_trade 整链复核 + 篡改 ────────────────────────────────


def test_verify_trade_rejects_forged_new_state(tmp_path) -> None:
    """独立审查回归 (CS1 R1)：claimant 自签一个 delivery 事件却把
    new_state 直接写成 'settled'（跳过验收+结算）→ verify_trade 必须
    用"该事件类型唯一合法 new_state"比对，判链断。否则 claimant 能把
    自己的交易伪造成已结算，绕过整个状态机。"""
    from nth_dao.commerce.trade import (
        TradeEvent, sign_trade_event, EVENT_DELIVERY_SUBMITTED,
    )
    store = TradeStore(tmp_path)
    auth = AgentIdentity.generate(label="dao")
    pub = AgentIdentity.generate(label="pub")
    worker = AgentIdentity.generate(label="worker")
    open_trade(store, authority=auth, claim_record=_claim("forge", worker, pub))
    # claimant 真签一个 delivery 事件，但 new_state 伪造成 settled
    path = store._path("forge")
    data = json.loads(path.read_text(encoding="utf-8"))
    ev = TradeEvent(trade_id="forge", seq=1, type=EVENT_DELIVERY_SUBMITTED,
                    actor_did=worker.as_did(), prev_state=STATE_EXECUTING,
                    new_state=STATE_SETTLED, payload={"delivery": {}}, created_at_ms=1)
    sign_trade_event(worker, ev)   # 签名真实（claimant 有私钥）
    data["events"].append(ev.to_dict())
    path.write_text(json.dumps(data), encoding="utf-8")

    ok, reason = verify_trade(store, "forge")
    assert not ok, "伪造 new_state 跳步必须被 verify_trade 拒"
    assert reason == REJECT_ILLEGAL_TRANSITION


def test_verify_trade_rejects_forged_verdict_state(tmp_path) -> None:
    """verification 事件把 verdict=fail 却写 new_state=verified（想骗过
    FAILED）→ verify_trade 按 verdict 算期望态，判非法。"""
    from nth_dao.commerce.trade import (
        TradeEvent, sign_trade_event, EVENT_VERIFICATION_RECORDED,
    )
    store = TradeStore(tmp_path)
    auth = AgentIdentity.generate(label="dao")
    pub = AgentIdentity.generate(label="pub")
    worker = AgentIdentity.generate(label="worker")
    open_trade(store, authority=auth, claim_record=_claim("v", worker, pub))
    submit_delivery(store, "v", claimant=worker, delivery={})
    path = store._path("v")
    data = json.loads(path.read_text(encoding="utf-8"))
    # verdict=fail 但 new_state 伪造成 verified
    ev = TradeEvent(trade_id="v", seq=2, type=EVENT_VERIFICATION_RECORDED,
                    actor_did=pub.as_did(), prev_state=STATE_DELIVERED,
                    new_state=STATE_VERIFIED, payload={"verdict": VERDICT_FAIL, "result": {}},
                    created_at_ms=1)
    sign_trade_event(pub, ev)
    data["events"].append(ev.to_dict())
    path.write_text(json.dumps(data), encoding="utf-8")
    ok, reason = verify_trade(store, "v")
    assert not ok
    assert reason == REJECT_ILLEGAL_TRANSITION


def test_wrong_actor_settlement_rejected(tmp_path) -> None:
    store = TradeStore(tmp_path)
    auth = AgentIdentity.generate(label="dao")
    pub = AgentIdentity.generate(label="pub")
    worker = AgentIdentity.generate(label="worker")
    settler = AgentIdentity.generate(label="settler")
    intruder = AgentIdentity.generate(label="intruder")
    open_trade(store, authority=auth, claim_record=_claim("s1", worker, pub),
               settler_did=settler.as_did())
    submit_delivery(store, "s1", claimant=worker, delivery={})
    record_verification(store, "s1", verifier=pub, verdict=VERDICT_PASS, result={})
    with pytest.raises(TradeRejected) as exc:
        record_settlement(store, "s1", settler=intruder, settlement={})
    assert exc.value.reason == REJECT_WRONG_ACTOR


def test_verify_trade_detects_tampered_event(tmp_path) -> None:
    store = TradeStore(tmp_path)
    auth = AgentIdentity.generate(label="dao")
    pub = AgentIdentity.generate(label="pub")
    worker = AgentIdentity.generate(label="worker")
    open_trade(store, authority=auth, claim_record=_claim("a9", worker, pub))
    submit_delivery(store, "a9", claimant=worker,
                    delivery={"artifact_sha256": "real"})
    assert verify_trade(store, "a9")[0]
    # 直接篡改落盘的交付 payload → 该事件验签失败
    path = store._path("a9")
    data = json.loads(path.read_text(encoding="utf-8"))
    data["events"][1]["payload"]["delivery"]["artifact_sha256"] = "swapped"
    path.write_text(json.dumps(data), encoding="utf-8")
    ok, reason = verify_trade(store, "a9")
    assert not ok
    assert reason == "event-sig-invalid"


@pytest.mark.parametrize("event_sig", ["A" * 129, "AA", "valid-padded"])
def test_trade_signature_input_is_bounded_and_exact_length(
    tmp_path, event_sig
) -> None:
    store = TradeStore(tmp_path)
    auth = AgentIdentity.generate(label="dao")
    pub = AgentIdentity.generate(label="pub")
    worker = AgentIdentity.generate(label="worker")
    open_trade(store, authority=auth, claim_record=_claim("sig-bound", worker, pub))
    path = store._path("sig-bound")
    data = json.loads(path.read_text(encoding="utf-8"))
    data["events"][0]["event_sig"] = (
        data["events"][0]["event_sig"] + "=="
        if event_sig == "valid-padded"
        else event_sig
    )
    path.write_text(json.dumps(data), encoding="utf-8")

    assert verify_trade(store, "sig-bound") == (False, "event-sig-invalid")


# ─── 并发 open ───────────────────────────────────────────────────


def _open_worker(workspace, ann_id, auth_path, claim_json, result_queue):
    sys.path.insert(0, str(Path(__file__).parent.parent))
    try:
        from nth_dao.identity import AgentIdentity
        from nth_dao.commerce import TradeStore, open_trade, TradeRejected
        auth = AgentIdentity.load(auth_path)
        store = TradeStore(workspace)
        claim = json.loads(claim_json)
        try:
            open_trade(store, authority=auth, claim_record=claim)
            result_queue.put("opened")
        except TradeRejected:
            result_queue.put("exists")
    except Exception as e:  # noqa: BLE001
        result_queue.put(("error", repr(e)))


def test_concurrent_open_exactly_one_winner(tmp_path) -> None:
    """N 进程同时为一笔认领开 trade → 恰好 1 胜，其余拿到 already-exists。"""
    auth = AgentIdentity.generate(label="dao")
    pub = AgentIdentity.generate(label="pub")
    worker = AgentIdentity.generate(label="worker")
    apath = str(tmp_path / "auth.json")
    auth.save(apath)
    claim = _claim("race", worker, pub)
    cj = json.dumps(claim)

    ctx = mp.get_context("spawn")
    q = ctx.Queue()
    n = 5
    procs = [ctx.Process(target=_open_worker, args=(str(tmp_path), "race", apath, cj, q))
             for _ in range(n)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=60)
    results = [q.get() for _ in range(n)]
    assert results.count("opened") == 1, f"必须恰好 1 个 winner: {results}"
    assert results.count("exists") == n - 1
