"""M3 测试 —— 原子认领 + cap_token 授权 + ClaimReceipt（修 C4 + 约束 E）。

退出门槛（开发指导 M3）：
  - N 进程并发抢一公告恰好一胜；
  - capability 不足的 cap_token 被拒；
  - 每步 receipt 可独立验签。

覆盖：
  - 认领成功 → 返回 receipt，verify_receipt 通过，authorizing_cap_token 挂上
  - 能力不足 token 被拒
  - subject 不匹配（A 拿 B 的 token）被拒
  - 过期 / 不存在公告被拒
  - 二次认领（不同 Agent）→ ClaimConflict
  - 幂等再认领（同一 Agent）→ 同一 receipt
  - **C4 核心**：N 个独立进程抢一公告 → 恰好 1 胜
"""

from __future__ import annotations

import json
import multiprocessing as mp
import sys
from pathlib import Path

import pytest

from nth_dao.cap_token import (
    sign_cap_token, CAP_NTH_RECEIPT_SIGN, verify_cap_token as _verify_cap_token,
)
from nth_dao.execution_receipt import verify_receipt
from nth_dao.identity import AgentIdentity
from nth_dao.market import (
    MarketFeed,
    ClaimStore,
    claim_announcement,
    sign_announcement,
    ClaimConflict,
    ClaimRejected,
    REJECT_ANN_NOT_FOUND,
    REJECT_ANN_EXPIRED,
    REJECT_CAP_TOKEN_INVALID,
    REJECT_SUBJECT_MISMATCH,
    REJECT_SKILL_INSUFFICIENT,
    CLAIM_STATUS_CLAIMED,
)

pytest.importorskip("nacl")


# ─── helpers ─────────────────────────────────────────────────────


def _publish(feed, publisher, caps=("code_review",), reward=10, **kw):
    ann = sign_announcement(
        publisher=publisher, title=kw.pop("title", "task"),
        capability_set=list(caps), reward_minor=reward, **kw,
    )
    feed.publish(ann)
    return ann


def _token_for(issuer, claimant, caps=("code_review", CAP_NTH_RECEIPT_SIGN)):
    return sign_cap_token(
        issuer=issuer, subject_did=claimant.as_did(),
        capabilities=list(caps),
    )


# ─── 认领成功 + 收据可验 ─────────────────────────────────────────


def test_claim_success_returns_verifiable_receipt(tmp_path) -> None:
    feed = MarketFeed(tmp_path)
    store = ClaimStore(tmp_path)
    issuer = AgentIdentity.generate(label="issuer")
    publisher = AgentIdentity.generate(label="publisher")
    claimant = AgentIdentity.generate(label="claimant")

    ann = _publish(feed, publisher, caps=["code_review"])
    token = _token_for(issuer, claimant, caps=["code_review", CAP_NTH_RECEIPT_SIGN])

    out = claim_announcement(
        feed, store, ann.announcement_id,
        claimant=claimant, cap_token=token,
    )
    # 收据可独立验签（约束 E）
    assert verify_receipt(out.receipt), "ClaimReceipt 必须独立可验签"
    # 收据 signer == claimant
    assert out.receipt["signer_did"] == claimant.as_did()
    # authorizing_cap_token 挂上且可独立验链
    attached = out.receipt.get("authorizing_cap_token")
    assert attached is not None
    ok, _ = _verify_cap_token(attached)
    assert ok, "挂载的 cap_token 必须独立可验"
    # claim 记录落盘
    rec = store.get(ann.announcement_id)
    assert rec["status"] == CLAIM_STATUS_CLAIMED
    assert rec["claimant_did"] == claimant.as_did()
    assert rec["receipt_id"] == out.receipt["receipt_id"]


def test_claim_receipt_payload_pins_economics(tmp_path) -> None:
    feed = MarketFeed(tmp_path)
    store = ClaimStore(tmp_path)
    issuer = AgentIdentity.generate(label="i")
    pub = AgentIdentity.generate(label="p")
    claimant = AgentIdentity.generate(label="c")
    ann = _publish(feed, pub, caps=["code_review"], reward=42)
    token = _token_for(issuer, claimant)

    out = claim_announcement(feed, store, ann.announcement_id,
                             claimant=claimant, cap_token=token)
    entry = next(e for e in out.receipt["timeline"]
                 if e["type"] == "nth.task_claimed")
    p = entry["payload"]
    assert p["reward_minor"] == 42
    assert p["announcement_id"] == ann.announcement_id
    assert p["claimant_did"] == claimant.as_did()
    assert p["publisher_did"] == pub.as_did()
    assert p["cap_token_id"] == token["token_id"]


# ─── 授权拒绝 ────────────────────────────────────────────────────


def test_claim_rejected_capability_insufficient(tmp_path) -> None:
    feed = MarketFeed(tmp_path)
    store = ClaimStore(tmp_path)
    issuer = AgentIdentity.generate(label="i")
    pub = AgentIdentity.generate(label="p")
    claimant = AgentIdentity.generate(label="c")
    # 公告要 deploy，token 只授 code_review
    ann = _publish(feed, pub, caps=["deploy"])
    token = _token_for(issuer, claimant, caps=["code_review", CAP_NTH_RECEIPT_SIGN])

    with pytest.raises(ClaimRejected) as exc:
        claim_announcement(feed, store, ann.announcement_id,
                           claimant=claimant, cap_token=token)
    assert exc.value.reason == REJECT_SKILL_INSUFFICIENT
    # 认领被拒后无 claim 记录
    assert store.get(ann.announcement_id) is None


def test_claim_skill_check_is_normalized_consistent_with_discovery(tmp_path) -> None:
    """独立审查回归 (M3 R1)：M2 discovery 与 M3 claim 的能力判定必须用
    同一套归一，否则"能发现却认领被拒"。

    场景：外部发布方写 'Code_Review'（未规范化），issuer 授 'code_review'
    （规范化）。修复前 claim 用 verify_cap_token 精确比对 → 'Code_Review'
    not in {'code_review'} → 误拒。修复后两侧归一 → 通过。
    """
    feed = MarketFeed(tmp_path)
    store = ClaimStore(tmp_path)
    issuer = AgentIdentity.generate(label="i")
    pub = AgentIdentity.generate(label="p")
    claimant = AgentIdentity.generate(label="c")
    ann = sign_announcement(publisher=pub, title="t",
                            capability_set=["Code_Review"], reward_minor=5)
    feed.publish(ann)
    assert ann.capability_set == ["Code_Review"]   # 存的是未规范化原样
    token = sign_cap_token(
        issuer=issuer, subject_did=claimant.as_did(),
        capabilities=["code_review", CAP_NTH_RECEIPT_SIGN],
    )
    out = claim_announcement(feed, store, ann.announcement_id,
                             claimant=claimant, cap_token=token)
    assert verify_receipt(out.receipt)   # 认领成功且收据可验


def test_claim_rejected_subject_mismatch(tmp_path) -> None:
    """A 拿签发给 B 的 token 来认领 → 拒。"""
    feed = MarketFeed(tmp_path)
    store = ClaimStore(tmp_path)
    issuer = AgentIdentity.generate(label="i")
    pub = AgentIdentity.generate(label="p")
    agent_a = AgentIdentity.generate(label="a")
    agent_b = AgentIdentity.generate(label="b")
    ann = _publish(feed, pub, caps=["code_review"])
    token_for_b = _token_for(issuer, agent_b)

    with pytest.raises(ClaimRejected) as exc:
        claim_announcement(feed, store, ann.announcement_id,
                           claimant=agent_a, cap_token=token_for_b)
    assert exc.value.reason == REJECT_SUBJECT_MISMATCH


def test_claim_rejected_expired(tmp_path) -> None:
    feed = MarketFeed(tmp_path)
    store = ClaimStore(tmp_path)
    issuer = AgentIdentity.generate(label="i")
    pub = AgentIdentity.generate(label="p")
    claimant = AgentIdentity.generate(label="c")
    ann = _publish(feed, pub, caps=["code_review"],
                   published_at_ms=1000, not_after=2000)
    token = _token_for(issuer, claimant)
    with pytest.raises(ClaimRejected) as exc:
        claim_announcement(feed, store, ann.announcement_id,
                           claimant=claimant, cap_token=token,
                           now_ms_override=5000)
    assert exc.value.reason == REJECT_ANN_EXPIRED


def test_claim_rejected_not_found(tmp_path) -> None:
    feed = MarketFeed(tmp_path)
    store = ClaimStore(tmp_path)
    issuer = AgentIdentity.generate(label="i")
    claimant = AgentIdentity.generate(label="c")
    token = _token_for(issuer, claimant)
    with pytest.raises(ClaimRejected) as exc:
        claim_announcement(feed, store, "does-not-exist",
                           claimant=claimant, cap_token=token)
    assert exc.value.reason == REJECT_ANN_NOT_FOUND


# ─── 冲突 + 幂等 ─────────────────────────────────────────────────


def test_second_claim_by_other_agent_conflicts(tmp_path) -> None:
    feed = MarketFeed(tmp_path)
    store = ClaimStore(tmp_path)
    issuer = AgentIdentity.generate(label="i")
    pub = AgentIdentity.generate(label="p")
    a = AgentIdentity.generate(label="a")
    b = AgentIdentity.generate(label="b")
    ann = _publish(feed, pub, caps=["code_review"])

    claim_announcement(feed, store, ann.announcement_id,
                       claimant=a, cap_token=_token_for(issuer, a))
    with pytest.raises(ClaimConflict):
        claim_announcement(feed, store, ann.announcement_id,
                           claimant=b, cap_token=_token_for(issuer, b))


def test_idempotent_reclaim_same_agent(tmp_path) -> None:
    feed = MarketFeed(tmp_path)
    store = ClaimStore(tmp_path)
    issuer = AgentIdentity.generate(label="i")
    pub = AgentIdentity.generate(label="p")
    a = AgentIdentity.generate(label="a")
    ann = _publish(feed, pub, caps=["code_review"])
    token = _token_for(issuer, a)

    out1 = claim_announcement(feed, store, ann.announcement_id,
                              claimant=a, cap_token=token)
    out2 = claim_announcement(feed, store, ann.announcement_id,
                              claimant=a, cap_token=token)
    # 幂等：同一 receipt_id，不重签
    assert out1.receipt["receipt_id"] == out2.receipt["receipt_id"]


# ─── C4 核心：N 进程并发抢一公告恰好一胜 ────────────────────────


def _claim_worker(workspace, announcement_id, claimant_path, token_json,
                  result_queue):
    """子进程入口：load 自己的身份 + token，抢同一公告，报结果。"""
    sys.path.insert(0, str(Path(__file__).parent.parent))
    try:
        from nth_dao.identity import AgentIdentity
        from nth_dao.market import (
            MarketFeed, ClaimStore, claim_announcement,
            ClaimConflict, ClaimRejected,
        )
        claimant = AgentIdentity.load(claimant_path)
        token = json.loads(token_json)
        feed = MarketFeed(workspace)
        store = ClaimStore(workspace)
        try:
            out = claim_announcement(feed, store, announcement_id,
                                     claimant=claimant, cap_token=token)
            if out.claim_record["claimant_did"] == claimant.as_did():
                result_queue.put(("won", claimant.as_did()))
            else:
                result_queue.put(("lost", claimant.as_did()))
        except ClaimConflict:
            result_queue.put(("conflict", claimant.as_did()))
        except ClaimRejected as e:
            result_queue.put(("rejected", claimant.as_did(), e.reason))
    except Exception as e:  # noqa: BLE001
        result_queue.put(("error", repr(e)))


def test_exactly_one_winner_across_processes(tmp_path) -> None:
    """C4 退出门槛：N 个独立进程同时认领同一公告 → 恰好 1 胜，其余 conflict。"""
    feed = MarketFeed(tmp_path)
    ClaimStore(tmp_path)
    issuer = AgentIdentity.generate(label="issuer")
    publisher = AgentIdentity.generate(label="publisher")
    ann = _publish(feed, publisher, caps=["code_review"])

    n = 6
    args = []
    for i in range(n):
        claimant = AgentIdentity.generate(label=f"claimant-{i}")
        cpath = str(tmp_path / f"claimant_{i}.json")
        claimant.save(cpath)
        token = _token_for(issuer, claimant)
        args.append((str(tmp_path), ann.announcement_id, cpath,
                     json.dumps(token)))

    ctx = mp.get_context("spawn")  # Windows-safe
    q = ctx.Queue()
    procs = [
        ctx.Process(target=_claim_worker, args=(*a, q))
        for a in args
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=60)

    results = [q.get() for _ in range(n)]
    outcomes = [r[0] for r in results]
    won = outcomes.count("won")
    conflict = outcomes.count("conflict")
    errors = [r for r in results if r[0] in ("error", "rejected")]

    assert not errors, f"unexpected worker failures: {errors}"
    assert won == 1, f"必须恰好 1 个 winner，实际 {won}（outcomes={outcomes}）"
    assert conflict == n - 1, f"其余必须全 conflict，实际 {conflict}"

    # 最终 claim 记录与那个 winner 一致
    final = ClaimStore(tmp_path).get(ann.announcement_id)
    winner_did = next(r[1] for r in results if r[0] == "won")
    assert final["claimant_did"] == winner_did
