"""M5 测试 —— Mission 关联 + 可解释信誉 + 发布方侧 claimant 准入。

退出门槛（开发指导 M5）：
  - 一个 Mission 分解的多条公告并行完成并回填；
  - 信誉投影无全局单分。

覆盖：
  - ReputationProfile 无 score/trust 单分（约束 D）
  - compute_reputation 从签名 claim 记录聚合可解释维度
  - claimant_policy：空 = permissionless（默认），非空 = 按信誉门槛准入
  - claim 在公告设门槛但没给信誉时 fail-closed
  - mission_progress：多公告并行认领后回填进度
"""

from __future__ import annotations

import pytest

from nth_dao.cap_token import sign_cap_token, CAP_NTH_RECEIPT_SIGN
from nth_dao.identity import AgentIdentity
from nth_dao.market import (
    MarketFeed,
    ClaimStore,
    claim_announcement,
    sign_announcement,
    ReputationProfile,
    compute_reputation,
    mission_progress,
    MissionProgress,
    ClaimRejected,
    REJECT_CLAIMANT_BELOW_POLICY,
    REJECT_CLAIMANT_REP_MISSING,
)

pytest.importorskip("nacl")


def _token(issuer, claimant, caps=("code_review", CAP_NTH_RECEIPT_SIGN)):
    return sign_cap_token(issuer=issuer, subject_did=claimant.as_did(),
                          capabilities=list(caps))


# ─── 可解释信誉：无全局单分 ─────────────────────────────────────


def test_reputation_profile_has_no_global_score() -> None:
    """约束 D：ReputationProfile 刻意不含 score/trust/reputation 单一分。"""
    prof = ReputationProfile(subject_did="did:key:zX")
    fields = set(prof.to_dict().keys())
    for forbidden in ("score", "trust", "reputation", "rating", "rank"):
        assert forbidden not in fields, (
            f"信誉投影不该有全局单分字段 {forbidden!r}（约束 D）"
        )
    # 暴露的是可解释维度
    assert "claims_count" in fields
    assert "distinct_publishers" in fields
    assert "distinct_capabilities" in fields


def test_compute_reputation_aggregates_dimensions(tmp_path) -> None:
    """从真实签名 claim 记录聚合维度（counterparty diversity 抗自刷）。"""
    feed = MarketFeed(tmp_path)
    store = ClaimStore(tmp_path)
    issuer = AgentIdentity.generate(label="i")
    worker = AgentIdentity.generate(label="worker")
    pub1 = AgentIdentity.generate(label="pub1")
    pub2 = AgentIdentity.generate(label="pub2")

    # worker 认领：pub1 的 code_review×1（reward 10）+ pub2 的 research×1（reward 5）
    a1 = sign_announcement(publisher=pub1, title="t1",
                           capability_set=["code_review"], reward_minor=10)
    a2 = sign_announcement(publisher=pub2, title="t2",
                           capability_set=["research"], reward_minor=5)
    feed.publish(a1)
    feed.publish(a2)
    claim_announcement(feed, store, a1.announcement_id, claimant=worker,
                       cap_token=_token(issuer, worker, ["code_review", CAP_NTH_RECEIPT_SIGN]))
    claim_announcement(feed, store, a2.announcement_id, claimant=worker,
                       cap_token=_token(issuer, worker, ["research", CAP_NTH_RECEIPT_SIGN]))

    prof = compute_reputation(worker.as_did(), store.all_records())
    assert prof.claims_count == 2
    assert prof.distinct_publishers == 2          # pub1 + pub2（抗自刷）
    assert prof.distinct_capabilities == 2        # code_review + research
    assert prof.total_reward_minor == 15
    assert prof.first_seen_ms > 0
    assert prof.last_seen_ms >= prof.first_seen_ms


def test_compute_reputation_rejects_forged_records() -> None:
    """独立审查回归 (M5 R2)：compute_reputation 必须验签嵌入的 receipt，
    不能信任未验证输入。否则跨 DAO 汇集时，攻击者伪造一批无签名 claim
    记录即可刷出高信誉。

    构造 10 条纯伪造记录（无有效 receipt）→ 信誉必须为 0。
    """
    victim = "did:key:zVictimForgeTarget"
    forged = [
        {"claimant_did": victim, "publisher_did": f"did:key:zPub{i}",
         "claimed_at_ms": 1000 + i, "capability_set": ["code_review"],
         "reward_minor": 9999}
        for i in range(10)
    ]
    prof = compute_reputation(victim, forged)
    assert prof.claims_count == 0, "无签名伪造记录不得计入信誉"
    assert prof.distinct_publishers == 0
    assert prof.total_reward_minor == 0


def test_compute_reputation_rejects_tampered_receipt(tmp_path) -> None:
    """已签名 receipt 落地后被改 reward → 验签失败 → 不计入。"""
    feed = MarketFeed(tmp_path)
    store = ClaimStore(tmp_path)
    issuer = AgentIdentity.generate(label="i")
    pub = AgentIdentity.generate(label="p")
    worker = AgentIdentity.generate(label="w")
    a = sign_announcement(publisher=pub, title="t", capability_set=["code_review"],
                          reward_minor=10)
    feed.publish(a)
    out = claim_announcement(feed, store, a.announcement_id, claimant=worker,
                             cap_token=_token(issuer, worker))
    # 真实记录先确认计入
    good = compute_reputation(worker.as_did(), store.all_records())
    assert good.claims_count == 1
    # 篡改记录里 receipt 的 payload reward —— 验签应失败
    rec = store.get(a.announcement_id)
    rec["receipt"]["timeline"][0]["payload"]["reward_minor"] = 999999
    tampered = compute_reputation(worker.as_did(), [rec])
    assert tampered.claims_count == 0, "篡改 receipt 后验签失败，不得计入"


def test_compute_reputation_rejects_wrong_signer(tmp_path) -> None:
    """receipt 由别人签、却挂在 victim 名下 → signer != subject → 不计入。"""
    feed = MarketFeed(tmp_path)
    store = ClaimStore(tmp_path)
    issuer = AgentIdentity.generate(label="i")
    pub = AgentIdentity.generate(label="p")
    real = AgentIdentity.generate(label="real")
    victim = AgentIdentity.generate(label="victim")
    a = sign_announcement(publisher=pub, title="t", capability_set=["code_review"],
                          reward_minor=10)
    feed.publish(a)
    out = claim_announcement(feed, store, a.announcement_id, claimant=real,
                             cap_token=_token(issuer, real))
    rec = store.get(a.announcement_id)
    # 把顶层 claimant_did 改成 victim，但 receipt 仍是 real 签的
    rec["claimant_did"] = victim.as_did()
    prof = compute_reputation(victim.as_did(), [rec])
    assert prof.claims_count == 0, "顶层 claimant 伪造、signer 不符 → 不得计入"
    # real 用同一条（signer 匹配）仍算
    assert compute_reputation(real.as_did(), [rec]).claims_count == 1


def test_compute_reputation_ignores_other_agents(tmp_path) -> None:
    feed = MarketFeed(tmp_path)
    store = ClaimStore(tmp_path)
    issuer = AgentIdentity.generate(label="i")
    pub = AgentIdentity.generate(label="p")
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    a1 = sign_announcement(publisher=pub, title="t1", capability_set=["code_review"], reward_minor=10)
    a2 = sign_announcement(publisher=pub, title="t2", capability_set=["code_review"], reward_minor=10)
    feed.publish(a1)
    feed.publish(a2)
    claim_announcement(feed, store, a1.announcement_id, claimant=alice, cap_token=_token(issuer, alice))
    claim_announcement(feed, store, a2.announcement_id, claimant=bob, cap_token=_token(issuer, bob))

    prof = compute_reputation(alice.as_did(), store.all_records())
    assert prof.claims_count == 1   # 只算 alice 的，不含 bob


# ─── claimant_policy：permissionless 默认 + 门槛准入 ────────────


def test_claim_open_by_default_no_policy(tmp_path) -> None:
    """空 claimant_policy = permissionless（M4 默认保持）。"""
    feed = MarketFeed(tmp_path)
    store = ClaimStore(tmp_path)
    issuer = AgentIdentity.generate(label="i")
    pub = AgentIdentity.generate(label="p")
    fresh = AgentIdentity.generate(label="fresh")   # 零历史新手
    ann = sign_announcement(publisher=pub, title="open",
                            capability_set=["code_review"], reward_minor=1)
    feed.publish(ann)
    # 不传 claimant_reputation 也能认领（无门槛）
    out = claim_announcement(feed, store, ann.announcement_id,
                             claimant=fresh, cap_token=_token(issuer, fresh))
    assert out.claim_record["claimant_did"] == fresh.as_did()


def test_claim_gated_by_policy_rejects_low_reputation(tmp_path) -> None:
    """公告设 claimant_policy → 信誉不达标的认领被拒（发布方侧门槛）。"""
    feed = MarketFeed(tmp_path)
    store = ClaimStore(tmp_path)
    issuer = AgentIdentity.generate(label="i")
    pub = AgentIdentity.generate(label="p")
    newbie = AgentIdentity.generate(label="newbie")
    ann = sign_announcement(
        publisher=pub, title="trusted-only",
        capability_set=["code_review"], reward_minor=100,
        claimant_policy={"min_claims_count": 3, "min_distinct_publishers": 2},
    )
    feed.publish(ann)
    # newbie 零历史
    rep = compute_reputation(newbie.as_did(), store.all_records())
    assert rep.claims_count == 0
    with pytest.raises(ClaimRejected) as exc:
        claim_announcement(feed, store, ann.announcement_id, claimant=newbie,
                           cap_token=_token(issuer, newbie),
                           claimant_reputation=rep)
    assert exc.value.reason == REJECT_CLAIMANT_BELOW_POLICY
    assert store.get(ann.announcement_id) is None


def test_claim_gated_policy_missing_reputation_fail_closed(tmp_path) -> None:
    """有门槛但没给 claimant_reputation → fail-closed（无法核验即拒）。"""
    feed = MarketFeed(tmp_path)
    store = ClaimStore(tmp_path)
    issuer = AgentIdentity.generate(label="i")
    pub = AgentIdentity.generate(label="p")
    agent = AgentIdentity.generate(label="a")
    ann = sign_announcement(
        publisher=pub, title="trusted-only", capability_set=["code_review"],
        reward_minor=100, claimant_policy={"min_claims_count": 1},
    )
    feed.publish(ann)
    with pytest.raises(ClaimRejected) as exc:
        claim_announcement(feed, store, ann.announcement_id, claimant=agent,
                           cap_token=_token(issuer, agent))  # 没传 reputation
    assert exc.value.reason == REJECT_CLAIMANT_REP_MISSING


def test_claim_gated_policy_accepts_qualified(tmp_path) -> None:
    """信誉达标的 Agent 通过门槛认领成功。"""
    feed = MarketFeed(tmp_path)
    store = ClaimStore(tmp_path)
    issuer = AgentIdentity.generate(label="i")
    pub = AgentIdentity.generate(label="p")
    veteran = AgentIdentity.generate(label="veteran")
    # 用一个手工 profile 模拟达标历史（compute_reputation 的输出形状）
    rep = ReputationProfile(subject_did=veteran.as_did(), claims_count=5,
                            distinct_publishers=3)
    ann = sign_announcement(
        publisher=pub, title="trusted-only", capability_set=["code_review"],
        reward_minor=100,
        claimant_policy={"min_claims_count": 3, "min_distinct_publishers": 2},
    )
    feed.publish(ann)
    out = claim_announcement(feed, store, ann.announcement_id, claimant=veteran,
                             cap_token=_token(issuer, veteran),
                             claimant_reputation=rep)
    assert out.claim_record["claimant_did"] == veteran.as_did()


def test_unknown_policy_dimension_fail_closed() -> None:
    """门槛写了未知维度名 → fail-closed（防发布方写错却以为设了门槛）。"""
    prof = ReputationProfile(subject_did="x", claims_count=100)
    ok, reason = prof.meets({"min_frobnications": 1})
    assert not ok
    assert "unknown-claimant-policy-dimension" in reason


def test_non_min_prefix_key_fail_closed() -> None:
    """独立审查回归 (M5 R1)：发布方漏 min_ 前缀（写 'claims_count' 而非
    'min_claims_count'）→ fail-closed，不静默放过。否则发布方以为设了
    门槛，实则 permissionless。"""
    prof = ReputationProfile(subject_did="x", claims_count=0)
    ok, reason = prof.meets({"claims_count": 3})
    assert not ok, "非 min_ 键必须 fail-closed，不能被静默忽略"
    assert "unknown-claimant-policy-key" in reason


# ─── Mission 关联：多公告并行认领后回填进度 ────────────────────


def test_mission_progress_reconstructed_from_claims(tmp_path) -> None:
    """M5 退出门槛：一个 Mission 分解的多条公告，多 Agent 并行认领，
    进度从签名认领重建（无中心状态）。"""
    feed = MarketFeed(tmp_path)
    store = ClaimStore(tmp_path)
    issuer = AgentIdentity.generate(label="i")
    pub = AgentIdentity.generate(label="pub")
    mission_id = "build-web-app"

    # 一个 mission 分解成 4 条公告
    anns = []
    for i, cap in enumerate(["design", "api", "frontend", "tests"]):
        a = sign_announcement(publisher=pub, title=f"task-{cap}",
                              capability_set=[cap], reward_minor=10,
                              mission_id=mission_id)
        feed.publish(a)
        anns.append(a)

    # 三个不同 Agent 并行认领前 3 条，第 4 条留空
    workers = [AgentIdentity.generate(label=f"w{i}") for i in range(3)]
    for a, w, cap in zip(anns[:3], workers, ["design", "api", "frontend"]):
        claim_announcement(feed, store, a.announcement_id, claimant=w,
                           cap_token=_token(issuer, w, [cap, CAP_NTH_RECEIPT_SIGN]))

    prog = mission_progress(store, anns)
    assert isinstance(prog, MissionProgress)
    assert prog.mission_id == mission_id
    assert prog.total == 4
    assert prog.claimed == 3
    assert prog.unclaimed == 1
    assert not prog.all_claimed
    assert prog.distinct_claimants() == 3   # 三个不同 Agent 并行
    claimed_ids = {c.announcement_id for c in prog.claims}
    assert claimed_ids == {a.announcement_id for a in anns[:3]}


def test_mission_progress_all_claimed(tmp_path) -> None:
    feed = MarketFeed(tmp_path)
    store = ClaimStore(tmp_path)
    issuer = AgentIdentity.generate(label="i")
    pub = AgentIdentity.generate(label="pub")
    a = sign_announcement(publisher=pub, title="only", capability_set=["x"],
                          reward_minor=1, mission_id="m1")
    feed.publish(a)
    w = AgentIdentity.generate(label="w")
    claim_announcement(feed, store, a.announcement_id, claimant=w,
                       cap_token=_token(issuer, w, ["x", CAP_NTH_RECEIPT_SIGN]))
    prog = mission_progress(store, [a])
    assert prog.all_claimed
