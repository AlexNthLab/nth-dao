"""XDAO-1:跨 DAO 认领的两个加密函数 —— sign_claim_receipt(只签) +
record_foreign_claim(来源 DAO 验 + CAS)。

这是信任边界(收据来自不可信网络),所以攻击面逐项测透:伪造收据、重放到
别的公告、token/收据 claimant 不绑定、技能不足、冲突、幂等、过期。
permissionless 路径用**自签 cap_token**(issuer==subject==agent)。
"""
from __future__ import annotations

import pytest

pytest.importorskip("nacl")

from nth_dao.cap_token import CAP_NTH_RECEIPT_SIGN, sign_cap_token
from nth_dao.execution_receipt import verify_receipt
from nth_dao.identity import AgentIdentity
from nth_dao.market import (
    ClaimConflict,
    ClaimRejected,
    ClaimStore,
    MarketFeed,
    REJECT_ANN_EXPIRED,
    REJECT_RECEIPT_BINDING,
    REJECT_RECEIPT_INVALID,
    REJECT_SKILL_INSUFFICIENT,
    REJECT_SUBJECT_MISMATCH,
    record_foreign_claim,
    sign_announcement,
    sign_claim_receipt,
)


def _selfissue(agent, caps):
    """agent 给自己自签一张 cap_token(permissionless 跨 DAO 路径)。"""
    return sign_cap_token(
        issuer=agent, subject_did=agent.as_did(),
        capabilities=[*caps, CAP_NTH_RECEIPT_SIGN],
    )


def _setup(tmp_path, caps=("code_review",), **ann_kw):
    feed = MarketFeed(tmp_path)
    store = ClaimStore(tmp_path)
    pub = AgentIdentity.generate(label="pub")
    agent = AgentIdentity.generate(label="agent")
    ann = sign_announcement(
        publisher=pub, title="task", capability_set=list(caps),
        reward_minor=5, **ann_kw,
    )
    feed.publish(ann)
    return feed, store, pub, agent, ann


def test_sign_then_record_happy_path(tmp_path) -> None:
    feed, store, pub, agent, ann = _setup(tmp_path)
    token = _selfissue(agent, ["code_review"])
    receipt = sign_claim_receipt(ann, agent, token)
    assert verify_receipt(receipt)                     # agent 自签,可验
    assert receipt["signer_did"] == agent.as_did()

    out = record_foreign_claim(feed, store, ann.announcement_id, token, receipt)
    assert out.claim_record["claimant_did"] == agent.as_did()
    assert out.claim_record["foreign"] is True
    assert store.is_claimed(ann.announcement_id)
    # 落盘的是 agent 那张收据原文(来源没重签)。
    assert out.claim_record["receipt"]["receipt_id"] == receipt["receipt_id"]


def test_idempotent_same_agent(tmp_path) -> None:
    feed, store, pub, agent, ann = _setup(tmp_path)
    token = _selfissue(agent, ["code_review"])
    receipt = sign_claim_receipt(ann, agent, token)
    out1 = record_foreign_claim(feed, store, ann.announcement_id, token, receipt)
    out2 = record_foreign_claim(feed, store, ann.announcement_id, token, receipt)
    assert out1.claim_record["receipt_id"] == out2.claim_record["receipt_id"]


def test_conflict_different_agent(tmp_path) -> None:
    feed, store, pub, agentA, ann = _setup(tmp_path)
    tokenA = _selfissue(agentA, ["code_review"])
    record_foreign_claim(
        feed, store, ann.announcement_id, tokenA,
        sign_claim_receipt(ann, agentA, tokenA),
    )
    agentB = AgentIdentity.generate(label="B")
    tokenB = _selfissue(agentB, ["code_review"])
    with pytest.raises(ClaimConflict):
        record_foreign_claim(
            feed, store, ann.announcement_id, tokenB,
            sign_claim_receipt(ann, agentB, tokenB),
        )


def test_forged_receipt_rejected(tmp_path) -> None:
    # 篡改签名体内字段(timeline payload)→ content_hash 不符 → verify_receipt 拒。
    feed, store, pub, agent, ann = _setup(tmp_path)
    token = _selfissue(agent, ["code_review"])
    receipt = sign_claim_receipt(ann, agent, token)
    receipt["timeline"][0]["payload"]["reward_minor"] = 999_999
    with pytest.raises(ClaimRejected) as e:
        record_foreign_claim(feed, store, ann.announcement_id, token, receipt)
    assert e.value.reason == REJECT_RECEIPT_INVALID


def test_replay_receipt_to_other_announcement(tmp_path) -> None:
    # 给公告 A 签的收据,拿去认领公告 B → 绑定校验拦下(防重放/换标的)。
    feed, store, pub, agent, annA = _setup(tmp_path)
    annB = sign_announcement(
        publisher=pub, title="B", capability_set=["code_review"], reward_minor=5)
    feed.publish(annB)
    token = _selfissue(agent, ["code_review"])
    recA = sign_claim_receipt(annA, agent, token)
    with pytest.raises(ClaimRejected) as e:
        record_foreign_claim(feed, store, annB.announcement_id, token, recA)
    assert e.value.reason == REJECT_RECEIPT_BINDING


def test_record_rejects_token_subject_not_signer(tmp_path) -> None:
    # 攻击:拿 agent 的有效收据,配一张 subject 是别人的 token 提交。
    # cap_token.subject 必须 == 签收据的 claimant,否则拒。
    feed, store, pub, agent, ann = _setup(tmp_path)
    token = _selfissue(agent, ["code_review"])
    receipt = sign_claim_receipt(ann, agent, token)
    other = AgentIdentity.generate(label="other")
    mism = _selfissue(other, ["code_review"])  # subject = other
    with pytest.raises(ClaimRejected) as e:
        record_foreign_claim(feed, store, ann.announcement_id, mism, receipt)
    assert e.value.reason == REJECT_SUBJECT_MISMATCH


def test_sign_rejects_subject_mismatch(tmp_path) -> None:
    # 只签侧也早拦:token.subject != claimant → 不签。
    feed, store, pub, agent, ann = _setup(tmp_path)
    other = AgentIdentity.generate(label="other")
    bad = _selfissue(other, ["code_review"])  # subject = other, 不是 agent
    with pytest.raises(ClaimRejected) as e:
        sign_claim_receipt(ann, agent, bad)
    assert e.value.reason == REJECT_SUBJECT_MISMATCH


def test_record_rejects_receipt_token_mismatch(tmp_path) -> None:
    # 加固:收据绑定到签它时那张 cap_token(payload.cap_token_id 在签名体内)。
    # 换一张 token(同 subject、技能够,但 token_id 不同)提交 → 绑定校验拒。
    feed, store, pub, agent, ann = _setup(tmp_path)
    token_a = _selfissue(agent, ["code_review"])
    receipt = sign_claim_receipt(ann, agent, token_a)
    token_b = _selfissue(agent, ["code_review", "extra_skill"])  # token_id 必不同
    with pytest.raises(ClaimRejected) as e:
        record_foreign_claim(feed, store, ann.announcement_id, token_b, receipt)
    assert e.value.reason == REJECT_RECEIPT_BINDING


def test_skill_insufficient(tmp_path) -> None:
    feed, store, pub, agent, ann = _setup(tmp_path, caps=("legal_review",))
    token = _selfissue(agent, ["code_review"])  # 缺 legal_review
    receipt = sign_claim_receipt(ann, agent, token)
    with pytest.raises(ClaimRejected) as e:
        record_foreign_claim(feed, store, ann.announcement_id, token, receipt)
    assert e.value.reason == REJECT_SKILL_INSUFFICIENT


def test_expired_announcement_rejected(tmp_path) -> None:
    feed, store, pub, agent, ann = _setup(tmp_path, not_after=1)  # 1ms 早过期
    token = _selfissue(agent, ["code_review"])
    receipt = sign_claim_receipt(ann, agent, token, now_ms_override=2)
    with pytest.raises(ClaimRejected) as e:
        record_foreign_claim(
            feed, store, ann.announcement_id, token, receipt, now_ms_override=10)
    assert e.value.reason == REJECT_ANN_EXPIRED
