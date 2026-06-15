"""信誉层:从 spine 事件派生可验证贡献 + 争议归属(顺序无关)。"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("nacl")

from nth_dao.dispute import record_dispute, sign_dispute_statement
from nth_dao.identity import AgentIdentity
from nth_dao.market.acceptance import sign_acceptance, verify_acceptance
from nth_dao.market.announcement import sign_announcement
from nth_dao.reputation_spine import ReputationProjection
from nth_dao.spine import SignedEventLog, replay


def _id() -> AgentIdentity:
    return AgentIdentity.generate()


def _claim_payload(aid, claimant, pub):
    return {
        "announcement_id": aid, "claimant_did": claimant.as_did(),
        "publisher_did": pub.as_did(),
    }


def test_reputation_from_spine(tmp_path: Path) -> None:
    node, pub, agent = _id(), _id(), _id()
    spine = SignedEventLog(tmp_path / "spine.jsonl", node)
    a1 = sign_announcement(publisher=pub, title="t1", capability_set=["x"])
    a2 = sign_announcement(publisher=pub, title="t2", capability_set=["x"])
    a3 = sign_announcement(publisher=pub, title="t3", capability_set=["x"])
    for a in (a1, a2, a3):
        spine.append("market.announce", a.to_dict())
        spine.append("market.claim", _claim_payload(a.announcement_id, agent, pub))
    # 发布方验收 a1、a2(交付);a3 只承接、未验收 → 不计 score。
    spine.append("market.acceptance", sign_acceptance(
        publisher=pub, announcement_id=a1.announcement_id, completer_did=agent.as_did()))
    spine.append("market.acceptance", sign_acceptance(
        publisher=pub, announcement_id=a2.announcement_id, completer_did=agent.as_did()))
    # 对已验收的 a2 开争议 → 它从净分里扣掉。
    record_dispute(spine, sign_dispute_statement(
        signer=pub, statement_type="open", announcement_id=a2.announcement_id))

    ok, why = spine.verify_chain()
    assert ok, why
    proj = ReputationProjection()
    replay(spine.read_all(), proj)

    ar = proj.get(agent.as_did())
    assert ar.tasks_claimed == 3        # 承接 3
    assert ar.tasks_accepted == 2       # 交付被验收 2
    assert ar.disputed_claims == 1      # a2 被争议(在承接集)
    assert ar.score == 1                # 被验收 2 − 被争议的被验收 1(a2)

    pr = proj.get(pub.as_did())
    assert pr.tasks_published == 3
    assert pr.tasks_claimed == 0

    assert proj.top()[0].did == agent.as_did()


def test_only_accepted_scores_not_claimed(tmp_path: Path) -> None:
    # 承接不计入 score(接了 ≠ 交付);验收签名篡改受益人即失效。
    node, pub, agent = _id(), _id(), _id()
    acc = sign_acceptance(publisher=pub, announcement_id="a1", completer_did=agent.as_did())
    ok, why = verify_acceptance(acc)
    assert ok, why
    acc["completer_did"] = "did:key:zEvil"          # 篡改受益人
    bad, _ = verify_acceptance(acc)
    assert not bad

    spine = SignedEventLog(tmp_path / "spine.jsonl", node)
    a1 = sign_announcement(publisher=pub, title="t", capability_set=["x"])
    spine.append("market.announce", a1.to_dict())
    spine.append("market.claim", _claim_payload(a1.announcement_id, agent, pub))
    rec = _project_get(spine, agent.as_did())
    assert rec.tasks_claimed == 1 and rec.tasks_accepted == 0 and rec.score == 0


def test_forged_acceptance_not_credited(tmp_path: Path) -> None:
    # 伪造验收(签名无效)绝不计分(防刷)。
    node, agent = _id(), _id()
    spine = SignedEventLog(tmp_path / "spine.jsonl", node)
    spine.append("market.acceptance", {
        "kind": "nth-task-acceptance-v1", "announcement_id": "a1",
        "completer_did": agent.as_did(), "publisher_did": "did:key:zFake",
        "sig": "forged"})
    rec = _project_get(spine, agent.as_did())
    assert rec.tasks_accepted == 0 and rec.score == 0


def _project_get(spine, did):
    proj = ReputationProjection()
    replay(spine.read_all(), proj)
    return proj.get(did)


def test_order_independent_dispute_before_claim(tmp_path: Path) -> None:
    node, pub, agent = _id(), _id(), _id()
    spine = SignedEventLog(tmp_path / "spine.jsonl", node)
    a1 = sign_announcement(publisher=pub, title="t", capability_set=["x"])
    spine.append("market.announce", a1.to_dict())
    # 争议先到、认领后到 —— 集合交集法仍正确归属。
    record_dispute(spine, sign_dispute_statement(
        signer=pub, statement_type="open", announcement_id=a1.announcement_id))
    spine.append("market.claim", _claim_payload(a1.announcement_id, agent, pub))

    proj = ReputationProjection()
    replay(spine.read_all(), proj)
    ar = proj.get(agent.as_did())
    assert ar.tasks_claimed == 1 and ar.disputed_claims == 1 and ar.score == 0


def test_published_and_claimed_dedup_by_announcement(tmp_path: Path) -> None:
    # 对抗审查修复:同一公告出现两条 announce / claim 事件 → 各只计一次(对称去重)。
    node, pub, agent = _id(), _id(), _id()
    spine = SignedEventLog(tmp_path / "spine.jsonl", node)
    a1 = sign_announcement(publisher=pub, title="t", capability_set=["x"])
    spine.append("market.announce", a1.to_dict())
    spine.append("market.announce", a1.to_dict())                       # 重复 announce
    spine.append("market.claim", _claim_payload(a1.announcement_id, agent, pub))
    spine.append("market.claim", _claim_payload(a1.announcement_id, agent, pub))  # 重复 claim

    proj = ReputationProjection()
    replay(spine.read_all(), proj)
    assert proj.get(pub.as_did()).tasks_published == 1
    assert proj.get(agent.as_did()).tasks_claimed == 1


def test_acceptance_from_non_publisher_not_credited(tmp_path: Path) -> None:
    # 联邦伪造防护:非真发布方对公告签验收 → 不计分。
    node, realpub, fakepub, agent = _id(), _id(), _id(), _id()
    spine = SignedEventLog(tmp_path / "spine.jsonl", node)
    a1 = sign_announcement(publisher=realpub, title="t", capability_set=["x"])
    spine.append("market.announce", a1.to_dict())
    spine.append("market.claim", _claim_payload(a1.announcement_id, agent, realpub))
    spine.append("market.acceptance", sign_acceptance(
        publisher=fakepub, announcement_id=a1.announcement_id,
        completer_did=agent.as_did()))                    # 假发布方签的验收
    assert _project_get(spine, agent.as_did()).tasks_accepted == 0


def test_acceptance_without_claim_not_credited(tmp_path: Path) -> None:
    # 验收一个没认领过的人 → 不计分。
    node, pub, agent = _id(), _id(), _id()
    spine = SignedEventLog(tmp_path / "spine.jsonl", node)
    a1 = sign_announcement(publisher=pub, title="t", capability_set=["x"])
    spine.append("market.announce", a1.to_dict())         # 无 market.claim
    spine.append("market.acceptance", sign_acceptance(
        publisher=pub, announcement_id=a1.announcement_id,
        completer_did=agent.as_did()))
    assert _project_get(spine, agent.as_did()).tasks_accepted == 0


def test_unknown_did_zero(tmp_path: Path) -> None:
    spine = SignedEventLog(tmp_path / "spine.jsonl", _id())
    proj = ReputationProjection()
    replay(spine.read_all(), proj)
    r = proj.get("did:key:zNobody")
    assert r.tasks_claimed == 0 and r.score == 0
    assert proj.all() == []
