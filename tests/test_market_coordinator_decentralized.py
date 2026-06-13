"""协调平面去中心化 keystone:announce → 原子 claim(无中心仲裁)。

证明:
  - 两个 worker 抢同一公告 → claim_announcement 的 CAS 让**恰好一个**胜出,
    败者 None(ClaimConflict)。冲突由市场原子认领消解,非协调者仲裁。
  - 胜者 pull→claim→execute→签工作 receipt 闭环,receipt 经
    verify_work_receipt 校验(signer==自己、绑定 prompt/response)。
  - 没有中心 push:协调者只 announce,worker 自治拉活。
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("nacl")

from nth_dao.cap_token import sign_cap_token, CAP_NTH_RECEIPT_SIGN
from nth_dao.identity import AgentIdentity
from nth_dao.market import MarketFeed, ClaimStore
from nth_dao.execution_receipt import verify_receipt, now_ms
from nth_dao.web.dummy_agent import _build_a2a_ask_receipt
from nth_dao.orchestration.a2a_coordinator import PeerResponse
from nth_dao.orchestration.market_coordinator import (
    announce_step, MarketWorker,
)


class _Step:
    def __init__(self, sid, caps, desc=""):
        self.id = sid
        self.required_capabilities = caps
        self.description = desc


def _worker(tmp_path, feed, label, skill):
    """造一个 MarketWorker:自有签名身份 + 授 skill 的 cap_token + 本地
    执行并**亲签**工作 receipt 的 dispatch。"""
    issuer = AgentIdentity.generate(label="issuer")
    ident = AgentIdentity.generate(label=label)
    cap = sign_cap_token(issuer=issuer, subject_did=ident.as_did(),
                         capabilities=[skill, CAP_NTH_RECEIPT_SIGN])

    def dispatch(prompt: str) -> PeerResponse:
        resp = f"({label}) done: {prompt[:40]}"
        t0 = now_ms()
        receipt, reason = _build_a2a_ask_receipt(
            identity=ident, method="ask", backend_name="local",
            token=cap, agent_did=ident.as_did(),
            params={"prompt": prompt}, result={"response": resp},
            started_at_ms=t0, ended_at_ms=now_ms())
        assert receipt is not None, reason
        return PeerResponse(text=resp, receipt=receipt, agent_did=ident.as_did())

    store = ClaimStore(tmp_path)
    return MarketWorker(feed, store, ident, cap, dispatch)


def test_two_workers_race_exactly_one_claims(tmp_path: Path) -> None:
    """去中心冲突消解:两 worker 抢同一公告,恰好一个胜出。"""
    feed = MarketFeed(tmp_path)
    publisher = AgentIdentity.generate(label="pub")
    ann = announce_step(feed, _Step("s1", ["solo"], "干一件事"),
                        publisher=publisher, reward_minor=10)

    # 两个 worker 共用同一 ClaimStore(同一市场视图)才能真竞态。
    shared = ClaimStore(tmp_path)
    wa = _worker(tmp_path, feed, "A", "solo"); wa.claim_store = shared
    wb = _worker(tmp_path, feed, "B", "solo"); wb.claim_store = shared

    ra = wa.try_claim(ann.announcement_id)
    rb = wb.try_claim(ann.announcement_id)

    winners = [r for r in (ra, rb) if r is not None]
    assert len(winners) == 1, "必须恰好一个胜出(原子认领)"
    # 胜者的 ClaimReceipt 可独立验签
    assert verify_receipt(winners[0].receipt)


def test_pull_claim_execute_sign_loop(tmp_path: Path) -> None:
    """胜者 pull→claim→execute→签工作 receipt 闭环,校验通过。"""
    feed = MarketFeed(tmp_path)
    publisher = AgentIdentity.generate(label="pub")
    ann = announce_step(feed, _Step("s1", ["solo"], "干一件事"),
                        publisher=publisher, reward_minor=10)

    w = _worker(tmp_path, feed, "solo-worker", "solo")
    out = w.claim_and_execute(ann.announcement_id, prompt="请处理 s1")
    assert out is not None
    assert out.verified, f"工作 receipt 应校验通过: {out.reason}"
    assert "done" in out.response
    # claim 记录锚定真公告
    assert out.claim_record.get("announcement_id") == ann.announcement_id


def test_loser_gets_nothing_no_double_work(tmp_path: Path) -> None:
    """先认领者拿走;第二个 worker claim_and_execute → None(不重复干)。"""
    feed = MarketFeed(tmp_path)
    publisher = AgentIdentity.generate(label="pub")
    ann = announce_step(feed, _Step("s1", ["solo"]), publisher=publisher,
                        reward_minor=10)
    shared = ClaimStore(tmp_path)
    wa = _worker(tmp_path, feed, "A", "solo"); wa.claim_store = shared
    wb = _worker(tmp_path, feed, "B", "solo"); wb.claim_store = shared

    first = wa.claim_and_execute(ann.announcement_id, prompt="p")
    second = wb.claim_and_execute(ann.announcement_id, prompt="p")
    assert first is not None and first.verified
    assert second is None  # 败者不重复干活


def test_worker_without_skill_token_cannot_claim(tmp_path: Path) -> None:
    """cap_token 不含公告所需技能 → 认领被拒(None),不入场。"""
    feed = MarketFeed(tmp_path)
    publisher = AgentIdentity.generate(label="pub")
    ann = announce_step(feed, _Step("s1", ["solo"]), publisher=publisher,
                        reward_minor=10)
    # 这个 worker 的 token 只授 "other",不含 "solo"。
    wrong = _worker(tmp_path, feed, "wrong", "other")
    assert wrong.try_claim(ann.announcement_id) is None
