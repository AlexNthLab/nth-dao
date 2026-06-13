"""协调平面去中心化:中心 push → 联邦市场 pull。

根本方案最后一块。前面 A2ACoordinator 仍是**中心 push**:协调者挑 peer、
派活。全网尺度这会撞上"谁来派、派给谁"的协调冲突(你最初指出的 relay
之根的另一面)。

去中心模型:协调者**不派活**,只把 step ``announce`` 到市场 feed(公告,
publisher 签名,带能力+悬赏)。worker **自己** poll feed、**原子认领**
(claim_announcement → 签名 ClaimReceipt + CAS)、自己执行、自己签工作
receipt。**没有中心仲裁** —— 谁拿到活由市场的原子认领决定。

冲突消解(回答"全网冲突更严重"):两个 worker 抢同一公告,
``claim_announcement`` 的 InterProcessLock CAS 保证**恰好一个**胜出,败者
得 ClaimConflict。这就是去中心的 single-writer —— 不是协调者选的,是市场
的原子认领选的。再叠加 commerce 的"一公告一交易"(open_trade CAS),
胜者唯一、可结算。

复用:market(announce/feed/claim,已建)+ A2A 工作签名证据
(verify_work_receipt,前几轮加固)+ reputation/cap_token 准入。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Optional

from nth_dao.market import (
    MarketFeed, ClaimStore, claim_announcement, sign_announcement,
    ClaimConflict, ClaimRejected,
)
from nth_dao.orchestration.a2a_coordinator import (
    DispatchFn, PeerResponse, verify_work_receipt,
)


def announcement_id_for(mission_id: str, step_id: str) -> str:
    """(mission_id, step_id) → 确定性 announcement_id。

    同一份活永远映射到同一个 id。这是去中心幂等的关键:claim 的 CAS 锁
    是按 announcement_id 建的,所以哪怕同一 step 被**重复 announce**(协调者
    重试/重启/多副本并发),所有副本共享同一 id → 认领仍只成一份 → 一个
    worker、一笔交易。否则随机 id 会让一份活裂成多条公告、被多人各干一遍、
    付多次(CAS 只在单条公告内防双认领,挡不住"多条公告")。
    """
    import hashlib
    h = hashlib.sha256(f"{mission_id}\x00{step_id}".encode("utf-8")).hexdigest()
    return f"mstep-{h[:40]}"


def announce_step(
    feed: MarketFeed,
    step: Any,
    *,
    publisher: Any,           # AgentIdentity(can_sign)
    mission_id: str = "",
    reward_minor: int = 0,
    reward_asset: str = "credit",
    title_prefix: str = "mission-step",
    default_capability: str = "general",
) -> Any:
    """把一个 mission step 发成市场公告(publisher 签名),发布到 feed。

    capability_set = step.required_capabilities(空则 [default_capability])。
    announcement_id 由 (mission_id, step.id) **确定性**派生 —— 重复 announce
    幂等(认领仍只成一份,见 ``announcement_id_for``)。**应传 mission_id**
    以避免跨 mission 的 step_id 撞车。返回签名后的 TaskAnnouncement。
    """
    caps = list(getattr(step, "required_capabilities", []) or []) or [default_capability]
    step_id = str(getattr(step, "id", ""))
    ann = sign_announcement(
        publisher=publisher,
        title=f"{title_prefix}: {step_id}",
        capability_set=caps,
        reward_minor=reward_minor,
        reward_asset=reward_asset,
        description=str(getattr(step, "description", "")),
        announcement_id=announcement_id_for(mission_id, step_id),
    )
    feed.publish(ann)
    return ann


@dataclass
class WorkOutcome:
    """worker 拉到并干完一件活的结果。"""
    announcement_id: str
    claim_record: dict
    response: str
    verified: bool
    reason: str = ""


class MarketWorker:
    """去中心 worker:自己从 feed 拉活、原子认领、执行、签工作 receipt。

    协调者不碰它 —— 它是自治的 pull 端。``dispatch`` 是它执行活的方式
    (打自己的 A2A /a2a/ask,产出**自己 DID 亲签**的工作 receipt)。
    """

    def __init__(
        self,
        feed: MarketFeed,
        claim_store: ClaimStore,
        identity: Any,           # AgentIdentity(can_sign)
        cap_token: dict,
        dispatch: DispatchFn,
    ) -> None:
        self.feed = feed
        self.claim_store = claim_store
        self.identity = identity
        self.cap_token = cap_token
        self.dispatch = dispatch
        self.did = identity.as_did()

    def try_claim(self, announcement_id: str) -> Optional[Any]:
        """原子认领。胜者得 ClaimOutcome;竞态败者/无权限 → None。

        已知限制(审查记录,非本轮修):
          - 把 ClaimConflict(竞态败者)与 ClaimRejected(无权限/过期/信誉
            不达)都吞成 None —— 对调度足够,但丢了"为何没拿到"的可观测性。
          - **不支持** claimant_policy 公告:本方法不传 claimant_reputation,
            故带信誉门槛的公告一律 ClaimRejected→None(fail-closed,安全但
            功能缺)。网络部署要支持时,须由认领权威服务端算信誉后传入。
        """
        try:
            return claim_announcement(
                self.feed, self.claim_store, announcement_id,
                claimant=self.identity, cap_token=self.cap_token)
        except (ClaimConflict, ClaimRejected):
            return None  # 输了 CAS 竞态 或 不达准入 → 没拿到活

    def execute(self, prompt: str) -> PeerResponse:
        """执行活:经自己的 A2A dispatch 产出签名工作 receipt。"""
        return self.dispatch(prompt)

    def claim_and_execute(
        self, announcement_id: str, prompt: str,
    ) -> Optional[WorkOutcome]:
        """拉活闭环:原子认领 → 执行 → 校验自己的工作 receipt。

        认领失败(竞态败者)→ None。认领成功 → 执行 + verify_work_receipt
        (signer==自己、绑定本 prompt/response)→ WorkOutcome。
        """
        outcome = self.try_claim(announcement_id)
        if outcome is None:
            return None
        resp = self.execute(prompt)
        ok, reason = verify_work_receipt(
            resp.receipt, expected_signer=self.did,
            prompt=prompt, response=resp.text or "")
        return WorkOutcome(
            announcement_id=announcement_id,
            claim_record=outcome.claim_record,
            response=resp.text or "",
            verified=ok,
            reason=reason,
        )
