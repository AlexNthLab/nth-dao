"""match —— 公告 × 订阅的四维匹配（修 C3）+ feed 组合器。

C3 问题：旧 ``broadcast_order`` 用 ``capability="code_review"`` 精确串
相等，无 skill 子集、无兴趣维度、无匹配质量。``match()`` 是一个**无状态
纯函数**，做四维判定：

  1. 能力（客观）：公告所需能力 ⊆ Agent 声明能力（子集，非精确相等）
  2. context（兴趣）：公告类别在订阅的 contexts 内（空=全接）
  3. reward（兴趣）：公告报酬 ≥ 订阅门槛
  4. publisher 信誉（约束 D）：发布方本地信誉 ≥ 订阅门槛

纯函数 = 不起 socket、不读盘、可全边界单测。任一维不过即"不匹配"并给出
machine-readable reason，便于 UI/日志解释"为什么这条没推给我"。

``poll_matching(feed, sub)`` 把 ``MarketFeed.poll`` 和 ``match`` 组合成
"订阅视图"：Agent 用自己的订阅一次 poll，只拿到匹配的公告，按 score
（M2 = 报酬）降序 —— 这就是主动市场"任务主动找到对的 Agent"的兑现。

两侧能力/context 都在 match 内规范化（vocabulary.normalize），所以即便
公告来自没规范化的外部发布方，也能正确对齐（M1 的 announcement 只 strip
未 lowercase，外部 DAO 更可能不一致 —— 故在此防御性归一）。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional

from nth_dao.market.announcement import TaskAnnouncement
from nth_dao.market.subscription import MarketSubscription
from nth_dao.market.vocabulary import normalize_capability

# ── reject reasons（machine-readable）──

REJECT_EXPIRED = "announcement-expired"
REJECT_CAP_INSUFFICIENT = "capability-insufficient"
REJECT_CONTEXT_NOT_SUBSCRIBED = "context-not-subscribed"
REJECT_REWARD_BELOW_FLOOR = "reward-below-floor"
REJECT_PUBLISHER_BELOW_TRUST = "publisher-below-trust-floor"


@dataclass
class MatchResult:
    ok: bool
    reason: str = ""
    score: float = 0.0


@dataclass
class ScoredAnnouncement:
    announcement: TaskAnnouncement
    score: float


@dataclass
class MatchingPollResult:
    """订阅视图的 poll 结果。

    ``matches`` 按 score 降序（高报酬在前）—— 主动市场的"优先推送"。
    ``cursor`` 语义同 ``feed.PollResult.cursor``：已检视的最高 seq（含
    不匹配/过期的，它们被"看过并跳过"，下次不再评估），传回作为下次
    ``since_seq``。
    """

    matches: List[ScoredAnnouncement] = field(default_factory=list)
    cursor: int = -1


def match(
    ann: TaskAnnouncement,
    sub: MarketSubscription,
    *,
    publisher_rep: float = 0.0,
    now_ms_override: int = 0,
) -> MatchResult:
    """判定一条公告是否匹配一个订阅。四维全过才 ok=True。

    Args:
        ann: 任务公告。
        sub: 订阅条件（capabilities/contexts 已在 __post_init__ 规范化）。
        publisher_rep: 发布方在**订阅方本地**的信誉分（约束 D）。M2 默认
            0.0；M5 接 reputation 投影后由调用方传入。
        now_ms_override: 测试用，钉死"现在"。

    Returns:
        MatchResult(ok, reason, score)。
    """
    # 0. 过期的不匹配（双保险：feed.poll 默认已滤，但 match 独立可用）
    if ann.is_expired(now_ms_override):
        return MatchResult(ok=False, reason=REJECT_EXPIRED)

    # 1. 能力子集：公告所需 ⊆ Agent 声明（两侧规范化）
    need = {normalize_capability(c) for c in ann.capability_set}
    need.discard("")
    have = sub.capability_set()  # 已规范化
    if not need <= have:
        return MatchResult(ok=False, reason=REJECT_CAP_INSUFFICIENT)

    # 2. 兴趣 context：空订阅 = 全接；否则公告 context 必须在订阅内
    if sub.contexts:
        ann_ctx = normalize_capability(ann.context)
        if ann_ctx not in sub.contexts:
            return MatchResult(ok=False, reason=REJECT_CONTEXT_NOT_SUBSCRIBED)

    # 3. 经济门槛
    if ann.reward_minor < sub.min_reward_minor:
        return MatchResult(ok=False, reason=REJECT_REWARD_BELOW_FLOOR)

    # 4. 发布方信誉门槛（约束 D：门槛由订阅方定）
    if publisher_rep < sub.publisher_trust_floor:
        return MatchResult(ok=False, reason=REJECT_PUBLISHER_BELOW_TRUST)

    return MatchResult(ok=True, reason="", score=_score(ann, publisher_rep))


def _score(ann: TaskAnnouncement, publisher_rep: float) -> float:
    """匹配质量分（用于排序）。

    M2：可解释、报酬驱动 —— score = 报酬。多条都匹配时，高报酬优先推。
    更复杂的打分（按能力契合度、发布方信誉、新鲜度加权）留到 M5，那时
    有真实信誉数据可校准；现在不引入无法校准的魔法权重（继承交易铁律
    §5.2E"过早的全局公式"教训）。
    """
    return float(ann.reward_minor)


def poll_matching(
    feed: "Any",  # MarketFeed —— 避免 feed↔match 双向 import
    sub: MarketSubscription,
    since_seq: int = -1,
    *,
    rep_lookup: Optional[Callable[[str], float]] = None,
    now_ms_override: int = 0,
) -> MatchingPollResult:
    """订阅视图：poll feed 中游标之后的新公告，只返回匹配的，按 score 降序。

    Args:
        feed: MarketFeed 实例。
        sub: 订阅条件。
        since_seq: 上次游标。
        rep_lookup: did -> 本地信誉分；None = 一律 0.0（M2 默认，无信誉源）。
        now_ms_override: 测试用。

    Returns:
        MatchingPollResult(matches=[ScoredAnnouncement...降序], cursor)。

    游标：复用 feed.poll 的推进语义。poll(include_expired=False) 已把游标
    推过过期/坏行，并返回有效公告；此处把不匹配的过滤掉但**保留 cursor**
    （= 已检视的最高 seq），所以下次不会重复评估已看过的不匹配公告。
    """
    base = feed.poll(
        since_seq, include_expired=False, now_ms_override=now_ms_override,
    )
    scored: List[ScoredAnnouncement] = []
    for ann in base.announcements:
        rep = rep_lookup(ann.publisher_did) if rep_lookup else 0.0
        m = match(ann, sub, publisher_rep=rep, now_ms_override=now_ms_override)
        if m.ok:
            scored.append(ScoredAnnouncement(announcement=ann, score=m.score))
    # 高报酬优先；同分按发布时间升序（先发先得），最后按 id 稳定排序。
    scored.sort(
        key=lambda s: (
            -s.score,
            s.announcement.published_at_ms,
            s.announcement.announcement_id,
        )
    )
    return MatchingPollResult(matches=scored, cursor=base.cursor)
