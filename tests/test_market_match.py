"""M2 测试 —— 能力∩兴趣订阅过滤（修 C2/C3）。

退出门槛（开发指导 M2）：
  - 一条公告只推给"能力覆盖且兴趣匹配"的 Agent；
  - match 纯函数全边界测试绿。

覆盖：
  - vocabulary 规范化（C3 的根：写法收敛）
  - subscription __post_init__ 规范化 + 去重
  - match 四维各正反例（能力子集 / context / reward / trust）+ 过期
  - poll_matching 组合器：只返回匹配、按 score 降序、游标推进
"""

from __future__ import annotations

import pytest

from nth_dao.identity import AgentIdentity
from nth_dao.market import (
    MarketFeed,
    MarketSubscription,
    match,
    poll_matching,
    sign_announcement,
    vocabulary,
    REJECT_CAP_INSUFFICIENT,
    REJECT_CONTEXT_NOT_SUBSCRIBED,
    REJECT_REWARD_BELOW_FLOOR,
    REJECT_PUBLISHER_BELOW_TRUST,
    REJECT_EXPIRED,
)

pytest.importorskip("nacl")


# ─── vocabulary 规范化（C3 根因） ───────────────────────────────


def test_normalize_capability_folds_variants() -> None:
    n = vocabulary.normalize_capability
    assert n("  Code Review ") == "code_review"
    assert n("bug-fix") == "bug_fix"
    assert n("RESEARCH") == "research"
    assert n("write__docs") == "write_docs"   # 折叠多下划线
    assert n("--deploy--") == "deploy"        # strip 边缘分隔
    assert n("") == ""
    assert n(123) == ""                        # 非字符串 → 空


def test_validate_capability_shape() -> None:
    ok, _ = vocabulary.validate_capability("code_review")
    assert ok
    ok, reason = vocabulary.validate_capability("")
    assert not ok and reason == vocabulary.REJECT_CAP_EMPTY
    ok, reason = vocabulary.validate_capability("bad:colon")
    assert not ok and reason == vocabulary.REJECT_CAP_BAD_SHAPE  # 冒号留给协议能力


def test_is_known_skill() -> None:
    assert vocabulary.is_known_skill("Code Review")   # 规范化后命中
    assert vocabulary.is_known_skill("test_execution")
    assert not vocabulary.is_known_skill("frobnicate")  # 未在册但不报错


# ─── subscription 规范化 ─────────────────────────────────────────


def test_subscription_normalizes_and_dedups() -> None:
    sub = MarketSubscription(
        subscriber_did="did:key:zSub",
        capabilities=["Code Review", "code_review", "bug-fix"],
        contexts=["Research", "research"],
    )
    assert sub.capabilities == ["bug_fix", "code_review"]   # 去重 + 排序
    assert sub.contexts == ["research"]                      # 去重
    assert sub.max_concurrent == 1


def test_subscription_clamps_bad_concurrent() -> None:
    sub = MarketSubscription(
        subscriber_did="did:key:zSub", capabilities=["x"], max_concurrent=0,
    )
    assert sub.max_concurrent == 1   # 0/负数无意义 → 夹到 1


# ─── match 四维 ──────────────────────────────────────────────────


def _ann(pub, **kw):
    return sign_announcement(publisher=pub, title=kw.pop("title", "t"), **kw)


def test_match_capability_subset_ok() -> None:
    pub = AgentIdentity.generate(label="p")
    ann = _ann(pub, capability_set=["code_review"], reward_minor=5)
    sub = MarketSubscription(
        subscriber_did="did:key:zS",
        capabilities=["code_review", "bug_fix"],  # 超集 → 覆盖
    )
    r = match(ann, sub)
    assert r.ok, r.reason
    assert r.score == 5.0


def test_match_capability_insufficient() -> None:
    pub = AgentIdentity.generate(label="p")
    ann = _ann(pub, capability_set=["code_review", "deploy"], reward_minor=5)
    sub = MarketSubscription(
        subscriber_did="did:key:zS",
        capabilities=["code_review"],  # 缺 deploy
    )
    r = match(ann, sub)
    assert not r.ok
    assert r.reason == REJECT_CAP_INSUFFICIENT


def test_match_capability_normalizes_both_sides() -> None:
    """C3 核心：公告侧写 'Code Review'（未规范化的外部发布方），订阅侧
    写 'code_review'，仍应匹配 —— match 内部两侧都归一。"""
    pub = AgentIdentity.generate(label="p")
    # sign_announcement 只 strip 不 lowercase，模拟外部不规范发布方：
    # 直接构造一个 capability_set 含大小写混写
    ann = _ann(pub, capability_set=["Code_Review"], reward_minor=1)
    # 注意 sign_announcement 会 strip+dedup+sort 但不 lowercase，
    # 所以存的是 "Code_Review"
    assert ann.capability_set == ["Code_Review"]
    sub = MarketSubscription(
        subscriber_did="did:key:zS", capabilities=["code review"],
    )
    r = match(ann, sub)
    assert r.ok, "match 必须两侧规范化后对齐（修 C3）"


def test_match_context_not_subscribed() -> None:
    pub = AgentIdentity.generate(label="p")
    ann = _ann(pub, capability_set=["x"], context="deploy", reward_minor=1)
    sub = MarketSubscription(
        subscriber_did="did:key:zS", capabilities=["x"],
        contexts=["code_review"],  # 只接 code_review
    )
    r = match(ann, sub)
    assert not r.ok
    assert r.reason == REJECT_CONTEXT_NOT_SUBSCRIBED


def test_context_defaults_to_primary_capability() -> None:
    """独立审查回归 (M2 R1)：未显式设 context 时，类别从主能力派生，
    而非恒为 'general'。否则 capability_set=['code_review'] 但漏设
    context 的公告会被 contexts=['code_review'] 的订阅挡掉（能干却
    看不见）—— 真实 footgun。"""
    pub = AgentIdentity.generate(label="p")
    ann = _ann(pub, capability_set=["code_review"], reward_minor=1)
    assert ann.context == "code_review"   # 派生自主能力，不是 'general'

    sub = MarketSubscription(
        subscriber_did="did:key:zS",
        capabilities=["code_review"],
        contexts=["code_review"],
    )
    assert match(ann, sub).ok, "能干 code_review 的订阅必须看见 code_review 任务"


def test_explicit_context_overrides_capability_default() -> None:
    """显式 context 永远优先于能力派生。"""
    pub = AgentIdentity.generate(label="p")
    ann = _ann(pub, capability_set=["code_review"], context="urgent_review",
               reward_minor=1)
    assert ann.context == "urgent_review"


def test_no_capability_falls_back_to_general() -> None:
    """无能力且无显式 context → 回落 'general'（保持旧默认行为）。"""
    pub = AgentIdentity.generate(label="p")
    ann = _ann(pub, reward_minor=1)  # 无 capability_set，无 context
    assert ann.context == "general"


def test_match_empty_contexts_accepts_any() -> None:
    pub = AgentIdentity.generate(label="p")
    ann = _ann(pub, capability_set=["x"], context="anything", reward_minor=1)
    sub = MarketSubscription(
        subscriber_did="did:key:zS", capabilities=["x"], contexts=[],
    )
    assert match(ann, sub).ok   # 空 contexts = 全接


def test_match_reward_below_floor() -> None:
    pub = AgentIdentity.generate(label="p")
    ann = _ann(pub, capability_set=["x"], reward_minor=3)
    sub = MarketSubscription(
        subscriber_did="did:key:zS", capabilities=["x"], min_reward_minor=5,
    )
    r = match(ann, sub)
    assert not r.ok
    assert r.reason == REJECT_REWARD_BELOW_FLOOR


def test_match_publisher_below_trust() -> None:
    pub = AgentIdentity.generate(label="p")
    ann = _ann(pub, capability_set=["x"], reward_minor=5)
    sub = MarketSubscription(
        subscriber_did="did:key:zS", capabilities=["x"],
        publisher_trust_floor=3.0,
    )
    # 信誉 2.0 < 门槛 3.0
    r = match(ann, sub, publisher_rep=2.0)
    assert not r.ok
    assert r.reason == REJECT_PUBLISHER_BELOW_TRUST
    # 信誉 4.0 ≥ 门槛 → 过
    assert match(ann, sub, publisher_rep=4.0).ok


def test_match_expired_announcement() -> None:
    pub = AgentIdentity.generate(label="p")
    ann = _ann(
        pub, capability_set=["x"], reward_minor=5,
        published_at_ms=1000, not_after=2000,
    )
    sub = MarketSubscription(subscriber_did="did:key:zS", capabilities=["x"])
    r = match(ann, sub, now_ms_override=5000)
    assert not r.ok
    assert r.reason == REJECT_EXPIRED


# ─── poll_matching 组合器（M2 退出门槛） ────────────────────────


def test_poll_matching_only_returns_matches(tmp_path) -> None:
    """退出门槛：一条公告只推给能力覆盖且兴趣匹配的订阅。"""
    feed = MarketFeed(tmp_path)
    pub = AgentIdentity.generate(label="p")

    # 三条公告：能匹配 / 能力不足 / 报酬太低
    feed.publish(_ann(pub, title="match-me", capability_set=["code_review"],
                      context="code_review", reward_minor=10))
    feed.publish(_ann(pub, title="cap-short", capability_set=["deploy"],
                      context="code_review", reward_minor=10))
    feed.publish(_ann(pub, title="too-cheap", capability_set=["code_review"],
                      context="code_review", reward_minor=1))

    sub = MarketSubscription(
        subscriber_did="did:key:zS",
        capabilities=["code_review"],     # 不含 deploy
        contexts=["code_review"],
        min_reward_minor=5,               # 排除 too-cheap
    )
    res = poll_matching(feed, sub)
    titles = [s.announcement.title for s in res.matches]
    assert titles == ["match-me"], "只应推送唯一匹配的那条"
    assert res.cursor == 2   # 游标推过全部三条（含不匹配的）


def test_poll_matching_sorts_by_score_desc(tmp_path) -> None:
    """多条匹配时按 score（报酬）降序 —— 主动市场的优先推送。"""
    feed = MarketFeed(tmp_path)
    pub = AgentIdentity.generate(label="p")
    feed.publish(_ann(pub, title="low", capability_set=["x"], reward_minor=3))
    feed.publish(_ann(pub, title="high", capability_set=["x"], reward_minor=20))
    feed.publish(_ann(pub, title="mid", capability_set=["x"], reward_minor=10))

    sub = MarketSubscription(subscriber_did="did:key:zS", capabilities=["x"])
    res = poll_matching(feed, sub)
    assert [s.announcement.title for s in res.matches] == ["high", "mid", "low"]
    assert [s.score for s in res.matches] == [20.0, 10.0, 3.0]


def test_poll_matching_cursor_advances_past_nonmatching(tmp_path) -> None:
    """游标推过不匹配的公告 —— 下次 poll 不重复评估它们。"""
    feed = MarketFeed(tmp_path)
    pub = AgentIdentity.generate(label="p")
    feed.publish(_ann(pub, title="nope", capability_set=["deploy"], reward_minor=5))
    sub = MarketSubscription(subscriber_did="did:key:zS", capabilities=["x"])

    r1 = poll_matching(feed, sub)
    assert r1.matches == []
    assert r1.cursor == 0   # 看过 seq0（不匹配），游标推进

    # 再发一条匹配的；用上次游标 poll，只拿新的
    feed.publish(_ann(pub, title="yes", capability_set=["x"], reward_minor=5))
    r2 = poll_matching(feed, sub, since_seq=r1.cursor)
    assert [s.announcement.title for s in r2.matches] == ["yes"]


def test_poll_matching_uses_rep_lookup(tmp_path) -> None:
    """rep_lookup 注入发布方信誉，参与 trust 门槛判定（约束 D 接口）。"""
    feed = MarketFeed(tmp_path)
    pub = AgentIdentity.generate(label="p")
    feed.publish(_ann(pub, title="t", capability_set=["x"], reward_minor=5))
    sub = MarketSubscription(
        subscriber_did="did:key:zS", capabilities=["x"],
        publisher_trust_floor=3.0,
    )
    # 信誉源说该发布方 1.0 < 门槛 → 不匹配
    res_low = poll_matching(feed, sub, rep_lookup=lambda did: 1.0)
    assert res_low.matches == []
    # 信誉源说 5.0 ≥ 门槛 → 匹配
    res_hi = poll_matching(feed, sub, rep_lookup=lambda did: 5.0)
    assert [s.announcement.title for s in res_hi.matches] == ["t"]
