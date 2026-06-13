"""M1 测试 —— 主动任务市场的持久可订阅 Feed。

退出门槛（开发指导 M1）：
  - Agent 离线期间发布的公告，上线 poll 能补齐；50 条无丢失。

覆盖：
  - 公告签名 round-trip + 篡改检测
  - publish 拒绝验签不过的公告
  - poll 游标语义（since_seq / limit 截断 / FIFO）
  - **C1 核心**：离线补齐，50 条无丢失
  - 过期公告跳过
  - 同毫秒多条不漏（序号游标 vs 时间戳游标）
  - 坏行不卡死游标
"""

from __future__ import annotations

import pytest

from nth_dao.identity import AgentIdentity
from nth_dao.market import (
    MarketFeed,
    TaskAnnouncement,
    sign_announcement,
    verify_announcement,
)

pytest.importorskip("nacl")


# ─── 公告签名 ────────────────────────────────────────────────────


def test_sign_and_verify_round_trip() -> None:
    pub = AgentIdentity.generate(label="publisher")
    ann = sign_announcement(
        publisher=pub,
        title="review PR #42",
        capability_set=["code_review"],
        context="code_review",
        reward_minor=10,
    )
    assert ann.publisher_did == pub.as_did()
    assert ann.capability_set == ["code_review"]
    ok, reason = verify_announcement(ann)
    assert ok, reason


def test_verify_detects_tampered_title() -> None:
    pub = AgentIdentity.generate(label="publisher")
    ann = sign_announcement(publisher=pub, title="cheap task", reward_minor=1)
    # 篡改正文 —— 签名应当失效。
    ann.title = "expensive task"
    ok, reason = verify_announcement(ann)
    assert not ok
    assert reason == "ann-sig-invalid"


def test_verify_detects_tampered_reward() -> None:
    pub = AgentIdentity.generate(label="publisher")
    ann = sign_announcement(publisher=pub, title="t", reward_minor=5)
    ann.reward_minor = 5_000_000  # 偷偷加价
    ok, reason = verify_announcement(ann)
    assert not ok
    assert reason == "ann-sig-invalid"


def test_verify_rejects_whitespace_only_required_field() -> None:
    """独立审查回归 (M4 R2)：必填字段为纯空白串也算缺失。``not val``
    会漏判 "   "（not "   " 为 False），改用按字符串语义判空后必拒。"""
    pub = AgentIdentity.generate(label="publisher")
    ann = sign_announcement(publisher=pub, title="real", reward_minor=1)
    ann.title = "   "   # 纯空格 —— 应判缺失
    ok, reason = verify_announcement(ann)
    assert not ok
    assert reason == "ann-missing-field"
    # 空串同理
    ann2 = sign_announcement(publisher=pub, title="real2", reward_minor=1)
    ann2.publisher_sig = ""
    ok2, reason2 = verify_announcement(ann2)
    assert not ok2
    assert reason2 == "ann-missing-field"


def test_capability_set_is_sorted_and_deduped() -> None:
    pub = AgentIdentity.generate(label="publisher")
    ann = sign_announcement(
        publisher=pub, title="t",
        capability_set=["write_docs", "code_review", "code_review", " bug_fix "],
    )
    # 去重 + strip + 排序，让 canonical body 稳定。
    assert ann.capability_set == ["bug_fix", "code_review", "write_docs"]
    ok, _ = verify_announcement(ann)
    assert ok


def test_sign_rejects_float_reward() -> None:
    pub = AgentIdentity.generate(label="publisher")
    with pytest.raises(ValueError, match="minor units"):
        sign_announcement(publisher=pub, title="t", reward_minor=1.5)  # type: ignore[arg-type]


def test_sign_rejects_bool_reward() -> None:
    # bool 是 int 子类 —— reward_minor=True 不该静默当 1。
    pub = AgentIdentity.generate(label="publisher")
    with pytest.raises(ValueError, match="non-bool int"):
        sign_announcement(publisher=pub, title="t", reward_minor=True)  # type: ignore[arg-type]


def test_sign_rejects_empty_title() -> None:
    pub = AgentIdentity.generate(label="publisher")
    with pytest.raises(ValueError, match="non-empty"):
        sign_announcement(publisher=pub, title="   ")


# ─── Feed publish ────────────────────────────────────────────────


def test_publish_rejects_unverifiable(tmp_path) -> None:
    feed = MarketFeed(tmp_path)
    # 手工造一条没签名的公告 —— publish 必须拒绝，feed 不被污染。
    bad = TaskAnnouncement(
        announcement_id="x", publisher_did="did:key:zBad",
        title="forged", publisher_sig="",
    )
    with pytest.raises(ValueError, match="unverifiable"):
        feed.publish(bad)
    assert feed.latest_seq() == -1  # feed 仍为空


def test_publish_then_poll_returns_it(tmp_path) -> None:
    feed = MarketFeed(tmp_path)
    pub = AgentIdentity.generate(label="publisher")
    ann = sign_announcement(publisher=pub, title="task A", reward_minor=3)
    feed.publish(ann)

    res = feed.poll(since_seq=-1)
    assert len(res.announcements) == 1
    assert res.announcements[0].title == "task A"
    assert res.cursor == 0


# ─── C1 核心：离线补齐，50 条无丢失 ─────────────────────────────


def test_offline_agent_catches_up_no_loss(tmp_path) -> None:
    """C1 回归：Agent 离线期间发布的公告，上线后用旧游标 poll 能补齐。

    模拟：
      1. Agent 先 poll 一次（cursor=-1 → 空 feed），记下 cursor。
      2. Agent "离线"期间，发布方连发 50 条。
      3. Agent "上线"，用步骤 1 的旧 cursor 再 poll —— 必须拿到全部 50 条,
         顺序正确，无重复无丢失。
    """
    feed = MarketFeed(tmp_path)
    pub = AgentIdentity.generate(label="publisher")

    # 1. 上线初探：空 feed
    first = feed.poll(since_seq=-1)
    assert first.announcements == []
    cursor = first.cursor  # -1

    # 2. 离线期间发布 50 条
    titles = [f"task-{i:02d}" for i in range(50)]
    for t in titles:
        feed.publish(sign_announcement(publisher=pub, title=t, reward_minor=1))

    # 3. 用旧游标补齐
    caught = feed.poll(since_seq=cursor)
    got_titles = [a.title for a in caught.announcements]
    assert got_titles == titles, "离线补齐必须按 FIFO 顺序拿到全部 50 条，无丢失"
    assert caught.cursor == 49

    # 4. 再 poll 一次（已无新）—— 空，游标不动
    again = feed.poll(since_seq=caught.cursor)
    assert again.announcements == []
    assert again.cursor == 49


def test_incremental_poll_no_duplicates(tmp_path) -> None:
    """增量 poll：每次只拿新的，不重复。"""
    feed = MarketFeed(tmp_path)
    pub = AgentIdentity.generate(label="publisher")

    feed.publish(sign_announcement(publisher=pub, title="a", reward_minor=1))
    r1 = feed.poll(since_seq=-1)
    assert [a.title for a in r1.announcements] == ["a"]

    feed.publish(sign_announcement(publisher=pub, title="b", reward_minor=1))
    r2 = feed.poll(since_seq=r1.cursor)
    assert [a.title for a in r2.announcements] == ["b"]  # 不含 a


def test_poll_limit_truncates_and_cursor_resumes(tmp_path) -> None:
    """limit 截断时，cursor 停在已返回末尾，下次从未读处继续。"""
    feed = MarketFeed(tmp_path)
    pub = AgentIdentity.generate(label="publisher")
    for i in range(5):
        feed.publish(sign_announcement(publisher=pub, title=f"t{i}", reward_minor=1))

    r1 = feed.poll(since_seq=-1, limit=2)
    assert [a.title for a in r1.announcements] == ["t0", "t1"]
    assert r1.cursor == 1  # 停在 t1，不跳过 t2..t4

    r2 = feed.poll(since_seq=r1.cursor, limit=2)
    assert [a.title for a in r2.announcements] == ["t2", "t3"]
    assert r2.cursor == 3

    r3 = feed.poll(since_seq=r2.cursor)
    assert [a.title for a in r3.announcements] == ["t4"]


# ─── 过期 / 同毫秒 / 坏行 ────────────────────────────────────────


def test_poll_skips_expired(tmp_path) -> None:
    feed = MarketFeed(tmp_path)
    pub = AgentIdentity.generate(label="publisher")
    # not_after 在过去 → 过期
    feed.publish(sign_announcement(
        publisher=pub, title="stale", reward_minor=1,
        published_at_ms=1000, not_after=2000,
    ))
    feed.publish(sign_announcement(
        publisher=pub, title="fresh", reward_minor=1,
        published_at_ms=1000, not_after=0,  # 不过期
    ))
    # now=5000：stale 已过期
    res = feed.poll(since_seq=-1, now_ms_override=5000)
    assert [a.title for a in res.announcements] == ["fresh"]
    # 但 cursor 推进过 stale，下次不会再尝试它
    assert res.cursor == 1

    # include_expired=True 时两条都返回
    res2 = feed.poll(since_seq=-1, include_expired=True, now_ms_override=5000)
    assert [a.title for a in res2.announcements] == ["stale", "fresh"]


def test_same_millisecond_announcements_not_lost(tmp_path) -> None:
    """序号游标的关键优势：同毫秒发布的多条公告不会因时间戳游标而漏掉。"""
    feed = MarketFeed(tmp_path)
    pub = AgentIdentity.generate(label="publisher")
    # 三条公告同一 published_at_ms —— 时间戳游标会漏，序号游标不会
    for t in ["x", "y", "z"]:
        feed.publish(sign_announcement(
            publisher=pub, title=t, reward_minor=1, published_at_ms=7777,
        ))
    res = feed.poll(since_seq=-1)
    assert [a.title for a in res.announcements] == ["x", "y", "z"]


def test_corrupt_line_does_not_stall_cursor(tmp_path) -> None:
    """坏行不能让 poll 卡死 —— 游标必须能跨过它继续。"""
    feed = MarketFeed(tmp_path)
    pub = AgentIdentity.generate(label="publisher")
    feed.publish(sign_announcement(publisher=pub, title="good1", reward_minor=1))
    # 手工往日志塞一行垃圾
    with open(feed.log_path, "a", encoding="utf-8") as f:
        f.write("{ this is not valid json\n")
    feed.publish(sign_announcement(publisher=pub, title="good2", reward_minor=1))

    res = feed.poll(since_seq=-1)
    # 坏行被丢弃，但前后两条好公告都拿到，且顺序正确
    assert [a.title for a in res.announcements] == ["good1", "good2"]
    assert res.cursor == 2  # 跨过了 seq=1 的坏行


def test_unicode_line_separator_in_title_not_lost(tmp_path) -> None:
    """独立审查回归：标题/正文含 Unicode 行分隔符（U+2028 等）的公告
    必须能 publish→poll 无损。

    根因：safe_append_jsonl 用 ensure_ascii=False 落盘，json.dumps 只
    转义 \\n/\\r，不转义 U+2028/U+2029/U+0085 等。若 _read_all 用
    str.splitlines()（会在这些字符断行），含 U+2028 的公告会被切两半、
    解析失败、永久丢失，违反 C1。修复后用 split("\\n") 切行。
    """
    feed = MarketFeed(tmp_path)
    pub = AgentIdentity.generate(label="publisher")
    # 标题里嵌入 U+2028(LINE SEP) / U+2029(PARA SEP) / U+0085(NEL)
    nasty = "线上任务 第二段 第三段第四段"
    feed.publish(sign_announcement(publisher=pub, title=nasty, reward_minor=1))
    feed.publish(sign_announcement(publisher=pub, title="normal", reward_minor=1))

    res = feed.poll(since_seq=-1)
    titles = [a.title for a in res.announcements]
    assert nasty in titles, "含 U+2028 的公告不能丢（C1）"
    assert "normal" in titles
    assert len(res.announcements) == 2
    assert res.cursor == 1  # 恰好两条记录，seq 与记录数对齐


def test_latest_seq_aligns_with_record_count(tmp_path) -> None:
    """独立审查回归：latest_seq 必须等于"真实记录数-1"，不被末尾
    换行产生的空串拉高（split("\\n") 的 trailing-empty 必须丢弃）。
    """
    feed = MarketFeed(tmp_path)
    pub = AgentIdentity.generate(label="publisher")
    assert feed.latest_seq() == -1
    feed.publish(sign_announcement(publisher=pub, title="one", reward_minor=1))
    assert feed.latest_seq() == 0  # 一条记录 → seq 0（不是 1）
    feed.publish(sign_announcement(publisher=pub, title="two", reward_minor=1))
    assert feed.latest_seq() == 1


def test_post_publish_tampering_dropped_on_poll(tmp_path) -> None:
    """落盘后被篡改的公告，poll 时验签不过被丢弃（防绕过 publish 直接写文件）。"""
    feed = MarketFeed(tmp_path)
    pub = AgentIdentity.generate(label="publisher")
    ann = sign_announcement(publisher=pub, title="legit", reward_minor=1)
    feed.publish(ann)

    # 直接改日志文件里的 reward —— 模拟落盘后篡改
    import json
    line = json.loads(feed.log_path.read_text(encoding="utf-8").strip())
    line["reward_minor"] = 999999
    feed.log_path.write_text(json.dumps(line) + "\n", encoding="utf-8")

    res = feed.poll(since_seq=-1)
    assert res.announcements == []  # 篡改的被丢弃
    assert res.cursor == 0  # 但游标推进过它
