"""M4 测试 —— 跨 DAO 联邦（约束 C：无中心索引）。

退出门槛（开发指导 M4）：
  - DAO-A 公告，DAO-B Agent 能发现、能 poll、能认领；无中心索引。

覆盖：
  - digest 构建 + 签名 round-trip + 篡改检测
  - match_digest_refs 复用 M2 四维匹配
  - **退出门槛 E2E**：A 发布 → digest 传 B → B 匹配 → 拉全文验签 →
    回 A 主权威认领
  - 信任模型：digest 里塞假 ref，拉全文时 publisher_sig 验不过被丢
  - 中继审查（丢公告）可行、伪造不可行
  - 多源 digest 去重
"""

from __future__ import annotations

import pytest

from nth_dao.b64u import b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.cap_token import sign_cap_token, CAP_NTH_RECEIPT_SIGN
from nth_dao.execution_receipt import verify_receipt
from nth_dao.identity import AgentIdentity
from nth_dao.market import (
    MarketFeed,
    ClaimStore,
    MarketSubscription,
    claim_announcement,
    sign_announcement,
    build_digest,
    verify_digest,
    match_digest_refs,
    merge_digest_refs,
    pull_announcements,
    verify_announcement,
    FeedDigest,
    REJECT_DIGEST_SIG_INVALID,
    REJECT_DIGEST_BAD_SOURCE_DID,
)

pytest.importorskip("nacl")


def _pub(feed, publisher, **kw):
    ann = sign_announcement(
        publisher=publisher, title=kw.pop("title", "task"),
        capability_set=kw.pop("caps", ["code_review"]),
        reward_minor=kw.pop("reward", 10), **kw,
    )
    feed.publish(ann)
    return ann


# ─── digest 构建 + 验证 ─────────────────────────────────────────


def test_build_and_verify_digest(tmp_path) -> None:
    feed = MarketFeed(tmp_path / "A")
    dao_a = AgentIdentity.generate(label="dao-A")
    pub = AgentIdentity.generate(label="pub")
    _pub(feed, pub, title="t1", caps=["code_review"])
    _pub(feed, pub, title="t2", caps=["research"])

    digest = build_digest(feed, dao_a)
    assert digest.source_did == dao_a.as_did()
    assert len(digest.refs) == 2
    # ref 只带匹配字段，不带 input_schema/acceptance
    assert "input_schema" not in digest.refs[0]
    assert "capability_set" in digest.refs[0]
    ok, reason = verify_digest(digest)
    assert ok, reason


def test_verify_digest_detects_tampered_ref(tmp_path) -> None:
    """digest 落地后被改 ref（比如偷偷加 reward）→ source 签名失效。"""
    feed = MarketFeed(tmp_path / "A")
    dao_a = AgentIdentity.generate(label="dao-A")
    pub = AgentIdentity.generate(label="pub")
    _pub(feed, pub, reward=5)
    digest = build_digest(feed, dao_a)
    digest.refs[0]["reward_minor"] = 999999  # 篡改
    ok, reason = verify_digest(digest)
    assert not ok
    assert reason == REJECT_DIGEST_SIG_INVALID


def test_verify_digest_rejects_bad_source(tmp_path) -> None:
    feed = MarketFeed(tmp_path / "A")
    dao_a = AgentIdentity.generate(label="dao-A")
    pub = AgentIdentity.generate(label="pub")
    _pub(feed, pub)
    digest = build_digest(feed, dao_a)
    digest.source_did = "not-a-did"
    ok, reason = verify_digest(digest)
    assert not ok
    assert reason == REJECT_DIGEST_BAD_SOURCE_DID


def test_digest_dict_roundtrip(tmp_path) -> None:
    feed = MarketFeed(tmp_path / "A")
    dao_a = AgentIdentity.generate(label="dao-A")
    pub = AgentIdentity.generate(label="pub")
    _pub(feed, pub)
    digest = build_digest(feed, dao_a)
    # 模拟 gossip：序列化→反序列化后仍可验
    restored = FeedDigest.from_dict(digest.to_dict())
    ok, _ = verify_digest(restored)
    assert ok


# ─── 退出门槛：跨 DAO 发现 + 认领 ──────────────────────────────


def test_cross_dao_discover_and_claim_at_home_authority(tmp_path) -> None:
    """M4 退出门槛 E2E。

    DAO-A 发布 → 生成 digest → "传"给 DAO-B（直接传对象，模拟 gossip）
    → DAO-B 的 Agent 匹配 ref → 拉全文验签 → 回 DAO-A 主权威认领。
    全程无第三方中心索引。
    """
    # —— DAO-A：发布方 + 主 feed + 主 claim 权威 ——
    feed_a = MarketFeed(tmp_path / "A")
    store_a = ClaimStore(tmp_path / "A")
    dao_a = AgentIdentity.generate(label="dao-A")
    publisher = AgentIdentity.generate(label="publisher")
    issuer = AgentIdentity.generate(label="issuer")   # 给 B 的 Agent 授权的 issuer
    ann = _pub(feed_a, publisher, title="review-this", caps=["code_review"], reward=10)

    # —— DAO-A 生成签名 digest（要广播的东西）——
    digest = build_digest(feed_a, dao_a)

    # —— 传输：digest 直达 DAO-B（无中心索引；这里直接传对象）——
    received = FeedDigest.from_dict(digest.to_dict())

    # —— DAO-B：Agent 验 digest provenance → 匹配 → 决定拉哪些 ——
    agent_b = AgentIdentity.generate(label="agent-B")
    ok, _ = verify_digest(received)
    assert ok, "digest provenance 必须可验"
    sub = MarketSubscription(
        subscriber_did=agent_b.as_did(), capabilities=["code_review"],
    )
    hits = match_digest_refs(received, sub)
    assert len(hits) == 1, "B 应在 A 的 digest 里发现这条 code_review 任务"
    want_ids = [r["announcement_id"] for r in hits]

    # —— 按需拉全文（主 DAO serve 侧）+ 验签 ——
    pulled = pull_announcements(feed_a, want_ids)
    assert len(pulled) == 1
    full = pulled[0]
    assert verify_announcement(full)[0], "拉回的全文必须 publisher_sig 自验"
    assert full.announcement_id == ann.announcement_id

    # —— 回 DAO-A 主权威认领（跨机 CAS 难题的解：主 DAO 仲裁）——
    token = sign_cap_token(
        issuer=issuer, subject_did=agent_b.as_did(),
        capabilities=["code_review", CAP_NTH_RECEIPT_SIGN],
    )
    out = claim_announcement(
        feed_a, store_a, full.announcement_id,
        claimant=agent_b, cap_token=token,
    )
    assert verify_receipt(out.receipt), "跨 DAO 认领的收据可独立验签"
    assert out.claim_record["claimant_did"] == agent_b.as_did()
    # 认领落在 A 的权威 store
    assert store_a.is_claimed(ann.announcement_id)


# ─── 信任模型：digest 不可信，全文验签是真相 ──────────────────


def test_forged_ref_in_digest_dropped_on_pull(tmp_path) -> None:
    """恶意/错误 source 在 digest 里塞一个 feed 里根本不存在的 ref。
    匹配可能命中，但 pull 时源 feed 没有这条 → 被丢。digest 是提示，
    全文（或其不存在）才是真相。"""
    feed_a = MarketFeed(tmp_path / "A")
    dao_a = AgentIdentity.generate(label="dao-A")
    pub = AgentIdentity.generate(label="pub")
    _pub(feed_a, pub, title="real", caps=["code_review"])

    digest = build_digest(feed_a, dao_a)
    # source 往自己的 digest 里加一条假 ref（指向不存在的公告）
    digest.refs.append({
        "announcement_id": "ghost-id",
        "publisher_did": pub.as_did(),
        "capability_set": ["code_review"],
        "context": "code_review",
        "reward_minor": 100,
        "reward_asset": "credit",
        "published_at_ms": 1,
        "not_after": 0,
    })
    # 重签（source 确实签了含假 ref 的 digest —— provenance 成立）
    digest.digest_sig = b64u_encode(dao_a.sign(canonical_json(digest.signing_body())))
    assert verify_digest(digest)[0]   # provenance 仍 ok（确实是 A 签的）

    sub = MarketSubscription(subscriber_did="did:key:zB", capabilities=["code_review"])
    hits = match_digest_refs(digest, sub)
    ids = [r["announcement_id"] for r in hits]
    assert "ghost-id" in ids   # 假 ref 匹配上了（digest 不可信）
    # 但拉全文时，ghost-id 在源 feed 不存在 → 被丢
    pulled = pull_announcements(feed_a, ids)
    pulled_ids = [a.announcement_id for a in pulled]
    assert "ghost-id" not in pulled_ids   # 假的被全文层丢弃
    assert len(pulled) == 1                # 只剩真的那条


def test_malicious_ref_types_do_not_crash_consumer(tmp_path) -> None:
    """独立审查回归 (M4 R2)：恶意 source 签名推送类型错乱的 ref
    （reward_minor="abc" / capability_set=int / not_after=str）→ 消费方
    match_digest_refs 必须**不崩**（联邦信任模型：digest 不可信，解析要
    类型安全，绝不裸 int()/list()）。坏类型静默回退，全文层再兜底。"""
    feed_a = MarketFeed(tmp_path / "A")
    dao_a = AgentIdentity.generate(label="dao-A")
    pub = AgentIdentity.generate(label="pub")
    _pub(feed_a, pub, title="real", caps=["code_review"])
    digest = build_digest(feed_a, dao_a)
    # source 把字段类型搞乱，再重签（provenance 成立）
    digest.refs[0]["reward_minor"] = "abc"
    digest.refs[0]["capability_set"] = 12345
    digest.refs[0]["not_after"] = "soon"
    digest.refs[0]["published_at_ms"] = {"nested": "junk"}
    digest.digest_sig = b64u_encode(dao_a.sign(canonical_json(digest.signing_body())))
    assert verify_digest(digest)[0]   # 确实是 A 签的
    sub = MarketSubscription(subscriber_did="did:key:zB", capabilities=["code_review"])
    # 不崩即过（结果不重要，关键是 TypeError/ValueError 不抛出来）
    hits = match_digest_refs(digest, sub)
    assert isinstance(hits, list)


def test_relay_can_censor_cannot_forge(tmp_path) -> None:
    """中继能丢公告（审查）但不能伪造：篡改 ref 后 digest 验签失败。"""
    feed_a = MarketFeed(tmp_path / "A")
    dao_a = AgentIdentity.generate(label="dao-A")
    pub = AgentIdentity.generate(label="pub")
    _pub(feed_a, pub, title="a", caps=["code_review"])
    _pub(feed_a, pub, title="b", caps=["research"])
    digest = build_digest(feed_a, dao_a)

    # 中继审查：删掉一条 ref（不重签）→ 签名失效，下游能察觉被动过
    censored = FeedDigest.from_dict(digest.to_dict())
    censored.refs = censored.refs[:1]
    assert not verify_digest(censored)[0], "删 ref 不重签 → 验签失败，篡改可见"

    # 中继若想伪造一条 → 同样验签失败（无 A 的私钥重签不了）
    forged = FeedDigest.from_dict(digest.to_dict())
    forged.refs[0]["reward_minor"] = 1
    assert not verify_digest(forged)[0]


# ─── 多源去重 ────────────────────────────────────────────────────


def test_merge_digest_refs_dedups(tmp_path) -> None:
    """同一公告经两个中继到达 → 合并后去重一份。"""
    feed_a = MarketFeed(tmp_path / "A")
    dao_a = AgentIdentity.generate(label="dao-A")
    pub = AgentIdentity.generate(label="pub")
    _pub(feed_a, pub, title="shared", caps=["code_review"])
    d1 = build_digest(feed_a, dao_a)
    # 第二个"中继"转发同一份 digest（相同 ann）
    d2 = FeedDigest.from_dict(d1.to_dict())
    merged = merge_digest_refs([d1, d2])
    assert len(merged) == 1   # 去重
