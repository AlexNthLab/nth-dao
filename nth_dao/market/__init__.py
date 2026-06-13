"""Nth DAO 主动任务市场（active task marketplace）。

设计与里程碑见桌面文档 `Nth-DAO-主动任务市场-开发指导.md`。

内核四元组：Announce → Feed → Match → Claim。

本包不取代 ``nth_dao.marketplace``（claim/submit/accept 状态机 +
credits），而是在其旁边补齐"主动市场"缺的部分：

  M1 ✅  durable 可订阅 Feed —— 修 C1（fire-and-forget → 离线丢任务）
  M2 ✅  能力∩兴趣订阅过滤 —— 修 C2/C3
  M3 ✅  原子认领 + cap_token + receipt —— 修 C4 + 签名
  M4 ✅  跨 DAO 联邦（FeedDigest + 按需拉全文，无中心索引）
  M5 ⏳  Mission 关联 + 可解释信誉

暴露（按里程碑）：
  M1  TaskAnnouncement / sign_announcement / verify_announcement /
      MarketFeed（publish + poll + get）
  M2  MarketSubscription / match / poll_matching / vocabulary
  M3  claim_announcement / ClaimStore / ClaimOutcome
  M4  FeedDigest / build_digest / verify_digest / match_digest_refs /
      merge_digest_refs / pull_announcements
"""

from nth_dao.market.announcement import (
    TaskAnnouncement,
    sign_announcement,
    verify_announcement,
    REJECT_ANN_MISSING_FIELD,
    REJECT_ANN_BAD_PUBLISHER_DID,
    REJECT_ANN_SIG_INVALID,
    REJECT_ANN_SIG_DECODE_FAILED,
    REJECT_ANN_CRYPTO_UNAVAILABLE,
)
from nth_dao.market.feed import MarketFeed, PollResult
from nth_dao.market.subscription import MarketSubscription
from nth_dao.market.match import (
    match,
    poll_matching,
    MatchResult,
    ScoredAnnouncement,
    MatchingPollResult,
    REJECT_EXPIRED,
    REJECT_CAP_INSUFFICIENT,
    REJECT_CONTEXT_NOT_SUBSCRIBED,
    REJECT_REWARD_BELOW_FLOOR,
    REJECT_PUBLISHER_BELOW_TRUST,
)
from nth_dao.market import vocabulary
from nth_dao.market.federation import (
    FeedDigest,
    build_digest,
    verify_digest,
    match_digest_refs,
    merge_digest_refs,
    pull_announcements,
    REJECT_DIGEST_MISSING_FIELD,
    REJECT_DIGEST_BAD_SOURCE_DID,
    REJECT_DIGEST_SIG_INVALID,
    REJECT_DIGEST_SIG_DECODE_FAILED,
    REJECT_DIGEST_CRYPTO_UNAVAILABLE,
)
from nth_dao.market.claim import (
    claim_announcement,
    ClaimStore,
    ClaimOutcome,
    ClaimConflict,
    ClaimRejected,
    REJECT_ANN_NOT_FOUND,
    REJECT_ANN_EXPIRED,
    REJECT_CAP_TOKEN_INVALID,
    REJECT_SUBJECT_MISMATCH,
    REJECT_SKILL_INSUFFICIENT,
    CLAIM_STATUS_CLAIMED,
)

__all__ = [
    # M1
    "TaskAnnouncement",
    "sign_announcement",
    "verify_announcement",
    "MarketFeed",
    "PollResult",
    "REJECT_ANN_MISSING_FIELD",
    "REJECT_ANN_BAD_PUBLISHER_DID",
    "REJECT_ANN_SIG_INVALID",
    "REJECT_ANN_SIG_DECODE_FAILED",
    "REJECT_ANN_CRYPTO_UNAVAILABLE",
    # M2
    "MarketSubscription",
    "match",
    "poll_matching",
    "MatchResult",
    "ScoredAnnouncement",
    "MatchingPollResult",
    "vocabulary",
    "REJECT_EXPIRED",
    "REJECT_CAP_INSUFFICIENT",
    "REJECT_CONTEXT_NOT_SUBSCRIBED",
    "REJECT_REWARD_BELOW_FLOOR",
    "REJECT_PUBLISHER_BELOW_TRUST",
    # M3
    "claim_announcement",
    "ClaimStore",
    "ClaimOutcome",
    "ClaimConflict",
    "ClaimRejected",
    "REJECT_ANN_NOT_FOUND",
    "REJECT_ANN_EXPIRED",
    "REJECT_CAP_TOKEN_INVALID",
    "REJECT_SUBJECT_MISMATCH",
    "REJECT_SKILL_INSUFFICIENT",
    "CLAIM_STATUS_CLAIMED",
    # M4 federation
    "FeedDigest",
    "build_digest",
    "verify_digest",
    "match_digest_refs",
    "merge_digest_refs",
    "pull_announcements",
    "REJECT_DIGEST_MISSING_FIELD",
    "REJECT_DIGEST_BAD_SOURCE_DID",
    "REJECT_DIGEST_SIG_INVALID",
    "REJECT_DIGEST_SIG_DECODE_FAILED",
    "REJECT_DIGEST_CRYPTO_UNAVAILABLE",
]
