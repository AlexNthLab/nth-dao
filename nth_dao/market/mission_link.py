"""Mission 关联（约束 B）—— 大工程分解成公告流，从签名认领回填进度。

愿景第 4 点"流浪地球级协作"：一个 Mission（如"造一个 Web 应用"）分解
成几十条 TaskAnnouncement（设计 schema / 写 API / 写前端 / 写测试 /
部署……），发到市场，多个 Agent **并行**认领、交付。Mission 的进度应能
被追踪、被审计。

TaskAnnouncement 已带 ``mission_id``（M1），认领记录已 pin mission_id +
嵌签名 receipt（M3）。本模块把这些**签名证据**重组成一张 mission 进度
视图 —— 这是 local-first、evidence-based 的"回填"：进度不是某个中心服
务的状态，而是从一批可独立验证的认领记录重建出来的。

M5 阶段的"进度"= 认领状态（claimed / unclaimed），因为交付/验收
（delivery/verify）属于交易状态机，尚未落地。等那一层就位，本视图可
扩展出 delivered / verified / settled。现在不展示尚不存在的状态
（诚实性）。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List

from nth_dao.market.claim import CLAIM_STATUS_CLAIMED


@dataclass
class MissionClaim:
    announcement_id: str
    claimant_did: str
    claimed_at_ms: int


@dataclass
class MissionProgress:
    """一个 Mission 的市场侧进度（从签名认领重建）。"""

    mission_id: str
    total: int = 0               # 该 mission 分解的公告数
    claimed: int = 0
    unclaimed: int = 0
    claims: List[MissionClaim] = field(default_factory=list)

    @property
    def all_claimed(self) -> bool:
        return self.total > 0 and self.claimed == self.total

    def distinct_claimants(self) -> int:
        return len({c.claimant_did for c in self.claims})


def mission_progress(
    claim_store: "Any",  # ClaimStore
    announcements: List["Any"],  # 属于同一 mission 的 TaskAnnouncement 列表
) -> MissionProgress:
    """给定一个 mission 分解出的全部公告，重建其认领进度。

    Args:
        claim_store: 认领权威的 ClaimStore（主 DAO）。
        announcements: 该 mission 的公告列表（调用方负责筛出
            ``mission_id`` 相同的那些）。

    Returns:
        MissionProgress —— total / claimed / unclaimed + 每条认领的
        (announcement_id, claimant_did, claimed_at_ms)。

    进度只认 status == claimed 的记录；未认领或记录缺失的算 unclaimed。
    """
    mission_id = ""
    for ann in announcements:
        mid = getattr(ann, "mission_id", "")
        if mid:
            mission_id = mid
            break

    claims: List[MissionClaim] = []
    for ann in announcements:
        aid = getattr(ann, "announcement_id", "")
        rec = claim_store.get(aid, announcement=ann)
        if isinstance(rec, dict) and rec.get("status") == CLAIM_STATUS_CLAIMED:
            claims.append(MissionClaim(
                announcement_id=aid,
                claimant_did=str(rec.get("claimant_did", "")),
                claimed_at_ms=int(rec.get("claimed_at_ms", 0) or 0),
            ))

    total = len(announcements)
    claimed = len(claims)
    return MissionProgress(
        mission_id=mission_id,
        total=total,
        claimed=claimed,
        unclaimed=total - claimed,
        claims=claims,
    )
