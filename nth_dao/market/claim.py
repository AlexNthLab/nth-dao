"""原子认领 + cap_token 授权 + ClaimReceipt（修 C4 + 约束 E）。

C4 问题：旧 marketplace.claim 非原子，prior 审计标了 double-claim 风险
（两个 Agent 并发 claim 同一单可能都成功）。M3 用与 ``MissionStore``
相同、已被 ``test_concurrent_claim`` 验证过的 CAS 模式：
``_thread_lock_for + InterProcessLock`` 下 read-check-write，N 进程抢
一条公告 → 恰好一胜，其余抛 ``ClaimConflict``。

约束 E（全程签名）：认领成功立即签一张 ``nth.task_claimed`` 执行收据
（claimant 签名），并把授权用的 cap_token 作为 ``authorizing_cap_token``
挂上 —— 收据可独立验签（verify_receipt），cap_token 可独立验链
（verify_cap_token），二者各自成立。

授权模型（与 Phase 6 双层哲学一致）：
  - 订阅的 ``capabilities``（M2）是 Agent **自声明**的兴趣，驱动发现，
    不可信。
  - cap_token 的 ``capabilities`` 是 issuer **签名授权**的能力，驱动
    认领，可信。
  认领校验 ``公告所需能力 ⊆ cap_token.capabilities`` —— 一个 Agent 即便
  在订阅里自称会 code_review、也发现了任务，但若其 cap_token 没被授予
  code_review，认领被拒。自声明能发现，签名授权才能认领。

  另外校验 ``token.subject_did == claimant`` —— 防 Agent B 拿 Agent A 的
  token 认领。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from nth_dao.cap_token import verify_cap_token
from nth_dao.execution_receipt import TimelineEntry, now_ms, sign_receipt
from nth_dao.market.announcement import TaskAnnouncement
from nth_dao.market.vocabulary import normalize_capability
from nth_dao.util.io import InterProcessLock, atomic_write_json, safe_id, safe_load_json

logger = logging.getLogger("nth_dao.market.claim")

PathLike = Union[str, Path]


# ── reject reasons ──

REJECT_ANN_NOT_FOUND = "announcement-not-found"
REJECT_ANN_EXPIRED = "announcement-expired"
REJECT_CAP_TOKEN_INVALID = "cap-token-invalid"        # 携带底层 reason（crypto/时效/撤销）
REJECT_SUBJECT_MISMATCH = "cap-token-subject-mismatch"
REJECT_SKILL_INSUFFICIENT = "skill-insufficient"      # token 未授予公告所需技能

CLAIM_STATUS_CLAIMED = "claimed"


class ClaimConflict(Exception):
    """公告已被别的 Agent 认领（CAS 竞态的败者）。"""


class ClaimRejected(Exception):
    """认领因授权/公告问题被拒（区别于竞态冲突）。

    ``reason`` 是 machine-readable 码，便于 UI/日志解释。
    """

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


# ─── 进程内线程锁（与 mission_store 同款，配合 InterProcessLock）───

import threading

_LOCKS: Dict[str, threading.RLock] = {}
_LOCK_GUARD = threading.Lock()


def _thread_lock_for(path: str) -> threading.RLock:
    with _LOCK_GUARD:
        if path not in _LOCKS:
            _LOCKS[path] = threading.RLock()
        return _LOCKS[path]


@dataclass
class ClaimOutcome:
    """认领成功的产物。"""

    claim_record: Dict[str, Any]
    receipt: Dict[str, Any]


class ClaimStore:
    """文件持久的认领状态库（一公告一文件，CAS 防双重认领）。

    布局：``<root>/market_claims/<announcement_id>.json``
    """

    def __init__(self, root: PathLike) -> None:
        self.root = Path(root) / "market_claims"
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, announcement_id: str) -> Path:
        # safe_id 防路径穿越（公告 id 进文件名）
        return self.root / f"{safe_id(announcement_id)}.json"

    def get(self, announcement_id: str) -> Optional[Dict[str, Any]]:
        return safe_load_json(self._path(announcement_id), fallback=None)

    def is_claimed(self, announcement_id: str) -> bool:
        rec = self.get(announcement_id)
        return bool(rec) and rec.get("status") == CLAIM_STATUS_CLAIMED


def claim_announcement(
    feed: "Any",  # MarketFeed
    claim_store: ClaimStore,
    announcement_id: str,
    *,
    claimant: "Any",  # AgentIdentity，必须 can_sign
    cap_token: Dict[str, Any],
    revoked_ids: Optional[set] = None,
    now_ms_override: int = 0,
) -> ClaimOutcome:
    """原子认领一条公告。

    步骤：
      1. 取公告（不存在/过期 → ClaimRejected）。
      2. 验 cap_token（sig/时效/撤销 + 公告所需能力 ⊆ token.capabilities
         + token.subject_did == claimant）→ 不过 → ClaimRejected。
      3. CAS：锁内 read-check-write。已被他人认领 → ClaimConflict；
         同一 claimant 重复认领 → 幂等返回原结果。
      4. 锁内签 ClaimReceipt 并连同 claim 记录一次性落盘（保证记录里
         的 receipt_id 与收据原子一致）。

    Raises:
        ClaimRejected —— 授权/公告问题（带 machine-readable reason）。
        ClaimConflict —— 竞态败者（已被他人认领）。
    """
    claimant_did = claimant.as_did()

    # ── 1. 取公告 ──（feed 不可变，锁外读安全）
    ann: Optional[TaskAnnouncement] = feed.get(
        announcement_id, include_expired=True,
    )
    if ann is None:
        raise ClaimRejected(REJECT_ANN_NOT_FOUND, announcement_id)
    if ann.is_expired(now_ms_override):
        raise ClaimRejected(REJECT_ANN_EXPIRED, announcement_id)

    # ── 2. 验 cap_token ──（只读，无副作用，锁外做）
    # 拆成两层（独立审查修复 M3 R1）：
    #   (a) verify_cap_token 只管密码学/时效/撤销 —— 不传
    #       required_capabilities，因为它做的是**精确字符串**子集判定，
    #       而市场技能名需要规范化（"Code_Review" ≡ "code_review"）。
    #   (b) 市场技能子集判定单独做，两侧都过 vocabulary.normalize ——
    #       与 M2 match 的归一保持一致。否则会出现"M2 能发现、M3 认领被拒"
    #       的撕裂（外部发布方写 'Code_Review'，issuer 授 'code_review'，
    #       discovery 归一后匹配但 claim 精确比对失败）。
    ok, reason = verify_cap_token(
        cap_token,
        now_ms_override=now_ms_override,
        revoked_ids=revoked_ids,
    )
    if not ok:
        raise ClaimRejected(REJECT_CAP_TOKEN_INVALID, reason)
    # subject 绑定：token 必须是签发给这个 claimant 的
    if str(cap_token.get("subject_did", "")) != claimant_did:
        raise ClaimRejected(
            REJECT_SUBJECT_MISMATCH,
            f"token subject={cap_token.get('subject_did')!r} "
            f"!= claimant={claimant_did!r}",
        )
    # 市场技能授权（归一两侧，与 M2 discovery 一致）
    need_skills = {normalize_capability(c) for c in ann.capability_set}
    need_skills.discard("")
    token_caps = cap_token.get("capabilities", [])
    have_skills = {normalize_capability(c) for c in token_caps}
    if not need_skills <= have_skills:
        raise ClaimRejected(
            REJECT_SKILL_INSUFFICIENT,
            f"announcement needs {sorted(need_skills)}, "
            f"token grants {sorted(have_skills)}",
        )

    # ── 3+4. CAS + 签收据 + 落盘（锁内一次完成）──
    path = claim_store._path(announcement_id)
    claimed_at = now_ms_override or now_ms()
    with _thread_lock_for(str(path)), InterProcessLock(path):
        existing = safe_load_json(path, fallback=None)
        if existing is not None:
            # 已有认领记录
            if existing.get("claimant_did") == claimant_did:
                # 幂等：同一 Agent 重复认领 → 返回原记录 + 原收据
                # （收据嵌在记录里，避免重签产生新 id）
                return ClaimOutcome(
                    claim_record=existing,
                    receipt=existing.get("receipt", {}),
                )
            raise ClaimConflict(
                f"announcement {announcement_id} already claimed by "
                f"{existing.get('claimant_did')}"
            )

        # CAS 胜者：签 ClaimReceipt（约束 E）
        timeline = [
            TimelineEntry(
                timestamp=int(claimed_at),
                type="nth.task_claimed",
                payload={
                    "announcement_id": announcement_id,
                    "claimant_did": claimant_did,
                    "publisher_did": ann.publisher_did,
                    "cap_token_id": str(cap_token.get("token_id", "")),
                    "capability_set": list(ann.capability_set),
                    "reward_minor": ann.reward_minor,
                    "reward_asset": ann.reward_asset,
                    "mission_id": ann.mission_id,
                    "claimed_at_ms": int(claimed_at),
                },
            ),
        ]
        receipt = sign_receipt(
            timeline, claimant,
            goal_id=f"market:claim:{announcement_id}",
            authorizing_cap_token=cap_token,
        )

        claim_record = {
            "announcement_id": announcement_id,
            "status": CLAIM_STATUS_CLAIMED,
            "claimant_did": claimant_did,
            "publisher_did": ann.publisher_did,
            "cap_token_id": str(cap_token.get("token_id", "")),
            "claimed_at_ms": int(claimed_at),
            "receipt_id": receipt.get("receipt_id", ""),
            # 收据全文嵌入，便于幂等返回 + 离线审计（收据自带签名，
            # 落盘后被篡改也会 verify_receipt 失败）
            "receipt": receipt,
        }
        atomic_write_json(path, claim_record)
        return ClaimOutcome(claim_record=claim_record, receipt=receipt)
