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

授权边界（M4 独立审查确认，permissionless-by-design）：
  认领是**无许可**的 —— 任何持有效 cap_token（哪怕自己给自己签的，
  issuer == subject）且具备所需技能的 Agent，都能认领公开发布的公告。
  这是开放去中心化市场的正确模型（类比 x402；"绝对去中心化" = 没有
  中心 gatekeeper 决定谁能接活；"一人公司" 的 Agent 本就是自己的
  issuer）。问责靠**签名认领收据**（claimant DID 在案）+ 未来 M5 的
  可解释信誉，而非认领时的准入。
  发布方若想"只让可信 Agent 接我的活"，那是 **M5 的 publisher 侧
  claimant 信誉门槛**（对称于订阅的 ``publisher_trust_floor``），不在
  M4 范围。本层故意不做准入，保持市场开放。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from nth_dao.cap_token import verify_cap_token
from nth_dao.execution_receipt import (
    TimelineEntry, now_ms, sign_receipt, verify_receipt,
)
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
REJECT_CLAIMANT_BELOW_POLICY = "claimant-below-policy"  # 信誉不满足发布方门槛
REJECT_CLAIMANT_REP_MISSING = "claimant-reputation-missing"  # 有门槛但没给信誉

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

    def all_records(self) -> List[Dict[str, Any]]:
        """枚举本 store 的全部 claim 记录（M5：信誉聚合 + mission 进度用）。

        损坏/无法解析的文件静默略过。顺序不保证。
        """
        out: List[Dict[str, Any]] = []
        for p in self.root.glob("*.json"):
            rec = safe_load_json(p, fallback=None)
            if isinstance(rec, dict):
                out.append(rec)
        return out


def claim_announcement(
    feed: "Any",  # MarketFeed
    claim_store: ClaimStore,
    announcement_id: str,
    *,
    claimant: "Any",  # AgentIdentity，必须 can_sign
    cap_token: Dict[str, Any],
    revoked_ids: Optional[set] = None,
    claimant_reputation: "Any" = None,  # M5: ReputationProfile（仅当公告设了 claimant_policy 才需要）
    now_ms_override: int = 0,
) -> ClaimOutcome:
    """原子认领一条公告。

    ⚠️ claimant_reputation 安全契约（独立审查 M5 R2）：当公告设了
    claimant_policy，此参数**必须由认领权威（主 DAO）自己用
    ``compute_reputation`` 计算**（该函数会验签每条 claim receipt），
    **绝不能直接采信认领方请求里自带的信誉**。网络部署时，claim 端点
    要在服务端算 reputation，而不是从请求体读 —— 否则认领方塞一个
    伪造的高信誉 profile 即可绕过门槛。本函数信任传入的 profile，因为
    它假定调用方就是权威。

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

    # ── M5: 发布方侧 claimant 准入门槛（约束 D 的对称面）──
    # 公告的 claimant_policy 非空时，认领权威按自己计算的 claimant 信誉
    # 判定是否达标。空 policy = 无许可（保持 M4 permissionless 默认）。
    # 有门槛但调用方没给信誉 → fail-closed（无法核验即拒）。
    policy = ann.claimant_policy or {}
    if policy:
        if claimant_reputation is None:
            raise ClaimRejected(
                REJECT_CLAIMANT_REP_MISSING,
                f"announcement sets claimant_policy {policy} but no "
                "claimant_reputation was supplied to verify against",
            )
        ok_rep, rep_reason = claimant_reputation.meets(policy)
        if not ok_rep:
            raise ClaimRejected(REJECT_CLAIMANT_BELOW_POLICY, rep_reason)

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


# ── 跨 DAO 认领(XDAO-1)──────────────────────────────────────────────
# 把 claim_announcement 的"验 + 锁内签 + CAS"原子三合一**拆成两半**,让
# 认领能跨节点:agent(有私钥)在自己这边只签收据,来源 DAO(认领权威、
# 持有公告 + ClaimStore)收下预签收据后验证 + CAS 落盘。现有
# claim_announcement 不动(本地认领照旧)。

REJECT_RECEIPT_INVALID = "claim-receipt-invalid"   # 收据签名/结构验不过
REJECT_RECEIPT_BINDING = "claim-receipt-binding"   # 收据没绑定到本公告/claimant


def _claim_timeline(ann: TaskAnnouncement, claimant_did: str, claimed_at: int) -> List[TimelineEntry]:
    """认领收据的 timeline —— 与 claim_announcement 锁内签的**同构**,
    保证来源侧 record_foreign_claim 能用同一套绑定校验。"""
    return [
        TimelineEntry(
            timestamp=int(claimed_at),
            type="nth.task_claimed",
            payload={
                "announcement_id": ann.announcement_id,
                "claimant_did": claimant_did,
                "publisher_did": ann.publisher_did,
                "cap_token_id": "",  # 占位:不进绑定校验(token_id 另在记录里)
                "capability_set": list(ann.capability_set),
                "reward_minor": ann.reward_minor,
                "reward_asset": ann.reward_asset,
                "mission_id": ann.mission_id,
                "claimed_at_ms": int(claimed_at),
            },
        ),
    ]


def sign_claim_receipt(
    ann: TaskAnnouncement,
    claimant: "Any",  # AgentIdentity，必须 can_sign
    cap_token: Dict[str, Any],
    *,
    now_ms_override: int = 0,
) -> Dict[str, Any]:
    """跨 DAO 认领的「只签」侧:agent(有私钥)为一条公告签 ClaimReceipt,
    **不做 CAS、不落盘**。产出的收据 + cap_token 交给来源 DAO 的
    ``record_foreign_claim`` 去验 + CAS。

    不做权威校验(那是来源侧的事),但仍要求 ``cap_token.subject == claimant``
    —— 否则签了来源也会拒,早失败更清晰。``goal_id`` 绑定到该公告。
    """
    claimant_did = claimant.as_did()
    if str(cap_token.get("subject_did", "")) != claimant_did:
        raise ClaimRejected(
            REJECT_SUBJECT_MISMATCH,
            f"token subject={cap_token.get('subject_did')!r} "
            f"!= claimant={claimant_did!r}",
        )
    claimed_at = now_ms_override or now_ms()
    timeline = _claim_timeline(ann, claimant_did, claimed_at)
    return sign_receipt(
        timeline, claimant,
        goal_id=f"market:claim:{ann.announcement_id}",
        authorizing_cap_token=cap_token,
    )


def record_foreign_claim(
    feed: "Any",  # MarketFeed（来源 DAO 的，含该公告）
    claim_store: ClaimStore,  # 来源 DAO 的认领权威 store
    announcement_id: str,
    cap_token: Dict[str, Any],
    receipt: Dict[str, Any],
    *,
    revoked_ids: Optional[set] = None,
    claimant_reputation: "Any" = None,
    now_ms_override: int = 0,
) -> ClaimOutcome:
    """跨 DAO 认领的「验 + CAS」侧:来源 DAO 接受外部 agent **预签**的
    ClaimReceipt,验证后 CAS 落盘。**绝不重签**(收据已由 claimant 签)。

    这是信任边界 —— 收据来自不可信网络,逐项严验(任一不过即 ClaimRejected):
      1. 公告存在 / 未过期(本地 feed)。
      2. ``verify_receipt`` —— 收据签名有效(binds signer_did → timeline)。
      3. ``claimant_did := receipt.signer_did``;``cap_token.subject_did == claimant_did``。
      4. ``verify_cap_token`` —— crypto / 时效 / 撤销。
      5. **绑定本公告**(防重放到别的公告 / 换 claimant):
         ``goal_id == market:claim:{id}`` 且 timeline payload 的
         ``announcement_id``/``claimant_did`` 一致。
      6. 技能子集(两侧 normalize,与 discovery 一致)。
      7. ``claimant_policy``(若公告设了;权威侧自算信誉)。
      8. CAS 锁内 read-check-write,落盘**传入的** receipt(不重签)。
    """
    claimed_at = now_ms_override or now_ms()

    # 1. 公告
    ann: Optional[TaskAnnouncement] = feed.get(announcement_id, include_expired=True)
    if ann is None:
        raise ClaimRejected(REJECT_ANN_NOT_FOUND, announcement_id)
    if ann.is_expired(now_ms_override):
        raise ClaimRejected(REJECT_ANN_EXPIRED, announcement_id)

    # 2. 收据签名(真相层:agent 用自己的私钥签的)
    if not isinstance(receipt, dict) or not verify_receipt(receipt):
        raise ClaimRejected(REJECT_RECEIPT_INVALID, "claim receipt signature invalid")
    claimant_did = str(receipt.get("signer_did", ""))
    if not claimant_did:
        raise ClaimRejected(REJECT_RECEIPT_INVALID, "receipt missing signer_did")

    # 3. cap_token subject 必须就是签收据的 claimant
    if str(cap_token.get("subject_did", "")) != claimant_did:
        raise ClaimRejected(
            REJECT_SUBJECT_MISMATCH,
            f"token subject={cap_token.get('subject_did')!r} != claimant={claimant_did!r}",
        )

    # 4. 验 cap_token
    ok, reason = verify_cap_token(
        cap_token, now_ms_override=now_ms_override, revoked_ids=revoked_ids,
    )
    if not ok:
        raise ClaimRejected(REJECT_CAP_TOKEN_INVALID, reason)

    # 5. 收据绑定本公告(防重放 / 换标的)
    if str(receipt.get("goal_id", "")) != f"market:claim:{announcement_id}":
        raise ClaimRejected(
            REJECT_RECEIPT_BINDING, "receipt goal_id does not bind this announcement")
    timeline = receipt.get("timeline") or []
    payload = timeline[0].get("payload", {}) if (timeline and isinstance(timeline[0], dict)) else {}
    if (
        payload.get("announcement_id") != announcement_id
        or payload.get("claimant_did") != claimant_did
    ):
        raise ClaimRejected(
            REJECT_RECEIPT_BINDING,
            "receipt timeline does not bind this announcement/claimant")

    # 6. 技能子集
    need_skills = {normalize_capability(c) for c in ann.capability_set}
    need_skills.discard("")
    have_skills = {normalize_capability(c) for c in cap_token.get("capabilities", [])}
    if not need_skills <= have_skills:
        raise ClaimRejected(
            REJECT_SKILL_INSUFFICIENT,
            f"announcement needs {sorted(need_skills)}, token grants {sorted(have_skills)}")

    # 7. claimant_policy(若公告设了门槛)
    policy = ann.claimant_policy or {}
    if policy:
        if claimant_reputation is None:
            raise ClaimRejected(
                REJECT_CLAIMANT_REP_MISSING,
                f"announcement sets claimant_policy {policy} but no "
                "claimant_reputation was supplied to verify against")
        ok_rep, rep_reason = claimant_reputation.meets(policy)
        if not ok_rep:
            raise ClaimRejected(REJECT_CLAIMANT_BELOW_POLICY, rep_reason)

    # 8. CAS（落盘传入的 receipt，不重签）
    path = claim_store._path(announcement_id)
    with _thread_lock_for(str(path)), InterProcessLock(path):
        existing = safe_load_json(path, fallback=None)
        if existing is not None:
            if existing.get("claimant_did") == claimant_did:
                return ClaimOutcome(
                    claim_record=existing, receipt=existing.get("receipt", {}))
            raise ClaimConflict(
                f"announcement {announcement_id} already claimed by "
                f"{existing.get('claimant_did')}")
        claim_record = {
            "announcement_id": announcement_id,
            "status": CLAIM_STATUS_CLAIMED,
            "claimant_did": claimant_did,
            "publisher_did": ann.publisher_did,
            "cap_token_id": str(cap_token.get("token_id", "")),
            "claimed_at_ms": int(claimed_at),
            "receipt_id": receipt.get("receipt_id", ""),
            "receipt": receipt,   # 外部预签收据，原样落盘（自带签名，篡改即失效）
            "foreign": True,      # 标记：跨 DAO 认领
        }
        atomic_write_json(path, claim_record)
        return ClaimOutcome(claim_record=claim_record, receipt=receipt)
