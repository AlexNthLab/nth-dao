"""可解释信誉投影（约束 D）—— 多维度，无全局单分。

铁律（交易路线图 §5.2E + 开发指导 §2.4）：**不发布"可信度 87.3"这种
全局单分**。全局分把复杂风险压成虚假精度，且极易被 Sybil / 串谋操纵。
取而代之：暴露一组**可解释维度**，权重和门槛**由消费方自己定**——
订阅方按自己的权重看发布方，发布方按自己的门槛看认领方。

``ReputationProfile`` 刻意没有 ``score`` / ``trust`` 单一字段。任何想把
它压成一个数的，必须自己显式定义权重（于是这套权重可被审计、可被质疑）。

M5 能算的维度（全部从 M1-M4 已有的签名 claim 记录派生，不编造）：
  - claims_count          认领过多少任务
  - distinct_publishers   服务过多少个不同发布方（counterparty diversity,
                          抗"自己给自己刷单"）
  - distinct_capabilities 涉及多少种技能（task category 广度）
  - total_reward_minor    累计认领报酬（整数最小单位）
  - first_seen_ms / last_seen_ms   活跃时间窗（credential age 的基础）

尚不能算、留给交易状态机（delivery/verify）落地后补的维度：
  completions_count / verifier_pass_rate / dispute_rate / median_latency /
  price_deviation。**现在不放这些字段**，免得永远是 0 看着像数据
  （诚实性：不展示尚不存在的指标）。
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class ReputationProfile:
    """一个 subject DID 的可解释信誉投影。无全局单分。"""

    subject_did: str
    claims_count: int = 0
    distinct_publishers: int = 0
    distinct_capabilities: int = 0
    total_reward_minor: int = 0
    first_seen_ms: int = 0
    last_seen_ms: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def meets(self, policy: Dict[str, Any]) -> Tuple[bool, str]:
        """该 profile 是否满足一份门槛策略（claimant_policy）。

        policy 是 ``{"min_<dimension>": threshold, ...}`` 形式，每个键对
        本 profile 的一个整数维度。空 policy = 无门槛 = 永远满足（保持
        permissionless 默认）。未知的 ``min_*`` 键 fail-closed（拒绝），
        免得发布方写错维度名却以为设了门槛。

        Returns ``(ok, reason)``；ok=True 时 reason 为 ""。
        """
        if not policy:
            return True, ""
        for key, threshold in policy.items():
            if not key.startswith("min_"):
                # 独立审查修复 (M5 R1)：非 min_ 前缀的键 fail-closed,
                # 不再静默忽略。footgun 根因 —— 发布方写 ``claims_count``
                # （漏了 min_ 前缀）本想设门槛，旧逻辑 ``continue`` 把它
                # 忽略 → 策略变空 → permissionless，与发布方意图相反。
                # 授权门槛绝不能静默放过看不懂的键。
                return False, f"unknown-claimant-policy-key:{key}"
            dim = key[len("min_"):]
            if dim not in _SCALAR_DIMENSIONS:
                # 未知维度 → fail-closed
                return False, f"unknown-claimant-policy-dimension:{dim}"
            have = getattr(self, dim, 0)
            try:
                need = int(threshold)
            except (TypeError, ValueError):
                return False, f"bad-claimant-policy-threshold:{key}"
            if have < need:
                return False, f"below:{dim}({have}<{need})"
        return True, ""


# 可作为门槛的标量维度（meets() 校验用）。
_SCALAR_DIMENSIONS = frozenset({
    "claims_count",
    "distinct_publishers",
    "distinct_capabilities",
    "total_reward_minor",
})


def compute_reputation(
    subject_did: str,
    claim_records: List[Dict[str, Any]],
) -> ReputationProfile:
    """从签名 claim 记录聚合一个 subject 的可解释信誉投影。

    Args:
        subject_did: 要算谁的信誉。
        claim_records: claim 记录列表（ClaimStore.all_records() 或跨 DAO
            汇集）。每条形如 claim.py 写的 claim_record：含 claimant_did /
            publisher_did / claimed_at_ms + 嵌入的 receipt（payload 里有
            capability_set / reward_minor）。只统计 claimant_did == subject
            的记录。

    Returns:
        ReputationProfile（多维，无全局分）。

    说明：reward / capability 优先从 claim 记录里嵌入的签名 receipt 的
    payload 取（不可被篡改），取不到再退到 claim 记录顶层字段。
    """
    publishers = set()
    capabilities = set()
    total_reward = 0
    claims = 0
    first_seen = 0
    last_seen = 0

    for rec in claim_records:
        if not isinstance(rec, dict):
            continue
        if rec.get("claimant_did") != subject_did:
            continue
        claims += 1
        pub = rec.get("publisher_did")
        if pub:
            publishers.add(pub)

        # 优先从签名 receipt 的 payload 取（防篡改顶层字段）
        payload = _claimed_payload(rec)
        caps = payload.get("capability_set") or rec.get("capability_set") or []
        for c in caps:
            capabilities.add(c)
        reward = payload.get("reward_minor")
        if reward is None:
            reward = rec.get("reward_minor", 0)
        if isinstance(reward, int) and not isinstance(reward, bool):
            total_reward += reward

        ts = payload.get("claimed_at_ms") or rec.get("claimed_at_ms") or 0
        if isinstance(ts, int) and ts > 0:
            first_seen = ts if first_seen == 0 else min(first_seen, ts)
            last_seen = max(last_seen, ts)

    return ReputationProfile(
        subject_did=subject_did,
        claims_count=claims,
        distinct_publishers=len(publishers),
        distinct_capabilities=len(capabilities),
        total_reward_minor=total_reward,
        first_seen_ms=first_seen,
        last_seen_ms=last_seen,
    )


def _claimed_payload(rec: Dict[str, Any]) -> Dict[str, Any]:
    """从 claim 记录里嵌入的 receipt 取 nth.task_claimed 的 payload。

    取不到（旧记录 / 结构异常）返回空 dict，调用方退回顶层字段。
    """
    receipt = rec.get("receipt")
    if not isinstance(receipt, dict):
        return {}
    timeline = receipt.get("timeline")
    if not isinstance(timeline, list):
        return {}
    for entry in timeline:
        if isinstance(entry, dict) and entry.get("type") == "nth.task_claimed":
            payload = entry.get("payload")
            if isinstance(payload, dict):
                return payload
    return {}
