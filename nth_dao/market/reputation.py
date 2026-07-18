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

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple

from nth_dao.execution_receipt import verify_receipt


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
            汇集）。每条含嵌入的签名 receipt。

    Returns:
        ReputationProfile（多维，无全局分）。

    安全（独立审查 M5 R2 加固）：**每条记录的嵌入 receipt 都要验签**,
    且 receipt.signer_did 必须 == subject —— 只有 subject 亲手签名认领
    的、密码学可验证的记录才计入。所有维度（publisher / capability /
    reward / 时间）都从**已验签的 payload** 取，绝不碰 claim 记录的顶层
    字段（顶层可被伪造）。

    为什么必须验：compute_reputation 是通用函数，输入可能来自跨 DAO 网络
    汇集（约束 D"用对方 receipt 历史算"）。若信任未验证输入，攻击者伪造
    一批 claim 记录即可刷出高信誉。reputation 建立在签名证据上，就必须
    验签名，不能只读不验（与 M5 R1"授权门槛 fail-closed"同一原则）。

    代价：每条记录一次 verify_receipt（Ed25519 验签）。reputation 非
    热路径，正确性优先于速度。
    """
    publishers = set()
    capabilities = set()
    total_reward = 0
    claims = 0
    first_seen = 0
    last_seen = 0

    for rec in claim_records:
        payload = _verified_claim_payload(rec, subject_did)
        if payload is None:
            continue  # 无 receipt / 验签失败 / signer 不是 subject → 不计入
        claims += 1

        pub = payload.get("publisher_did")
        if pub:
            publishers.add(pub)
        for c in (payload.get("capability_set") or []):
            capabilities.add(c)
        reward = payload.get("reward_minor", 0)
        if isinstance(reward, int) and not isinstance(reward, bool):
            total_reward += reward
        ts = payload.get("claimed_at_ms") or 0
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


def _verified_claim_payload(
    rec: Dict[str, Any], subject_did: str,
) -> Optional[Dict[str, Any]]:
    """返回该记录中**已验签**的 nth.task_claimed payload；任一环节不过
    → None（不计入信誉）。

    校验链：
      1. rec 是 dict 且有 dict 形式的 receipt。
      2. verify_receipt(receipt) —— 签名 + content_hash 有效。
      3. receipt.signer_did == subject —— 确认是 subject 亲签
         （受签名保护，不是顶层可伪造的 claimant_did）。
      4. timeline 里有 nth.task_claimed 条目，其 payload.claimant_did
         也 == subject（双保险）。
    """
    if not isinstance(rec, dict):
        return None
    receipt = rec.get("receipt")
    if not isinstance(receipt, dict):
        return None
    if not verify_receipt(receipt):
        return None
    if str(receipt.get("signer_did", "")) != subject_did:
        return None
    timeline = receipt.get("timeline")
    if not isinstance(timeline, list):
        return None
    for entry in timeline:
        if isinstance(entry, dict) and entry.get("type") == "nth.task_claimed":
            payload = entry.get("payload")
            if isinstance(payload, dict) and \
                    str(payload.get("claimant_did", "")) == subject_did:
                return payload
    return None
