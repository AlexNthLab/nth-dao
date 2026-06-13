"""MarketSubscription —— Agent 的"能力 ∩ 兴趣"订阅过滤器（修 C2）。

C2 问题：旧市场只有一个 ``accepting_tasks=True/False`` 的 bool，无法
表达"我只接 code_review、报酬 ≥ 5、信誉门槛我自己定"。订阅把"想不想
接"从一个开关升级成一组可解释的条件。

两个维度刻意分开（见开发指导 §2.5）：
  - **能力（客观：能不能干）** —— ``capabilities``：Agent 声明会做的
    技能。匹配时要求"公告所需能力 ⊆ 我的能力"。
  - **兴趣（主观：想不想干）** —— ``contexts`` / ``min_reward_minor``
    / ``publisher_trust_floor``：即便能干，也可以因为类别/报酬/对发布
    方的信任不足而不接。

约束 D（本地优先信誉）：``publisher_trust_floor`` 是**订阅方自己**定的
门槛，权重在订阅方手里 —— 市场不发布全局信誉分。M2 阶段还没有真实
信誉源，门槛默认 0.0（不挡），等 M5 接入 reputation 投影后生效。

本模块只是纯数据 + 规范化，不含匹配逻辑（在 ``match.py``）也不含 I/O。
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

from nth_dao.market.vocabulary import normalize_capability


@dataclass
class MarketSubscription:
    """一个 Agent 对市场的订阅条件。

    Fields:
        subscriber_did: 订阅者 DID。
        capabilities: 我声明会做的技能（规范化 + 去重）。匹配的"能力"侧。
        contexts: 只接这些 context（如 ["code_review", "research"]）；
            空列表 = 不限类别（全接）。匹配的"兴趣"侧之一。
        min_reward_minor: 报酬门槛（整数最小单位）。低于此的不接。
        max_concurrent: 并发认领上限（M3 认领时强制；M2 只是携带，
            不参与 match —— match 是无状态纯函数，并发计数是有状态的，
            放认领层）。
        publisher_trust_floor: 对发布方的本地信誉门槛（约束 D）。
    """

    subscriber_did: str
    capabilities: List[str] = field(default_factory=list)
    contexts: List[str] = field(default_factory=list)
    min_reward_minor: int = 0
    max_concurrent: int = 1
    publisher_trust_floor: float = 0.0

    def __post_init__(self) -> None:
        # 能力规范化 + 去重 + 排序，让匹配两端用同一形式（修 C3 的一半，
        # 另一半在公告侧；只要双方都过 normalize 就能对上）。
        norm_caps = set()
        for c in self.capabilities:
            n = normalize_capability(c)
            if n:
                norm_caps.add(n)
        self.capabilities = sorted(norm_caps)
        # context 也规范化（与公告的 context 对齐）
        norm_ctx = []
        seen = set()
        for c in self.contexts:
            n = normalize_capability(c)
            if n and n not in seen:
                seen.add(n)
                norm_ctx.append(n)
        self.contexts = norm_ctx
        # 防御性：max_concurrent 至少 1（0/负数没有意义）
        if not isinstance(self.max_concurrent, int) or self.max_concurrent < 1:
            self.max_concurrent = 1

    def capability_set(self) -> frozenset:
        """我的能力集（match 用）。"""
        return frozenset(self.capabilities)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MarketSubscription":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})
