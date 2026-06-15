"""治理投影 —— 从 spine 的 governance.* 事件回放出"当前生效策略"(Phase 4b)。

自治、自修订、带授权的治理:
  - ``governance.genesis``:第一条立宪 → 设初始策略 + 记录 founder。
  - ``governance.amend``:全量替换式新策略,**仅当签名者被当时生效策略授权**
    (``can(current_policy, signer, "policy.amend")``)才应用。

按 spine 顺序回放 → 确定性:任何节点都能独立复算出同一"当前策略"与版本史。
修宪权限随策略自身演进(若某次修订收/放了 policy.amend,后续修宪据新策略判定)。
"""
from __future__ import annotations

from typing import List

from nth_dao.governance.engine import ACTION_POLICY_AMEND, can
from nth_dao.governance.policy import Policy
from nth_dao.governance.statement import verify_governance_statement
from nth_dao.spine.event import SpineEvent
from nth_dao.spine.projection import Projection

EVENT_GOV_GENESIS = "governance.genesis"
EVENT_GOV_AMEND = "governance.amend"
_GOV_EVENTS = (EVENT_GOV_GENESIS, EVENT_GOV_AMEND)


class PolicyProjection(Projection):
    """折叠 governance.genesis/amend → 当前生效 Policy(+ 版本史)。"""

    def __init__(self) -> None:
        self._policy = Policy()
        self._established = False
        self._founder_did = ""
        self._version = 0
        self._history: List[str] = []   # 每次应用的 signer_did(审计)

    def reset(self) -> None:
        self._policy = Policy()
        self._established = False
        self._founder_did = ""
        self._version = 0
        self._history = []

    def apply(self, event: SpineEvent) -> None:
        if event.type not in _GOV_EVENTS:
            return
        stmt = event.payload
        ok, _ = verify_governance_statement(stmt)
        if not ok:
            return
        try:
            new_policy = Policy.from_dict(stmt["policy"])
        except (TypeError, ValueError):
            return
        signer = stmt["signer_did"]

        if event.type == EVENT_GOV_GENESIS:
            if not self._established:   # 第一条 genesis 立宪,后续 genesis 忽略
                self._policy = new_policy
                self._established = True
                self._founder_did = signer
                self._version = 1
                self._history.append(signer)
            return

        # amend:必须已立宪,且签名者被**当前**策略授权修宪。
        if not self._established:
            return
        if can(self._policy, signer, ACTION_POLICY_AMEND).allowed:
            self._policy = new_policy
            self._version += 1
            self._history.append(signer)

    @property
    def policy(self) -> Policy:
        return self._policy

    @property
    def established(self) -> bool:
        return self._established

    @property
    def founder_did(self) -> str:
        return self._founder_did

    @property
    def version(self) -> int:
        return self._version

    @property
    def history(self) -> List[str]:
        return list(self._history)
