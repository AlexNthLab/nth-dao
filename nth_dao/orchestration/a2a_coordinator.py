"""A2A-native 协调者 —— 根本方案的传输平面 keystone。

问题(relay 之根):旧的多 backend 协调把 worker 分成"本地 subprocess"和
"远程节点"两类,各用各的够法 —— 于是跨域要 relay、人肉桥接、N×域、凭据
复制、双认领脑裂。

根本方案:协调者**只认一种 worker —— A2A peer**。peer 是什么(本地被监管
进程 / 同局域网 Hermes / 公网节点)协调者一概不知,它只持有一个
``dispatch(prompt) -> response`` 回调,底层走 A2A(``/a2a/ask`` + cap_token)。
本地和远程因此**同构**,relay 这个概念从代码里消失。

本模块把"协调"与"传输"彻底分开:
  - 协调:沿用 MissionStore/MissionRunner —— 能力路由 + depends_on 门控 +
    try_claim CAS + evaluate 质量门(已验证,见 test_mumolawos_*)。
  - 传输:每个 peer 的 ``dispatch`` 回调,统一 A2A。本地 peer 的 dispatch
    打 ``POST /api/v2/agents/{did}/ask``;远程 peer 的 dispatch 打对端
    ``/a2a/ask`` —— **协调者代码一行不变**。

下一步(全网):把 ``A2APeer`` 的来源从"本地 spawn"换成"联邦 DID→endpoint
发现",协调者依旧不变。那是发现平面的事,不在本模块。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from nth_dao.orchestration.mission_store import MissionStore
from nth_dao.orchestration.mission_runner import MissionRunner


# dispatch 回调:把一段 prompt 交给某个 A2A peer 执行,返回它的文本回应。
# 底层实现(本地 hub /ask 还是远程 /a2a/ask)对协调者透明 —— 这就是
# "本地=远程=同一种 peer"的落点。
DispatchFn = Callable[[str], str]


@dataclass
class A2APeer:
    """一个 A2A 对端 worker。协调者只通过 ``dispatch`` 够它。"""

    did: str
    capabilities: List[str]
    dispatch: DispatchFn
    label: str = ""

    def __post_init__(self) -> None:
        if not callable(self.dispatch):
            raise TypeError("A2APeer.dispatch 必须可调用(prompt -> response)")


@dataclass
class StepResult:
    step_id: str
    peer_did: str
    ok: bool
    detail: str = ""
    response: str = ""


@dataclass
class CoordinationResult:
    mission_id: str
    done: int
    total: int
    steps: List[StepResult] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return self.done == self.total and self.total > 0


class A2ACoordinator:
    """沿 mission DAG 把每个 step 经 A2A 派给能胜任的 peer。

    协调者**不**做 subprocess 驱动、**不**区分本地/远程 —— 只调
    ``peer.dispatch``。认领/完成走 MissionRunner(真实 CAS + evaluate)。
    """

    def __init__(self, store: MissionStore, peers: List[A2APeer]) -> None:
        if not peers:
            raise ValueError("至少要一个 A2APeer")
        self.store = store
        self.peers = peers
        # 每个 peer 一个 MissionRunner(agent_id=did,带其能力)做认领/完成。
        self._runners: Dict[str, MissionRunner] = {
            p.did: MissionRunner(store, agent_id=p.did, capabilities=p.capabilities)
            for p in peers
        }

    def run_mission(
        self,
        mission_id: str,
        *,
        output_key_for: Callable[[str], Optional[str]],
        build_prompt: Optional[Callable[[Any], str]] = None,
        max_rounds: int = 50,
    ) -> CoordinationResult:
        """跑完一个 mission 的 DAG。

        Args:
            mission_id: 目标 mission(须已在 store 里,状态 active)。
            output_key_for: step_id -> 该 step 输出里要带的 required key
                (满足 acceptance_criteria);返回 None 表示无附加 key。
            build_prompt: step -> 给 peer 的 prompt 文本。默认用
                "<description>\\n输入: <inputs>"。
            max_rounds: 调度轮上限(防卡死)。

        Returns:
            CoordinationResult。
        """
        bp = build_prompt or _default_prompt
        results: List[StepResult] = []
        mission = self.store.get(mission_id)
        if mission is None:
            raise ValueError(f"mission {mission_id!r} 不存在")
        total = len(mission.steps)

        for _ in range(max_rounds):
            mission = self.store.get(mission_id)
            if len(mission.completed_step_ids()) == total:
                break
            progressed = False
            for peer in self.peers:
                mission = self.store.get(mission_id)
                actionable = mission.next_actionable(peer.capabilities)  # 能力+依赖门控
                if not actionable:
                    continue
                step = actionable[0]
                runner = self._runners[peer.did]
                if runner.claim(mission_id, step.id) is None:  # try_claim CAS
                    continue
                # —— 传输:经 A2A 把活交给 peer(协调者唯一对外动作)——
                try:
                    response = peer.dispatch(bp(step))
                except Exception as exc:  # peer 故障 → 标 fail,不卡整盘
                    runner.fail(mission_id, step.id, f"dispatch 失败: {exc}")
                    results.append(StepResult(step.id, peer.did, False,
                                              f"dispatch error: {exc}"))
                    progressed = True
                    break
                # 包装成满足 acceptance_criteria 的输出
                output: Dict[str, Any] = {"content": response}
                key = output_key_for(step.id)
                if key:
                    output[key] = f"{peer.did}:{step.id}: {response[:60]}"
                outcome = runner.complete(mission_id, step.id, output)
                results.append(StepResult(
                    step.id, peer.did, outcome.success,
                    "" if outcome.success else outcome.reason,
                    response=response[:200]))
                progressed = True
                break
            if not progressed:
                break  # 无人可推进(缺能力/等依赖/全 claim 完)

        mission = self.store.get(mission_id)
        return CoordinationResult(
            mission_id=mission_id,
            done=len(mission.completed_step_ids()),
            total=total,
            steps=results,
        )


def _default_prompt(step: Any) -> str:
    desc = getattr(step, "description", "")
    inputs = getattr(step, "inputs", {}) or {}
    return f"{desc}\n输入: {inputs}" if inputs else desc
