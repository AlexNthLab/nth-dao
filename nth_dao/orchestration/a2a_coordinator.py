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


@dataclass
class PeerResponse:
    """A2A peer 的一次回应。除了文本,还带**签名执行 receipt** —— 协调者
    据此密码学验证"确是这个 peer DID 干的活",而非轻信传输层文本。"""

    text: str
    receipt: Optional[Dict[str, Any]] = None  # 签名的 nth.a2a_ask_executed
    agent_did: str = ""                        # 回应里 peer 自称的 DID


# dispatch 回调:把一段 prompt 交给某个 A2A peer 执行,返回 PeerResponse。
# 底层实现(本地 hub /ask 还是远程 /a2a/ask)对协调者透明 —— 这就是
# "本地=远程=同一种 peer"的落点。**契约**:实现必须自带超时上界(协调者
# 不为注入的 dispatch 兜底超时;一个挂死的 dispatch 会卡住整盘)。
DispatchFn = Callable[[str], "PeerResponse"]


@dataclass
class A2APeer:
    """一个 A2A 对端 worker。协调者只通过 ``dispatch`` 够它。"""

    did: str
    capabilities: List[str]
    dispatch: DispatchFn
    label: str = ""

    def __post_init__(self) -> None:
        if not callable(self.dispatch):
            raise TypeError("A2APeer.dispatch 必须可调用(prompt -> PeerResponse)")


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

    def __init__(
        self,
        store: MissionStore,
        peers: List[A2APeer],
        *,
        verify_receipts: bool = True,
    ) -> None:
        if not peers:
            raise ValueError("至少要一个 A2APeer")
        self.store = store
        self.peers = peers
        # verify_receipts=True(默认):一个 step 只有在 peer 回了**签名且
        # signer==该 peer DID** 的 receipt 时才算完成 —— 不轻信传输层文本。
        # 这是把全系统"只认签名证据"的原则贯彻到协调平面;去中心/远程
        # peer 场景下,关掉它等于让任意 peer 谎称干完活骗信誉/报酬。
        # 仅在全内网可信 / crypto 不可用的封闭环境才显式置 False。
        self.verify_receipts = verify_receipts
        # 每个 peer 一个 MissionRunner(agent_id=did,带其能力)做认领/完成。
        self._runners: Dict[str, MissionRunner] = {
            p.did: MissionRunner(store, agent_id=p.did, capabilities=p.capabilities)
            for p in peers
        }

    def _verify_peer_work(
        self, peer: A2APeer, resp: "PeerResponse", prompt: str,
    ) -> str:
        """返回 "" 表示通过;非空为拒绝原因。委托给模块级
        ``verify_work_receipt``(协调者与市场 worker 共用同一套校验)。"""
        ok, why = verify_work_receipt(
            resp.receipt, expected_signer=peer.did,
            prompt=prompt, response=resp.text or "")
        return "" if ok else why

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
                prompt = bp(step)
                try:
                    resp = peer.dispatch(prompt)
                except Exception as exc:  # peer 故障 → 标 fail,不卡整盘
                    runner.fail(mission_id, step.id, f"dispatch 失败: {exc}")
                    results.append(StepResult(step.id, peer.did, False,
                                              f"dispatch error: {exc}"))
                    progressed = True
                    break
                # —— 验签:确是该 peer 为本请求/回应亲签的证据,才认完成 ——
                if self.verify_receipts:
                    why = self._verify_peer_work(peer, resp, prompt)
                    if why:
                        runner.fail(mission_id, step.id, f"unverified work: {why}")
                        results.append(StepResult(step.id, peer.did, False,
                                                  f"unverified: {why}",
                                                  response=resp.text[:200]))
                        progressed = True
                        break
                # 包装成满足 acceptance_criteria 的输出(附签名 receipt 作凭据)
                output: Dict[str, Any] = {"content": resp.text}
                key = output_key_for(step.id)
                if key:
                    output[key] = f"{peer.did}:{step.id}: {resp.text[:60]}"
                if resp.receipt is not None:
                    output["receipt"] = resp.receipt
                outcome = runner.complete(mission_id, step.id, output)
                results.append(StepResult(
                    step.id, peer.did, outcome.success,
                    "" if outcome.success else outcome.reason,
                    response=resp.text[:200]))
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


def _a2a_ask_payload(receipt: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """从签名 receipt 的 timeline 取 nth.a2a_ask_executed 那条 payload。"""
    timeline = receipt.get("timeline")
    if not isinstance(timeline, list):
        return None
    for entry in timeline:
        if isinstance(entry, dict) and entry.get("type") == "nth.a2a_ask_executed":
            p = entry.get("payload")
            if isinstance(p, dict):
                return p
    return None


def verify_work_receipt(
    receipt: Optional[Dict[str, Any]],
    *,
    expected_signer: str,
    prompt: str,
    response: str,
) -> "tuple[bool, str]":
    """校验一张 A2A 工作 receipt 是否"这个 DID 为这个请求/回应亲签"。

    协调者(_verify_peer_work)与市场 worker 共用。三道:
      1. 验签 + signer_did == expected_signer(同 reputation/binding 模式);
      2. request_sha256 == sha256(prompt) —— 否则重放别处签的 receipt;
      3. response_sha256 == sha256(response) —— 否则文本被伪造。
    返回 (ok, reason)。
    """
    import hashlib

    if not isinstance(receipt, dict) or not receipt:
        return False, "no-receipt"
    try:
        from nth_dao.execution_receipt import verify_receipt
    except ImportError:
        return False, "crypto-unavailable"
    if not verify_receipt(receipt):
        return False, "receipt-sig-invalid"
    if str(receipt.get("signer_did", "")) != expected_signer:
        return False, "receipt-signer-mismatch"
    payload = _a2a_ask_payload(receipt)
    if payload is None:
        return False, "receipt-no-ask-entry"
    if str(payload.get("request_sha256", "")) != hashlib.sha256(
        prompt.encode("utf-8")
    ).hexdigest():
        return False, "request-not-bound"
    if str(payload.get("response_sha256", "")) != hashlib.sha256(
        (response or "").encode("utf-8")
    ).hexdigest():
        return False, "response-not-bound"
    return True, ""
