"""发现平面 → 传输平面的接缝:把发现到的 peer 解析成 A2APeer。

根本方案第二块(发现平面):A2ACoordinator 只认 A2APeer{did, capabilities,
dispatch}。本模块把 LAN/联邦发现到的对端(LANPeer 等,带 did + 网络地址 +
能力)映射成 A2APeer —— **协调者代码一行不变**,peer 的来源从"本地 spawn"
换成"全网发现"。这就是把"同构 peer"从本机扩到全网的那一步。

边界(诚实):
  - DID→endpoint 解析:✅ 发现记录已带 did + source_addr/ws_url。
  - 跨节点驱动远程 /a2a/ask 需要对端接受的 cap_token —— 那是**联邦信任
    握手**(对端给你签一张 token),不在本模块。这里把"怎么够到对端 +
    带什么凭据"作为 ``dispatch_for`` 注入,信任模型可插拔、不写死。
  - 无 DID 的 legacy peer 不可寻址、其工作也无法验签(协调者已强制
    signed-receipt)→ 直接滤掉,不让它进组。
  - ⚠️ 发现是**未认证**的(UDP/mDNS 广播)。恶意节点可广播
    ``did=受害者DID`` 配自己的 endpoint(冒名)。但协调者要求"完成的
    step 必须附该 DID 亲签的 receipt"——冒名者没有受害者私钥,**伪造的
    工作会被拒**(这正是上一步先做 signed-receipt 的回报)。**未**绑定的
    是 endpoint↔DID:一条冒名记录仍可能把任务**误路由/DoS**到错的
    endpoint(任务发出去但完不成、step 失败)。彻底绑定靠联邦信任握手
    (对端用其 DID 签一张 token 证明"这个 endpoint 确是我")—— 下一层。
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Callable, Iterable, List, Optional, Protocol

from nth_dao.orchestration.a2a_coordinator import A2APeer, DispatchFn, PeerResponse


class DiscoveredPeer(Protocol):
    """发现记录的最小形状(LANPeer 满足)。"""

    did: str
    capabilities: List[str]
    label: str


# dispatch_for(peer) -> 该 peer 的 DispatchFn。把"怎么够到 + 带什么凭据"
# 留给调用方(本地 hub /ask 代理 / 远程 /a2a/ask + CapToken)。
DispatchForFn = Callable[[Any], DispatchFn]


def resolve_a2a_peers(
    discovered: Iterable[Any],
    *,
    dispatch_for: DispatchForFn,
    want_capabilities: Optional[Iterable[str]] = None,
) -> List[A2APeer]:
    """把发现记录映射成 A2APeer 列表。

    Args:
        discovered: 发现到的 peer 记录(需有 .did/.capabilities/.label)。
        dispatch_for: peer -> DispatchFn(注入传输+信任)。
        want_capabilities: 若给定,只保留能力有交集的 peer。

    过滤:无 did 的记录直接跳过(不可寻址 + 工作无法验签)。
    """
    want = set(want_capabilities) if want_capabilities else None
    out: List[A2APeer] = []
    seen: set[str] = set()
    for p in discovered:
        did = str(getattr(p, "did", "") or "")
        if not did or did in seen:
            continue  # 无 DID 或重复 → 不入组
        caps = list(getattr(p, "capabilities", []) or [])
        if want is not None and not (want & set(caps)):
            continue
        label = str(getattr(p, "label", "") or getattr(p, "agent_id", "") or did)
        out.append(A2APeer(did=did, capabilities=caps,
                           dispatch=dispatch_for(p), label=label))
        seen.add(did)
    return out


# ── 真实 HTTP dispatch(指向真节点时用)──

# post(url, body, headers) -> (status_code, parsed_json)。默认 urllib;
# 测试可注入假实现,无需真 socket。
PostFn = Callable[[str, dict, dict], "tuple[int, dict]"]


def _urllib_post(url: str, body: dict, headers: dict, *, timeout: float) -> "tuple[int, dict]":
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace") if e.fp else ""
        try:
            return e.code, json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            return e.code, {"detail": raw[:200]}


def make_http_dispatch(
    ask_url: str,
    *,
    auth_header: Optional[str] = None,
    timeout: float = 60.0,
    post: Optional[PostFn] = None,
) -> DispatchFn:
    """构造一个打真 HTTP /a2a/ask 的 DispatchFn(满足"自带超时"契约)。

    Args:
        ask_url: 对端 ask 端点的完整 URL。
        auth_header: ``Authorization`` 头(如 ``CapToken <...>``);跨节点
            驱动必带,本地 hub 代理可省。
        timeout: 硬超时(秒)—— 兑现 dispatch 契约,挂死 peer 不卡协调者。
        post: 可注入的 POST 实现(测试用);默认 urllib。

    解析对端 ``{result:{response, receipt, agent_did}}`` → PeerResponse。
    """
    _post: PostFn = post or (lambda u, b, h: _urllib_post(u, b, h, timeout=timeout))

    def dispatch(prompt: str) -> PeerResponse:
        headers = {"Accept": "application/json"}
        if auth_header:
            headers["Authorization"] = auth_header
        status, payload = _post(ask_url, {"prompt": prompt}, headers)
        if status != 200:
            raise RuntimeError(f"ask {ask_url} → HTTP {status}: "
                               f"{str(payload.get('detail', payload))[:160]}")
        result = payload.get("result", payload) if isinstance(payload, dict) else {}
        return PeerResponse(
            text=str(result.get("response", "")),
            receipt=result.get("receipt"),
            agent_did=str(result.get("agent_did", "")),
        )

    return dispatch
