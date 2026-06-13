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
  - 发现是**未认证**的(UDP/mDNS 广播),恶意节点可广播 ``did=受害者DID``
    配自己的 endpoint(冒名)。两道闸已合上:
      1. 工作伪造:协调者要求 step 附该 DID 亲签且**绑定请求/回应**的
         receipt —— 冒名者无受害者私钥,伪造工作被拒(2ad19b1 + 198f4cb)。
      2. endpoint↔DID 误路由:``resolve_a2a_peers(verify_identity=True)`` 用
         ``verify_peer_identity`` 挑战-应答,**证明 endpoint 确实掌握所称
         DID 的私钥**才入组 —— 冒名记录连组都进不去,任务不会被误路由
         (本次收口)。
    至此发现→传输链的"身份+内容+落点"三绑全闭环。
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Callable, Iterable, List, Optional, Protocol

from nth_dao.orchestration.a2a_coordinator import (
    A2APeer, DispatchFn, PeerResponse, _a2a_ask_payload,
)


class DiscoveredPeer(Protocol):
    """发现记录的最小形状(LANPeer 满足)。"""

    did: str
    capabilities: List[str]
    label: str


# dispatch_for(peer) -> 该 peer 的 DispatchFn。把"怎么够到 + 带什么凭据"
# 留给调用方(本地 hub /ask 代理 / 远程 /a2a/ask + CapToken)。
DispatchForFn = Callable[[Any], DispatchFn]


def verify_peer_identity(
    did: str, dispatch: DispatchFn, *, nonce: Optional[str] = None,
) -> "tuple[bool, str]":
    """挑战-应答:证明应答 ``dispatch`` 的 endpoint 确实掌握 ``did`` 的私钥。

    返回 (ok, reason)。发一个**随机 nonce** 当 prompt,要求回的签名 receipt
    满足:signer_did==did 且 request_sha256==sha256(nonce)。冒名者(在错的
    endpoint 上谎称是 did)既签不出该 did 的 receipt,也绑不上这个**当场新
    生成**的 nonce(防 replay 旧 receipt)→ 失败。复用 receipt 内容绑定
    (198f4cb)即得身份证明,无需新端点。

    代价:一次 ask 往返(对真 LLM backend 是一次廉价调用)。发现不频繁,
    可接受;未来可加一个只签 nonce、不跑 backend 的轻量 challenge 端点。

    残留(诚实):这证明的是"该 endpoint 能拿到 did 私钥签的应答"——一个
    **透明 MITM 代理**(转发给真 agent)也能过握手,从而窃听 prompt / 拖延
    (DoS)。但它**改不了**回应(response_sha256 绑定),也偷不到工作信誉。
    彻底防 MITM 需信道绑定(TLS / 证书钉);LAN/testnet 范围内可接受。
    """
    import hashlib
    import secrets

    try:
        from nth_dao.execution_receipt import verify_receipt
    except ImportError:
        return False, "crypto-unavailable"
    challenge = nonce or ("nth-id-challenge:" + secrets.token_hex(16))
    try:
        resp = dispatch(challenge)
    except Exception as exc:
        return False, f"dispatch-failed: {exc}"
    receipt = resp.receipt
    if not isinstance(receipt, dict) or not receipt:
        return False, "no-receipt"
    if not verify_receipt(receipt):
        return False, "sig-invalid"
    if str(receipt.get("signer_did", "")) != did:
        return False, "signer-mismatch"
    payload = _a2a_ask_payload(receipt)
    if payload is None:
        return False, "no-ask-entry"
    if str(payload.get("request_sha256", "")) != hashlib.sha256(
        challenge.encode("utf-8")
    ).hexdigest():
        return False, "challenge-not-bound"
    return True, ""


def resolve_a2a_peers(
    discovered: Iterable[Any],
    *,
    dispatch_for: DispatchForFn,
    want_capabilities: Optional[Iterable[str]] = None,
    verify_identity: bool = False,
    max_candidates: Optional[int] = 256,
    on_reject: Optional[Callable[[str, str], None]] = None,
) -> List[A2APeer]:
    """把发现记录映射成 A2APeer 列表。

    Args:
        discovered: 发现到的 peer 记录(需有 .did/.capabilities/.label)。
        dispatch_for: peer -> DispatchFn(注入传输+信任)。
        want_capabilities: 若给定,只保留能力有交集的 peer。
        verify_identity: True 时对每个候选跑 ``verify_peer_identity`` 挑战-
            应答,**证明 endpoint 确实掌握所声称 DID 的私钥**才入组 —— 关掉
            "冒名记录把任务误路由到错 endpoint"的最后缺口。默认 False(纯
            映射,适用于来源本就可信/本地的场景)。
        max_candidates: **审查加固(DoS 上限)**。发现是未认证的,攻击者可
            灌入海量假记录;verify_identity 开时每条都触发一次阻塞 dispatch
            (网络往返),且记录可指向**第三方**端点,把协调者变成对其的
            反射式 DoS。这里硬性只处理前 N 条;超出即停(剩余 on_reject
            "over-limit")。调用方应在 resolve 前按能力/信誉先行收窄
            ``discovered``——这是兜底,不是替代。None=不限(仅用于可信来源)。
        on_reject: (did, reason) 回调,记录被剔除的候选(可观测性)。

    过滤:无 did / 重复 / 能力不符 / 超量 / (开了校验时)身份证明不过 → 不入组。

    ⚠️ 前置去重是"先到先得":``verify_identity=False`` 时,同一 DID 谁先
    广播谁占位 —— 攻击者抢先广播即可劫持该 DID 的路由。**未认证来源必须
    开 verify_identity=True**(此时冒名者过不了握手,先到也无效)。
    """
    want = set(want_capabilities) if want_capabilities else None
    out: List[A2APeer] = []
    seen: set[str] = set()
    processed = 0
    for p in discovered:
        if max_candidates is not None and processed >= max_candidates:
            did = str(getattr(p, "did", "") or "")
            if did and on_reject:
                on_reject(did, "over-limit")
            continue  # 超出上限:不再做阻塞握手,兜底防 DoS
        did = str(getattr(p, "did", "") or "")
        if not did or did in seen:
            if did and on_reject:
                on_reject(did, "duplicate")
            continue  # 无 DID 或重复 → 不入组
        caps = list(getattr(p, "capabilities", []) or [])
        if want is not None and not (want & set(caps)):
            if on_reject:
                on_reject(did, "capability-mismatch")
            continue
        label = str(getattr(p, "label", "") or getattr(p, "agent_id", "") or did)
        dispatch = dispatch_for(p)
        if verify_identity:
            processed += 1  # 握手是昂贵步:只对真正发起握手的候选计数
            ok, reason = verify_peer_identity(did, dispatch)
            if not ok:
                if on_reject:
                    on_reject(did, f"identity:{reason}")
                continue  # endpoint 证明不了它掌握该 DID → 拒(防冒名误路由)
        else:
            processed += 1
        out.append(A2APeer(did=did, capabilities=caps,
                           dispatch=dispatch, label=label))
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
