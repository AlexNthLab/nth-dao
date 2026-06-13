"""NodeClient —— 够到一个 NTH DAO 节点的可复用 HTTP 客户端。

封装节点的 ``/api/v2`` 面:列 agent、驱动 agent(``/ask``)、并对每次回应
**验签**(verify_work_receipt:signer==agent DID 且绑定本请求/回应)。

谁用它:
  - 跨节点协调(本机协调者驱动远程节点的 agent);
  - Telegram → A2A 桥(把聊天消息转成对某 agent 的 ask)。
两者都因此继承"只认签名工作证据"的保证 —— 任何回到 Telegram / 协调者的
答复,都背书着一张该 agent 亲签、绑定内容的 receipt。

HTTP 可注入(``_http``),便于测试无需真 socket。
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from nth_dao.orchestration.a2a_coordinator import verify_work_receipt


class NodeError(Exception):
    """节点交互失败(HTTP 错误 / agent 不就绪 / 解析失败)。"""


@dataclass
class AskResult:
    """一次 ask 的结果(含签名校验结论)。"""

    text: str
    agent_did: str
    receipt: Optional[Dict[str, Any]]
    verified: bool
    reason: str = ""


# post/get 注入点:(method, url, body_or_None, headers) -> (status, parsed_json)
HttpFn = Callable[[str, str, Optional[dict], dict], "tuple[int, dict]"]


def _urllib_http(method: str, url: str, body: Optional[dict], headers: dict,
                 *, timeout: float) -> "tuple[int, dict]":
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            raw = resp.read().decode("utf-8", "replace")
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace") if e.fp else ""
        try:
            return e.code, (json.loads(raw) if raw else {})
        except json.JSONDecodeError:
            return e.code, {"detail": raw[:200]}


class NodeClient:
    """一个 NTH DAO 节点的客户端。"""

    def __init__(
        self,
        base_url: str,
        token: Optional[str] = None,
        *,
        verify_receipts: bool = True,
        timeout: float = 70.0,
        _http: Optional[HttpFn] = None,
    ) -> None:
        self.base = base_url.rstrip("/")
        self.token = token
        self.verify_receipts = verify_receipts
        self.timeout = timeout
        self._http: HttpFn = _http or (
            lambda m, u, b, h: _urllib_http(m, u, b, h, timeout=timeout))

    def _headers(self, *, json_body: bool = False) -> dict:
        h = {"Accept": "application/json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        if json_body:
            h["Content-Type"] = "application/json"
        return h

    def list_agents(self) -> List[Dict[str, Any]]:
        st, data = self._http("GET", f"{self.base}/api/v2/agents", None,
                              self._headers())
        if st != 200:
            raise NodeError(f"list_agents → HTTP {st}: {str(data)[:160]}")
        return data if isinstance(data, list) else []

    def drivable_agents(self) -> List[Dict[str, Any]]:
        """只留可经 /ask 驱动的:supervised + alive + 有 a2a_port(int)。"""
        out = []
        for a in self.list_agents():
            if (a.get("supervised") and a.get("alive")
                    and isinstance(a.get("a2a_port"), int)):
                out.append(a)
        return out

    def resolve_agent(self, ref: str) -> Optional[Dict[str, Any]]:
        """按 did 或 label 找一个可驱动 agent。"""
        for a in self.drivable_agents():
            if a.get("did") == ref or a.get("label") == ref:
                return a
        return None

    def ask(
        self,
        did: str,
        prompt: str,
        *,
        poll_tries: int = 30,
        poll_interval: float = 2.0,
    ) -> AskResult:
        """驱动 agent 干活,轮询等 authorized,返回带验签结论的结果。

        not-yet-authorized 窗口内继续轮询;真错误(401 缺 token/404 等)立即
        抛 NodeError。verify_receipts 开时,receipt 必须验签通过且 signer==did
        且绑定本 prompt/response,否则 verified=False(reason 说明)。
        """
        url = f"{self.base}/api/v2/agents/{did}/ask"
        last = ""
        for _ in range(poll_tries):
            st, data = self._http("POST", url, {"prompt": prompt},
                                  self._headers(json_body=True))
            blob = json.dumps(data, ensure_ascii=False)
            if "not-yet-authorized" in blob:
                last = "not-yet-authorized"
                time.sleep(poll_interval)
                continue
            if st != 200:
                raise NodeError(f"ask {did} → HTTP {st}: {str(data)[:160]}")
            res = data.get("result", data) if isinstance(data, dict) else {}
            text = str(res.get("response", ""))
            receipt = res.get("receipt")
            agent_did = str(res.get("agent_did", ""))
            verified, reason = True, ""
            if self.verify_receipts:
                verified, reason = verify_work_receipt(
                    receipt, expected_signer=did, prompt=prompt, response=text)
            return AskResult(text=text, agent_did=agent_did, receipt=receipt,
                             verified=verified, reason=reason)
        raise NodeError(f"agent {did} 未就绪({last or '无响应'})")

    def ask_ref(self, ref: str, prompt: str, **kw: Any) -> AskResult:
        """按 did/label 解析后 ask;解析不到 → NodeError。"""
        a = self.resolve_agent(ref)
        if a is None:
            raise NodeError(f"找不到可驱动 agent: {ref!r}")
        return self.ask(str(a["did"]), prompt, **kw)
