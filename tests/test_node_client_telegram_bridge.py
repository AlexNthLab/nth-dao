"""NodeClient + Telegram 桥纯逻辑测试(假 HTTP,无 socket / 无 Telegram)。

验证桥的核心:对节点 /ask 的回应**验签**(signer==agent + 绑定请求/回应),
并把结论格式化成带徽标的 Telegram 文本。
"""

from __future__ import annotations

import pytest

pytest.importorskip("nacl")

from nth_dao.cap_token import sign_cap_token, CAP_NTH_RECEIPT_SIGN
from nth_dao.identity import AgentIdentity
from nth_dao.execution_receipt import now_ms
from nth_dao.web.dummy_agent import _build_a2a_ask_receipt
from nth_dao.integrations.node_client import NodeClient, NodeError, AskResult
from nth_dao.integrations.telegram_bridge import (
    format_reply, list_agents_text, resolve_target,
)


def _fake_http(agent, cap, *, response="42", not_yet=0, tamper_text=None):
    calls = {"n": 0}

    def http(method, url, body, headers):
        if url.endswith("/api/v2/agents") and method == "GET":
            return 200, [{
                "did": agent.as_did(), "label": "calc", "supervised": True,
                "alive": True, "a2a_port": 1234, "capabilities": ["math"],
            }, {
                "did": "did:key:zDead", "label": "dead", "supervised": True,
                "alive": False, "a2a_port": None, "capabilities": [],
            }]
        if "/ask" in url and method == "POST":
            calls["n"] += 1
            if calls["n"] <= not_yet:
                return 401, {"error": {"code": "not-yet-authorized"}}
            prompt = body["prompt"]
            t0 = now_ms()
            receipt, _ = _build_a2a_ask_receipt(
                identity=agent, method="ask", backend_name="t", token=cap,
                agent_did=agent.as_did(), params={"prompt": prompt},
                result={"response": response}, started_at_ms=t0, ended_at_ms=now_ms())
            # tamper_text:回的文本和 receipt 里 hash 的不一致(模拟伪造)
            ret_text = tamper_text if tamper_text is not None else response
            return 200, {"result": {"response": ret_text, "receipt": receipt,
                                    "agent_did": agent.as_did()}}
        return 404, {"detail": "nf"}

    return http, calls


def _client(http):
    return NodeClient("http://node", token="t", _http=http)


def test_ask_returns_verified_signed_result() -> None:
    agent = AgentIdentity.generate(label="calc")
    cap = sign_cap_token(issuer=AgentIdentity.generate(), subject_did=agent.as_did(),
                         capabilities=["math", CAP_NTH_RECEIPT_SIGN])
    http, _ = _fake_http(agent, cap, response="42")
    res = _client(http).ask(agent.as_did(), "6*7?", poll_interval=0)
    assert res.text == "42" and res.verified and not res.reason
    assert res.agent_did == agent.as_did()


def test_ask_polls_past_not_yet_authorized() -> None:
    agent = AgentIdentity.generate()
    cap = sign_cap_token(issuer=AgentIdentity.generate(), subject_did=agent.as_did(),
                         capabilities=[CAP_NTH_RECEIPT_SIGN])
    http, calls = _fake_http(agent, cap, not_yet=2)
    res = _client(http).ask(agent.as_did(), "hi", poll_interval=0)
    assert res.verified and calls["n"] == 3  # 2 次未授权 + 第 3 次成功


def test_ask_rejects_tampered_text() -> None:
    """receipt 真签,但回的文本被改 → verify_work_receipt 判 response-not-bound。"""
    agent = AgentIdentity.generate()
    cap = sign_cap_token(issuer=AgentIdentity.generate(), subject_did=agent.as_did(),
                         capabilities=[CAP_NTH_RECEIPT_SIGN])
    http, _ = _fake_http(agent, cap, response="real", tamper_text="伪造")
    res = _client(http).ask(agent.as_did(), "q", poll_interval=0)
    assert not res.verified and res.reason == "response-not-bound"


def test_ask_raises_on_http_error() -> None:
    agent = AgentIdentity.generate()
    cap = sign_cap_token(issuer=AgentIdentity.generate(), subject_did=agent.as_did(),
                         capabilities=[CAP_NTH_RECEIPT_SIGN])
    http, _ = _fake_http(agent, cap)
    # 打一个不存在的 did → 假 http 的 /ask 分支仍回 200… 用未知 url 触发 404:
    c = _client(lambda m, u, b, h: (404, {"detail": "x"}))
    with pytest.raises(NodeError):
        c.ask("did:key:zX", "q", poll_tries=1, poll_interval=0)


def test_drivable_and_resolve_filtering() -> None:
    agent = AgentIdentity.generate()
    cap = sign_cap_token(issuer=AgentIdentity.generate(), subject_did=agent.as_did(),
                         capabilities=[CAP_NTH_RECEIPT_SIGN])
    http, _ = _fake_http(agent, cap)
    c = _client(http)
    dr = c.drivable_agents()
    assert [a["label"] for a in dr] == ["calc"]  # dead(alive=False/a2a_port=None)被滤
    assert c.resolve_agent("calc")["did"] == agent.as_did()      # 按 label
    assert c.resolve_agent(agent.as_did())["label"] == "calc"    # 按 did
    assert c.resolve_agent("nope") is None


def test_format_reply_badges() -> None:
    ok = AskResult(text="hi", agent_did="did:key:zAbcdef0123456789", receipt={"x": 1}, verified=True)
    assert "✓ 已验签" in format_reply(ok) and "hi" in format_reply(ok)
    bad = AskResult(text="hi", agent_did="did:key:z", receipt={"x": 1}, verified=False, reason="response-not-bound")
    assert "⚠️ 验签失败" in format_reply(bad)
    nor = AskResult(text="hi", agent_did="", receipt=None, verified=False)
    assert "无签名 receipt" in format_reply(nor)
    empty = AskResult(text="", agent_did="d", receipt=None, verified=False)
    assert "(空回复)" in format_reply(empty)


def test_resolve_target_precedence() -> None:
    agent = AgentIdentity.generate()
    cap = sign_cap_token(issuer=AgentIdentity.generate(), subject_did=agent.as_did(),
                         capabilities=[CAP_NTH_RECEIPT_SIGN])
    http, _ = _fake_http(agent, cap)
    c = _client(http)
    # 本聊天 /use 的优先于默认
    assert resolve_target(c, {7: "calc"}, 7, None)["label"] == "calc"
    # 没选 + 没默认 → None
    assert resolve_target(c, {}, 7, None) is None
    # 用默认
    assert resolve_target(c, {}, 7, "calc")["label"] == "calc"
