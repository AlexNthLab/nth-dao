"""温层签名摘要测试:make + 独立验证 + 篡改检测(假 HTTP,无 socket)。

证明压缩**不丢可验性**:摘要由 agent 亲签、锚定确切原文;改原文或改摘要
都验不过。
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("nacl")

from nth_dao.cap_token import sign_cap_token, CAP_NTH_RECEIPT_SIGN
from nth_dao.identity import AgentIdentity
from nth_dao.execution_receipt import now_ms
from nth_dao.web.dummy_agent import _build_a2a_ask_receipt
from nth_dao.integrations.node_client import NodeClient
from nth_dao.conversation.summary import (
    canonical_transcript, make_summary, verify_summary, SummaryRecord,
)

MSGS = [
    {"message_id": "1", "sender_label": "you", "body": "天空为什么是蓝的?"},
    {"message_id": "2", "sender_label": "agent", "body": "瑞利散射,蓝光散射更强。"},
    {"message_id": "3", "sender_label": "you", "body": "那日落为什么红?"},
    {"message_id": "4", "sender_label": "agent", "body": "斜射穿过更厚大气,蓝光被散掉,剩红。"},
]
SUMMARY = "讨论了天空蓝(瑞利散射)与日落红(斜射厚大气滤蓝)。"


def _node(agent, cap, response):
    """假 HTTP 的 NodeClient:/ask 对任意 prompt 都签一张真 receipt 并回 response。"""
    def http(method, url, body, headers):
        if "/ask" in url and method == "POST":
            prompt = body["prompt"]
            t0 = now_ms()
            receipt, _ = _build_a2a_ask_receipt(
                identity=agent, method="ask", backend_name="t", token=cap,
                agent_did=agent.as_did(), params={"prompt": prompt},
                result={"response": response}, started_at_ms=t0, ended_at_ms=now_ms())
            return 200, {"result": {"response": response, "receipt": receipt,
                                    "agent_did": agent.as_did()}}
        return 404, {"detail": "nf"}
    return NodeClient("http://n", _http=http)


def test_canonical_transcript_deterministic() -> None:
    t1 = canonical_transcript(MSGS)
    t2 = canonical_transcript(MSGS)
    assert t1 == t2 and "[1] you: 天空为什么是蓝的?" in t1


def test_transcript_injective_no_newline_collision() -> None:
    """审查A 回归:一条含换行的消息**不能**冒充成两条 → 转录必须不同,
    否则签给 A 的摘要会验过伪造的 B。"""
    a = [{"message_id": "1", "sender_label": "you", "body": "hello\nyou: world"}]
    b = [
        {"message_id": "1", "sender_label": "you", "body": "hello"},
        {"message_id": "2", "sender_label": "you", "body": "world"},
    ]
    assert canonical_transcript(a) != canonical_transcript(b)
    # 顺带:改 message_id 也改变转录(id 进了签名锚)
    c = [dict(MSGS[0], message_id="99"), *MSGS[1:]]
    assert canonical_transcript(c) != canonical_transcript(MSGS)


def test_summary_does_not_verify_for_collision_set() -> None:
    """端到端:对带换行的单条消息签摘要,拿"看似等价"的两条来验 → 拒。"""
    agent = AgentIdentity.generate()
    cap = sign_cap_token(issuer=AgentIdentity.generate(), subject_did=agent.as_did(),
                         capabilities=[CAP_NTH_RECEIPT_SIGN])
    single = [{"message_id": "1", "sender_label": "you", "body": "a\nyou: b"}]
    rec = make_summary(_node(agent, cap, SUMMARY), agent.as_did(), single)
    forged = [
        {"message_id": "1", "sender_label": "you", "body": "a"},
        {"message_id": "x", "sender_label": "you", "body": "b"},
    ]
    ok, why = verify_summary(rec.receipt, summary_text=rec.summary_text,
                             messages=forged, expected_signer=agent.as_did())
    assert not ok and why == "request-not-bound"


def test_make_summary_signed_and_verifiable() -> None:
    agent = AgentIdentity.generate()
    cap = sign_cap_token(issuer=AgentIdentity.generate(), subject_did=agent.as_did(),
                         capabilities=[CAP_NTH_RECEIPT_SIGN])
    rec = make_summary(_node(agent, cap, SUMMARY), agent.as_did(), MSGS,
                       conversation_id="dm-x")
    assert rec.verified and rec.reason == ""
    assert rec.summary_text == SUMMARY
    assert rec.covered_message_ids == ["1", "2", "3", "4"]
    assert rec.agent_did == agent.as_did()

    # 离线独立验证(别人拿 receipt + 原文也能验)
    ok, why = verify_summary(rec.receipt, summary_text=rec.summary_text,
                             messages=MSGS, expected_signer=agent.as_did())
    assert ok, why


def test_tampered_messages_rejected() -> None:
    """改了被概括的原文(插一条)→ 转录哈希不符 → request-not-bound。"""
    agent = AgentIdentity.generate()
    cap = sign_cap_token(issuer=AgentIdentity.generate(), subject_did=agent.as_did(),
                         capabilities=[CAP_NTH_RECEIPT_SIGN])
    rec = make_summary(_node(agent, cap, SUMMARY), agent.as_did(), MSGS)
    tampered = MSGS + [{"message_id": "5", "sender_label": "you", "body": "偷偷插入"}]
    ok, why = verify_summary(rec.receipt, summary_text=rec.summary_text,
                             messages=tampered, expected_signer=agent.as_did())
    assert not ok and why == "request-not-bound"


def test_tampered_summary_rejected() -> None:
    """改了摘要文本 → response 哈希不符 → response-not-bound。"""
    agent = AgentIdentity.generate()
    cap = sign_cap_token(issuer=AgentIdentity.generate(), subject_did=agent.as_did(),
                         capabilities=[CAP_NTH_RECEIPT_SIGN])
    rec = make_summary(_node(agent, cap, SUMMARY), agent.as_did(), MSGS)
    ok, why = verify_summary(rec.receipt, summary_text="伪造的摘要内容",
                             messages=MSGS, expected_signer=agent.as_did())
    assert not ok and why == "response-not-bound"


def test_wrong_signer_rejected() -> None:
    """换个 DID 来认领这条摘要 → signer 不符。"""
    agent = AgentIdentity.generate()
    cap = sign_cap_token(issuer=AgentIdentity.generate(), subject_did=agent.as_did(),
                         capabilities=[CAP_NTH_RECEIPT_SIGN])
    rec = make_summary(_node(agent, cap, SUMMARY), agent.as_did(), MSGS)
    ok, why = verify_summary(rec.receipt, summary_text=rec.summary_text,
                             messages=MSGS, expected_signer="did:key:zSomeoneElse")
    assert not ok and why == "receipt-signer-mismatch"
