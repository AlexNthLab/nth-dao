"""温层:签名摘要(对话压缩,但保留可验价值)。

对话方案(见对话):热层是易耗工作记忆;**温层把累积的原文滚成一条
签名摘要**,原文随后让热层 TTL 自然蒸发,活跃上下文 = 最新摘要 + 最近 K
条。摘要必须**可独立验证**——否则压缩就是"丢证据"。

关键:不造新加密。一条摘要 = 一次特殊的 ask(prompt=对话**规范转录**,
response=摘要)。agent 的 ask receipt 已经把 request_sha256(转录)+
response_sha256(摘要)都签上了。于是 ``verify_summary`` 直接复用
``verify_work_receipt`` 就能证明:**这条摘要确由该 agent、为这段确切原文
而签**。和 federation digest(把海量记录压成可验 digest)同构。

冷层(承诺收据)是另一回事:对话产生付款/决议/工作时引用已有 receipt,
不在这里。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from nth_dao.orchestration.a2a_coordinator import verify_work_receipt

# 固定摘要指令(必须 make/verify 两侧一致 —— 它是签名 prompt 的一部分)。
DEFAULT_INSTRUCTION = (
    "请把下面这段对话压缩成简短摘要,保留关键决定、事实与待办事项,"
    "中文,不要寒暄、不要复述无关内容:"
)


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def canonical_transcript(messages: List[Dict[str, Any]]) -> str:
    """把消息列表规范化成**确定性**转录(摘要 prompt 的主体)。

    确定性是可验性的前提:make 和 verify 必须从同一批消息得到同一字符串,
    才能让 receipt 的 request_sha256 对得上。形如每行 ``<who>: <body>``。
    """
    lines = []
    for m in messages:
        who = str(m.get("sender_label") or m.get("sender_id") or "?")
        body = str(m.get("body") or "")
        lines.append(f"{who}: {body}")
    return "\n".join(lines)


def summary_prompt(transcript: str, instruction: Optional[str] = None) -> str:
    return f"{instruction or DEFAULT_INSTRUCTION}\n\n{transcript}"


@dataclass
class SummaryRecord:
    """温层一条签名摘要(小、可验、可持久;原文可随后蒸发)。"""

    conversation_id: str
    covered_message_ids: List[str]
    transcript_sha256: str          # 锚定被概括的原文(内容寻址)
    summary_text: str
    agent_did: str
    instruction: str
    receipt: Optional[Dict[str, Any]]
    verified: bool
    reason: str = ""
    prev_summary_sha256: str = ""   # 预留:摘要可链成可验 rollup(像 append-only 日志)
    created_at_ms: int = 0

    def summary_sha256(self) -> str:
        return _sha256(self.summary_text)


def make_summary(
    node: Any,                      # NodeClient(有 .ask(did, prompt)->AskResult)
    did: str,
    messages: List[Dict[str, Any]],
    *,
    conversation_id: str = "",
    instruction: Optional[str] = None,
    prev_summary_sha256: str = "",
) -> SummaryRecord:
    """让 agent 把 messages 压成一条**签名摘要**(经 node.ask)。

    返回的 SummaryRecord 自带验签结论(node.ask 内部已 verify_work_receipt:
    signer==did + 绑定转录/摘要)。
    """
    instr = instruction or DEFAULT_INSTRUCTION
    transcript = canonical_transcript(messages)
    res = node.ask(did, summary_prompt(transcript, instr))
    return SummaryRecord(
        conversation_id=conversation_id,
        covered_message_ids=[str(m.get("message_id", "")) for m in messages],
        transcript_sha256=_sha256(transcript),
        summary_text=res.text,
        agent_did=res.agent_did or did,
        instruction=instr,
        receipt=res.receipt,
        verified=res.verified,
        reason=res.reason,
    )


def verify_summary(
    receipt: Optional[Dict[str, Any]],
    *,
    summary_text: str,
    messages: List[Dict[str, Any]],
    expected_signer: str,
    instruction: Optional[str] = None,
) -> "tuple[bool, str]":
    """离线独立验证:这条摘要确由 expected_signer、为这批 messages 而签。

    重建同样的摘要 prompt(规范转录 + 同一指令),交给 verify_work_receipt:
    signer 对不上 / 转录被改(request-not-bound)/ 摘要被改(response-not-bound)
    任一即 (False, reason)。
    """
    prompt = summary_prompt(canonical_transcript(messages), instruction)
    return verify_work_receipt(
        receipt, expected_signer=expected_signer,
        prompt=prompt, response=summary_text)
