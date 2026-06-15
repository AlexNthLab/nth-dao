"""签名因果事件 —— Nth DAO 统一日志 spine 的最小单元(Phase 1)。

每条事件不可变,通过 ``prev_hash`` 链回前一条 → 形成防篡改 hash 链;
``content_hash`` 是对签名核心字段的 SHA-256(内容寻址,即事件 id);``sig`` 是
作者 DID 用 Ed25519 对 **32 字节哈希摘要** 的签名(与 ``execution_receipt`` 同一
签名约定,跨子系统字节一致)。

完全沿用本仓库既有原语:``canonical_json``(线格式)、``identity``(签名)、
``b64u``(签名编码)、``did_key``(DID↔公钥)—— 不引入外来风格。

信封模型(对齐 execution_receipt):``content_hash``/``sig`` 是信封外字段,不在
签名核心内;核心被 ``content_hash`` 覆盖,``content_hash`` 被 ``sig`` 绑定。改核心
→ 哈希变;改哈希 → 签名失效。
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Tuple

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.identity import AgentIdentity

# 创世事件的 prev_hash:64 个 0(没有前驱)。
GENESIS_PREV = "0" * 64


def event_content_hash(core: Dict[str, Any]) -> str:
    """对签名核心做 canonical_json → SHA-256 → 小写 hex(= 事件内容地址 / id)。"""
    return hashlib.sha256(canonical_json(core)).hexdigest()


@dataclass
class SpineEvent:
    """一条签名因果事件。``core()`` 是被签名覆盖的字段集合。"""

    seq: int
    prev_hash: str
    type: str
    payload: Dict[str, Any]
    author_did: str
    ts_ms: int
    content_hash: str = ""
    sig: str = ""

    @property
    def event_id(self) -> str:
        return self.content_hash

    def core(self) -> Dict[str, Any]:
        return {
            "seq": self.seq,
            "prev_hash": self.prev_hash,
            "type": self.type,
            "payload": self.payload,
            "author_did": self.author_did,
            "ts_ms": self.ts_ms,
        }

    def to_dict(self) -> Dict[str, Any]:
        d = self.core()
        d["content_hash"] = self.content_hash
        d["sig"] = self.sig
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SpineEvent":
        return cls(
            seq=int(d["seq"]),
            prev_hash=str(d["prev_hash"]),
            type=str(d["type"]),
            payload=dict(d["payload"]),
            author_did=str(d["author_did"]),
            ts_ms=int(d["ts_ms"]),
            content_hash=str(d.get("content_hash", "")),
            sig=str(d.get("sig", "")),
        )


def sign_event(
    *,
    seq: int,
    prev_hash: str,
    event_type: str,
    payload: Dict[str, Any],
    identity: AgentIdentity,
    ts_ms: int,
) -> SpineEvent:
    """构造并用 ``identity`` 签名一条事件。作者 DID = ``identity.as_did()``。"""
    core = {
        "seq": int(seq),
        "prev_hash": str(prev_hash),
        "type": str(event_type),
        "payload": payload,
        "author_did": identity.as_did(),
        "ts_ms": int(ts_ms),
    }
    content_hash = event_content_hash(core)
    sig = b64u_encode(identity.sign(bytes.fromhex(content_hash)))
    ev = SpineEvent.from_dict(core)
    ev.content_hash = content_hash
    ev.sig = sig
    return ev


def verify_event(event: SpineEvent) -> Tuple[bool, str]:
    """校验单条事件:重算 content_hash 一致 + 作者 DID 签名有效。fail-closed。"""
    try:
        recomputed = event_content_hash(event.core())
    except Exception as exc:  # noqa: BLE001
        return False, f"content not canonical-json: {exc}"
    if recomputed != event.content_hash:
        return False, "content_hash mismatch (tampered core)"
    try:
        verifier = AgentIdentity.from_did(event.author_did)
        sig_bytes = b64u_decode(event.sig)
    except Exception as exc:  # noqa: BLE001
        return False, f"bad author_did/sig encoding: {exc}"
    if not verifier.verify(bytes.fromhex(event.content_hash), sig_bytes):
        return False, "signature invalid"
    return True, "ok"
