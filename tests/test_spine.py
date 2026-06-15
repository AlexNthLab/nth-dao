"""Spine(统一签名因果日志)Phase 1 测试:链接、持久化、防篡改、签名、投影。"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("nacl")

from nth_dao.identity import AgentIdentity
from nth_dao.spine import (
    GENESIS_PREV,
    Projection,
    SignedEventLog,
    replay,
    sign_event,
    verify_event,
)


def _id() -> AgentIdentity:
    return AgentIdentity.generate()


def _rewrite_line(path: Path, idx: int, obj: dict) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[idx] = json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_append_chains_and_verifies(tmp_path: Path) -> None:
    log = SignedEventLog(tmp_path / "events.jsonl", _id())
    e0 = log.append("market.announce", {"id": "a"})
    e1 = log.append("market.claim", {"id": "a", "by": "x"})
    e2 = log.append("receipt.record", {"rid": "r1"})
    assert [e0.seq, e1.seq, e2.seq] == [0, 1, 2]
    assert e0.prev_hash == GENESIS_PREV
    assert e1.prev_hash == e0.content_hash
    assert e2.prev_hash == e1.content_hash
    ok, why = log.verify_chain()
    assert ok, why


def test_persistence_reloads_head_and_continues(tmp_path: Path) -> None:
    p = tmp_path / "events.jsonl"
    ident = _id()
    log = SignedEventLog(p, ident)
    log.append("t", {"n": 1})
    log.append("t", {"n": 2})
    # 新实例同路径:应重载链头,继续链(不从 0 重开)。
    log2 = SignedEventLog(p, ident)
    assert log2.head_seq == 1
    e = log2.append("t", {"n": 3})
    assert e.seq == 2
    assert e.prev_hash != GENESIS_PREV
    ok, why = log2.verify_chain()
    assert ok, why


def test_tamper_payload_breaks_verification(tmp_path: Path) -> None:
    p = tmp_path / "events.jsonl"
    log = SignedEventLog(p, _id())
    log.append("t", {"amount": 5})
    log.append("t", {"amount": 6})
    first = json.loads(p.read_text(encoding="utf-8").splitlines()[0])
    first["payload"]["amount"] = 9999   # 篡改历史 payload,不改 content_hash
    _rewrite_line(p, 0, first)
    ok, why = SignedEventLog(p, _id()).verify_chain()
    assert not ok
    assert "content_hash mismatch" in why


def test_tamper_prev_hash_breaks_chain(tmp_path: Path) -> None:
    p = tmp_path / "events.jsonl"
    log = SignedEventLog(p, _id())
    log.append("t", {"n": 1})
    log.append("t", {"n": 2})
    second = json.loads(p.read_text(encoding="utf-8").splitlines()[1])
    second["prev_hash"] = "1" * 64   # 断链
    _rewrite_line(p, 1, second)
    ok, why = SignedEventLog(p, _id()).verify_chain()
    assert not ok


def test_corrupt_line_fails_closed_not_crash(tmp_path: Path) -> None:
    # 对抗审查发现:损坏行(非法 JSON / 结构坏)必须返回 False,不能抛异常。
    # 用**已构造的 handle** 校验(模拟"在跑的进程持有日志句柄,文件被静默篡改")。
    p = tmp_path / "events.jsonl"
    log = SignedEventLog(p, _id())
    log.append("t", {"n": 1})
    log.append("t", {"n": 2})
    line0 = p.read_text(encoding="utf-8").splitlines()[0]

    # ① 第二行换成非法 JSON → verify_chain 返回 False(不抛)。
    p.write_text(line0 + "\n{not json]\n", encoding="utf-8")
    ok, why = log.verify_chain()
    assert not ok and "unparseable" in why

    # ② 结构坏:payload 不是 dict(JSON 合法但 from_dict 失败)→ 仍 False。
    _rewrite_line(p, 1, {"seq": 1, "prev_hash": "0" * 64, "type": "t",
                         "payload": "notdict", "author_did": "did:key:zX",
                         "ts_ms": 1, "content_hash": "", "sig": ""})
    ok2, _ = log.verify_chain()
    assert not ok2

    # ③ 构造写入者拒绝打开损坏日志(清晰错误,不裸崩)。
    with pytest.raises(ValueError, match="corrupt"):
        SignedEventLog(p, _id())


def test_event_authored_by_other_did_verifies(tmp_path: Path) -> None:
    # 事件用作者 DID 的公钥校验(非日志持有者),跨主体可验。
    author = _id()
    e = sign_event(
        seq=0, prev_hash=GENESIS_PREV, event_type="t",
        payload={"x": 1}, identity=author, ts_ms=1,
    )
    ok, why = verify_event(e)
    assert ok, why
    assert e.author_did == author.as_did()
    # 篡改签名 → 失败。
    e.sig = e.sig[:-2] + ("aa" if not e.sig.endswith("aa") else "bb")
    ok2, _ = verify_event(e)
    assert not ok2


def test_projection_folds_event_stream(tmp_path: Path) -> None:
    p = tmp_path / "events.jsonl"
    log = SignedEventLog(p, _id())
    log.append("deposit", {"amount": 10})
    log.append("deposit", {"amount": 5})
    log.append("withdraw", {"amount": 3})

    class Balance(Projection):
        def __init__(self) -> None:
            self.total = 0

        def reset(self) -> None:
            self.total = 0

        def apply(self, ev) -> None:
            if ev.type == "deposit":
                self.total += ev.payload["amount"]
            elif ev.type == "withdraw":
                self.total -= ev.payload["amount"]

    ok, why = log.verify_chain()
    assert ok, why
    bal = Balance()
    replay(log.read_all(), bal)
    assert bal.total == 12
