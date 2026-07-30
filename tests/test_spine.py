"""Spine(统一签名因果日志)Phase 1 测试:链接、持久化、防篡改、签名、投影。"""
from __future__ import annotations

import json
import multiprocessing
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
from nth_dao.spine.log import MAX_SPINE_LINE_BYTES


def _id() -> AgentIdentity:
    return AgentIdentity.generate()


def _rewrite_line(path: Path, idx: int, obj: dict) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[idx] = json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _append_in_process(path: str, index: int, output) -> None:
    try:
        event = SignedEventLog(
            path,
            AgentIdentity.generate(),
            lock_timeout=20,
        ).append("test.concurrent", {"index": index})
        output.put(("ok", event.seq))
    except Exception as exc:
        output.put(("error", type(exc).__name__, str(exc)))


def _append_unique_in_process(path: str, output) -> None:
    try:
        event, created = SignedEventLog(
            path,
            AgentIdentity.generate(),
            lock_timeout=20,
        ).append_unique(
            "trade.execution.recorded",
            {
                "execution_id": "exec-one",
                "receipt_digest": "digest-one",
            },
            unique_payload_fields=("execution_id", "receipt_digest"),
            ts_ms=1,
        )
        output.put(("ok", event.event_id, created))
    except Exception as exc:
        output.put(("error", type(exc).__name__, str(exc)))


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


def test_append_refuses_structurally_valid_tampered_chain(
    tmp_path: Path,
) -> None:
    p = tmp_path / "events.jsonl"
    log = SignedEventLog(p, _id())
    log.append("test.original", {"amount": 5})
    first = json.loads(p.read_text(encoding="utf-8").splitlines()[0])
    first["payload"]["amount"] = 9999
    _rewrite_line(p, 0, first)

    diagnostic = SignedEventLog(p, _id())
    ok, why = diagnostic.verify_chain()
    assert not ok and "content_hash mismatch" in why
    with pytest.raises(ValueError, match="cannot be appended"):
        diagnostic.append("test.must-not-append", {})
    assert len(p.read_text(encoding="utf-8").splitlines()) == 1


def test_verified_snapshot_never_returns_unverified_events(
    tmp_path: Path,
) -> None:
    path = tmp_path / "events.jsonl"
    log = SignedEventLog(path, _id())
    log.append("test.original", {"id": "one"})
    event = json.loads(path.read_text(encoding="utf-8"))
    event["payload"]["id"] = "tampered"
    _rewrite_line(path, 0, event)

    with pytest.raises(ValueError, match="verified snapshot"):
        log.verified_snapshot()


def test_append_unique_is_idempotent_and_rejects_key_reuse(
    tmp_path: Path,
) -> None:
    path = tmp_path / "events.jsonl"
    first_log = SignedEventLog(path, _id())
    payload = {"execution_id": "exec-1", "receipt_digest": "digest-1"}

    first, first_created = first_log.append_unique(
        "trade.execution.recorded",
        payload,
        unique_payload_fields=("execution_id", "receipt_digest"),
        ts_ms=1,
    )
    second, second_created = SignedEventLog(path, _id()).append_unique(
        "trade.execution.recorded",
        payload,
        unique_payload_fields=("execution_id", "receipt_digest"),
        ts_ms=2,
    )

    assert first_created is True
    assert second_created is False
    assert second == first
    with pytest.raises(ValueError, match="conflicting payload"):
        first_log.append_unique(
            "trade.execution.recorded",
            {
                "execution_id": "exec-1",
                "receipt_digest": "digest-2",
            },
            unique_payload_fields=("execution_id", "receipt_digest"),
            ts_ms=3,
        )
    assert len(first_log.verified_snapshot()) == 1


def test_cross_process_append_serializes_and_reloads_chain(
    tmp_path: Path,
) -> None:
    path = str(tmp_path / "events.jsonl")
    context = multiprocessing.get_context("spawn")
    output = context.Queue()
    processes = [
        context.Process(
            target=_append_in_process,
            args=(path, index, output),
        )
        for index in range(6)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=30)
        assert process.exitcode == 0

    results = [output.get(timeout=5) for _ in processes]
    assert all(result[0] == "ok" for result in results), results
    assert sorted(result[1] for result in results) == list(range(6))
    log = SignedEventLog(path, _id())
    ok, why = log.verify_chain()
    assert ok, why
    assert len(list(log.read_all())) == 6


def test_cross_process_append_unique_writes_one_semantic_event(
    tmp_path: Path,
) -> None:
    path = str(tmp_path / "events.jsonl")
    context = multiprocessing.get_context("spawn")
    output = context.Queue()
    processes = [
        context.Process(
            target=_append_unique_in_process,
            args=(path, output),
        )
        for _ in range(6)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=30)
        assert process.exitcode == 0

    results = [output.get(timeout=5) for _ in processes]
    assert all(result[0] == "ok" for result in results), results
    assert len({result[1] for result in results}) == 1
    assert sum(result[2] for result in results) == 1
    log = SignedEventLog(path, _id())
    assert len(log.verified_snapshot()) == 1


def test_spine_rejects_oversized_line_without_unbounded_read(
    tmp_path: Path,
) -> None:
    path = tmp_path / "events.jsonl"
    path.write_bytes(b"{" + b"x" * MAX_SPINE_LINE_BYTES)

    with pytest.raises(ValueError, match="exceeds byte limit"):
        SignedEventLog(path, _id())


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
