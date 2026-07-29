"""签名 hash 链事件日志 —— per-DAO 单写者的统一事实源(Phase 1)。

append-only;内存维护链头(``head_seq`` + ``head_hash``),每次 append 用本节点
identity 签名并链回前一条;落盘 jsonl(每行一个事件)。``verify_chain`` 整段重放:
seq 单调、prev_hash 逐条对上、每条签名有效 → 任何历史篡改都暴露(fail-closed)。

**单写者约定**:一个日志文件由一个节点进程独占写入(类比 git 索引)。跨节点是
联邦 / 合并(后续 Phase),不是多进程共享同一文件。进程内并发用锁串行化。
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Iterator, Optional, Tuple, Union

from nth_dao.execution_receipt import now_ms
from nth_dao.identity import AgentIdentity
from nth_dao.spine.event import GENESIS_PREV, SpineEvent, sign_event, verify_event
from nth_dao.util.io import InterProcessLock

MAX_SPINE_LINE_BYTES = 2 * 1024 * 1024
DEFAULT_SPINE_LOCK_TIMEOUT_SECONDS = 30.0


class SignedEventLog:
    """append-only 签名 hash 链日志。落盘 jsonl,内存维护链头。"""

    def __init__(
        self,
        path: Union[str, Path],
        identity: AgentIdentity,
        *,
        lock_timeout: float = DEFAULT_SPINE_LOCK_TIMEOUT_SECONDS,
    ) -> None:
        self._path = Path(path)
        self._identity = identity
        self._lock = threading.Lock()
        if (
            isinstance(lock_timeout, bool)
            or not isinstance(lock_timeout, (int, float))
            or lock_timeout <= 0
        ):
            raise ValueError("lock_timeout must be a positive number")
        self._lock_timeout = float(lock_timeout)
        self._head_hash = GENESIS_PREV
        self._head_seq = -1
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._load_head()

    def _load_head(self) -> None:
        last: Optional[SpineEvent] = None
        try:
            for event in self.read_all():
                last = event
        except (OSError, TypeError, ValueError) as exc:
            raise ValueError(
                f"spine log at {self._path} is corrupt and cannot be opened "
                f"for diagnosis or appending: {exc}"
            ) from exc
        self._head_hash = last.content_hash if last is not None else GENESIS_PREV
        self._head_seq = last.seq if last is not None else -1

    def _decode_line(self, raw: bytes, line_number: int) -> SpineEvent:
        if len(raw) > MAX_SPINE_LINE_BYTES:
            raise ValueError(f"line {line_number}: event exceeds byte limit")
        try:
            document = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError(f"line {line_number}: unparseable ({exc})") from exc
        try:
            return SpineEvent.from_dict(document)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"line {line_number}: invalid event structure ({exc})"
            ) from exc

    def _raw_lines(self) -> Iterator[tuple[int, bytes]]:
        with self._path.open("rb") as stream:
            line_number = 0
            while True:
                raw = stream.readline(MAX_SPINE_LINE_BYTES + 1)
                if not raw:
                    return
                line_number += 1
                if len(raw) > MAX_SPINE_LINE_BYTES:
                    raise ValueError(
                        f"line {line_number}: event exceeds byte limit"
                    )
                yield line_number, raw

    def _scan_verified(
        self,
    ) -> tuple[bool, str, Optional[SpineEvent]]:
        if not self._path.exists():
            return True, "ok", None
        expected_prev = GENESIS_PREV
        expected_seq = 0
        last: Optional[SpineEvent] = None
        try:
            for line_number, raw in self._raw_lines():
                if not raw.strip():
                    continue
                event = self._decode_line(raw, line_number)
                if event.seq != expected_seq:
                    return (
                        False,
                        f"seq gap at {event.seq} (expected {expected_seq})",
                        last,
                    )
                if event.prev_hash != expected_prev:
                    return False, f"chain break at seq {event.seq}", last
                ok, reason = verify_event(event)
                if not ok:
                    return False, f"event {event.seq}: {reason}", last
                expected_prev = event.content_hash
                expected_seq += 1
                last = event
        except (OSError, TypeError, ValueError) as exc:
            return False, str(exc), last
        return True, "ok", last

    def read_all(self) -> Iterator[SpineEvent]:
        """按落盘顺序产出全部事件(不校验,校验走 verify_chain)。"""
        if not self._path.exists():
            return
        for line_number, raw in self._raw_lines():
            if raw.strip():
                yield self._decode_line(raw, line_number)

    @property
    def head_hash(self) -> str:
        return self._head_hash

    @property
    def head_seq(self) -> int:
        return self._head_seq

    def append(
        self, event_type: str, payload: dict, *, ts_ms: Optional[int] = None,
    ) -> SpineEvent:
        """Sign and append one event with thread and process serialization."""
        with self._lock:
            with InterProcessLock(
                self._path,
                timeout=self._lock_timeout,
            ):
                # A second process may have advanced the chain since this
                # instance was constructed.
                ok, reason, last = self._scan_verified()
                if not ok:
                    raise ValueError(
                        f"spine log at {self._path} is corrupt and cannot be "
                        f"appended: {reason}"
                    )
                self._head_hash = (
                    last.content_hash if last is not None else GENESIS_PREV
                )
                self._head_seq = last.seq if last is not None else -1
                ev = sign_event(
                    seq=self._head_seq + 1,
                    prev_hash=self._head_hash,
                    event_type=event_type,
                    payload=payload,
                    identity=self._identity,
                    ts_ms=ts_ms if ts_ms is not None else now_ms(),
                )
                line = json.dumps(
                    ev.to_dict(),
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                ).encode("ascii")
                if len(line) > MAX_SPINE_LINE_BYTES:
                    raise ValueError("spine event exceeds line byte limit")
                with self._path.open("ab") as stream:
                    stream.write(line + b"\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                self._head_hash = ev.content_hash
                self._head_seq = ev.seq
                return ev

    def verify_chain(self) -> Tuple[bool, str]:
        """整段重放校验:seq 从 0 单调、prev_hash 逐条链上、每条签名有效。

        **必须 fail-closed**:对损坏行(非法 JSON / 结构不合法 / 缺字段)返回
        ``(False, reason)``,绝不抛异常 —— 篡改恰会制造这种坏行,完整性校验崩溃
        等于漏过篡改。故这里自己防御式解析,不走严格的 ``read_all``。
        """
        ok, reason, _last = self._scan_verified()
        return ok, reason
