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


class SignedEventLog:
    """append-only 签名 hash 链日志。落盘 jsonl,内存维护链头。"""

    def __init__(self, path: Union[str, Path], identity: AgentIdentity) -> None:
        self._path = Path(path)
        self._identity = identity
        self._lock = threading.Lock()
        self._head_hash = GENESIS_PREV
        self._head_seq = -1
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._load_head()

    def _load_head(self) -> None:
        last: Optional[SpineEvent] = None
        try:
            for ev in self.read_all():
                last = ev
        except Exception as exc:  # noqa: BLE001
            # 拒绝在损坏日志上构造写入者(否则会在坏行后续写 → 永久分叉)。
            # 报清晰错误而非裸 JSONDecodeError;定位用 verify_chain。
            raise ValueError(
                f"spine log at {self._path} is corrupt and cannot be opened "
                f"for appending; run verify_chain on a clean handle to locate "
                f"the break ({exc})"
            ) from exc
        if last is not None:
            self._head_hash = last.content_hash
            self._head_seq = last.seq

    def read_all(self) -> Iterator[SpineEvent]:
        """按落盘顺序产出全部事件(不校验,校验走 verify_chain)。"""
        if not self._path.exists():
            return
        with self._path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    yield SpineEvent.from_dict(json.loads(line))

    @property
    def head_hash(self) -> str:
        return self._head_hash

    @property
    def head_seq(self) -> int:
        return self._head_seq

    def append(
        self, event_type: str, payload: dict, *, ts_ms: Optional[int] = None,
    ) -> SpineEvent:
        """签名并追加一条事件,返回它。链头随之推进。进程内并发安全。"""
        with self._lock:
            ev = sign_event(
                seq=self._head_seq + 1,
                prev_hash=self._head_hash,
                event_type=event_type,
                payload=payload,
                identity=self._identity,
                ts_ms=ts_ms if ts_ms is not None else now_ms(),
            )
            line = json.dumps(
                ev.to_dict(), sort_keys=True,
                separators=(",", ":"), ensure_ascii=False,
            )
            with self._path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
                os.fsync(f.fileno())
            self._head_hash = ev.content_hash
            self._head_seq = ev.seq
            return ev

    def verify_chain(self) -> Tuple[bool, str]:
        """整段重放校验:seq 从 0 单调、prev_hash 逐条链上、每条签名有效。

        **必须 fail-closed**:对损坏行(非法 JSON / 结构不合法 / 缺字段)返回
        ``(False, reason)``,绝不抛异常 —— 篡改恰会制造这种坏行,完整性校验崩溃
        等于漏过篡改。故这里自己防御式解析,不走严格的 ``read_all``。
        """
        if not self._path.exists():
            return True, "ok"   # 空日志合法
        expected_prev = GENESIS_PREV
        expected_seq = 0
        with self._path.open("r", encoding="utf-8") as f:
            for lineno, raw in enumerate(f):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    ev = SpineEvent.from_dict(json.loads(raw))
                except Exception as exc:  # noqa: BLE001
                    return False, f"line {lineno}: unparseable ({exc})"
                if ev.seq != expected_seq:
                    return False, f"seq gap at {ev.seq} (expected {expected_seq})"
                if ev.prev_hash != expected_prev:
                    return False, f"chain break at seq {ev.seq}"
                ok, why = verify_event(ev)
                if not ok:
                    return False, f"event {ev.seq}: {why}"
                expected_prev = ev.content_hash
                expected_seq += 1
        return True, "ok"
