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
MAX_SPINE_APPEND_BATCH = 1_000
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

    def _verified_events_unlocked(
        self,
    ) -> tuple[bool, str, tuple[SpineEvent, ...]]:
        if not self._path.exists():
            return True, "ok", ()
        expected_prev = GENESIS_PREV
        expected_seq = 0
        events: list[SpineEvent] = []
        try:
            for line_number, raw in self._raw_lines():
                if not raw.strip():
                    continue
                event = self._decode_line(raw, line_number)
                if event.seq != expected_seq:
                    return (
                        False,
                        f"seq gap at {event.seq} (expected {expected_seq})",
                        tuple(events),
                    )
                if event.prev_hash != expected_prev:
                    return (
                        False,
                        f"chain break at seq {event.seq}",
                        tuple(events),
                    )
                ok, reason = verify_event(event)
                if not ok:
                    return (
                        False,
                        f"event {event.seq}: {reason}",
                        tuple(events),
                    )
                expected_prev = event.content_hash
                expected_seq += 1
                events.append(event)
        except (OSError, TypeError, ValueError) as exc:
            return False, str(exc), tuple(events)
        return True, "ok", tuple(events)

    def _scan_verified(
        self,
    ) -> tuple[bool, str, Optional[SpineEvent]]:
        ok, reason, events = self._verified_events_unlocked()
        return ok, reason, events[-1] if events else None

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
                ok, reason, events = self._verified_events_unlocked()
                if not ok:
                    raise ValueError(
                        f"spine log at {self._path} is corrupt and cannot be "
                        f"appended: {reason}"
                    )
                return self._append_after_verified(
                    event_type,
                    payload,
                    ts_ms=ts_ms,
                    last=events[-1] if events else None,
                )

    def _append_after_verified(
        self,
        event_type: str,
        payload: dict,
        *,
        ts_ms: Optional[int],
        last: Optional[SpineEvent],
    ) -> SpineEvent:
        self._head_hash = (
            last.content_hash if last is not None else GENESIS_PREV
        )
        self._head_seq = last.seq if last is not None else -1
        event = sign_event(
            seq=self._head_seq + 1,
            prev_hash=self._head_hash,
            event_type=event_type,
            payload=payload,
            identity=self._identity,
            ts_ms=ts_ms if ts_ms is not None else now_ms(),
        )
        line = json.dumps(
            event.to_dict(),
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
        self._head_hash = event.content_hash
        self._head_seq = event.seq
        return event

    def verified_snapshot(self) -> tuple[SpineEvent, ...]:
        """Return one lock-consistent, signature-verified event snapshot."""

        with self._lock:
            with InterProcessLock(
                self._path,
                timeout=self._lock_timeout,
            ):
                ok, reason, events = self._verified_events_unlocked()
                if not ok:
                    raise ValueError(
                        f"spine log at {self._path} is corrupt and cannot be "
                        f"read as a verified snapshot: {reason}"
                    )
                return events

    def append_unique(
        self,
        event_type: str,
        payload: dict,
        *,
        unique_payload_fields: tuple[str, ...],
        ts_ms: Optional[int] = None,
    ) -> tuple[SpineEvent, bool]:
        """Append once, rejecting any event that reuses a semantic key."""

        return self.append_unique_many(
            event_type,
            (payload,),
            unique_payload_fields=unique_payload_fields,
            ts_ms=ts_ms,
        )[0]

    def append_unique_many(
        self,
        event_type: str,
        payloads: tuple[dict, ...],
        *,
        unique_payload_fields: tuple[str, ...],
        ts_ms: Optional[int] = None,
    ) -> tuple[tuple[SpineEvent, bool], ...]:
        """Append one idempotent batch after a single verified scan.

        All semantic conflicts are checked before the first write. An I/O
        failure may still leave a valid prefix, which remains retryable by the
        same semantic keys.
        """

        if (
            not isinstance(unique_payload_fields, tuple)
            or not unique_payload_fields
            or any(
                not isinstance(field, str) or not field
                for field in unique_payload_fields
            )
            or len(set(unique_payload_fields)) != len(unique_payload_fields)
        ):
            raise ValueError(
                "unique_payload_fields must be unique non-empty strings"
            )
        if not isinstance(payloads, tuple):
            raise ValueError("payloads must be a tuple")
        if not payloads:
            return ()
        if len(payloads) > MAX_SPINE_APPEND_BATCH:
            raise ValueError(
                f"payload batch exceeds {MAX_SPINE_APPEND_BATCH} events"
            )
        for payload in payloads:
            if not isinstance(payload, dict):
                raise ValueError("payload must be an object")
            for field in unique_payload_fields:
                if (
                    field not in payload
                    or not isinstance(payload[field], str)
                    or not payload[field]
                ):
                    raise ValueError(
                        f"unique payload field {field!r} must be a non-empty string"
                    )
        with self._lock:
            with InterProcessLock(
                self._path,
                timeout=self._lock_timeout,
            ):
                ok, reason, events = self._verified_events_unlocked()
                if not ok:
                    raise ValueError(
                        f"spine log at {self._path} is corrupt and cannot be "
                        f"appended: {reason}"
                    )
                owners: dict[
                    tuple[str, str], set[tuple[str, int]]
                ] = {}
                existing_by_seq = {event.seq: event for event in events}
                for event in events:
                    if event.type != event_type:
                        continue
                    for field in unique_payload_fields:
                        value = event.payload.get(field)
                        if isinstance(value, str) and value:
                            owners.setdefault((field, value), set()).add(
                                ("existing", event.seq)
                            )

                planned: list[dict] = []
                resolutions: list[tuple[tuple[str, int], bool]] = []
                for payload in payloads:
                    matched: set[tuple[str, int]] = set()
                    for field in unique_payload_fields:
                        matched.update(
                            owners.get((field, payload[field]), set())
                        )
                    if len(matched) > 1:
                        raise ValueError(
                            "spine contains duplicate semantic event keys"
                        )
                    if matched:
                        owner = next(iter(matched))
                        owner_payload = (
                            existing_by_seq[owner[1]].payload
                            if owner[0] == "existing"
                            else planned[owner[1]]
                        )
                        if owner_payload != payload:
                            raise ValueError(
                                "spine semantic event key has conflicting payload"
                            )
                        resolutions.append((owner, False))
                        continue
                    owner = ("planned", len(planned))
                    planned.append(payload)
                    resolutions.append((owner, True))
                    for field in unique_payload_fields:
                        owners.setdefault((field, payload[field]), set()).add(
                            owner
                        )

                appended: list[SpineEvent] = []
                last = events[-1] if events else None
                for payload in planned:
                    event = self._append_after_verified(
                        event_type,
                        payload,
                        ts_ms=ts_ms,
                        last=last,
                    )
                    appended.append(event)
                    last = event
                return tuple(
                    (
                        existing_by_seq[owner[1]]
                        if owner[0] == "existing"
                        else appended[owner[1]],
                        created,
                    )
                    for owner, created in resolutions
                )

    def verify_chain(self) -> Tuple[bool, str]:
        """整段重放校验:seq 从 0 单调、prev_hash 逐条链上、每条签名有效。

        **必须 fail-closed**:对损坏行(非法 JSON / 结构不合法 / 缺字段)返回
        ``(False, reason)``,绝不抛异常 —— 篡改恰会制造这种坏行,完整性校验崩溃
        等于漏过篡改。故这里自己防御式解析,不走严格的 ``read_all``。
        """
        ok, reason, _last = self._scan_verified()
        return ok, reason
