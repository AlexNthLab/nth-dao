"""nth_dao.util — 跨模块共享的小工具

把分散在 6+ 文件里复制的 _safe_id、atomic write、json safe load、
文件锁等代码集中到这里，避免不一致和漂移。
"""

from .io import (
    safe_id,
    atomic_write_bytes,
    atomic_write_json,
    atomic_write_text,
    safe_load_json,
    file_lock,
    InterProcessLock,
)
from .jsonl_safe import (
    LOCK_TIMEOUT_DEFAULT,
    LOCK_TIMEOUT_FAST,
    LOCK_TIMEOUT_PATIENT,
    safe_append_jsonl,
    safe_append_jsonl_batch,
)
from .time_utils import now_iso, monotonic_ms

__all__ = [
    "safe_id",
    "atomic_write_bytes",
    "atomic_write_json",
    "atomic_write_text",
    "safe_load_json",
    "safe_append_jsonl",
    "safe_append_jsonl_batch",
    "LOCK_TIMEOUT_FAST",
    "LOCK_TIMEOUT_DEFAULT",
    "LOCK_TIMEOUT_PATIENT",
    "file_lock",
    "InterProcessLock",
    "now_iso",
    "monotonic_ms",
]
