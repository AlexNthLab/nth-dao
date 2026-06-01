"""nth_dao.util — 跨模块共享的小工具

把分散在 6+ 文件里复制的 _safe_id、atomic write、json safe load、
文件锁等代码集中到这里，避免不一致和漂移。
"""

from .io import (
    safe_id,
    atomic_write_json,
    atomic_write_text,
    safe_load_json,
    file_lock,
    InterProcessLock,
)

__all__ = [
    "safe_id",
    "atomic_write_json",
    "atomic_write_text",
    "safe_load_json",
    "file_lock",
    "InterProcessLock",
]
