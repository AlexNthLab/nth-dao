"""nth_dao.util.io — atomic write / safe read / safe_id / inter-process lock

设计目标：
    1. 把 6 个文件里复制的 `safe_id` / `atomic_write` / `safe_load_json` 抽出来
    2. 提供 **跨进程** 文件锁（POSIX fcntl + Windows msvcrt），让 mission claim
       这种需要 compare-and-swap 的操作能在多终端协作时不丢更新
    3. JSON 读写不再静默吞异常 —— 至少 log 一次到 stderr，让运维察觉损坏

零第三方依赖。
"""

from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional, Union

logger = logging.getLogger("nth_dao.util.io")

PathLike = Union[str, Path]

# ─────────────────────── safe_id ───────────────────────


def safe_id(value: str, allow_extra: str = "_-.", fallback: str = "anon") -> str:
    """把任意字符串变成可以做文件名的安全 id。

    Args:
        value: 原始 agent_id / channel_id 等
        allow_extra: 允许的额外非字母数字字符
        fallback: value 完全为空 / 纯非法字符时的回退值
    """
    if not value:
        return fallback
    safe = "".join(c if c.isalnum() or c in allow_extra else "-" for c in value)
    safe = safe.strip("-") or fallback
    # 防止路径穿越
    if safe in (".", "..") or "/" in safe or "\\" in safe:
        return fallback
    # 防过长（NTFS / ext4 限制 255 字节）
    return safe[:200]


# ─────────────────────── JSON I/O ───────────────────────


def atomic_write_text(path: PathLike, content: str, *, encoding: str = "utf-8") -> None:
    """同目录 tmp 文件 + os.replace 原子替换。

    比 NamedTemporaryFile + rename 安全：tmp 在同一文件系统，replace 原子。
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # 用 NamedTemporaryFile 让多进程并行写不冲突 tmp 名
    fd, tmp = tempfile.mkstemp(
        prefix=path.name + ".",
        suffix=".tmp",
        dir=str(path.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding=encoding) as f:
            f.write(content)
            f.flush()
            try:
                os.fsync(f.fileno())  # 确保写入磁盘
            except OSError:
                pass  # 某些 FS（如 procfs）不支持 fsync
        os.replace(tmp, str(path))
    except Exception:
        # 失败要清理 tmp
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def atomic_write_json(
    path: PathLike,
    data: Any,
    *,
    indent: Optional[int] = 2,
    ensure_ascii: bool = False,
) -> None:
    """原子写 JSON 文件。"""
    content = json.dumps(data, indent=indent, ensure_ascii=ensure_ascii, sort_keys=False)
    atomic_write_text(path, content)


def safe_load_json(
    path: PathLike,
    *,
    fallback: Any = None,
    log_warn: bool = True,
) -> Any:
    """读 JSON，文件不存在 / 损坏时返回 fallback。

    与之前每个文件里 `try: ... except Exception: continue` 的差别：
    至少在损坏时 logger.warning 一次，让运维知道有"幽灵文件"。
    """
    path = Path(path)
    if not path.exists():
        return fallback
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        if log_warn:
            logger.warning("corrupt JSON at %s: %s", path, e)
        return fallback
    except OSError as e:
        if log_warn:
            logger.warning("I/O error reading %s: %s", path, e)
        return fallback


# ─────────────────────── 跨进程文件锁 ───────────────────────


class InterProcessLock:
    """跨进程独占文件锁（POSIX fcntl / Windows msvcrt）。

    用 lock-file（path + ".lock"）单独存锁，避免锁住被读写的目标文件本身。
    支持 with-statement。

    使用：
        with InterProcessLock(mission_path):
            data = read(mission_path)
            data["status"] = "done"
            write(mission_path, data)
    """

    def __init__(self, path: PathLike, timeout: float = 10.0, poll: float = 0.05):
        self.lock_path = Path(str(path) + ".lock")
        self.timeout = timeout
        self.poll = poll
        self._fh = None
        self._acquired = False

    def acquire(self) -> bool:
        import time

        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.time() + self.timeout
        self._fh = open(self.lock_path, "a+")

        if sys.platform == "win32":
            import msvcrt

            while True:
                try:
                    msvcrt.locking(self._fh.fileno(), msvcrt.LK_NBLCK, 1)
                    self._acquired = True
                    return True
                except OSError:
                    if time.time() >= deadline:
                        self._fh.close()
                        self._fh = None
                        raise TimeoutError(
                            f"could not acquire lock {self.lock_path} within {self.timeout}s"
                        )
                    time.sleep(self.poll)
        else:
            import fcntl

            while True:
                try:
                    fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    self._acquired = True
                    return True
                except (BlockingIOError, OSError):
                    if time.time() >= deadline:
                        self._fh.close()
                        self._fh = None
                        raise TimeoutError(
                            f"could not acquire lock {self.lock_path} within {self.timeout}s"
                        )
                    time.sleep(self.poll)

    def release(self) -> None:
        if not self._acquired or self._fh is None:
            return
        try:
            if sys.platform == "win32":
                import msvcrt

                try:
                    self._fh.seek(0)
                    msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
            else:
                import fcntl

                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
        finally:
            self._fh.close()
            self._fh = None
            self._acquired = False

    def __enter__(self) -> "InterProcessLock":
        self.acquire()
        return self

    def __exit__(self, *exc):
        self.release()


@contextmanager
def file_lock(path: PathLike, timeout: float = 10.0) -> Iterator[InterProcessLock]:
    """便捷上下文形态：with file_lock(path): ..."""
    lock = InterProcessLock(path, timeout=timeout)
    lock.acquire()
    try:
        yield lock
    finally:
        lock.release()
