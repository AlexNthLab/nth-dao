"""读端 head_hash 缓存:链头不变返回同一已验证快照,append 后失效。"""
from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("nacl")

from nth_dao.web import create_app
from nth_dao.web.v2_api import _verified_spine_events
from fastapi import HTTPException


def test_verified_events_cached_by_head(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    req = SimpleNamespace(app=app)

    e1 = _verified_spine_events(req)
    e2 = _verified_spine_events(req)
    assert e1 is e2                       # 同 head → 同一缓存对象(未重放)

    spine = app.state.nth.spine
    assert spine is not None
    spine.append("t", {"x": 1})           # append 改 head_hash

    e3 = _verified_spine_events(req)
    assert e3 is not e1                    # 缓存失效 → 新对象
    assert len(e3) == len(e1) + 1

    e4 = _verified_spine_events(req)
    assert e4 is e3                        # 再次命中缓存


def test_verified_events_cache_detects_another_process_append(
    tmp_path: Path,
) -> None:
    first_app = create_app(tmp_path, require_console_auth=False)
    second_app = create_app(tmp_path, require_console_auth=False)
    first_spine = first_app.state.nth.spine
    second_spine = second_app.state.nth.spine
    second_request = SimpleNamespace(app=second_app)

    cached_empty = _verified_spine_events(second_request)
    assert cached_empty == []
    stale_in_memory_head = second_spine.head_hash

    appended = first_spine.append("cross-process", {"value": 1})
    refreshed = _verified_spine_events(second_request)

    assert second_spine.head_hash == stale_in_memory_head
    assert [event.event_id for event in refreshed] == [appended.event_id]
    assert refreshed is not cached_empty


def test_verified_events_cache_detects_same_size_retimestamped_tamper(
    tmp_path: Path,
) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    request = SimpleNamespace(app=app)
    spine = app.state.nth.spine
    spine.append("cache-integrity", {"status": "original"})
    assert len(_verified_spine_events(request)) == 1

    path = spine._path
    before = path.stat()
    raw = path.read_bytes()
    assert b"original" in raw
    path.write_bytes(raw.replace(b"original", b"tampered", 1))
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert path.stat().st_size == before.st_size

    with pytest.raises(HTTPException, match="spine integrity check failed"):
        _verified_spine_events(request)
