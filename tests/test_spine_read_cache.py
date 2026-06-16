"""读端 head_hash 缓存:链头不变返回同一已验证快照,append 后失效。"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("nacl")

from nth_dao.web import create_app
from nth_dao.web.v2_api import _verified_spine_events


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
