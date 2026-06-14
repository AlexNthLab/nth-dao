"""启动自检回归:版本指纹 + 路由横幅,且任何失败都不得阻断服务启动。

防的是"JS 重构了、Python 没重启"导致新路由报 405 的漂移 ——
横幅里的 git HEAD 与 `git log` 对不上即说明进程旧了。
"""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from nth_dao.web import _repo_git_head, _startup_selfcheck, create_app


def test_git_head_returns_str() -> None:
    head = _repo_git_head()
    assert isinstance(head, str) and head  # 至少是 "unknown",不抛异常


def test_selfcheck_prints_banner(tmp_path, capsys) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    _startup_selfcheck(app, "127.0.0.1", 8080)
    out = capsys.readouterr().out
    assert "git HEAD" in out
    assert "127.0.0.1:8080" in out
    # 路由总数应为正整数(== 实际带 methods 的路由数)。
    expected = len([r for r in app.routes if hasattr(r, "methods")])
    assert str(expected) in out


def test_selfcheck_never_raises_on_broken_app() -> None:
    # 自检对坏对象也只能静默吞掉,绝不能把启动拖垮。
    class _Boom:
        @property
        def routes(self):  # noqa: D401
            raise RuntimeError("boom")

    _startup_selfcheck(_Boom(), "127.0.0.1", 8080)  # 不抛即通过


def test_git_head_degrades_to_unknown(monkeypatch) -> None:
    import subprocess

    def _fail(*a, **k):
        raise FileNotFoundError("git not found")

    monkeypatch.setattr(subprocess, "check_output", _fail)
    assert _repo_git_head() == "unknown"
