"""默认入口必须是 v2 聊天优先控制台,不是 v1 旧版。

根因回归(2026-06-14):此前 `/` 服务 index.html(v1 决策队列控制台),
导致"本地启动 NTH DAO 打开的是旧版页面"。修复后 `/` 与所有未知深链
都回 v2.html,v1 仅在显式 `/v1` 才出现。

区分标记(取自构建产物,避开会随构建变化的 hash):
  - v2.html  →  含 notranslate meta + 引用 /assets/v2-*.js
  - index.html(v1) →  引用 /assets/main-*.js,无 notranslate
"""

from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from nth_dao.web import create_app


def _client(tmp_path: Path) -> TestClient:
    return TestClient(create_app(tmp_path, require_console_auth=False))


def _is_v2(text: str) -> bool:
    return "/assets/v2-" in text and "notranslate" in text


def _is_v1(text: str) -> bool:
    return "/assets/main-" in text


def test_root_serves_v2_console(tmp_path: Path) -> None:
    r = _client(tmp_path).get("/")
    assert r.status_code == 200
    assert _is_v2(r.text), "默认 `/` 必须是 v2 聊天优先控制台"
    assert not _is_v1(r.text)


def test_v2_aliases_serve_v2(tmp_path: Path) -> None:
    c = _client(tmp_path)
    for path in ("/v2", "/v2.html"):
        r = c.get(path)
        assert r.status_code == 200, path
        assert _is_v2(r.text), path


def test_unknown_deep_link_falls_back_to_v2(tmp_path: Path) -> None:
    # 前端路由接管未知路径,默认就是新版,而非旧版。
    r = _client(tmp_path).get("/some/deep/link")
    assert r.status_code == 200
    assert _is_v2(r.text)


def test_v1_still_reachable_but_demoted(tmp_path: Path) -> None:
    # 旧版功能不删除,显式 `/v1` 仍可访问。
    c = _client(tmp_path)
    for path in ("/v1", "/v1.html"):
        r = c.get(path)
        assert r.status_code == 200, path
        assert _is_v1(r.text), f"{path} 应服务 v1 旧版控制台"
        assert not _is_v2(r.text), path
