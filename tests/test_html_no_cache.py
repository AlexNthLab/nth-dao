"""HTML 外壳必须 no-cache —— 否则浏览器缓存旧 HTML → 加载旧 bundle →
"启动的 UI 是旧版"(用户 2026-06-14 报告)。hashed /assets 不在此约束内。"""

from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from nth_dao.web import create_app


def test_html_shell_responses_are_no_cache(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    c = TestClient(app)
    for path in ("/", "/v2", "/v2.html", "/some/deep/link"):
        r = c.get(path)
        assert r.status_code in (200, 503), f"{path} → {r.status_code}"
        cc = r.headers.get("cache-control", "")
        assert "no-cache" in cc and "no-store" in cc, f"{path} cache-control={cc!r}"
