"""Liveness must not cold-import optional discovery stacks."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest


def test_health_does_not_probe_optional_mdns(tmp_path, monkeypatch):
    httpx = pytest.importorskip("httpx")
    from nth_dao import discovery
    from nth_dao.web import create_app

    app = create_app(tmp_path, require_console_auth=True)

    def unexpected():
        pytest.fail("health imported/probed optional mDNS")

    monkeypatch.setattr(discovery, "mdns_available", unexpected)

    async def exercise():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver",
        ) as client:
            result = await client.get("/api/v2/health")
            assert result.status_code == 200 and result.json()["ok"] is True
            assert "lan_mdns_available" not in result.json()["federation"]

    asyncio.run(exercise())


@pytest.mark.parametrize("broken", [False, True])
def test_full_federation_diagnostics_keep_optional_import_status(monkeypatch, broken):
    from nth_dao import discovery
    from nth_dao.web.v2_api import _lan_federation_runtime_status

    calls = []

    def available():
        calls.append(True)
        if broken:
            raise ImportError("injected optional dependency failure")
        return True

    monkeypatch.setattr(discovery, "mdns_available", available)
    app = SimpleNamespace(state=SimpleNamespace())
    full = _lan_federation_runtime_status(app)
    assert calls == [True] and full["lan_mdns_available"] is (not broken)
    liveness = _lan_federation_runtime_status(app, probe_mdns=False)
    assert calls == [True]
    for field in ("lan_transport_available", "lan_publish_enabled", "lan_federation_ready"):
        assert liveness[field] == full[field]
