"""Regression tests for the supervised-agent authorization handshake."""

from __future__ import annotations

import asyncio
import json

import nth_dao.web.v2_api as v2_api


def _body(code: str) -> bytes:
    return json.dumps({"error": {"code": code}}).encode("utf-8")


def test_transient_not_ready_response_is_retried(monkeypatch) -> None:
    responses = [
        (401, _body("not-yet-authorized")),
        (200, json.dumps({"result": {"response": "ready"}}).encode("utf-8")),
    ]
    calls = 0
    monkeypatch.setattr(v2_api, "_AGENT_AUTH_READINESS_RETRY_S", 0.0)

    def forward():
        nonlocal calls
        calls += 1
        return responses.pop(0)

    status, content = asyncio.run(
        v2_api._forward_local_agent_with_readiness_retry(forward)
    )

    assert status == 200
    assert content["result"]["response"] == "ready"
    assert calls == 2


def test_other_unauthorized_response_is_not_retried(monkeypatch) -> None:
    calls = 0
    monkeypatch.setattr(v2_api, "_AGENT_AUTH_READINESS_RETRY_S", 0.0)

    def forward():
        nonlocal calls
        calls += 1
        return 401, _body("issuer-mismatch")

    status, content = asyncio.run(
        v2_api._forward_local_agent_with_readiness_retry(forward)
    )

    assert status == 401
    assert content["error"]["code"] == "issuer-mismatch"
    assert calls == 1


def test_not_ready_text_without_machine_code_is_not_retried(monkeypatch) -> None:
    calls = 0
    monkeypatch.setattr(v2_api, "_AGENT_AUTH_READINESS_RETRY_S", 0.0)

    def forward():
        nonlocal calls
        calls += 1
        return 401, json.dumps(
            {"error": {"code": "denied", "message": "not-yet-authorized"}}
        ).encode("utf-8")

    status, _content = asyncio.run(
        v2_api._forward_local_agent_with_readiness_retry(forward)
    )

    assert status == 401
    assert calls == 1
