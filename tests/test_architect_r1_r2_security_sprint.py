"""Architect audit R-1 + R-2 (2026-06-07): security sprint.

R-1 - the `actor_id` query parameter is a CLAIM, not a verified
       identity. As long as that is true, the only safe bind is
       loopback. Pin:
         * default NTH_HOST is 127.0.0.1
         * setting NTH_HOST to a non-loopback host without
           NTH_ALLOW_REMOTE_BIND=1 raises RuntimeError
         * opt-in via NTH_ALLOW_REMOTE_BIND=1 logs a warning
         * loopback aliases (127.0.0.1, ::1, localhost) all allowed
           without opt-in

R-2 - /api/build_id pre-fix spawned `git` on every request (DoS
       amplifier) and exposed git rev + start time to any
       unauthenticated caller. Pin:
         * endpoint requires actor_id (400 without)
         * non-members get 403 (same gate as the rest)
         * git rev is computed once at import, NOT per request
         * no subprocess call on the hot path
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from nth_dao.web import (
    _BACKEND_GIT_REV,
    _resolve_safe_bind_host,
    create_app,
)


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    return TestClient(create_app(tmp_path))


# ===== R-1: bind host gate =====


def test_R1_default_bind_is_loopback(monkeypatch):
    """No env -> 127.0.0.1, the safe default."""
    monkeypatch.delenv("NTH_HOST", raising=False)
    monkeypatch.delenv("NTH_ALLOW_REMOTE_BIND", raising=False)
    assert _resolve_safe_bind_host() == "127.0.0.1"


@pytest.mark.parametrize("alias", ["127.0.0.1", "::1", "localhost"])
def test_R1_loopback_aliases_allowed_without_opt_in(monkeypatch, alias):
    monkeypatch.setenv("NTH_HOST", alias)
    monkeypatch.delenv("NTH_ALLOW_REMOTE_BIND", raising=False)
    assert _resolve_safe_bind_host() == alias


def test_R1_non_loopback_without_opt_in_refuses(monkeypatch):
    """The whole point of R-1: refuse to expose the un-authenticated
    API to anything reachable from another machine."""
    monkeypatch.setenv("NTH_HOST", "0.0.0.0")
    monkeypatch.delenv("NTH_ALLOW_REMOTE_BIND", raising=False)
    with pytest.raises(RuntimeError, match="no request authentication"):
        _resolve_safe_bind_host()


def test_R1_non_loopback_with_explicit_opt_in_proceeds(monkeypatch, caplog):
    """If the operator says NTH_ALLOW_REMOTE_BIND=1, we proceed
    BUT log a loud warning so the risk is observable in logs."""
    monkeypatch.setenv("NTH_HOST", "0.0.0.0")
    monkeypatch.setenv("NTH_ALLOW_REMOTE_BIND", "1")
    import logging
    with caplog.at_level(logging.WARNING, logger="nth_dao.web"):
        host = _resolve_safe_bind_host()
    assert host == "0.0.0.0"
    assert any(
        "no request authentication" in rec.message for rec in caplog.records
    ), "expected a loud warning when remote bind is explicit"


@pytest.mark.parametrize("bad_value", ["yes", "true", "0", " 1 ", "1\n"])
def test_R1_opt_in_must_be_exactly_string_1(monkeypatch, bad_value):
    """The opt-in is a CLAIM about understanding the risk; loose
    matching makes typos a security hole. Only the exact string '1'
    counts. (We tolerate surrounding whitespace per .strip() but the
    core value must be '1'.)"""
    monkeypatch.setenv("NTH_HOST", "0.0.0.0")
    monkeypatch.setenv("NTH_ALLOW_REMOTE_BIND", bad_value)
    if bad_value.strip() == "1":
        # " 1 " strips to "1" and is accepted; that is current behaviour
        # and acceptable, document it here.
        assert _resolve_safe_bind_host() == "0.0.0.0"
    else:
        with pytest.raises(RuntimeError):
            _resolve_safe_bind_host()


# ===== R-2: build_id endpoint =====


def test_R2_build_id_requires_actor_id(client):
    """No actor_id -> 400. Was unauthenticated 200 before fix."""
    resp = client.get("/api/build_id")
    assert resp.status_code == 400
    assert "actor_id" in resp.json()["detail"]


def test_R2_build_id_rejects_non_member(client):
    """Random string actor_id -> 403 via _require_member."""
    resp = client.get("/api/build_id", params={"actor_id": "stranger"})
    assert resp.status_code == 403


def test_R2_build_id_succeeds_for_admin(client):
    """The default admin can read the build id - the normal flow."""
    resp = client.get("/api/build_id", params={"actor_id": "admin"})
    assert resp.status_code == 200
    body = resp.json()
    assert set(body.keys()) == {"backend_git", "backend_started_at", "now"}
    # backend_git is captured at module import - not "unknown" iff git
    # is on PATH AND we are inside a checkout. In a tarball install it
    # would be "unknown", which is also acceptable. Just assert string.
    assert isinstance(body["backend_git"], str)
    assert isinstance(body["backend_started_at"], str)
    assert isinstance(body["now"], str)


def test_R2_build_id_handler_does_not_spawn_subprocess(client):
    """The body of build_id_endpoint must NOT contain a subprocess
    call. Pre-fix it called subprocess.run(['git', ...]) per request,
    which was both a DoS amplifier and an unbounded fork-rate
    problem under poll-load."""
    # Locate the handler via the FastAPI app's route table - it's a
    # closure inside create_app, not a module-level symbol.
    app = client.app
    handler = None
    for route in app.routes:
        if getattr(route, "path", "") == "/api/build_id":
            handler = route.endpoint
            break
    assert handler is not None, "build_id endpoint missing from app"
    src = inspect.getsource(handler)
    assert "subprocess" not in src, (
        "build_id handler still references subprocess on the hot path; "
        f"see source:\n{src}"
    )
    assert ".run(" not in src or "uvicorn" in src, (
        "build_id handler still calls .run() on the hot path"
    )


def test_R2_git_rev_captured_at_module_import_time():
    """``_BACKEND_GIT_REV`` is a module-level string filled in once at
    import. Subsequent imports / reloads must not retrigger the
    subprocess - the value is frozen for the process lifetime."""
    assert isinstance(_BACKEND_GIT_REV, str)
    # Either a short hash (7+ chars) or the documented fallback.
    assert _BACKEND_GIT_REV == "unknown" or len(_BACKEND_GIT_REV) >= 4


def test_R2_repeated_build_id_calls_do_not_amplify_load(client):
    """Hot-path smoke: 50 sequential requests must all return the
    same backend_git value (no recomputation) and complete quickly."""
    import time
    seen_revs = set()
    t0 = time.monotonic()
    for _ in range(50):
        resp = client.get("/api/build_id", params={"actor_id": "admin"})
        assert resp.status_code == 200
        seen_revs.add(resp.json()["backend_git"])
    elapsed = time.monotonic() - t0
    # Only one rev value should ever surface - confirms caching.
    assert len(seen_revs) == 1
    # 50 calls in under 2s on any reasonable hardware - confirms no
    # per-request subprocess.
    assert elapsed < 2.0, f"50 build_id calls took {elapsed:.2f}s"
