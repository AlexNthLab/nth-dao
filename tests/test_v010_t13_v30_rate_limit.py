"""V-30: per-actor rate limiting + timing-side-channel mitigation.

Covers:

  V-30a unit-level RateLimiter behaviour (sliding window, retry-after)
  V-30b /api/mandates/verify is rate-limited per actor_id, returns 429
        with Retry-After header when the budget is blown
  V-30c /api/mandates/store is rate-limited per actor_id (separate
        budget)
  V-30d verify endpoint has a 50ms response-time floor on every path
        - so "missing proof" and "Ed25519 verify failed" take roughly
        the same wall-clock to return (the residual difference is
        kernel-scheduling jitter, not gate semantics)
  V-30e separate keys have separate budgets (no global throttle)
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import pytest
from fastapi.testclient import TestClient

from nth_dao.identity import AgentIdentity, crypto_available
from nth_dao.mandate.intent import (
    build_intent_mandate,
    intent_mandate_digest,
    sign_intent_mandate,
)
from nth_dao.web import create_app
from nth_dao.web.rate_limit import (
    PersistentRateLimiter,
    RateLimitDecision,
    RateLimiter,
    enforce_min_response_time,
)


# =====================================================================
# V-30a: RateLimiter unit behaviour
# =====================================================================


def test_T13_V30a_rate_limiter_blocks_after_max():
    lim = RateLimiter(max_per_window=3, window_seconds=10.0)
    for _ in range(3):
        d = lim.check("actor-a")
        assert d.allowed is True
    blocked = lim.check("actor-a")
    assert blocked.allowed is False
    assert blocked.retry_after_seconds > 0
    assert blocked.remaining == 0


def test_T13_V30a_rate_limiter_separate_keys_separate_budgets():
    lim = RateLimiter(max_per_window=2, window_seconds=10.0)
    # exhaust actor-a
    assert lim.check("actor-a").allowed
    assert lim.check("actor-a").allowed
    assert not lim.check("actor-a").allowed
    # actor-b is unaffected
    assert lim.check("actor-b").allowed
    assert lim.check("actor-b").allowed


def test_T13_V30a_rate_limiter_window_slides():
    """After the window passes, the budget resets."""
    lim = RateLimiter(max_per_window=2, window_seconds=0.05)
    lim.check("actor-a")
    lim.check("actor-a")
    assert not lim.check("actor-a").allowed
    time.sleep(0.06)
    # Window has passed; budget restored
    assert lim.check("actor-a").allowed


def test_T13_V30a_denied_requests_do_not_extend_window():
    """A burst of denied requests must NOT push the window forward.
    Otherwise a client hitting 429 would lock themselves out for
    longer than the policy intended."""
    lim = RateLimiter(max_per_window=1, window_seconds=0.05)
    assert lim.check("actor-a").allowed
    # Hammer with denied requests
    for _ in range(20):
        assert not lim.check("actor-a").allowed
    # After the original window expires, budget restores
    time.sleep(0.06)
    assert lim.check("actor-a").allowed


def test_T13_V30a_empty_key_skips_rate_limit():
    """Per-key tracking requires a key. An empty / None key returns
    allowed=True (callers should pass a default like 'anonymous')."""
    lim = RateLimiter(max_per_window=1, window_seconds=10.0)
    for _ in range(10):
        assert lim.check("").allowed is True


def test_T13_V30a_rate_limiter_validates_construction():
    with pytest.raises(ValueError, match="max_per_window"):
        RateLimiter(max_per_window=0, window_seconds=1.0)
    with pytest.raises(ValueError, match="window_seconds"):
        RateLimiter(max_per_window=1, window_seconds=0.0)


def test_persistent_rate_limiter_shares_budget_without_storing_raw_key(
    tmp_path,
) -> None:
    now = [100.0]
    path = tmp_path / "rate-limit.json"
    worker_a = PersistentRateLimiter(
        path, max_per_window=2, window_seconds=10.0, clock=lambda: now[0],
    )
    worker_b = PersistentRateLimiter(
        path, max_per_window=2, window_seconds=10.0, clock=lambda: now[0],
    )

    assert worker_a.check("203.0.113.9").allowed
    assert worker_b.check("203.0.113.9").allowed
    assert not worker_a.check("203.0.113.9").allowed
    assert "203.0.113.9" not in path.read_text(encoding="utf-8")

    now[0] += 10.1
    assert worker_b.check("203.0.113.9").allowed


def test_persistent_rate_limiter_clock_rollback_does_not_reset_budget(
    tmp_path,
) -> None:
    now = [100.0]
    limiter = PersistentRateLimiter(
        tmp_path / "rate-limit.json",
        max_per_window=1,
        window_seconds=10.0,
        clock=lambda: now[0],
    )

    assert limiter.check("203.0.113.10").allowed
    now[0] = 90.0
    rolled_back = limiter.check("203.0.113.10")
    assert not rolled_back.allowed
    assert rolled_back.retry_after_seconds == pytest.approx(10.0)

    now[0] = 110.1
    assert limiter.check("203.0.113.10").allowed


def test_persistent_rate_limiter_rebases_implausible_future_window(tmp_path) -> None:
    now = [2_000.0]
    path = tmp_path / "rate-limit.json"
    first = PersistentRateLimiter(
        path,
        max_per_window=1,
        window_seconds=10.0,
        clock=lambda: now[0],
    )
    assert first.check("203.0.113.11").allowed

    now[0] = 1_000.0
    restarted = PersistentRateLimiter(
        path,
        max_per_window=1,
        window_seconds=10.0,
        clock=lambda: now[0],
    )
    denied = restarted.check("203.0.113.11")
    assert not denied.allowed
    assert denied.retry_after_seconds == pytest.approx(10.0)

    now[0] = 1_010.1
    assert restarted.check("203.0.113.11").allowed


def test_persistent_limiter_denials_do_not_rewrite_or_reread_state(
    tmp_path, monkeypatch,
) -> None:
    import nth_dao.web.rate_limit as rate_limit_module

    path = tmp_path / "rate-limit.json"
    writes = []
    real_write = rate_limit_module.atomic_write_json

    def counted_write(target, payload):
        writes.append(target)
        return real_write(target, payload)

    monkeypatch.setattr(rate_limit_module, "atomic_write_json", counted_write)
    limiter = PersistentRateLimiter(
        path, max_per_window=1, window_seconds=60.0,
    )
    assert limiter.check("203.0.113.20").allowed
    assert len(writes) == 1
    first_denial = limiter.check("203.0.113.20")
    assert not first_denial.allowed
    assert len(writes) == 1

    monkeypatch.setattr(
        limiter,
        "_load_state",
        lambda: (_ for _ in ()).throw(AssertionError("state reread")),
    )
    assert not limiter.check("203.0.113.20").allowed
    assert len(writes) == 1
    assert "203.0.113.20" not in repr(limiter._denied_until)


def test_persistent_rate_limiter_corrupt_state_fails_closed(tmp_path) -> None:
    path = tmp_path / "rate-limit.json"
    path.write_text("{}", encoding="utf-8")
    limiter = PersistentRateLimiter(
        path, max_per_window=1, window_seconds=10.0,
    )

    with pytest.raises(ValueError, match="state is malformed"):
        limiter.check("203.0.113.11")
    assert path.read_text(encoding="utf-8") == "{}"


def test_T13_V30a_rate_limit_decision_dataclass():
    """The returned object exposes the three documented fields."""
    d = RateLimitDecision(True, 0.0, 5)
    assert d.allowed is True
    assert d.retry_after_seconds == 0.0
    assert d.remaining == 5


# =====================================================================
# V-30d: timing-floor helper
# =====================================================================


def _async_run(coro):
    return asyncio.get_event_loop().run_until_complete(coro) if not asyncio.get_event_loop().is_running() else asyncio.run(coro)


def test_T13_V30d_enforce_min_response_time_pads_short_calls():
    """A handler that returns "immediately" should sleep up to the
    floor so the response time has a known lower bound."""

    async def fast_call():
        start = time.monotonic()
        # No work
        await enforce_min_response_time(start, 0.05)
        return time.monotonic() - start

    elapsed = asyncio.run(fast_call())
    assert elapsed >= 0.045    # allow scheduler jitter


def test_T13_V30d_enforce_min_response_time_does_not_truncate_long_calls():
    """If the real work exceeded the floor, the helper is a no-op."""

    async def slow_call():
        start = time.monotonic()
        await asyncio.sleep(0.08)
        await enforce_min_response_time(start, 0.05)
        return time.monotonic() - start

    elapsed = asyncio.run(slow_call())
    # Should be ~80ms, not extended further
    assert 0.07 <= elapsed <= 0.15


def test_T13_V30d_enforce_min_response_time_zero_floor_no_op():
    async def zero():
        start = time.monotonic()
        await enforce_min_response_time(start, 0)
        return time.monotonic() - start

    elapsed = asyncio.run(zero())
    assert elapsed < 0.02


# =====================================================================
# V-30b: /api/mandates/verify rate limit + 429 + Retry-After
# =====================================================================


@pytest.fixture
def dao() -> AgentIdentity:
    if not crypto_available():
        pytest.skip("PyNaCl required")
    return AgentIdentity.generate(label="t13-dao")


@pytest.fixture
def seller() -> AgentIdentity:
    if not crypto_available():
        pytest.skip("PyNaCl required")
    return AgentIdentity.generate(label="t13-seller")


@pytest.fixture
def agent_did() -> str:
    if not crypto_available():
        pytest.skip("PyNaCl required")
    return AgentIdentity.generate(label="t13-agent").as_did()


def _future(s: int = 3600) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=s)).isoformat()


def _signed_intent(dao, agent_did, *, seller=None) -> Dict[str, Any]:
    m = build_intent_mandate(
        issuer_did=dao.as_did(), agent_did=agent_did, purpose="x",
        constraints={
            "max_amount": {"value": "100.00", "currency": "USDC"},
            "allowed_counterparties": (
                [seller.as_did()] if seller is not None else []
            ),
            "allowed_settlement_methods": ["x402:usdc"],
        },
        expires_at=_future(86400),
    )
    return sign_intent_mandate(m, dao)


def _client_with_members(tmp_path, *actor_ids: str) -> TestClient:
    client = TestClient(create_app(tmp_path))
    membership = client.app.state.nth.membership
    for actor_id in actor_ids:
        ok, reason = membership.ensure_member(actor_id)
        assert ok, reason
    return client


def test_T13_V30b_verify_returns_429_after_budget_exhausted(
    tmp_path, dao, seller, agent_did,
):
    """Tighten the limiter to 3/min so we can exhaust it in the test
    without sleeping. Confirm the 4th call returns 429 with a
    Retry-After header."""
    client = _client_with_members(tmp_path, "actor-a")
    # Tighten the in-process limiter for this test
    state = client.app.state.nth
    from nth_dao.web.rate_limit import RateLimiter
    state.verify_limiter = RateLimiter(
        max_per_window=3, window_seconds=60.0,
    )

    intent = _signed_intent(dao, agent_did, seller=seller)
    payload = {"kind": "intent", "mandate": intent, "actor_id": "actor-a"}

    for _ in range(3):
        resp = client.post("/api/mandates/verify", json=payload)
        assert resp.status_code == 200
    blocked = client.post("/api/mandates/verify", json=payload)
    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers
    assert "rate limit exceeded" in blocked.json()["detail"]


def test_T13_V30b_verify_separate_actors_have_separate_budgets(
    tmp_path, dao, seller, agent_did,
):
    client = _client_with_members(tmp_path, "actor-a", "actor-b")
    state = client.app.state.nth
    from nth_dao.web.rate_limit import RateLimiter
    state.verify_limiter = RateLimiter(
        max_per_window=2, window_seconds=60.0,
    )

    intent = _signed_intent(dao, agent_did, seller=seller)

    # Exhaust actor-a's budget
    for _ in range(2):
        client.post("/api/mandates/verify", json={
            "kind": "intent", "mandate": intent, "actor_id": "actor-a",
        })
    blocked = client.post("/api/mandates/verify", json={
        "kind": "intent", "mandate": intent, "actor_id": "actor-a",
    })
    assert blocked.status_code == 429

    # actor-b should still be allowed
    ok = client.post("/api/mandates/verify", json={
        "kind": "intent", "mandate": intent, "actor_id": "actor-b",
    })
    assert ok.status_code == 200


# =====================================================================
# V-30c: /api/mandates/store rate limit
# =====================================================================


def test_T13_V30c_store_returns_429_after_budget_exhausted(
    tmp_path, dao, seller, agent_did,
):
    client = _client_with_members(tmp_path, "actor-a")
    state = client.app.state.nth
    from nth_dao.web.rate_limit import RateLimiter
    state.store_limiter = RateLimiter(
        max_per_window=2, window_seconds=60.0,
    )

    intent = _signed_intent(dao, agent_did, seller=seller)
    payload = {"kind": "intent", "mandate": intent, "actor_id": "actor-a"}

    for _ in range(2):
        resp = client.post("/api/mandates/store", json=payload)
        assert resp.status_code == 200
    blocked = client.post("/api/mandates/store", json=payload)
    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers


def test_T13_V30c_store_and_verify_have_independent_budgets(
    tmp_path, dao, seller, agent_did,
):
    """Exhausting the store budget must not throttle verify on the
    same actor, since they're separate limiters."""
    client = _client_with_members(tmp_path, "actor-a")
    state = client.app.state.nth
    from nth_dao.web.rate_limit import RateLimiter
    state.store_limiter = RateLimiter(
        max_per_window=1, window_seconds=60.0,
    )
    # Leave verify_limiter at its default (30/min)

    intent = _signed_intent(dao, agent_did, seller=seller)

    client.post("/api/mandates/store", json={
        "kind": "intent", "mandate": intent, "actor_id": "actor-a",
    })
    blocked_store = client.post("/api/mandates/store", json={
        "kind": "intent", "mandate": intent, "actor_id": "actor-a",
    })
    assert blocked_store.status_code == 429

    # verify still works
    ok_verify = client.post("/api/mandates/verify", json={
        "kind": "intent", "mandate": intent, "actor_id": "actor-a",
    })
    assert ok_verify.status_code == 200


def test_T13_F5_store_response_time_floor_applies_to_success(
    tmp_path, dao, seller, agent_did,
):
    client = _client_with_members(tmp_path, "actor-a")
    intent = _signed_intent(dao, agent_did, seller=seller)

    start = time.monotonic()
    resp = client.post("/api/mandates/store", json={
        "kind": "intent", "mandate": intent, "actor_id": "actor-a",
    })
    elapsed = time.monotonic() - start

    assert resp.status_code == 200
    assert elapsed >= 0.040, (
        f"successful store took {elapsed*1000:.1f}ms, expected >= ~50ms floor"
    )


def test_T13_F5_store_response_time_floor_applies_to_403_membership_path(tmp_path):
    (tmp_path / "team.json").write_text(
        '{"team_name":"Closed","join_policy":"invite_only",'
        '"admin_ids":["admin"],"member_ids":["admin"],'
        '"roles":{"admin":"owner"}}',
        encoding="utf-8",
    )
    client = TestClient(create_app(tmp_path))

    start = time.monotonic()
    resp = client.post("/api/mandates/store", json={
        "kind": "intent",
        "mandate": {"junk": True},
        "actor_id": "stranger",
    })
    elapsed = time.monotonic() - start

    assert resp.status_code == 403
    assert elapsed >= 0.040, (
        f"403 store took {elapsed*1000:.1f}ms, expected >= ~50ms floor"
    )


def test_T13_F5_store_response_time_floor_applies_to_429_rate_limit_path(
    tmp_path, dao, seller, agent_did,
):
    client = _client_with_members(tmp_path, "actor-a")
    state = client.app.state.nth
    from nth_dao.web.rate_limit import RateLimiter
    state.store_limiter = RateLimiter(
        max_per_window=1, window_seconds=60.0,
    )

    intent = _signed_intent(dao, agent_did, seller=seller)
    payload = {"kind": "intent", "mandate": intent, "actor_id": "actor-a"}
    client.post("/api/mandates/store", json=payload)

    start = time.monotonic()
    resp = client.post("/api/mandates/store", json=payload)
    elapsed = time.monotonic() - start

    assert resp.status_code == 429
    assert elapsed >= 0.040, (
        f"429 store took {elapsed*1000:.1f}ms, expected >= ~50ms floor"
    )


# =====================================================================
# V-30d: verify endpoint has a response-time floor (timing oracle defence)
# =====================================================================


def test_T13_V30d_verify_response_time_floor_applies(
    tmp_path, dao, seller, agent_did,
):
    """Confirm the floor is enforced: a "missing proof" rejection
    should take at least the floor's worth of wall-clock. Without
    the floor, the rejection path is sub-millisecond, which is the
    timing oracle Voss V-30 calls out."""
    client = _client_with_members(tmp_path, "actor-a")

    # An obviously-malformed body that goes through the fast path
    fast_body = {"kind": "intent", "mandate": {"junk": True}, "actor_id": "actor-a"}

    start = time.monotonic()
    resp = client.post("/api/mandates/verify", json=fast_body)
    elapsed = time.monotonic() - start

    assert resp.status_code == 200
    # The floor is 50ms; allow for scheduler jitter. The KEY claim is
    # not "exactly 50ms" but "noticeably more than the underlying
    # work would take" (sub-millisecond without the floor).
    assert elapsed >= 0.040, (
        f"verify took {elapsed*1000:.1f}ms, expected >= ~50ms "
        "floor (V-30d timing oracle defence missing?)"
    )


def test_T13_V30d_timing_floor_applies_to_403_membership_path(tmp_path):
    """A non-member hitting /api/mandates/verify must also see the
    timing floor, otherwise the 403 path returns in microseconds
    while the 200 path returns in 50ms - leaking the actor's
    membership status via wall-clock.

    The verify route's outer try/except HTTPException ensures the
    floor walks before the exception propagates.
    """
    # invite_only policy so a stranger gets 403
    (tmp_path / "team.json").write_text(
        '{"team_name":"Closed","join_policy":"invite_only",'
        '"admin_ids":["admin"],"member_ids":["admin"],'
        '"roles":{"admin":"owner"}}',
        encoding="utf-8",
    )
    client = TestClient(create_app(tmp_path))

    start = time.monotonic()
    resp = client.post("/api/mandates/verify", json={
        "kind": "intent",
        "mandate": {"junk": True},
        "actor_id": "stranger",
    })
    elapsed = time.monotonic() - start

    assert resp.status_code == 403
    assert elapsed >= 0.040, (
        f"403 verify took {elapsed*1000:.1f}ms, expected >= ~50ms "
        "floor - membership status leaks via timing without it"
    )


def test_T13_V30d_timing_floor_applies_to_429_rate_limit_path(
    tmp_path, dao, seller, agent_did,
):
    """Same defence for the 429 rate-limit path: an attacker shouldn't
    distinguish "you're rate-limited" from "you're not a member"
    via wall-clock."""
    client = _client_with_members(tmp_path, "actor-a")
    state = client.app.state.nth
    from nth_dao.web.rate_limit import RateLimiter
    state.verify_limiter = RateLimiter(
        max_per_window=1, window_seconds=60.0,
    )

    intent = _signed_intent(dao, agent_did, seller=seller)
    payload = {"kind": "intent", "mandate": intent, "actor_id": "actor-a"}

    # First call burns the budget
    client.post("/api/mandates/verify", json=payload)

    # Second call: 429
    start = time.monotonic()
    resp = client.post("/api/mandates/verify", json=payload)
    elapsed = time.monotonic() - start

    assert resp.status_code == 429
    assert elapsed >= 0.040, (
        f"429 verify took {elapsed*1000:.1f}ms, expected >= ~50ms floor"
    )
