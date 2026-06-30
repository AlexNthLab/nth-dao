"""Regression tests for the second-round Voss review (T-2 - T-9).

Covers:
  V-21 binding-check require_signed
  V-22 empty allow-lists = fail-closed at runtime
  V-23 cart.total NaN / Infinity rejection
  V-24 A2A body size cap
  V-25 A2A explicit-auth gate
  V-26 A2A batch size cap
  V-27 JSON-RPC positional params + V-41 id-vs-taskId presence
  V-28 /api/mandates/* membership gate
  V-29 /api/mandates/store verify-before-persist
  V-31 triad chain runs cheap structural gates first
  V-32 payment_satisfies_cart(intent=) issuer continuity
  V-33 settlement_methods / settlement_choice tight regex
  V-34 emit_*_received verify-before-emit
  V-35 Agent Card URL urlparse + CR/LF + length cap
  V-36 MandateStore preserves earlier proof on digest collision
  V-38 write_agent_card atomic write

The horizontal V-1..V-20 propagation from T-1 to cart/payment lives
in the T-1.1 ticket and is not retested here.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from nth_dao.a2a.agent_card import (
    build_agent_card,
    validate_agent_card,
    write_agent_card,
)
from nth_dao.a2a.server import (
    A2A_REQUEST_TOO_LARGE,
    A2A_UNAUTHENTICATED,
    JSONRPC_INVALID_PARAMS,
    JsonRpcError,
    create_a2a_app,
)
from nth_dao.event_bus import EventBus
from nth_dao.identity import AgentIdentity, crypto_available
from nth_dao.mandate.cart import (
    build_cart_mandate,
    cart_mandate_digest,
    cart_satisfies_intent,
    sign_cart_mandate,
)
from nth_dao.mandate.events import (
    emit_cart_received,
    emit_intent_issued,
    emit_payment_authorised,
)
from nth_dao.mandate.intent import (
    build_intent_mandate,
    intent_mandate_digest,
    sign_intent_mandate,
)
from nth_dao.mandate.payment import (
    build_payment_mandate,
    complete_triad_chain,
    payment_satisfies_cart,
    sign_payment_mandate,
)
from nth_dao.mandate.store import MandateStore
from nth_dao.web import create_app


# ----- shared fixtures -----


@pytest.fixture
def dao() -> AgentIdentity:
    if not crypto_available():
        pytest.skip("PyNaCl required")
    return AgentIdentity.generate(label="voss-dao")


@pytest.fixture
def seller() -> AgentIdentity:
    if not crypto_available():
        pytest.skip("PyNaCl required")
    return AgentIdentity.generate(label="voss-seller")


@pytest.fixture
def hijacker() -> AgentIdentity:
    if not crypto_available():
        pytest.skip("PyNaCl required")
    return AgentIdentity.generate(label="voss-hijacker")


@pytest.fixture
def agent_did() -> str:
    if not crypto_available():
        pytest.skip("PyNaCl required")
    return AgentIdentity.generate(label="voss-agent").as_did()


def _future(s: int = 3600) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=s)).isoformat()


def _sign_intent(dao, agent_did, *, seller=None, **constraint_overrides):
    constraints = {
        "max_amount": {"value": "100.00", "currency": "USDC"},
        "allowed_counterparties": (
            [seller.as_did()] if seller is not None else []
        ),
        "allowed_settlement_methods": ["x402:usdc"],
    }
    constraints.update(constraint_overrides)
    m = build_intent_mandate(
        issuer_did=dao.as_did(), agent_did=agent_did,
        purpose="x", constraints=constraints, expires_at=_future(86400),
    )
    return sign_intent_mandate(m, dao)


def _sign_cart(seller, agent_did, intent_digest, *, total=None, methods=None):
    c = build_cart_mandate(
        issuer_did=seller.as_did(), buyer_did=agent_did,
        intent_mandate_digest_hex=intent_digest,
        items=[{"description": "x", "quantity": 1}],
        total=total or {"value": "50.00", "currency": "USDC"},
        settlement_methods=methods or ["x402:usdc"],
        expires_at=_future(3600),
    )
    return sign_cart_mandate(c, seller)


def _sign_payment(dao, seller, cart_digest, *, issuer_did=None):
    p = build_payment_mandate(
        issuer_did=issuer_did or dao.as_did(),
        payee_did=seller.as_did(),
        cart_mandate_digest_hex=cart_digest,
        settlement_choice="x402:usdc", expires_at=_future(900),
    )
    return sign_payment_mandate(p, dao)


def _bare_card() -> Dict[str, Any]:
    return build_agent_card(
        name="Voss Test Agent", description="",
        url="https://localhost:8080/a2a",
        capabilities=["echo"],
    )


# ===== V-21 binding-check require_signed =====


def test_voss_V21a_cart_satisfies_rejects_unsigned_intent(dao, seller, agent_did):
    unsigned_intent = build_intent_mandate(
        issuer_did=dao.as_did(), agent_did=agent_did, purpose="x",
        constraints={
            "max_amount": {"value": "9999.00", "currency": "USDC"},
            "allowed_counterparties": [seller.as_did()],
            "allowed_settlement_methods": ["x402:usdc"],
        },
        expires_at=_future(86400),
    )
    cart = _sign_cart(seller, agent_did, intent_mandate_digest(unsigned_intent))
    ok, reason = cart_satisfies_intent(cart, unsigned_intent)
    assert ok is False and "intent must be signed" in reason


def test_voss_V21b_payment_satisfies_rejects_unsigned(dao, seller, agent_did):
    intent = _sign_intent(dao, agent_did, seller=seller)
    cart = _sign_cart(seller, agent_did, intent_mandate_digest(intent))
    unsigned_payment = build_payment_mandate(
        issuer_did=dao.as_did(), payee_did=seller.as_did(),
        cart_mandate_digest_hex=cart_mandate_digest(cart),
        settlement_choice="x402:usdc", expires_at=_future(900),
    )
    ok, reason = payment_satisfies_cart(unsigned_payment, cart)
    assert ok is False and "payment must be signed" in reason


def test_voss_V21c_opt_out_with_require_signed_false(dao, seller, agent_did):
    intent = build_intent_mandate(
        issuer_did=dao.as_did(), agent_did=agent_did, purpose="x",
        constraints={
            "max_amount": {"value": "100.00", "currency": "USDC"},
            "allowed_counterparties": [seller.as_did()],
            "allowed_settlement_methods": ["x402:usdc"],
        },
        expires_at=_future(86400),
    )
    cart = build_cart_mandate(
        issuer_did=seller.as_did(), buyer_did=agent_did,
        intent_mandate_digest_hex=intent_mandate_digest(intent),
        items=[{"description": "x", "quantity": 1}],
        total={"value": "50.00", "currency": "USDC"},
        settlement_methods=["x402:usdc"], expires_at=_future(3600),
    )
    ok, _ = cart_satisfies_intent(cart, intent, require_signed=False)
    assert ok is True


# ===== V-22 empty allow-list = fail-closed at runtime =====


def test_voss_V22a_empty_counterparties_rejects(dao, seller, agent_did):
    # seller=None -> empty whitelist
    intent = _sign_intent(dao, agent_did)
    cart = _sign_cart(seller, agent_did, intent_mandate_digest(intent))
    ok, reason = cart_satisfies_intent(cart, intent)
    assert ok is False and "allowed_counterparties is empty" in reason


def test_voss_V22b_empty_methods_rejects(dao, seller, agent_did):
    intent = _sign_intent(
        dao, agent_did, seller=seller, allowed_settlement_methods=[],
    )
    cart = _sign_cart(seller, agent_did, intent_mandate_digest(intent))
    ok, reason = cart_satisfies_intent(cart, intent)
    assert ok is False and "allowed_settlement_methods is empty" in reason


# ===== V-23 cart total NaN / Inf =====


@pytest.mark.parametrize("bad", ["NaN", "Infinity", "-Infinity"])
def test_voss_V23_cart_total_non_finite_rejected(dao, seller, agent_did, bad):
    intent = _sign_intent(dao, agent_did, seller=seller)
    cart = _sign_cart(seller, agent_did, intent_mandate_digest(intent))
    # Smuggle non-finite total past build (build rejects it). Tampering
    # invalidates the cart's signature, but V-23 is a STRUCTURAL gate
    # specifically about the numeric value, not about signatures.
    # Bypass V-21's strict signature check (F-2 4th-round) so the
    # finite check is reachable.
    cart["credentialSubject"] = dict(cart["credentialSubject"])
    cart["credentialSubject"]["total"] = {"value": bad, "currency": "USDC"}
    ok, reason = cart_satisfies_intent(cart, intent, require_signed=False)
    assert ok is False and "finite" in reason


# ===== V-24 / V-25 / V-26 A2A guards =====


def test_voss_V24_a2a_rejects_oversized_body():
    app = create_a2a_app(
        agent_card=_bare_card(), allow_unauthenticated=True,
        max_request_bytes=1024,
    )
    with TestClient(app) as c:
        resp = c.post(
            "/a2a/jsonrpc", content="x" * 2048,
            headers={"content-type": "application/json"},
        )
        assert resp.status_code == 413
        assert resp.json()["error"]["code"] == A2A_REQUEST_TOO_LARGE


def test_voss_V25a_create_app_requires_explicit_auth_choice():
    with pytest.raises(ValueError, match="auth_callable=<...>"):
        create_a2a_app(agent_card=_bare_card())


def test_voss_V25b_unauthenticated_is_explicit_opt_in():
    app = create_a2a_app(agent_card=_bare_card(), allow_unauthenticated=True)
    assert app is not None


def test_voss_V25c_auth_callable_can_refuse():
    async def deny(request: Request) -> None:
        raise JsonRpcError(A2A_UNAUTHENTICATED, "no")

    app = create_a2a_app(agent_card=_bare_card(), auth_callable=deny)
    with TestClient(app) as c:
        resp = c.post("/a2a/jsonrpc", json={
            "jsonrpc": "2.0", "id": 1, "method": "tasks/get",
            "params": {"id": "x"},
        })
        assert resp.status_code == 401
        assert resp.json()["error"]["code"] == A2A_UNAUTHENTICATED


def test_voss_V26_a2a_rejects_oversized_batch():
    app = create_a2a_app(
        agent_card=_bare_card(), allow_unauthenticated=True,
        max_batch_size=3,
    )
    with TestClient(app) as c:
        batch = [
            {"jsonrpc": "2.0", "id": i, "method": "tasks/get",
             "params": {"id": "x"}}
            for i in range(10)
        ]
        resp = c.post("/a2a/jsonrpc", json=batch)
        assert resp.json()["error"]["code"] == A2A_REQUEST_TOO_LARGE


# ===== V-27 + V-41 positional / id-vs-taskId presence =====


def test_voss_V27a_positional_array_params_accepted():
    app = create_a2a_app(agent_card=_bare_card(), allow_unauthenticated=True)
    with TestClient(app) as c:
        resp = c.post("/a2a/jsonrpc", json={
            "jsonrpc": "2.0", "id": 1, "method": "tasks/get",
            "params": ["task-001"],
        })
        # Not -32602: we got past param-shape into the no-mission-store branch.
        assert resp.json()["error"]["code"] != JSONRPC_INVALID_PARAMS


def test_voss_V27b_positional_arity_check():
    app = create_a2a_app(agent_card=_bare_card(), allow_unauthenticated=True)
    with TestClient(app) as c:
        resp = c.post("/a2a/jsonrpc", json={
            "jsonrpc": "2.0", "id": 1, "method": "tasks/get",
            "params": ["a", "b"],
        })
        assert resp.json()["error"]["code"] == JSONRPC_INVALID_PARAMS


def test_voss_V41_empty_id_does_not_alias_to_taskId():
    app = create_a2a_app(agent_card=_bare_card(), allow_unauthenticated=True)
    with TestClient(app) as c:
        resp = c.post("/a2a/jsonrpc", json={
            "jsonrpc": "2.0", "id": 1, "method": "tasks/get",
            "params": {"id": "", "taskId": "should-not-be-used"},
        })
        assert resp.json()["error"]["code"] == JSONRPC_INVALID_PARAMS


# ===== V-28 mandate-routes auth gate =====


def test_voss_V28_mandate_routes_gated_by_membership(tmp_path):
    # Pre-seed an invite_only team.json so stranger can't auto-join.
    # The mandate route runs _require_member_or_joinable -> can_join
    # -> returns False for invite_only -> 403.
    (tmp_path / "team.json").write_text(
        '{"team_name":"Closed","join_policy":"invite_only",'
        '"admin_ids":["admin"],"member_ids":["admin"],'
        '"roles":{"admin":"owner"}}',
        encoding="utf-8",
    )
    client = TestClient(create_app(tmp_path))
    resp = client.get("/api/mandates?actor_id=stranger")
    assert resp.status_code == 403


# ===== V-29 store verifies before persist =====


def test_voss_V29a_store_refuses_unsigned(tmp_path, dao, seller, agent_did):
    client = TestClient(create_app(tmp_path))
    unsigned = build_intent_mandate(
        issuer_did=dao.as_did(), agent_did=agent_did, purpose="x",
        constraints={
            "max_amount": {"value": "10.00", "currency": "USDC"},
            "allowed_counterparties": [seller.as_did()],
            "allowed_settlement_methods": ["x402:usdc"],
        },
        expires_at=_future(86400),
    )
    resp = client.post(
        "/api/mandates/store",
        json={"kind": "intent", "mandate": unsigned, "actor_id": "admin"},
    )
    assert resp.status_code == 400
    assert "signature" in resp.json()["detail"].lower()


def test_voss_V29b_store_accepts_signed(tmp_path, dao, seller, agent_did):
    client = TestClient(create_app(tmp_path))
    intent = _sign_intent(dao, agent_did, seller=seller)
    resp = client.post(
        "/api/mandates/store",
        json={"kind": "intent", "mandate": intent, "actor_id": "admin"},
    )
    assert resp.status_code == 200
    assert resp.json()["digest"] == intent_mandate_digest(intent)


# ===== V-31 triad chain check order =====


def test_voss_V31_triad_chain_rejects_hijacker_first(dao, seller, hijacker, agent_did):
    intent = _sign_intent(dao, agent_did, seller=seller)
    cart = _sign_cart(seller, agent_did, intent_mandate_digest(intent))
    hijacked = _sign_payment(hijacker, seller, cart_mandate_digest(cart),
                              issuer_did=hijacker.as_did())
    ok, reason = complete_triad_chain(intent, cart, hijacked)
    assert ok is False and "issuer continuity broken" in reason


# ===== V-32 payment_satisfies_cart(intent=) =====


def test_voss_V32_payment_satisfies_with_intent_catches_hijacker(
    dao, seller, hijacker, agent_did,
):
    intent = _sign_intent(dao, agent_did, seller=seller)
    cart = _sign_cart(seller, agent_did, intent_mandate_digest(intent))
    hijacked = _sign_payment(hijacker, seller, cart_mandate_digest(cart),
                              issuer_did=hijacker.as_did())
    # without intent= the hijack slips past payment_satisfies_cart
    ok_no_guard, _ = payment_satisfies_cart(hijacked, cart)
    assert ok_no_guard is True
    # with intent= the continuity check fires
    ok_guarded, reason = payment_satisfies_cart(hijacked, cart, intent=intent)
    assert ok_guarded is False and "issuer continuity broken" in reason


# ===== V-33 tight settlement_methods / settlement_choice regex =====


@pytest.mark.parametrize(
    "bad", [" : ", "::", "X:Y", "x: y", "x:\ny"],
    ids=["spaces", "double-colon", "upper", "embedded-space", "newline"],
)
def test_voss_V33a_cart_rejects_loose_methods(seller, agent_did, bad):
    with pytest.raises(ValueError, match="<adapter>:<asset>"):
        build_cart_mandate(
            issuer_did=seller.as_did(), buyer_did=agent_did,
            intent_mandate_digest_hex="a" * 64,
            items=[{"description": "x", "quantity": 1}],
            total={"value": "10.00", "currency": "USDC"},
            settlement_methods=[bad], expires_at=_future(3600),
        )


def test_voss_V33b_payment_rejects_loose_choice(dao, seller):
    with pytest.raises(ValueError, match="<adapter>:<asset>"):
        build_payment_mandate(
            issuer_did=dao.as_did(), payee_did=seller.as_did(),
            cart_mandate_digest_hex="a" * 64,
            settlement_choice="X:Y", expires_at=_future(900),
        )


# ===== V-34 emit verifies first =====


def test_voss_V34a_emit_intent_issued_refuses_unsigned(tmp_path, dao, seller, agent_did):
    bus = EventBus(tmp_path, identity=dao)
    unsigned = build_intent_mandate(
        issuer_did=dao.as_did(), agent_did=agent_did, purpose="x",
        constraints={
            "max_amount": {"value": "10.00", "currency": "USDC"},
            "allowed_counterparties": [seller.as_did()],
            "allowed_settlement_methods": ["x402:usdc"],
        },
        expires_at=_future(86400),
    )
    with pytest.raises(ValueError, match="refuse to emit"):
        emit_intent_issued(bus, unsigned)


def test_voss_V34b_emit_intent_issued_accepts_signed(tmp_path, dao, seller, agent_did):
    bus = EventBus(tmp_path, identity=dao)
    ev = emit_intent_issued(bus, _sign_intent(dao, agent_did, seller=seller))
    assert ev.event_type == "mandate.intent.issued"


def test_voss_V34c_emit_cart_received_refuses_unsigned(tmp_path, dao, seller, agent_did):
    bus = EventBus(tmp_path, identity=dao)
    unsigned = build_cart_mandate(
        issuer_did=seller.as_did(), buyer_did=agent_did,
        intent_mandate_digest_hex="a" * 64,
        items=[{"description": "x", "quantity": 1}],
        total={"value": "10.00", "currency": "USDC"},
        settlement_methods=["x402:usdc"], expires_at=_future(3600),
    )
    with pytest.raises(ValueError, match="refuse to emit"):
        emit_cart_received(bus, unsigned)


def test_voss_V34d_emit_payment_authorised_refuses_unsigned(tmp_path, dao, seller):
    bus = EventBus(tmp_path, identity=dao)
    unsigned = build_payment_mandate(
        issuer_did=dao.as_did(), payee_did=seller.as_did(),
        cart_mandate_digest_hex="a" * 64,
        settlement_choice="x402:usdc", expires_at=_future(900),
    )
    with pytest.raises(ValueError, match="refuse to emit"):
        emit_payment_authorised(bus, unsigned)


# ===== V-35 Agent Card URL hardening =====


@pytest.mark.parametrize("bad", [
    "http://", "https://",
    "https://x.com/path\nEvil: x",
    "https://x.com/" + ("a" * 3000),
    "ftp://example.com/",
])
def test_voss_V35_build_agent_card_rejects_bad_url(bad):
    with pytest.raises(ValueError):
        build_agent_card(name="X", description="", url=bad)


def test_voss_V35_validate_rejects_mutated_bad_url():
    good = build_agent_card(name="X", description="", url="https://x.com/a")
    good["supportedInterfaces"][0]["url"] = "http://"
    ok, reason = validate_agent_card(good)
    assert ok is False and "host" in reason


# ===== V-36 MandateStore preserves earlier proof =====


def test_voss_V36_store_preserves_earlier_proof(tmp_path, dao, seller, agent_did):
    store = MandateStore(tmp_path)
    unsigned = build_intent_mandate(
        issuer_did=dao.as_did(), agent_did=agent_did,
        purpose="buy code review",
        constraints={
            "max_amount": {"value": "100.00", "currency": "USDC"},
            "allowed_counterparties": [seller.as_did()],
            "allowed_settlement_methods": ["x402:usdc"],
        },
        expires_at=_future(86400),
    )
    first = sign_intent_mandate(
        unsigned, dao, created_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
    )
    d1 = store.save_intent(first)

    second = sign_intent_mandate(
        unsigned, dao, created_at=datetime(2026, 6, 2, tzinfo=timezone.utc),
    )
    d2 = store.save_intent(second)
    assert d1 == d2

    on_disk = store.get("intent", d1)
    assert on_disk is not None
    # The earlier sign is preserved
    assert on_disk["proof"]["created"].startswith("2026-06-01")


# ===== V-38 atomic write =====


def test_voss_V38_write_agent_card_atomic(tmp_path):
    card = build_agent_card(
        name="Atomic", description="", url="https://example.com/a2a",
    )
    target = tmp_path / "well-known" / "agent.json"
    write_agent_card(target, card)
    assert target.exists()
    tmp_leftover = target.with_suffix(target.suffix + ".tmp")
    assert not tmp_leftover.exists()
