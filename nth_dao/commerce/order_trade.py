"""Compatibility bridge from an authorised service Order into Trade."""

from __future__ import annotations

from typing import Any, Dict, Tuple

from nth_dao.commerce.order import OrderEvent, OrderStore, verify_order
from nth_dao.commerce.trade import (
    EVENT_TRADE_OPENED,
    STATE_EXECUTING,
    REJECT_TRADE_EXISTS,
    TradeEvent,
    TradeRejected,
    TradeStore,
    _append_event,
    verify_trade,
)


class OrderTradeRejected(ValueError):
    pass


def _verified_order(store: OrderStore, order_id: str) -> OrderEvent:
    events = store.get_events(order_id)
    if not events:
        raise OrderTradeRejected("order not found")
    ok, reason = verify_order(events)
    if not ok:
        raise OrderTradeRejected(f"order verification failed: {reason}")
    return OrderEvent.from_dict(events[0])


def _trade_open_payload(
    order: OrderEvent,
    *,
    verifier_did: str,
    resolver_did: str,
) -> Dict[str, Any]:
    op = order.payload
    buyer = op["buyer_did"]
    seller = op["seller_did"]
    return {
        "source": "commerce_order",
        "order_id": order.order_id,
        "listing_id": op["listing_id"],
        "listing_digest": op["listing_digest"],
        "payment_mandate_digest": op["payment_mandate_digest"],
        # Reuse legacy Trade role names without changing its state machine:
        # provider/seller delivers as claimant; buyer is the requester/publisher.
        "claimant_did": seller,
        "publisher_did": buyer,
        "verifier_did": verifier_did or buyer,
        "settler_did": buyer,
        "resolver_did": resolver_did or verifier_did or buyer,
        "claim_receipt_id": "",
        "terms": {
            "amount_minor": op["amount_minor"],
            "currency": op["currency"],
            "payee_did": seller,
        },
    }


def open_commerce_trade(
    trade_store: TradeStore,
    order_store: OrderStore,
    order_id: str,
    *,
    authority: Any,
    now_ms_override: int = 0,
) -> TradeEvent:
    """Open one idempotent service Trade whose id is the signed Order id."""
    order = _verified_order(order_store, order_id)
    if order.payload["listing_type"] != "service":
        raise OrderTradeRejected("only service orders can open a Trade")
    if authority.as_did() != order.payload["buyer_did"]:
        raise OrderTradeRejected("trade authority is not the order buyer")
    # v1 has no signed evaluator delegation in the Order snapshot. Keep all
    # acceptance/settlement authority with the buyer until that policy exists.
    payload = _trade_open_payload(
        order,
        verifier_did=order.payload["buyer_did"],
        resolver_did=order.payload["buyer_did"],
    )
    existing = trade_store.get_events(order_id)
    if existing:
        opened = TradeEvent.from_dict(existing[0])
        if opened.type == EVENT_TRADE_OPENED and opened.payload == payload:
            ok, reason = verify_trade(trade_store, order_id)
            if ok:
                return opened
            raise OrderTradeRejected(f"existing trade is invalid: {reason}")
        raise OrderTradeRejected("order already maps to a different trade")
    try:
        return _append_event(
            trade_store,
            order_id,
            actor=authority,
            event_type=EVENT_TRADE_OPENED,
            new_state=STATE_EXECUTING,
            payload=payload,
            expect_open=True,
            allowed_actor_dids=None,
            now_ms_override=now_ms_override,
        )
    except TradeRejected as exc:
        # Another process may have won after our optimistic read.
        if exc.reason != REJECT_TRADE_EXISTS:
            raise
        existing = trade_store.get_events(order_id) or []
        if existing:
            opened = TradeEvent.from_dict(existing[0])
            if opened.payload == payload and verify_trade(trade_store, order_id)[0]:
                return opened
        raise OrderTradeRejected("concurrent trade conflicts with this order") from exc


def verify_order_trade_binding(
    order_store: OrderStore,
    trade_store: TradeStore,
    order_id: str,
) -> Tuple[bool, str]:
    """Prove that Trade roles and terms are derived from the signed Order."""
    try:
        order = _verified_order(order_store, order_id)
    except OrderTradeRejected as exc:
        return False, str(exc)
    if order.payload.get("listing_type") != "service":
        return False, "order is not a service order"
    events = trade_store.get_events(order_id)
    if not events:
        return False, "trade not found"
    ok, reason = verify_trade(trade_store, order_id)
    if not ok:
        return False, f"trade verification failed: {reason}"
    opened = TradeEvent.from_dict(events[0])
    payload = opened.payload
    op = order.payload
    expected = {
        "source": "commerce_order",
        "order_id": order_id,
        "listing_id": op["listing_id"],
        "listing_digest": op["listing_digest"],
        "payment_mandate_digest": op["payment_mandate_digest"],
        "claimant_did": op["seller_did"],
        "publisher_did": op["buyer_did"],
        "settler_did": op["buyer_did"],
        "claim_receipt_id": "",
        "terms": {
            "amount_minor": op["amount_minor"],
            "currency": op["currency"],
            "payee_did": op["seller_did"],
        },
    }
    expected_fields = set(expected) | {"verifier_did", "resolver_did"}
    if set(payload) != expected_fields:
        return False, "trade/order binding mismatch: payload fields"
    for key, value in expected.items():
        if payload.get(key) != value:
            return False, f"trade/order binding mismatch: {key}"
    if opened.actor_did != op["buyer_did"]:
        return False, "trade opener is not order buyer"
    # Order v1 has no signed delegation object.  Acceptance and dispute
    # authority therefore remain with the buyer; accepting any other DID here
    # would let a validly signed opener redirect those powers out of band.
    for role in ("verifier_did", "resolver_did"):
        if payload.get(role) != op["buyer_did"]:
            return False, f"trade/order binding mismatch: {role}"
    return True, "ok"
