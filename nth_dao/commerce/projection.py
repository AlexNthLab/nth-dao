"""Verified buyer/seller views over immutable Order and Trade records."""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional

from nth_dao.canonical_json import canonical_json
from nth_dao.commerce.order import OrderStore
from nth_dao.commerce.order_trade import verify_order_trade_binding
from nth_dao.commerce.trade import TradeStore, trade_state, verify_trade


class CommerceProjectionRejected(ValueError):
    pass


def _event_receipt(event: Dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(event)).hexdigest()


def _event_details(event: Dict[str, Any]) -> Dict[str, Any]:
    payload = event.get("payload")
    if not isinstance(payload, dict):
        return {}
    event_type = event.get("type")
    allowed = {
        "delivery_submitted": ("delivery",),
        "verification_recorded": ("verdict", "result"),
        "settlement_recorded": ("settlement",),
        "dispute_opened": ("reason", "disputant_role", "evidence"),
        "dispute_resolved": ("resolution", "rationale", "settlement"),
    }.get(event_type, ())
    return {key: payload[key] for key in allowed if key in payload}


def project_order(
    order_store: OrderStore,
    trade_store: TradeStore,
    order_id: str,
    *,
    viewer_did: str = "",
) -> Dict[str, Any]:
    order = order_store.get(order_id)
    if order is None:
        raise CommerceProjectionRejected("order not found or failed verification")
    payload = order.payload
    buyer = payload["buyer_did"]
    seller = payload["seller_did"]
    if viewer_did and viewer_did not in {buyer, seller}:
        raise CommerceProjectionRejected("viewer is not an order party")

    trade_events = trade_store.get_events(order_id)
    state = "created"
    binding = "not-opened"
    projected_events: List[Dict[str, Any]] = [{
        "seq": 0,
        "type": order.type,
        "actor_did": order.actor_did,
        "state": order.new_state,
        "created_at_ms": order.created_at_ms,
        "receipt_id": _event_receipt(order.to_dict()),
    }]
    if trade_events:
        ok, reason = verify_trade(trade_store, order_id)
        if not ok:
            raise CommerceProjectionRejected(f"trade failed verification: {reason}")
        ok, reason = verify_order_trade_binding(order_store, trade_store, order_id)
        if not ok:
            raise CommerceProjectionRejected(reason)
        binding = "verified"
        state = trade_state(trade_store, order_id) or "created"
        projected_events.extend({
            "seq": int(raw["seq"]) + 1,
            "type": str(raw["type"]),
            "actor_did": str(raw["actor_did"]),
            "state": str(raw["new_state"]),
            "created_at_ms": int(raw["created_at_ms"]),
            "receipt_id": _event_receipt(raw),
            "details": _event_details(raw),
        } for raw in trade_events)

    return {
        "order_id": order_id,
        "role": "buyer" if viewer_did == buyer else "seller" if viewer_did == seller else "observer",
        "state": state,
        "buyer_did": buyer,
        "seller_did": seller,
        "listing_id": payload["listing_id"],
        "listing_digest": payload["listing_digest"],
        "listing_type": payload["listing_type"],
        "title": payload["authorization_snapshot"]["listing"]["title"],
        "amount_minor": payload["amount_minor"],
        "currency": payload["currency"],
        "settlement_method": payload["settlement_method"],
        "created_at_ms": order.created_at_ms,
        "binding": binding,
        "events": projected_events,
    }


def list_order_views(
    order_store: OrderStore,
    trade_store: TradeStore,
    *,
    viewer_did: str,
    role: Optional[str] = None,
    limit: int = 500,
) -> List[Dict[str, Any]]:
    if role not in (None, "buyer", "seller"):
        raise CommerceProjectionRejected("role must be buyer or seller")
    rows: List[Dict[str, Any]] = []
    for order in order_store.list_verified(limit=limit):
        payload = order.payload
        expected = payload["buyer_did"] if role == "buyer" else payload["seller_did"] if role == "seller" else ""
        if expected and expected != viewer_did:
            continue
        if viewer_did not in {payload["buyer_did"], payload["seller_did"]}:
            continue
        rows.append(project_order(
            order_store, trade_store, order.order_id, viewer_did=viewer_did,
        ))
    return rows
