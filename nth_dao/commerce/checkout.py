"""Fail-closed conversion of an authorised Mandate triad into an Order."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict

from nth_dao.execution_receipt import now_ms
from nth_dao.commerce.listing import SignedListing, listing_digest, verify_listing
from nth_dao.commerce.money import decimal_to_minor
from nth_dao.commerce.order import OrderEvent, OrderStore, create_order
from nth_dao.mandate import (
    cart_mandate_digest,
    complete_triad_chain,
    intent_mandate_digest,
    payment_mandate_digest,
)


class CheckoutRejected(ValueError):
    pass


def _subject(mandate: Dict[str, Any], label: str) -> Dict[str, Any]:
    subject = mandate.get("credentialSubject")
    if not isinstance(subject, dict):
        raise CheckoutRejected(f"{label} credentialSubject malformed")
    return subject


def create_order_from_mandates(
    store: OrderStore,
    *,
    authority: Any,
    intent: Dict[str, Any],
    cart: Dict[str, Any],
    payment: Dict[str, Any],
    listing: SignedListing,
    now_ms_override: int = 0,
) -> OrderEvent:
    if isinstance(now_ms_override, bool) or not isinstance(now_ms_override, int) or now_ms_override < 0:
        raise CheckoutRejected("now_ms_override must be a non-negative integer")
    effective_now = now_ms_override or now_ms()
    authorization_time = datetime.fromtimestamp(
        effective_now / 1000, tz=timezone.utc,
    )
    ok, reason = complete_triad_chain(
        intent, cart, payment, now=authorization_time,
    )
    if not ok:
        raise CheckoutRejected(f"mandate triad rejected: {reason}")
    ok, reason = verify_listing(listing)
    if not ok:
        raise CheckoutRejected(f"listing rejected: {reason}")
    if effective_now < listing.published_at_ms:
        raise CheckoutRejected("listing is not published yet")
    if effective_now >= listing.not_after_ms:
        raise CheckoutRejected("listing has expired")

    intent_subject = _subject(intent, "intent")
    cart_subject = _subject(cart, "cart")
    payment_subject = _subject(payment, "payment")
    buyer_did = intent.get("issuer")
    buyer_agent_did = intent_subject.get("id")
    seller_did = cart.get("issuer")
    if authority.as_did() != buyer_did:
        raise CheckoutRejected("checkout authority is not the buyer principal")
    if seller_did != listing.seller_did or payment_subject.get("id") != listing.seller_did:
        raise CheckoutRejected("listing seller does not match mandate counterparty")

    items = cart_subject.get("items")
    if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], dict):
        raise CheckoutRejected("v1 checkout requires exactly one listing item")
    item = items[0]
    digest = listing_digest(listing)
    if item.get("listing_digest") != digest or item.get("listing_id") != listing.listing_id:
        raise CheckoutRejected("cart item is not bound to this listing")
    quantity = item.get("quantity")
    if isinstance(quantity, bool) or quantity != 1:
        raise CheckoutRejected("v1 checkout supports quantity=1 only")

    total = cart_subject.get("total")
    if not isinstance(total, dict):
        raise CheckoutRejected("cart total malformed")
    currency = total.get("currency")
    try:
        amount_minor = decimal_to_minor(total.get("value"), currency, require_positive=True)
        price_minor = decimal_to_minor(
            listing.price_value, listing.price_currency, require_positive=True
        )
    except ValueError as exc:
        raise CheckoutRejected(f"amount rejected: {exc}") from exc
    if currency != listing.price_currency or amount_minor != price_minor:
        raise CheckoutRejected("cart total does not equal listing price")

    settlement_method = payment_subject.get("settlement_choice")
    if settlement_method not in listing.settlement_methods:
        raise CheckoutRejected("settlement method is not accepted by listing")

    intent_digest = intent_mandate_digest(intent)
    cart_digest = cart_mandate_digest(cart)
    payment_digest = payment_mandate_digest(payment)
    payload = {
        "schema_version": 1,
        "listing_id": listing.listing_id,
        "listing_digest": digest,
        "listing_type": listing.listing_type,
        "buyer_did": buyer_did,
        "buyer_agent_did": buyer_agent_did,
        "seller_did": seller_did,
        "intent_mandate_digest": intent_digest,
        "cart_mandate_digest": cart_digest,
        "payment_mandate_digest": payment_digest,
        "payment_id": str(payment_subject.get("payment_id", "")),
        "items": items,
        "amount_minor": amount_minor,
        "currency": currency,
        "settlement_method": settlement_method,
        "authorization_snapshot": {
            "listing": deepcopy(listing.to_dict()),
            "intent": deepcopy(intent),
            "cart": deepcopy(cart),
            "payment": deepcopy(payment),
        },
    }
    return create_order(
        store,
        authority,
        payment_digest=payment_digest,
        payload=payload,
        now_ms_override=now_ms_override,
    )
