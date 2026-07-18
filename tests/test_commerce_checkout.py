from datetime import datetime, timedelta, timezone

import pytest

from nth_dao.commerce.checkout import CheckoutRejected, create_order_from_mandates
from nth_dao.commerce.listing import (
    LISTING_SERVICE,
    SignedListing,
    listing_digest,
    sign_listing,
)
from nth_dao.commerce.money import MAX_MINOR_AMOUNT
from nth_dao.commerce.order import (
    OrderEvent,
    OrderRejected,
    OrderStore,
    create_order,
    sign_order_event,
    verify_order,
)
from nth_dao.commerce.order_trade import (
    open_commerce_trade,
    verify_order_trade_binding,
)
from nth_dao.commerce.trade import (
    TradeEvent,
    TradeStore,
    sign_trade_event,
    submit_delivery,
    verify_trade,
)
from nth_dao.identity import AgentIdentity
from nth_dao.util.io import atomic_write_json
from nth_dao.mandate import (
    build_cart_mandate,
    build_intent_mandate,
    build_payment_mandate,
    cart_mandate_digest,
    intent_mandate_digest,
    sign_cart_mandate,
    sign_intent_mandate,
    sign_payment_mandate,
)


def _authorised_checkout():
    buyer = AgentIdentity.generate()
    agent = AgentIdentity.generate()
    seller = AgentIdentity.generate()
    issued = datetime.now(timezone.utc)
    expires = (issued + timedelta(hours=1)).isoformat()
    published = int(issued.timestamp() * 1000)
    listing = sign_listing(
        seller,
        SignedListing(
            listing_id="svc-review-v1",
            listing_type=LISTING_SERVICE,
            seller_did=seller.as_did(),
            title="Code review",
            description="One signed review",
            price_value="50.00",
            price_currency="USDC",
            settlement_methods=["x402:usdc"],
            details={"fulfillment_type": "digital"},
            published_at_ms=published,
            not_after_ms=published + 3_600_000,
        ),
    )
    intent = sign_intent_mandate(
        build_intent_mandate(
            buyer.as_did(),
            agent.as_did(),
            "buy one code review",
            {
                "max_amount": {"value": "50.00", "currency": "USDC"},
                "allowed_counterparties": [seller.as_did()],
                "allowed_settlement_methods": ["x402:usdc"],
            },
            expires,
            issued_at=issued,
        ),
        buyer,
        created_at=issued,
    )
    cart = sign_cart_mandate(
        build_cart_mandate(
            seller.as_did(),
            agent.as_did(),
            intent_mandate_digest(intent),
            [{
                "description": "Code review",
                "listing_id": listing.listing_id,
                "listing_digest": listing_digest(listing),
                "quantity": 1,
            }],
            {"value": "50.00", "currency": "USDC"},
            ["x402:usdc"],
            expires,
            issued_at=issued,
        ),
        seller,
        created_at=issued,
    )
    payment = sign_payment_mandate(
        build_payment_mandate(
            buyer.as_did(),
            seller.as_did(),
            cart_mandate_digest(cart),
            "x402:usdc",
            expires,
            issued_at=issued,
        ),
        buyer,
        created_at=issued,
    )
    return buyer, agent, seller, listing, intent, cart, payment


def test_checkout_creates_one_idempotent_signed_order(tmp_path):
    buyer, _, _, listing, intent, cart, payment = _authorised_checkout()
    store = OrderStore(tmp_path)
    first = create_order_from_mandates(
        store=store,
        authority=buyer,
        intent=intent,
        cart=cart,
        payment=payment,
        listing=listing,
        now_ms_override=listing.published_at_ms + 1_000,
    )
    second = create_order_from_mandates(
        store=store,
        authority=buyer,
        intent=intent,
        cart=cart,
        payment=payment,
        listing=listing,
        now_ms_override=listing.published_at_ms + 2_000,
    )
    assert second.to_dict() == first.to_dict()
    events = store.get_events(first.order_id)
    assert events is not None
    assert len(events) == 1
    assert verify_order(events) == (True, "ok")
    assert first.payload["amount_minor"] == 50_000_000
    events[0]["unsigned_surprise"] = "settled"
    assert verify_order(events)[0] is False


def test_checkout_uses_order_time_for_mandate_freshness(tmp_path, monkeypatch):
    import nth_dao.commerce.checkout as checkout_module

    buyer, _, _, listing, intent, cart, payment = _authorised_checkout()
    expected_ms = listing.published_at_ms + 1_000
    observed = []
    real_gate = checkout_module.complete_triad_chain

    def recording_gate(intent_doc, cart_doc, payment_doc, *, now=None):
        observed.append(now)
        return real_gate(intent_doc, cart_doc, payment_doc, now=now)

    monkeypatch.setattr(checkout_module, "complete_triad_chain", recording_gate)
    create_order_from_mandates(
        OrderStore(tmp_path),
        authority=buyer,
        intent=intent,
        cart=cart,
        payment=payment,
        listing=listing,
        now_ms_override=expected_ms,
    )

    assert len(observed) == 1
    assert int(observed[0].timestamp() * 1000) == expected_ms


def test_public_create_order_rejects_unbacked_authorization(tmp_path):
    buyer = AgentIdentity.generate()
    seller = AgentIdentity.generate()
    payment_digest = "1" * 64
    payload = {
        "schema_version": 1,
        "listing_id": "invented",
        "listing_digest": "sha256:" + "2" * 64,
        "listing_type": "service",
        "buyer_did": buyer.as_did(),
        "buyer_agent_did": buyer.as_did(),
        "seller_did": seller.as_did(),
        "intent_mandate_digest": "3" * 64,
        "cart_mandate_digest": "4" * 64,
        "payment_mandate_digest": payment_digest,
        "payment_id": "invented-payment",
        "items": [{
            "listing_id": "invented",
            "listing_digest": "sha256:" + "2" * 64,
            "quantity": 1,
        }],
        "amount_minor": 999_999,
        "currency": "USDC",
        "settlement_method": "x402:usdc",
        "authorization_snapshot": {
            "listing": {}, "intent": {}, "cart": {}, "payment": {},
        },
    }

    with pytest.raises(OrderRejected, match="authorization"):
        create_order(
            OrderStore(tmp_path),
            buyer,
            payment_digest=payment_digest,
            payload=payload,
            now_ms_override=1_000,
        )


def test_checkout_rejects_unbound_listing(tmp_path):
    buyer, _, seller, listing, intent, cart, payment = _authorised_checkout()
    other = sign_listing(
        seller,
        SignedListing(
            listing_id="other",
            listing_type=LISTING_SERVICE,
            seller_did=seller.as_did(),
            title="Other",
            description="Different service",
            price_value="50.00",
            price_currency="USDC",
            settlement_methods=["x402:usdc"],
            details={},
            published_at_ms=listing.published_at_ms,
            not_after_ms=listing.not_after_ms,
        ),
    )
    with pytest.raises(CheckoutRejected, match="not bound"):
        create_order_from_mandates(
            OrderStore(tmp_path),
            authority=buyer,
            intent=intent,
            cart=cart,
            payment=payment,
            listing=other,
        )


def test_checkout_rejects_wrong_authority(tmp_path):
    buyer, agent, _, listing, intent, cart, payment = _authorised_checkout()
    with pytest.raises(CheckoutRejected, match="buyer principal"):
        create_order_from_mandates(
            OrderStore(tmp_path),
            authority=agent,
            intent=intent,
            cart=cart,
            payment=payment,
            listing=listing,
        )


def test_checkout_rejects_expired_listing(tmp_path):
    buyer, _, _, listing, intent, cart, payment = _authorised_checkout()
    with pytest.raises(CheckoutRejected, match="expired"):
        create_order_from_mandates(
            OrderStore(tmp_path),
            authority=buyer,
            intent=intent,
            cart=cart,
            payment=payment,
            listing=listing,
            now_ms_override=listing.not_after_ms,
        )


def test_service_order_opens_idempotent_provider_trade(tmp_path):
    buyer, _, seller, listing, intent, cart, payment = _authorised_checkout()
    order_store = OrderStore(tmp_path)
    order = create_order_from_mandates(
        order_store,
        authority=buyer,
        intent=intent,
        cart=cart,
        payment=payment,
        listing=listing,
        now_ms_override=listing.published_at_ms + 1_000,
    )
    trade_store = TradeStore(tmp_path)
    first = open_commerce_trade(
        trade_store,
        order_store,
        order.order_id,
        authority=buyer,
        now_ms_override=listing.published_at_ms + 2_000,
    )
    second = open_commerce_trade(
        trade_store,
        order_store,
        order.order_id,
        authority=buyer,
        now_ms_override=listing.published_at_ms + 3_000,
    )
    assert second.to_dict() == first.to_dict()
    assert verify_trade(trade_store, order.order_id) == (True, "")
    events = trade_store.get_events(order.order_id)
    assert events is not None
    events[0]["unsigned_surprise"] = "settled"
    atomic_write_json(
        trade_store._path(order.order_id),
        {"trade_id": order.order_id, "events": events},
    )
    assert verify_trade(trade_store, order.order_id)[0] is False
    del events[0]["unsigned_surprise"]
    atomic_write_json(
        trade_store._path(order.order_id),
        {"trade_id": order.order_id, "events": events},
    )
    assert verify_order_trade_binding(
        order_store, trade_store, order.order_id
    ) == (True, "ok")
    assert first.payload["claimant_did"] == seller.as_did()
    assert first.payload["publisher_did"] == buyer.as_did()
    submit_delivery(
        trade_store,
        order.order_id,
        claimant=seller,
        delivery={"artifact_digest": "sha256:" + "b" * 64},
    )
    assert verify_trade(trade_store, order.order_id) == (True, "")


def test_order_store_get_never_returns_unverified_storage(tmp_path):
    buyer, _, _, listing, intent, cart, payment = _authorised_checkout()
    store = OrderStore(tmp_path)
    order = create_order_from_mandates(
        store,
        authority=buyer,
        intent=intent,
        cart=cart,
        payment=payment,
        listing=listing,
        now_ms_override=listing.published_at_ms + 1_000,
    )
    assert store.get(order.order_id) == order

    events = store.get_events(order.order_id)
    assert events is not None
    events[0]["payload"]["amount_minor"] += 1
    atomic_write_json(
        store._path(order.order_id),
        {"order_id": order.order_id, "events": events},
    )

    assert store.get(order.order_id) is None


@pytest.mark.parametrize("event_sig", ["A" * 129, "AA", "valid-padded"])
def test_order_signature_input_is_bounded_and_exact_length(tmp_path, event_sig):
    buyer, _, _, listing, intent, cart, payment = _authorised_checkout()
    store = OrderStore(tmp_path)
    order = create_order_from_mandates(
        store,
        authority=buyer,
        intent=intent,
        cart=cart,
        payment=payment,
        listing=listing,
        now_ms_override=listing.published_at_ms + 1_000,
    )
    events = store.get_events(order.order_id)
    assert events is not None
    events[0]["event_sig"] = (
        events[0]["event_sig"] + "=="
        if event_sig == "valid-padded"
        else event_sig
    )
    assert verify_order(events) == (False, "event signature invalid")


def test_order_wire_rejects_signed_amount_above_protocol_range(tmp_path):
    buyer, _, _, listing, intent, cart, payment = _authorised_checkout()
    store = OrderStore(tmp_path)
    order = create_order_from_mandates(
        store,
        authority=buyer,
        intent=intent,
        cart=cart,
        payment=payment,
        listing=listing,
        now_ms_override=listing.published_at_ms + 1_000,
    )
    oversized = OrderEvent.from_dict(order.to_dict())
    oversized.payload = dict(oversized.payload)
    oversized.payload["amount_minor"] = MAX_MINOR_AMOUNT + 1
    sign_order_event(buyer, oversized)

    assert verify_order([oversized.to_dict()]) == (
        False,
        "invalid amount_minor",
    )


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        (lambda payload: payload["items"][0].__setitem__("quantity", 2),
         "order item is not bound to listing"),
        (lambda payload: payload["items"].append(dict(payload["items"][0])),
         "order v1 requires exactly one item"),
        (lambda payload: payload["items"][0].__setitem__(
            "description", "x" * (128 * 1024)),
         "order payload too large"),
    ],
)
def test_order_wire_enforces_single_listing_snapshot(tmp_path, mutation, reason):
    buyer, _, _, listing, intent, cart, payment = _authorised_checkout()
    store = OrderStore(tmp_path)
    order = create_order_from_mandates(
        store,
        authority=buyer,
        intent=intent,
        cart=cart,
        payment=payment,
        listing=listing,
        now_ms_override=listing.published_at_ms + 1_000,
    )
    altered = OrderEvent.from_dict(order.to_dict())
    altered.payload = {
        **altered.payload,
        "items": [dict(item) for item in altered.payload["items"]],
    }
    mutation(altered.payload)
    sign_order_event(buyer, altered)

    assert verify_order([altered.to_dict()]) == (False, reason)


def test_order_wire_rejects_unknown_top_level_payload_field(tmp_path):
    buyer, _, _, listing, intent, cart, payment = _authorised_checkout()
    store = OrderStore(tmp_path)
    order = create_order_from_mandates(
        store,
        authority=buyer,
        intent=intent,
        cart=cart,
        payment=payment,
        listing=listing,
        now_ms_override=listing.published_at_ms + 1_000,
    )
    altered = OrderEvent.from_dict(order.to_dict())
    altered.payload = dict(altered.payload)
    altered.payload["unsigned_surprise"] = True
    sign_order_event(buyer, altered)

    assert verify_order([altered.to_dict()]) == (
        False,
        "order payload has missing or unknown fields",
    )


@pytest.mark.parametrize("role", ["verifier_did", "resolver_did"])
def test_order_trade_binding_rejects_redirected_buyer_authority(tmp_path, role):
    buyer, _, _, listing, intent, cart, payment = _authorised_checkout()
    order_store = OrderStore(tmp_path)
    order = create_order_from_mandates(
        order_store,
        authority=buyer,
        intent=intent,
        cart=cart,
        payment=payment,
        listing=listing,
        now_ms_override=listing.published_at_ms + 1_000,
    )
    trade_store = TradeStore(tmp_path)
    opened = open_commerce_trade(
        trade_store,
        order_store,
        order.order_id,
        authority=buyer,
        now_ms_override=listing.published_at_ms + 2_000,
    )
    redirected = TradeEvent.from_dict(opened.to_dict())
    redirected.payload = dict(redirected.payload)
    redirected.payload[role] = AgentIdentity.generate().as_did()
    sign_trade_event(buyer, redirected)

    from nth_dao.util.io import atomic_write_json
    atomic_write_json(
        trade_store._path(order.order_id),
        {"trade_id": order.order_id, "events": [redirected.to_dict()]},
    )

    assert verify_trade(trade_store, order.order_id) == (True, "")
    ok, reason = verify_order_trade_binding(
        order_store, trade_store, order.order_id
    )
    assert ok is False
    assert reason == f"trade/order binding mismatch: {role}"


def test_order_trade_binding_rejects_extra_signed_open_payload(tmp_path):
    buyer, _, _, listing, intent, cart, payment = _authorised_checkout()
    order_store = OrderStore(tmp_path)
    order = create_order_from_mandates(
        order_store,
        authority=buyer,
        intent=intent,
        cart=cart,
        payment=payment,
        listing=listing,
        now_ms_override=listing.published_at_ms + 1_000,
    )
    trade_store = TradeStore(tmp_path)
    opened = open_commerce_trade(
        trade_store,
        order_store,
        order.order_id,
        authority=buyer,
        now_ms_override=listing.published_at_ms + 2_000,
    )
    altered = TradeEvent.from_dict(opened.to_dict())
    altered.payload = dict(altered.payload)
    altered.payload["unsigned_surprise"] = "buyer-signed-but-undefined"
    sign_trade_event(buyer, altered)
    atomic_write_json(
        trade_store._path(order.order_id),
        {"trade_id": order.order_id, "events": [altered.to_dict()]},
    )

    assert verify_trade(trade_store, order.order_id) == (True, "")
    assert verify_order_trade_binding(
        order_store, trade_store, order.order_id
    ) == (False, "trade/order binding mismatch: payload fields")
