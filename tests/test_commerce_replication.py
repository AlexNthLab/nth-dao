from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
import json

import pytest

from nth_dao.commerce.checkout import create_order_from_mandates
from nth_dao.commerce.listing import LISTING_SERVICE, SignedListing, listing_digest, sign_listing
from nth_dao.commerce.order import OrderStore
from nth_dao.commerce.order_trade import open_commerce_trade
from nth_dao.commerce.outbox import (
    CommerceEnvelope,
    CommerceEnvelopeRejected,
    CommerceOutbox,
    sign_envelope,
    verify_envelope,
)
from nth_dao.commerce.projection import (
    CommerceProjectionRejected,
    list_order_views,
    project_order,
)
from nth_dao.commerce.trade import (
    TradeRejected,
    TradeStore,
    open_dispute,
    record_verification,
    submit_delivery,
)
from nth_dao.identity import AgentIdentity
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


def _order(tmp_path):
    buyer = AgentIdentity.generate()
    seller = AgentIdentity.generate()
    agent = AgentIdentity.generate()
    issued = datetime.now(timezone.utc)
    expires = (issued + timedelta(hours=1)).isoformat()
    published = int(issued.timestamp() * 1000)
    listing = sign_listing(seller, SignedListing(
        listing_id="review-v1",
        listing_type=LISTING_SERVICE,
        seller_did=seller.as_did(),
        title="Code review",
        description="Signed report",
        price_value="5",
        price_currency="NTH-TEST",
        settlement_methods=["manual:nth_test"],
        details={"fulfillment_type": "digital"},
        published_at_ms=published,
        not_after_ms=published + 3_600_000,
    ))
    intent = sign_intent_mandate(build_intent_mandate(
        buyer.as_did(), agent.as_did(), "buy review",
        {
            "max_amount": {"value": "5", "currency": "NTH-TEST"},
            "allowed_counterparties": [seller.as_did()],
            "allowed_settlement_methods": ["manual:nth_test"],
        },
        expires, issued_at=issued,
    ), buyer, created_at=issued)
    cart = sign_cart_mandate(build_cart_mandate(
        seller.as_did(), agent.as_did(), intent_mandate_digest(intent),
        [{
            "description": listing.title,
            "listing_id": listing.listing_id,
            "listing_digest": listing_digest(listing),
            "quantity": 1,
        }],
        {"value": "5", "currency": "NTH-TEST"},
        ["manual:nth_test"], expires, issued_at=issued,
    ), seller, created_at=issued)
    payment = sign_payment_mandate(build_payment_mandate(
        buyer.as_did(), seller.as_did(), cart_mandate_digest(cart),
        "manual:nth_test", expires, issued_at=issued,
    ), buyer, created_at=issued)
    orders = OrderStore(tmp_path)
    order = create_order_from_mandates(
        orders, authority=buyer, intent=intent, cart=cart, payment=payment,
        listing=listing, now_ms_override=published + 1_000,
    )
    trades = TradeStore(tmp_path)
    open_commerce_trade(
        trades, orders, order.order_id, authority=buyer,
        now_ms_override=published + 2_000,
    )
    return buyer, seller, order, orders, trades, published


def test_projection_is_same_verified_state_for_buyer_and_seller(tmp_path):
    buyer, seller, order, orders, trades, published = _order(tmp_path)
    submit_delivery(
        trades, order.order_id, claimant=seller,
        delivery={"artifact_digest": "sha256:" + "a" * 64},
        now_ms_override=published + 3_000,
    )

    buyer_view = project_order(orders, trades, order.order_id, viewer_did=buyer.as_did())
    seller_view = project_order(orders, trades, order.order_id, viewer_did=seller.as_did())
    assert buyer_view["state"] == seller_view["state"] == "delivered"
    assert buyer_view["role"] == "buyer"
    assert seller_view["role"] == "seller"
    assert buyer_view["events"] == seller_view["events"]
    assert buyer_view["events"][-1]["details"]["delivery"]["artifact_digest"] == "sha256:" + "a" * 64
    assert list_order_views(orders, trades, viewer_did=buyer.as_did(), role="buyer")[0]["order_id"] == order.order_id
    with pytest.raises(CommerceProjectionRejected, match="not an order party"):
        project_order(
            orders, trades, order.order_id,
            viewer_did=AgentIdentity.generate().as_did(),
        )


def test_outbox_envelope_is_content_bound_idempotent_and_acknowledged(tmp_path):
    source = AgentIdentity.generate()
    target = AgentIdentity.generate()
    envelope = sign_envelope(
        source,
        target_did=target.as_did(),
        payload={"order": {"id": "order-1"}},
        created_at_ms=1_900_000_000_000,
    )
    assert verify_envelope(envelope) == (True, "ok")
    outbox = CommerceOutbox(tmp_path)
    first = outbox.enqueue(envelope, target_url="https://seller.example/")
    second = outbox.enqueue(envelope, target_url="https://seller.example")
    assert first == second
    later_retry = sign_envelope(
        source,
        target_did=target.as_did(),
        payload={"order": {"id": "order-1"}},
        created_at_ms=1_900_000_000_500,
    )
    assert later_retry.message_id == envelope.message_id
    assert outbox.enqueue(later_retry, target_url="https://seller.example") == first
    assert len(outbox.pending()) == 1
    acked = outbox.record_attempt(
        envelope.message_id, acknowledged_at_ms=1_900_000_001_000,
    )
    assert acked.status == "acknowledged"
    assert outbox.pending() == []

    tampered = CommerceEnvelope.from_dict(envelope.to_dict())
    tampered.payload = {"order": {"id": "other"}}
    assert verify_envelope(tampered)[0] is False
    with pytest.raises(CommerceEnvelopeRejected):
        outbox.enqueue(tampered, target_url="https://seller.example")


def test_outbox_claim_is_exclusive_and_expired_leases_are_recoverable(tmp_path):
    source = AgentIdentity.generate()
    target = AgentIdentity.generate()
    envelope = sign_envelope(
        source,
        target_did=target.as_did(),
        payload={"order": {"id": "order-lease"}},
        created_at_ms=1_900_000_000_000,
    )
    outbox = CommerceOutbox(tmp_path)
    outbox.enqueue(envelope, target_url="https://seller.example")

    with ThreadPoolExecutor(max_workers=8) as executor:
        claims = list(executor.map(
            lambda _index: outbox.claim(
                envelope.message_id,
                lease_ms=1_000,
                now_ms_override=1_900_000_001_000,
            ),
            range(8),
        ))
    winners = [record for record in claims if record is not None]
    assert len(winners) == 1
    first = winners[0]
    assert first.status == "inflight"

    second = outbox.claim(
        envelope.message_id,
        lease_ms=1_000,
        now_ms_override=first.lease_expires_at_ms + 1,
    )
    assert second is not None
    assert second.lease_id != first.lease_id
    with pytest.raises(CommerceEnvelopeRejected, match="lease does not match"):
        outbox.record_attempt(
            envelope.message_id,
            acknowledged_at_ms=1_900_000_003_000,
            lease_id=first.lease_id,
        )
    acknowledged = outbox.record_attempt(
        envelope.message_id,
        acknowledged_at_ms=1_900_000_003_000,
        lease_id=second.lease_id,
    )
    assert acknowledged.status == "acknowledged"
    assert outbox.claim(envelope.message_id) is None

    duplicate_failure = outbox.record_attempt(
        envelope.message_id,
        error="a stale caller must not revive acknowledged work",
        lease_id=first.lease_id,
    )
    assert duplicate_failure.status == "acknowledged"
    assert duplicate_failure.attempts == acknowledged.attempts


def test_invalid_remote_trade_is_rejected_before_durable_write(tmp_path, monkeypatch):
    buyer, seller, order, _orders, trades, published = _order(tmp_path)
    submit_delivery(
        trades, order.order_id, claimant=seller,
        delivery={"artifact_digest": "sha256:" + "a" * 64},
        now_ms_override=published + 3_000,
    )
    original = trades.get_events(order.order_id)
    assert original is not None
    candidate = [dict(item) for item in original]
    forged_suffix = dict(candidate[-1])
    forged_suffix["seq"] = len(candidate)
    forged_suffix["prev_state"] = candidate[-1]["new_state"]
    forged_suffix["new_state"] = "settled"
    candidate.append(forged_suffix)

    import nth_dao.commerce.trade as trade_module

    writes = []
    real_write = trade_module.atomic_write_json

    def recording_write(path, value, **kwargs):
        writes.append((path, value))
        return real_write(path, value, **kwargs)

    monkeypatch.setattr(trade_module, "atomic_write_json", recording_write)
    with pytest.raises(TradeRejected):
        trades.import_verified_events(order.order_id, candidate)
    assert writes == []
    assert trades.get_events(order.order_id) == original


def test_append_reverifies_stored_chain_and_enforces_total_budget(tmp_path):
    buyer, seller, order, _orders, trades, published = _order(tmp_path)
    submit_delivery(
        trades, order.order_id, claimant=seller,
        delivery={"summary": "d" * 100_000},
        now_ms_override=published + 3_000,
    )
    record_verification(
        trades, order.order_id, verifier=buyer, verdict="pass",
        result={"report": "v" * 100_000},
        now_ms_override=published + 4_000,
    )
    before = trades.get_events(order.order_id)
    with pytest.raises(TradeRejected, match="320 KiB"):
        open_dispute(
            trades, order.order_id, disputant=buyer, reason="budget test",
            evidence={"blob": "e" * 140_000},
            now_ms_override=published + 5_000,
        )
    assert trades.get_events(order.order_id) == before

    path = trades._path(order.order_id)
    tampered = json.loads(path.read_text(encoding="utf-8"))
    tampered["events"][0]["payload"]["terms"]["amount_minor"] += 1
    path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(TradeRejected, match="stored trade failed verification"):
        open_dispute(trades, order.order_id, disputant=buyer, reason="must fail")
