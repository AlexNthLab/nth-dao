from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
import json

import pytest

from nth_dao.commerce.checkout import create_order_from_mandates
from nth_dao.commerce.listing import LISTING_SERVICE, SignedListing, listing_digest, sign_listing
from nth_dao.commerce.order import OrderStore
from nth_dao.commerce.order_trade import open_commerce_trade
from nth_dao.commerce.outbox import (
    OUTBOX_ERROR_DELIVERY_FAILED,
    OUTBOX_ERROR_DELIVERY_REJECTED,
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
from nth_dao.util.io import atomic_write_json, safe_load_json
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


@pytest.mark.parametrize(
    "target_url",
    [
        "https://token@peer.example",
        "https://user:password@peer.example",
        "ftp://peer.example",
        "javascript:alert(1)",
        "https://peer.example\n.evil.example",
        "https://peer .example",
        " https://peer.example",
        "https://",
        "https://peer.example/?api_key=must-not-persist",
        "https://peer.example/#fragment",
    ],
)
def test_outbox_rejects_credential_bearing_or_non_http_targets(
    tmp_path,
    target_url,
):
    source = AgentIdentity.generate(label="source")
    target = AgentIdentity.generate(label="target")
    envelope = sign_envelope(
        source,
        target_did=target.as_did(),
        payload={"order": {"id": "order-target-policy"}},
        created_at_ms=1_900_000_000_000,
    )
    outbox = CommerceOutbox(tmp_path)

    with pytest.raises(CommerceEnvelopeRejected, match="invalid target URL"):
        outbox.enqueue(envelope, target_url=target_url)

    assert not outbox._path(envelope.message_id).exists()


def test_outbox_rejects_oversized_record_before_json_decode(tmp_path):
    source = AgentIdentity.generate(label="source")
    target = AgentIdentity.generate(label="target")
    envelope = sign_envelope(
        source,
        target_did=target.as_did(),
        payload={"order": {"id": "order-oversized-record"}},
        created_at_ms=1_900_000_000_000,
    )
    outbox = CommerceOutbox(tmp_path)
    outbox.enqueue(envelope, target_url="https://seller.example")
    path = outbox._path(envelope.message_id)
    with path.open("wb") as handle:
        handle.write(b"{" + b"x" * (768 * 1024) + b"}")

    with pytest.raises(CommerceEnvelopeRejected, match="too large"):
        outbox.get(envelope.message_id)


def test_outbox_rejects_tampered_stored_target_credentials(tmp_path):
    source = AgentIdentity.generate(label="source")
    target = AgentIdentity.generate(label="target")
    envelope = sign_envelope(
        source,
        target_did=target.as_did(),
        payload={"order": {"id": "order-stored-target-policy"}},
        created_at_ms=1_900_000_000_000,
    )
    outbox = CommerceOutbox(tmp_path)
    outbox.enqueue(envelope, target_url="https://seller.example")
    path = outbox._path(envelope.message_id)
    value = json.loads(path.read_text(encoding="utf-8"))
    value["target_url"] = "https://secret@peer.example"
    atomic_write_json(path, value)

    with pytest.raises(CommerceEnvelopeRejected, match="invalid target URL"):
        outbox.get(envelope.message_id)


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


def test_outbox_persists_retry_schedule_and_supports_explicit_force(tmp_path):
    source = AgentIdentity.generate()
    target = AgentIdentity.generate()
    envelope = sign_envelope(
        source,
        target_did=target.as_did(),
        payload={"order": {"id": "order-retry-schedule"}},
        created_at_ms=1_900_000_000_000,
    )
    outbox = CommerceOutbox(tmp_path)
    outbox.enqueue(envelope, target_url="https://seller.example")
    claimed = outbox.claim(
        envelope.message_id,
        lease_ms=1_000,
        now_ms_override=1_900_000_001_000,
    )
    assert claimed is not None

    failed = outbox.record_attempt(
        envelope.message_id,
        error="peer offline",
        lease_id=claimed.lease_id,
        retry_after_ms=5_000,
        now_ms_override=1_900_000_001_100,
    )
    assert failed.last_attempt_at_ms == 1_900_000_001_100
    assert failed.next_attempt_at_ms == 1_900_000_006_100
    assert failed.last_error == OUTBOX_ERROR_DELIVERY_FAILED
    restarted = CommerceOutbox(tmp_path)
    assert restarted.claim(
        envelope.message_id,
        now_ms_override=1_900_000_006_099,
    ) is None
    forced = restarted.claim(
        envelope.message_id,
        now_ms_override=1_900_000_006_099,
        force=True,
    )
    assert forced is not None


def test_outbox_never_persists_raw_delivery_error_and_migrates_legacy_text(tmp_path):
    source = AgentIdentity.generate()
    target = AgentIdentity.generate()
    envelope = sign_envelope(
        source,
        target_did=target.as_did(),
        payload={"order": {"id": "secret-error"}},
        created_at_ms=1_900_000_000_000,
    )
    outbox = CommerceOutbox(tmp_path)
    outbox.enqueue(envelope, target_url="https://seller.example")
    claimed = outbox.claim(
        envelope.message_id,
        now_ms_override=1_900_000_001_000,
    )
    secret = "sensitive-provider-detail at /synthetic/redacted/location"
    failed = outbox.record_attempt(
        envelope.message_id,
        error=secret,
        lease_id=claimed.lease_id,
        now_ms_override=1_900_000_001_100,
    )
    record_path = next((tmp_path / "commerce" / "outbox").glob("*.json"))

    assert failed.last_error == OUTBOX_ERROR_DELIVERY_FAILED
    assert secret not in record_path.read_text(encoding="utf-8")

    legacy = json.loads(record_path.read_text(encoding="utf-8"))
    legacy["status"] = "blocked"
    legacy["blocked_at_ms"] = 1_900_000_001_200
    legacy["last_error"] = secret
    record_path.write_text(json.dumps(legacy), encoding="utf-8")

    loaded = outbox.get(envelope.message_id)
    assert loaded.last_error == OUTBOX_ERROR_DELIVERY_REJECTED
    assert secret not in record_path.read_text(encoding="utf-8")


def test_outbox_reads_records_created_before_retry_schedule_fields(tmp_path):
    source = AgentIdentity.generate()
    target = AgentIdentity.generate()
    envelope = sign_envelope(
        source,
        target_did=target.as_did(),
        payload={"order": {"id": "order-legacy-outbox"}},
        created_at_ms=1_900_000_000_000,
    )
    outbox = CommerceOutbox(tmp_path)
    outbox.enqueue(envelope, target_url="https://seller.example")
    path = outbox._path(envelope.message_id)
    stored = safe_load_json(path, fallback={})
    stored.pop("last_attempt_at_ms")
    stored.pop("next_attempt_at_ms")
    atomic_write_json(path, stored)

    loaded = CommerceOutbox(tmp_path).get(envelope.message_id)
    assert loaded is not None
    assert loaded.last_attempt_at_ms == 0
    assert loaded.next_attempt_at_ms == 0


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"lease_ms": 999}, "lease_ms"),
        ({"now_ms_override": -1}, "now_ms_override"),
        ({"force": "yes"}, "force"),
    ],
)
def test_claim_pending_rejects_bad_worker_config_even_when_empty(
    tmp_path, kwargs, message,
):
    with pytest.raises(CommerceEnvelopeRejected, match=message):
        CommerceOutbox(tmp_path).claim_pending(**kwargs)


def test_claim_pending_isolates_corrupt_record_and_claims_healthy_work(tmp_path):
    source = AgentIdentity.generate()
    target = AgentIdentity.generate()
    envelope = sign_envelope(
        source,
        target_did=target.as_did(),
        payload={"order": {"id": "order-after-corruption"}},
        created_at_ms=1_900_000_000_000,
    )
    outbox = CommerceOutbox(tmp_path)
    outbox.enqueue(envelope, target_url="https://seller.example")
    atomic_write_json(outbox.root / f"{'0' * 64}.json", {
        "envelope": {},
        "target_url": "https://broken.example",
        "status": "inflight",
        "attempts": 0,
        "last_error": "",
        "acknowledged_at_ms": 0,
        "last_attempt_at_ms": 0,
        "next_attempt_at_ms": 0,
        "lease_id": "broken",
        "lease_expires_at_ms": "not-an-integer",
    })

    pending = outbox.pending()
    assert len(pending) == 1
    assert pending[0].envelope["message_id"] == envelope.message_id
    claimed = outbox.claim_pending(now_ms_override=1_900_000_001_000)
    assert len(claimed) == 1
    assert claimed[0].envelope["message_id"] == envelope.message_id


def test_claim_pending_propagates_storage_failure(tmp_path, monkeypatch):
    source = AgentIdentity.generate()
    target = AgentIdentity.generate()
    envelope = sign_envelope(
        source,
        target_did=target.as_did(),
        payload={"order": {"id": "order-storage-failure"}},
        created_at_ms=1_900_000_000_000,
    )
    outbox = CommerceOutbox(tmp_path)
    outbox.enqueue(envelope, target_url="https://seller.example")

    def fail_claim(*_args, **_kwargs):
        raise OSError("simulated lock failure")

    monkeypatch.setattr(outbox, "claim", fail_claim)
    with pytest.raises(OSError, match="lock failure"):
        outbox.claim_pending()


def test_pending_scan_propagates_storage_failure(tmp_path, monkeypatch):
    source = AgentIdentity.generate()
    target = AgentIdentity.generate()
    envelope = sign_envelope(
        source,
        target_did=target.as_did(),
        payload={"order": {"id": "order-pending-read-failure"}},
        created_at_ms=1_900_000_000_000,
    )
    outbox = CommerceOutbox(tmp_path)
    outbox.enqueue(envelope, target_url="https://seller.example")

    def fail_read(_path):
        raise OSError("simulated outbox read failure")

    monkeypatch.setattr(outbox, "_load_record", fail_read)
    with pytest.raises(OSError, match="read failure"):
        outbox.pending()


@pytest.mark.parametrize("bad_timestamp", [True, -1, "1900000000000"])
def test_record_attempt_rejects_invalid_ack_timestamp(tmp_path, bad_timestamp):
    source = AgentIdentity.generate()
    target = AgentIdentity.generate()
    envelope = sign_envelope(
        source,
        target_did=target.as_did(),
        payload={"order": {"id": "order-invalid-ack-time"}},
        created_at_ms=1_900_000_000_000,
    )
    outbox = CommerceOutbox(tmp_path)
    outbox.enqueue(envelope, target_url="https://seller.example")

    with pytest.raises(CommerceEnvelopeRejected, match="acknowledged_at_ms"):
        outbox.record_attempt(
            envelope.message_id,
            acknowledged_at_ms=bad_timestamp,
        )
    assert outbox.get(envelope.message_id).status == "pending"


def test_permanent_failure_is_blocked_until_explicit_force(tmp_path):
    source = AgentIdentity.generate()
    target = AgentIdentity.generate()
    envelope = sign_envelope(
        source,
        target_did=target.as_did(),
        payload={"order": {"id": "order-permanent-rejection"}},
        created_at_ms=1_900_000_000_000,
    )
    outbox = CommerceOutbox(tmp_path)
    outbox.enqueue(envelope, target_url="https://seller.example")
    claimed = outbox.claim(
        envelope.message_id,
        now_ms_override=1_900_000_001_000,
    )
    assert claimed is not None
    blocked = outbox.record_attempt(
        envelope.message_id,
        error="target DID binding is invalid",
        lease_id=claimed.lease_id,
        retryable=False,
        now_ms_override=1_900_000_001_100,
    )

    assert blocked.status == "blocked"
    assert blocked.blocked_at_ms == 1_900_000_001_100
    assert outbox.pending() == []
    assert outbox.blocked() == [blocked]
    assert outbox.claim(
        envelope.message_id,
        now_ms_override=1_900_000_002_000,
    ) is None
    forced = outbox.claim(
        envelope.message_id,
        force=True,
        now_ms_override=1_900_000_002_000,
    )
    assert forced is not None
    assert forced.status == "inflight"
    assert forced.blocked_at_ms == 0


def test_pending_route_can_only_change_with_explicit_audited_retarget(tmp_path):
    source = AgentIdentity.generate()
    target = AgentIdentity.generate()
    envelope = sign_envelope(
        source,
        target_did=target.as_did(),
        payload={"order": {"id": "order-peer-migration"}},
        created_at_ms=1_900_000_000_000,
    )
    outbox = CommerceOutbox(tmp_path)
    outbox.enqueue(envelope, target_url="https://old.example")

    with pytest.raises(CommerceEnvelopeRejected, match="retarget authorization"):
        outbox.enqueue(envelope, target_url="https://new.example")

    moved = outbox.enqueue(
        envelope,
        target_url="https://new.example",
        allow_retarget=True,
        now_ms_override=1_900_000_001_000,
    )
    assert moved.target_url == "https://new.example"
    assert moved.status == "pending"
    assert moved.route_history == [{
        "target_did": target.as_did(),
        "previous_url": "https://old.example",
        "new_url": "https://new.example",
        "changed_at_ms": 1_900_000_001_000,
    }]

    claimed = outbox.claim(
        envelope.message_id,
        now_ms_override=1_900_000_002_000,
    )
    acknowledged = outbox.record_attempt(
        envelope.message_id,
        acknowledged_at_ms=1_900_000_002_100,
        lease_id=claimed.lease_id,
    )
    assert acknowledged.status == "acknowledged"
    with pytest.raises(CommerceEnvelopeRejected, match="acknowledged outbox work"):
        outbox.enqueue(
            envelope,
            target_url="https://third.example",
            allow_retarget=True,
        )


def test_acknowledged_retention_moves_records_to_audit_archive(tmp_path):
    source = AgentIdentity.generate()
    target = AgentIdentity.generate()
    envelope = sign_envelope(
        source,
        target_did=target.as_did(),
        payload={"order": {"id": "order-archive"}},
        created_at_ms=1_900_000_000_000,
    )
    outbox = CommerceOutbox(tmp_path)
    outbox.enqueue(envelope, target_url="https://seller.example")
    claimed = outbox.claim(
        envelope.message_id,
        now_ms_override=1_900_000_001_000,
    )
    outbox.record_attempt(
        envelope.message_id,
        acknowledged_at_ms=1_900_000_002_000,
        lease_id=claimed.lease_id,
    )

    assert outbox.archive_acknowledged(before_ms=1_900_000_002_000) == []
    archived = outbox.archive_acknowledged(before_ms=1_900_000_002_001)
    assert archived == [envelope.message_id]
    assert outbox.get(envelope.message_id).status == "acknowledged"
    assert not outbox._path(envelope.message_id).exists()
    archive_path = outbox.archive_root / f"{envelope.message_id[7:]}.json"
    assert archive_path.exists()
    stored = safe_load_json(archive_path, fallback={})
    assert stored["status"] == "acknowledged"
    assert stored["envelope"]["message_id"] == envelope.message_id
    replay = outbox.enqueue(envelope, target_url="https://seller.example")
    assert replay.status == "acknowledged"
    assert not outbox._path(envelope.message_id).exists()


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
