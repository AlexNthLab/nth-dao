import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from nth_dao.commerce import (
    CommerceReconciler,
    OrderStore,
    ProvisionalImportStore,
    ReconcilerConfig,
    TradeStore,
)
from nth_dao.commerce.outbox import CommerceOutbox
from nth_dao.util.io import atomic_write_json
from nth_dao.web import create_app


def _source_bundle(tmp_path):
    seller_app = create_app(tmp_path / "seller", require_console_auth=False)
    buyer_app = create_app(tmp_path / "buyer", require_console_auth=False)
    seller = TestClient(seller_app)
    buyer = TestClient(buyer_app)
    listing = seller.post("/api/v2/commerce/listings", json={
        "listing_id": "provisional-test",
        "title": "Provisional import test",
        "price_value": "1",
    }).json()
    intent = buyer.post("/api/v2/commerce/intents", json={
        "listing": listing["listing"],
        "purpose": "test crash recovery",
    }).json()["intent"]
    cart = seller.post("/api/v2/commerce/carts", json={
        "listing_digest": listing["digest"],
        "intent": intent,
    }).json()["cart"]
    order = buyer.post("/api/v2/commerce/orders", json={
        "listing": listing["listing"],
        "intent": intent,
        "cart": cart,
    }).json()["order"]
    state = buyer_app.state.nth
    return (
        state.commerce_orders.get(order["order_id"]),
        state.commerce_trades.get_events(order["order_id"]),
        state.node_identity.as_did(),
    )


def _leave_provisional(
    tmp_path,
    monkeypatch,
    *,
    created_at_ms=1_900_000_000_000,
):
    order, events, source_did = _source_bundle(tmp_path)
    root = tmp_path / "target"
    orders = OrderStore(root)
    trades = TradeStore(root)
    provisional = ProvisionalImportStore(root)
    monkeypatch.setattr(
        orders,
        "import_verified",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("fault after hidden trade commit")
        ),
    )
    with pytest.raises(OSError, match="hidden trade"):
        provisional.import_bundle(
            order=order,
            trade_events=events,
            message_id="sha256:" + "a" * 64,
            source_did=source_did,
            orders=orders,
            trades=trades,
            created_at_ms=created_at_ms,
        )
    monkeypatch.undo()
    return provisional, orders, trades, order, events


def test_young_provisional_trade_is_retained(tmp_path, monkeypatch):
    provisional, orders, trades, order, _events = _leave_provisional(
        tmp_path,
        monkeypatch,
    )

    result = provisional.reconcile(
        orders=orders,
        trades=trades,
        orphan_after_s=86_400,
        limit=10,
        now_ms_override=1_900_000_000_000 + 86_399_000,
    )

    assert result == {
        "scanned": 1,
        "completed": 0,
        "quarantined": 0,
        "retained": 1,
        "invalid": 0,
    }
    assert trades.get_events(order.order_id)


def test_old_provisional_trade_is_quarantined_with_audit(
    tmp_path,
    monkeypatch,
):
    provisional, orders, trades, order, _events = _leave_provisional(
        tmp_path,
        monkeypatch,
    )

    result = provisional.reconcile(
        orders=orders,
        trades=trades,
        orphan_after_s=86_400,
        limit=10,
        now_ms_override=1_900_000_000_000 + 86_400_001,
    )

    assert result["quarantined"] == 1
    assert trades.get_events(order.order_id) is None
    assert list((provisional.quarantine_root / "trades").glob("*.json"))
    assert list(
        (provisional.quarantine_root / "provisional_imports").glob("*.json")
    )
    audit = [
        json.loads(line)
        for line in provisional.audit_path.read_text(encoding="utf-8").splitlines()
    ]
    assert [row["type"] for row in audit] == [
        "commerce.provisional.orphan_quarantine_requested",
        "commerce.provisional.orphan_quarantined",
    ]
    assert all(row["order_id"] == order.order_id for row in audit)


def test_reconciler_never_touches_trade_without_provisional_marker(
    tmp_path,
):
    order, events, _source_did = _source_bundle(tmp_path)
    root = tmp_path / "target"
    orders = OrderStore(root)
    trades = TradeStore(root)
    provisional = ProvisionalImportStore(root)
    trades.import_verified_events(order.order_id, events)

    result = provisional.reconcile(
        orders=orders,
        trades=trades,
        orphan_after_s=86_400,
        limit=10,
        now_ms_override=2_000_000_000_000,
    )

    assert result["scanned"] == 0
    assert trades.get_events(order.order_id) == events


def test_mismatched_chain_head_quarantines_only_marker_once(
    tmp_path,
    monkeypatch,
):
    provisional, orders, trades, order, events = _leave_provisional(
        tmp_path,
        monkeypatch,
    )
    marker_path = provisional._path(order.order_id)
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["chain_head"] = "sha256:" + "f" * 64
    atomic_write_json(marker_path, marker)

    result = provisional.reconcile(
        orders=orders,
        trades=trades,
        orphan_after_s=86_400,
        limit=10,
        now_ms_override=2_000_000_000_000,
    )

    assert result["invalid"] == 1
    assert result["quarantined"] == 1
    assert trades.get_events(order.order_id) == events
    assert not marker_path.exists()
    assert list(
        (provisional.quarantine_root / "invalid_provisional_imports").glob(
            "*.json"
        )
    )
    audit = [
        json.loads(line)
        for line in provisional.audit_path.read_text(encoding="utf-8").splitlines()
    ]
    assert [row["type"] for row in audit] == [
        "commerce.provisional.validation_failed",
        "commerce.provisional.invalid_quarantined",
    ]

    again = provisional.reconcile(
        orders=orders,
        trades=trades,
        orphan_after_s=86_400,
        limit=10,
        now_ms_override=2_000_000_000_001,
    )
    assert again["scanned"] == 0


def test_visible_order_allows_stale_marker_cleanup(tmp_path, monkeypatch):
    order, events, source_did = _source_bundle(tmp_path)
    root = tmp_path / "target"
    orders = OrderStore(root)
    trades = TradeStore(root)
    provisional = ProvisionalImportStore(root)
    marker = provisional._path(order.order_id)
    original_unlink = Path.unlink

    def fail_marker_unlink(path, *args, **kwargs):
        if path == marker:
            raise OSError("marker cleanup fault")
        return original_unlink(path, *args, **kwargs)

    with monkeypatch.context() as context:
        context.setattr(Path, "unlink", fail_marker_unlink)
        with pytest.raises(OSError, match="marker cleanup"):
            provisional.import_bundle(
                order=order,
                trade_events=events,
                message_id="sha256:" + "b" * 64,
                source_did=source_did,
                orders=orders,
                trades=trades,
                created_at_ms=1_900_000_000_000,
            )

    assert orders.get(order.order_id) is not None
    assert marker.exists()
    result = provisional.reconcile(
        orders=orders,
        trades=trades,
        orphan_after_s=86_400,
        limit=10,
        now_ms_override=1_900_000_000_001,
    )
    assert result["completed"] == 1
    assert not marker.exists()
    assert trades.get_events(order.order_id)


def test_reconciler_reports_provisional_maintenance_counts(tmp_path):
    calls = []

    def maintenance(now_ms, limit):
        calls.append((now_ms, limit))
        return {"scanned": 3, "quarantined": 1}

    reconciler = CommerceReconciler(
        CommerceOutbox(tmp_path),
        lambda *_args: {},
        config=ReconcilerConfig(batch_limit=7),
        maintenance=maintenance,
    )

    assert reconciler.run_once(now_ms_override=1_900_000_000_000)["failed"] == 0
    assert calls == [(1_900_000_000_000, 7)]
    assert reconciler.status()["maintenance_total"] == 3
    assert reconciler.status()["quarantined_total"] == 1
