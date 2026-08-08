from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from nth_dao.commerce.listing import ListingStore, SignedListing, sign_listing
from nth_dao.commerce.listing_announcement import publish_listing_announcement
from nth_dao.execution_receipt import now_ms
from nth_dao.identity import crypto_available
from nth_dao.market.announcement import sign_announcement
from nth_dao.market.feed import MarketFeed
from nth_dao.web import create_app


pytestmark = pytest.mark.skipif(
    not crypto_available(),
    reason="Market search projection tests require PyNaCl",
)


def _publish_commerce_service(app, root: Path) -> None:
    identity = app.state.nth.node_identity
    published_at = now_ms()
    listing = sign_listing(
        identity,
        SignedListing(
            listing_id="service:verified-review",
            listing_type="service",
            seller_did=identity.as_did(),
            title="Verified review service",
            description="One signed code review listing.",
            price_value="25",
            price_currency="USDC",
            settlement_methods=["test:none"],
            published_at_ms=published_at,
            not_after_ms=published_at + 3_600_000,
        ),
    )
    publish_listing_announcement(
        ListingStore(root),
        MarketFeed(root),
        seller=identity,
        listing=listing,
        capability_set=["code_review"],
        availability_summary={"status": "publisher-asserted-available"},
    )


def test_market_search_preserves_protocol_boundaries(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)

    task_response = client.post(
        "/api/v2/market/announce",
        json={
            "title": "Debug the worker",
            "listing_type": "task",
            "reward_minor": 50,
            "reward_asset": "credit",
        },
    )
    rejected_legacy_write = client.post(
        "/api/v2/market/announce",
        json={"title": "Legacy design service", "listing_type": "service"},
    )
    legacy = sign_announcement(
        publisher=app.state.nth.node_identity,
        title="Legacy design service",
        input_schema={"__nth_listing_type": "service"},
        reward_minor=20,
        reward_asset="credit",
    )
    MarketFeed(tmp_path).publish(legacy)
    assert task_response.status_code == 200, task_response.text
    assert rejected_legacy_write.status_code == 400
    _publish_commerce_service(app, tmp_path)

    response = client.get("/api/v2/market/search")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["projection_only"] is True
    assert payload["count"] == 3
    assert payload["truncated"] is False
    assert {row["category"]: row["count"] for row in payload["facets"]} == {
        "services": 2,
        "tasks": 1,
    }

    by_title = {row["title"]: row for row in payload["items"]}
    task = by_title["Debug the worker"]
    assert task["entry_kind"] == "task"
    assert task["protocol_kind"] == "task-announcement"
    assert task["market_intent"] == "request"
    assert task["category"] == "tasks"
    assert task["claimable"] is True
    assert task["legacy"] is False
    assert task["value"] == {
        "kind": "reward",
        "amount_minor": 50,
        "asset": "credit",
    }
    assert task["target"]["announcement_id"]
    assert task["target"]["federation_key"] == task["entry_id"]
    assert task["target"]["offer_digest"] == ""

    legacy = by_title["Legacy design service"]
    assert legacy["entry_kind"] == "task"
    assert legacy["market_intent"] == "request"
    assert legacy["category"] == "services"
    assert legacy["claimable"] is True
    assert legacy["legacy"] is True
    assert "not a signed Trade Offer" in legacy["warning"]

    offer = by_title["Verified review service"]
    assert offer["entry_kind"] == "offer"
    assert offer["protocol_kind"] == "commerce-listing-announcement"
    assert offer["market_intent"] == "provide"
    assert offer["category"] == "services"
    assert offer["claimable"] is False
    assert offer["legacy"] is False
    assert offer["value"] == {
        "kind": "price",
        "amount_minor": 25_000_000,
        "asset": "USDC",
    }
    assert offer["target"]["offer_digest"].startswith("sha256:")

    task_categories = client.get(
        "/api/v2/market/categories",
        params={"listing_type": "task"},
    )
    assert task_categories.status_code == 200
    assert task_categories.json() == [{"context": "general", "count": 1}]
    assert client.get(
        "/api/v2/market/categories",
        params={"listing_type": "unknown"},
    ).status_code == 400


def test_market_search_filters_and_bounds_results(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)
    assert client.post(
        "/api/v2/market/announce",
        json={"title": "Repair Python service", "reward_minor": 10},
    ).status_code == 200
    assert client.post(
        "/api/v2/market/announce",
        json={"title": "Document Rust service", "reward_minor": 30},
    ).status_code == 200

    filtered = client.get(
        "/api/v2/market/search",
        params={
            "q": "service",
            "category": "tasks",
            "intent": "request",
            "min_value": 20,
            "value_asset": "credit",
            "limit": 1,
        },
    )
    assert filtered.status_code == 200, filtered.text
    payload = filtered.json()
    assert payload["count"] == 1
    assert [row["title"] for row in payload["items"]] == [
        "Document Rust service"
    ]
    assert payload["offset"] == 0

    second_page = client.get(
        "/api/v2/market/search",
        params={"source": "local", "offset": 1, "limit": 1},
    )
    assert second_page.status_code == 200
    assert second_page.json()["count"] == 2
    assert second_page.json()["offset"] == 1
    assert len(second_page.json()["items"]) == 1
    assert second_page.json()["items"][0]["source"] == "local"
    assert second_page.json()["truncated"] is False

    federated_only = client.get(
        "/api/v2/market/search",
        params={"source": "federated"},
    )
    assert federated_only.status_code == 200
    assert federated_only.json()["count"] == 0
    assert federated_only.json()["items"] == []

    for params in (
        {"category": "cars"},
        {"intent": "purchase"},
        {"limit": 0},
        {"limit": 501},
        {"min_value": -1},
        {"min_value": 1},
        {"value_asset": "x" * 65},
        {"q": "x" * 201},
        {"source": "unknown"},
        {"offset": -1},
        {"offset": 10_001},
    ):
        assert client.get(
            "/api/v2/market/search", params=params
        ).status_code == 400


def test_empty_market_search_has_no_storage_side_effect(tmp_path: Path) -> None:
    client = TestClient(create_app(tmp_path, require_console_auth=False))
    response = client.get("/api/v2/market/search")
    assert response.status_code == 200
    assert response.json()["items"] == []
    assert not (tmp_path / "market_feed").exists()
