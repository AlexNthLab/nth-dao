from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from nth_dao.identity import AgentIdentity, crypto_available
from nth_dao.market.resource_profile import (
    ResourceProfileStore,
    resource_profile_body,
    sign_resource_profile,
)
from nth_dao.trade_rules.canonical import trade_canonical_json
from nth_dao.web import create_app


pytestmark = pytest.mark.skipif(
    not crypto_available(), reason="Trade Offer signatures require PyNaCl"
)


def _headers(app) -> dict[str, str]:
    return {"Authorization": f"Bearer {app.state.nth_console_token}"}


def _resource(
    leg_id: str,
    *,
    category: str,
    resource_type: str,
    resource_id: str,
    quantity: str = "1",
    unit: str = "item",
) -> dict:
    return {
        "leg_id": leg_id,
        "category": category,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "quantity": quantity,
        "unit": unit,
        "profile_rule_id": "org.nthdao.profiles/basic",
        "profile_digest": "sha256:" + ("a" * 64),
        "attributes": {"label": leg_id, "condition": "publisher-claimed"},
    }


def _body(*, key: str = "market-offer-key-0001", title: str = "Remote review") -> dict:
    return {
        "idempotency_key": key,
        "intent": "exchange",
        "category": "services",
        "title": title,
        "summary": "One review in exchange for test credits.",
        "provides": [
            _resource(
                "review",
                category="services",
                resource_type="service",
                resource_id="urn:nthdao:service:review",
                unit="job",
            )
        ],
        "requests": [
            _resource(
                "payment",
                category="digital-assets",
                resource_type="digital-asset",
                resource_id="urn:nthdao:asset:nth-test",
                quantity="2000000",
                unit="minor-unit",
            )
        ],
        "rule_refs": [],
        "capability_set": ["code-review"],
        "offer_validity_seconds": 30 * 24 * 60 * 60,
        "discovery_ttl_seconds": 3600,
    }


def test_market_offer_publish_requires_console_auth(tmp_path):
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)

    denied = client.post("/api/v2/market/offers", json=_body())
    accepted = client.post(
        "/api/v2/market/offers",
        json=_body(),
        headers=_headers(app),
    )

    assert denied.status_code == 401
    assert accepted.status_code == 200


def test_market_offer_publish_signs_profiles_announces_and_projects(tmp_path):
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app, headers=_headers(app))

    response = client.post("/api/v2/market/offers", json=_body())

    assert response.status_code == 200, response.text
    result = response.json()
    assert result["appended"] is True
    assert result["announcement_published"] is True
    assert result["digest"].startswith("sha256:")
    assert result["audit_event_id"]
    assert result["offer"]["publisher_did"] == app.state.nth.node_identity.as_did()
    assert result["offer"]["proof"]["proof_value"]
    assert result["announcement"]["offer_digest"] == result["digest"]
    assert result["announcement"]["availability_summary"]["market_category"] == "services"
    assert result["announcement"]["availability_summary"]["market_intent"] == "exchange"

    extension = result["offer"]["extensions"][
        "org.nthdao.market/resource-descriptors-v1"
    ]
    descriptors = extension["descriptors"]
    assert len(descriptors) == 2
    for digest, descriptor in descriptors.items():
        assert digest == "sha256:" + hashlib.sha256(
            trade_canonical_json(descriptor)
        ).hexdigest()
    assert result["offer"]["extensions"][
        "org.nthdao.market/publication-v1"
    ] == {
        "category": "services",
        "intent": "exchange",
        "capability_set": ["code-review"],
        "offer_validity_seconds": 30 * 24 * 60 * 60,
    }

    search = client.get("/api/v2/market/search", params={"category": "services"})
    assert search.status_code == 200
    entry = search.json()["items"][0]
    assert {item["category"]: item["count"] for item in search.json()["facets"]} == {
        "exchanges": 1,
        "services": 1,
    }
    assert entry["protocol_kind"] == "trade-offer-announcement"
    assert entry["category"] == "services"
    assert entry["market_intent"] == "exchange"
    assert entry["target"]["offer_digest"] == result["digest"]
    assert entry["claimable"] is False

    exchange_search = client.get(
        "/api/v2/market/search",
        params={"category": "exchanges"},
    )
    assert exchange_search.status_code == 200
    assert [
        item["target"]["offer_digest"]
        for item in exchange_search.json()["items"]
    ] == [result["digest"]]

    inspection = client.get(f"/api/v2/trade/offers/{result['digest']}")
    assert inspection.status_code == 200, inspection.text
    descriptor_view = inspection.json()["resource_descriptors"]
    assert descriptor_view["status"] == "verified-inline"
    assert descriptor_view["referenced_count"] == 2
    assert descriptor_view["verified_inline_count"] == 2
    assert descriptor_view["profile_packages_resolved"] is False
    assert descriptor_view["execution_ready"] is False
    assert all(
        item["content_hash_valid"] is True
        and item["profile_resolution"] == "missing-local"
        for item in descriptor_view["items"]
    )


def test_market_offer_publish_validates_cached_profile_before_signing(tmp_path):
    publisher = AgentIdentity.generate(label="profile-publisher")
    profile = sign_resource_profile(
        publisher,
        resource_profile_body(
            profile_id="org.nthdao.profiles/game-item",
            version="1.0.0",
            publisher_did=publisher.as_did(),
            summary="Game item attributes.",
            resource_types=["game/item"],
            category_mappings=[{
                "community_category": "gaming/items",
                "market_category": "products",
            }],
            schema={
                "type": "object",
                "properties": {
                    "game": {
                        "type": "string",
                        "required": True,
                        "description": "Game identifier.",
                        "enum": [],
                    },
                },
                "additional_properties": False,
            },
            published_at="2026-08-08T00:00:00Z",
            not_after="2027-08-08T00:00:00Z",
        ),
        created="2026-08-08T00:00:01Z",
    )
    ResourceProfileStore(tmp_path).install(profile)
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app, headers=_headers(app))
    body = _body(key="market-profile-validation-0001")
    body["provides"][0].update({
        "resource_type": "game/item",
        "profile_rule_id": profile.profile_id,
        "profile_digest": profile.digest,
        "attributes": {"display_reference": "invalid for this profile"},
    })

    rejected = client.post("/api/v2/market/offers", json=body)

    assert rejected.status_code == 400
    assert "profile attribute" in rejected.json()["detail"].lower()

    body["provides"][0]["attributes"] = {
        "game": "nth",
        "community_category": "gaming/items",
    }
    accepted = client.post("/api/v2/market/offers", json=body)
    assert accepted.status_code == 200, accepted.text


def test_market_offer_digital_asset_facet_is_searchable(tmp_path):
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app, headers=_headers(app))
    body = _body(key="market-offer-key-asset")
    body["category"] = "digital-assets"
    body["provides"][0].update(
        category="digital-assets",
        resource_type="digital-asset",
        resource_id="urn:nthdao:asset:example-token",
    )

    published = client.post("/api/v2/market/offers", json=body)
    search = client.get(
        "/api/v2/market/search",
        params={"category": "digital-assets"},
    )

    assert published.status_code == 200, published.text
    assert search.status_code == 200, search.text
    assert [item["target"]["offer_digest"] for item in search.json()["items"]] == [
        published.json()["digest"]
    ]


def test_market_offer_publish_is_idempotent_and_rejects_key_rebinding(tmp_path):
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app, headers=_headers(app))

    first = client.post("/api/v2/market/offers", json=_body())
    retry = client.post("/api/v2/market/offers", json=_body())
    conflict = client.post(
        "/api/v2/market/offers",
        json=_body(title="Different content"),
    )

    assert first.status_code == 200
    assert retry.status_code == 200
    assert retry.json()["digest"] == first.json()["digest"]
    assert retry.json()["appended"] is False
    assert retry.json()["announcement_published"] is False
    assert conflict.status_code == 409
    assert "already bound" in conflict.json()["detail"]
    assert len(app.state.nth.trade_offers.poll().records) == 1


def test_market_offer_retry_rejects_discovery_metadata_rebinding(tmp_path):
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app, headers=_headers(app))
    changed = _body()
    changed["capability_set"] = ["different-capability"]

    first = client.post("/api/v2/market/offers", json=_body())
    conflict = client.post("/api/v2/market/offers", json=changed)

    assert first.status_code == 200
    assert conflict.status_code == 409
    assert "different Offer content" in conflict.json()["detail"]
    assert len(app.state.nth.trade_offers.poll().records) == 1
    announcements = app.state.trade_offer_market_feed.poll(
        since_seq=-1,
        include_expired=True,
    ).announcements
    assert len(announcements) == 1
    assert announcements[0].capability_set == ["code-review"]


def test_market_offer_retry_rejects_validity_rebinding(tmp_path):
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app, headers=_headers(app))
    changed = _body()
    changed["offer_validity_seconds"] = 60 * 24 * 60 * 60

    first = client.post("/api/v2/market/offers", json=_body())
    conflict = client.post("/api/v2/market/offers", json=changed)

    assert first.status_code == 200
    assert conflict.status_code == 409
    assert "different Offer content" in conflict.json()["detail"]
    assert len(app.state.nth.trade_offers.poll().records) == 1


def test_market_offer_refreshes_expired_discovery_without_replacing_offer(
    tmp_path,
    monkeypatch,
):
    from nth_dao.market import announcement as announcement_module
    from nth_dao.market import trade_offer_announcement as binding_module
    from nth_dao.web import v2_api

    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app, headers=_headers(app))
    first = client.post("/api/v2/market/offers", json=_body())
    assert first.status_code == 200, first.text

    published_at = datetime.fromisoformat(
        first.json()["offer"]["published_at"].replace("Z", "+00:00")
    )
    future = published_at + timedelta(hours=2)

    class FutureDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return future if tz is not None else future.replace(tzinfo=None)

    monkeypatch.setattr(v2_api, "datetime", FutureDateTime)
    monkeypatch.setattr(binding_module, "datetime", FutureDateTime)
    monkeypatch.setattr(
        announcement_module,
        "now_ms",
        lambda: int(future.timestamp() * 1_000),
    )

    refreshed = client.post("/api/v2/market/offers", json=_body())

    assert refreshed.status_code == 200, refreshed.text
    assert refreshed.json()["digest"] == first.json()["digest"]
    assert refreshed.json()["appended"] is False
    assert refreshed.json()["announcement_published"] is True
    announcements = app.state.trade_offer_market_feed.poll(
        since_seq=-1,
        include_expired=True,
    ).announcements
    assert len(announcements) == 2


def test_market_offer_expired_retry_requires_new_idempotency_key(
    tmp_path,
    monkeypatch,
):
    from nth_dao.web import v2_api

    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app, headers=_headers(app))
    first = client.post("/api/v2/market/offers", json=_body())
    assert first.status_code == 200, first.text

    published_at = datetime.fromisoformat(
        first.json()["offer"]["published_at"].replace("Z", "+00:00")
    )
    future = published_at + timedelta(days=31)

    class FutureDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return future if tz is not None else future.replace(tzinfo=None)

    monkeypatch.setattr(v2_api, "datetime", FutureDateTime)
    expired = client.post("/api/v2/market/offers", json=_body())

    assert expired.status_code == 409
    detail = expired.json()["detail"]
    assert detail["code"] == "trade-offer-expired"
    assert detail["offer_digest"] == first.json()["digest"]
    assert detail["offer_persisted"] is True
    assert detail["retryable"] is False
    assert detail["new_idempotency_key_required"] is True


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda body: body.update(intent="provide"), "must not contain"),
        (lambda body: body.update(requests=[]), "requires at least one"),
        (
            lambda body: body["provides"][0].update(
                profile_digest="sha256:" + ("A" * 64)
            ),
            "lowercase sha256",
        ),
        (
            lambda body: body["provides"][0].update(
                resource_id="file:///private/key"
            ),
            "local file URI",
        ),
        (
            lambda body: body.update(capability_set=["x" * 101]),
            "must not exceed 100",
        ),
        (
            lambda body: body["provides"][0]["attributes"].update(
                display_reference=(
                    r"C:" + r"\Users\LocalOperator\Desktop\private.txt"
                )
            ),
            "Windows user path",
        ),
        (
            lambda body: body.update(summary="credential ghp_" + ("A" * 24)),
            "GitHub token",
        ),
    ],
)
def test_market_offer_publish_rejects_invalid_protocol_material(
    tmp_path,
    mutate,
    message,
):
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app, headers=_headers(app))
    body = _body()
    mutate(body)

    response = client.post("/api/v2/market/offers", json=body)

    assert response.status_code in {400, 422}
    assert message in response.text
    assert app.state.nth.trade_offers.poll().records == ()


def test_market_offer_publish_is_exactly_once_under_concurrent_retry(tmp_path):
    app = create_app(tmp_path, require_console_auth=False)

    def publish() -> tuple[int, dict]:
        with TestClient(app, headers=_headers(app)) as client:
            response = client.post("/api/v2/market/offers", json=_body())
            return response.status_code, response.json()

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: publish(), range(4)))

    assert {status for status, _ in results} == {200}
    assert len({body["digest"] for _, body in results}) == 1
    assert sum(body["appended"] is True for _, body in results) == 1
    assert len(app.state.nth.trade_offers.poll().records) == 1


def test_market_offer_publish_reports_durable_partial_and_retries_discovery(
    tmp_path,
    monkeypatch,
):
    from nth_dao.web import v2_api

    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app, headers=_headers(app))
    original = v2_api._ensure_local_trade_offer_announcement

    def fail_discovery(*args, **kwargs):
        raise RuntimeError("feed unavailable")

    monkeypatch.setattr(v2_api, "_ensure_local_trade_offer_announcement", fail_discovery)
    partial = client.post("/api/v2/market/offers", json=_body())

    assert partial.status_code == 503
    detail = partial.json()["detail"]
    assert detail["code"] == "trade-offer-discovery-incomplete"
    assert detail["offer_persisted"] is True
    assert detail["retryable"] is True
    assert app.state.nth.trade_offers.get(detail["offer_digest"]) is not None

    monkeypatch.setattr(v2_api, "_ensure_local_trade_offer_announcement", original)
    completed = client.post("/api/v2/market/offers", json=_body())
    assert completed.status_code == 200
    assert completed.json()["digest"] == detail["offer_digest"]
    assert completed.json()["appended"] is False
    assert completed.json()["announcement_published"] is True


def test_market_offer_publish_reports_audit_partial_before_discovery(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app, headers=_headers(app))
    spine = app.state.nth.spine
    original_append = spine.append

    def fail_audit(*args, **kwargs):
        raise OSError("spine unavailable")

    monkeypatch.setattr(spine, "append", fail_audit)
    partial = client.post("/api/v2/market/offers", json=_body())

    assert partial.status_code == 503
    detail = partial.json()["detail"]
    assert detail == {
        "code": "trade-offer-audit-incomplete",
        "message": "signed spine append failed",
        "offer_digest": detail["offer_digest"],
        "offer_persisted": True,
        "announcement_published": False,
        "retryable": True,
    }
    assert app.state.nth.trade_offers.get(detail["offer_digest"]) is not None
    assert not (tmp_path / "market_feed" / "announcements.jsonl").exists()

    monkeypatch.setattr(spine, "append", original_append)
    completed = client.post("/api/v2/market/offers", json=_body())

    assert completed.status_code == 200, completed.text
    assert completed.json()["digest"] == detail["offer_digest"]
    assert completed.json()["appended"] is False
    assert completed.json()["audit_event_id"]
    assert completed.json()["announcement_published"] is True
