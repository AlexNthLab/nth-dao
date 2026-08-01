from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import time
from urllib.parse import urlsplit

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from nth_dao.identity import AgentIdentity, crypto_available
from nth_dao.market import MarketFeed, create_trade_offer_announcement
from nth_dao.market.federation import FeedDigest, verify_digest
from nth_dao.trade_rules import offer_body, offer_digest, sign_offer
from nth_dao.web import create_app
from nth_dao.web.market_federation_poll import (
    FederationCache,
    federate_once,
)
from nth_dao.web.rate_limit import RateLimiter

pytestmark = pytest.mark.skipif(
    not crypto_available(),
    reason="Trade Offer federation requires PyNaCl",
)


def _offer(identity: AgentIdentity, *, offer_id: str = "org.nthdao.tests/swap"):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    published_at = now - timedelta(minutes=1)
    proof_created = published_at + timedelta(seconds=1)
    not_after = now + timedelta(days=1)

    def timestamp(value: datetime) -> str:
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")

    return sign_offer(
        identity,
        offer_body(
            offer_id=offer_id,
            publisher_did=identity.as_did(),
            title="Compute for design",
            summary="Exchange one compute task for one design review.",
            provides=[
                {
                    "leg_id": "compute",
                    "resource_type": "service:compute",
                    "resource_id": "urn:nth:test:compute",
                    "quantity": "1",
                    "unit": "task",
                    "descriptor_digest": "sha256:" + ("a" * 64),
                }
            ],
            requests=[
                {
                    "leg_id": "review",
                    "resource_type": "service:design-review",
                    "resource_id": "urn:nth:test:design-review",
                    "quantity": "1",
                    "unit": "review",
                    "descriptor_digest": "sha256:" + ("b" * 64),
                }
            ],
            published_at=timestamp(published_at),
            not_after=timestamp(not_after),
        ),
        created=timestamp(proof_created),
    )


def _withdrawn_successor(identity: AgentIdentity, previous):
    document = previous.to_dict()
    document.pop("proof")
    successor_published = datetime.fromisoformat(
        document["published_at"].replace("Z", "+00:00")
    ) + timedelta(minutes=1)
    proof_created = successor_published + timedelta(seconds=1)
    document.update({
        "revision": document["revision"] + 1,
        "previous_offer_digest": offer_digest(previous),
        "state": "withdrawn",
        "published_at": successor_published.strftime("%Y-%m-%dT%H:%M:%SZ"),
    })
    return sign_offer(
        identity,
        document,
        created=proof_created.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


def _http_get_via(client: TestClient):
    def get(url: str):
        parsed = urlsplit(url)
        path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        response = client.get(path)
        if response.status_code >= 400:
            raise ValueError(f"peer returned HTTP {response.status_code}")
        return response.json()

    return get


def test_trade_offer_announce_is_idempotent_and_public_by_digest(
    tmp_path: Path,
) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)
    offer = _offer(app.state.nth.node_identity)
    digest = offer_digest(offer)

    assert client.post("/api/v2/trade/offers", json=offer.to_dict()).status_code == 200
    assert client.get(
        f"/api/v2/trade/federation/offers/{digest}"
    ).status_code == 404

    first = client.post(
        f"/api/v2/trade/offers/{digest}/announce",
        json={
            "capability_set": ["compute", "design-review"],
            "availability_summary": {"status": "publisher-asserted-available"},
        },
    )
    retried = client.post(
        f"/api/v2/trade/offers/{digest}/announce",
        json={},
    )

    assert first.status_code == 200
    assert first.json()["published"] is True
    assert retried.status_code == 200
    assert retried.json()["published"] is False
    assert (
        retried.json()["announcement"]["announcement_id"]
        == first.json()["announcement"]["announcement_id"]
    )
    fetched = client.get(f"/api/v2/trade/federation/offers/{digest}")
    assert fetched.status_code == 200
    assert fetched.json() == offer.to_dict()

    rows = client.get(
        "/api/v2/market/open", params={"listing_type": "exchange"}
    ).json()
    assert len(rows) == 1
    assert rows[0]["offer_digest"] == digest
    assert rows[0]["claimable"] is False
    digest_page = FeedDigest.from_dict(
        client.get("/api/v2/market/federation/digest").json()
    )
    assert verify_digest(digest_page) == (True, "")
    assert digest_page.refs[0]["listing_type"] == "exchange"


def test_public_offer_reads_reuse_verified_feed_index(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)
    offer = _offer(app.state.nth.node_identity)
    digest = offer_digest(offer)
    assert client.post(
        "/api/v2/trade/offers", json=offer.to_dict()
    ).status_code == 200
    assert client.post(
        f"/api/v2/trade/offers/{digest}/announce", json={}
    ).status_code == 200

    feed = app.state.trade_offer_market_feed
    original_read_all = feed._read_all
    scans = 0

    def counted_read_all():
        nonlocal scans
        scans += 1
        return original_read_all()

    monkeypatch.setattr(feed, "_read_all", counted_read_all)
    feed._trade_index_fingerprint = None

    assert client.get(
        f"/api/v2/trade/federation/offers/{digest}"
    ).status_code == 200
    assert client.get(
        f"/api/v2/trade/federation/offers/{digest}"
    ).status_code == 200
    assert scans == 1


def test_public_offer_reads_are_rate_limited(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    app.state.trade_offer_fed_read_limiter = RateLimiter(
        max_per_window=1,
        window_seconds=60.0,
    )
    app.state.trade_offer_fed_read_global_limiter = RateLimiter(
        max_per_window=10,
        window_seconds=60.0,
    )
    client = TestClient(app)
    offer = _offer(app.state.nth.node_identity)
    digest = offer_digest(offer)
    assert client.post(
        "/api/v2/trade/offers", json=offer.to_dict()
    ).status_code == 200
    assert client.post(
        f"/api/v2/trade/offers/{digest}/announce", json={}
    ).status_code == 200

    assert client.get(
        f"/api/v2/trade/federation/offers/{digest}"
    ).status_code == 200
    denied = client.get(f"/api/v2/trade/federation/offers/{digest}")
    assert denied.status_code == 429
    assert int(denied.headers["retry-after"]) >= 1


def test_source_rate_limit_rejects_before_persistent_global_gate(
    tmp_path: Path,
) -> None:
    class CountingGlobal:
        calls = 0

        def check(self, _key: str):
            self.calls += 1
            return type(
                "Decision",
                (),
                {"allowed": True, "retry_after_seconds": 0.0},
            )()

    app = create_app(tmp_path, require_console_auth=False)
    app.state.trade_offer_fed_read_limiter = RateLimiter(
        max_per_window=1,
        window_seconds=60.0,
    )
    global_gate = CountingGlobal()
    app.state.trade_offer_fed_read_global_limiter = global_gate
    client = TestClient(app)
    digest = "sha256:" + ("a" * 64)

    # Spend the process-local source budget without reaching a valid Offer.
    first = client.get(f"/api/v2/trade/federation/offers/{digest}")
    assert first.status_code == 404
    denied = client.get(f"/api/v2/trade/federation/offers/{digest}")
    assert denied.status_code == 429
    assert global_gate.calls == 1


def test_expired_discovery_hint_is_replaced_while_offer_remains_active(
    tmp_path: Path,
) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)
    offer = _offer(app.state.nth.node_identity)
    digest = offer_digest(offer)
    assert client.post(
        "/api/v2/trade/offers", json=offer.to_dict()
    ).status_code == 200

    now = int(time.time() * 1_000)
    expired = create_trade_offer_announcement(
        app.state.nth.node_identity,
        offer,
        published_at_ms=now - 10_000,
        not_after_ms=now - 5_000,
    )
    MarketFeed(tmp_path).publish(expired)
    assert client.get(
        f"/api/v2/trade/federation/offers/{digest}"
    ).status_code == 404

    renewed = client.post(
        f"/api/v2/trade/offers/{digest}/announce", json={}
    )
    assert renewed.status_code == 200
    assert renewed.json()["published"] is True
    assert (
        renewed.json()["announcement"]["announcement_id"]
        != expired.announcement_id
    )
    assert client.get(
        f"/api/v2/trade/federation/offers/{digest}"
    ).status_code == 200


def test_node_cannot_announce_another_publishers_trade_offer(
    tmp_path: Path,
) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)
    foreign_offer = _offer(AgentIdentity.generate(label="foreign"))
    digest = offer_digest(foreign_offer)
    assert client.post(
        "/api/v2/trade/offers", json=foreign_offer.to_dict()
    ).status_code == 200

    response = client.post(
        f"/api/v2/trade/offers/{digest}/announce", json={}
    )

    assert response.status_code == 403
    assert client.get(
        f"/api/v2/trade/federation/offers/{digest}"
    ).status_code == 404


def test_withdrawal_removes_public_offer_and_old_revision_cannot_reannounce(
    tmp_path: Path,
) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)
    offer = _offer(app.state.nth.node_identity)
    digest = offer_digest(offer)
    assert client.post(
        "/api/v2/trade/offers", json=offer.to_dict()
    ).status_code == 200
    assert client.post(
        f"/api/v2/trade/offers/{digest}/announce", json={}
    ).status_code == 200

    withdrawn = _withdrawn_successor(app.state.nth.node_identity, offer)
    assert client.post(
        "/api/v2/trade/offers", json=withdrawn.to_dict()
    ).status_code == 200

    assert client.get(
        f"/api/v2/trade/federation/offers/{digest}"
    ).status_code == 404
    retried = client.post(
        f"/api/v2/trade/offers/{digest}/announce", json={}
    )
    assert retried.status_code == 409
    assert "canonical chain head" in retried.json()["detail"]


def test_generic_market_endpoint_cannot_forge_exchange_listing(
    tmp_path: Path,
) -> None:
    client = TestClient(create_app(tmp_path, require_console_auth=False))

    response = client.post(
        "/api/v2/market/announce",
        json={"title": "Not a signed offer", "listing_type": "exchange"},
    )

    assert response.status_code == 400
    assert "signed Trade Offer" in response.json()["detail"]


def test_trade_offer_announce_requires_console_auth(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=True)
    client = TestClient(app)
    offer = _offer(app.state.nth.node_identity)
    digest = offer_digest(offer)
    authorization = {
        "Authorization": f"Bearer {app.state.nth_console_token}",
    }
    assert client.post(
        "/api/v2/trade/offers",
        json=offer.to_dict(),
        headers=authorization,
    ).status_code == 200
    assert client.get(
        f"/api/v2/trade/federation/offers/{digest}"
    ).status_code == 404
    assert client.get(f"/api/v2/trade/offers/{digest}").status_code == 401

    denied = client.post(
        f"/api/v2/trade/offers/{digest}/announce", json={}
    )
    allowed = client.post(
        f"/api/v2/trade/offers/{digest}/announce",
        json={},
        headers=authorization,
    )

    assert denied.status_code == 401
    assert allowed.status_code == 200
    public = client.get(f"/api/v2/trade/federation/offers/{digest}")
    assert public.status_code == 200
    assert public.json() == offer.to_dict()


def test_trade_offer_is_discovered_and_reverified_across_nodes(
    tmp_path: Path,
) -> None:
    source_app = create_app(tmp_path / "source", require_console_auth=False)
    source = TestClient(source_app)
    offer = _offer(source_app.state.nth.node_identity)
    digest = offer_digest(offer)
    assert source.post(
        "/api/v2/trade/offers", json=offer.to_dict()
    ).status_code == 200
    announced = source.post(
        f"/api/v2/trade/offers/{digest}/announce", json={}
    )
    announcement_id = announced.json()["announcement"]["announcement_id"]

    entries = federate_once(
        ["https://source.example"],
        _http_get_via(source),
        verify_seed_peer=lambda _url: source_app.state.nth.node_identity.as_did(),
    )
    assert any(
        entry["ann"].announcement_id == announcement_id
        for entry in entries.values()
    )

    target_app = create_app(tmp_path / "target", require_console_auth=False)
    cache = FederationCache()
    cache.replace_all(entries)
    target_app.state.market_fed_cache = cache
    target = TestClient(target_app)
    rows = target.get(
        "/api/v2/market/open", params={"listing_type": "exchange"}
    ).json()

    assert len(rows) == 1
    assert rows[0]["federated"] is True
    assert rows[0]["offer_digest"] == digest
    assert rows[0]["claimable"] is False
