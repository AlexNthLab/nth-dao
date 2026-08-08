from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import multiprocessing
import threading
import time
from urllib.parse import urlsplit

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from nth_dao.identity import AgentIdentity, crypto_available
from nth_dao.market import (
    MarketFeed,
    TaskAnnouncement,
    VerifiedTradeOfferHeadProof,
    announcement_federation_key,
    build_trade_offer_head_proof,
    create_trade_offer_announcement,
    sign_announcement,
)
from nth_dao.market.federation import FeedDigest, verify_digest
from nth_dao.spine import SignedEventLog
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


def _exercise_store_spine_transaction_lock(
    workspace: str,
    counter_path: str,
    start_event,
    result_queue,
) -> None:
    """Spawn-safe worker proving the production transaction lock is global."""

    from nth_dao.util.io import InterProcessLock
    from nth_dao.web.v2_api import (
        _trade_offer_store_spine_transaction_lock_path,
    )

    if not start_event.wait(timeout=10):
        raise RuntimeError("transaction lock test did not start")
    lock_path = _trade_offer_store_spine_transaction_lock_path(Path(workspace))
    with InterProcessLock(lock_path, timeout=10):
        entered_ns = time.monotonic_ns()
        counter = Path(counter_path)
        current = int(counter.read_text(encoding="ascii"))
        time.sleep(0.2)
        counter.write_text(str(current + 1), encoding="ascii")
        exited_ns = time.monotonic_ns()
    result_queue.put((entered_ns, exited_ns))


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


def _active_successor(identity: AgentIdentity, previous):
    document = previous.to_dict()
    document.pop("proof")
    successor_published = datetime.fromisoformat(
        document["published_at"].replace("Z", "+00:00")
    ) + timedelta(seconds=30)
    proof_created = successor_published + timedelta(seconds=1)
    document.update({
        "revision": document["revision"] + 1,
        "previous_offer_digest": offer_digest(previous),
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


def _cached_remote_offer(
    root: Path,
) -> tuple[object, object, TestClient, object, str]:
    source_app = create_app(root / "source", require_console_auth=False)
    source = _authed_client(source_app)
    offer = _offer(source_app.state.nth.node_identity)
    digest = offer_digest(offer)
    assert source.post(
        "/api/v2/trade/offers", json=offer.to_dict()
    ).status_code == 200
    assert source.post(
        f"/api/v2/trade/offers/{digest}/announce", json={}
    ).status_code == 200
    entries = federate_once(
        ["https://source.example"],
        _http_get_via(source),
        verify_seed_peer=lambda _url: (
            source_app.state.nth.node_identity.as_did()
        ),
    )
    target_app = create_app(root / "target", require_console_auth=False)
    cache = FederationCache()
    cache.replace_all(entries)
    target_app.state.market_fed_cache = cache
    target = TestClient(target_app)
    return source_app, target_app, target, offer, digest


def _console_headers(app: object) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {app.state.nth_console_token}",
    }


def _authed_client(app: object) -> TestClient:
    return TestClient(app, headers=_console_headers(app))


def test_trade_offer_announce_is_idempotent_and_public_by_digest(
    tmp_path: Path,
) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = _authed_client(app)
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
    rebound = client.post(
        f"/api/v2/trade/offers/{digest}/announce",
        json={"capability_set": ["different"]},
    )

    assert first.status_code == 200
    assert first.json()["published"] is True
    assert retried.status_code == 200
    assert rebound.status_code == 409
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


def test_trade_offer_announce_rejects_store_record_without_spine_anchor(
    tmp_path: Path,
) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = _authed_client(app)
    identity = app.state.nth.node_identity
    offer = _offer(identity)
    digest = offer_digest(offer)
    app.state.nth.trade_offers.publish(
        offer,
        source_kind="local-operator",
        source_id=identity.as_did(),
    )

    response = client.post(
        f"/api/v2/trade/offers/{digest}/announce",
        json={},
    )

    assert response.status_code == 503
    assert "missing offer import anchor" in response.json()["detail"]


def test_public_exact_offer_rejects_store_record_without_spine_anchor(
    tmp_path: Path,
) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = _authed_client(app)
    identity = app.state.nth.node_identity
    offer = _offer(identity)
    digest = offer_digest(offer)
    app.state.nth.trade_offers.publish(
        offer,
        source_kind="local-operator",
        source_id=identity.as_did(),
    )
    feed = MarketFeed(
        tmp_path,
        spine=app.state.nth.spine,
        trade_offer_store=app.state.nth.trade_offers,
    )
    feed.publish(create_trade_offer_announcement(identity, offer))
    app.state.trade_offer_market_feed = feed

    response = client.get(f"/api/v2/trade/federation/offers/{digest}")

    assert response.status_code == 503
    assert "missing offer import anchor" in response.json()["detail"]


def test_public_offer_reads_reuse_verified_feed_index(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = _authed_client(app)
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
    client = _authed_client(app)
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
    client = _authed_client(app)
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
    client = _authed_client(app)
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
    client = _authed_client(app)
    foreign_offer = _offer(AgentIdentity.generate(label="foreign"))
    digest = offer_digest(foreign_offer)
    rejected = client.post(
        "/api/v2/trade/offers", json=foreign_offer.to_dict()
    )
    assert rejected.status_code == 403

    response = client.post(
        f"/api/v2/trade/offers/{digest}/announce", json={}
    )

    assert response.status_code == 404
    assert app.state.nth.trade_offers.poll(-1).records == ()
    assert client.get(
        f"/api/v2/trade/federation/offers/{digest}"
    ).status_code == 404


def test_withdrawal_removes_public_offer_and_old_revision_cannot_reannounce(
    tmp_path: Path,
) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = _authed_client(app)
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


def test_trade_offer_head_proof_serves_only_live_canonical_head(
    tmp_path: Path,
) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = _authed_client(app)
    first = _offer(app.state.nth.node_identity)
    second = _active_successor(app.state.nth.node_identity, first)
    first_digest = offer_digest(first)
    second_digest = offer_digest(second)
    assert client.post(
        "/api/v2/trade/offers", json=first.to_dict()
    ).status_code == 200
    assert client.post(
        "/api/v2/trade/offers", json=second.to_dict()
    ).status_code == 200
    assert client.post(
        f"/api/v2/trade/offers/{second_digest}/announce", json={}
    ).status_code == 200

    response = client.get(
        f"/api/v2/trade/federation/offers/{second_digest}/head-proof"
    )

    assert response.status_code == 200
    proof = VerifiedTradeOfferHeadProof.from_dict(response.json())
    assert tuple(offer_digest(item) for item in proof.offers) == (
        first_digest,
        second_digest,
    )
    assert client.get(
        f"/api/v2/trade/federation/offers/{first_digest}/head-proof"
    ).status_code == 404


def test_trade_offer_announce_requires_route_auth_when_global_auth_is_off(
    tmp_path: Path,
) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    authorized = _authed_client(app)
    unauthenticated = TestClient(app)
    offer = _offer(app.state.nth.node_identity)
    digest = offer_digest(offer)
    assert authorized.post(
        "/api/v2/trade/offers",
        json=offer.to_dict(),
    ).status_code == 200

    denied = unauthenticated.post(
        f"/api/v2/trade/offers/{digest}/announce",
        json={},
    )

    assert denied.status_code == 401
    assert unauthenticated.get(
        f"/api/v2/trade/federation/offers/{digest}"
    ).status_code == 404


def test_trade_offer_is_discovered_and_reverified_across_nodes(
    tmp_path: Path,
) -> None:
    source_app = create_app(tmp_path / "source", require_console_auth=False)
    source = _authed_client(source_app)
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
    remote_entry = next(
        entry
        for entry in entries.values()
        if entry["ann"].announcement_id == announcement_id
    )
    assert remote_entry["trade_offer"].to_dict() == offer.to_dict()
    source_identity = source_app.state.nth.node_identity
    unrelated = sign_announcement(
        publisher=source_identity,
        authority_did=source_identity.as_did(),
        title="unrelated task",
    )
    entries["unrelated"] = {
        "ann": unrelated,
        "source": "https://source.example",
        "source_did": source_identity.as_did(),
    }

    target_app = create_app(tmp_path / "target", require_console_auth=False)
    cache = FederationCache()
    cache.replace_all(entries)
    cached_entry = next(
        entry for entry in cache.snapshot().values()
        if "trade_offer" in entry
    )
    assert cached_entry["trade_offer"].to_dict() == offer.to_dict()
    assert cached_entry["trade_offer"] is not remote_entry["trade_offer"]
    verified_at = cached_entry["last_verified_ms"]
    targeted = cache.trade_offer_snapshot(
        digest,
        now_ms_override=verified_at,
    )
    assert len(targeted) == 1
    assert targeted[0]["trade_offer"].to_dict() == offer.to_dict()
    checks = 0
    original_check = cache._entry_is_current

    def counted_check(entry, observed_at):
        nonlocal checks
        checks += 1
        return original_check(entry, observed_at)

    cache._entry_is_current = counted_check  # type: ignore[method-assign]
    assert cache.trade_offer_snapshot(
        digest,
        now_ms_override=verified_at,
    )
    assert checks == 1
    target_app.state.market_fed_cache = cache
    target = TestClient(target_app)
    rows = target.get(
        "/api/v2/market/open", params={"listing_type": "exchange"}
    ).json()

    assert len(rows) == 1
    assert rows[0]["federated"] is True
    assert rows[0]["offer_digest"] == digest
    assert rows[0]["claimable"] is False
    cache.snapshot = lambda: (_ for _ in ()).throw(  # type: ignore[method-assign]
        AssertionError("offer inspection must not snapshot the entire cache")
    )
    inspected = target.get(
        f"/api/v2/trade/federation/cached-offers/{digest}",
        headers={
            "Authorization": f"Bearer {target_app.state.nth_console_token}",
        },
    )
    assert inspected.status_code == 200
    detail = inspected.json()
    assert detail["offer"] == offer.to_dict()
    assert detail["digest"] == digest
    assert detail["authority"] == "remote-publisher"
    assert detail["storage_provenance"] is None
    assert detail["actionable"] is False
    assert detail["verification"] == {
        "offer_signature_valid": True,
        "announcement_binding_valid": True,
        "source_did_bound": True,
        "recent_source_verified": True,
        "head_chain_valid": True,
        "publisher_head_claim_valid": True,
    }
    assert detail["head_claim"] == {
        "publisher_claim_verified": True,
        "disclosed_chain_complete": True,
        "globally_latest_proven": False,
        "head_revision": 1,
        "chain_length": 1,
        "chain_digests": [digest],
        "claimed_at_ms": remote_entry["ann"].published_at_ms,
        "expires_at_ms": remote_entry["ann"].not_after,
    }
    assert detail["discoveries"][0]["source_peer"] == (
        "https://source.example"
    )


def test_federation_retains_verified_offer_head_revision_chain(
    tmp_path: Path,
) -> None:
    source_app = create_app(tmp_path / "source", require_console_auth=False)
    source = _authed_client(source_app)
    first = _offer(source_app.state.nth.node_identity)
    second = _active_successor(source_app.state.nth.node_identity, first)
    second_digest = offer_digest(second)
    for offer in (first, second):
        assert source.post(
            "/api/v2/trade/offers", json=offer.to_dict()
        ).status_code == 200
    assert source.post(
        f"/api/v2/trade/offers/{second_digest}/announce", json={}
    ).status_code == 200

    entries = federate_once(
        ["https://source.example"],
        _http_get_via(source),
        verify_seed_peer=lambda _url: (
            source_app.state.nth.node_identity.as_did()
        ),
    )

    assert len(entries) == 1
    entry = next(iter(entries.values()))
    proof = entry["trade_offer_head_proof"]
    assert isinstance(proof, VerifiedTradeOfferHeadProof)
    assert tuple(offer_digest(item) for item in proof.offers) == (
        offer_digest(first),
        second_digest,
    )
    cache = FederationCache()
    cache.replace_all(entries)
    cached = cache.trade_offer_snapshot(second_digest)
    assert len(cached) == 1
    assert tuple(
        offer_digest(item)
        for item in cached[0]["trade_offer_head_proof"].offers
    ) == (offer_digest(first), second_digest)
    target_app = create_app(tmp_path / "target", require_console_auth=False)
    target_app.state.market_fed_cache = cache
    inspected = TestClient(target_app).get(
        f"/api/v2/trade/federation/cached-offers/{second_digest}",
        headers=_console_headers(target_app),
    )
    assert inspected.status_code == 200
    assert inspected.json()["head_claim"]["chain_length"] == 2
    assert inspected.json()["head_claim"]["chain_digests"] == [
        offer_digest(first),
        second_digest,
    ]
    imported = TestClient(target_app).post(
        f"/api/v2/trade/federation/cached-offers/{second_digest}/import",
        headers=_console_headers(target_app),
    )
    assert imported.status_code == 200
    assert imported.json()["imported_revisions"] == 2
    assert {
        offer_digest(record.offer)
        for record in target_app.state.nth.trade_offers.poll(-1).records
    } == {offer_digest(first), second_digest}
    assert {
        event.payload["offer_digest"]
        for event in target_app.state.nth.spine.read_all()
        if event.type == "trade.offer.imported"
    } == {offer_digest(first), second_digest}


def test_federated_revision_chain_import_recovers_after_restart_without_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_app = create_app(tmp_path / "source", require_console_auth=False)
    source = _authed_client(source_app)
    first = _offer(source_app.state.nth.node_identity)
    second = _active_successor(source_app.state.nth.node_identity, first)
    first_digest = offer_digest(first)
    head_digest = offer_digest(second)
    for offer in (first, second):
        assert source.post(
            "/api/v2/trade/offers", json=offer.to_dict()
        ).status_code == 200
    assert source.post(
        f"/api/v2/trade/offers/{head_digest}/announce", json={}
    ).status_code == 200

    cache = FederationCache()
    cache.replace_all(
        federate_once(
            ["https://source.example"],
            _http_get_via(source),
            verify_seed_peer=lambda _url: (
                source_app.state.nth.node_identity.as_did()
            ),
        )
    )
    target_root = tmp_path / "target"
    target_app = create_app(target_root, require_console_auth=False)
    target_app.state.market_fed_cache = cache
    target = TestClient(target_app)
    path = f"/api/v2/trade/federation/cached-offers/{head_digest}/import"
    spine = target_app.state.nth.spine
    original_append = spine.append

    def fail_head_completion(event_type, payload, **kwargs):
        if (
            event_type == "trade.offer.imported"
            and payload.get("offer_digest") == head_digest
        ):
            raise OSError("simulated head completion outage")
        return original_append(event_type, payload, **kwargs)

    monkeypatch.setattr(spine, "append", fail_head_completion)
    failed = target.post(path, headers=_console_headers(target_app))
    assert failed.status_code == 503
    assert {
        offer_digest(record.offer)
        for record in target_app.state.nth.trade_offers.poll(-1).records
    } == {first_digest, head_digest}
    before_restart_anchors = [
        event
        for event in spine.read_all()
        if event.type == "trade.offer.imported"
    ]
    assert [event.payload["offer_digest"] for event in before_restart_anchors] == [
        first_digest
    ]

    restarted_app = create_app(target_root, require_console_auth=False)
    assert not hasattr(restarted_app.state, "market_fed_cache")
    restarted = TestClient(restarted_app)
    recovered = restarted.post(
        path,
        headers=_console_headers(restarted_app),
    )

    assert recovered.status_code == 200
    assert recovered.json()["imported_revisions"] == 2
    assert recovered.json()["appended_revisions"] == 0
    assert recovered.json()["audit_event_ids"][0] == (
        before_restart_anchors[0].event_id
    )
    recovered_anchors = [
        event
        for event in restarted_app.state.nth.spine.read_all()
        if event.type == "trade.offer.imported"
    ]
    assert [event.payload["offer_digest"] for event in recovered_anchors] == [
        first_digest,
        head_digest,
    ]
    assert restarted.get(
        f"/api/v2/trade/offers/{head_digest}"
    ).status_code == 200


def test_federation_cache_rejects_missing_mismatched_or_wrong_source_offer(
    tmp_path: Path,
) -> None:
    source_app = create_app(tmp_path / "source", require_console_auth=False)
    source = _authed_client(source_app)
    identity = source_app.state.nth.node_identity
    offer = _offer(identity)
    digest = offer_digest(offer)
    assert source.post(
        "/api/v2/trade/offers", json=offer.to_dict()
    ).status_code == 200
    assert source.post(
        f"/api/v2/trade/offers/{digest}/announce", json={}
    ).status_code == 200
    entries = federate_once(
        ["https://source.example"],
        _http_get_via(source),
        verify_seed_peer=lambda _url: identity.as_did(),
    )
    entry = next(iter(entries.values()))
    key = entry["federation_key"]

    missing = dict(entry)
    missing.pop("trade_offer_head_proof")
    with pytest.raises(TypeError, match="verified head proof"):
        FederationCache().replace_all({key: missing})

    other_identity = AgentIdentity.generate(label="different-publisher")
    other_offer = _offer(
        other_identity,
        offer_id="org.nthdao.tests/different-swap",
    )
    other_announcement = create_trade_offer_announcement(
        other_identity,
        other_offer,
    )
    mismatched = {
        **entry,
        "trade_offer_head_proof": VerifiedTradeOfferHeadProof.from_dict(
            {
                "kind": "nth-trade-offer-head-proof-v1",
                "announcement": other_announcement.to_dict(),
                "offers": [other_offer.to_dict()],
            }
        ),
    }
    with pytest.raises(ValueError, match="head claim mismatch"):
        FederationCache().replace_all({key: mismatched})

    redundant_head_tamper = {**entry, "trade_offer": other_offer}
    rebuilt = FederationCache()
    rebuilt.replace_all({key: redundant_head_tamper})
    assert rebuilt.trade_offer_snapshot(digest)[0][
        "trade_offer"
    ].canonical_bytes == offer.canonical_bytes

    wrong_source = {**entry, "source_did": AgentIdentity.generate().as_did()}
    with pytest.raises(ValueError, match="source DID mismatch"):
        FederationCache().replace_all({key: wrong_source})


@pytest.mark.parametrize("require_console_auth", [False, True])
def test_cached_remote_offer_inspection_always_requires_console_bearer(
    tmp_path: Path,
    require_console_auth: bool,
) -> None:
    source_app = create_app(tmp_path / "source", require_console_auth=False)
    source = _authed_client(source_app)
    offer = _offer(source_app.state.nth.node_identity)
    digest = offer_digest(offer)
    assert source.post(
        "/api/v2/trade/offers", json=offer.to_dict()
    ).status_code == 200
    assert source.post(
        f"/api/v2/trade/offers/{digest}/announce", json={}
    ).status_code == 200
    entries = federate_once(
        ["https://source.example"],
        _http_get_via(source),
        verify_seed_peer=lambda _url: source_app.state.nth.node_identity.as_did(),
    )

    target_app = create_app(
        tmp_path / "target",
        require_console_auth=require_console_auth,
    )
    cache = FederationCache()
    cache.replace_all(entries)
    target_app.state.market_fed_cache = cache
    target = TestClient(target_app)
    path = f"/api/v2/trade/federation/cached-offers/{digest}"

    assert target.get(path).status_code == 401
    allowed = target.get(path, headers={
        "Authorization": f"Bearer {target_app.state.nth_console_token}",
    })
    assert allowed.status_code == 200
    assert allowed.json()["offer"] == offer.to_dict()


def test_cached_remote_offer_inspection_fails_closed_on_cache_corruption(
    tmp_path: Path,
) -> None:
    class CorruptCache:
        def trade_offer_snapshot(self, _digest):
            raise ValueError("simulated cache corruption")

    app = create_app(tmp_path, require_console_auth=False)
    app.state.market_fed_cache = CorruptCache()
    client = TestClient(app)
    response = client.get(
        "/api/v2/trade/federation/cached-offers/sha256:" + ("a" * 64),
        headers={
            "Authorization": f"Bearer {app.state.nth_console_token}",
        },
    )
    assert response.status_code == 503
    assert response.json()["detail"] == (
        "federation cache integrity check failed"
    )


def test_cached_remote_offer_import_requires_console_and_anchors_provenance(
    tmp_path: Path,
) -> None:
    _, target_app, target, offer, digest = _cached_remote_offer(tmp_path)
    path = f"/api/v2/trade/federation/cached-offers/{digest}/import"

    assert target.post(path).status_code == 401
    imported = target.post(path, headers=_console_headers(target_app))

    assert imported.status_code == 200
    result = imported.json()
    assert result == {
        "digest": digest,
        "appended": True,
        "persisted": True,
        "classification": "canonical",
        "entry_hash": result["entry_hash"],
        "source_kind": "federation-cache",
        "source_id": target_app.state.nth.node_identity.as_did(),
        "audit_event_id": result["audit_event_id"],
        "audit_event_ids": [result["audit_event_id"]],
        "imported_revisions": 1,
        "appended_revisions": 1,
        "discovery_sources": 1,
        "trusted": False,
        "actionable": False,
        "warning": (
            "Saved locally as a signed claim. This does not accept the "
            "Offer, trust its publisher, reserve assets, or authorize execution."
        ),
    }
    records = target_app.state.nth.trade_offers.poll(-1).records
    assert len(records) == 1
    assert records[0].offer.to_dict() == offer.to_dict()
    assert records[0].source_kind == "federation-cache"
    assert records[0].source_id == target_app.state.nth.node_identity.as_did()
    anchors = [
        event for event in target_app.state.nth.spine.read_all()
        if event.type == "trade.offer.imported"
    ]
    assert len(anchors) == 1
    assert anchors[0].event_id == result["audit_event_id"]
    assert anchors[0].payload["source_kind"] == "federation-cache"
    assert anchors[0].payload["source_id"] == anchors[0].author_did
    assert anchors[0].author_did == target_app.state.nth.node_identity.as_did()
    discovery = anchors[0].payload["discovery"]
    assert discovery["announcement"]["offer_digest"] == digest
    assert discovery["federation_key"] == announcement_federation_key(
        TaskAnnouncement.from_dict(discovery["announcement"])
    )

    cached_again = target.get(
        f"/api/v2/trade/federation/cached-offers/{digest}",
        headers=_console_headers(target_app),
    )
    assert cached_again.status_code == 200
    assert cached_again.json()["storage_provenance"] == {
        "source_kind": "federation-cache",
        "source_id": target_app.state.nth.node_identity.as_did(),
    }

    target_app.state.market_fed_cache = FederationCache()
    local = target.get(f"/api/v2/trade/offers/{digest}")
    assert local.status_code == 200
    assert local.json()["offer"] == offer.to_dict()
    assert local.json()["authority"] == "remote-publisher"
    assert local.json()["storage_provenance"] == {
        "source_kind": "federation-cache",
        "source_id": target_app.state.nth.node_identity.as_did(),
    }


def test_cached_remote_offer_import_counts_distinct_verified_source_peers(
    tmp_path: Path,
) -> None:
    publisher = AgentIdentity.generate(label="publisher")
    offer = _offer(publisher)
    digest = offer_digest(offer)
    announcements = (
        create_trade_offer_announcement(
            publisher,
            offer,
            announcement_id="offer-observation-primary",
        ),
        create_trade_offer_announcement(
            publisher,
            offer,
            announcement_id="offer-observation-backup",
        ),
    )
    entries = {}
    for index, announcement in enumerate(announcements, start=1):
        proof = VerifiedTradeOfferHeadProof.from_dict(
            build_trade_offer_head_proof(announcement, [offer])
        )
        federation_key = announcement_federation_key(announcement)
        entries[federation_key] = {
            "ann": announcement,
            "source": f"https://source-{index}.example",
            "source_did": publisher.as_did(),
            "federation_key": federation_key,
            "trade_offer": offer,
            "trade_offer_head_proof": proof,
        }
    cache = FederationCache()
    cache.replace_all(entries)
    target_app = create_app(tmp_path / "target", require_console_auth=False)
    target_app.state.market_fed_cache = cache
    target = TestClient(target_app)
    inspected = target.get(
        f"/api/v2/trade/federation/cached-offers/{digest}",
        headers=_console_headers(target_app),
    )
    assert inspected.status_code == 200
    assert len(inspected.json()["discoveries"]) == 2
    response = target.post(
        f"/api/v2/trade/federation/cached-offers/{digest}/import",
        headers=_console_headers(target_app),
    )

    assert response.status_code == 200
    assert response.json()["discovery_sources"] == 2
    proposals = [
        event for event in target_app.state.nth.spine.read_all()
        if event.type == "trade.offer.import.proposed"
    ]
    assert len(proposals) == 1
    assert proposals[0].payload["discovery_sources"] == 2
    evidence_set = proposals[0].payload["discoveries"]
    assert len(evidence_set) == 2
    assert proposals[0].payload["discovery"] in evidence_set
    assert {
        (item["source_did"], item["source_peer"])
        for item in evidence_set
    } == {
        (publisher.as_did(), "https://source-1.example"),
        (publisher.as_did(), "https://source-2.example"),
    }


def test_local_offer_read_rejects_signed_discovery_source_count_without_evidence(
    tmp_path: Path,
) -> None:
    _, target_app, target, _, digest = _cached_remote_offer(tmp_path)
    imported = target.post(
        f"/api/v2/trade/federation/cached-offers/{digest}/import",
        headers=_console_headers(target_app),
    )
    assert imported.status_code == 200
    events = target_app.state.nth.spine.read_all()
    proposal = next(
        event for event in events
        if event.type == "trade.offer.import.proposed"
    )
    anchor = next(
        event for event in events if event.type == "trade.offer.imported"
    )
    proposal_payload = deepcopy(proposal.payload)
    proposal_payload["discovery_sources"] += 1

    replacement = SignedEventLog(
        tmp_path / "false-discovery-count.jsonl",
        target_app.state.nth.node_identity,
    )
    replacement_proposal = replacement.append(
        "trade.offer.import.proposed",
        proposal_payload,
    )
    anchor_payload = deepcopy(anchor.payload)
    anchor_payload["proposal_event_id"] = replacement_proposal.event_id
    replacement.append("trade.offer.imported", anchor_payload)
    target_app.state.nth.spine = replacement

    response = target.get(f"/api/v2/trade/offers/{digest}")

    assert response.status_code == 503
    assert "source count does not match its evidence" in response.json()["detail"]


def test_discovery_evidence_budget_rejects_excessive_nesting_without_crashing(
) -> None:
    from nth_dao.web.v2_api import (
        _verify_trade_offer_discovery_evidence_set,
    )

    nested: dict = {}
    cursor = nested
    for _ in range(1_100):
        child: dict = {}
        cursor["nested"] = child
        cursor = child

    ok, reason = _verify_trade_offer_discovery_evidence_set(
        [nested],
        nested,
        object(),
        imported_at_ms=1,
        expected_count=1,
    )

    assert ok is False
    assert reason == "federated discovery evidence set is not canonical JSON"


def test_cached_remote_offer_import_validates_digest_before_lock_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = create_app(tmp_path / "target", require_console_auth=False)
    client = TestClient(app)
    malformed = r"sha256:x\..\..\..\escaped"

    class UnexpectedLock:
        def __init__(self, _path: Path) -> None:
            raise AssertionError("invalid digest reached the filesystem lock")

    monkeypatch.setattr("nth_dao.util.io.InterProcessLock", UnexpectedLock)

    response = client.post(
        f"/api/v2/trade/federation/cached-offers/{malformed}/import",
        headers=_console_headers(app),
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "digest must be a lowercase sha256 digest"
    )
    assert not (tmp_path / "target" / "trade" / "escaped.lock").exists()


@pytest.mark.parametrize(
    "tamper",
    ["federation_key", "source_did", "announcement", "verified_at"],
)
def test_local_offer_read_rejects_signed_but_false_discovery_evidence(
    tmp_path: Path,
    tamper: str,
) -> None:
    _, target_app, target, _, digest = _cached_remote_offer(tmp_path)
    imported = target.post(
        f"/api/v2/trade/federation/cached-offers/{digest}/import",
        headers=_console_headers(target_app),
    )
    assert imported.status_code == 200
    anchor = next(
        event for event in target_app.state.nth.spine.read_all()
        if event.type == "trade.offer.imported"
    )
    proposal = next(
        event for event in target_app.state.nth.spine.read_all()
        if event.type == "trade.offer.import.proposed"
    )
    payload = deepcopy(anchor.payload)
    proposal_payload = deepcopy(proposal.payload)
    if tamper == "federation_key":
        proposal_payload["discovery"]["federation_key"] = (
            "nth-ann-sha256:" + ("0" * 64)
        )
    elif tamper == "source_did":
        proposal_payload["discovery"]["source_did"] = (
            AgentIdentity.generate().as_did()
        )
    elif tamper == "verified_at":
        proposal_payload["discovery"]["last_verified_ms"] = (1 << 63) - 1
    else:
        proposal_payload["discovery"]["announcement"]["title"] = (
            "tampered title"
        )

    replacement = SignedEventLog(
        tmp_path / f"false-evidence-{tamper}.jsonl",
        target_app.state.nth.node_identity,
    )
    replacement_proposal = replacement.append(
        "trade.offer.import.proposed",
        proposal_payload,
    )
    payload["discovery"] = deepcopy(proposal_payload["discovery"])
    payload["proposal_event_id"] = replacement_proposal.event_id
    replacement.append("trade.offer.imported", payload)
    target_app.state.nth.spine = replacement

    response = target.get(f"/api/v2/trade/offers/{digest}")

    assert response.status_code == 503
    assert "discovery evidence failure" in response.json()["detail"]


def test_cached_offer_recomputes_federation_key_before_import(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, target_app, target, _, digest = _cached_remote_offer(tmp_path)
    cache = target_app.state.market_fed_cache
    snapshot = cache.trade_offer_snapshot(digest)
    snapshot[0]["federation_key"] = "nth-ann-sha256:" + ("0" * 64)
    monkeypatch.setattr(cache, "trade_offer_snapshot", lambda _digest: snapshot)

    inspected = target.get(
        f"/api/v2/trade/federation/cached-offers/{digest}",
        headers=_console_headers(target_app),
    )
    imported = target.post(
        f"/api/v2/trade/federation/cached-offers/{digest}/import",
        headers=_console_headers(target_app),
    )

    assert inspected.status_code == 503
    assert imported.status_code == 503
    assert target_app.state.nth.trade_offers.latest_seq() == -1


def test_local_read_rejects_signed_proposal_with_different_offer(
    tmp_path: Path,
) -> None:
    _, target_app, target, _, digest = _cached_remote_offer(tmp_path)
    imported = target.post(
        f"/api/v2/trade/federation/cached-offers/{digest}/import",
        headers=_console_headers(target_app),
    )
    assert imported.status_code == 200
    events = list(target_app.state.nth.spine.read_all())
    proposal = next(
        event for event in events
        if event.type == "trade.offer.import.proposed"
    )
    anchor = next(
        event for event in events
        if event.type == "trade.offer.imported"
    )
    proposal_payload = deepcopy(proposal.payload)
    proposal_payload["offer"]["summary"] = "different signed claim"

    replacement = SignedEventLog(
        tmp_path / "proposal-offer-mismatch.jsonl",
        target_app.state.nth.node_identity,
    )
    replacement_proposal = replacement.append(
        "trade.offer.import.proposed",
        proposal_payload,
    )
    anchor_payload = deepcopy(anchor.payload)
    anchor_payload["proposal_event_id"] = replacement_proposal.event_id
    replacement.append("trade.offer.imported", anchor_payload)
    target_app.state.nth.spine = replacement

    response = target.get(f"/api/v2/trade/offers/{digest}")

    assert response.status_code == 503
    assert "proposal Offer" in response.json()["detail"]


def test_cached_remote_offer_import_is_idempotent_and_concurrent(
    tmp_path: Path,
) -> None:
    _, target_app, _, _, digest = _cached_remote_offer(tmp_path)
    path = f"/api/v2/trade/federation/cached-offers/{digest}/import"
    headers = _console_headers(target_app)
    clients = [TestClient(target_app) for _ in range(4)]

    with ThreadPoolExecutor(max_workers=4) as pool:
        responses = list(pool.map(
            lambda client: client.post(path, headers=headers),
            clients,
        ))

    assert [response.status_code for response in responses] == [200] * 4
    bodies = [response.json() for response in responses]
    assert sum(body["appended"] is True for body in bodies) == 1
    assert len({body["entry_hash"] for body in bodies}) == 1
    assert len({body["audit_event_id"] for body in bodies}) == 1
    assert len(target_app.state.nth.trade_offers.poll(-1).records) == 1
    anchors = [
        event for event in target_app.state.nth.spine.read_all()
        if event.type == "trade.offer.imported"
    ]
    assert len(anchors) == 1


def test_different_offer_imports_share_one_store_spine_transaction_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_app = create_app(tmp_path / "source", require_console_auth=False)
    source = _authed_client(source_app)
    identity = source_app.state.nth.node_identity
    offers = (
        _offer(identity, offer_id="org.nthdao.tests/swap-a"),
        _offer(identity, offer_id="org.nthdao.tests/swap-b"),
    )
    digests = tuple(offer_digest(offer) for offer in offers)
    for offer, digest in zip(offers, digests):
        assert source.post(
            "/api/v2/trade/offers", json=offer.to_dict()
        ).status_code == 200
        assert source.post(
            f"/api/v2/trade/offers/{digest}/announce", json={}
        ).status_code == 200
    cache = FederationCache()
    cache.replace_all(
        federate_once(
            ["https://source.example"],
            _http_get_via(source),
            verify_seed_peer=lambda _url: identity.as_did(),
        )
    )
    target_app = create_app(tmp_path / "target", require_console_auth=False)
    target_app.state.market_fed_cache = cache
    store = target_app.state.nth.trade_offers
    original_publish = store.publish
    state_lock = threading.Lock()
    active = 0
    overlapped = False

    def slow_publish(*args, **kwargs):
        nonlocal active, overlapped
        with state_lock:
            active += 1
            overlapped = overlapped or active > 1
        try:
            result = original_publish(*args, **kwargs)
            time.sleep(0.15)
            return result
        finally:
            with state_lock:
                active -= 1

    monkeypatch.setattr(store, "publish", slow_publish)
    headers = _console_headers(target_app)
    clients = [TestClient(target_app), TestClient(target_app)]
    paths = [
        f"/api/v2/trade/federation/cached-offers/{digest}/import"
        for digest in digests
    ]

    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(
            lambda item: item[0].post(item[1], headers=headers),
            zip(clients, paths),
        ))

    assert [response.status_code for response in responses] == [200, 200]
    assert overlapped is False
    assert len(store.poll(-1).records) == 2
    anchors = [
        event
        for event in target_app.state.nth.spine.read_all()
        if event.type == "trade.offer.imported"
    ]
    assert len(anchors) == 2


def test_store_spine_transaction_lock_serializes_spawned_processes(
    tmp_path: Path,
) -> None:
    context = multiprocessing.get_context("spawn")
    start_event = context.Event()
    result_queue = context.Queue()
    counter_path = tmp_path / "transaction-counter.txt"
    counter_path.write_text("0", encoding="ascii")
    processes = [
        context.Process(
            target=_exercise_store_spine_transaction_lock,
            args=(
                str(tmp_path),
                str(counter_path),
                start_event,
                result_queue,
            ),
        )
        for _ in range(2)
    ]
    for process in processes:
        process.start()
    start_event.set()
    for process in processes:
        process.join(timeout=20)
    try:
        assert [process.exitcode for process in processes] == [0, 0]
        intervals = sorted(result_queue.get(timeout=2) for _ in processes)
        assert intervals[0][1] <= intervals[1][0]
        assert counter_path.read_text(encoding="ascii") == "2"
    finally:
        for process in processes:
            if process.is_alive():
                process.kill()
                process.join(timeout=5)


def test_cached_remote_offer_import_recovers_after_restart_without_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, target_app, target, _, digest = _cached_remote_offer(tmp_path)
    path = f"/api/v2/trade/federation/cached-offers/{digest}/import"
    headers = _console_headers(target_app)
    spine = target_app.state.nth.spine
    original_append = spine.append

    def fail_completion(event_type, payload, **kwargs):
        if event_type == "trade.offer.imported":
            raise OSError("simulated completion outage")
        return original_append(event_type, payload, **kwargs)

    monkeypatch.setattr(spine, "append", fail_completion)
    failed = target.post(path, headers=headers)
    assert failed.status_code == 503
    assert failed.json()["detail"] == (
        "federated Trade Offer could not be durably imported"
    )
    assert len(target_app.state.nth.trade_offers.poll(-1).records) == 1
    proposed = [
        event for event in spine.read_all()
        if event.type == "trade.offer.import.proposed"
    ]
    assert len(proposed) == 1
    unavailable = target.get(f"/api/v2/trade/offers/{digest}")
    assert unavailable.status_code == 503
    assert "missing offer import anchor" in unavailable.json()["detail"]

    restarted_app = create_app(
        tmp_path / "target",
        require_console_auth=False,
    )
    original_importer = restarted_app.state.nth.node_identity.as_did()
    old_spine = restarted_app.state.nth.spine
    replacement = AgentIdentity.generate(label="recovery-node")
    restarted_app.state.nth.node_identity = replacement
    restarted_app.state.nth.spine = SignedEventLog(
        old_spine._path,
        replacement,
    )
    restarted = TestClient(restarted_app)
    recovered = restarted.post(
        path,
        headers=_console_headers(restarted_app),
    )
    assert recovered.status_code == 200
    assert recovered.json()["appended"] is False
    assert recovered.json()["source_id"] == original_importer
    anchors = [
        event for event in restarted_app.state.nth.spine.read_all()
        if event.type == "trade.offer.imported"
    ]
    assert len(anchors) == 1
    assert anchors[0].event_id == recovered.json()["audit_event_id"]
    assert anchors[0].author_did == replacement.as_did()
    assert restarted.get(f"/api/v2/trade/offers/{digest}").status_code == 200


def test_cached_remote_offer_import_rejects_incompatible_existing_provenance(
    tmp_path: Path,
) -> None:
    _, target_app, target, offer, digest = _cached_remote_offer(tmp_path)
    target_app.state.nth.trade_offers.publish(
        offer,
        source_kind="local-library",
        source_id="test-fixture",
    )

    response = target.post(
        f"/api/v2/trade/federation/cached-offers/{digest}/import",
        headers=_console_headers(target_app),
    )

    assert response.status_code == 409
    assert response.json()["detail"] == (
        "offer already exists with incompatible import provenance"
    )
    assert list(target_app.state.nth.spine.read_all()) == []


def test_cached_remote_offer_import_anchor_survives_local_key_rotation(
    tmp_path: Path,
) -> None:
    _, target_app, target, offer, digest = _cached_remote_offer(tmp_path)
    path = f"/api/v2/trade/federation/cached-offers/{digest}/import"
    imported = target.post(path, headers=_console_headers(target_app))
    assert imported.status_code == 200
    original_importer = imported.json()["source_id"]

    replacement = AgentIdentity.generate(label="replacement-node")
    old_spine = target_app.state.nth.spine
    target_app.state.nth.node_identity = replacement
    target_app.state.nth.spine = SignedEventLog(old_spine._path, replacement)

    listed = target.get("/api/v2/trade/offers")
    retried = target.post(path, headers=_console_headers(target_app))

    assert listed.status_code == 200
    assert retried.status_code == 200
    assert retried.json()["appended"] is False
    assert retried.json()["source_id"] == original_importer
    assert retried.json()["source_id"] != replacement.as_did()
    assert target.get(f"/api/v2/trade/offers/{digest}").json()["offer"] == (
        offer.to_dict()
    )
