from datetime import datetime, timedelta, timezone
import hashlib
import threading
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

from nth_dao.identity import crypto_available
from nth_dao.trade_rules import (
    build_rule_package,
    build_rule_package_bundle,
    manifest_body,
    offer_body,
    offer_digest,
    parse_rule_package_bundle,
    rule_package_bundle_bytes,
    sign_manifest,
    sign_offer_package_binding,
    sign_offer,
)
from nth_dao.web import create_app
import nth_dao.web.market_federation_poll as federation_poll
import nth_dao.web.v2_api as web_v2_api
import nth_dao.trade_rules as trade_rules_api
from nth_dao.web.rate_limit import (
    PersistentRateBudgetLimiter,
    RateBudgetLimiter,
    RateLimiter,
)

pytestmark = pytest.mark.skipif(
    not crypto_available(), reason="Trade Rule signatures require PyNaCl"
)


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _timestamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _published_package(
    app,
    tmp_path,
    *,
    include_missing_sibling=False,
    no_package_expiry=False,
):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    payload = b'{"delivery":"manual"}'
    payload_digest = _digest(payload)
    manifest = sign_manifest(
        app.state.nth.node_identity,
        manifest_body(
            rule_id="org.nthdao.test.public-package",
            version="1.0.0",
            publisher_did=app.state.nth.node_identity.as_did(),
            summary="Public package transport test",
            applies_to=["service"],
            families=["fulfillment"],
            resources=[{
                "purpose": "terms",
                "media_type": "application/json",
                "digest": payload_digest,
                "size": len(payload),
            }],
            published_at=_timestamp(now - timedelta(minutes=2)),
            not_after=(
                None
                if no_package_expiry
                else _timestamp(now + timedelta(days=1))
            ),
        ),
        created=_timestamp(now - timedelta(minutes=1)),
    )
    package = build_rule_package(manifest, {payload_digest: payload})
    app.state.nth.trade_rule_packages.install(
        manifest,
        package.resources,
        source="local",
    )
    rule_refs = [{
        "rule_id": manifest.rule_id,
        "digest": package.digest,
    }]
    if include_missing_sibling:
        rule_refs.append({
            "rule_id": "org.nthdao.test.missing-sibling",
            "digest": "sha256:" + ("0" * 64),
        })
    offer = sign_offer(
        app.state.nth.node_identity,
        offer_body(
            offer_id="org.nthdao.test/public-package",
            publisher_did=app.state.nth.node_identity.as_did(),
            title="Package-backed service",
            summary="A test service with an exact Trade Skill.",
            provides=[{
                "leg_id": "service",
                "resource_type": "service:test",
                "resource_id": "urn:nth:test:package-service",
                "quantity": "1",
                "unit": "task",
                "descriptor_digest": _digest(b"descriptor"),
            }],
            rule_refs=rule_refs,
            published_at=_timestamp(now - timedelta(minutes=1)),
            not_after=_timestamp(now + timedelta(days=1)),
        ),
        created=_timestamp(now - timedelta(seconds=30)),
    )
    return package, offer


def _published_package_with_dependency(app):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    child_payload = b'{"term":"child"}'
    child_payload_digest = _digest(child_payload)
    child_manifest = sign_manifest(
        app.state.nth.node_identity,
        manifest_body(
            rule_id="org.nthdao.test.child-package",
            version="1.0.0",
            publisher_did=app.state.nth.node_identity.as_did(),
            summary="Public transitive child package",
            applies_to=["service"],
            families=["fulfillment"],
            resources=[{
                "purpose": "terms",
                "media_type": "application/json",
                "digest": child_payload_digest,
                "size": len(child_payload),
            }],
            published_at=_timestamp(now - timedelta(minutes=3)),
            not_after=_timestamp(now + timedelta(days=1)),
        ),
        created=_timestamp(now - timedelta(minutes=2)),
    )
    child = build_rule_package(
        child_manifest,
        {child_payload_digest: child_payload},
    )
    app.state.nth.trade_rule_packages.install(
        child_manifest,
        child.resources,
        source="local",
    )

    root_payload = b'{"term":"root"}'
    root_payload_digest = _digest(root_payload)
    root_manifest = sign_manifest(
        app.state.nth.node_identity,
        manifest_body(
            rule_id="org.nthdao.test.root-package",
            version="1.0.0",
            publisher_did=app.state.nth.node_identity.as_did(),
            summary="Public package with a signed dependency",
            applies_to=["service"],
            families=["fulfillment"],
            resources=[{
                "purpose": "terms",
                "media_type": "application/json",
                "digest": root_payload_digest,
                "size": len(root_payload),
            }],
            dependencies=[{
                "rule_id": child_manifest.rule_id,
                "digest": child.digest,
            }],
            published_at=_timestamp(now - timedelta(minutes=2)),
            not_after=_timestamp(now + timedelta(days=1)),
        ),
        created=_timestamp(now - timedelta(minutes=1)),
    )
    root = build_rule_package(
        root_manifest,
        {root_payload_digest: root_payload},
    )
    app.state.nth.trade_rule_packages.install(
        root_manifest,
        root.resources,
        source="local",
    )
    offer = sign_offer(
        app.state.nth.node_identity,
        offer_body(
            offer_id="org.nthdao.test/dependency-package",
            publisher_did=app.state.nth.node_identity.as_did(),
            title="Dependency-backed service",
            summary="A service whose Trade Skill has a dependency.",
            provides=[{
                "leg_id": "service",
                "resource_type": "service:test",
                "resource_id": "urn:nth:test:dependency-service",
                "quantity": "1",
                "unit": "task",
                "descriptor_digest": _digest(b"dependency descriptor"),
            }],
            rule_refs=[{
                "rule_id": root_manifest.rule_id,
                "digest": root.digest,
            }],
            published_at=_timestamp(now - timedelta(minutes=1)),
            not_after=_timestamp(now + timedelta(days=1)),
        ),
        created=_timestamp(now - timedelta(seconds=30)),
    )
    return child, root, offer


def test_trade_rule_package_catalog_is_bounded_verified_and_private(tmp_path):
    app = create_app(tmp_path, require_console_auth=True)
    public = TestClient(app)
    auth = {"Authorization": f"Bearer {app.state.nth_console_token}"}
    client = TestClient(app, headers=auth)
    child, root, _offer = _published_package_with_dependency(app)

    assert public.get("/api/v2/trade/rule-packages").status_code == 401
    first = client.get("/api/v2/trade/rule-packages", params={"limit": 1})
    assert first.status_code == 200, first.text
    assert first.headers["cache-control"] == "no-store"
    first_body = first.json()
    assert first_body["cache_only"] is True
    assert first_body["execution_authorized"] is False
    assert len(first_body["items"]) == 1
    assert first_body["next_cursor"].startswith("sha256:")
    assert first_body["items"][0]["verification"] == {
        "status": "verified-cache",
        "publisher_signature": True,
        "resource_digests": True,
    }
    assert first_body["items"][0]["trust"] == {
        "status": "not-evaluated",
        "advisory": True,
        "execution_authorized": False,
    }
    assert first_body["items"][0]["provenance"] == {
        "status": "explicit",
        "sources": ["local"],
    }

    second = client.get(
        "/api/v2/trade/rule-packages",
        params={"limit": 1, "cursor": first_body["next_cursor"]},
    )
    assert second.status_code == 200, second.text
    assert len(second.json()["items"]) == 1
    assert second.json()["next_cursor"] == ""
    assert {
        first_body["items"][0]["package_digest"],
        second.json()["items"][0]["package_digest"],
    } == {child.digest, root.digest}

    detail = client.get(
        f"/api/v2/trade/rule-packages/{root.digest}"
    )
    assert detail.status_code == 200, detail.text
    assert detail.headers["cache-control"] == "no-store"
    payload = detail.json()
    assert payload["package_digest"] == root.digest
    assert payload["manifest"]["rule_id"] == "org.nthdao.test.root-package"
    assert payload["dependency_count"] == 1
    assert payload["resource_count"] == 1
    assert payload["resource_bytes"] == len(b'{"term":"root"}')
    assert "resources" not in payload
    assert all(
        "content" not in resource
        for resource in payload["manifest"]["resources"]
    )


def test_trade_rule_package_catalog_preserves_no_expiry(tmp_path):
    app = create_app(tmp_path, require_console_auth=True)
    client = TestClient(
        app,
        headers={"Authorization": f"Bearer {app.state.nth_console_token}"},
    )
    package, _offer = _published_package(
        app,
        tmp_path,
        no_package_expiry=True,
    )

    page = client.get("/api/v2/trade/rule-packages")
    detail = client.get(f"/api/v2/trade/rule-packages/{package.digest}")

    assert page.status_code == 200, page.text
    assert page.json()["items"][0]["not_after"] is None
    assert detail.status_code == 200, detail.text
    assert detail.json()["not_after"] is None
    assert detail.json()["manifest"]["not_after"] is None


def test_trade_rule_package_catalog_rejects_bad_bounds_and_missing_digest(tmp_path):
    app = create_app(tmp_path, require_console_auth=True)
    client = TestClient(
        app,
        headers={"Authorization": f"Bearer {app.state.nth_console_token}"},
    )

    assert client.get(
        "/api/v2/trade/rule-packages", params={"limit": 0}
    ).status_code == 400
    assert client.get(
        "/api/v2/trade/rule-packages", params={"cursor": "not-a-digest"}
    ).status_code == 400
    assert client.get(
        "/api/v2/trade/rule-packages/not-a-digest"
    ).status_code == 400
    missing = client.get(
        f"/api/v2/trade/rule-packages/sha256:{'f' * 64}"
    )
    assert missing.status_code == 404


def test_trade_rule_package_catalog_fails_closed_on_store_corruption(
    tmp_path,
    monkeypatch,
):
    from nth_dao.trade_rules import RulePackageCorruptionError

    app = create_app(tmp_path, require_console_auth=True)
    client = TestClient(
        app,
        headers={"Authorization": f"Bearer {app.state.nth_console_token}"},
    )
    package, _offer = _published_package(app, tmp_path)
    original_load = app.state.nth.trade_rule_packages._load_locked

    def corrupt_load(digest):
        if digest == package.digest:
            raise RulePackageCorruptionError("test corruption")
        return original_load(digest)

    monkeypatch.setattr(
        app.state.nth.trade_rule_packages,
        "_load_locked",
        corrupt_load,
    )
    response = client.get("/api/v2/trade/rule-packages")
    assert response.status_code == 503
    assert response.json()["detail"] == (
        "trade rule package catalog integrity failure"
    )


def test_trade_rule_package_catalog_verifies_only_the_selected_page(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path, require_console_auth=True)
    client = TestClient(
        app,
        headers={"Authorization": f"Bearer {app.state.nth_console_token}"},
    )
    _child, _root, _offer = _published_package_with_dependency(app)
    store = app.state.nth.trade_rule_packages
    original = store._load_locked
    loaded = []

    def counted(digest):
        loaded.append(digest)
        return original(digest)

    monkeypatch.setattr(store, "_load_locked", counted)
    response = client.get(
        "/api/v2/trade/rule-packages",
        params={"limit": 1},
    )

    assert response.status_code == 200, response.text
    assert len(response.json()["items"]) == 1
    assert loaded == [response.json()["items"][0]["package_digest"]]


def test_public_package_requires_live_local_offer_and_round_trips(tmp_path):
    app = create_app(tmp_path, require_console_auth=True)
    client = TestClient(
        app,
        headers={"Authorization": f"Bearer {app.state.nth_console_token}"},
    )
    package, offer = _published_package(app, tmp_path)
    digest = offer_digest(offer)
    path = (
        f"/api/v2/trade/federation/offers/{digest}/rule-packages/"
        f"{package.digest}"
    )

    assert client.post("/api/v2/trade/offers", json=offer.to_dict()).status_code == 200
    assert client.get(path).status_code == 404
    assert client.post(
        f"/api/v2/trade/offers/{digest}/announce", json={}
    ).status_code == 200

    public = TestClient(app).get(path)
    assert public.status_code == 200, public.text
    assert public.headers["x-nth-offer-digest"] == digest
    assert public.headers["x-nth-package-digest"] == package.digest
    assert public.headers["cache-control"] == "public, max-age=300"
    restored = parse_rule_package_bundle(
        public.content,
        expected_offer_digest=digest,
        expected_package_digest=package.digest,
    )
    assert restored.digest == package.digest
    assert dict(restored.resources) == dict(package.resources)

    encoded_path = (
        "/api/v2/trade/federation/offers/"
        f"{quote(digest, safe='')}/rule-packages/"
        f"{quote(package.digest, safe='')}"
    )
    assert TestClient(app).get(encoded_path).status_code == 200


def test_public_package_rejects_unreferenced_local_cache(tmp_path):
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(
        app,
        headers={"Authorization": f"Bearer {app.state.nth_console_token}"},
    )
    package, offer = _published_package(app, tmp_path)
    digest = offer_digest(offer)
    assert client.post("/api/v2/trade/offers", json=offer.to_dict()).status_code == 200
    assert client.post(
        f"/api/v2/trade/offers/{digest}/announce", json={}
    ).status_code == 200

    # A random digest cannot enumerate or retrieve other cached content.
    response = client.get(
        f"/api/v2/trade/federation/offers/{digest}/rule-packages/"
        f"sha256:{'f' * 64}"
    )
    assert response.status_code == 404


def test_public_package_serves_verified_transitive_dependency(tmp_path):
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(
        app,
        headers={"Authorization": f"Bearer {app.state.nth_console_token}"},
    )
    child, _root, offer = _published_package_with_dependency(app)
    digest = offer_digest(offer)
    assert client.post("/api/v2/trade/offers", json=offer.to_dict()).status_code == 200
    assert client.post(
        f"/api/v2/trade/offers/{digest}/announce", json={}
    ).status_code == 200

    response = TestClient(app).get(
        f"/api/v2/trade/federation/offers/{digest}/rule-packages/"
        f"{child.digest}"
    )
    assert response.status_code == 200, response.text
    assert parse_rule_package_bundle(
        response.content,
        expected_offer_digest=digest,
        expected_package_digest=child.digest,
    ).digest == child.digest


def test_missing_sibling_does_not_hide_intact_exact_package(tmp_path):
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(
        app,
        headers={"Authorization": f"Bearer {app.state.nth_console_token}"},
    )
    package, offer = _published_package(
        app,
        tmp_path,
        include_missing_sibling=True,
    )
    digest = offer_digest(offer)
    assert client.post("/api/v2/trade/offers", json=offer.to_dict()).status_code == 200
    assert client.post(
        f"/api/v2/trade/offers/{digest}/announce", json={}
    ).status_code == 200

    response = TestClient(app).get(
        f"/api/v2/trade/federation/offers/{digest}/rule-packages/"
        f"{package.digest}"
    )
    assert response.status_code == 200, response.text


def test_peer_fetch_pins_dns_and_uses_bounded_encoded_exact_route(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path, require_console_auth=False)
    package, offer = _published_package(app, tmp_path)
    digest = offer_digest(offer)
    raw = rule_package_bundle_bytes(build_rule_package_bundle(
        package,
        offer_package_binding=sign_offer_package_binding(
            app.state.nth.node_identity,
            offer_digest=digest,
            package_digest=package.digest,
            created=offer.to_dict()["published_at"],
        ),
    ))
    observed = {}
    monkeypatch.setattr(
        web_v2_api,
        "_normalize_configured_fed_peer",
        lambda value: "http://peer.example:8080",
    )
    monkeypatch.setattr(
        web_v2_api,
        "_resolve_operator_trade_peer_ips",
        lambda value: ("192.0.2.10",),
    )

    def fake_get(url, resolved_ip, *, timeout_s, max_bytes):
        observed.update({
            "url": url,
            "resolved_ip": resolved_ip,
            "timeout_s": timeout_s,
            "max_bytes": max_bytes,
        })
        return raw

    monkeypatch.setattr(
        federation_poll,
        "_urllib_get_bytes_pinned",
        fake_get,
    )
    restored = web_v2_api._fetch_trade_rule_package_from_peer(
        "http://ignored.example",
        offer_digest=digest,
        package_digest=package.digest,
        offer_publisher_did=offer.publisher_did,
        timeout_seconds=7.5,
    )

    assert restored.digest == package.digest
    assert observed["resolved_ip"] == "192.0.2.10"
    assert 0 < observed["timeout_s"] <= 7.5
    assert observed["max_bytes"] >= len(raw)
    assert observed["url"] == (
        "http://peer.example:8080/api/v2/trade/federation/offers/"
        f"{quote(digest, safe='')}/rule-packages/"
        f"{quote(package.digest, safe='')}"
    )


def test_public_package_conditional_get_skips_encoding_and_byte_charge(tmp_path):
    app = create_app(tmp_path, require_console_auth=False)
    operator = TestClient(
        app,
        headers={"Authorization": f"Bearer {app.state.nth_console_token}"},
    )
    package, offer = _published_package(app, tmp_path)
    digest = offer_digest(offer)
    assert operator.post("/api/v2/trade/offers", json=offer.to_dict()).status_code == 200
    assert operator.post(
        f"/api/v2/trade/offers/{digest}/announce", json={}
    ).status_code == 200
    path = (
        f"/api/v2/trade/federation/offers/{digest}/rule-packages/"
        f"{package.digest}"
    )
    public = TestClient(app)
    first = public.get(path)
    assert first.status_code == 200
    app.state.trade_rule_package_byte_limiter = RateBudgetLimiter(
        max_cost_per_window=1,
        window_seconds=60,
    )
    app.state.trade_rule_package_global_byte_limiter = RateBudgetLimiter(
        max_cost_per_window=1,
        window_seconds=60,
    )

    cached = public.get(path, headers={"If-None-Match": first.headers["etag"]})

    assert cached.status_code == 304
    assert cached.content == b""
    assert cached.headers["etag"] == first.headers["etag"]


def test_public_package_rejects_when_encoder_concurrency_is_full(tmp_path):
    app = create_app(tmp_path, require_console_auth=False)
    operator = TestClient(
        app,
        headers={"Authorization": f"Bearer {app.state.nth_console_token}"},
    )
    package, offer = _published_package(app, tmp_path)
    digest = offer_digest(offer)
    assert operator.post("/api/v2/trade/offers", json=offer.to_dict()).status_code == 200
    assert operator.post(
        f"/api/v2/trade/offers/{digest}/announce", json={}
    ).status_code == 200
    semaphore = threading.BoundedSemaphore(1)
    assert semaphore.acquire(blocking=False)
    app.state.trade_rule_package_serve_semaphore = semaphore

    response = TestClient(app).get(
        f"/api/v2/trade/federation/offers/{digest}/rule-packages/"
        f"{package.digest}"
    )

    assert response.status_code == 503
    assert response.headers["retry-after"] == "1"
    semaphore.release()


def test_public_package_rejects_byte_budget_before_bundle_encoding(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path, require_console_auth=False)
    operator = TestClient(
        app,
        headers={"Authorization": f"Bearer {app.state.nth_console_token}"},
    )
    package, offer = _published_package(app, tmp_path)
    digest = offer_digest(offer)
    assert operator.post("/api/v2/trade/offers", json=offer.to_dict()).status_code == 200
    assert operator.post(
        f"/api/v2/trade/offers/{digest}/announce", json={}
    ).status_code == 200
    app.state.trade_rule_package_byte_limiter = RateBudgetLimiter(
        max_cost_per_window=1,
        window_seconds=60,
    )
    app.state.trade_rule_package_global_byte_limiter = RateBudgetLimiter(
        max_cost_per_window=1024 * 1024,
        window_seconds=60,
    )
    monkeypatch.setattr(
        trade_rules_api,
        "build_rule_package_bundle",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("budget rejection must precede Bundle encoding")
        ),
    )

    response = TestClient(app).get(
        f"/api/v2/trade/federation/offers/{digest}/rule-packages/"
        f"{package.digest}"
    )

    assert response.status_code == 429
    assert response.headers["retry-after"]


def test_persistent_byte_budget_is_shared_without_storing_source_key(tmp_path):
    path = tmp_path / "package-byte-budget.json"
    first = PersistentRateBudgetLimiter(
        path,
        max_cost_per_window=10,
        window_seconds=60,
    )
    second = PersistentRateBudgetLimiter(
        path,
        max_cost_per_window=10,
        window_seconds=60,
    )

    assert first.check("198.51.100.7", 6).allowed is True
    denied = second.check("198.51.100.7", 5)

    assert denied.allowed is False
    assert "198.51.100.7" not in path.read_text(encoding="utf-8")


def test_persistent_byte_budget_rebases_future_window_after_clock_recovery(
    tmp_path,
):
    now = [2_000.0]
    path = tmp_path / "package-byte-budget.json"
    first = PersistentRateBudgetLimiter(
        path,
        max_cost_per_window=10,
        window_seconds=60,
        clock=lambda: now[0],
    )
    assert first.check("198.51.100.8", 10).allowed is True

    now[0] = 1_000.0
    restarted = PersistentRateBudgetLimiter(
        path,
        max_cost_per_window=10,
        window_seconds=60,
        clock=lambda: now[0],
    )
    denied = restarted.check("198.51.100.8", 1)
    assert denied.allowed is False
    assert denied.retry_after_seconds == pytest.approx(60.0)

    now[0] = 1_060.1
    assert restarted.check("198.51.100.8", 1).allowed is True


def test_public_package_request_budget_rejects_before_package_verification(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path, require_console_auth=False)
    operator = TestClient(
        app,
        headers={"Authorization": f"Bearer {app.state.nth_console_token}"},
    )
    package, offer = _published_package(app, tmp_path)
    digest = offer_digest(offer)
    assert operator.post("/api/v2/trade/offers", json=offer.to_dict()).status_code == 200
    assert operator.post(
        f"/api/v2/trade/offers/{digest}/announce", json={}
    ).status_code == 200
    path = (
        f"/api/v2/trade/federation/offers/{digest}/rule-packages/"
        f"{package.digest}"
    )
    app.state.trade_rule_package_request_limiter = RateLimiter(
        max_per_window=1,
        window_seconds=60,
    )
    app.state.trade_rule_package_global_request_limiter = RateLimiter(
        max_per_window=10,
        window_seconds=60,
    )
    public = TestClient(app)
    assert public.get(path).status_code == 200
    monkeypatch.setattr(
        web_v2_api,
        "_load_public_trade_rule_package",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("request budget must precede package verification")
        ),
    )

    rejected = public.get(path)

    assert rejected.status_code == 429
    assert rejected.headers["retry-after"]
