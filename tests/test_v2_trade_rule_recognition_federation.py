from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from nth_dao.identity import AgentIdentity, crypto_available
from nth_dao.trade_rules import (
    EVENT_TRADE_RULE_RECOGNITION_RECORDED,
    TradeRuleRecognition,
    build_rule_package,
    build_rule_recognition_proof_pages,
    create_rule_recognition,
    offer_body,
    offer_digest,
    parse_rule_recognition_proof_bundle,
    parse_rule_recognition_proof_pages,
    sign_offer_package_binding,
    sign_offer,
    trade_canonical_json,
)
from nth_dao.trade_rules.recognition_conformance import VECTORS_PATH
from nth_dao.web import create_app

pytestmark = pytest.mark.skipif(
    not crypto_available(),
    reason="Trade Rule Recognition requires PyNaCl",
)


def _setup(tmp_path, *, enable_disclosure=True):
    vectors = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    package = build_rule_package(
        vectors["package_manifest"],
        {
            digest: bytes.fromhex(payload)
            for digest, payload in vectors["package_resources_hex"].items()
        },
    )
    statements = (
        TradeRuleRecognition.from_dict(vectors["recognized"]),
        TradeRuleRecognition.from_dict(vectors["revoked"]),
    )
    app = create_app(tmp_path, require_console_auth=False)
    app.state.nth_rule_recognition_federation_enabled = enable_disclosure
    app.state.nth_rule_recognition_federation_issuers = (
        {"*"} if enable_disclosure else set()
    )
    app.state.nth.trade_rule_packages.install(
        package.manifest,
        package.resources,
        source="local",
    )
    identity = app.state.nth.node_identity
    offer = sign_offer(
        identity,
        offer_body(
            offer_id="org.nthdao.test/recognition-federation",
            publisher_did=identity.as_did(),
            title="Recognition federation test",
            summary="Public package with observed community opinions.",
            provides=[{
                "leg_id": "service",
                "resource_type": "service:test",
                "resource_id": "urn:nth:test:recognition-federation",
                "quantity": "1",
                "unit": "task",
                "descriptor_digest": "sha256:" + ("d" * 64),
            }],
            rule_refs=[{
                "rule_id": package.manifest.rule_id,
                "digest": package.digest,
            }],
            published_at="2026-08-01T00:00:00Z",
            not_after="2027-08-01T00:00:00Z",
        ),
        created="2026-08-01T00:00:01Z",
    )
    digest = offer_digest(offer)
    path = (
        f"/api/v2/trade/federation/offers/{digest}/rule-packages/"
        f"{package.digest}/recognition-proof"
    )
    return app, package, statements, offer, digest, path


def _publish(client, package, statements, offer, digest):
    auth = {
        "Authorization": f"Bearer {client.app.state.nth_console_token}"
    }
    assert client.post(
        "/api/v2/trade/offers",
        json=offer.to_dict(),
        headers=auth,
    ).status_code == 200
    assert client.post(
        f"/api/v2/trade/offers/{digest}/announce",
        json={},
        headers=auth,
    ).status_code == 200
    for statement in statements:
        response = client.post(
            f"/api/v2/trade/rule-packages/{package.digest}/recognitions",
            json=statement.to_dict(),
            headers=auth,
        )
        assert response.status_code == 200, response.text


def test_public_recognition_proof_requires_live_offer_and_round_trips(tmp_path):
    app, package, statements, offer, digest, path = _setup(tmp_path)
    client = TestClient(app)

    assert client.get(path).status_code == 404
    _publish(client, package, statements, offer, digest)
    response = client.get(path)

    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "public, max-age=30"
    assert response.headers["x-nth-recognition-semantics"] == (
        "observed-not-globally-fresh"
    )
    assert response.headers["x-nth-recognition-disclosure"] == (
        "operator-enabled"
    )
    assert response.headers["x-nth-trust-granted"] == "false"
    assert response.headers["x-nth-execution-authorized"] == "false"
    proof = parse_rule_recognition_proof_bundle(
        response.content,
        package=package,
        expected_offer_digest=digest,
        expected_offer_publisher_did=app.state.nth.node_identity.as_did(),
    )
    assert [item.digest for item in proof.statements] == [
        item.digest for item in statements
    ]

    cached = client.get(path, headers={"If-None-Match": response.headers["etag"]})
    assert cached.status_code == 304
    assert cached.content == b""


def test_public_recognition_proof_page_is_cached_and_round_trips(tmp_path):
    app, package, statements, offer, digest, legacy_path = _setup(tmp_path)
    path = legacy_path.replace(
        "/recognition-proof",
        "/recognition-proof-pages/0",
    )
    client = TestClient(app)

    assert client.get(path).status_code == 404
    _publish(client, package, statements, offer, digest)
    response = client.get(path)

    assert response.status_code == 200, response.text
    assert response.headers["x-nth-recognition-page-index"] == "0"
    assert response.headers["x-nth-recognition-page-count"] == "1"
    assert response.headers["x-nth-recognition-observation-digest"].startswith(
        "sha256:"
    )
    proof_set = parse_rule_recognition_proof_pages(
        [response.content],
        package=package,
        expected_offer_digest=digest,
        expected_offer_publisher_did=app.state.nth.node_identity.as_did(),
    )
    assert [item.digest for item in proof_set.statements] == [
        item.digest for item in statements
    ]
    cached = client.get(
        path,
        headers={"If-None-Match": response.headers["etag"]},
    )
    assert cached.status_code == 304
    app.state.trade_rule_recognition_proof_page_cache["corrupt"] = (
        float("inf"),
        (b"x",),
        99,
    )
    assert client.get(path).status_code == 200
    assert "corrupt" not in app.state.trade_rule_recognition_proof_page_cache
    assert client.get(path[:-1] + "1").status_code == 404


def test_public_recognition_pages_serve_graph_beyond_v1_limit(
    tmp_path,
    monkeypatch,
):
    app, package, seed_statements, offer, digest, legacy_path = _setup(tmp_path)
    client = TestClient(app)
    _publish(client, package, seed_statements, offer, digest)
    issuer = AgentIdentity.generate()
    statements = []
    previous = None
    issued_at = datetime(2026, 8, 1, tzinfo=timezone.utc)
    for _index in range(300):
        previous = create_rule_recognition(
            issuer,
            package=package,
            decision="recognized",
            issued_at="2026-08-01T00:00:00Z",
            not_after="2026-08-20T00:00:00Z",
            previous=previous,
            now=issued_at,
        )
        statements.append(previous)
    monkeypatch.setattr(
        app.state.nth.trade_rule_recognition_audit,
        "verified_statements",
        lambda *, package: tuple(statements),
    )

    assert client.get(legacy_path).status_code == 503
    page_base = legacy_path.replace(
        "/recognition-proof",
        "/recognition-proof-pages/",
    )
    first = client.get(page_base + "0")
    assert first.status_code == 200, first.text
    page_count = int(first.headers["x-nth-recognition-page-count"])
    assert page_count >= 3
    pages = [first.content]
    for page_index in range(1, page_count):
        response = client.get(page_base + str(page_index))
        assert response.status_code == 200, response.text
        assert int(response.headers["x-nth-recognition-page-count"]) == page_count
        pages.append(response.content)
    proof_set = parse_rule_recognition_proof_pages(
        pages,
        package=package,
        expected_offer_digest=digest,
        expected_offer_publisher_did=app.state.nth.node_identity.as_did(),
    )
    assert len(proof_set.statements) == 300


def test_peer_page_fetch_uses_one_pinned_ip_and_complete_deadline(
    tmp_path,
    monkeypatch,
):
    import nth_dao.web.market_federation_poll as federation_http
    import nth_dao.web.v2_api as web_v2_api

    app, package, statements, offer, digest, _legacy_path = _setup(tmp_path)
    identity = app.state.nth.node_identity
    binding = sign_offer_package_binding(
        identity,
        offer_digest=digest,
        package_digest=package.digest,
        created=offer.to_dict()["published_at"],
    )
    monkeypatch.setattr(
        "nth_dao.trade_rules.recognition_transport_pages."
        "MAX_RULE_RECOGNITION_PROOF_PAGE_STATEMENTS",
        1,
    )
    wires = build_rule_recognition_proof_pages(
        package,
        statements,
        offer_package_binding=binding,
        observer_identity=identity,
    )
    raws = tuple(trade_canonical_json(wire) for wire in wires)
    calls = []

    def get_page(url, resolved_ip, *, timeout_s, max_bytes):
        page_index = int(url.rsplit("/", 1)[1])
        calls.append((resolved_ip, timeout_s, max_bytes, page_index))
        return raws[page_index]

    monkeypatch.setattr(
        federation_http,
        "_urllib_get_bytes_pinned",
        get_page,
    )
    monkeypatch.setattr(
        web_v2_api,
        "_normalize_configured_fed_peer",
        lambda value: value,
    )
    monkeypatch.setattr(
        web_v2_api,
        "_call_operator_trade_peer_with_fallback",
        lambda _url, operation, *, timeout_seconds: operation(
            "203.0.113.7",
            timeout_seconds,
        ),
    )

    proof_set = web_v2_api._fetch_trade_rule_recognition_proof_pages_from_peer(
        "https://peer.example",
        offer_digest=digest,
        package=package,
        offer_publisher_did=identity.as_did(),
    )

    assert len(proof_set.pages) == 2
    assert [call[0] for call in calls] == ["203.0.113.7", "203.0.113.7"]
    assert [call[3] for call in calls] == [0, 1]
    assert all(0 < call[1] <= 15.0 for call in calls)
    assert all(call[2] == 256 * 1024 for call in calls)


def test_public_recognition_disclosure_is_disabled_by_default(tmp_path):
    app, package, statements, offer, digest, path = _setup(
        tmp_path,
        enable_disclosure=False,
    )
    client = TestClient(app)
    _publish(client, package, statements, offer, digest)

    response = client.get(path)

    assert response.status_code == 404
    assert response.json()["detail"] == (
        "Rule Recognition federation disclosure is disabled"
    )


def test_enabled_disclosure_still_requires_explicit_issuer_allowlist(tmp_path):
    app, package, statements, offer, digest, path = _setup(tmp_path)
    app.state.nth_rule_recognition_federation_issuers = set()
    client = TestClient(app)
    _publish(client, package, statements, offer, digest)

    response = client.get(path)

    assert response.status_code == 404
    assert response.json()["detail"] == (
        "Rule Recognition federation issuer allowlist is empty"
    )


def test_disclosure_filters_unlisted_third_party_issuers(tmp_path):
    app, package, statements, offer, digest, path = _setup(tmp_path)
    app.state.nth_rule_recognition_federation_issuers = {
        app.state.nth.node_identity.as_did()
    }
    client = TestClient(app)
    _publish(client, package, statements, offer, digest)

    response = client.get(path)

    assert response.status_code == 200
    proof = parse_rule_recognition_proof_bundle(
        response.content,
        package=package,
        expected_offer_digest=digest,
        expected_offer_publisher_did=app.state.nth.node_identity.as_did(),
    )
    assert proof.statements == ()


def test_public_recognition_proof_304_does_not_spend_byte_budget(
    tmp_path,
    monkeypatch,
):
    import nth_dao.web.v2_api as web_v2_api

    app, package, statements, offer, digest, path = _setup(tmp_path)
    client = TestClient(app)
    _publish(client, package, statements, offer, digest)
    first = client.get(path)
    assert first.status_code == 200

    monkeypatch.setattr(
        web_v2_api,
        "_require_trade_rule_package_byte_budget",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("304 must not spend response bytes")
        ),
    )
    cached = client.get(
        path,
        headers={"If-None-Match": first.headers["etag"]},
    )
    assert cached.status_code == 304


def test_public_recognition_proof_fails_closed_on_cross_log_damage(tmp_path):
    app, package, statements, offer, digest, path = _setup(tmp_path)
    client = TestClient(app)
    _publish(client, package, statements, offer, digest)
    original_snapshot = app.state.nth.spine.verified_snapshot

    def missing_anchor():
        return tuple(
            event
            for event in original_snapshot()
            if event.type != EVENT_TRADE_RULE_RECOGNITION_RECORDED
        )

    app.state.nth.spine.verified_snapshot = missing_anchor
    response = client.get(path)

    assert response.status_code == 503
    assert response.json()["detail"] == (
        "public Rule Recognition proof integrity verification failed"
    )
    assert str(tmp_path) not in response.text


def test_public_recognition_proof_rejects_unreferenced_package(tmp_path):
    app, package, statements, offer, digest, _path = _setup(tmp_path)
    client = TestClient(app)
    _publish(client, package, statements, offer, digest)
    other_digest = "sha256:" + ("0" * 64)

    response = client.get(
        f"/api/v2/trade/federation/offers/{digest}/rule-packages/"
        f"{other_digest}/recognition-proof"
    )

    assert response.status_code in {404, 503}
