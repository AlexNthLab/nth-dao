import asyncio
import hashlib
import json
import threading

import pytest
from fastapi.testclient import TestClient

from nth_dao.canonical_json import canonical_json
from nth_dao.identity import AgentIdentity, crypto_available
from nth_dao.spine import SignedEventLog
from nth_dao.trade_rules import (
    MAX_TRADE_JSON_BYTES,
    offer_body,
    offer_digest,
    sign_offer,
)
from nth_dao.web import create_app

pytestmark = pytest.mark.skipif(
    not crypto_available(), reason="Trade Offer signatures require PyNaCl"
)


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _signed_offer(identity, *, day=29):
    body = offer_body(
        offer_id="org.nthdao.test/api",
        publisher_did=identity.as_did(),
        title="API trade offer",
        summary="A signed offer submitted by its publisher.",
        provides=[
            {
                "leg_id": "review",
                "resource_type": "service",
                "resource_id": "urn:nthdao:test:review",
                "quantity": "1",
                "unit": "job",
                "descriptor_digest": _digest(b"review descriptor"),
            }
        ],
        requests=[],
        rule_refs=[],
        published_at=f"2026-07-{day:02d}T00:00:00Z",
        not_after=f"2027-07-{day:02d}T00:00:00Z",
    )
    return sign_offer(
        identity,
        body,
        created=f"2026-07-{day:02d}T00:00:01Z",
    )


def _console_headers(app) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {app.state.nth_console_token}",
    }


def _authed_client(app, **kwargs) -> TestClient:
    return TestClient(app, headers=_console_headers(app), **kwargs)


def _local_client(root) -> TestClient:
    return _authed_client(create_app(root, require_console_auth=False))


def test_trade_offer_publish_requires_console_and_node_publisher(tmp_path):
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)
    local_offer = _signed_offer(app.state.nth.node_identity)
    remote_offer = _signed_offer(AgentIdentity.generate())

    unauthenticated = client.post(
        "/api/v2/trade/offers",
        json=local_offer.to_dict(),
    )
    wrong_publisher = client.post(
        "/api/v2/trade/offers",
        json=remote_offer.to_dict(),
        headers=_console_headers(app),
    )
    published = client.post(
        "/api/v2/trade/offers",
        json=local_offer.to_dict(),
        headers=_console_headers(app),
    )

    assert unauthenticated.status_code == 401
    assert wrong_publisher.status_code == 403
    assert "publisher_did must match this node" in wrong_publisher.json()["detail"]
    assert published.status_code == 200


def test_trade_offer_publish_list_get_and_duplicate(tmp_path):
    client = _local_client(tmp_path)
    identity = client.app.state.nth.node_identity
    offer = _signed_offer(identity)
    digest = offer_digest(offer)

    published = client.post("/api/v2/trade/offers", json=offer.to_dict())
    duplicate = client.post("/api/v2/trade/offers", json=offer.to_dict())
    listed = client.get("/api/v2/trade/offers")
    fetched = client.get(f"/api/v2/trade/offers/{digest}")

    assert published.status_code == 200
    assert published.json()["appended"] is True
    assert published.json()["classification"] == "canonical"
    assert published.json()["entry_hash"].startswith("sha256:")
    assert published.json()["audit_event_id"]
    assert published.json()["audit_warning"] == ""
    assert duplicate.status_code == 200
    assert duplicate.json()["appended"] is False
    assert duplicate.json()["classification"] == "duplicate"
    assert duplicate.json()["audit_event_id"] == published.json()["audit_event_id"]
    assert listed.status_code == 200
    assert listed.json()["items"][0]["canonical_head_digest"] == digest
    assert fetched.status_code == 200
    assert fetched.json() == {
        "digest": digest,
        "offer": offer.to_dict(),
        "discoveries": [],
        "verification": {
            "offer_signature_valid": True,
            "announcement_binding_valid": None,
            "source_did_bound": None,
            "recent_source_verified": None,
        },
        "authority": "local-publisher",
        "storage_provenance": {
            "source_kind": "local-operator",
            "source_id": identity.as_did(),
        },
        "actionable": False,
        "warning": (
            "A valid signature proves authorship, not availability, fairness, "
            "ownership, or settlement. Create a new bilateral Agreement "
            "before execution."
        ),
    }
    record = client.app.state.nth.trade_offers.poll().records[0]
    assert record.source_kind == "local-operator"
    assert record.source_id == client.app.state.nth.node_identity.as_did()
    audit_events = list(client.app.state.nth.spine.read_all())
    assert any(
        event.type == "trade.offer.imported"
        and event.payload["offer_digest"] == digest
        and event.payload["entry_hash"] == published.json()["entry_hash"]
        for event in audit_events
    )


def test_local_offer_authority_survives_node_identity_rotation(tmp_path):
    app = create_app(tmp_path, require_console_auth=False)
    client = _authed_client(app)
    original_identity = app.state.nth.node_identity
    offer = _signed_offer(original_identity)
    digest = offer_digest(offer)
    assert client.post(
        "/api/v2/trade/offers",
        json=offer.to_dict(),
    ).status_code == 200

    old_spine = app.state.nth.spine
    replacement = AgentIdentity.generate(label="rotated-node")
    app.state.nth.node_identity = replacement
    app.state.nth.spine = SignedEventLog(old_spine._path, replacement)

    response = client.get(f"/api/v2/trade/offers/{digest}")

    assert response.status_code == 200
    assert response.json()["authority"] == "local-publisher"
    assert response.json()["storage_provenance"] == {
        "source_kind": "local-operator",
        "source_id": original_identity.as_did(),
    }


def test_trade_offer_api_rejects_tampering_without_persisting(tmp_path):
    client = _local_client(tmp_path)
    identity = client.app.state.nth.node_identity
    document = _signed_offer(identity).to_dict()
    document["summary"] = "tampered after signing"

    rejected = client.post("/api/v2/trade/offers", json=document)

    assert rejected.status_code == 400
    assert "signature" in rejected.json()["detail"]
    assert client.get("/api/v2/trade/offers").json()["items"] == []


def test_trade_offer_publish_rejects_oversized_body_before_parsing(tmp_path):
    app = create_app(tmp_path, require_console_auth=False)
    client = _authed_client(app)

    response = client.post(
        "/api/v2/trade/offers",
        content=b"{}",
        headers={
            "Content-Type": "application/json",
            "Content-Length": str(MAX_TRADE_JSON_BYTES + 1),
        },
    )

    assert response.status_code == 413
    assert "exceeds" in response.json()["detail"]
    assert app.state.nth.trade_offers.latest_seq() == -1


def test_trade_offer_api_rejects_duplicate_json_keys_before_normalization(
    tmp_path,
):
    client = _local_client(tmp_path)
    identity = client.app.state.nth.node_identity
    offer = _signed_offer(identity)
    raw = offer.canonical_bytes.decode("utf-8")
    duplicated = '{"kind":"org.nthdao.trade.offer",' + raw[1:]

    response = client.post(
        "/api/v2/trade/offers",
        content=duplicated,
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 400
    assert "duplicate" in response.json()["detail"]
    assert client.get("/api/v2/trade/offers").json()["items"] == []


def test_trade_offer_api_rejects_oversized_body_before_parsing(tmp_path):
    client = _local_client(tmp_path)
    response = client.post(
        "/api/v2/trade/offers",
        content=b"{" + (b" " * (256 * 1024)) + b"}",
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json()["detail"] == "trade offer body exceeds 256 KiB"


@pytest.mark.parametrize("content_type", ["text/plain", "", "application/xml"])
def test_trade_offer_api_requires_json_content_type(tmp_path, content_type):
    client = _local_client(tmp_path)
    headers = {"Content-Type": content_type} if content_type else {}
    response = client.post(
        "/api/v2/trade/offers",
        content=b"{}",
        headers=headers,
    )

    assert response.status_code == 415


def test_trade_offer_api_exposes_fork_without_selecting_a_winner(tmp_path):
    client = _local_client(tmp_path)
    identity = client.app.state.nth.node_identity
    first = _signed_offer(identity, day=29)
    competing = _signed_offer(identity, day=30)

    assert client.post(
        "/api/v2/trade/offers", json=first.to_dict()
    ).status_code == 200
    conflict = client.post(
        "/api/v2/trade/offers", json=competing.to_dict()
    )

    assert conflict.status_code == 200
    chain = conflict.json()["chain"]
    assert chain["status"] == "forked"
    assert chain["canonical_head_digest"] is None
    assert set(chain["fork_digests"]) == {
        offer_digest(first),
        offer_digest(competing),
    }


def test_trade_offer_api_fails_closed_on_corrupt_local_log(tmp_path):
    app = create_app(tmp_path, require_console_auth=False)
    client = _authed_client(app)
    log_path = app.state.nth.trade_offers.log_path
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_bytes(b"{broken}\n")

    response = client.get("/api/v2/trade/offers")

    assert response.status_code == 503
    assert "integrity failure" in response.json()["detail"]


def test_trade_offer_write_requires_console_auth_when_enabled(tmp_path):
    app = create_app(tmp_path, require_console_auth=True)
    client = TestClient(app)
    identity = app.state.nth.node_identity
    document = _signed_offer(identity).to_dict()

    denied = client.post("/api/v2/trade/offers", json=document)
    allowed = client.post(
        "/api/v2/trade/offers",
        json=document,
        headers={
            "Authorization": f"Bearer {app.state.nth_console_token}",
        },
    )

    assert denied.status_code == 401
    assert allowed.status_code == 200


def test_trade_offer_list_is_bounded_and_paginated(tmp_path):
    client = _local_client(tmp_path)
    identity = client.app.state.nth.node_identity
    for index in range(3):
        offer = _signed_offer(identity)
        document = offer.to_dict()
        document["offer_id"] = f"org.nthdao.test/api-{index}"
        document["proof"]["proof_value"] = "A" * 86
        body = offer_body(
            offer_id=document["offer_id"],
            publisher_did=identity.as_did(),
            title=document["title"],
            summary=document["summary"],
            provides=document["provides"],
            requests=[],
            rule_refs=[],
            published_at=document["published_at"],
            not_after=document["not_after"],
        )
        signed = sign_offer(
            identity, body, created=document["proof"]["created"]
        )
        assert client.post(
            "/api/v2/trade/offers",
            content=signed.canonical_bytes,
            headers={"Content-Type": "application/json"},
        ).status_code == 200

    first = client.get("/api/v2/trade/offers", params={"limit": 2})
    second = client.get(
        "/api/v2/trade/offers",
        params={"cursor": first.json()["next_cursor"], "limit": 2},
    )
    invalid = client.get("/api/v2/trade/offers", params={"limit": 501})

    assert len(first.json()["items"]) == 2
    assert first.json()["next_cursor"]
    assert len(second.json()["items"]) == 1
    assert second.json()["next_cursor"] == ""
    assert invalid.status_code == 400


def test_trade_offer_cursor_is_stable_when_earlier_key_is_inserted(tmp_path):
    client = _local_client(tmp_path)
    identity = client.app.state.nth.node_identity

    def publish(offer_id):
        body = offer_body(
            offer_id=offer_id,
            publisher_did=identity.as_did(),
            title=offer_id,
            summary="cursor stability",
            provides=[
                {
                    "leg_id": "work",
                    "resource_type": "service",
                    "resource_id": "urn:nthdao:test:cursor",
                    "quantity": "1",
                    "unit": "job",
                    "descriptor_digest": _digest(b"cursor"),
                }
            ],
            requests=[],
            rule_refs=[],
            published_at="2026-07-29T00:00:00Z",
            not_after="2027-07-29T00:00:00Z",
        )
        offer = sign_offer(
            identity, body, created="2026-07-29T00:00:01Z"
        )
        response = client.post(
            "/api/v2/trade/offers", json=offer.to_dict()
        )
        assert response.status_code == 200

    publish("org.nthdao.test/b")
    publish("org.nthdao.test/c")
    first = client.get("/api/v2/trade/offers", params={"limit": 1}).json()
    publish("org.nthdao.test/a")
    second = client.get(
        "/api/v2/trade/offers",
        params={"limit": 5, "cursor": first["next_cursor"]},
    ).json()

    assert [item["offer_id"] for item in first["items"]] == [
        "org.nthdao.test/b"
    ]
    assert [item["offer_id"] for item in second["items"]] == [
        "org.nthdao.test/c"
    ]


@pytest.mark.parametrize(
    "digest, status",
    [
        ("not-a-digest", 400),
        ("sha256:" + ("0" * 64), 404),
    ],
)
def test_trade_offer_get_distinguishes_bad_and_missing_digest(
    tmp_path, digest, status
):
    client = _local_client(tmp_path)
    response = client.get(f"/api/v2/trade/offers/{digest}")
    assert response.status_code == status


def test_trade_offer_api_reports_crypto_unavailable_as_503(
    tmp_path, monkeypatch
):
    import nth_dao.trade_rules.signing as signing

    app = create_app(tmp_path, require_console_auth=False)
    client = _authed_client(app)
    identity = app.state.nth.node_identity
    document = _signed_offer(identity).to_dict()
    monkeypatch.setattr(signing, "_VerifyKey", None)

    response = client.post("/api/v2/trade/offers", json=document)

    assert response.status_code == 503
    assert "PyNaCl" in response.json()["detail"]


def test_trade_offer_api_maps_lock_contention_to_retryable_503(tmp_path):
    from nth_dao.util.io import InterProcessLock

    app = create_app(tmp_path, require_console_auth=False)
    app.state.nth.trade_offers.lock_timeout = 0.05
    client = _authed_client(app, raise_server_exceptions=False)
    store = app.state.nth.trade_offers
    store.publish(_signed_offer(AgentIdentity.generate()))

    with InterProcessLock(store.lock_path, timeout=1):
        response = client.get("/api/v2/trade/offers")

    assert response.status_code == 503
    assert response.headers["Retry-After"] == "1"
    assert response.json()["detail"] == "trade offer store is busy"


def test_trade_offer_publish_does_not_block_the_asgi_event_loop(
    tmp_path, monkeypatch
):
    import httpx

    app = create_app(tmp_path, require_console_auth=False)
    identity = app.state.nth.node_identity
    offer = _signed_offer(identity)
    store = app.state.nth.trade_offers
    real_publish = store.publish
    started = threading.Event()
    release = threading.Event()

    def slow_publish(value, **kwargs):
        started.set()
        assert release.wait(timeout=2)
        return real_publish(value, **kwargs)

    monkeypatch.setattr(store, "publish", slow_publish)

    async def exercise():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            publishing = asyncio.create_task(
                client.post(
                    "/api/v2/trade/offers",
                    content=offer.canonical_bytes,
                    headers={
                        "Content-Type": "application/json",
                        **_console_headers(app),
                    },
                )
            )
            for _ in range(100):
                if started.is_set():
                    break
                await asyncio.sleep(0.01)
            assert started.is_set()
            health = await asyncio.wait_for(
                client.get("/api/v2/health"), timeout=0.5
            )
            release.set()
            published = await asyncio.wait_for(publishing, timeout=2)
            return health, published

    health, published = asyncio.run(exercise())
    assert health.status_code == 200
    assert published.status_code == 200


def test_trade_offer_api_reports_spine_audit_failure(tmp_path, monkeypatch):
    app = create_app(tmp_path, require_console_auth=False)
    identity = app.state.nth.node_identity
    offer = _signed_offer(identity)
    monkeypatch.setattr(
        app.state.nth.spine,
        "append",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("disk full")),
    )
    client = _authed_client(app)

    response = client.post("/api/v2/trade/offers", json=offer.to_dict())

    assert response.status_code == 503
    assert response.headers["Retry-After"] == "1"
    detail = response.json()["detail"]
    assert detail == {
        "code": "trade-offer-audit-incomplete",
        "message": "signed spine append failed",
        "offer_digest": offer_digest(offer),
        "retryable": True,
    }
    unavailable = client.get("/api/v2/trade/offers")
    assert unavailable.status_code == 503
    assert "missing offer import anchor" in unavailable.json()["detail"]


def test_duplicate_retry_repairs_missing_spine_anchor(tmp_path, monkeypatch):
    app = create_app(tmp_path, require_console_auth=False)
    client = _authed_client(app)
    offer = _signed_offer(app.state.nth.node_identity)
    spine = app.state.nth.spine
    real_append = spine.append
    attempts = 0

    def fail_once(*args, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OSError("injected audit failure")
        return real_append(*args, **kwargs)

    monkeypatch.setattr(spine, "append", fail_once)
    first = client.post("/api/v2/trade/offers", json=offer.to_dict())
    retried = client.post("/api/v2/trade/offers", json=offer.to_dict())
    listed = client.get("/api/v2/trade/offers")

    assert first.status_code == 503
    assert first.headers["Retry-After"] == "1"
    assert first.json()["detail"]["code"] == "trade-offer-audit-incomplete"
    assert first.json()["detail"]["offer_digest"] == offer_digest(offer)
    assert retried.status_code == 200
    assert retried.json()["appended"] is False
    assert retried.json()["audit_event_id"]
    assert retried.json()["audit_warning"] == ""
    assert listed.status_code == 200


def test_trade_offer_api_does_not_write_without_signed_spine(tmp_path):
    app = create_app(tmp_path, require_console_auth=False)
    client = _authed_client(app)
    offer = _signed_offer(app.state.nth.node_identity)
    store = app.state.nth.trade_offers
    app.state.nth.spine = None

    response = client.post("/api/v2/trade/offers", json=offer.to_dict())

    assert response.status_code == 503
    assert response.json()["detail"] == "signed Spine unavailable"
    assert store.latest_seq() == -1


def test_trade_offer_read_fails_closed_when_spine_disappears(tmp_path):
    app = create_app(tmp_path, require_console_auth=False)
    client = _authed_client(app)
    offer = _signed_offer(app.state.nth.node_identity)
    digest = offer_digest(offer)
    assert client.post("/api/v2/trade/offers", json=offer.to_dict()).status_code == 200
    app.state.nth.spine = None

    response = client.get(f"/api/v2/trade/offers/{digest}")

    assert response.status_code == 503
    assert "signed Spine unavailable" in response.json()["detail"]


def test_cross_log_cache_invalidates_on_store_and_external_spine_writes(
    tmp_path,
    monkeypatch,
):
    app = create_app(tmp_path, require_console_auth=False)
    client = _authed_client(app)
    identity = app.state.nth.node_identity
    offer = _signed_offer(identity)
    digest = offer_digest(offer)
    assert client.post("/api/v2/trade/offers", json=offer.to_dict()).status_code == 200
    store = app.state.nth.trade_offers
    store._v2_spine_anchor_cache = None
    real_verify = store.verify_import_anchors
    calls = 0

    def counted_verify(anchors):
        nonlocal calls
        calls += 1
        return real_verify(anchors)

    monkeypatch.setattr(store, "verify_import_anchors", counted_verify)

    assert client.get(f"/api/v2/trade/offers/{digest}").status_code == 200
    assert client.get(f"/api/v2/trade/offers/{digest}").status_code == 200
    assert calls == 1

    store.publish(
        _signed_offer(identity, day=30),
        source_kind="local-library",
        source_id="cache-invalidation-test",
    )
    assert client.get(f"/api/v2/trade/offers/{digest}").status_code == 200
    assert calls == 2

    second_process = SignedEventLog(app.state.nth.spine._path, identity)
    second_process.append("test.cache.invalidated", {"reason": "external-write"})
    assert client.get(f"/api/v2/trade/offers/{digest}").status_code == 200
    assert calls == 3


def test_trade_offer_api_detects_log_and_checkpoint_rollback(tmp_path):
    app = create_app(tmp_path, require_console_auth=False)
    client = _authed_client(app)
    identity = app.state.nth.node_identity
    first = _signed_offer(identity, day=29)
    second = _signed_offer(identity, day=30)

    assert client.post(
        "/api/v2/trade/offers", json=first.to_dict()
    ).status_code == 200
    assert client.post(
        "/api/v2/trade/offers", json=second.to_dict()
    ).status_code == 200

    store = app.state.nth.trade_offers
    first_line = store.log_path.read_bytes().splitlines(keepends=True)[0]
    first_entry = json.loads(first_line)
    store.log_path.write_bytes(first_line)
    checkpoint = {
        "kind": "org.nthdao.trade.offer-log-checkpoint",
        "protocol_version": "1.0",
        "seq": 0,
        "entry_hash": first_entry["entry_hash"],
    }
    store.checkpoint_path.write_bytes(canonical_json(checkpoint) + b"\n")

    response = client.get("/api/v2/trade/offers")

    assert response.status_code == 503
    assert "cross-log integrity failure" in response.json()["detail"]
    assert "missing offer log seq 1" in response.json()["detail"]


def test_trade_offer_api_rejects_signed_anchor_with_forged_metadata(tmp_path):
    app = create_app(tmp_path, require_console_auth=False)
    client = _authed_client(app)
    identity = app.state.nth.node_identity
    offer = _signed_offer(identity)
    published = client.post("/api/v2/trade/offers", json=offer.to_dict())
    assert published.status_code == 200

    app.state.nth.spine.append(
        "trade.offer.imported",
        {
            "seq": 0,
            "offer_digest": published.json()["digest"],
            "entry_hash": published.json()["entry_hash"],
            "publisher_did": AgentIdentity.generate().as_did(),
            "offer_id": offer.offer_id,
            "source_kind": "local-operator",
            "source_id": app.state.nth.node_identity.as_did(),
        },
    )

    response = client.get("/api/v2/trade/offers")

    assert response.status_code == 503
    assert "metadata mismatch" in response.json()["detail"]
