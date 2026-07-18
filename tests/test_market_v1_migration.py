"""Compatibility and collision tests for the v1-to-v2 market migration."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("nacl")

from fastapi.testclient import TestClient

from nth_dao.b64u import b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.cap_token import CAP_NTH_RECEIPT_SIGN, sign_cap_token
from nth_dao.identity import AgentIdentity
from nth_dao.market import ClaimStore, MarketFeed, build_digest, sign_announcement
from nth_dao.market.announcement import (
    NTH_ANNOUNCEMENT_KIND_V1,
    TaskAnnouncement,
    announcement_federation_key,
    verify_announcement,
)
from nth_dao.market.claim import claim_announcement, sign_claim_receipt
from nth_dao.web import create_app
from nth_dao.web.market_federation_poll import pull_from_peer


def _signed_v1(identity: AgentIdentity, announcement_id: str) -> TaskAnnouncement:
    announcement = TaskAnnouncement(
        announcement_id=announcement_id,
        publisher_did=identity.as_did(),
        title="legacy announcement",
        capability_set=[],
        kind=NTH_ANNOUNCEMENT_KIND_V1,
    )
    announcement.publisher_sig = b64u_encode(
        identity.sign(canonical_json(announcement.signing_body()))
    )
    return announcement


def test_signed_v1_printable_id_remains_readable(tmp_path: Path) -> None:
    publisher = AgentIdentity.generate(label="legacy")
    announcement = _signed_v1(publisher, "legacy/task,100% complete")

    assert verify_announcement(announcement) == (True, "")
    feed = MarketFeed(tmp_path)
    feed.publish(announcement)
    assert feed.get(announcement.announcement_id) == announcement
    assert feed.get_by_federation_key(
        announcement_federation_key(announcement),
    ) == announcement


def test_v1_unsafe_id_federates_by_content_key(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)
    identity = app.state.nth.node_identity
    announcement = _signed_v1(identity, "legacy/task,100% complete")
    MarketFeed(tmp_path).publish(announcement)

    digest = build_digest(MarketFeed(tmp_path), identity)
    key = announcement_federation_key(announcement)
    assert digest.refs[0]["federation_key"] == key
    pulled = client.get(
        "/api/v2/market/federation/pull", params={"keys": key},
    )
    assert pulled.status_code == 200
    assert pulled.json()[0]["announcement_id"] == announcement.announcement_id

    def get(url: str):
        from urllib.parse import urlsplit

        parsed = urlsplit(url)
        path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        return client.get(path).json()

    discovered = pull_from_peer(
        "https://legacy.example",
        get,
        expected_source_did=identity.as_did(),
    )
    assert [item.announcement_id for item in discovered] == [
        announcement.announcement_id,
    ]


def test_undelegated_v1_is_readable_but_reported_for_resign(
    tmp_path: Path,
) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)
    publisher = AgentIdentity.generate(label="external-publisher")
    announcement = _signed_v1(publisher, "legacy/external")
    feed = MarketFeed(tmp_path)
    feed.publish(announcement)

    assert feed.get(announcement.announcement_id) == announcement
    assert build_digest(feed, app.state.nth.node_identity).refs == []
    report = client.get(
        "/api/v2/market/federation/status",
    ).json()["announcement_compatibility"]
    assert report == {
        "v1_records": 1,
        "federation_ready_v1_records": 0,
        "requires_publisher_resign": 1,
    }


def test_foreign_claim_by_key_supports_legacy_id(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=True)
    client = TestClient(app)
    authority = app.state.nth.node_identity
    announcement = _signed_v1(authority, "legacy/task,100% complete")
    MarketFeed(tmp_path).publish(announcement)
    claimant = AgentIdentity.generate(label="claimant")
    token = sign_cap_token(
        issuer=claimant,
        subject_did=claimant.as_did(),
        capabilities=[CAP_NTH_RECEIPT_SIGN],
    )
    receipt = sign_claim_receipt(announcement, claimant, token)

    response = client.post(
        "/api/v2/market/federation/claim-foreign",
        json={
            "federation_key": announcement_federation_key(announcement),
            "cap_token": token,
            "receipt": receipt,
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["announcement_id"] == announcement.announcement_id
    assert ClaimStore(tmp_path).is_claimed(announcement.announcement_id)


def test_claim_store_hash_paths_do_not_alias_valid_ids(tmp_path: Path) -> None:
    feed = MarketFeed(tmp_path)
    store = ClaimStore(tmp_path)
    publisher = AgentIdentity.generate(label="publisher")
    first = sign_announcement(
        publisher=publisher,
        authority_did=publisher.as_did(),
        announcement_id="task:a-b",
        title="first",
    )
    second = sign_announcement(
        publisher=publisher,
        authority_did=publisher.as_did(),
        announcement_id="task-a-b",
        title="second",
    )
    feed.publish(first)
    feed.publish(second)

    for announcement in (first, second):
        claimant = AgentIdentity.generate(label=announcement.title)
        token = sign_cap_token(
            issuer=claimant,
            subject_did=claimant.as_did(),
            capabilities=[CAP_NTH_RECEIPT_SIGN],
        )
        claim_announcement(
            feed,
            store,
            announcement.announcement_id,
            claimant=claimant,
            cap_token=token,
        )

    assert store._path(first.announcement_id) != store._path(second.announcement_id)
    assert len(store.all_records()) == 2


def test_claim_store_reads_matching_legacy_record_only(tmp_path: Path) -> None:
    store = ClaimStore(tmp_path)
    legacy_path = store._legacy_path("task:a-b")
    legacy_path.write_text(
        json.dumps({
            "announcement_id": "task:a-b",
            "status": "claimed",
            "claimant_did": "did:key:legacy",
        }),
        encoding="utf-8",
    )

    # Historical records without a signed receipt occupy the CAS slot but can
    # no longer be promoted to trusted claim state.
    assert not store.is_claimed("task:a-b")
    assert store.is_unavailable("task:a-b")
    assert store.get("task-a-b") is None
