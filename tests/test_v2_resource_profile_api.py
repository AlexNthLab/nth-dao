from __future__ import annotations

import copy

import pytest
from fastapi.testclient import TestClient

from nth_dao.identity import AgentIdentity, crypto_available
from nth_dao.market.resource_profile import (
    resource_profile_body,
    sign_resource_profile,
)
from nth_dao.web import create_app


pytestmark = pytest.mark.skipif(
    not crypto_available(), reason="PyNaCl is required for signed profiles",
)


def _profile(label: str):
    identity = AgentIdentity.generate(label=label)
    body = resource_profile_body(
        profile_id=f"org.example/{label}",
        version="1.0.0",
        publisher_did=identity.as_did(),
        summary=f"Profile for {label}.",
        resource_types=[f"example/{label}"],
        category_mappings=[{
            "community_category": f"examples/{label}",
            "market_category": "products",
        }],
        schema={
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "required": True,
                    "description": "Display name.",
                    "enum": [],
                },
            },
            "additional_properties": False,
        },
        published_at="2026-08-08T00:00:00Z",
        not_after="2027-08-08T00:00:00Z",
    )
    return sign_resource_profile(
        identity, body, created="2026-08-08T00:00:01Z",
    )


def _authorized_client(tmp_path):
    client = TestClient(create_app(tmp_path, require_console_auth=True))
    headers = {
        "Authorization": f"Bearer {client.app.state.nth_console_token}",
    }
    return client, headers


def test_resource_profile_api_requires_console_bearer(tmp_path):
    client = TestClient(create_app(tmp_path, require_console_auth=True))
    profile = _profile("auth")

    assert client.get("/api/v2/market/resource-profiles").status_code == 401
    assert client.post(
        "/api/v2/market/resource-profiles/import",
        json={"document": profile.to_dict()},
    ).status_code == 401


def test_resource_profile_import_list_and_recognition_are_audited(tmp_path):
    client, headers = _authorized_client(tmp_path)
    profile = _profile("widget")

    imported = client.post(
        "/api/v2/market/resource-profiles/import",
        headers=headers,
        json={"document": profile.to_dict()},
    )
    assert imported.status_code == 200, imported.text
    assert imported.json()["installed"] is True
    assert imported.json()["profile"]["digest"] == profile.digest
    assert imported.json()["profile"]["recognized"] is False

    listed = client.get(
        "/api/v2/market/resource-profiles",
        headers=headers,
    )
    assert listed.status_code == 200, listed.text
    assert listed.json()["count"] == 1
    assert listed.json()["returned"] == 1
    assert listed.json()["next_cursor"] == ""
    assert listed.json()["truncated"] is False
    assert listed.json()["items"][0]["signature_verified"] is True
    assert listed.json()["items"][0]["execution_authority_granted"] is False

    recognized = client.post(
        f"/api/v2/market/resource-profiles/{profile.digest}/recognition",
        headers=headers,
        json={
            "accepted": True,
            "idempotency_key": "recognize-widget-0001",
        },
    )
    assert recognized.status_code == 200, recognized.text
    assert recognized.json()["changed"] is True
    assert recognized.json()["profile"]["recognized"] is True

    event_types = [
        event.type
        for event in client.app.state.nth.spine.verified_snapshot()
    ]
    assert "market.resource-profile.imported" in event_types
    assert "market.resource-profile.recognition.proposed" in event_types
    assert "market.resource-profile.recognition.applied" in event_types


def test_resource_profile_import_rejects_signature_tamper(tmp_path):
    client, headers = _authorized_client(tmp_path)
    document = copy.deepcopy(_profile("tamper").to_dict())
    document["summary"] = "Tampered after signing."

    response = client.post(
        "/api/v2/market/resource-profiles/import",
        headers=headers,
        json={"document": document},
    )

    assert response.status_code == 422
    assert not (tmp_path / "market" / "resource_profiles").exists()


def test_resource_profile_import_rejects_oversized_body_before_json_parse(tmp_path):
    client, headers = _authorized_client(tmp_path)
    payload = b'{"document":{"padding":"' + (b"x" * (256 * 1024)) + b'"}}'

    response = client.post(
        "/api/v2/market/resource-profiles/import",
        headers={**headers, "Content-Type": "application/json"},
        content=payload,
    )

    assert response.status_code == 413
    assert response.json()["detail"] == "Resource Profile body exceeds 256 KiB"


def test_resource_profile_list_surfaces_damaged_policy(tmp_path):
    client, headers = _authorized_client(tmp_path)
    policy_path = tmp_path / "market" / "resource_profile_policy.json"
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    policy_path.write_text("{broken", encoding="utf-8")

    response = client.get(
        "/api/v2/market/resource-profiles",
        headers=headers,
    )

    assert response.status_code == 503
    assert "policy" in response.json()["detail"].lower()


def test_recognition_idempotency_conflict_precedes_policy_mutation(tmp_path):
    client, headers = _authorized_client(tmp_path)
    first = _profile("first")
    second = _profile("second")
    for profile in (first, second):
        response = client.post(
            "/api/v2/market/resource-profiles/import",
            headers=headers,
            json={"document": profile.to_dict()},
        )
        assert response.status_code == 200, response.text

    key = "shared-idempotency-0001"
    accepted = client.post(
        f"/api/v2/market/resource-profiles/{first.digest}/recognition",
        headers=headers,
        json={"accepted": True, "idempotency_key": key},
    )
    assert accepted.status_code == 200, accepted.text

    conflict = client.post(
        f"/api/v2/market/resource-profiles/{second.digest}/recognition",
        headers=headers,
        json={"accepted": True, "idempotency_key": key},
    )
    assert conflict.status_code == 409

    listed = client.get(
        "/api/v2/market/resource-profiles",
        headers=headers,
    ).json()["items"]
    recognition = {item["digest"]: item["recognized"] for item in listed}
    assert recognition == {first.digest: True, second.digest: False}


def test_resource_profile_api_paginates_by_digest_cursor(tmp_path):
    client, headers = _authorized_client(tmp_path)
    profiles = [_profile("page-a"), _profile("page-b"), _profile("page-c")]
    for profile in profiles:
        response = client.post(
            "/api/v2/market/resource-profiles/import",
            headers=headers,
            json={"document": profile.to_dict()},
        )
        assert response.status_code == 200, response.text

    first = client.get(
        "/api/v2/market/resource-profiles",
        headers=headers,
        params={"limit": 1},
    )
    assert first.status_code == 200, first.text
    first_page = first.json()
    assert first_page["count"] == 3
    assert first_page["returned"] == 1
    assert first_page["truncated"] is True
    assert first_page["next_cursor"] == first_page["items"][0]["digest"]

    second = client.get(
        "/api/v2/market/resource-profiles",
        headers=headers,
        params={"limit": 2, "cursor": first_page["next_cursor"]},
    )
    assert second.status_code == 200, second.text
    second_page = second.json()
    assert second_page["count"] == 3
    assert second_page["returned"] == 2
    assert second_page["next_cursor"] == ""
    assert second_page["truncated"] is False
    assert not ({first_page["items"][0]["digest"]} & {
        item["digest"] for item in second_page["items"]
    })

    invalid = client.get(
        "/api/v2/market/resource-profiles",
        headers=headers,
        params={"cursor": "not-a-digest"},
    )
    assert invalid.status_code == 400
