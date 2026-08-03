from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from nth_dao.identity import crypto_available
from nth_dao.trade_rules import (
    EVENT_TRADE_RULE_RECOGNITION_RECORDED,
    TradeRuleRecognition,
    build_rule_package,
    rule_recognition_audit_payload,
)
from nth_dao.trade_rules.recognition_conformance import VECTORS_PATH
from nth_dao.web import create_app

pytestmark = pytest.mark.skipif(
    not crypto_available(),
    reason="Trade Rule Recognition requires PyNaCl",
)


def _artifacts():
    vectors = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    package = build_rule_package(
        vectors["package_manifest"],
        {
            digest: bytes.fromhex(payload)
            for digest, payload in vectors["package_resources_hex"].items()
        },
    )
    return (
        vectors,
        package,
        TradeRuleRecognition.from_dict(vectors["recognized"]),
        TradeRuleRecognition.from_dict(vectors["revoked"]),
    )


def _client(tmp_path):
    client = TestClient(
        create_app(tmp_path, require_console_auth=False)
    )
    _vectors, package, _recognized, _revoked = _artifacts()
    installed = client.app.state.nth.trade_rule_packages.install(
        package.manifest,
        package.resources,
    )
    assert installed.digest == package.digest
    return client, package


def _url(package_digest: str, suffix: str = "") -> str:
    return (
        f"/api/v2/trade/rule-packages/{package_digest}"
        f"/recognitions{suffix}"
    )


def test_recognition_api_records_lists_and_retries_idempotently(tmp_path):
    client, package = _client(tmp_path)
    _vectors, _package, statement, _revoked = _artifacts()

    first = client.post(_url(package.digest), json=statement.to_dict())
    duplicate = client.post(
        _url(package.digest),
        json=statement.to_dict(),
    )
    listed = client.get(_url(package.digest))
    rules = client.get("/api/v2/rules")
    trade_skills = client.get(
        "/api/v2/trade/rule-packages",
        headers={
            "Authorization": (
                f"Bearer {client.app.state.nth_console_token}"
            )
        },
    )

    assert first.status_code == 200
    assert first.json()["store_created"] is True
    assert first.json()["anchor_created"] is True
    assert first.json()["audit_event_id"]
    assert duplicate.status_code == 200
    assert duplicate.json()["store_created"] is False
    assert duplicate.json()["anchor_created"] is False
    assert (
        duplicate.json()["audit_event_id"]
        == first.json()["audit_event_id"]
    )
    assert listed.status_code == 200
    assert listed.json()["items"] == [statement.to_dict()]
    assert rules.json() == []
    assert trade_skills.status_code == 200
    assert [
        item["package_digest"] for item in trade_skills.json()["items"]
    ] == [package.digest]


def test_recognition_api_rejects_invalid_or_uninstalled_input(tmp_path):
    client, package = _client(tmp_path)
    vectors, _package, statement, _revoked = _artifacts()

    tampered = statement.to_dict()
    tampered["not_after"] = "2026-08-19T00:00:00Z"
    invalid = client.post(_url(package.digest), json=tampered)
    missing = client.post(
        _url("sha256:" + ("0" * 64)),
        json=statement.to_dict(),
    )
    wrong_type = client.post(
        _url(package.digest),
        content=json.dumps(vectors["recognized"]),
        headers={"Content-Type": "text/plain"},
    )

    assert invalid.status_code == 400
    assert "signature invalid" in invalid.json()["detail"]
    assert missing.status_code == 404
    assert wrong_type.status_code == 415
    assert client.get(_url(package.digest)).json()["items"] == []


def test_recognition_api_never_degrades_to_unaudited_cas(tmp_path):
    client, package = _client(tmp_path)
    _vectors, _package, statement, _revoked = _artifacts()
    client.app.state.nth.trade_rule_recognition_audit = None

    response = client.post(
        _url(package.digest),
        json=statement.to_dict(),
    )

    assert response.status_code == 503
    assert "unaudited" in response.json()["detail"]
    assert (
        client.app.state.nth.trade_rule_recognitions.list_for_package(
            package
        )
        == ()
    )


def test_recognition_api_fails_closed_on_orphan_rollback(tmp_path):
    client, package = _client(tmp_path)
    _vectors, _package, recognized, revoked = _artifacts()
    state = client.app.state.nth
    state.spine.append(
        EVENT_TRADE_RULE_RECOGNITION_RECORDED,
        rule_recognition_audit_payload(recognized, package=package),
        ts_ms=1_785_542_400_000,
    )

    response = client.post(
        _url(package.digest),
        json=revoked.to_dict(),
    )

    assert response.status_code == 503
    assert "rollback evidence" in response.json()["detail"]
    assert state.trade_rule_recognitions.list_for_package(package) == ()
    assert len(state.spine.verified_snapshot()) == 1


def test_recognition_api_reconcile_repairs_store_first_crash(tmp_path):
    client, package = _client(tmp_path)
    _vectors, _package, statement, _revoked = _artifacts()
    state = client.app.state.nth
    imported = state.trade_rule_recognitions.import_json(
        statement.canonical_bytes,
        package=package,
    )
    assert imported.accepted
    assert state.spine.verified_snapshot() == ()

    unavailable = client.get(_url(package.digest))
    assert unavailable.status_code == 503
    assert "missing Recognition anchor" in unavailable.json()["detail"]

    repaired = client.post(
        _url(package.digest, "/reconcile"),
        params={"limit": 1},
    )

    assert repaired.status_code == 200
    assert repaired.json()["anchored"] == 1
    assert repaired.json()["remaining"] == 0
    assert (
        state.trade_rule_recognition_audit.verify_anchors(
            package=package
        )
        == (True, "ok")
    )


def test_recognition_write_rejects_oversized_body_before_persistence(
    tmp_path,
):
    client, package = _client(tmp_path)

    response = client.post(
        _url(package.digest),
        content=b'{"padding":"' + (b"x" * (256 * 1024)) + b'"}',
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 413
    assert (
        client.app.state.nth.trade_rule_recognitions.list_for_package(
            package
        )
        == ()
    )
    assert client.app.state.nth.spine.verified_snapshot() == ()


def test_recognition_write_obeys_console_auth(tmp_path):
    app = create_app(tmp_path, require_console_auth=True)
    client = TestClient(app)
    _vectors, package, statement, _revoked = _artifacts()
    app.state.nth.trade_rule_packages.install(
        package.manifest,
        package.resources,
    )

    denied = client.post(
        _url(package.digest),
        json=statement.to_dict(),
    )

    assert denied.status_code in {401, 403}
    assert (
        app.state.nth.trade_rule_recognitions.list_for_package(
            package
        )
        == ()
    )
