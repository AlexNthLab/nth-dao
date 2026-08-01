from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from nth_dao.cap_token import (
    CAP_NTH_POST_MESSAGE,
    encode_authorization_header,
    sign_cap_token,
)
from nth_dao.identity import (
    AgentIdentity,
    crypto_available,
    default_identity_path,
)
from nth_dao.trade_rules import (
    RuleRecognitionPolicyStoreError,
    RuleRecognitionTrustPolicy,
    TradeRuleRecognition,
    build_rule_package,
    create_rule_recognition_policy,
)
from nth_dao.trade_rules.recognition_conformance import VECTORS_PATH
from nth_dao.web import create_app
from nth_dao.web.rate_limit import RateLimiter

pytestmark = pytest.mark.skipif(
    not crypto_available(),
    reason="Recognition policy requires PyNaCl",
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
    return package, TradeRuleRecognition.from_dict(vectors["recognized"])


def _client(tmp_path, *, require_console_auth: bool = False):
    app = create_app(
        tmp_path,
        require_console_auth=require_console_auth,
    )
    client = TestClient(app)
    package, statement = _artifacts()
    app.state.nth.trade_rule_packages.install(
        package.manifest,
        package.resources,
    )
    node = app.state.nth.node_identity
    policy = create_rule_recognition_policy(
        node,
        node_did=node.as_did(),
        trust_policy=RuleRecognitionTrustPolicy(
            trusted_issuers={statement.to_dict()["issuer_did"]},
            threshold=1,
            issuer_rule_scopes={
                statement.to_dict()["issuer_did"]: ("*",),
            },
        ),
        issued_at="2026-08-01T00:00:00Z",
        now=datetime(2026, 8, 1, tzinfo=timezone.utc),
    )
    return client, package, statement, policy


def _console_headers(client: TestClient) -> dict[str, str]:
    return {
        "Authorization": (
            f"Bearer {client.app.state.nth_console_token}"
        )
    }


def _attacker_cap_headers() -> dict[str, str]:
    attacker = AgentIdentity.generate(label="untrusted-policy-writer")
    token = sign_cap_token(
        issuer=attacker,
        subject_did=attacker.as_did(),
        capabilities=[CAP_NTH_POST_MESSAGE],
    )
    return {
        "Authorization": (
            f"CapToken {encode_authorization_header(token)}"
        )
    }


def _evaluation_url(package_digest: str) -> str:
    return (
        f"/api/v2/trade/rule-packages/{package_digest}"
        "/recognition-evaluation"
    )


def _recognition_url(package_digest: str) -> str:
    return (
        f"/api/v2/trade/rule-packages/{package_digest}/recognitions"
    )


def test_policy_api_records_lists_and_retries_idempotently(tmp_path):
    client, _package, _statement, policy = _client(tmp_path)
    headers = _console_headers(client)

    first = client.post(
        "/api/v2/trade/recognition-policy",
        json=policy.to_dict(),
        headers=headers,
    )
    duplicate = client.post(
        "/api/v2/trade/recognition-policy",
        json=policy.to_dict(),
        headers=headers,
    )
    listed = client.get(
        "/api/v2/trade/recognition-policy",
        headers=_console_headers(client),
    )

    assert first.status_code == 200
    assert first.json()["store_created"] is True
    assert first.json()["anchor_created"] is True
    assert duplicate.status_code == 200
    assert duplicate.json()["store_created"] is False
    assert duplicate.json()["anchor_created"] is False
    assert duplicate.json()["audit_event_id"] == first.json()["audit_event_id"]
    assert listed.status_code == 200
    assert listed.json()["head_digest"] == policy.digest
    assert listed.json()["items"] == [policy.to_dict()]
    assert listed.json()["has_more"] is False


def test_policy_api_survives_authorized_identity_rotation(tmp_path):
    client, _package, _statement, _policy = _client(tmp_path)
    old_identity = client.app.state.nth.node_identity
    replacement = AgentIdentity.generate(label="replacement-node-key")
    issuer = AgentIdentity.generate(label="issuer")
    first = create_rule_recognition_policy(
        old_identity,
        node_did=old_identity.as_did(),
        controllers=[old_identity.as_did(), replacement.as_did()],
        trust_policy=RuleRecognitionTrustPolicy(
            trusted_issuers={issuer.as_did()},
            threshold=1,
            issuer_rule_scopes={issuer.as_did(): ("*",)},
        ),
        issued_at="2026-08-01T00:00:00Z",
        now=datetime(2026, 8, 1, tzinfo=timezone.utc),
    )
    recorded = client.post(
        "/api/v2/trade/recognition-policy",
        json=first.to_dict(),
        headers=_console_headers(client),
    )
    assert recorded.status_code == 200
    replacement.save(default_identity_path(tmp_path))

    restarted = TestClient(create_app(tmp_path))
    policy_store = restarted.app.state.nth.trade_rule_recognition_policy_store
    assert policy_store.node_did == old_identity.as_did()
    successor = create_rule_recognition_policy(
        replacement,
        node_did=old_identity.as_did(),
        controllers=[replacement.as_did()],
        trust_policy=first.trust_policy,
        issued_at="2026-08-01T00:00:01Z",
        previous=first,
        now=datetime(2026, 8, 1, 0, 0, 1, tzinfo=timezone.utc),
    )
    advanced = restarted.post(
        "/api/v2/trade/recognition-policy",
        json=successor.to_dict(),
        headers=_console_headers(restarted),
    )

    assert advanced.status_code == 200
    assert advanced.json()["policy_digest"] == successor.digest
    assert policy_store.head() == successor


def test_policy_api_rejects_tampering_without_persistence(tmp_path):
    client, _package, _statement, policy = _client(tmp_path)
    tampered = policy.to_dict()
    tampered["threshold"] = 2

    response = client.post(
        "/api/v2/trade/recognition-policy",
        json=tampered,
        headers=_console_headers(client),
    )

    assert response.status_code == 400
    assert client.app.state.nth.trade_rule_recognition_policy_store.head() is None


def test_policy_api_never_degrades_to_unaudited_store(tmp_path):
    client, _package, _statement, policy = _client(tmp_path)
    state = client.app.state.nth
    state.trade_rule_recognition_policy_audit = None

    response = client.post(
        "/api/v2/trade/recognition-policy",
        json=policy.to_dict(),
        headers=_console_headers(client),
    )

    assert response.status_code == 503
    assert "unaudited" in response.json()["detail"]
    assert state.trade_rule_recognition_policy_store.head() is None


def test_policy_reconcile_repairs_store_first_crash(tmp_path):
    client, _package, _statement, policy = _client(tmp_path)
    state = client.app.state.nth
    state.trade_rule_recognition_policy_store.append(policy)

    unavailable = client.get(
        "/api/v2/trade/recognition-policy",
        headers=_console_headers(client),
    )
    repaired = client.post(
        "/api/v2/trade/recognition-policy/reconcile",
        params={"limit": 1},
        headers=_console_headers(client),
    )
    available = client.get(
        "/api/v2/trade/recognition-policy",
        headers=_console_headers(client),
    )

    assert unavailable.status_code == 503
    assert unavailable.json()["detail"] == {
        "code": "recognition-policy-integrity-failed",
        "message": "Recognition policy integrity check failed",
    }
    assert repaired.status_code == 200
    assert repaired.json()["anchored"] == 1
    assert repaired.json()["remaining"] == 0
    assert available.status_code == 200
    assert available.json()["head_digest"] == policy.digest


def test_policy_evaluation_is_advisory_and_audit_bound(tmp_path):
    client, package, statement, policy = _client(tmp_path)
    headers = _console_headers(client)
    recorded = client.post(
        "/api/v2/trade/recognition-policy",
        json=policy.to_dict(),
        headers=headers,
    )
    assert recorded.status_code == 200

    before = client.get(
        _evaluation_url(package.digest),
        params={"at": "2026-08-01T00:00:00Z"},
        headers=headers,
    )
    recognized = client.post(
        _recognition_url(package.digest),
        json=statement.to_dict(),
    )
    after = client.get(
        _evaluation_url(package.digest),
        params={"at": "2026-08-01T00:00:00Z"},
        headers=headers,
    )

    assert before.status_code == 200
    assert before.json()["snapshot"]["observed_quorum_met"] is False
    assert recognized.status_code == 200
    assert after.status_code == 200
    assert after.json()["snapshot"]["observed_quorum_met"] is True
    assert after.json()["advisory"] is True
    assert after.json()["execution_authorized"] is False
    assert after.json()["policy_digest"] == policy.digest


@pytest.mark.parametrize(
    "at",
    [
        "2026-02-30T00:00:00Z",
        "2026-08-01T00:00:00+00:00",
        "2026-08-01T00:00:00.000000Z",
    ],
)
def test_policy_evaluation_rejects_invalid_time(tmp_path, at):
    client, package, _statement, policy = _client(tmp_path)
    client.post(
        "/api/v2/trade/recognition-policy",
        json=policy.to_dict(),
        headers=_console_headers(client),
    )

    response = client.get(
        _evaluation_url(package.digest),
        params={"at": at},
        headers=_console_headers(client),
    )

    assert response.status_code == 400


def test_policy_sensitive_reads_require_console_bearer(tmp_path):
    client, package, _statement, _policy = _client(tmp_path)

    history = client.get("/api/v2/trade/recognition-policy")
    evaluation = client.get(_evaluation_url(package.digest))

    assert history.status_code == 401
    assert evaluation.status_code == 401


def test_policy_write_obeys_console_auth(tmp_path):
    client, _package, _statement, policy = _client(
        tmp_path,
        require_console_auth=True,
    )

    denied = client.post(
        "/api/v2/trade/recognition-policy",
        json=policy.to_dict(),
    )
    allowed = client.post(
        "/api/v2/trade/recognition-policy",
        json=policy.to_dict(),
        headers=_console_headers(client),
    )

    assert denied.status_code in {401, 403}
    assert allowed.status_code == 200


@pytest.mark.parametrize("require_console_auth", [False, True])
def test_policy_write_rejects_self_signed_cap_token(
    tmp_path,
    require_console_auth,
):
    client, _package, _statement, policy = _client(
        tmp_path,
        require_console_auth=require_console_auth,
    )

    response = client.post(
        "/api/v2/trade/recognition-policy",
        json=policy.to_dict(),
        headers=_attacker_cap_headers(),
    )

    assert response.status_code in {401, 403}
    assert client.app.state.nth.trade_rule_recognition_policy_store.head() is None


@pytest.mark.parametrize("require_console_auth", [False, True])
def test_policy_reconcile_rejects_self_signed_cap_token(
    tmp_path,
    require_console_auth,
):
    client, _package, _statement, policy = _client(
        tmp_path,
        require_console_auth=require_console_auth,
    )
    state = client.app.state.nth
    state.trade_rule_recognition_policy_store.append(policy)

    response = client.post(
        "/api/v2/trade/recognition-policy/reconcile",
        params={"limit": 1},
        headers=_attacker_cap_headers(),
    )

    assert response.status_code in {401, 403}
    ok, reason = state.trade_rule_recognition_policy_audit.verify_anchors()
    assert ok is False
    assert "missing Recognition policy anchor" in reason


def test_policy_write_rejects_oversized_body_before_persistence(tmp_path):
    client, _package, _statement, _policy = _client(tmp_path)

    response = client.post(
        "/api/v2/trade/recognition-policy",
        content=b'{"padding":"' + (b"x" * (256 * 1024)) + b'"}',
        headers={
            **_console_headers(client),
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 413
    assert client.app.state.nth.trade_rule_recognition_policy_store.head() is None


def test_policy_mutations_are_rate_limited(tmp_path):
    client, _package, _statement, policy = _client(tmp_path)
    client.app.state.nth.trade_rule_recognition_policy_limiter = RateLimiter(
        max_per_window=1,
        window_seconds=60.0,
    )
    headers = _console_headers(client)

    first = client.post(
        "/api/v2/trade/recognition-policy",
        json=policy.to_dict(),
        headers=headers,
    )
    limited = client.post(
        "/api/v2/trade/recognition-policy",
        json=policy.to_dict(),
        headers=headers,
    )

    assert first.status_code == 200
    assert limited.status_code == 429
    assert int(limited.headers["Retry-After"]) >= 1


def test_policy_service_error_does_not_leak_local_path(tmp_path, monkeypatch):
    client, _package, _statement, policy = _client(tmp_path)
    leaked = "/private/operator/secret-policy.json"
    coordinator = client.app.state.nth.trade_rule_recognition_policy_audit

    def _fail(_policy):
        raise RuleRecognitionPolicyStoreError(leaked)

    monkeypatch.setattr(coordinator, "record", _fail)
    response = client.post(
        "/api/v2/trade/recognition-policy",
        json=policy.to_dict(),
        headers=_console_headers(client),
    )

    assert response.status_code == 503
    assert response.json()["detail"] == {
        "code": "recognition-policy-unavailable",
        "message": "Recognition policy service is unavailable",
    }
    assert leaked not in response.text
    assert "/private/operator" not in response.text
