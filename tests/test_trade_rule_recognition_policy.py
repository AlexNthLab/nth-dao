from __future__ import annotations

import copy
from datetime import datetime, timezone

import pytest

from nth_dao.identity import AgentIdentity, crypto_available
from nth_dao.trade_rules.recognition import RuleRecognitionTrustPolicy
from nth_dao.trade_rules.recognition_policy import (
    RULE_RECOGNITION_POLICY_SIGNING_DOMAIN,
    TradeRuleRecognitionPolicy,
    TradeRuleRecognitionPolicyRejected,
    create_rule_recognition_policy,
    verify_rule_recognition_policy_successor,
)
from nth_dao.trade_rules.signing import (
    encode_ed25519_signature,
    signed_document_input,
)

pytestmark = pytest.mark.skipif(
    not crypto_available(),
    reason="Recognition policy requires PyNaCl",
)


def _trust(*issuers: str, threshold: int = 1):
    return RuleRecognitionTrustPolicy(
        trusted_issuers=frozenset(issuers),
        threshold=threshold,
        max_statement_ttl_seconds=86_400,
        issuer_rule_scopes={
            issuer: ("*",) if index == 0 else ("org.nthdao.delivery",)
            for index, issuer in enumerate(issuers)
        },
    )


def _first():
    node = AgentIdentity.generate(label="node")
    issuer_a = AgentIdentity.generate(label="issuer-a")
    issuer_b = AgentIdentity.generate(label="issuer-b")
    policy = create_rule_recognition_policy(
        node,
        node_did=node.as_did(),
        trust_policy=_trust(
            issuer_a.as_did(),
            issuer_b.as_did(),
            threshold=2,
        ),
        issued_at="2026-08-01T00:00:00Z",
        now=datetime(2026, 8, 1, tzinfo=timezone.utc),
    )
    return node, issuer_a, issuer_b, policy


def test_signed_policy_round_trip_and_projection():
    node, issuer_a, issuer_b, policy = _first()

    loaded = TradeRuleRecognitionPolicy.from_json(policy.canonical_bytes)
    document = loaded.to_dict()

    assert document["node_did"] == node.as_did()
    assert document["signer_did"] == node.as_did()
    assert document["sequence"] == 1
    assert document["previous_policy_digest"] is None
    assert document["policy_id"].startswith(
        "nth-trade-recognition-policy-sha256:"
    )
    assert loaded.digest == policy.digest
    assert loaded.trust_policy.threshold == 2
    assert loaded.trust_policy.trusted_issuers == frozenset(
        {issuer_a.as_did(), issuer_b.as_did()}
    )


def test_successor_may_be_signed_by_another_authorized_identity():
    node = AgentIdentity.generate(label="node")
    issuer_a = AgentIdentity.generate(label="issuer-a")
    issuer_b = AgentIdentity.generate(label="issuer-b")
    admin = AgentIdentity.generate(label="admin")
    first = create_rule_recognition_policy(
        node,
        node_did=node.as_did(),
        trust_policy=_trust(issuer_a.as_did(), issuer_b.as_did()),
        controllers=[node.as_did(), admin.as_did()],
        issued_at="2026-08-01T00:00:00Z",
        now=datetime(2026, 8, 1, tzinfo=timezone.utc),
    )
    second = create_rule_recognition_policy(
        admin,
        node_did=node.as_did(),
        trust_policy=_trust(issuer_a.as_did(), issuer_b.as_did()),
        issued_at="2026-08-01T00:00:01Z",
        previous=first,
        now=datetime(2026, 8, 1, 0, 0, 1, tzinfo=timezone.utc),
    )

    verify_rule_recognition_policy_successor(first, second)
    assert second.to_dict()["sequence"] == 2
    assert second.to_dict()["previous_policy_digest"] == first.digest
    assert second.to_dict()["signer_did"] == admin.as_did()


def test_genesis_and_successor_controller_authorization():
    node, issuer_a, issuer_b, first = _first()
    stranger = AgentIdentity.generate(label="stranger")

    with pytest.raises(
        TradeRuleRecognitionPolicyRejected,
        match="genesis policy",
    ):
        create_rule_recognition_policy(
            stranger,
            node_did=node.as_did(),
            trust_policy=_trust(issuer_a.as_did()),
            issued_at="2026-08-01T00:00:00Z",
            now=datetime(2026, 8, 1, tzinfo=timezone.utc),
        )
    with pytest.raises(
        TradeRuleRecognitionPolicyRejected,
        match="authorized controller",
    ):
        create_rule_recognition_policy(
            stranger,
            node_did=node.as_did(),
            trust_policy=_trust(issuer_a.as_did(), issuer_b.as_did()),
            issued_at="2026-08-01T00:00:01Z",
            previous=first,
            now=datetime(2026, 8, 1, 0, 0, 1, tzinfo=timezone.utc),
        )


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda value: value.update({"threshold": 1}), "signature invalid"),
        (lambda value: value.update({"node_did": "did:key:zBad"}), "node_did"),
        (lambda value: value.update({"sequence": True}), "sequence"),
        (lambda value: value.update({"controllers": []}), "controllers"),
        (
            lambda value: value.update(
                {"issued_at": "2026-02-30T00:00:00Z"}
            ),
            "real timestamp",
        ),
        (
            lambda value: value["trusted_issuers"].reverse(),
            "sorted and unique",
        ),
        (
            lambda value: value["trusted_issuers"][0][
                "rule_scopes"
            ].append("*"),
            "unique",
        ),
        (lambda value: value.update({"unexpected": True}), "unknown fields"),
    ],
)
def test_policy_rejects_tamper_and_noncanonical_semantics(mutate, message):
    _node, _issuer_a, _issuer_b, policy = _first()
    document = copy.deepcopy(policy.to_dict())
    mutate(document)

    with pytest.raises(TradeRuleRecognitionPolicyRejected, match=message):
        TradeRuleRecognitionPolicy.from_dict(document)


def test_successor_rejects_wrong_predecessor_and_time_regression():
    node, issuer_a, issuer_b, first = _first()
    second = create_rule_recognition_policy(
        node,
        node_did=node.as_did(),
        trust_policy=_trust(issuer_a.as_did(), issuer_b.as_did()),
        issued_at="2026-08-01T00:00:01Z",
        previous=first,
        now=datetime(2026, 8, 1, 0, 0, 1, tzinfo=timezone.utc),
    )
    wrong_previous = copy.deepcopy(second.to_dict())
    wrong_previous["previous_policy_digest"] = "sha256:" + ("0" * 64)
    signing_input = signed_document_input(
        RULE_RECOGNITION_POLICY_SIGNING_DOMAIN,
        wrong_previous,
    )
    wrong_previous["proof"]["proof_value"] = encode_ed25519_signature(
        node.sign(signing_input)
    )

    with pytest.raises(
        TradeRuleRecognitionPolicyRejected,
        match="predecessor digest mismatch",
    ):
        verify_rule_recognition_policy_successor(first, wrong_previous)

    with pytest.raises(
        TradeRuleRecognitionPolicyRejected,
        match="predates previous",
    ):
        create_rule_recognition_policy(
            node,
            node_did=node.as_did(),
            trust_policy=_trust(issuer_a.as_did(), issuer_b.as_did()),
            issued_at="2026-07-31T23:59:59Z",
            previous=first,
            now=datetime(2026, 7, 31, 23, 59, 59, tzinfo=timezone.utc),
        )


def test_create_rejects_clock_skew_and_foreign_previous():
    node, issuer_a, issuer_b, first = _first()
    other = AgentIdentity.generate(label="other-node")

    with pytest.raises(
        TradeRuleRecognitionPolicyRejected,
        match="clock-skew",
    ):
        create_rule_recognition_policy(
            node,
            node_did=node.as_did(),
            trust_policy=_trust(issuer_a.as_did()),
            issued_at="2026-08-01T01:00:00Z",
            now=datetime(2026, 8, 1, tzinfo=timezone.utc),
        )
    with pytest.raises(
        TradeRuleRecognitionPolicyRejected,
        match="another node",
    ):
        create_rule_recognition_policy(
            node,
            node_did=other.as_did(),
            trust_policy=_trust(issuer_a.as_did(), issuer_b.as_did()),
            issued_at="2026-08-01T00:00:01Z",
            previous=first,
            now=datetime(2026, 8, 1, 0, 0, 1, tzinfo=timezone.utc),
        )
