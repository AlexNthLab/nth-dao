import copy
import hashlib
import json
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from nth_dao.identity import AgentIdentity, crypto_available
from nth_dao.trade_rules.manifest import manifest_body, sign_manifest
from nth_dao.trade_rules.package_store import build_rule_package
from nth_dao.trade_rules.recognition import (
    RULE_RECOGNITION_SIGNING_DOMAIN,
    RuleRecognitionTrustPolicy,
    TradeRuleRecognition,
    TradeRuleRecognitionRejected,
    create_rule_recognition,
    evaluate_rule_recognition,
    rule_recognition_digest,
    verify_rule_recognition_binding,
)
from nth_dao.trade_rules.recognition_conformance import (
    SCHEMA_PATH,
    VECTORS_PATH,
    generate_vectors,
)
from nth_dao.trade_rules.signing import signed_document_input

pytestmark = pytest.mark.skipif(
    not crypto_available(),
    reason="Trade Rule signatures require PyNaCl",
)

_AT = datetime(2026, 8, 1, 12, tzinfo=timezone.utc)


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _package(
    publisher: AgentIdentity | None = None,
    *,
    rule_id: str = "org.nthdao.community.exchange",
):
    identity = publisher or AgentIdentity.generate(label="publisher")
    resource = b'{"type":"object"}'
    resource_digest = _digest(resource)
    body = manifest_body(
        rule_id=rule_id,
        version="1.0.0",
        publisher_did=identity.as_did(),
        summary="Community-defined exchange procedure",
        applies_to=["product", "service"],
        families=["acceptance", "dispute", "fulfillment"],
        resources=[
            {
                "purpose": "terms",
                "media_type": "application/json",
                "digest": resource_digest,
                "size": len(resource),
            }
        ],
        published_at="2026-07-31T00:00:00Z",
        not_after="2027-07-31T00:00:00Z",
    )
    manifest = sign_manifest(
        identity,
        body,
        created="2026-07-31T00:00:00Z",
    )
    return build_rule_package(manifest, {resource_digest: resource})


def _recognize(
    issuer: AgentIdentity,
    package,
    *,
    issued_at: str = "2026-08-01T00:00:00Z",
    previous=None,
    decision: str = "recognized",
    reasons=(),
    not_after: str = "2026-08-20T00:00:00Z",
):
    return create_rule_recognition(
        issuer,
        package=package,
        decision=decision,
        issued_at=issued_at,
        previous=previous,
        reason_codes=reasons,
        not_after=not_after,
        now=datetime.fromisoformat(issued_at.replace("Z", "+00:00")),
    )


def _policy(
    trusted_issuers,
    *,
    threshold: int = 1,
    scopes=None,
    **kwargs,
):
    issuers = set(trusted_issuers)
    return RuleRecognitionTrustPolicy(
        trusted_issuers=issuers,
        threshold=threshold,
        issuer_rule_scopes=(
            scopes
            if scopes is not None
            else {issuer: ("*",) for issuer in issuers}
        ),
        **kwargs,
    )


def test_recognition_round_trip_and_exact_package_binding():
    package = _package()
    issuer = AgentIdentity.generate(label="community-reviewer")
    statement = _recognize(issuer, package)

    loaded = TradeRuleRecognition.from_json(statement.canonical_bytes)
    assert loaded.canonical_bytes == statement.canonical_bytes
    assert loaded.to_dict()["issuer_did"] == issuer.as_did()
    assert loaded.to_dict()["package_digest"] == package.digest
    assert loaded.digest == rule_recognition_digest(loaded)
    assert (
        verify_rule_recognition_binding(loaded, package).canonical_bytes
        == loaded.canonical_bytes
    )


def test_recognition_rejects_signature_and_binding_tampering():
    package = _package()
    other_package = _package(rule_id="org.nthdao.community.other")
    issuer = AgentIdentity.generate()
    statement = _recognize(issuer, package)

    tampered = statement.to_dict()
    tampered["decision"] = "revoked"
    tampered["reason_codes"] = ["security.malware"]
    with pytest.raises(TradeRuleRecognitionRejected, match="signature invalid"):
        TradeRuleRecognition.from_dict(tampered)
    with pytest.raises(
        TradeRuleRecognitionRejected,
        match="package_digest does not match",
    ):
        verify_rule_recognition_binding(statement, other_package)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("sequence", True, "sequence is invalid"),
        ("previous_statement_digest", "sha256:BAD", "cannot have a predecessor"),
        ("decision", "approved", "decision is invalid"),
        ("reason_codes", ["Bad reason"], "reason_codes"),
        ("issued_at", "2026-08-01T00:00:00.000000Z", "issued_at"),
    ],
)
def test_recognition_rejects_malformed_wire_values(field, value, message):
    package = _package()
    issuer = AgentIdentity.generate()
    document = _recognize(issuer, package).to_dict()
    document[field] = value
    with pytest.raises(TradeRuleRecognitionRejected, match=message):
        TradeRuleRecognition.from_dict(document)


def test_negative_decision_requires_reason_and_chains_exact_predecessor():
    package = _package()
    issuer = AgentIdentity.generate()
    first = _recognize(issuer, package)

    with pytest.raises(TradeRuleRecognitionRejected, match="require a reason"):
        _recognize(
            issuer,
            package,
            previous=first,
            decision="revoked",
            issued_at="2026-08-01T00:01:00Z",
        )
    second = _recognize(
        issuer,
        package,
        previous=first,
        decision="revoked",
        reasons=["security.malware"],
        issued_at="2026-08-01T00:01:00Z",
    )
    assert second.to_dict()["sequence"] == 2
    assert second.to_dict()["previous_statement_digest"] == first.digest


def test_predecessor_must_match_issuer_package_and_time():
    package = _package()
    other = _package(rule_id="org.nthdao.community.other")
    first_issuer = AgentIdentity.generate()
    second_issuer = AgentIdentity.generate()
    first = _recognize(first_issuer, package)

    with pytest.raises(
        TradeRuleRecognitionRejected,
        match="another issuer",
    ):
        _recognize(
            second_issuer,
            package,
            previous=first,
            issued_at="2026-08-01T00:01:00Z",
        )
    with pytest.raises(
        TradeRuleRecognitionRejected,
        match="package_digest does not match",
    ):
        _recognize(
            first_issuer,
            other,
            previous=first,
            issued_at="2026-08-01T00:01:00Z",
        )
    with pytest.raises(
        TradeRuleRecognitionRejected,
        match="precedes its predecessor",
    ):
        _recognize(
            first_issuer,
            package,
            previous=first,
            issued_at="2026-07-31T23:59:59Z",
        )


def test_local_threshold_requires_independent_current_recognitions():
    package = _package()
    first_issuer = AgentIdentity.generate()
    second_issuer = AgentIdentity.generate()
    policy = _policy(
        trusted_issuers={
            first_issuer.as_did(),
            second_issuer.as_did(),
        },
        threshold=2,
    )
    first = _recognize(first_issuer, package)
    one_vote = evaluate_rule_recognition(
        package,
        [first],
        policy=policy,
        at=_AT,
    )
    assert not one_vote.observed_quorum_met
    assert one_vote.recognized_by == (first_issuer.as_did(),)

    second = _recognize(second_issuer, package)
    two_votes = evaluate_rule_recognition(
        package,
        [second, first],
        policy=policy,
        at=_AT,
    )
    assert two_votes.observed_quorum_met
    assert two_votes.quorum_valid_until == "2026-08-20T00:00:00Z"
    assert set(two_votes.recognized_by) == {
        first_issuer.as_did(),
        second_issuer.as_did(),
    }


def test_revocation_removes_only_that_issuer_vote():
    package = _package()
    issuer = AgentIdentity.generate()
    first = _recognize(issuer, package)
    revoked = _recognize(
        issuer,
        package,
        previous=first,
        decision="revoked",
        reasons=["policy.withdrawn"],
        issued_at="2026-08-01T00:01:00Z",
    )
    snapshot = evaluate_rule_recognition(
        package,
        [revoked, first],
        policy=_policy(
            trusted_issuers={issuer.as_did()},
        ),
        at=_AT,
    )
    assert not snapshot.observed_quorum_met
    assert snapshot.revoked_by == (issuer.as_did(),)
    assert snapshot.issuer_states[0].sequence == 2


def test_expired_recognition_and_future_head_do_not_count():
    package = _package()
    expired_issuer = AgentIdentity.generate()
    future_issuer = AgentIdentity.generate()
    expired = _recognize(
        expired_issuer,
        package,
        issued_at="2026-07-31T00:00:00Z",
        not_after="2026-07-31T12:00:00Z",
    )
    future = _recognize(
        future_issuer,
        package,
        issued_at="2026-08-02T00:00:00Z",
    )
    snapshot = evaluate_rule_recognition(
        package,
        [future, expired],
        policy=_policy(
            trusted_issuers={
                expired_issuer.as_did(),
                future_issuer.as_did(),
            },
        ),
        at=_AT,
    )
    assert not snapshot.observed_quorum_met
    assert snapshot.expired_issuers == (expired_issuer.as_did(),)
    assert snapshot.incomplete_issuers == (future_issuer.as_did(),)


def test_expiry_is_mandatory_and_local_policy_bounds_statement_lifetime():
    package = _package()
    issuer = AgentIdentity.generate()
    document = _recognize(issuer, package).to_dict()
    document["not_after"] = None
    with pytest.raises(TradeRuleRecognitionRejected, match="not_after"):
        TradeRuleRecognition.from_dict(document)

    long_lived = _recognize(
        issuer,
        package,
        not_after="2027-08-01T00:00:00Z",
    )
    snapshot = evaluate_rule_recognition(
        package,
        [long_lived],
        policy=_policy(
            trusted_issuers={issuer.as_did()},
        ),
        at=_AT,
    )
    assert not snapshot.observed_quorum_met
    assert snapshot.issuer_states[0].status == "policy_rejected"


def test_future_successor_does_not_revoke_current_recognition_early():
    package = _package()
    issuer = AgentIdentity.generate()
    current = _recognize(
        issuer,
        package,
        issued_at="2026-08-01T00:00:00Z",
    )
    future_revocation = _recognize(
        issuer,
        package,
        previous=current,
        decision="revoked",
        reasons=["policy.future-withdrawal"],
        issued_at="2026-08-02T00:00:00Z",
    )
    policy = _policy(
        trusted_issuers={issuer.as_did()},
    )
    before = evaluate_rule_recognition(
        package,
        [future_revocation, current],
        policy=policy,
        at=_AT,
    )
    assert before.observed_quorum_met
    assert before.recognized_by == (issuer.as_did(),)
    assert before.issuer_states[0].sequence == 1

    after = evaluate_rule_recognition(
        package,
        [current, future_revocation],
        policy=policy,
        at=datetime(2026, 8, 2, 1, tzinfo=timezone.utc),
    )
    assert not after.observed_quorum_met
    assert after.revoked_by == (issuer.as_did(),)
    assert after.issuer_states[0].sequence == 2


def test_forked_or_incomplete_issuer_chain_fails_closed():
    package = _package()
    issuer = AgentIdentity.generate()
    first = _recognize(issuer, package)
    second = _recognize(
        issuer,
        package,
        previous=first,
        issued_at="2026-08-01T00:01:00Z",
    )
    fork = _recognize(
        issuer,
        package,
        previous=first,
        decision="revoked",
        reasons=["policy.changed"],
        issued_at="2026-08-01T00:02:00Z",
    )
    policy = _policy(
        trusted_issuers={issuer.as_did()},
    )
    conflicted = evaluate_rule_recognition(
        package,
        [first, second, fork],
        policy=policy,
        at=_AT,
    )
    assert not conflicted.observed_quorum_met
    assert conflicted.conflicted_issuers == (issuer.as_did(),)

    incomplete = evaluate_rule_recognition(
        package,
        [second],
        policy=policy,
        at=_AT,
    )
    assert not incomplete.observed_quorum_met
    assert incomplete.incomplete_issuers == (issuer.as_did(),)


def test_wrong_predecessor_and_time_reversal_fail_as_conflicts():
    package = _package()
    issuer = AgentIdentity.generate()
    first = _recognize(issuer, package)
    second = _recognize(
        issuer,
        package,
        previous=first,
        issued_at="2026-08-01T00:02:00Z",
    )
    wrong_predecessor = second.to_dict()
    wrong_predecessor["previous_statement_digest"] = "sha256:" + ("0" * 64)
    wrong_predecessor["proof"]["proof_value"] = (
        "A" * len(wrong_predecessor["proof"]["proof_value"])
    )
    signing_input = signed_document_input(
        RULE_RECOGNITION_SIGNING_DOMAIN,
        wrong_predecessor,
    )
    from nth_dao.trade_rules.signing import encode_ed25519_signature

    wrong_predecessor["proof"]["proof_value"] = encode_ed25519_signature(
        issuer.sign(signing_input)
    )
    wrong = TradeRuleRecognition.from_dict(wrong_predecessor)
    policy = _policy(
        trusted_issuers={issuer.as_did()},
    )
    snapshot = evaluate_rule_recognition(
        package,
        [first, wrong],
        policy=policy,
        at=_AT,
    )
    assert snapshot.conflicted_issuers == (issuer.as_did(),)
    assert not snapshot.observed_quorum_met

    time_reversal = second.to_dict()
    time_reversal["issued_at"] = "2026-07-31T23:59:59Z"
    time_reversal["proof"]["created"] = time_reversal["issued_at"]
    time_reversal["proof"]["proof_value"] = "A" * 86
    time_reversal["proof"]["proof_value"] = encode_ed25519_signature(
        issuer.sign(
            signed_document_input(
                RULE_RECOGNITION_SIGNING_DOMAIN,
                time_reversal,
            )
        )
    )
    reversed_statement = TradeRuleRecognition.from_dict(time_reversal)
    reversed_snapshot = evaluate_rule_recognition(
        package,
        [first, reversed_statement],
        policy=policy,
        at=_AT,
    )
    assert reversed_snapshot.conflicted_issuers == (issuer.as_did(),)
    assert not reversed_snapshot.observed_quorum_met


def test_sparse_maximum_sequence_is_bounded_and_incomplete():
    package = _package()
    issuer = AgentIdentity.generate()
    first = _recognize(issuer, package)
    sparse = first.to_dict()
    sparse["sequence"] = 2_147_483_647
    sparse["previous_statement_digest"] = first.digest
    sparse["issued_at"] = "2026-08-01T00:01:00Z"
    sparse["proof"]["created"] = sparse["issued_at"]
    sparse["proof"]["proof_value"] = "A" * 86
    from nth_dao.trade_rules.signing import encode_ed25519_signature

    sparse["proof"]["proof_value"] = encode_ed25519_signature(
        issuer.sign(
            signed_document_input(
                RULE_RECOGNITION_SIGNING_DOMAIN,
                sparse,
            )
        )
    )
    sparse_statement = TradeRuleRecognition.from_dict(sparse)
    snapshot = evaluate_rule_recognition(
        package,
        [first, sparse_statement],
        policy=_policy(
            trusted_issuers={issuer.as_did()},
        ),
        at=_AT,
    )
    assert not snapshot.observed_quorum_met
    assert snapshot.incomplete_issuers == (issuer.as_did(),)


def test_untrusted_recognition_does_not_count_or_grant_execution():
    package = _package()
    trusted = AgentIdentity.generate()
    outsider = AgentIdentity.generate()
    statement = _recognize(outsider, package)
    snapshot = evaluate_rule_recognition(
        package,
        [statement],
        policy=_policy(
            trusted_issuers={trusted.as_did()},
        ),
        at=_AT,
    )
    assert not snapshot.observed_quorum_met
    assert snapshot.recognized_by == ()
    assert snapshot.issuer_states[0].status == "missing"
    assert not hasattr(snapshot, "approved_executable_digests")


def test_projection_quarantines_tampered_input_without_losing_valid_view():
    package = _package()
    issuer = AgentIdentity.generate()
    statement = _recognize(issuer, package)
    policy = _policy(
        trusted_issuers={issuer.as_did()},
    )
    tampered = copy.deepcopy(statement.to_dict())
    tampered["reason_codes"] = ["policy.changed"]
    projected = evaluate_rule_recognition(
        package,
        [statement, tampered, "not-an-object"],
        policy=policy,
        at=_AT,
    )
    assert projected.observed_quorum_met
    assert projected.quarantined_statement_indexes == (1, 2)
    with pytest.raises(
        TradeRuleRecognitionRejected,
        match="signature invalid",
    ):
        evaluate_rule_recognition(
            package,
            [statement, tampered],
            policy=policy,
            at=_AT,
            strict_invalid=True,
        )


def test_projection_ignores_statements_for_another_package():
    package = _package()
    other = _package(rule_id="org.nthdao.community.other")
    issuer = AgentIdentity.generate()
    statement = _recognize(issuer, package)
    policy = _policy(
        trusted_issuers={issuer.as_did()},
    )
    unrelated = evaluate_rule_recognition(
        other,
        [statement],
        policy=policy,
        at=_AT,
    )
    assert not unrelated.observed_quorum_met
    assert unrelated.issuer_states[0].status == "missing"
    assert unrelated.quarantined_statement_indexes == ()


def test_reason_codes_are_bounded_before_materializing_untrusted_input():
    package = _package()
    issuer = AgentIdentity.generate()

    def too_many():
        for index in range(10_000):
            yield f"reason.{index}"

    with pytest.raises(TradeRuleRecognitionRejected, match="32-entry limit"):
        create_rule_recognition(
            issuer,
            package=package,
            decision="revoked",
            reason_codes=too_many(),
            issued_at="2026-08-01T00:00:00Z",
            not_after="2026-08-20T00:00:00Z",
            now=_AT,
            clock_skew_seconds=24 * 60 * 60,
        )


def test_projection_verifies_rule_package_once_not_once_per_statement():
    package = _package()
    issuer = AgentIdentity.generate()
    first = _recognize(issuer, package)
    second = _recognize(
        issuer,
        package,
        previous=first,
        issued_at="2026-08-01T00:01:00Z",
    )
    import nth_dao.trade_rules.recognition as recognition_module

    original = recognition_module._verified_package
    with patch.object(
        recognition_module,
        "_verified_package",
        wraps=original,
    ) as verified_package:
        snapshot = evaluate_rule_recognition(
            package,
            [first, second],
            policy=_policy(
                trusted_issuers={issuer.as_did()},
            ),
            at=_AT,
        )
    assert snapshot.observed_quorum_met
    assert verified_package.call_count == 1


def test_issuer_rule_scopes_prevent_cross_domain_recognition():
    package = _package()
    community_issuer = AgentIdentity.generate()
    shipping_issuer = AgentIdentity.generate()
    community_statement = _recognize(community_issuer, package)
    shipping_statement = _recognize(shipping_issuer, package)
    policy = _policy(
        {
            community_issuer.as_did(),
            shipping_issuer.as_did(),
        },
        scopes={
            community_issuer.as_did(): ("org.nthdao.community",),
            shipping_issuer.as_did(): ("org.nthdao.shipping",),
        },
    )
    snapshot = evaluate_rule_recognition(
        package,
        [shipping_statement, community_statement],
        policy=policy,
        at=_AT,
    )
    assert snapshot.observed_quorum_met
    assert snapshot.recognized_by == (community_issuer.as_did(),)
    assert snapshot.scope_excluded_issuers == (
        shipping_issuer.as_did(),
    )


def test_trust_policy_rejects_invalid_configuration():
    issuer = AgentIdentity.generate().as_did()
    invalid_cases = [
        {"trusted_issuers": set(), "issuer_rule_scopes": {}},
        {
            "trusted_issuers": "did:key:not-a-set",
            "issuer_rule_scopes": {},
        },
        {
            "trusted_issuers": {"not-a-did"},
            "issuer_rule_scopes": {"not-a-did": ("*",)},
        },
        {
            "trusted_issuers": {issuer},
            "issuer_rule_scopes": {issuer: ("*",)},
            "threshold": 2,
        },
        {
            "trusted_issuers": {issuer},
            "issuer_rule_scopes": {issuer: ("*",)},
            "threshold": True,
        },
        {
            "trusted_issuers": {issuer},
            "issuer_rule_scopes": {},
        },
        {
            "trusted_issuers": {issuer},
            "issuer_rule_scopes": {issuer: ("not a rule",)},
        },
        {
            "trusted_issuers": {issuer},
            "issuer_rule_scopes": {issuer: ("org.nthdao", "org.nthdao")},
        },
    ]
    for kwargs in invalid_cases:
        with pytest.raises(ValueError):
            RuleRecognitionTrustPolicy(**kwargs)


def test_recognition_conformance_vector_is_current_and_replayable():
    stored = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    assert stored == generate_vectors()
    package = build_rule_package(
        stored["package_manifest"],
        {
            digest: bytes.fromhex(payload)
            for digest, payload in stored["package_resources_hex"].items()
        },
    )
    assert package.digest == stored["package_digest"]
    recognized = TradeRuleRecognition.from_dict(stored["recognized"])
    revoked = TradeRuleRecognition.from_dict(stored["revoked"])
    assert (
        recognized.canonical_bytes.hex()
        == stored["expected_recognized_canonical_hex"]
    )
    assert (
        signed_document_input(
            RULE_RECOGNITION_SIGNING_DOMAIN,
            recognized.to_dict(),
        ).hex()
        == stored["expected_recognized_signing_input_hex"]
    )
    snapshot = evaluate_rule_recognition(
        package,
        [recognized, revoked],
        policy=_policy(
            trusted_issuers={stored["issuer_did"]},
        ),
        at=datetime(2026, 8, 3, tzinfo=timezone.utc),
    )
    assert not snapshot.observed_quorum_met
    assert snapshot.revoked_by == (stored["issuer_did"],)
    with pytest.raises(TradeRuleRecognitionRejected, match="signature invalid"):
        TradeRuleRecognition.from_dict(
            stored["invalid"]["tampered_decision"]
        )
    with pytest.raises(TradeRuleRecognitionRejected, match="require a reason"):
        TradeRuleRecognition.from_dict(stored["invalid"]["missing_reason"])
    with pytest.raises(TradeRuleRecognitionRejected, match="not_after"):
        TradeRuleRecognition.from_dict(stored["invalid"]["missing_expiry"])
    bad_predecessor = TradeRuleRecognition.from_dict(
        stored["invalid"]["bad_predecessor"]
    )
    bad_projection = evaluate_rule_recognition(
        package,
        [recognized, bad_predecessor],
        policy=_policy(
            trusted_issuers={stored["issuer_did"]},
        ),
        at=datetime(2026, 8, 3, tzinfo=timezone.utc),
    )
    assert not bad_projection.observed_quorum_met
    assert bad_projection.conflicted_issuers == (stored["issuer_did"],)


def test_recognition_schema_accepts_vectors_and_rejects_missing_reason():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    vectors = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(vectors["recognized"])
    jsonschema.Draft202012Validator(schema).validate(vectors["revoked"])
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(
            vectors["invalid"]["missing_reason"]
        )
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(
            vectors["invalid"]["missing_expiry"]
        )
    zero_fraction = copy.deepcopy(vectors["recognized"])
    zero_fraction["issued_at"] = "2026-08-01T00:00:00.000000Z"
    zero_fraction["proof"]["created"] = zero_fraction["issued_at"]
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(zero_fraction)
