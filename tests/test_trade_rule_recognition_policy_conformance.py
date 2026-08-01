from __future__ import annotations

import copy
import json

import pytest

from nth_dao.identity import crypto_available
from nth_dao.trade_rules.recognition_policy import (
    RULE_RECOGNITION_POLICY_SIGNING_DOMAIN,
    TradeRuleRecognitionPolicy,
    TradeRuleRecognitionPolicyRejected,
    verify_rule_recognition_policy_successor,
)
from nth_dao.trade_rules.recognition_policy_audit import (
    RuleRecognitionPolicyAuditError,
    validate_rule_recognition_policy_audit_payload,
)
from nth_dao.trade_rules.recognition_policy_conformance import (
    AUDIT_SCHEMA_PATH,
    SCHEMA_PATH,
    VECTORS_PATH,
    generate_vectors,
)
from nth_dao.trade_rules.signing import signed_document_input

pytestmark = pytest.mark.skipif(
    not crypto_available(),
    reason="Recognition policy conformance requires PyNaCl",
)


def test_policy_conformance_vector_is_current_and_replayable():
    stored = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))

    assert stored == generate_vectors()
    genesis = TradeRuleRecognitionPolicy.from_dict(stored["genesis"])
    successor = TradeRuleRecognitionPolicy.from_dict(stored["successor"])
    verify_rule_recognition_policy_successor(genesis, successor)
    assert (
        genesis.canonical_bytes.hex()
        == stored["expected_genesis_canonical_hex"]
    )
    assert (
        signed_document_input(
            RULE_RECOGNITION_POLICY_SIGNING_DOMAIN,
            genesis.to_dict(),
        ).hex()
        == stored["expected_genesis_signing_input_hex"]
    )
    assert validate_rule_recognition_policy_audit_payload(
        stored["genesis_audit_payload"]
    ) == stored["genesis_audit_payload"]
    assert validate_rule_recognition_policy_audit_payload(
        stored["successor_audit_payload"]
    ) == stored["successor_audit_payload"]


def test_policy_conformance_rejects_semantic_negative_vectors():
    stored = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    genesis = TradeRuleRecognitionPolicy.from_dict(stored["genesis"])

    with pytest.raises(TradeRuleRecognitionPolicyRejected):
        TradeRuleRecognitionPolicy.from_dict(
            stored["invalid"]["tampered_threshold"]
        )
    bad_predecessor = TradeRuleRecognitionPolicy.from_dict(
        stored["invalid"]["bad_predecessor"]
    )
    with pytest.raises(
        TradeRuleRecognitionPolicyRejected,
        match="predecessor digest mismatch",
    ):
        verify_rule_recognition_policy_successor(genesis, bad_predecessor)
    unauthorized = TradeRuleRecognitionPolicy.from_dict(
        stored["invalid"]["unauthorized_successor"]
    )
    with pytest.raises(
        TradeRuleRecognitionPolicyRejected,
        match="not an authorized controller",
    ):
        verify_rule_recognition_policy_successor(genesis, unauthorized)
    with pytest.raises(RuleRecognitionPolicyAuditError, match="issued_at"):
        validate_rule_recognition_policy_audit_payload(
            stored["invalid_audit_payloads"]["impossible_issued_at"]
        )
    with pytest.raises(
        RuleRecognitionPolicyAuditError,
        match="does not bind node_did",
    ):
        validate_rule_recognition_policy_audit_payload(
            stored["invalid_audit_payloads"]["mismatched_policy_id"]
        )


def test_policy_schemas_accept_vectors_and_reject_missing_fields():
    jsonschema = pytest.importorskip("jsonschema")
    stored = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    policy_schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    audit_schema = json.loads(
        AUDIT_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    policy_validator = jsonschema.Draft202012Validator(policy_schema)
    audit_validator = jsonschema.Draft202012Validator(audit_schema)

    policy_validator.validate(stored["genesis"])
    policy_validator.validate(stored["successor"])
    audit_validator.validate(stored["genesis_audit_payload"])
    audit_validator.validate(stored["successor_audit_payload"])

    missing_controllers = copy.deepcopy(stored["genesis"])
    del missing_controllers["controllers"]
    with pytest.raises(jsonschema.ValidationError):
        policy_validator.validate(missing_controllers)
    missing_policy_digest = copy.deepcopy(
        stored["genesis_audit_payload"]
    )
    del missing_policy_digest["policy_digest"]
    with pytest.raises(jsonschema.ValidationError):
        audit_validator.validate(missing_policy_digest)
