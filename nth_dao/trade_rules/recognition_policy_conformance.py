"""Deterministic conformance vectors for Recognition trust policy v1."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nth_dao.identity import AgentID, AgentIdentity
from nth_dao.trade_rules.recognition import RuleRecognitionTrustPolicy
from nth_dao.trade_rules.recognition_policy import (
    RULE_RECOGNITION_POLICY_ID_PREFIX,
    RULE_RECOGNITION_POLICY_SIGNING_DOMAIN,
    create_rule_recognition_policy,
)
from nth_dao.trade_rules.recognition_policy_audit import (
    rule_recognition_policy_audit_payload,
)
from nth_dao.trade_rules.signing import (
    encode_ed25519_signature,
    signed_document_input,
    verification_method_for_did,
)

VECTORS_PATH = (
    Path(__file__).with_name("vectors")
    / "rule-recognition-policy-v1.json"
)
SCHEMA_PATH = (
    Path(__file__).with_name("schemas")
    / "trade-rule-recognition-policy.schema.json"
)
AUDIT_SCHEMA_PATH = (
    Path(__file__).with_name("schemas")
    / "trade-rule-recognition-policy-audit-payload.schema.json"
)

_NODE_SEED = hashlib.sha256(
    b"NTH Recognition policy public node seed"
).digest()
_CONTROLLER_SEED = hashlib.sha256(
    b"NTH Recognition policy public controller seed"
).digest()
_ISSUER_SEED = hashlib.sha256(
    b"NTH Recognition policy public trusted issuer seed"
).digest()
_OUTSIDER_SEED = hashlib.sha256(
    b"NTH Recognition policy public unauthorized signer seed"
).digest()


def _test_identity(seed: bytes, *, label: str) -> AgentIdentity:
    try:
        from nacl.signing import SigningKey
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError(
            "regenerating Recognition policy vectors requires PyNaCl"
        ) from exc
    signing_key = SigningKey(seed)
    verify_key = signing_key.verify_key.encode()
    return AgentIdentity(
        agent_id=AgentID.from_pubkey(verify_key.hex()),
        label=label,
        _signing_key=signing_key.encode(),
        _verify_key=verify_key,
    )


def _resign(
    identity: AgentIdentity,
    document: dict[str, Any],
) -> dict[str, Any]:
    value = copy.deepcopy(document)
    signer_did = identity.as_did()
    value["signer_did"] = signer_did
    value["proof"]["verification_method"] = verification_method_for_did(
        signer_did
    )
    value["proof"]["proof_value"] = encode_ed25519_signature(
        identity.sign(
            signed_document_input(
                RULE_RECOGNITION_POLICY_SIGNING_DOMAIN,
                value,
            )
        )
    )
    return value


def generate_vectors() -> dict[str, Any]:
    node = _test_identity(_NODE_SEED, label="public-policy-node")
    controller = _test_identity(
        _CONTROLLER_SEED,
        label="public-policy-controller",
    )
    issuer = _test_identity(
        _ISSUER_SEED,
        label="public-recognition-issuer",
    )
    outsider = _test_identity(
        _OUTSIDER_SEED,
        label="public-unauthorized-signer",
    )
    trust = RuleRecognitionTrustPolicy(
        trusted_issuers={issuer.as_did()},
        threshold=1,
        max_statement_ttl_seconds=2_592_000,
        issuer_rule_scopes={
            issuer.as_did(): (
                "org.nthdao.reference",
                "org.nthdao.reference/digital-delivery",
            ),
        },
    )
    genesis = create_rule_recognition_policy(
        node,
        node_did=node.as_did(),
        controllers=[controller.as_did()],
        trust_policy=trust,
        issued_at="2026-08-01T00:00:00Z",
        now=datetime(2026, 8, 1, tzinfo=timezone.utc),
    )
    successor = create_rule_recognition_policy(
        controller,
        node_did=node.as_did(),
        controllers=[controller.as_did(), node.as_did()],
        trust_policy=trust,
        issued_at="2026-08-01T00:00:01Z",
        previous=genesis,
        now=datetime(2026, 8, 1, 0, 0, 1, tzinfo=timezone.utc),
    )
    tampered_threshold = genesis.to_dict()
    tampered_threshold["threshold"] = 2
    bad_predecessor = successor.to_dict()
    bad_predecessor["previous_policy_digest"] = "sha256:" + ("0" * 64)
    bad_predecessor = _resign(controller, bad_predecessor)
    unauthorized_successor = _resign(outsider, successor.to_dict())
    invalid_audit = rule_recognition_policy_audit_payload(genesis)
    invalid_audit["issued_at"] = "2026-02-30T00:00:00Z"
    mismatched_policy_id_audit = rule_recognition_policy_audit_payload(
        genesis
    )
    mismatched_policy_id_audit["policy_id"] = (
        RULE_RECOGNITION_POLICY_ID_PREFIX + ("0" * 64)
    )
    return {
        "format": "nth-trade-rule-recognition-policy-conformance-v1",
        "schema_version": 1,
        "warning": "Deterministic public test keys; never trust or reuse them.",
        "node_did": node.as_did(),
        "controller_did": controller.as_did(),
        "trusted_issuer_did": issuer.as_did(),
        "unauthorized_signer_did": outsider.as_did(),
        "genesis": genesis.to_dict(),
        "successor": successor.to_dict(),
        "genesis_audit_payload": (
            rule_recognition_policy_audit_payload(genesis)
        ),
        "successor_audit_payload": (
            rule_recognition_policy_audit_payload(successor)
        ),
        "expected_genesis_canonical_hex": genesis.canonical_bytes.hex(),
        "expected_genesis_signing_input_hex": signed_document_input(
            RULE_RECOGNITION_POLICY_SIGNING_DOMAIN,
            genesis.to_dict(),
        ).hex(),
        "invalid": {
            "tampered_threshold": tampered_threshold,
            "bad_predecessor": bad_predecessor,
            "unauthorized_successor": unauthorized_successor,
        },
        "invalid_audit_payloads": {
            "impossible_issued_at": invalid_audit,
            "mismatched_policy_id": mismatched_policy_id_audit,
        },
    }


def write_vectors(path: Path = VECTORS_PATH) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            generate_vectors(),
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return path


if __name__ == "__main__":  # pragma: no cover - operator command
    write_vectors()
