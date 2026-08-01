"""Deterministic conformance vectors for Rule Recognition v1."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nth_dao.identity import AgentID, AgentIdentity
from nth_dao.trade_rules.manifest import manifest_body, sign_manifest
from nth_dao.trade_rules.package_store import build_rule_package
from nth_dao.trade_rules.recognition import (
    RULE_RECOGNITION_SIGNING_DOMAIN,
    create_rule_recognition,
)
from nth_dao.trade_rules.recognition_audit import (
    rule_recognition_audit_payload,
)
from nth_dao.trade_rules.signing import (
    encode_ed25519_signature,
    signed_document_input,
)

VECTORS_PATH = (
    Path(__file__).with_name("vectors") / "rule-recognition-v1.json"
)
SCHEMA_PATH = (
    Path(__file__).with_name("schemas")
    / "trade-rule-recognition.schema.json"
)
AUDIT_SCHEMA_PATH = (
    Path(__file__).with_name("schemas")
    / "trade-rule-recognition-audit-payload.schema.json"
)
_PUBLISHER_SEED = hashlib.sha256(
    b"NTH Trade Rule Recognition publisher public seed"
).digest()
_ISSUER_SEED = hashlib.sha256(
    b"NTH Trade Rule Recognition issuer public seed"
).digest()


def _test_identity(seed: bytes, *, label: str) -> AgentIdentity:
    try:
        from nacl.signing import SigningKey
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError(
            "regenerating Rule Recognition vectors requires PyNaCl"
        ) from exc
    signing_key = SigningKey(seed)
    verify_key = signing_key.verify_key.encode()
    return AgentIdentity(
        agent_id=AgentID.from_pubkey(verify_key.hex()),
        label=label,
        _signing_key=signing_key.encode(),
        _verify_key=verify_key,
    )


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _package():
    publisher = _test_identity(
        _PUBLISHER_SEED,
        label="public-conformance-publisher",
    )
    resource = b'{"type":"object","required":["delivery"]}'
    resource_digest = _digest(resource)
    body = manifest_body(
        rule_id="org.nthdao.reference/digital-delivery",
        version="1.0.0",
        publisher_did=publisher.as_did(),
        summary="Public conformance package; never trust this test key.",
        applies_to=["service"],
        families=["acceptance", "fulfillment"],
        resources=[
            {
                "purpose": "terms",
                "media_type": "application/schema+json",
                "digest": resource_digest,
                "size": len(resource),
            }
        ],
        published_at="2026-07-31T00:00:00Z",
        not_after="2027-07-31T00:00:00Z",
    )
    manifest = sign_manifest(
        publisher,
        body,
        created="2026-07-31T00:00:00Z",
    )
    return build_rule_package(manifest, {resource_digest: resource})


def _sign_semantically_invalid(
    identity: AgentIdentity,
    document: dict[str, Any],
) -> dict[str, Any]:
    value = copy.deepcopy(document)
    value["proof"]["proof_value"] = encode_ed25519_signature(
        identity.sign(
            signed_document_input(
                RULE_RECOGNITION_SIGNING_DOMAIN,
                value,
            )
        )
    )
    return value


def generate_vectors() -> dict[str, Any]:
    package = _package()
    issuer = _test_identity(
        _ISSUER_SEED,
        label="public-conformance-issuer",
    )
    first = create_rule_recognition(
        issuer,
        package=package,
        decision="recognized",
        issued_at="2026-08-01T00:00:00Z",
        not_after="2026-08-20T00:00:00Z",
        now=datetime(2026, 8, 1, tzinfo=timezone.utc),
    )
    revoked = create_rule_recognition(
        issuer,
        package=package,
        decision="revoked",
        reason_codes=["security.withdrawn"],
        issued_at="2026-08-02T00:00:00Z",
        not_after="2026-08-20T00:00:00Z",
        previous=first,
        now=datetime(2026, 8, 2, tzinfo=timezone.utc),
    )
    tampered_decision = first.to_dict()
    tampered_decision["decision"] = "revoked"
    tampered_decision["reason_codes"] = ["security.withdrawn"]
    bad_predecessor = revoked.to_dict()
    bad_predecessor["previous_statement_digest"] = "sha256:" + ("0" * 64)
    bad_predecessor = _sign_semantically_invalid(
        issuer,
        bad_predecessor,
    )
    missing_reason = revoked.to_dict()
    missing_reason["reason_codes"] = []
    missing_reason = _sign_semantically_invalid(issuer, missing_reason)
    missing_expiry = first.to_dict()
    missing_expiry["not_after"] = None
    missing_expiry = _sign_semantically_invalid(issuer, missing_expiry)
    valid_audit_payload = rule_recognition_audit_payload(
        first,
        package=package,
    )
    invalid_audit_did = copy.deepcopy(valid_audit_payload)
    invalid_audit_did["issuer_did"] = "did:key:z123"
    invalid_audit_date = copy.deepcopy(valid_audit_payload)
    invalid_audit_date["issued_at"] = "2026-02-30T00:00:00Z"
    reversed_audit_interval = copy.deepcopy(valid_audit_payload)
    reversed_audit_interval["not_after"] = valid_audit_payload["issued_at"]
    return {
        "format": "nth-trade-rule-recognition-conformance-v1",
        "schema_version": 1,
        "warning": (
            "Deterministic public test keys; never trust or reuse them."
        ),
        "package_digest": package.digest,
        "package_manifest": package.manifest.to_dict(),
        "package_resources_hex": {
            digest: payload.hex()
            for digest, payload in sorted(package.resources.items())
        },
        "rule_id": package.manifest.rule_id,
        "issuer_did": issuer.as_did(),
        "recognized": first.to_dict(),
        "revoked": revoked.to_dict(),
        "recognized_audit_payload": rule_recognition_audit_payload(
            first,
            package=package,
        ),
        "revoked_audit_payload": rule_recognition_audit_payload(
            revoked,
            package=package,
        ),
        "expected_recognized_canonical_hex": first.canonical_bytes.hex(),
        "expected_recognized_signing_input_hex": signed_document_input(
            RULE_RECOGNITION_SIGNING_DOMAIN,
            first.to_dict(),
        ).hex(),
        "invalid": {
            "tampered_decision": tampered_decision,
            "bad_predecessor": bad_predecessor,
            "missing_expiry": missing_expiry,
            "missing_reason": missing_reason,
        },
        "invalid_audit_payloads": {
            "invalid_issuer_did": invalid_audit_did,
            "invalid_issued_at": invalid_audit_date,
            "reversed_interval": reversed_audit_interval,
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
