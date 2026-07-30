"""Deterministic conformance vectors for Trade Rule Manifest v1."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from nth_dao.identity import AgentID, AgentIdentity
from nth_dao.trade_rules.canonical import trade_canonical_json
from nth_dao.trade_rules.manifest import (
    manifest_body,
    manifest_digest,
    manifest_signing_input,
    sign_manifest,
)

VECTORS_PATH = Path(__file__).with_name("vectors") / "manifest-v1.json"
SCHEMA_PATH = Path(__file__).with_name("schemas") / "trade-rule-manifest.schema.json"
_SEED = hashlib.sha256(b"NTH Trade Rule Manifest v1 public conformance seed").digest()


def _test_identity() -> AgentIdentity:
    try:
        from nacl.signing import SigningKey
    except ImportError as exc:  # pragma: no cover - optional crypto environment
        raise RuntimeError("regenerating Trade Rule vectors requires PyNaCl") from exc
    signing_key = SigningKey(_SEED)
    verify_key = signing_key.verify_key.encode()
    return AgentIdentity(
        agent_id=AgentID.from_pubkey(verify_key.hex()),
        label="public-conformance-only",
        _signing_key=signing_key.encode(),
        _verify_key=verify_key,
    )


def generate_vectors() -> dict[str, Any]:
    identity = _test_identity()
    body = manifest_body(
        rule_id="org.nthdao.reference.free-digital-result",
        version="0.1.0",
        publisher_did=identity.as_did(),
        summary="Public conformance package; never use this key for real trust.",
        applies_to=["digital_resource", "service"],
        families=["pricing", "fulfillment", "acceptance", "rights"],
        resources=[
            {
                "purpose": "terms-schema",
                "media_type": "application/schema+json",
                "digest": "sha256:" + hashlib.sha256(b"terms-v1").hexdigest(),
                "size": 8,
            }
        ],
        required_capabilities=["org.nthdao.core.content-addressed-evidence/1"],
        hook_contracts=[
            {
                "name": "acceptance.evaluate",
                "version": "1",
                "input_schema_digest": (
                    "sha256:" + hashlib.sha256(b"acceptance-input-v1").hexdigest()
                ),
                "output_schema_digest": (
                    "sha256:" + hashlib.sha256(b"acceptance-output-v1").hexdigest()
                ),
                "side_effect": "none",
                "permissions": [],
            }
        ],
        published_at="2026-07-28T00:00:00Z",
        not_after="2027-07-28T00:00:00Z",
    )
    manifest = sign_manifest(identity, body, created="2026-07-28T00:00:01Z")
    document = manifest.to_dict()

    tampered_summary = copy.deepcopy(document)
    tampered_summary["summary"] = "tampered"
    tampered_proof_time = copy.deepcopy(document)
    tampered_proof_time["proof"]["created"] = "2026-07-28T00:00:02Z"
    tampered_signature = copy.deepcopy(document)
    replacement = "A" if document["proof"]["proof_value"][0] != "A" else "B"
    tampered_signature["proof"]["proof_value"] = (
        replacement + document["proof"]["proof_value"][1:]
    )

    canonical_cases = [
        {"id": "nested-order", "input": {"z": 2, "a": {"b": 2, "a": 1}}},
        {
            "id": "empty-containers",
            "input": {"empty_array": [], "empty_object": {}},
        },
        {
            "id": "null-and-booleans",
            "input": {"false": False, "null": None, "true": True},
        },
        {
            "id": "control-escaping",
            "input": {"text": 'line\n\t"slash\\'},
        },
        {"id": "unicode-value", "input": {"label": "caf\u00e9"}},
        {"id": "non-bmp-value", "input": {"symbol": "\U0001f680"}},
        {"id": "combining-value", "input": {"text": "e\u0301"}},
        {
            "id": "safe-integers",
            "input": {
                "min": -9_007_199_254_740_991,
                "max": 9_007_199_254_740_991,
            },
        },
    ]
    for case in canonical_cases:
        case["expected_hex"] = trade_canonical_json(case["input"]).hex()

    return {
        "format": "nth-trade-rule-conformance-v1",
        "schema_version": 1,
        "warning": "The generator uses a deterministic public test seed only.",
        "canonical_cases": canonical_cases,
        "canonical_rejections": [
            {"id": "float", "wire": '{"x":1.5}'},
            {
                "id": "unsafe-integer",
                "wire": '{"x":9007199254740992}',
            },
            {
                "id": "unsafe-negative-integer",
                "wire": '{"x":-9007199254740992}',
            },
            {"id": "duplicate-key", "wire": '{"x":1,"x":2}'},
            {"id": "non-ascii-key", "wire": '{"\u00e9":"bad"}'},
        ],
        "manifest": document,
        "expected_manifest_canonical_hex": manifest.canonical_bytes.hex(),
        "expected_signing_input_hex": manifest_signing_input(document).hex(),
        "expected_manifest_digest": manifest_digest(manifest),
        "negative_manifests": [
            {
                "id": "tampered-summary",
                "document": tampered_summary,
                "expected_valid": False,
            },
            {
                "id": "tampered-proof-created",
                "document": tampered_proof_time,
                "expected_valid": False,
            },
            {
                "id": "tampered-proof-value",
                "document": tampered_signature,
                "expected_valid": False,
            },
        ],
    }


def encoded_vectors() -> bytes:
    return (
        json.dumps(
            generate_vectors(),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def regenerate_vectors(path: Path = VECTORS_PATH) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encoded_vectors())
    return path


def load_vectors(path: Path = VECTORS_PATH) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Trade Rule conformance vectors must be an object")
    return data


__all__ = [
    "SCHEMA_PATH",
    "VECTORS_PATH",
    "encoded_vectors",
    "generate_vectors",
    "load_vectors",
    "regenerate_vectors",
]
