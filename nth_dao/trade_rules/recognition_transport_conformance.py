"""Deterministic conformance vectors for Recognition proof transport v1."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from nth_dao.identity import AgentID, AgentIdentity
from nth_dao.trade_rules.package_binding import sign_offer_package_binding
from nth_dao.trade_rules.package_store import build_rule_package
from nth_dao.trade_rules.recognition import TradeRuleRecognition
from nth_dao.trade_rules.recognition_conformance import (
    generate_vectors as generate_recognition_vectors,
)
from nth_dao.trade_rules.recognition_transport import (
    build_rule_recognition_proof_bundle,
)

VECTORS_PATH = (
    Path(__file__).with_name("vectors")
    / "rule-recognition-proof-bundle-v1.json"
)
SCHEMA_PATH = (
    Path(__file__).with_name("schemas")
    / "trade-rule-recognition-proof-bundle.schema.json"
)
_OFFER_PUBLISHER_SEED = hashlib.sha256(
    b"NTH Rule Recognition proof Offer publisher public seed"
).digest()
_OFFER_DIGEST = "sha256:" + hashlib.sha256(
    b"NTH public Recognition proof conformance Offer"
).hexdigest()


def _test_identity(seed: bytes, *, label: str) -> AgentIdentity:
    try:
        from nacl.signing import SigningKey
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError(
            "regenerating Recognition proof vectors requires PyNaCl"
        ) from exc
    signing_key = SigningKey(seed)
    verify_key = signing_key.verify_key.encode()
    return AgentIdentity(
        agent_id=AgentID.from_pubkey(verify_key.hex()),
        label=label,
        _signing_key=signing_key.encode(),
        _verify_key=verify_key,
    )


def generate_vectors() -> dict:
    recognition_vectors = generate_recognition_vectors()
    package = build_rule_package(
        recognition_vectors["package_manifest"],
        {
            digest: bytes.fromhex(payload)
            for digest, payload in recognition_vectors[
                "package_resources_hex"
            ].items()
        },
    )
    publisher = _test_identity(
        _OFFER_PUBLISHER_SEED,
        label="public-recognition-proof-offer-publisher",
    )
    statements = (
        TradeRuleRecognition.from_dict(recognition_vectors["recognized"]),
        TradeRuleRecognition.from_dict(recognition_vectors["revoked"]),
    )
    binding = sign_offer_package_binding(
        publisher,
        offer_digest=_OFFER_DIGEST,
        package_digest=package.digest,
        created="2026-08-01T00:00:00Z",
    )
    bundle = build_rule_recognition_proof_bundle(
        package,
        statements,
        offer_package_binding=binding,
        observer_identity=publisher,
        observed_at="2026-08-03T00:00:00Z",
        not_after="2026-08-03T00:05:00Z",
        now=datetime(2026, 8, 3, tzinfo=timezone.utc),
    )
    missing_predecessor = copy.deepcopy(bundle)
    missing_predecessor["issuer_chains"][0]["statements"].pop(0)
    hidden_head = copy.deepcopy(bundle)
    hidden_head["issuer_chains"][0]["head_digests"] = [
        statements[0].digest
    ]
    relabelled_offer = copy.deepcopy(bundle)
    relabelled_offer["offer_digest"] = "sha256:" + ("0" * 64)
    return {
        "format": "nth-trade-rule-recognition-proof-conformance-v1",
        "schema_version": 1,
        "warning": "Deterministic public test keys; never trust or reuse them.",
        "package_digest": package.digest,
        "package_manifest": package.manifest.to_dict(),
        "package_resources_hex": {
            digest: payload.hex()
            for digest, payload in sorted(package.resources.items())
        },
        "offer_digest": _OFFER_DIGEST,
        "offer_publisher_did": publisher.as_did(),
        "bundle": bundle,
        "expected_canonical_hex": json.dumps(
            bundle,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8").hex(),
        "invalid": {
            "missing_predecessor": missing_predecessor,
            "hidden_head": hidden_head,
            "relabelled_offer": relabelled_offer,
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
