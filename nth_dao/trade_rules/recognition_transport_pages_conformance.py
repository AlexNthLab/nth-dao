"""Deterministic conformance vectors for Recognition proof pages v2."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from nth_dao.identity import AgentID, AgentIdentity
from nth_dao.trade_rules.canonical import trade_canonical_json
from nth_dao.trade_rules.package_binding import sign_offer_package_binding
from nth_dao.trade_rules.package_store import build_rule_package
from nth_dao.trade_rules.recognition import create_rule_recognition
from nth_dao.trade_rules.recognition_conformance import (
    generate_vectors as generate_recognition_vectors,
)
from nth_dao.trade_rules.recognition_transport_pages import (
    build_rule_recognition_proof_pages,
)

VECTORS_PATH = (
    Path(__file__).with_name("vectors")
    / "rule-recognition-proof-pages-v2.json"
)
SCHEMA_PATH = (
    Path(__file__).with_name("schemas")
    / "trade-rule-recognition-proof-page.schema.json"
)
_PUBLISHER_SEED = hashlib.sha256(
    b"NTH Recognition proof page publisher public test seed"
).digest()
_ISSUER_SEED = hashlib.sha256(
    b"NTH Recognition proof page issuer public test seed"
).digest()
_OFFER_DIGEST = "sha256:" + hashlib.sha256(
    b"NTH Recognition proof page conformance Offer"
).hexdigest()
_NOW = datetime(2026, 8, 3, tzinfo=timezone.utc)


def _test_identity(seed: bytes, *, label: str) -> AgentIdentity:
    try:
        from nacl.signing import SigningKey
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError(
            "regenerating Recognition page vectors requires PyNaCl"
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
        _PUBLISHER_SEED,
        label="recognition-page-offer-publisher",
    )
    issuer = _test_identity(
        _ISSUER_SEED,
        label="recognition-page-issuer",
    )
    statements = []
    previous = None
    for _index in range(129):
        previous = create_rule_recognition(
            issuer,
            package=package,
            decision="recognized",
            issued_at="2026-08-01T00:00:00Z",
            not_after="2026-08-20T00:00:00Z",
            previous=previous,
            now=datetime(2026, 8, 1, tzinfo=timezone.utc),
        )
        statements.append(previous)
    binding = sign_offer_package_binding(
        publisher,
        offer_digest=_OFFER_DIGEST,
        package_digest=package.digest,
        created="2026-08-01T00:00:00Z",
    )
    pages = list(build_rule_recognition_proof_pages(
        package,
        statements,
        offer_package_binding=binding,
        observer_identity=publisher,
        observed_at="2026-08-03T00:00:00Z",
        not_after="2026-08-03T00:05:00Z",
        now=_NOW,
    ))
    refreshed_at = _NOW + timedelta(minutes=1)
    refreshed = list(build_rule_recognition_proof_pages(
        package,
        statements,
        offer_package_binding=binding,
        observer_identity=publisher,
        observed_at="2026-08-03T00:01:00Z",
        not_after="2026-08-03T00:06:00Z",
        now=refreshed_at,
    ))
    missing_page = list(copy.deepcopy(pages[:-1]))
    mixed_observation = list(copy.deepcopy(pages))
    mixed_observation[-1] = copy.deepcopy(refreshed[-1])
    tampered_page = list(copy.deepcopy(pages))
    tampered_page[0]["issuer_segments"][0]["statements"][0][
        "not_after"
    ] = "2026-08-19T00:00:00Z"
    return {
        "format": "nth-trade-rule-recognition-proof-conformance-v2",
        "schema_version": 2,
        "warning": "Deterministic public test keys; never trust or reuse them.",
        "package_digest": package.digest,
        "package_manifest": package.manifest.to_dict(),
        "package_resources_hex": {
            digest: payload.hex()
            for digest, payload in sorted(package.resources.items())
        },
        "offer_digest": _OFFER_DIGEST,
        "offer_publisher_did": publisher.as_did(),
        "pages": pages,
        "expected_page_digests": [
            "sha256:" + hashlib.sha256(trade_canonical_json(page)).hexdigest()
            for page in pages
        ],
        "expected_canonical_hex": [
            trade_canonical_json(page).hex() for page in pages
        ],
        "invalid_page_sets": {
            "missing_page": missing_page,
            "mixed_observation": mixed_observation,
            "tampered_page": tampered_page,
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
