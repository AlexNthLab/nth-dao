"""Deterministic v2 audit vectors for paged Recognition proof imports."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from nth_dao.trade_rules.package_store import build_rule_package
from nth_dao.trade_rules.recognition_import import (
    EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORTED,
    EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORT_PROPOSED,
    recognition_proof_import_payload,
)
from nth_dao.trade_rules.recognition_transport_pages import (
    parse_rule_recognition_proof_pages,
)
from nth_dao.trade_rules.recognition_transport_pages_conformance import (
    generate_vectors as generate_page_vectors,
)

VECTORS_PATH = (
    Path(__file__).with_name("vectors")
    / "rule-recognition-proof-import-pages-v2.json"
)
SCHEMA_PATH = (
    Path(__file__).with_name("schemas")
    / "trade-rule-recognition-proof-import-audit.schema.json"
)


def generate_vectors() -> dict:
    vectors = generate_page_vectors()
    package = build_rule_package(
        vectors["package_manifest"],
        {
            digest: bytes.fromhex(payload)
            for digest, payload in vectors["package_resources_hex"].items()
        },
    )
    proof_set = parse_rule_recognition_proof_pages(
        vectors["pages"],
        package=package,
        expected_offer_digest=vectors["offer_digest"],
        expected_offer_publisher_did=vectors["offer_publisher_did"],
        now=datetime(2026, 8, 3, tzinfo=timezone.utc),
    )
    common = {
        "order_digest": "sha256:" + ("2" * 64),
        "offer_digest": vectors["offer_digest"],
        "source_origin": "https://peer.example",
    }
    proposed_pages = [
        recognition_proof_import_payload(
            page,
            event_type=EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORT_PROPOSED,
            **common,
        )
        for page in proof_set.pages
    ]
    completed_pages = [
        recognition_proof_import_payload(
            page,
            event_type=EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORTED,
            **common,
        )
        for page in proof_set.pages
    ]
    return {
        "format": "nth-trade-rule-recognition-proof-import-conformance-v2",
        "schema_version": 2,
        "warning": "Deterministic public vectors; never treat them as authority.",
        "event_types": {
            "proposed": EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORT_PROPOSED,
            "completed": EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORTED,
        },
        "observation_digest": proof_set.observation_digest,
        "proposed_pages": proposed_pages,
        "completed_pages": completed_pages,
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
