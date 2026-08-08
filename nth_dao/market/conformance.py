"""Deterministic conformance vectors for Market extensions v1."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from nth_dao.market.resource_descriptor import (
    MARKET_PUBLICATION_EXTENSION,
    RESOURCE_DESCRIPTOR_EXTENSION,
    inline_resource_descriptor_digest,
    validate_inline_resource_descriptor,
    validate_market_publication_metadata,
)
from nth_dao.trade_rules.canonical import trade_canonical_json


VECTORS_PATH = Path(__file__).with_name("vectors") / "market-extensions-v1.json"


def generate_vectors() -> dict[str, Any]:
    descriptor = {
        "kind": "org.nthdao.resource-profile.inline",
        "version": "1",
        "category": "services",
        "resource_type": "service",
        "resource_id": "urn:nthdao:service:review",
        "profile_ref": {
            "rule_id": "org.nthdao.profiles/basic-service",
            "digest": "sha256:" + ("a" * 64),
        },
        "attributes": {
            "delivery": "signed-report",
            "display_reference": "Code review package",
        },
    }
    digest = inline_resource_descriptor_digest(descriptor)
    publication = {
        "category": "services",
        "intent": "provide",
        "capability_set": ["code-review"],
        "offer_validity_seconds": 2_592_000,
    }
    descriptor_negatives = []
    for case_id, mutate in (
        ("wrong-kind", lambda item: item.update(kind="example.invalid")),
        ("partial-profile-ref", lambda item: item.update(profile_ref={"rule_id": "org.nthdao.profiles/basic-service"})),
        ("non-object-attributes", lambda item: item.update(attributes=[])),
    ):
        candidate = copy.deepcopy(descriptor)
        mutate(candidate)
        descriptor_negatives.append({"id": case_id, "descriptor": candidate})
    publication_negatives = []
    for case_id, mutate in (
        ("legacy-shared-ttl", lambda item: item.update(ttl_seconds=86_400)),
        ("discovery-ttl-in-offer", lambda item: item.update(discovery_ttl_seconds=86_400)),
        ("unsorted-capabilities", lambda item: item.update(capability_set=["review", "code"])),
        ("short-offer-validity", lambda item: item.update(offer_validity_seconds=60)),
    ):
        candidate = copy.deepcopy(publication)
        mutate(candidate)
        publication_negatives.append({"id": case_id, "publication": candidate})
    return {
        "format": "nth-market-extensions-conformance-v1",
        "schema_version": 1,
        "warning": "Public deterministic data; it grants no trust or execution authority.",
        "resource_descriptor_extension": RESOURCE_DESCRIPTOR_EXTENSION,
        "publication_extension": MARKET_PUBLICATION_EXTENSION,
        "descriptor": descriptor,
        "expected_descriptor_canonical_hex": trade_canonical_json(descriptor).hex(),
        "expected_descriptor_digest": digest,
        "publication": publication,
        "expected_publication_canonical_hex": trade_canonical_json(publication).hex(),
        "negative_descriptors": descriptor_negatives,
        "negative_publications": publication_negatives,
    }


def encoded_vectors() -> bytes:
    return (
        json.dumps(generate_vectors(), ensure_ascii=True, indent=2, sort_keys=True)
        + "\n"
    ).encode("ascii")


def regenerate_vectors(path: Path = VECTORS_PATH) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encoded_vectors())
    return path


def load_vectors(path: Path = VECTORS_PATH) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="ascii"))
    if not isinstance(value, dict):
        raise ValueError("Market extension conformance vectors must be an object")
    return value


def verify_vectors(value: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    try:
        validate_inline_resource_descriptor(value["descriptor"])
        if inline_resource_descriptor_digest(value["descriptor"]) != value["expected_descriptor_digest"]:
            failures.append("descriptor digest mismatch")
        if trade_canonical_json(value["descriptor"]).hex() != value["expected_descriptor_canonical_hex"]:
            failures.append("descriptor canonical bytes mismatch")
        validate_market_publication_metadata(value["publication"])
        if trade_canonical_json(value["publication"]).hex() != value["expected_publication_canonical_hex"]:
            failures.append("publication canonical bytes mismatch")
    except (KeyError, TypeError, ValueError) as exc:
        failures.append(f"positive vector rejected: {exc}")
    for case in value.get("negative_descriptors", []):
        try:
            validate_inline_resource_descriptor(case["descriptor"])
        except (KeyError, TypeError, ValueError):
            continue
        failures.append(f"negative descriptor accepted: {case.get('id', '')}")
    for case in value.get("negative_publications", []):
        try:
            validate_market_publication_metadata(case["publication"])
        except (KeyError, TypeError, ValueError):
            continue
        failures.append(f"negative publication accepted: {case.get('id', '')}")
    return failures


__all__ = [
    "VECTORS_PATH",
    "encoded_vectors",
    "generate_vectors",
    "load_vectors",
    "regenerate_vectors",
    "verify_vectors",
]
