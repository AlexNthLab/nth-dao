from __future__ import annotations

from nth_dao.market.conformance import (
    VECTORS_PATH,
    encoded_vectors,
    load_vectors,
    verify_vectors,
)
from nth_dao.market.resource_descriptor import (
    inline_resource_descriptor_digest,
    inspect_offer_resource_descriptors,
)


def test_shipped_market_extension_vectors_match_generator_byte_for_byte():
    assert VECTORS_PATH.read_bytes() == encoded_vectors()


def test_python_reference_passes_market_extension_vectors():
    assert verify_vectors(load_vectors()) == []


def test_descriptor_inspection_rejects_hash_mismatch_without_granting_readiness():
    vectors = load_vectors()
    descriptor = vectors["descriptor"]
    valid_digest = inline_resource_descriptor_digest(descriptor)
    offer = {
        "provides": [{"leg_id": "service", "descriptor_digest": valid_digest}],
        "requests": [],
        "extensions": {
            vectors["resource_descriptor_extension"]: {
                "descriptors": {"sha256:" + ("0" * 64): descriptor},
            }
        },
    }

    inspected = inspect_offer_resource_descriptors(offer)

    assert inspected["status"] == "incomplete"
    assert inspected["verified_inline_count"] == 0
    assert inspected["profile_packages_resolved"] is False
    assert inspected["execution_ready"] is False
    assert inspected["items"][0]["content_hash_valid"] is False


def test_market_extension_negative_vectors_are_actually_rejected():
    vectors = load_vectors()
    assert len(vectors["negative_descriptors"]) >= 3
    assert len(vectors["negative_publications"]) >= 4
    assert verify_vectors(vectors) == []
