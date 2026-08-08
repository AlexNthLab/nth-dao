import copy
import json

import pytest

from nth_dao.identity import crypto_available
from nth_dao.trade_rules import (
    OfferRejected,
    TradeOffer,
    offer_digest,
    verify_offer,
    verify_offer_successor,
)
from nth_dao.trade_rules.offer_conformance import (
    SCHEMA_PATH,
    VECTORS_PATH,
    encoded_vectors,
    load_vectors,
)

requires_crypto = pytest.mark.skipif(
    not crypto_available(), reason="Trade Offer vectors require PyNaCl"
)


def test_offer_schema_is_packaged_and_matches_wire_constants():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert schema["$schema"].endswith("2020-12/schema")
    assert schema["properties"]["kind"]["const"] == "org.nthdao.trade.offer"
    assert schema["properties"]["protocol_version"]["const"] == "2.0"
    assert schema["properties"]["revision"]["minimum"] == 1
    assert schema["properties"]["provides"]["minItems"] == 1
    assert schema["properties"]["requests"].get("minItems", 0) == 0
    assert "price" not in schema["properties"]


@requires_crypto
def test_shipped_offer_vectors_match_generator_byte_for_byte():
    assert VECTORS_PATH.read_bytes() == encoded_vectors()


@requires_crypto
def test_golden_offer_bytes_signature_and_digest():
    vectors = load_vectors()
    offer = TradeOffer.from_dict(vectors["offer"])
    assert offer.canonical_bytes.hex() == vectors["expected_offer_canonical_hex"]
    from nth_dao.trade_rules import offer_signing_input

    assert (
        offer_signing_input(vectors["offer"]).hex()
        == vectors["expected_signing_input_hex"]
    )
    assert offer_digest(offer) == vectors["expected_offer_digest"]
    withdrawal = TradeOffer.from_dict(vectors["withdrawal_offer"])
    assert offer_digest(withdrawal) == vectors["expected_withdrawal_digest"]
    assert verify_offer_successor(offer, withdrawal) == (True, "ok")


@requires_crypto
def test_negative_offer_vectors_fail_closed():
    vectors = load_vectors()
    for case in vectors["negative_offers"]:
        assert case["expected_valid"] is False
        assert verify_offer(case["document"])[0] is False
        with pytest.raises(OfferRejected):
            TradeOffer.from_dict(case["document"])


@requires_crypto
def test_proof_and_rule_binding_are_covered_by_signature():
    vectors = load_vectors()
    original = vectors["offer"]
    mutations = [
        ("proof", "created", "2026-07-29T00:00:02Z"),
        ("proof", "proof_purpose", "authentication"),
        ("rule_refs", 0, "digest", "sha256:" + ("0" * 64)),
    ]
    for path in mutations:
        tampered = copy.deepcopy(original)
        target = tampered
        for key in path[:-2]:
            target = target[key]
        target[path[-2]] = path[-1]
        assert verify_offer(tampered)[0] is False


@requires_crypto
def test_market_extensions_are_covered_by_offer_signature():
    vectors = load_vectors()
    original = vectors["offer"]
    assert vectors["market_extensions_vector"] == "market-extensions-v1.json"
    assert "org.nthdao.market/resource-descriptors-v1" in original["extensions"]
    assert "org.nthdao.market/publication-v1" in original["extensions"]
    tampered = copy.deepcopy(original)
    tampered["extensions"]["org.nthdao.market/publication-v1"][
        "offer_validity_seconds"
    ] = 86_400
    assert verify_offer(tampered)[0] is False
