import copy
import json

import pytest

from nth_dao.identity import crypto_available
from nth_dao.trade_rules import (
    ManifestRejected,
    TradeCanonicalJSONError,
    TradeRuleManifest,
    manifest_digest,
    manifest_signing_input,
    parse_trade_json,
    trade_canonical_json,
    verify_manifest,
)
from nth_dao.trade_rules.conformance import (
    SCHEMA_PATH,
    VECTORS_PATH,
    encoded_vectors,
    load_vectors,
)

requires_crypto = pytest.mark.skipif(
    not crypto_available(), reason="Trade Rule vectors require PyNaCl"
)


def test_manifest_schema_is_packaged_and_matches_wire_constants():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert schema["$schema"].endswith("2020-12/schema")
    assert schema["properties"]["kind"]["const"] == ("org.nthdao.trade.rule-manifest")
    assert schema["properties"]["protocol_version"]["const"] == "1.0"
    proof = schema["$defs"]["proof"]["properties"]
    assert proof["type"]["const"] == "NthEd25519SignatureV1"
    assert proof["proof_value"]["minLength"] == 86
    assert proof["proof_value"]["maxLength"] == 86


@requires_crypto
def test_shipped_vectors_match_generator_byte_for_byte():
    assert VECTORS_PATH.read_bytes() == encoded_vectors()


@requires_crypto
def test_golden_manifest_bytes_signature_and_digest():
    vectors = load_vectors()
    document = vectors["manifest"]
    manifest = TradeRuleManifest.from_dict(document)
    assert (
        manifest.canonical_bytes.hex() == (vectors["expected_manifest_canonical_hex"])
    )
    assert (
        manifest_signing_input(document).hex()
        == (vectors["expected_signing_input_hex"])
    )
    assert manifest_digest(manifest) == vectors["expected_manifest_digest"]


def test_canonical_vectors_match():
    vectors = load_vectors()
    for case in vectors["canonical_cases"]:
        assert trade_canonical_json(case["input"]).hex() == case["expected_hex"]


def test_canonical_rejection_vectors_fail_closed():
    vectors = load_vectors()
    for case in vectors["canonical_rejections"]:
        with pytest.raises(TradeCanonicalJSONError):
            parse_trade_json(case["wire"])


@requires_crypto
def test_negative_manifest_vectors_do_not_verify():
    vectors = load_vectors()
    for case in vectors["negative_manifests"]:
        assert case["expected_valid"] is False
        assert verify_manifest(case["document"])[0] is False
        with pytest.raises(ManifestRejected):
            TradeRuleManifest.from_dict(case["document"])


@requires_crypto
def test_proof_options_are_covered_by_signature():
    vectors = load_vectors()
    original = vectors["manifest"]
    for field, replacement in (
        ("type", "OtherProof"),
        ("created", "2026-07-28T00:00:02Z"),
        ("proof_purpose", "authentication"),
    ):
        tampered = copy.deepcopy(original)
        tampered["proof"][field] = replacement
        assert verify_manifest(tampered)[0] is False
