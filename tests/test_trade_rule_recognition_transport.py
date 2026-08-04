from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from nth_dao.identity import AgentIdentity, crypto_available
from nth_dao.trade_rules import (
    RuleRecognitionProofBundleRejected,
    TradeRuleRecognition,
    build_rule_package,
    build_rule_recognition_proof_bundle,
    build_rule_recognition_proof_pages,
    create_rule_recognition,
    parse_rule_recognition_proof_bundle,
    parse_rule_recognition_proof_pages,
    sign_offer_package_binding,
)
from nth_dao.trade_rules.recognition_conformance import VECTORS_PATH
from nth_dao.trade_rules.recognition_transport_conformance import (
    SCHEMA_PATH as PROOF_SCHEMA_PATH,
    VECTORS_PATH as PROOF_VECTORS_PATH,
    generate_vectors as generate_proof_vectors,
)
from nth_dao.trade_rules.recognition_transport_pages_conformance import (
    SCHEMA_PATH as PAGE_PROOF_SCHEMA_PATH,
    VECTORS_PATH as PAGE_PROOF_VECTORS_PATH,
    generate_vectors as generate_page_proof_vectors,
)
from nth_dao.trade_rules.canonical import trade_canonical_json

pytestmark = pytest.mark.skipif(
    not crypto_available(),
    reason="Trade Rule Recognition requires PyNaCl",
)

_PROOF_NOW = datetime(2026, 8, 3, tzinfo=timezone.utc)
_PROOF_OBSERVED_AT = "2026-08-03T00:00:00Z"
_PROOF_NOT_AFTER = "2026-08-03T00:05:00Z"


def _artifacts():
    vectors = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    package = build_rule_package(
        vectors["package_manifest"],
        {
            digest: bytes.fromhex(payload)
            for digest, payload in vectors["package_resources_hex"].items()
        },
    )
    statements = (
        TradeRuleRecognition.from_dict(vectors["recognized"]),
        TradeRuleRecognition.from_dict(vectors["revoked"]),
    )
    publisher = AgentIdentity.generate()
    offer_digest = "sha256:" + ("a" * 64)
    binding = sign_offer_package_binding(
        publisher,
        offer_digest=offer_digest,
        package_digest=package.digest,
        created="2026-08-01T00:00:00Z",
    )
    return package, statements, publisher, offer_digest, binding


def _build_proof(package, statements, publisher, binding):
    return build_rule_recognition_proof_bundle(
        package,
        statements,
        offer_package_binding=binding,
        observer_identity=publisher,
        observed_at=_PROOF_OBSERVED_AT,
        not_after=_PROOF_NOT_AFTER,
        now=_PROOF_NOW,
    )


def _long_recognition_chain(package, *, count=300):
    issuer = AgentIdentity.generate()
    statements = []
    previous = None
    for _index in range(count):
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
    return tuple(statements)


def test_paged_proof_round_trips_chain_beyond_v1_limit():
    package, _statements, publisher, offer_digest, binding = _artifacts()
    statements = _long_recognition_chain(package)

    with pytest.raises(
        RuleRecognitionProofBundleRejected,
        match="statement count exceeds",
    ):
        _build_proof(package, statements, publisher, binding)
    wires = build_rule_recognition_proof_pages(
        package,
        statements,
        offer_package_binding=binding,
        observer_identity=publisher,
        observed_at=_PROOF_OBSERVED_AT,
        not_after=_PROOF_NOT_AFTER,
        now=_PROOF_NOW,
    )
    verified = parse_rule_recognition_proof_pages(
        wires,
        package=package,
        expected_offer_digest=offer_digest,
        expected_offer_publisher_did=publisher.as_did(),
        now=_PROOF_NOW,
    )

    assert len(wires) >= 3
    assert len(verified.statements) == 300
    assert [item.digest for item in verified.statements] == [
        item.digest for item in statements
    ]
    assert all(
        len(trade_canonical_json(page)) <= 262_144 for page in wires
    )


def test_paged_proof_rejects_missing_tampered_or_cross_observation_page():
    package, _statements, publisher, offer_digest, binding = _artifacts()
    statements = _long_recognition_chain(package)
    wires = build_rule_recognition_proof_pages(
        package,
        statements,
        offer_package_binding=binding,
        observer_identity=publisher,
        observed_at=_PROOF_OBSERVED_AT,
        not_after=_PROOF_NOT_AFTER,
        now=_PROOF_NOW,
    )
    with pytest.raises(
        RuleRecognitionProofBundleRejected,
        match="incomplete or duplicated",
    ):
        parse_rule_recognition_proof_pages(
            wires[:-1],
            package=package,
            expected_offer_digest=offer_digest,
            expected_offer_publisher_did=publisher.as_did(),
            now=_PROOF_NOW,
        )

    tampered = copy.deepcopy(wires)
    tampered[0]["issuer_segments"][0]["statements"][0]["decision"] = "revoked"
    with pytest.raises(RuleRecognitionProofBundleRejected):
        parse_rule_recognition_proof_pages(
            tampered,
            package=package,
            expected_offer_digest=offer_digest,
            expected_offer_publisher_did=publisher.as_did(),
            now=_PROOF_NOW,
        )

    refreshed_at = _PROOF_NOW + timedelta(minutes=1)
    refreshed = build_rule_recognition_proof_pages(
        package,
        statements,
        offer_package_binding=binding,
        observer_identity=publisher,
        observed_at=refreshed_at.isoformat().replace("+00:00", "Z"),
        not_after=(refreshed_at + timedelta(minutes=5)).isoformat().replace(
            "+00:00",
            "Z",
        ),
        now=refreshed_at,
    )
    mixed = list(wires)
    mixed[-1] = refreshed[-1]
    with pytest.raises(
        RuleRecognitionProofBundleRejected,
        match="different observations",
    ):
        parse_rule_recognition_proof_pages(
            mixed,
            package=package,
            expected_offer_digest=offer_digest,
            expected_offer_publisher_did=publisher.as_did(),
            now=refreshed_at,
        )


def test_paged_proof_enforces_page_and_total_byte_limits(monkeypatch):
    package, statements, publisher, offer_digest, binding = _artifacts()
    wires = build_rule_recognition_proof_pages(
        package,
        statements,
        offer_package_binding=binding,
        observer_identity=publisher,
        observed_at=_PROOF_OBSERVED_AT,
        not_after=_PROOF_NOT_AFTER,
        now=_PROOF_NOW,
    )
    page_size = len(trade_canonical_json(wires[0]))
    monkeypatch.setattr(
        "nth_dao.trade_rules.recognition_transport_pages."
        "MAX_RULE_RECOGNITION_PROOF_PAGE_BYTES",
        page_size - 1,
    )
    with pytest.raises(
        RuleRecognitionProofBundleRejected,
        match="page exceeds its byte limit",
    ):
        parse_rule_recognition_proof_pages(
            wires,
            package=package,
            expected_offer_digest=offer_digest,
            expected_offer_publisher_did=publisher.as_did(),
            now=_PROOF_NOW,
        )

    monkeypatch.setattr(
        "nth_dao.trade_rules.recognition_transport_pages."
        "MAX_RULE_RECOGNITION_PROOF_PAGE_BYTES",
        256 * 1024,
    )
    monkeypatch.setattr(
        "nth_dao.trade_rules.recognition_transport_pages."
        "MAX_RULE_RECOGNITION_PROOF_PAGE_SET_BYTES",
        page_size - 1,
    )
    with pytest.raises(
        RuleRecognitionProofBundleRejected,
        match="page set exceeds its byte limit",
    ):
        parse_rule_recognition_proof_pages(
            wires,
            package=package,
            expected_offer_digest=offer_digest,
            expected_offer_publisher_did=publisher.as_did(),
            now=_PROOF_NOW,
        )


def test_observed_recognition_proof_round_trip_grants_no_authority():
    package, statements, publisher, offer_digest, binding = _artifacts()

    wire = _build_proof(package, statements, publisher, binding)
    proof = parse_rule_recognition_proof_bundle(
        json.dumps(wire, separators=(",", ":"), sort_keys=True).encode(),
        package=package,
        expected_offer_digest=offer_digest,
        expected_offer_publisher_did=publisher.as_did(),
        now=_PROOF_NOW,
    )

    assert proof.offer_digest == offer_digest
    assert proof.package_digest == package.digest
    assert [item.digest for item in proof.statements] == [
        item.digest for item in statements
    ]
    assert wire["issuer_chains"][0]["head_digests"] == [
        statements[-1].digest
    ]
    assert "trust_granted" not in wire
    assert "execution_authorized" not in wire


def test_proof_preserves_and_discloses_forked_heads():
    package, _statements, publisher, _offer_digest, binding = _artifacts()
    issuer = AgentIdentity.generate()
    first = create_rule_recognition(
        issuer,
        package=package,
        decision="recognized",
        issued_at="2026-08-01T00:00:00Z",
        not_after="2026-08-20T00:00:00Z",
        now=datetime(2026, 8, 1, tzinfo=timezone.utc),
    )
    branch_a = create_rule_recognition(
        issuer,
        package=package,
        decision="revoked",
        reason_codes=["security.withdrawn"],
        issued_at="2026-08-02T00:00:00Z",
        not_after="2026-08-20T00:00:00Z",
        previous=first,
        now=datetime(2026, 8, 2, tzinfo=timezone.utc),
    )
    branch_b = create_rule_recognition(
        issuer,
        package=package,
        decision="deprecated",
        reason_codes=["quality.changed"],
        issued_at="2026-08-03T00:00:00Z",
        not_after="2026-08-20T00:00:00Z",
        previous=first,
        now=datetime(2026, 8, 3, tzinfo=timezone.utc),
    )

    wire = _build_proof(
        package,
        [first, branch_b, branch_a],
        publisher,
        binding,
    )

    assert wire["issuer_chains"][0]["head_digests"] == sorted(
        [branch_a.digest, branch_b.digest]
    )
    assert len(
        parse_rule_recognition_proof_bundle(
            wire,
            package=package,
            now=_PROOF_NOW,
        ).statements
    ) == 3


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda value: value["issuer_chains"][0]["statements"].pop(0),
            "missing a predecessor",
        ),
        (
            lambda value: value["issuer_chains"][0].update(
                {"head_digests": [value["issuer_chains"][0]["statements"][0]["proof"]["proof_value"]]}
            ),
            "heads do not match",
        ),
        (
            lambda value: value.update({"offer_digest": "sha256:" + ("b" * 64)}),
            "binding is for another Offer",
        ),
    ],
)
def test_proof_rejects_incomplete_or_relabelled_disclosure(mutate, message):
    package, statements, publisher, _offer_digest, binding = _artifacts()
    wire = _build_proof(package, statements, publisher, binding)
    invalid = copy.deepcopy(wire)
    mutate(invalid)

    with pytest.raises(RuleRecognitionProofBundleRejected, match=message):
        parse_rule_recognition_proof_bundle(
            invalid,
            package=package,
            now=_PROOF_NOW,
        )


def test_observer_signature_rejects_validly_reheaded_revocation_stripping():
    package, statements, publisher, _offer_digest, binding = _artifacts()
    wire = _build_proof(package, statements, publisher, binding)
    stripped = copy.deepcopy(wire)
    chain = stripped["issuer_chains"][0]
    chain["statements"].pop()
    retained = [
        TradeRuleRecognition.from_dict(item)
        for item in chain["statements"]
    ]
    digests = {item.digest for item in retained}
    referenced = {
        item.to_dict()["previous_statement_digest"]
        for item in retained
        if item.to_dict()["previous_statement_digest"] is not None
    }
    chain["head_digests"] = sorted(digests - referenced)
    stripped["observed_heads_digest"] = "sha256:" + hashlib.sha256(
        trade_canonical_json({
            "issuer_heads": [{
                "issuer_did": chain["issuer_did"],
                "head_digests": chain["head_digests"],
            }]
        })
    ).hexdigest()

    with pytest.raises(
        RuleRecognitionProofBundleRejected,
        match="observer signature invalid",
    ):
        parse_rule_recognition_proof_bundle(
            stripped,
            package=package,
            now=_PROOF_NOW,
        )


def test_observed_proof_rejects_expiry_and_wrong_observer():
    package, statements, publisher, _offer_digest, binding = _artifacts()
    wire = _build_proof(package, statements, publisher, binding)

    with pytest.raises(
        RuleRecognitionProofBundleRejected,
        match="has expired",
    ):
        parse_rule_recognition_proof_bundle(
            wire,
            package=package,
            now=datetime(2026, 8, 3, 0, 5, tzinfo=timezone.utc),
        )

    with pytest.raises(
        RuleRecognitionProofBundleRejected,
        match="signer is not the Offer publisher",
    ):
        build_rule_recognition_proof_bundle(
            package,
            statements,
            offer_package_binding=binding,
            observer_identity=AgentIdentity.generate(),
            observed_at=_PROOF_OBSERVED_AT,
            not_after=_PROOF_NOT_AFTER,
            now=_PROOF_NOW,
        )


def test_proof_rejects_duplicate_and_unsorted_issuer_graph():
    package, statements, publisher, _offer_digest, binding = _artifacts()
    wire = _build_proof(package, statements, publisher, binding)
    duplicate = copy.deepcopy(wire)
    duplicate["issuer_chains"][0]["statements"].append(
        copy.deepcopy(duplicate["issuer_chains"][0]["statements"][-1])
    )

    with pytest.raises(
        RuleRecognitionProofBundleRejected,
        match="duplicate statements",
    ):
        parse_rule_recognition_proof_bundle(
            duplicate,
            package=package,
            now=_PROOF_NOW,
        )

    unsorted = copy.deepcopy(wire)
    unsorted["issuer_chains"][0]["statements"].reverse()
    with pytest.raises(
        RuleRecognitionProofBundleRejected,
        match="sequence/digest sorted",
    ):
        parse_rule_recognition_proof_bundle(
            unsorted,
            package=package,
            now=_PROOF_NOW,
        )


def test_proof_is_bounded_before_materializing_untrusted_statements():
    package, statements, publisher, _offer_digest, binding = _artifacts()
    wire = _build_proof(package, statements, publisher, binding)
    oversized = copy.deepcopy(wire)
    oversized["issuer_chains"] = [
        copy.deepcopy(wire["issuer_chains"][0]) for _ in range(65)
    ]

    with pytest.raises(
        RuleRecognitionProofBundleRejected,
        match="issuer count exceeds",
    ):
        parse_rule_recognition_proof_bundle(
            oversized,
            package=package,
            now=_PROOF_NOW,
        )


def test_trade_rules_facade_exports_recognition_transport_contract():
    import nth_dao.trade_rules as facade

    for name in (
        "MAX_RULE_RECOGNITION_PROOF_PAGE_BYTES",
        "MAX_RULE_RECOGNITION_PROOF_PAGE_SET_BYTES",
        "RuleRecognitionProofBundleRejected",
        "VerifiedRuleRecognitionProofBundle",
        "VerifiedRuleRecognitionProofPage",
        "VerifiedRuleRecognitionProofSet",
        "build_rule_recognition_proof_bundle",
        "build_rule_recognition_proof_pages",
        "parse_rule_recognition_proof_bundle",
        "parse_rule_recognition_proof_pages",
    ):
        assert name in facade.__all__
        assert getattr(facade, name) is not None


def test_recognition_proof_conformance_vector_is_current_and_replayable():
    stored = json.loads(PROOF_VECTORS_PATH.read_text(encoding="utf-8"))
    assert stored == generate_proof_vectors()
    package = build_rule_package(
        stored["package_manifest"],
        {
            digest: bytes.fromhex(payload)
            for digest, payload in stored["package_resources_hex"].items()
        },
    )
    proof = parse_rule_recognition_proof_bundle(
        stored["bundle"],
        package=package,
        expected_offer_digest=stored["offer_digest"],
        expected_offer_publisher_did=stored["offer_publisher_did"],
        now=_PROOF_NOW,
    )
    assert proof.canonical_bytes.hex() == stored["expected_canonical_hex"]
    for name, invalid in stored["invalid"].items():
        with pytest.raises(
            RuleRecognitionProofBundleRejected,
            match={
                "missing_predecessor": "missing a predecessor",
                "hidden_head": "heads do not match",
                "relabelled_offer": "binding is for another Offer",
            }[name],
        ):
            parse_rule_recognition_proof_bundle(
                invalid,
                package=package,
                now=_PROOF_NOW,
            )


def test_recognition_proof_schema_accepts_vector_and_rejects_unknown_field():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(PROOF_SCHEMA_PATH.read_text(encoding="utf-8"))
    recognition_schema = json.loads(
        (
            Path(__file__).parents[1]
            / "nth_dao"
            / "trade_rules"
            / "schemas"
            / "trade-rule-recognition.schema.json"
        ).read_text(encoding="utf-8")
    )
    schema["properties"]["issuer_chains"]["items"]["properties"][
        "statements"
    ]["items"] = recognition_schema
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema)
    stored = json.loads(PROOF_VECTORS_PATH.read_text(encoding="utf-8"))
    validator.validate(stored["bundle"])

    invalid = copy.deepcopy(stored["bundle"])
    invalid["unexpected"] = True
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(invalid)


def test_recognition_page_conformance_vector_is_current_and_replayable():
    stored = json.loads(PAGE_PROOF_VECTORS_PATH.read_text(encoding="utf-8"))
    assert stored == generate_page_proof_vectors()
    package = build_rule_package(
        stored["package_manifest"],
        {
            digest: bytes.fromhex(payload)
            for digest, payload in stored["package_resources_hex"].items()
        },
    )
    proof_set = parse_rule_recognition_proof_pages(
        stored["pages"],
        package=package,
        expected_offer_digest=stored["offer_digest"],
        expected_offer_publisher_did=stored["offer_publisher_did"],
        now=_PROOF_NOW,
    )
    assert list(proof_set.proof_digests) == stored["expected_page_digests"]
    assert [
        page.canonical_bytes.hex() for page in proof_set.pages
    ] == stored["expected_canonical_hex"]
    for name, invalid in stored["invalid_page_sets"].items():
        with pytest.raises(
            RuleRecognitionProofBundleRejected,
            match={
                "missing_page": "incomplete or duplicated",
                "mixed_observation": "different observations",
                "tampered_page": "signature invalid",
            }[name],
        ):
            parse_rule_recognition_proof_pages(
                invalid,
                package=package,
                expected_offer_digest=stored["offer_digest"],
                expected_offer_publisher_did=stored[
                    "offer_publisher_did"
                ],
                now=_PROOF_NOW,
            )


def test_recognition_page_schema_accepts_vector_and_rejects_unknown_field():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(PAGE_PROOF_SCHEMA_PATH.read_text(encoding="utf-8"))
    recognition_schema = json.loads(
        (
            Path(__file__).parents[1]
            / "nth_dao"
            / "trade_rules"
            / "schemas"
            / "trade-rule-recognition.schema.json"
        ).read_text(encoding="utf-8")
    )
    schema["properties"]["issuer_segments"]["items"]["properties"][
        "statements"
    ]["items"] = recognition_schema
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema)
    stored = json.loads(PAGE_PROOF_VECTORS_PATH.read_text(encoding="utf-8"))
    for page in stored["pages"]:
        validator.validate(page)
    invalid = copy.deepcopy(stored["pages"][0])
    invalid["unexpected"] = True
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(invalid)


def test_proof_rebuilds_large_package_only_once(monkeypatch):
    import nth_dao.trade_rules.recognition_transport as transport

    package, statements, publisher, _offer_digest, binding = _artifacts()
    original = transport.build_rule_package
    calls = 0

    def counted(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(transport, "build_rule_package", counted)
    build_rule_recognition_proof_bundle(
        package,
        statements,
        offer_package_binding=binding,
        observer_identity=publisher,
        observed_at=_PROOF_OBSERVED_AT,
        not_after=_PROOF_NOT_AFTER,
        now=_PROOF_NOW,
    )

    assert calls == 1
