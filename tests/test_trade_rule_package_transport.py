import copy
import hashlib
import json
from pathlib import Path

import pytest

from nth_dao.b64u import b64u_encode
from nth_dao.identity import AgentIdentity, crypto_available
from nth_dao.trade_rules import (
    MAX_PACKAGE_RESOURCE_BYTES,
    MAX_RESOURCE_BYTES,
    manifest_body,
    sign_manifest,
    sign_offer_package_binding,
)
from nth_dao.trade_rules.package_store import build_rule_package
from nth_dao.trade_rules.package_transport import (
    MAX_RULE_PACKAGE_BUNDLE_BYTES,
    RulePackageBundleRejected,
    build_rule_package_bundle,
    parse_rule_package_bundle,
    rule_package_bundle_bytes,
)

pytestmark = pytest.mark.skipif(
    not crypto_available(), reason="Trade Rule signatures require PyNaCl"
)


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _package():
    identity = AgentIdentity.generate()
    resources = {
        _digest(b'{"schema":1}'): b'{"schema":1}',
        _digest(b"terms"): b"terms",
    }
    manifest = sign_manifest(
        identity,
        manifest_body(
            rule_id="org.nthdao.test.transport",
            version="1.0.0",
            publisher_did=identity.as_did(),
            summary="Transport test",
            applies_to=["service"],
            families=["fulfillment"],
            resources=[
                {
                    "purpose": f"resource-{index}",
                    "media_type": "application/octet-stream",
                    "digest": digest,
                    "size": len(payload),
                }
                for index, (digest, payload) in enumerate(resources.items())
            ],
            published_at="2026-08-01T00:00:00Z",
            not_after="2027-08-01T00:00:00Z",
        ),
        created="2026-08-01T00:00:01Z",
    )
    return identity, build_rule_package(manifest, resources)


def test_rule_package_bundle_round_trip_is_deterministic_and_bound():
    identity, package = _package()
    offer_digest = "sha256:" + ("a" * 64)
    bundle = build_rule_package_bundle(
        package,
        offer_package_binding=sign_offer_package_binding(
            identity,
            offer_digest=offer_digest,
            package_digest=package.digest,
            created="2026-08-01T00:00:01Z",
        ),
    )

    encoded = rule_package_bundle_bytes(bundle)
    parsed = parse_rule_package_bundle(
        encoded,
        expected_offer_digest=offer_digest,
        expected_package_digest=package.digest,
    )

    assert parsed.digest == package.digest
    assert dict(parsed.resources) == dict(package.resources)
    assert encoded == rule_package_bundle_bytes(bundle)
    assert len(encoded) <= MAX_RULE_PACKAGE_BUNDLE_BYTES


@pytest.mark.parametrize(
    "mutator, reason",
    [
        (lambda value: value.update({"extra": True}), "fields"),
        (
            lambda value: value.update({"offer_digest": "sha256:" + ("b" * 64)}),
            "another Offer",
        ),
        (
            lambda value: value["resources"].reverse(),
            "digest-sorted",
        ),
        (
            lambda value: value["resources"][0].update({"bytes_b64u": "Zh"}),
            "canonical base64url",
        ),
        (
            lambda value: value["resources"][0].update(
                {"bytes_b64u": b64u_encode(b"tampered")}
            ),
            "verification failed",
        ),
        (
            lambda value: value["manifest"].update({"summary": "tampered"}),
            "verification failed",
        ),
    ],
)
def test_rule_package_bundle_rejects_tampering(mutator, reason):
    identity, package = _package()
    offer_digest = "sha256:" + ("a" * 64)
    bundle = copy.deepcopy(
        build_rule_package_bundle(
            package,
            offer_package_binding=sign_offer_package_binding(
                identity,
                offer_digest=offer_digest,
                package_digest=package.digest,
                created="2026-08-01T00:00:01Z",
            ),
        )
    )
    mutator(bundle)

    with pytest.raises(RulePackageBundleRejected, match=reason):
        parse_rule_package_bundle(
            bundle,
            expected_offer_digest="sha256:" + ("a" * 64),
            expected_package_digest=package.digest,
        )


def test_rule_package_bundle_rejects_oversized_wire_before_json_parse():
    raw = b"{" + (b" " * MAX_RULE_PACKAGE_BUNDLE_BYTES) + b"}"
    with pytest.raises(RulePackageBundleRejected, match="wire limit"):
        parse_rule_package_bundle(raw)


def test_rule_package_bundle_offer_digest_cannot_be_relabelled_by_caller():
    identity, package = _package()
    original_offer_digest = "sha256:" + ("a" * 64)
    relabelled_offer_digest = "sha256:" + ("b" * 64)
    bundle = build_rule_package_bundle(
        package,
        offer_package_binding=sign_offer_package_binding(
            identity,
            offer_digest=original_offer_digest,
            package_digest=package.digest,
            created="2026-08-01T00:00:01Z",
        ),
    )
    bundle["offer_digest"] = relabelled_offer_digest

    with pytest.raises(RulePackageBundleRejected, match="another Offer"):
        parse_rule_package_bundle(
            bundle,
            expected_offer_digest=relabelled_offer_digest,
            expected_package_digest=package.digest,
            expected_offer_publisher_did=identity.as_did(),
        )


def test_rule_package_bundle_requires_offer_publisher_as_binding_signer():
    identity, package = _package()
    wrong_identity = AgentIdentity.generate()
    offer_digest = "sha256:" + ("a" * 64)
    bundle = build_rule_package_bundle(
        package,
        offer_package_binding=sign_offer_package_binding(
            wrong_identity,
            offer_digest=offer_digest,
            package_digest=package.digest,
            created="2026-08-01T00:00:01Z",
        ),
    )

    with pytest.raises(RulePackageBundleRejected, match="not the Offer publisher"):
        parse_rule_package_bundle(
            bundle,
            expected_offer_digest=offer_digest,
            expected_package_digest=package.digest,
            expected_offer_publisher_did=identity.as_did(),
        )


def test_rule_package_bundle_json_rejects_non_object():
    with pytest.raises(RulePackageBundleRejected, match="JSON object"):
        parse_rule_package_bundle(json.dumps([]).encode())


def test_trade_rules_facade_exports_package_transport_contract():
    import nth_dao.trade_rules as facade

    for name in (
        "RulePackageBundleRejected",
        "build_rule_package_bundle",
        "parse_rule_package_bundle",
        "rule_package_bundle_bytes",
    ):
        assert name in facade.__all__
        assert getattr(facade, name) is not None


def test_rule_package_bundle_schema_accepts_fixture_and_rejects_unknown_field():
    jsonschema = pytest.importorskip("jsonschema")
    schema_root = Path(__file__).parents[1] / "nth_dao" / "trade_rules" / "schemas"
    schema = json.loads(
        (schema_root / "trade-rule-package-bundle.schema.json").read_text(
            encoding="utf-8"
        )
    )
    manifest_schema = json.loads(
        (schema_root / "trade-rule-manifest.schema.json").read_text(
            encoding="utf-8"
        )
    )
    # Resolve the packaged Manifest schema locally; runtime semantic checks
    # remain stricter than JSON Schema.
    schema["properties"]["manifest"] = manifest_schema
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema)
    identity, package = _package()
    bundle = build_rule_package_bundle(
        package,
        offer_package_binding=sign_offer_package_binding(
            identity,
            offer_digest="sha256:" + ("a" * 64),
            package_digest=package.digest,
            created="2026-08-01T00:00:01Z",
        ),
    )
    validator.validate(bundle)

    invalid = copy.deepcopy(bundle)
    invalid["unexpected"] = True
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(invalid)


def test_rule_package_bundle_near_limit_preserves_legal_unicode_manifest():
    identity = AgentIdentity.generate()
    payloads = [bytes([index]) * MAX_RESOURCE_BYTES for index in range(16)]
    resources = {_digest(payload): payload for payload in payloads}
    assert sum(map(len, resources.values())) == MAX_PACKAGE_RESOURCE_BYTES
    manifest = sign_manifest(
        identity,
        manifest_body(
            rule_id="org.nthdao.test.unicode-transport",
            version="1.0.0",
            publisher_did=identity.as_did(),
            summary="Unicode transport boundary",
            applies_to=["service"],
            families=["fulfillment"],
            resources=[
                {
                    "purpose": f"resource-{index:02d}",
                    "media_type": "application/octet-stream",
                    "digest": digest,
                    "size": len(payload),
                }
                for index, (digest, payload) in enumerate(resources.items())
            ],
            published_at="2026-08-01T00:00:00Z",
            not_after="2027-08-01T00:00:00Z",
            extensions={
                "org.nthdao.test/unicode": {
                    f"section_{index}": "\u4ea4\u6613" * 8_000
                    for index in range(4)
                }
            },
        ),
        created="2026-08-01T00:00:01Z",
    )
    package = build_rule_package(manifest, resources)
    bundle = build_rule_package_bundle(
        package,
        offer_package_binding=sign_offer_package_binding(
            identity,
            offer_digest="sha256:" + ("a" * 64),
            package_digest=package.digest,
            created="2026-08-01T00:00:01Z",
        ),
    )

    encoded = rule_package_bundle_bytes(bundle)
    restored = parse_rule_package_bundle(encoded)

    assert len(encoded) <= MAX_RULE_PACKAGE_BUNDLE_BYTES
    assert restored.digest == package.digest
    assert restored.manifest.to_dict()["extensions"] == (
        manifest.to_dict()["extensions"]
    )
