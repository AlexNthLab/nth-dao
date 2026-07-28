import copy
import hashlib

import pytest

import nth_dao.trade_rules.manifest as manifest_module
from nth_dao.identity import AgentIdentity, crypto_available
from nth_dao.trade_rules import (
    MANIFEST_PROOF_TYPE,
    MANIFEST_SIGNING_DOMAIN,
    InspectedTradeRuleManifest,
    ManifestRejected,
    TradeRuleManifest,
    inspection_digest,
    manifest_body,
    manifest_digest,
    manifest_signing_input,
    sign_manifest,
    verify_manifest,
)

pytestmark = pytest.mark.skipif(
    not crypto_available(), reason="Trade Rule signatures require PyNaCl"
)


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _body(identity: AgentIdentity, **overrides):
    values = {
        "rule_id": "org.nthdao.reference.free-digital-result",
        "version": "0.1.0",
        "publisher_did": identity.as_did(),
        "summary": "Free content-addressed digital result",
        "applies_to": ["digital_resource", "service"],
        "families": ["pricing", "fulfillment", "acceptance", "rights"],
        "resources": [
            {
                "purpose": "terms-schema",
                "media_type": "application/schema+json",
                "digest": _digest(b"terms"),
                "size": 5,
            }
        ],
        "required_capabilities": ["org.nthdao.core.content-addressed-evidence/1"],
        "hook_contracts": [
            {
                "name": "acceptance.evaluate",
                "version": "1",
                "input_schema_digest": _digest(b"input"),
                "output_schema_digest": _digest(b"output"),
                "side_effect": "none",
            }
        ],
        "published_at": "2026-07-28T00:00:00Z",
        "not_after": "2027-07-28T00:00:00Z",
    }
    values.update(overrides)
    return manifest_body(**values)


def _signed(identity=None):
    identity = identity or AgentIdentity.generate(label="rule-publisher")
    return identity, sign_manifest(
        identity,
        _body(identity),
        created="2026-07-28T00:00:01Z",
    )


def test_manifest_sign_verify_digest_and_json_round_trip():
    _, manifest = _signed()
    assert manifest.verified
    assert verify_manifest(manifest) == (True, "ok")
    assert manifest.to_dict()["proof"]["type"] == MANIFEST_PROOF_TYPE
    assert manifest_signing_input(manifest.to_dict()).startswith(
        MANIFEST_SIGNING_DOMAIN + b"\x00"
    )
    digest = manifest_digest(manifest)
    loaded = TradeRuleManifest.from_json(manifest.canonical_bytes)
    assert loaded.canonical_bytes == manifest.canonical_bytes
    assert manifest_digest(loaded) == digest


def test_manifest_wrapper_is_immutable_from_returned_dict():
    _, manifest = _signed()
    document = manifest.to_dict()
    document["summary"] = "tampered"
    document["resources"][0]["size"] = 999
    assert manifest.to_dict()["summary"] != "tampered"
    assert manifest.to_dict()["resources"][0]["size"] == 5
    assert verify_manifest(manifest) == (True, "ok")


def test_manifest_verifies_the_same_snapshot_that_it_stores(monkeypatch):
    _, valid_manifest = _signed()
    valid_document = valid_manifest.to_dict()
    shared_document = copy.deepcopy(valid_document)
    shared_document["summary"] = "tampered before verification"
    real_verify = manifest_module._verify_snapshot_signature

    def mutate_caller_then_verify(snapshot):
        shared_document.clear()
        shared_document.update(copy.deepcopy(valid_document))
        return real_verify(snapshot)

    monkeypatch.setattr(
        manifest_module,
        "_verify_snapshot_signature",
        mutate_caller_then_verify,
    )
    with pytest.raises(ManifestRejected, match="signature"):
        TradeRuleManifest.from_dict(shared_document)


def test_manifest_digest_is_independent_of_input_key_order():
    identity, manifest = _signed()
    reordered_body = dict(reversed(list(_body(identity).items())))
    reordered = sign_manifest(identity, reordered_body, created="2026-07-28T00:00:01Z")
    assert reordered.canonical_bytes == manifest.canonical_bytes
    assert manifest_digest(reordered) == manifest_digest(manifest)


@pytest.mark.parametrize(
    "path, value",
    [
        (("summary",), "tampered"),
        (("proof", "created"), "2026-07-28T00:00:02Z"),
        (("proof", "proof_purpose"), "authentication"),
        (("proof", "verification_method"), "did:key:zBad#zBad"),
    ],
)
def test_manifest_tampering_fails_verification(path, value):
    _, manifest = _signed()
    document = manifest.to_dict()
    target = document
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    assert verify_manifest(document)[0] is False
    with pytest.raises(ManifestRejected):
        TradeRuleManifest.from_dict(document)


def test_manifest_rejects_signer_publisher_mismatch():
    publisher = AgentIdentity.generate()
    attacker = AgentIdentity.generate()
    with pytest.raises(ManifestRejected, match="signer"):
        sign_manifest(
            attacker,
            _body(publisher),
            created="2026-07-28T00:00:01Z",
        )


def test_manifest_rejects_unknown_top_level_field():
    _, manifest = _signed()
    document = manifest.to_dict()
    document["unsigned_extension"] = {}
    assert verify_manifest(document)[0] is False


def test_manifest_rejects_duplicate_resource_binding():
    identity = AgentIdentity.generate()
    resource = {
        "purpose": "terms-schema",
        "media_type": "application/schema+json",
        "digest": _digest(b"terms"),
        "size": 5,
    }
    with pytest.raises(ManifestRejected, match="duplicate"):
        _body(identity, resources=[resource, copy.deepcopy(resource)])


def test_manifest_rejects_declarative_permission_escalation():
    identity = AgentIdentity.generate()
    with pytest.raises(ManifestRejected, match="cannot request permissions"):
        manifest_body(
            **{
                **{
                    key: value
                    for key, value in _body(identity).items()
                    if key
                    not in {
                        "kind",
                        "protocol_version",
                        "dependencies",
                        "conflicts",
                        "execution",
                        "extensions",
                    }
                },
                "permissions": ["network:domain:example.com"],
            }
        )


def test_manifest_allows_future_execution_declaration_without_executing_it():
    identity = AgentIdentity.generate()
    body = manifest_body(
        rule_id="com.example.payment/adapter",
        version="1.0.0",
        publisher_did=identity.as_did(),
        summary="Requires a separately installed adapter",
        applies_to=["service"],
        families=["payment"],
        resources=[
            {
                "purpose": "terms-schema",
                "media_type": "application/schema+json",
                "digest": _digest(b"schema"),
                "size": 6,
            }
        ],
        execution_mode="adapter",
        permissions=["payment:authorize:test"],
        published_at="2026-07-28T00:00:00Z",
    )
    manifest = sign_manifest(identity, body, created="2026-07-28T00:00:01Z")
    assert verify_manifest(manifest) == (True, "ok")
    assert manifest.to_dict()["execution"]["mode"] == "adapter"


@pytest.mark.parametrize(
    "published, created, not_after, reason",
    [
        (
            "2026-07-28T00:00:02Z",
            "2026-07-28T00:00:01Z",
            "2027-07-28T00:00:00Z",
            "before published",
        ),
        (
            "2026-07-28T00:00:00Z",
            "2026-07-28T00:00:01Z",
            "2026-07-28T00:00:01Z",
            "later than proof",
        ),
    ],
)
def test_manifest_rejects_invalid_proof_time_order(
    published, created, not_after, reason
):
    identity = AgentIdentity.generate()
    with pytest.raises(ManifestRejected, match=reason):
        sign_manifest(
            identity,
            _body(
                identity,
                published_at=published,
                not_after=not_after,
            ),
            created=created,
        )


def test_manifest_rejects_noncanonical_signature_encoding():
    _, manifest = _signed()
    document = manifest.to_dict()
    document["proof"]["proof_value"] += "="
    ok, reason = verify_manifest(document)
    assert not ok
    assert "proof_value" in reason


def test_inspected_manifest_has_distinct_type_and_digest_namespace():
    _, manifest = _signed()
    document = manifest.to_dict()
    document["proof"]["proof_value"] = "A" * 86
    inspected = InspectedTradeRuleManifest.from_dict(document)
    assert not isinstance(inspected, TradeRuleManifest)
    assert not inspected.verified
    with pytest.raises(ManifestRejected, match="verified manifest"):
        manifest_digest(inspected)
    assert inspection_digest(inspected).startswith("unverified-sha256:")


def test_manifest_json_parser_rejects_duplicate_keys():
    _, manifest = _signed()
    raw = manifest.canonical_bytes.decode("utf-8")
    duplicated = '{"kind":"org.nthdao.trade.rule-manifest",' + raw[1:]
    with pytest.raises(ManifestRejected, match="duplicate"):
        TradeRuleManifest.from_json(duplicated)


def test_manifest_body_copies_mutable_inputs():
    identity = AgentIdentity.generate()
    resources = [
        {
            "purpose": "terms-schema",
            "media_type": "application/schema+json",
            "digest": _digest(b"terms"),
            "size": 5,
        }
    ]
    body = _body(identity, resources=resources)
    resources[0]["size"] = 999
    assert body["resources"][0]["size"] == 5


def test_manifest_body_normalizes_set_like_array_order():
    identity = AgentIdentity.generate()
    body = _body(
        identity,
        applies_to=["service", "digital_resource"],
        families=["rights", "acceptance", "pricing", "fulfillment"],
        required_capabilities=["z.example/cap", "a.example/cap"],
    )
    assert body["applies_to"] == ["digital_resource", "service"]
    assert body["families"] == [
        "acceptance",
        "fulfillment",
        "pricing",
        "rights",
    ]
    assert body["required_capabilities"] == ["a.example/cap", "z.example/cap"]


def test_manifest_parser_rejects_noncanonical_set_order():
    _, manifest = _signed()
    document = manifest.to_dict()
    document["families"].reverse()
    with pytest.raises(ManifestRejected, match="sorted"):
        InspectedTradeRuleManifest.from_dict(document)


@pytest.mark.parametrize(
    "rule_id",
    [
        "local",
        "org..example",
        ".org.example",
        "org.example.",
        "org.example/-bad",
    ],
)
def test_manifest_rejects_ambiguous_rule_namespaces(rule_id):
    identity = AgentIdentity.generate()
    with pytest.raises(ManifestRejected, match="rule_id"):
        _body(identity, rule_id=rule_id)


@pytest.mark.parametrize(
    "version",
    [
        "1.0.0-01",
        "1.0.0-alpha..1",
        "1.0.0+build..1",
        "01.0.0",
    ],
)
def test_manifest_rejects_non_semver_versions(version):
    identity = AgentIdentity.generate()
    with pytest.raises(ManifestRejected, match="SemVer"):
        _body(identity, version=version)


def test_manifest_wrapper_has_no_public_trust_forging_constructor():
    with pytest.raises(TypeError):
        TradeRuleManifest(b"{}", True)


def test_manifest_private_factory_cannot_forge_verified_state():
    forged = TradeRuleManifest._create(b"{}")
    assert forged.verified is False


def test_manifest_rejects_reference_that_is_dependency_and_conflict():
    identity = AgentIdentity.generate()
    reference = {
        "rule_id": "org.example.shared",
        "digest": _digest(b"shared"),
    }
    with pytest.raises(ManifestRejected, match="both a dependency and a conflict"):
        _body(
            identity,
            dependencies=[reference],
            conflicts=[copy.deepcopy(reference)],
        )


def test_manifest_rejects_ambiguous_hook_version():
    identity = AgentIdentity.generate()
    hooks = copy.deepcopy(_body(identity)["hook_contracts"])
    hooks[0]["version"] = "version 1"
    with pytest.raises(ManifestRejected, match="namespaced token"):
        _body(identity, hook_contracts=hooks)


@pytest.mark.parametrize(
    "overrides",
    [
        {"summary": "\ud800"},
        {"extensions": {"org.example/test": {"text": "\ud800"}}},
    ],
)
def test_manifest_body_normalizes_invalid_unicode_error(overrides):
    identity = AgentIdentity.generate()
    with pytest.raises(ManifestRejected, match="invalid Unicode"):
        _body(identity, **overrides)


@pytest.mark.parametrize(
    "mutator",
    [
        lambda document: document.__setitem__(1, "bad-key"),
        lambda document: document["execution"].__setitem__("mode", []),
        lambda document: document["hook_contracts"][0].__setitem__("side_effect", []),
        lambda document: document["extensions"].__setitem__(1, {}),
    ],
)
def test_from_dict_type_confusion_fails_as_manifest_rejected(mutator):
    _, manifest = _signed()
    document = manifest.to_dict()
    mutator(document)
    with pytest.raises(ManifestRejected):
        InspectedTradeRuleManifest.from_dict(document)
