from __future__ import annotations

import copy
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import pytest

from nth_dao.identity import AgentIdentity, crypto_available
from nth_dao.market.resource_profile import (
    ResourceProfile,
    ResourceProfilePolicy,
    ResourceProfileRejected,
    ResourceProfileStore,
    map_community_category,
    resource_profile_body,
    sign_resource_profile,
    validate_profile_attributes,
    verify_resource_profile,
)
from nth_dao.market.resource_descriptor import (
    RESOURCE_DESCRIPTOR_EXTENSION,
    inline_resource_descriptor_digest,
    inspect_offer_resource_descriptors,
)
from nth_dao.market.resource_profile_conformance import (
    VECTORS_PATH,
    encoded_vectors,
    load_vectors,
    verify_vectors,
)


pytestmark = pytest.mark.skipif(
    not crypto_available(), reason="PyNaCl is required for signed profiles",
)


def test_shipped_resource_profile_vectors_match_generator_byte_for_byte():
    assert VECTORS_PATH.read_bytes() == encoded_vectors()


def test_resource_profile_reference_passes_positive_and_negative_vectors():
    assert verify_vectors(load_vectors()) == []


def _profile(identity: AgentIdentity) -> ResourceProfile:
    body = resource_profile_body(
        profile_id="org.nthdao.community/game-item",
        version="1.0.0",
        publisher_did=identity.as_did(),
        summary="Community description for transferable game items.",
        resource_types=["game/item"],
        category_mappings=[{
            "community_category": "gaming/items",
            "market_category": "products",
        }],
        schema={
            "type": "object",
            "properties": {
                "game": {
                    "type": "string",
                    "required": True,
                    "description": "Game namespace.",
                    "enum": [],
                },
                "quantity": {
                    "type": "integer",
                    "required": False,
                    "description": "Publisher-claimed quantity.",
                    "enum": [],
                },
                "server": {
                    "type": "string",
                    "required": False,
                    "description": "Publisher-claimed server.",
                    "enum": [],
                },
            },
            "additional_properties": False,
        },
        published_at="2026-08-08T00:00:00Z",
        not_after="2027-08-08T00:00:00Z",
    )
    return sign_resource_profile(
        identity, body, created="2026-08-08T00:00:01Z",
    )


def test_signed_resource_profile_round_trip_and_digest_are_stable():
    profile = _profile(AgentIdentity.generate(label="profile-publisher"))

    restored = ResourceProfile.from_json(profile.canonical_bytes)

    assert restored.canonical_bytes == profile.canonical_bytes
    assert restored.digest == profile.digest
    assert verify_resource_profile(restored) == (True, "ok")


def test_profile_signature_rejects_tampered_category_mapping():
    profile = _profile(AgentIdentity.generate(label="profile-publisher"))
    tampered = profile.to_dict()
    tampered["category_mappings"][0]["market_category"] = "services"

    ok, reason = verify_resource_profile(tampered)

    assert ok is False
    assert reason == "signature invalid"
    with pytest.raises(ResourceProfileRejected, match="signature invalid"):
        ResourceProfile.from_dict(tampered)


def test_profile_rejects_executable_or_remote_schema_features():
    identity = AgentIdentity.generate(label="profile-publisher")
    profile = _profile(identity).to_dict()
    body = {key: copy.deepcopy(value) for key, value in profile.items() if key != "proof"}
    body["schema"]["$ref"] = "https://attacker.example/schema.json"

    with pytest.raises(ResourceProfileRejected, match="schema fields"):
        sign_resource_profile(identity, body, created="2026-08-08T00:00:01Z")


def test_profile_schema_cannot_claim_descriptor_reserved_category_field():
    identity = AgentIdentity.generate(label="profile-publisher")
    body = {
        key: copy.deepcopy(value)
        for key, value in _profile(identity).to_dict().items()
        if key != "proof"
    }
    body["schema"]["properties"] = {
        "community_category": {
            "type": "string",
            "required": True,
            "description": "Ambiguous descriptor-owned field.",
            "enum": ["gaming/items"],
        },
    }

    with pytest.raises(ResourceProfileRejected, match="reserved by the descriptor"):
        sign_resource_profile(identity, body, created="2026-08-08T00:00:01Z")


@pytest.mark.parametrize("value", [1, "", "UPPER/CASE", "a" * 129])
def test_inline_descriptor_rejects_invalid_community_category_token(value):
    descriptor = {
        "kind": "org.nthdao.resource-profile.inline",
        "version": "1",
        "category": "products",
        "resource_type": "game/item",
        "resource_id": "urn:nthdao:game-item:example",
        "profile_ref": {},
        "attributes": {"community_category": value},
    }

    with pytest.raises(ValueError, match="community_category"):
        inline_resource_descriptor_digest(descriptor)


def test_profile_ref_uses_the_exact_profile_id_contract():
    long_profile_id = "a" * 63 + "." + "b" * 63 + "." + "c" * 50
    identity = AgentIdentity.generate(label="long-profile-id")
    body = resource_profile_body(
        profile_id=long_profile_id,
        version="1.0.0",
        publisher_did=identity.as_did(),
        summary="Long but valid shared profile identifier.",
        resource_types=["game/item"],
        category_mappings=[{
            "community_category": "gaming/items",
            "market_category": "products",
        }],
        schema={
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "required": False,
                    "description": "Display name.",
                    "enum": [],
                },
            },
            "additional_properties": False,
        },
        published_at="2026-08-08T00:00:00Z",
    )
    assert body["profile_id"] == long_profile_id

    descriptor = {
        "kind": "org.nthdao.resource-profile.inline",
        "version": "1",
        "category": "products",
        "resource_type": "game/item",
        "resource_id": "urn:nthdao:game-item:long-id",
        "profile_ref": {
            "rule_id": long_profile_id,
            "digest": "sha256:" + ("a" * 64),
        },
        "attributes": {},
    }
    assert inline_resource_descriptor_digest(descriptor).startswith("sha256:")

    descriptor["profile_ref"]["rule_id"] = 123
    with pytest.raises(ValueError, match="profile_ref rule_id"):
        inline_resource_descriptor_digest(descriptor)


def test_profile_rejects_wrong_signer_and_noncanonical_resource_types():
    owner = AgentIdentity.generate(label="owner")
    other = AgentIdentity.generate(label="other")
    body = {key: value for key, value in _profile(owner).to_dict().items() if key != "proof"}

    with pytest.raises(ResourceProfileRejected, match="signer"):
        sign_resource_profile(other, body, created="2026-08-08T00:00:01Z")

    body["resource_types"] = ["z/type", "a/type"]
    with pytest.raises(ResourceProfileRejected, match="sorted and unique"):
        sign_resource_profile(owner, body, created="2026-08-08T00:00:01Z")


def test_category_mapping_requires_explicit_local_recognition():
    profile = _profile(AgentIdentity.generate(label="profile-publisher"))

    assert map_community_category(
        profile, "gaming/items", accepted_digests=(),
    ) == ("other", "profile-not-recognized")
    assert map_community_category(
        profile, "gaming/items", accepted_digests={profile.digest},
    ) == ("products", "recognized-profile")
    assert map_community_category(
        profile, "gaming/unknown", accepted_digests={profile.digest},
    ) == ("other", "community-category-unmapped")
    assert map_community_category(
        profile,
        "gaming/items",
        accepted_digests={profile.digest},
        at=datetime(2028, 1, 1, tzinfo=timezone.utc),
    ) == ("other", "expired")


def test_profile_attribute_schema_rejects_missing_wrong_and_unknown_fields():
    profile = _profile(AgentIdentity.generate(label="profile-publisher"))

    assert validate_profile_attributes(profile, {"game": "NTH", "server": "global"}) == {
        "game": "NTH",
        "server": "global",
    }
    with pytest.raises(ResourceProfileRejected, match="game is required"):
        validate_profile_attributes(profile, {})
    with pytest.raises(ResourceProfileRejected, match="game must be string"):
        validate_profile_attributes(profile, {"game": 1})
    with pytest.raises(ResourceProfileRejected, match="quantity must be integer"):
        validate_profile_attributes(profile, {"game": "NTH", "quantity": True})
    with pytest.raises(ResourceProfileRejected, match="unknown field"):
        validate_profile_attributes(profile, {"game": "NTH", "script": "run me"})


def test_offer_inspection_separates_profile_recognition_from_schema_validity():
    profile = _profile(AgentIdentity.generate(label="profile-publisher"))
    descriptor = {
        "kind": "org.nthdao.resource-profile.inline",
        "version": "1",
        "category": "other",
        "resource_type": "game/item",
        "resource_id": "urn:nthdao:game-item:example",
        "profile_ref": {
            "rule_id": profile.profile_id,
            "digest": profile.digest,
        },
        "attributes": {
            "community_category": "gaming/items",
            "game": "NTH",
        },
    }
    digest = inline_resource_descriptor_digest(descriptor)
    offer = {
        "provides": [{"leg_id": "item", "descriptor_digest": digest}],
        "requests": [],
        "extensions": {
            RESOURCE_DESCRIPTOR_EXTENSION: {"descriptors": {digest: descriptor}},
        },
    }

    inspected = inspect_offer_resource_descriptors(
        offer,
        profile_resolver=lambda requested: profile if requested == profile.digest else None,
        accepted_profile_digests={profile.digest},
        at=datetime(2026, 8, 9, tzinfo=timezone.utc),
    )

    assert inspected["profile_packages_resolved"] is True
    assert inspected["profile_packages_recognized"] == 1
    assert inspected["profile_packages_applicable"] == 1
    assert inspected["items"][0]["profile_resolution"] == "recognized-local"
    assert inspected["items"][0]["profile_schema_valid"] is True
    assert inspected["items"][0]["mapped_market_category"] == "products"
    assert inspected["execution_ready"] is False

    invalid_descriptor = copy.deepcopy(descriptor)
    invalid_descriptor["attributes"].pop("game")
    invalid_digest = inline_resource_descriptor_digest(invalid_descriptor)
    invalid_offer = copy.deepcopy(offer)
    invalid_offer["provides"][0]["descriptor_digest"] = invalid_digest
    invalid_offer["extensions"][RESOURCE_DESCRIPTOR_EXTENSION]["descriptors"] = {
        invalid_digest: invalid_descriptor,
    }
    invalid = inspect_offer_resource_descriptors(
        invalid_offer,
        profile_resolver=lambda _: profile,
        accepted_profile_digests={profile.digest},
        at=datetime(2026, 8, 9, tzinfo=timezone.utc),
    )

    assert invalid["items"][0]["profile_resolution"] == "recognized-local"
    assert invalid["items"][0]["profile_schema_valid"] is False
    assert invalid["items"][0]["mapped_market_category"] == ""
    assert invalid["profile_packages_applicable"] == 0

    wrong_type_descriptor = copy.deepcopy(descriptor)
    wrong_type_descriptor["resource_type"] = "service"
    wrong_type_digest = inline_resource_descriptor_digest(wrong_type_descriptor)
    wrong_type_offer = copy.deepcopy(offer)
    wrong_type_offer["provides"][0]["descriptor_digest"] = wrong_type_digest
    wrong_type_offer["extensions"][RESOURCE_DESCRIPTOR_EXTENSION]["descriptors"] = {
        wrong_type_digest: wrong_type_descriptor,
    }
    wrong_type = inspect_offer_resource_descriptors(
        wrong_type_offer,
        profile_resolver=lambda _: profile,
        accepted_profile_digests={profile.digest},
        at=datetime(2026, 8, 9, tzinfo=timezone.utc),
    )
    assert wrong_type["items"][0]["profile_resolution"] == "invalid-local"
    assert wrong_type["items"][0]["profile_error"] == (
        "profile-resource-type-mismatch"
    )


def test_profile_store_is_content_addressed_and_detects_corruption(tmp_path):
    profile = _profile(AgentIdentity.generate(label="profile-publisher"))
    store = ResourceProfileStore(tmp_path)

    assert store.install(profile).digest == profile.digest
    assert store.install(profile).canonical_bytes == profile.canonical_bytes
    assert store.load(profile.digest).canonical_bytes == profile.canonical_bytes

    path = (
        tmp_path / "market" / "resource_profiles"
        / f"{profile.digest.removeprefix('sha256:')}.json"
    )
    path.write_bytes(b"{}")
    with pytest.raises(ResourceProfileRejected):
        store.load(profile.digest)


def test_profile_store_reports_exactly_one_concurrent_install(tmp_path):
    profile = _profile(AgentIdentity.generate(label="concurrent-publisher"))
    store = ResourceProfileStore(tmp_path)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(
            lambda _index: store.install_with_status(profile),
            range(8),
        ))

    assert sum(created for _stored, created in results) == 1
    assert {stored.digest for stored, _created in results} == {profile.digest}


def test_profile_store_rejects_oversized_files_and_capacity_overflow(tmp_path):
    first = _profile(AgentIdentity.generate(label="first-publisher"))
    second = _profile(AgentIdentity.generate(label="second-publisher"))
    store = ResourceProfileStore(tmp_path, max_profiles=1)
    store.install(first)

    with pytest.raises(ResourceProfileRejected, match="capacity"):
        store.install(second)

    path = (
        tmp_path / "market" / "resource_profiles"
        / f"{first.digest.removeprefix('sha256:')}.json"
    )
    path.write_bytes(b"{" + (b" " * 262_144) + b"}")
    with pytest.raises(ResourceProfileRejected, match="byte limit"):
        store.load(first.digest)


def test_profile_persistence_rejects_linked_parent_directory(tmp_path):
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()
    market = workspace / "market"
    try:
        market.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks are unavailable: {exc}")

    profile = _profile(AgentIdentity.generate(label="profile-publisher"))
    with pytest.raises(ResourceProfileRejected, match="symlinks or junctions"):
        ResourceProfileStore(workspace).install(profile)
    with pytest.raises(ResourceProfileRejected, match="symlinks or junctions"):
        ResourceProfilePolicy(workspace).set_accepted(profile.digest, True)
    assert list(outside.iterdir()) == []


def test_profile_store_checks_linklike_parent_before_mkdir(tmp_path, monkeypatch):
    import nth_dao.market.resource_profile as profile_module

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    profile = _profile(AgentIdentity.generate(label="profile-publisher"))
    real_check = profile_module._is_linklike

    monkeypatch.setattr(
        profile_module,
        "_is_linklike",
        lambda path: path == workspace / "market" or real_check(path),
    )
    with pytest.raises(ResourceProfileRejected, match="symlinks or junctions"):
        ResourceProfileStore(workspace).install(profile)
    assert not (workspace / "market").exists()


def test_profile_policy_is_local_explicit_and_persistent(tmp_path):
    profile = _profile(AgentIdentity.generate(label="profile-publisher"))
    policy = ResourceProfilePolicy(tmp_path)

    policy.set_accepted(profile.digest, True)
    assert ResourceProfilePolicy(tmp_path).accepted_digests() == {profile.digest}

    policy.set_accepted(profile.digest, False)
    assert policy.accepted_digests() == frozenset()


@pytest.mark.parametrize(
    "payload",
    [
        {"version": 2, "accepted_digests": []},
        {"version": 1, "accepted_digests": [{"digest": "not-a-string"}]},
        {"version": 1, "accepted_digests": [], "unexpected": True},
    ],
)
def test_profile_policy_fails_closed_for_malformed_documents(tmp_path, payload):
    policy = ResourceProfilePolicy(tmp_path)
    policy.path.parent.mkdir(parents=True, exist_ok=True)
    policy.path.write_text(json.dumps(payload), encoding="utf-8")

    assert policy.accepted_digests() == frozenset()

    original = policy.path.read_bytes()
    with pytest.raises(ResourceProfileRejected, match="malformed"):
        policy.set_accepted("sha256:" + ("a" * 64), True)
    assert policy.path.read_bytes() == original


def test_profile_policy_bounds_file_before_parsing_or_mutation(tmp_path):
    policy = ResourceProfilePolicy(tmp_path)
    policy.path.parent.mkdir(parents=True, exist_ok=True)
    policy.path.write_bytes(b"{" + (b" " * (8 * 1024 * 1024)) + b"}")

    assert policy.accepted_digests() == frozenset()
    with pytest.raises(ResourceProfileRejected, match="byte limit"):
        policy.set_accepted("sha256:" + ("b" * 64), True)
