"""Deterministic conformance vectors for Resource Profile Skills v1."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from nth_dao.identity import AgentID, AgentIdentity
from nth_dao.market.resource_profile import (
    ResourceProfile,
    resource_profile_body,
    sign_resource_profile,
    validate_profile_attributes,
    verify_resource_profile,
)
from nth_dao.market.resource_descriptor import (
    RESOURCE_DESCRIPTOR_RESERVED_ATTRIBUTE_FIELDS,
)
from nth_dao.market.resource_profile_id import (
    RESOURCE_PROFILE_ID_MAX_LENGTH,
    validate_resource_profile_id,
)


VECTORS_PATH = Path(__file__).with_name("vectors") / "resource-profile-v1.json"
_SEED = bytes.fromhex("55" * 32)


def _identity() -> AgentIdentity:
    from nacl.signing import SigningKey

    signing_key = SigningKey(_SEED)
    verify_key = signing_key.verify_key.encode()
    return AgentIdentity(
        agent_id=AgentID.from_pubkey(verify_key.hex()),
        label="Resource Profile Vector Publisher",
        _signing_key=signing_key.encode(),
        _verify_key=verify_key,
    )


def generate_vectors() -> dict[str, Any]:
    identity = _identity()
    body = resource_profile_body(
        profile_id="org.nthdao.community/game-item",
        version="1.0.0",
        publisher_did=identity.as_did(),
        summary="Deterministic community profile for game items.",
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
            },
            "additional_properties": False,
        },
        published_at="2026-08-08T00:00:00Z",
        not_after="2027-08-08T00:00:00Z",
    )
    profile = sign_resource_profile(
        identity, body, created="2026-08-08T00:00:01Z",
    )
    negative: list[dict[str, Any]] = []
    for case_id, mutate in (
        ("summary-tamper", lambda item: item.update(summary="tampered")),
        (
            "category-tamper",
            lambda item: item["category_mappings"][0].update(
                market_category="services",
            ),
        ),
        (
            "schema-tamper",
            lambda item: item["schema"]["properties"]["game"].update(
                required=False,
            ),
        ),
    ):
        candidate = copy.deepcopy(profile.to_dict())
        mutate(candidate)
        negative.append({"id": case_id, "profile": candidate})
    return {
        "format": "nth-resource-profile-conformance-v1",
        "schema_version": 1,
        "warning": "Signature validity grants provenance, not trust or execution authority.",
        "profile": profile.to_dict(),
        "expected_profile_digest": profile.digest,
        "reserved_descriptor_attribute_fields": sorted(
            RESOURCE_DESCRIPTOR_RESERVED_ATTRIBUTE_FIELDS,
        ),
        "profile_id_contract": {
            "max_length": RESOURCE_PROFILE_ID_MAX_LENGTH,
            "cases": [
                {
                    "id": "valid-near-limit",
                    "value": "a" * 63 + "." + "b" * 63 + "." + "c" * 62,
                    "expected_valid": True,
                },
                {
                    "id": "invalid-non-string",
                    "value": 123,
                    "expected_valid": False,
                },
                {
                    "id": "invalid-uppercase",
                    "value": "org.nthdao.Community/game-item",
                    "expected_valid": False,
                },
            ],
        },
        "negative_profiles": negative,
        "attribute_cases": [
            {
                "id": "valid-required-field",
                "attributes": {"game": "NTH Arena"},
                "expected_valid": True,
            },
            {
                "id": "missing-required-field",
                "attributes": {},
                "expected_valid": False,
            },
            {
                "id": "wrong-field-type",
                "attributes": {"game": 7},
                "expected_valid": False,
            },
            {
                "id": "unknown-field",
                "attributes": {"game": "NTH Arena", "script": "ignored"},
                "expected_valid": False,
            },
        ],
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
        raise ValueError("Resource Profile vectors must be an object")
    return value


def verify_vectors(value: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if value.get("reserved_descriptor_attribute_fields") != sorted(
        RESOURCE_DESCRIPTOR_RESERVED_ATTRIBUTE_FIELDS,
    ):
        failures.append("reserved descriptor attribute fields mismatch")
    contract = value.get("profile_id_contract")
    if not isinstance(contract, dict):
        failures.append("profile ID contract is missing")
    else:
        if contract.get("max_length") != RESOURCE_PROFILE_ID_MAX_LENGTH:
            failures.append("profile ID maximum length mismatch")
        cases = contract.get("cases")
        if not isinstance(cases, list):
            failures.append("profile ID cases are missing")
        else:
            for case in cases:
                if not isinstance(case, dict):
                    failures.append("profile ID case is malformed")
                    continue
                accepted = True
                try:
                    validate_resource_profile_id(case.get("value"))
                except (TypeError, ValueError):
                    accepted = False
                if accepted is not (case.get("expected_valid") is True):
                    failures.append(
                        f"profile ID case result mismatch: {case.get('id', '')}",
                    )
    try:
        profile = ResourceProfile.from_dict(value["profile"])
        if profile.digest != value["expected_profile_digest"]:
            failures.append("profile digest mismatch")
    except (KeyError, TypeError, ValueError) as exc:
        failures.append(f"positive profile rejected: {exc}")
    for case in value.get("negative_profiles", []):
        ok, _ = verify_resource_profile(case.get("profile"))
        if ok:
            failures.append(f"negative profile accepted: {case.get('id', '')}")
    try:
        profile = ResourceProfile.from_dict(value["profile"])
    except (KeyError, TypeError, ValueError):
        return failures
    for case in value.get("attribute_cases", []):
        accepted = True
        try:
            validate_profile_attributes(profile, case.get("attributes"))
        except (TypeError, ValueError):
            accepted = False
        if accepted is not (case.get("expected_valid") is True):
            failures.append(
                f"attribute case result mismatch: {case.get('id', '')}",
            )
    return failures


__all__ = [
    "VECTORS_PATH", "encoded_vectors", "generate_vectors", "load_vectors",
    "regenerate_vectors", "verify_vectors",
]
