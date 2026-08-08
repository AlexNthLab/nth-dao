"""Wire validation for Market resource descriptors and publication metadata."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from nth_dao.trade_rules.canonical import trade_canonical_json


RESOURCE_DESCRIPTOR_EXTENSION = "org.nthdao.market/resource-descriptors-v1"
MARKET_PUBLICATION_EXTENSION = "org.nthdao.market/publication-v1"
RESOURCE_DESCRIPTOR_KIND = "org.nthdao.resource-profile.inline"
RESOURCE_DESCRIPTOR_VERSION = "1"
MARKET_RESOURCE_CATEGORIES = frozenset(
    {"products", "services", "digital-assets", "other"}
)
MARKET_OFFER_INTENTS = frozenset({"provide", "exchange"})

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_PROFILE_RULE_ID = re.compile(
    r"^[a-z0-9](?:[a-z0-9.-]{1,157}[a-z0-9])"
    r"(?:/[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?)?$"
)
_DESCRIPTOR_FIELDS = frozenset(
    {
        "kind",
        "version",
        "category",
        "resource_type",
        "resource_id",
        "profile_ref",
        "attributes",
    }
)
_PUBLICATION_FIELDS = frozenset(
    {"category", "intent", "capability_set", "offer_validity_seconds"}
)


def _bounded_text(value: Any, *, label: str, minimum: int, maximum: int) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        raise ValueError(f"{label} length must be in {minimum}..{maximum}")
    return value


def validate_inline_resource_descriptor(descriptor: Any) -> dict[str, Any]:
    """Validate one exact v1 inline descriptor without resolving its Profile."""
    if not isinstance(descriptor, dict):
        raise ValueError("resource descriptor must be an object")
    if set(descriptor) != _DESCRIPTOR_FIELDS:
        raise ValueError("resource descriptor fields do not match v1")
    if descriptor["kind"] != RESOURCE_DESCRIPTOR_KIND:
        raise ValueError("resource descriptor kind is invalid")
    if descriptor["version"] != RESOURCE_DESCRIPTOR_VERSION:
        raise ValueError("resource descriptor version is invalid")
    if descriptor["category"] not in MARKET_RESOURCE_CATEGORIES:
        raise ValueError("resource descriptor category is invalid")
    _bounded_text(
        descriptor["resource_type"],
        label="resource_type",
        minimum=1,
        maximum=160,
    )
    _bounded_text(
        descriptor["resource_id"],
        label="resource_id",
        minimum=3,
        maximum=512,
    )
    profile_ref = descriptor["profile_ref"]
    if not isinstance(profile_ref, dict):
        raise ValueError("profile_ref must be an object")
    if profile_ref:
        if set(profile_ref) != {"rule_id", "digest"}:
            raise ValueError("profile_ref must bind rule_id and digest")
        if _PROFILE_RULE_ID.fullmatch(str(profile_ref["rule_id"])) is None:
            raise ValueError("profile_ref rule_id is invalid")
        if _DIGEST.fullmatch(str(profile_ref["digest"])) is None:
            raise ValueError("profile_ref digest must be a lowercase sha256 digest")
    attributes = descriptor["attributes"]
    if not isinstance(attributes, dict):
        raise ValueError("resource descriptor attributes must be an object")
    try:
        encoded = trade_canonical_json(attributes)
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise ValueError("resource descriptor attributes are not canonical JSON") from exc
    if len(encoded) > 16 * 1024:
        raise ValueError("resource descriptor attributes exceed 16 KiB")
    return descriptor


def inline_resource_descriptor_digest(descriptor: Any) -> str:
    validated = validate_inline_resource_descriptor(descriptor)
    return "sha256:" + hashlib.sha256(
        trade_canonical_json(validated)
    ).hexdigest()


def validate_market_publication_metadata(value: Any) -> dict[str, Any]:
    """Validate signed human-market classification metadata."""
    if not isinstance(value, dict):
        raise ValueError("market publication metadata must be an object")
    if set(value) != _PUBLICATION_FIELDS:
        raise ValueError("market publication fields do not match v1")
    if value["category"] not in MARKET_RESOURCE_CATEGORIES:
        raise ValueError("market publication category is invalid")
    if value["intent"] not in MARKET_OFFER_INTENTS:
        raise ValueError("market publication intent is invalid")
    capabilities = value["capability_set"]
    if (
        not isinstance(capabilities, list)
        or len(capabilities) > 32
        or any(not isinstance(item, str) or not item or len(item) > 100 for item in capabilities)
        or capabilities != sorted(set(capabilities))
    ):
        raise ValueError("market publication capabilities are invalid")
    validity = value["offer_validity_seconds"]
    if (
        isinstance(validity, bool)
        or not isinstance(validity, int)
        or not 60 * 60 <= validity <= 365 * 24 * 60 * 60
    ):
        raise ValueError("offer_validity_seconds is outside 3600..31536000")
    return value


def inspect_offer_resource_descriptors(offer: Any) -> dict[str, Any]:
    """Verify descriptor content hashes without claiming Profile recognition."""
    document = offer.to_dict() if hasattr(offer, "to_dict") else dict(offer)
    extensions = document.get("extensions")
    extension = (
        extensions.get(RESOURCE_DESCRIPTOR_EXTENSION)
        if isinstance(extensions, dict)
        else None
    )
    raw_descriptors = extension.get("descriptors") if isinstance(extension, dict) else None
    descriptors = raw_descriptors if isinstance(raw_descriptors, dict) else {}
    legs = list(document.get("provides") or []) + list(document.get("requests") or [])
    leg_ids_by_digest: dict[str, list[str]] = {}
    for leg in legs:
        if isinstance(leg, dict):
            digest = str(leg.get("descriptor_digest") or "")
            leg_ids_by_digest.setdefault(digest, []).append(str(leg.get("leg_id") or ""))

    items: list[dict[str, Any]] = []
    for declared_digest, descriptor in sorted(descriptors.items()):
        digest = str(declared_digest)
        computed_digest = ""
        valid = False
        if isinstance(descriptor, dict):
            try:
                computed_digest = inline_resource_descriptor_digest(descriptor)
                valid = digest == computed_digest
            except (TypeError, ValueError, OverflowError, RecursionError):
                pass
        profile_ref = (
            descriptor.get("profile_ref")
            if isinstance(descriptor, dict) and isinstance(descriptor.get("profile_ref"), dict)
            else {}
        )
        items.append(
            {
                "digest": digest,
                "computed_digest": computed_digest,
                "content_hash_valid": valid,
                "leg_ids": sorted(leg_ids_by_digest.get(digest, [])),
                "descriptor": descriptor if isinstance(descriptor, dict) else {},
                "profile_ref": profile_ref,
                "profile_resolution": "unresolved" if profile_ref else "not-declared",
                "execution_ready": False,
            }
        )
    referenced = {
        str(leg.get("descriptor_digest") or "")
        for leg in legs
        if isinstance(leg, dict)
    }
    verified = {item["digest"] for item in items if item["content_hash_valid"]}
    return {
        "status": (
            "verified-inline"
            if referenced and referenced <= verified
            else "incomplete"
            if referenced
            else "absent"
        ),
        "referenced_count": len(referenced),
        "verified_inline_count": len(referenced & verified),
        "items": items,
        "profile_packages_resolved": False,
        "execution_ready": False,
        "warning": (
            "Inline descriptor hashes may be verified, but Resource Profile "
            "Skill references are not resolved, recognized, or authorized for "
            "execution by this implementation."
        ),
    }


__all__ = [
    "MARKET_PUBLICATION_EXTENSION",
    "MARKET_RESOURCE_CATEGORIES",
    "RESOURCE_DESCRIPTOR_EXTENSION",
    "RESOURCE_DESCRIPTOR_KIND",
    "RESOURCE_DESCRIPTOR_VERSION",
    "inline_resource_descriptor_digest",
    "inspect_offer_resource_descriptors",
    "validate_inline_resource_descriptor",
    "validate_market_publication_metadata",
]
