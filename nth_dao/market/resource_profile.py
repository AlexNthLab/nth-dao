"""Signed, non-executing Resource Profile Skills and local category policy."""

from __future__ import annotations

import bisect
import copy
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from nth_dao.did_key import is_did_key
from nth_dao.identity import AgentIdentity
from nth_dao.market.resource_descriptor import (
    MARKET_RESOURCE_CATEGORIES,
    RESOURCE_DESCRIPTOR_RESERVED_ATTRIBUTE_FIELDS,
)
from nth_dao.market.resource_profile_id import validate_resource_profile_id
from nth_dao.trade_rules.canonical import (
    MAX_TRADE_JSON_BYTES,
    parse_trade_json,
    trade_canonical_json,
)
from nth_dao.trade_rules.signing import (
    encode_ed25519_signature,
    signed_document_input,
    verification_method_for_did,
    verify_ed25519_did_signature,
)
from nth_dao.util.io import (
    InterProcessLock,
    atomic_write_bytes,
    atomic_write_json,
)


PROFILE_KIND = "org.nthdao.resource-profile"
PROFILE_PROTOCOL_VERSION = "1.0"
PROFILE_PROOF_TYPE = "NthEd25519SignatureV1"
PROFILE_PROOF_PURPOSE = "assertionMethod"
PROFILE_SIGNING_DOMAIN = b"NTH-RESOURCE-PROFILE-V1"

_TOP_FIELDS = frozenset({
    "kind", "protocol_version", "profile_id", "version", "publisher_did",
    "summary", "resource_types", "category_mappings", "schema",
    "published_at", "not_after", "extensions", "proof",
})
_BODY_FIELDS = _TOP_FIELDS - {"proof"}
_PROOF_FIELDS = frozenset({
    "type", "created", "verification_method", "proof_purpose", "proof_value",
})
_MAPPING_FIELDS = frozenset({"community_category", "market_category"})
_SCHEMA_FIELDS = frozenset({"type", "properties", "additional_properties"})
_PROPERTY_FIELDS = frozenset({"type", "required", "description", "enum"})
_PROPERTY_TYPES = frozenset({"string", "integer", "boolean"})
_VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_TOKEN = re.compile(r"^[a-z0-9][a-z0-9._:/-]{0,127}$")
_FIELD_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
_MAX_POLICY_BYTES = 8 * 1024 * 1024


class ResourceProfileRejected(ValueError):
    """Raised when a Resource Profile is malformed or unverifiable."""


def _reject(message: str) -> None:
    raise ResourceProfileRejected(message)


def _exact(value: Any, fields: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        _reject(f"{label} must be an object")
    if set(value) != fields:
        _reject(f"{label} fields are invalid")
    return value


def _text(value: Any, label: str, maximum: int, *, minimum: int = 1) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        _reject(f"{label} must be a string of length {minimum}..{maximum}")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ResourceProfileRejected(f"{label} contains invalid Unicode") from exc
    return value


def _timestamp(value: Any, label: str) -> datetime:
    text = _text(value, label, 20)
    if _TIMESTAMP.fullmatch(text) is None:
        _reject(f"{label} must be a UTC second timestamp")
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ResourceProfileRejected(f"{label} is invalid") from exc


def _is_linklike(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    if is_junction and is_junction():
        return True
    if os.name == "nt":
        try:
            metadata = os.lstat(path)
        except FileNotFoundError:
            return False
        return bool(
            getattr(metadata, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        )
    return False


def _assert_workspace_path(workspace: Path, path: Path) -> None:
    """Reject link-like components before touching Profile persistence."""
    try:
        relative = path.relative_to(workspace)
    except ValueError as exc:
        raise ResourceProfileRejected("profile path escapes workspace root") from exc
    candidates = [workspace]
    candidates.extend(
        workspace.joinpath(*relative.parts[:index])
        for index in range(1, len(relative.parts) + 1)
    )
    for candidate in candidates:
        if _is_linklike(candidate):
            raise ResourceProfileRejected(
                "profile persistence must not contain symlinks or junctions",
            )


def _validate_schema(value: Any) -> None:
    schema = _exact(value, _SCHEMA_FIELDS, "schema")
    if schema["type"] != "object" or type(schema["additional_properties"]) is not bool:
        _reject("schema must describe an object with explicit additional_properties")
    properties = schema["properties"]
    if not isinstance(properties, dict) or not 1 <= len(properties) <= 64:
        _reject("schema properties must contain 1..64 fields")
    if list(properties) != sorted(properties):
        _reject("schema properties must be sorted")
    reserved = sorted(
        set(properties) & RESOURCE_DESCRIPTOR_RESERVED_ATTRIBUTE_FIELDS,
    )
    if reserved:
        _reject(f"schema property {reserved[0]} is reserved by the descriptor")
    for name, raw in properties.items():
        if not isinstance(name, str) or _FIELD_NAME.fullmatch(name) is None:
            _reject("schema property name is invalid")
        prop = _exact(raw, _PROPERTY_FIELDS, f"schema property {name}")
        property_type = prop["type"]
        if property_type not in _PROPERTY_TYPES or type(prop["required"]) is not bool:
            _reject(f"schema property {name} type or required flag is invalid")
        _text(prop["description"], f"schema property {name} description", 500, minimum=0)
        enum = prop["enum"]
        if not isinstance(enum, list) or len(enum) > 64:
            _reject(f"schema property {name} enum is invalid")
        expected_type = {"string": str, "integer": int, "boolean": bool}[property_type]
        seen: set[bytes] = set()
        for item in enum:
            if type(item) is not expected_type:
                _reject(f"schema property {name} enum type is invalid")
            encoded = trade_canonical_json({"value": item})
            if encoded in seen:
                _reject(f"schema property {name} enum contains duplicates")
            seen.add(encoded)


def _validate_body(document: Any) -> dict[str, Any]:
    body = _exact(document, _BODY_FIELDS, "Resource Profile body")
    if body["kind"] != PROFILE_KIND or body["protocol_version"] != PROFILE_PROTOCOL_VERSION:
        _reject("Resource Profile kind or protocol_version is unsupported")
    try:
        validate_resource_profile_id(body["profile_id"])
    except ValueError as exc:
        raise ResourceProfileRejected(str(exc)) from exc
    if _VERSION.fullmatch(_text(body["version"], "version", 32)) is None:
        _reject("version must be a stable semantic version")
    publisher_did = _text(body["publisher_did"], "publisher_did", 256)
    if not is_did_key(publisher_did):
        _reject("publisher_did must be an Ed25519 did:key")
    _text(body["summary"], "summary", 1000)

    resource_types = body["resource_types"]
    if not isinstance(resource_types, list) or not 1 <= len(resource_types) <= 64:
        _reject("resource_types must contain 1..64 entries")
    if any(not isinstance(item, str) or _TOKEN.fullmatch(item) is None for item in resource_types):
        _reject("resource_types contains an invalid token")
    if resource_types != sorted(set(resource_types)):
        _reject("resource_types must be sorted and unique")

    mappings = body["category_mappings"]
    if not isinstance(mappings, list) or not 1 <= len(mappings) <= 64:
        _reject("category_mappings must contain 1..64 entries")
    community_categories: list[str] = []
    for raw in mappings:
        mapping = _exact(raw, _MAPPING_FIELDS, "category mapping")
        community = _text(mapping["community_category"], "community_category", 128)
        if _TOKEN.fullmatch(community) is None:
            _reject("community_category is invalid")
        if mapping["market_category"] not in MARKET_RESOURCE_CATEGORIES:
            _reject("market_category is invalid")
        community_categories.append(community)
    if community_categories != sorted(set(community_categories)):
        _reject("category_mappings must be sorted and unique")

    _validate_schema(body["schema"])
    published = _timestamp(body["published_at"], "published_at")
    if body["not_after"] is not None:
        expires = _timestamp(body["not_after"], "not_after")
        if expires <= published:
            _reject("not_after must be later than published_at")
    if not isinstance(body["extensions"], dict):
        _reject("extensions must be an object")
    trade_canonical_json(body)
    return body


def _validate_complete(document: Any) -> dict[str, Any]:
    complete = _exact(document, _TOP_FIELDS, "Resource Profile")
    _validate_body({key: copy.deepcopy(complete[key]) for key in _BODY_FIELDS})
    proof = _exact(complete["proof"], _PROOF_FIELDS, "proof")
    if proof["type"] != PROFILE_PROOF_TYPE or proof["proof_purpose"] != PROFILE_PROOF_PURPOSE:
        _reject("proof type or purpose is invalid")
    if proof["verification_method"] != verification_method_for_did(complete["publisher_did"]):
        _reject("proof verification_method does not match publisher_did")
    created = _timestamp(proof["created"], "proof.created")
    if created < _timestamp(complete["published_at"], "published_at"):
        _reject("proof predates publication")
    if complete["not_after"] is not None and created >= _timestamp(complete["not_after"], "not_after"):
        _reject("proof is outside the publication window")
    if not isinstance(proof["proof_value"], str):
        _reject("proof_value must be a string")
    trade_canonical_json(complete)
    return complete


@dataclass(frozen=True, init=False)
class ResourceProfile:
    _canonical: bytes

    @classmethod
    def _create(cls, canonical: bytes) -> "ResourceProfile":
        value = object.__new__(cls)
        object.__setattr__(value, "_canonical", bytes(canonical))
        return value

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> "ResourceProfile":
        snapshot = _validate_complete(copy.deepcopy(document))
        ok, reason = verify_resource_profile(snapshot)
        if not ok:
            _reject(reason)
        return cls._create(trade_canonical_json(snapshot))

    @classmethod
    def from_json(cls, raw: bytes | str) -> "ResourceProfile":
        return cls.from_dict(parse_trade_json(raw))

    @property
    def canonical_bytes(self) -> bytes:
        return self._canonical

    @property
    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(self._canonical).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return parse_trade_json(self._canonical)

    @property
    def profile_id(self) -> str:
        return self.to_dict()["profile_id"]


def resource_profile_body(
    *,
    profile_id: str,
    version: str,
    publisher_did: str,
    summary: str,
    resource_types: Iterable[str],
    category_mappings: Iterable[dict[str, str]],
    schema: dict[str, Any],
    published_at: str,
    not_after: str | None = None,
    extensions: dict[str, Any] | None = None,
) -> dict[str, Any]:
    body = {
        "kind": PROFILE_KIND,
        "protocol_version": PROFILE_PROTOCOL_VERSION,
        "profile_id": profile_id,
        "version": version,
        "publisher_did": publisher_did,
        "summary": summary,
        "resource_types": sorted(resource_types),
        "category_mappings": sorted(
            (copy.deepcopy(item) for item in category_mappings),
            key=lambda item: item.get("community_category", ""),
        ),
        "schema": copy.deepcopy(schema),
        "published_at": published_at,
        "not_after": not_after,
        "extensions": copy.deepcopy(extensions or {}),
    }
    _validate_body(body)
    return body


def sign_resource_profile(
    identity: AgentIdentity,
    body: dict[str, Any],
    *,
    created: str | None = None,
) -> ResourceProfile:
    if not identity.can_sign:
        raise RuntimeError("identity has no signing key")
    document = copy.deepcopy(body)
    _validate_body(document)
    if document["publisher_did"] != identity.as_did():
        _reject("signer does not match publisher_did")
    proof = {
        "type": PROFILE_PROOF_TYPE,
        "created": created or datetime.now(timezone.utc).replace(
            microsecond=0,
        ).isoformat().replace("+00:00", "Z"),
        "verification_method": verification_method_for_did(identity.as_did()),
        "proof_purpose": PROFILE_PROOF_PURPOSE,
        "proof_value": "A" * 86,
    }
    document["proof"] = proof
    _validate_complete(document)
    proof["proof_value"] = encode_ed25519_signature(
        identity.sign(signed_document_input(PROFILE_SIGNING_DOMAIN, document))
    )
    document["proof"] = proof
    return ResourceProfile.from_dict(document)


def verify_resource_profile(value: ResourceProfile | dict[str, Any]) -> tuple[bool, str]:
    try:
        document = value.to_dict() if isinstance(value, ResourceProfile) else copy.deepcopy(value)
        _validate_complete(document)
        return verify_ed25519_did_signature(
            publisher_did=document["publisher_did"],
            proof_value=document["proof"]["proof_value"],
            signing_input=signed_document_input(PROFILE_SIGNING_DOMAIN, document),
        )
    except (ResourceProfileRejected, TypeError, ValueError) as exc:
        return False, str(exc)


def evaluate_resource_profile(
    profile: ResourceProfile,
    *,
    at: datetime | None = None,
) -> tuple[bool, str]:
    """Evaluate a verified profile's signed activation window."""
    if not isinstance(profile, ResourceProfile):
        raise TypeError("profile must be a verified ResourceProfile")
    moment = at or datetime.now(timezone.utc)
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("at must be timezone-aware")
    moment = moment.astimezone(timezone.utc).replace(microsecond=0)
    document = profile.to_dict()
    active_from = max(
        _timestamp(document["published_at"], "published_at"),
        _timestamp(document["proof"]["created"], "proof.created"),
    )
    if moment < active_from:
        return False, "not-yet-active"
    if document["not_after"] is not None and moment >= _timestamp(
        document["not_after"], "not_after",
    ):
        return False, "expired"
    return True, "active"


def validate_profile_attributes(
    profile: ResourceProfile,
    attributes: dict[str, Any],
) -> dict[str, Any]:
    """Validate profile-owned attributes without evaluating executable code."""
    if not isinstance(profile, ResourceProfile):
        raise TypeError("profile must be a verified ResourceProfile")
    if not isinstance(attributes, dict) or any(
        not isinstance(key, str) for key in attributes
    ):
        _reject("profile attributes must be an object with string keys")
    try:
        trade_canonical_json(attributes)
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise ResourceProfileRejected(
            "profile attributes are not canonical JSON",
        ) from exc

    schema = profile.to_dict()["schema"]
    properties = schema["properties"]
    unknown = sorted(set(attributes) - set(properties))
    if unknown and not schema["additional_properties"]:
        _reject(f"profile attributes contain unknown field: {unknown[0]}")

    for name, definition in properties.items():
        if name not in attributes:
            if definition["required"]:
                _reject(f"profile attribute {name} is required")
            continue
        value = attributes[name]
        expected_type = {
            "string": str,
            "integer": int,
            "boolean": bool,
        }[definition["type"]]
        if type(value) is not expected_type:
            _reject(
                f"profile attribute {name} must be {definition['type']}",
            )
        if definition["enum"] and value not in definition["enum"]:
            _reject(f"profile attribute {name} is outside its enum")
    return copy.deepcopy(attributes)


class ResourceProfileStore:
    """Process-safe CAS for verified profiles; stored documents never execute."""

    def __init__(self, workspace: str | Path, *, max_profiles: int = 4096) -> None:
        if type(max_profiles) is not int or not 1 <= max_profiles <= 65_536:
            raise ValueError("max_profiles must be an integer in 1..65536")
        self.workspace = Path(workspace)
        self.root = self.workspace / "market" / "resource_profiles"
        self.lock_path = self.root / ".lock"
        self.max_profiles = max_profiles

    @staticmethod
    def _suffix(digest: str) -> str:
        if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
            raise ValueError("profile digest must be a lowercase sha256 digest")
        return digest.removeprefix("sha256:")

    def _path(self, digest: str) -> Path:
        return self.root / f"{self._suffix(digest)}.json"

    def _read_path(self, path: Path) -> ResourceProfile:
        _assert_workspace_path(self.workspace, path)
        if _is_linklike(path) or not path.is_file():
            raise ResourceProfileRejected("profile path is not a regular file")
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise ResourceProfileRejected("profile path cannot be inspected") from exc
        if size < 2 or size > MAX_TRADE_JSON_BYTES:
            raise ResourceProfileRejected("stored profile exceeds the byte limit")
        return ResourceProfile.from_json(path.read_bytes())

    def install_with_status(
        self,
        value: ResourceProfile | dict[str, Any],
    ) -> tuple[ResourceProfile, bool]:
        """Atomically install a profile and report whether this call created it."""
        profile = (
            ResourceProfile.from_json(value.canonical_bytes)
            if isinstance(value, ResourceProfile)
            else ResourceProfile.from_dict(value)
        )
        path = self._path(profile.digest)
        _assert_workspace_path(self.workspace, self.root)
        self.root.mkdir(parents=True, exist_ok=True)
        _assert_workspace_path(self.workspace, self.root)
        with InterProcessLock(self.lock_path):
            _assert_workspace_path(self.workspace, path)
            if path.exists():
                existing = self._read_path(path)
                if existing.canonical_bytes != profile.canonical_bytes:
                    raise ResourceProfileRejected("profile CAS collision")
                return existing, False
            installed = sum(
                1 for candidate in self.root.glob("*.json")
                if candidate.is_file() and not candidate.is_symlink()
            )
            if installed >= self.max_profiles:
                raise ResourceProfileRejected("profile store capacity exceeded")
            atomic_write_bytes(path, profile.canonical_bytes)
            _assert_workspace_path(self.workspace, path)
        return profile, True

    def install(self, value: ResourceProfile | dict[str, Any]) -> ResourceProfile:
        return self.install_with_status(value)[0]

    def load(self, digest: str) -> ResourceProfile | None:
        path = self._path(digest)
        _assert_workspace_path(self.workspace, path)
        if _is_linklike(path):
            raise ResourceProfileRejected("profile path is not a regular file")
        if not path.exists():
            return None
        profile = self._read_path(path)
        if profile.digest != digest:
            raise ResourceProfileRejected("stored profile digest mismatch")
        return profile

    def list_profiles(self, *, limit: int = 200) -> tuple[ResourceProfile, ...]:
        return self.list_page(limit=limit)[0]

    def list_page(
        self,
        *,
        after: str | None = None,
        limit: int = 200,
    ) -> tuple[tuple[ResourceProfile, ...], str | None, int]:
        """Return a stable digest-ordered page and a continuation cursor."""

        if type(limit) is not int or not 1 <= limit <= self.max_profiles:
            raise ValueError("limit must be an integer within store capacity")
        after_suffix = self._suffix(after) if after is not None else ""
        _assert_workspace_path(self.workspace, self.root)
        if not self.root.exists():
            return (), None, 0
        if _is_linklike(self.root) or not self.root.is_dir():
            raise ResourceProfileRejected("profile store root is not a directory")
        paths = sorted(self.root.glob("*.json"))
        stems = [path.stem for path in paths]
        start = bisect.bisect_right(stems, after_suffix) if after is not None else 0
        page_paths = paths[start:start + limit]
        profiles: list[ResourceProfile] = []
        for path in page_paths:
            profile = self._read_path(path)
            if path.stem != profile.digest.removeprefix("sha256:"):
                raise ResourceProfileRejected("stored profile filename mismatch")
            profiles.append(profile)
        next_cursor = (
            profiles[-1].digest
            if profiles and start + len(profiles) < len(paths)
            else None
        )
        return tuple(profiles), next_cursor, len(paths)


class ResourceProfilePolicy:
    """Explicit local recognition; signature validity alone grants no mapping."""

    def __init__(self, workspace: str | Path) -> None:
        self.workspace = Path(workspace)
        self.path = self.workspace / "market" / "resource_profile_policy.json"
        self.lock_path = self.path.with_suffix(".lock")

    def _read_values(self, *, strict: bool) -> frozenset[str]:
        _assert_workspace_path(self.workspace, self.path)
        if not self.path.exists():
            return frozenset()
        if _is_linklike(self.path) or not self.path.is_file():
            if strict:
                raise ResourceProfileRejected("profile policy path is not a regular file")
            return frozenset()
        try:
            size = self.path.stat().st_size
            if size < 2 or size > _MAX_POLICY_BYTES:
                if strict:
                    raise ResourceProfileRejected(
                        "profile policy exceeds the byte limit",
                    )
                return frozenset()
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            if strict:
                raise ResourceProfileRejected("profile policy is unreadable") from exc
            return frozenset()
        if (
            not isinstance(raw, dict)
            or set(raw) != {"version", "accepted_digests"}
            or raw.get("version") != 1
            or not isinstance(raw.get("accepted_digests"), list)
        ):
            if strict:
                raise ResourceProfileRejected("profile policy document is malformed")
            return frozenset()
        values = raw["accepted_digests"]
        if (
            len(values) > 65_536
            or any(
                not isinstance(item, str) or _DIGEST.fullmatch(item) is None
                for item in values
            )
            or values != sorted(set(values))
        ):
            if strict:
                raise ResourceProfileRejected("profile policy digests are malformed")
            return frozenset()
        return frozenset(values)

    def accepted_digests(self, *, strict: bool = False) -> frozenset[str]:
        """Return local recognition, optionally surfacing damaged policy state."""
        return self._read_values(strict=strict)

    def set_accepted(self, digest: str, accepted: bool) -> bool:
        ResourceProfileStore._suffix(digest)
        _assert_workspace_path(self.workspace, self.path.parent)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        _assert_workspace_path(self.workspace, self.path.parent)
        with InterProcessLock(self.lock_path):
            current = set(self._read_values(strict=True))
            values = set(current)
            if accepted:
                values.add(digest)
            else:
                values.discard(digest)
            changed = values != current
            if not changed:
                return False
            atomic_write_json(self.path, {
                "version": 1,
                "accepted_digests": sorted(values),
            })
            _assert_workspace_path(self.workspace, self.path)
            return True


def map_community_category(
    profile: ResourceProfile,
    community_category: str,
    *,
    accepted_digests: Iterable[str],
    at: datetime | None = None,
) -> tuple[str, str]:
    """Map only through an explicitly recognized profile; otherwise `other`."""
    if profile.digest not in set(accepted_digests):
        return "other", "profile-not-recognized"
    active, reason = evaluate_resource_profile(profile, at=at)
    if not active:
        return "other", reason
    for mapping in profile.to_dict()["category_mappings"]:
        if mapping["community_category"] == community_category:
            return mapping["market_category"], "recognized-profile"
    return "other", "community-category-unmapped"


__all__ = [
    "PROFILE_KIND", "PROFILE_PROTOCOL_VERSION", "ResourceProfile",
    "ResourceProfilePolicy", "ResourceProfileRejected", "ResourceProfileStore",
    "evaluate_resource_profile", "map_community_category", "resource_profile_body",
    "sign_resource_profile", "validate_profile_attributes", "verify_resource_profile",
]
