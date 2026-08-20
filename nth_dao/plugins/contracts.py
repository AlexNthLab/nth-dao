"""Versioned, fail-closed contracts for NTH DAO host plugins.

The first host supports reviewed built-ins only. These contracts are still
wire-shaped so a future subprocess or WASI host can consume the same manifest
without depending on Python class identity.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from typing import Any, ClassVar, Dict, Iterable, Mapping, Tuple

from nth_dao.canonical_json import canonical_json
from nth_dao.did_key import is_did_key


PLUGIN_MANIFEST_VERSION = 1
PLUGIN_HOST_API_VERSION = "1.0"

PLUGIN_KINDS = frozenset(
    {
        "agent.provider",
        "artifact.store",
        "commerce.connector",
        "discovery.provider",
        "identity.resolver",
        "intent.policy",
        "intent.resolver",
        "intent.solver",
        "market.index",
        "message.store",
        "observability.exporter",
        "payment.rail",
        "settlement.adapter",
        "trade.execution",
        "transport.provider",
    }
)

PLUGIN_PERMISSIONS = frozenset(
    {
        "artifact.read",
        "artifact.write",
        "credential.use",
        "event.append",
        "filesystem.read.workspace",
        "filesystem.write.workspace",
        "identity.resolve",
        "network.client",
        "network.listen",
        "payment.commit",
        "payment.prepare",
        "process.spawn",
    }
)

PERMISSION_RISK_TIER = {
    "artifact.read": 2,
    "artifact.write": 3,
    "credential.use": 4,
    "event.append": 3,
    "filesystem.read.workspace": 2,
    "filesystem.write.workspace": 3,
    "identity.resolve": 2,
    "network.client": 3,
    "network.listen": 3,
    "payment.commit": 4,
    "payment.prepare": 4,
    "process.spawn": 3,
}

CAPABILITY_EFFECTS = frozenset(
    {
        "artifact-read",
        "artifact-write",
        "credential-use",
        "event-append",
        "filesystem-read",
        "filesystem-write",
        "identity-resolve",
        "network-read",
        "network-listen",
        "network-write",
        "none",
        "payment-commit",
        "payment-prepare",
        "process-spawn",
    }
)

EFFECT_PERMISSION = {
    "artifact-read": "artifact.read",
    "artifact-write": "artifact.write",
    "credential-use": "credential.use",
    "event-append": "event.append",
    "filesystem-read": "filesystem.read.workspace",
    "filesystem-write": "filesystem.write.workspace",
    "identity-resolve": "identity.resolve",
    "network-read": "network.client",
    "network-listen": "network.listen",
    "network-write": "network.client",
    "payment-commit": "payment.commit",
    "payment-prepare": "payment.prepare",
    "process-spawn": "process.spawn",
}

CONSISTENCY_CLASSES = frozenset({"C0", "C1", "C2", "C3", "C4"})
PRIVACY_CLASSES = frozenset({"public", "workspace", "confidential", "secret"})
SECURITY_CLASSES = frozenset(
    {"untrusted-hint", "verified-input", "authoritative", "irreversible"}
)
CAPABILITY_CARDINALITIES = frozenset({"one", "many"})
RETENTION_CLASSES = frozenset({"none", "ephemeral", "durable", "authoritative"})
FAILURE_SEMANTICS = frozenset(
    {"best-effort", "retry-safe", "at-most-once", "fail-closed"}
)

_ID_SEGMENT = r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?"
_PLUGIN_ID_RE = re.compile(rf"^{_ID_SEGMENT}(?:\.{_ID_SEGMENT}){{1,7}}$")
_CAPABILITY_ID_RE = re.compile(rf"^{_ID_SEGMENT}(?:\.{_ID_SEGMENT}){{1,7}}$")
_SEMVER_RE = re.compile(
    r"^(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
_HOST_API_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class PluginContractError(ValueError):
    """Raised when a plugin contract is malformed or internally inconsistent."""


def _is_strict_semver(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    matched = _SEMVER_RE.fullmatch(value)
    if matched is None:
        return False
    prerelease = matched.group(4)
    if prerelease is None:
        return True
    return all(
        not (part.isdigit() and len(part) > 1 and part.startswith("0"))
        for part in prerelease.split(".")
    )


def _require_exact_fields(
    value: Mapping[str, Any], *, expected: frozenset[str], label: str
) -> None:
    actual = frozenset(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        detail = []
        if missing:
            detail.append(f"missing={missing}")
        if unknown:
            detail.append(f"unknown={unknown}")
        raise PluginContractError(f"{label} fields are invalid ({', '.join(detail)})")


def _require_text(value: Any, *, label: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise PluginContractError(f"{label} must be non-empty text up to {maximum} bytes")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise PluginContractError(f"{label} must not contain control characters")
    return value


def _require_sorted_unique_texts(
    value: Any,
    *,
    label: str,
    allowed: frozenset[str] | None = None,
    maximum_items: int = 64,
) -> Tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or len(value) > maximum_items:
        raise PluginContractError(f"{label} must be a list with at most {maximum_items} items")
    items = tuple(_require_text(item, label=f"{label} item", maximum=128) for item in value)
    if items != tuple(sorted(set(items))):
        raise PluginContractError(f"{label} must be sorted and unique")
    if allowed is not None:
        unknown = sorted(set(items) - allowed)
        if unknown:
            raise PluginContractError(f"{label} contains unsupported values: {unknown}")
    return items


def schema_digest(schema: Mapping[str, Any]) -> str:
    """Return the content address used by capability schema contracts."""
    if not isinstance(schema, Mapping):
        raise TypeError("schema must be a mapping")
    body = dict(schema)
    return f"sha256:{hashlib.sha256(canonical_json(body)).hexdigest()}"


@dataclass(frozen=True)
class CapabilityContract:
    capability_id: str
    version: str
    input_schema_digest: str
    output_schema_digest: str
    effects: Tuple[str, ...]
    consistency: str
    privacy: str
    security: str
    cardinality: str
    deterministic: bool
    retention: str
    failure_semantics: str

    FIELDS: ClassVar[frozenset[str]] = frozenset(
        {
            "capability_id",
            "version",
            "input_schema_digest",
            "output_schema_digest",
            "effects",
            "consistency",
            "privacy",
            "security",
            "cardinality",
            "deterministic",
            "retention",
            "failure_semantics",
        }
    )

    def __post_init__(self) -> None:
        if not isinstance(self.capability_id, str) or not _CAPABILITY_ID_RE.fullmatch(
            self.capability_id
        ):
            raise PluginContractError("capability_id must be a lowercase namespaced identifier")
        if not _is_strict_semver(self.version):
            raise PluginContractError("capability version must be strict semantic version text")
        for label, digest in (
            ("input_schema_digest", self.input_schema_digest),
            ("output_schema_digest", self.output_schema_digest),
        ):
            if not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest):
                raise PluginContractError(f"{label} must be a lowercase sha256 digest")
        effects = _require_sorted_unique_texts(
            self.effects,
            label="capability effects",
            allowed=CAPABILITY_EFFECTS,
        )
        if not effects:
            raise PluginContractError("capability effects must not be empty")
        if "none" in effects and len(effects) != 1:
            raise PluginContractError("the 'none' effect cannot be combined with other effects")
        object.__setattr__(self, "effects", effects)
        for label, value, allowed in (
            ("consistency", self.consistency, CONSISTENCY_CLASSES),
            ("privacy", self.privacy, PRIVACY_CLASSES),
            ("security", self.security, SECURITY_CLASSES),
            ("cardinality", self.cardinality, CAPABILITY_CARDINALITIES),
            ("retention", self.retention, RETENTION_CLASSES),
            ("failure_semantics", self.failure_semantics, FAILURE_SEMANTICS),
        ):
            if value not in allowed:
                raise PluginContractError(f"unsupported capability {label}: {value!r}")
        if type(self.deterministic) is not bool:
            raise PluginContractError("capability deterministic must be a boolean")
        if self.security == "irreversible" and effects == ("none",):
            raise PluginContractError(
                "irreversible capabilities must declare at least one external effect"
            )
        if self.consistency in {"C3", "C4"} and self.failure_semantics == "best-effort":
            raise PluginContractError(
                "C3/C4 capabilities cannot use best-effort failure semantics"
            )

    @classmethod
    def from_dict(cls, value: Any) -> "CapabilityContract":
        if not isinstance(value, dict):
            raise PluginContractError("capability contract must be an object")
        _require_exact_fields(value, expected=cls.FIELDS, label="capability contract")
        return cls(
            capability_id=value["capability_id"],
            version=value["version"],
            input_schema_digest=value["input_schema_digest"],
            output_schema_digest=value["output_schema_digest"],
            effects=tuple(value["effects"]) if isinstance(value["effects"], list) else value["effects"],
            consistency=value["consistency"],
            privacy=value["privacy"],
            security=value["security"],
            cardinality=value["cardinality"],
            deterministic=value["deterministic"],
            retention=value["retention"],
            failure_semantics=value["failure_semantics"],
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capability_id": self.capability_id,
            "version": self.version,
            "input_schema_digest": self.input_schema_digest,
            "output_schema_digest": self.output_schema_digest,
            "effects": list(self.effects),
            "consistency": self.consistency,
            "privacy": self.privacy,
            "security": self.security,
            "cardinality": self.cardinality,
            "deterministic": self.deterministic,
            "retention": self.retention,
            "failure_semantics": self.failure_semantics,
        }

    @property
    def major_version(self) -> int:
        return int(self.version.split(".", 1)[0])

    @property
    def digest(self) -> str:
        return f"sha256:{hashlib.sha256(canonical_json(self.to_dict())).hexdigest()}"

    @property
    def required_permissions(self) -> frozenset[str]:
        return frozenset(EFFECT_PERMISSION[item] for item in self.effects if item != "none")


@dataclass(frozen=True)
class CapabilityRequirement:
    capability_id: str
    major_version: int
    contract_digest: str
    optional: bool = False

    FIELDS: ClassVar[frozenset[str]] = frozenset(
        {"capability_id", "major_version", "contract_digest", "optional"}
    )

    def __post_init__(self) -> None:
        if not isinstance(self.capability_id, str) or not _CAPABILITY_ID_RE.fullmatch(
            self.capability_id
        ):
            raise PluginContractError("required capability id is invalid")
        if type(self.major_version) is not int or not 0 <= self.major_version <= 65535:
            raise PluginContractError("required capability major_version is invalid")
        if not isinstance(self.contract_digest, str) or not _DIGEST_RE.fullmatch(
            self.contract_digest
        ):
            raise PluginContractError(
                "required capability contract_digest must be a lowercase sha256 digest"
            )
        if type(self.optional) is not bool:
            raise PluginContractError("required capability optional must be a boolean")

    @classmethod
    def from_dict(cls, value: Any) -> "CapabilityRequirement":
        if not isinstance(value, dict):
            raise PluginContractError("capability requirement must be an object")
        _require_exact_fields(value, expected=cls.FIELDS, label="capability requirement")
        return cls(
            capability_id=value["capability_id"],
            major_version=value["major_version"],
            contract_digest=value["contract_digest"],
            optional=value["optional"],
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capability_id": self.capability_id,
            "major_version": self.major_version,
            "contract_digest": self.contract_digest,
            "optional": self.optional,
        }


@dataclass(frozen=True)
class PluginManifest:
    manifest_version: int
    plugin_id: str
    version: str
    host_api: str
    kind: str
    runtime: str
    provides: Tuple[CapabilityContract, ...]
    requires: Tuple[CapabilityRequirement, ...]
    permissions: Tuple[str, ...]
    artifact_digest: str
    publisher_did: str = ""
    proof: str = ""

    FIELDS: ClassVar[frozenset[str]] = frozenset(
        {
            "manifest_version",
            "plugin_id",
            "version",
            "host_api",
            "kind",
            "runtime",
            "provides",
            "requires",
            "permissions",
            "artifact_digest",
            "publisher_did",
            "proof",
        }
    )

    def __post_init__(self) -> None:
        if type(self.manifest_version) is not int or self.manifest_version != PLUGIN_MANIFEST_VERSION:
            raise PluginContractError("unsupported plugin manifest version")
        if not isinstance(self.plugin_id, str) or not _PLUGIN_ID_RE.fullmatch(self.plugin_id):
            raise PluginContractError("plugin_id must be a lowercase namespaced identifier")
        if len(self.plugin_id) > 255:
            raise PluginContractError("plugin_id is too long")
        if not _is_strict_semver(self.version):
            raise PluginContractError("plugin version must be strict semantic version text")
        if not isinstance(self.host_api, str) or not _HOST_API_RE.fullmatch(self.host_api):
            raise PluginContractError("host_api must be a major.minor version")
        if self.kind not in PLUGIN_KINDS:
            raise PluginContractError(f"unsupported plugin kind: {self.kind!r}")
        if self.runtime != "builtin":
            raise PluginContractError("the current host accepts builtin plugins only")
        if not isinstance(self.provides, tuple) or not self.provides:
            raise PluginContractError("plugin must provide at least one capability")
        if len(self.provides) > 64 or any(
            not isinstance(item, CapabilityContract) for item in self.provides
        ):
            raise PluginContractError("plugin provides list is invalid")
        provide_ids = tuple(item.capability_id for item in self.provides)
        if provide_ids != tuple(sorted(set(provide_ids))):
            raise PluginContractError("provided capabilities must be sorted and unique")
        if not isinstance(self.requires, tuple) or len(self.requires) > 64 or any(
            not isinstance(item, CapabilityRequirement) for item in self.requires
        ):
            raise PluginContractError("plugin requires list is invalid")
        requirement_keys = tuple(
            (item.capability_id, item.major_version) for item in self.requires
        )
        if requirement_keys != tuple(sorted(set(requirement_keys))):
            raise PluginContractError("required capabilities must be sorted and unique")
        permissions = _require_sorted_unique_texts(
            self.permissions,
            label="plugin permissions",
            allowed=PLUGIN_PERMISSIONS,
        )
        object.__setattr__(self, "permissions", permissions)
        effect_permissions = frozenset().union(
            *(item.required_permissions for item in self.provides)
        )
        missing_permissions = sorted(effect_permissions - frozenset(permissions))
        if missing_permissions:
            raise PluginContractError(
                f"plugin capabilities require undeclared permissions: {missing_permissions}"
            )
        unused_permissions = sorted(frozenset(permissions) - effect_permissions)
        if unused_permissions:
            raise PluginContractError(
                f"plugin requests permissions not declared by capability effects: "
                f"{unused_permissions}"
            )
        if not isinstance(self.artifact_digest, str) or not _DIGEST_RE.fullmatch(
            self.artifact_digest
        ):
            raise PluginContractError("artifact_digest must be a lowercase sha256 digest")
        if bool(self.publisher_did) != bool(self.proof):
            raise PluginContractError("publisher_did and proof must be supplied together")
        if self.publisher_did:
            if len(self.publisher_did) > 512 or not is_did_key(self.publisher_did):
                raise PluginContractError("publisher_did must be an Ed25519 did:key")
            _require_text(self.proof, label="plugin proof", maximum=512)

    @classmethod
    def from_dict(cls, value: Any) -> "PluginManifest":
        if not isinstance(value, dict):
            raise PluginContractError("plugin manifest must be an object")
        _require_exact_fields(value, expected=cls.FIELDS, label="plugin manifest")
        provides_raw = value["provides"]
        requires_raw = value["requires"]
        if not isinstance(provides_raw, list) or not isinstance(requires_raw, list):
            raise PluginContractError("plugin provides/requires must be arrays")
        permissions_raw = value["permissions"]
        if not isinstance(permissions_raw, list):
            raise PluginContractError("plugin permissions must be an array")
        return cls(
            manifest_version=value["manifest_version"],
            plugin_id=value["plugin_id"],
            version=value["version"],
            host_api=value["host_api"],
            kind=value["kind"],
            runtime=value["runtime"],
            provides=tuple(CapabilityContract.from_dict(item) for item in provides_raw),
            requires=tuple(CapabilityRequirement.from_dict(item) for item in requires_raw),
            permissions=tuple(permissions_raw),
            artifact_digest=value["artifact_digest"],
            publisher_did=value["publisher_did"],
            proof=value["proof"],
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "manifest_version": self.manifest_version,
            "plugin_id": self.plugin_id,
            "version": self.version,
            "host_api": self.host_api,
            "kind": self.kind,
            "runtime": self.runtime,
            "provides": [item.to_dict() for item in self.provides],
            "requires": [item.to_dict() for item in self.requires],
            "permissions": list(self.permissions),
            "artifact_digest": self.artifact_digest,
            "publisher_did": self.publisher_did,
            "proof": self.proof,
        }

    @property
    def risk_tier(self) -> int:
        permission_tier = max(
            (PERMISSION_RISK_TIER[item] for item in self.permissions),
            default=0,
        )
        capability_tier = max(
            (4 if item.security == "irreversible" else 0 for item in self.provides),
            default=0,
        )
        return max(permission_tier, capability_tier)

    @property
    def digest(self) -> str:
        return f"sha256:{hashlib.sha256(canonical_json(self.to_dict())).hexdigest()}"


def ensure_host_api_compatible(requested: str, supported: str) -> None:
    """Require matching major and a plugin minor no newer than the host."""
    requested_match = _HOST_API_RE.fullmatch(str(requested))
    supported_match = _HOST_API_RE.fullmatch(str(supported))
    if requested_match is None or supported_match is None:
        raise PluginContractError("host API versions must use major.minor form")
    requested_major, requested_minor = (int(part) for part in requested.split("."))
    supported_major, supported_minor = (int(part) for part in supported.split("."))
    if requested_major != supported_major or requested_minor > supported_minor:
        raise PluginContractError(
            f"plugin host API {requested!r} is not compatible with host {supported!r}"
        )


def validate_manifest_set(manifests: Iterable[PluginManifest]) -> Tuple[PluginManifest, ...]:
    """Return a deterministic manifest tuple, rejecting duplicate identities."""
    values = tuple(manifests)
    if any(not isinstance(item, PluginManifest) for item in values):
        raise TypeError("all manifests must be PluginManifest instances")
    ids = [item.plugin_id for item in values]
    if len(ids) != len(set(ids)):
        raise PluginContractError("plugin manifest set contains duplicate plugin ids")
    return tuple(sorted(values, key=lambda item: item.plugin_id))


__all__ = [
    "CAPABILITY_CARDINALITIES",
    "CAPABILITY_EFFECTS",
    "CONSISTENCY_CLASSES",
    "FAILURE_SEMANTICS",
    "PLUGIN_HOST_API_VERSION",
    "PLUGIN_KINDS",
    "PLUGIN_MANIFEST_VERSION",
    "PLUGIN_PERMISSIONS",
    "PERMISSION_RISK_TIER",
    "PRIVACY_CLASSES",
    "RETENTION_CLASSES",
    "SECURITY_CLASSES",
    "CapabilityContract",
    "CapabilityRequirement",
    "PluginContractError",
    "PluginManifest",
    "ensure_host_api_compatible",
    "schema_digest",
    "validate_manifest_set",
]
