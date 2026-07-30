"""Signed, content-addressed Trade Rule Manifest v1."""

from __future__ import annotations

import copy
import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

from nth_dao.did_key import is_did_key
from nth_dao.identity import AgentIdentity
from nth_dao.trade_rules.canonical import (
    TradeCanonicalJSONError,
    parse_trade_json,
    trade_canonical_json,
)
from nth_dao.trade_rules.signing import (
    TradeProofError,
    decode_canonical_ed25519_signature,
    encode_ed25519_signature,
    signed_document_input,
    verification_method_for_did,
    verify_ed25519_did_signature,
)

MANIFEST_KIND = "org.nthdao.trade.rule-manifest"
MANIFEST_PROTOCOL_VERSION = "1.0"
MANIFEST_PROOF_TYPE = "NthEd25519SignatureV1"
MANIFEST_PROOF_PURPOSE = "assertionMethod"
MANIFEST_SIGNING_DOMAIN = b"NTH-TRADE-RULE-MANIFEST-V1"

MAX_RESOURCE_BYTES = 1_048_576
MAX_PACKAGE_RESOURCE_BYTES = 16_777_216

_TOP_LEVEL_FIELDS = frozenset(
    {
        "kind",
        "protocol_version",
        "rule_id",
        "version",
        "publisher_did",
        "summary",
        "applies_to",
        "families",
        "resources",
        "dependencies",
        "conflicts",
        "required_capabilities",
        "hook_contracts",
        "execution",
        "published_at",
        "not_after",
        "extensions",
        "proof",
    }
)
_BODY_FIELDS = _TOP_LEVEL_FIELDS - {"proof"}
_PROOF_FIELDS = frozenset(
    {
        "type",
        "created",
        "verification_method",
        "proof_purpose",
        "proof_value",
    }
)
_RESOURCE_FIELDS = frozenset({"purpose", "media_type", "digest", "size"})
_RULE_REF_FIELDS = frozenset({"rule_id", "digest"})
_HOOK_FIELDS = frozenset(
    {
        "name",
        "version",
        "input_schema_digest",
        "output_schema_digest",
        "side_effect",
        "permissions",
    }
)
_EXECUTION_FIELDS = frozenset({"mode", "permissions"})
MANIFEST_EXECUTION_MODES = frozenset(
    {"declarative", "adapter", "sandboxed_wasm", "external_service"}
)
_SIDE_EFFECTS = frozenset({"none", "local", "external", "funds"})

_RULE_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_RULE_ID = re.compile(
    rf"^{_RULE_LABEL}(?:\.{_RULE_LABEL})+"
    r"(?:/[a-z0-9](?:[a-z0-9._-]{0,30}[a-z0-9])?)?$"
)
_VERSION = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
_TOKEN = re.compile(r"^[a-z0-9][a-z0-9._:/-]*$")
_MEDIA_TYPE = re.compile(r"^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_EXTENSION_ID = re.compile(
    rf"^{_RULE_LABEL}(?:\.{_RULE_LABEL})+"
    r"/[a-z0-9](?:[a-z0-9._-]{0,30}[a-z0-9])?$"
)
_TIMESTAMP = re.compile(
    r"^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.([0-9]{1,9}))?Z$"
)


class ManifestRejected(ValueError):
    """Raised when a manifest is malformed, untrusted, or unverifiable."""


def _reject(message: str) -> None:
    raise ManifestRejected(message)


def _exact_fields(value: Any, expected: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _reject(f"{label} must be an object")
    if any(not isinstance(key, str) for key in value):
        _reject(f"{label} keys must be strings")
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        _reject(f"{label} fields invalid; missing={missing}, unknown={unknown}")
    return value


def _bounded_string(
    value: Any,
    *,
    label: str,
    minimum: int = 1,
    maximum: int,
) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        _reject(f"{label} must be a string of length {minimum}..{maximum}")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ManifestRejected(f"{label} contains invalid Unicode") from exc
    return value


def _token(value: Any, *, label: str, maximum: int = 160) -> str:
    text = _bounded_string(value, label=label, maximum=maximum)
    if not _TOKEN.fullmatch(text):
        _reject(f"{label} is not a valid namespaced token")
    return text


def _unique_strings(
    value: Any,
    *,
    label: str,
    minimum: int,
    maximum: int,
    validator: Any = _token,
) -> list[str]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        _reject(f"{label} must contain {minimum}..{maximum} entries")
    output = [
        validator(item, label=f"{label}[{index}]") for index, item in enumerate(value)
    ]
    if len(set(output)) != len(output):
        _reject(f"{label} contains duplicate entries")
    if output != sorted(output):
        _reject(f"{label} must be sorted")
    return output


def _digest(value: Any, *, label: str) -> str:
    text = _bounded_string(value, label=label, maximum=71)
    if not _DIGEST.fullmatch(text):
        _reject(f"{label} must be a lowercase sha256 digest")
    return text


def _rule_id(value: Any, *, label: str) -> str:
    text = _bounded_string(value, label=label, minimum=3, maximum=160)
    if not _RULE_ID.fullmatch(text):
        _reject(f"{label} is invalid")
    return text


def _timestamp_value(value: Any, *, label: str) -> tuple[datetime, int]:
    text = _bounded_string(value, label=label, maximum=35)
    match = _TIMESTAMP.fullmatch(text)
    if not match:
        _reject(f"{label} must be a UTC RFC3339 timestamp")
    try:
        base = datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ManifestRejected(f"{label} is not a real timestamp") from exc
    nanos = int((match.group(2) or "").ljust(9, "0") or "0")
    return base, nanos


def _validate_rule_refs(value: Any, *, label: str) -> set[tuple[str, str]]:
    if not isinstance(value, list) or len(value) > 64:
        _reject(f"{label} must be a list with at most 64 entries")
    seen: set[tuple[str, str]] = set()
    order: list[tuple[str, str]] = []
    for index, raw in enumerate(value):
        item = _exact_fields(raw, _RULE_REF_FIELDS, f"{label}[{index}]")
        key = (
            _rule_id(item["rule_id"], label=f"{label}[{index}].rule_id"),
            _digest(item["digest"], label=f"{label}[{index}].digest"),
        )
        if key in seen:
            _reject(f"{label} contains duplicate entries")
        seen.add(key)
        order.append(key)
    if order != sorted(order):
        _reject(f"{label} must be sorted by rule_id and digest")
    return seen


def _validate_resources(value: Any) -> None:
    if not isinstance(value, list) or not 1 <= len(value) <= 128:
        _reject("resources must contain 1..128 entries")
    seen: set[tuple[str, str]] = set()
    order: list[tuple[str, str]] = []
    total = 0
    for index, raw in enumerate(value):
        item = _exact_fields(raw, _RESOURCE_FIELDS, f"resources[{index}]")
        purpose = _token(item["purpose"], label=f"resources[{index}].purpose")
        media_type = _bounded_string(
            item["media_type"], label=f"resources[{index}].media_type", maximum=128
        )
        if not _MEDIA_TYPE.fullmatch(media_type):
            _reject(f"resources[{index}].media_type is invalid")
        digest = _digest(item["digest"], label=f"resources[{index}].digest")
        size = item["size"]
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or not 0 <= size <= MAX_RESOURCE_BYTES
        ):
            _reject(f"resources[{index}].size is invalid")
        total += size
        if total > MAX_PACKAGE_RESOURCE_BYTES:
            _reject("declared package resources exceed byte limit")
        key = (purpose, digest)
        if key in seen:
            _reject("resources contains duplicate purpose/digest entries")
        seen.add(key)
        order.append(key)
    if order != sorted(order):
        _reject("resources must be sorted by purpose and digest")


def _validate_hooks(value: Any) -> set[str]:
    if not isinstance(value, list) or len(value) > 32:
        _reject("hook_contracts must be a list with at most 32 entries")
    seen: set[tuple[str, str]] = set()
    order: list[tuple[str, str]] = []
    required_permissions: set[str] = set()
    for index, raw in enumerate(value):
        item = _exact_fields(raw, _HOOK_FIELDS, f"hook_contracts[{index}]")
        name = _token(item["name"], label=f"hook_contracts[{index}].name")
        version = _token(
            item["version"],
            label=f"hook_contracts[{index}].version",
            maximum=32,
        )
        _digest(
            item["input_schema_digest"],
            label=f"hook_contracts[{index}].input_schema_digest",
        )
        _digest(
            item["output_schema_digest"],
            label=f"hook_contracts[{index}].output_schema_digest",
        )
        if (
            not isinstance(item["side_effect"], str)
            or item["side_effect"] not in _SIDE_EFFECTS
        ):
            _reject(f"hook_contracts[{index}].side_effect is invalid")
        hook_permissions = _unique_strings(
            item["permissions"],
            label=f"hook_contracts[{index}].permissions",
            minimum=0,
            maximum=64,
        )
        required_permissions.update(hook_permissions)
        key = (name, version)
        if key in seen:
            _reject("hook_contracts contains duplicate name/version entries")
        seen.add(key)
        order.append(key)
    if order != sorted(order):
        _reject("hook_contracts must be sorted by name and version")
    return required_permissions


def _validate_common(document: dict[str, Any]) -> None:
    if document["kind"] != MANIFEST_KIND:
        _reject("wrong manifest kind")
    if document["protocol_version"] != MANIFEST_PROTOCOL_VERSION:
        _reject("unsupported manifest protocol_version")
    _rule_id(document["rule_id"], label="rule_id")
    version = _bounded_string(document["version"], label="version", maximum=64)
    if not _VERSION.fullmatch(version):
        _reject("version is not valid SemVer")
    publisher_did = _bounded_string(
        document["publisher_did"], label="publisher_did", maximum=256
    )
    if not is_did_key(publisher_did):
        _reject("publisher_did must be an Ed25519 did:key")
    summary = _bounded_string(document["summary"], label="summary", maximum=500)
    if len(summary.encode("utf-8")) > 2_000:
        _reject("summary exceeds UTF-8 byte limit")
    _unique_strings(document["applies_to"], label="applies_to", minimum=1, maximum=32)
    _unique_strings(document["families"], label="families", minimum=1, maximum=32)
    _validate_resources(document["resources"])
    dependencies = _validate_rule_refs(document["dependencies"], label="dependencies")
    conflicts = _validate_rule_refs(document["conflicts"], label="conflicts")
    if dependencies & conflicts:
        _reject("the same rule reference cannot be both a dependency and a conflict")
    _unique_strings(
        document["required_capabilities"],
        label="required_capabilities",
        minimum=0,
        maximum=64,
    )
    hook_permissions = _validate_hooks(document["hook_contracts"])

    execution = _exact_fields(document["execution"], _EXECUTION_FIELDS, "execution")
    if (
        not isinstance(execution["mode"], str)
        or execution["mode"] not in MANIFEST_EXECUTION_MODES
    ):
        _reject("execution.mode is invalid")
    permissions = _unique_strings(
        execution["permissions"],
        label="execution.permissions",
        minimum=0,
        maximum=64,
    )
    if execution["mode"] == "declarative" and permissions:
        _reject("declarative manifests cannot request permissions")
    if not hook_permissions <= set(permissions):
        _reject(
            "hook_contracts permissions must be declared by execution.permissions"
        )

    published = _timestamp_value(document["published_at"], label="published_at")
    not_after_raw = document["not_after"]
    if not_after_raw is not None:
        not_after = _timestamp_value(not_after_raw, label="not_after")
        if not_after <= published:
            _reject("not_after must be later than published_at")

    extensions = document["extensions"]
    if not isinstance(extensions, dict) or len(extensions) > 32:
        _reject("extensions must be an object with at most 32 entries")
    for extension_id, extension_value in extensions.items():
        if not isinstance(extension_id, str) or not _EXTENSION_ID.fullmatch(
            extension_id
        ):
            _reject(f"invalid extension id: {extension_id!r}")
        if not isinstance(extension_value, dict):
            _reject(f"extension {extension_id!r} must be an object")


def _validate_body(body: Any) -> dict[str, Any]:
    document = _exact_fields(body, _BODY_FIELDS, "manifest body")
    _validate_common(document)
    try:
        trade_canonical_json(document)
    except TradeCanonicalJSONError as exc:
        raise ManifestRejected(str(exc)) from exc
    return document


def _validate_complete(document: Any) -> dict[str, Any]:
    value = _exact_fields(document, _TOP_LEVEL_FIELDS, "manifest")
    _validate_common(value)
    proof = _exact_fields(value["proof"], _PROOF_FIELDS, "proof")
    if proof["type"] != MANIFEST_PROOF_TYPE:
        _reject("unsupported proof.type")
    if proof["proof_purpose"] != MANIFEST_PROOF_PURPOSE:
        _reject("unsupported proof.proof_purpose")
    proof_created = _timestamp_value(proof["created"], label="proof.created")
    published = _timestamp_value(value["published_at"], label="published_at")
    if proof_created < published:
        _reject("proof.created must not be before published_at")
    if value["not_after"] is not None:
        not_after = _timestamp_value(value["not_after"], label="not_after")
        if not_after <= proof_created:
            _reject("not_after must be later than proof.created")

    expected_method = verification_method_for_did(value["publisher_did"])
    if proof["verification_method"] != expected_method:
        _reject("proof.verification_method does not match publisher_did")

    proof_value = _bounded_string(
        proof["proof_value"], label="proof.proof_value", minimum=86, maximum=86
    )
    try:
        decode_canonical_ed25519_signature(proof_value)
    except TradeProofError as exc:
        raise ManifestRejected(str(exc)) from exc
    try:
        trade_canonical_json(value)
    except TradeCanonicalJSONError as exc:
        raise ManifestRejected(str(exc)) from exc
    return value


def _complete_snapshot(document: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    """Freeze untrusted mutable input before semantic validation or verification."""
    try:
        canonical = trade_canonical_json(document)
    except TradeCanonicalJSONError as exc:
        raise ManifestRejected(str(exc)) from exc
    snapshot = parse_trade_json(canonical)
    _validate_complete(snapshot)
    return canonical, snapshot


def _signing_input_from_snapshot(snapshot: dict[str, Any]) -> bytes:
    try:
        return signed_document_input(MANIFEST_SIGNING_DOMAIN, snapshot)
    except TradeProofError as exc:
        raise ManifestRejected(str(exc)) from exc


def manifest_signing_input(document: dict[str, Any]) -> bytes:
    """Return the domain-separated bytes covered by the manifest signature."""
    _, snapshot = _complete_snapshot(document)
    return _signing_input_from_snapshot(snapshot)


def _verify_snapshot_signature(snapshot: dict[str, Any]) -> tuple[bool, str]:
    try:
        signing_input = _signing_input_from_snapshot(snapshot)
    except (ManifestRejected, TradeCanonicalJSONError, TypeError, ValueError):
        return False, "manifest signature invalid"
    ok, reason = verify_ed25519_did_signature(
        publisher_did=snapshot["publisher_did"],
        proof_value=snapshot["proof"]["proof_value"],
        signing_input=signing_input,
    )
    return (ok, "ok" if ok else ("crypto unavailable" if reason == "crypto unavailable"
                                 else "manifest signature invalid"))


def _verify_signature(document: dict[str, Any]) -> tuple[bool, str]:
    try:
        _, snapshot = _complete_snapshot(document)
    except (
        ManifestRejected,
        TradeCanonicalJSONError,
        TypeError,
        ValueError,
        UnicodeError,
    ):
        return False, "manifest signature invalid"
    return _verify_snapshot_signature(snapshot)


@dataclass(frozen=True, init=False)
class InspectedTradeRuleManifest:
    """Immutable canonical manifest without an implied trust decision."""

    _canonical: bytes

    @classmethod
    def _create(cls, canonical: bytes) -> "InspectedTradeRuleManifest":
        instance = object.__new__(cls)
        object.__setattr__(instance, "_canonical", canonical)
        return instance

    @classmethod
    def from_dict(
        cls,
        document: dict[str, Any],
    ) -> "InspectedTradeRuleManifest":
        try:
            canonical, _ = _complete_snapshot(document)
        except ManifestRejected:
            raise
        except TradeCanonicalJSONError as exc:
            raise ManifestRejected(str(exc)) from exc
        return cls._create(canonical)

    @classmethod
    def from_json(
        cls,
        raw: bytes | str,
    ) -> "InspectedTradeRuleManifest":
        try:
            document = parse_trade_json(raw)
        except TradeCanonicalJSONError as exc:
            raise ManifestRejected(str(exc)) from exc
        return cls.from_dict(document)

    def to_dict(self) -> dict[str, Any]:
        return parse_trade_json(self._canonical)

    @property
    def canonical_bytes(self) -> bytes:
        return self._canonical

    @property
    def verified(self) -> bool:
        try:
            document = self.to_dict()
            ok, _ = _verify_signature(document)
        except (ManifestRejected, TradeCanonicalJSONError, TypeError, ValueError):
            return False
        return ok

    @property
    def rule_id(self) -> str:
        return self.to_dict()["rule_id"]

    @property
    def version(self) -> str:
        return self.to_dict()["version"]

    @property
    def publisher_did(self) -> str:
        return self.to_dict()["publisher_did"]


@dataclass(frozen=True, init=False)
class TradeRuleManifest(InspectedTradeRuleManifest):
    """Immutable manifest verified against its publisher did:key."""

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> "TradeRuleManifest":
        try:
            canonical, snapshot = _complete_snapshot(document)
        except ManifestRejected:
            raise
        except TradeCanonicalJSONError as exc:
            raise ManifestRejected(str(exc)) from exc
        ok, reason = _verify_snapshot_signature(snapshot)
        if not ok:
            raise ManifestRejected(reason)
        return cls._create(canonical)

    @classmethod
    def from_json(cls, raw: bytes | str) -> "TradeRuleManifest":
        try:
            document = parse_trade_json(raw)
        except TradeCanonicalJSONError as exc:
            raise ManifestRejected(str(exc)) from exc
        return cls.from_dict(document)


def sign_manifest(
    identity: AgentIdentity,
    body: dict[str, Any],
    *,
    created: str | None = None,
) -> TradeRuleManifest:
    """Validate and sign one proof-free manifest body."""
    if not identity.can_sign:
        raise RuntimeError("identity has no signing key")
    document = copy.deepcopy(body)
    _validate_body(document)
    if document["publisher_did"] != identity.as_did():
        raise ManifestRejected("signer does not match publisher_did")
    proof_created = created or datetime.now(timezone.utc).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")
    proof = {
        "type": MANIFEST_PROOF_TYPE,
        "created": proof_created,
        "verification_method": verification_method_for_did(identity.as_did()),
        "proof_purpose": MANIFEST_PROOF_PURPOSE,
    }
    unsigned = dict(document)
    unsigned["proof"] = proof
    # Validate proof metadata and timestamp ordering before signing. A canonical
    # placeholder has the same shape as a real Ed25519 signature.
    unsigned["proof"]["proof_value"] = "A" * 86
    _validate_complete(unsigned)
    signing_input = _signing_input_from_snapshot(unsigned)
    unsigned["proof"]["proof_value"] = encode_ed25519_signature(
        identity.sign(signing_input)
    )
    return TradeRuleManifest.from_dict(unsigned)


def verify_manifest(
    manifest: InspectedTradeRuleManifest | dict[str, Any],
) -> tuple[bool, str]:
    try:
        document = (
            manifest.to_dict()
            if isinstance(manifest, InspectedTradeRuleManifest)
            else manifest
        )
        _validate_complete(document)
    except (ManifestRejected, TradeCanonicalJSONError, TypeError, ValueError) as exc:
        return False, str(exc)
    return _verify_signature(document)


def evaluate_manifest(
    manifest: TradeRuleManifest | dict[str, Any],
    *,
    at: datetime | None = None,
) -> tuple[bool, str]:
    """Evaluate signature integrity and signed publication/expiry bounds."""

    try:
        verified = (
            TradeRuleManifest.from_json(manifest.canonical_bytes)
            if isinstance(manifest, TradeRuleManifest)
            else TradeRuleManifest.from_dict(manifest)
        )
    except (ManifestRejected, TradeCanonicalJSONError, TypeError, ValueError) as exc:
        return False, f"invalid: {exc}"
    moment = at or datetime.now(timezone.utc)
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("at must be timezone-aware")
    moment = moment.astimezone(timezone.utc)
    moment_value = (moment.replace(microsecond=0), moment.microsecond * 1_000)
    document = verified.to_dict()
    published = _timestamp_value(document["published_at"], label="published_at")
    if moment_value < published:
        return False, "not_yet_active"
    if document["not_after"] is not None:
        not_after = _timestamp_value(document["not_after"], label="not_after")
        if moment_value >= not_after:
            return False, "expired"
    return True, "active"


def manifest_digest(
    manifest: TradeRuleManifest | dict[str, Any],
) -> str:
    if isinstance(manifest, TradeRuleManifest):
        document = manifest.to_dict()
        _validate_complete(document)
        ok, reason = _verify_signature(document)
        if not ok:
            raise ManifestRejected(reason)
        canonical = trade_canonical_json(document)
    elif isinstance(manifest, InspectedTradeRuleManifest):
        raise ManifestRejected(
            "manifest_digest requires a cryptographically verified manifest"
        )
    else:
        parsed = TradeRuleManifest.from_dict(manifest)
        canonical = parsed.canonical_bytes
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def inspection_digest(
    manifest: InspectedTradeRuleManifest | dict[str, Any],
) -> str:
    """Hash a structurally valid manifest without granting trust."""
    if isinstance(manifest, InspectedTradeRuleManifest):
        canonical, _ = _complete_snapshot(manifest.to_dict())
    else:
        canonical = InspectedTradeRuleManifest.from_dict(manifest).canonical_bytes
    return "unverified-sha256:" + hashlib.sha256(canonical).hexdigest()


def manifest_body(
    *,
    rule_id: str,
    version: str,
    publisher_did: str,
    summary: str,
    applies_to: Iterable[str],
    families: Iterable[str],
    resources: Iterable[dict[str, Any]],
    dependencies: Iterable[dict[str, Any]] = (),
    conflicts: Iterable[dict[str, Any]] = (),
    required_capabilities: Iterable[str] = (),
    hook_contracts: Iterable[dict[str, Any]] = (),
    execution_mode: str = "declarative",
    permissions: Iterable[str] = (),
    published_at: str,
    not_after: str | None = None,
    extensions: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build and validate a proof-free manifest body."""
    applies_values = list(applies_to)
    family_values = list(families)
    resource_values = [copy.deepcopy(value) for value in resources]
    dependency_values = [copy.deepcopy(value) for value in dependencies]
    conflict_values = [copy.deepcopy(value) for value in conflicts]
    capability_values = list(required_capabilities)
    hook_values = [copy.deepcopy(value) for value in hook_contracts]
    permission_values = list(permissions)

    if all(isinstance(item, str) for item in applies_values):
        applies_values.sort()
    if all(isinstance(item, str) for item in family_values):
        family_values.sort()
    if all(
        isinstance(item, dict)
        and isinstance(item.get("purpose"), str)
        and isinstance(item.get("digest"), str)
        for item in resource_values
    ):
        resource_values.sort(key=lambda item: (item["purpose"], item["digest"]))
    for values in (dependency_values, conflict_values):
        if all(
            isinstance(item, dict)
            and isinstance(item.get("rule_id"), str)
            and isinstance(item.get("digest"), str)
            for item in values
        ):
            values.sort(key=lambda item: (item["rule_id"], item["digest"]))
    if all(isinstance(item, str) for item in capability_values):
        capability_values.sort()
    if all(
        isinstance(item, dict)
        and isinstance(item.get("name"), str)
        and isinstance(item.get("version"), str)
        for item in hook_values
    ):
        hook_values.sort(key=lambda item: (item["name"], item["version"]))
    if all(isinstance(item, str) for item in permission_values):
        permission_values.sort()

    body = {
        "kind": MANIFEST_KIND,
        "protocol_version": MANIFEST_PROTOCOL_VERSION,
        "rule_id": rule_id,
        "version": version,
        "publisher_did": publisher_did,
        "summary": summary,
        "applies_to": applies_values,
        "families": family_values,
        "resources": resource_values,
        "dependencies": dependency_values,
        "conflicts": conflict_values,
        "required_capabilities": capability_values,
        "hook_contracts": hook_values,
        "execution": {
            "mode": execution_mode,
            "permissions": permission_values,
        },
        "published_at": published_at,
        "not_after": not_after,
        "extensions": copy.deepcopy(extensions or {}),
    }
    _validate_body(body)
    return body


__all__ = [
    "MAX_PACKAGE_RESOURCE_BYTES",
    "MAX_RESOURCE_BYTES",
    "MANIFEST_KIND",
    "MANIFEST_EXECUTION_MODES",
    "MANIFEST_PROOF_PURPOSE",
    "MANIFEST_PROOF_TYPE",
    "MANIFEST_PROTOCOL_VERSION",
    "MANIFEST_SIGNING_DOMAIN",
    "InspectedTradeRuleManifest",
    "ManifestRejected",
    "TradeRuleManifest",
    "inspection_digest",
    "evaluate_manifest",
    "manifest_body",
    "manifest_digest",
    "manifest_signing_input",
    "sign_manifest",
    "verify_manifest",
]
