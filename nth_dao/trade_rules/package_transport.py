"""Bounded wire transport for non-executing Trade Rule Packages."""

from __future__ import annotations

import json
import re
from typing import Any

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.trade_rules.canonical import MAX_TRADE_JSON_BYTES
from nth_dao.trade_rules.manifest import (
    MAX_PACKAGE_RESOURCE_BYTES,
    MAX_RESOURCE_BYTES,
    TradeRuleManifest,
)
from nth_dao.trade_rules.package_binding import (
    OfferPackageBindingRejected,
    SignedOfferPackageBinding,
    require_offer_package_binding,
)
from nth_dao.trade_rules.package_store import (
    RulePackage,
    RulePackageValidationError,
    build_rule_package,
)

RULE_PACKAGE_BUNDLE_KIND = "nth.dao.trade.rule-package-bundle"
RULE_PACKAGE_BUNDLE_PROTOCOL_VERSION = "1"
MAX_RULE_PACKAGE_BUNDLE_BYTES = (
    MAX_TRADE_JSON_BYTES
    + ((MAX_PACKAGE_RESOURCE_BYTES + 2) // 3 * 4)
    + (128 * 256)
)

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_BUNDLE_FIELDS = frozenset({
    "kind",
    "protocol_version",
    "offer_digest",
    "offer_package_binding",
    "package_digest",
    "manifest",
    "resources",
})
_RESOURCE_FIELDS = frozenset({"digest", "bytes_b64u"})


class RulePackageBundleRejected(ValueError):
    """A remote Rule Package bundle is malformed or fails exact binding."""


def _digest(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise RulePackageBundleRejected(f"{label} must be a lowercase sha256 digest")
    return value


def _verified_package(package: RulePackage) -> RulePackage:
    if not isinstance(package, RulePackage):
        raise TypeError("package must be a RulePackage")
    try:
        rebuilt = build_rule_package(package.manifest, package.resources)
    except (TypeError, ValueError, RulePackageValidationError) as exc:
        raise RulePackageBundleRejected(f"Rule Package is invalid: {exc}") from exc
    if rebuilt.digest != package.digest:
        raise RulePackageBundleRejected("Rule Package digest is inconsistent")
    return rebuilt


def build_rule_package_bundle(
    package: RulePackage,
    *,
    offer_package_binding: SignedOfferPackageBinding | dict[str, Any],
) -> dict[str, Any]:
    """Return a deterministic transport object without granting authority."""

    verified = _verified_package(package)
    try:
        binding = require_offer_package_binding(
            offer_package_binding,
            expected_package_digest=verified.digest,
        )
    except OfferPackageBindingRejected as exc:
        raise RulePackageBundleRejected(str(exc)) from exc
    return {
        "kind": RULE_PACKAGE_BUNDLE_KIND,
        "protocol_version": RULE_PACKAGE_BUNDLE_PROTOCOL_VERSION,
        "offer_digest": binding.offer_digest,
        "offer_package_binding": binding.to_dict(),
        "package_digest": verified.digest,
        "manifest": verified.manifest.to_dict(),
        "resources": [
            {
                "digest": digest,
                "bytes_b64u": b64u_encode(payload),
            }
            for digest, payload in sorted(verified.resources.items())
        ],
    }


def rule_package_bundle_bytes(document: dict[str, Any]) -> bytes:
    """Encode a bundle deterministically and enforce its public wire bound."""

    try:
        encoded = json.dumps(
            document,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise RulePackageBundleRejected(
            "Rule Package bundle cannot be encoded as strict UTF-8 JSON"
        ) from exc
    if len(encoded) > MAX_RULE_PACKAGE_BUNDLE_BYTES:
        raise RulePackageBundleRejected("Rule Package bundle exceeds the wire limit")
    # Validate the frozen wire bytes, never the caller's still-mutable object.
    parse_rule_package_bundle(encoded)
    return encoded


def parse_rule_package_bundle(
    value: dict[str, Any] | bytes | str,
    *,
    expected_offer_digest: str | None = None,
    expected_package_digest: str | None = None,
    expected_offer_publisher_did: str | None = None,
) -> RulePackage:
    """Verify one bounded bundle and return immutable, non-executing content."""

    if isinstance(value, (bytes, str)):
        raw = value.encode("utf-8") if isinstance(value, str) else value
        if len(raw) > MAX_RULE_PACKAGE_BUNDLE_BYTES:
            raise RulePackageBundleRejected("Rule Package bundle exceeds the wire limit")
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RulePackageBundleRejected("Rule Package bundle is not valid JSON") from exc
    elif isinstance(value, dict):
        document = value
    else:
        raise TypeError("Rule Package bundle must be an object or JSON bytes")

    if not isinstance(document, dict):
        raise RulePackageBundleRejected("Rule Package bundle must be a JSON object")
    if set(document) != _BUNDLE_FIELDS:
        raise RulePackageBundleRejected("Rule Package bundle fields are invalid")
    if document["kind"] != RULE_PACKAGE_BUNDLE_KIND:
        raise RulePackageBundleRejected("Rule Package bundle kind is invalid")
    if document["protocol_version"] != RULE_PACKAGE_BUNDLE_PROTOCOL_VERSION:
        raise RulePackageBundleRejected("Rule Package bundle version is unsupported")
    offer_digest = _digest(document["offer_digest"], label="offer_digest")
    package_digest = _digest(document["package_digest"], label="package_digest")
    if expected_offer_digest is not None and offer_digest != _digest(
        expected_offer_digest,
        label="expected_offer_digest",
    ):
        raise RulePackageBundleRejected("Rule Package bundle is bound to another Offer")
    if expected_package_digest is not None and package_digest != _digest(
        expected_package_digest,
        label="expected_package_digest",
    ):
        raise RulePackageBundleRejected("Rule Package bundle has another package digest")
    try:
        require_offer_package_binding(
            document["offer_package_binding"],
            expected_offer_digest=offer_digest,
            expected_package_digest=package_digest,
            expected_publisher_did=expected_offer_publisher_did,
        )
    except OfferPackageBindingRejected as exc:
        raise RulePackageBundleRejected(str(exc)) from exc

    resources_value = document["resources"]
    if not isinstance(resources_value, list) or len(resources_value) > 128:
        raise RulePackageBundleRejected("Rule Package bundle resources are invalid")
    resources: dict[str, bytes] = {}
    previous_digest = ""
    total_bytes = 0
    for index, item in enumerate(resources_value):
        if not isinstance(item, dict) or set(item) != _RESOURCE_FIELDS:
            raise RulePackageBundleRejected(
                f"Rule Package bundle resource {index} fields are invalid"
            )
        digest = _digest(item["digest"], label=f"resources[{index}].digest")
        if digest <= previous_digest:
            raise RulePackageBundleRejected(
                "Rule Package bundle resources must be unique and digest-sorted"
            )
        previous_digest = digest
        encoded = item["bytes_b64u"]
        if not isinstance(encoded, str) or len(encoded) > (
            ((MAX_RESOURCE_BYTES + 2) // 3 * 4)
        ):
            raise RulePackageBundleRejected(
                f"Rule Package bundle resource {index} exceeds its encoded limit"
            )
        try:
            payload = b64u_decode(encoded)
        except (UnicodeError, ValueError) as exc:
            raise RulePackageBundleRejected(
                f"Rule Package bundle resource {index} is not canonical base64url"
            ) from exc
        if b64u_encode(payload) != encoded:
            raise RulePackageBundleRejected(
                f"Rule Package bundle resource {index} is not canonical base64url"
            )
        if len(payload) > MAX_RESOURCE_BYTES:
            raise RulePackageBundleRejected(
                f"Rule Package bundle resource {index} exceeds the byte limit"
            )
        total_bytes += len(payload)
        if total_bytes > MAX_PACKAGE_RESOURCE_BYTES:
            raise RulePackageBundleRejected(
                "Rule Package bundle exceeds the aggregate resource byte limit"
            )
        resources[digest] = payload

    manifest_value = document["manifest"]
    if not isinstance(manifest_value, dict):
        raise RulePackageBundleRejected("Rule Package bundle manifest is invalid")
    try:
        manifest = TradeRuleManifest.from_dict(manifest_value)
        package = build_rule_package(manifest, resources)
    except (TypeError, ValueError, RulePackageValidationError) as exc:
        raise RulePackageBundleRejected(f"Rule Package bundle verification failed: {exc}") from exc
    if package.digest != package_digest:
        raise RulePackageBundleRejected("Rule Package bundle digest does not match Manifest")
    return package


__all__ = [
    "MAX_RULE_PACKAGE_BUNDLE_BYTES",
    "RULE_PACKAGE_BUNDLE_KIND",
    "RULE_PACKAGE_BUNDLE_PROTOCOL_VERSION",
    "RulePackageBundleRejected",
    "build_rule_package_bundle",
    "parse_rule_package_bundle",
    "rule_package_bundle_bytes",
]
