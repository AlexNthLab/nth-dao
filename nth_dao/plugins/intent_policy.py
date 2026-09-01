"""Deterministic Host policy for accepting an exact reviewed Intent draft.

The policy snapshot is local trusted state, not a remotely asserted permission
and not an executable mandate. It deliberately contains no signing helper and
cannot create Tasks, Missions, Agreements, payments, or plugin invocations.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any

from nth_dao.canonical_json import canonical_json
from nth_dao.did_key import (
    DIDKeyError,
    decode_ed25519_did_key,
    encode_ed25519_did_key,
    is_prime_order_ed25519_point,
)

from .intent_acceptance import IntentAcceptanceHead
from .intent_envelope import IntentAcceptanceContext
from .intent_resolver import INTENT_RESOLVER_MAX_SAFE_INTEGER


INTENT_POLICY_FORMAT = "org.nth-dao.intent-acceptance-policy-snapshot"
INTENT_POLICY_VERSION = "1"
INTENT_POLICY_MAX_MEMBERS = 64
INTENT_POLICY_MAX_TTL_MS = 31 * 86_400_000
INTENT_POLICY_MAX_DOCUMENT_BYTES = 512 * 1024

_HASH = re.compile(r"sha256:[0-9a-f]{64}")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}")
_ROLES = ("admin", "member", "owner")
_ACCEPTANCE_ROLES = frozenset(_ROLES)
_STATUSES = ("active", "revoked")
_LEVELS = ("A0", "A1")
_MEMBER_FIELDS = frozenset(
    {
        "signer_did",
        "role",
        "status",
        "allowed_solver_classes",
        "automation_ceiling",
    }
)
_POLICY_FIELDS = frozenset(
    {
        "format",
        "version",
        "authority",
        "commit_authority",
        "executable",
        "audience_did",
        "scope_id",
        "reviewed_draft_digest",
        "membership_digest",
        "revocation_digest",
        "policy_revision",
        "previous_policy_digest",
        "issued_at_ms",
        "expires_at_ms",
        "allowed_acceptance_roles",
        "members",
    }
)


class IntentPolicyError(ValueError):
    """The Host policy snapshot is malformed, stale, or inconsistent."""


class IntentPolicyDenied(PermissionError):
    """The current Host policy does not authorize this direct signer."""


def _did(value: Any, label: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 128:
        raise IntentPolicyError(f"{label} must be a bounded Ed25519 did:key")
    try:
        public_key = decode_ed25519_did_key(value)
        if encode_ed25519_did_key(public_key) != value:
            raise IntentPolicyError(f"{label} is not canonical")
        if not is_prime_order_ed25519_point(public_key):
            raise IntentPolicyError(f"{label} is not a strict Ed25519 public key")
    except DIDKeyError:
        raise IntentPolicyError(f"{label} must be an Ed25519 did:key") from None
    return value


def _digest(value: Any, label: str, *, empty: bool = False) -> str:
    if not isinstance(value, str):
        raise IntentPolicyError(f"{label} must be a content hash")
    if empty and value == "":
        return value
    if _HASH.fullmatch(value) is None:
        raise IntentPolicyError(f"{label} must be a content hash")
    return value


def _safe_integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if (
        type(value) is not int
        or not minimum <= value <= INTENT_RESOLVER_MAX_SAFE_INTEGER
    ):
        raise IntentPolicyError(f"{label} must be a safe integer >= {minimum}")
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise IntentPolicyError(f"{label} must be a bounded exact identifier")
    return value


def _solver_classes(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not 1 <= len(value) <= 16:
        raise IntentPolicyError("allowed_solver_classes must contain 1..16 values")
    result = tuple(value)
    if any(not isinstance(item, str) or _ID.fullmatch(item) is None for item in result):
        raise IntentPolicyError("allowed_solver_classes contains an invalid identifier")
    if result != tuple(sorted(set(result))):
        raise IntentPolicyError("allowed_solver_classes must be sorted and unique")
    return result


@dataclass(frozen=True)
class IntentPolicyMember:
    """One direct DID membership decision captured in trusted Host state."""

    signer_did: str
    role: str
    status: str
    allowed_solver_classes: tuple[str, ...]
    automation_ceiling: str

    def __post_init__(self) -> None:
        _did(self.signer_did, "member signer_did")
        if self.role not in _ROLES:
            raise IntentPolicyError("member role is unsupported")
        if self.status not in _STATUSES:
            raise IntentPolicyError("member status is unsupported")
        if type(self.allowed_solver_classes) is not tuple:
            raise IntentPolicyError("member solver classes must be an immutable tuple")
        object.__setattr__(
            self,
            "allowed_solver_classes",
            _solver_classes(self.allowed_solver_classes),
        )
        if self.automation_ceiling not in _LEVELS:
            raise IntentPolicyError("member automation ceiling must be A0 or A1")

    @classmethod
    def from_dict(cls, value: Any) -> "IntentPolicyMember":
        if (
            type(value) is not dict
            or len(value) != len(_MEMBER_FIELDS)
            or any(field not in value for field in _MEMBER_FIELDS)
        ):
            raise IntentPolicyError("policy member has missing or unknown fields")
        classes = value["allowed_solver_classes"]
        if type(classes) is not list or not 1 <= len(classes) <= 16:
            raise IntentPolicyError("member allowed_solver_classes must be an array")
        return cls(
            signer_did=value["signer_did"],
            role=value["role"],
            status=value["status"],
            allowed_solver_classes=tuple(classes),
            automation_ceiling=value["automation_ceiling"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "signer_did": self.signer_did,
            "role": self.role,
            "status": self.status,
            "allowed_solver_classes": list(self.allowed_solver_classes),
            "automation_ceiling": self.automation_ceiling,
        }


@dataclass(frozen=True, init=False)
class IntentAcceptancePolicySnapshot:
    """Closed, immutable and content-addressed local authorization snapshot."""

    _canonical_bytes: bytes

    @classmethod
    def _create(cls, canonical: bytes) -> "IntentAcceptancePolicySnapshot":
        value = object.__new__(cls)
        object.__setattr__(value, "_canonical_bytes", bytes(canonical))
        return value

    @classmethod
    def from_dict(cls, value: Any) -> "IntentAcceptancePolicySnapshot":
        if (
            type(value) is not dict
            or len(value) != len(_POLICY_FIELDS)
            or any(field not in value for field in _POLICY_FIELDS)
        ):
            raise IntentPolicyError("intent policy has missing or unknown fields")
        members = value["members"]
        roles = value["allowed_acceptance_roles"]
        if type(members) is not list or type(roles) is not list:
            raise IntentPolicyError("policy members and roles must be arrays")
        if not 1 <= len(members) <= INTENT_POLICY_MAX_MEMBERS:
            raise IntentPolicyError("policy must contain 1..64 members")
        if not 1 <= len(roles) <= len(_ROLES):
            raise IntentPolicyError("policy must contain 1..3 acceptance roles")
        parsed_members = tuple(IntentPolicyMember.from_dict(item) for item in members)
        signer_ids = tuple(item.signer_did for item in parsed_members)
        if signer_ids != tuple(sorted(set(signer_ids))):
            raise IntentPolicyError("policy members must be sorted and unique by DID")
        role_values = tuple(roles)
        if (
            not role_values
            or role_values != tuple(sorted(set(role_values)))
            or any(role not in _ACCEPTANCE_ROLES for role in role_values)
        ):
            raise IntentPolicyError(
                "allowed_acceptance_roles must be a sorted unique supported role list"
            )
        if value["format"] != INTENT_POLICY_FORMAT or value["version"] != INTENT_POLICY_VERSION:
            raise IntentPolicyError("unsupported intent policy format or version")
        if (
            value["authority"] != "intent-draft-acceptance"
            or value["commit_authority"] is not False
            or value["executable"] is not False
        ):
            raise IntentPolicyError("intent policy authority boundary is invalid")
        _did(value["audience_did"], "policy audience_did")
        _identifier(value["scope_id"], "policy scope_id")
        for field in (
            "reviewed_draft_digest",
            "membership_digest",
            "revocation_digest",
        ):
            _digest(value[field], field)
        revision = _safe_integer(value["policy_revision"], "policy_revision", minimum=1)
        previous = value["previous_policy_digest"]
        if revision == 1:
            if previous != "":
                raise IntentPolicyError("genesis policy must have an empty predecessor")
        else:
            _digest(previous, "previous_policy_digest")
        issued = _safe_integer(value["issued_at_ms"], "issued_at_ms")
        expires = _safe_integer(value["expires_at_ms"], "expires_at_ms")
        if not issued < expires or expires - issued > INTENT_POLICY_MAX_TTL_MS:
            raise IntentPolicyError("policy validity interval is invalid or too long")
        normalized = {
            **value,
            "allowed_acceptance_roles": list(role_values),
            "members": [member.to_dict() for member in parsed_members],
        }
        try:
            canonical = canonical_json(normalized)
        except (TypeError, ValueError, UnicodeError) as exc:
            raise IntentPolicyError("intent policy is not canonicalizable") from exc
        if len(canonical) > INTENT_POLICY_MAX_DOCUMENT_BYTES:
            raise IntentPolicyError("intent policy exceeds the document byte limit")
        return cls._create(canonical)

    @classmethod
    def from_json(cls, value: str | bytes) -> "IntentAcceptancePolicySnapshot":
        """Parse one bounded canonical policy JSON document."""

        if not isinstance(value, (str, bytes)):
            raise IntentPolicyError("intent policy JSON must be text or bytes")
        encoded = value.encode() if isinstance(value, str) else value
        if len(encoded) > INTENT_POLICY_MAX_DOCUMENT_BYTES:
            raise IntentPolicyError("intent policy exceeds the document byte limit")
        try:
            document = json.loads(encoded)
        except (json.JSONDecodeError, UnicodeError):
            raise IntentPolicyError("intent policy JSON is invalid") from None
        policy = cls.from_dict(document)
        if policy.canonical_bytes != encoded:
            raise IntentPolicyError("intent policy JSON must use canonical encoding")
        return policy

    @classmethod
    def create(
        cls,
        *,
        audience_did: str,
        scope_id: str,
        reviewed_draft_digest: str,
        membership_digest: str,
        revocation_digest: str,
        policy_revision: int,
        previous_policy_digest: str,
        issued_at_ms: int,
        expires_at_ms: int,
        allowed_acceptance_roles: tuple[str, ...] | list[str],
        members: tuple[IntentPolicyMember, ...] | list[IntentPolicyMember],
    ) -> "IntentAcceptancePolicySnapshot":
        if not isinstance(allowed_acceptance_roles, (tuple, list)):
            raise IntentPolicyError("allowed_acceptance_roles must be a list or tuple")
        if not isinstance(members, (tuple, list)) or any(
            type(member) is not IntentPolicyMember for member in members
        ):
            raise IntentPolicyError("members must contain IntentPolicyMember values")
        return cls.from_dict(
            {
                "format": INTENT_POLICY_FORMAT,
                "version": INTENT_POLICY_VERSION,
                "authority": "intent-draft-acceptance",
                "commit_authority": False,
                "executable": False,
                "audience_did": audience_did,
                "scope_id": scope_id,
                "reviewed_draft_digest": reviewed_draft_digest,
                "membership_digest": membership_digest,
                "revocation_digest": revocation_digest,
                "policy_revision": policy_revision,
                "previous_policy_digest": previous_policy_digest,
                "issued_at_ms": issued_at_ms,
                "expires_at_ms": expires_at_ms,
                "allowed_acceptance_roles": list(allowed_acceptance_roles),
                "members": [member.to_dict() for member in members],
            }
        )

    @property
    def canonical_bytes(self) -> bytes:
        return self._canonical_bytes

    @property
    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(self._canonical_bytes).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self._canonical_bytes)

    def is_valid_at(self, now_ms: int) -> bool:
        """Return whether one trusted clock reading is inside this snapshot."""

        _safe_integer(now_ms, "now_ms")
        document = self.to_dict()
        return document["issued_at_ms"] <= now_ms < document["expires_at_ms"]

    @property
    def members(self) -> tuple[IntentPolicyMember, ...]:
        return tuple(IntentPolicyMember.from_dict(item) for item in self.to_dict()["members"])

    def resolve(
        self,
        *,
        signer_did: str,
        head: IntentAcceptanceHead,
        now_ms: int,
    ) -> IntentAcceptanceContext:
        """Resolve one direct signer without trusting any envelope field."""

        _did(signer_did, "requested signer_did")
        if type(head) is not IntentAcceptanceHead:
            raise IntentPolicyError("head must be an IntentAcceptanceHead")
        _safe_integer(now_ms, "now_ms")
        document = self.to_dict()
        if not document["issued_at_ms"] <= now_ms < document["expires_at_ms"]:
            raise IntentPolicyDenied("intent acceptance policy is not currently valid")
        members = tuple(IntentPolicyMember.from_dict(item) for item in document["members"])
        member = next((item for item in members if item.signer_did == signer_did), None)
        if member is None:
            raise IntentPolicyDenied("signer is not a member of the current intent policy")
        if member.status != "active":
            raise IntentPolicyDenied("signer is revoked by the current intent policy")
        if member.role not in document["allowed_acceptance_roles"]:
            raise IntentPolicyDenied("member role may not accept this reviewed intent")
        return IntentAcceptanceContext(
            signer_did=member.signer_did,
            audience_did=document["audience_did"],
            scope_id=document["scope_id"],
            draft_digest=document["reviewed_draft_digest"],
            revision=head.revision + 1,
            previous_digest=head.digest,
            allowed_solver_classes=member.allowed_solver_classes,
            automation_ceiling=member.automation_ceiling,
            authorization_digest=self.digest,
        )


def verify_intent_policy_successor(
    previous: IntentAcceptancePolicySnapshot,
    successor: IntentAcceptancePolicySnapshot,
) -> None:
    """Require one contiguous policy chain for an exact audience and scope."""

    if type(previous) is not IntentAcceptancePolicySnapshot or type(successor) is not IntentAcceptancePolicySnapshot:
        raise TypeError("policy revisions must be IntentAcceptancePolicySnapshot values")
    first = previous.to_dict()
    second = successor.to_dict()
    if second["audience_did"] != first["audience_did"] or second["scope_id"] != first["scope_id"]:
        raise IntentPolicyError("successor changes the policy audience or scope")
    if second["policy_revision"] != first["policy_revision"] + 1:
        raise IntentPolicyError("successor policy revision is not contiguous")
    if second["previous_policy_digest"] != previous.digest:
        raise IntentPolicyError("successor policy predecessor digest mismatch")
    if second["issued_at_ms"] < first["issued_at_ms"]:
        raise IntentPolicyError("successor policy predates its predecessor")
    first_revoked = {
        member["signer_did"]
        for member in first["members"]
        if member["status"] == "revoked"
    }
    second_revoked = {
        member["signer_did"]
        for member in second["members"]
        if member["status"] == "revoked"
    }
    if not first_revoked.issubset(second_revoked):
        raise IntentPolicyError("successor policy removes or reactivates a revoked DID")


__all__ = [
    "INTENT_POLICY_FORMAT",
    "INTENT_POLICY_MAX_DOCUMENT_BYTES",
    "INTENT_POLICY_MAX_MEMBERS",
    "INTENT_POLICY_MAX_TTL_MS",
    "INTENT_POLICY_VERSION",
    "IntentAcceptancePolicySnapshot",
    "IntentPolicyDenied",
    "IntentPolicyError",
    "IntentPolicyMember",
    "verify_intent_policy_successor",
]
