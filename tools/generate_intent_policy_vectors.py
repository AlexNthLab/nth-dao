"""Generate deterministic cross-language Intent policy conformance vectors."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from nacl.bindings import crypto_core_ed25519_add

from nth_dao.did_key import encode_ed25519_did_key
from nth_dao.plugins.intent_acceptance import IntentAcceptanceHead
from nth_dao.plugins.intent_policy import (
    IntentAcceptancePolicySnapshot,
    IntentPolicyMember,
)
from tools.generate_intent_envelope_vectors import _test_identity


ROOT = Path(__file__).parents[1]
TARGET = ROOT / "nth_dao/plugins/vectors/intent-policy-wire-cases-v1.json"


def _hash(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def build_vectors() -> dict:
    signer = _test_identity("intent-envelope-signer-v1")
    audience = _test_identity("intent-envelope-audience-v1")
    active = IntentPolicyMember(
        signer_did=signer.as_did(),
        role="member",
        status="active",
        allowed_solver_classes=("org.nth-dao.solver.review",),
        automation_ceiling="A1",
    )
    genesis = IntentAcceptancePolicySnapshot.create(
        audience_did=audience.as_did(),
        scope_id="workspace:conformance-intent",
        reviewed_draft_digest=_hash("reviewed-draft-v1"),
        membership_digest=_hash("membership-v1"),
        revocation_digest=_hash("revocations-v1"),
        policy_revision=1,
        previous_policy_digest="",
        issued_at_ms=900,
        expires_at_ms=2_000,
        allowed_acceptance_roles=("admin", "member", "owner"),
        members=(active,),
    )
    context = genesis.resolve(
        signer_did=signer.as_did(),
        head=IntentAcceptanceHead(0, ""),
        now_ms=1_000,
    )
    revoked = IntentPolicyMember(
        signer_did=signer.as_did(),
        role="member",
        status="revoked",
        allowed_solver_classes=("org.nth-dao.solver.review",),
        automation_ceiling="A1",
    )
    successor = IntentAcceptancePolicySnapshot.create(
        audience_did=audience.as_did(),
        scope_id="workspace:conformance-intent",
        reviewed_draft_digest=_hash("reviewed-draft-v1"),
        membership_digest=_hash("membership-v2"),
        revocation_digest=_hash("revocations-v2"),
        policy_revision=2,
        previous_policy_digest=genesis.digest,
        issued_at_ms=1_000,
        expires_at_ms=3_000,
        allowed_acceptance_roles=("admin", "member", "owner"),
        members=(revoked,),
    )
    unknown = genesis.to_dict() | {"payment_grant": True}
    duplicate = genesis.to_dict()
    duplicate["members"] = duplicate["members"] * 2
    identity_point = genesis.to_dict()
    identity_point["members"][0]["signer_did"] = encode_ed25519_did_key(
        b"\x01" + bytes(31)
    )
    zero_point = genesis.to_dict()
    zero_point["members"][0]["signer_did"] = encode_ed25519_did_key(bytes(32))
    mixed_order_point = genesis.to_dict()
    field_prime = 2**255 - 19
    order_two_point = (field_prime - 1).to_bytes(32, "little")
    mixed_order_point["members"][0]["signer_did"] = encode_ed25519_did_key(
        crypto_core_ed25519_add(bytes.fromhex(signer.pubkey_hex), order_two_point)
    )
    bad_previous = successor.to_dict() | {"previous_policy_digest": _hash("wrong")}
    return {
        "format": "org.nth-dao.intent-policy-conformance.v1",
        "test_only": True,
        "positive_cases": [
            {
                "id": "genesis-active-member",
                "policy": genesis.to_dict(),
                "canonical_hex": genesis.canonical_bytes.hex(),
                "digest": genesis.digest,
                "resolution": {
                    "signer_did": signer.as_did(),
                    "head": {"revision": 0, "digest": ""},
                    "now_ms": 1_000,
                    "expected": {
                        **context.__dict__,
                        "allowed_solver_classes": list(context.allowed_solver_classes),
                    },
                },
            },
            {
                "id": "successor-revoked-member",
                "policy": successor.to_dict(),
                "canonical_hex": successor.canonical_bytes.hex(),
                "digest": successor.digest,
            },
        ],
        "negative_cases": [
            {"id": "unknown-field", "policy": unknown},
            {"id": "duplicate-member", "policy": duplicate},
            {"id": "identity-ed25519-point", "policy": identity_point},
            {"id": "zero-ed25519-point", "policy": zero_point},
            {"id": "mixed-order-ed25519-point", "policy": mixed_order_point},
        ],
        "successor_cases": [
            {
                "id": "contiguous-revocation",
                "previous": genesis.to_dict(),
                "successor": successor.to_dict(),
                "valid": True,
            },
            {
                "id": "wrong-predecessor",
                "previous": genesis.to_dict(),
                "successor": bad_previous,
                "valid": False,
            },
        ],
    }


def main() -> None:
    TARGET.write_text(
        json.dumps(build_vectors(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
