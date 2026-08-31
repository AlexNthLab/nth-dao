"""Generate public test-only IntentEnvelope vectors; never read an identity file.

Run with ``python -m tools.generate_intent_envelope_vectors``. Test keys are
derived from public labels and MUST NOT be used as real identities.
"""

from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
from pathlib import Path

from nth_dao.canonical_json import canonical_json
from nth_dao.did_key import encode_ed25519_did_key
from nth_dao.identity import AgentID, AgentIdentity
from nth_dao.plugins.intent_envelope import (
    INTENT_ENVELOPE_BODY_SCHEMA,
    INTENT_ENVELOPE_SCHEMA,
    INTENT_ENVELOPE_SIGNING_DOMAIN,
    IntentAcceptanceContext,
    build_intent_envelope_body,
    intent_envelope_digest,
    intent_envelope_signing_bytes,
    sign_intent_envelope,
)
from nth_dao.plugins.intent_resolver import intent_resolver_wire_vectors


VECTOR_ROOT = Path(__file__).resolve().parents[1] / "nth_dao" / "plugins" / "vectors"


def _test_identity(label):
    from nacl.signing import SigningKey

    key = SigningKey(hashlib.sha256(("PUBLIC-NTH-TEST-ONLY:" + label).encode()).digest())
    public = key.verify_key.encode()
    return AgentIdentity(
        agent_id=AgentID.from_pubkey(public.hex()), _signing_key=key.encode(),
        _verify_key=public,
    )


def invalid_point_vectors(public_key: bytes):
    from nacl.bindings import crypto_core_ed25519_add

    p = 2**255 - 19
    order_two = (p - 1).to_bytes(32, "little")
    return {
        "identity": bytes([1]) + bytes(31),
        "order-two": order_two,
        "order-four": bytes(32),
        "noncanonical-identity": (p + 1).to_bytes(32, "little"),
        "negative-zero": bytes([1]) + bytes(30) + bytes([128]),
        "off-curve": bytes([2]) + bytes(31),
        "mixed-order": crypto_core_ed25519_add(public_key, order_two),
    }


def raw_number_vectors(positives):
    """Preserve numeric lexemes that a JS Number would otherwise normalize."""
    first = positives[0]
    cases = []

    def render(section, field, token):
        parts = []
        for name in ("envelope", "expected", "now_ms"):
            value = first[name]
            if name == section and field:
                encoded = "{" + ",".join(
                    json.dumps(key) + ":" + (token if key == field else json.dumps(item, ensure_ascii=False))
                    for key, item in value.items()
                ) + "}"
            else:
                encoded = token if name == section else json.dumps(value, ensure_ascii=False)
            parts.append(json.dumps(name) + ":" + encoded)
        return "{" + ",".join(parts) + "}"

    for case in positives:
        cases.append({
            "id": "raw-" + case["id"], "accept": True,
            "case_json": json.dumps({key: case[key] for key in ("envelope", "expected", "now_ms")}, ensure_ascii=False, indent=2),
        })
    for section, field in (
        ("envelope", "issued_at_ms"), ("envelope", "expires_at_ms"),
        ("envelope", "revision"), ("expected", "revision"), ("now_ms", None),
    ):
        value = first[section][field] if field else first[section]
        for label, token in (
            ("decimal", f"{value}.0"), ("exponent", f"{value}e0"),
            ("upper-exponent", f"{value}E+0"),
            ("rounded-fraction", f"{value}.00000000000000001"),
        ):
            cases.append({
                "id": f"raw-{section}-{field or 'clock'}-{label}", "accept": False,
                "case_json": render(section, field, token),
            })
    for token in ("01000", "NaN", "Infinity", "1e999", "9007199254740992"):
        cases.append({
            "id": "raw-invalid-clock-" + token, "accept": False,
            "case_json": render("now_ms", None, token),
        })
    return cases


def vector_documents():
    signer = _test_identity("intent-envelope-signer-v1")
    audience = _test_identity("intent-envelope-audience-v1")
    draft = json.loads(intent_resolver_wire_vectors()["positive_exchanges"][1]["response"]["draft_json"])
    draft["outcomes"] = ["Provide a review proposal without executing it."]
    draft["clarifications"] = []
    body = build_intent_envelope_body(
        draft_json=canonical_json(draft).decode(), signer_did=signer.as_did(),
        audience_did=audience.as_did(), scope_id="workspace:conformance-intent",
        solver_classes=["org.nth-dao.solver.review"], automation_ceiling="A1",
        issued_at_ms=1000, expires_at_ms=61000,
        nonce=hashlib.sha256(b"PUBLIC-NTH-TEST-ONLY:nonce-v1").hexdigest()[:32],
    )
    signed = sign_intent_envelope(body, signer=signer)
    expected = asdict(IntentAcceptanceContext(
        signer_did=signer.as_did(), audience_did=audience.as_did(),
        scope_id=body["scope_id"], draft_digest=body["draft_digest"], revision=1,
        previous_digest="", allowed_solver_classes=tuple(body["solver_classes"]),
        automation_ceiling="A1",
    ))
    expected["allowed_solver_classes"] = list(expected["allowed_solver_classes"])
    positives = [{
        "id": "genesis", "envelope": signed, "expected": expected, "now_ms": 1000,
        "signing_bytes_hex": intent_envelope_signing_bytes(body).hex(),
        "document_digest": intent_envelope_digest(signed),
    }]
    revision = body | {
        "revision": 2, "previous_digest": intent_envelope_digest(signed),
        "nonce": hashlib.sha256(b"PUBLIC-NTH-TEST-ONLY:nonce-v2").hexdigest()[:32],
    }
    signed_revision = sign_intent_envelope(revision, signer=signer)
    positives.append({
        "id": "revision", "envelope": signed_revision,
        "expected": expected | {"revision": 2, "previous_digest": revision["previous_digest"]},
        "now_ms": 60999, "signing_bytes_hex": intent_envelope_signing_bytes(revision).hex(),
        "document_digest": intent_envelope_digest(signed_revision),
    })
    unicode_draft = draft | {"summary": "\U0001f9ea" * 1001}
    unicode_json = canonical_json(unicode_draft).decode()
    unicode_body = body | {
        "draft_json": unicode_json,
        "draft_digest": "sha256:" + hashlib.sha256(unicode_json.encode()).hexdigest(),
    }
    unicode_signed = sign_intent_envelope(unicode_body, signer=signer)
    positives.append({
        "id": "unicode-byte-vs-character-bound", "envelope": unicode_signed,
        "expected": expected | {"draft_digest": unicode_body["draft_digest"]},
        "now_ms": 1001, "signing_bytes_hex": intent_envelope_signing_bytes(unicode_body).hex(),
        "document_digest": intent_envelope_digest(unicode_signed),
    })
    negatives = []

    def negative(label, updates=None, *, expected_updates=None, now_ms=1000, resign=True):
        changed = body | (updates or {})
        signature = signer.sign(INTENT_ENVELOPE_SIGNING_DOMAIN + canonical_json(changed)).hex()
        negatives.append({
            "id": label, "body_updates": updates or {},
            "signature": signature if resign else signed["signature"],
            "expected_updates": expected_updates or {}, "now_ms": now_ms,
            "signature_valid": resign or not updates,
        })

    for label, updates in [
        ("commit-authority", {"commit_authority": True}),
        ("executable", {"executable": True}), ("numeric-false", {"executable": 0}),
        ("unknown-field", {"mandate": "not-a-grant"}), ("wrong-purpose", {"purpose": "payment"}),
        ("wrong-version", {"version": "2"}), ("wrong-authority", {"authority": "owner"}),
        ("boolean-time", {"issued_at_ms": True}), ("unsafe-time", {"expires_at_ms": 2**53}),
        ("expired-ttl", {"expires_at_ms": 1000}), ("excessive-ttl", {"expires_at_ms": 86401001}),
        ("uppercase-nonce", {"nonce": "A" * 32}), ("missing-nonce", {"nonce": ""}),
        ("wildcard-scope", {"scope_id": "*"}), ("wildcard-solver", {"solver_classes": ["*"]}),
        ("duplicate-solver", {"solver_classes": ["a", "a"]}),
        ("unordered-solver", {"solver_classes": ["z", "a"]}),
        ("empty-solver", {"solver_classes": []}), ("too-many-solvers", {"solver_classes": ["a"] * 17}),
        ("automation-escalation", {"automation_ceiling": "A2"}),
        ("missing-predecessor", {"revision": 2}),
        ("invalid-genesis", {"previous_digest": "sha256:" + "a" * 64}),
        ("invalid-did", {"audience_did": "did:web:example.test"}),
        ("draft-hash-mismatch", {"draft_digest": "sha256:" + "f" * 64}),
    ]:
        negative(label, updates)
    for label, field, value in [
        ("unresolved-draft", "clarifications", [{"code": "unknown", "question": "Which scope?"}]),
        ("empty-outcomes", "outcomes", []),
        ("source-rebinding", "source_text", "Altered source with its old digest"),
        ("request-rebinding", "request_digest", "sha256:" + "a" * 64),
    ]:
        changed = draft | {field: value}
        encoded = canonical_json(changed)
        negative(label, {"draft_json": encoded.decode(), "draft_digest": "sha256:" + hashlib.sha256(encoded).hexdigest()})
    negative("noncanonical-draft", {"draft_json": body["draft_json"] + "\n"})
    negative("signature-tamper", {"scope_id": "workspace:another"}, resign=False)
    for field, value in [
        ("signer_did", audience.as_did()), ("audience_did", signer.as_did()),
        ("scope_id", "workspace:another"), ("draft_digest", "sha256:" + "f" * 64),
        ("allowed_solver_classes", ["org.nth-dao.solver.other"]), ("automation_ceiling", "A0"),
    ]:
        negative("expected-" + field, expected_updates={field: value})
    negative("stale-revision-head", expected_updates={"revision": 2, "previous_digest": "sha256:" + "a" * 64})
    negative("future", now_ms=999)
    negative("expired", now_ms=61000)
    negative("boolean-clock", now_ms=True)
    negative("scope-trailing-newline", {"scope_id": "workspace:conformance-intent\n"}, expected_updates={"scope_id": "workspace:conformance-intent\n"})
    negative("solver-trailing-newline", {"solver_classes": ["solver\n"]}, expected_updates={"allowed_solver_classes": ["solver\n"]})
    for label, changes in [
        ("string-policy", {"allowed_solver_classes": "prefix:" + body["solver_classes"][0] + ":suffix"}),
        ("null-policy", {"allowed_solver_classes": None}),
        ("boolean-policy", {"allowed_solver_classes": True}),
        ("object-policy", {"allowed_solver_classes": {"class": body["solver_classes"][0]}}),
        ("empty-policy", {"allowed_solver_classes": []}),
        ("duplicate-policy", {"allowed_solver_classes": body["solver_classes"] * 2}),
        ("unordered-policy", {"allowed_solver_classes": ["zzz", *body["solver_classes"]]}),
        ("oversized-policy", {"allowed_solver_classes": body["solver_classes"] * 17}),
        ("wildcard-policy", {"allowed_solver_classes": ["*"]}),
        ("bad-policy-member", {"allowed_solver_classes": [None]}),
        ("unknown-field", {"grants": "all"}),
        ("invalid-signer", {"signer_did": "admin"}),
        ("invalid-audience", {"audience_did": "did:web:example.test"}),
        ("invalid-scope", {"scope_id": "*"}),
        ("invalid-draft-digest", {"draft_digest": "sha256:" + "g" * 64}),
        ("boolean-revision", {"revision": True}),
        ("invalid-lineage", {"previous_digest": "unknown"}),
        ("invalid-ceiling", {"automation_ceiling": "A4"}),
    ]:
        negative("context-" + label, expected_updates=changes)
    negative("context-missing-field")
    negatives[-1]["expected_omissions"] = ["revision"]
    identity_point = bytes([1]) + bytes(31)
    forged_did = encode_ed25519_did_key(identity_point)
    negatives.append({
        "id": "small-order-public-key-forgery",
        "body_updates": {"signer_did": forged_did},
        "signature": (identity_point + bytes(32)).hex(),
        "expected_updates": {"signer_did": forged_did},
        "now_ms": 1000, "signature_valid": False,
    })
    # A zero nonce yields a valid loose verification equation with R = identity.
    # This public-test-key-only vector detects removal of the separate R guard.
    from nacl.bindings import (
        crypto_core_ed25519_scalar_add,
        crypto_core_ed25519_scalar_mul,
        crypto_core_ed25519_scalar_reduce,
        crypto_scalarmult_ed25519_base_noclamp,
    )

    scalar = bytearray(hashlib.sha512(signer._signing_key).digest()[:32])
    scalar[0] &= 248
    scalar[31] = (scalar[31] & 63) | 64
    secret_scalar = crypto_core_ed25519_scalar_reduce(bytes(scalar) + bytes(32))
    challenge = crypto_core_ed25519_scalar_reduce(hashlib.sha512(
        identity_point + bytes.fromhex(signer.pubkey_hex)
        + INTENT_ENVELOPE_SIGNING_DOMAIN + canonical_json(body)
    ).digest())
    zero_nonce_signature = identity_point + crypto_core_ed25519_scalar_mul(challenge, secret_scalar)
    negatives.append({
        "id": "crypto-R-zero-nonce-equation", "body_updates": {},
        "signature": zero_nonce_signature.hex(), "expected_updates": {},
        "now_ms": 1000, "signature_valid": False,
    })
    mixed = invalid_point_vectors(bytes.fromhex(signer.pubkey_hex))["mixed-order"]
    mixed_did = encode_ed25519_did_key(mixed)
    one = bytes([1]) + bytes(31)
    r_point = crypto_scalarmult_ed25519_base_noclamp(one)
    # With odd h, the order-two component survives the uncofactored equation
    # but disappears under a loose cofactored verifier. All keys are test-only.
    for counter in range(128):
        changes = {"signer_did": mixed_did, "nonce": f"{counter:032x}"}
        h = crypto_core_ed25519_scalar_reduce(hashlib.sha512(
            r_point + mixed + INTENT_ENVELOPE_SIGNING_DOMAIN + canonical_json(body | changes)
        ).digest())
        if h[0] & 1:
            break
    else:
        raise AssertionError("deterministic mixed-order fixture did not converge")
    s = crypto_core_ed25519_scalar_add(one, crypto_core_ed25519_scalar_mul(h, secret_scalar))
    negatives.append({
        "id": "crypto-public-key-mixed-equation", "body_updates": changes,
        "signature": (r_point + s).hex(), "expected_updates": {"signer_did": mixed_did},
        "now_ms": 1000, "signature_valid": False,
    })
    for label, point in invalid_point_vectors(bytes.fromhex(signer.pubkey_hex)).items():
        bad_did = encode_ed25519_did_key(point)
        negatives.extend([
            {
                "id": "crypto-public-key-" + label,
                "body_updates": {"signer_did": bad_did},
                "signature": signed["signature"],
                "expected_updates": {"signer_did": bad_did},
                "now_ms": 1000, "signature_valid": False,
            },
            {
                "id": "crypto-R-" + label, "body_updates": {},
                "signature": point.hex() + signed["signature"][64:],
                "expected_updates": {}, "now_ms": 1000, "signature_valid": False,
            },
        ])
    order = 2**252 + 27742317777372353535851937790883648493
    for label, scalar in (
        ("at-order", order),
        ("malleated", order + int.from_bytes(bytes.fromhex(signed["signature"])[32:], "little")),
        ("max", 2**256 - 1),
    ):
        negatives.append({
            "id": "crypto-S-" + label, "body_updates": {},
            "signature": signed["signature"][:64] + scalar.to_bytes(32, "little").hex(),
            "expected_updates": {}, "now_ms": 1000, "signature_valid": False,
        })
    return {
        "intent-envelope-body-schema-v1.json": deepcopy(INTENT_ENVELOPE_BODY_SCHEMA),
        "intent-envelope-schema-v1.json": deepcopy(INTENT_ENVELOPE_SCHEMA),
        "intent-envelope-wire-cases-v1.json": {
            "format": "org.nth-dao.intent-envelope-conformance.v1",
            "signature_scheme": "Ed25519 over domain prefix followed by NTH canonical JSON body; A and R canonical nonzero prime-order points, S < L",
            "signing_domain_hex": INTENT_ENVELOPE_SIGNING_DOMAIN.hex(),
            "positive_cases": positives, "negative_cases": negatives,
            "raw_json_cases": raw_number_vectors(positives),
        },
    }


if __name__ == "__main__":
    for name, value in vector_documents().items():
        (VECTOR_ROOT / name).write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
