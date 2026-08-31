"""Adversarial protocol checks for signed, non-executable draft acceptance."""

from copy import deepcopy
from dataclasses import replace
import json
import secrets
import traceback

import pytest

from nth_dao.canonical_json import canonical_json
from nth_dao.identity import AgentIdentity
from nth_dao.plugins.intent_envelope import (
    INTENT_ENVELOPE_BODY_SCHEMA,
    INTENT_ENVELOPE_SCHEMA,
    INTENT_ENVELOPE_MAX_TTL_MS,
    IntentAcceptanceContext,
    IntentEnvelopeError,
    build_intent_envelope_body,
    intent_envelope_digest,
    intent_envelope_signing_bytes,
    sign_intent_envelope,
    verify_intent_envelope,
)
from nth_dao.plugins.intent_resolver import intent_resolver_wire_vectors
from nth_dao.plugins.schema import validate_schema


@pytest.fixture
def identities():
    pytest.importorskip("nacl.signing")
    return AgentIdentity.generate(), AgentIdentity.generate()


def reviewed_draft():
    response = intent_resolver_wire_vectors()["positive_exchanges"][1]["response"]
    draft = json.loads(response["draft_json"])
    draft["clarifications"] = []
    draft["outcomes"] = ["Provide a review proposal without executing it."]
    return canonical_json(draft).decode("utf-8")


def body_for(identities, **overrides):
    signer, audience = identities
    values = {
        "draft_json": reviewed_draft(), "signer_did": signer.as_did(),
        "audience_did": audience.as_did(), "scope_id": "workspace:test-intent",
        "solver_classes": ["org.nth-dao.solver.review"], "automation_ceiling": "A1",
        "issued_at_ms": 1000, "expires_at_ms": 61000, "nonce": secrets.token_hex(16),
    }
    return build_intent_envelope_body(**(values | overrides))


def test_closed_schemas_and_signed_snapshot(identities):
    validate_schema(INTENT_ENVELOPE_BODY_SCHEMA)
    validate_schema(INTENT_ENVELOPE_SCHEMA)
    body = body_for(identities)
    before = deepcopy(body)
    signed = sign_intent_envelope(body, signer=identities[0])
    assert body == before and "signature" not in body
    assert signed["authority"] == "none"
    assert signed["commit_authority"] is False and signed["executable"] is False
    digest = intent_envelope_digest(signed)
    body["solver_classes"].append("malicious")
    assert intent_envelope_digest(signed) == digest
    assert identities[0].verify(
        intent_envelope_signing_bytes(before), bytes.fromhex(signed["signature"]),
    )


@pytest.mark.parametrize("changes", [
    {"authority": "execute"}, {"commit_authority": True}, {"executable": True},
    {"commit_authority": 0}, {"purpose": "payment"}, {"version": "2"},
    {"unknown": "field"}, {"automation_ceiling": "A2"},
    {"draft_digest": "sha256:" + "0" * 64}, {"issued_at_ms": True},
    {"expires_at_ms": 1000}, {"expires_at_ms": 999},
    {"expires_at_ms": 1001 + INTENT_ENVELOPE_MAX_TTL_MS},
    {"nonce": "../" * 10 + "aa"}, {"nonce": "A" * 32},
    {"scope_id": "*"}, {"scope_id": "workspace:test\n"},
    {"solver_classes": []}, {"solver_classes": ["*"]},
    {"solver_classes": ["x", "x"]}, {"solver_classes": ["z", "a"]},
    {"solver_classes": ["a"] * 17}, {"solver_classes": "a"},
    {"revision": 0}, {"revision": False}, {"revision": 2},
    {"previous_digest": "sha256:" + "a" * 64},
    {"signer_did": "did:web:example.test"}, {"audience_did": "*"},
    {"issued_at_ms": 2**53}, {"issued_at_ms": 1000.0},
])
def test_reject_invalid_bodies_even_before_signing(identities, changes):
    body = body_for(identities) | changes
    with pytest.raises(IntentEnvelopeError):
        sign_intent_envelope(body, signer=identities[0])


@pytest.mark.parametrize("field,value", [
    ("clarifications", [{"code": "unknown", "question": "Which outcome?"}]),
    ("outcomes", []), ("request_digest", "sha256:" + "0" * 64),
    ("source_text", "A rewritten source with a stale request digest"),
    ("executable", True), ("authority", "owner"),
])
def test_refuse_unreviewed_or_rebound_draft(identities, field, value):
    draft = json.loads(reviewed_draft())
    draft[field] = value
    with pytest.raises(IntentEnvelopeError):
        body_for(identities, draft_json=canonical_json(draft).decode())


@pytest.mark.parametrize("changes", [
    {"signature": "0" * 128}, {"signature": "A" * 128},
    {"signature": "00"}, {"scope_id": "workspace:another"},
    {"nonce": "1" * 32}, {"expires_at_ms": 62000},
    {"solver_classes": ["org.nth-dao.solver.another"]},
])
def test_reject_tampered_signed_documents(identities, changes):
    signed = sign_intent_envelope(body_for(identities), signer=identities[0])
    with pytest.raises(IntentEnvelopeError):
        intent_envelope_digest(signed | changes)


def test_domain_separation_and_signer_key_match(identities):
    body = body_for(identities)
    with pytest.raises(IntentEnvelopeError, match="signer does not match"):
        sign_intent_envelope(body, signer=identities[1])
    signed_without_domain = body | {"signature": identities[0].sign(canonical_json(body)).hex()}
    with pytest.raises(IntentEnvelopeError, match="signature is invalid"):
        intent_envelope_digest(signed_without_domain)
    impostor = deepcopy(identities[0])
    impostor._signing_key = identities[1]._signing_key
    with pytest.raises(IntentEnvelopeError, match="signature is invalid"):
        sign_intent_envelope(body, signer=impostor)


def test_linked_revision_and_exact_ttl(identities):
    first = sign_intent_envelope(body_for(identities), signer=identities[0])
    next_body = body_for(
        identities, revision=2, previous_digest=intent_envelope_digest(first),
        expires_at_ms=1000 + INTENT_ENVELOPE_MAX_TTL_MS,
    )
    second = sign_intent_envelope(next_body, signer=identities[0])
    assert intent_envelope_digest(first) != intent_envelope_digest(second)
    assert second["previous_digest"] == intent_envelope_digest(first)


@pytest.mark.parametrize("draft_json", ["{}", "[]", "invalid", "{}\n", "\ud800"])
def test_invalid_draft_json_has_precise_error(identities, draft_json):
    with pytest.raises(IntentEnvelopeError):
        body_for(identities, draft_json=draft_json)


def test_crypto_unavailable_fails_closed(identities, monkeypatch):
    signed = sign_intent_envelope(body_for(identities), signer=identities[0])
    monkeypatch.setattr("nth_dao.plugins.intent_envelope.crypto_available", lambda: False)
    with pytest.raises(ImportError, match=r"nth-dao\[crypto\]"):
        intent_envelope_digest(signed)


def context_for(body):
    # Test-only convenience; production expectations must come from Host state.
    return IntentAcceptanceContext(
        **{key: body[key] for key in (
            "signer_did", "audience_did", "scope_id", "draft_digest",
            "revision", "previous_digest", "automation_ceiling",
        )},
        allowed_solver_classes=tuple(body["solver_classes"]),
    )


def test_live_verifier_returns_detached_snapshot_and_is_not_a_nonce_store(identities):
    body = body_for(identities)
    signed = sign_intent_envelope(body, signer=identities[0])
    expected = context_for(body)
    first = verify_intent_envelope(signed, expected=expected, now_ms=1000)
    second = verify_intent_envelope(signed, expected=expected, now_ms=1000)
    assert first == second == signed
    first["solver_classes"].append("malicious")
    assert second["solver_classes"] == body["solver_classes"]
    assert signed["solver_classes"] == body["solver_classes"]


@pytest.mark.parametrize("field,value", [
    ("scope_id", "workspace:other"), ("draft_digest", "sha256:" + "b" * 64),
    ("revision", 2), ("previous_digest", "sha256:" + "b" * 64),
    ("automation_ceiling", "A0"),
    ("allowed_solver_classes", ("org.nth-dao.solver.other",)),
    ("signer_did", "other-did"), ("audience_did", "other-did"),
])
def test_authentic_signature_cannot_cross_host_context(identities, field, value):
    body = body_for(identities, revision=2, previous_digest="sha256:" + "a" * 64)
    signed = sign_intent_envelope(body, signer=identities[0])
    expected = context_for(body)
    if field.endswith("did"):
        value = AgentIdentity.generate().as_did()
    if field == "revision":
        value = 3
    changed = replace(expected, **{field: value})
    with pytest.raises(IntentEnvelopeError):
        verify_intent_envelope(signed, expected=changed, now_ms=1001)


@pytest.mark.parametrize("now", [999, 61000, -1, True, 2**53, 1000.0, "1000"])
def test_clock_and_expiry_fail_closed(identities, now):
    body = body_for(identities)
    signed = sign_intent_envelope(body, signer=identities[0])
    with pytest.raises(IntentEnvelopeError):
        verify_intent_envelope(signed, expected=context_for(body), now_ms=now)


@pytest.mark.parametrize("overrides", [
    {"allowed_solver_classes": ["a"]}, {"allowed_solver_classes": ("*",)},
    {"allowed_solver_classes": ()}, {"automation_ceiling": "A4"},
    {"draft_digest": "*"}, {"scope_id": "*"}, {"signer_did": "admin"},
    {"audience_did": ""}, {"revision": True}, {"previous_digest": "unknown"},
])
def test_invalid_host_context_cannot_be_constructed(identities, overrides):
    with pytest.raises(IntentEnvelopeError):
        replace(context_for(body_for(identities)), **overrides)


def test_host_ceiling_and_draft_ceiling_both_apply(identities):
    from nth_dao.plugins.intent_resolver import intent_resolver_request_digest

    draft = json.loads(reviewed_draft())
    draft["automation_ceiling"] = "A0"
    draft["request_digest"] = intent_resolver_request_digest({
        **{key: draft[key] for key in (
            "attachments", "automation_ceiling", "locale", "request_id",
            "source_kind", "source_text",
        )}, "operation": "resolve",
    })
    with pytest.raises(IntentEnvelopeError, match="raise the draft"):
        body_for(identities, draft_json=canonical_json(draft).decode())
    body = body_for(identities, draft_json=canonical_json(draft).decode(), automation_ceiling="A0")
    signed = sign_intent_envelope(body, signer=identities[0])
    expected = replace(context_for(body), automation_ceiling="A1")
    assert verify_intent_envelope(signed, expected=expected, now_ms=60999) == signed


def test_context_is_mandatory_not_a_self_declared_wire_object(identities):
    body = body_for(identities)
    signed = sign_intent_envelope(body, signer=identities[0])
    with pytest.raises(IntentEnvelopeError, match="trusted"):
        verify_intent_envelope(signed, expected=body, now_ms=1000)


def test_public_facade_exposes_protocol_not_an_invokable_signing_capability():
    import nth_dao.plugins as facade

    for symbol in (
        IntentAcceptanceContext, IntentEnvelopeError, build_intent_envelope_body,
        intent_envelope_digest, intent_envelope_signing_bytes,
        sign_intent_envelope, verify_intent_envelope,
    ):
        assert getattr(facade, symbol.__name__) is symbol
        assert symbol.__name__ in facade.__all__
    assert not hasattr(facade, "INTENT_ENVELOPE_CONTRACT")


@pytest.mark.parametrize("part", ["public-key", "R"])
def test_point_checks_precede_signature_backend(identities, monkeypatch, part):
    from nth_dao.did_key import encode_ed25519_did_key
    from tools.generate_intent_envelope_vectors import invalid_point_vectors

    signed = sign_intent_envelope(body_for(identities), signer=identities[0])
    # Preflight must enforce the profile even if a backend uses looser rules.
    monkeypatch.setattr(AgentIdentity, "verify", lambda *_args, **_kwargs: True)
    for point in invalid_point_vectors(bytes.fromhex(identities[0].pubkey_hex)).values():
        bad = deepcopy(signed)
        if part == "public-key":
            bad["signer_did"] = encode_ed25519_did_key(point)
        else:
            bad["signature"] = point.hex() + signed["signature"][64:]
        with pytest.raises(IntentEnvelopeError, match="strict Ed25519"):
            intent_envelope_digest(bad)


def test_mixed_order_rejected_with_legacy_point_validation(identities, monkeypatch):
    from nth_dao.plugins.intent_envelope import _is_prime_order_point
    from tools.generate_intent_envelope_vectors import invalid_point_vectors

    public = bytes.fromhex(identities[0].pubkey_hex)
    monkeypatch.setattr("nacl.bindings.crypto_core_ed25519_is_valid_point", lambda _: True)
    assert _is_prime_order_point(public)
    assert not _is_prime_order_point(invalid_point_vectors(public)["mixed-order"])


def test_unavailable_sodium_operations_are_configuration_error(identities, monkeypatch):
    from nacl.exceptions import UnavailableError

    signed = sign_intent_envelope(body_for(identities), signer=identities[0])

    def unavailable(_point):
        raise UnavailableError("minimal build")

    monkeypatch.setattr("nacl.bindings.crypto_core_ed25519_is_valid_point", unavailable)
    with pytest.raises(ImportError, match="full libsodium build"):
        intent_envelope_digest(signed)


@pytest.mark.parametrize("signed_input", [False, True])
@pytest.mark.parametrize("case", ["large-key", "replacement-key", "many-keys", "non-string-key"])
def test_reject_unknown_fields_before_schema_or_serialization(identities, monkeypatch, signed_input, case):
    from nth_dao.plugins import intent_envelope as module

    value = body_for(identities)
    operation = intent_envelope_signing_bytes
    if signed_input:
        value = sign_intent_envelope(value, signer=identities[0])
        operation = intent_envelope_digest
    if case == "replacement-key":
        value.pop("nonce")
    if case == "many-keys":
        value.update({f"untrusted-{n}": True for n in range(1000)})
    elif case == "non-string-key":
        value.pop("nonce")
        value[b"untrusted-key"] = True
    else:
        value["DO-NOT-LOG-" + "Z" * 1_048_576] = True

    def must_not_run(*_args, **_kwargs):
        raise AssertionError("unbounded input reached schema or serializer")

    monkeypatch.setattr(module, "validate_instance", must_not_run)
    monkeypatch.setattr(module, "canonical_json", must_not_run)
    with pytest.raises(IntentEnvelopeError) as rejected:
        operation(value)
    assert len(str(rejected.value).encode()) <= 256


@pytest.mark.parametrize("case", ["root-key", "draft-key", "draft-json", "surrogate", "deep-json"])
def test_diagnostics_do_not_reflect_untrusted_content(identities, case):
    marker = "DO-NOT-LOG-" + "Z" * 60000
    value = body_for(identities)
    if case == "root-key":
        value[marker] = True
    elif case == "draft-key":
        draft = json.loads(value["draft_json"])
        draft[marker] = True
        value["draft_json"] = canonical_json(draft).decode()
    elif case == "draft-json":
        value["draft_json"] = marker
    elif case == "surrogate":
        value["draft_json"] = "\ud800"
    else:
        value["draft_json"] = "[" * 1500 + "0" + "]" * 1500
    with pytest.raises(IntentEnvelopeError) as rejected:
        intent_envelope_signing_bytes(value)
    assert len(str(rejected.value).encode()) <= 256
    assert marker not in "".join(traceback.format_exception(rejected.value))


def test_builder_draft_errors_are_bounded_without_chained_payload(identities):
    marker = "DO-NOT-LOG-" + "Z" * 60000
    draft = json.loads(reviewed_draft())
    draft[marker] = True
    with pytest.raises(IntentEnvelopeError) as rejected:
        body_for(identities, draft_json=canonical_json(draft).decode())
    assert len(str(rejected.value).encode()) <= 256
    assert marker not in "".join(traceback.format_exception(rejected.value))


@pytest.mark.parametrize("field", ["signer_did", "audience_did"])
@pytest.mark.parametrize("operation", ["build", "signing-bytes", "sign", "verify", "digest", "context"])
@pytest.mark.parametrize("invalid_did", [
    "PRIVATE-INPUT-MARKER-NEVER-LOG", "did:key:fprivate-input", "did:key:z0",
])
def test_did_diagnostics_suppress_raw_exception_chains(identities, field, operation, invalid_did):
    body = body_for(identities)
    expected = context_for(body)
    signed = sign_intent_envelope(body, signer=identities[0])
    bad_body = body | {field: invalid_did}
    bad_signed = signed | {field: invalid_did}
    with pytest.raises(IntentEnvelopeError) as rejected:
        if operation == "build":
            body_for(identities, **{field: invalid_did})
        elif operation == "signing-bytes":
            intent_envelope_signing_bytes(bad_body)
        elif operation == "sign":
            sign_intent_envelope(bad_body, signer=identities[0])
        elif operation == "verify":
            verify_intent_envelope(bad_signed, expected=expected, now_ms=1000)
        elif operation == "digest":
            intent_envelope_digest(bad_signed)
        else:
            replace(expected, **{field: invalid_did})
    assert rejected.value.__cause__ is None
    assert rejected.value.__suppress_context__ is True
    assert invalid_did not in "".join(traceback.format_exception(rejected.value))
    assert len(str(rejected.value).encode()) <= 128
    assert field in str(rejected.value)


def test_serialized_snapshot_is_revalidated(identities, monkeypatch):
    from nth_dao.plugins import intent_envelope as module

    value = body_for(identities)
    original = module.canonical_json

    def corrupted_snapshot(document):
        if document is value:
            document = document | {"commit_authority": True}
        return original(document)

    monkeypatch.setattr(module, "canonical_json", corrupted_snapshot)
    with pytest.raises(IntentEnvelopeError):
        intent_envelope_signing_bytes(value)
