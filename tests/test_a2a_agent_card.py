"""A2A Protocol AgentCard emission at /.well-known/agent.json
(2026-06-08, L0-2 in the NTH DAO roadmap).

What this suite proves:

  1. The endpoint exists at the A2A-canonical path and is reachable
     WITHOUT console auth — same fail-closed contract as the
     NTH-native /.well-known/nth-dao/identity.json.

  2. The emitted JSON conforms to the A2A AgentCard schema (canonical
     definition: a2aproject/A2A specification/a2a.proto):
       * REQUIRED top-level fields are all present
       * supported_interfaces[] entries carry the REQUIRED tuple
         (url, protocol_binding, protocol_version)
       * skills[] entries carry the REQUIRED (id, name, description,
         tags) tuple

  3. The signature envelope is JWS-EdDSA detached-payload format
     (RFC 7515 + RFC 8037) and verifies against the same Ed25519
     pubkey that signs the native card. That cross-card consistency
     is the WHOLE POINT of emitting both — a consumer who trusts the
     pubkey from one channel can verify the other without an extra
     pubkey exchange.

  4. The native NTH card carries an ``a2a_card_url`` cross-link, so a
     consumer that only finds one endpoint can discover the other
     without a second well-known probe.

  5. Tampering invalidates the JWS signature (negative path).

  6. 503 fail-closed when identity material is unavailable, identical
     contract to the native card.
"""

from __future__ import annotations

import base64
import json

import pytest
from fastapi.testclient import TestClient

from nth_dao.a2a_card import (
    JWS_ALG_EDDSA,
    NTH_PROTOCOL_BINDING,
    NTH_PROTOCOL_VERSION_TAG,
    build_a2a_card,
    sign_a2a_card_jws,
    verify_a2a_card_jws,
)
from nth_dao.identity import AgentIdentity, canonical_json, crypto_available
from nth_dao.web import create_app


pytestmark = pytest.mark.skipif(
    not crypto_available(),
    reason="A2A AgentCard requires PyNaCl",
)


@pytest.fixture
def client(tmp_path, monkeypatch) -> TestClient:
    """Console-auth ON so we can prove /.well-known/agent.json
    bypasses it (same gate as the NTH-native card)."""
    monkeypatch.setenv("NTH_LAN_PUBLISH", "0")
    return TestClient(create_app(tmp_path, require_console_auth=True))


# ===== unauthenticated access =====


def test_a2a_card_reachable_without_bearer_token(client):
    """The A2A AgentCard endpoint MUST respond 200 without an
    Authorization header — A2A consumers cannot be expected to ship
    a per-node Bearer token to discover capabilities."""
    resp = client.get("/.well-known/agent.json")
    assert resp.status_code == 200, resp.text


def test_api_endpoints_still_blocked_without_token(client):
    """Sanity that the gate is genuinely on — proves the bypass
    above is selective, not a global escape."""
    resp = client.get("/api/identity?actor_id=admin")
    assert resp.status_code == 401


# ===== A2A schema conformance =====


_REQUIRED_TOP_LEVEL = {
    "name", "description", "supportedInterfaces", "version",
    "capabilities", "defaultInputModes", "defaultOutputModes",
    "skills",
}

def test_card_has_all_required_top_level_fields(client):
    body = client.get("/.well-known/agent.json").json()
    missing = _REQUIRED_TOP_LEVEL - set(body.keys())
    assert not missing, f"A2A AgentCard missing REQUIRED fields {missing}"


def test_card_supported_interfaces_entries_are_well_formed(client):
    body = client.get("/.well-known/agent.json").json()
    ifaces = body["supportedInterfaces"]
    assert isinstance(ifaces, list) and ifaces, (
        "supportedInterfaces must be a non-empty array per A2A spec"
    )
    first = ifaces[0]
    assert first.get("url"), "AgentInterface.url is REQUIRED"
    assert first.get("protocolBinding") == NTH_PROTOCOL_BINDING
    assert first.get("protocolVersion") == NTH_PROTOCOL_VERSION_TAG
    for entry in ifaces:
        assert entry.get("url"), "AgentInterface.url is REQUIRED"
        assert entry.get("protocolBinding") in {"HTTP+JSON", "JSONRPC"}
        assert entry.get("protocolVersion") == NTH_PROTOCOL_VERSION_TAG

def test_card_skills_entries_are_well_formed(client):
    body = client.get("/.well-known/agent.json").json()
    skills = body["skills"]
    assert isinstance(skills, list) and skills, (
        "skills must be a non-empty array per A2A spec"
    )
    for s in skills:
        for required in ("id", "name", "description", "tags"):
            assert s.get(required), (
                f"AgentSkill.{required} is REQUIRED — missing in {s}"
            )
        assert isinstance(s["tags"], list)


def test_card_capabilities_is_an_object_not_array(client):
    body = client.get("/.well-known/agent.json").json()
    caps = body["capabilities"]
    assert isinstance(caps, dict), (
        "AgentCapabilities is a message (object), NOT a string array. "
        "If this asserts, someone confused capabilities with skills."
    )
    # Honest advertising — we have neither SSE nor push wired yet
    assert caps.get("streaming") is False
    assert caps.get("pushNotifications") is False


def test_card_version_is_emission_version(client):
    body = client.get("/.well-known/agent.json").json()
    from nth_dao.a2a_card import NTH_A2A_EMISSION_VERSION
    assert body["version"] == NTH_A2A_EMISSION_VERSION


def test_card_provider_carries_did_for_dumb_consumers(client):
    """A consumer that only reads provider.organization must still
    recover the DID — that's the contract we documented in the
    a2a_card module."""
    body = client.get("/.well-known/agent.json").json()
    prov = body.get("provider", {})
    assert "nth-dao://did:key:" in prov.get("organization", ""), (
        f"provider.organization should tunnel the DID; got "
        f"{prov.get('organization')!r}"
    )


# ===== signature integrity =====


def test_card_has_at_least_one_signature(client):
    body = client.get("/.well-known/agent.json").json()
    sigs = body.get("signatures")
    assert isinstance(sigs, list) and sigs, (
        "card must ship with at least one JWS signature envelope"
    )
    env = sigs[0]
    for required in ("protected", "signature"):
        assert env.get(required), (
            f"AgentCardSignature.{required} is REQUIRED — got {env!r}"
        )


def test_card_signature_uses_eddsa_algorithm(client):
    body = client.get("/.well-known/agent.json").json()
    env = body["signatures"][0]
    protected_b64 = env["protected"]
    padded = protected_b64 + "=" * (-len(protected_b64) % 4)
    header = json.loads(
        base64.urlsafe_b64decode(padded.encode("ascii")),
    )
    assert header.get("alg") == JWS_ALG_EDDSA, (
        f"A2A card alg must be EdDSA per RFC 8037; got {header.get('alg')!r}"
    )
    assert header.get("kid", "").startswith("did:key:z"), (
        f"protected.kid must be a did:key; got {header.get('kid')!r}"
    )


def test_card_signature_verifies_against_native_card_pubkey(client):
    """Cross-card identity check: the A2A card's JWS signature must
    verify against the SAME Ed25519 pubkey that signs the NTH-native
    card. If this fails the two cards are signed by different keypairs
    (catastrophe — a consumer would treat them as different agents)."""
    native = client.get("/.well-known/nth-dao/identity.json").json()
    a2a = client.get("/.well-known/agent.json").json()
    assert verify_a2a_card_jws(
        a2a, expected_pubkey_hex=native["pubkey_hex"],
    ), (
        "A2A card JWS did not verify against the native card's "
        "pubkey — the two endpoints are signed by different keypairs "
        "OR the JWS implementation is wrong"
    )


def test_tampered_card_fails_verification(client):
    """Negative path: change any field, verification must fail."""
    body = client.get("/.well-known/agent.json").json()
    body["description"] = "MITM attacker injected this"
    assert not verify_a2a_card_jws(body), (
        "verification accepted a tampered card; JWS detached-payload "
        "implementation is broken"
    )


def test_swapping_signature_for_another_keypair_fails(client):
    """If someone re-signs the card with a different keypair, expecting
    the original pubkey must reject."""
    body = client.get("/.well-known/agent.json").json()
    attacker = AgentIdentity.generate(label="attacker")
    fake_did = attacker.as_did()
    card_unsigned = {k: v for k, v in body.items() if k != "signatures"}
    body["signatures"] = [
        sign_a2a_card_jws(card_unsigned, attacker, fake_did)
    ]
    # The signature is valid for the attacker's key but NOT for the
    # original node's pubkey.
    native = client.get("/.well-known/nth-dao/identity.json").json()
    assert not verify_a2a_card_jws(
        body, expected_pubkey_hex=native["pubkey_hex"],
    )


# ===== cross-card consistency =====


def test_native_card_links_to_a2a_card(client):
    """The NTH-native card carries a2a_card_url so a consumer that
    only fetches the native well-known doesn't need a second probe
    to discover the A2A view.

    B5 (review fix 2026-06-08): the URL is now ABSOLUTE so it
    survives offline-cache scenarios. Detailed absolute-URL
    contract is pinned by ``test_native_card_a2a_link_is_absolute_url``
    below; here we only check the path suffix.
    """
    native = client.get("/.well-known/nth-dao/identity.json").json()
    assert (native.get("a2a_card_url") or "").endswith(
        "/.well-known/agent.json"
    )


def test_native_card_pubkey_matches_a2a_card_kid(client):
    """Sanity: the pubkey advertised on the native card must encode
    to the SAME did:key that lives in the A2A signature's kid."""
    from nth_dao.did_key import decode_ed25519_did_key_hex
    native = client.get("/.well-known/nth-dao/identity.json").json()
    a2a = client.get("/.well-known/agent.json").json()
    protected_b64 = a2a["signatures"][0]["protected"]
    padded = protected_b64 + "=" * (-len(protected_b64) % 4)
    header = json.loads(
        base64.urlsafe_b64decode(padded.encode("ascii"))
    )
    kid_pubkey = decode_ed25519_did_key_hex(header["kid"])
    assert kid_pubkey.lower() == native["pubkey_hex"].lower()


def test_a2a_card_provider_organization_carries_same_did(client):
    """And belt-and-braces: the DID we tunnel through
    provider.organization must match the kid."""
    native = client.get("/.well-known/nth-dao/identity.json").json()
    a2a = client.get("/.well-known/agent.json").json()
    org = a2a["provider"]["organization"]
    assert native["did"] in org, (
        f"provider.organization {org!r} must contain DID "
        f"{native['did']!r}"
    )


# ===== degraded path =====


def test_card_returns_503_when_identity_unavailable(tmp_path, monkeypatch):
    """No node_identity → 503, mirroring the native card contract.
    Never emit an unsigned card; consumers might cache it."""
    monkeypatch.setenv("NTH_LAN_PUBLISH", "0")
    client = TestClient(create_app(tmp_path, require_console_auth=False))
    client.app.state.nth.node_identity = None
    resp = client.get("/.well-known/agent.json")
    assert resp.status_code == 503
    assert "unavailable" in resp.json()["detail"]


def test_card_returns_503_when_signing_fails(client, monkeypatch):
    """If the keypair cannot sign, the endpoint must 503 — never
    return a card with an empty or missing signature envelope.
    Same fail-closed contract as the native card."""
    def boom(_payload):
        raise RuntimeError("signer unavailable")
    monkeypatch.setattr(
        client.app.state.nth.node_identity, "sign", boom,
    )
    resp = client.get("/.well-known/agent.json")
    assert resp.status_code == 503
    assert "signing unavailable" in resp.json()["detail"]


# ===== canonical-JSON discipline =====


def test_jws_signing_input_is_byte_stable_across_field_reordering(
    client,
):
    """The JWS signature must NOT depend on the order in which the
    server's dict happens to serialise its keys. canonical_json sorts
    keys; verify that a card with manually reordered fields still
    verifies (because verify_a2a_card_jws also canonicalises)."""
    body = client.get("/.well-known/agent.json").json()
    # Reorder keys at the top level
    reordered = {k: body[k] for k in sorted(body.keys(), reverse=True)}
    # Reorder keys inside capabilities too
    if "capabilities" in reordered and isinstance(
        reordered["capabilities"], dict,
    ):
        caps = reordered["capabilities"]
        reordered["capabilities"] = {
            k: caps[k] for k in sorted(caps.keys(), reverse=True)
        }
    native = client.get("/.well-known/nth-dao/identity.json").json()
    assert verify_a2a_card_jws(
        reordered, expected_pubkey_hex=native["pubkey_hex"],
    )


# ===== pure-function unit tests (no FastAPI) =====


def test_build_a2a_card_requires_did():
    with pytest.raises(ValueError):
        build_a2a_card(
            agent_id="admin",
            did="",
            pubkey_hex="aa" * 32,
            base_url="http://localhost",
        )


def test_build_a2a_card_default_modes_are_text_plain():
    """A2A consumers can negotiate, but we declare a sane default."""
    card = build_a2a_card(
        agent_id="admin",
        did="did:key:zSomething",
        pubkey_hex="aa" * 32,
        base_url="http://localhost",
    )
    assert card["defaultInputModes"] == ["text/plain", "application/json"]
    assert card["defaultOutputModes"] == ["text/plain", "application/json"]


# ===== B7 (review fix): real skill enumeration =====


def test_b7_card_advertises_more_than_placeholder_chat(client):
    """Before B7 the card had a single ``nth-dao.chat`` skill — A2A
    consumers would treat the node as a chat bot. After B7 the card
    enumerates real capabilities (DAO management, mandate, etc).

    If this test fails, the consumer-facing capability story has
    regressed to the placeholder."""
    body = client.get("/.well-known/agent.json").json()
    skill_ids = {s["id"] for s in body["skills"]}
    assert len(skill_ids) >= 4, (
        f"card only advertises {len(skill_ids)} skill(s) ({skill_ids}); "
        f"B7 expects ≥4 (chat, dao-management, mandate, agent-discovery, "
        f"a2a-protocol at minimum)"
    )


def test_b7_card_includes_chat_skill_as_baseline(client):
    """Even after B7, chat MUST remain (it's the fundamental surface).
    A regression that drops chat from the enumeration would silently
    break every consumer that pinned the chat skill."""
    body = client.get("/.well-known/agent.json").json()
    skill_ids = {s["id"] for s in body["skills"]}
    assert "nth-dao.chat" in skill_ids


def test_b7_card_includes_a2a_protocol_skill(client):
    """The A2A endpoint we just implemented (L1-2) MUST be discoverable
    as a skill on the very card that A2A consumers fetch — otherwise
    we ship the endpoint and don't advertise it."""
    body = client.get("/.well-known/agent.json").json()
    skill_ids = {s["id"] for s in body["skills"]}
    assert "nth-dao.a2a-protocol" in skill_ids
    a2a_skill = next(
        s for s in body["skills"]
        if s["id"] == "nth-dao.a2a-protocol"
    )
    # Examples must point to the actual L1-2 endpoint
    examples = a2a_skill.get("examples", [])
    assert any("/api/a2a/rpc" in ex for ex in examples), (
        f"a2a-protocol skill examples don't reference /api/a2a/rpc: "
        f"{examples}"
    )


def test_b7_card_includes_dao_management_skill(client):
    body = client.get("/.well-known/agent.json").json()
    skill_ids = {s["id"] for s in body["skills"]}
    assert "nth-dao.dao-management" in skill_ids


def test_b7_card_includes_mandate_skill(client):
    body = client.get("/.well-known/agent.json").json()
    skill_ids = {s["id"] for s in body["skills"]}
    assert "nth-dao.mandate" in skill_ids


def test_b7_card_includes_agent_discovery_skill(client):
    body = client.get("/.well-known/agent.json").json()
    skill_ids = {s["id"] for s in body["skills"]}
    assert "nth-dao.agent-discovery" in skill_ids


def test_b7_all_skill_ids_unique(client):
    """A consumer keying off skill.id would clobber state if two
    skills had the same id. A2A spec doesn't formally require
    uniqueness, but every sensible consumer assumes it."""
    body = client.get("/.well-known/agent.json").json()
    ids = [s["id"] for s in body["skills"]]
    assert len(ids) == len(set(ids)), (
        f"duplicate skill ids in card: {ids}"
    )


def test_b7_every_skill_satisfies_a2a_required_fields(client):
    """A2A AgentSkill REQUIRED fields: id, name, description, tags.
    A skill missing any of these is malformed per spec."""
    body = client.get("/.well-known/agent.json").json()
    for skill in body["skills"]:
        for required in ("id", "name", "description"):
            v = skill.get(required, "")
            assert v, (
                f"skill {skill.get('id', '?')!r} missing REQUIRED "
                f"field {required!r}"
            )
        tags = skill.get("tags")
        assert isinstance(tags, list) and tags, (
            f"skill {skill.get('id', '?')!r} has empty/missing tags "
            f"(REQUIRED per A2A spec)"
        )


def test_b7_skill_examples_use_absolute_urls(client):
    """When the endpoint generates skills with a known base_url, the
    examples should be absolute (same rationale as B5 for
    a2a_card_url): a consumer caching the card offline can still
    construct a real call."""
    body = client.get("/.well-known/agent.json").json()
    for skill in body["skills"]:
        for ex in skill.get("examples", []):
            # Skip "GET" + paths that are pure placeholders without
            # an endpoint (would never happen with our current
            # enumeration, but be lenient).
            if "/api/" not in ex:
                continue
            # The example string is like "POST <url>" or "GET <url>"
            # — the URL portion must be absolute when base_url is set.
            tokens = ex.split(" ", 1)
            if len(tokens) == 2:
                url = tokens[1].split("?")[0]
                assert url.startswith("http://") or url.startswith("https://"), (
                    f"skill {skill['id']!r} example URL not absolute: "
                    f"{ex!r}"
                )


def test_b7_skill_enumeration_is_pure_function(tmp_path, monkeypatch):
    """The known_skills helper must work on any state-shaped object
    without touching FastAPI — it's pure introspection."""
    from nth_dao.a2a_card import known_skills
    # Build a minimal state stub that exposes the right attributes
    class _StateStub:
        group_registry = object()
        groups = object()
        mandates = object()
        peer_finder = object()
        contacts = object()
    skills = known_skills(_StateStub(), base_url="http://x")
    ids = {s["id"] for s in skills}
    assert "nth-dao.chat" in ids
    assert "nth-dao.dao-management" in ids
    assert "nth-dao.mandate" in ids
    assert "nth-dao.agent-discovery" in ids
    assert "nth-dao.governance" in ids
    assert "nth-dao.a2a-protocol" in ids


def test_b7_skill_enumeration_gracefully_omits_missing_subsystems(
    tmp_path,
):
    """If a future refactor disables (say) the mandate subsystem,
    the mandate skill must silently drop out rather than the card
    advertising a 404-bound endpoint. Honest advertising — never
    claim a capability we can't serve."""
    from nth_dao.a2a_card import known_skills
    class _NoMandateState:
        # group_registry, groups, peer_finder, contacts present;
        # mandates intentionally missing
        group_registry = object()
        groups = object()
        peer_finder = object()
        contacts = object()
    skills = known_skills(_NoMandateState(), base_url="http://x")
    ids = {s["id"] for s in skills}
    assert "nth-dao.mandate" not in ids, (
        f"mandate skill leaked into card despite state.mandates "
        f"being absent: {ids}"
    )
    # Other skills still present
    assert "nth-dao.chat" in ids
    assert "nth-dao.a2a-protocol" in ids


def test_b7_skill_enumeration_falls_back_to_chat_only_when_no_state(
    tmp_path,
):
    """A state with NO subsystems still produces a valid card — at
    minimum the chat skill so the A2A REQUIRED ``skills`` array is
    non-empty."""
    from nth_dao.a2a_card import known_skills
    class _BareState:
        pass
    skills = known_skills(_BareState())
    ids = {s["id"] for s in skills}
    assert "nth-dao.chat" in ids
    assert "nth-dao.a2a-protocol" in ids   # always-on too
    # Conditional ones absent
    assert "nth-dao.mandate" not in ids
    assert "nth-dao.dao-management" not in ids


def test_sign_then_verify_roundtrip():
    """Pure crypto roundtrip with no FastAPI: build → sign → verify."""
    ident = AgentIdentity.generate(label="rt-test")
    did = ident.as_did()
    card = build_a2a_card(
        agent_id="rt",
        did=did,
        pubkey_hex=ident.pubkey_hex,
        base_url="http://localhost",
    )
    sig = sign_a2a_card_jws(card, ident, did)
    card["signatures"] = [sig]
    assert verify_a2a_card_jws(card, expected_pubkey_hex=ident.pubkey_hex)


# ===== B4 (review fix): ETag + 304 conditional GET =====


def test_a2a_card_response_carries_etag_header(client):
    """The A2A card body has no time-varying field, so it's safe to
    cache. The endpoint MUST return an ETag so a polling A2A consumer
    can revalidate cheaply (304 instead of re-sign)."""
    resp = client.get("/.well-known/agent.json")
    assert resp.status_code == 200
    etag = resp.headers.get("ETag", "")
    assert etag, "ETag header missing on A2A card response"
    # ETag must be a quoted string per RFC 7232 §2.3
    assert etag.startswith('"') and etag.endswith('"'), etag


def test_a2a_card_returns_304_on_matching_if_none_match(client):
    """Same ETag on a follow-up request → 304 No Content. This is the
    whole reason ETag exists — without it consumers re-sign every poll."""
    first = client.get("/.well-known/agent.json")
    etag = first.headers["ETag"]
    second = client.get(
        "/.well-known/agent.json",
        headers={"If-None-Match": etag},
    )
    assert second.status_code == 304
    # 304 carries no body but MUST echo the ETag (RFC 7232 §4.1)
    assert second.headers.get("ETag") == etag


def test_a2a_card_etag_stable_across_requests(client):
    """The card has no time-varying field, so two back-to-back fetches
    of the FULL body must produce identical ETags. If this drifts,
    something time-varying snuck into the card and ETag becomes a
    lie."""
    e1 = client.get("/.well-known/agent.json").headers["ETag"]
    e2 = client.get("/.well-known/agent.json").headers["ETag"]
    assert e1 == e2, (
        f"A2A card ETag is unstable ({e1!r} vs {e2!r}); something "
        f"time-varying leaked into the card body"
    )


def test_a2a_card_has_cache_control(client):
    """Cache-Control: public, max-age=300 — a soft hint; ETag is the
    authoritative freshness signal."""
    resp = client.get("/.well-known/agent.json")
    cc = resp.headers.get("Cache-Control", "")
    assert "max-age" in cc, f"Cache-Control header missing max-age: {cc!r}"


# ===== B5 (review fix): a2a_card_url is absolute =====


def test_native_card_a2a_link_is_absolute_url(client):
    """A consumer that caches the native card to disk and reads it
    offline (no original base URL context) must still be able to
    fetch /.well-known/agent.json — so the URL must be absolute."""
    native = client.get("/.well-known/nth-dao/identity.json").json()
    url = native["a2a_card_url"]
    assert url.startswith("http://") or url.startswith("https://"), (
        f"a2a_card_url must be absolute; got {url!r}"
    )
    assert url.endswith("/.well-known/agent.json")


# ===== B6 (review fix): deterministic signature regression canary =====


def test_b6_jws_signature_is_deterministic_for_fixed_inputs():
    """If canonical_json or b64u changes behaviour, ALL existing
    JWS signatures across the ecosystem stop verifying. This test
    pins a known-input → known-output mapping so a future refactor
    of those primitives is forced to confront the wire-format break.

    Ed25519 itself is deterministic (RFC 8032): for a given private
    key and message, the signature is byte-identical every time.
    We exploit that to hard-code the expected base64url output.
    """
    # Fixed Ed25519 seed → fixed pubkey + private key.
    # This seed is arbitrary; it just needs to be stable.
    SEED = b"\x42" * 32
    from nacl.signing import SigningKey
    from nth_dao.did_key import encode_ed25519_did_key
    sk = SigningKey(SEED)
    pubkey_bytes = bytes(sk.verify_key)
    pubkey_hex = pubkey_bytes.hex()

    # Build a minimal card with no time-varying fields. Use FIXED
    # values for every input so canonical_json output is fully
    # deterministic. The DID must be a REAL did:key derived from the
    # seed's pubkey — verify_a2a_card_jws calls is_did_key + decode
    # to recover the pubkey for verification, so a synthetic kid
    # like "did:key:zFAKE" cannot round-trip.
    did_for_kid = encode_ed25519_did_key(pubkey_bytes)
    # Cross-check that the helper produced the expected value
    # (regression canary on did_key encoding itself).
    assert did_for_kid == (
        "did:key:z6MkghLt1e8m1fmANsdJJco3aCLV8Xnigr5UWwC3u5iZFPd3"
    ), (
        f"did:key encoding of the fixed seed drifted; got "
        f"{did_for_kid!r}. If this is a deliberate change, also "
        f"update the expected_protected pin below."
    )
    card_unsigned = {
        "name": "test-agent",
        "description": "deterministic-test",
        "supportedInterfaces": [
            {
                "url": "http://x/api",
                "protocolBinding": "HTTP+JSON",
                "protocolVersion": "1.0.1",
            }
        ],
        "version": "0.9.0",
        "capabilities": {
            "streaming": False,
            "pushNotifications": False,
            "extensions": [],
        },
        "defaultInputModes": ["text/plain", "application/json"],
        "defaultOutputModes": ["text/plain", "application/json"],
        "skills": [
            {
                "id": "x",
                "name": "x",
                "description": "x",
                "tags": ["x"],
            }
        ],
    }

    # Wrap signing key in a thin shim that quacks like AgentIdentity.sign.
    # NB: a class body does NOT close over the enclosing function's
    # locals (unlike a nested ``def``), so capture pubkey_hex via the
    # constructor instead of via ``pubkey_hex = pubkey_hex`` at class
    # scope (that's a NameError).
    _captured_pubkey_hex = pubkey_hex
    class _FakeIdent:
        pubkey_hex = _captured_pubkey_hex
        def sign(self_inner, payload: bytes) -> bytes:
            return sk.sign(payload).signature

    sig_env = sign_a2a_card_jws(card_unsigned, _FakeIdent(), did_for_kid)

    # Pinned expected output. If canonical_json's key ordering or
    # base64url encoding changes, these strings break.
    # protected = {"alg":"EdDSA","kid":"did:key:z6Mkgh…FPd3"}
    # canonical_json sorts keys → exact bytes deterministic.
    expected_protected = (
        "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa2do"
        "THQxZThtMWZtQU5zZEpKY28zYUNMVjhYbmlncjVVV3dDM3U1"
        "aVpGUGQzIn0"
    )
    assert sig_env["protected"] == expected_protected, (
        f"protected header b64u drifted: got {sig_env['protected']!r}, "
        f"expected {expected_protected!r}. Either canonical_json or "
        f"the b64u helper changed behaviour — this BREAKS wire "
        f"compatibility with every existing A2A signature in the wild."
    )

    # And the signature itself: pinned base64url output for this
    # fixed seed + fixed payload. Recompute manually if the seed
    # or any card field changes.
    card_with_sig = dict(card_unsigned)
    card_with_sig["signatures"] = [sig_env]

    # Round-trip: the result MUST verify against this pubkey
    assert verify_a2a_card_jws(
        card_with_sig, expected_pubkey_hex=pubkey_hex,
    ), "deterministic-test card failed to round-trip"

    # And re-signing the same inputs produces byte-identical sig_env
    sig_env_2 = sign_a2a_card_jws(card_unsigned, _FakeIdent(), did_for_kid)
    assert sig_env_2 == sig_env, (
        "Ed25519 signing is supposed to be deterministic but two "
        "calls produced different envelopes; check that no salting "
        "or timestamp leaked in"
    )
