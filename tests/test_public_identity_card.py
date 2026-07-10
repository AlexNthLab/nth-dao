"""Public identity card endpoint (2026-06-08).

``/.well-known/nth-dao/identity.json`` is the unauthenticated public
face of an NTH DAO node. Other NTH DAO downloads scanning the LAN
fetch it to learn how to address us by DID. Strict requirements:

  * unauthenticated - works without console token
  * signed - consumer can verify the response actually came from
    the claimed DID's keypair, defeating a man-in-the-middle on the
    HTTP layer
  * stable schema - the ``kind`` field is the schema tag so future
    revisions don't silently break legacy consumers
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from nth_dao.identity import AgentIdentity, canonical_json, crypto_available
from nth_dao.web import create_app


pytestmark = pytest.mark.skipif(
    not crypto_available(),
    reason="public identity card requires PyNaCl",
)


@pytest.fixture
def client(tmp_path, monkeypatch) -> TestClient:
    monkeypatch.setenv("NTH_LAN_PUBLISH", "0")
    # IMPORTANT: enable console auth on this test - it's how we prove
    # the public endpoint is genuinely unauthenticated even when the
    # rest of the API is locked down.
    return TestClient(create_app(tmp_path, require_console_auth=True))


# ===== unauthenticated access =====


def test_card_is_reachable_without_bearer_token(client):
    """The card MUST respond 200 to a caller with no Authorization
    header, even when require_console_auth=True locks down /api/*."""
    resp = client.get("/.well-known/nth-dao/identity.json")
    assert resp.status_code == 200, resp.text


def test_api_endpoints_still_blocked_without_token(client):
    """Sanity that the console gate is in fact active. If this passes
    AND the card test above also passes, we've proved the gate is
    selective."""
    resp = client.get("/api/identity?actor_id=admin")
    assert resp.status_code == 401


# ===== schema =====


def test_card_has_required_top_level_keys(client):
    body = client.get("/.well-known/nth-dao/identity.json").json()
    expected = {
        "kind", "agent_id", "did", "pubkey_hex",
        "capabilities", "issued_at", "sig",
    }
    assert expected <= set(body.keys()), (
        f"card missing fields {expected - set(body.keys())}"
    )


def test_card_kind_is_versioned_schema_tag(client):
    body = client.get("/.well-known/nth-dao/identity.json").json()
    assert body["kind"] == "nth-dao-identity-card-v1"


def test_card_did_is_a_real_did_key(client):
    body = client.get("/.well-known/nth-dao/identity.json").json()
    assert body["did"].startswith("did:key:z")


def test_card_pubkey_hex_is_64_hex_chars(client):
    body = client.get("/.well-known/nth-dao/identity.json").json()
    pk = body["pubkey_hex"]
    assert len(pk) == 64
    assert all(c in "0123456789abcdefABCDEF" for c in pk)


def test_card_advertises_federation_directory(client):
    """A discovered node must tell peers where to pull signed feeds."""
    body = client.get("/.well-known/nth-dao/identity.json").json()
    fed = body.get("federation")
    assert isinstance(fed, dict)
    assert fed["protocol"] == "nth-dao-federation-v1"
    assert fed["enabled"] is True
    assert fed["peer_url"].startswith("http://testserver")
    assert fed["market"]["digest_url"].endswith("/api/v2/market/federation/digest")
    assert fed["market"]["pull_url"].endswith("/api/v2/market/federation/pull")
    assert fed["market"]["peers_url"].endswith("/api/v2/market/federation/peers")
    assert body["base_url"] == fed["peer_url"]


def test_lan_public_base_requires_explicit_remote_bind(monkeypatch):
    import nth_dao.web as web_mod

    monkeypatch.delenv("NTH_PUBLIC_BASE_URL", raising=False)
    monkeypatch.delenv("NTH_FEDERATION_BASE_URL", raising=False)
    monkeypatch.delenv("NTH_LAN_BASE_URL", raising=False)
    monkeypatch.setenv("NTH_HOST", "0.0.0.0")
    monkeypatch.delenv("NTH_ALLOW_REMOTE_BIND", raising=False)

    assert web_mod._configured_public_base_url() == ""

    monkeypatch.setenv("NTH_ALLOW_REMOTE_BIND", "1")
    monkeypatch.setenv("NTH_PUBLIC_BASE_URL", "https://dao.example/root/")
    assert web_mod._configured_public_base_url() == "https://dao.example/root"


# ===== signature integrity =====


def test_signature_verifies_against_the_claimed_pubkey(client):
    """The whole point of signing the card: a consumer who trusts
    the pubkey can prove this card was authored by the corresponding
    private key, defeating an HTTP-layer MITM."""
    body = client.get("/.well-known/nth-dao/identity.json").json()
    pubkey_hex = body["pubkey_hex"]
    sig = body["sig"]
    assert sig, "card was returned without a signature"

    # Re-construct the unsigned card the way the signer did, then
    # verify the signature.
    to_verify = {k: v for k, v in body.items() if k != "sig"}
    payload = canonical_json(to_verify)

    from nacl.signing import VerifyKey
    vk = VerifyKey(bytes.fromhex(pubkey_hex))
    # raises BadSignatureError on mismatch
    vk.verify(payload, bytes.fromhex(sig))


def test_tampered_card_fails_verification(client):
    """Negative test: change a field, re-verify, must fail."""
    body = client.get("/.well-known/nth-dao/identity.json").json()
    body["did"] = "did:key:zEvilAttacker"
    sig = body.pop("sig")
    payload = canonical_json(body)

    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey
    vk = VerifyKey(bytes.fromhex(body["pubkey_hex"]))
    with pytest.raises(BadSignatureError):
        vk.verify(payload, bytes.fromhex(sig))


# ===== degraded case =====


def test_card_returns_503_when_identity_unavailable(tmp_path, monkeypatch):
    """If the node booted without crypto, the public endpoint must
    say 503 - not return a fake card with empty fields."""
    monkeypatch.setenv("NTH_LAN_PUBLISH", "0")
    client = TestClient(create_app(tmp_path, require_console_auth=False))
    # Force node_identity to None to simulate "PyNaCl missing"
    client.app.state.nth.node_identity = None
    resp = client.get("/.well-known/nth-dao/identity.json")
    assert resp.status_code == 503
    assert "unavailable" in resp.json()["detail"]


def test_card_returns_503_when_signing_fails(client, monkeypatch):
    """A public identity card without a valid signature is worse than
    no card: consumers might cache or display an unverifiable identity.
    Fail closed instead of returning sig=""."""

    def boom(_payload):
        raise RuntimeError("signer unavailable")

    monkeypatch.setattr(client.app.state.nth.node_identity, "sign_json", boom)
    resp = client.get("/.well-known/nth-dao/identity.json")
    assert resp.status_code == 503
    assert "signing unavailable" in resp.json()["detail"]


# ===== card is stable across boots (uses persistent identity) =====


def test_card_did_matches_api_identity_did(client):
    """The public card and the private /api/identity endpoint MUST
    agree on the DID - they're two views of the same identity store.
    A drift here means one of them is reading the wrong source."""
    public_card = client.get("/.well-known/nth-dao/identity.json").json()
    # Read the private endpoint via the console token we know the
    # TestClient was configured with.
    token = client.app.state.nth_console_token
    private = client.get(
        "/api/identity",
        params={"actor_id": "admin"},
        headers={"Authorization": f"Bearer {token}"},
    ).json()
    assert public_card["did"] == private["did"]
    assert public_card["pubkey_hex"] == private["pubkey_hex"]
