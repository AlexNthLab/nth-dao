"""P6 regression tests: endorsement revocation, LAN PSK filtering, Invitation."""

import json
import socket
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest

import nth_dao as nth
from nth_dao.identity import AgentIdentity, crypto_available
from nth_dao.web_of_trust import (
    Endorsement,
    Revocation,
    TrustGraph,
    issue_endorsement,
    issue_revocation,
)
from nth_dao.invitation import Invitation, InvitationError, INVITE_URL_SCHEME
from nth_dao.discovery.lan import LANDiscovery
from nth_dao.membership import MembershipManager, TeamConfig


pytestmark = pytest.mark.skipif(
    not crypto_available(), reason="PyNaCl required for P6 tests"
)


# ─────────────────── Revocation ───────────────────


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def test_revocation_round_trip(tmp_path):
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    e = issue_endorsement(alice, bob.pubkey_hex, "bob")
    r = issue_revocation(alice, e, reason="rotated key")
    assert r.verify_sig()
    assert r.matches(e)
    # Round-trip via dict
    r2 = Revocation.from_dict(r.to_dict())
    assert r2.verify_sig()
    assert r2.matches(e)


def test_revocation_by_wrong_identity_rejected(tmp_path):
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    mallory = AgentIdentity.generate(label="mallory")
    e = issue_endorsement(alice, bob.pubkey_hex, "bob")
    # mallory can't revoke alice's endorsement
    with pytest.raises(ValueError, match="cannot revoke"):
        issue_revocation(mallory, e)


def test_revocation_drops_endorsement_from_load(tmp_path):
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    tg = TrustGraph(tmp_path)
    tg.add_root("alice", alice.pubkey_hex)
    e = issue_endorsement(alice, bob.pubkey_hex, "bob")
    tg.import_endorsement(e)
    assert tg.is_trusted("bob", bob.pubkey_hex)
    # Revoke
    r = tg.revoke(alice, e, reason="key rotated")
    assert r is not None
    # bob no longer trusted
    assert not tg.is_trusted("bob", bob.pubkey_hex)


def test_revocation_persists_across_instances(tmp_path):
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    tg1 = TrustGraph(tmp_path)
    tg1.add_root("alice", alice.pubkey_hex)
    e = issue_endorsement(alice, bob.pubkey_hex, "bob")
    tg1.import_endorsement(e)
    tg1.revoke(alice, e)
    # New instance reads same files
    tg2 = TrustGraph(tmp_path)
    assert not tg2.is_trusted("bob", bob.pubkey_hex)


def test_revocation_without_matching_endorsement_rejected(tmp_path):
    """Pre-emptive revocations (without a matching endorsement) are dropped
    to prevent DoS planting."""
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    tg = TrustGraph(tmp_path)
    tg.add_root("alice", alice.pubkey_hex)
    # Fabricate a revocation for an endorsement that was never imported
    fake_e = issue_endorsement(alice, bob.pubkey_hex, "bob")
    r = issue_revocation(alice, fake_e)
    # Don't import the endorsement — only try to plant the revocation
    accepted = tg.import_revocation(r)
    assert not accepted


def test_revocation_with_tampered_signature_rejected(tmp_path):
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    tg = TrustGraph(tmp_path)
    tg.add_root("alice", alice.pubkey_hex)
    e = issue_endorsement(alice, bob.pubkey_hex, "bob")
    tg.import_endorsement(e)
    r = issue_revocation(alice, e)
    # Tamper signature
    r.sig = "00" * 64
    accepted = tg.import_revocation(r)
    assert not accepted
    # Endorsement still active
    assert tg.is_trusted("bob", bob.pubkey_hex)


# ─────────────────── LAN PSK filtering ───────────────────


def test_lan_psk_blocks_query_without_token(tmp_path):
    port = _free_port()
    responder = LANDiscovery(
        agent_id="alice", capabilities=["x"],
        port=port, psk="secret-team-token",
    )
    responder.start()
    try:
        time.sleep(0.1)
        # Querier without psk → blocked
        querier_open = LANDiscovery(agent_id="me", port=port)
        peers = querier_open.discover(timeout=0.8, target_addrs=["127.0.0.1"])
    finally:
        responder.stop()
    assert peers == []


def test_lan_psk_matches_allows_discovery(tmp_path):
    port = _free_port()
    psk = "secret-team-token"
    responder = LANDiscovery(
        agent_id="alice", capabilities=["x"],
        port=port, psk=psk,
    )
    responder.start()
    try:
        time.sleep(0.1)
        querier = LANDiscovery(agent_id="me", port=port, psk=psk)
        peers = querier.discover(timeout=1.5, target_addrs=["127.0.0.1"])
    finally:
        responder.stop()
    assert len(peers) == 1
    assert peers[0].agent_id == "alice"


def test_lan_psk_wrong_token_does_not_match(tmp_path):
    port = _free_port()
    responder = LANDiscovery(
        agent_id="alice", capabilities=["x"],
        port=port, psk="real-token",
    )
    responder.start()
    try:
        time.sleep(0.1)
        querier = LANDiscovery(agent_id="me", port=port, psk="wrong-token")
        peers = querier.discover(timeout=0.8, target_addrs=["127.0.0.1"])
    finally:
        responder.stop()
    assert peers == []


def test_lan_no_psk_anywhere_is_open_mode(tmp_path):
    """Backward-compat: when nobody sets psk, discovery is open like before."""
    port = _free_port()
    responder = LANDiscovery(agent_id="alice", capabilities=["x"], port=port)
    responder.start()
    try:
        time.sleep(0.1)
        querier = LANDiscovery(agent_id="me", port=port)
        peers = querier.discover(timeout=1.0, target_addrs=["127.0.0.1"])
    finally:
        responder.stop()
    assert len(peers) == 1


# ─────────────────── Invitation ───────────────────


def _team_cfg(team_id="t1", team_name="Test Team", owner_pubkey="", token=""):
    return TeamConfig(
        team_id=team_id, team_name=team_name,
        join_token=token, owner_pubkey=owner_pubkey,
    )


def test_invitation_mint_round_trip(tmp_path):
    owner = AgentIdentity.generate(label="owner")
    cfg = _team_cfg(owner_pubkey=owner.pubkey_hex, token="join-secret")
    inv = Invitation.mint(cfg, owner, ws_url="ws://192.168.1.5:9876")
    assert inv.verify_signature()
    assert inv.join_token == "join-secret"
    # URL encode → decode
    url = inv.to_url()
    assert url.startswith(INVITE_URL_SCHEME)
    inv2 = Invitation.from_url(url)
    assert inv2.verify_signature()
    assert inv2.team_id == "t1"
    assert inv2.ws_url == "ws://192.168.1.5:9876"


def test_invitation_validate_passes_clean(tmp_path):
    owner = AgentIdentity.generate(label="owner")
    cfg = _team_cfg(owner_pubkey=owner.pubkey_hex)
    inv = Invitation.mint(cfg, owner)
    inv.validate()  # no raise


def test_invitation_tampered_signature_fails(tmp_path):
    owner = AgentIdentity.generate(label="owner")
    cfg = _team_cfg(owner_pubkey=owner.pubkey_hex)
    inv = Invitation.mint(cfg, owner)
    inv.join_token = "hijacked"  # tamper after signing
    with pytest.raises(InvitationError, match="signature"):
        inv.validate()


def test_invitation_expired_fails(tmp_path):
    owner = AgentIdentity.generate(label="owner")
    cfg = _team_cfg(owner_pubkey=owner.pubkey_hex)
    inv = Invitation.mint(cfg, owner)
    inv.expires_at = (datetime.now() - timedelta(days=1)).isoformat()
    # Re-sign with the backdated expiry, so verify_sig() passes but expiry fails
    inv.sig = owner.sign_json(inv.signable_dict())
    with pytest.raises(InvitationError, match="expired"):
        inv.validate()


def test_invitation_mint_by_non_owner_rejected(tmp_path):
    owner = AgentIdentity.generate(label="owner")
    mallory = AgentIdentity.generate(label="mallory")
    cfg = _team_cfg(owner_pubkey=owner.pubkey_hex)
    with pytest.raises(ValueError, match="legitimate owner"):
        Invitation.mint(cfg, mallory)


def test_invitation_url_rejects_wrong_scheme(tmp_path):
    with pytest.raises(InvitationError, match="not a nthdao invitation URL"):
        Invitation.from_url("https://evil.example.com/x")


def test_invitation_url_rejects_garbage_payload(tmp_path):
    with pytest.raises(InvitationError):
        Invitation.from_url(INVITE_URL_SCHEME + "!!!!")  # invalid base64


def test_invitation_to_qr_terminal_works_if_qrcode_installed():
    try:
        import qrcode  # noqa
    except ImportError:
        pytest.skip("qrcode not installed")
    owner = AgentIdentity.generate(label="owner")
    cfg = _team_cfg(owner_pubkey=owner.pubkey_hex)
    inv = Invitation.mint(cfg, owner)
    ascii_qr = inv.to_qr_terminal()
    assert isinstance(ascii_qr, str)
    assert len(ascii_qr) > 0  # non-empty rendering


def test_invitation_to_qr_png_raises_helpful_without_extra():
    try:
        import qrcode  # noqa
        pytest.skip("qrcode IS installed; helpful-error path not tested here")
    except ImportError:
        pass
    owner = AgentIdentity.generate(label="owner")
    cfg = _team_cfg(owner_pubkey=owner.pubkey_hex)
    inv = Invitation.mint(cfg, owner)
    with pytest.raises(ImportError, match=r"\[ux\]"):
        inv.to_qr_png()


# ─────────────────── facade ───────────────────


def test_facade_exports_p6_symbols():
    assert nth.Revocation is Revocation
    assert nth.issue_revocation is issue_revocation
    assert nth.Invitation is Invitation
    assert nth.InvitationError is InvitationError
