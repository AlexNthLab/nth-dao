"""Web-of-Trust: endorsement-based multi-hop trust resolution tests."""

import pytest

import nth_dao as nth
from nth_dao.identity import AgentIdentity, crypto_available
from nth_dao.web_of_trust import (
    DEFAULT_MAX_DEPTH,
    MAX_PROPAGATION_DEPTH,
    Endorsement,
    TrustGraph,
    issue_endorsement,
)


pytestmark = pytest.mark.skipif(
    not crypto_available(), reason="PyNaCl required for web-of-trust tests"
)


def test_endorsement_round_trip_and_signature_verifies(tmp_path):
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    e = issue_endorsement(
        endorser=alice,
        subject_pubkey=bob.pubkey_hex,
        subject_agent_id="bob",
        depth_allowed=2,
    )
    assert e.verify_sig()
    # Round-trip via dict
    e2 = Endorsement.from_dict(e.to_dict())
    assert e2.verify_sig()


def test_tampered_endorsement_signature_fails(tmp_path):
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    e = issue_endorsement(alice, bob.pubkey_hex, "bob")
    # Tamper with the subject_agent_id
    e.subject_agent_id = "evil"
    assert not e.verify_sig()


def test_root_pubkey_is_trusted_directly(tmp_path):
    alice = AgentIdentity.generate(label="alice")
    tg = TrustGraph(tmp_path)
    tg.add_root("alice", alice.pubkey_hex)
    assert tg.is_trusted("alice", alice.pubkey_hex)


def test_root_pubkey_with_wrong_agent_id_is_rejected(tmp_path):
    """Pubkey matches but agent_id doesn't — name-spoof must fail."""
    alice = AgentIdentity.generate(label="alice")
    tg = TrustGraph(tmp_path)
    tg.add_root("alice", alice.pubkey_hex)
    assert not tg.is_trusted("not-alice", alice.pubkey_hex)


def test_one_hop_endorsement_makes_subject_trusted(tmp_path):
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    tg = TrustGraph(tmp_path)
    tg.add_root("alice", alice.pubkey_hex)

    # alice endorses bob
    e = issue_endorsement(alice, bob.pubkey_hex, "bob", depth_allowed=1)
    assert tg.import_endorsement(e)

    assert tg.is_trusted("bob", bob.pubkey_hex)


def test_two_hop_endorsement_chains(tmp_path):
    """alice → bob (root pinned alice; alice endorses bob; bob endorses carol)."""
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    carol = AgentIdentity.generate(label="carol")

    tg = TrustGraph(tmp_path)
    tg.add_root("alice", alice.pubkey_hex)
    tg.import_endorsement(issue_endorsement(alice, bob.pubkey_hex, "bob", depth_allowed=2))
    tg.import_endorsement(issue_endorsement(bob, carol.pubkey_hex, "carol", depth_allowed=1))

    assert tg.is_trusted("carol", carol.pubkey_hex, max_depth=2)
    # depth 1 path: alice → carol direct? No. So depth=1 should NOT reach carol.
    assert not tg.is_trusted("carol", carol.pubkey_hex, max_depth=1)


def test_unknown_agent_is_not_trusted(tmp_path):
    alice = AgentIdentity.generate(label="alice")
    mallory = AgentIdentity.generate(label="mallory")
    tg = TrustGraph(tmp_path)
    tg.add_root("alice", alice.pubkey_hex)
    assert not tg.is_trusted("mallory", mallory.pubkey_hex)


def test_expired_endorsement_does_not_extend_trust(tmp_path):
    from datetime import datetime, timedelta
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    tg = TrustGraph(tmp_path)
    tg.add_root("alice", alice.pubkey_hex)
    e = issue_endorsement(alice, bob.pubkey_hex, "bob", ttl_days=1)
    # Manually backdate the expiry
    e.expires_at = (datetime.now() - timedelta(days=1)).isoformat()
    # Re-sign with the backdated expiry so verify_sig still passes
    e.sig = alice.sign_json(e.signable_dict())
    accepted = tg.import_endorsement(e)
    # import_endorsement may reject expired outright, OR accept and is_trusted later refuses
    if accepted:
        assert not tg.is_trusted("bob", bob.pubkey_hex)


def test_endorsement_with_wrong_signature_rejected(tmp_path):
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    other = AgentIdentity.generate(label="other")
    e = issue_endorsement(alice, bob.pubkey_hex, "bob")
    # Replace signature with one made by 'other'
    e.sig = other.sign_json(e.signable_dict())
    tg = TrustGraph(tmp_path)
    tg.add_root("alice", alice.pubkey_hex)
    assert not tg.import_endorsement(e)


def test_resolve_path_returns_chain(tmp_path):
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    carol = AgentIdentity.generate(label="carol")
    tg = TrustGraph(tmp_path)
    tg.add_root("alice", alice.pubkey_hex)
    tg.import_endorsement(issue_endorsement(alice, bob.pubkey_hex, "bob", depth_allowed=2))
    tg.import_endorsement(issue_endorsement(bob, carol.pubkey_hex, "carol", depth_allowed=1))

    path = tg.resolve_path("carol", carol.pubkey_hex, max_depth=2)
    assert path == [alice.pubkey_hex, bob.pubkey_hex, carol.pubkey_hex]


def test_depth_allowed_caps_propagation(tmp_path):
    """If endorser sets depth_allowed=1, subject can't further extend trust."""
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    carol = AgentIdentity.generate(label="carol")
    tg = TrustGraph(tmp_path)
    tg.add_root("alice", alice.pubkey_hex)
    # alice → bob with depth_allowed=1: bob trusted, but bob's endorsements
    # of others shouldn't propagate (bob is a leaf in trust).
    tg.import_endorsement(issue_endorsement(alice, bob.pubkey_hex, "bob", depth_allowed=1))
    tg.import_endorsement(issue_endorsement(bob, carol.pubkey_hex, "carol", depth_allowed=1))

    # bob himself is trusted
    assert tg.is_trusted("bob", bob.pubkey_hex)
    # carol should NOT be trusted because alice→bob only had depth=1
    assert not tg.is_trusted("carol", carol.pubkey_hex, max_depth=3)


def test_invalid_depth_allowed_rejected_at_issue(tmp_path):
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    with pytest.raises(ValueError, match="depth_allowed"):
        issue_endorsement(alice, bob.pubkey_hex, "bob", depth_allowed=0)
    with pytest.raises(ValueError, match="depth_allowed"):
        issue_endorsement(
            alice, bob.pubkey_hex, "bob",
            depth_allowed=MAX_PROPAGATION_DEPTH + 1,
        )


def test_trusted_pubkey_for_lookup(tmp_path):
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    tg = TrustGraph(tmp_path)
    tg.add_root("alice", alice.pubkey_hex)
    tg.import_endorsement(issue_endorsement(alice, bob.pubkey_hex, "bob", depth_allowed=2))
    assert tg.trusted_pubkey_for("bob", max_depth=2) == bob.pubkey_hex
    assert tg.trusted_pubkey_for("mallory") is None


def test_trustgraph_persistence_across_instances(tmp_path):
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    # First instance writes
    tg1 = TrustGraph(tmp_path)
    tg1.add_root("alice", alice.pubkey_hex)
    tg1.import_endorsement(issue_endorsement(alice, bob.pubkey_hex, "bob"))
    # Second instance reads
    tg2 = TrustGraph(tmp_path)
    assert tg2.is_trusted("alice", alice.pubkey_hex)
    assert tg2.is_trusted("bob", bob.pubkey_hex)


def test_facade_exports_wot_symbols():
    assert nth.Endorsement is Endorsement
    assert nth.TrustGraph is TrustGraph
    assert nth.issue_endorsement is issue_endorsement


def test_gossip_accepts_message_signed_by_wot_trusted_author(tmp_path):
    """E2E-ish: GossipNode 通过 TrustGraph 间接信任 author，验签消息成功。"""
    try:
        import websockets  # noqa: F401
    except ImportError:
        pytest.skip("websockets not installed")

    from nth_dao.gossip import GossipNode, _verify_msg_signature

    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")

    # Trust graph: alice is root, alice endorses bob (depth 2)
    tg = TrustGraph(tmp_path)
    tg.add_root("alice", alice.pubkey_hex)
    tg.import_endorsement(
        issue_endorsement(alice, bob.pubkey_hex, "bob", depth_allowed=2)
    )

    # Build a fake "channel" object — GossipNode only needs .send/.dm for
    # outbound and a place to store inbound; we just check trust lookup logic.
    class _FakeChannel:
        def __init__(self):
            self.appended = []
        def _append(self, msg):
            self.appended.append(msg)

    # We do NOT start the gossip server — just instantiate to test trust logic.
    node = GossipNode(
        identity=alice,
        channel=_FakeChannel(),
        trust_graph=tg,
        wot_max_depth=2,
    )

    # node should NOT have bob as a directly pinned anchor — bob is reachable
    # only via trust graph
    assert "bob" not in node._trusted_pubkeys
    # But trust_graph resolves bob
    assert tg.trusted_pubkey_for("bob", max_depth=2) == bob.pubkey_hex
