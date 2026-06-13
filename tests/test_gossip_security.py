import asyncio
import time

import pytest

from nth_dao.gossip import GossipNode
from nth_dao.identity import AgentIdentity, crypto_available


class _FakeChannel:
    def __init__(self):
        self.messages = []

    def _append(self, msg):
        self.messages.append(msg)


@pytest.mark.skipif(not crypto_available(), reason="PyNaCl not installed")
def test_gossip_trust_agent_rejects_pubkey_rotation():
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    evil = AgentIdentity.generate(label="evil")
    node = GossipNode(alice, _FakeChannel(), trusted_pubkeys={"bob": bob.pubkey_hex})

    with pytest.raises(ValueError, match="already pinned"):
        node.trust_agent("bob", evil.pubkey_hex)

    assert node.trusted_pubkey_for("bob") == bob.pubkey_hex


@pytest.mark.skipif(not crypto_available(), reason="PyNaCl not installed")
def test_gossip_invalid_message_does_not_poison_seen_cache():
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    channel = _FakeChannel()
    node = GossipNode(alice, channel, trusted_pubkeys={"bob": bob.pubkey_hex})
    msg = {
        "id": "msg-invalid-sig",
        "from_agent": "bob",
        "channel": "general",
        "body": "hello",
        "ts": time.time(),
        "sig": "00",
    }

    asyncio.run(node._handle_gossip({"message": msg}, relay_peer_id="relay"))

    assert "msg-invalid-sig" not in node._seen_set
    assert channel.messages == []


# 入站 peer 连接数上限(2026-06-14 审查补:网络面 auto/scale 上限)。
@pytest.mark.skipif(not crypto_available(), reason="PyNaCl not installed")
def test_gossip_peer_capacity_gate():
    alice = AgentIdentity.generate(label="alice")
    node = GossipNode(alice, _FakeChannel(), allow_tofu=True, max_peers=2)

    assert node._can_accept_peer("new-1") is True
    node.peers["p1"] = object()
    node.peers["p2"] = object()
    # 满 → 新 peer 拒。
    assert node._can_accept_peer("new-2") is False
    # 已在册 → 允许重连(替换旧连接)。
    assert node._can_accept_peer("p1") is True


@pytest.mark.skipif(not crypto_available(), reason="PyNaCl not installed")
def test_gossip_peer_cap_zero_means_unlimited():
    alice = AgentIdentity.generate(label="alice")
    node = GossipNode(alice, _FakeChannel(), allow_tofu=True, max_peers=0)
    node.peers.update({f"p{i}": object() for i in range(10)})
    assert node._can_accept_peer("any") is True
