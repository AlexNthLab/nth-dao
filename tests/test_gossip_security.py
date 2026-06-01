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
