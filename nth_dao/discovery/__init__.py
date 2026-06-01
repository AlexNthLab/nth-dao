"""nth_dao.discovery — find other agents in your team.

Three layers, increasing scope:

1. AgentRegistry / AgentRecord
   File-based registry of registered agents, with heartbeat-based liveness
   filtering. Survives across processes / terminals via the shared
   workspace directory (and can be git-synced across machines).

2. PeerFinder
   Query helpers on top of the registry: by capability / backend / status /
   group / fuzzy name. Includes ranking & best_match for "find me a teammate".

3. LANDiscovery / LANPeer (new — "people nearby")
   UDP-based zero-config discovery of nth-dao agents on the same local
   network. No git_sync, no shared filesystem required — pure broadcast.
"""

from .agent_registry import AgentRecord, AgentRegistry
from .peer_finder import MatchResult, PeerFinder
from .lan import LANDiscovery, LANPeer

__all__ = [
    "AgentRecord",
    "AgentRegistry",
    "MatchResult",
    "PeerFinder",
    "LANDiscovery",
    "LANPeer",
]
