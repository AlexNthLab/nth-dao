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
from .lan import LANDiscovery, LANPeer, configured_discovery_port
from .federation_registry import LearnedPeerRecord, LearnedPeerStore

# Optional mDNS backend (requires `pip install nth-dao[lan]`). We re-export
# the names with a thin try-block so `from nth_dao.discovery import MDNSDiscovery`
# works when zeroconf is installed without forcing it on the core install.
try:
    from .lan_mdns import MDNSDiscovery, is_available as mdns_available
    _MDNS_AVAILABLE = True
except ImportError:
    MDNSDiscovery = None  # type: ignore[assignment]
    def mdns_available() -> bool:  # type: ignore[misc]
        return False
    _MDNS_AVAILABLE = False

__all__ = [
    "AgentRecord",
    "AgentRegistry",
    "MatchResult",
    "PeerFinder",
    "LANDiscovery",
    "LANPeer",
    "configured_discovery_port",
    "LearnedPeerRecord",
    "LearnedPeerStore",
    "MDNSDiscovery",
    "mdns_available",
]
