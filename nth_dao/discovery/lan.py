"""LANDiscovery — UDP-based "people nearby" agent discovery.

Solves the "I just opened the app, who else is on my LAN?" problem without
needing a centralized registry, mDNS, or pre-shared peer URLs.

Wire format (JSON over UDP):
    Query (multicast/broadcast/unicast):
        {"type": "nth-dao-query", "v": 1, "from": "<agent_id>",
         "wants": ["python", ...] | [], "nonce": "<hex>"}

    Hello (sent as response to query, and optionally periodically):
        {"type": "nth-dao-hello", "v": 1, "agent_id": "<id>",
         "label": "<display name>", "capabilities": [...], "groups": [...],
         "ws_url": "ws://host:9876",   # for follow-up GossipNode.connect()
         "pubkey_hex": "<hex>",         # so caller can trust_agent() it
         "nonce": "<reply-to nonce>", "ts": <epoch>}

Design notes:
    - Pure stdlib (socket only). No zeroconf / Bonjour required.
    - Listener is a background daemon thread; broadcasting is one-shot.
    - SO_BROADCAST is set on the sender for 255.255.255.255 to work.
    - SO_REUSEADDR/REUSEPORT are set on the listener so multiple agents
      on the same host can each bind the discovery port.
    - The discover() method returns whoever responded within `timeout`.
    - To support unit tests, the broadcast target list is configurable —
      tests pass ["127.0.0.1"] to avoid OS-level broadcast quirks.
    - Privacy: this module does NOT speak gossip/sign messages. It's a
      *plaintext local-LAN announce*. Anything you put in `capabilities` /
      `label` is visible to whoever is on the same broadcast domain.
      For private discovery, use a token in metadata and filter on receive.
"""

from __future__ import annotations

import json
import logging
import secrets
import socket
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("nth_dao.discovery.lan")


DEFAULT_DISCOVERY_PORT = 9877
DEFAULT_BROADCAST_ADDRS = ("255.255.255.255",)
MAX_MESSAGE_BYTES = 4096          # safe single-packet UDP size
WIRE_VERSION = 1
RECV_BUF = 8192

MSG_QUERY = "nth-dao-query"
MSG_HELLO = "nth-dao-hello"


@dataclass
class LANPeer:
    """One LAN-discovered peer."""

    agent_id: str
    label: str = ""
    capabilities: List[str] = field(default_factory=list)
    groups: List[str] = field(default_factory=list)
    ws_url: str = ""
    pubkey_hex: str = ""
    source_addr: str = ""   # "ip:port" the response came from
    rtt_ms: float = 0.0
    discovered_at: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    def __repr__(self) -> str:
        return (
            f"<LANPeer {self.agent_id[:12]} caps={self.capabilities[:3]} "
            f"@ {self.source_addr} rtt={self.rtt_ms:.0f}ms>"
        )


class LANDiscovery:
    """Zero-config UDP-based agent discovery on a local subnet.

    Usage (responder side):
        lan = LANDiscovery(
            agent_id="alice",
            label="Alice's laptop",
            capabilities=["python", "web"],
            ws_url="ws://192.168.1.5:9876",
            pubkey_hex=identity.pubkey_hex,
        )
        lan.start()   # background listener; responds to queries

    Usage (querier side):
        lan = LANDiscovery(agent_id="me", port=9877)
        peers = lan.discover(timeout=3.0)
        for p in peers:
            print(p)
            # Pass to gossip:
            # await gossip.connect(p.ws_url)
            # trust_graph.add_root(p.agent_id, p.pubkey_hex)  # if appropriate

        lan.stop()  # always stop when done if you started()
    """

    def __init__(
        self,
        agent_id: str,
        *,
        label: str = "",
        capabilities: Optional[List[str]] = None,
        groups: Optional[List[str]] = None,
        ws_url: str = "",
        pubkey_hex: str = "",
        metadata: Optional[Dict[str, Any]] = None,
        port: int = DEFAULT_DISCOVERY_PORT,
        broadcast_addrs: Tuple[str, ...] = DEFAULT_BROADCAST_ADDRS,
        bind_addr: str = "",  # "" = bind to all interfaces
        psk: str = "",
    ):
        """
        Args:
            ... (others as above) ...
            psk: optional pre-shared key. When set, both query and hello carry
                 an HMAC-SHA256(psk, nonce) tag; the listener only responds to
                 queries carrying a matching tag, and the querier only accepts
                 hellos carrying one. This makes LAN discovery private to peers
                 who share the same psk — anyone else on the same broadcast
                 domain sees only opaque traffic.
        """
        self.agent_id = agent_id
        self.label = label
        self.capabilities = list(capabilities or [])
        self.groups = list(groups or [])
        self.ws_url = ws_url
        self.pubkey_hex = pubkey_hex
        self.metadata = dict(metadata or {})
        self.port = port
        self.broadcast_addrs = tuple(broadcast_addrs)
        self.bind_addr = bind_addr
        self.psk = psk  # empty = open / public discovery

        self._listener_sock: Optional[socket.socket] = None
        self._listener_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        # Optional filter: lambda (peer_dict) -> bool; reject silently if False
        self.peer_filter: Optional[Callable[[dict], bool]] = None

    # ─── psk helpers ───────────────────────────────────────────────────

    def _psk_tag(self, message: dict) -> str:
        """HMAC-SHA256(psk, nonce).hex() — empty psk → empty tag."""
        if not self.psk:
            return ""
        import hashlib
        import hmac as _hmac
        return _hmac.new(
            self.psk.encode("utf-8"),
            json.dumps(
                {k: v for k, v in message.items() if k != "psk_tag"},
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _seal_message(self, message: dict) -> dict:
        sealed = dict(message)
        sealed["psk_tag"] = self._psk_tag(sealed)
        return sealed

    def _psk_ok(self, message: dict) -> bool:
        """Constant-time verify a peer's psk tag.

        - If we have no psk:  accept everything (open mode).
        - If we have a psk:   peer's tag must equal HMAC(psk, nonce).
        """
        if not self.psk:
            return True
        claimed_tag = str(message.get("psk_tag", ""))
        if not claimed_tag:
            return False
        import hmac as _hmac
        return _hmac.compare_digest(claimed_tag, self._psk_tag(message))

    # ─── responder ─────────────────────────────────────────────────────

    def start(self) -> None:
        """Start background listener that responds to discovery queries."""
        if self._listener_thread is not None:
            return
        sock = self._make_listener_socket()
        self._listener_sock = sock
        self._stop.clear()
        t = threading.Thread(
            target=self._listen_loop, daemon=True,
            name=f"LANDiscovery-{self.agent_id}",
        )
        self._listener_thread = t
        t.start()

    def stop(self) -> None:
        self._stop.set()
        if self._listener_sock is not None:
            try:
                self._listener_sock.close()
            except OSError:
                pass
            self._listener_sock = None
        if self._listener_thread is not None:
            self._listener_thread.join(timeout=2)
            self._listener_thread = None

    def _make_listener_socket(self) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if sys.platform != "win32" and hasattr(socket, "SO_REUSEPORT"):
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.bind((self.bind_addr, self.port))
        s.settimeout(0.5)  # so the loop can check _stop
        return s

    def _listen_loop(self) -> None:
        sock = self._listener_sock
        if sock is None:
            return
        while not self._stop.is_set():
            try:
                data, addr = sock.recvfrom(RECV_BUF)
            except socket.timeout:
                continue
            except ConnectionResetError:
                # Windows ICMP-unreachable bleed-through — ignore and retry
                continue
            except OSError:
                # Socket closed during stop() (real exit) — break out
                if self._stop.is_set():
                    break
                continue
            try:
                msg = json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if not isinstance(msg, dict):
                continue
            if msg.get("type") != MSG_QUERY or msg.get("v") != WIRE_VERSION:
                continue
            # Pre-shared-key gate: reject queries without matching tag.
            nonce = msg.get("nonce", "")
            if not self._psk_ok(msg):
                logger.debug("dropping query from %s: psk mismatch", addr)
                continue
            # Optional capability filter — sender said `wants`, only respond
            # if we satisfy all of them. Empty wants = match everyone.
            wants = msg.get("wants") or []
            if wants and not set(wants).issubset(set(self.capabilities)):
                continue
            # Don't echo our own queries back to ourselves
            if msg.get("from") == self.agent_id:
                continue
            self._send_hello(sock, addr, reply_nonce=nonce)

    def _build_hello(self, nonce: str) -> dict:
        return self._seal_message({
            "type": MSG_HELLO,
            "v": WIRE_VERSION,
            "agent_id": self.agent_id,
            "label": self.label,
            "capabilities": self.capabilities,
            "groups": self.groups,
            "ws_url": self.ws_url,
            "pubkey_hex": self.pubkey_hex,
            "metadata": self.metadata,
            "nonce": nonce,
            "ts": time.time(),
        })

    def _send_hello(self, sock: socket.socket, dest: Tuple[str, int], reply_nonce: str) -> None:
        payload = json.dumps(self._build_hello(reply_nonce)).encode("utf-8")
        if len(payload) > MAX_MESSAGE_BYTES:
            logger.warning("hello payload too big (%d bytes); skipping", len(payload))
            return
        try:
            sock.sendto(payload, dest)
        except OSError as e:
            logger.debug("sendto %s failed: %s", dest, e)

    # ─── querier ───────────────────────────────────────────────────────

    def discover(
        self,
        timeout: float = 3.0,
        wanted_capabilities: Optional[List[str]] = None,
        target_addrs: Optional[List[str]] = None,
    ) -> List[LANPeer]:
        """Broadcast a discovery query and collect hellos for `timeout` seconds.

        Args:
            timeout: seconds to wait for responses
            wanted_capabilities: only peers whose capabilities ⊇ this list reply
            target_addrs: where to send the query. Defaults to broadcast_addrs.
                          Tests can pass ["127.0.0.1"] to avoid OS broadcast quirks.

        Returns:
            List of LANPeer ordered by arrival time (first heard first), de-duped
            by agent_id (only the first response per agent kept).
        """
        nonce = secrets.token_hex(8)
        query = self._seal_message({
            "type": MSG_QUERY,
            "v": WIRE_VERSION,
            "from": self.agent_id,
            "wants": list(wanted_capabilities or []),
            "nonce": nonce,
        })
        payload = json.dumps(query).encode("utf-8")
        if len(payload) > MAX_MESSAGE_BYTES:
            raise ValueError("query payload exceeds MAX_MESSAGE_BYTES")

        # Open a transient sender/receiver socket on an ephemeral port.
        # This is separate from the listener; replies come back to *this*
        # socket because we put its port in the from address.
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sender.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sender.bind(("", 0))  # ephemeral
        sender.settimeout(0.3)

        send_ts = time.time()
        targets = target_addrs if target_addrs is not None else list(self.broadcast_addrs)
        for addr in targets:
            try:
                sender.sendto(payload, (addr, self.port))
            except OSError as e:
                logger.debug("query sendto %s:%d failed: %s", addr, self.port, e)

        peers: Dict[str, LANPeer] = {}
        deadline = send_ts + timeout
        try:
            while time.time() < deadline:
                try:
                    data, addr = sender.recvfrom(RECV_BUF)
                except socket.timeout:
                    continue
                except ConnectionResetError:
                    # Windows: a previous sendto landed on a closed port and
                    # the OS surfaced the ICMP "port unreachable" on the next
                    # recv. Harmless — keep listening for legitimate replies.
                    continue
                except OSError:
                    # Other transient network errors — keep going until deadline
                    continue
                try:
                    msg = json.loads(data.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                if not isinstance(msg, dict):
                    continue
                if msg.get("type") != MSG_HELLO or msg.get("v") != WIRE_VERSION:
                    continue
                if msg.get("nonce") != nonce:
                    continue  # stale response from a previous round
                # psk gate (querier side): only accept hellos whose psk_tag
                # matches our nonce under our psk
                if not self._psk_ok(msg):
                    logger.debug("dropping hello from %s: psk mismatch", addr)
                    continue
                aid = msg.get("agent_id", "")
                if not aid or aid == self.agent_id or aid in peers:
                    continue
                if self.peer_filter and not self.peer_filter(msg):
                    continue
                peer = LANPeer(
                    agent_id=aid,
                    label=msg.get("label", ""),
                    capabilities=list(msg.get("capabilities", [])),
                    groups=list(msg.get("groups", [])),
                    ws_url=msg.get("ws_url", ""),
                    pubkey_hex=msg.get("pubkey_hex", ""),
                    source_addr=f"{addr[0]}:{addr[1]}",
                    rtt_ms=(time.time() - send_ts) * 1000,
                    discovered_at=time.time(),
                    metadata=msg.get("metadata", {}) if isinstance(msg.get("metadata"), dict) else {},
                )
                peers[aid] = peer
        finally:
            try:
                sender.close()
            except OSError:
                pass

        return list(peers.values())

    # ─── context manager ───────────────────────────────────────────────

    def __enter__(self) -> "LANDiscovery":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()
