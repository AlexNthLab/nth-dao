"""LANDiscovery -- UDP-based "people nearby" agent discovery.

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
    - To support unit tests, the broadcast target list is configurable --
      tests pass ["127.0.0.1"] to avoid OS-level broadcast quirks.
    - Privacy: this module does NOT speak gossip/sign messages. It's a
      *plaintext local-LAN announce*. Anything you put in `capabilities` /
      `label` is visible to whoever is on the same broadcast domain.
      For private discovery, use a token in metadata and filter on receive.
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
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
MAX_DISCOVERED_PEERS = 256
MAX_DISCOVERED_PEERS_PER_SOURCE = 8

MSG_QUERY = "nth-dao-query"
MSG_HELLO = "nth-dao-hello"

_NONCE = re.compile(r"^[0-9a-f]{16}$")
_PUBKEY_HEX = re.compile(r"^[0-9a-fA-F]{64}$")
_PSK_TAG = re.compile(r"^[0-9a-f]{64}$")
_QUERY_FIELDS = frozenset({"type", "v", "from", "wants", "nonce", "psk_tag"})
_HELLO_FIELDS = frozenset({
    "type", "v", "agent_id", "label", "capabilities", "groups",
    "ws_url", "pubkey_hex", "did", "metadata", "nonce", "ts", "psk_tag",
})


def _bounded_text(value: Any, *, minimum: int = 0, maximum: int) -> bool:
    return isinstance(value, str) and minimum <= len(value) <= maximum


def _bounded_string_list(value: Any, *, maximum_items: int = 64) -> bool:
    return (
        isinstance(value, list)
        and len(value) <= maximum_items
        and all(_bounded_text(item, minimum=1, maximum=128) for item in value)
    )


def _valid_psk_tag(value: Any) -> bool:
    return value == "" or (
        isinstance(value, str) and _PSK_TAG.fullmatch(value) is not None
    )


def _validate_query_message(message: Any) -> bool:
    """Validate the exact bounded v1 query shape before using any field."""
    return (
        isinstance(message, dict)
        and set(message) == _QUERY_FIELDS
        and message.get("type") == MSG_QUERY
        and message.get("v") == WIRE_VERSION
        and _bounded_text(message.get("from"), minimum=1, maximum=160)
        and _bounded_string_list(message.get("wants"))
        and isinstance(message.get("nonce"), str)
        and _NONCE.fullmatch(message["nonce"]) is not None
        and _valid_psk_tag(message.get("psk_tag"))
    )


def _validate_hello_message(message: Any, *, expected_nonce: str) -> bool:
    """Validate one untrusted v1 hello without granting identity trust."""
    if (
        not isinstance(message, dict)
        or set(message) != _HELLO_FIELDS
        or message.get("type") != MSG_HELLO
        or message.get("v") != WIRE_VERSION
        or message.get("nonce") != expected_nonce
        or not _bounded_text(message.get("agent_id"), minimum=1, maximum=160)
        or not _bounded_text(message.get("label"), maximum=256)
        or not _bounded_string_list(message.get("capabilities"))
        or not _bounded_string_list(message.get("groups"))
        or not _bounded_text(message.get("ws_url"), maximum=2048)
        or not _bounded_text(message.get("pubkey_hex"), maximum=64)
        or not _bounded_text(message.get("did"), maximum=256)
        or not isinstance(message.get("metadata"), dict)
        or not _valid_psk_tag(message.get("psk_tag"))
    ):
        return False
    pubkey_hex = message["pubkey_hex"]
    if pubkey_hex and _PUBKEY_HEX.fullmatch(pubkey_hex) is None:
        return False
    did = message["did"]
    if did and not did.startswith("did:key:z"):
        return False
    timestamp = message.get("ts")
    if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)):
        return False
    if not math.isfinite(float(timestamp)):
        return False
    try:
        encoded_metadata = json.dumps(
            message["metadata"], ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        return False
    return len(encoded_metadata) <= 2048


def configured_discovery_port() -> int:
    """Return the shared UDP discovery port with strict env validation."""
    raw = os.environ.get("NTH_LAN_DISCOVERY_PORT", str(DEFAULT_DISCOVERY_PORT))
    try:
        port = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("NTH_LAN_DISCOVERY_PORT must be an integer") from exc
    if not 1024 <= port <= 65_535:
        raise ValueError("NTH_LAN_DISCOVERY_PORT must be in 1024..65535")
    return port


@dataclass
class LANPeer:
    """One LAN-discovered peer."""

    agent_id: str
    label: str = ""
    capabilities: List[str] = field(default_factory=list)
    groups: List[str] = field(default_factory=list)
    ws_url: str = ""
    pubkey_hex: str = ""
    # LAN DID publish (2026-06-07): the peer's permanent did:key. Each
    # NTH DAO node's ``_bootstrap`` auto-generates a workspace identity;
    # the corresponding did:key travels here as part of the mDNS TXT
    # record so the discoverer learns "this LAN peer is provably DID X"
    # without an extra round-trip. Empty when the peer is a legacy
    # NTH DAO build that does not publish DIDs or when the responder
    # could not load identity.json.
    did: str = ""
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
        did: str = "",
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
        # LAN DID publish (2026-06-07): the node's did:key. Travels in
        # the broadcast and hello messages so listeners can map a
        # discovered peer to its permanent identifier without an extra
        # round-trip.
        self.did = did
        self.metadata = dict(metadata or {})
        self.port = port
        self.broadcast_addrs = tuple(broadcast_addrs)
        self.bind_addr = bind_addr
        self.psk = psk  # empty = open / public discovery

        self._listener_sock: Optional[socket.socket] = None
        self._listener_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._lifecycle_lock = threading.Lock()
        # Optional filter: lambda (peer_dict) -> bool; reject silently if False
        self.peer_filter: Optional[Callable[[dict], bool]] = None

    # PSK helpers

    def _psk_tag(self, message: dict) -> str:
        """Return HMAC-SHA256(psk, nonce) as hex; empty PSK gives an empty tag."""
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

    # Responder

    def start(self) -> None:
        """Start background listener that responds to discovery queries."""
        with self._lifecycle_lock:
            if self._listener_thread is not None and self._listener_thread.is_alive():
                return
            if self._listener_sock is not None:
                try:
                    self._listener_sock.close()
                except OSError:
                    pass
            sock = self._make_listener_socket()
            self._listener_sock = sock
            self._stop.clear()
            thread = threading.Thread(
                target=self._listen_loop, daemon=True,
                name=f"LANDiscovery-{self.agent_id}",
            )
            self._listener_thread = thread
            thread.start()

    def is_running(self) -> bool:
        """Return whether the responder thread and socket are both live."""
        thread = self._listener_thread
        return bool(
            thread is not None
            and thread.is_alive()
            and self._listener_sock is not None
            and not self._stop.is_set()
        )

    def stop(self) -> None:
        with self._lifecycle_lock:
            self._stop.set()
            sock = self._listener_sock
            thread = self._listener_thread
            self._listener_sock = None
            self._listener_thread = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2)

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
                # Ignore Windows ICMP-unreachable bleed-through and retry.
                continue
            except OSError:
                # A socket closed by stop() is a real exit.
                if self._stop.is_set():
                    break
                continue
            try:
                msg = json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if not _validate_query_message(msg):
                continue
            # Pre-shared-key gate: reject queries without matching tag.
            nonce = msg.get("nonce", "")
            if not self._psk_ok(msg):
                logger.debug("dropping query from %s: psk mismatch", addr)
                continue
            # Apply the optional capability filter from the sender's `wants`.
            # if we satisfy all of them. Empty wants = match everyone.
            wants = msg["wants"]
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
            # LAN DID publish: travels alongside pubkey so listeners
            # can map the discovered peer to its permanent identifier.
            # Older NTH DAO builds without this field arrive as did="".
            "did": self.did,
            "metadata": self.metadata,
            "nonce": nonce,
            "ts": time.time(),
        })

    def _send_hello(self, sock: socket.socket, dest: Tuple[str, int], reply_nonce: str) -> None:
        try:
            payload = json.dumps(self._build_hello(reply_nonce)).encode("utf-8")
        except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
            logger.warning("hello payload is not serializable: %s", exc)
            return
        if len(payload) > MAX_MESSAGE_BYTES:
            logger.warning("hello payload too big (%d bytes); skipping", len(payload))
            return
        try:
            sock.sendto(payload, dest)
        except OSError as e:
            logger.debug("sendto %s failed: %s", dest, e)

    # Querier

    def discover(
        self,
        timeout: float = 3.0,
        wanted_capabilities: Optional[List[str]] = None,
        target_addrs: Optional[List[str]] = None,
    ) -> List[LANPeer]:
        """Broadcast a discovery query and collect hellos for `timeout` seconds.

        Args:
            timeout: seconds to wait for responses
            wanted_capabilities: only peers containing all listed capabilities reply
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

        peers: Dict[tuple[str, str, str, str, str], LANPeer] = {}
        source_counts: Dict[str, int] = {}
        capacity_warned = False
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
                    # recv. This is harmless; keep listening for legitimate replies.
                    continue
                except OSError:
                    # Keep going through other transient errors until the deadline.
                    continue
                try:
                    msg = json.loads(data.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                if not _validate_hello_message(msg, expected_nonce=nonce):
                    continue
                # psk gate (querier side): only accept hellos whose psk_tag
                # matches our nonce under our psk
                if not self._psk_ok(msg):
                    logger.debug("dropping hello from %s: psk mismatch", addr)
                    continue
                aid = msg.get("agent_id", "")
                if not aid:
                    continue
                # R-25 (2026-06-08): filter "self" by identity, not by
                # agent_id alone. Crypto identifiers (pubkey_hex, did)
                # are authoritative when present on BOTH sides - if
                # they differ, the peer is definitely a distinct
                # identity even if the agent_id label happens to
                # match. Falls back to agent_id only when neither
                # side carries crypto (legacy peers).
                msg_pk = (msg.get("pubkey_hex") or "").lower()
                msg_did = msg.get("did") or ""
                self_pk = (self.pubkey_hex or "").lower()
                if msg_pk and self_pk:
                    if msg_pk == self_pk:
                        continue   # self
                    # else: distinct identity even if aid matches
                elif msg_did and self.did:
                    if msg_did == self.did:
                        continue
                else:
                    # neither side has crypto - agent_id fallback
                    if aid == self.agent_id:
                        continue
                source_ip = str(addr[0])
                candidate_key = (
                    source_ip,
                    aid,
                    msg_did,
                    msg_pk,
                    str(msg.get("ws_url") or ""),
                )
                if candidate_key in peers:
                    continue
                if source_counts.get(source_ip, 0) >= MAX_DISCOVERED_PEERS_PER_SOURCE:
                    continue
                if len(peers) >= MAX_DISCOVERED_PEERS:
                    # Do not terminate the receive loop. A later response from a
                    # new source may replace one surplus candidate from a noisy
                    # source, preserving discovery under a bounded local flood.
                    donor = next((
                        key for key in reversed(peers)
                        if source_counts.get(key[0], 0) > 1
                    ), None)
                    if donor is None:
                        if not capacity_warned:
                            logger.warning(
                                "LAN discovery peer limit reached (%d)",
                                MAX_DISCOVERED_PEERS,
                            )
                            capacity_warned = True
                        continue
                    peers.pop(donor)
                    source_counts[donor[0]] -= 1
                if self.peer_filter:
                    try:
                        if not self.peer_filter(msg):
                            continue
                    except Exception:  # noqa: BLE001 - isolate caller callback
                        logger.exception("LAN peer_filter rejected with an exception")
                        continue
                peer = LANPeer(
                    agent_id=aid,
                    label=msg.get("label", ""),
                    capabilities=list(msg.get("capabilities", [])),
                    groups=list(msg.get("groups", [])),
                    ws_url=msg.get("ws_url", ""),
                    pubkey_hex=msg.get("pubkey_hex", ""),
                    # LAN DID publish: pick up the peer's did:key from
                    # the hello message; empty string when the peer is
                    # an older NTH DAO build that does not publish DIDs.
                    did=msg.get("did", "") or "",
                    source_addr=f"{addr[0]}:{addr[1]}",
                    rtt_ms=(time.time() - send_ts) * 1000,
                    discovered_at=time.time(),
                    metadata=msg.get("metadata", {}) if isinstance(msg.get("metadata"), dict) else {},
                )
                peers[candidate_key] = peer
                source_counts[source_ip] = source_counts.get(source_ip, 0) + 1
        finally:
            try:
                sender.close()
            except OSError:
                pass

        return list(peers.values())

    # Context manager

    def __enter__(self) -> "LANDiscovery":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()
