"""MDNSDiscovery - mDNS/Bonjour backend for "people nearby".

The plain UDP `LANDiscovery` is great where every peer is on the same
broadcast domain and broadcast traffic is allowed. Modern networks
(corporate Wi-Fi, container overlays, isolated VLANs) often drop
broadcast but still pass multicast. mDNS is the standard tool for
this case, and it's also what other LAN tools (printers, AirDrop,
Spotify Connect) already use. Adding an mDNS backend means NTH DAO
peers find each other on any network where mDNS works.

This module is the optional `[lan]` extra. Install with
`pip install nth-dao[lan]` to pull in `zeroconf>=0.131`. Without it,
the module still imports, while start()/discover() raise a clear ImportError.

Service type: `_nth-dao._tcp.local.` (we register over the existing
gossip ws_url's host:port, not the UDP discovery port). The TXT record
carries the same fields a UDP hello would: agent_id, label, capabilities,
groups, ws_url, pubkey_hex, plus optional metadata.

API mirrors `LANDiscovery` so callers can swap backends with one import:

    >>> from nth_dao.discovery.lan_mdns import MDNSDiscovery
    >>> mdns = MDNSDiscovery(agent_id="alice", ws_url="ws://192.168.1.5:9876")
    >>> mdns.start()                # advertise self
    >>> peers = mdns.discover(3.0)  # find others
    >>> mdns.stop()
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from .lan import LANPeer  # Reuse the value type so callers can mix backends.

logger = logging.getLogger("nth_dao.discovery.lan_mdns")


SERVICE_TYPE = "_nth-dao._tcp.local."
DEFAULT_HTTP_PORT = 9876
TXT_MAX_VALUE_BYTES = 200  # mDNS TXT records have a hard cap per entry
CRITICAL_TXT_FIELDS = {"agent_id", "ws_url", "pubkey_hex"}


def _zeroconf_available() -> bool:
    try:
        import zeroconf  # noqa: F401
        return True
    except ImportError:
        return False


def _require_zeroconf() -> None:
    if not _zeroconf_available():
        raise ImportError(
            "MDNSDiscovery requires zeroconf. Install with "
            "`pip install nth-dao[lan]` or `pip install zeroconf>=0.131`."
        )


def _local_ip() -> str:
    """Best-effort outbound IP used as the mDNS service address.

    Falls back to 127.0.0.1 if no network is reachable. Same trick the
    stdlib examples use; not perfect for multi-homed boxes but adequate
    for "tell my neighbors where to dial me back."
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def _ws_url_port(ws_url: str, fallback: int = DEFAULT_HTTP_PORT) -> int:
    if not ws_url:
        return fallback
    try:
        parsed = urlparse(ws_url)
        return parsed.port or fallback
    except (AttributeError, TypeError, ValueError):
        return fallback

def _pack_props(props: Dict[str, Any]) -> Dict[bytes, bytes]:
    """Encode TXT props as bytes, splitting list values with ``|``.

    Critical identity/routing fields are rejected if too large. Display and
    metadata fields are truncated on UTF-8 character boundaries. Empty values
    are emitted as b"" so the receiving side can see the key existed.
    """
    out: Dict[bytes, bytes] = {}
    for key, value in props.items():
        if isinstance(value, (list, tuple)):
            payload = "|".join(str(v) for v in value)
        elif isinstance(value, dict):
            # rare; flatten to k=v;k=v for one level
            payload = ";".join(f"{k}={v}" for k, v in value.items())
        else:
            payload = "" if value is None else str(value)
        out[str(key).encode("utf-8")] = _encode_txt_value(str(key), payload)
    return out


def _encode_txt_value(key: str, payload: str) -> bytes:
    encoded = payload.encode("utf-8")
    if len(encoded) <= TXT_MAX_VALUE_BYTES:
        return encoded
    if key in CRITICAL_TXT_FIELDS:
        raise ValueError(
            f"mDNS TXT field {key!r} is too large ({len(encoded)} > {TXT_MAX_VALUE_BYTES} bytes)"
        )
    logger.warning(
        "mDNS TXT field %r truncated (%d > %d bytes)",
        key, len(encoded), TXT_MAX_VALUE_BYTES,
    )
    while payload and len(payload.encode("utf-8")) > TXT_MAX_VALUE_BYTES:
        payload = payload[:-1]
    return payload.encode("utf-8")



def _unpack_props(props: Dict[bytes, Optional[bytes]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key, value in props.items():
        try:
            k = key.decode("utf-8") if isinstance(key, (bytes, bytearray)) else str(key)
        except UnicodeDecodeError:
            continue
        if value is None:
            out[k] = ""
            continue
        try:
            v = value.decode("utf-8") if isinstance(value, (bytes, bytearray)) else str(value)
        except UnicodeDecodeError:
            v = ""
        if k in ("capabilities", "groups") and v:
            out[k] = v.split("|")
        else:
            out[k] = v
    return out


@dataclass
class MDNSDiscovery:
    """mDNS-backed peer discovery / advertisement.

    Lifecycle:
        m = MDNSDiscovery(agent_id="alice", ws_url="ws://1.2.3.4:9876")
        m.start()                  # registers a `_nth-dao._tcp.local.` record
        peers = m.discover(2.0)    # browse for siblings; returns LANPeer list
        m.stop()                   # withdraw record and close socket

    A single instance can do both sides simultaneously: announce yourself
    AND browse for others. `discover()` returns whoever the local mDNS
    cache knows about, plus anyone who responds in `timeout` seconds.
    """

    agent_id: str
    label: str = ""
    capabilities: List[str] = field(default_factory=list)
    groups: List[str] = field(default_factory=list)
    ws_url: str = ""
    pubkey_hex: str = ""
    # LAN DID publish (2026-06-07): the node's persistent did:key,
    # propagated in the mDNS TXT record so any browser on the same
    # network learns the discovered peer's permanent identifier.
    did: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    service_type: str = SERVICE_TYPE
    instance_name: str = ""  # auto-derived from agent_id when empty

    _zc: Any = field(default=None, init=False, repr=False)
    _info: Any = field(default=None, init=False, repr=False)
    _started: bool = field(default=False, init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def _make_service_info(self):
        from zeroconf import ServiceInfo  # type: ignore
        ip = _local_ip()
        port = _ws_url_port(self.ws_url)
        name = (self.instance_name or f"nth-dao-{self.agent_id}")[:62]
        full_name = f"{name}.{self.service_type}"
        props = _pack_props({
            "agent_id":     self.agent_id,
            "label":        self.label,
            "capabilities": self.capabilities,
            "groups":       self.groups,
            "ws_url":       self.ws_url,
            "pubkey_hex":   self.pubkey_hex,
            # LAN DID publish: the node's permanent did:key. Listeners
            # extract this from the TXT record alongside agent_id and
            # pubkey, giving them a stable handle without needing a
            # second HTTP round-trip to /api/identity.
            "did":          self.did,
            **{f"meta_{k}": v for k, v in (self.metadata or {}).items()},
        })
        return ServiceInfo(
            type_=self.service_type,
            name=full_name,
            addresses=[socket.inet_aton(ip)],
            port=port,
            properties=props,
            server=f"{name}.local.",
        )

    def start(self) -> None:
        """Register ourselves on the network so others can browse for us."""
        _require_zeroconf()
        from zeroconf import Zeroconf  # type: ignore
        with self._lock:
            if self._started:
                return
            self._zc = Zeroconf()
            self._info = self._make_service_info()
            try:
                self._zc.register_service(self._info, allow_name_change=True)
            except Exception as e:
                self._zc.close()
                self._zc = None
                self._info = None
                raise RuntimeError(f"mDNS register_service failed: {e}") from e
            self._started = True

    def stop(self) -> None:
        with self._lock:
            if not self._started:
                if self._zc is not None:
                    try:
                        self._zc.close()
                    except Exception as e:
                        logger.debug("zeroconf.close() failed: %s", e)
                    self._zc = None
                return
            try:
                if self._info is not None:
                    self._zc.unregister_service(self._info)
            except Exception as e:
                logger.debug("mDNS unregister failed: %s", e)
            try:
                self._zc.close()
            except Exception as e:
                logger.debug("zeroconf.close() failed: %s", e)
            self._zc = None
            self._info = None
            self._started = False

    def discover(self, timeout: float = 3.0) -> List[LANPeer]:
        """Browse for peers and return a list of LANPeer instances.

        `timeout` bounds how long we wait for service-resolved callbacks;
        anything already in the local cache returns immediately.
        """
        _require_zeroconf()
        from zeroconf import ServiceBrowser, Zeroconf  # type: ignore

        results: Dict[str, LANPeer] = {}
        results_lock = threading.Lock()
        # We always use a fresh Zeroconf instance for browsing because the
        # same Zeroconf running register_service() suppresses local results
        # in some versions. Two instances on the same host don't conflict.
        zc = Zeroconf()

        class _Listener:
            def add_service(_, zc_inner, type_, name):
                try:
                    info = zc_inner.get_service_info(type_, name, timeout=int(timeout * 1000))
                except Exception as e:
                    logger.debug("mDNS get_service_info failed for %s: %s", name, e)
                    return
                if info is None:
                    return
                props = _unpack_props(info.properties or {})
                aid = props.get("agent_id", "")
                if not aid:
                    return
                addr = ""
                try:
                    if info.addresses:
                        addr = socket.inet_ntoa(info.addresses[0])
                except OSError:
                    addr = ""
                peer = LANPeer(
                    agent_id=aid,
                    label=props.get("label", ""),
                    capabilities=list(props.get("capabilities") or []),
                    groups=list(props.get("groups") or []),
                    ws_url=props.get("ws_url", ""),
                    pubkey_hex=props.get("pubkey_hex", ""),
                    did=props.get("did", "") or "",
                    source_addr=f"{addr}:{info.port}" if addr else f":{info.port}",
                    rtt_ms=0.0,  # mDNS doesn't give us a meaningful RTT here
                    discovered_at=time.time(),
                    metadata={k[5:]: v for k, v in props.items() if k.startswith("meta_")},
                )
                with results_lock:
                    if aid not in results:
                        results[aid] = peer

            # zeroconf >= 0.40 requires these even if no-ops
            def update_service(_, zc_inner, type_, name): pass
            def remove_service(_, zc_inner, type_, name): pass

        try:
            ServiceBrowser(zc, self.service_type, _Listener())
            time.sleep(max(0.05, timeout))
        finally:
            try:
                zc.close()
            except Exception as e:
                logger.debug("zeroconf.close() failed: %s", e)

        with results_lock:
            # R-25 (2026-06-08): filter "self" out by IDENTITY, not by
            # agent_id. The bootstrap path used to hard-code
            # agent_id="admin" for every node, which made every peer
            # look like "self" and discover() returned []. Now we use
            # the multi-source check ``_is_self_record`` so any of
            # (pubkey_hex, did, agent_id) that matches our own
            # excludes the peer - whichever identifier the responder
            # happened to broadcast.
            return [
                p for p in results.values()
                if not self._is_self_record(
                    agent_id=p.agent_id,
                    pubkey_hex=p.pubkey_hex,
                    did=p.did,
                )
            ]

    def _is_self_record(
        self, *, agent_id: str, pubkey_hex: str, did: str,
    ) -> bool:
        """True if this record describes the LOCAL node.

        Cryptographic identifiers (pubkey_hex, did) are authoritative
        when present on BOTH sides - if they're populated and they
        differ, the peer is definitely a different identity even if
        the agent_id label happens to collide.

        Falls back to agent_id only when neither side advertised any
        crypto material (legacy peers, pre-DID builds).
        """
        # Pubkey is the strongest signal - if both sides have one,
        # it's the source of truth. Match OR mismatch is final.
        if pubkey_hex and self.pubkey_hex:
            return pubkey_hex.lower() == self.pubkey_hex.lower()
        # DID is next - same finality.
        if did and self.did:
            return did == self.did
        # Neither side has crypto in common. Fall back to the agent_id
        # label.
        if agent_id and self.agent_id:
            return agent_id == self.agent_id
        return False

    # Context manager
    def __enter__(self) -> "MDNSDiscovery":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()


def is_available() -> bool:
    """True if the `[lan]` extra is installed (zeroconf importable)."""
    return _zeroconf_available()


__all__ = ["MDNSDiscovery", "SERVICE_TYPE", "is_available"]
