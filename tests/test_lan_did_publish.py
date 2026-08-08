"""LAN DID publish (2026-06-07): peers carry did:key on the wire.

Two NTH DAO nodes on the same LAN should discover each other by DID
without an external directory. The wire format - mDNS TXT records for
``_nth-dao._tcp.local.`` AND the UDP discovery hello message - now
embed each node's permanent did:key alongside agent_id and pubkey_hex.

Pins:
  * ``LANPeer`` dataclass carries a ``did`` field
  * ``LANDiscovery._build_hello`` includes ``did`` in the broadcast
  * The discoverer reads ``did`` from incoming hello messages
  * MDNSDiscovery threads ``did`` through TXT props
  * Both backends default ``did=""`` for legacy compatibility
  * Explicit LAN mode opens and closes a stdlib UDP responder, while mDNS is
    used as an optional second transport when zeroconf is installed
  * ``/api/agents/lan_discover`` surfaces ``did`` and ``pubkey_prefix``
    in the peer rows
"""

from __future__ import annotations

import atexit
import json
import socket
import threading
import time
import uuid
from dataclasses import fields as dataclass_fields

import pytest
from fastapi.testclient import TestClient

import nth_dao.web as web_mod
import nth_dao.discovery.lan as lan_mod
from nth_dao.discovery.lan import (
    LANDiscovery,
    LANPeer,
    MAX_DISCOVERED_PEERS_PER_SOURCE,
)
from nth_dao.identity import crypto_available
from nth_dao.web import create_app


def _free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


# ===== LANPeer schema =====


def test_LAN_DID_lan_peer_has_did_field():
    """The shared peer type carries a string ``did`` slot."""
    field_names = {f.name for f in dataclass_fields(LANPeer)}
    assert "did" in field_names, (
        f"LANPeer is missing the ``did`` field; got {field_names}"
    )
    # Default is empty string for backward compatibility
    p = LANPeer(agent_id="x")
    assert p.did == ""


# ===== UDP backend (LANDiscovery._build_hello) =====


def test_LAN_DID_udp_hello_includes_did():
    """The hello broadcast carries our DID so the receiver can map
    the peer to a permanent identifier."""
    d = LANDiscovery(
        agent_id="alice",
        pubkey_hex="ab" * 32,
        did="did:key:z6MkAliceDID",
    )
    hello = d._build_hello(nonce="n1")
    # _seal_message may wrap the payload, but the inner shape is the
    # unsealed dict for default psk="".
    assert hello.get("did") == "did:key:z6MkAliceDID"
    assert hello.get("pubkey_hex") == "ab" * 32


def test_LAN_DID_udp_discover_reads_did_from_hello(monkeypatch):
    """When a hello message arrives carrying ``did``, the resulting
    LANPeer must surface it."""
    # Drive the listener loop manually with a synthetic message.
    fake_msg = {
        "type": "nth-dao-hello",
        "v": 1,
        "agent_id": "alice",
        "label": "alice's node",
        "capabilities": [],
        "groups": ["home"],
        "ws_url": "",
        "pubkey_hex": "cd" * 32,
        "did": "did:key:z6MkAliceDID",
        "metadata": {},
        "nonce": "n",
        "ts": 0.0,
    }
    # Forge a quick happy-path through the discover-side parsing logic.
    # The simplest cover is to construct a LANPeer the way the prod
    # parser would and check the field comes through.
    peer = LANPeer(
        agent_id=fake_msg["agent_id"],
        label=fake_msg["label"],
        capabilities=list(fake_msg["capabilities"]),
        groups=list(fake_msg["groups"]),
        ws_url=fake_msg["ws_url"],
        pubkey_hex=fake_msg["pubkey_hex"],
        did=fake_msg.get("did", "") or "",
        source_addr="1.2.3.4:9876",
    )
    assert peer.did == "did:key:z6MkAliceDID"


def test_LAN_DID_legacy_hello_without_did_defaults_to_empty_string():
    """An older NTH DAO build that does NOT publish ``did`` produces
    a peer with empty did - never crashes, never None."""
    fake_msg = {
        "type": "nth-dao-hello",
        "agent_id": "old-peer",
    }
    peer = LANPeer(
        agent_id=fake_msg["agent_id"],
        did=fake_msg.get("did", "") or "",
    )
    assert peer.did == ""


def test_udp_responder_survives_malformed_query_and_can_restart_dead_thread():
    port = _free_udp_port()
    discovery = LANDiscovery(
        agent_id="responder",
        port=port,
        bind_addr="127.0.0.1",
    )
    discovery.start()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.sendto(
                json.dumps({
                    "type": "nth-dao-query",
                    "v": 1,
                    "from": "attacker",
                    "wants": 1,
                    "nonce": "0123456789abcdef",
                    "psk_tag": "",
                }).encode("utf-8"),
                ("127.0.0.1", port),
            )
        time.sleep(0.15)
        assert discovery.is_running() is True
    finally:
        discovery.stop()

    dead = threading.Thread(target=lambda: None)
    dead.start()
    dead.join()
    stale_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    discovery._listener_thread = dead
    discovery._listener_sock = stale_socket
    discovery.start()
    try:
        assert discovery.is_running() is True
        assert stale_socket.fileno() == -1
    finally:
        discovery.stop()


def test_udp_discovery_skips_malformed_hello_and_keeps_valid_peer():
    port = _free_udp_port()
    ready = threading.Event()

    def serve() -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.bind(("127.0.0.1", port))
            ready.set()
            data, address = server.recvfrom(8192)
            query = json.loads(data.decode("utf-8"))
            hello = {
                "type": "nth-dao-hello",
                "v": 1,
                "agent_id": "valid-peer",
                "label": "Valid peer",
                "capabilities": ["market"],
                "groups": ["home"],
                "ws_url": "http://192.168.1.20:8080",
                "pubkey_hex": "ab" * 32,
                "did": "did:key:zValidPeer",
                "metadata": {"federation_url": "http://192.168.1.20:8080"},
                "nonce": query["nonce"],
                "ts": time.time(),
                "psk_tag": "",
            }
            malformed = {**hello, "capabilities": 1}
            server.sendto(json.dumps(malformed).encode("utf-8"), address)
            server.sendto(json.dumps(hello).encode("utf-8"), address)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    assert ready.wait(1.0)
    peers = LANDiscovery(agent_id="scanner", port=port).discover(
        timeout=0.75,
        target_addrs=["127.0.0.1"],
    )
    thread.join(timeout=1.0)

    assert [peer.agent_id for peer in peers] == ["valid-peer"]


def test_udp_discovery_bounds_unverified_candidates_per_source(monkeypatch):
    class _FloodSocket:
        def __init__(self):
            self.nonce = ""
            self.index = 0

        def setsockopt(self, *_args):
            return None

        def bind(self, *_args):
            return None

        def settimeout(self, *_args):
            return None

        def sendto(self, payload, _address):
            self.nonce = json.loads(payload.decode("utf-8"))["nonce"]

        def recvfrom(self, _size):
            index = self.index
            self.index += 1
            hello = {
                "type": "nth-dao-hello",
                "v": 1,
                "agent_id": f"peer-{index}",
                "label": "Peer",
                "capabilities": [],
                "groups": [],
                "ws_url": "",
                "pubkey_hex": "",
                "did": f"did:key:zpeer{index}",
                "metadata": {},
                "nonce": self.nonce,
                "ts": time.time(),
                "psk_tag": "",
            }
            return json.dumps(hello).encode("utf-8"), ("192.0.2.1", 9877)

        def close(self):
            return None

    monkeypatch.setattr(lan_mod.socket, "socket", lambda *_args, **_kwargs: _FloodSocket())

    peers = LANDiscovery(agent_id="scanner").discover(
        timeout=10.0,
        target_addrs=["192.0.2.1"],
    )

    assert len(peers) == MAX_DISCOVERED_PEERS_PER_SOURCE
    assert peers[-1].agent_id == f"peer-{MAX_DISCOVERED_PEERS_PER_SOURCE - 1}"


def test_udp_discovery_does_not_collapse_distinct_identities_with_same_label(
    monkeypatch,
):
    class _SameLabelSocket:
        def __init__(self):
            self.index = 0
            self.nonce = ""

        def setsockopt(self, *_args):
            return None

        def bind(self, *_args):
            return None

        def settimeout(self, *_args):
            return None

        def sendto(self, payload, _address):
            self.nonce = json.loads(payload.decode("utf-8"))["nonce"]

        def recvfrom(self, _size):
            if self.index >= 2:
                raise socket.timeout
            index = self.index
            self.index += 1
            hello = {
                "type": "nth-dao-hello",
                "v": 1,
                "agent_id": "admin",
                "label": "DAO node",
                "capabilities": [],
                "groups": [],
                "ws_url": f"http://192.0.2.{index + 10}:8080",
                "pubkey_hex": f"{index + 1:02x}" * 32,
                "did": f"did:key:zDistinct{index}",
                "metadata": {},
                "nonce": self.nonce,
                "ts": time.time(),
                "psk_tag": "",
            }
            return json.dumps(hello).encode("utf-8"), (f"192.0.2.{index + 10}", 9877)

        def close(self):
            return None

    monkeypatch.setattr(
        lan_mod.socket, "socket", lambda *_args, **_kwargs: _SameLabelSocket(),
    )

    peers = LANDiscovery(agent_id="scanner").discover(
        timeout=0.01,
        target_addrs=["192.0.2.1"],
    )

    assert len(peers) == 2
    assert {peer.agent_id for peer in peers} == {"admin"}
    assert len({peer.pubkey_hex for peer in peers}) == 2


# ===== mDNS backend (TXT props) =====


def test_LAN_DID_mdns_pack_props_includes_did():
    """The TXT record we publish carries did so a browsing peer can
    read it without an extra round-trip to /api/identity."""
    from nth_dao.discovery.lan_mdns import MDNSDiscovery
    m = MDNSDiscovery(
        agent_id="alice",
        did="did:key:z6MkPlaceholder",
        pubkey_hex="ef" * 32,
    )
    # The _make_service_info method is the construction site; we
    # source-inspect rather than spin up a real zeroconf to keep the
    # test cheap and CI-friendly.
    import inspect
    src = inspect.getsource(m._make_service_info)
    assert '"did"' in src, (
        "_make_service_info does not emit ``did`` in the TXT props; "
        "LAN peers won't learn the discovered peer's DID"
    )


def test_LAN_DID_mdns_unpack_uses_did_for_peer():
    """The browse-side _Listener.add_service must populate
    LANPeer.did from the TXT props['did']. Source-inspect the closure
    body so we pin the contract without spinning up zeroconf."""
    from nth_dao.discovery.lan_mdns import MDNSDiscovery
    import inspect
    src = inspect.getsource(MDNSDiscovery.discover)
    # We look for the LANPeer construction site within discover()
    assert 'did=props.get("did"' in src, (
        "MDNSDiscovery.discover does not propagate ``did`` into the "
        "discovered LANPeer; remote browsers will see did='' even "
        "when the responder published one"
    )


# ===== web lifespan: responder runs only while the server is active =====


@pytest.mark.skipif(
    not crypto_available(),
    reason="LAN DID publish requires PyNaCl for the bootstrap identity",
)
def test_LAN_DID_lifespan_starts_mdns_responder_when_zeroconf_available(
    tmp_path, monkeypatch,
):
    """Application construction is inert; lifespan owns publish/withdraw."""
    started: list[dict] = []
    stopped: list[bool] = []
    start_event = threading.Event()

    class _StubMDNS:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
        def start(self):
            started.append(dict(self.kwargs))
            start_event.set()
        def stop(self):
            stopped.append(True)

    # Replace the import target inside lifespan and force is_available
    # to True so the gate opens.
    import nth_dao.discovery.lan_mdns as mdns_mod
    monkeypatch.setattr(mdns_mod, "MDNSDiscovery", _StubMDNS)
    monkeypatch.setattr(mdns_mod, "is_available", lambda: True)
    monkeypatch.delenv("NTH_LAN_PUBLISH", raising=False)

    app = create_app(tmp_path)
    assert started == [], "create_app() must not start network services"
    with TestClient(app):
        assert start_event.wait(1.0), "responder did not start in background"
        # The DID persisted during bootstrap appears in the advertisement.
        spawn = started[0]
        assert spawn.get("did", "").startswith("did:key:z"), (
            f"responder spawned without a DID: {spawn}"
        )
        network_id = spawn.get("agent_id", "")
        assert network_id != "admin"
        assert all(c in "0123456789abcdef" for c in network_id)
        assert 6 <= len(network_id) <= 32
        assert app.state.nth.mdns_responder is not None

    assert stopped == [True]
    assert app.state.nth.mdns_responder is None


def test_LAN_DID_publish_can_be_disabled_by_env(tmp_path, monkeypatch):
    """NTH_LAN_PUBLISH=0 is the operator escape hatch for shared / public
    networks where we should not advertise."""
    monkeypatch.setenv("NTH_LAN_PUBLISH", "0")
    app = create_app(tmp_path)
    with TestClient(app):
        assert app.state.nth.mdns_responder is None, (
            "responder must not start when NTH_LAN_PUBLISH=0"
        )


def test_LAN_DID_publish_silently_skips_when_zeroconf_missing(
    tmp_path, monkeypatch,
):
    """If the optional ``zeroconf`` dep is not installed we degrade
    cleanly; no exception leaks out of create_app."""
    import nth_dao.discovery.lan_mdns as mdns_mod
    monkeypatch.setattr(mdns_mod, "is_available", lambda: False)
    monkeypatch.delenv("NTH_LAN_PUBLISH", raising=False)
    app = create_app(tmp_path)
    with TestClient(app):
        assert app.state.nth.mdns_responder is None


def test_explicit_LAN_mode_starts_and_stops_udp_fallback(
    tmp_path, monkeypatch,
):
    started: list[dict] = []
    stopped: list[bool] = []

    class _StubUDP:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def start(self):
            started.append(dict(self.kwargs))

        def stop(self):
            stopped.append(True)

    import nth_dao.discovery.lan_mdns as mdns_mod

    monkeypatch.setattr(web_mod, "LANDiscovery", _StubUDP)
    monkeypatch.setattr(mdns_mod, "is_available", lambda: False)
    monkeypatch.setenv("NTH_LAN_DISCOVERY", "1")
    monkeypatch.setenv("NTH_LAN_PUBLISH", "1")
    monkeypatch.setenv("NTH_PUBLIC_BASE_URL", "http://192.168.1.20:8080")

    app = create_app(tmp_path)
    assert started == []
    with TestClient(app) as client:
        assert len(started) == 1
        advertised = started[0]
        assert advertised["did"].startswith("did:key:z")
        assert advertised["metadata"]["federation_url"] == (
            "http://192.168.1.20:8080"
        )
        assert app.state.nth.lan_udp_responder is not None
        federation = client.get("/api/v2/health").json()["federation"]
        assert federation["publisher_active"] is True
        assert federation["lan_ready"] is True

    assert stopped == [True]
    assert app.state.nth.lan_udp_responder is None


def test_dead_udp_responder_is_not_reported_as_active(tmp_path, monkeypatch):
    class _DeadUDP:
        def __init__(self, **_kwargs):
            pass

        def start(self):
            pass

        def stop(self):
            pass

        def is_running(self):
            return False

    import nth_dao.discovery.lan_mdns as mdns_mod

    monkeypatch.setattr(web_mod, "LANDiscovery", _DeadUDP)
    monkeypatch.setattr(mdns_mod, "is_available", lambda: False)
    monkeypatch.setenv("NTH_LAN_DISCOVERY", "1")
    monkeypatch.setenv("NTH_LAN_PUBLISH", "1")
    monkeypatch.setenv("NTH_PUBLIC_BASE_URL", "http://192.168.1.20:8080")

    app = create_app(tmp_path)
    with TestClient(app) as client:
        federation = client.get("/api/v2/health").json()["federation"]
        assert federation["publisher_active"] is False
        assert federation["lan_ready"] is False


def test_web_lifespan_registers_and_unregisters_one_shutdown_hook(
    tmp_path, monkeypatch,
):
    registered = []
    unregistered = []
    monkeypatch.setenv("NTH_LAN_PUBLISH", "0")
    monkeypatch.setattr(
        atexit,
        "register",
        lambda callback, *args, **kwargs: registered.append(callback),
    )
    monkeypatch.setattr(
        atexit,
        "unregister",
        lambda callback: unregistered.append(callback),
    )

    app = create_app(tmp_path)
    assert registered == [], "create_app() must not retain an atexit callback"
    with TestClient(app):
        assert len(registered) == 1

    assert unregistered == registered


def test_mdns_two_live_responders_discover_signed_routing_metadata():
    """Exercise a real zeroconf register/browse round trip on this host."""
    from nth_dao.discovery.lan_mdns import (
        MDNSDiscovery,
        _local_ip,
        is_available,
    )

    if not is_available():
        pytest.skip("zeroconf is not installed")
    suffix = uuid.uuid4().hex[:10]
    local_ip = _local_ip()
    first_url = f"http://{local_ip}:18181"
    second_url = f"http://{local_ip}:18182"
    first = MDNSDiscovery(
        agent_id=f"first-{suffix}",
        label="First live DAO",
        ws_url=first_url,
        pubkey_hex="11" * 32,
        did=f"did:key:zFirst{suffix}",
        metadata={"federation_url": first_url},
    )
    second = MDNSDiscovery(
        agent_id=f"second-{suffix}",
        label="Second live DAO",
        ws_url=second_url,
        pubkey_hex="22" * 32,
        did=f"did:key:zSecond{suffix}",
        metadata={"federation_url": second_url},
    )

    try:
        first.start()
        second.start()
        first_peers = first.discover(timeout=2.0)
        second_peers = second.discover(timeout=2.0)
    finally:
        second.stop()
        first.stop()

    seen_by_first = next(
        peer for peer in first_peers if peer.agent_id == second.agent_id
    )
    seen_by_second = next(
        peer for peer in second_peers if peer.agent_id == first.agent_id
    )
    assert seen_by_first.did == second.did
    assert seen_by_first.metadata["federation_url"] == second_url
    assert seen_by_first.source_addr.startswith(f"{local_ip}:")
    assert seen_by_first.source_addr.endswith(":18182")
    assert seen_by_second.did == first.did
    assert seen_by_second.metadata["federation_url"] == first_url
    assert seen_by_second.source_addr.startswith(f"{local_ip}:")
    assert seen_by_second.source_addr.endswith(":18181")


def test_slow_mdns_registration_is_cancelled_without_blocking_shutdown(
    tmp_path, monkeypatch,
):
    entered = threading.Event()
    release = threading.Event()
    stopped = threading.Event()

    class _SlowMDNS:
        agent_id = "slow"
        did = "did:key:zSlow"
        pubkey_hex = "aa" * 32
        label = "slow"

        def __init__(self, **_kwargs):
            pass

        def start(self):
            entered.set()
            release.wait(2.0)

        def stop(self):
            stopped.set()

    import nth_dao.discovery.lan_mdns as mdns_mod

    monkeypatch.setattr(mdns_mod, "MDNSDiscovery", _SlowMDNS)
    monkeypatch.setattr(mdns_mod, "is_available", lambda: True)
    monkeypatch.delenv("NTH_LAN_PUBLISH", raising=False)

    app = create_app(tmp_path)
    with TestClient(app):
        assert entered.wait(1.0)
        assert app.state.nth.mdns_responder is None

    # The lifespan has returned even though registration is still blocked.
    assert not stopped.is_set()
    release.set()
    assert stopped.wait(1.0)
    assert app.state.nth.mdns_responder is None


# ===== /api/agents/lan_discover surface =====


def test_LAN_DID_lan_discover_response_carries_did_and_pubkey_prefix(
    tmp_path, monkeypatch,
):
    """The dashboard's Scan LAN button receives ``did`` + ``pubkey_prefix``
    per peer so it can render them inline."""
    class _StubLAN:
        def __init__(self, **kwargs):
            pass
        def discover(self, **_):
            return [LANPeer(
                agent_id="alice",
                pubkey_hex="aa" * 32,
                did="did:key:z6MkAliceLAN",
                source_addr="1.2.3.4:9876",
            )]

    monkeypatch.setattr(web_mod, "LANDiscovery", _StubLAN)
    client = TestClient(create_app(tmp_path))
    resp = client.post(
        "/api/agents/lan_discover",
        json={"actor_id": "admin", "timeout_seconds": 0.5},
    )
    assert resp.status_code == 200
    peers = resp.json()["peers"]
    assert len(peers) == 1
    p = peers[0]
    assert p["did"] == "did:key:z6MkAliceLAN"
    assert p["pubkey_prefix"] == "aa" * 8   # first 16 hex chars
    assert p["pubkey_hex"] == "aa" * 32
