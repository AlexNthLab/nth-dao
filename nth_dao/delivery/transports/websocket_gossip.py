"""WebSocket gossip transport — wraps the existing P2P gossip as a delivery
Transport (Phase 1 of the integration design doc §8.1: "先接入已经存在且可
稳定测试的 WebSocket ...").

Borrowing rule: this adapter adds NO new wire protocol. It reuses
``nth_dao.gossip.GossipNode`` (signed challenge-response handshake, replay
window, dedup, web-of-trust) as-is and only bridges the asyncio world into
the delivery layer's synchronous Transport contract on a background thread.

Flow:

* send   — the canonical envelope JSON becomes the *content* of one signed
  gossip message (``ChannelMessage``, content_type ``json``). The gossip
  layer signs the message with the node identity; the envelope INSIDE keeps
  its own author signature. Two independent signatures, two independent
  verifications — relays authenticate nodes, inboxes authenticate authors.
* poll   — inbound gossip messages whose content parses as an envelope are
  queued (bounded) for the host to drain. The inbox re-validates everything;
  the transport only refuses obvious non-envelopes.
* trust  — ``trusted_pubkeys`` maps peer agent_id → pubkey_hex and is passed
  straight to ``GossipNode(require_signature=True)``: unsigned or untrusted
  gossip is dropped by the borrowed layer, never by new code.

``TeamChannel`` deliberately bypassed: it truncates content at 10 000 chars,
which would destroy envelopes up to 512 KiB. The shim channel below signs
identically but never truncates and never writes a ledger.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import uuid
from collections import deque
from typing import Any, Dict, List, Optional

from nth_dao.canonical_json import canonical_json
from nth_dao.channel import ChannelMessage
from nth_dao.delivery.envelope import (
    MAX_ENVELOPE_BYTES,
    TransportEnvelope,
    validate_envelope,
)
from nth_dao.delivery.transports.base import (
    PRIVACY_PEER,
    SendResult,
    Transport,
    TransportCapabilities,
    TransportHealth,
)
from nth_dao.gossip import GossipNode
from nth_dao.identity import AgentIdentity

logger = logging.getLogger("nth_dao.delivery")

GOSSIP_SCOPE = "dao"
GOSSIP_CONTENT_TYPE = "json"
_INBOUND_QUEUE_SIZE = 4_096
_MAX_TRUSTED_PEERS = 1_024
_DEFAULT_SEND_TIMEOUT = 10.0


class GossipTransportError(RuntimeError):
    """Raised for gossip transport lifecycle failures."""


class _EnvelopeChannel:
    """Minimal channel sink for GossipNode: signs, never truncates, no ledger.

    ``GossipNode`` only needs ``channel.send(...)`` (outbound) and
    ``channel._append(msg)`` (inbound ledger append). Both are provided;
    ``_append`` is a no-op because envelope persistence is the inbox/outbox's
    job, not the transport's.
    """

    def __init__(self, identity: AgentIdentity) -> None:
        self.agent_id = str(identity.agent_id)
        self.identity = identity

    def send(
        self,
        content: str,
        scope: str = GOSSIP_SCOPE,
        content_type: str = GOSSIP_CONTENT_TYPE,
        reply_to: str = "",
        mentions: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ChannelMessage:
        msg = ChannelMessage(
            msg_id="",
            channel=scope,
            from_agent=self.agent_id,
            content=content,
            content_type=content_type,
            reply_to=reply_to,
            mentions=mentions or [],
            metadata=metadata or {},
        )
        # ChannelMessage has no default id generator; mirror TeamChannel and
        # use a random hex id. Signed over exactly the same payload shape as
        # TeamChannel.send so receiving GossipNodes verify it unchanged.
        msg.msg_id = uuid.uuid4().hex
        if self.identity.can_sign:
            payload = {
                "msg_id": msg.msg_id,
                "channel": msg.channel,
                "from_agent": msg.from_agent,
                "content": msg.content,
                "content_type": msg.content_type,
                "reply_to": msg.reply_to,
                "mentions": msg.mentions,
                "timestamp": msg.timestamp,
                "metadata": msg.metadata,
            }
            msg.sig = self.identity.sign_json(payload)
        return msg

    def dm(
        self,
        to_agent: str,
        content: str,
        content_type: str = GOSSIP_CONTENT_TYPE,
    ) -> ChannelMessage:
        """GossipNode.direct_message calls this; route to send with a DM scope."""

        return self.send(content=content, scope=f"dm:{self.agent_id}--{to_agent}",
                         content_type=content_type)

    def _append(self, msg: ChannelMessage) -> None:  # pragma: no cover - shim
        """Inbound ledger hook: intentionally a no-op (inbox persists)."""


class WebSocketGossipTransport(Transport):
    """Synchronous delivery Transport over the borrowed async GossipNode."""

    def __init__(
        self,
        identity: AgentIdentity,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        trusted_pubkeys: Optional[Dict[str, str]] = None,
        bootstrap_peers: Optional[List[str]] = None,
        name: str = "gossip-ws",
        send_timeout: float = _DEFAULT_SEND_TIMEOUT,
        wot_max_depth: int = 2,
    ) -> None:
        if trusted_pubkeys is not None and len(trusted_pubkeys) > _MAX_TRUSTED_PEERS:
            raise ValueError(f"trusted_pubkeys is capped at {_MAX_TRUSTED_PEERS} peers")
        if not 0.1 <= float(send_timeout) <= 60.0:
            raise ValueError("send_timeout must be between 0.1 and 60 seconds")
        self._identity = identity
        self._host = host
        self._port = port
        self._trusted = dict(trusted_pubkeys or {})
        self._bootstrap = list(bootstrap_peers or [])
        self._send_timeout = float(send_timeout)
        self.capabilities = TransportCapabilities(
            name=name,
            unicast=True,
            broadcast=True,
            realtime=True,
            privacy_level=PRIVACY_PEER,
            external_infrastructure=False,
            ack_mode="host",
        )
        self._channel = _EnvelopeChannel(identity)
        self._node: Optional[GossipNode] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._started = threading.Event()
        self._start_error: Optional[str] = None
        self._running = False
        self._inbox: deque = deque(maxlen=_INBOUND_QUEUE_SIZE)
        self._inbox_lock = threading.Lock()
        self.dropped_inbound = 0

    # ─────────────────────── lifecycle ───────────────────────

    def start(self) -> str:
        """Start the background loop and the gossip node; return its URL."""

        if self._running:
            return self._node.url if self._node else ""
        # macOS/Windows system proxies happily intercept loopback WebSockets
        # and break local gossip with 503s. Merge a loopback bypass into any
        # user-configured no_proxy (websockets consults urllib's
        # proxy_bypass, which honours it); users who explicitly WANT the
        # proxy in the path must exclude loopback themselves — this
        # transport cannot function through a loopback proxy.
        import os

        for variable in ("no_proxy", "NO_PROXY"):
            current = os.environ.get(variable, "")
            entries = [
                entry.strip() for entry in current.split(",") if entry.strip()
            ]
            for required in ("127.0.0.1", "localhost"):
                if required not in entries:
                    entries.append(required)
            os.environ[variable] = ",".join(entries)
        # restart hygiene: a previous run leaves _started set and possibly a
        # stale _start_error — clear both or start() would return before the
        # new node has bound its port (round-5 review bug U)
        self._started.clear()
        self._start_error = None
        try:
            self._node = GossipNode(
                identity=self._identity,
                channel=self._channel,
                host=self._host,
                port=self._port,
                bootstrap_peers=self._bootstrap,
                trusted_pubkeys=self._trusted,
                require_signature=True,
            )
        except Exception as exc:
            # lifecycle errors speak one type: an unsignable identity, a bad
            # trust map, anything the borrowed constructor rejects
            raise GossipTransportError(f"gossip node construction failed: {exc}") from exc
        self._node.on_message(self._on_gossip_message)
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._run_loop, name=f"nth-gossip-{self.capabilities.name}", daemon=True
        )
        self._thread.start()
        if not self._started.wait(timeout=15.0):
            self._shutdown_loop()
            raise GossipTransportError("gossip node failed to start within 15s")
        if self._start_error is not None:
            self._running = False
            self._shutdown_loop()
            raise GossipTransportError(f"gossip node failed to start: {self._start_error}")
        self._running = True
        return self._node.url

    def _shutdown_loop(self) -> None:
        """Stop and join a loop thread that never reached the running state."""

        loop = self._loop
        self._loop = None
        if loop is not None and loop.is_running():
            loop.call_soon_threadsafe(loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None

    def _run_loop(self) -> None:
        loop = self._loop
        assert loop is not None
        asyncio.set_event_loop(loop)

        async def _boot() -> None:
            try:
                url = await self._node.start()
                for peer in self._bootstrap:
                    try:
                        await self._node.connect(peer)
                    except Exception as exc:  # noqa: BLE001 - bootstrap is best-effort
                        logger.warning("bootstrap connect %s failed: %s", peer, exc)
                self._url = url
                self._start_error = None
            except Exception as exc:  # noqa: BLE001 - surfaced via the event
                self._start_error = str(exc)
            finally:
                self._started.set()

        startup = loop.create_task(_boot())
        try:
            loop.run_forever()
        finally:
            # finish the cancellation on the loop before closing it, or the
            # pending boot task triggers "Task was destroyed but it is pending"
            startup.cancel()
            try:
                loop.run_until_complete(startup)
            except (asyncio.CancelledError, Exception):
                pass
            loop.close()

    def stop(self) -> None:
        if not self._running or self._loop is None or self._node is None:
            return
        try:
            stopper = asyncio.run_coroutine_threadsafe(self._node.stop(), self._loop)
            stopper.result(timeout=5.0)
        except Exception as exc:  # noqa: BLE001 - stop must never raise
            logger.warning("gossip node stop failed: %s", exc)
        finally:
            self._running = False
            self._shutdown_loop()

    # ─────────────────────── Transport API ───────────────────────

    def send(self, envelope: TransportEnvelope) -> SendResult:
        if not self._running or self._node is None or self._loop is None:
            return SendResult(accepted=False, error_code="transport-stopped")
        # local validation first — a malformed envelope is refused even when
        # no peer is connected, so the error names the real problem. The TTL
        # *window* is deliberately NOT checked here: expiry is the receiver's
        # inbox decision (its clock), and a sender-side clock check would
        # break deterministic replay in tests and conformance vectors.
        ok, reason = validate_envelope(envelope, require_signature=True)
        if not ok:
            return SendResult(accepted=False, error_code=f"invalid-envelope: {reason}")
        if self._node.peer_count() == 0:
            return SendResult(accepted=False, error_code="no-connected-peers")
        content = canonical_json(envelope.to_dict()).decode("utf-8")
        try:
            fut = asyncio.run_coroutine_threadsafe(
                self._node.broadcast(content, scope=GOSSIP_SCOPE,
                                     content_type=GOSSIP_CONTENT_TYPE),
                self._loop,
            )
            fut.result(timeout=self._send_timeout)
        except asyncio.TimeoutError:
            return SendResult(accepted=False, error_code="gossip-send-timeout")
        except Exception as exc:  # noqa: BLE001 - transport bugs are failures
            logger.warning("gossip send failed: %s", exc)
            return SendResult(accepted=False, error_code="gossip-send-error")
        # post-broadcast honesty check: if every peer vanished between the
        # pre-check and the actual gossip, nothing was delivered — report
        # failure so the outbox retries instead of trusting a false accept
        # (round-6 review bug W)
        if self._node.peer_count() == 0:
            return SendResult(accepted=False, error_code="no-connected-peers")
        return SendResult(accepted=True)

    def poll(self, *, max_items: int = 64) -> List[TransportEnvelope]:
        items: List[TransportEnvelope] = []
        with self._inbox_lock:
            while self._inbox and len(items) < max_items:
                items.append(self._inbox.popleft())
        return items

    def health(self) -> TransportHealth:
        return TransportHealth(reachable=self._running)

    def peer_count(self) -> int:
        return self._node.peer_count() if (self._running and self._node) else 0

    @property
    def url(self) -> str:
        """The bound gossip URL (real port even with port=0)."""

        return getattr(self, "_url", "")

    # ─────────────────────── internals ───────────────────────

    def _on_gossip_message(self, msg_dict: Dict[str, Any], relay_peer_id: str = "") -> None:
        """GossipNode callback (runs on the loop thread): queue envelopes."""

        content = msg_dict.get("content") if isinstance(msg_dict, dict) else None
        if not isinstance(content, str) or not content:
            return
        try:
            if len(content.encode("utf-8")) > MAX_ENVELOPE_BYTES:
                logger.warning("gossip envelope exceeds the wire limit; dropping")
                return
            parsed = json.loads(content)
            envelope = TransportEnvelope.from_dict(parsed)
        except (
            json.JSONDecodeError,
            UnicodeDecodeError,
            ValueError,
            TypeError,
            RecursionError,
        ):
            # not a delivery envelope — some other gossip content; ignore
            return
        with self._inbox_lock:
            if len(self._inbox) == self._inbox.maxlen:
                self._inbox.popleft()  # drop oldest under flood
                self.dropped_inbound += 1
            self._inbox.append(envelope)


__all__ = [
    "GOSSIP_CONTENT_TYPE",
    "GOSSIP_SCOPE",
    "GossipTransportError",
    "WebSocketGossipTransport",
]
