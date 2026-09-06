"""Nostr transport — public relay tier for the delivery router (Phase 2 N3).

Borrowing rule: the event construction, signature, and relay wire protocol
are entirely nostr-sdk's (N1 + N2). This module is the delivery-layer
Transport adapter: wraps a ``NostrRelayClient`` and the envelope↔event
mapping behind the standard ``Transport`` interface.

Security boundary (design doc §8.3): the Nostr relay tier is world-readable
broadcast infrastructure. Only envelopes with broadcast recipients
(dao:/channel:) are accepted — private (did:key) envelopes are refused at
send time by the N1 core's public-tier policy. The privacy level is
declared ``PRIVACY_PUBLIC_RELAY`` so the router's privacy floors exclude
this transport for sensitive traffic automatically.
"""

from __future__ import annotations

import logging
from typing import Any, List

from nth_dao.delivery.envelope import TransportEnvelope
from nth_dao.delivery.transports.base import (
    PRIVACY_PUBLIC_RELAY,
    SendResult,
    Transport,
    TransportCapabilities,
    TransportHealth,
)
from nth_dao.nostr import (
    NOSTR_EVENT_KIND,
    NostrKeys,
    NostrRelayClient,
    envelope_event,
    envelope_from_event,
)

logger = logging.getLogger("nth_dao.nostr")

NOSTR_SUBSCRIBE_KINDS = [NOSTR_EVENT_KIND]


class NostrTransport(Transport):
    """Delivery Transport over the public Nostr relay tier."""

    def __init__(
        self,
        identity_keys: NostrKeys,
        *,
        relay_urls: List[str],
        name: str = "nostr",
        publish_timeout: float = 10.0,
        binding: Any = None,
    ) -> None:
        self._relay_client = NostrRelayClient(
            identity_keys,
            relay_urls=relay_urls,
            name=name,
            publish_timeout=publish_timeout,
        )
        self._keys = identity_keys
        self._binding = binding
        self.capabilities = TransportCapabilities(
            name=name,
            unicast=False,
            broadcast=True,
            realtime=True,
            privacy_level=PRIVACY_PUBLIC_RELAY,
            external_infrastructure=True,
            ack_mode="host",
        )

    def start(self) -> None:
        self._relay_client.start()
        try:
            self._relay_client.subscribe_events(kinds=NOSTR_SUBSCRIBE_KINDS)
        except Exception as exc:  # noqa: BLE001 - operability: publish-only
            logger.warning(
                "nostr subscription setup failed; transport continues in "
                "publish-only mode (poll returns empty): %s", exc
            )

    def stop(self) -> None:
        self._relay_client.stop()

    def send(self, envelope: TransportEnvelope) -> SendResult:
        try:
            event = envelope_event(
                envelope, self._keys, created_at_seconds=int(_time()),
                binding=self._binding,
            )
        except Exception as exc:  # noqa: BLE001 - policy/crypto rejections
            logger.warning("nostr send rejected: %s", exc)
            return SendResult(accepted=False, error_code=str(exc)[:200])
        if self._relay_client.publish(event):
            return SendResult(accepted=True)
        return SendResult(accepted=False, error_code="nostr-relay-unreachable")

    def poll(self, *, max_items: int = 64) -> List[TransportEnvelope]:
        """Drain subscribed Nostr events, re-validating each envelope."""

        envelopes: List[TransportEnvelope] = []
        for event in self._relay_client.poll_events(max_items=max_items):
            try:
                envelopes.append(envelope_from_event(event))
            except Exception:  # noqa: BLE001 - hostile events fail closed
                logger.debug("nostr event failed envelope validation; dropping")
                continue
        return envelopes

    def health(self) -> TransportHealth:
        return TransportHealth(reachable=self._relay_client.is_running)


def _time() -> float:
    import time

    return time.time()


__all__ = ["NOSTR_SUBSCRIBE_KINDS", "NostrTransport"]
