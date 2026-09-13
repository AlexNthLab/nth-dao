"""Transport contract and capabilities for the delivery layer.

This is the Python reference implementation of the design doc §5.2 minimal
transport interface, adapted to the codebase's synchronous core (the plugin
transport contract in ``nth_dao.plugins.transport`` is likewise synchronous;
async adapters can wrap these without protocol changes).

A Transport moves opaque signed envelopes. It NEVER:

* grants authority or membership;
* verifies business semantics (the inbox does that);
* rewrites signed envelope fields (hop_count is the only relay-mutable
  field, and only mesh-style transports may touch it).

Transports declare their capabilities so the router can score them:
reachability, realtime-ness, payload limits, privacy exposure, whether the
ACK comes from the transport or from the remote host, and whether external
infrastructure (a relay server, a relay network) is required.
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List

from nth_dao.delivery.envelope import (
    MAX_ENVELOPE_BYTES,
    TransportEnvelope,
)

logger = logging.getLogger("nth_dao.delivery")

PRIVACY_PUBLIC_RELAY = 0   # relays see metadata (e.g. future Nostr adapter)
PRIVACY_PEER = 1           # only the named peer sees the envelope
PRIVACY_LOCAL = 2          # stays on-device / LAN-local / offline bundle

TRANSPORT_ACK_HOST = "host"      # remote host signs the ACK (delivery ACKs)
TRANSPORT_ACK_NONE = "none"

DEFAULT_COOLDOWN_MS = 30_000
DEFAULT_FAILURE_THRESHOLD = 3


@dataclass(frozen=True)
class TransportCapabilities:
    """What this transport can do. The router scores from these."""

    name: str
    unicast: bool = True
    broadcast: bool = False
    max_envelope_bytes: int = MAX_ENVELOPE_BYTES
    realtime: bool = False
    privacy_level: int = PRIVACY_PEER
    external_infrastructure: bool = False
    ack_mode: str = TRANSPORT_ACK_HOST

    def __post_init__(self) -> None:
        if (
            not isinstance(self.name, str)
            or not self.name
            or len(self.name.encode("utf-8")) > 64
            or not self.name.isprintable()
        ):
            raise ValueError(
                "transport capability name must be printable text of 1..64 UTF-8 bytes"
            )
        for field_name in (
            "unicast",
            "broadcast",
            "realtime",
            "external_infrastructure",
        ):
            if type(getattr(self, field_name)) is not bool:
                raise TypeError(f"transport capability {field_name} must be a bool")
        if type(self.privacy_level) is not int or self.privacy_level not in (
            PRIVACY_PUBLIC_RELAY,
            PRIVACY_PEER,
            PRIVACY_LOCAL,
        ):
            raise ValueError("privacy_level must be 0, 1, or 2")
        if not isinstance(self.ack_mode, str) or self.ack_mode not in (
            TRANSPORT_ACK_HOST,
            TRANSPORT_ACK_NONE,
        ):
            raise ValueError("ack_mode must be 'host' or 'none'")
        if (
            type(self.max_envelope_bytes) is not int
            or self.max_envelope_bytes < 1
        ):
            raise ValueError("max_envelope_bytes must be a positive integer")


@dataclass
class TransportHealth:
    """Rolling health signal; ``reachable`` is the send-side signal."""

    reachable: bool = True
    receive_reachable: bool | None = None
    consecutive_failures: int = 0
    last_success_ms: int = 0
    last_failure_ms: int = 0

    def __post_init__(self) -> None:
        if type(self.reachable) is not bool:
            raise TypeError("transport health reachable must be a bool")
        if self.receive_reachable is None:
            self.receive_reachable = self.reachable
        elif type(self.receive_reachable) is not bool:
            raise TypeError("transport health receive_reachable must be a bool")
        for name, value in (
            ("consecutive_failures", self.consecutive_failures),
            ("last_success_ms", self.last_success_ms),
            ("last_failure_ms", self.last_failure_ms),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"transport health {name} must be a non-negative integer")

    def in_cooldown(self, now_ms: int, *, threshold: int, cooldown_ms: int) -> bool:
        if self.consecutive_failures < threshold:
            return False
        return now_ms - self.last_failure_ms < cooldown_ms


@dataclass(frozen=True)
class SendResult:
    """Outcome of one transport send attempt."""

    accepted: bool
    error_code: str = ""

    def __post_init__(self) -> None:
        if type(self.accepted) is not bool:
            raise TypeError("send result accepted must be a bool")
        if (
            not isinstance(self.error_code, str)
            or len(self.error_code.encode("utf-8")) > 256
            or (bool(self.error_code) and not self.error_code.isprintable())
        ):
            raise ValueError(
                "send result error_code must be printable text no longer than "
                "256 UTF-8 bytes"
            )
        if self.accepted and self.error_code:
            raise ValueError("an accepted send result cannot carry an error_code")


class Transport(ABC):
    """Minimal sync transport interface (design doc §5.2, Python flavor)."""

    capabilities: TransportCapabilities

    def start(self) -> None:
        """Acquire resources. Default: stateless transport, nothing to do."""

    def stop(self) -> None:
        """Release resources. Default: stateless transport, nothing to do."""

    @abstractmethod
    def send(self, envelope: TransportEnvelope) -> SendResult:
        """Hand one envelope to the wire. Must not verify business payload."""

    def poll(self, *, max_items: int = 64) -> List[TransportEnvelope]:
        """Drain received envelopes (pull model). Default: none."""

        return []

    def health(self) -> TransportHealth:
        return TransportHealth()


def monotonic_ms() -> int:
    """Router clock base: wall clock in ms (matches envelope timestamps)."""

    return int(time.time() * 1000)


__all__ = [
    "DEFAULT_COOLDOWN_MS",
    "DEFAULT_FAILURE_THRESHOLD",
    "PRIVACY_LOCAL",
    "PRIVACY_PEER",
    "PRIVACY_PUBLIC_RELAY",
    "SendResult",
    "Transport",
    "TransportCapabilities",
    "TransportHealth",
    "monotonic_ms",
]
