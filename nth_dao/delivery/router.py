"""DeliveryRouter — policy-scored transport selection (design doc §8.2).

The router never decides whether an event is trustworthy; it only picks a
route. For one envelope it:

1. filters registered transports by policy (allowlist, privacy floor,
   payload fit, cooldown, reachability);
2. scores the survivors (realtime preference, privacy, infrastructure-free,
   health) deterministically — ties keep registration order;
3. sends to the top ``policy.copy_count`` transports, and — when
   ``allow_fallback`` is set — keeps trying the remaining candidates in
   score order until at least one accepts;
4. tracks rolling health so repeatedly failing transports cool down instead
   of eating every attempt.

Duplicate suppression across transports is the outbox's job: the first
valid signed ACK cancels the other copies. The router is stateless beyond
health counters.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from nth_dao.canonical_json import canonical_json
from nth_dao.delivery.envelope import (
    TransportEnvelope,
    TransportEnvelopeRejected,
    validate_envelope,
)
from nth_dao.delivery.policy import RoutePolicy
from nth_dao.delivery.transports.base import (
    DEFAULT_COOLDOWN_MS,
    DEFAULT_FAILURE_THRESHOLD,
    SendResult,
    Transport,
    TRANSPORT_ACK_HOST,
    TransportHealth,
    monotonic_ms,
)

logger = logging.getLogger("nth_dao.delivery")

RouterClock = Callable[[], int]


@dataclass
class RouteAttempt:
    transport: str
    accepted: bool
    error_code: str = ""


@dataclass
class RoutingResult:
    """Outcome of one routed send."""

    attempts: List[RouteAttempt] = field(default_factory=list)
    sent_via: List[str] = field(default_factory=list)
    exhausted: bool = True

    @property
    def accepted(self) -> bool:
        return bool(self.sent_via)


@dataclass
class ReceivedEnvelope:
    transport: str
    envelope: TransportEnvelope


@dataclass
class _RouterAttemptHealth:
    """Failures observed by the router, separate from provider probes."""

    consecutive_failures: int = 0
    last_success_ms: int = 0
    last_failure_ms: int = 0


class DeliveryRouter:
    """Score-based router over registered transports."""

    def __init__(
        self,
        *,
        clock: Optional[RouterClock] = None,
        failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
        cooldown_ms: int = DEFAULT_COOLDOWN_MS,
    ) -> None:
        if (
            isinstance(failure_threshold, bool)
            or not isinstance(failure_threshold, int)
            or failure_threshold < 1
        ):
            raise ValueError("failure_threshold must be a positive integer")
        if (
            isinstance(cooldown_ms, bool)
            or not isinstance(cooldown_ms, int)
            or cooldown_ms < 0
        ):
            raise ValueError("cooldown_ms must be a non-negative integer")
        if clock is not None and not callable(clock):
            raise TypeError("clock must be callable")
        self._clock = clock or monotonic_ms
        self._failure_threshold = failure_threshold
        self._cooldown_ms = cooldown_ms
        self._transports: Dict[str, Transport] = {}
        self._provider_health: Dict[str, TransportHealth] = {}
        self._attempt_health: Dict[str, _RouterAttemptHealth] = {}
        self._health: Dict[str, TransportHealth] = {}
        self._order: List[str] = []
        self._lock = threading.RLock()

    # ─────────────────────── registry ───────────────────────

    def register(self, transport: Transport) -> None:
        capabilities = transport.capabilities
        with self._lock:
            if capabilities.name in self._transports:
                raise ValueError(f"transport already registered: {capabilities.name}")
        initial_health = self._read_transport_health(transport)
        with self._lock:
            # A concurrent registration may have won while health was probed.
            if capabilities.name in self._transports:
                raise ValueError(f"transport already registered: {capabilities.name}")
            self._transports[capabilities.name] = transport
            self._provider_health[capabilities.name] = initial_health
            self._attempt_health[capabilities.name] = _RouterAttemptHealth()
            self._recompute_health_locked(capabilities.name)
            self._order.append(capabilities.name)

    def unregister(self, name: str) -> None:
        with self._lock:
            self._transports.pop(name, None)
            self._provider_health.pop(name, None)
            self._attempt_health.pop(name, None)
            self._health.pop(name, None)
            if name in self._order:
                self._order.remove(name)

    def transport_names(self) -> List[str]:
        with self._lock:
            return list(self._order)

    def health_of(self, name: str) -> Optional[TransportHealth]:
        with self._lock:
            health = self._health.get(name)
            if health is None:
                return None
            return TransportHealth(
                reachable=health.reachable,
                receive_reachable=health.receive_reachable,
                consecutive_failures=health.consecutive_failures,
                last_success_ms=health.last_success_ms,
                last_failure_ms=health.last_failure_ms,
            )

    # ─────────────────────── routing ───────────────────────

    def send(self, envelope: TransportEnvelope, policy: Optional[RoutePolicy] = None) -> RoutingResult:
        policy = policy or RoutePolicy()
        if not isinstance(policy, RoutePolicy):
            raise TypeError("policy must be a RoutePolicy")
        if not isinstance(envelope, TransportEnvelope):
            raise TransportEnvelopeRejected("envelope must be a TransportEnvelope")
        try:
            stable_envelope = TransportEnvelope.from_dict(envelope.to_dict())
        except (TransportEnvelopeRejected, TypeError, ValueError, RecursionError):
            raise TransportEnvelopeRejected("envelope snapshot could not be created") from None
        ok, reason = validate_envelope(stable_envelope, require_signature=True)
        if not ok:
            raise TransportEnvelopeRejected(reason)
        if stable_envelope.routing["hop_limit"] > policy.max_hop_limit:
            raise TransportEnvelopeRejected(
                "envelope hop_limit exceeds the active route policy"
            )
        self.refresh_health()
        candidates = self._score(stable_envelope, policy)
        result = RoutingResult()
        now = self._now_ms()
        primary = candidates[: policy.copy_count]
        fallback = candidates[policy.copy_count:] if policy.allow_fallback else []

        for name in primary:
            outcome = self._dispatch(name, stable_envelope, now)
            result.attempts.append(outcome)
            if outcome.accepted:
                result.sent_via.append(name)

        if not result.accepted and policy.allow_fallback:
            for name in fallback:
                outcome = self._dispatch(name, stable_envelope, now)
                result.attempts.append(outcome)
                if outcome.accepted:
                    result.sent_via.append(name)
                    break

        result.exhausted = not result.accepted
        return result

    def receive(self, *, max_items: int = 64) -> List[ReceivedEnvelope]:
        """Poll every registered transport and drain what arrived."""

        if isinstance(max_items, bool) or not isinstance(max_items, int) or max_items < 1:
            raise ValueError("max_items must be a positive integer")
        self.refresh_health()
        received: List[ReceivedEnvelope] = []
        with self._lock:
            names = list(self._order)
            transports = dict(self._transports)
            receive_health = {
                name: self._health[name].receive_reachable for name in names
            }
        for name in names:
            remaining = max_items - len(received)
            if remaining <= 0:
                break
            if receive_health[name] is not True:
                continue
            transport = transports[name]
            try:
                items = transport.poll(max_items=remaining)
            except Exception as exc:
                logger.warning(
                    "transport %s poll failed (%s)", name, type(exc).__name__
                )
                self._note_receive_failure(name, self._now_ms())
                continue
            for envelope in items[:remaining]:
                received.append(ReceivedEnvelope(transport=name, envelope=envelope))
        return received

    def refresh_health(self) -> None:
        """Refresh provider reachability without calling provider code under lock."""

        with self._lock:
            transports = tuple(self._transports.items())
        snapshots = [
            (name, transport, self._read_transport_health(transport))
            for name, transport in transports
        ]
        with self._lock:
            for name, transport, snapshot in snapshots:
                if self._transports.get(name) is not transport:
                    continue
                self._provider_health[name] = snapshot
                self._recompute_health_locked(name)

    def stats(self) -> Dict[str, Dict[str, object]]:
        now = self._now_ms()
        with self._lock:
            snapshot: Dict[str, Dict[str, object]] = {}
            for name in self._order:
                health = self._health[name]
                snapshot[name] = {
                    "reachable": health.reachable,
                    "receive_reachable": health.receive_reachable,
                    "consecutive_failures": health.consecutive_failures,
                    "in_cooldown": health.in_cooldown(
                        now,
                        threshold=self._failure_threshold,
                        cooldown_ms=self._cooldown_ms,
                    ),
                }
            return snapshot

    # ─────────────────────── internals ───────────────────────

    def _score(
        self, envelope: TransportEnvelope, policy: RoutePolicy
    ) -> List[str]:
        envelope_bytes = len(canonical_json(envelope.to_dict()))
        scored: List[tuple[int, int, str]] = []
        now = self._now_ms()
        with self._lock:
            for index, name in enumerate(self._order):
                transport = self._transports[name]
                capabilities = transport.capabilities
                if policy.allowed_transports and name not in policy.allowed_transports:
                    continue
                if envelope.recipient.startswith("did:key:") and not capabilities.unicast:
                    continue
                if capabilities.privacy_level < policy.privacy_floor:
                    continue
                if policy.require_ack and capabilities.ack_mode != TRANSPORT_ACK_HOST:
                    continue
                infrastructure = policy.require_external_infrastructure
                if (
                    infrastructure is not None
                    and capabilities.external_infrastructure != infrastructure
                ):
                    continue
                if envelope_bytes > capabilities.max_envelope_bytes:
                    continue
                health = self._health[name]
                if not health.reachable:
                    continue
                if health.in_cooldown(
                    now,
                    threshold=self._failure_threshold,
                    cooldown_ms=self._cooldown_ms,
                ):
                    continue
                score = 0
                if capabilities.realtime == policy.prefer_realtime:
                    score += 4
                score += capabilities.privacy_level
                if not capabilities.external_infrastructure:
                    score += 2
                if health.consecutive_failures == 0:
                    score += 1
                scored.append((-score, index, name))
        scored.sort()
        return [name for _, _, name in scored]

    def _dispatch(self, name: str, envelope: TransportEnvelope, now: int) -> RouteAttempt:
        with self._lock:
            transport = self._transports.get(name)
        if transport is None:  # pragma: no cover - raced with unregister
            return RouteAttempt(transport=name, accepted=False, error_code="unregistered")
        transport_envelope = TransportEnvelope.from_dict(envelope.to_dict())
        try:
            outcome = transport.send(transport_envelope)
        except Exception as exc:
            logger.warning(
                "transport %s send failed (%s)", name, type(exc).__name__
            )
            self._note_failure(name, now)
            return RouteAttempt(transport=name, accepted=False, error_code="transport-error")
        if type(outcome) is not SendResult:
            logger.warning("transport %s returned an invalid SendResult", name)
            self._note_failure(name, now)
            return RouteAttempt(
                transport=name,
                accepted=False,
                error_code="invalid-send-result",
            )
        try:
            outcome = SendResult(
                accepted=outcome.accepted,
                error_code=outcome.error_code,
            )
        except (TypeError, ValueError):
            logger.warning("transport %s returned a mutated SendResult", name)
            self._note_failure(name, now)
            return RouteAttempt(
                transport=name,
                accepted=False,
                error_code="invalid-send-result",
            )
        if outcome.accepted:
            self._note_success(name, now)
        else:
            self._note_failure(name, now)
        return RouteAttempt(
            transport=name, accepted=outcome.accepted, error_code=outcome.error_code
        )

    def _note_success(self, name: str, now_ms: int) -> None:
        with self._lock:
            attempts = self._attempt_health.get(name)
            if attempts is None:
                return
            attempts.consecutive_failures = 0
            attempts.last_success_ms = now_ms
            self._recompute_health_locked(name)

    def _note_failure(self, name: str, now_ms: int) -> None:
        with self._lock:
            attempts = self._attempt_health.get(name)
            if attempts is None:
                return
            attempts.consecutive_failures += 1
            attempts.last_failure_ms = now_ms
            self._recompute_health_locked(name)

    def _note_receive_failure(self, name: str, now_ms: int) -> None:
        with self._lock:
            provider = self._provider_health.get(name)
            if provider is None:
                return
            provider.receive_reachable = False
            provider.last_failure_ms = max(provider.last_failure_ms, now_ms)
            self._recompute_health_locked(name)

    def _recompute_health_locked(self, name: str) -> None:
        provider = self._provider_health[name]
        attempts = self._attempt_health[name]
        self._health[name] = TransportHealth(
            reachable=provider.reachable,
            receive_reachable=provider.receive_reachable,
            consecutive_failures=max(
                provider.consecutive_failures,
                attempts.consecutive_failures,
            ),
            last_success_ms=max(provider.last_success_ms, attempts.last_success_ms),
            last_failure_ms=max(provider.last_failure_ms, attempts.last_failure_ms),
        )

    def _read_transport_health(self, transport: Transport) -> TransportHealth:
        try:
            health = transport.health()
            if not isinstance(health, TransportHealth):
                raise TypeError("health() did not return TransportHealth")
            return TransportHealth(
                reachable=health.reachable,
                receive_reachable=health.receive_reachable,
                consecutive_failures=health.consecutive_failures,
                last_success_ms=health.last_success_ms,
                last_failure_ms=health.last_failure_ms,
            )
        except Exception as exc:
            logger.warning(
                "transport %s health probe failed (%s)",
                transport.capabilities.name,
                type(exc).__name__,
            )
            return TransportHealth(
                reachable=False,
                receive_reachable=False,
                consecutive_failures=1,
                last_failure_ms=self._now_ms(),
            )

    def _now_ms(self) -> int:
        value = self._clock()
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("router clock must return a non-negative integer ms")
        return value


__all__ = [
    "DeliveryRouter",
    "ReceivedEnvelope",
    "RouteAttempt",
    "RoutePolicy",
    "RoutingResult",
]
