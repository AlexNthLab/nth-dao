"""Bounded in-memory reference provider for ``transport.provider``.

The provider is a conformance sample, not a network transport. It derives a
local route from the Host-selected invocation principal, partitions receive
leases by that principal, and never accepts caller-supplied source identity.
It is installed disabled and does not replace gossip, A2A, or Channel storage.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import heapq
import math
from pathlib import Path
import threading
import time
from typing import Any, Dict, Optional

from nth_dao.canonical_json import canonical_json
from nth_dao.plugins.contracts import PLUGIN_BASE_HOST_API_VERSION, PluginManifest
from nth_dao.plugins.host import (
    CapabilitySchemas,
    PluginContext,
    PluginHost,
    PluginInvocationContext,
    PluginInvocationError,
)
from nth_dao.plugins.transport import (
    TRANSPORT_CAPABILITY_ID,
    TRANSPORT_INPUT_SCHEMA,
    TRANSPORT_LOCAL_CONTRACT,
    TRANSPORT_MAX_BATCH_SIZE,
    TRANSPORT_MAX_DOCUMENT_BYTES,
    TRANSPORT_MAX_ENVELOPE_BYTES,
    TRANSPORT_MAX_LEASE_MS,
    TRANSPORT_MAX_SAFE_INTEGER,
    TRANSPORT_OUTPUT_SCHEMA,
    TransportOperationError,
    transport_batch_digest,
    validate_transport_authority,
    validate_transport_exchange,
    validate_transport_input,
    validate_transport_output,
)


LOOPBACK_TRANSPORT_PLUGIN_ID = "org.nth-dao.transport.loopback"
LOOPBACK_TRANSPORT_MAX_DELIVERIES = 8_192
LOOPBACK_TRANSPORT_MAX_DELIVERIES_PER_PRINCIPAL = 1_024
LOOPBACK_TRANSPORT_MAX_DELIVERIES_PER_ROUTE = 1_024
LOOPBACK_TRANSPORT_MAX_BYTES = 67_108_864
LOOPBACK_TRANSPORT_MAX_BYTES_PER_PRINCIPAL = 16_777_216
LOOPBACK_TRANSPORT_MAX_BYTES_PER_ROUTE = 16_777_216
LOOPBACK_TRANSPORT_MAX_TTL_SECONDS = 604_800
LOOPBACK_TRANSPORT_MAX_CLAIMS = 8_192
LOOPBACK_TRANSPORT_MAX_CLAIMS_PER_PRINCIPAL = 1_024
LOOPBACK_TRANSPORT_CLAIM_REPLAY_RETENTION_SECONDS = 300
LOOPBACK_TRANSPORT_MAX_IDEMPOTENCY_KEYS_PER_PRINCIPAL = 1_024
LOOPBACK_TRANSPORT_MAX_TOMBSTONES = 8_192

_REVIEWED_ARTIFACT_PATHS = (
    "nth_dao/canonical_json.py",
    "nth_dao/plugins/builtin/loopback_transport.py",
    "nth_dao/plugins/contracts.py",
    "nth_dao/plugins/host.py",
    "nth_dao/plugins/schema.py",
    "nth_dao/plugins/transport.py",
)


def _reviewed_artifact_digest() -> str:
    root = Path(__file__).parents[3]
    files = [
        {
            "path": relative,
            "sha256": hashlib.sha256((root / relative).read_bytes()).hexdigest(),
        }
        for relative in _REVIEWED_ARTIFACT_PATHS
    ]
    document = {"format": "nth-dao-reviewed-source-set-v1", "files": files}
    return f"sha256:{hashlib.sha256(canonical_json(document)).hexdigest()}"


def loopback_transport_manifest() -> PluginManifest:
    return PluginManifest(
        manifest_version=1,
        plugin_id=LOOPBACK_TRANSPORT_PLUGIN_ID,
        version="1.0.0",
        host_api=PLUGIN_BASE_HOST_API_VERSION,
        kind="transport.provider",
        runtime="builtin",
        provides=(TRANSPORT_LOCAL_CONTRACT,),
        requires=(),
        permissions=(),
        artifact_digest=_reviewed_artifact_digest(),
    )


def loopback_route_id(principal: str) -> str:
    """Derive a non-authoritative local route without exposing principal text."""

    if not isinstance(principal, str) or not principal:
        raise ValueError("principal must be non-empty text")
    encoded = principal.encode("utf-8")
    if len(encoded) > 512:
        raise ValueError("principal is too long")
    return f"loopback:sha256:{hashlib.sha256(encoded).hexdigest()}"


@dataclass
class _Delivery:
    source_principal: str
    destination_route_id: str
    delivery_id: str
    envelope_json: str
    envelope_sha256: str
    expires_at_ms: int
    accepted_at_ms: int
    sequence: int
    byte_length: int
    fingerprint: str
    transport_delivery_id: str
    lease_id: str = ""
    lease_expires_at_ms: int = 0


@dataclass
class _ReceiveClaim:
    principal: str
    receive_id: str
    request_fingerprint: str
    lease_id: str
    lease_expires_at_ms: int
    batch_sha256: str
    delivery_keys: tuple[tuple[str, str], ...]
    retention_until_ms: int
    generation: int
    status: str = "active"
    acknowledged_count: int = 0


@dataclass(frozen=True)
class _DeliveryTombstone:
    fingerprint: str
    state: str
    expires_at_ms: int


class LoopbackTransportProvider:
    """Thread-safe, bounded, principal-scoped leased-delivery transport."""

    def __init__(self, *, clock: Callable[[], float] = time.time) -> None:
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._clock = clock
        self._lock = threading.RLock()
        self._active = True
        self._sequence = 0
        self._claim_generation = 0
        self._last_now_ms = 0
        self._deliveries: Dict[tuple[str, str], _Delivery] = {}
        self._delivery_expiries: list[
            tuple[int, int, tuple[str, str]]
        ] = []
        self._route_queues: Dict[
            str, OrderedDict[tuple[str, str], None]
        ] = {}
        self._claims: OrderedDict[tuple[str, str], _ReceiveClaim] = OrderedDict()
        self._claim_lease_expiries: list[
            tuple[int, int, tuple[str, str]]
        ] = []
        self._claim_retention_expiries: list[
            tuple[int, int, tuple[str, str]]
        ] = []
        self._delivery_tombstones: OrderedDict[
            tuple[str, str], _DeliveryTombstone
        ] = OrderedDict()
        self._tombstone_expiries: list[
            tuple[int, tuple[str, str], str]
        ] = []
        self._total_bytes = 0
        self._source_counts: Dict[str, int] = {}
        self._source_bytes: Dict[str, int] = {}
        self._claim_counts: Dict[str, int] = {}
        self._tombstone_counts: Dict[str, int] = {}
        self._route_counts: Dict[str, int] = {}
        self._route_bytes: Dict[str, int] = {}

    def deactivate(self) -> None:
        with self._lock:
            self._active = False
            self._deliveries.clear()
            self._claims.clear()
            self._claim_lease_expiries.clear()
            self._claim_retention_expiries.clear()
            self._delivery_tombstones.clear()
            self._delivery_expiries.clear()
            self._route_queues.clear()
            self._tombstone_expiries.clear()
            self._total_bytes = 0
            self._source_counts.clear()
            self._source_bytes.clear()
            self._claim_counts.clear()
            self._tombstone_counts.clear()
            self._route_counts.clear()
            self._route_bytes.clear()

    def invoke(
        self,
        payload: Mapping[str, Any],
        context: PluginInvocationContext,
    ) -> Mapping[str, Any]:
        if not isinstance(context, PluginInvocationContext):
            raise TypeError("context must be a PluginInvocationContext")
        if context.plugin_id != LOOPBACK_TRANSPORT_PLUGIN_ID:
            raise PluginInvocationError("loopback transport plugin context id mismatch")
        if context.capability_id != TRANSPORT_CAPABILITY_ID:
            raise PluginInvocationError("loopback transport capability context mismatch")
        if TRANSPORT_CAPABILITY_ID not in context.authority.capability_ids:
            raise PluginInvocationError("loopback transport authority lacks capability scope")
        if context.granted_permissions:
            raise PluginInvocationError("loopback transport accepts no permissions")
        validate_transport_input(payload)
        validate_transport_authority(payload, context.authority)
        principal = context.authority.principal
        operation = payload["operation"]
        with self._lock:
            self._require_active()
            now_ms = self._now_ms()
            self._purge(now_ms)
            if operation == "probe":
                return self._checked(self._base_response("probe", principal))
            if operation == "send":
                return self._send(payload, principal, now_ms)
            if operation == "receive":
                return self._receive(payload, principal, now_ms)
            if operation == "ack":
                return self._ack(payload, principal, now_ms)
        raise PluginInvocationError("unsupported loopback transport operation")

    def _send(
        self,
        payload: Mapping[str, Any],
        principal: str,
        now_ms: int,
    ) -> Mapping[str, Any]:
        expires_at_ms = payload["expires_at_ms"]
        key = (principal, payload["delivery_id"])
        fingerprint = self._send_fingerprint(payload)
        existing = self._deliveries.get(key)
        if existing is not None:
            if existing.fingerprint != fingerprint:
                raise TransportOperationError(
                    "conflict", "delivery_id already binds a different envelope"
                )
            state = "leased" if existing.lease_id else "queued"
            return self._checked(
                self._send_response(existing, principal, state=state, replayed=True)
            )
        tombstone = self._delivery_tombstones.get(key)
        if tombstone is not None:
            if tombstone.fingerprint != fingerprint:
                raise TransportOperationError(
                    "conflict", "delivery_id already binds a terminal envelope"
                )
            return self._checked(
                self._terminal_send_response(
                    payload,
                    principal,
                    tombstone,
                )
            )

        if expires_at_ms <= now_ms:
            raise TransportOperationError(
                "expired", "envelope expiry must be in the future"
            )
        if expires_at_ms - now_ms > LOOPBACK_TRANSPORT_MAX_TTL_SECONDS * 1_000:
            raise TransportOperationError(
                "limit-exceeded", "envelope expiry exceeds the provider TTL limit"
            )

        byte_length = len(payload["envelope_json"].encode("utf-8"))
        route = payload["destination_route_id"]
        self._require_capacity(principal, route, byte_length)
        next_sequence = self._sequence + 1
        if next_sequence > TRANSPORT_MAX_SAFE_INTEGER:
            raise TransportOperationError(
                "limit-exceeded", "transport sequence space is exhausted"
            )
        delivery = _Delivery(
            source_principal=principal,
            destination_route_id=route,
            delivery_id=payload["delivery_id"],
            envelope_json=payload["envelope_json"],
            envelope_sha256=payload["envelope_sha256"],
            expires_at_ms=expires_at_ms,
            accepted_at_ms=now_ms,
            sequence=next_sequence,
            byte_length=byte_length,
            fingerprint=fingerprint,
            transport_delivery_id=self._transport_delivery_id(
                principal, payload["delivery_id"]
            ),
        )
        self._require_single_delivery_retrievable(delivery, principal)
        response = self._checked(self._send_response(delivery, principal, state="queued"))
        self._sequence = next_sequence
        self._deliveries[key] = delivery
        self._add_usage(delivery)
        return response

    def _receive(
        self,
        payload: Mapping[str, Any],
        principal: str,
        now_ms: int,
    ) -> Mapping[str, Any]:
        claim_key = (principal, payload["receive_id"])
        request_fingerprint = self._receive_fingerprint(payload)
        prior = self._claims.get(claim_key)
        if prior is not None:
            self._claims.move_to_end(claim_key)
            if prior.request_fingerprint != request_fingerprint:
                raise TransportOperationError(
                    "conflict", "receive_id already binds different lease input"
                )
            if prior.status == "acknowledged":
                raise TransportOperationError(
                    "claim-closed", "receive claim was already acknowledged"
                )
            if prior.status == "empty":
                if prior.lease_expires_at_ms <= now_ms:
                    self._expire_claim(prior)
                    raise TransportOperationError(
                        "lease-expired", "empty receive claim lease has expired"
                    )
                return self._checked(
                    self._empty_receive_response(prior, replayed=True)
                )
            if prior.status == "expired":
                raise TransportOperationError(
                    "lease-expired", "receive claim lease has expired"
                )
            if prior.lease_expires_at_ms <= now_ms:
                self._expire_claim(prior)
                raise TransportOperationError(
                    "lease-expired", "receive claim lease has expired"
                )
            return self._checked(self._claim_response(prior, replayed=True))

        route = loopback_route_id(principal)
        candidates: list[_Delivery] = []
        for key in self._route_queues.get(route, {}):
            delivery = self._deliveries.get(key)
            if delivery is None:
                raise RuntimeError("loopback transport route index is inconsistent")
            if not delivery.lease_id:
                candidates.append(delivery)
        if not candidates:
            self._require_claim_capacity(principal, now_ms)
            lease_expires_at_ms = now_ms + payload["lease_ms"]
            claim = _ReceiveClaim(
                principal=principal,
                receive_id=payload["receive_id"],
                request_fingerprint=request_fingerprint,
                lease_id="",
                lease_expires_at_ms=lease_expires_at_ms,
                batch_sha256="",
                delivery_keys=(),
                retention_until_ms=lease_expires_at_ms,
                generation=self._next_claim_generation(),
                status="empty",
            )
            response = self._checked(self._empty_receive_response(claim))
            self._remember_claim(claim_key, claim)
            return response

        lease_id = self._lease_id(principal, payload["receive_id"], request_fingerprint)
        selected: list[_Delivery] = []
        lease_expires_at_ms = now_ms + payload["lease_ms"]
        for delivery in candidates:
            if len(selected) >= payload["limit"]:
                break
            tentative = [*selected, delivery]
            tentative_expiry = min(
                lease_expires_at_ms,
                *(item.expires_at_ms for item in tentative),
            )
            if not self._batch_fits(
                principal,
                payload["receive_id"],
                lease_id,
                tentative_expiry,
                tentative,
            ):
                break
            selected = tentative
            lease_expires_at_ms = tentative_expiry
        if not selected:
            raise TransportOperationError(
                "limit-exceeded", "delivery cannot fit in a complete receive envelope"
            )
        self._require_claim_capacity(principal, now_ms)

        items = [self._delivery_item(item) for item in selected]
        claim = _ReceiveClaim(
            principal=principal,
            receive_id=payload["receive_id"],
            request_fingerprint=request_fingerprint,
            lease_id=lease_id,
            lease_expires_at_ms=lease_expires_at_ms,
            batch_sha256=transport_batch_digest(items),
            delivery_keys=tuple(
                (item.source_principal, item.delivery_id) for item in selected
            ),
            retention_until_ms=max(item.expires_at_ms for item in selected),
            generation=self._next_claim_generation(),
        )
        response = self._checked(self._claim_response(claim, deliveries=selected))
        for delivery in selected:
            delivery.lease_id = lease_id
            delivery.lease_expires_at_ms = lease_expires_at_ms
        self._remember_claim(claim_key, claim)
        return response

    def _ack(
        self,
        payload: Mapping[str, Any],
        principal: str,
        now_ms: int,
    ) -> Mapping[str, Any]:
        claim_key = (principal, payload["receive_id"])
        claim = self._claims.get(claim_key)
        if claim is None:
            raise TransportOperationError(
                "delivery-not-found", "receive claim was not found"
            )
        self._claims.move_to_end(claim_key)
        if claim.status == "empty":
            raise TransportOperationError(
                "claim-closed", "empty receive claim cannot be acknowledged"
            )
        self._require_ack_binding(claim, payload)
        if claim.status == "acknowledged":
            return self._checked(self._ack_response(claim, principal, replayed=True))
        if claim.status == "expired" or claim.lease_expires_at_ms <= now_ms:
            if claim.status != "expired":
                self._expire_claim(claim)
            raise TransportOperationError(
                "lease-expired", "receive claim lease has expired"
            )

        deliveries: list[_Delivery] = []
        for key in claim.delivery_keys:
            delivery = self._deliveries.get(key)
            if delivery is None or delivery.lease_id != claim.lease_id:
                raise PluginInvocationError(
                    "loopback transport lease state changed under lock"
                )
            deliveries.append(delivery)
        response = self._checked(
            self._ack_response(claim, principal, count=len(deliveries))
        )
        for key, delivery in zip(claim.delivery_keys, deliveries):
            self._remember_delivery_tombstone(key, delivery, state="acknowledged")
            self._remove_delivery(key, delivery)
        claim.status = "acknowledged"
        claim.acknowledged_count = len(deliveries)
        self._shorten_claim_retention(
            claim,
            now_ms + LOOPBACK_TRANSPORT_CLAIM_REPLAY_RETENTION_SECONDS * 1_000,
        )
        self._trim_claims(now_ms)
        return response

    @staticmethod
    def _require_ack_binding(
        claim: _ReceiveClaim,
        payload: Mapping[str, Any],
    ) -> None:
        if (
            payload["lease_id"] != claim.lease_id
            or payload["batch_sha256"] != claim.batch_sha256
        ):
            raise TransportOperationError(
                "lease-conflict", "ack does not bind the active receive lease"
            )

    def _purge(self, now_ms: int) -> None:
        while (
            self._claim_lease_expiries
            and self._claim_lease_expiries[0][0] <= now_ms
        ):
            _, generation, key = heapq.heappop(self._claim_lease_expiries)
            claim = self._claims.get(key)
            if (
                claim is not None
                and claim.generation == generation
                and claim.status in {"active", "empty"}
            ):
                self._expire_claim(claim)
        while self._delivery_expiries and self._delivery_expiries[0][0] <= now_ms:
            _, sequence, key = heapq.heappop(self._delivery_expiries)
            delivery = self._deliveries.get(key)
            if delivery is not None and delivery.sequence == sequence:
                self._remove_delivery(key, delivery)
        self._prune_delivery_tombstones(now_ms)
        self._trim_claims(now_ms)

    def _expire_claim(self, claim: _ReceiveClaim) -> None:
        for key in claim.delivery_keys:
            delivery = self._deliveries.get(key)
            if delivery is not None and delivery.lease_id == claim.lease_id:
                delivery.lease_id = ""
                delivery.lease_expires_at_ms = 0
        claim.status = "expired"
        if claim.delivery_keys:
            self._shorten_claim_retention(
                claim,
                claim.lease_expires_at_ms
                + LOOPBACK_TRANSPORT_CLAIM_REPLAY_RETENTION_SECONDS * 1_000,
            )

    def _shorten_claim_retention(
        self,
        claim: _ReceiveClaim,
        deadline_ms: int,
    ) -> None:
        if deadline_ms >= claim.retention_until_ms:
            return
        claim.retention_until_ms = deadline_ms
        key = (claim.principal, claim.receive_id)
        heapq.heappush(
            self._claim_retention_expiries,
            (claim.retention_until_ms, claim.generation, key),
        )

    def _trim_claims(self, now_ms: int) -> None:
        while (
            self._claim_retention_expiries
            and self._claim_retention_expiries[0][0] <= now_ms
        ):
            _, generation, key = heapq.heappop(self._claim_retention_expiries)
            claim = self._claims.get(key)
            if claim is None or claim.generation != generation:
                continue
            if claim.status not in {"acknowledged", "expired"}:
                raise RuntimeError(
                    "loopback transport retained a live claim past its deadline"
                )
            self._remove_claim(key)

    def _require_claim_capacity(self, principal: str, now_ms: int) -> None:
        self._trim_claims(now_ms)
        if len(self._claims) >= LOOPBACK_TRANSPORT_MAX_CLAIMS:
            raise TransportOperationError(
                "quota-exceeded", "transport receive claim quota is full"
            )
        if (
            self._claim_counts.get(principal, 0)
            >= LOOPBACK_TRANSPORT_MAX_CLAIMS_PER_PRINCIPAL
        ):
            raise TransportOperationError(
                "quota-exceeded", "transport principal receive claim quota is full"
            )

    def _remember_claim(
        self,
        key: tuple[str, str],
        claim: _ReceiveClaim,
    ) -> None:
        if key in self._claims:
            raise RuntimeError("loopback transport claim key changed under lock")
        self._claims[key] = claim
        self._claim_counts[claim.principal] = (
            self._claim_counts.get(claim.principal, 0) + 1
        )
        heapq.heappush(
            self._claim_lease_expiries,
            (claim.lease_expires_at_ms, claim.generation, key),
        )
        heapq.heappush(
            self._claim_retention_expiries,
            (claim.retention_until_ms, claim.generation, key),
        )

    def _remove_claim(self, key: tuple[str, str]) -> None:
        claim = self._claims.pop(key)
        self._claim_counts[claim.principal] -= 1
        if self._claim_counts[claim.principal] == 0:
            del self._claim_counts[claim.principal]

    def _remember_delivery_tombstone(
        self,
        key: tuple[str, str],
        delivery: _Delivery,
        *,
        state: str,
    ) -> None:
        self._delivery_tombstones[key] = _DeliveryTombstone(
            fingerprint=delivery.fingerprint,
            state=state,
            expires_at_ms=delivery.expires_at_ms,
        )
        principal = key[0]
        self._tombstone_counts[principal] = (
            self._tombstone_counts.get(principal, 0) + 1
        )
        self._delivery_tombstones.move_to_end(key)
        heapq.heappush(
            self._tombstone_expiries,
            (delivery.expires_at_ms, key, delivery.fingerprint),
        )
        if len(self._delivery_tombstones) > LOOPBACK_TRANSPORT_MAX_TOMBSTONES:
            raise RuntimeError("loopback transport tombstone capacity invariant failed")

    def _prune_delivery_tombstones(self, now_ms: int) -> None:
        while self._tombstone_expiries and self._tombstone_expiries[0][0] <= now_ms:
            _, key, fingerprint = heapq.heappop(self._tombstone_expiries)
            tombstone = self._delivery_tombstones.get(key)
            if tombstone is None or tombstone.fingerprint != fingerprint:
                continue
            del self._delivery_tombstones[key]
            principal = key[0]
            self._tombstone_counts[principal] -= 1
            if self._tombstone_counts[principal] == 0:
                del self._tombstone_counts[principal]

    def _require_capacity(
        self,
        principal: str,
        route: str,
        byte_length: int,
    ) -> None:
        if byte_length > TRANSPORT_MAX_ENVELOPE_BYTES:
            raise TransportOperationError(
                "limit-exceeded", "envelope exceeds the provider byte limit"
            )
        if len(self._deliveries) >= LOOPBACK_TRANSPORT_MAX_DELIVERIES:
            raise TransportOperationError(
                "quota-exceeded", "transport global delivery quota is full"
            )
        if (
            len(self._deliveries) + len(self._delivery_tombstones)
            >= LOOPBACK_TRANSPORT_MAX_TOMBSTONES
        ):
            raise TransportOperationError(
                "quota-exceeded", "transport idempotency evidence quota is full"
            )
        if (
            self._source_counts.get(principal, 0)
            >= LOOPBACK_TRANSPORT_MAX_DELIVERIES_PER_PRINCIPAL
        ):
            raise TransportOperationError(
                "quota-exceeded", "transport sender delivery quota is full"
            )
        if (
            self._source_counts.get(principal, 0)
            + self._tombstone_counts.get(principal, 0)
            >= LOOPBACK_TRANSPORT_MAX_IDEMPOTENCY_KEYS_PER_PRINCIPAL
        ):
            raise TransportOperationError(
                "quota-exceeded", "transport sender idempotency quota is full"
            )
        if (
            self._route_counts.get(route, 0)
            >= LOOPBACK_TRANSPORT_MAX_DELIVERIES_PER_ROUTE
        ):
            raise TransportOperationError(
                "quota-exceeded", "transport destination delivery quota is full"
            )
        if self._total_bytes + byte_length > LOOPBACK_TRANSPORT_MAX_BYTES:
            raise TransportOperationError(
                "quota-exceeded", "transport global byte quota is full"
            )
        if (
            self._source_bytes.get(principal, 0) + byte_length
            > LOOPBACK_TRANSPORT_MAX_BYTES_PER_PRINCIPAL
        ):
            raise TransportOperationError(
                "quota-exceeded", "transport sender byte quota is full"
            )
        if (
            self._route_bytes.get(route, 0) + byte_length
            > LOOPBACK_TRANSPORT_MAX_BYTES_PER_ROUTE
        ):
            raise TransportOperationError(
                "quota-exceeded", "transport destination byte quota is full"
            )

    def _add_usage(self, delivery: _Delivery) -> None:
        key = (delivery.source_principal, delivery.delivery_id)
        self._total_bytes += delivery.byte_length
        self._source_counts[delivery.source_principal] = (
            self._source_counts.get(delivery.source_principal, 0) + 1
        )
        self._source_bytes[delivery.source_principal] = (
            self._source_bytes.get(delivery.source_principal, 0)
            + delivery.byte_length
        )
        self._route_counts[delivery.destination_route_id] = (
            self._route_counts.get(delivery.destination_route_id, 0) + 1
        )
        self._route_bytes[delivery.destination_route_id] = (
            self._route_bytes.get(delivery.destination_route_id, 0)
            + delivery.byte_length
        )
        self._route_queues.setdefault(
            delivery.destination_route_id, OrderedDict()
        )[key] = None
        heapq.heappush(
            self._delivery_expiries,
            (delivery.expires_at_ms, delivery.sequence, key),
        )

    def _remove_delivery(
        self,
        key: tuple[str, str],
        delivery: _Delivery,
    ) -> None:
        if self._deliveries.get(key) is not delivery:
            raise RuntimeError("loopback transport delivery identity changed under lock")
        del self._deliveries[key]
        route_queue = self._route_queues[delivery.destination_route_id]
        del route_queue[key]
        if not route_queue:
            del self._route_queues[delivery.destination_route_id]
        self._total_bytes -= delivery.byte_length
        self._source_counts[delivery.source_principal] -= 1
        self._source_bytes[delivery.source_principal] -= delivery.byte_length
        self._route_counts[delivery.destination_route_id] -= 1
        self._route_bytes[delivery.destination_route_id] -= delivery.byte_length
        if self._source_counts[delivery.source_principal] == 0:
            del self._source_counts[delivery.source_principal]
        if self._source_bytes[delivery.source_principal] == 0:
            del self._source_bytes[delivery.source_principal]
        if self._route_counts[delivery.destination_route_id] == 0:
            del self._route_counts[delivery.destination_route_id]
        if self._route_bytes[delivery.destination_route_id] == 0:
            del self._route_bytes[delivery.destination_route_id]

    def _require_single_delivery_retrievable(
        self,
        delivery: _Delivery,
        principal: str,
    ) -> None:
        lease_id = "lease:sha256:" + "0" * 64
        if not self._batch_fits(
            principal,
            "r" * 256,
            lease_id,
            delivery.expires_at_ms,
            [delivery],
        ):
            raise TransportOperationError(
                "limit-exceeded", "delivery cannot fit in a complete receive envelope"
            )

    def _batch_fits(
        self,
        principal: str,
        receive_id: str,
        lease_id: str,
        lease_expires_at_ms: int,
        deliveries: list[_Delivery],
    ) -> bool:
        items = [self._delivery_item(item) for item in deliveries]
        response = self._base_response("receive", principal)
        response.update(
            {
                "batch_sha256": transport_batch_digest(items),
                "found": True,
                "items": items,
                "lease_expires_at_ms": lease_expires_at_ms,
                "lease_id": lease_id,
                "receive_id": receive_id,
                "state": "leased",
            }
        )
        return len(canonical_json(response)) <= TRANSPORT_MAX_DOCUMENT_BYTES

    def _empty_receive_response(
        self,
        claim: _ReceiveClaim,
        *,
        replayed: bool = False,
    ) -> Dict[str, Any]:
        response = self._base_response("receive", claim.principal)
        response["receive_id"] = claim.receive_id
        response["replayed"] = replayed
        return response

    def _claim_response(
        self,
        claim: _ReceiveClaim,
        *,
        deliveries: Optional[list[_Delivery]] = None,
        replayed: bool = False,
    ) -> Dict[str, Any]:
        if deliveries is None:
            deliveries = []
            for key in claim.delivery_keys:
                delivery = self._deliveries.get(key)
                if delivery is None or delivery.lease_id != claim.lease_id:
                    raise PluginInvocationError(
                        "loopback transport claim content changed under lock"
                    )
                deliveries.append(delivery)
        response = self._base_response("receive", claim.principal)
        response.update(
            {
                "batch_sha256": claim.batch_sha256,
                "found": True,
                "items": [self._delivery_item(item) for item in deliveries],
                "lease_expires_at_ms": claim.lease_expires_at_ms,
                "lease_id": claim.lease_id,
                "receive_id": claim.receive_id,
                "replayed": replayed,
                "state": "leased",
            }
        )
        return response

    def _ack_response(
        self,
        claim: _ReceiveClaim,
        principal: str,
        *,
        count: Optional[int] = None,
        replayed: bool = False,
    ) -> Dict[str, Any]:
        response = self._base_response("ack", principal)
        response.update(
            {
                "acknowledged": True,
                "acknowledged_count": (
                    claim.acknowledged_count if count is None else count
                ),
                "batch_sha256": claim.batch_sha256,
                "lease_id": claim.lease_id,
                "receive_id": claim.receive_id,
                "replayed": replayed,
                "state": "acknowledged",
            }
        )
        return response

    def _send_response(
        self,
        delivery: _Delivery,
        principal: str,
        *,
        state: str,
        replayed: bool = False,
    ) -> Dict[str, Any]:
        response = self._base_response("send", principal)
        response.update(
            {
                "accepted": True,
                "delivery_id": delivery.delivery_id,
                "expires_at_ms": delivery.expires_at_ms,
                "replayed": replayed,
                "state": state,
                "transport_delivery_id": delivery.transport_delivery_id,
            }
        )
        return response

    def _terminal_send_response(
        self,
        payload: Mapping[str, Any],
        principal: str,
        tombstone: _DeliveryTombstone,
    ) -> Dict[str, Any]:
        response = self._base_response("send", principal)
        response.update(
            {
                "accepted": True,
                "delivery_id": payload["delivery_id"],
                "expires_at_ms": tombstone.expires_at_ms,
                "replayed": True,
                "state": tombstone.state,
                "transport_delivery_id": self._transport_delivery_id(
                    principal, payload["delivery_id"]
                ),
            }
        )
        return response

    @staticmethod
    def _delivery_item(delivery: _Delivery) -> Dict[str, Any]:
        return {
            "accepted_at_ms": delivery.accepted_at_ms,
            "delivery_id": delivery.delivery_id,
            "envelope_json": delivery.envelope_json,
            "envelope_sha256": delivery.envelope_sha256,
            "expires_at_ms": delivery.expires_at_ms,
            "transport_delivery_id": delivery.transport_delivery_id,
        }

    @staticmethod
    def _send_fingerprint(payload: Mapping[str, Any]) -> str:
        document = {
            key: payload[key]
            for key in (
                "delivery_id",
                "destination_route_id",
                "envelope_json",
                "envelope_sha256",
                "expires_at_ms",
            )
        }
        return hashlib.sha256(canonical_json(document)).hexdigest()

    @staticmethod
    def _receive_fingerprint(payload: Mapping[str, Any]) -> str:
        document = {
            key: payload[key]
            for key in ("lease_ms", "limit", "receive_id")
        }
        return hashlib.sha256(canonical_json(document)).hexdigest()

    @staticmethod
    def _lease_id(principal: str, receive_id: str, fingerprint: str) -> str:
        document = {
            "principal_sha256": hashlib.sha256(principal.encode("utf-8")).hexdigest(),
            "receive_id": receive_id,
            "request_sha256": fingerprint,
        }
        return f"lease:sha256:{hashlib.sha256(canonical_json(document)).hexdigest()}"

    @staticmethod
    def _transport_delivery_id(principal: str, delivery_id: str) -> str:
        document = {
            "delivery_id": delivery_id,
            "source_principal_sha256": hashlib.sha256(
                principal.encode("utf-8")
            ).hexdigest(),
        }
        return f"delivery:sha256:{hashlib.sha256(canonical_json(document)).hexdigest()}"

    @staticmethod
    def _base_response(operation: str, principal: str) -> Dict[str, Any]:
        return {
            "accepted": False,
            "acknowledged": False,
            "acknowledged_count": 0,
            "batch_sha256": "",
            "delivery_guarantee": "ephemeral-at-least-once-until-ack",
            "delivery_id": "",
            "detail": "",
            "expires_at_ms": 0,
            "found": False,
            "items": [],
            "lease_expires_at_ms": 0,
            "lease_id": "",
            "local_route_id": loopback_route_id(principal),
            "max_batch_size": TRANSPORT_MAX_BATCH_SIZE,
            "max_envelope_bytes": TRANSPORT_MAX_ENVELOPE_BYTES,
            "max_lease_ms": TRANSPORT_MAX_LEASE_MS,
            "max_ttl_seconds": LOOPBACK_TRANSPORT_MAX_TTL_SECONDS,
            "operation": operation,
            "ready": True,
            "receive_id": "",
            "replayed": False,
            "state": "",
            "supports_ack": True,
            "supports_streaming": False,
            "transport_id": LOOPBACK_TRANSPORT_PLUGIN_ID,
            "transport_delivery_id": "",
        }

    @staticmethod
    def _checked(response: Dict[str, Any]) -> Dict[str, Any]:
        validate_transport_output(response)
        return response

    def _now_ms(self) -> int:
        value = self._clock()
        if (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(value)
            or value < 0
            or value > TRANSPORT_MAX_SAFE_INTEGER / 1_000
        ):
            raise RuntimeError("loopback transport clock returned an invalid timestamp")
        now_ms = int(value * 1_000)
        self._last_now_ms = max(self._last_now_ms, now_ms)
        return self._last_now_ms

    def _next_claim_generation(self) -> int:
        self._claim_generation += 1
        if self._claim_generation > TRANSPORT_MAX_SAFE_INTEGER:
            raise TransportOperationError(
                "limit-exceeded", "transport claim generation space is exhausted"
            )
        return self._claim_generation

    def _require_active(self) -> None:
        if not self._active:
            raise TransportOperationError(
                "inactive", "loopback transport provider is inactive"
            )


class LoopbackTransportPlugin:
    def __init__(self) -> None:
        self._provider: Optional[LoopbackTransportProvider] = None

    def start(self, context: PluginContext) -> Mapping[str, object]:
        if context.plugin_id != LOOPBACK_TRANSPORT_PLUGIN_ID:
            raise RuntimeError("loopback transport plugin context id mismatch")
        if context.granted_permissions:
            raise PermissionError("loopback transport accepts no host permissions")
        self._provider = LoopbackTransportProvider()
        return {TRANSPORT_CAPABILITY_ID: self._provider}

    def stop(self) -> None:
        provider = self._provider
        self._provider = None
        if provider is not None:
            provider.deactivate()


def register_loopback_transport(host: PluginHost) -> PluginManifest:
    """Install the local reference transport without enabling it."""

    if not isinstance(host, PluginHost):
        raise TypeError("host must be a PluginHost")
    item = loopback_transport_manifest()
    host.register_builtin(
        item,
        LoopbackTransportPlugin,
        allow_manifest_upgrade=True,
        schemas={
            TRANSPORT_CAPABILITY_ID: CapabilitySchemas(
                TRANSPORT_INPUT_SCHEMA,
                TRANSPORT_OUTPUT_SCHEMA,
                input_validator=validate_transport_input,
                output_validator=validate_transport_output,
                exchange_validator=validate_transport_exchange,
                authority_validator=validate_transport_authority,
            )
        },
    )
    return item


__all__ = [
    "LOOPBACK_TRANSPORT_MAX_BYTES",
    "LOOPBACK_TRANSPORT_MAX_BYTES_PER_PRINCIPAL",
    "LOOPBACK_TRANSPORT_MAX_BYTES_PER_ROUTE",
    "LOOPBACK_TRANSPORT_MAX_CLAIMS",
    "LOOPBACK_TRANSPORT_MAX_CLAIMS_PER_PRINCIPAL",
    "LOOPBACK_TRANSPORT_CLAIM_REPLAY_RETENTION_SECONDS",
    "LOOPBACK_TRANSPORT_MAX_DELIVERIES",
    "LOOPBACK_TRANSPORT_MAX_DELIVERIES_PER_PRINCIPAL",
    "LOOPBACK_TRANSPORT_MAX_DELIVERIES_PER_ROUTE",
    "LOOPBACK_TRANSPORT_MAX_IDEMPOTENCY_KEYS_PER_PRINCIPAL",
    "LOOPBACK_TRANSPORT_MAX_TOMBSTONES",
    "LOOPBACK_TRANSPORT_MAX_TTL_SECONDS",
    "LOOPBACK_TRANSPORT_PLUGIN_ID",
    "LoopbackTransportPlugin",
    "LoopbackTransportProvider",
    "loopback_route_id",
    "loopback_transport_manifest",
    "register_loopback_transport",
]
