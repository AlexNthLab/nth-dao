"""Bounded in-memory reference provider for ``message.store``.

This provider is a conformance sample and an ephemeral local option. It is not
the default Channel persistence path and is installed disabled. Records are
partitioned by the host-selected local invocation principal and an explicit
namespace. Host API v1 does not authenticate a remote origin; the embedding
application must derive the principal from its verified boundary.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
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
from nth_dao.plugins.message_store import (
    MESSAGE_STORE_CAPABILITY_ID,
    MESSAGE_STORE_CONTRACT,
    MESSAGE_STORE_INPUT_SCHEMA,
    MESSAGE_STORE_MAX_DOCUMENT_BYTES,
    MESSAGE_STORE_MAX_MESSAGE_BYTES,
    MESSAGE_STORE_MAX_SAFE_INTEGER,
    MESSAGE_STORE_OUTPUT_SCHEMA,
    MessageStoreOperationError,
    validate_message_store_input,
    validate_message_store_output,
)


MEMORY_MESSAGE_STORE_PLUGIN_ID = "org.nth-dao.message.memory"
MEMORY_MESSAGE_STORE_MAX_RECORDS = 8_192
MEMORY_MESSAGE_STORE_MAX_RECORDS_PER_PRINCIPAL = 1_024
MEMORY_MESSAGE_STORE_MAX_BYTES = 67_108_864
MEMORY_MESSAGE_STORE_MAX_BYTES_PER_PRINCIPAL = 16_777_216
MEMORY_MESSAGE_STORE_MAX_TTL_SECONDS = 2_592_000
MEMORY_MESSAGE_STORE_MAX_TOMBSTONES = 8_192

_REVIEWED_ARTIFACT_PATHS = (
    "nth_dao/canonical_json.py",
    "nth_dao/plugins/builtin/memory_message_store.py",
    "nth_dao/plugins/contracts.py",
    "nth_dao/plugins/host.py",
    "nth_dao/plugins/message_store.py",
    "nth_dao/plugins/schema.py",
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


def memory_message_store_manifest() -> PluginManifest:
    return PluginManifest(
        manifest_version=1,
        plugin_id=MEMORY_MESSAGE_STORE_PLUGIN_ID,
        version="1.0.0",
        host_api=PLUGIN_BASE_HOST_API_VERSION,
        kind="message.store",
        runtime="builtin",
        provides=(MESSAGE_STORE_CONTRACT,),
        requires=(),
        permissions=(),
        artifact_digest=_reviewed_artifact_digest(),
    )


@dataclass(frozen=True)
class _StoredMessage:
    principal: str
    namespace: str
    message_id: str
    message_json: str
    message_sha256: str
    retention_mode: str
    delivery_mode: str
    expires_at_ms: int
    created_at_ms: int
    sequence: int
    byte_length: int
    put_fingerprint: str


@dataclass(frozen=True)
class _DeletionTombstone:
    message_sha256: str
    operation: str
    sequence: int


class MemoryMessageStoreProvider:
    """Thread-safe, bounded, principal-partitioned reference store."""

    def __init__(self, *, clock: Callable[[], float] = time.time) -> None:
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._clock = clock
        self._lock = threading.RLock()
        self._active = True
        self._sequence = 0
        self._last_now_ms = 0
        self._records: Dict[tuple[str, str, str], _StoredMessage] = {}
        self._tombstones: OrderedDict[
            tuple[str, str, str], _DeletionTombstone
        ] = OrderedDict()
        self._total_bytes = 0
        self._principal_counts: Dict[str, int] = {}
        self._principal_bytes: Dict[str, int] = {}

    def deactivate(self) -> None:
        with self._lock:
            self._active = False
            self._records.clear()
            self._tombstones.clear()
            self._total_bytes = 0
            self._principal_counts.clear()
            self._principal_bytes.clear()

    def invoke(
        self,
        payload: Mapping[str, Any],
        context: PluginInvocationContext,
    ) -> Mapping[str, Any]:
        if not isinstance(context, PluginInvocationContext):
            raise TypeError("context must be a PluginInvocationContext")
        if context.plugin_id != MEMORY_MESSAGE_STORE_PLUGIN_ID:
            raise PluginInvocationError("message store plugin context id mismatch")
        if context.capability_id != MESSAGE_STORE_CAPABILITY_ID:
            raise PluginInvocationError("message store capability context mismatch")
        if MESSAGE_STORE_CAPABILITY_ID not in context.authority.capability_ids:
            raise PluginInvocationError("message store authority lacks capability scope")
        if context.granted_permissions:
            raise PluginInvocationError("memory message store accepts no permissions")
        validate_message_store_input(payload)
        operation = payload["operation"]
        principal = context.authority.principal
        read_response: Dict[str, Any] | None = None
        with self._lock:
            self._require_active()
            now_ms = self._now_ms()
            self._purge_expired(now_ms)
            if operation == "probe":
                read_response = self._base_response("probe")
            elif operation == "put":
                return self._put(payload, principal, now_ms)
            elif operation == "list":
                read_response = self._list(payload, principal)
            elif operation == "get":
                read_response = self._get(payload, principal, consume=False)
            elif operation == "consume":
                return self._get(payload, principal, consume=True)
            elif operation == "delete":
                return self._delete(payload, principal)
        if read_response is None:
            raise PluginInvocationError("unsupported message store operation")
        return self._checked(read_response)

    def _put(
        self,
        payload: Mapping[str, Any],
        principal: str,
        now_ms: int,
    ) -> Mapping[str, Any]:
        expires_at_ms = payload["expires_at_ms"]
        if payload["retention_mode"] == "ttl":
            if expires_at_ms <= now_ms:
                raise MessageStoreOperationError(
                    "expired", "message expiry must be in the future"
                )
            if expires_at_ms - now_ms > MEMORY_MESSAGE_STORE_MAX_TTL_SECONDS * 1_000:
                raise MessageStoreOperationError(
                    "limit-exceeded", "message expiry exceeds the provider TTL limit"
                )
        key = (principal, payload["namespace"], payload["message_id"])
        fingerprint = self._put_fingerprint(payload)
        existing = self._records.get(key)
        if existing is not None:
            if existing.put_fingerprint != fingerprint:
                raise MessageStoreOperationError(
                    "conflict",
                    "message_id is immutable and already binds a different record"
                )
            return self._checked(self._record_response("put", existing, replayed=True))

        byte_length = len(payload["message_json"].encode("utf-8"))
        if byte_length > MESSAGE_STORE_MAX_MESSAGE_BYTES:
            raise MessageStoreOperationError(
                "limit-exceeded", "message exceeds the provider byte limit"
            )
        if len(self._records) >= MEMORY_MESSAGE_STORE_MAX_RECORDS:
            raise MessageStoreOperationError(
                "quota-exceeded", "message store global record quota is full"
            )
        if (
            self._principal_counts.get(principal, 0)
            >= MEMORY_MESSAGE_STORE_MAX_RECORDS_PER_PRINCIPAL
        ):
            raise MessageStoreOperationError(
                "quota-exceeded", "message store principal record quota is full"
            )
        if self._total_bytes + byte_length > MEMORY_MESSAGE_STORE_MAX_BYTES:
            raise MessageStoreOperationError(
                "quota-exceeded", "message store global byte quota is full"
            )
        if (
            self._principal_bytes.get(principal, 0) + byte_length
            > MEMORY_MESSAGE_STORE_MAX_BYTES_PER_PRINCIPAL
        ):
            raise MessageStoreOperationError(
                "quota-exceeded", "message store principal byte quota is full"
            )

        next_sequence = self._sequence + 1
        if next_sequence > MESSAGE_STORE_MAX_SAFE_INTEGER:
            raise MessageStoreOperationError(
                "sequence-exhausted", "message store sequence space is exhausted"
            )
        record = _StoredMessage(
            principal=principal,
            namespace=payload["namespace"],
            message_id=payload["message_id"],
            message_json=payload["message_json"],
            message_sha256=payload["message_sha256"],
            retention_mode=payload["retention_mode"],
            delivery_mode=payload["delivery_mode"],
            expires_at_ms=expires_at_ms,
            created_at_ms=now_ms,
            sequence=next_sequence,
            byte_length=byte_length,
            put_fingerprint=fingerprint,
        )
        self._require_retrievable_envelope(record)
        response = self._checked(self._record_response("put", record))
        self._sequence = next_sequence
        self._records[key] = record
        self._add_usage(record)
        return response

    def _list(
        self,
        payload: Mapping[str, Any],
        principal: str,
    ) -> Mapping[str, Any]:
        after_sequence = payload["after_sequence"]
        matching = sorted(
            (
                record
                for record in self._records.values()
                if record.principal == principal
                and record.namespace == payload["namespace"]
                and record.sequence > after_sequence
            ),
            key=lambda item: item.sequence,
        )[: payload["limit"]]
        response = self._base_response("list")
        response["found"] = bool(matching)
        response["items"] = [self._descriptor(record) for record in matching]
        response["next_sequence"] = (
            matching[-1].sequence if matching else after_sequence
        )
        return response

    def _get(
        self,
        payload: Mapping[str, Any],
        principal: str,
        *,
        consume: bool,
    ) -> Mapping[str, Any]:
        operation = "consume" if consume else "get"
        key = (principal, payload["namespace"], payload["message_id"])
        record = self._records.get(key)
        if record is None:
            if not consume:
                return self._base_response(operation)
            self._raise_missing_or_applied(key, payload)
        if consume:
            self._require_expected_generation(record, payload)
        if consume and record.delivery_mode != "consume-on-read":
            raise MessageStoreOperationError(
                "unsupported-delivery-mode",
                "read-many messages must use get or delete",
            )
        if not consume and record.delivery_mode != "read-many":
            raise MessageStoreOperationError(
                "unsupported-delivery-mode",
                "consume-on-read messages must use consume",
            )
        response = self._record_response(
            operation,
            record,
            include_content=True,
            deleted=consume,
        )
        if consume:
            checked = self._checked(response)
            self._remember_tombstone(key, record, operation="consume")
            self._remove(key, record)
            return checked
        return response

    def _delete(
        self,
        payload: Mapping[str, Any],
        principal: str,
    ) -> Mapping[str, Any]:
        key = (principal, payload["namespace"], payload["message_id"])
        record = self._records.get(key)
        if record is None:
            self._raise_missing_or_applied(key, payload)
        self._require_expected_generation(record, payload)
        response = self._base_response("delete")
        response["found"] = True
        response["deleted"] = True
        checked = self._checked(response)
        self._remember_tombstone(key, record, operation="delete")
        self._remove(key, record)
        return checked

    @staticmethod
    def _require_expected_generation(
        record: _StoredMessage,
        payload: Mapping[str, Any],
    ) -> None:
        if (
            payload["expected_sequence"] != record.sequence
            or payload["expected_message_sha256"] != record.message_sha256
        ):
            raise MessageStoreOperationError(
                "stale-generation", "destructive CAS does not match the live record"
            )

    def _raise_missing_or_applied(
        self,
        key: tuple[str, str, str],
        payload: Mapping[str, Any],
    ) -> None:
        tombstone = self._tombstones.get(key)
        if tombstone is not None and (
            tombstone.sequence == payload["expected_sequence"]
            and tombstone.message_sha256 == payload["expected_message_sha256"]
        ):
            raise MessageStoreOperationError(
                "already-applied",
                f"message {tombstone.operation} was already applied",
            )
        raise MessageStoreOperationError(
            "generation-not-found", "message generation was not found"
        )

    def _remember_tombstone(
        self,
        key: tuple[str, str, str],
        record: _StoredMessage,
        *,
        operation: str,
    ) -> None:
        self._tombstones[key] = _DeletionTombstone(
            message_sha256=record.message_sha256,
            operation=operation,
            sequence=record.sequence,
        )
        self._tombstones.move_to_end(key)
        while len(self._tombstones) > MEMORY_MESSAGE_STORE_MAX_TOMBSTONES:
            self._tombstones.popitem(last=False)

    def _purge_expired(self, now_ms: int) -> None:
        expired = [
            (key, record)
            for key, record in self._records.items()
            if record.expires_at_ms and record.expires_at_ms <= now_ms
        ]
        for key, record in expired:
            self._remove(key, record)

    def _remove(self, key: tuple[str, str, str], record: _StoredMessage) -> None:
        current = self._records.get(key)
        if current is not record:
            raise RuntimeError("message store record identity changed under lock")
        del self._records[key]
        self._total_bytes -= record.byte_length
        self._principal_counts[record.principal] -= 1
        self._principal_bytes[record.principal] -= record.byte_length
        if self._principal_counts[record.principal] == 0:
            del self._principal_counts[record.principal]
        if self._principal_bytes[record.principal] == 0:
            del self._principal_bytes[record.principal]

    def _add_usage(self, record: _StoredMessage) -> None:
        self._total_bytes += record.byte_length
        self._principal_counts[record.principal] = (
            self._principal_counts.get(record.principal, 0) + 1
        )
        self._principal_bytes[record.principal] = (
            self._principal_bytes.get(record.principal, 0) + record.byte_length
        )

    @staticmethod
    def _put_fingerprint(payload: Mapping[str, Any]) -> str:
        document = {
            key: payload[key]
            for key in (
                "delivery_mode",
                "expires_at_ms",
                "message_id",
                "message_json",
                "message_sha256",
                "namespace",
                "retention_mode",
            )
        }
        return hashlib.sha256(canonical_json(document)).hexdigest()

    def _require_retrievable_envelope(self, record: _StoredMessage) -> None:
        operation = (
            "consume" if record.delivery_mode == "consume-on-read" else "get"
        )
        response = self._record_response(
            operation,
            record,
            include_content=True,
            deleted=operation == "consume",
        )
        if len(canonical_json(response)) > MESSAGE_STORE_MAX_DOCUMENT_BYTES:
            raise MessageStoreOperationError(
                "limit-exceeded",
                "message cannot fit in a complete retrieval envelope",
            )

    @staticmethod
    def _descriptor(record: _StoredMessage) -> Dict[str, Any]:
        return {
            "created_at_ms": record.created_at_ms,
            "delivery_mode": record.delivery_mode,
            "expires_at_ms": record.expires_at_ms,
            "message_id": record.message_id,
            "message_sha256": record.message_sha256,
            "retention_mode": record.retention_mode,
            "sequence": record.sequence,
        }

    def _record_response(
        self,
        operation: str,
        record: _StoredMessage,
        *,
        include_content: bool = False,
        deleted: bool = False,
        replayed: bool = False,
    ) -> Dict[str, Any]:
        response = self._base_response(operation)
        response.update(self._descriptor(record))
        response["deleted"] = deleted
        response["found"] = True
        response["message_json"] = record.message_json if include_content else ""
        response["namespace"] = record.namespace
        response["replayed"] = replayed
        return response

    @staticmethod
    def _base_response(operation: str) -> Dict[str, Any]:
        return {
            "created_at_ms": 0,
            "deleted": False,
            "deletion_guarantee": "logical-only",
            "delivery_mode": "",
            "detail": "",
            "expires_at_ms": 0,
            "found": False,
            "items": [],
            "max_message_bytes": MESSAGE_STORE_MAX_MESSAGE_BYTES,
            "max_records_per_principal": MEMORY_MESSAGE_STORE_MAX_RECORDS_PER_PRINCIPAL,
            "max_ttl_seconds": MEMORY_MESSAGE_STORE_MAX_TTL_SECONDS,
            "message_id": "",
            "message_json": "",
            "message_sha256": "",
            "namespace": "",
            "next_sequence": 0,
            "operation": operation,
            "ready": True,
            "replayed": False,
            "retention_mode": "",
            "sequence": 0,
            "store_id": MEMORY_MESSAGE_STORE_PLUGIN_ID,
            "supported_delivery_modes": ["consume-on-read", "read-many"],
            "supported_retention_modes": ["session", "ttl"],
        }

    @staticmethod
    def _checked(response: Dict[str, Any]) -> Dict[str, Any]:
        validate_message_store_output(response)
        return response

    def _now_ms(self) -> int:
        value = self._clock()
        if (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(value)
            or value < 0
            or value > MESSAGE_STORE_MAX_SAFE_INTEGER / 1_000
        ):
            raise RuntimeError("message store clock returned an invalid timestamp")
        now_ms = int(value * 1_000)
        self._last_now_ms = max(self._last_now_ms, now_ms)
        return self._last_now_ms

    def _require_active(self) -> None:
        if not self._active:
            raise MessageStoreOperationError(
                "inactive", "message store provider is inactive"
            )


class MemoryMessageStorePlugin:
    def __init__(self) -> None:
        self._provider: Optional[MemoryMessageStoreProvider] = None

    def start(self, context: PluginContext) -> Mapping[str, object]:
        if context.plugin_id != MEMORY_MESSAGE_STORE_PLUGIN_ID:
            raise RuntimeError("memory message store plugin context id mismatch")
        if context.granted_permissions:
            raise PermissionError("memory message store accepts no host permissions")
        self._provider = MemoryMessageStoreProvider()
        return {MESSAGE_STORE_CAPABILITY_ID: self._provider}

    def stop(self) -> None:
        provider = self._provider
        self._provider = None
        if provider is not None:
            provider.deactivate()


def register_memory_message_store(host: PluginHost) -> PluginManifest:
    """Install the ephemeral reference store without enabling it."""

    if not isinstance(host, PluginHost):
        raise TypeError("host must be a PluginHost")
    item = memory_message_store_manifest()
    host.register_builtin(
        item,
        MemoryMessageStorePlugin,
        allow_manifest_upgrade=True,
        schemas={
            MESSAGE_STORE_CAPABILITY_ID: CapabilitySchemas(
                MESSAGE_STORE_INPUT_SCHEMA,
                MESSAGE_STORE_OUTPUT_SCHEMA,
                input_validator=validate_message_store_input,
                output_validator=validate_message_store_output,
            )
        },
    )
    return item


__all__ = [
    "MEMORY_MESSAGE_STORE_MAX_BYTES",
    "MEMORY_MESSAGE_STORE_MAX_BYTES_PER_PRINCIPAL",
    "MEMORY_MESSAGE_STORE_MAX_RECORDS",
    "MEMORY_MESSAGE_STORE_MAX_RECORDS_PER_PRINCIPAL",
    "MEMORY_MESSAGE_STORE_MAX_TTL_SECONDS",
    "MEMORY_MESSAGE_STORE_MAX_TOMBSTONES",
    "MEMORY_MESSAGE_STORE_PLUGIN_ID",
    "MemoryMessageStorePlugin",
    "MemoryMessageStoreProvider",
    "memory_message_store_manifest",
    "register_memory_message_store",
]
