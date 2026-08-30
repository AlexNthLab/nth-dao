"""Bounded in-memory reference provider for ``market.index``.

This provider demonstrates lifecycle, principal isolation, optimistic CAS,
quota enforcement, and snapshot-consistent search pagination. It is an
ephemeral projection only and is installed disabled by default.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
import base64
import hashlib
import hmac
import json
import math
from pathlib import Path
import secrets
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
from nth_dao.plugins.market_index import (
    MARKET_INDEX_CAPABILITY_ID,
    MARKET_INDEX_CONTRACT,
    MARKET_INDEX_INPUT_SCHEMA,
    MARKET_INDEX_MAX_CURSOR_AGE_MS,
    MARKET_INDEX_MAX_ENTRY_BYTES,
    MARKET_INDEX_MAX_SAFE_INTEGER,
    MARKET_INDEX_MUTATION_REPLAY_WINDOW_MS,
    MARKET_INDEX_OUTPUT_SCHEMA,
    MARKET_INDEX_STALE_RETENTION_MS,
    MarketIndexOperationError,
    canonical_market_index_entry,
    validate_market_index_exchange,
    validate_market_index_input,
    validate_market_index_output,
)


MEMORY_MARKET_INDEX_PLUGIN_ID = "org.nth-dao.market.memory-index"
MEMORY_MARKET_INDEX_MAX_ENTRIES = 8_192
MEMORY_MARKET_INDEX_MAX_ENTRIES_PER_PRINCIPAL = 2_048
MEMORY_MARKET_INDEX_MAX_BYTES = 67_108_864
MEMORY_MARKET_INDEX_MAX_BYTES_PER_PRINCIPAL = 16_777_216
MEMORY_MARKET_INDEX_MAX_MUTATION_RECEIPTS = 8_192
MEMORY_MARKET_INDEX_MAX_MUTATION_RECEIPTS_PER_PRINCIPAL = 2_048

_REVIEWED_ARTIFACT_PATHS = (
    "nth_dao/canonical_json.py",
    "nth_dao/did_key.py",
    "nth_dao/plugins/builtin/memory_market_index.py",
    "nth_dao/plugins/contracts.py",
    "nth_dao/plugins/host.py",
    "nth_dao/plugins/market_index.py",
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


def memory_market_index_manifest() -> PluginManifest:
    return PluginManifest(
        manifest_version=1,
        plugin_id=MEMORY_MARKET_INDEX_PLUGIN_ID,
        version="1.0.0",
        host_api=PLUGIN_BASE_HOST_API_VERSION,
        kind="market.index",
        runtime="builtin",
        provides=(MARKET_INDEX_CONTRACT,),
        requires=(),
        permissions=(),
        artifact_digest=_reviewed_artifact_digest(),
    )


@dataclass(frozen=True)
class _IndexedEntry:
    principal: str
    entry_id: str
    entry_json: str
    entry_sha256: str
    byte_length: int
    categories: tuple[str, ...]
    intents: tuple[str, ...]
    source_protocol: str
    published_at_ms: int
    not_after_ms: int
    stale: bool
    search_text: str
    title: str


@dataclass(frozen=True)
class _MutationReceipt:
    request_json: str
    response_json: str
    expires_at_ms: int


class MemoryMarketIndexProvider:
    """Thread-safe, bounded, principal-partitioned reference index."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.time,
        cursor_secret: bytes | None = None,
    ) -> None:
        if not callable(clock):
            raise TypeError("clock must be callable")
        secret = cursor_secret if cursor_secret is not None else secrets.token_bytes(32)
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError("cursor_secret must contain at least 32 bytes")
        self._clock = clock
        self._cursor_secret = bytes(secret)
        self._lock = threading.RLock()
        self._active = True
        self._records: Dict[tuple[str, str], _IndexedEntry] = {}
        self._mutation_receipts: OrderedDict[
            tuple[str, str], _MutationReceipt
        ] = OrderedDict()
        self._principal_mutation_receipt_counts: Dict[str, int] = {}
        self._principal_revisions: Dict[str, int] = {}
        self._principal_counts: Dict[str, int] = {}
        self._principal_bytes: Dict[str, int] = {}
        self._total_bytes = 0
        self._last_now_ms = 0

    def deactivate(self) -> None:
        with self._lock:
            self._active = False
            self._records.clear()
            self._mutation_receipts.clear()
            self._principal_mutation_receipt_counts.clear()
            self._principal_revisions.clear()
            self._principal_counts.clear()
            self._principal_bytes.clear()
            self._total_bytes = 0

    def invoke(
        self,
        payload: Mapping[str, Any],
        context: PluginInvocationContext,
    ) -> Mapping[str, Any]:
        self._validate_context(context)
        validate_market_index_input(payload)
        principal = context.authority.principal
        operation = payload["operation"]
        with self._lock:
            self._require_active()
            now_ms = self._now_ms()
            self._purge_expired_mutation_receipts(now_ms)
            self._purge_expired_records(now_ms)
            if operation == "probe":
                return self._checked(self._base_response("probe", principal))
            if operation == "get":
                return self._get(payload, principal)
            if operation == "search":
                return self._search(payload, principal)
            replay = self._replay_mutation(payload, principal)
            if replay is not None:
                return replay
            if operation == "upsert":
                return self._upsert(payload, principal, now_ms=now_ms)
            if operation == "remove":
                return self._remove(payload, principal, now_ms=now_ms)
        raise PluginInvocationError("unsupported market index operation")

    def _validate_context(self, context: PluginInvocationContext) -> None:
        if not isinstance(context, PluginInvocationContext):
            raise TypeError("context must be a PluginInvocationContext")
        if context.plugin_id != MEMORY_MARKET_INDEX_PLUGIN_ID:
            raise PluginInvocationError("market index plugin context id mismatch")
        if context.capability_id != MARKET_INDEX_CAPABILITY_ID:
            raise PluginInvocationError("market index capability context mismatch")
        if MARKET_INDEX_CAPABILITY_ID not in context.authority.capability_ids:
            raise PluginInvocationError("market index authority lacks capability scope")
        if context.granted_permissions:
            raise PluginInvocationError("memory market index accepts no permissions")

    def _get(self, payload: Mapping[str, Any], principal: str) -> Mapping[str, Any]:
        record = self._records.get((principal, payload["entry_id"]))
        response = self._base_response("get", principal)
        if record is None:
            return self._checked(response)
        response.update(
            {
                "entry_id": record.entry_id,
                "entry_json": record.entry_json,
                "entry_sha256": record.entry_sha256,
                "found": True,
            }
        )
        return self._checked(response)

    def _upsert(
        self,
        payload: Mapping[str, Any],
        principal: str,
        *,
        now_ms: int,
    ) -> Mapping[str, Any]:
        key = (principal, payload["entry_id"])
        existing = self._records.get(key)
        if existing is not None and existing.entry_sha256 == payload["entry_sha256"]:
            if existing.entry_json != payload["entry_json"]:
                raise PluginInvocationError("equal market digest binds unequal content")
            self._check_mutation_receipt_quota(principal, now_ms=now_ms)
            response = self._mutation_response(
                "upsert",
                principal,
                entry_id=existing.entry_id,
                entry_sha256=existing.entry_sha256,
                changed=False,
                found=True,
                replayed=True,
            )
            self._checked(response)
            self._store_mutation_receipt(payload, principal, response, now_ms=now_ms)
            return response
        expected = payload["expected_entry_sha256"]
        if existing is None:
            if expected:
                raise MarketIndexOperationError(
                    "conflict", "entry does not exist for the expected content digest"
                )
        elif expected != existing.entry_sha256:
            raise MarketIndexOperationError(
                "conflict", "expected content digest does not match the live entry"
            )

        parsed, _ = canonical_market_index_entry(payload["entry_json"])
        if (
            parsed["not_after_ms"]
            and parsed["not_after_ms"] + MARKET_INDEX_STALE_RETENTION_MS <= now_ms
        ):
            raise MarketIndexOperationError(
                "expired-entry",
                "entry is already beyond the stale-retention horizon",
            )
        byte_length = len(payload["entry_json"].encode("utf-8"))
        self._check_quota(principal, byte_length, existing)
        self._check_mutation_receipt_quota(principal, now_ms=now_ms)
        revision = self._next_revision_value(principal)
        record = _IndexedEntry(
            principal=principal,
            entry_id=payload["entry_id"],
            entry_json=payload["entry_json"],
            entry_sha256=payload["entry_sha256"],
            byte_length=byte_length,
            categories=tuple(parsed["categories"]),
            intents=tuple(parsed["intents"]),
            source_protocol=parsed["source_protocol"],
            published_at_ms=parsed["published_at_ms"],
            not_after_ms=parsed["not_after_ms"],
            stale=parsed["stale"],
            search_text=" ".join(
                [
                    parsed["title"],
                    parsed["summary"],
                    *parsed["categories"],
                    *parsed["capabilities"],
                ]
            ).casefold(),
            title=parsed["title"].casefold(),
        )
        response = self._mutation_response(
            "upsert",
            principal,
            entry_id=record.entry_id,
            entry_sha256=record.entry_sha256,
            changed=True,
            found=True,
            revision=revision,
        )
        self._checked(response)

        previous_bytes = existing.byte_length if existing is not None else 0
        self._records[key] = record
        self._principal_revisions[principal] = revision
        self._total_bytes += byte_length - previous_bytes
        self._principal_bytes[principal] = (
            self._principal_bytes.get(principal, 0) + byte_length - previous_bytes
        )
        if existing is None:
            self._principal_counts[principal] = self._principal_counts.get(principal, 0) + 1
        self._store_mutation_receipt(payload, principal, response, now_ms=now_ms)
        return response

    def _remove(
        self,
        payload: Mapping[str, Any],
        principal: str,
        *,
        now_ms: int,
    ) -> Mapping[str, Any]:
        key = (principal, payload["entry_id"])
        expected = payload["expected_entry_sha256"]
        existing = self._records.get(key)
        if existing is None:
            raise MarketIndexOperationError(
                "conflict", "entry does not exist for the expected content digest"
            )
        if existing.entry_sha256 != expected:
            raise MarketIndexOperationError(
                "conflict", "expected content digest does not match the live entry"
            )
        self._check_mutation_receipt_quota(principal, now_ms=now_ms)
        revision = self._next_revision_value(principal)
        response = self._mutation_response(
            "remove",
            principal,
            entry_id=existing.entry_id,
            entry_sha256=existing.entry_sha256,
            changed=True,
            found=False,
            removed=True,
            revision=revision,
        )
        self._checked(response)

        del self._records[key]
        self._principal_revisions[principal] = revision
        self._total_bytes -= existing.byte_length
        self._principal_bytes[principal] -= existing.byte_length
        self._principal_counts[principal] -= 1
        self._store_mutation_receipt(payload, principal, response, now_ms=now_ms)
        return response

    def _replay_mutation(
        self,
        payload: Mapping[str, Any],
        principal: str,
    ) -> Dict[str, Any] | None:
        request_json = canonical_json(dict(payload)).decode("utf-8")
        request_digest = hashlib.sha256(request_json.encode("utf-8")).hexdigest()
        key = (principal, request_digest)
        receipt = self._mutation_receipts.get(key)
        if receipt is None:
            return None
        if not hmac.compare_digest(receipt.request_json, request_json):
            raise PluginInvocationError("equal mutation digest binds unequal request")
        self._mutation_receipts.move_to_end(key)
        response = json.loads(receipt.response_json)
        return self._checked(response)

    def _check_mutation_receipt_quota(self, principal: str, *, now_ms: int) -> None:
        if now_ms > MARKET_INDEX_MAX_SAFE_INTEGER - MARKET_INDEX_MUTATION_REPLAY_WINDOW_MS:
            raise MarketIndexOperationError(
                "limit-exceeded", "mutation replay retention time exceeds the wire range"
            )
        if len(self._mutation_receipts) >= MEMORY_MARKET_INDEX_MAX_MUTATION_RECEIPTS:
            raise MarketIndexOperationError(
                "quota-exceeded", "mutation replay retention capacity is full"
            )
        if (
            self._principal_mutation_receipt_counts.get(principal, 0)
            >= MEMORY_MARKET_INDEX_MAX_MUTATION_RECEIPTS_PER_PRINCIPAL
        ):
            raise MarketIndexOperationError(
                "quota-exceeded", "principal mutation replay retention capacity is full"
            )

    def _store_mutation_receipt(
        self,
        payload: Mapping[str, Any],
        principal: str,
        response: Mapping[str, Any],
        *,
        now_ms: int,
    ) -> None:
        request_json = canonical_json(dict(payload)).decode("utf-8")
        request_digest = hashlib.sha256(request_json.encode("utf-8")).hexdigest()
        key = (principal, request_digest)
        if key in self._mutation_receipts:
            raise PluginInvocationError("mutation receipt was inserted concurrently")
        self._mutation_receipts[key] = _MutationReceipt(
            request_json=request_json,
            response_json=canonical_json(
                {
                    **dict(response),
                    "changed": False,
                    "replayed": True,
                }
            ).decode("utf-8"),
            expires_at_ms=now_ms + MARKET_INDEX_MUTATION_REPLAY_WINDOW_MS,
        )
        self._principal_mutation_receipt_counts[principal] = (
            self._principal_mutation_receipt_counts.get(principal, 0) + 1
        )
        self._mutation_receipts.move_to_end(key)

    def _purge_expired_mutation_receipts(self, now_ms: int) -> None:
        expired = [
            key
            for key, receipt in self._mutation_receipts.items()
            if receipt.expires_at_ms <= now_ms
        ]
        for key in expired:
            principal = key[0]
            self._drop_mutation_receipt(key)
            self._cleanup_principal_if_unused(principal)

    def _drop_mutation_receipt(self, key: tuple[str, str]) -> None:
        del self._mutation_receipts[key]
        principal = key[0]
        remaining = self._principal_mutation_receipt_counts.get(principal, 0) - 1
        if remaining > 0:
            self._principal_mutation_receipt_counts[principal] = remaining
        else:
            self._principal_mutation_receipt_counts.pop(principal, None)

    def _purge_expired_records(self, now_ms: int) -> None:
        expired_by_principal: Dict[str, list[tuple[str, str]]] = {}
        for key, record in self._records.items():
            if (
                record.not_after_ms
                and record.not_after_ms + MARKET_INDEX_STALE_RETENTION_MS <= now_ms
            ):
                expired_by_principal.setdefault(record.principal, []).append(key)
        if not expired_by_principal:
            return

        next_revisions = {
            principal: self._next_revision_value(principal)
            for principal in expired_by_principal
        }
        for principal, keys in expired_by_principal.items():
            removed_bytes = 0
            for key in keys:
                removed_bytes += self._records.pop(key).byte_length
            self._total_bytes -= removed_bytes
            self._principal_bytes[principal] -= removed_bytes
            self._principal_counts[principal] -= len(keys)
            self._principal_revisions[principal] = next_revisions[principal]
            self._cleanup_principal_if_unused(principal)

    def _search(
        self,
        payload: Mapping[str, Any],
        principal: str,
    ) -> Mapping[str, Any]:
        revision = self._principal_revisions.get(principal, 0)
        cursor = payload["cursor"]
        query_sha256 = self._search_query_digest(payload)
        if cursor:
            cursor_value = self._decode_cursor(
                cursor,
                principal,
                query_sha256=query_sha256,
            )
            if cursor_value["revision"] != revision:
                raise MarketIndexOperationError(
                    "stale-cursor", "market index changed during pagination"
                )
            snapshot_ms = cursor_value["snapshot_ms"]
            after_key = (
                cursor_value["score_key"],
                cursor_value["published_key"],
                cursor_value["entry_id"],
            )
        else:
            snapshot_ms = self._now_ms()
            after_key = None

        query = payload["q"].strip().casefold()
        wanted_categories = set(payload["categories"])
        wanted_intents = set(payload["intents"])
        wanted_protocols = set(payload["source_protocols"])
        ranked: list[tuple[tuple[int, int, str], _IndexedEntry, int]] = []
        for (record_principal, _), record in self._records.items():
            if record_principal != principal:
                continue
            stale = record.stale or bool(
                record.not_after_ms and record.not_after_ms <= snapshot_ms
            )
            if stale and not payload["include_stale"]:
                continue
            if wanted_categories and not wanted_categories.intersection(record.categories):
                continue
            if wanted_intents and not wanted_intents.intersection(record.intents):
                continue
            if wanted_protocols and record.source_protocol not in wanted_protocols:
                continue
            score = self._score(record, query)
            if query and score == 0:
                continue
            key = (-score, -record.published_at_ms, record.entry_id)
            if after_key is not None and key <= after_key:
                continue
            ranked.append((key, record, score))
        ranked.sort(key=lambda item: item[0])
        limit = payload["limit"]
        selected = ranked[:limit]
        response = self._base_response("search", principal)
        response["items"] = [
            {
                "entry_id": record.entry_id,
                "entry_json": record.entry_json,
                "entry_sha256": record.entry_sha256,
                "score": score,
            }
            for _, record, score in selected
        ]
        response["found"] = bool(selected)
        if len(ranked) > limit and selected:
            last_key = selected[-1][0]
            response["next_cursor"] = self._encode_cursor(
                principal,
                revision=revision,
                snapshot_ms=snapshot_ms,
                key=last_key,
                query_sha256=query_sha256,
            )
        return self._checked(response)

    @staticmethod
    def _score(record: _IndexedEntry, query: str) -> int:
        if not query:
            return 0
        if record.title == query:
            return 100
        if record.title.startswith(query):
            return 80
        if query in record.title:
            return 60
        if any(query == item.casefold() for item in record.categories):
            return 40
        if query in record.search_text:
            return 20
        return 0

    def _cleanup_principal_if_unused(self, principal: str) -> None:
        if any(record_principal == principal for record_principal, _ in self._records):
            return
        if any(
            item_principal == principal
            for item_principal, _request_digest in self._mutation_receipts
        ):
            return
        self._principal_revisions.pop(principal, None)
        self._principal_counts.pop(principal, None)
        self._principal_bytes.pop(principal, None)
        self._principal_mutation_receipt_counts.pop(principal, None)

    def _check_quota(
        self,
        principal: str,
        byte_length: int,
        existing: _IndexedEntry | None,
    ) -> None:
        if byte_length > MARKET_INDEX_MAX_ENTRY_BYTES:
            raise MarketIndexOperationError("limit-exceeded", "entry exceeds wire limit")
        old_bytes = existing.byte_length if existing is not None else 0
        new_record = existing is None
        if new_record and len(self._records) >= MEMORY_MARKET_INDEX_MAX_ENTRIES:
            raise MarketIndexOperationError("quota-exceeded", "global entry quota is full")
        if (
            new_record
            and self._principal_counts.get(principal, 0)
            >= MEMORY_MARKET_INDEX_MAX_ENTRIES_PER_PRINCIPAL
        ):
            raise MarketIndexOperationError(
                "quota-exceeded", "principal entry quota is full"
            )
        if self._total_bytes - old_bytes + byte_length > MEMORY_MARKET_INDEX_MAX_BYTES:
            raise MarketIndexOperationError("quota-exceeded", "global byte quota is full")
        if (
            self._principal_bytes.get(principal, 0) - old_bytes + byte_length
            > MEMORY_MARKET_INDEX_MAX_BYTES_PER_PRINCIPAL
        ):
            raise MarketIndexOperationError(
                "quota-exceeded", "principal byte quota is full"
            )

    def _base_response(self, operation: str, principal: str) -> Dict[str, Any]:
        return {
            "changed": False,
            "detail": "",
            "entry_id": "",
            "entry_json": "",
            "entry_sha256": "",
            "found": False,
            "index_id": MEMORY_MARKET_INDEX_PLUGIN_ID,
            "items": [],
            "max_entries_per_principal": MEMORY_MARKET_INDEX_MAX_ENTRIES_PER_PRINCIPAL,
            "max_entry_bytes": MARKET_INDEX_MAX_ENTRY_BYTES,
            "next_cursor": "",
            "operation": operation,
            "ready": True,
            "removed": False,
            "replayed": False,
            "revision": self._principal_revisions.get(principal, 0),
        }

    def _mutation_response(
        self,
        operation: str,
        principal: str,
        *,
        entry_id: str,
        entry_sha256: str,
        changed: bool,
        found: bool,
        removed: bool = False,
        replayed: bool = False,
        revision: int | None = None,
    ) -> Dict[str, Any]:
        response = self._base_response(operation, principal)
        response.update(
            {
                "changed": changed,
                "entry_id": entry_id,
                "entry_sha256": entry_sha256,
                "found": found,
                "removed": removed,
                "replayed": replayed,
            }
        )
        if revision is not None:
            response["revision"] = revision
        return response

    def _next_revision_value(self, principal: str) -> int:
        revision = self._principal_revisions.get(principal, 0)
        if revision >= MARKET_INDEX_MAX_SAFE_INTEGER:
            raise MarketIndexOperationError(
                "limit-exceeded", "principal revision range is exhausted"
            )
        return revision + 1

    def _encode_cursor(
        self,
        principal: str,
        *,
        revision: int,
        snapshot_ms: int,
        key: tuple[int, int, str],
        query_sha256: str,
    ) -> str:
        body = canonical_json(
            {
                "entry_id": key[2],
                "principal_sha256": hashlib.sha256(principal.encode("utf-8")).hexdigest(),
                "published_key": key[1],
                "query_sha256": query_sha256,
                "revision": revision,
                "score_key": key[0],
                "snapshot_ms": snapshot_ms,
                "version": 1,
            }
        )
        signature = hmac.new(self._cursor_secret, body, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(body + signature).rstrip(b"=").decode("ascii")

    def _decode_cursor(
        self,
        token: str,
        principal: str,
        *,
        query_sha256: str,
    ) -> Dict[str, Any]:
        try:
            padding = "=" * (-len(token) % 4)
            raw = base64.b64decode(token + padding, altchars=b"-_", validate=True)
            canonical_token = (
                base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
            )
            if not hmac.compare_digest(token, canonical_token):
                raise ValueError("cursor base64url encoding is not canonical")
            if len(raw) <= 32:
                raise ValueError("cursor is too short")
            body, signature = raw[:-32], raw[-32:]
            expected = hmac.new(self._cursor_secret, body, hashlib.sha256).digest()
            if not hmac.compare_digest(signature, expected):
                raise ValueError("cursor signature mismatch")
            value = json.loads(body)
            if not isinstance(value, dict) or set(value) != {
                "entry_id",
                "principal_sha256",
                "published_key",
                "query_sha256",
                "revision",
                "score_key",
                "snapshot_ms",
                "version",
            }:
                raise ValueError("cursor shape mismatch")
            if canonical_json(value) != body or value["version"] != 1:
                raise ValueError("cursor encoding mismatch")
            expected_principal = hashlib.sha256(principal.encode("utf-8")).hexdigest()
            if not hmac.compare_digest(value["principal_sha256"], expected_principal):
                raise ValueError("cursor principal mismatch")
            if not hmac.compare_digest(value["query_sha256"], query_sha256):
                raise ValueError("cursor query mismatch")
            from nth_dao.plugins.market_index import validate_market_index_identifier

            validate_market_index_identifier(value["entry_id"], field="entry_id")
            for field in ("published_key", "revision", "score_key", "snapshot_ms"):
                item = value[field]
                if isinstance(item, bool) or not isinstance(item, int):
                    raise ValueError("cursor integer is invalid")
                if not -MARKET_INDEX_MAX_SAFE_INTEGER <= item <= MARKET_INDEX_MAX_SAFE_INTEGER:
                    raise ValueError("cursor integer exceeds the safe range")
            if value["revision"] < 0 or value["snapshot_ms"] < 0:
                raise ValueError("cursor state is invalid")
            now_ms = self._now_ms()
            if (
                value["snapshot_ms"] > now_ms
                or now_ms - value["snapshot_ms"] > MARKET_INDEX_MAX_CURSOR_AGE_MS
            ):
                raise ValueError("cursor snapshot expired")
            return value
        except (UnicodeEncodeError, ValueError, json.JSONDecodeError, TypeError) as exc:
            raise MarketIndexOperationError("invalid-cursor", "search cursor is invalid") from exc

    @staticmethod
    def _search_query_digest(payload: Mapping[str, Any]) -> str:
        query = {
            "categories": list(payload["categories"]),
            "include_stale": payload["include_stale"],
            "intents": list(payload["intents"]),
            "limit": payload["limit"],
            "q": payload["q"].strip().casefold(),
            "source_protocols": list(payload["source_protocols"]),
            "version": 1,
        }
        return hashlib.sha256(canonical_json(query)).hexdigest()

    def _now_ms(self) -> int:
        value = self._clock()
        if (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(value)
            or value < 0
            or value > MARKET_INDEX_MAX_SAFE_INTEGER / 1_000
        ):
            raise RuntimeError("market index clock returned an invalid timestamp")
        now_ms = int(value * 1_000)
        self._last_now_ms = max(self._last_now_ms, now_ms)
        return self._last_now_ms

    @staticmethod
    def _checked(response: Dict[str, Any]) -> Dict[str, Any]:
        validate_market_index_output(response)
        return response

    def _require_active(self) -> None:
        if not self._active:
            raise MarketIndexOperationError("inactive", "market index provider is inactive")


class MemoryMarketIndexPlugin:
    def __init__(self) -> None:
        self._provider: Optional[MemoryMarketIndexProvider] = None

    def start(self, context: PluginContext) -> Mapping[str, object]:
        if context.plugin_id != MEMORY_MARKET_INDEX_PLUGIN_ID:
            raise RuntimeError("memory market index plugin context id mismatch")
        if context.granted_permissions:
            raise PermissionError("memory market index accepts no host permissions")
        self._provider = MemoryMarketIndexProvider()
        return {MARKET_INDEX_CAPABILITY_ID: self._provider}

    def stop(self) -> None:
        provider = self._provider
        self._provider = None
        if provider is not None:
            provider.deactivate()


def register_memory_market_index(host: PluginHost) -> PluginManifest:
    """Install the non-authoritative ephemeral reference index without enabling it."""

    if not isinstance(host, PluginHost):
        raise TypeError("host must be a PluginHost")
    item = memory_market_index_manifest()
    host.register_builtin(
        item,
        MemoryMarketIndexPlugin,
        allow_manifest_upgrade=True,
        schemas={
            MARKET_INDEX_CAPABILITY_ID: CapabilitySchemas(
                MARKET_INDEX_INPUT_SCHEMA,
                MARKET_INDEX_OUTPUT_SCHEMA,
                input_validator=validate_market_index_input,
                output_validator=validate_market_index_output,
                exchange_validator=validate_market_index_exchange,
            )
        },
    )
    return item


__all__ = [
    "MEMORY_MARKET_INDEX_MAX_BYTES",
    "MEMORY_MARKET_INDEX_MAX_BYTES_PER_PRINCIPAL",
    "MEMORY_MARKET_INDEX_MAX_ENTRIES",
    "MEMORY_MARKET_INDEX_MAX_ENTRIES_PER_PRINCIPAL",
    "MEMORY_MARKET_INDEX_MAX_MUTATION_RECEIPTS",
    "MEMORY_MARKET_INDEX_MAX_MUTATION_RECEIPTS_PER_PRINCIPAL",
    "MEMORY_MARKET_INDEX_PLUGIN_ID",
    "MemoryMarketIndexPlugin",
    "MemoryMarketIndexProvider",
    "memory_market_index_manifest",
    "register_memory_market_index",
]
