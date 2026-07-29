"""Immutable bilateral Order snapshots for Trade Offer v2."""

from __future__ import annotations

import hashlib
import math
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nth_dao.trade_rules.agreement import (
    TradeAcceptance,
    TradeAgreementRejected,
    TradeProposal,
    acceptance_digest,
    proposal_digest,
    verify_acceptance_binding,
)
from nth_dao.trade_rules.canonical import (
    MAX_TRADE_JSON_BYTES,
    TradeCanonicalJSONError,
    parse_trade_json,
    trade_canonical_json,
)
from nth_dao.trade_rules.offer import TradeOffer, offer_digest
from nth_dao.util.io import InterProcessLock
from nth_dao.util.jsonl_safe import LOCK_TIMEOUT_PATIENT

ORDER_KIND = "nth.dao.trade.order"
ORDER_PROTOCOL_VERSION = "1"
ORDER_ID_PREFIX = "nth-trade-order-sha256:"
DEFAULT_MAX_TRADE_ORDERS = 4_096
DEFAULT_MAX_TRADE_ORDER_STORE_BYTES = 256 * 1024 * 1024

_DIGEST = re.compile(r"^sha256:([0-9a-f]{64})$")
_ORDER_ID = re.compile(r"^nth-trade-order-sha256:([0-9a-f]{64})$")
_ORDER_FILE = re.compile(r"^([0-9a-f]{64})\.json$")
_CONFLICT_FILE = re.compile(
    r"^([0-9a-f]{16})\.([0-9a-f]{64})\.conflict\.json$"
)
_ORDER_FIELDS = frozenset(
    {
        "kind",
        "protocol_version",
        "order_id",
        "proposal_digest",
        "acceptance_digest",
        "offer_digest",
        "maker_did",
        "taker_did",
        "rule_bindings",
        "policy_digests",
        "created_at",
        "snapshot",
    }
)
_POLICY_FIELDS = frozenset({"maker", "taker"})
_SNAPSHOT_FIELDS = frozenset({"offer", "proposal", "acceptance"})


class TradeOrderRejected(ValueError):
    """An Order snapshot is malformed or its nested signatures do not bind."""


class TradeOrderConflict(RuntimeError):
    """One proposal-derived Order ID already contains different accepted bytes."""


class TradeOrderStoreBusy(RuntimeError):
    """Another process owns the Trade Order store lock."""


class TradeOrderStoreCapacity(RuntimeError):
    """The configured Trade Order CAS cache bound was exceeded."""


@dataclass(frozen=True)
class TradeOrderReconciliationReport:
    temporary_files: tuple[str, ...]
    corrupt_files: tuple[str, ...]
    orphan_conflicts: tuple[str, ...]
    removed_temporary_files: tuple[str, ...]


def _reject(message: str) -> None:
    raise TradeOrderRejected(message)


def _verified_order_document(document: dict[str, Any]) -> bytes:
    if not isinstance(document, dict) or set(document) != _ORDER_FIELDS:
        _reject("order has missing or unknown fields")
    if document["kind"] != ORDER_KIND:
        _reject("wrong order kind")
    if document["protocol_version"] != ORDER_PROTOCOL_VERSION:
        _reject("unsupported order protocol_version")
    order_id = document["order_id"]
    order_match = (
        _ORDER_ID.fullmatch(order_id) if isinstance(order_id, str) else None
    )
    if order_match is None:
        _reject("order_id is invalid")
    for field in ("proposal_digest", "acceptance_digest", "offer_digest"):
        value = document[field]
        if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
            _reject(f"{field} is invalid")
    policy = document["policy_digests"]
    if not isinstance(policy, dict) or set(policy) != _POLICY_FIELDS:
        _reject("policy_digests has missing or unknown fields")
    if any(
        not isinstance(value, str) or _DIGEST.fullmatch(value) is None
        for value in policy.values()
    ):
        _reject("policy digest is invalid")
    snapshot = document["snapshot"]
    if not isinstance(snapshot, dict) or set(snapshot) != _SNAPSHOT_FIELDS:
        _reject("snapshot has missing or unknown fields")
    try:
        offer = TradeOffer.from_dict(snapshot["offer"])
        proposal = TradeProposal.from_dict(snapshot["proposal"])
        acceptance = TradeAcceptance.from_dict(snapshot["acceptance"])
    except (TypeError, ValueError, TradeAgreementRejected) as exc:
        raise TradeOrderRejected(f"order snapshot rejected: {exc}") from exc
    ok, reason = verify_acceptance_binding(proposal, acceptance)
    if not ok:
        _reject(f"order agreement rejected: {reason}")
    proposal_document = proposal.to_dict()
    acceptance_document = acceptance.to_dict()
    expected_proposal_digest = proposal_digest(proposal)
    expected_acceptance_digest = acceptance_digest(acceptance)
    expected_offer_digest = offer_digest(offer)
    if document["proposal_digest"] != expected_proposal_digest:
        _reject("order proposal_digest mismatch")
    if document["acceptance_digest"] != expected_acceptance_digest:
        _reject("order acceptance_digest mismatch")
    if document["offer_digest"] != expected_offer_digest:
        _reject("order offer_digest mismatch")
    if proposal_document["offer_digest"] != expected_offer_digest:
        _reject("proposal is not bound to the Order Offer")
    if proposal_document["offer_id"] != offer.offer_id:
        _reject("proposal offer_id mismatch")
    if proposal_document["offer_revision"] != offer.to_dict()["revision"]:
        _reject("proposal offer_revision mismatch")
    if proposal_document["offer_publisher_did"] != offer.publisher_did:
        _reject("proposal Offer publisher mismatch")
    offer_rule_bindings = {
        (item["rule_id"], item["digest"])
        for item in offer.to_dict()["rule_refs"]
    }
    proposal_rule_bindings = {
        (item["rule_id"], item["digest"])
        for item in proposal_document["rule_bindings"]
    }
    if not offer_rule_bindings.issubset(proposal_rule_bindings):
        _reject("proposal omits a required Offer root Rule Package")
    if (
        document["maker_did"] != proposal_document["maker_did"]
        or document["taker_did"] != proposal_document["taker_did"]
    ):
        _reject("order party binding mismatch")
    if document["rule_bindings"] != proposal_document["rule_bindings"]:
        _reject("order rule_bindings mismatch")
    if document["policy_digests"] != {
        "maker": acceptance_document["maker_policy_digest"],
        "taker": proposal_document["taker_policy_digest"],
    }:
        _reject("order policy_digests mismatch")
    if document["created_at"] != acceptance_document["created_at"]:
        _reject("order created_at mismatch")
    if order_match.group(1) != expected_proposal_digest.removeprefix("sha256:"):
        _reject("order_id is not derived from proposal_digest")
    try:
        return trade_canonical_json(document)
    except TradeCanonicalJSONError as exc:
        raise TradeOrderRejected(str(exc)) from exc


@dataclass(frozen=True, init=False)
class TradeOrder:
    _canonical_bytes: bytes

    @classmethod
    def _create(cls, canonical: bytes) -> "TradeOrder":
        value = object.__new__(cls)
        object.__setattr__(value, "_canonical_bytes", bytes(canonical))
        return value

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> "TradeOrder":
        return cls._create(_verified_order_document(document))

    @classmethod
    def from_json(cls, raw: bytes | str) -> "TradeOrder":
        try:
            return cls.from_dict(parse_trade_json(raw))
        except TradeCanonicalJSONError as exc:
            raise TradeOrderRejected(str(exc)) from exc

    @property
    def canonical_bytes(self) -> bytes:
        return self._canonical_bytes

    @property
    def order_id(self) -> str:
        return self.to_dict()["order_id"]

    def to_dict(self) -> dict[str, Any]:
        return parse_trade_json(self._canonical_bytes)


def create_trade_order(
    *,
    offer: TradeOffer,
    proposal: TradeProposal,
    acceptance: TradeAcceptance,
) -> TradeOrder:
    verified_offer = TradeOffer.from_json(offer.canonical_bytes)
    verified_proposal = TradeProposal.from_json(proposal.canonical_bytes)
    verified_acceptance = TradeAcceptance.from_json(
        acceptance.canonical_bytes
    )
    ok, reason = verify_acceptance_binding(
        verified_proposal,
        verified_acceptance,
    )
    if not ok:
        _reject(reason)
    proposal_document = verified_proposal.to_dict()
    acceptance_document = verified_acceptance.to_dict()
    proposal_hash = proposal_digest(verified_proposal)
    document = {
        "kind": ORDER_KIND,
        "protocol_version": ORDER_PROTOCOL_VERSION,
        "order_id": ORDER_ID_PREFIX + proposal_hash.removeprefix("sha256:"),
        "proposal_digest": proposal_hash,
        "acceptance_digest": acceptance_digest(verified_acceptance),
        "offer_digest": offer_digest(verified_offer),
        "maker_did": proposal_document["maker_did"],
        "taker_did": proposal_document["taker_did"],
        "rule_bindings": proposal_document["rule_bindings"],
        "policy_digests": {
            "maker": acceptance_document["maker_policy_digest"],
            "taker": proposal_document["taker_policy_digest"],
        },
        "created_at": acceptance_document["created_at"],
        "snapshot": {
            "offer": verified_offer.to_dict(),
            "proposal": proposal_document,
            "acceptance": acceptance_document,
        },
    }
    return TradeOrder.from_dict(document)


def trade_order_digest(order: TradeOrder | dict[str, Any]) -> str:
    verified = (
        TradeOrder.from_json(order.canonical_bytes)
        if isinstance(order, TradeOrder)
        else TradeOrder.from_dict(order)
    )
    return "sha256:" + hashlib.sha256(verified.canonical_bytes).hexdigest()


class TradeOrderStore:
    """Bounded local CAS cache for verified Trade Order v2 snapshots.

    The API never overwrites accepted bytes, but this cache is not an audit
    ledger. A durable Spine outbox must anchor accepted Order digests before
    callers treat persistence as rollback-evident.
    """

    def __init__(
        self,
        root: str | Path,
        *,
        max_orders: int = DEFAULT_MAX_TRADE_ORDERS,
        max_bytes: int = DEFAULT_MAX_TRADE_ORDER_STORE_BYTES,
        lock_timeout: float = LOCK_TIMEOUT_PATIENT,
    ) -> None:
        if (
            isinstance(max_orders, bool)
            or not isinstance(max_orders, int)
            or max_orders < 1
        ):
            raise ValueError("max_orders must be a positive integer")
        if (
            isinstance(max_bytes, bool)
            or not isinstance(max_bytes, int)
            or max_bytes < MAX_TRADE_JSON_BYTES
        ):
            raise ValueError(
                f"max_bytes must be at least {MAX_TRADE_JSON_BYTES}"
            )
        if (
            isinstance(lock_timeout, bool)
            or not isinstance(lock_timeout, (int, float))
            or not math.isfinite(lock_timeout)
            or lock_timeout <= 0
        ):
            raise ValueError("lock_timeout must be a finite positive number")
        self.workspace_root = Path(root)
        self.root = self.workspace_root / "trade" / "orders_v2"
        self.lock_path = self.root / ".locks" / "orders"
        self.max_orders = max_orders
        self.max_bytes = max_bytes
        self.lock_timeout = float(lock_timeout)

    @staticmethod
    def _is_linklike(path: Path) -> bool:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        if is_junction and is_junction():
            return True
        if os.name == "nt":
            try:
                metadata = os.lstat(path)
            except FileNotFoundError:
                return False
            return bool(
                getattr(metadata, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            )
        return False

    def _assert_path(self, path: Path) -> None:
        try:
            relative = path.relative_to(self.workspace_root)
        except ValueError as exc:
            raise TradeOrderRejected(
                "order-store path escapes workspace root"
            ) from exc
        candidates = [self.workspace_root]
        current = self.workspace_root
        for part in relative.parts:
            current = current / part
            candidates.append(current)
        for candidate in candidates:
            if self._is_linklike(candidate):
                raise TradeOrderRejected(
                    "order store must not contain symlinks or junctions"
                )

    def _path(self, order_id: str) -> Path:
        match = (
            _ORDER_ID.fullmatch(order_id)
            if isinstance(order_id, str)
            else None
        )
        if match is None:
            raise TradeOrderRejected("order_id is invalid")
        return self.root / f"{match.group(1)}.json"

    def _actual_lock_path(self) -> Path:
        return Path(str(self.lock_path) + ".lock")

    def _conflict_path(self, order: TradeOrder) -> Path:
        order_suffix = order.order_id.removeprefix(ORDER_ID_PREFIX)
        key = hashlib.sha256(
            (
                order.order_id
                + "\x00"
                + trade_order_digest(order)
            ).encode("ascii")
        ).hexdigest()
        return self.root / (
            f"{order_suffix[:16]}.{key}.conflict.json"
        )

    def _conflict_paths(self, order_id: str) -> tuple[Path, ...]:
        order_path = self._path(order_id)
        order_prefix = order_path.stem[:16]
        output: list[Path] = []
        for path in sorted(
            self.root.glob(f"{order_prefix}.*.conflict.json")
        ):
            conflict = TradeOrder.from_json(self._read(path))
            if conflict.order_id == order_id:
                output.append(path)
        return tuple(output)

    def _acquire(self):
        lock_directory = self.lock_path.parent
        self._assert_path(lock_directory)
        try:
            lock_directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise TradeOrderRejected(
                f"unable to create Trade Order lock directory: {exc}"
            ) from exc
        self._assert_path(lock_directory)
        self._assert_path(self._actual_lock_path())
        return InterProcessLock(self.lock_path, timeout=self.lock_timeout)

    def _read(self, path: Path) -> bytes:
        self._assert_path(path)
        try:
            size = path.stat().st_size
            if size > MAX_TRADE_JSON_BYTES:
                raise TradeOrderRejected("stored order exceeds byte limit")
            payload = path.read_bytes()
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise TradeOrderRejected(f"unable to read stored order: {exc}") from exc
        if len(payload) != size:
            raise TradeOrderRejected("stored order changed while being read")
        return payload

    def _atomic_write(self, path: Path, payload: bytes) -> None:
        descriptor: int | None = None
        temporary: str | None = None
        try:
            try:
                self._assert_path(path.parent)
                path.parent.mkdir(parents=True, exist_ok=True)
                self._assert_path(path.parent)
                self._assert_path(path)
                descriptor, temporary = tempfile.mkstemp(
                    prefix=path.name + ".",
                    suffix=".tmp",
                    dir=str(path.parent),
                )
                with os.fdopen(descriptor, "wb") as stream:
                    descriptor = None
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, path)
                temporary = None
                if os.name != "nt":
                    directory = os.open(
                        path.parent,
                        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
                    )
                    try:
                        os.fsync(directory)
                    finally:
                        os.close(directory)
            except OSError as exc:
                raise TradeOrderRejected(
                    f"unable to persist Trade Order: {exc}"
                ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass

    def _usage_locked(self) -> tuple[int, int]:
        if not self.root.exists():
            return 0, 0
        count = 0
        total = 0
        for path in self.root.rglob("*"):
            relative = path.relative_to(self.root)
            if self._is_linklike(path):
                raise TradeOrderRejected(
                    "order store must not contain symlinks or junctions"
                )
            if relative.parts and relative.parts[0] == ".locks":
                continue
            if path.is_dir():
                raise TradeOrderRejected("order store contains a directory")
            if path.name.endswith(".tmp"):
                raise TradeOrderRejected(
                    "order store contains temporary crash residue"
                )
            if (
                _ORDER_FILE.fullmatch(path.name) is None
                and _CONFLICT_FILE.fullmatch(path.name) is None
            ):
                raise TradeOrderRejected("order store contains an unknown file")
            if _ORDER_FILE.fullmatch(path.name) is not None:
                count += 1
            if _CONFLICT_FILE.fullmatch(path.name) is not None:
                count += 1
            total += path.stat().st_size
        return count, total

    def put(self, order: TradeOrder | dict[str, Any]) -> TradeOrder:
        verified = (
            TradeOrder.from_json(order.canonical_bytes)
            if isinstance(order, TradeOrder)
            else TradeOrder.from_dict(order)
        )
        path = self._path(verified.order_id)
        try:
            with self._acquire():
                self._assert_path(self._actual_lock_path())
                count, total = self._usage_locked()
                if path.exists():
                    existing = TradeOrder.from_json(self._read(path))
                    existing_conflicts = self._conflict_paths(
                        verified.order_id
                    )
                    if existing.canonical_bytes != verified.canonical_bytes:
                        conflict_path = self._conflict_path(verified)
                        if conflict_path.exists():
                            retained = TradeOrder.from_json(
                                self._read(conflict_path)
                            )
                            if (
                                retained.canonical_bytes
                                != verified.canonical_bytes
                            ):
                                raise TradeOrderRejected(
                                    "conflict record digest collision or "
                                    "corruption detected"
                                )
                        else:
                            if count + 1 > self.max_orders:
                                raise TradeOrderStoreCapacity(
                                    "max_orders prevents conflict retention"
                                )
                            if (
                                total + len(verified.canonical_bytes)
                                > self.max_bytes
                            ):
                                raise TradeOrderStoreCapacity(
                                    "max_bytes prevents conflict retention"
                                )
                            self._atomic_write(
                                conflict_path,
                                verified.canonical_bytes,
                            )
                        raise TradeOrderConflict(
                            "proposal-derived order already contains "
                            "different accepted bytes; all candidates retained"
                        )
                    if existing_conflicts:
                        raise TradeOrderConflict(
                            "order has multiple retained acceptance candidates"
                        )
                    return existing
                if count + 1 > self.max_orders:
                    raise TradeOrderStoreCapacity("max_orders exceeded")
                if total + len(verified.canonical_bytes) > self.max_bytes:
                    raise TradeOrderStoreCapacity("max_bytes exceeded")
                self._atomic_write(path, verified.canonical_bytes)
                return verified
        except TimeoutError as exc:
            raise TradeOrderStoreBusy("Trade Order store is busy") from exc

    def get(self, order_id: str) -> TradeOrder | None:
        path = self._path(order_id)
        self._assert_path(path)
        if not self.root.exists():
            return None
        try:
            with self._acquire():
                self._assert_path(self._actual_lock_path())
                self._usage_locked()
                conflicts = self._conflict_paths(order_id)
                if conflicts and not path.exists():
                    raise TradeOrderConflict(
                        "retained acceptance candidate has no primary order"
                    )
                if conflicts:
                    raise TradeOrderConflict(
                        "order has multiple retained acceptance candidates"
                    )
                if not path.exists():
                    return None
                return TradeOrder.from_json(self._read(path))
        except TimeoutError as exc:
            raise TradeOrderStoreBusy("Trade Order store is busy") from exc

    def list_ids(self) -> tuple[str, ...]:
        if not self.root.exists():
            return ()
        try:
            with self._acquire():
                self._assert_path(self._actual_lock_path())
                self._usage_locked()
                output: list[str] = []
                conflict_order_ids: set[str] = set()
                for path in self.root.iterdir():
                    if path.name == ".locks" or path.name.endswith(".tmp"):
                        continue
                    if _CONFLICT_FILE.fullmatch(path.name) is not None:
                        conflict_order_ids.add(
                            TradeOrder.from_json(self._read(path)).order_id
                        )
                        continue
                    match = _ORDER_FILE.fullmatch(path.name)
                    if match is None:
                        raise TradeOrderRejected(
                            "order store contains an unknown file"
                        )
                    order = TradeOrder.from_json(self._read(path))
                    output.append(order.order_id)
                orphaned = conflict_order_ids - set(output)
                if orphaned:
                    raise TradeOrderConflict(
                        "retained acceptance candidate has no primary order"
                    )
                return tuple(sorted(output))
        except TimeoutError as exc:
            raise TradeOrderStoreBusy("Trade Order store is busy") from exc

    def list_conflicts(self, order_id: str) -> tuple[TradeOrder, ...]:
        self._path(order_id)
        if not self.root.exists():
            return ()
        try:
            with self._acquire():
                self._assert_path(self._actual_lock_path())
                primary = self._path(order_id)
                conflicts = tuple(
                    TradeOrder.from_json(self._read(path))
                    for path in self._conflict_paths(order_id)
                )
                if conflicts and not primary.exists():
                    raise TradeOrderConflict(
                        "retained acceptance candidate has no primary order"
                    )
                if any(order.order_id != order_id for order in conflicts):
                    raise TradeOrderRejected(
                        "retained conflict has wrong order_id"
                    )
                return conflicts
        except TimeoutError as exc:
            raise TradeOrderStoreBusy("Trade Order store is busy") from exc

    def reconcile(
        self,
        *,
        prune: bool = False,
    ) -> TradeOrderReconciliationReport:
        """Inspect crash residue without deleting signed records.

        Only temporary files may be removed, and only after the caller
        explicitly requests ``prune=True``. Corrupt or orphaned signed
        candidates remain available for operator investigation.
        """
        if not isinstance(prune, bool):
            raise TypeError("prune must be a bool")
        if not self.root.exists():
            return TradeOrderReconciliationReport((), (), (), ())
        try:
            with self._acquire():
                self._assert_path(self._actual_lock_path())
                temporary: list[str] = []
                corrupt: list[str] = []
                orphaned: list[str] = []
                removed: list[str] = []
                primary_ids: set[str] = set()
                conflicts: list[tuple[Path, TradeOrder]] = []

                for path in sorted(self.root.iterdir()):
                    if path.name == ".locks":
                        continue
                    self._assert_path(path)
                    if self._is_linklike(path) or path.is_dir():
                        corrupt.append(path.name)
                        continue
                    if path.name.endswith(".tmp"):
                        temporary.append(path.name)
                        continue
                    try:
                        if _ORDER_FILE.fullmatch(path.name) is not None:
                            primary_ids.add(
                                TradeOrder.from_json(
                                    self._read(path)
                                ).order_id
                            )
                        elif _CONFLICT_FILE.fullmatch(path.name) is not None:
                            conflicts.append(
                                (
                                    path,
                                    TradeOrder.from_json(
                                        self._read(path)
                                    ),
                                )
                            )
                        else:
                            corrupt.append(path.name)
                    except (OSError, TypeError, ValueError):
                        corrupt.append(path.name)

                for path, conflict in conflicts:
                    if conflict.order_id not in primary_ids:
                        orphaned.append(path.name)
                if prune:
                    for name in temporary:
                        path = self.root / name
                        self._assert_path(path)
                        try:
                            path.unlink()
                        except OSError as exc:
                            raise TradeOrderRejected(
                                "unable to prune temporary Order residue"
                            ) from exc
                        removed.append(name)
                return TradeOrderReconciliationReport(
                    temporary_files=tuple(sorted(temporary)),
                    corrupt_files=tuple(sorted(corrupt)),
                    orphan_conflicts=tuple(sorted(orphaned)),
                    removed_temporary_files=tuple(sorted(removed)),
                )
        except TimeoutError as exc:
            raise TradeOrderStoreBusy("Trade Order store is busy") from exc


__all__ = [
    "DEFAULT_MAX_TRADE_ORDERS",
    "DEFAULT_MAX_TRADE_ORDER_STORE_BYTES",
    "ORDER_ID_PREFIX",
    "ORDER_KIND",
    "ORDER_PROTOCOL_VERSION",
    "TradeOrder",
    "TradeOrderConflict",
    "TradeOrderRejected",
    "TradeOrderReconciliationReport",
    "TradeOrderStore",
    "TradeOrderStoreBusy",
    "TradeOrderStoreCapacity",
    "create_trade_order",
    "trade_order_digest",
]
