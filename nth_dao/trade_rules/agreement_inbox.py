"""Bounded content-addressed inbox for independently verified Proposals."""

from __future__ import annotations

import math
import os
import stat
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nth_dao.did_key import is_did_key
from nth_dao.trade_rules.agreement import (
    TradeProposal,
    proposal_digest,
)
from nth_dao.trade_rules.canonical import MAX_TRADE_JSON_BYTES
from nth_dao.trade_rules.agreement_transport import (
    TradeProposalDelivery,
    TradeProposalDeliveryRejected,
    TradeProposalIntakeReceipt,
    TradeProposalIntakeReceiptRejected,
    verify_trade_proposal_intake_receipt,
)
from nth_dao.util.io import InterProcessLock, atomic_write_json, safe_load_json

DEFAULT_MAX_TRADE_PROPOSALS = 10_000
DEFAULT_MAX_TRADE_PROPOSAL_INBOX_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_TRADE_PROPOSALS_PER_TAKER = 1_000
DEFAULT_MAX_TRADE_PROPOSALS_PER_OFFER = 2_000
_DIGEST_PREFIX = "sha256:"


class TradeProposalInboxError(RuntimeError):
    """Base error for Proposal inbox validation or persistence."""


class TradeProposalInboxRejected(TradeProposalInboxError):
    """The signed Proposal does not match the receiver's local state."""


class TradeProposalInboxBusy(TradeProposalInboxError):
    """Another process owns the Proposal inbox write lock."""


class TradeProposalInboxCapacity(TradeProposalInboxError):
    """A configured inbox capacity would be exceeded."""


class TradeProposalInboxCorruption(TradeProposalInboxError):
    """Stored bytes or filesystem layout violate CAS invariants."""


class TradeProposalInboxForeignReceiver(TradeProposalInboxCorruption):
    """A valid record belongs to another receiver and must be quarantined."""


@dataclass(frozen=True)
class TradeProposalInboxResult:
    digest: str
    appended: bool
    proposal: TradeProposal
    delivery: TradeProposalDelivery
    intake_receipt: TradeProposalIntakeReceipt


@dataclass(frozen=True)
class TradeProposalInboxEntry:
    digest: str
    proposal: TradeProposal
    delivery: TradeProposalDelivery
    intake_receipt: TradeProposalIntakeReceipt


class TradeProposalInbox:
    """Immutable local retention for replay-verified remote Proposals.

    Retention is not acceptance. The inbox stores only the exact signed
    Proposal bytes and deliberately carries no trust, reservation, or
    execution state.
    """

    def __init__(
        self,
        workspace_root: str | Path,
        *,
        receiver_did: str,
        max_proposals: int = DEFAULT_MAX_TRADE_PROPOSALS,
        max_bytes: int = DEFAULT_MAX_TRADE_PROPOSAL_INBOX_BYTES,
        max_per_taker: int = DEFAULT_MAX_TRADE_PROPOSALS_PER_TAKER,
        max_per_offer: int = DEFAULT_MAX_TRADE_PROPOSALS_PER_OFFER,
        lock_timeout: float = 10.0,
    ) -> None:
        if not isinstance(receiver_did, str) or not is_did_key(receiver_did):
            raise ValueError("receiver_did must be an Ed25519 did:key")
        for label, value in (
            ("max_proposals", max_proposals),
            ("max_bytes", max_bytes),
            ("max_per_taker", max_per_taker),
            ("max_per_offer", max_per_offer),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value <= 0
            ):
                raise ValueError(f"{label} must be a positive integer")
        if (
            isinstance(lock_timeout, bool)
            or not isinstance(lock_timeout, (int, float))
            or not math.isfinite(lock_timeout)
            or lock_timeout <= 0
        ):
            raise ValueError("lock_timeout must be a finite positive number")
        self.workspace_root = Path(workspace_root)
        self.root = self.workspace_root / "trade" / "agreement_proposals_v1"
        self.deliveries_root = self.root / "deliveries"
        self.receipts_root = self.root / "intake_receipts"
        self.quarantine_root = self.root / "quarantine" / "foreign_receivers"
        self.archive_root = self.root / "archive"
        # Kept as an introspection alias for embedders that exposed this path
        # before the receiver-signed commit-marker design was introduced.
        self.proposals_root = self.deliveries_root
        self.lock_path = self.root / ".locks" / "inbox"
        self.usage_path = self.root / "usage.json"
        self.max_proposals = max_proposals
        self.max_bytes = max_bytes
        self.max_per_taker = max_per_taker
        self.max_per_offer = max_per_offer
        self.lock_timeout = float(lock_timeout)
        self.receiver_did = receiver_did

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
            raise TradeProposalInboxCorruption(
                "Proposal inbox path escapes its workspace"
            ) from exc
        current = self.workspace_root
        for candidate in (
            self.workspace_root,
            *(
                self.workspace_root.joinpath(*relative.parts[:index])
                for index in range(1, len(relative.parts) + 1)
            ),
        ):
            current = candidate
            if self._is_linklike(current):
                raise TradeProposalInboxCorruption(
                    "Proposal inbox must not contain symlinks or junctions"
                )

    @staticmethod
    def _digest_suffix(digest: str) -> str:
        if (
            not isinstance(digest, str)
            or not digest.startswith(_DIGEST_PREFIX)
            or len(digest) != 71
            or any(
                character not in "0123456789abcdef"
                for character in digest[len(_DIGEST_PREFIX):]
            )
        ):
            raise ValueError("Proposal digest must be lowercase sha256")
        return digest[len(_DIGEST_PREFIX):]

    def _delivery_path(self, digest: str) -> Path:
        return self.deliveries_root / f"{self._digest_suffix(digest)}.json"

    def _receipt_path(self, digest: str) -> Path:
        return self.receipts_root / f"{self._digest_suffix(digest)}.json"

    def _acquire(self) -> InterProcessLock:
        self._assert_path(self.lock_path.parent)
        try:
            self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise TradeProposalInboxError(
                f"unable to create Proposal inbox lock directory: {exc}"
            ) from exc
        self._assert_path(self.lock_path.parent)
        return InterProcessLock(self.lock_path, timeout=self.lock_timeout)

    def _json_files(self, root: Path, *, label: str) -> list[Path]:
        self._assert_path(root)
        if not root.exists():
            return []
        try:
            files = sorted(root.iterdir())
        except OSError as exc:
            raise TradeProposalInboxError(
                f"unable to enumerate Proposal {label}: {exc}"
            ) from exc
        for path in files:
            self._assert_path(path)
        if any(
            not path.is_file()
            or path.suffix != ".json"
            or len(path.stem) != 64
            or any(
                character not in "0123456789abcdef"
                for character in path.stem
            )
            for path in files
        ):
            raise TradeProposalInboxCorruption(
                f"Proposal {label} contains an unexpected entry"
            )
        return files

    def _proposal_files(self) -> list[Path]:
        """Return committed intake markers, never uncommitted deliveries."""

        return self._json_files(self.receipts_root, label="intake receipts")

    def _read_bounded(self, path: Path, *, label: str) -> bytes:
        self._assert_path(path)
        try:
            size = path.stat().st_size
            if size > MAX_TRADE_JSON_BYTES:
                raise TradeProposalInboxCorruption(
                    f"stored {label} exceeds its byte limit"
                )
            payload = path.read_bytes()
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise TradeProposalInboxError(
                f"unable to read stored {label}: {exc}"
            ) from exc
        if len(payload) != size:
            raise TradeProposalInboxCorruption(
                f"stored {label} changed while being read"
            )
        return payload

    def _load_path(self, path: Path) -> TradeProposalInboxEntry:
        digest = _DIGEST_PREFIX + path.stem
        delivery_path = self._delivery_path(digest)
        try:
            receipt = TradeProposalIntakeReceipt.from_json(
                self._read_bounded(path, label="Proposal intake receipt")
            )
            delivery = TradeProposalDelivery.from_json(
                self._read_bounded(delivery_path, label="Proposal Delivery")
            )
        except FileNotFoundError as exc:
            raise TradeProposalInboxCorruption(
                "committed Proposal intake record is incomplete"
            ) from exc
        except (
            TradeProposalDeliveryRejected,
            TradeProposalIntakeReceiptRejected,
        ) as exc:
            raise TradeProposalInboxCorruption(
                f"stored Proposal intake record is invalid: {exc}"
            ) from exc
        receipt_document = receipt.to_dict()
        if receipt_document["receiver_did"] != self.receiver_did:
            raise TradeProposalInboxForeignReceiver(
                "Proposal intake receipt belongs to another receiver"
            )
        ok, reason = verify_trade_proposal_intake_receipt(
            receipt,
            delivery=delivery,
            receiver_did=self.receiver_did,
        )
        if not ok:
            raise TradeProposalInboxCorruption(
                f"stored Proposal intake receipt is unbound: {reason}"
            )
        proposal = delivery.proposal
        if proposal_digest(proposal) != digest:
            raise TradeProposalInboxCorruption(
                "stored Proposal does not match its content address"
            )
        return TradeProposalInboxEntry(
            digest=digest,
            proposal=proposal,
            delivery=delivery,
            intake_receipt=receipt,
        )

    def _quarantine_foreign_unlocked(self, receipt_path: Path) -> None:
        """Move one foreign record out of active storage without deleting it."""

        digest = _DIGEST_PREFIX + receipt_path.stem
        target_root = self.quarantine_root / receipt_path.stem
        self._preserve_pair_then_deactivate_unlocked(digest, target_root)

    def _preserve_pair_then_deactivate_unlocked(
        self,
        digest: str,
        target_root: Path,
    ) -> None:
        """Copy a complete pair, then remove only the active commit marker."""

        delivery_path = self._delivery_path(digest)
        receipt_path = self._receipt_path(digest)
        self._assert_path(target_root)
        try:
            target_root.mkdir(parents=True, exist_ok=True)
            self._assert_path(target_root)
            for source, name, label in (
                (delivery_path, "delivery.json", "Proposal Delivery"),
                (
                    receipt_path,
                    "intake_receipt.json",
                    "Proposal intake receipt",
                ),
            ):
                target = target_root / name
                self._assert_path(source)
                self._assert_path(target)
                payload = self._read_bounded(source, label=label)
                if target.exists():
                    if self._read_bounded(target, label=label) != payload:
                        raise TradeProposalInboxCorruption(
                            "Proposal archive contains conflicting bytes"
                        )
                else:
                    self._atomic_write(target, payload)
            # Receipt is the active commit marker. Remove it only after both
            # archive copies are durable; a crash before this point leaves the
            # original active record intact and retryable.
            receipt_path.unlink()
            try:
                delivery_path.unlink()
            except FileNotFoundError:
                pass
        except OSError as exc:
            raise TradeProposalInboxError(
                f"unable to preserve Proposal intake outside active storage: {exc}"
            ) from exc

    @staticmethod
    def _utc_at(value: datetime) -> datetime:
        if (
            not isinstance(value, datetime)
            or value.tzinfo is None
            or value.utcoffset() is None
        ):
            raise ValueError("at must be a timezone-aware datetime")
        return value.astimezone(timezone.utc)

    def list_expired_digests(
        self,
        *,
        at: datetime,
        limit: int = 1_000,
    ) -> tuple[str, ...]:
        """List active records whose signed Proposal lifetime has ended."""

        moment = self._utc_at(at)
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("limit must be an integer")
        if not 1 <= limit <= 1_000:
            raise ValueError("limit must be between 1 and 1000")
        expired: list[str] = []
        try:
            with self._acquire():
                for receipt_path in self._proposal_files():
                    entry = self._load_path(receipt_path)
                    not_after = datetime.fromisoformat(
                        entry.proposal.to_dict()["not_after"].replace(
                            "Z", "+00:00"
                        )
                    )
                    if moment >= not_after:
                        expired.append(entry.digest)
                        if len(expired) == limit:
                            break
        except TimeoutError as exc:
            raise TradeProposalInboxBusy("Proposal inbox is busy") from exc
        return tuple(expired)

    def archive_digests(self, digests: tuple[str, ...]) -> tuple[str, ...]:
        """Deactivate locally verified records after their audit tombstones."""

        if not isinstance(digests, tuple):
            raise TypeError("digests must be a tuple")
        if len(digests) > 1_000:
            raise ValueError("archive batch exceeds 1000 records")
        for digest in digests:
            self._digest_suffix(digest)
        archived: list[str] = []
        try:
            with self._acquire():
                try:
                    for digest in digests:
                        receipt_path = self._receipt_path(digest)
                        if not receipt_path.exists():
                            continue
                        self._load_path(receipt_path)
                        self._preserve_pair_then_deactivate_unlocked(
                            digest,
                            self.archive_root / digest[7:],
                        )
                        archived.append(digest)
                finally:
                    if archived:
                        self._rebuild_usage_unlocked()
        except TimeoutError as exc:
            raise TradeProposalInboxBusy("Proposal inbox is busy") from exc
        return tuple(archived)

    def _atomic_write(self, path: Path, payload: bytes) -> None:
        descriptor: int | None = None
        temporary: str | None = None
        try:
            self._assert_path(path.parent)
            path.parent.mkdir(parents=True, exist_ok=True)
            self._assert_path(path.parent)
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
            raise TradeProposalInboxError(
                f"unable to durably write Proposal inbox: {exc}"
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass

    @staticmethod
    def _usage_counts(value: Any, *, label: str) -> dict[str, int]:
        if not isinstance(value, dict):
            raise TradeProposalInboxCorruption(
                f"Proposal inbox usage {label} is malformed"
            )
        result: dict[str, int] = {}
        for key, count in value.items():
            if (
                not isinstance(key, str)
                or not key
                or isinstance(count, bool)
                or not isinstance(count, int)
                or count < 0
            ):
                raise TradeProposalInboxCorruption(
                    f"Proposal inbox usage {label} is malformed"
                )
            result[key] = count
        return result

    def _load_usage_unlocked(self) -> dict[str, Any] | None:
        self._assert_path(self.usage_path)
        existed = self.usage_path.exists()
        raw = safe_load_json(
            self.usage_path,
            fallback=None,
            log_warn=False,
        )
        if raw is None and not existed:
            return None
        if not isinstance(raw, dict) or set(raw) != {
            "version",
            "records",
            "bytes",
            "by_taker",
            "by_offer",
        }:
            raise TradeProposalInboxCorruption(
                "Proposal inbox usage ledger is malformed"
            )
        if raw["version"] != 1:
            raise TradeProposalInboxCorruption(
                "Proposal inbox usage ledger version is unsupported"
            )
        for field in ("records", "bytes"):
            value = raw[field]
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
            ):
                raise TradeProposalInboxCorruption(
                    "Proposal inbox usage ledger is malformed"
                )
        return {
            "version": 1,
            "records": raw["records"],
            "bytes": raw["bytes"],
            "by_taker": self._usage_counts(
                raw["by_taker"], label="by_taker"
            ),
            "by_offer": self._usage_counts(
                raw["by_offer"], label="by_offer"
            ),
        }

    def _write_usage_unlocked(self, usage: dict[str, Any]) -> None:
        self._assert_path(self.usage_path.parent)
        atomic_write_json(self.usage_path, usage)

    def _rebuild_usage_unlocked(self) -> dict[str, Any]:
        usage: dict[str, Any] = {
            "version": 1,
            "records": 0,
            "bytes": 0,
            "by_taker": {},
            "by_offer": {},
        }
        for receipt_path in self._proposal_files():
            try:
                entry = self._load_path(receipt_path)
            except TradeProposalInboxForeignReceiver:
                self._quarantine_foreign_unlocked(receipt_path)
                continue
            document = entry.proposal.to_dict()
            usage["records"] += 1
            usage["bytes"] += (
                len(entry.intake_receipt.canonical_bytes)
                + len(entry.delivery.canonical_bytes)
            )
            taker = document["taker_did"]
            offer = f"{document['offer_publisher_did']}|{document['offer_id']}"
            usage["by_taker"][taker] = usage["by_taker"].get(taker, 0) + 1
            usage["by_offer"][offer] = usage["by_offer"].get(offer, 0) + 1
        self._write_usage_unlocked(usage)
        return usage

    def reconcile_usage(self) -> dict[str, int]:
        """Rebuild conservative capacity metadata from committed receipts."""

        try:
            with self._acquire():
                usage = self._rebuild_usage_unlocked()
        except TimeoutError as exc:
            raise TradeProposalInboxBusy("Proposal inbox is busy") from exc
        except OSError as exc:
            raise TradeProposalInboxError(
                f"unable to rebuild Proposal inbox usage: {exc}"
            ) from exc
        return {
            "records": usage["records"],
            "bytes": usage["bytes"],
        }

    def _reserve_usage_unlocked(
        self,
        delivery: TradeProposalDelivery,
        receipt: TradeProposalIntakeReceipt,
    ) -> None:
        usage = self._load_usage_unlocked()
        if usage is None:
            usage = self._rebuild_usage_unlocked()
        proposal_document = delivery.proposal.to_dict()
        taker = proposal_document["taker_did"]
        offer = (
            f"{proposal_document['offer_publisher_did']}|"
            f"{proposal_document['offer_id']}"
        )
        incoming_bytes = len(delivery.canonical_bytes) + len(
            receipt.canonical_bytes
        )

        def exceeded(candidate: dict[str, Any]) -> str:
            if candidate["records"] + 1 > self.max_proposals:
                return "Proposal inbox record capacity exceeded"
            if candidate["bytes"] + incoming_bytes > self.max_bytes:
                return "Proposal inbox byte capacity exceeded"
            if candidate["by_taker"].get(taker, 0) + 1 > self.max_per_taker:
                return "Proposal inbox taker capacity exceeded"
            if candidate["by_offer"].get(offer, 0) + 1 > self.max_per_offer:
                return "Proposal inbox Offer capacity exceeded"
            return ""

        reason = exceeded(usage)
        if reason:
            # A crash after reservation but before the receipt commit marker
            # can only over-count. Rebuild once at the limit before rejecting.
            usage = self._rebuild_usage_unlocked()
            reason = exceeded(usage)
        if reason:
            raise TradeProposalInboxCapacity(reason)
        usage["records"] += 1
        usage["bytes"] += incoming_bytes
        usage["by_taker"][taker] = usage["by_taker"].get(taker, 0) + 1
        usage["by_offer"][offer] = usage["by_offer"].get(offer, 0) + 1
        # Reserve before committing the receipt. A crash is fail-closed and
        # startup reconciliation removes any conservative over-count.
        self._write_usage_unlocked(usage)

    def put(
        self,
        delivery: TradeProposalDelivery | dict[str, Any],
        intake_receipt: TradeProposalIntakeReceipt | dict[str, Any],
    ) -> TradeProposalInboxResult:
        """Commit a verified Delivery using its receiver-signed marker."""

        try:
            verified_delivery = (
                delivery
                if isinstance(delivery, TradeProposalDelivery)
                else TradeProposalDelivery.from_dict(delivery)
            )
            verified_receipt = (
                intake_receipt
                if isinstance(intake_receipt, TradeProposalIntakeReceipt)
                else TradeProposalIntakeReceipt.from_dict(intake_receipt)
            )
        except (
            TradeProposalDeliveryRejected,
            TradeProposalIntakeReceiptRejected,
            TypeError,
            ValueError,
        ) as exc:
            raise TradeProposalInboxRejected(str(exc)) from exc
        receipt_document = verified_receipt.to_dict()
        if receipt_document["receiver_did"] != self.receiver_did:
            raise TradeProposalInboxRejected(
                "Proposal intake receipt belongs to another receiver"
            )
        ok, reason = verify_trade_proposal_intake_receipt(
            verified_receipt,
            delivery=verified_delivery,
            receiver_did=self.receiver_did,
        )
        if not ok:
            raise TradeProposalInboxRejected(reason)
        verified = verified_delivery.proposal
        digest = proposal_digest(verified)
        delivery_path = self._delivery_path(digest)
        receipt_path = self._receipt_path(digest)
        try:
            with self._acquire():
                self._assert_path(delivery_path)
                self._assert_path(receipt_path)
                if receipt_path.exists():
                    stored = self._load_path(receipt_path)
                    if (
                        stored.proposal.canonical_bytes
                        != verified.canonical_bytes
                    ):
                        raise TradeProposalInboxCorruption(
                            "content-addressed Proposal bytes changed"
                        )
                    return TradeProposalInboxResult(
                        digest=digest,
                        appended=False,
                        proposal=stored.proposal,
                        delivery=stored.delivery,
                        intake_receipt=stored.intake_receipt,
                    )
                self._reserve_usage_unlocked(
                    verified_delivery,
                    verified_receipt,
                )
                # The receiver-signed receipt is the commit marker and must
                # always be replaced last. A crash before it leaves only an
                # uncommitted Delivery, which reconciliation ignores.
                self._atomic_write(
                    delivery_path,
                    verified_delivery.canonical_bytes,
                )
                self._atomic_write(
                    receipt_path,
                    verified_receipt.canonical_bytes,
                )
                stored = self._load_path(receipt_path)
                if stored.proposal.canonical_bytes != verified.canonical_bytes:
                    raise TradeProposalInboxCorruption(
                        "Proposal changed during durable write verification"
                    )
                return TradeProposalInboxResult(
                    digest=digest,
                    appended=True,
                    proposal=stored.proposal,
                    delivery=stored.delivery,
                    intake_receipt=stored.intake_receipt,
                )
        except TimeoutError as exc:
            raise TradeProposalInboxBusy(
                "Proposal inbox is busy"
            ) from exc
        except OSError as exc:
            raise TradeProposalInboxError(
                f"unable to update Proposal inbox usage: {exc}"
            ) from exc

    def get(self, digest: str) -> TradeProposal | None:
        """Load an immutable signed Proposal without asserting freshness."""

        entry = self.get_entry(digest)
        return entry.proposal if entry is not None else None

    def get_entry(self, digest: str) -> TradeProposalInboxEntry | None:
        """Load one committed receiver-signed intake record."""

        path = self._receipt_path(digest)
        self._assert_path(path)
        if not path.exists():
            return None
        try:
            return self._load_path(path)
        except FileNotFoundError:
            return None

    def list_digests(
        self,
        *,
        limit: int = 100,
        after: str | None = None,
    ) -> tuple[str, ...]:
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("limit must be an integer")
        if not 1 <= limit <= 1_000:
            raise ValueError("limit must be between 1 and 1000")
        after_suffix = self._digest_suffix(after) if after is not None else None
        try:
            with self._acquire():
                return tuple(
                    _DIGEST_PREFIX + path.stem
                    for path in self._proposal_files()
                    if after_suffix is None or path.stem > after_suffix
                )[:limit]
        except TimeoutError as exc:
            raise TradeProposalInboxBusy(
                "Proposal inbox is busy"
            ) from exc


__all__ = [
    "DEFAULT_MAX_TRADE_PROPOSALS",
    "DEFAULT_MAX_TRADE_PROPOSAL_INBOX_BYTES",
    "DEFAULT_MAX_TRADE_PROPOSALS_PER_OFFER",
    "DEFAULT_MAX_TRADE_PROPOSALS_PER_TAKER",
    "TradeProposalInbox",
    "TradeProposalInboxBusy",
    "TradeProposalInboxCapacity",
    "TradeProposalInboxCorruption",
    "TradeProposalInboxError",
    "TradeProposalInboxEntry",
    "TradeProposalInboxForeignReceiver",
    "TradeProposalInboxRejected",
    "TradeProposalInboxResult",
]
