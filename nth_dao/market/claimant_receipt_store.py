"""Claimant-owned observation of a source-signed completion receipt.

This records a verified source statement, not work acceptance or settlement.
The source event is retained as evidence; a separate local Spine event records
only that this node observed it after checking its own confirmed claim.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any

from nth_dao.canonical_json import canonical_json
from nth_dao.market.claim_evidence import resolve_confirmed_claim_evidence
from nth_dao.market.completion_flow import build_portable_completion_proof_with_pins
from nth_dao.market.source_completion_inbox import (
    SourceCompletionConflict,
    _io_path,
    _publish_immutable,
    _requires_directory_fsync,
    _sync_directory_chain,
)
from nth_dao.market.source_completion_receipt import (
    MAX_SOURCE_RECEIPT_RESPONSE_BYTES,
    extract_source_completion_receipt,
    verify_source_completion_receipt,
)
from nth_dao.market.source_identity import source_identity_precedes
from nth_dao.spine.log import SignedEventLog, SpineSemanticConflict
from nth_dao.util.io import InterProcessLock

OBSERVED_EVENT = "market.claim.completion.source_receipt.observed"
_NONCE_RE = re.compile(r"[A-Za-z0-9]{16,64}\Z")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ID_RE = re.compile(r"[0-9a-f]{64}\Z")
_NAME_RE = re.compile(r"([0-9a-f]{64})-([0-9a-f]{64})\.json\Z")
_MAX_RECEIPTS_PER_CLAIM = 8


class ClaimantReceiptRejected(ValueError):
    """The imported response is invalid against the local confirmed claim."""


class ClaimantReceiptMissing(ClaimantReceiptRejected):
    """The selected signed completion is not retained on this claimant."""


class ClaimantReceiptConflict(ValueError):
    """A different source event already occupies this completion head."""


class ClaimantReceiptPending(ClaimantReceiptConflict):
    """The exact imported event awaits a local signed observation."""


class ClaimantReceiptCorrupt(ValueError):
    """The retained receipt or observation is unavailable or inconsistent."""


class ClaimantSourceReceiptStore:
    """Import immutable evidence by source ACK and completion head."""

    def __init__(
        self, workspace: Path, *, observer_did: str, spine: SignedEventLog,
    ) -> None:
        self.workspace = Path(workspace)
        self.root = _io_path(self.workspace / "federation" / "claim_completion_receipts")
        self.observer_did = observer_did
        self.spine = spine
        if spine is None or spine.signer_did != observer_did:
            raise ClaimantReceiptCorrupt("local observation signer is unavailable")

    @staticmethod
    def _source_id(value: Any) -> str:
        if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
            raise ClaimantReceiptRejected("source claim ID is invalid")
        return value

    @staticmethod
    def _head(value: Any) -> str:
        if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
            raise ClaimantReceiptRejected("completion head digest is invalid")
        return value

    @staticmethod
    def _nonce(value: Any) -> str:
        if not isinstance(value, str) or _NONCE_RE.fullmatch(value) is None:
            raise ClaimantReceiptRejected("claim nonce is invalid")
        return value

    def _slot(self, source_claim_id: str) -> Path:
        return self.root / self._source_id(source_claim_id)

    def _check_slot(self, slot: Path) -> None:
        if any(path.is_symlink() for path in (self.root.parent, self.root, slot)):
            raise ClaimantReceiptCorrupt("claimant receipt directory is a symlink")

    def _lock_target(self, source_claim_id: str) -> Path:
        private = _io_path(self.workspace / ".nth")
        locks = private / "locks"
        receipt_locks = locks / "claim_completion_receipts"
        if any(path.is_symlink() for path in (private, locks, receipt_locks)):
            raise ClaimantReceiptCorrupt("claimant receipt lock path is a symlink")
        return receipt_locks / source_claim_id

    def _entries(self, slot: Path) -> list[Path]:
        self._check_slot(slot)
        if not slot.exists():
            return []
        found: list[Path] = []
        with os.scandir(slot) as entries:
            for entry in entries:
                info = entry.stat(follow_symlinks=False)
                if (
                    _NAME_RE.fullmatch(entry.name) is None
                    or not stat.S_ISREG(info.st_mode)
                    or info.st_size > MAX_SOURCE_RECEIPT_RESPONSE_BYTES
                ):
                    raise ClaimantReceiptCorrupt("claimant receipt slot has an unsafe entry")
                found.append(slot / entry.name)
                if len(found) > _MAX_RECEIPTS_PER_CLAIM:
                    raise ClaimantReceiptCorrupt("claimant receipt slot exceeds capacity")
        return found

    @staticmethod
    def _read(path: Path) -> tuple[dict, list, bytes]:
        before = path.stat(follow_symlinks=False)
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            after = path.stat(follow_symlinks=False)
            if (
                not all(stat.S_ISREG(item.st_mode) for item in (before, opened, after))
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
                or (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
                or opened.st_size > MAX_SOURCE_RECEIPT_RESPONSE_BYTES
            ):
                raise ClaimantReceiptCorrupt("claimant receipt file is unsafe")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(MAX_SOURCE_RECEIPT_RESPONSE_BYTES + 1)
        finally:
            os.close(fd)
        if len(raw) > MAX_SOURCE_RECEIPT_RESPONSE_BYTES:
            raise ClaimantReceiptCorrupt("claimant receipt file exceeds size limit")
        match = _NAME_RE.fullmatch(path.name)
        if match is None or match[2] != hashlib.sha256(raw).hexdigest():
            raise ClaimantReceiptCorrupt("claimant receipt content hash changed")
        try:
            value = json.loads(raw.decode("utf-8"))
            if canonical_json(value) != raw or set(value) != {
                "version", "source_receipt_event", "source_rotation_chain",
            } or type(value["version"]) is not int or value["version"] != 1:
                raise ValueError("claimant receipt envelope is invalid")
            event = value["source_receipt_event"]
            chain = value["source_rotation_chain"]
            if not isinstance(event, dict) or not isinstance(chain, list):
                raise TypeError("claimant receipt evidence is invalid")
        except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError) as exc:
            raise ClaimantReceiptCorrupt("claimant receipt encoding is invalid") from exc
        return event, chain, raw

    def _verified(
        self, nonce: str, event: dict, chain: list,
    ) -> dict[str, Any]:
        payload = event.get("payload")
        if not isinstance(payload, dict):
            raise ClaimantReceiptRejected("source receipt payload is invalid")
        head = self._head(payload.get("completion_head_digest"))
        built = build_portable_completion_proof_with_pins(
            self.workspace, self._nonce(nonce), head_digest=head,
        )
        if built is None:
            raise ClaimantReceiptMissing("matching local completion head is unavailable")
        proof, source_did, federation_key = built
        valid, reason = verify_source_completion_receipt(
            proof, event, expected_source_did=source_did,
            expected_federation_key=federation_key, rotation_chain=chain,
        )
        if not valid:
            raise ClaimantReceiptRejected(reason)
        return {
            "receipt_key": f'{proof["source_claim_id"]}:{head}',
            "source_claim_id": proof["source_claim_id"],
            "completion_head_digest": head,
            "source_receipt_event_id": event["content_hash"],
            "claimant_did": proof["intent"]["claimant_did"],
            "source_did": source_did,
            "nonce_authenticated": False,
            "accepted": False,
            "settled": False,
        }

    def _require_observer_author(self, author_did: str) -> None:
        try:
            authorized = source_identity_precedes(
                self.workspace, author_did, self.observer_did,
            )
        except ValueError as exc:
            raise ClaimantReceiptCorrupt(
                "local observation identity rotation is invalid"
            ) from exc
        if not authorized:
            raise ClaimantReceiptCorrupt("local observation signer differs from this node")

    def _audit(self, payload: dict[str, Any]) -> Any:
        try:
            event = self.spine.find_unique_event(
                OBSERVED_EVENT, payload_field="receipt_key",
                payload_value=payload["receipt_key"],
            )
        except SpineSemanticConflict as exc:
            raise ClaimantReceiptCorrupt("local receipt observations conflict") from exc
        if event is not None:
            self._require_observer_author(event.author_did)
            if canonical_json(event.payload) != canonical_json(payload):
                raise ClaimantReceiptConflict("local observation binds different evidence")
        return event

    @staticmethod
    def _matched(entries: list[Path], head: str) -> Path | None:
        matches = [path for path in entries if path.name.startswith(head[7:] + "-")]
        if len(matches) > 1:
            raise ClaimantReceiptCorrupt("multiple receipts bind one completion head")
        return matches[0] if matches else None

    def _write_immutable(self, slot: Path, target: Path, raw: bytes) -> None:
        private = _io_path(self.workspace / ".nth")
        staging = private / "claimant_receipt_staging"
        if private.is_symlink() or staging.is_symlink():
            raise ClaimantReceiptCorrupt("claimant receipt staging path is a symlink")
        staging.mkdir(parents=True, exist_ok=True)
        slot.mkdir(parents=True, exist_ok=True)
        self._check_slot(slot)
        if _requires_directory_fsync():
            _sync_directory_chain(slot, self.workspace)
        fd, temporary = tempfile.mkstemp(prefix="receipt-", dir=staging)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            _publish_immutable(Path(temporary), target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    @staticmethod
    def _summary(payload: dict[str, Any], event: Any, *, created: bool) -> dict[str, Any]:
        return {
            **payload,
            "receipt_verified": True,
            "observed_locally": True,
            "already_observed": not created,
            "local_observation_event_id": event.event_id,
            "verification_scope": "source_statement_and_proof_binding",
            "audit_inclusion_verified": False,
            "source_retention_verified": False,
        }

    def record(self, nonce: str, response: Any) -> dict[str, Any]:
        try:
            event, chain = extract_source_completion_receipt(response)
            raw = canonical_json({
                "version": 1, "source_receipt_event": event,
                "source_rotation_chain": chain,
            })
        except (TypeError, ValueError, OverflowError, RecursionError) as exc:
            raise ClaimantReceiptRejected(str(exc)) from exc
        if len(raw) > MAX_SOURCE_RECEIPT_RESPONSE_BYTES:
            raise ClaimantReceiptRejected("claimant receipt exceeds size limit")
        snapshot = json.loads(raw)
        payload = self._verified(
            nonce, snapshot["source_receipt_event"], snapshot["source_rotation_chain"],
        )
        payload["response_digest"] = "sha256:" + hashlib.sha256(raw).hexdigest()
        slot = self._slot(payload["source_claim_id"])
        target = slot / (
            payload["completion_head_digest"][7:] + "-" + payload["response_digest"][7:]
            + ".json"
        )
        with InterProcessLock(self._lock_target(payload["source_claim_id"])):
            entries = self._entries(slot)
            existing = self._matched(entries, payload["completion_head_digest"])
            audited = self._audit(payload)
            if existing is not None:
                _, _, retained_raw = self._read(existing)
                if retained_raw != raw:
                    raise ClaimantReceiptConflict("completion head binds another source receipt")
            elif audited is not None:
                raise ClaimantReceiptCorrupt("audited claimant receipt file is missing")
            else:
                if len(entries) >= _MAX_RECEIPTS_PER_CLAIM:
                    raise ClaimantReceiptConflict("claimant receipt slot is at capacity")
                try:
                    self._write_immutable(slot, target, raw)
                except SourceCompletionConflict as exc:
                    raise ClaimantReceiptConflict(str(exc)) from exc
            if audited is None:
                try:
                    audited, created = self.spine.append_unique(
                        OBSERVED_EVENT, payload, unique_payload_fields=("receipt_key",),
                    )
                except SpineSemanticConflict as exc:
                    raise ClaimantReceiptConflict("local observation binds another receipt") from exc
            else:
                created = False
            result = self.get(nonce, payload["completion_head_digest"], _locked=True)
            if result is None or result["local_observation_event_id"] != audited.event_id:
                raise ClaimantReceiptCorrupt("local receipt observation could not be reread")
            result["already_observed"] = not created
            return result

    def reconcile_pending(
        self, nonce: str, head_digest: str, *, expected_response_digest: str,
    ) -> dict[str, Any]:
        """Audit a retained receipt after independently rechecking exact bytes."""
        nonce = self._nonce(nonce)
        head = self._head(head_digest)
        expected = self._head(expected_response_digest)
        claim = resolve_confirmed_claim_evidence(self.workspace, nonce)
        source_claim_id = self._source_id(claim["authority_ack"]["ack_id"])
        slot = self._slot(source_claim_id)
        with InterProcessLock(self._lock_target(source_claim_id)):
            path = self._matched(self._entries(slot), head)
            if path is None:
                key = f"{source_claim_id}:{head}"
                audited = self.spine.find_unique_event(
                    OBSERVED_EVENT, payload_field="receipt_key", payload_value=key,
                )
                if audited is not None:
                    raise ClaimantReceiptCorrupt("audited claimant receipt file is missing")
                raise ClaimantReceiptMissing("pending claimant receipt is absent")
            event, chain, raw = self._read(path)
            digest = "sha256:" + hashlib.sha256(raw).hexdigest()
            if digest != expected:
                raise ClaimantReceiptConflict("retained receipt digest differs")
            try:
                payload = self._verified(nonce, event, chain)
            except ClaimantReceiptRejected as exc:
                raise ClaimantReceiptCorrupt("retained source receipt no longer verifies") from exc
            payload["response_digest"] = digest
            if payload["receipt_key"] != f"{source_claim_id}:{head}":
                raise ClaimantReceiptCorrupt("claimant receipt path differs from its proof")
            audited = self._audit(payload)
            if audited is None:
                try:
                    audited, created = self.spine.append_unique(
                        OBSERVED_EVENT, payload, unique_payload_fields=("receipt_key",),
                    )
                except SpineSemanticConflict as exc:
                    raise ClaimantReceiptConflict(
                        "local observation binds another receipt"
                    ) from exc
            else:
                created = False
            result = self.get(nonce, head, _locked=True)
            if result is None or result["local_observation_event_id"] != audited.event_id:
                raise ClaimantReceiptCorrupt("reconciled local observation could not be reread")
            result["already_observed"] = not created
            return result

    def pending_info(self, nonce: str, head_digest: str) -> dict[str, Any]:
        """Return a verified local digest for operator-controlled reconciliation."""
        nonce = self._nonce(nonce)
        head = self._head(head_digest)
        claim = resolve_confirmed_claim_evidence(self.workspace, nonce)
        source_claim_id = self._source_id(claim["authority_ack"]["ack_id"])
        slot = self._slot(source_claim_id)
        with InterProcessLock(self._lock_target(source_claim_id)):
            path = self._matched(self._entries(slot), head)
            if path is None:
                audited = self.spine.find_unique_event(
                    OBSERVED_EVENT, payload_field="receipt_key",
                    payload_value=f"{source_claim_id}:{head}",
                )
                if audited is not None:
                    raise ClaimantReceiptCorrupt("audited claimant receipt file is missing")
                raise ClaimantReceiptMissing("claimant receipt is not retained")
            event, chain, raw = self._read(path)
            try:
                payload = self._verified(nonce, event, chain)
            except ClaimantReceiptRejected as exc:
                raise ClaimantReceiptCorrupt("retained source receipt no longer verifies") from exc
            payload["response_digest"] = "sha256:" + hashlib.sha256(raw).hexdigest()
            if payload["receipt_key"] != f"{source_claim_id}:{head}":
                raise ClaimantReceiptCorrupt("claimant receipt path differs from its proof")
            audited = self._audit(payload)
            return {
                "source_claim_id": source_claim_id,
                "completion_head_digest": head,
                "expected_response_digest": payload["response_digest"],
                "receipt_verified": True,
                "pending": audited is None,
                "observed_locally": audited is not None,
                "local_observation_event_id": audited.event_id if audited else None,
                "accepted": False,
                "settled": False,
            }

    def get(
        self, nonce: str, head_digest: str, *, _locked: bool = False,
    ) -> dict[str, Any] | None:
        nonce = self._nonce(nonce)
        head = self._head(head_digest)
        claim = resolve_confirmed_claim_evidence(self.workspace, nonce)
        source_claim_id = self._source_id(claim["authority_ack"]["ack_id"])
        slot = self._slot(source_claim_id)

        def read_locked() -> dict[str, Any] | None:
            entries = self._entries(slot)
            path = self._matched(entries, head)
            key = f"{source_claim_id}:{head}"
            try:
                audited = self.spine.find_unique_event(
                    OBSERVED_EVENT, payload_field="receipt_key", payload_value=key,
                )
            except SpineSemanticConflict as exc:
                raise ClaimantReceiptCorrupt("local receipt observations conflict") from exc
            if path is None:
                if audited is not None:
                    raise ClaimantReceiptCorrupt("audited claimant receipt file is missing")
                return None
            event, chain, raw = self._read(path)
            try:
                payload = self._verified(nonce, event, chain)
            except ClaimantReceiptRejected as exc:
                raise ClaimantReceiptCorrupt("retained source receipt no longer verifies") from exc
            payload["response_digest"] = "sha256:" + hashlib.sha256(raw).hexdigest()
            if payload["receipt_key"] != key:
                raise ClaimantReceiptCorrupt("claimant receipt path differs from its proof")
            if audited is None:
                raise ClaimantReceiptPending("claimant receipt awaits local audit")
            self._require_observer_author(audited.author_did)
            if canonical_json(audited.payload) != canonical_json(payload):
                raise ClaimantReceiptCorrupt("local audit differs from retained receipt")
            return self._summary(payload, audited, created=False)

        if _locked:
            return read_locked()
        with InterProcessLock(self._lock_target(source_claim_id)):
            return read_locked()


__all__ = [
    "OBSERVED_EVENT", "ClaimantReceiptConflict", "ClaimantReceiptCorrupt",
    "ClaimantReceiptMissing", "ClaimantReceiptPending", "ClaimantReceiptRejected",
    "ClaimantSourceReceiptStore",
]
