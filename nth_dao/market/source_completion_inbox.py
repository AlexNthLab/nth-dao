"""Source-owned, audited inbox for explicitly transferred completion proofs.

Receiving a claimant statement does not accept the work or settle a trade.
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
from nth_dao.market.completion_flow import (
    MAX_PORTABLE_COMPLETION_PROOF_BYTES,
    SourceCompletionEvidenceUnavailable,
    verify_source_claim_completion,
)
from nth_dao.market.mission_completion import (
    COMPLETION_MERGE_VERSION,
    COMPLETION_REVISION_VERSION,
    CompletionLineageError,
    receipt_digest,
    resolve_completion_lineage,
)
from nth_dao.market.source_completion_receipt import (
    RECEIVED_EVENT,
    _payload_for_verified_proof,
    _same_payload_bytes,
)
from nth_dao.market.source_identity import (
    export_source_identity_rotation_chain,
    source_identity_precedes,
)
from nth_dao.spine.log import SignedEventLog, SpineSemanticConflict
from nth_dao.util.io import InterProcessLock

_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_MAX_HEADS_PER_CLAIM = 8
_MAX_BYTES_PER_CLAIM = 64 * 1024 * 1024


def _io_path(path: Path) -> Path:
    """Use Win32 extended paths for content-addressed inbox filenames."""
    if os.name != "nt":
        return path
    absolute = os.path.abspath(path)
    if absolute.startswith("\\\\?\\"):
        return Path(absolute)
    if absolute.startswith("\\\\"):
        return Path("\\\\?\\UNC\\" + absolute[2:])
    return Path("\\\\?\\" + absolute)


def _publish_immutable(source: Path, target: Path) -> None:
    """Atomically publish without replacing an existing proof."""
    if os.name == "nt":
        import ctypes

        move = ctypes.WinDLL("kernel32", use_last_error=True).MoveFileExW
        move.argtypes = (ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_ulong)
        move.restype = ctypes.c_int
        # MOVEFILE_WRITE_THROUGH, deliberately without REPLACE_EXISTING.
        if not move(str(_io_path(source)), str(_io_path(target)), 0x8):
            error = ctypes.get_last_error()
            if error in (80, 183):
                raise SourceCompletionConflict("source proof already exists")
            raise OSError(error, "durable source proof publication failed")
        return
    os.link(source, target, follow_symlinks=False)
    directory_fd = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _fsync_directory(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _sync_directory_chain(slot: Path, workspace: Path) -> None:
    """Persist new inbox directory entries before publishing a proof."""
    if slot.parent.parent.parent != workspace:
        raise ValueError("source inbox slot is outside its workspace")
    for directory in (slot, slot.parent, slot.parent.parent, workspace):
        _fsync_directory(directory)


def _requires_directory_fsync() -> bool:
    return os.name != "nt"


class SourceCompletionRejected(ValueError):
    """The transferred statement is invalid against source evidence."""


class SourceCompletionConflict(ValueError):
    """A semantic completion head is already bound to different evidence."""


class SourceCompletionPending(SourceCompletionConflict):
    """A verified local proof blob is waiting for an explicit source audit."""


class SourceCompletionCorrupt(ValueError):
    """The retained inbox or signed audit cannot be trusted."""


class SourceCompletionInbox:
    """Retain exact proofs by source ACK and signed completion head.

    The blob is written before the signed audit event. If the audit append
    fails, a retry with identical bytes repairs the pending blob. Readers
    never describe a blob without its matching signed event as recorded.
    """

    def __init__(
        self, workspace: Path, *, source_did: str, spine: SignedEventLog,
    ) -> None:
        self.workspace = Path(workspace)
        self.root = _io_path(self.workspace / "federation" / "inbox")
        self.source_did = source_did
        self.spine = spine
        if spine is None or spine.signer_did != source_did:
            raise SourceCompletionCorrupt("source audit signer is unavailable")

    @staticmethod
    def _digest(value: str) -> str:
        if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
            raise SourceCompletionRejected("completion identifier is invalid")
        return value

    def _slot(self, source_claim_id: str) -> Path:
        return self.root / self._digest(source_claim_id)

    def _lock_target(self, source_claim_id: str) -> Path:
        private = _io_path(self.workspace / ".nth")
        locks = private / "locks"
        inbox_locks = locks / "received_claim_completions"
        if any(path.is_symlink() for path in (private, locks, inbox_locks)):
            raise SourceCompletionCorrupt("source inbox lock path is a symlink")
        return inbox_locks / source_claim_id

    def _check_slot(self, slot: Path) -> None:
        if any(path.is_symlink() for path in (self.root.parent, self.root, slot)):
            raise SourceCompletionCorrupt("source inbox directory is a symlink")

    def _write_immutable(self, path: Path, raw: bytes) -> None:
        private = _io_path(self.workspace / ".nth")
        stage = private / "completion_staging"
        if private.is_symlink() or stage.is_symlink():
            raise SourceCompletionCorrupt("source inbox staging path is a symlink")
        stage.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix="proof-", dir=stage)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            self._check_slot(path.parent)
            _publish_immutable(Path(temporary), path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _entries(self, slot: Path) -> tuple[int, int]:
        self._check_slot(slot)
        if not slot.exists():
            return 0, 0
        count = total = 0
        with os.scandir(slot) as entries:
            for entry in entries:
                info = entry.stat(follow_symlinks=False)
                if (
                    not entry.name.endswith(".json")
                    or _DIGEST_RE.fullmatch(entry.name[:-5]) is None
                    or not stat.S_ISREG(info.st_mode)
                    or info.st_size > MAX_PORTABLE_COMPLETION_PROOF_BYTES
                ):
                    raise SourceCompletionCorrupt("source inbox contains an unsafe entry")
                count += 1
                total += info.st_size
                if count > _MAX_HEADS_PER_CLAIM or total > _MAX_BYTES_PER_CLAIM:
                    raise SourceCompletionCorrupt("source inbox exceeds its capacity")
        return count, total

    @staticmethod
    def _read_raw(path: Path) -> bytes:
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
                or opened.st_size > MAX_PORTABLE_COMPLETION_PROOF_BYTES
            ):
                raise SourceCompletionCorrupt("source proof file is unsafe")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(MAX_PORTABLE_COMPLETION_PROOF_BYTES + 1)
        finally:
            os.close(fd)
        if len(raw) > MAX_PORTABLE_COMPLETION_PROOF_BYTES:
            raise SourceCompletionCorrupt("source proof file is oversized")
        return raw

    def _verified_payload(self, proof: Any) -> tuple[bytes, dict[str, Any]]:
        valid, reason = verify_source_claim_completion(
            self.workspace, proof, source_did=self.source_did,
            strict_source_evidence=True,
        )
        if not valid:
            raise SourceCompletionRejected(reason)
        raw = canonical_json(proof)
        if len(raw) > MAX_PORTABLE_COMPLETION_PROOF_BYTES:
            raise SourceCompletionRejected("source proof exceeds size limit")
        self._digest(proof["source_claim_id"])
        payload = _payload_for_verified_proof(proof, raw)
        return raw, payload

    def _audit(self, payload: dict[str, Any]) -> Any:
        event = self.spine.find_unique_event(
            RECEIVED_EVENT, payload_field="completion_key",
            payload_value=payload["completion_key"],
        )
        if event is not None and not source_identity_precedes(
            self.workspace, event.author_did, self.source_did,
        ):
            raise SourceCompletionCorrupt("source audit signer is not in the rotation chain")
        if event is not None and not _same_payload_bytes(event.payload, payload):
            raise SourceCompletionConflict("source audit binds a different proof")
        return event

    def _audited_heads(self, source_claim_id: str) -> dict[str, Any]:
        events = self.spine.find_events_by_payload(
            RECEIVED_EVENT, payload_field="source_claim_id",
            payload_value=source_claim_id, limit=_MAX_HEADS_PER_CLAIM,
        )
        audited: dict[str, Any] = {}
        for event in events:
            digest = event.payload.get("completion_head_digest")
            if (
                not isinstance(digest, str)
                or not digest.startswith("sha256:")
                or _DIGEST_RE.fullmatch(digest[7:]) is None
                or event.payload.get("completion_key") != f"{source_claim_id}:{digest}"
                or digest in audited
                or not source_identity_precedes(
                    self.workspace, event.author_did, self.source_did,
                )
            ):
                raise SourceCompletionCorrupt("source audit head is invalid")
            audited[digest] = event
        return audited

    def _lineage_state(
        self, slot: Path, *, allow_missing_audited: str | None = None,
    ) -> tuple[
        dict[str, tuple[dict[str, Any], Any]], dict[str, dict[str, Any]],
        dict[str, str], dict[str, Any],
    ]:
        self._entries(slot)
        audited = self._audited_heads(slot.name)
        retained: dict[str, tuple[dict[str, Any], Any]] = {}
        pending: dict[str, dict[str, Any]] = {}
        signed_head_by_envelope: dict[str, str] = {}
        graph: dict[str, dict[str, Any]] = {}
        for path in sorted(slot.glob("*.json")):
            raw = self._read_raw(path)
            try:
                proof = json.loads(raw)
                if canonical_json(proof) != raw:
                    raise ValueError("source proof is not canonical JSON")
            except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
                raise SourceCompletionCorrupt("source proof encoding is invalid") from exc
            try:
                _, payload = self._verified_payload(proof)
            except SourceCompletionRejected as exc:
                raise SourceCompletionCorrupt("retained source proof is invalid") from exc
            digest = payload["completion_head_digest"]
            event = audited.get(digest)
            if (
                payload["source_claim_id"] != slot.name
                or path.stem != digest[7:]
                or payload["proof_digest"] != "sha256:" + hashlib.sha256(raw).hexdigest()
            ):
                raise SourceCompletionCorrupt("source proof path or audit does not match")
            signed_head_by_envelope[digest] = receipt_digest(
                proof["completion_chain"][-1]["completion_record"]
            )
            if event is None:
                pending[digest] = payload
                continue
            if not _same_payload_bytes(event.payload, payload):
                raise SourceCompletionCorrupt("source proof and audit disagree")
            retained[digest] = payload, event
            for envelope in proof["completion_chain"]:
                parent_digest = receipt_digest(envelope)
                previous = graph.setdefault(parent_digest, envelope)
                if previous != envelope:
                    raise SourceCompletionCorrupt("completion lineage digest collision")
        missing = audited.keys() - retained.keys()
        if missing and missing != {allow_missing_audited}:
            raise SourceCompletionCorrupt("audited source proof is missing")
        has_aliases = len(set(signed_head_by_envelope.values())) != len(
            signed_head_by_envelope
        )
        if pending or missing:
            return retained, pending, signed_head_by_envelope, {
                "lineage_state": "pending_audit" if pending else "pending_repair",
                "lineage_heads": [],
                "single_retained_head_digest": None,
                "has_duplicate_signed_head": has_aliases,
                "pending_head_digests": sorted(pending),
                "outcome_scope": "submitted_head_only",
            }
        try:
            _, heads = resolve_completion_lineage(graph)
        except CompletionLineageError as exc:
            raise SourceCompletionCorrupt("retained completion lineage is invalid") from exc
        signed_record_by_envelope = {
            digest: receipt_digest(envelope["completion_record"])
            for digest, envelope in graph.items()
        }
        superseded_records: set[str] = set()
        for envelope in graph.values():
            record = envelope["completion_record"]
            if record["version"] == COMPLETION_REVISION_VERSION:
                parents = [record["supersedes_digest"]]
            elif record["version"] == COMPLETION_MERGE_VERSION:
                parents = record["supersedes_digests"]
            else:
                parents = []
            superseded_records.update(
                signed_record_by_envelope[parent] for parent in parents
            )
        semantic_heads = set(signed_record_by_envelope.values()) - superseded_records
        state = {
            "lineage_state": (
                "unresolved_fork" if len(semantic_heads) > 1 else
                "duplicate_signed_head" if has_aliases else "single_retained_head"
            ),
            "lineage_heads": sorted(heads),
            "single_retained_head_digest": (
                heads[0] if len(heads) == 1 and not has_aliases else None
            ),
            "has_duplicate_signed_head": has_aliases,
            "pending_head_digests": [],
            "outcome_scope": "submitted_head_only",
        }
        return retained, pending, signed_head_by_envelope, state

    def _summary(
        self, payload: dict[str, Any], event: Any, *, created: bool,
        lineage: dict[str, Any],
    ) -> dict[str, Any]:
        try:
            rotation_chain = export_source_identity_rotation_chain(
                self.workspace, payload["source_did"], event.author_did,
            )
        except (OSError, ValueError) as exc:
            raise SourceCompletionCorrupt("source rotation proof is unavailable") from exc
        return {
            **payload, **lineage,
            "audit_event_id": event.event_id,
            "source_receipt_event": event.to_dict(),
            "source_rotation_chain": rotation_chain,
            "verified": True,
            "verification_scope": "source_claim_binding_only",
            "recorded": True,
            "already_recorded": not created,
        }

    def record(self, proof: Any) -> dict[str, Any]:
        raw, payload = self._verified_payload(proof)
        source_claim_id = payload["source_claim_id"]
        slot = self._slot(source_claim_id)
        path = slot / (payload["completion_head_digest"][7:] + ".json")
        with InterProcessLock(self._lock_target(source_claim_id)):
            count, total = self._entries(slot)
            existing_event = self._audit(payload)
            try:
                export_source_identity_rotation_chain(
                    self.workspace, payload["source_did"],
                    existing_event.author_did if existing_event is not None else self.source_did,
                )
            except (OSError, ValueError) as exc:
                raise SourceCompletionCorrupt("source rotation proof is unavailable") from exc
            _, pending, signed_heads, _ = self._lineage_state(
                slot,
                allow_missing_audited=(
                    payload["completion_head_digest"] if existing_event is not None else None
                ),
            )
            signed_head = receipt_digest(proof["completion_chain"][-1]["completion_record"])
            if existing_event is None and any(
                other != payload["completion_head_digest"] and value == signed_head
                for other, value in signed_heads.items()
            ):
                raise SourceCompletionConflict(
                    "same signed completion already binds a different proof wrapper"
                )
            if pending and not existing_event and payload["completion_head_digest"] not in pending:
                raise SourceCompletionPending(
                    "source inbox has an unaudited proof; reconcile it first"
                )
            if path.exists() or path.is_symlink():
                existing_raw = self._read_raw(path)
                if existing_event is not None and (
                    "sha256:" + hashlib.sha256(existing_raw).hexdigest()
                    != existing_event.payload["proof_digest"]
                ):
                    raise SourceCompletionCorrupt("audited source proof content changed")
                if existing_raw != raw:
                    raise SourceCompletionConflict("source inbox head binds a different proof")
            else:
                if count >= _MAX_HEADS_PER_CLAIM or total + len(raw) > _MAX_BYTES_PER_CLAIM:
                    raise SourceCompletionConflict("source inbox is at capacity")
                slot.mkdir(parents=True, exist_ok=True)
                self._check_slot(slot)
                if _requires_directory_fsync():
                    _sync_directory_chain(slot, self.workspace)
                self._write_immutable(path, raw)
            if existing_event is None:
                try:
                    event, created = self.spine.append_unique(
                        RECEIVED_EVENT, payload,
                        unique_payload_fields=("completion_key",),
                    )
                except SpineSemanticConflict as exc:
                    raise SourceCompletionConflict("source audit binds a different proof") from exc
            else:
                event, created = existing_event, False
            if not source_identity_precedes(
                self.workspace, event.author_did, self.source_did,
            ) or not _same_payload_bytes(event.payload, payload):
                raise SourceCompletionCorrupt("source audit signer or payload changed")
            retained, _, _, lineage = self._lineage_state(slot)
            if payload["completion_head_digest"] not in retained:
                raise SourceCompletionCorrupt("recorded proof is absent from source lineage")
            return self._summary(payload, event, created=created, lineage=lineage)

    def reconcile_pending(
        self, source_claim_id: str, head_hex: str, *, expected_proof_digest: str,
    ) -> dict[str, Any]:
        """Explicitly audit one retained, source-verified proof by exact digest."""
        slot = self._slot(source_claim_id)
        digest = "sha256:" + self._digest(head_hex)
        if (
            not isinstance(expected_proof_digest, str)
            or not expected_proof_digest.startswith("sha256:")
            or _DIGEST_RE.fullmatch(expected_proof_digest[7:]) is None
        ):
            raise SourceCompletionRejected("expected proof digest is invalid")
        self._check_slot(slot)
        if not slot.exists():
            if self._audited_heads(source_claim_id):
                raise SourceCompletionCorrupt("audited source proof is missing")
            raise SourceCompletionRejected("pending source proof is absent")
        with InterProcessLock(self._lock_target(source_claim_id)):
            retained, pending, _, lineage = self._lineage_state(slot)
            item = retained.get(digest)
            if item is not None:
                payload, event = item
                if payload["proof_digest"] != expected_proof_digest:
                    raise SourceCompletionConflict("source proof digest differs")
                return self._summary(payload, event, created=False, lineage=lineage)
            payload = pending.get(digest)
            if payload is None:
                raise SourceCompletionRejected("pending source proof is absent")
            if payload["proof_digest"] != expected_proof_digest:
                raise SourceCompletionConflict("source proof digest differs")
            try:
                event, created = self.spine.append_unique(
                    RECEIVED_EVENT, payload, unique_payload_fields=("completion_key",),
                )
            except SpineSemanticConflict as exc:
                raise SourceCompletionConflict("source audit binds a different proof") from exc
            retained, _, _, lineage = self._lineage_state(slot)
            if digest not in retained or retained[digest][1].event_id != event.event_id:
                raise SourceCompletionCorrupt("reconciled source audit does not match")
            return self._summary(payload, event, created=created, lineage=lineage)

    def get(self, source_claim_id: str, head_hex: str) -> dict[str, Any] | None:
        slot = self._slot(source_claim_id)
        self._digest(head_hex)
        self._check_slot(slot)
        if not slot.exists():
            if self._audited_heads(source_claim_id):
                raise SourceCompletionCorrupt("audited source proof is missing")
            if not slot.exists():
                return None
        with InterProcessLock(self._lock_target(source_claim_id)):
            self._entries(slot)
            retained, pending, _, lineage = self._lineage_state(slot)
            item = retained.get(f"sha256:{head_hex}")
            if item is None:
                if f"sha256:{head_hex}" in pending:
                    raise SourceCompletionPending("source proof is pending audit")
                return None
            payload, event = item
            return self._summary(payload, event, created=False, lineage=lineage)


__all__ = [
    "RECEIVED_EVENT",
    "SourceCompletionConflict",
    "SourceCompletionCorrupt",
    "SourceCompletionEvidenceUnavailable",
    "SourceCompletionInbox",
    "SourceCompletionPending",
    "SourceCompletionRejected",
]
