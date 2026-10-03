"""Authority-signed acknowledgement of a cross-DAO claim CAS result."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.did_key import is_did_key
from nth_dao.execution_receipt import verify_receipt
from nth_dao.identity import AgentIdentity
from nth_dao.market.announcement import (
    TaskAnnouncement,
    announcement_federation_key,
)
from nth_dao.util.io import InterProcessLock, atomic_write_json, safe_load_json

AUTHORITY_CLAIM_ACK_KIND = "nth-authority-claim-ack-v1"
_ACK_KEYS = {
    "kind",
    "ack_id",
    "federation_key",
    "announcement_id",
    "claimant_did",
    "claim_receipt_id",
    "claim_receipt_hash",
    "claim_record_hash",
    "authority_did",
    "outcome",
    "accepted_at_ms",
    "authority_sig",
}
_MAX_ACK_FILE_BYTES = 64 * 1024
_ACK_ID_RE = re.compile(r"[0-9a-f]{64}\Z")


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _ack_identity_body(ack: Dict[str, Any]) -> Dict[str, Any]:
    return {
        key: value for key, value in ack.items()
        if key not in {"ack_id", "authority_sig"}
    }


def _ack_signing_body(ack: Dict[str, Any]) -> Dict[str, Any]:
    return {key: value for key, value in ack.items() if key != "authority_sig"}


def sign_authority_claim_ack(
    *,
    authority: AgentIdentity,
    announcement: TaskAnnouncement,
    claim_record: Dict[str, Any],
) -> Dict[str, Any]:
    """Sign the authority's durable acceptance of one claimant receipt."""
    if not authority.can_sign:
        raise ValueError("claim authority identity cannot sign")
    authority_did = authority.as_did()
    if announcement.effective_authority_did() != authority_did:
        raise ValueError("signer is not the announcement claim authority")
    if not isinstance(claim_record, dict):
        raise ValueError("claim_record must be an object")
    receipt = claim_record.get("receipt")
    claimant_did = claim_record.get("claimant_did")
    receipt_id = claim_record.get("receipt_id")
    claimed_at_ms = claim_record.get("claimed_at_ms")
    if not isinstance(receipt, dict) or not receipt:
        raise ValueError("claim record is missing its signed receipt")
    if not isinstance(claimant_did, str) or not is_did_key(claimant_did):
        raise ValueError("claim record has an invalid claimant DID")
    if not isinstance(receipt_id, str) or not receipt_id:
        raise ValueError("claim record is missing receipt_id")
    if type(claimed_at_ms) is not int or claimed_at_ms <= 0:
        raise ValueError("claim record has an invalid claimed_at_ms")

    ack: Dict[str, Any] = {
        "kind": AUTHORITY_CLAIM_ACK_KIND,
        "federation_key": announcement_federation_key(announcement),
        "announcement_id": announcement.announcement_id,
        "claimant_did": claimant_did,
        "claim_receipt_id": receipt_id,
        "claim_receipt_hash": _sha256_json(receipt),
        "claim_record_hash": _sha256_json(claim_record),
        "authority_did": authority_did,
        "outcome": "claimed",
        "accepted_at_ms": claimed_at_ms,
    }
    ack["ack_id"] = _sha256_json(_ack_identity_body(ack))
    ack["authority_sig"] = b64u_encode(
        authority.sign(canonical_json(_ack_signing_body(ack)))
    )
    return ack


def verify_authority_claim_ack(
    ack: Dict[str, Any],
    *,
    expected_authority_did: str = "",
    expected_federation_key: str = "",
    expected_claimant_did: str = "",
    expected_claim_receipt: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, str]:
    """Verify strict schema, content bindings, identifier and signature."""
    if not isinstance(ack, dict) or set(ack) != _ACK_KEYS:
        return False, "claim ack schema is invalid"
    if ack.get("kind") != AUTHORITY_CLAIM_ACK_KIND:
        return False, "claim ack kind is invalid"
    bounded_strings = (
        "ack_id", "federation_key", "announcement_id", "claimant_did",
        "claim_receipt_id", "claim_receipt_hash", "claim_record_hash",
        "authority_did", "outcome", "authority_sig",
    )
    if any(
        not isinstance(ack.get(field), str)
        or not ack[field]
        or len(ack[field].encode("utf-8")) > 1024
        for field in bounded_strings
    ):
        return False, "claim ack contains an invalid string field"
    if ack.get("outcome") != "claimed":
        return False, "claim ack outcome is invalid"
    if type(ack.get("accepted_at_ms")) is not int or ack["accepted_at_ms"] <= 0:
        return False, "claim ack accepted_at_ms is invalid"
    if not is_did_key(ack["authority_did"]) or not is_did_key(ack["claimant_did"]):
        return False, "claim ack DID is invalid"
    if expected_authority_did and ack["authority_did"] != expected_authority_did:
        return False, "claim ack authority does not match the source"
    if expected_federation_key and ack["federation_key"] != expected_federation_key:
        return False, "claim ack does not bind the requested announcement"
    if expected_claimant_did and ack["claimant_did"] != expected_claimant_did:
        return False, "claim ack does not bind the requesting agent"
    if expected_claim_receipt is not None:
        if not isinstance(expected_claim_receipt, dict):
            return False, "expected claimant receipt is invalid"
        if ack["claim_receipt_id"] != str(
            expected_claim_receipt.get("receipt_id") or ""
        ):
            return False, "claim ack receipt id does not match the claimant receipt"
        if ack["claim_receipt_hash"] != _sha256_json(expected_claim_receipt):
            return False, "claim ack receipt hash does not match the claimant receipt"
    if ack["ack_id"] != _sha256_json(_ack_identity_body(ack)):
        return False, "claim ack identifier is invalid"
    try:
        verifier = AgentIdentity.from_did(ack["authority_did"])
        signature = b64u_decode(ack["authority_sig"])
    except (TypeError, ValueError, UnicodeError) as exc:
        return False, f"claim ack encoding is invalid: {exc}"
    if len(signature) != 64:
        return False, "claim ack signature length is invalid"
    if not verifier.verify(canonical_json(_ack_signing_body(ack)), signature):
        return False, "claim ack signature is invalid"
    return True, "ok"


class AuthorityClaimAckStore:
    """Immutable local store of source-authority claim acknowledgements."""

    _cache_lock = threading.RLock()
    _directory_cache: OrderedDict[Path, dict[str, str]] = OrderedDict()
    _MAX_CACHED_WORKSPACES = 16
    _MAX_DIRECTORY_ENTRIES = 65_536

    def __init__(self, workspace: Path) -> None:
        self.root = Path(workspace) / "federation" / "claim_acks"

    def _cached_bindings(self) -> dict[str, str]:
        key = self.root.absolute()
        mapping = self._directory_cache.setdefault(key, {})
        self._directory_cache.move_to_end(key)
        while len(self._directory_cache) > self._MAX_CACHED_WORKSPACES:
            self._directory_cache.popitem(last=False)
        return mapping

    def _candidates(self, receipt_hash: str) -> list[Path]:
        """Map immutable ACK filenames from disk; never trust a mutable index.

        Enumerating names on every read discovers Git-synced files even when a
        directory mtime is restored. A valid ACK cannot change its receipt
        binding without changing its content-addressed ACK ID.
        """
        if self.root.is_symlink():
            raise ValueError("claim ACK store root must not be a symlink")
        if not self.root.exists():
            return []
        with self._cache_lock:
            mapping = self._cached_bindings()
            with os.scandir(self.root) as entries:
                names = set()
                for count, entry in enumerate(entries, start=1):
                    if count > self._MAX_DIRECTORY_ENTRIES:
                        raise ValueError("claim ACK directory exceeds lookup limit")
                    if entry.name.endswith(".json") and _ACK_ID_RE.fullmatch(
                        entry.name[:-5]
                    ):
                        names.add(entry.name[:-5])
            for missing in mapping.keys() - names:
                del mapping[missing]
            for ack_id in names - mapping.keys():
                try:
                    ack = self._read_ack(self.root / f"{ack_id}.json")
                except (ValueError, OSError, UnicodeError, json.JSONDecodeError) as exc:
                    raise ValueError(
                        "claim ACK store contains an unreadable record"
                    ) from exc
                ok, reason = verify_authority_claim_ack(ack)
                if not ok:
                    raise ValueError(
                        f"claim ACK store contains invalid evidence: {reason}"
                    )
                mapping[ack_id] = ack["claim_receipt_hash"]
            return [self.root / f"{ack_id}.json" for ack_id, value in mapping.items()
                    if value == receipt_hash]

    @staticmethod
    def _read_ack(path: Path) -> Dict[str, Any]:
        if path.is_symlink():
            raise ValueError("claim ACK store contains an unsafe entry")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        before = os.stat(path, follow_symlinks=False)
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            after = os.stat(path, follow_symlinks=False)
            if (
                not stat.S_ISREG(opened.st_mode)
                or not stat.S_ISREG(before.st_mode)
                or not stat.S_ISREG(after.st_mode)
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
                or (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
            ):
                raise ValueError("claim ACK store contains an unsafe entry")
            if opened.st_size > _MAX_ACK_FILE_BYTES:
                raise ValueError("claim ACK store contains an oversized record")
            chunks = []
            remaining = _MAX_ACK_FILE_BYTES + 1
            while remaining:
                chunk = os.read(fd, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) > _MAX_ACK_FILE_BYTES:
                raise ValueError("claim ACK store contains an oversized record")
        finally:
            os.close(fd)

        def unique_fields(pairs: list[tuple[str, Any]]) -> Dict[str, Any]:
            value: Dict[str, Any] = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError("claim ACK record repeats a field")
                value[key] = item
            return value

        ack = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_fields)
        if (
            not isinstance(ack, dict)
            or path.stem != ack.get("ack_id")
            or not isinstance(ack.get("claim_receipt_hash"), str)
            or len(ack["claim_receipt_hash"]) != 64
        ):
            raise ValueError("claim ACK store contains a malformed record")
        return ack

    def audit(self) -> int:
        """Verify every ACK, including records not selected by the lookup index."""
        count = 0
        if self.root.is_symlink():
            raise ValueError("claim ACK store root must not be a symlink")
        if not self.root.exists():
            return count
        for path in self.root.glob("*.json"):
            ack = self._read_ack(path)
            ok, reason = verify_authority_claim_ack(ack)
            if not ok:
                raise ValueError(f"claim ACK store contains invalid evidence: {reason}")
            count += 1
        return count

    def save(self, ack: Dict[str, Any]) -> Path:
        ok, reason = verify_authority_claim_ack(ack)
        if not ok:
            raise ValueError(reason)
        ack_id = str(ack["ack_id"])
        if len(ack_id) != 64 or any(ch not in "0123456789abcdef" for ch in ack_id):
            raise ValueError("claim ack id is not a SHA-256 hex digest")
        if self.root.is_symlink():
            raise ValueError("claim ACK store root must not be a symlink")
        path = self.root / f"{ack_id}.json"
        with InterProcessLock(path):
            if path.exists() or path.is_symlink():
                existing = self._read_ack(path)
                if existing != ack:
                    raise ValueError("claim ack id collision")
            else:
                atomic_write_json(path, ack, ensure_ascii=True, indent=2)
        with self._cache_lock:
            self._cached_bindings()[ack_id] = ack["claim_receipt_hash"]
        return path

    def load(self, ack_id: str) -> Optional[Dict[str, Any]]:
        if (
            not isinstance(ack_id, str)
            or len(ack_id) != 64
            or any(ch not in "0123456789abcdef" for ch in ack_id)
        ):
            return None
        value = safe_load_json(self.root / f"{ack_id}.json", fallback=None)
        return value if isinstance(value, dict) else None

    def find_for_receipt(
        self,
        receipt: Dict[str, Any],
        *,
        expected_authority_did: str,
        expected_federation_key: str,
        expected_claimant_did: str,
    ) -> Optional[Dict[str, Any]]:
        """Resolve a retained ACK by exact signed receipt and pinned source.

        No untrusted directory index may omit a candidate. Malformed files
        with valid ACK names fail closed because their receipt binding cannot
        be recovered from their content.
        """

        if (
            not isinstance(receipt, dict)
            or not verify_receipt(receipt)
            or receipt.get("signer_did") != expected_claimant_did
            or not is_did_key(expected_claimant_did)
            or not is_did_key(expected_authority_did)
            or not isinstance(expected_federation_key, str)
            or not expected_federation_key
        ):
            raise ValueError(
                "claim evidence lookup requires a signed receipt and pinned source"
            )
        timeline = receipt.get("timeline")
        if not isinstance(timeline, list) or len(timeline) != 1:
            raise ValueError("claim receipt must contain one signed claim event")
        entry = timeline[0]
        payload = entry.get("payload") if isinstance(entry, dict) else None
        if (
            not isinstance(payload, dict)
            or entry.get("type") != "nth.task_claimed"
            or payload.get("claimant_did") != expected_claimant_did
            or not isinstance(payload.get("announcement_id"), str)
            or not payload["announcement_id"]
            or receipt.get("goal_id")
            != f"market:claim:{payload.get('announcement_id', '')}"
        ):
            raise ValueError("claim receipt envelope does not bind its signed event")
        wanted_hash = _sha256_json(receipt)
        matches: list[Dict[str, Any]] = []
        try:
            for path in self._candidates(wanted_hash):
                ack = self._read_ack(path)
                ok, reason = verify_authority_claim_ack(ack)
                if not ok:
                    raise ValueError(
                        f"claim ACK store contains invalid evidence: {reason}"
                    )
                if ack["claim_receipt_hash"] != wanted_hash:
                    raise ValueError("indexed claim ACK receipt binding changed")
                if ack["authority_did"] != expected_authority_did:
                    continue
                ok, reason = verify_authority_claim_ack(
                    ack,
                    expected_authority_did=expected_authority_did,
                    expected_federation_key=expected_federation_key,
                    expected_claimant_did=expected_claimant_did,
                    expected_claim_receipt=receipt,
                )
                if not ok:
                    raise ValueError(
                        f"matching claim ACK does not bind the source: {reason}"
                    )
                if ack["announcement_id"] != payload["announcement_id"]:
                    raise ValueError(
                        "matching claim ACK does not bind the signed claim event"
                    )
                matches.append(ack)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("claim ACK store cannot be audited") from exc
        if len(matches) > 1:
            raise ValueError("more than one source ACK binds the same claim receipt")
        return matches[0] if matches else None
