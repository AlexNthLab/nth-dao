"""Durable write-ahead audit for federated Recognition proof imports."""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from nth_dao.did_key import is_did_key
from nth_dao.spine import SignedEventLog, SpineEvent
from nth_dao.trade_rules.canonical import (
    MAX_TRADE_JSON_BYTES,
    TradeCanonicalJSONError,
    parse_trade_json,
    trade_canonical_json,
)
from nth_dao.trade_rules.recognition_transport import (
    MAX_RULE_RECOGNITION_PROOF_BUNDLE_STATEMENTS,
    VerifiedRuleRecognitionProofBundle,
)
from nth_dao.trade_rules.recognition import MAX_RULE_RECOGNITION_STATEMENTS
from nth_dao.trade_rules.recognition_transport_pages import (
    MAX_RULE_RECOGNITION_PROOF_PAGES,
    MAX_RULE_RECOGNITION_PROOF_PAGE_STATEMENTS,
    RULE_RECOGNITION_PROOF_PAGE_KIND,
    VerifiedRuleRecognitionProofPage,
)
from nth_dao.util.io import InterProcessLock, atomic_write_bytes

EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORT_PROPOSED = (
    "trade.rule-recognition-proof.import.proposed"
)
EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORTED = (
    "trade.rule-recognition-proof.imported"
)
RULE_RECOGNITION_PROOF_IMPORT_PROTOCOL_VERSION = "1"
RULE_RECOGNITION_PROOF_PAGE_IMPORT_PROTOCOL_VERSION = "2"
DEFAULT_MAX_RULE_RECOGNITION_PROOFS = 2_048
DEFAULT_MAX_RULE_RECOGNITION_PROOF_STORE_BYTES = 512 * 1024 * 1024

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IMPORT_ID = re.compile(r"^[0-9a-f]{64}$")
_FIELDS_V1 = frozenset({
    "protocol_version",
    "import_id",
    "order_digest",
    "offer_digest",
    "package_digest",
    "proof_digest",
    "observer_did",
    "observed_heads_digest",
    "source_origin",
    "statement_digests",
    "action",
})
_FIELDS_V2_PAGE = _FIELDS_V1 | frozenset({
    "proof_kind",
    "observation_digest",
    "page_index",
    "page_count",
    "statement_count",
    "statement_set_digest",
})
_ACTIONS = {
    EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORT_PROPOSED: (
        "recognition-proof-import-proposed"
    ),
    EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORTED: (
        "recognition-proof-imported"
    ),
}


class RuleRecognitionProofImportError(RuntimeError):
    """A proof import CAS or Spine binding is invalid or unavailable."""


RuleRecognitionProofDocument = (
    VerifiedRuleRecognitionProofBundle | VerifiedRuleRecognitionProofPage
)


def recognition_proof_digest(
    proof: RuleRecognitionProofDocument,
) -> str:
    if not isinstance(
        proof,
        (VerifiedRuleRecognitionProofBundle, VerifiedRuleRecognitionProofPage),
    ):
        raise TypeError("proof must be a verified Recognition proof document")
    return "sha256:" + hashlib.sha256(proof.canonical_bytes).hexdigest()


def recognition_proof_import_id(
    *,
    order_digest: str,
    package_digest: str,
    proof_digest: str,
    source_origin: str,
) -> str:
    binding = {
        "order_digest": order_digest,
        "package_digest": package_digest,
        "proof_digest": proof_digest,
        "source_origin": source_origin,
    }
    return hashlib.sha256(trade_canonical_json(binding)).hexdigest()


def canonical_recognition_source_origin(value: str) -> str:
    """Return the semantic HTTP origin used for observation matching.

    Historical signed import events retain their original spelling.  This
    projection is deliberately separate from ``import_id`` so an upgrade can
    match equivalent origins without invalidating those signed payloads.
    """

    if (
        not isinstance(value, str)
        or not 8 <= len(value) <= 2_048
        or value != value.strip()
        or re.fullmatch(
            r"https?://[^/\\?#\x00-\x20\x7f]+",
            value,
            flags=re.IGNORECASE,
        )
        is None
    ):
        raise ValueError("Recognition source origin is invalid")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Recognition source origin is invalid") from exc
    scheme = parsed.scheme.lower()
    if (
        scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Recognition source origin must be an HTTP origin")
    host = parsed.hostname.rstrip(".")
    if not host:
        raise ValueError("Recognition source host is invalid")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("Recognition source host is invalid") from exc
    else:
        host = str(address)
        if isinstance(address, ipaddress.IPv6Address):
            host = f"[{host}]"
    if port is not None and not (
        (scheme == "http" and port == 80)
        or (scheme == "https" and port == 443)
    ):
        host = f"{host}:{port}"
    return f"{scheme}://{host}"


def recognition_proof_observation_id(value: dict[str, Any]) -> str:
    """Identify one observed graph independently of envelope refresh time."""

    if not isinstance(value, dict):
        raise TypeError("Recognition proof import payload must be an object")
    fields = (
        "order_digest",
        "offer_digest",
        "package_digest",
        "observer_did",
        "observed_heads_digest",
        "source_origin",
        "statement_digests",
    )
    if any(field not in value for field in fields):
        raise RuleRecognitionProofImportError(
            "Recognition proof observation binding is incomplete"
        )
    projection = {field: value[field] for field in fields}
    if value.get("protocol_version") == (
        RULE_RECOGNITION_PROOF_PAGE_IMPORT_PROTOCOL_VERSION
    ):
        page_fields = (
            "page_index",
            "page_count",
            "statement_count",
            "statement_set_digest",
        )
        if any(field not in value for field in page_fields):
            raise RuleRecognitionProofImportError(
                "Recognition proof page observation binding is incomplete"
            )
        projection.update({field: value[field] for field in page_fields})
    try:
        projection["source_origin"] = canonical_recognition_source_origin(
            projection["source_origin"]
        )
        return hashlib.sha256(trade_canonical_json(projection)).hexdigest()
    except (TradeCanonicalJSONError, TypeError, ValueError) as exc:
        raise RuleRecognitionProofImportError(
            "Recognition proof observation binding is invalid"
        ) from exc


def _valid_origin(value: Any) -> bool:
    try:
        parsed = urlsplit(value) if isinstance(value, str) else None
    except ValueError:
        return False
    return bool(
        parsed is not None
        and parsed.scheme in {"http", "https"}
        and parsed.hostname
        and not parsed.username
        and not parsed.password
        and parsed.path == ""
        and not parsed.query
        and not parsed.fragment
        and value == f"{parsed.scheme}://{parsed.netloc}"
    )


def validate_recognition_proof_import_payload(
    event_type: str,
    value: Any,
) -> dict[str, Any]:
    if event_type not in _ACTIONS:
        raise RuleRecognitionProofImportError(
            "Recognition proof import event type is invalid"
        )
    if not isinstance(value, dict):
        raise RuleRecognitionProofImportError(
            "Recognition proof import payload has missing or unknown fields"
        )
    protocol_version = value.get("protocol_version")
    fields = (
        _FIELDS_V2_PAGE
        if protocol_version
        == RULE_RECOGNITION_PROOF_PAGE_IMPORT_PROTOCOL_VERSION
        else _FIELDS_V1
    )
    if set(value) != fields:
        raise RuleRecognitionProofImportError(
            "Recognition proof import payload has missing or unknown fields"
        )
    for field in (
        "order_digest",
        "offer_digest",
        "package_digest",
        "proof_digest",
        "observed_heads_digest",
    ):
        if not isinstance(value[field], str) or _DIGEST.fullmatch(value[field]) is None:
            raise RuleRecognitionProofImportError(
                f"Recognition proof import {field} is invalid"
            )
    statement_digests = value["statement_digests"]
    statement_limit = (
        MAX_RULE_RECOGNITION_PROOF_PAGE_STATEMENTS
        if protocol_version
        == RULE_RECOGNITION_PROOF_PAGE_IMPORT_PROTOCOL_VERSION
        else MAX_RULE_RECOGNITION_PROOF_BUNDLE_STATEMENTS
    )
    if (
        not isinstance(statement_digests, list)
        or len(statement_digests) > statement_limit
        or statement_digests != sorted(set(statement_digests))
        or any(
            not isinstance(item, str) or _DIGEST.fullmatch(item) is None
            for item in statement_digests
        )
    ):
        raise RuleRecognitionProofImportError(
            "Recognition proof import statement_digests are invalid"
        )
    if (
        protocol_version
        not in {
            RULE_RECOGNITION_PROOF_IMPORT_PROTOCOL_VERSION,
            RULE_RECOGNITION_PROOF_PAGE_IMPORT_PROTOCOL_VERSION,
        }
        or not isinstance(value["import_id"], str)
        or _IMPORT_ID.fullmatch(value["import_id"]) is None
        or not isinstance(value["observer_did"], str)
        or not is_did_key(value["observer_did"])
        or not _valid_origin(value["source_origin"])
        or value["action"] != _ACTIONS[event_type]
        or value["import_id"]
        != recognition_proof_import_id(
            order_digest=value["order_digest"],
            package_digest=value["package_digest"],
            proof_digest=value["proof_digest"],
            source_origin=value["source_origin"],
        )
    ):
        raise RuleRecognitionProofImportError(
            "Recognition proof import binding is invalid"
        )
    if protocol_version == RULE_RECOGNITION_PROOF_PAGE_IMPORT_PROTOCOL_VERSION:
        for field in ("observation_digest", "statement_set_digest"):
            if (
                not isinstance(value[field], str)
                or _DIGEST.fullmatch(value[field]) is None
            ):
                raise RuleRecognitionProofImportError(
                    f"Recognition proof page import {field} is invalid"
                )
        page_index = value["page_index"]
        page_count = value["page_count"]
        statement_count = value["statement_count"]
        if (
            value["proof_kind"] != RULE_RECOGNITION_PROOF_PAGE_KIND
            or isinstance(page_index, bool)
            or not isinstance(page_index, int)
            or isinstance(page_count, bool)
            or not isinstance(page_count, int)
            or not 1 <= page_count <= MAX_RULE_RECOGNITION_PROOF_PAGES
            or not 0 <= page_index < page_count
            or isinstance(statement_count, bool)
            or not isinstance(statement_count, int)
            or not 0 <= statement_count <= MAX_RULE_RECOGNITION_STATEMENTS
            or len(statement_digests) > statement_count
            or (
                statement_count == 0
                and (page_count != 1 or page_index != 0 or statement_digests)
            )
            or (
                statement_count > 0
                and (not statement_digests or page_count > statement_count)
            )
        ):
            raise RuleRecognitionProofImportError(
                "Recognition proof page import binding is invalid"
            )
    return dict(value)


def recognition_proof_import_payload(
    proof: RuleRecognitionProofDocument,
    *,
    event_type: str,
    order_digest: str,
    offer_digest: str,
    source_origin: str,
) -> dict[str, Any]:
    digest = recognition_proof_digest(proof)
    protocol_version = (
        RULE_RECOGNITION_PROOF_PAGE_IMPORT_PROTOCOL_VERSION
        if isinstance(proof, VerifiedRuleRecognitionProofPage)
        else RULE_RECOGNITION_PROOF_IMPORT_PROTOCOL_VERSION
    )
    payload = {
        "protocol_version": protocol_version,
        "import_id": recognition_proof_import_id(
            order_digest=order_digest,
            package_digest=proof.package_digest,
            proof_digest=digest,
            source_origin=source_origin,
        ),
        "order_digest": order_digest,
        "offer_digest": offer_digest,
        "package_digest": proof.package_digest,
        "proof_digest": digest,
        "observer_did": proof.observer_did,
        "observed_heads_digest": proof.observed_heads_digest,
        "source_origin": source_origin,
        "statement_digests": sorted(
            statement.digest for statement in proof.statements
        ),
        "action": _ACTIONS.get(event_type, ""),
    }
    if isinstance(proof, VerifiedRuleRecognitionProofPage):
        payload.update({
            "proof_kind": RULE_RECOGNITION_PROOF_PAGE_KIND,
            "observation_digest": proof.observation_digest,
            "page_index": proof.page_index,
            "page_count": proof.page_count,
            "statement_count": proof.total_statement_count,
            "statement_set_digest": proof.statement_set_digest,
        })
    return validate_recognition_proof_import_payload(event_type, payload)


@dataclass(frozen=True)
class RuleRecognitionProofImportState:
    payload: dict[str, Any]
    proposed_event: SpineEvent
    completed_event: SpineEvent | None


def recognition_proof_import_states(
    events: tuple[SpineEvent, ...],
    *,
    package_digest: str | None = None,
    order_digest: str | None = None,
) -> tuple[RuleRecognitionProofImportState, ...]:
    proposed: dict[str, tuple[dict[str, Any], SpineEvent]] = {}
    completed: dict[str, tuple[dict[str, Any], SpineEvent]] = {}
    for event in events:
        if event.type not in _ACTIONS:
            continue
        payload = validate_recognition_proof_import_payload(
            event.type,
            event.payload,
        )
        import_id = payload["import_id"]
        target = proposed if event.type.endswith(".proposed") else completed
        if import_id in target:
            raise RuleRecognitionProofImportError(
                "Recognition proof import audit repeats a semantic event"
            )
        target[import_id] = (payload, event)
    if set(completed) - set(proposed):
        raise RuleRecognitionProofImportError(
            "Recognition proof import completion has no write-ahead proposal"
        )
    output = []
    for import_id, (proposal, proposed_event) in proposed.items():
        completion = completed.get(import_id)
        if completion is not None:
            completed_payload, completed_event = completion
            if completed_event.seq <= proposed_event.seq:
                raise RuleRecognitionProofImportError(
                    "Recognition proof import completion precedes its proposal"
                )
            expected = dict(proposal)
            expected["action"] = _ACTIONS[
                EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORTED
            ]
            if completed_payload != expected:
                raise RuleRecognitionProofImportError(
                    "Recognition proof import stages have conflicting bindings"
                )
        else:
            completed_event = None
        if package_digest is not None and proposal["package_digest"] != package_digest:
            continue
        if order_digest is not None and proposal["order_digest"] != order_digest:
            continue
        output.append(
            RuleRecognitionProofImportState(
                payload=proposal,
                proposed_event=proposed_event,
                completed_event=completed_event,
            )
        )
    return tuple(sorted(output, key=lambda item: item.proposed_event.seq))


class RuleRecognitionProofStore:
    """Content-addressed cache for signed proof envelopes used in recovery."""

    def __init__(
        self,
        workspace_root: str | Path,
        *,
        max_proofs: int = DEFAULT_MAX_RULE_RECOGNITION_PROOFS,
        max_bytes: int = DEFAULT_MAX_RULE_RECOGNITION_PROOF_STORE_BYTES,
    ) -> None:
        if (
            isinstance(max_proofs, bool)
            or not isinstance(max_proofs, int)
            or max_proofs <= 0
            or isinstance(max_bytes, bool)
            or not isinstance(max_bytes, int)
            or max_bytes <= 0
        ):
            raise ValueError("proof store limits must be positive integers")
        self.workspace_root = Path(workspace_root).resolve()
        self.root = (
            self.workspace_root / "trade" / "rule_recognition_proofs_v1"
        )
        self.lock_path = self.root / ".locks" / "proofs"
        self.max_proofs = max_proofs
        self.max_bytes = max_bytes

    @staticmethod
    def _is_linklike(path: Path) -> bool:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        return bool(is_junction and is_junction())

    def _assert_safe_path(self, path: Path) -> None:
        resolved = path.resolve(strict=False)
        root = self.root.resolve(strict=False)
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise RuleRecognitionProofImportError(
                "proof store path escapes its root"
            ) from exc
        current = path
        while current != self.workspace_root and current != current.parent:
            if current.exists() and self._is_linklike(current):
                raise RuleRecognitionProofImportError(
                    "proof store must not contain symlinks or junctions"
                )
            current = current.parent

    def _files(self) -> list[Path]:
        self._assert_safe_path(self.root)
        if not self.root.exists():
            return []
        output = []
        for item in sorted(self.root.iterdir()):
            self._assert_safe_path(item)
            if item.name == ".locks" and item.is_dir():
                continue
            if (
                not item.is_file()
                or item.suffix != ".json"
                or len(item.stem) != 64
                or any(character not in "0123456789abcdef" for character in item.stem)
            ):
                raise RuleRecognitionProofImportError(
                    "proof store contains an unexpected entry"
                )
            output.append(item)
        return output

    def _path(self, digest: str) -> Path:
        if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
            raise RuleRecognitionProofImportError("proof digest is invalid")
        path = self.root / f"{digest[7:]}.json"
        self._assert_safe_path(path)
        return path

    def _read_bounded(self, path: Path) -> bytes:
        self._assert_safe_path(path)
        try:
            with path.open("rb") as stream:
                size = os.fstat(stream.fileno()).st_size
                if size > MAX_TRADE_JSON_BYTES:
                    raise RuleRecognitionProofImportError(
                        "stored proof exceeds its byte limit"
                    )
                raw = stream.read(MAX_TRADE_JSON_BYTES + 1)
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise RuleRecognitionProofImportError(
                "stored proof is unavailable"
            ) from exc
        if len(raw) > MAX_TRADE_JSON_BYTES:
            raise RuleRecognitionProofImportError(
                "stored proof exceeds its byte limit"
            )
        if len(raw) != size:
            raise RuleRecognitionProofImportError(
                "stored proof changed while being read"
            )
        return raw

    def put(self, proof: RuleRecognitionProofDocument) -> tuple[str, bool]:
        digest = recognition_proof_digest(proof)
        raw = proof.canonical_bytes
        if len(raw) > MAX_TRADE_JSON_BYTES:
            raise RuleRecognitionProofImportError("proof exceeds its byte limit")
        path = self._path(digest)
        self._assert_safe_path(self.lock_path.parent)
        try:
            with InterProcessLock(self.lock_path, timeout=10.0):
                self.root.mkdir(parents=True, exist_ok=True)
                files = self._files()
                if path.exists():
                    existing = self._read_bounded(path)
                    if existing != raw:
                        raise RuleRecognitionProofImportError(
                            "content-addressed proof bytes changed"
                        )
                    return digest, False
                if len(files) >= self.max_proofs:
                    raise RuleRecognitionProofImportError(
                        "proof store count limit reached"
                    )
                if sum(item.stat().st_size for item in files) + len(raw) > self.max_bytes:
                    raise RuleRecognitionProofImportError(
                        "proof store byte limit reached"
                    )
                atomic_write_bytes(path, raw)
                return digest, True
        except TimeoutError as exc:
            raise RuleRecognitionProofImportError("proof store is busy") from exc
        except OSError as exc:
            raise RuleRecognitionProofImportError(
                "unable to persist Recognition proof"
            ) from exc

    def repair_exact(
        self,
        proof: RuleRecognitionProofDocument,
        *,
        expected_digest: str,
    ) -> bool:
        """Restore one audited CAS object without changing its digest."""

        digest = recognition_proof_digest(proof)
        if digest != expected_digest:
            raise RuleRecognitionProofImportError(
                "repair proof does not match the audited proof digest"
            )
        raw = proof.canonical_bytes
        if len(raw) > MAX_TRADE_JSON_BYTES:
            raise RuleRecognitionProofImportError("proof exceeds its byte limit")
        path = self._path(digest)
        self._assert_safe_path(self.lock_path.parent)
        try:
            with InterProcessLock(self.lock_path, timeout=10.0):
                self.root.mkdir(parents=True, exist_ok=True)
                files = self._files()
                if path.exists():
                    try:
                        existing = self._read_bounded(path)
                    except RuleRecognitionProofImportError:
                        existing = None
                    if existing == raw:
                        return False
                    atomic_write_bytes(path, raw)
                    return True
                if len(files) >= self.max_proofs:
                    raise RuleRecognitionProofImportError(
                        "proof store count limit reached"
                    )
                if sum(item.stat().st_size for item in files) + len(raw) > self.max_bytes:
                    raise RuleRecognitionProofImportError(
                        "proof store byte limit reached"
                    )
                atomic_write_bytes(path, raw)
                return True
        except TimeoutError as exc:
            raise RuleRecognitionProofImportError("proof store is busy") from exc
        except OSError as exc:
            raise RuleRecognitionProofImportError(
                "unable to repair Recognition proof"
            ) from exc

    def get(self, digest: str) -> bytes:
        path = self._path(digest)
        self._assert_safe_path(self.lock_path.parent)
        try:
            with InterProcessLock(self.lock_path, timeout=10.0):
                raw = self._read_bounded(path)
        except FileNotFoundError as exc:
            raise RuleRecognitionProofImportError(
                "stored proof is unavailable"
            ) from exc
        except TimeoutError as exc:
            raise RuleRecognitionProofImportError("proof store is busy") from exc
        if "sha256:" + hashlib.sha256(raw).hexdigest() != digest:
            raise RuleRecognitionProofImportError(
                "stored proof failed its content-address check"
            )
        return raw

    def find_observation_pages(
        self,
        observation_digest: str,
    ) -> tuple[bytes, ...]:
        """Recover all retained page bytes for one signed observation."""

        if (
            not isinstance(observation_digest, str)
            or _DIGEST.fullmatch(observation_digest) is None
        ):
            raise RuleRecognitionProofImportError(
                "observation digest is invalid"
            )
        self._assert_safe_path(self.lock_path.parent)
        try:
            with InterProcessLock(self.lock_path, timeout=10.0):
                matches = []
                for path in self._files():
                    raw = self._read_bounded(path)
                    try:
                        document = parse_trade_json(raw)
                    except TradeCanonicalJSONError as exc:
                        raise RuleRecognitionProofImportError(
                            "stored proof is not canonical Trade JSON"
                        ) from exc
                    if (
                        document.get("kind")
                        == RULE_RECOGNITION_PROOF_PAGE_KIND
                        and document.get("observation_digest")
                        == observation_digest
                    ):
                        matches.append(raw)
                return tuple(matches)
        except TimeoutError as exc:
            raise RuleRecognitionProofImportError("proof store is busy") from exc


def append_recognition_proof_import_event(
    spine: SignedEventLog,
    *,
    event_type: str,
    payload: dict[str, Any],
) -> tuple[SpineEvent, bool]:
    verified = validate_recognition_proof_import_payload(event_type, payload)
    try:
        return spine.append_unique(
            event_type,
            verified,
            unique_payload_fields=("import_id",),
        )
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise RuleRecognitionProofImportError(
            "Recognition proof import audit append failed"
        ) from exc


__all__ = [
    "EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORTED",
    "EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORT_PROPOSED",
    "RULE_RECOGNITION_PROOF_IMPORT_PROTOCOL_VERSION",
    "RULE_RECOGNITION_PROOF_PAGE_IMPORT_PROTOCOL_VERSION",
    "RuleRecognitionProofImportError",
    "RuleRecognitionProofImportState",
    "RuleRecognitionProofDocument",
    "RuleRecognitionProofStore",
    "append_recognition_proof_import_event",
    "canonical_recognition_source_origin",
    "recognition_proof_digest",
    "recognition_proof_import_payload",
    "recognition_proof_import_states",
    "recognition_proof_observation_id",
    "validate_recognition_proof_import_payload",
]
