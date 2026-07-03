"""Signed handoff capsules for agent-to-agent debugging continuity.

A handoff capsule is deliberately modest: it proves who made a structured
claim, which immutable evidence they pointed at, and how later agents refuted
or superseded that claim. It does not prove the claim is correct. The next
agent still has to reason over the pinned evidence.
"""
from __future__ import annotations

import hashlib
import re
import subprocess
from urllib.parse import urlparse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.execution_receipt import now_ms
from nth_dao.identity import AgentIdentity
from nth_dao.spine.event import SpineEvent
from nth_dao.spine.projection import Projection

HANDOFF_CAPSULE_KIND = "nth-handoff-capsule-v1"
HANDOFF_RESPONSE_KIND = "nth-handoff-response-v1"

EVENT_EXEC_HANDOFF = "exec.handoff"
EVENT_EXEC_HANDOFF_REFUTED = "exec.handoff.refuted"
EVENT_EXEC_HANDOFF_SUPERSEDED = "exec.handoff.superseded"

STATUS_PROPOSED = "proposed"
STATUS_CONTESTED = "contested"
STATUS_REFUTED = "refuted"
STATUS_SUPERSESSION_PROPOSED = "supersession_proposed"
STATUS_SUPERSEDED = "superseded"

MAX_HANDOFF_STATEMENT_BYTES = 65536
MAX_HANDOFF_ITEM_BYTES = 4096

VERIFICATION_STATUSES = (
    "unverified",
    "partially_verified",
    "reproduced",
    "refuted",
)
RESPONSE_TYPES = ("refuted", "superseded")

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_SCP_GIT_RE = re.compile(r"^[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+:[^\s]+$")
_REPO_ID_RE = re.compile(r"^[A-Za-z0-9_.:/@+-]{1,256}$")
_ALLOWED_REPO_URL_SCHEMES = {"https", "ssh", "git"}


def _hash_body(stmt: Dict[str, Any], hash_field: str) -> Dict[str, Any]:
    return {k: v for k, v in stmt.items() if k not in ("sig", hash_field)}


def _signing_body(stmt: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in stmt.items() if k != "sig"}


def _digest_statement(stmt: Dict[str, Any], hash_field: str) -> str:
    return "sha256:" + hashlib.sha256(
        canonical_json(_hash_body(stmt, hash_field)),
    ).hexdigest()


def _is_hash(value: Any) -> bool:
    return isinstance(value, str) and bool(_SHA256_RE.match(value))


def _canonical_size(value: Dict[str, Any]) -> int:
    return len(canonical_json(value))


def _validate_statement_size(stmt: Dict[str, Any]) -> None:
    if _canonical_size(stmt) > MAX_HANDOFF_STATEMENT_BYTES:
        raise ValueError("handoff statement too large")


def _validate_item_size(value: Any, field: str) -> None:
    try:
        size = _canonical_size({field: value})
    except TypeError as exc:
        raise ValueError(f"{field} is not canonical JSON") from exc
    if size > MAX_HANDOFF_ITEM_BYTES:
        raise ValueError(f"{field} item too large")


def _require_nonempty_str(
    stmt: Dict[str, Any], field: str, *, max_len: int = 4096,
) -> str:
    value = stmt.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"missing/invalid {field}")
    if len(value) > max_len:
        raise ValueError(f"{field} too long")
    return value


def _validate_repo_path(path: Any) -> None:
    if not isinstance(path, str) or not path:
        raise ValueError("evidence.path required")
    if len(path) > 512:
        raise ValueError("evidence.path too long")
    if "\\" in path:
        raise ValueError("evidence.path must use '/' separators")
    if path.startswith(("/", "~")) or _WINDOWS_DRIVE_RE.match(path):
        raise ValueError("evidence.path must be repository-relative")
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError("evidence.path must not contain empty/dot segments")


def _validate_repo_url(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("source.repo_url must be a non-empty string")
    url = value.strip()
    if len(url) > 1024:
        raise ValueError("source.repo_url too long")
    if any(ch.isspace() for ch in url):
        raise ValueError("source.repo_url must not contain whitespace")
    if "\\" in url or _WINDOWS_DRIVE_RE.match(url) or url.startswith(("/", "~", "file:")):
        raise ValueError("source.repo_url must not be a local path")
    if _SCP_GIT_RE.match(url):
        return url
    parsed = urlparse(url)
    if parsed.scheme not in _ALLOWED_REPO_URL_SCHEMES:
        raise ValueError("source.repo_url must use https, ssh, git, or git@host:path")
    if not parsed.netloc:
        raise ValueError("source.repo_url requires a host")
    if parsed.scheme == "https" and (parsed.username or parsed.password):
        raise ValueError("source.repo_url must not contain userinfo or tokens")
    if parsed.password:
        raise ValueError("source.repo_url must not contain a password")
    return url


def _validate_source_locator(locator: Any, item: Dict[str, Any]) -> None:
    if not isinstance(locator, dict):
        raise ValueError("evidence.source must be a dict")
    if locator.get("type") != "git":
        raise ValueError("evidence.source.type must be 'git'")
    if locator.get("commit") != item.get("commit"):
        raise ValueError("evidence.source.commit must match evidence.commit")
    if locator.get("path") != item.get("path"):
        raise ValueError("evidence.source.path must match evidence.path")
    if locator.get("content_hash") != item.get("content_hash"):
        raise ValueError("evidence.source.content_hash must match evidence.content_hash")
    repo_id = locator.get("repo_id", "")
    if repo_id and (not isinstance(repo_id, str) or not _REPO_ID_RE.match(repo_id)):
        raise ValueError("evidence.source.repo_id is invalid")
    repo_url = locator.get("repo_url", "")
    if repo_url:
        _validate_repo_url(repo_url)


def _git(
    repo_root: str | Path, args: List[str], *, text: bool = True,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(Path(repo_root)), *args],
        check=True,
        capture_output=True,
        text=text,
    )


def _resolve_commit(repo_root: str | Path, commit: str) -> str:
    if commit != "HEAD" and not _COMMIT_RE.match(commit):
        raise ValueError("commit must be HEAD or a hex commit SHA")
    result = _git(repo_root, ["rev-parse", "--verify", f"{commit}^{{commit}}"])
    full = result.stdout.strip()
    if not re.match(r"^[0-9a-f]{40,64}$", full):
        raise ValueError("git returned an invalid commit SHA")
    return full


def source_evidence_from_git(
    repo_root: str | Path,
    path: str,
    *,
    commit: str = "HEAD",
    symbol: str = "",
    line_hint: Optional[int] = None,
    end_line_hint: Optional[int] = None,
    repo_url: str = "",
    repo_id: str = "",
) -> Dict[str, Any]:
    """Build a source_span evidence pointer from an immutable git blob."""
    _validate_repo_path(path)
    full_commit = _resolve_commit(repo_root, commit)
    blob = _git(repo_root, ["show", f"{full_commit}:{path}"], text=False).stdout
    item: Dict[str, Any] = {
        "kind": "source_span",
        "commit": full_commit,
        "path": path,
        "content_hash": "sha256:" + hashlib.sha256(blob).hexdigest(),
    }
    if symbol:
        item["symbol"] = str(symbol)
    if line_hint is not None:
        item["line_hint"] = int(line_hint)
    if end_line_hint is not None:
        item["end_line_hint"] = int(end_line_hint)
    if repo_url or repo_id:
        source: Dict[str, Any] = {
            "type": "git",
            "commit": full_commit,
            "path": path,
            "content_hash": item["content_hash"],
        }
        if repo_url:
            source["repo_url"] = _validate_repo_url(repo_url)
        if repo_id:
            if not _REPO_ID_RE.match(repo_id):
                raise ValueError("repo_id is invalid")
            source["repo_id"] = repo_id
        item["source"] = source
    _validate_source_evidence(item)
    _validate_item_size(item, "evidence")
    return item


def verify_source_evidence_report(
    repo_root: str | Path, evidence: Dict[str, Any],
) -> Dict[str, Any]:
    """Return a structured local verification report for source evidence.

    Cross-node consumers can use the optional ``source`` locator to fetch the
    same git object elsewhere, then run this verifier against their checkout.
    """
    report: Dict[str, Any] = {
        "kind": evidence.get("kind") if isinstance(evidence, dict) else "",
        "path": evidence.get("path") if isinstance(evidence, dict) else "",
        "commit": evidence.get("commit") if isinstance(evidence, dict) else "",
        "content_hash": evidence.get("content_hash") if isinstance(evidence, dict) else "",
        "source": evidence.get("source", {}) if isinstance(evidence, dict) else {},
        "status": "invalid",
        "reason": "",
        "local_reachable": False,
        "content_match": False,
    }
    try:
        _validate_source_evidence(evidence)
    except (TypeError, ValueError) as exc:
        report["reason"] = str(exc)
        return report
    try:
        rebuilt = source_evidence_from_git(
            repo_root,
            str(evidence["path"]),
            commit=str(evidence["commit"]),
        )
        report["local_reachable"] = True
    except (OSError, subprocess.CalledProcessError, TypeError, ValueError) as exc:
        report["status"] = "unreachable"
        report["reason"] = str(exc)
        return report
    if rebuilt["content_hash"] != evidence.get("content_hash"):
        report["status"] = "mismatch"
        report["reason"] = "content_hash mismatch"
        return report
    report["status"] = "verified"
    report["reason"] = "ok"
    report["content_match"] = True
    return report


def verify_source_evidence(
    repo_root: str | Path, evidence: Dict[str, Any],
) -> Tuple[bool, str]:
    """Verify a source_span evidence pointer against a local git checkout."""
    report = verify_source_evidence_report(repo_root, evidence)
    return report["status"] == "verified", str(report.get("reason", ""))


def _validate_source_evidence(item: Dict[str, Any]) -> None:
    commit = item.get("commit")
    if not isinstance(commit, str) or not _COMMIT_RE.match(commit):
        raise ValueError("source_span evidence requires commit SHA")
    _validate_repo_path(item.get("path"))
    if "line_hint" in item:
        line_hint = item["line_hint"]
        if not isinstance(line_hint, int) or isinstance(line_hint, bool) or line_hint < 1:
            raise ValueError("evidence.line_hint must be a positive int")
    if "end_line_hint" in item:
        end_line_hint = item["end_line_hint"]
        if (
            not isinstance(end_line_hint, int)
            or isinstance(end_line_hint, bool)
            or end_line_hint < 1
        ):
            raise ValueError("evidence.end_line_hint must be a positive int")
    if "source" in item:
        _validate_source_locator(item["source"], item)


def _validate_evidence_list(evidence: Any) -> List[Dict[str, Any]]:
    if not isinstance(evidence, list) or not evidence:
        raise ValueError("evidence must be a non-empty list")
    if len(evidence) > 64:
        raise ValueError("too many evidence entries")
    out: List[Dict[str, Any]] = []
    for raw in evidence:
        if not isinstance(raw, dict):
            raise ValueError("evidence entries must be dicts")
        kind = raw.get("kind")
        if not isinstance(kind, str) or not kind:
            raise ValueError("evidence.kind required")
        if not _is_hash(raw.get("content_hash")):
            raise ValueError("evidence.content_hash must be sha256:<hex>")
        if kind == "source_span":
            _validate_source_evidence(raw)
        _validate_item_size(raw, "evidence")
        out.append(dict(raw))
    return out


def _validate_json_list_field(stmt: Dict[str, Any], field: str, *, limit: int) -> None:
    value = stmt.get(field)
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list")
    if len(value) > limit:
        raise ValueError(f"{field} too long")
    for item in value:
        _validate_item_size(item, field)


def _validate_str_list_field(
    stmt: Dict[str, Any], field: str, *, limit: int, item_max_len: int = 512,
) -> None:
    value = stmt.get(field)
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list")
    if len(value) > limit:
        raise ValueError(f"{field} too long")
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{field} entries must be strings")
        if len(item) > item_max_len:
            raise ValueError(f"{field} entry too long")


def _validate_capsule_shape(stmt: Dict[str, Any]) -> None:
    if not isinstance(stmt, dict):
        raise ValueError("not a dict")
    if stmt.get("kind") != HANDOFF_CAPSULE_KIND:
        raise ValueError("wrong kind")
    _require_nonempty_str(stmt, "mission_id", max_len=160)
    _require_nonempty_str(stmt, "finding")
    _require_nonempty_str(stmt, "root_cause_hypothesis")
    _require_nonempty_str(stmt, "author_did", max_len=256)
    _require_nonempty_str(stmt, "sig", max_len=512)
    step_id = stmt.get("step_id", "")
    if not isinstance(step_id, str) or len(step_id) > 160:
        raise ValueError("step_id must be a short string")
    current_status = stmt.get("current_status", "")
    if not isinstance(current_status, str) or len(current_status) > 512:
        raise ValueError("current_status must be a short string")
    if not _is_hash(stmt.get("capsule_hash")):
        raise ValueError("capsule_hash must be sha256:<hex>")
    verification_status = stmt.get("verification_status")
    if verification_status not in VERIFICATION_STATUSES:
        raise ValueError("invalid verification_status")
    parent_hash = stmt.get("parent_capsule_hash", "")
    if parent_hash and not _is_hash(parent_hash):
        raise ValueError("parent_capsule_hash must be sha256:<hex>")
    issued_at = stmt.get("issued_at_ms")
    if not isinstance(issued_at, int) or isinstance(issued_at, bool) or issued_at <= 0:
        raise ValueError("issued_at_ms must be a positive int")
    _validate_evidence_list(stmt.get("evidence"))
    _validate_str_list_field(stmt, "changed_files", limit=64, item_max_len=512)
    _validate_json_list_field(stmt, "tests", limit=64)
    _validate_str_list_field(stmt, "next_actions", limit=32, item_max_len=512)
    _validate_str_list_field(stmt, "risks", limit=32, item_max_len=512)
    _validate_statement_size(stmt)


def _validate_response_shape(stmt: Dict[str, Any]) -> None:
    if not isinstance(stmt, dict):
        raise ValueError("not a dict")
    if stmt.get("kind") != HANDOFF_RESPONSE_KIND:
        raise ValueError("wrong kind")
    response_type = stmt.get("response_type")
    if response_type not in RESPONSE_TYPES:
        raise ValueError("invalid response_type")
    _require_nonempty_str(stmt, "mission_id", max_len=160)
    _require_nonempty_str(stmt, "reason")
    _require_nonempty_str(stmt, "author_did", max_len=256)
    _require_nonempty_str(stmt, "sig", max_len=512)
    if not _is_hash(stmt.get("response_hash")):
        raise ValueError("response_hash must be sha256:<hex>")
    if not _is_hash(stmt.get("target_capsule_hash")):
        raise ValueError("target_capsule_hash must be sha256:<hex>")
    replacement_hash = stmt.get("replacement_capsule_hash", "")
    if response_type == "superseded" and not _is_hash(replacement_hash):
        raise ValueError("superseded responses require replacement_capsule_hash")
    if replacement_hash and not _is_hash(replacement_hash):
        raise ValueError("replacement_capsule_hash must be sha256:<hex>")
    issued_at = stmt.get("issued_at_ms")
    if not isinstance(issued_at, int) or isinstance(issued_at, bool) or issued_at <= 0:
        raise ValueError("issued_at_ms must be a positive int")
    counter_evidence = stmt.get("counter_evidence", [])
    if counter_evidence:
        _validate_evidence_list(counter_evidence)
    elif not isinstance(counter_evidence, list):
        raise ValueError("counter_evidence must be a list")
    _validate_statement_size(stmt)


def sign_handoff_capsule(
    *,
    signer: AgentIdentity,
    mission_id: str,
    finding: str,
    root_cause_hypothesis: str,
    evidence: List[Dict[str, Any]],
    step_id: str = "",
    changed_files: Optional[List[str]] = None,
    tests: Optional[List[Any]] = None,
    current_status: str = "",
    next_actions: Optional[List[str]] = None,
    risks: Optional[List[str]] = None,
    verification_status: str = "unverified",
    parent_capsule_hash: str = "",
    issued_at_ms: int = 0,
) -> Dict[str, Any]:
    """Sign a handoff claim.

    The resulting signature verifies author and byte-level integrity only. It
    does not certify that ``root_cause_hypothesis`` is true.
    """
    stmt: Dict[str, Any] = {
        "kind": HANDOFF_CAPSULE_KIND,
        "mission_id": str(mission_id),
        "step_id": str(step_id),
        "finding": str(finding),
        "root_cause_hypothesis": str(root_cause_hypothesis),
        "evidence": [dict(item) for item in evidence],
        "changed_files": [str(item) for item in (changed_files or [])],
        "tests": list(tests or []),
        "current_status": str(current_status),
        "next_actions": [str(item) for item in (next_actions or [])],
        "risks": [str(item) for item in (risks or [])],
        "verification_status": str(verification_status),
        "parent_capsule_hash": str(parent_capsule_hash),
        "author_did": signer.as_did(),
        "issued_at_ms": int(issued_at_ms or now_ms()),
    }
    stmt["capsule_hash"] = _digest_statement(stmt, "capsule_hash")
    _validate_capsule_shape({**stmt, "sig": "placeholder"})
    stmt["sig"] = b64u_encode(signer.sign(canonical_json(_signing_body(stmt))))
    return stmt


def verify_handoff_capsule(stmt: Dict[str, Any]) -> Tuple[bool, str]:
    """Verify capsule structure, content hash, and author signature.

    This intentionally does not verify that the finding or root-cause
    hypothesis is correct. Later agents should inspect evidence and, when
    needed, record a refutation or superseding capsule.
    """
    try:
        _validate_capsule_shape(stmt)
        expected_hash = _digest_statement(stmt, "capsule_hash")
        if stmt["capsule_hash"] != expected_hash:
            return False, "capsule_hash mismatch"
        verifier = AgentIdentity.from_did(stmt["author_did"])
        sig = b64u_decode(stmt["sig"])
        body = canonical_json(_signing_body(stmt))
    except Exception as exc:  # noqa: BLE001
        return False, f"bad handoff capsule: {exc}"
    if not verifier.verify(body, sig):
        return False, "signature invalid"
    return True, "ok"


def sign_handoff_response(
    *,
    signer: AgentIdentity,
    response_type: str,
    target_capsule_hash: str,
    mission_id: str,
    reason: str,
    counter_evidence: Optional[List[Dict[str, Any]]] = None,
    replacement_capsule_hash: str = "",
    issued_at_ms: int = 0,
) -> Dict[str, Any]:
    """Sign a refutation or supersession for an existing capsule."""
    stmt: Dict[str, Any] = {
        "kind": HANDOFF_RESPONSE_KIND,
        "response_type": str(response_type),
        "target_capsule_hash": str(target_capsule_hash),
        "replacement_capsule_hash": str(replacement_capsule_hash),
        "mission_id": str(mission_id),
        "reason": str(reason),
        "counter_evidence": [dict(item) for item in (counter_evidence or [])],
        "author_did": signer.as_did(),
        "issued_at_ms": int(issued_at_ms or now_ms()),
    }
    stmt["response_hash"] = _digest_statement(stmt, "response_hash")
    _validate_response_shape({**stmt, "sig": "placeholder"})
    stmt["sig"] = b64u_encode(signer.sign(canonical_json(_signing_body(stmt))))
    return stmt


def verify_handoff_response(stmt: Dict[str, Any]) -> Tuple[bool, str]:
    """Verify a signed response to a capsule."""
    try:
        _validate_response_shape(stmt)
        expected_hash = _digest_statement(stmt, "response_hash")
        if stmt["response_hash"] != expected_hash:
            return False, "response_hash mismatch"
        verifier = AgentIdentity.from_did(stmt["author_did"])
        sig = b64u_decode(stmt["sig"])
        body = canonical_json(_signing_body(stmt))
    except Exception as exc:  # noqa: BLE001
        return False, f"bad handoff response: {exc}"
    if not verifier.verify(body, sig):
        return False, "signature invalid"
    return True, "ok"


def record_handoff(spine: Any, statement: Dict[str, Any]) -> Any:
    """Record a valid handoff capsule to the signed spine."""
    ok, why = verify_handoff_capsule(statement)
    if not ok:
        raise ValueError(f"refusing to record invalid handoff capsule: {why}")
    return spine.append(EVENT_EXEC_HANDOFF, statement)


def record_handoff_response(spine: Any, statement: Dict[str, Any]) -> Any:
    """Record a valid handoff refutation or supersession to the signed spine."""
    ok, why = verify_handoff_response(statement)
    if not ok:
        raise ValueError(f"refusing to record invalid handoff response: {why}")
    event_type = (
        EVENT_EXEC_HANDOFF_SUPERSEDED
        if statement.get("response_type") == "superseded"
        else EVENT_EXEC_HANDOFF_REFUTED
    )
    return spine.append(event_type, statement)


@dataclass
class HandoffRecord:
    capsule_hash: str
    mission_id: str
    author_did: str
    capsule: Dict[str, Any]
    status: str = STATUS_PROPOSED
    refutations: List[Dict[str, Any]] = field(default_factory=list)
    superseded_by: str = ""
    supersessions: List[Dict[str, Any]] = field(default_factory=list)


ResponderAuthorizer = Callable[[HandoffRecord, Dict[str, Any]], Tuple[bool, str]]


class HandoffProjection(Projection):
    """Fold signed handoff events into current capsule state."""

    def __init__(
        self,
        trusted_responders: Optional[Iterable[str]] = None,
        responder_authorizer: Optional[ResponderAuthorizer] = None,
    ) -> None:
        self._records: Dict[str, HandoffRecord] = {}
        self._by_mission: Dict[str, List[str]] = {}
        self._trusted_responders: Set[str] = set(trusted_responders or [])
        self._responder_authorizer = responder_authorizer

    def reset(self) -> None:
        self._records.clear()
        self._by_mission.clear()

    def apply(self, event: SpineEvent) -> None:
        if event.type == EVENT_EXEC_HANDOFF:
            self._apply_capsule(event.payload if isinstance(event.payload, dict) else {})
            return
        if event.type in (EVENT_EXEC_HANDOFF_REFUTED, EVENT_EXEC_HANDOFF_SUPERSEDED):
            self._apply_response(event.payload if isinstance(event.payload, dict) else {})

    def _apply_capsule(self, stmt: Dict[str, Any]) -> None:
        ok, _ = verify_handoff_capsule(stmt)
        if not ok:
            return
        capsule_hash = stmt["capsule_hash"]
        if capsule_hash in self._records:
            return
        rec = HandoffRecord(
            capsule_hash=capsule_hash,
            mission_id=stmt["mission_id"],
            author_did=stmt["author_did"],
            capsule=dict(stmt),
        )
        self._records[capsule_hash] = rec
        self._by_mission.setdefault(rec.mission_id, []).append(capsule_hash)
        self._resolve_waiting_supersessions(capsule_hash)

    def _apply_response(self, stmt: Dict[str, Any]) -> None:
        ok, _ = verify_handoff_response(stmt)
        if not ok:
            return
        rec = self._records.get(stmt["target_capsule_hash"])
        if rec is None:
            return
        if stmt["mission_id"] != rec.mission_id:
            return
        authorized, reason = self._authorize_response(rec, stmt)
        stored = dict(stmt)
        stored["authorized"] = authorized
        stored["authorization_reason"] = reason
        if stmt["response_type"] == "refuted":
            rec.refutations.append(stored)
            if authorized:
                rec.status = STATUS_REFUTED
            elif rec.status == STATUS_PROPOSED:
                rec.status = STATUS_CONTESTED
            return
        rec.supersessions.append(stored)
        rec.superseded_by = stmt.get("replacement_capsule_hash", "")
        if authorized and self._valid_replacement(rec):
            rec.status = STATUS_SUPERSEDED
        elif authorized and rec.status == STATUS_PROPOSED:
            rec.status = STATUS_SUPERSESSION_PROPOSED
        elif not authorized and rec.status == STATUS_PROPOSED:
            rec.status = STATUS_CONTESTED

    def _authorize_response(
        self, rec: HandoffRecord, stmt: Dict[str, Any],
    ) -> Tuple[bool, str]:
        responder = str(stmt.get("author_did", "") or "")
        if responder == rec.author_did:
            return True, "capsule_author"
        if responder in self._trusted_responders:
            return True, "trusted_responder"
        if self._responder_authorizer is None:
            return False, "not_authorized"
        try:
            allowed, reason = self._responder_authorizer(rec, stmt)
        except (RuntimeError, TypeError, ValueError) as exc:
            return False, f"authorizer_error:{exc}"
        return bool(allowed), str(reason or ("authorized" if allowed else "not_authorized"))

    def _valid_replacement(self, rec: HandoffRecord) -> bool:
        replacement = self._records.get(rec.superseded_by)
        return replacement is not None and replacement.mission_id == rec.mission_id

    def _resolve_waiting_supersessions(self, capsule_hash: str) -> None:
        for rec in self._records.values():
            if rec.superseded_by == capsule_hash and rec.status == STATUS_SUPERSESSION_PROPOSED:
                if self._valid_replacement(rec):
                    rec.status = STATUS_SUPERSEDED

    def get(self, capsule_hash: str) -> Optional[HandoffRecord]:
        return self._records.get(capsule_hash)

    def for_mission(self, mission_id: str) -> List[HandoffRecord]:
        return [
            self._records[h]
            for h in self._by_mission.get(mission_id, [])
            if h in self._records
        ]

    def all(self) -> List[HandoffRecord]:
        return list(self._records.values())
