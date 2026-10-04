"""Locally retained, dual-signed source identity rotation evidence."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from nth_dao.did_key import is_did_key
from nth_dao.identity import AgentIdentity
from nth_dao.util.io import InterProcessLock
from nth_dao.util.jsonl_safe import safe_append_jsonl

logger = logging.getLogger("nth_dao.market.source_identity")

_KIND = "nth-market-source-identity-rotation"
_FIELDS = frozenset({
    "kind", "version", "previous_did", "successor_did", "created_at_ms",
    "previous_sig", "successor_sig",
})
_MAX_LOG_BYTES = 1024 * 1024


def _rotation_path(workspace: Path) -> Path:
    return Path(workspace) / "market_feed" / "source_identity_rotations.jsonl"


def record_source_identity_rotation(
    workspace: Path, previous: AgentIdentity, successor: AgentIdentity,
) -> dict[str, Any]:
    """Retain a planned rotation while both signing keys are available.

    This does not rotate the workspace key or team ownership. Lost-key
    guardian recovery needs a separate, anchored authorization path.
    """
    if not previous.can_sign or not successor.can_sign:
        raise ValueError("both source identities must be able to sign")
    previous_did, successor_did = previous.as_did(), successor.as_did()
    if previous_did == successor_did:
        raise ValueError("source identity rotation must change the DID")
    body = {
        "kind": _KIND, "version": 1,
        "previous_did": previous_did, "successor_did": successor_did,
        "created_at_ms": int(time.time() * 1000),
    }
    record = {
        **body,
        "previous_sig": previous.sign_json(body),
        "successor_sig": successor.sign_json(body),
    }
    if _verified_rotation(record) != (previous_did, successor_did):
        raise ValueError("source identity rotation signatures do not match the DIDs")
    path = _rotation_path(Path(workspace))
    encoded_size = len(json.dumps(record, ensure_ascii=False).encode("utf-8")) + 1
    with InterProcessLock(path.parent / ".locks" / path.name):
        try:
            existing_size = path.stat().st_size
        except FileNotFoundError:
            existing_size = 0
        if existing_size + encoded_size > _MAX_LOG_BYTES:
            raise ValueError("source identity rotation history is at capacity")
        if existing_size:
            with path.open("rb") as stream:
                stream.seek(-1, 2)
                if stream.read(1) != b"\n":
                    raise ValueError("source identity rotation history has a truncated tail")
        safe_append_jsonl(path, record, external_lock_held=True)
    return record


def _verified_rotation(raw: Any) -> tuple[str, str] | None:
    if not isinstance(raw, dict) or frozenset(raw) != _FIELDS:
        return None
    if raw.get("kind") != _KIND or type(raw.get("version")) is not int or raw["version"] != 1:
        return None
    previous, successor = raw.get("previous_did"), raw.get("successor_did")
    created = raw.get("created_at_ms")
    if (
        not isinstance(previous, str) or not is_did_key(previous)
        or not isinstance(successor, str) or not is_did_key(successor)
        or previous == successor or type(created) is not int or created <= 0
    ):
        return None
    body = {key: value for key, value in raw.items() if key not in {"previous_sig", "successor_sig"}}
    try:
        previous_identity = AgentIdentity.from_did(previous)
        successor_identity = AgentIdentity.from_did(successor)
    except ValueError:
        return None
    for identity, signature in (
        (previous_identity, raw["previous_sig"]),
        (successor_identity, raw["successor_sig"]),
    ):
        if not isinstance(signature, str) or len(signature) != 128:
            return None
        if not identity.verify_json(body, signature):
            return None
    return previous, successor


def source_identity_precedes(
    workspace: Path, previous_did: str, current_did: str,
) -> bool:
    """Only a local, unambiguous dual-signed chain authorizes an old DID."""
    if not is_did_key(previous_did) or not is_did_key(current_did):
        return False
    if previous_did == current_did:
        return True
    path = _rotation_path(Path(workspace))
    try:
        path.stat()
    except FileNotFoundError:
        return False
    edges: dict[str, str] = {}
    corrupt_rows = 0
    with InterProcessLock(path.parent / ".locks" / path.name), path.open("rb") as stream:
        data = stream.read(_MAX_LOG_BYTES + 1)
    if len(data) > _MAX_LOG_BYTES:
        raise ValueError("source identity rotation history exceeds its size limit")
    if data and not data.endswith(b"\n"):
        raise ValueError("source identity rotation history has a truncated tail")
    if not data:
        return False
    for seq, line in enumerate(data.split(b"\n")[:-1]):
        try:
            edge = _verified_rotation(json.loads(line))
        except (UnicodeError, ValueError, TypeError, RecursionError):
            edge = None
        if edge is None:
            logger.warning("source identity rotation seq=%d is invalid", seq)
            corrupt_rows += 1
            continue
        old, new = edge
        if old in edges and edges[old] != new:
            logger.warning("source identity rotation history forks at %s", old)
            return False
        edges[old] = new
    visited: set[str] = set()
    candidate = previous_did
    reached_current = False
    while candidate not in visited and candidate in edges:
        visited.add(candidate)
        candidate = edges[candidate]
        if candidate == current_did:
            reached_current = True
    if candidate in visited:
        logger.warning("source identity rotation history contains a cycle")
        return False
    if reached_current and candidate == current_did:
        return True
    if corrupt_rows:
        raise ValueError("corrupt source identity history may conceal the rotation")
    return False


__all__ = ["record_source_identity_rotation", "source_identity_precedes"]
