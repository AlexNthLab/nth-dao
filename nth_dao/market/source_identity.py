"""Locally retained, dual-signed source identity rotation evidence."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from nth_dao.canonical_json import canonical_json
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
MAX_PORTABLE_SOURCE_ROTATION_CHAIN_BYTES = _MAX_LOG_BYTES
MAX_PORTABLE_SOURCE_ROTATION_HOPS = 256


def _rotation_path(workspace: Path) -> Path:
    return Path(workspace) / "market_feed" / "source_identity_rotations.jsonl"


def _unique_json_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("source identity rotation repeats a JSON field")
        value[key] = item
    return value


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


def verify_portable_source_rotation_chain(
    chain: Any, previous_did: str, current_did: str,
) -> bool:
    """Verify an exact dual-signed path from an external DID pin to a signer."""
    if not is_did_key(previous_did) or not is_did_key(current_did):
        return False
    if not isinstance(chain, list) or len(chain) > MAX_PORTABLE_SOURCE_ROTATION_HOPS:
        return False
    try:
        if len(canonical_json({"chain": chain})) > MAX_PORTABLE_SOURCE_ROTATION_CHAIN_BYTES:
            return False
    except (TypeError, ValueError, OverflowError, RecursionError):
        return False
    candidate = previous_did
    visited = {candidate}
    for record in chain:
        edge = _verified_rotation(record)
        if edge is None or edge[0] != candidate or edge[1] in visited:
            return False
        candidate = edge[1]
        visited.add(candidate)
    return candidate == current_did


def export_source_identity_rotation_chain(
    workspace: Path, previous_did: str, current_did: str,
) -> list[dict[str, Any]]:
    """Export only the required, unambiguous path; never export private keys."""
    if not is_did_key(previous_did) or not is_did_key(current_did):
        raise ValueError("source rotation DID is invalid")
    if previous_did == current_did:
        return []
    path = _rotation_path(Path(workspace))
    with InterProcessLock(path.parent / ".locks" / path.name), path.open("rb") as stream:
        data = stream.read(_MAX_LOG_BYTES + 1)
    if len(data) > _MAX_LOG_BYTES or not data.endswith(b"\n"):
        raise ValueError("source rotation history is oversized or truncated")
    edges: dict[str, dict[str, Any]] = {}
    corrupt_rows = 0
    for seq, line in enumerate(data.split(b"\n")[:-1]):
        try:
            record = json.loads(line, object_pairs_hook=_unique_json_fields)
            edge = _verified_rotation(record)
        except (UnicodeError, ValueError, TypeError, RecursionError):
            edge = None
        if edge is None:
            logger.warning("source identity rotation seq=%d is invalid", seq)
            corrupt_rows += 1
            continue
        previous = edges.get(edge[0])
        if previous is not None:
            if previous["successor_did"] != edge[1]:
                raise ValueError("source rotation history is invalid or ambiguous")
            continue
        edges[edge[0]] = record
    chain: list[dict[str, Any]] = []
    candidate = previous_did
    visited: set[str] = set()
    while candidate != current_did:
        record = edges.get(candidate)
        if (
            record is None or candidate in visited
            or len(chain) >= MAX_PORTABLE_SOURCE_ROTATION_HOPS
        ):
            if corrupt_rows:
                raise ValueError("corrupt source identity history may conceal the rotation")
            raise ValueError("source rotation chain is absent or too long")
        visited.add(candidate)
        chain.append(record)
        candidate = record["successor_did"]
        if candidate in visited:
            raise ValueError("source rotation chain contains a cycle")
    if not verify_portable_source_rotation_chain(chain, previous_did, current_did):
        raise ValueError("source rotation chain is not portable")
    return chain


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
            edge = _verified_rotation(json.loads(line, object_pairs_hook=_unique_json_fields))
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


__all__ = [
    "MAX_PORTABLE_SOURCE_ROTATION_CHAIN_BYTES",
    "MAX_PORTABLE_SOURCE_ROTATION_HOPS",
    "export_source_identity_rotation_chain",
    "record_source_identity_rotation",
    "source_identity_precedes",
    "verify_portable_source_rotation_chain",
]
