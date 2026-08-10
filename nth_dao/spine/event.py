"""Signed causal event, the smallest unit in the NTH DAO event spine.

``prev_hash`` creates the chain. ``content_hash`` is the SHA-256 address of
the canonical event core, and ``sig`` is the author's Ed25519 signature over
that 32-byte digest.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Dict, Tuple

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.identity import AgentIdentity

# The genesis event has no predecessor.
GENESIS_PREV = "0" * 64
MAX_SPINE_PAYLOAD_BYTES = 1024 * 1024
_HASH = re.compile(r"^[0-9a-f]{64}$")
_EVENT_TYPE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_EVENT_FIELDS = frozenset(
    {
        "seq",
        "prev_hash",
        "type",
        "payload",
        "author_did",
        "ts_ms",
        "content_hash",
        "sig",
    }
)


def event_content_hash(core: Dict[str, Any]) -> str:
    """Return the lowercase SHA-256 address of a canonical event core."""
    return hashlib.sha256(canonical_json(core)).hexdigest()


@dataclass
class SpineEvent:
    """A signed causal event whose ``core()`` is hash protected."""

    seq: int
    prev_hash: str
    type: str
    payload: Dict[str, Any]
    author_did: str
    ts_ms: int
    content_hash: str = ""
    sig: str = ""

    @property
    def event_id(self) -> str:
        return self.content_hash

    def core(self) -> Dict[str, Any]:
        return {
            "seq": self.seq,
            "prev_hash": self.prev_hash,
            "type": self.type,
            "payload": self.payload,
            "author_did": self.author_did,
            "ts_ms": self.ts_ms,
        }

    def to_dict(self) -> Dict[str, Any]:
        d = self.core()
        d["content_hash"] = self.content_hash
        d["sig"] = self.sig
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SpineEvent":
        if not isinstance(d, dict) or set(d) != _EVENT_FIELDS:
            raise ValueError("spine event has missing or unknown fields")
        seq = d["seq"]
        ts_ms = d["ts_ms"]
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise ValueError("spine event seq must be a non-negative integer")
        if (
            isinstance(ts_ms, bool)
            or not isinstance(ts_ms, int)
            or ts_ms <= 0
        ):
            raise ValueError("spine event ts_ms must be a positive integer")
        if (
            not isinstance(d["prev_hash"], str)
            or _HASH.fullmatch(d["prev_hash"]) is None
        ):
            raise ValueError("spine event prev_hash is invalid")
        if (
            not isinstance(d["content_hash"], str)
            or _HASH.fullmatch(d["content_hash"]) is None
        ):
            raise ValueError("spine event content_hash is invalid")
        if (
            not isinstance(d["type"], str)
            or _EVENT_TYPE.fullmatch(d["type"]) is None
        ):
            raise ValueError("spine event type is invalid")
        if not isinstance(d["payload"], dict):
            raise ValueError("spine event payload must be an object")
        if not isinstance(d["author_did"], str) or not d["author_did"]:
            raise ValueError("spine event author_did is invalid")
        if not isinstance(d["sig"], str) or not d["sig"]:
            raise ValueError("spine event sig is invalid")
        try:
            payload_size = len(canonical_json(d["payload"]))
        except (TypeError, ValueError, OverflowError, RecursionError) as exc:
            raise ValueError("spine event payload is not canonical JSON") from exc
        if payload_size > MAX_SPINE_PAYLOAD_BYTES:
            raise ValueError("spine event payload exceeds byte limit")
        return cls(
            seq=seq,
            prev_hash=d["prev_hash"],
            type=d["type"],
            payload=dict(d["payload"]),
            author_did=d["author_did"],
            ts_ms=ts_ms,
            content_hash=d["content_hash"],
            sig=d["sig"],
        )


def sign_event(
    *,
    seq: int,
    prev_hash: str,
    event_type: str,
    payload: Dict[str, Any],
    identity: AgentIdentity,
    ts_ms: int,
) -> SpineEvent:
    """Construct and sign one event with ``identity`` as its author."""
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ValueError("spine event seq must be a non-negative integer")
    if (
        isinstance(ts_ms, bool)
        or not isinstance(ts_ms, int)
        or ts_ms <= 0
    ):
        raise ValueError("spine event ts_ms must be a positive integer")
    if not isinstance(prev_hash, str) or _HASH.fullmatch(prev_hash) is None:
        raise ValueError("spine event prev_hash is invalid")
    if (
        not isinstance(event_type, str)
        or _EVENT_TYPE.fullmatch(event_type) is None
    ):
        raise ValueError("spine event type is invalid")
    if not isinstance(payload, dict):
        raise ValueError("spine event payload must be an object")
    try:
        payload_size = len(canonical_json(payload))
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise ValueError("spine event payload is not canonical JSON") from exc
    if payload_size > MAX_SPINE_PAYLOAD_BYTES:
        raise ValueError("spine event payload exceeds byte limit")
    core = {
        "seq": seq,
        "prev_hash": prev_hash,
        "type": event_type,
        "payload": payload,
        "author_did": identity.as_did(),
        "ts_ms": ts_ms,
    }
    content_hash = event_content_hash(core)
    sig = b64u_encode(identity.sign(bytes.fromhex(content_hash)))
    return SpineEvent.from_dict(
        {
            **core,
            "content_hash": content_hash,
            "sig": sig,
        }
    )


def verify_event(event: SpineEvent) -> Tuple[bool, str]:
    """Verify one event's content hash and author signature fail-closed."""
    if not isinstance(event, SpineEvent):
        return False, "event has the wrong type"
    try:
        validated = SpineEvent.from_dict(event.to_dict())
        recomputed = event_content_hash(validated.core())
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        return False, f"invalid event structure: {exc}"
    if recomputed != event.content_hash:
        return False, "content_hash mismatch (tampered core)"
    try:
        verifier = AgentIdentity.from_did(event.author_did)
        sig_bytes = b64u_decode(event.sig)
    except (TypeError, ValueError, UnicodeError) as exc:
        return False, f"bad author_did/sig encoding: {exc}"
    if len(sig_bytes) != 64 or b64u_encode(sig_bytes) != event.sig:
        return False, "signature encoding is not canonical"
    if not verifier.verify(bytes.fromhex(event.content_hash), sig_bytes):
        return False, "signature invalid"
    return True, "ok"
