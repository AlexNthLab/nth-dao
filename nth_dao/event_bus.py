"""
EventBus — team-level unified append-only signed event stream.

Problem this solves:
    NTH DAO has three separate logging systems:
    1. groups.py → _append_audit() → team_audit/audit.jsonl (unsigned)
    2. agent_ledger.py → personal ledger (optionally signed, pubkey-scoped)
    3. web_of_trust.py → endorsements.jsonl + revocations.jsonl (signed)

    Three logs = three trust models, three replay paths, zero cross-reference.
    This module introduces a unified EventBus — a single append-only, signed
    event stream that every layer writes to. It is the missing L0 in
    NTH DAO's "identity-first layered architecture + event-sourcing audit"
    design.

Design:
    1. **Append-only** — events are a JSONL stream at `team_audit/events.jsonl`.
       Never modified, never deleted. Derived snapshots may be rebuilt.

    2. **Signed by actor** — when the emitting identity has Ed25519 keys,
       `BusEvent.sig` carries a signature over canonical JSON of the event
       payload. All layers (groups, agent_ledger, web_of_trust) emit through
       the same bus, so every event inherits the same verification model.

    3. **O(1) lookup via index** — `team_audit/events.index.json` maps
       `event_id → byte_offset` for point lookups without scanning.

    4. **Replay-friendly** — `EventBus.replay()` yields events in insertion
       order with optional filters (type, actor, time range, limit). The
       deterministic event stream is the physical form of the 'organisation
       identity proof' — not `is_member=true` in a DB, but a complete,
       verifiable fact chain.

    5. **Team-level aggregation** — `EventBus.agent_stats(fp)` folds all
       events for a given pubkey fingerprint into a contribution summary.
       This complements `AgentLedger` (which is scoped to one pubkey's
       personal view); the EventBus provides the cross-agent team view.

Storage layout:

    workspace/team_audit/
    ├── events.jsonl         ← append-only, one signed BusEvent per line
    └── events.index.json    ← {event_id: byte_offset} for O(1) lookup
                              (absent when no events yet)

Event type taxonomy (layered, canonical):
    group.channel.created          — channel creation
    group.message.posted           — message post
    group.task.created             — task creation
    group.task.status_updated      — task state transition
    group.announcement.posted      — admin announcement
    group.trust_hint.set           — trust hint update
    membership.member_approved     — approval in membership module
    membership.member_removed      — removal
    membership.team_config_updated — team.json mutation
    agent_ledger.step.claimed      — mission step claim
    agent_ledger.step.completed    — mission step completion
    agent_ledger.step.failed       — mission step failure
    agent_ledger.handoff.given     — step reassignment
    agent_ledger.review.given      — mission review submitted
    wot.endorsed                   — web-of-trust endorsement issued
    wot.revoked                    — endorsement revocation
    identity.key_rotated           — guardian-based key replacement

Usage:

    from nth_dao.event_bus import EventBus, BusEvent

    bus = EventBus(workspace, identity=my_identity)

    # Low-level emit (any layer)
    bus.emit("group.message.sent", {
        "channel_id": "general",
        "sender_id": "alice",
        "body": "deploy done",
    })

    # Replay with filters
    for event in bus.replay(event_types=["group.message.sent"], limit=100):
        print(event.event_type, event.actor_id, event.payload["body"])

    # Verify an event's signature
    bus.verify(event)  # True/False

    # Team-level agent contribution stats
    stats = bus.agent_stats("a1b2c3d4e5f6a7b8")  # fingerprint[:16]
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple, Union

from .identity import (
    AgentIdentity,
    _NACL_AVAILABLE,
    _VerifyKey,
    canonical_json,
)
from .util import (
    InterProcessLock,
    atomic_write_json,
    safe_load_json,
)

logger = logging.getLogger("nth_dao.event_bus")

# ── Constants ──────────────────────────────────────────────────

DEFAULT_EVENTS_DIR = "team_audit"
DEFAULT_EVENTS_FILE = "events.jsonl"
DEFAULT_INDEX_FILE = "events.index.json"


def _is_hex(value: str, expected_len: int) -> bool:
    """Check if a string is valid hex of exact length (case-insensitive)."""
    if not isinstance(value, str) or len(value) != expected_len:
        return False
    try:
        bytes.fromhex(value)
        return True
    except ValueError:
        return False

# ── VerificationResult ────────────────────────────────────────


class VerificationResult(str, Enum):
    """Outcome of BusEvent signature verification.

    Callers MUST explicitly decide how to handle UNVERIFIABLE results
    rather than silently accepting them as valid.
    """
    VALID = "valid"             # signature verified against actor_pubkey
    INVALID = "invalid"         # signature mismatch or malformed
    UNSIGNED = "unsigned"       # no signature — accept under local trust model
    UNVERIFIABLE = "unverifiable"  # PyNaCl not installed, cannot check


# ── BusEvent ────────────────────────────────────────────────────


@dataclass
class BusEvent:
    """A single signed, append-only event on the team-level event bus.

    When `sig` is non-empty, it is an Ed25519 signature (hex-encoded) over
    the canonical JSON of all other fields. Verification is:
        identity.verify_json(self.signable_dict(), self.sig, pubkey_hex=self.actor_pubkey)
    """

    event_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    event_type: str = ""               # e.g. "group.message.sent"
    actor_id: str = ""                 # agent_id that performed the action
    actor_pubkey: str = ""             # Ed25519 pubkey hex of actor
    payload: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    sig: str = ""                      # Ed25519 signature hex (empty if unsigned)

    def signable_dict(self) -> Dict[str, Any]:
        """Return the dict that is signed (all fields except `sig`)."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "actor_id": self.actor_id,
            "actor_pubkey": self.actor_pubkey,
            "payload": self.payload,
            "timestamp": self.timestamp,
        }

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("sig", None)
        d["sig"] = self.sig
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "BusEvent":
        """Deserialize a BusEvent from a dict.

        Raises:
            ValueError: if actor_pubkey or sig are present but not valid hex.
        """
        pubkey = data.get("actor_pubkey", "")
        sig = data.get("sig", "")
        if pubkey and not _is_hex(pubkey, 64):
            raise ValueError(
                f"actor_pubkey must be 64 hex chars, got "
                f"'{pubkey[:20]}...' ({len(pubkey)} chars)"
            )
        if sig and not _is_hex(sig, 128):
            raise ValueError(
                f"sig must be 128 hex chars, got "
                f"'{sig[:20]}...' ({len(sig)} chars)"
            )
        return cls(
            event_id=data.get("event_id", uuid.uuid4().hex[:16]),
            event_type=data.get("event_type", ""),
            actor_id=data.get("actor_id", ""),
            actor_pubkey=pubkey,
            payload=data.get("payload", {}),
            timestamp=data.get("timestamp", datetime.now().isoformat()),
            sig=sig,
        )


# ── EventBus ────────────────────────────────────────────────────


class EventBus:
    """Team-level unified append-only signed event stream.

    All NTH DAO layers write here. The event stream is the physical form
    of the 'organisation identity proof' — a complete, verifiable fact
    chain, not a mutable `is_member=true` flag.
    """

    def __init__(
        self,
        workspace: Union[str, Path],
        identity: Optional[AgentIdentity] = None,
    ):
        self.workspace = Path(workspace).resolve()
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.identity = identity

    # ── Paths ────────────────────────────────────────────────

    @property
    def events_dir(self) -> Path:
        return self.workspace / DEFAULT_EVENTS_DIR

    @property
    def events_path(self) -> Path:
        return self.events_dir / DEFAULT_EVENTS_FILE

    @property
    def index_path(self) -> Path:
        return self.events_dir / DEFAULT_INDEX_FILE

    @property
    def can_sign(self) -> bool:
        """Whether this bus can produce signed events."""
        return bool(self.identity and self.identity.can_sign)

    # ── Emit ──────────────────────────────────────────────────

    def emit(
        self,
        event_type: str,
        payload: Dict[str, Any],
        identity: Optional[AgentIdentity] = None,
    ) -> BusEvent:
        """Append a signed event to the bus.

        When `identity` (or `self.identity`) has signing keys, the event
        carries an Ed25519 signature. Otherwise `sig` is empty (unsigned,
        best-effort trust).

        File I/O is O(1) regardless of event log size — we append directly
        rather than read-modify-write the entire file.
        """
        signer = identity or self.identity
        actor_id = ""
        actor_pubkey = ""

        if signer is not None:
            actor_id = str(signer.agent_id)
            actor_pubkey = signer.pubkey_hex if signer.can_sign else ""

        event = BusEvent(
            event_type=event_type,
            actor_id=actor_id,
            actor_pubkey=actor_pubkey,
            payload=payload,
        )

        # Sign when crypto is available
        if _NACL_AVAILABLE and signer is not None and signer.can_sign:
            try:
                event.sig = signer.sign_json(event.signable_dict())
            except Exception as exc:
                logger.warning("Failed to sign event %s: %s", event.event_id, exc)
                event.sig = ""

        # Append to JSONL (O(1) — direct append, no read-modify-write)
        self.events_dir.mkdir(parents=True, exist_ok=True)
        line = json.dumps(event.to_dict(), ensure_ascii=False, separators=(",", ":"))
        line_bytes = line.encode("utf-8") + b"\n"

        with InterProcessLock(self.events_path.with_suffix(".jsonl.lock")):
            # Capture byte offset before appending
            try:
                offset = self.events_path.stat().st_size if self.events_path.exists() else 0
            except OSError:
                offset = 0

            # Append directly — no read-modify-write
            with self.events_path.open("ab") as fh:
                fh.write(line_bytes)
                fh.flush()
                os.fsync(fh.fileno())

            # Update index atomically
            index = self._load_index()
            index[event.event_id] = offset
            atomic_write_json(self.index_path, index)

        return event

    # ── Replay ────────────────────────────────────────────────

    def replay(
        self,
        from_id: Optional[str] = None,
        event_types: Optional[List[str]] = None,
        actor_id: Optional[str] = None,
        limit: Optional[int] = None,
        reverse: bool = False,
    ) -> Iterator[BusEvent]:
        """Yield events in insertion order with optional filters.

        Args:
            from_id: Resume replay *after* this event_id (exclusive).
                     Pass the last-processed event_id for incremental replay.
            event_types: Only yield events matching these types.
            actor_id: Only yield events from this actor.
            limit: Max events to yield.
            reverse: Yield newest-first instead of oldest-first.
        """
        if not self.events_path.exists():
            return

        # Use generator for forward path (99% of usage); accumulate only
        # when reversing (need the full list to sort).
        if reverse:
            events = list(self._iter_events(from_id, event_types, actor_id))
            events.reverse()
            yield from events[:limit] if limit else events
        else:
            count = 0
            for event in self._iter_events(from_id, event_types, actor_id):
                yield event
                count += 1
                if limit and count >= limit:
                    break

    def _iter_events(
        self,
        from_id: Optional[str] = None,
        event_types: Optional[List[str]] = None,
        actor_id: Optional[str] = None,
    ) -> Iterator[BusEvent]:
        """Internal: yield events, optionally starting after from_id (exclusive)."""
        try:
            with self.events_path.open("r", encoding="utf-8") as fh:
                # Skip until we've seen the from_id marker, then yield everything after
                if from_id is not None:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if data.get("event_id") == from_id:
                            break  # found marker — now yield everything after
                    # from_id not found? We've exhausted the file — nothing to replay
                    # (the caller asked to resume from an event that doesn't exist)

                # Yield matching events
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        logger.warning("Corrupt event line in %s, skipping", self.events_path)
                        continue
                    event = BusEvent.from_dict(data)

                    # type filter
                    if event_types and event.event_type not in event_types:
                        continue

                    # actor filter
                    if actor_id and event.actor_id != actor_id:
                        continue

                    yield event

        except Exception as exc:
            logger.warning("Error reading events from %s: %s", self.events_path, exc)

    def get(self, event_id: str) -> Optional[BusEvent]:
        """Point-lookup an event by its ID using the byte-offset index.

        Validates that the event at the indexed offset matches the requested
        event_id — if the index is stale (e.g. file rebuilt from another source),
        returns None instead of silently returning wrong data.
        """
        index = self._load_index()
        offset = index.get(event_id)
        if offset is None:
            return None
        try:
            with self.events_path.open("rb") as fh:
                fh.seek(offset)
                line = fh.readline().decode("utf-8").strip()
                if not line:
                    return None
                data = json.loads(line)
                event = BusEvent.from_dict(data)
                # Validate the event at this offset is the one we asked for
                if event.event_id != event_id:
                    logger.warning(
                        "Index offset %d for %s returned event %s — index may be stale",
                        offset, event_id, event.event_id,
                    )
                    return None
                return event
        except Exception as exc:
            logger.warning("Failed to read event %s at offset %d: %s", event_id, offset, exc)
            return None

    # ── Verify ────────────────────────────────────────────────

    def verify(self, event: BusEvent) -> VerificationResult:
        """Verify an event's Ed25519 signature against its actor's pubkey.

        Returns:
            VALID:        signature verifies against actor_pubkey.
            INVALID:      signature present but does not verify, or pubkey missing/malformed.
            UNSIGNED:     no signature — accept under local trust model.
            UNVERIFIABLE: PyNaCl not installed — cannot check. Caller must decide
                          whether to trust the event.
        """
        if not event.sig:
            return VerificationResult.UNSIGNED
        if not event.actor_pubkey or len(event.actor_pubkey) != 64:
            return VerificationResult.INVALID
        if not _NACL_AVAILABLE:
            logger.debug("Cannot verify event %s: PyNaCl not installed", event.event_id)
            return VerificationResult.UNVERIFIABLE

        try:
            payload_bytes = canonical_json(event.signable_dict())
            sig_bytes = bytes.fromhex(event.sig)
            pubkey_bytes = bytes.fromhex(event.actor_pubkey)
            assert _VerifyKey is not None
            _VerifyKey(pubkey_bytes).verify(payload_bytes, sig_bytes)
            return VerificationResult.VALID
        except Exception:
            return VerificationResult.INVALID

    def verify_all(
        self, event_types: Optional[List[str]] = None
    ) -> Tuple[int, int, int, int]:
        """Verify all events on the bus.

        Returns:
            (total, valid, invalid, unverifiable) counts.
        """
        total = 0
        valid = 0
        invalid = 0
        unverifiable = 0
        for event in self.replay(event_types=event_types):
            total += 1
            result = self.verify(event)
            if result == VerificationResult.VALID:
                valid += 1
            elif result == VerificationResult.INVALID:
                invalid += 1
            elif result == VerificationResult.UNVERIFIABLE:
                unverifiable += 1
        return total, valid, invalid, unverifiable

    # ── Team-level aggregation ────────────────────────────────

    def agent_stats(
        self,
        fingerprint: str,
        since: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Fold all events for a given pubkey fingerprint into contribution stats.

        This provides the team-level cross-agent view that complements
        `AgentLedger`, which is scoped to one pubkey's personal view.

        Args:
            fingerprint: First 16 hex chars of sha256(pubkey_hex).
            since: ISO timestamp, only count events after this.

        Returns:
            Dict with keys: missions_owned, steps_completed, steps_failed,
            reviews_given, endorsements_given, messages_sent, tasks_created,
            last_active_at, total_events.
        """
        stats = {
            "fingerprint": fingerprint,
            "missions_owned": 0,
            "steps_completed": 0,
            "steps_failed": 0,
            "reviews_given": 0,
            "endorsements_given": 0,
            "messages_sent": 0,
            "tasks_created": 0,
            "last_active_at": "",
            "total_events": 0,
            "since": since or "",
        }

        if not self.events_path.exists():
            return stats

        try:
            with self.events_path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    actor_pubkey = data.get("actor_pubkey", "")
                    if not actor_pubkey:
                        continue

                    actor_fp = hashlib.sha256(
                        actor_pubkey.encode("utf-8")
                    ).hexdigest()[:16]
                    if actor_fp != fingerprint:
                        continue

                    ts = data.get("timestamp", "")
                    if since and ts < since:
                        continue

                    stats["total_events"] += 1
                    stats["last_active_at"] = max(stats["last_active_at"], ts)

                    etype = data.get("event_type", "")
                    if etype == "agent_ledger.step.completed":
                        stats["steps_completed"] += 1
                    elif etype == "agent_ledger.step.failed":
                        stats["steps_failed"] += 1
                    elif etype == "agent_ledger.review.given":
                        stats["reviews_given"] += 1
                    elif etype == "wot.endorsed":
                        stats["endorsements_given"] += 1
                    elif etype == "group.message.posted":
                        stats["messages_sent"] += 1
                    elif etype in ("group.task.created", "task.created"):
                        stats["tasks_created"] += 1
                    elif etype == "agent_ledger.mission.owned":
                        stats["missions_owned"] += 1

        except Exception as exc:
            logger.warning("Error computing agent_stats for %s: %s", fingerprint, exc)

        return stats

    def team_stats(self) -> Dict[str, Any]:
        """Return aggregate stats for the whole team (all pubkeys)."""
        agents: Dict[str, Dict[str, Any]] = {}
        total_events = 0

        if not self.events_path.exists():
            return {"agent_count": 0, "total_events": 0, "agents": {}}

        try:
            with self.events_path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    actor_pubkey = data.get("actor_pubkey", "")
                    fp = ""
                    if actor_pubkey:
                        fp = hashlib.sha256(
                            actor_pubkey.encode("utf-8")
                        ).hexdigest()[:16]

                    if fp and fp not in agents:
                        agents[fp] = {
                            "fingerprint": fp,
                            "actor_id": data.get("actor_id", ""),
                            "events": 0,
                            "last_active_at": "",
                        }

                    total_events += 1
                    if fp:
                        agents[fp]["events"] += 1
                        ts = data.get("timestamp", "")
                        agents[fp]["last_active_at"] = max(
                            agents[fp]["last_active_at"], ts
                        )

        except Exception as exc:
            logger.warning("Error computing team_stats: %s", exc)

        return {
            "agent_count": len(agents),
            "total_events": total_events,
            "agents": agents,
        }

    # ── Internal helpers ──────────────────────────────────────

    def _load_index(self) -> Dict[str, int]:
        """Load the event_id → byte_offset index.

        Rejects float values (they indicate index corruption, not valid offsets).
        """
        data = safe_load_json(self.index_path, fallback=None)
        if isinstance(data, dict):
            index: Dict[str, int] = {}
            for k, v in data.items():
                if isinstance(v, int):
                    index[str(k)] = v
                elif isinstance(v, float):
                    logger.warning(
                        "Index entry %s has float value %.1f — "
                        "treating as corrupted, skipping", k, v
                    )
                # non-numeric values are silently skipped
            return index
        return {}

    def count(self, event_type: Optional[str] = None) -> int:
        """Count events, optionally filtered by type."""
        if not self.events_path.exists():
            return 0
        n = 0
        try:
            with self.events_path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    if event_type is None:
                        n += 1
                        continue
                    try:
                        data = json.loads(line)
                        if data.get("event_type") == event_type:
                            n += 1
                    except json.JSONDecodeError:
                        continue
        except Exception:
            pass
        return n
