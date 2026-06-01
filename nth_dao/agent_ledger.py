"""AgentLedger — per-pubkey-fingerprint append-only contribution ledger.

Layer 2 (Mission Template + Review) produces the raw events. This module
folds them into a personal contribution view that survives across releases
and is portable when the agent moves to a new machine.

Storage layout:

    sidechain/agents/<fingerprint>/
    ├── profile.json         # static identity facts (label, did, capabilities)
    ├── ledger.jsonl         # append-only events (claim, complete, review, ...)
    └── stats.json           # derived snapshot, refreshable from ledger.jsonl

Key design decisions:

  1. **Fingerprint-scoped** — `AgentIdentity.fingerprint()` is the storage
     key. Same pubkey across multiple agent_ids shares one ledger. New
     agent_ids on a new pubkey start clean. This is the same anti-Sybil
     pattern reputation credits use.

  2. **Append-only** — events are never modified or deleted. Editing past
     history is the surest way to forfeit trust; we don't even provide
     an API for it. `stats.json` is derived state and may be rebuilt.

  3. **Signed events** (optional) — when the agent has a crypto identity,
     events can be signed. This lets a future federated layer accept the
     ledger from another node without trusting that node's filesystem.
     `sig` is empty for unsigned events; rebuild treats them as best-effort.

  4. **Reducer is portable** — `compute_stats` walks `ledger.jsonl` with a
     deterministic reduction. A Rust/Go port would reduce identically given
     the same events.

The reducer outputs:

    {
        "period_start":      "<ISO>",
        "period_end":        "<ISO>",
        "missions_owned":    int,
        "steps_completed":   int,
        "steps_failed":      int,
        "success_rate":      float,
        "handoffs_received": int,
        "handoffs_given":    int,
        "templates_used":    {"code-review": 5, ...},  # by template_id
        "categories":        {"code_review": 12, ...},
        "total_token_cost":  int,
        "last_active_at":    "<ISO>",
    }

Usage:

    from nth_dao.agent_ledger import AgentLedger
    al = AgentLedger(workspace, identity=my_identity)
    al.record_step_complete(mission_id="...", step_id="...",
                            template_id="code-review",
                            template_version="1.0.0",
                            category="code_review",
                            token_cost=4800,
                            elapsed_seconds=120)
    print(al.stats())

A future "achievement reducer" (v0.9.6+) will fold a month's events into a
signed AchievementCredential — currently out of scope but the data is here.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from .identity import AgentIdentity, canonical_json
from .util import InterProcessLock, atomic_write_json, safe_id, safe_load_json

logger = logging.getLogger("nth_dao.agent_ledger")


# Event type taxonomy (open to extension). Strings, not enums, so a future
# version can add new types without breaking old readers.
EVENT_STEP_CLAIM    = "step_claim"
EVENT_STEP_COMPLETE = "step_complete"
EVENT_STEP_FAILED   = "step_failed"
EVENT_STEP_HANDOFF  = "step_handoff"
EVENT_REVIEW_GIVEN  = "review_given"
EVENT_REVIEW_RECEIVED = "review_received"
EVENT_ENDORSEMENT_GIVEN    = "endorsement_given"
EVENT_ENDORSEMENT_RECEIVED = "endorsement_received"
EVENT_MISSION_OWNED        = "mission_owned"

ZERO_HASH = "0" * 64


@dataclass
class LedgerEvent:
    """One append-only event in an agent's ledger.

    Fields kept deliberately flat — easier to grep, simpler to reduce in
    other languages. The `data` dict carries per-event-type detail.
    """

    event_id: str
    type: str
    agent_fingerprint: str
    agent_id: str
    timestamp: str
    data: Dict[str, Any] = field(default_factory=dict)
    pubkey: str = ""
    seq: int = 0
    prev_hash: str = ZERO_HASH
    event_hash: str = ""
    sig: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    def signable_dict(self) -> dict:
        d = self.to_dict()
        d.pop("sig", None)
        d.pop("event_hash", None)
        return d

    def compute_hash(self) -> str:
        return hashlib.sha256(canonical_json(self.signable_dict())).hexdigest()

    @classmethod
    def from_dict(cls, data: dict) -> "LedgerEvent":
        return cls(
            event_id=data.get("event_id", ""),
            type=data.get("type", ""),
            agent_fingerprint=data.get("agent_fingerprint", ""),
            agent_id=data.get("agent_id", ""),
            timestamp=data.get("timestamp", ""),
            data=dict(data.get("data", {})),
            pubkey=data.get("pubkey", ""),
            seq=int(data.get("seq", 0)),
            prev_hash=data.get("prev_hash", ZERO_HASH),
            event_hash=data.get("event_hash", ""),
            sig=data.get("sig", ""),
        )


class AgentLedger:
    """File-backed event ledger for one agent (keyed by pubkey fingerprint).

    Multiple agents can live in the same workspace; each gets its own
    subdirectory under `sidechain/agents/<fingerprint>/`.
    """

    LEDGER_NAME = "ledger.jsonl"
    PROFILE_NAME = "profile.json"
    STATS_NAME = "stats.json"
    SUBDIR_NAME = "agents"

    def __init__(
        self,
        workspace: Union[str, Path],
        *,
        identity: Optional[AgentIdentity] = None,
        agent_id: Optional[str] = None,
        sidechain_subdir: str = "sidechain",
    ):
        """
        Args:
            workspace: NTH DAO workspace root.
            identity: a crypto identity (preferred). When set, the agent
                      fingerprint is derived from the pubkey — stable across
                      multiple agent_ids on the same key.
            agent_id: fallback when no identity is provided. The fingerprint
                      derives from the agent_id string instead. Anti-Sybil
                      properties weaker; only use this when crypto isn't
                      available.
        """
        if identity is None and not agent_id:
            raise ValueError("AgentLedger requires identity or agent_id")
        self.workspace = Path(workspace)
        self.identity = identity
        if identity is not None:
            self.agent_id = str(identity.agent_id)
            self.fingerprint = identity.fingerprint()
        else:
            self.agent_id = agent_id or ""
            # Deterministic fingerprint from agent_id (matches identity.fingerprint
            # when AgentID is plain).
            import hashlib
            self.fingerprint = hashlib.sha256(
                self.agent_id.encode("utf-8"),
            ).hexdigest()[:16]

        self.base_dir = (
            self.workspace / sidechain_subdir / self.SUBDIR_NAME
            / safe_id(self.fingerprint)
        )
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.ledger_path = self.base_dir / self.LEDGER_NAME
        self.profile_path = self.base_dir / self.PROFILE_NAME
        self.stats_path = self.base_dir / self.STATS_NAME
        self._maybe_init_profile()

    # ─── profile ───

    def _maybe_init_profile(self) -> None:
        if self.profile_path.exists():
            return
        profile = {
            "fingerprint": self.fingerprint,
            "agent_id": self.agent_id,
            "label": getattr(self.identity, "label", "") if self.identity else "",
            "did": "",
            "created_at": datetime.now().isoformat(),
        }
        if self.identity and getattr(self.identity, "can_sign", False):
            try:
                profile["did"] = self.identity.as_did()
            except Exception:
                profile["did"] = ""
        atomic_write_json(self.profile_path, profile)

    def profile(self) -> Dict[str, Any]:
        return safe_load_json(self.profile_path, fallback={}) or {}

    # ─── append events ───

    def _append(self, event_type: str, data: Optional[Dict[str, Any]] = None) -> LedgerEvent:
        with InterProcessLock(self.ledger_path):
            previous = self._read_events_unlocked(strict=False)
            prev_hash = previous[-1].event_hash if previous else ZERO_HASH
            event = LedgerEvent(
                event_id=uuid.uuid4().hex[:12],
                type=event_type,
                agent_fingerprint=self.fingerprint,
                agent_id=self.agent_id,
                timestamp=datetime.now().isoformat(),
                data=dict(data or {}),
                pubkey=self.identity.pubkey_hex if self.identity else "",
                seq=len(previous) + 1,
                prev_hash=prev_hash,
            )
            event.event_hash = event.compute_hash()
            if self.identity and getattr(self.identity, "can_sign", False):
                try:
                    event.sig = self.identity.sign_json(event.signable_dict())
                except Exception as e:
                    logger.debug("ledger event sign failed: %s", e)
            with open(self.ledger_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")
        return event

    def record_step_claim(
        self,
        mission_id: str,
        step_id: str,
        *,
        template_id: str = "",
        template_version: str = "",
        category: str = "",
    ) -> LedgerEvent:
        return self._append(EVENT_STEP_CLAIM, {
            "mission_id": mission_id, "step_id": step_id,
            "template_id": template_id, "template_version": template_version,
            "category": category,
        })

    def record_step_complete(
        self,
        mission_id: str,
        step_id: str,
        *,
        template_id: str = "",
        template_version: str = "",
        category: str = "",
        token_cost: int = 0,
        elapsed_seconds: float = 0.0,
        output_summary: str = "",
    ) -> LedgerEvent:
        return self._append(EVENT_STEP_COMPLETE, {
            "mission_id": mission_id, "step_id": step_id,
            "template_id": template_id, "template_version": template_version,
            "category": category,
            "token_cost": int(token_cost),
            "elapsed_seconds": float(elapsed_seconds),
            "output_summary": output_summary[:200],
        })

    def record_step_failed(
        self,
        mission_id: str,
        step_id: str,
        *,
        template_id: str = "",
        category: str = "",
        reason: str = "",
    ) -> LedgerEvent:
        return self._append(EVENT_STEP_FAILED, {
            "mission_id": mission_id, "step_id": step_id,
            "template_id": template_id, "category": category,
            "reason": reason[:200],
        })

    def record_handoff_received(
        self,
        mission_id: str,
        step_id: str,
        from_agent: str,
        *,
        template_id: str = "",
    ) -> LedgerEvent:
        return self._append(EVENT_STEP_HANDOFF, {
            "direction": "received",
            "mission_id": mission_id, "step_id": step_id,
            "from_agent": from_agent,
            "template_id": template_id,
        })

    def record_handoff_given(
        self,
        mission_id: str,
        step_id: str,
        to_agent: str,
        *,
        template_id: str = "",
    ) -> LedgerEvent:
        return self._append(EVENT_STEP_HANDOFF, {
            "direction": "given",
            "mission_id": mission_id, "step_id": step_id,
            "to_agent": to_agent,
            "template_id": template_id,
        })

    def record_review_given(
        self,
        template_id: str,
        template_version: str,
        mission_id: str,
        score: float,
    ) -> LedgerEvent:
        return self._append(EVENT_REVIEW_GIVEN, {
            "template_id": template_id, "template_version": template_version,
            "mission_id": mission_id, "score": float(score),
        })

    def record_review_received(
        self,
        template_id: str,
        template_version: str,
        mission_id: str,
        score: float,
        reviewer_pubkey: str,
    ) -> LedgerEvent:
        return self._append(EVENT_REVIEW_RECEIVED, {
            "template_id": template_id, "template_version": template_version,
            "mission_id": mission_id, "score": float(score),
            "reviewer_pubkey": reviewer_pubkey,
        })

    def record_endorsement_given(self, subject_pubkey: str, context: str = "general") -> LedgerEvent:
        return self._append(EVENT_ENDORSEMENT_GIVEN, {
            "subject_pubkey": subject_pubkey, "context": context,
        })

    def record_endorsement_received(self, endorser_pubkey: str, context: str = "general") -> LedgerEvent:
        return self._append(EVENT_ENDORSEMENT_RECEIVED, {
            "endorser_pubkey": endorser_pubkey, "context": context,
        })

    def record_mission_owned(self, mission_id: str, template_id: str = "") -> LedgerEvent:
        return self._append(EVENT_MISSION_OWNED, {
            "mission_id": mission_id, "template_id": template_id,
        })

    # ─── query ───

    def _read_events_unlocked(self, *, strict: bool) -> List[LedgerEvent]:
        if not self.ledger_path.exists():
            return []
        out: List[LedgerEvent] = []
        try:
            lines = self.ledger_path.read_text(encoding="utf-8").splitlines()
        except OSError as e:
            if strict:
                raise
            logger.warning("failed to read ledger %s: %s", self.ledger_path, e)
            return []
        for line_no, line in enumerate(lines, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                out.append(LedgerEvent.from_dict(json.loads(line)))
            except (json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
                if strict:
                    raise ValueError(f"corrupt ledger line {line_no}: {e}") from e
                logger.warning("skipping corrupt ledger line %s in %s: %s", line_no, self.ledger_path, e)
        return out

    def all_events(self) -> List[LedgerEvent]:
        with InterProcessLock(self.ledger_path):
            return self._read_events_unlocked(strict=False)

    def ledger_hash(self) -> str:
        """Hash the current ledger file bytes for cache invalidation/audit."""
        if not self.ledger_path.exists():
            return ZERO_HASH
        try:
            return hashlib.sha256(self.ledger_path.read_bytes()).hexdigest()
        except OSError:
            return ZERO_HASH

    def verify_event(self, event: LedgerEvent, previous_hash: str, expected_seq: int) -> Tuple[bool, str]:
        if event.seq != expected_seq:
            return False, f"seq mismatch at {event.event_id}: expected {expected_seq}, got {event.seq}"
        if event.prev_hash != previous_hash:
            return False, f"prev_hash mismatch at {event.event_id}"
        actual_hash = event.compute_hash()
        if event.event_hash != actual_hash:
            return False, f"event_hash mismatch at {event.event_id}"
        expected_fingerprint = (
            hashlib.sha256(event.pubkey.encode("utf-8")).hexdigest()[:16]
            if event.pubkey else
            hashlib.sha256(event.agent_id.encode("utf-8")).hexdigest()[:16]
        )
        if event.agent_fingerprint != expected_fingerprint:
            return False, f"fingerprint mismatch at {event.event_id}"
        if event.pubkey and event.sig:
            try:
                from nacl.signing import VerifyKey
                VerifyKey(bytes.fromhex(event.pubkey)).verify(
                    canonical_json(event.signable_dict()),
                    bytes.fromhex(event.sig),
                )
            except Exception as e:
                return False, f"signature invalid at {event.event_id}: {e}"
        elif event.pubkey and not event.sig:
            return False, f"missing signature at {event.event_id}"
        return True, "ok"

    def verify_chain(self) -> Tuple[bool, str]:
        with InterProcessLock(self.ledger_path):
            try:
                events = self._read_events_unlocked(strict=True)
            except Exception as e:
                return False, str(e)
        prev_hash = ZERO_HASH
        for expected_seq, event in enumerate(events, start=1):
            ok, reason = self.verify_event(event, prev_hash, expected_seq)
            if not ok:
                return False, reason
            prev_hash = event.event_hash
        return True, "ok"

    def events_by_type(self, *types: str) -> List[LedgerEvent]:
        if not types:
            return self.all_events()
        types_set = set(types)
        return [e for e in self.all_events() if e.type in types_set]

    def events_since(self, since: str) -> List[LedgerEvent]:
        return [e for e in self.all_events() if e.timestamp >= since]

    # ─── reducer / stats ───

    def compute_stats(self) -> Dict[str, Any]:
        """Fold all events into a derived stats snapshot.

        Deterministic: a Rust/Go port walking the same `ledger.jsonl`
        produces the same dict.
        """
        events = self.all_events()
        if not events:
            return {
                "fingerprint": self.fingerprint,
                "agent_id": self.agent_id,
                "period_start": "",
                "period_end": "",
                "event_count": 0,
                "missions_owned": 0,
                "steps_completed": 0,
                "steps_failed": 0,
                "success_rate": 0.0,
                "handoffs_received": 0,
                "handoffs_given": 0,
                "reviews_given": 0,
                "reviews_received": 0,
                "endorsements_given": 0,
                "endorsements_received": 0,
                "templates_used": {},
                "categories": {},
                "total_token_cost": 0,
                "last_active_at": "",
                "ledger_hash": self.ledger_hash(),
            }

        stats: Dict[str, Any] = {
            "fingerprint": self.fingerprint,
            "agent_id": self.agent_id,
            "period_start": events[0].timestamp,
            "period_end": events[-1].timestamp,
            "event_count": len(events),
            "missions_owned": 0,
            "steps_completed": 0,
            "steps_failed": 0,
            "handoffs_received": 0,
            "handoffs_given": 0,
            "reviews_given": 0,
            "reviews_received": 0,
            "endorsements_given": 0,
            "endorsements_received": 0,
            "templates_used": {},
            "categories": {},
            "total_token_cost": 0,
            "last_active_at": events[-1].timestamp,
            "ledger_hash": self.ledger_hash(),
        }
        templates: Dict[str, int] = {}
        categories: Dict[str, int] = {}

        for e in events:
            d = e.data or {}
            if e.type == EVENT_MISSION_OWNED:
                stats["missions_owned"] += 1
            elif e.type == EVENT_STEP_COMPLETE:
                stats["steps_completed"] += 1
                stats["total_token_cost"] += int(d.get("token_cost", 0))
                tid = d.get("template_id")
                if tid:
                    templates[tid] = templates.get(tid, 0) + 1
                cat = d.get("category")
                if cat:
                    categories[cat] = categories.get(cat, 0) + 1
            elif e.type == EVENT_STEP_FAILED:
                stats["steps_failed"] += 1
                cat = d.get("category")
                if cat:
                    categories[cat] = categories.get(cat, 0) + 1
            elif e.type == EVENT_STEP_HANDOFF:
                if d.get("direction") == "received":
                    stats["handoffs_received"] += 1
                elif d.get("direction") == "given":
                    stats["handoffs_given"] += 1
            elif e.type == EVENT_REVIEW_GIVEN:
                stats["reviews_given"] += 1
            elif e.type == EVENT_REVIEW_RECEIVED:
                stats["reviews_received"] += 1
            elif e.type == EVENT_ENDORSEMENT_GIVEN:
                stats["endorsements_given"] += 1
            elif e.type == EVENT_ENDORSEMENT_RECEIVED:
                stats["endorsements_received"] += 1

        total_attempts = stats["steps_completed"] + stats["steps_failed"]
        stats["success_rate"] = (
            stats["steps_completed"] / total_attempts if total_attempts else 0.0
        )
        stats["templates_used"] = templates
        stats["categories"] = categories
        return stats

    def stats(self) -> Dict[str, Any]:
        """Return cached stats; recompute + persist if missing or stale."""
        cached = safe_load_json(self.stats_path, fallback=None)
        current_hash = self.ledger_hash()
        if cached and cached.get("ledger_hash") == current_hash:
            return cached
        fresh = self.compute_stats()
        atomic_write_json(self.stats_path, fresh)
        return fresh

    def refresh_stats(self) -> Dict[str, Any]:
        """Force a recompute of stats from raw events."""
        fresh = self.compute_stats()
        atomic_write_json(self.stats_path, fresh)
        return fresh
