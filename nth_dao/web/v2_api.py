"""Live HTTP API for the NTH DAO v2 operator console.

Operational views expose only workspace-backed or supervised runtime state.
An unavailable store returns an explicit empty/error response; this module
never substitutes demonstration records for live data.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import inspect
import json
import logging
import math
import os
import re
import secrets
import socket
import tempfile
import threading
import time
import urllib.error
import urllib.request
from contextlib import contextmanager, nullcontext
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple
from urllib.parse import quote, urlsplit

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field, field_validator
from starlette.concurrency import run_in_threadpool

from nth_dao.market.resource_descriptor import (
    MARKET_PUBLICATION_EXTENSION as _MARKET_PUBLICATION_EXTENSION,
    RESOURCE_DESCRIPTOR_EXTENSION as _MARKET_RESOURCE_PROFILE_EXTENSION,
)
from nth_dao.plugins.federation_trust import (
    FEDERATION_IDENTITY_CARD_KIND as _FED_IDENTITY_CARD_KIND,
    MAX_FEDERATION_IDENTITY_TEXT as _MAX_FED_IDENTITY_HEX,
)
from nth_dao.trade_rules.recognition_import_coordinator import (
    RuleRecognitionProofImportBusy as TradeRuleRecognitionImportBusy,
)
from nth_dao.trade_rules.recognition_import import (
    canonical_recognition_source_origin,
)
from nth_dao.util import InterProcessLock, atomic_write_json, safe_id, safe_load_json

logger = logging.getLogger(__name__)


class WorkScopeBusy(RuntimeError):
    """Another writable Agent currently owns the same project scope."""


@contextmanager
def _work_scope_lease(request: Request, record: Any) -> Iterator[None]:
    """Serialize writable Agent calls per project across hub processes."""

    scope = getattr(record, "work_scope", None)
    root = str(getattr(scope, "root", "") or "")
    access = str(getattr(scope, "access", "") or "")
    if not root or access != "workspace-write":
        yield
        return
    workspace = _state_workspace(request)
    if workspace is None:
        raise WorkScopeBusy("workspace unavailable for writable work-scope lease")
    scope_key = hashlib.sha256(root.encode("utf-8")).hexdigest()
    lock_target = workspace / "locks" / "work_scopes" / scope_key
    try:
        with InterProcessLock(lock_target, timeout=0.25):
            yield
    except TimeoutError as exc:
        raise WorkScopeBusy(
            "another Agent is already executing with write access to this project"
        ) from exc


def _env_float(
    name: str,
    default: float,
    *,
    minimum: float,
    maximum: float,
) -> float:
    """Read a bounded float from the environment."""
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = float(raw)
    except (TypeError, ValueError, OverflowError):
        logger.warning("%s=%r is not a valid number; using %.1f", name, raw, default)
        return default
    if value != value:
        logger.warning("%s is NaN; using %.1f", name, default)
        return default
    if value < minimum:
        logger.warning("%s=%.1f is below %.1f; clamping", name, value, minimum)
        return minimum
    if value > maximum:
        logger.warning("%s=%.1f is above %.1f; clamping", name, value, maximum)
        return maximum
    return value

MISSION_CREATED = "mission.created"
MISSION_ACTIVATED = "mission.activated"
MISSION_STEP_BOOTSTRAPPED = "mission.step.bootstrapped"
MISSION_STEP_ANNOUNCED = "mission.step.announced"
MISSION_STEP_CLAIMED = "mission.step.claimed"
MISSION_STEP_COMPLETED = "mission.step.completed"
MISSION_STEP_NEEDS_REVIEW = "mission.step.needs_review"
MISSION_STEP_BLOCKED = "mission.step.blocked"
MISSION_MARKET_CLAIM_VISIBLE = "mission.market_claim.visible"
MISSION_EVENT_TYPES = (
    MISSION_CREATED,
    MISSION_ACTIVATED,
    MISSION_STEP_BOOTSTRAPPED,
    MISSION_STEP_ANNOUNCED,
    MISSION_STEP_CLAIMED,
    MISSION_STEP_COMPLETED,
    MISSION_STEP_NEEDS_REVIEW,
    MISSION_STEP_BLOCKED,
    MISSION_MARKET_CLAIM_VISIBLE,
)


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()



def _mission_step_to_view(step: Any) -> Dict[str, Any]:
    notes = list(getattr(step, "notes", None) or [])
    return {
        "id": getattr(step, "id", "") or "",
        "description": getattr(step, "description", "") or "",
        "status": getattr(step, "status", "") or "",
        "assignee": getattr(step, "assignee", None),
        "required_capabilities": list(
            getattr(step, "required_capabilities", None) or []
        ),
        "depends_on": list(getattr(step, "depends_on", None) or []),
        "created_at": getattr(step, "created_at", None),
        "updated_at": getattr(step, "updated_at", None),
        "completed_at": getattr(step, "completed_at", None),
        "notes": notes[-5:],
        "notes_count": len(notes),
    }


def _mission_timeline_events(
    m: Any,
    step_views: List[Dict[str, Any]],
    audit_events: Optional[List[Dict[str, Any]]] = None,
    handoff_events: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Build the Mission timeline from real audit events plus state snapshots.

    EventBus/Receipt entries are the execution facts. The step rows below are
    retained as a UI snapshot fallback so an old workspace without Mission audit
    history still explains the current state instead of going blank.
    """
    events: List[Dict[str, Any]] = []
    for event in audit_events or []:
        if isinstance(event, dict):
            events.append(dict(event))
    for event in handoff_events or []:
        if isinstance(event, dict):
            events.append(dict(event))

    owner_did = getattr(m, "owner_did", "") or ""
    created_at = getattr(m, "created_at", "") or ""
    events.append({
        "id": f"{m.id}:mission-created",
        "kind": "mission",
        "label": "Mission created",
        "detail": getattr(m, "goal", "") or getattr(m, "title", "") or "",
        "at": created_at,
        "status": getattr(m, "status", "") or "",
        "agent_did": owner_did or None,
    })

    meta = getattr(m, "metadata", None) or {}
    source_announcement_id = meta.get("source_announcement_id")
    if source_announcement_id:
        events.append({
            "id": f"{m.id}:task-claim",
            "kind": "audit",
            "label": "Task claim source",
            "detail": f"source announcement {source_announcement_id}",
            "at": created_at,
            "status": "claimed",
            "agent_did": owner_did or None,
        })

    for step in step_views:
        desc = step["description"] or step["id"]
        caps = step.get("required_capabilities") or []
        cap_detail = f"requires {', '.join(caps)}" if caps else "no capability gate"
        changed_at = step.get("updated_at") or step.get("created_at") or created_at
        detail = f"current state snapshot; {cap_detail}"
        events.append(
            {
                "id": f"{m.id}:{step['id']}:current",
                "kind": "step",
                "label": f"Step current {step['status']}: {desc}",
                "detail": detail,
                "at": changed_at,
                "status": step["status"],
                "agent_did": step.get("assignee"),
            }
        )
        if step.get("completed_at"):
            events.append(
                {
                    "id": f"{m.id}:{step['id']}:completed",
                    "kind": "step",
                    "label": f"Step completed: {desc}",
                    "detail": cap_detail,
                    "at": step["completed_at"],
                    "status": "done",
                    "agent_did": step.get("assignee"),
                }
            )

    indexed = list(enumerate(events))
    indexed.sort(key=lambda item: (item[1].get("at") or "", item[0]))
    return [event for _, event in indexed]


def _mission_to_summary(m: Any, request: Optional[Request] = None) -> Dict[str, Any]:
    """真实 Mission(orchestration.mission)→ v2 MissionSummary 形状。

    driver 取 owner/owner_did(本层"谁推进"即 mission owner);next_actionable
    取第一个 TODO step 的描述;cap_token_id 取 metadata。"""
    from nth_dao.orchestration.mission import StepStatus

    steps = list(getattr(m, "steps", []) or [])
    prog = m.progress()
    in_progress_statuses = {
        StepStatus.ACTIVE.value,
        StepStatus.CLAIMED.value,
        StepStatus.NEEDS_REVIEW.value,
        StepStatus.BLOCKED.value,
    }
    in_progress = sum(1 for s in steps if getattr(s, "status", "") in in_progress_statuses)
    nxt = next(
        (s.description for s in steps if s.status == StepStatus.TODO.value),
        None,
    )
    current_statuses = (
        StepStatus.ACTIVE.value,
        StepStatus.CLAIMED.value,
        StepStatus.NEEDS_REVIEW.value,
        StepStatus.BLOCKED.value,
        StepStatus.FAILED.value,
    )
    cur_step = None
    for status in current_statuses:
        cur_step = next((s for s in steps if s.status == status), None)
        if cur_step is not None:
            break
    cur = getattr(cur_step, "description", None) if cur_step is not None else None
    meta = getattr(m, "metadata", None) or {}
    step_views = [_mission_step_to_view(s) for s in steps]
    return {
        "id": m.id,
        "title": m.title,
        "goal": m.goal,
        "status": m.status,
        "steps_total": prog["total"],
        "steps_done": prog["done"],
        "steps_in_progress": in_progress,
        "driver_label": getattr(m, "owner", "") or "",
        "driver_did": getattr(m, "owner_did", "") or "",
        "started_at": getattr(m, "created_at", "") or "",
        "cap_token_id": meta.get("cap_token_id"),
        "source_announcement_id": meta.get("source_announcement_id"),
        "process_id": meta.get("process_id"),
        "next_actionable": nxt,
        "current_action": cur,
        "current_step_id": getattr(cur_step, "id", None) if cur_step is not None else None,
        "current_step_status": getattr(cur_step, "status", None) if cur_step is not None else None,
        "steps": step_views,
        "timeline": _mission_timeline_events(
            m,
            step_views,
            _mission_audit_events(request, m.id) if request is not None else [],
            _mission_handoff_events(request, m.id) if request is not None else [],
        ),
    }


def _claim_visibility_ids(announcement_id: str) -> Tuple[str, str, str]:
    digest = hashlib.sha256(announcement_id.encode("utf-8")).hexdigest()
    return f"claim-{digest[:16]}", f"claim-{digest[:12]}", digest


def _ensure_claim_execution_visible(
    request: Request, ann: Any, announcement_id: str, claimant_did: str,
    agent_receipt_id: str = "",
) -> Dict[str, Any]:
    """Ensure a standalone claimed market task appears in Missions and Blackboard.

    Mission-linked announcements already flow through _reflect_claim_to_mission().
    Plain market tasks otherwise disappear from Tasks after claim with only a toast,
    leaving the user no visible execution trail. This helper creates an idempotent
    Mission plus a Blackboard process card keyed by announcement_id.
    """
    if getattr(ann, "mission_id", ""):
        return {"visibility_status": "ok", "visibility_warnings": []}

    mission_id, entry_id, digest = _claim_visibility_ids(announcement_id)
    out: Dict[str, Any] = {
        "visibility_status": "failed",
        "visibility_warnings": [],
    }
    mission_ok = False
    process_ok = False
    mission_created = False

    try:
        from nth_dao.orchestration.mission import Mission, MissionStatus, StepStatus
        from nth_dao.util.io import InterProcessLock

        mstore = getattr(request.app.state.nth, "missions", None)
        if mstore is None:
            raise RuntimeError("mission store unavailable")
        lock_root = Path(getattr(mstore, "root", Path("missions")))
        lock_path = lock_root / f".claim-visible-{digest}.mission"
        with InterProcessLock(lock_path):
            mission = mstore.get(mission_id)
            if mission is None:
                # Compatibility: adopt a legacy random-id mission if an older
                # build already created one for this announcement.
                for existing in mstore.list_all():
                    meta = getattr(existing, "metadata", None) or {}
                    if meta.get("source_announcement_id") == announcement_id:
                        mission = existing
                        break
            if mission is None:
                title = str(getattr(ann, "title", "") or "Claimed task").strip()
                desc = str(getattr(ann, "description", "") or title).strip() or title
                caps = [
                    str(c).strip()
                    for c in (getattr(ann, "capability_set", None) or [])
                    if str(c).strip()
                ]
                mission = Mission.new(
                    title=title[:200],
                    goal=desc[:2000],
                    owner=claimant_did,
                    owner_did=claimant_did,
                    steps=[{
                        "description": desc[:500],
                        "required_capabilities": caps[:16],
                    }],
                )
                mission.id = mission_id
                mission.status = MissionStatus.ACTIVE.value
                mission.metadata = dict(mission.metadata or {})
                mission.metadata.update({
                    "source": "market_claim",
                    "source_announcement_id": announcement_id,
                    "claimant_did": claimant_did,
                    "publisher_did": str(getattr(ann, "publisher_did", "") or ""),
                    "reward_minor": int(getattr(ann, "reward_minor", 0) or 0),
                    "reward_asset": str(getattr(ann, "reward_asset", "") or ""),
                })
                if mission.steps:
                    mission.steps[0].status = StepStatus.CLAIMED.value
                    mission.steps[0].assignee = claimant_did
                try:
                    mstore.create(mission)
                    mission_created = True
                except FileExistsError:
                    mission = mstore.get(mission_id)
                    if mission is None:
                        raise
            out["mission_id"] = mission.id
            mission_ok = True
    except Exception as exc:  # noqa: BLE001
        out["visibility_warnings"].append("mission_visibility_failed")
        logger.warning("claim->visible mission failed for %s: %s", announcement_id, exc)

    if mission_ok and mission_created:
        _emit_mission_evidence(request, MISSION_MARKET_CLAIM_VISIBLE, {
            "mission_id": str(out.get("mission_id", "") or ""),
            "status": "active",
            "visibility_status": "ok",
            "claimant_did": claimant_did,
            "source_announcement_id": announcement_id,
            "agent_claim_receipt_id": agent_receipt_id,
        })

    try:
        from nth_dao.util.io import InterProcessLock

        blackboard = _state_blackboard(request)
        if blackboard is None:
            raise RuntimeError("blackboard unavailable")
        lock_root = Path(getattr(blackboard, "root", Path("blackboard")))
        lock_path = lock_root / f".claim-visible-{digest}.blackboard"
        with InterProcessLock(lock_path):
            existing = blackboard.get(entry_id, "shared")
            if existing is None:
                meta: Dict[str, Any] = {
                    "workflow": "tasks",
                    "auto": True,
                    "current_agent": claimant_did,
                    "created_by": "nth-dao-hub",
                    "created_by_did": claimant_did,
                    "claimant_did": claimant_did,
                    "source": "market_claim",
                    "source_announcement_id": announcement_id,
                }
                if out.get("mission_id"):
                    meta["mission_id"] = out["mission_id"]
                entry = blackboard.post(
                    topic=str(getattr(ann, "title", "") or "Claimed task")[:200],
                    author="nth-dao-hub",
                    scope="shared",
                    status="doing",
                    content=str(getattr(ann, "description", "") or "")[:1000],
                    metadata=meta,
                    entry_id=entry_id,
                )
            else:
                entry = existing
                if out.get("mission_id") and not entry.metadata.get("mission_id"):
                    entry = blackboard.update(
                        entry_id,
                        author="nth-dao-hub",
                        scope="shared",
                        metadata_patch={"mission_id": out["mission_id"]},
                    )
            out["process_id"] = entry.id
            process_ok = True
    except Exception as exc:  # noqa: BLE001
        out["visibility_warnings"].append("blackboard_visibility_failed")
        logger.warning("claim->visible process failed for %s: %s", announcement_id, exc)

    if mission_ok and process_ok and out.get("mission_id") and out.get("process_id"):
        try:
            from nth_dao.util.io import InterProcessLock

            mstore = getattr(request.app.state.nth, "missions", None)
            if mstore is None:
                raise RuntimeError("mission store unavailable")
            lock_root = Path(getattr(mstore, "root", Path("missions")))
            lock_path = lock_root / f".claim-visible-{digest}.mission"
            with InterProcessLock(lock_path):
                mission = mstore.get(str(out["mission_id"]))
                if mission is not None:
                    mission.metadata = dict(getattr(mission, "metadata", None) or {})
                    if mission.metadata.get("process_id") != out["process_id"]:
                        mission.metadata["process_id"] = out["process_id"]
                        mstore.save(mission)
        except Exception as exc:  # noqa: BLE001
            out["visibility_warnings"].append("mission_process_link_failed")
            logger.warning(
                "claim->visible process link failed for %s: %s",
                announcement_id, exc,
            )

    if mission_ok and process_ok:
        out["visibility_status"] = "ok"
    elif mission_ok or process_ok:
        out["visibility_status"] = "partial"
    else:
        out["visibility_status"] = "failed"
    return out

def _reflect_claim_to_mission(
    request: Request, ann: Any, announcement_id: str, claimant_did: str,
    agent_receipt_id: str = "",
) -> Dict[str, Any]:
    """Reflect a successful market claim back into its linked Mission step.

    Returns a small status object instead of a bool so the API can distinguish
    "already reflected / already advanced" from real visibility failures. Claim
    settlement remains best-effort and never rolls back a signed receipt.
    """
    mid = getattr(ann, "mission_id", "") or ""
    if not mid:
        return {"reflected": False, "reason": "no_mission_id"}
    try:
        from nth_dao.orchestration.market_coordinator import announcement_id_for
        from nth_dao.orchestration.mission import StepStatus
        from nth_dao.util.io import InterProcessLock, safe_id

        mstore = getattr(request.app.state.nth, "missions", None)
        if mstore is None:
            return {"reflected": False, "reason": "mission_store_unavailable"}
        lock_root = Path(getattr(mstore, "root", Path("missions")))
        lock_path = lock_root / f".claim-reflect-{safe_id(mid)}"
        with InterProcessLock(lock_path):
            mission = mstore.get(mid)
            if mission is None:
                return {"reflected": False, "reason": "mission_missing"}
            for step in mission.steps:
                if announcement_id_for(mid, step.id) == announcement_id:
                    # Only todo -> claimed is a mutation. If the same claim is
                    # replayed after an agent has advanced the step, preserve
                    # that progress. It is visibility-ok only when the current
                    # assignee is the same claimant; otherwise the receipt and
                    # Mission execution view disagree and must be surfaced.
                    if step.status != StepStatus.TODO.value:
                        current_assignee = str(getattr(step, "assignee", "") or "")
                        if current_assignee == claimant_did:
                            return {
                                "reflected": False,
                                "reason": "already_same_claimant",
                                "step_status": step.status,
                            }
                        if current_assignee:
                            return {
                                "reflected": False,
                                "reason": "already_claimed_by_other",
                                "step_status": step.status,
                            }
                        return {
                            "reflected": False,
                            "reason": "already_non_todo_unassigned",
                            "step_status": step.status,
                        }
                    step.status = StepStatus.CLAIMED.value
                    step.assignee = claimant_did
                    mstore.save(mission)
                    _emit_mission_evidence(request, MISSION_STEP_CLAIMED, {
                        "mission_id": mid,
                        "step_id": step.id,
                        "step_status": step.status,
                        "claimant_did": claimant_did,
                        "announcement_id": announcement_id,
                        "agent_claim_receipt_id": agent_receipt_id,
                    })
                    return {"reflected": True, "reason": "reflected"}
            return {"reflected": False, "reason": "step_missing"}
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "claim->mission reflect failed for %s: %s", announcement_id, exc,

        )
        return {"reflected": False, "reason": "reflect_failed"}


_STAGE_FROM_BLACKBOARD = {
    "todo":      "received",
    "doing":     "in_progress",
    "waiting":   "awaiting_external",
    "blocked":   "blocked",
    "done":      "done",
    # Review fix C6 (2026-06-10): "cancelled" is a natural operational
    # status (user aborted, agent gave up) and was previously falling
    # through the default "received" — misplacing cancelled cards in
    # the Intake column on the Kanban. Map to "done" (terminal). Other
    # unknown statuses still fall through to "received" so the entry
    # at least shows up; we log a warning so we notice new vocabulary.
    "cancelled": "done",
    "canceled":  "done",  # American spelling — same intent
    "failed":    "done",  # also terminal
}
_PROCESS_STAGE_TO_BLACKBOARD = {
    "received":          "todo",
    "in_progress":       "doing",
    "awaiting_external": "waiting",
    "blocked":           "blocked",
    "done":              "done",
}


def _blackboard_subtitle(content: str) -> str:
    """Collapse newlines + truncate to 160 chars for the single-line
    ProcessCard.subtitle slot.

    P7 fix 2026-06-10 (refined): the original used replace("\\n",
    " ") which produces "Line1  Line2" from "Line1\\n\\nLine2"
    (double space). splitlines() + " ".join() still kept empty
    segments from consecutive newlines. str.split() with no args
    splits on ANY whitespace run AND drops empties — exactly what
    a "collapse to one line" mapper wants. """
    if not content:
        return ""
    return " ".join(content.split())[:160]


def _read_processes_from_blackboard(
    blackboard: Optional[Any] = None,
) -> List[Dict[str, Any]]:
    """Map ``Blackboard.list("shared")`` → ProcessCard[].

    Accepts the live ``Blackboard`` instance from app.state (review
    fix C5 2026-06-10): the previous version hardcoded a repo-
    relative path which never matched the workspace where WebState
    actually persists entries. Live data was therefore invisible —
    the endpoint always served seed even when real entries existed.
    Pass ``state.blackboard`` from the endpoint and we read the
    real source of truth.

    Returns [] if the blackboard is None / unusable, so seed takes
    over. Catches any read error and logs — never raises. """
    if blackboard is None:
        return []
    try:
        entries = blackboard.list(scope="shared")
    except Exception as e:
        logger.warning("v2_api: blackboard.list() failed: %s", e)
        return []

    processes: List[Dict[str, Any]] = []
    for e in entries:
        try:
            processes.append(_blackboard_entry_to_process_card(e))
        except Exception as ex:
            logger.warning("v2_api: skipping malformed blackboard entry: %s", ex)
    return processes


# Field-mapping table — explicit so a future BlackboardEntry field
# rename surfaces here loudly instead of silently producing empty
# values. The lambda form means refactor tools (rename symbol
# across project) will catch hits in BOTH sides. P10 fix 2026-06-10.
_BB_TO_PROCESS: Dict[str, Any] = {
    "id":            lambda e, m: e.id,
    "title":         lambda e, m: e.topic,           # BB.topic → UI.title
    "current_agent": lambda e, m: m.get("current_agent") or e.author,
    "updated_at":    lambda e, m: e.updated_at,
    "subtitle":      lambda e, m: _blackboard_subtitle(e.content or ""),
    "workflow":      lambda e, m: str(m.get("workflow", "general")),
    "next_agent":    lambda e, m: m.get("next_agent") or None,
    "cap_token_id":  lambda e, m: m.get("cap_token_id") or None,
    "amount":        lambda e, m: m.get("amount") or None,
    "auto":          lambda e, m: bool(m.get("auto", False)),
}


def _blackboard_entry_to_process_card(e: Any) -> Dict[str, Any]:
    """Translate BlackboardEntry → ProcessCard. The mapping is
    declarative in ``_BB_TO_PROCESS`` so a rename on the BB side is
    a single-line fix here rather than scattered ``e.<attr>``
    accesses (P10 fix 2026-06-10). """
    meta = e.metadata or {}
    stage = _STAGE_FROM_BLACKBOARD.get(e.status)
    if stage is None:
        logger.info(
            "v2_api: unknown blackboard status %r → default Intake",
            e.status,
        )
        stage = "received"
    out = {key: fn(e, meta) for key, fn in _BB_TO_PROCESS.items()}
    out["stage"] = stage
    return out


def _candidate_dirs(workspace: Optional[Path], subdir: str) -> List[Path]:
    """Return the single live workspace path for a disk-store directory.

    Production reads must never fall through to repository fixtures. A user
    who clears a workspace expects an empty workspace, not resurrected sample
    agents, receipts, or authority tokens from the source checkout.
    """
    return [workspace / subdir] if workspace else []


def _safe_iter(root: Path, pattern: Optional[str] = None) -> List[Path]:
    """Wrap glob/iterdir in try/except (review fix C3 2026-06-10).

    ``Path.glob`` / ``Path.iterdir`` can raise ``PermissionError``
    or ``OSError`` on Windows when the directory exists but is ACL-
    restricted, and a single such failure used to take down the
    whole endpoint with a 500. We return [] on any iteration error
    so the endpoint can fall back to seed. """
    if not root.is_dir():
        return []
    try:
        if pattern is None:
            return sorted(root.iterdir())
        return sorted(root.glob(pattern))
    except (OSError, PermissionError) as ex:
        logger.warning("v2_api: cannot iterate %s: %s", root, ex)
        return []


def _read_from_disk(
    workspace: Optional[Path],
    subdir: str,
    *,
    glob_pattern: Optional[str] = "*.json",
    mapper: Any,
    label: str,
    max_files: int = 500,
) -> List[Dict[str, Any]]:
    """Generic disk reader (P3 fix 2026-06-10 — DRY the 3 readers).

    ``mapper(path: Path, data: dict | None) -> dict`` does the
    field translation. When ``glob_pattern`` is None we iterate the
    directory (for layouts like team_agents/{id}/identity.json
    where the agent identity is a NAMED FILE inside a per-agent
    subdir — mapper handles the descent).

    ``max_files`` caps the iteration so a runaway directory with
    50k entries doesn't burn memory on the sort (P4 fix). The cap
    is a defensive ceiling; a real production reader would page. """
    out: List[Dict[str, Any]] = []
    for root in _candidate_dirs(workspace, subdir):
        items = _safe_iter(root, glob_pattern)
        if len(items) > max_files:
            logger.warning(
                "v2_api: %s has %d entries, capping at %d (P4 fix). "
                "Consider paging if this is real data.",
                root, len(items), max_files,
            )
            items = items[:max_files]
        for path in items:
            try:
                mapped = mapper(path)
                if mapped is not None:
                    out.append(mapped)
            except Exception as ex:
                logger.warning("v2_api: %s mapper failed for %s: %s", label, path, ex)
        if out:
            break
    return out


def _map_receipt(path: Path) -> Optional[Dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as ex:
        logger.warning("v2_api: unreadable receipt %s: %s", path, ex)
        return None
    return {
        "id": data.get("id") or path.stem,
        "signer_did": data.get("signer_did", ""),
        "signer_label": data.get("signer_label", data.get("signer_did", "")[:12]),
        "goal_id": data.get("goal_id", ""),
        "content_hash": data.get("content_hash", ""),
        "prev_content_hash": data.get("prev_content_hash", ""),
        "has_cap_token": bool(data.get("cap_token_id")) or bool(data.get("has_cap_token")),
        "summary": data.get("summary", path.stem),
        "issued_at": data.get("issued_at", ""),
        "principal_user_did": data.get("principal_user_did"),
    }

def _receipt_cap_scope_summary(receipt: Dict[str, Any]) -> Dict[str, Any]:
    """Return a compact UI-safe view of the receipt's authorizing scope."""

    def _int_or_zero(value: Any) -> int:
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    cap = receipt.get("authorizing_cap_token")
    if not isinstance(cap, dict):
        return {"present": False}
    capabilities = cap.get("capabilities", [])
    if not isinstance(capabilities, list):
        capabilities = []
    scope_model_allowlist = cap.get("scope_model_allowlist")
    if not isinstance(scope_model_allowlist, list):
        scope_model_allowlist = None
    return {
        "present": True,
        "token_id": str(cap.get("token_id", "") or ""),
        "issuer_did": str(cap.get("issuer_did", "") or ""),
        "subject_did": str(cap.get("subject_did", "") or ""),
        "capabilities": [str(c) for c in capabilities],
        "scope_task_id": str(cap.get("scope_task_id", "") or ""),
        "scope_dao": str(cap.get("scope_dao", "") or ""),
        "scope_model_allowlist": (
            [str(m) for m in scope_model_allowlist]
            if scope_model_allowlist is not None else None
        ),
        "not_before": _int_or_zero(cap.get("not_before")),
        "not_after": _int_or_zero(cap.get("not_after")),
    }

def _receipt_detail_to_wire(receipt: Dict[str, Any]) -> Dict[str, Any]:
    """Build the console inspection envelope for a raw signed receipt."""
    verified = False
    reason = ""
    try:
        from nth_dao.execution_receipt import verify_receipt

        verified = bool(verify_receipt(receipt))
        if not verified:
            reason = "receipt signature/content/cap-token verification failed"
    except Exception as exc:  # noqa: BLE001
        reason = _redact_local_paths(
            f"receipt verification raised {type(exc).__name__}: {exc}"
        )

    summary = {
        "receipt_id": str(
            receipt.get("receipt_id", "") or receipt.get("id", "") or ""
        ),
        "signer_did": str(receipt.get("signer_did", "") or ""),
        "goal_id": str(receipt.get("goal_id", "") or ""),
        "issued_at": str(receipt.get("issued_at", "") or ""),
        "content_hash": str(receipt.get("content_hash", "") or ""),
        "prev_content_hash": str(receipt.get("prev_content_hash", "") or ""),
        "kind": str(receipt.get("kind", "") or ""),
        "cap_scope": _receipt_cap_scope_summary(receipt),
    }
    return {
        "receipt": receipt,
        "summary": summary,
        "verification": {
            "verified": verified,
            "status": "verified" if verified else "failed",
            "reason": reason,
        },
    }


def _map_cap_token(path: Path) -> Optional[Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return {
        "token_id": data.get("token_id") or path.stem,
        "subject_did": data.get("subject_did", ""),
        "subject_label": data.get("subject_label", ""),
        "capabilities": data.get("capabilities", []),
        "scope_task_id": data.get("scope_task_id", ""),
        "not_before": int(data.get("not_before", 0)),
        "not_after": int(data.get("not_after", 0)),
        "revoked": bool(data.get("revoked", False)),
        "use_count": int(data.get("use_count", 0)),
    }


def _map_agent_dir(subdir: Path) -> Optional[Dict[str, Any]]:
    identity_file = subdir / "identity.json"
    if not identity_file.is_file():
        return None
    data = json.loads(identity_file.read_text(encoding="utf-8"))
    return {
        "did": data.get("did", ""),
        "code": data.get("code", subdir.name[:9]),
        "label": data.get("label", subdir.name),
        "source": data.get("source", "local"),
        "capabilities": data.get("capabilities", []),
        "last_seen": data.get("last_seen"),
        "has_active_cap": bool(data.get("has_active_cap", False)),
        "agent_card": data.get("agent_card"),
    }


def _parse_issued_at(ts: str) -> Optional[datetime]:
    """Parse an ISO-8601 timestamp into a UTC-aware datetime.

    Returns None for empty / malformed inputs so the caller can
    skip or place those receipts deterministically rather than
    let a bogus string land in the middle of a lex sort.

    Handles three observed formats:
      "2026-06-09T11:20:00Z"          — seed literal (Z suffix)
      "2026-06-11T15:00:00.123+00:00" — datetime.now(timezone.utc)
      "2026-06-11T07:00:00+08:00"     — imported / cross-timezone
    All normalised to UTC for cross-form comparison. """
    if not ts:
        return None
    try:
        # Python 3.11+ datetime.fromisoformat handles "Z"; for older
        # interpreters swap Z → +00:00 before parsing. The project
        # uses 3.14 so the swap is belt-and-braces.
        normalised = ts[:-1] + "+00:00" if ts.endswith("Z") else ts
        dt = datetime.fromisoformat(normalised)
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        # Naive datetime — treat as UTC. This matches the design
        # commitment in the issued_at docstring (UTC-aware), but
        # be defensive in case an older record bypassed that.
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _read_receipts_from_disk(workspace: Optional[Path] = None) -> List[Dict[str, Any]]:
    out = _read_from_disk(workspace, "team_receipts",
                          mapper=_map_receipt, label="receipt")
    # Sort by issued_at ascending so the LAST entry is the
    # chronological chain head. Filename ASCII order (what
    # _safe_iter returns) is wrong here because Phase 2 mints
    # receipts under uuid-hex filenames that sort BEFORE Phase
    # 1.5 seed names like "rcpt-aaa2.json" — the newest signed
    # receipt would sit in the middle, and StatusBar's chain
    # head would silently show stale data.
    #
    # Sort key uses _parse_issued_at to normalise across formats
    # (review fix 2026-06-11): string lex sort silently lies for
    # mixed timezone offsets — "2026-06-11T07:00:00+08:00"
    # (== 23:00 UTC) sorts BEFORE "2026-06-11T15:00:00+00:00" by
    # lex but is 8 hours LATER in UTC. Parsing to a UTC datetime
    # is the only safe key once cross-timezone receipts become
    # possible.
    #
    # Empty / malformed issued_at → datetime.min so those records
    # sort to the FRONT (i.e. NEVER end up at receipts[-1] when
    # there's at least one well-formed entry). This matches
    # ReceiptStore.head_content_hash which effectively skips
    # un-timestamped entries (they fail the `issued > ""` check).
    #
    # Tie-breaking: when normalised UTC instants match exactly,
    # secondary key is content_hash ASCENDING — Python's ascending
    # sort places the LEX-GREATEST hash LAST, matching
    # head_content_hash's documented "lex-greatest wins".
    #
    # Bug discovered during Phase 2 browser walk-through 2026-06-11.
    _MIN_TS = datetime.min.replace(tzinfo=timezone.utc)
    def _sort_key(r: Dict[str, Any]) -> Tuple[datetime, str]:
        parsed = _parse_issued_at(str(r.get("issued_at", "")))
        return (parsed or _MIN_TS, str(r.get("content_hash", "")))
    out.sort(key=_sort_key)
    return out


def _read_cap_tokens_from_disk(workspace: Optional[Path] = None) -> List[Dict[str, Any]]:
    return _read_from_disk(workspace, "team_cap_tokens",
                           mapper=_map_cap_token, label="cap_token")


def _read_agents_from_disk(workspace: Optional[Path] = None) -> List[Dict[str, Any]]:
    # Agents live in team_agents/{id}/identity.json — iterate subdirs.
    return _read_from_disk(workspace, "team_agents",
                           glob_pattern=None,
                           mapper=_map_agent_dir, label="agent")


# ─────────────────────────────────────────────────────────────
# Route registration
# ─────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────
# Pydantic response models (P5 fix 2026-06-10).
#
# Validate response shape at the boundary so a broken disk mapper
# or a typo in seed data fails loudly at the server rather than
# silently producing bad data that the frontend types lie about.
# Mirrors frontend/src/v2/types-v2.ts. ``extra = "allow"`` keeps
# us forward-compatible with the optional multi-user fields the
# types-v2.ts already declared (owner_user_did, version, etc.).
# ─────────────────────────────────────────────────────────────


class _Model(BaseModel):
    model_config = {"extra": "allow"}


class DecisionM(_Model):
    id: str
    title: str
    rationale: str
    impact: str
    proposer_did: str
    proposer_label: str
    preview_receipt: Dict[str, Any]
    raised_at: str
    mission_id: Optional[str] = None
    cap_expires_at: Optional[str] = None


class MissionStepViewM(_Model):
    id: str
    description: str
    status: str
    required_capabilities: List[str] = Field(default_factory=list)
    depends_on: List[str] = Field(default_factory=list)
    assignee: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    completed_at: Optional[str] = None
    notes: List[str] = Field(default_factory=list)
    notes_count: int = 0


class MissionTimelineEventM(_Model):
    id: str
    kind: str
    label: str
    detail: Optional[str] = None
    at: Optional[str] = None
    status: Optional[str] = None
    agent_did: Optional[str] = None
    receipt_id: Optional[str] = None
    announcement_id: Optional[str] = None
    source_announcement_id: Optional[str] = None
    process_id: Optional[str] = None


class MissionSummaryM(_Model):
    id: str
    title: str
    goal: str
    status: str
    steps_total: int
    steps_done: int
    steps_in_progress: int
    driver_label: str
    driver_did: str
    started_at: str
    cap_token_id: Optional[str] = None
    source_announcement_id: Optional[str] = None
    process_id: Optional[str] = None
    next_actionable: Optional[str] = None
    current_action: Optional[str] = None
    current_step_id: Optional[str] = None
    current_step_status: Optional[str] = None
    steps: List[MissionStepViewM] = Field(default_factory=list)
    timeline: List[MissionTimelineEventM] = Field(default_factory=list)


class CreateMissionStepBody(_Model):
    description: str
    required_capabilities: List[str] = Field(default_factory=list)

class CreateMissionBody(_Model):
    """POST /api/v2/missions 请求体:真正创建并落盘一个 mission(含 steps)。"""

    title: str
    goal: str = ""
    driver: str = Field(default="", description="负责推进的 agent 标签(owner)。")
    driver_did: str = Field(
        default="",
        description="driver agent 的 DID(owner_did)。DID 为本的系统里必须留存,"
                    "否则 mission 只知人类标签、不知密码学身份。",
    )
    steps: List[CreateMissionStepBody] = Field(default_factory=list)


class RunMissionStepBody(_Model):
    """Drive one mission step through a supervised local A2A agent."""

    agent_did: str = Field(default="")
    prompt: str = Field(default="")


class ProcessCardM(_Model):
    id: str
    title: str
    subtitle: str
    workflow: str
    stage: str
    current_agent: str
    updated_at: str
    auto: bool
    next_agent: Optional[str] = None
    cap_token_id: Optional[str] = None
    amount: Optional[str] = None

class CreateProcessBody(_Model):
    """POST /api/v2/processes: create a real Blackboard-backed process."""

    model_config = {"extra": "forbid"}

    title: str = Field(min_length=1, max_length=200)
    workflow: str = Field(default="general", max_length=80)
    subtitle: str = Field(default="", max_length=1000)
    current_agent: str = Field(default="admin", max_length=160)
    stage: str = Field(default="received")
    next_agent: Optional[str] = Field(default=None, max_length=160)
    cap_token_id: Optional[str] = Field(default=None, max_length=160)
    amount: Optional[str] = Field(default=None, max_length=80)
    auto: bool = False

    @field_validator(
        "title", "workflow", "subtitle", "current_agent", "stage",
        "next_agent", "cap_token_id", "amount", mode="before",
    )
    @classmethod
    def _trim_strings(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value

    @field_validator("workflow")
    @classmethod
    def _workflow_not_empty(cls, value: str) -> str:
        return value or "general"

    @field_validator("current_agent")
    @classmethod
    def _agent_not_empty(cls, value: str) -> str:
        return value or "admin"
    @field_validator("stage")
    @classmethod
    def _known_stage(cls, value: str) -> str:
        if value not in _PROCESS_STAGE_TO_BLACKBOARD:
            raise ValueError(f"unknown process stage: {value}")
        return value


class ReceiptSummaryM(_Model):
    id: str
    signer_did: str
    signer_label: str
    goal_id: str
    content_hash: str
    prev_content_hash: str
    has_cap_token: bool
    summary: str
    issued_at: str
    principal_user_did: Optional[str] = None


class CapTokenSummaryM(_Model):
    token_id: str
    subject_did: str
    subject_label: str
    capabilities: List[str]
    scope_task_id: str
    not_before: int
    not_after: int
    revoked: bool
    use_count: int


class AgentEntryM(_Model):
    agent_id: Optional[str] = None
    did: str
    code: str
    label: str
    source: str
    capabilities: List[str]
    has_active_cap: bool
    last_seen: Optional[str] = None
    agent_card: Optional[Dict[str, Any]] = None
    # Phase 3a additions (2026-06-11): present on supervisor-spawned
    # agents, absent on disk / seed / contact entries. extra="allow"
    # would let these through anyway but declaring them makes the
    # schema honest and the spawn endpoint's response_model valid.
    supervised: Optional[bool] = None
    alive: Optional[bool] = None
    kind: Optional[str] = None
    ask_timeout_s: Optional[float] = None
    work_scope_id: Optional[str] = None
    work_access: Optional[str] = None
    work_revision: Optional[str] = None
    provider_checked_at: Optional[str] = None
    # Phase 3d (2026-06-11): the child's localhost A2A HTTP port,
    # advertised on agent_started.a2a_port and stamped by the
    # supervisor at spawn time. None when the child didn't bind
    # (degraded state) or for disk / seed entries (no live process).
    # The v2 console uses this to surface a "/ping → :PORT" badge
    # and to invoke /api/v2/agents/{did}/ping.
    a2a_port: Optional[int] = None
    # Phase G (frontend integration): mirror the cap_token's
    # ``scope_model_allowlist`` (joined from cap_tokens store).
    # Lets the agent card show a "scoped: <models>" badge so the
    # operator can see at a glance which agents are pinned to a
    # narrower model set vs which are unrestricted. None when the
    # agent's cap_token has no scope field (legacy / unscoped) or
    # when join-side lookup fails.
    scope_model_allowlist: Optional[List[str]] = None


class SpawnResponseM(_Model):
    """POST /api/v2/agents/spawn response shape.

    Phase 3b (2026-06-11): ``cap_token_id`` carries the token_id of
    the cap_token the hub issued for the freshly-spawned agent. The
    full token isn't returned in the body — the operator's UI loads
    it from /api/v2/cap_tokens. ``did`` is now a real W3C did:key
    (was ``did:nth-hub-stub:`` in Phase 3a).

    Phase 3d (2026-06-11): ``a2a_port`` is the child's localhost
    HTTP port (None if the bind failed in the child — degraded
    state, agent is up but not reachable via the A2A proxy). """
    agent_id: str
    did: str
    kind: str
    label: str
    pid: Optional[int] = None
    cap_token_id: Optional[str] = None
    a2a_port: Optional[int] = None
    agent: AgentEntryM


# ─────────────────────────────────────────────────────────────
# Phase 2 — decision store + receipt-signing for POST endpoints.
#
# Production decisions live in a workspace-local SQLite queue. Test suites may
# inject a dict on ``app.state`` to isolate receipt-signing behavior.
# ─────────────────────────────────────────────────────────────


_DECISION_STORE_BUILD_LOCK = threading.Lock()


def _decision_store_for_state(state: Any) -> Any:
    """Return an injected test store or build the durable production store."""

    store = getattr(state, "v2_decisions_store", None)
    if store is not None:
        return store
    with _DECISION_STORE_BUILD_LOCK:
        store = getattr(state, "v2_decisions_store", None)
        if store is not None:
            return store
        from .decision_store import DecisionStore

        try:
            workspace = Path(state.nth.workspace)
        except (AttributeError, TypeError, ValueError) as exc:
            raise RuntimeError("decision workspace is unavailable") from exc
        store = DecisionStore(workspace)
        state.v2_decisions_store = store
        return store


def _decisions_store(request: Request) -> Any:
    return _decision_store_for_state(request.app.state)


def _state_node_identity(request: Request) -> Optional[Any]:
    """Signing identity from app.state.nth (set up in __init__.py
    by _bootstrap). Returns None if not initialised — endpoints
    handling that case must fail closed (503), never return an
    unsigned receipt. """
    try:
        return request.app.state.nth.node_identity
    except AttributeError:
        return None


def _state_spine(request: Request) -> Optional[Any]:
    """本 workspace 的 spine 单例(__init__._bootstrap 建,全进程共享)。

    缺失(node_identity 不可签 / 日志损坏 / 未接线)→ None,调用方回退到只写
    自身 feed(影子双写关闭)。绝不在此处新建实例——单例由 _bootstrap 持有,
    每请求新建会让并发 append 分叉。
    """
    try:
        return request.app.state.nth.spine
    except AttributeError:
        return None


_MARKET_FEED_STATE_LOCK = threading.Lock()


def _state_market_feed(request: Request) -> Any:
    """Return one mtime-invalidated MarketFeed projection per web process."""
    state = request.app.state
    feed = getattr(state, "trade_offer_market_feed", None)
    if feed is not None:
        return feed
    with _MARKET_FEED_STATE_LOCK:
        feed = getattr(state, "trade_offer_market_feed", None)
        if feed is None:
            from nth_dao.market import MarketFeed

            workspace = _state_workspace(request)
            if workspace is None:
                raise RuntimeError("market feed workspace unavailable")
            feed = MarketFeed(
                workspace,
                spine=_state_spine(request),
                trade_offer_store=_state_trade_offer_store(request),
            )
            state.trade_offer_market_feed = feed
    return feed


def _verified_spine_events(request: Request) -> Optional[list]:
    """hub spine 的**已验证**事件列表(Phase 4c 读端统一入口)。

    spine 缺失 → None(调用方返回空视图);链完整性校验失败 → 503,**绝不**把可能
    被篡改的数据投影出去(fail-closed)。校验通过才回放投影。

    性能(2026 优化):按 ``head_hash`` 和日志文件指纹缓存在 spine 实例上。
    文件指纹不可省略:另一个 hub 进程追加时不会更新本进程内的 head_hash。
    未变化时返回同一快照;变化时通过 SignedEventLog.verified_snapshot() 在同一
    跨进程锁内完成校验和读取,避免 verify/read 间的 TOCTOU 窗口。
    """
    spine = _state_spine(request)
    if spine is None:
        return None
    head = spine.head_hash
    path = getattr(spine, "_path", None)

    def storage_fingerprint() -> tuple[Any, ...]:
        if path is None:
            return (False, 0, 0, 0, 0, "")
        target = Path(path)
        try:
            before = target.stat()
            digest = hashlib.sha256()
            with target.open("rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    digest.update(chunk)
            after = target.stat()
        except FileNotFoundError:
            return (False, 0, 0, 0, 0, "")
        return (
            True,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
            before.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
            after.st_ino,
            digest.hexdigest(),
        )

    try:
        fingerprint = storage_fingerprint()
    except OSError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"spine integrity check failed: {exc}",
        ) from exc
    cache = getattr(spine, "_v2_verified_cache", None)
    cache_fingerprint = getattr(
        spine,
        "_v2_verified_cache_fingerprint",
        None,
    )
    if (
        cache is not None
        and cache[0] == head
        and cache_fingerprint == fingerprint
    ):
        return cache[1]
    try:
        events: list[Any] = []
        verified_fingerprint: tuple[Any, ...] | None = None
        for _attempt in range(3):
            before = storage_fingerprint()
            if hasattr(spine, "verified_snapshot"):
                events = list(spine.verified_snapshot())
            else:
                ok, why = spine.verify_chain()
                if not ok:
                    raise ValueError(why)
                events = list(spine.read_all())
            after = storage_fingerprint()
            if before == after:
                verified_fingerprint = after
                break
        if verified_fingerprint is None:
            raise RuntimeError("Spine changed repeatedly during verification")
    except OSError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"spine integrity check failed: {exc}",
        ) from exc
    except (RuntimeError, TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=503,
            detail=f"spine integrity check failed: {exc}",
        ) from exc
    spine._v2_verified_cache = (spine.head_hash, events)
    spine._v2_verified_cache_fingerprint = verified_fingerprint
    return events


_MAX_TRADE_OFFER_DISCOVERY_EVIDENCE = 16
_MAX_TRADE_OFFER_DISCOVERY_EVIDENCE_BYTES = 128 * 1024


def _trade_offer_store_spine_transaction_lock_path(workspace: Path) -> Path:
    """Return the lock shared by every Offer Store/Spine transaction."""

    return (
        workspace
        / "trade"
        / "offers"
        / ".locks"
        / "store-spine-transaction.lock"
    )


def _verify_trade_offer_discovery_evidence(
    evidence: Any,
    offer: Any,
    *,
    imported_at_ms: int,
) -> tuple[bool, str]:
    """Reverify the exact discovery claim signed into an import event."""

    from nth_dao.market import (
        TaskAnnouncement,
        announcement_federation_key,
        verify_trade_offer_announcement_binding,
    )

    required = {
        "announcement",
        "federation_key",
        "source_peer",
        "source_did",
        "stale",
        "last_verified_ms",
    }
    if not isinstance(evidence, dict) or set(evidence) != required:
        return False, "federated discovery evidence has an invalid shape"
    source_peer = evidence["source_peer"]
    source_did = evidence["source_did"]
    verified_ms = evidence["last_verified_ms"]
    try:
        source_peer_bytes = (
            source_peer.encode("utf-8") if isinstance(source_peer, str) else b""
        )
    except UnicodeEncodeError:
        source_peer_bytes = b""
    if (
        not isinstance(source_peer, str)
        or not isinstance(source_did, str)
        or not 1 <= len(source_peer_bytes) <= 2_048
        or any(ord(character) < 0x20 for character in source_peer)
    ):
        return False, "federated discovery source peer is invalid"
    try:
        parsed = urlsplit(source_peer)
        parsed_port = parsed.port
    except ValueError:
        return False, "federated discovery source peer is invalid"
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False, "federated discovery source peer is invalid"
    if parsed_port is not None and not 1 <= parsed_port <= 65_535:
        return False, "federated discovery source peer is invalid"
    if parsed.username or parsed.password or parsed.fragment:
        return False, "federated discovery source peer is invalid"
    if (
        type(verified_ms) is not int
        or not 0 < verified_ms <= (1 << 63) - 1
        or type(imported_at_ms) is not int
        or verified_ms > imported_at_ms
        or type(evidence["stale"]) is not bool
    ):
        return False, "federated discovery observation metadata is invalid"
    try:
        announcement = TaskAnnouncement.from_dict(evidence["announcement"])
    except (TypeError, ValueError) as exc:
        return False, f"federated discovery announcement is invalid: {exc}"
    ok, reason = verify_trade_offer_announcement_binding(offer, announcement)
    if not ok:
        return False, reason
    if evidence["federation_key"] != announcement_federation_key(announcement):
        return False, "federated discovery key does not match its announcement"
    if (
        source_did != announcement.effective_authority_did()
        or source_did != offer.publisher_did
    ):
        return False, "federated discovery source DID is not the Offer publisher"
    return True, "ok"


def _verify_trade_offer_discovery_evidence_set(
    discoveries: Any,
    selected: Any,
    offer: Any,
    *,
    imported_at_ms: int,
    expected_count: int,
) -> tuple[bool, str]:
    """Verify a bounded, source-distinct set of signed discovery claims."""

    from nth_dao.canonical_json import canonical_json

    if (
        not isinstance(discoveries, list)
        or not 1 <= len(discoveries) <= _MAX_TRADE_OFFER_DISCOVERY_EVIDENCE
    ):
        return False, "federated discovery evidence set has an invalid size"
    try:
        encoded_size = len(canonical_json({"discoveries": discoveries}))
    except (OverflowError, RecursionError, TypeError, ValueError):
        return False, "federated discovery evidence set is not canonical JSON"
    if encoded_size > _MAX_TRADE_OFFER_DISCOVERY_EVIDENCE_BYTES:
        return False, "federated discovery evidence set exceeds the audit budget"
    if not isinstance(selected, dict) or selected not in discoveries:
        return False, "selected discovery evidence is absent from its evidence set"

    source_keys: set[tuple[str, str]] = set()
    for evidence in discoveries:
        ok, reason = _verify_trade_offer_discovery_evidence(
            evidence,
            offer,
            imported_at_ms=imported_at_ms,
        )
        if not ok:
            return False, reason
        source_key = (evidence["source_did"], evidence["source_peer"])
        if source_key in source_keys:
            return False, "federated discovery evidence set repeats a source"
        source_keys.add(source_key)
    if type(expected_count) is not int or expected_count != len(source_keys):
        return False, "federated discovery source count does not match its evidence"
    return True, "ok"


def _validate_trade_offer_spine_anchor_snapshot(
    events: list[Any],
    store: Any,
) -> None:
    """Validate one already signature-verified Spine snapshot."""

    proposals = {
        event.event_id: event
        for event in events
        if event.type == "trade.offer.import.proposed"
    }
    anchors: list[dict[str, Any]] = []
    for event in events:
        if event.type != "trade.offer.imported":
            continue
        payload = event.payload
        if not isinstance(payload, dict):
            raise HTTPException(
                status_code=503,
                detail="trade offer Spine anchor has an invalid payload",
            )
        source_kind = payload.get("source_kind")
        source_id = payload.get("source_id")
        local_operator = (
            source_kind == "local-operator"
            and source_id == event.author_did
        )
        federation_import = (
            source_kind == "federation-cache"
            and payload.get("completion_did") == event.author_did
        )
        if not (local_operator or federation_import):
            raise HTTPException(
                status_code=503,
                detail="trade offer Spine anchor has invalid source authority",
            )
        if local_operator and "discovery" in payload:
            raise HTTPException(
                status_code=503,
                detail="local trade offer Spine anchor contains remote evidence",
            )
        if federation_import:
            from nth_dao.market import VerifiedTradeOfferHeadProof
            from nth_dao.trade_rules import TradeOffer, offer_digest

            proposal = proposals.get(payload.get("proposal_event_id"))
            if proposal is None:
                raise HTTPException(
                    status_code=503,
                    detail="federated Trade Offer anchor has no signed proposal",
                )
            proposal_payload = proposal.payload
            if (
                not isinstance(proposal_payload, dict)
                or proposal_payload.get("source_kind") != source_kind
                or proposal_payload.get("source_id") != source_id
                or proposal_payload.get("discovery") != payload.get("discovery")
                or proposal.author_did != source_id
            ):
                raise HTTPException(
                    status_code=503,
                    detail="federated Trade Offer proposal does not match its anchor",
                )
            try:
                proposed_head = TradeOffer.from_dict(
                    proposal_payload.get("offer")
                )
            except (TypeError, ValueError) as exc:
                raise HTTPException(
                    status_code=503,
                    detail="federated Trade Offer proposal Offer is invalid",
                ) from exc
            proposal_head_digest = proposal_payload.get("offer_digest")
            if offer_digest(proposed_head) != proposal_head_digest:
                raise HTTPException(
                    status_code=503,
                    detail="federated Trade Offer proposal head digest mismatch",
                )
            proposed_by_digest = {proposal_head_digest: proposed_head}
            if "head_proof" in proposal_payload:
                try:
                    head_proof = VerifiedTradeOfferHeadProof.from_dict(
                        proposal_payload["head_proof"],
                        now_ms_override=proposal.ts_ms,
                    )
                except (TypeError, ValueError) as exc:
                    raise HTTPException(
                        status_code=503,
                        detail="federated Trade Offer proposal head proof is invalid",
                    ) from exc
                if head_proof.head.canonical_bytes != proposed_head.canonical_bytes:
                    raise HTTPException(
                        status_code=503,
                        detail="federated Trade Offer proposal head proof mismatch",
                    )
                proposed_by_digest = {
                    offer_digest(item): item for item in head_proof.offers
                }
                if payload.get("head_offer_digest") != proposal_head_digest:
                    raise HTTPException(
                        status_code=503,
                        detail="federated Trade Offer anchor head digest mismatch",
                    )
            elif proposal_head_digest != payload.get("offer_digest"):
                raise HTTPException(
                    status_code=503,
                    detail="legacy Trade Offer proposal does not match its anchor",
                )
            proposed_offer = proposed_by_digest.get(payload.get("offer_digest"))
            if proposed_offer is None:
                raise HTTPException(
                    status_code=503,
                    detail="federated Trade Offer anchor is outside its head proof",
                )
            try:
                record = store.get_record(payload.get("offer_digest"))
            except (TypeError, ValueError) as exc:
                raise HTTPException(
                    status_code=503,
                    detail="trade offer Spine anchor has an invalid digest",
                ) from exc
            if record is None:
                raise HTTPException(
                    status_code=503,
                    detail="trade offer Spine anchor references a missing Offer",
                )
            if proposed_offer.canonical_bytes != record.offer.canonical_bytes:
                raise HTTPException(
                    status_code=503,
                    detail=(
                        "federated Trade Offer proposal Offer does not match "
                        "the persisted Offer"
                    ),
                )
            ok, reason = _verify_trade_offer_discovery_evidence(
                proposal_payload.get("discovery"),
                proposed_head,
                imported_at_ms=proposal.ts_ms,
            )
            if not ok:
                raise HTTPException(
                    status_code=503,
                    detail=(
                        "federated Trade Offer proposal discovery evidence "
                        f"failure: {reason}"
                    ),
                )
            if "discoveries" in proposal_payload:
                ok, reason = _verify_trade_offer_discovery_evidence_set(
                    proposal_payload["discoveries"],
                    proposal_payload.get("discovery"),
                    proposed_head,
                    imported_at_ms=proposal.ts_ms,
                    expected_count=proposal_payload.get("discovery_sources"),
                )
                if not ok:
                    raise HTTPException(
                        status_code=503,
                        detail=(
                            "federated Trade Offer proposal discovery evidence "
                            f"set failure: {reason}"
                        ),
                    )
            ok, reason = _verify_trade_offer_discovery_evidence(
                payload.get("discovery"),
                proposed_head,
                imported_at_ms=event.ts_ms,
            )
            if not ok:
                raise HTTPException(
                    status_code=503,
                    detail=f"trade offer discovery evidence failure: {reason}",
                )
        anchors.append(payload)
    ok, why = store.verify_import_anchors(anchors)
    if not ok:
        raise HTTPException(
            status_code=503,
            detail=f"trade offer cross-log integrity failure: {why}",
        )


def _verify_trade_offer_spine_anchors(request: Request, store: Any) -> None:
    """Fail closed unless one stable Store/Spine snapshot cross-verifies."""

    with store.integrity_verification_lock:
        for _attempt in range(3):
            try:
                store_before = store.integrity_fingerprint()
                events = _verified_spine_events(request)
            except HTTPException:
                raise
            except (OSError, RuntimeError, TypeError, ValueError) as exc:
                raise HTTPException(
                    status_code=503,
                    detail=f"trade offer Spine could not be verified: {exc}",
                ) from exc
            if events is None:
                if store.latest_seq() >= 0:
                    raise HTTPException(
                        status_code=503,
                        detail="signed Spine unavailable for persisted Trade Offers",
                    )
                return
            spine = _state_spine(request)
            spine_fingerprint = getattr(
                spine, "_v2_verified_cache_fingerprint", None
            )
            spine_head = events[-1].content_hash if events else "genesis"
            cache_key = (store_before, spine_fingerprint, spine_head)
            if getattr(store, "_v2_spine_anchor_cache", None) == cache_key:
                return

            _validate_trade_offer_spine_anchor_snapshot(events, store)

            try:
                store_after = store.integrity_fingerprint()
                events_after = _verified_spine_events(request)
            except HTTPException:
                raise
            except (OSError, RuntimeError, TypeError, ValueError) as exc:
                raise HTTPException(
                    status_code=503,
                    detail=f"trade offer Spine could not be verified: {exc}",
                ) from exc
            spine_after = _state_spine(request)
            if events_after is None or spine_after is None:
                continue
            fingerprint_after = getattr(
                spine_after, "_v2_verified_cache_fingerprint", None
            )
            head_after = (
                events_after[-1].content_hash if events_after else "genesis"
            )
            if (
                store_before == store_after
                and spine_fingerprint == fingerprint_after
                and spine_head == head_after
            ):
                store._v2_spine_anchor_cache = cache_key
                return
        raise HTTPException(
            status_code=503,
            detail="trade offer Store or Spine changed during verification",
            headers={"Retry-After": "1"},
        )


def _find_trade_offer_spine_anchor(
    request: Request,
    result: Any,
) -> Optional[Any]:
    """Return the exact existing import event for an idempotent retry."""

    events = _verified_spine_events(request)
    if events is None:
        return None
    expected = {
        "seq": result.seq,
        "offer_digest": result.digest,
        "entry_hash": result.entry_hash,
        "publisher_did": result.chain.publisher_did,
        "offer_id": result.chain.offer_id,
        "source_kind": result.source_kind,
        "source_id": result.source_id,
    }
    for event in reversed(events):
        if (
            event.type == "trade.offer.imported"
            and isinstance(event.payload, dict)
            and all(event.payload.get(key) == value for key, value in expected.items())
        ):
            return event
    return None


def _verified_trade_offer_import_proposal(
    request: Request,
    digest: str,
) -> Optional[tuple[tuple[Any, ...], Dict[str, Any], int, Any, Any]]:
    """Recover one signed, incomplete federated Offer import intent."""

    from nth_dao.market import VerifiedTradeOfferHeadProof
    from nth_dao.trade_rules import TradeOffer, offer_digest

    events = _verified_spine_events(request)
    if events is None:
        return None
    matches = [
        event
        for event in events
        if event.type == "trade.offer.import.proposed"
        and isinstance(event.payload, dict)
        and event.payload.get("offer_digest") == digest
    ]
    if len(matches) > 1:
        raise HTTPException(
            status_code=503,
            detail="Spine contains duplicate Trade Offer import proposals",
        )
    if not matches:
        return None
    event = matches[0]
    payload = event.payload
    legacy_required = {
        "offer_digest",
        "offer",
        "source_kind",
        "source_id",
        "discovery",
        "discovery_sources",
    }
    proof_required = legacy_required | {"head_proof"}
    auditable_required = proof_required | {"discoveries"}
    if frozenset(payload) not in {
        frozenset(legacy_required),
        frozenset(proof_required),
        frozenset(auditable_required),
    }:
        raise HTTPException(
            status_code=503,
            detail="Trade Offer import proposal has an invalid payload",
        )
    if (
        payload["source_kind"] != "federation-cache"
        or payload["source_id"] != event.author_did
        or type(payload["discovery_sources"]) is not int
        or not 1 <= payload["discovery_sources"] <= 100_000
    ):
        raise HTTPException(
            status_code=503,
            detail="Trade Offer import proposal has invalid provenance",
        )
    try:
        head_offer = TradeOffer.from_dict(payload["offer"])
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=503,
            detail="Trade Offer import proposal contains an invalid Offer",
        ) from exc
    if offer_digest(head_offer) != digest:
        raise HTTPException(
            status_code=503,
            detail="Trade Offer import proposal digest does not match its Offer",
        )
    ok, reason = _verify_trade_offer_discovery_evidence(
        payload["discovery"],
        head_offer,
        imported_at_ms=event.ts_ms,
    )
    if not ok:
        raise HTTPException(
            status_code=503,
            detail=f"Trade Offer import proposal evidence failure: {reason}",
        )
    if "discoveries" in payload:
        ok, reason = _verify_trade_offer_discovery_evidence_set(
            payload["discoveries"],
            payload["discovery"],
            head_offer,
            imported_at_ms=event.ts_ms,
            expected_count=payload["discovery_sources"],
        )
        if not ok:
            raise HTTPException(
                status_code=503,
                detail=(
                    "Trade Offer import proposal discovery evidence set "
                    f"failure: {reason}"
                ),
            )
    head_proof = None
    offers = (head_offer,)
    if "head_proof" in payload:
        try:
            head_proof = VerifiedTradeOfferHeadProof.from_dict(
                payload["head_proof"],
                now_ms_override=event.ts_ms,
            )
        except (TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail="Trade Offer import proposal head proof is invalid",
            ) from exc
        if head_proof.head.canonical_bytes != head_offer.canonical_bytes:
            raise HTTPException(
                status_code=503,
                detail="Trade Offer import proposal head proof does not match Offer",
            )
        discovery_announcement = payload["discovery"].get("announcement")
        if head_proof.announcement.to_dict() != discovery_announcement:
            raise HTTPException(
                status_code=503,
                detail="Trade Offer import proposal head claim does not match evidence",
            )
        offers = head_proof.offers
    return (
        offers,
        payload["discovery"],
        payload["discovery_sources"],
        event,
        head_proof,
    )


_MARKET_LISTING_TYPE_FIELD = "__nth_listing_type"
_MARKET_LISTING_TYPES = {"task", "service", "product", "exchange"}
_MARKET_SEARCH_CATEGORIES = {
    "tasks",
    "products",
    "services",
    "digital-assets",
    "exchanges",
    "other",
}
_MARKET_SEARCH_INTENTS = {"request", "provide", "exchange"}
_MARKET_OFFER_CATEGORIES = {"products", "services", "digital-assets", "other"}
_MARKET_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9._:-]{16,128}$")
_TRADE_DISPUTE_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9._:-]{16,128}$")


class TradeDisputeStatementCreateConflict(ValueError):
    """An idempotency key is already bound to another Statement request."""


def _trade_dispute_idempotency_key(request: Request) -> str:
    value = request.headers.get("Idempotency-Key", "").strip()
    if _TRADE_DISPUTE_IDEMPOTENCY_KEY.fullmatch(value) is None:
        raise HTTPException(
            status_code=400,
            detail=(
                "Idempotency-Key must contain 16..128 ASCII letters, digits, "
                "'.', ':', '_' or '-'"
            ),
        )
    return value


def _reserve_trade_dispute_statement_creation(
    request: Request,
    *,
    body: Dict[str, Any],
    order_digest: str,
    execution_id: str,
    review_id: str,
    author_did: str,
) -> tuple[str, str, datetime, str, bool]:
    """Durably bind one retry key before creating signed Statement bytes.

    The reservation is a local, signed Spine event. Its timestamp becomes the
    logical Statement creation time, so an HTTP retry after a partial Store /
    Spine failure recreates exactly the same content-addressed Statement.
    """

    from nth_dao.trade_rules import (
        EVENT_TRADE_DISPUTE_STATEMENT_CREATE_RESERVED,
        trade_dispute_statement_create_reservation_payload,
    )

    idempotency_key = _trade_dispute_idempotency_key(request)
    spine = _state_spine(request)
    if spine is None:
        raise HTTPException(
            status_code=503,
            detail="signed Spine unavailable for idempotent Statement creation",
        )
    payload = trade_dispute_statement_create_reservation_payload(
        idempotency_key=idempotency_key,
        body=body,
        order_digest=order_digest,
        execution_id=execution_id,
        review_id=review_id,
        author_did=author_did,
    )
    operation_id = payload["operation_id"]
    request_digest = payload["request_digest"]
    reserved_at_ms = int(datetime.now(timezone.utc).timestamp() * 1_000)
    if reserved_at_ms % 1_000 == 0:
        reserved_at_ms += 1
    try:
        event, created = spine.append_unique(
            EVENT_TRADE_DISPUTE_STATEMENT_CREATE_RESERVED,
            payload,
            unique_payload_fields=("operation_id",),
            ts_ms=reserved_at_ms,
        )
    except ValueError as exc:
        try:
            matches = [
                event
                for event in spine.verified_snapshot()
                if event.type == EVENT_TRADE_DISPUTE_STATEMENT_CREATE_RESERVED
                and event.payload.get("operation_id") == operation_id
            ]
        except (OSError, RuntimeError, TypeError, ValueError):
            raise RuntimeError(
                "unable to verify Dispute Statement creation reservation"
            ) from exc
        if len(matches) == 1 and matches[0].payload != payload:
            raise TradeDisputeStatementCreateConflict(
                "Idempotency-Key is already bound to another Statement request"
            ) from exc
        raise RuntimeError(
            "Dispute Statement creation reservation is invalid"
        ) from exc
    if event.author_did != spine.signer_did or event.payload != payload:
        raise RuntimeError(
            "Dispute Statement creation reservation is unauthorized or conflicting"
        )
    created_moment = datetime.fromtimestamp(
        event.ts_ms / 1_000,
        tz=timezone.utc,
    )
    created_at = created_moment.isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )
    return operation_id, request_digest, created_moment, created_at, created


def _record_trade_dispute_statement_creation_failure(
    request: Request,
    *,
    operation_id: str,
    request_digest: str,
    reason_code: str,
) -> tuple[Any, bool]:
    """Append one signed, idempotent failure class for a reserved operation."""

    from nth_dao.trade_rules import (
        EVENT_TRADE_DISPUTE_STATEMENT_CREATE_ATTEMPT_FAILED,
        trade_dispute_statement_create_failure_payload,
    )

    spine = _state_spine(request)
    if spine is None:
        raise RuntimeError("signed Spine unavailable for Statement failure audit")
    payload = trade_dispute_statement_create_failure_payload(
        operation_id=operation_id,
        request_digest=request_digest,
        reason_code=reason_code,
    )
    event, created = spine.append_unique(
        EVENT_TRADE_DISPUTE_STATEMENT_CREATE_ATTEMPT_FAILED,
        payload,
        unique_payload_fields=("failure_id",),
    )
    if event.author_did != spine.signer_did or event.payload != payload:
        raise RuntimeError(
            "Dispute Statement creation failure audit is unauthorized or conflicting"
        )
    return event, created


class MarketPublishConflict(ValueError):
    """An idempotency key is already bound to different signed content."""


class MarketPublishDiscoveryError(RuntimeError):
    """The Offer is durable, but its short-lived discovery hint is not."""

    def __init__(self, digest: str, reason: str) -> None:
        super().__init__(reason)
        self.digest = digest


class MarketPublishAuditError(RuntimeError):
    """The Offer is durable, but its required signed audit anchor is not."""

    def __init__(self, digest: str, reason: str) -> None:
        super().__init__(reason)
        self.digest = digest


class MarketPublishExpired(RuntimeError):
    """An idempotent retry refers to an Offer that can no longer be announced."""

    def __init__(self, digest: str, offer_id: str) -> None:
        super().__init__(
            "the signed Trade Offer has expired; publish a new Offer with a new "
            "idempotency_key"
        )
        self.digest = digest
        self.offer_id = offer_id


def _trade_offer_expiry_ms(offer: Any) -> int:
    document = offer.to_dict() if hasattr(offer, "to_dict") else dict(offer)
    value = document.get("not_after")
    if not isinstance(value, str) or not value:
        raise ValueError("Trade Offer not_after is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Trade Offer not_after is not ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ValueError("Trade Offer not_after must include a timezone")
    return int(parsed.timestamp() * 1_000)


def _normalize_market_listing_type(value: Any) -> str:
    listing_type = str(value or "task").strip().lower()
    if not listing_type:
        return "task"
    if listing_type not in _MARKET_LISTING_TYPES:
        raise ValueError(
            "listing_type must be task, service, product, or exchange"
        )
    return listing_type


def _market_announcement_listing_type(ann: Any) -> str:
    from nth_dao.market.announcement import announcement_listing_type

    try:
        return _normalize_market_listing_type(announcement_listing_type(ann))
    except ValueError:
        return "task"


def _market_announcement_to_wire(ann: Any) -> Dict[str, Any]:
    from nth_dao.market.announcement import announcement_federation_key

    data = ann.to_dict()
    data["listing_type"] = _market_announcement_listing_type(ann)
    data["claimable"] = data["listing_type"] != "exchange"
    data["federation_key"] = announcement_federation_key(ann)
    return data


def _market_search_entry(row: Dict[str, Any]) -> Dict[str, Any]:
    """Project one verified discovery announcement for human search.

    The returned object is deliberately not a protocol fact. Its source
    identifiers force every action to resolve the signed announcement or
    content-addressed Offer again.
    """
    from nth_dao.market import (
        NTH_ANNOUNCEMENT_KIND_V3,
        NTH_TRADE_OFFER_ANNOUNCEMENT_KIND_V1,
    )

    listing_type = _normalize_market_listing_type(row.get("listing_type"))
    signed_kind = str(row.get("kind") or "")
    is_trade_offer = signed_kind == NTH_TRADE_OFFER_ANNOUNCEMENT_KIND_V1
    is_commerce_listing = signed_kind == NTH_ANNOUNCEMENT_KIND_V3
    is_offer = is_trade_offer or is_commerce_listing
    legacy = not is_offer and listing_type != "task"

    category = {
        "task": "tasks",
        "product": "products",
        "service": "services",
        "exchange": "exchanges",
    }.get(listing_type, "other")
    if is_trade_offer:
        protocol_kind = "trade-offer-announcement"
        availability = row.get("availability_summary")
        if not isinstance(availability, dict):
            availability = {}
        hinted_category = str(availability.get("market_category") or "")
        hinted_intent = str(availability.get("market_intent") or "")
        if hinted_category in _MARKET_OFFER_CATEGORIES:
            category = hinted_category
        market_intent = (
            hinted_intent
            if hinted_intent in {"provide", "exchange"}
            else "exchange"
        )
    elif is_commerce_listing:
        protocol_kind = "commerce-listing-announcement"
        market_intent = "provide"
    else:
        protocol_kind = "task-announcement"
        market_intent = "request"

    value_kind = "none"
    amount_minor = 0
    asset = ""
    if is_commerce_listing:
        value_kind = "price"
        amount_minor = int(row.get("price_minor") or 0)
        asset = str(row.get("price_asset") or "")
    elif not is_trade_offer:
        value_kind = "reward"
        amount_minor = int(row.get("reward_minor") or 0)
        asset = str(row.get("reward_asset") or "")

    if legacy:
        warning = (
            "Legacy claimable TaskAnnouncement with a market category label; "
            "it is not a signed Trade Offer."
        )
    elif is_offer:
        warning = (
            "Signed discovery claim only; inspect and verify the exact source "
            "object before negotiation or execution."
        )
    else:
        warning = (
            "Signed task request; resolve the claim authority and current task "
            "state before claiming."
        )

    return {
        "entry_id": str(row.get("federation_key") or ""),
        "entry_kind": "offer" if is_offer else "task",
        "protocol_kind": protocol_kind,
        "market_intent": market_intent,
        "category": category,
        "title": str(row.get("title") or ""),
        "summary": str(row.get("description") or ""),
        "publisher_did": str(row.get("publisher_did") or ""),
        "published_at_ms": int(row.get("published_at_ms") or 0),
        "not_after_ms": int(row.get("not_after") or 0),
        "context": str(row.get("context") or ""),
        "capability_set": list(row.get("capability_set") or []),
        "claimable": bool(row.get("claimable", True)) and not is_offer,
        "legacy": legacy,
        "source": "federated" if row.get("federated") else "local",
        "source_peer": str(row.get("source_peer") or ""),
        "stale": bool(row.get("federation_stale", False)),
        "last_verified_at_ms": int(
            row.get("federation_verified_at_ms") or 0
        ),
        "value": {
            "kind": value_kind,
            "amount_minor": amount_minor,
            "asset": asset,
        },
        "target": {
            "announcement_id": str(row.get("announcement_id") or ""),
            "federation_key": str(row.get("federation_key") or ""),
            "offer_digest": str(row.get("offer_digest") or ""),
            "offer_uri": str(row.get("offer_uri") or ""),
        },
        "projection_only": True,
        "warning": warning,
    }


def _market_resource_descriptor(
    leg: Any,
) -> tuple[Dict[str, Any], Dict[str, Any]]:
    """Build one content-addressed inline descriptor and TradeOffer leg."""
    from nth_dao.market.resource_descriptor import (
        inline_resource_descriptor_digest,
    )

    value = leg.model_dump() if hasattr(leg, "model_dump") else dict(leg)
    category = str(value.get("category") or "").strip().lower()
    if category not in _MARKET_OFFER_CATEGORIES:
        raise ValueError(
            "resource category must be products, services, digital-assets, or other"
        )
    profile_rule_id = str(value.get("profile_rule_id") or "").strip()
    profile_digest = str(value.get("profile_digest") or "").strip()
    if bool(profile_rule_id) != bool(profile_digest):
        raise ValueError(
            "profile_rule_id and profile_digest must be supplied together"
        )
    attributes = value.get("attributes")

    descriptor = {
        "kind": "org.nthdao.resource-profile.inline",
        "version": "1",
        "category": category,
        "resource_type": str(value.get("resource_type") or "").strip(),
        "resource_id": str(value.get("resource_id") or "").strip(),
        "profile_ref": (
            {"rule_id": profile_rule_id, "digest": profile_digest}
            if profile_rule_id
            else {}
        ),
        "attributes": attributes,
    }
    descriptor_digest = inline_resource_descriptor_digest(descriptor)
    offer_leg = {
        "leg_id": str(value.get("leg_id") or "").strip(),
        "resource_type": descriptor["resource_type"],
        "resource_id": descriptor["resource_id"],
        "quantity": str(value.get("quantity") or "").strip(),
        "unit": str(value.get("unit") or "").strip(),
        "descriptor_digest": descriptor_digest,
    }
    return offer_leg, descriptor


def _market_offer_descriptor_inspection(
    offer: Any,
    *,
    workspace: Optional[Path] = None,
) -> Dict[str, Any]:
    """Inspect inline descriptors and any locally cached Profile Skills."""
    from nth_dao.market.resource_descriptor import (
        inspect_offer_resource_descriptors,
    )

    if workspace is None:
        return inspect_offer_resource_descriptors(offer)
    from nth_dao.market.resource_profile import (
        ResourceProfilePolicy,
        ResourceProfileStore,
    )

    store = ResourceProfileStore(workspace)
    policy = ResourceProfilePolicy(workspace)
    return inspect_offer_resource_descriptors(
        offer,
        profile_resolver=store.load,
        accepted_profile_digests=policy.accepted_digests(),
    )


def _market_resource_profile_to_wire(
    profile: Any,
    *,
    recognized: bool,
) -> Dict[str, Any]:
    from nth_dao.market.resource_profile import evaluate_resource_profile

    document = profile.to_dict()
    active, active_reason = evaluate_resource_profile(profile)
    return {
        "digest": profile.digest,
        "profile_id": document["profile_id"],
        "version": document["version"],
        "publisher_did": document["publisher_did"],
        "summary": document["summary"],
        "resource_types": list(document["resource_types"]),
        "category_mappings": list(document["category_mappings"]),
        "schema": dict(document["schema"]),
        "published_at": document["published_at"],
        "not_after": document["not_after"],
        "active": active,
        "active_reason": active_reason,
        "recognized": bool(recognized),
        "signature_verified": True,
        "execution_authority_granted": False,
    }


def _validate_local_market_profile_references(
    extensions: Dict[str, Any],
    *,
    workspace: Path,
) -> None:
    """Validate cached Profile semantics before the node signs an Offer."""

    from nth_dao.market.resource_descriptor import RESOURCE_DESCRIPTOR_EXTENSION
    from nth_dao.market.resource_profile import (
        ResourceProfileStore,
        evaluate_resource_profile,
        validate_profile_attributes,
    )

    extension = extensions.get(RESOURCE_DESCRIPTOR_EXTENSION)
    descriptors = extension.get("descriptors") if isinstance(extension, dict) else None
    if not isinstance(descriptors, dict):
        return
    store = ResourceProfileStore(workspace)
    for descriptor in descriptors.values():
        if not isinstance(descriptor, dict):
            continue
        profile_ref = descriptor.get("profile_ref")
        if not isinstance(profile_ref, dict) or not profile_ref:
            continue
        digest = profile_ref.get("digest")
        profile = store.load(digest)
        if profile is None:
            continue
        if profile.profile_id != profile_ref.get("rule_id"):
            raise ValueError("cached Resource Profile ID does not match profile_ref")
        document = profile.to_dict()
        if descriptor.get("resource_type") not in document["resource_types"]:
            raise ValueError("resource_type is not allowed by the cached Resource Profile")
        active, reason = evaluate_resource_profile(profile)
        if not active:
            raise ValueError(f"cached Resource Profile is {reason}")
        attributes = descriptor.get("attributes")
        if not isinstance(attributes, dict):
            raise ValueError("Resource Profile attributes must be an object")
        validate_profile_attributes(
            profile,
            {
                key: value for key, value in attributes.items()
                if key != "community_category"
            },
        )


def _market_offer_material(
    body: Any,
    *,
    publisher_did: str,
) -> tuple[
    str,
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    Dict[str, Any],
    List[str],
]:
    """Normalize human input into deterministic signed-offer material."""
    from nth_dao.market.publication_policy import reject_private_publication_data

    intent = str(body.intent or "").strip().lower()
    category = str(body.category or "").strip().lower()
    if intent not in {"provide", "exchange"}:
        raise ValueError("intent must be provide or exchange")
    if category not in _MARKET_OFFER_CATEGORIES:
        raise ValueError(
            "category must be products, services, digital-assets, or other"
        )
    if intent == "provide" and body.requests:
        raise ValueError("provide intent must not contain requested resource legs")
    if intent == "exchange" and not body.requests:
        raise ValueError("exchange intent requires at least one requested resource leg")
    key = str(body.idempotency_key or "")
    if _MARKET_IDEMPOTENCY_KEY.fullmatch(key) is None:
        raise ValueError(
            "idempotency_key must contain 16..128 ASCII letters, digits, '.', ':', '_' or '-'"
        )
    title = str(body.title or "").strip()
    if not title:
        raise ValueError("title must contain non-whitespace text")
    capabilities = sorted(
        {str(value).strip() for value in body.capability_set}
    )
    if any(not value for value in capabilities):
        raise ValueError("capability_set must not contain empty values")
    if any(len(value) > 100 for value in capabilities):
        raise ValueError("capability names must not exceed 100 characters")
    reject_private_publication_data(
        {
            "title": title,
            "summary": str(body.summary or "").strip(),
            "capability_set": capabilities,
            "provides": [item.model_dump() for item in body.provides],
            "requests": [item.model_dump() for item in body.requests],
        },
        label="market_offer",
    )

    descriptors: Dict[str, Any] = {}
    provides: List[Dict[str, Any]] = []
    requests: List[Dict[str, Any]] = []
    for source, target in ((body.provides, provides), (body.requests, requests)):
        for leg in source:
            normalized, descriptor = _market_resource_descriptor(leg)
            digest = normalized["descriptor_digest"]
            existing = descriptors.get(digest)
            if existing is not None and existing != descriptor:
                raise ValueError("resource descriptor digest collision")
            descriptors[digest] = descriptor
            target.append(normalized)

    rule_refs = [item.model_dump() for item in body.rule_refs]
    key_digest = hashlib.sha256(
        f"{publisher_did}\0{key}".encode("utf-8")
    ).hexdigest()
    offer_id = f"org.nthdao.market/offer-{key_digest}"
    extensions = {
        _MARKET_RESOURCE_PROFILE_EXTENSION: {
            "descriptors": descriptors,
        },
        _MARKET_PUBLICATION_EXTENSION: {
            "category": category,
            "intent": intent,
            "capability_set": capabilities,
            "offer_validity_seconds": body.offer_validity_seconds,
        },
    }
    return offer_id, provides, requests, rule_refs, extensions, capabilities


def _same_market_offer_material(
    document: Dict[str, Any],
    *,
    title: str,
    summary: str,
    provides: List[Dict[str, Any]],
    requests: List[Dict[str, Any]],
    rule_refs: List[Dict[str, Any]],
    extensions: Dict[str, Any],
) -> bool:
    expected = {
        "title": title,
        "summary": summary,
        "provides": provides,
        "requests": requests,
        "rule_refs": sorted(
            rule_refs,
            key=lambda item: (item["rule_id"], item["digest"]),
        ),
        "extensions": extensions,
    }
    return all(document.get(field) == value for field, value in expected.items())


def _persist_local_trade_offer_locked(
    request: Request,
    store: Any,
    offer: Any,
    *,
    source_id: str,
) -> tuple[Any, str, str]:
    """Persist and Spine-anchor one local Offer while the caller holds the lock."""
    result = store.publish(
        offer.to_dict(),
        source_kind="local-operator",
        source_id=source_id,
    )
    spine = _state_spine(request)
    if spine is None:
        raise RuntimeError("signed Spine unavailable")
    audit_event_id = ""
    audit_warning = ""
    try:
        existing_anchor = (
            None
            if result.appended
            else _find_trade_offer_spine_anchor(request, result)
        )
        if existing_anchor is not None:
            audit_event_id = existing_anchor.event_id
        elif result.source_kind == "local-operator" and result.source_id == source_id:
            event = spine.append(
                "trade.offer.imported",
                {
                    "seq": result.seq,
                    "offer_digest": result.digest,
                    "entry_hash": result.entry_hash,
                    "publisher_did": offer.publisher_did,
                    "offer_id": offer.offer_id,
                    "source_kind": result.source_kind,
                    "source_id": result.source_id,
                },
            )
            audit_event_id = event.event_id
        else:
            audit_warning = "existing offer provenance is not local-operator"
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        logger.warning("trade offer spine audit failed: %s", exc)
        audit_warning = "signed spine append failed"
    return result, audit_event_id, audit_warning


def _ensure_local_trade_offer_announcement(
    request: Request,
    store: Any,
    offer: Any,
    digest: str,
    *,
    capability_set: List[str],
    availability_summary: Dict[str, Any],
    discovery_ttl_seconds: int,
    match_capability_set: bool,
    match_availability_summary: bool,
) -> tuple[Any, bool]:
    """Idempotently publish a short-lived discovery hint for one local Offer."""
    from nth_dao.market import (
        NTH_TRADE_OFFER_ANNOUNCEMENT_KIND_V1,
        create_trade_offer_announcement,
    )

    workspace = _state_workspace(request)
    identity = _state_node_identity(request)
    if workspace is None:
        raise RuntimeError("workspace unavailable")
    if identity is None or not getattr(identity, "can_sign", False):
        raise RuntimeError("signing identity unavailable")
    if offer.publisher_did != identity.as_did():
        raise PermissionError("only this node's own Trade Offer can be announced")
    offer_expiry_ms = _trade_offer_expiry_ms(offer)
    announced_ms = int(datetime.now(timezone.utc).timestamp() * 1_000)
    if offer_expiry_ms <= announced_ms:
        raise MarketPublishExpired(digest, offer.offer_id)
    _verify_trade_offer_spine_anchors(request, store)
    lock_path = workspace / "market_feed" / ".locks" / f"trade-{digest[7:]}"
    with InterProcessLock(lock_path):
        feed = _state_market_feed(request)
        existing = next(
            (
                announcement
                for announcement in feed.poll(
                    since_seq=-1,
                    include_expired=True,
                ).announcements
                if (
                    announcement.kind == NTH_TRADE_OFFER_ANNOUNCEMENT_KIND_V1
                    and announcement.offer_digest == digest
                    and announcement.publisher_did == identity.as_did()
                    and not announcement.is_expired()
                )
            ),
            None,
        )
        if existing is not None:
            expected_capabilities = sorted(set(capability_set))
            existing_availability = dict(existing.availability_summary)
            for field in ("offer_id", "revision", "state"):
                existing_availability.pop(field, None)
            if (
                match_capability_set
                and existing.capability_set != expected_capabilities
            ) or (
                match_availability_summary
                and existing_availability != availability_summary
            ):
                raise MarketPublishConflict(
                    "the active discovery announcement is already bound to "
                    "different capability or availability metadata"
                )
            return existing, False
        announcement = create_trade_offer_announcement(
            identity,
            offer,
            capability_set=capability_set,
            availability_summary=availability_summary,
            published_at_ms=announced_ms,
            not_after_ms=min(
                offer_expiry_ms,
                announced_ms + discovery_ttl_seconds * 1_000,
            ),
        )
        feed.publish(announcement)
    return announcement, True


def _market_local_open(request: Request, passes) -> List[Dict[str, Any]]:
    """本地开放公告列表(Phase 2d:**可切事实源**)。

    默认从 feed+ClaimStore(现状,零风险);``NTH_MARKET_READ_SOURCE=spine`` 时改从
    **spine 投影**读(须先 backfill + ``/market/reconcile`` 显示 in_sync 再切)。spine
    缺失 / 链损坏 → **fail-safe 回退 feed**,绝不中断市场。两路口径一致(未过期 ∩
    未认领)、同 ``passes`` 过滤、同上限 500、新→老。
    """
    ws = _state_workspace(request)
    if ws is None:
        return []
    source = os.environ.get("NTH_MARKET_READ_SOURCE", "feed").strip().lower()

    if source == "spine":
        spine = _state_spine(request)
        if spine is not None:
            ok, _why = spine.verify_chain()
            if ok:
                from nth_dao.market.projection import MarketAnnounceProjection
                from nth_dao.market.claim import ClaimStore
                from nth_dao.spine import replay
                proj = MarketAnnounceProjection()
                replay(spine.read_all(), proj)
                claims = ClaimStore(ws)
                spine_local: List[Dict[str, Any]] = []
                for ann in proj.open():
                    if claims.is_unavailable(ann.announcement_id):
                        continue
                    if not passes(ann):
                        continue
                    d = _market_announcement_to_wire(ann)
                    d["claimed"] = False
                    spine_local.append(d)
                spine_local.sort(key=lambda d: -(d.get("published_at_ms") or 0))
                return spine_local[:500]
            logger.warning(
                "market read=spine but chain invalid; falling back to feed")
        # spine 不可用 → 落回 feed(下方)

    if not (ws / "market_feed" / "announcements.jsonl").exists():
        return []
    from nth_dao.market.claim import ClaimStore
    from nth_dao.market.feed import MarketFeed
    try:
        feed = MarketFeed(ws)
        claims = ClaimStore(ws)
    except OSError as e:  # noqa: BLE001
        logger.debug("v2_market_open: market store unavailable: %s", e)
        return []
    local: List[Dict[str, Any]] = []
    for ann in feed.poll(since_seq=-1, limit=500).announcements:
        if claims.is_unavailable(ann.announcement_id):
            continue
        if not passes(ann):
            continue
        d = _market_announcement_to_wire(ann)
        d["claimed"] = False
        local.append(d)
    local.reverse()   # 新→老
    return local


def _state_receipts_store(request: Request) -> Optional[Any]:
    """ReceiptStore from app.state.nth.receipts. Returns None if
    state isn't wired. """
    try:
        return request.app.state.nth.receipts
    except AttributeError:
        return None


def _has_console_bearer(request: Request) -> bool:
    """Return whether the request carries the current console Bearer token."""

    expected = str(getattr(request.app.state, "nth_console_token", "") or "")
    supplied = request.headers.get("Authorization", "")
    prefix = "Bearer "
    if not expected or not supplied.startswith(prefix):
        return False
    return hmac.compare_digest(supplied[len(prefix):].strip(), expected)


def _require_console_bearer_for_sensitive_read(request: Request) -> None:
    """Gate sensitive GET payloads that include raw private-console data.

    Most ``/api/v2`` GET routes are intentionally anonymous summaries so the
    local dashboard can boot without a login ceremony. Raw receipts are not a
    summary: they may embed authorizing cap_token material. Require the local
    console Bearer token here even when the global middleware bypasses GETs.
    """
    if not _has_console_bearer(request):
        raise HTTPException(status_code=401, detail="missing or invalid console token")


def _require_console_bearer_for_governance_mutation(request: Request) -> None:
    """Restrict local trust-policy mutations to the authenticated console.

    A cryptographically valid CapToken identifies its issuer, but it does not
    by itself grant authority over this node's Recognition trust policy. Until
    a dedicated, node-issued governance capability is defined, fail closed and
    accept only the per-process console Bearer token.
    """
    if not _has_console_bearer(request):
        raise HTTPException(status_code=401, detail="missing or invalid console token")


def _require_federation_operator(request: Request) -> None:
    """Authorize host-network and seed-registry mutations.

    A valid CapToken authenticates a delegated Agent, but no delegated
    capability currently grants control over this node's federation network
    targets.  Keep that authority with the console principal.  Development
    apps which explicitly disable console authentication remain usable only
    from the loopback interface (or Starlette's in-process test client).
    """

    if bool(getattr(request.app.state, "nth_require_console_auth", False)):
        if not _has_console_bearer(request):
            raise HTTPException(
                status_code=403,
                detail="federation administration requires the console principal",
            )
        return

    client_host = (
        str(request.client.host).strip()
        if request.client is not None and request.client.host
        else ""
    )
    if client_host == "testclient":
        return
    try:
        loopback = ipaddress.ip_address(client_host).is_loopback
    except ValueError:
        loopback = False
    if not loopback:
        raise HTTPException(
            status_code=403,
            detail="federation administration requires a loopback client",
        )


def _enforce_recognition_policy_mutation_limit(
    request: Request,
    *,
    operation: str,
) -> None:
    state = getattr(request.app.state, "nth", None)
    limiter = getattr(
        state,
        "trade_rule_recognition_policy_limiter",
        None,
    )
    if limiter is None:
        logger.error("Recognition policy limiter is unavailable")
        raise HTTPException(
            status_code=503,
            detail="Recognition policy governance is unavailable",
        )
    try:
        decision = limiter.check(operation)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        logger.warning(
            "Recognition policy limiter failed during %s: %s: %s",
            operation,
            type(exc).__name__,
            exc,
        )
        raise HTTPException(
            status_code=503,
            detail="Recognition policy governance is unavailable",
        ) from exc
    if not decision.allowed:
        raise HTTPException(
            status_code=429,
            detail="Recognition policy mutation rate limit exceeded",
            headers={
                "Retry-After": str(
                    max(1, int(decision.retry_after_seconds) + 1)
                )
            },
        )


def _recognition_policy_service_error(
    *,
    operation: str,
    code: str,
    message: str,
    exc: Exception,
    status_code: int = 503,
    retry_after: str | None = None,
) -> HTTPException:
    logger.warning(
        "Recognition policy %s failed [%s]: %s: %s",
        operation,
        code,
        type(exc).__name__,
        exc,
    )
    headers = {"Retry-After": retry_after} if retry_after else None
    return HTTPException(
        status_code=status_code,
        detail={"code": code, "message": message},
        headers=headers,
    )



def _state_event_bus(request: Request) -> Optional[Any]:
    """Return the workspace EventBus singleton used by v2 Mission evidence."""
    try:
        nth = request.app.state.nth
    except AttributeError:
        return None
    bus = getattr(nth, "event_bus", None)
    if bus is not None:
        return bus
    workspace = _state_workspace(request)
    if workspace is None:
        return None
    identity = _state_node_identity(request)
    if identity is not None and not getattr(identity, "can_sign", False):
        identity = None
    try:
        from nth_dao.event_bus import EventBus

        bus = EventBus(workspace, identity=identity)
        nth.event_bus = bus
        return bus
    except (OSError, RuntimeError, ValueError) as exc:
        logger.warning("mission evidence EventBus unavailable: %s", exc)
        return None



def _json_safe(value: Any) -> Any:
    """Constrain evidence payloads to canonical-JSON-friendly primitives."""
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, list):
        return [_json_safe(v) for v in value[:64]]
    if isinstance(value, tuple):
        return [_json_safe(v) for v in list(value)[:64]]
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in list(value.items())[:128]}
    return str(value)



def _mission_event_label(event_type: str) -> str:
    return {
        MISSION_CREATED: "Mission created (audited)",
        MISSION_ACTIVATED: "Mission activated",
        MISSION_STEP_BOOTSTRAPPED: "Step bootstrapped from mission goal",
        MISSION_STEP_ANNOUNCED: "Step announced to Tasks",
        MISSION_STEP_CLAIMED: "Step claimed by agent",
        MISSION_STEP_COMPLETED: "Step completed by agent",
        MISSION_STEP_NEEDS_REVIEW: "Step needs review",
        MISSION_STEP_BLOCKED: "Step blocked",
        MISSION_MARKET_CLAIM_VISIBLE: "Task claim linked to Mission",
    }.get(event_type, event_type)



def _mission_event_detail(event_type: str, payload: Dict[str, Any]) -> str:
    parts: List[str] = []
    step_id = str(payload.get("step_id", "") or "")
    announcement_id = str(payload.get("announcement_id", "") or "")
    source_announcement_id = str(payload.get("source_announcement_id", "") or "")
    if step_id:
        parts.append(f"step {step_id}")
    if announcement_id:
        parts.append(f"announcement {announcement_id}")
    elif source_announcement_id:
        parts.append(f"source announcement {source_announcement_id}")
    if event_type == MISSION_CREATED:
        title = str(payload.get("title", "") or payload.get("goal", "") or "")
        if title:
            parts.append(title[:120])
    if event_type == MISSION_STEP_ANNOUNCED:
        reward_minor = payload.get("reward_minor")
        reward_asset = str(payload.get("reward_asset", "") or "")
        if reward_minor is not None:
            parts.append(f"reward {reward_minor} {reward_asset}".strip())
    if event_type == MISSION_STEP_CLAIMED:
        claimant = str(payload.get("claimant_did", "") or "")
        if claimant:
            parts.append(f"claimant {claimant[:32]}...")
    if event_type in {
        MISSION_STEP_COMPLETED,
        MISSION_STEP_NEEDS_REVIEW,
        MISSION_STEP_BLOCKED,
    }:
        agent = str(payload.get("agent_did", "") or "")
        if agent:
            parts.append(f"agent {agent[:32]}...")
        response_preview = str(payload.get("response_preview", "") or "")
        if response_preview:
            parts.append(response_preview[:120])
    if payload.get("agent_claim_receipt_id"):
        parts.append(f"agent receipt {payload['agent_claim_receipt_id']}")
    if payload.get("agent_response_receipt_id"):
        parts.append(f"agent receipt {payload['agent_response_receipt_id']}")
    return "; ".join(parts)



def _mission_audit_event_to_view(event: Any) -> Optional[Dict[str, Any]]:
    payload = getattr(event, "payload", {}) or {}
    if not isinstance(payload, dict):
        return None
    event_type = str(getattr(event, "event_type", "") or "")
    status = (
        payload.get("status")
        or payload.get("step_status")
        or payload.get("visibility_status")
    )
    agent_did = (
        payload.get("agent_did")
        or payload.get("claimant_did")
        or payload.get("driver_did")
        or payload.get("owner_did")
    )
    return {
        "id": f"audit:{getattr(event, 'event_id', '')}",
        "kind": "audit",
        "label": _mission_event_label(event_type),
        "detail": _mission_event_detail(event_type, payload) or None,
        "at": str(getattr(event, "timestamp", "") or "") or None,
        "status": str(status) if status is not None else None,
        "agent_did": str(agent_did) if agent_did else None,
        "receipt_id": str(payload.get("receipt_id", "") or "") or None,
        "announcement_id": str(payload.get("announcement_id", "") or "") or None,
        "source_announcement_id": (
            str(payload.get("source_announcement_id", "") or "") or None
        ),
        "process_id": str(payload.get("process_id", "") or "") or None,
    }



def _mission_audit_events(
    request: Optional[Request], mission_id: str,
) -> List[Dict[str, Any]]:
    """Replay Mission-related EventBus facts for one mission.

    The per-request cache avoids scanning the append-only event log once for
    every row in GET /missions while keeping GET strictly read-only.
    """
    if request is None or not mission_id:
        return []
    req_state = getattr(request, "state", None)
    cache = getattr(req_state, "_v2_mission_audit_events", None) if req_state is not None else None
    if cache is None:
        cache = {}
        bus = _state_event_bus(request)
        if bus is not None:
            try:
                for event in bus.replay(event_types=list(MISSION_EVENT_TYPES)):
                    payload = getattr(event, "payload", {}) or {}
                    if not isinstance(payload, dict):
                        continue
                    mid = str(payload.get("mission_id", "") or "")
                    if not mid:
                        continue
                    view = _mission_audit_event_to_view(event)
                    if view is not None:
                        cache.setdefault(mid, []).append(view)
            except (OSError, RuntimeError, ValueError) as exc:
                logger.warning("mission evidence replay failed: %s", exc)
        if req_state is not None:
            setattr(req_state, "_v2_mission_audit_events", cache)
    return list(cache.get(mission_id, []))


def _ms_to_iso(value: Any) -> Optional[str]:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        return None
    try:
        return datetime.fromtimestamp(value / 1000, timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _mission_handoff_record_to_view(rec: Any) -> Dict[str, Any]:
    capsule = getattr(rec, "capsule", {}) or {}
    status = str(getattr(rec, "status", "") or "proposed")
    finding = str(capsule.get("finding", "") or "")
    hypothesis = str(capsule.get("root_cause_hypothesis", "") or "")
    evidence = capsule.get("evidence", []) if isinstance(capsule, dict) else []
    next_actions = capsule.get("next_actions", []) if isinstance(capsule, dict) else []
    refutations = list(getattr(rec, "refutations", []) or [])
    authorization_reasons = [
        str(item.get("authorization_reason", ""))
        for item in refutations
        if isinstance(item, dict) and item.get("authorized")
    ]
    detail_bits = []
    if hypothesis:
        detail_bits.append(f"hypothesis: {hypothesis}")
    if isinstance(evidence, list):
        detail_bits.append(f"claimed evidence: {len(evidence)} pointer(s)")
    if isinstance(next_actions, list) and next_actions:
        detail_bits.append(f"next: {next_actions[0]}")
    label = {
        "contested": "Handoff contested",
        "refuted": "Handoff refuted",
        "supersession_proposed": "Handoff supersession proposed",
        "superseded": "Handoff superseded",
    }.get(status, "Handoff proposed")
    if finding:
        label = f"{label}: {finding}"
    return {
        "id": f"handoff:{getattr(rec, 'capsule_hash', '')}",
        "kind": "handoff",
        "label": label,
        "detail": "; ".join(detail_bits) or None,
        "at": _ms_to_iso(capsule.get("issued_at_ms")),
        "status": status,
        "agent_did": str(getattr(rec, "author_did", "") or "") or None,
        "capsule_hash": str(getattr(rec, "capsule_hash", "") or ""),
        "refutation_count": len(refutations),
        "authorized_refutation_count": len(authorization_reasons),
        "authorization_reasons": authorization_reasons[:8],
        "evidence_count": len(evidence) if isinstance(evidence, list) else 0,
        "verification_status": str(capsule.get("verification_status", "") or ""),
        "next_action": str(next_actions[0]) if isinstance(next_actions, list) and next_actions else "",
        "superseded_by": str(getattr(rec, "superseded_by", "") or ""),
    }


def _handoff_mission_participant_dids(
    request: Request, mission_id: str,
) -> set[str]:
    """DIDs that are already part of the mission execution graph."""
    if not mission_id:
        return set()
    try:
        store = getattr(request.app.state.nth, "missions", None)
        mission = store.get(mission_id) if store is not None else None
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        return set()
    if mission is None:
        return set()

    out: set[str] = set()

    def add(value: Any) -> None:
        text = str(value or "").strip()
        if text.startswith("did:key:"):
            out.add(text)

    add(getattr(mission, "owner_did", ""))
    add(getattr(mission, "owner", ""))
    meta = getattr(mission, "metadata", None) or {}
    if isinstance(meta, dict):
        for key in ("driver_did", "claimant_did", "publisher_did"):
            add(meta.get(key))
    for step in list(getattr(mission, "steps", []) or []):
        add(getattr(step, "assignee", ""))
        for prior in list(getattr(step, "previous_assignees", []) or []):
            add(prior)
    return out


def _handoff_team_role_reason(request: Request, responder_did: str) -> str:
    """Return team role authority for a DID, or an empty string."""
    if not responder_did:
        return ""
    try:
        membership = getattr(request.app.state.nth, "membership", None)
        config = membership.load_config() if membership is not None else None
        role = config.role_for(responder_did) if config is not None else None
        role_value = getattr(role, "value", str(role or ""))
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        return ""
    if role_value in ("owner", "admin"):
        return f"team_role:{role_value}"
    return ""


def _handoff_governance_reason(events: list, responder_did: str) -> str:
    if not responder_did or not events:
        return ""
    try:
        from nth_dao.governance import (
            ACTION_HANDOFF_RESPOND,
            PolicyProjection,
            can,
        )

        gproj = PolicyProjection()
        for ev in events:
            gproj.apply(ev)
        if not gproj.established:
            return ""
        decision = can(gproj.policy, responder_did, ACTION_HANDOFF_RESPOND)
    except (ImportError, RuntimeError, TypeError, ValueError):
        return ""
    return "governance:handoff.respond" if decision.allowed else ""


def _handoff_trust_reason(request: Request, responder_did: str) -> str:
    if not responder_did:
        return ""
    try:
        from nth_dao.identity import AgentIdentity

        pubkey_hex = AgentIdentity.from_did(responder_did).pubkey_hex
    except (ImportError, RuntimeError, TypeError, ValueError):
        return ""
    try:
        trust = getattr(request.app.state.nth, "trust", None)
        if trust is None:
            return ""
        agent_ids = [responder_did]
        contacts = getattr(request.app.state.nth, "contacts", None)
        if contacts is not None:
            record = contacts.find_by_did(responder_did)
            agent_id = getattr(record, "agent_id", "") if record is not None else ""
            if agent_id and agent_id not in agent_ids:
                agent_ids.append(agent_id)
        for agent_id in agent_ids:
            if trust.is_trusted(agent_id, pubkey_hex, context="handoff"):
                return f"web_of_trust:{agent_id}"
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        return ""
    return ""


def _handoff_responder_authorizer(request: Request, events: list):
    """Build the real responder policy used by HandoffProjection.

    The response signature proves who spoke. This policy decides whether that
    speaker may move a capsule from contested into a terminal refuted or
    superseded state.
    """

    def authorize(rec: Any, stmt: Dict[str, Any]) -> Tuple[bool, str]:
        responder = str(stmt.get("author_did", "") or "")
        if responder in _handoff_mission_participant_dids(request, rec.mission_id):
            return True, "mission_participant"
        role_reason = _handoff_team_role_reason(request, responder)
        if role_reason:
            return True, role_reason
        gov_reason = _handoff_governance_reason(events, responder)
        if gov_reason:
            return True, gov_reason
        trust_reason = _handoff_trust_reason(request, responder)
        if trust_reason:
            return True, trust_reason
        return False, "no mission/team/governance/trust authority"

    return authorize


def _handoff_authz_cache_signature(request: Request) -> Tuple[Any, ...]:
    """Filesystem signature for non-spine inputs used by handoff authz."""
    workspace = _state_workspace(request)
    if workspace is None:
        return ()
    candidates = [
        workspace / "team.json",
        workspace / "team_trust" / "roots.json",
        workspace / "team_trust" / "endorsements.jsonl",
        workspace / "team_trust" / "revocations.jsonl",
        workspace / "contacts.json",
    ]
    missions_dir = workspace / "missions"
    try:
        candidates.extend(sorted(missions_dir.glob("*.json")))
    except OSError:
        pass
    signature: List[Tuple[str, int, int]] = []
    for path in candidates:
        try:
            st = path.stat()
            signature.append((str(path), st.st_mtime_ns, st.st_size))
        except OSError:
            signature.append((str(path), 0, 0))
    return tuple(signature)


def _handoff_source_repo_root() -> Optional[Path]:
    configured = os.environ.get("NTH_SOURCE_REPO", "").strip()
    candidates = [Path(configured)] if configured else []
    candidates.append(Path.cwd())
    for candidate in candidates:
        try:
            root = candidate.resolve()
        except OSError:
            continue
        if (root / ".git").exists():
            return root
    return None


def _handoff_source_repo_map() -> Dict[str, Path]:
    """Parse repo locator mappings without exposing local paths in API output.

    Format: ``NTH_SOURCE_REPOS="repo_id=PATH;repo_url=PATH"``. Keys are matched
    against evidence.source.repo_id and evidence.source.repo_url.
    """
    raw = os.environ.get("NTH_SOURCE_REPOS", "")
    out: Dict[str, Path] = {}
    for entry in raw.replace("\n", ";").split(";"):
        item = entry.strip()
        if not item or "=" not in item:
            continue
        key, value = item.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key or not value:
            continue
        out[key] = Path(value)
    return out


def _handoff_source_repo_root_for_evidence(
    evidence: Dict[str, Any],
) -> Tuple[Optional[Path], str, str]:
    source = evidence.get("source", {}) if isinstance(evidence, dict) else {}
    keys: List[str] = []
    if isinstance(source, dict):
        for field in ("repo_id", "repo_url"):
            value = str(source.get(field, "") or "").strip()
            if value:
                keys.append(value)
    repo_map = _handoff_source_repo_map()
    for key in keys:
        mapped = repo_map.get(key)
        if mapped is None:
            continue
        try:
            root = mapped.resolve()
        except OSError:
            return None, key, "mapped source repo cannot be resolved"
        if (root / ".git").exists():
            return root, key, ""
        return None, key, "mapped source repo is not a git checkout"
    return _handoff_source_repo_root(), "", ""


def _handoff_evidence_verification(evidence: List[Any]) -> List[Dict[str, Any]]:
    from nth_dao.runtime import verify_source_evidence_report

    reports: List[Dict[str, Any]] = []
    for item in evidence:
        if not isinstance(item, dict):
            reports.append({
                "status": "invalid",
                "reason": "evidence item is not a dict",
                "local_reachable": False,
                "content_match": False,
            })
            continue
        if item.get("kind") != "source_span":
            reports.append({
                "kind": item.get("kind", ""),
                "status": "unsupported",
                "reason": "only source_span local verification is implemented",
                "local_reachable": False,
                "content_match": False,
            })
            continue
        repo_root, matched_by, resolver_error = _handoff_source_repo_root_for_evidence(item)
        if repo_root is None:
            source = item.get("source", {}) if isinstance(item, dict) else {}
            reports.append(
                {
                    "kind": item.get("kind", ""),
                    "path": item.get("path", ""),
                    "commit": item.get("commit", ""),
                    "content_hash": item.get("content_hash", ""),
                    "source": source,
                    "resolver": {
                        "type": "git",
                        "repo_id": source.get("repo_id", "")
                        if isinstance(source, dict)
                        else "",
                        "repo_url": source.get("repo_url", "")
                        if isinstance(source, dict)
                        else "",
                        "commit": item.get("commit", ""),
                        "path": item.get("path", ""),
                        "content_hash": item.get("content_hash", ""),
                        "source_present": bool(source),
                        "matched_by": matched_by,
                    },
                    "status": "unavailable",
                    "reason": resolver_error
                    or (
                        "set NTH_SOURCE_REPOS repo_id=PATH or NTH_SOURCE_REPO, "
                        "or start the hub from a git checkout"
                    ),
                    "local_reachable": False,
                    "commit_reachable": False,
                    "blob_reachable": False,
                    "content_match": False,
                }
            )
            continue
        report = verify_source_evidence_report(repo_root, item)
        resolver = report.get("resolver")
        if isinstance(resolver, dict):
            resolver["matched_by"] = matched_by
        reports.append(report)
    return reports


def _handoff_review_packet(
    rec: Any,
    evidence_verification: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build the agent-facing minimal review packet for a handoff claim."""
    capsule = rec.capsule
    evidence_summary: Dict[str, int] = {
        "total": len(evidence_verification),
        "verified": 0,
        "unreachable": 0,
        "unavailable": 0,
        "mismatch": 0,
        "invalid": 0,
        "unsupported": 0,
    }
    for item in evidence_verification:
        status = str(item.get("status", "invalid"))
        evidence_summary[status] = evidence_summary.get(status, 0) + 1
    return {
        "packet_kind": "nth-handoff-review-packet-v1",
        "packet_version": 1,
        "packet_is_signed": False,
        "is_truth_verdict": False,
        "warning": "Signed handoff is a claim, not a verified fact.",
        "goal": (
            "Use the least context needed to re-check, continue, or refute "
            "this handoff."
        ),
        "mission_id": rec.mission_id,
        "step_id": str(capsule.get("step_id", "")),
        "capsule_hash": rec.capsule_hash,
        "status": rec.status,
        "verification_status": str(capsule.get("verification_status", "")),
        "author_did": rec.author_did,
        "finding": str(capsule.get("finding", "")),
        "root_cause_hypothesis": str(capsule.get("root_cause_hypothesis", "")),
        "evidence_summary": evidence_summary,
        "evidence_verification": evidence_verification,
        "changed_files": list(capsule.get("changed_files", [])),
        "tests": list(capsule.get("tests", [])),
        "risks": list(capsule.get("risks", [])),
        "next_actions": list(capsule.get("next_actions", [])),
        "required_review_steps": [
            "Verify each evidence pointer against its pinned commit and content hash.",
            "Rerun or inspect the listed tests before trusting the finding.",
            (
                "If the claim is wrong, sign a refutation or superseding "
                "handoff with a receipt."
            ),
        ],
    }


def _receipt_payload_binds_handoff_response(
    receipt: Dict[str, Any], stmt: Dict[str, Any],
) -> bool:
    """Return True when a signed receipt timeline names this response target.

    ``receipt_id`` and ``goal_id`` are discovery envelope fields. The binding
    that matters for handoff audit must live inside the signed timeline payload.
    """
    for entry in list(receipt.get("timeline", []) or []):
        if not isinstance(entry, dict):
            continue
        if str(entry.get("type", "")) != "nth.handoff_response":
            continue
        payload = entry.get("payload")
        if not isinstance(payload, dict):
            continue
        if str(payload.get("mission_id", "")) != str(stmt.get("mission_id", "")):
            continue
        if str(payload.get("response_type", "")) != str(stmt.get("response_type", "")):
            continue
        if str(payload.get("target_capsule_hash", "")) != str(
            stmt.get("target_capsule_hash", ""),
        ):
            continue
        if stmt.get("response_type") == "superseded":
            if str(payload.get("replacement_capsule_hash", "")) != str(
                stmt.get("replacement_capsule_hash", ""),
            ):
                continue
        return True
    return False


def _require_handoff_response_target_known(
    request: Request, stmt: Dict[str, Any],
) -> None:
    target_hash = str(stmt.get("target_capsule_hash", "") or "")
    proj = _verified_handoff_projection(request)
    if proj is None:
        raise HTTPException(
            status_code=503,
            detail="handoff projection unavailable; cannot verify target capsule",
        )
    if proj.get(target_hash) is None:
        raise HTTPException(
            status_code=404,
            detail=f"target handoff capsule not found: {target_hash}",
        )


def _validate_handoff_response_receipt_binding(
    request: Request, stmt: Dict[str, Any],
) -> None:
    receipt_id = str(stmt.get("receipt_id", "") or "")
    receipt_content_hash = str(stmt.get("receipt_content_hash", "") or "")
    if not receipt_id and not receipt_content_hash:
        return
    receipts = _state_receipts_store(request)
    if receipts is None:
        raise HTTPException(
            status_code=503,
            detail="receipt store unavailable; cannot verify handoff response receipt",
        )
    receipt = receipts.load(receipt_id)
    if receipt is None:
        raise HTTPException(
            status_code=400,
            detail=f"handoff response receipt not found: {receipt_id}",
        )
    if str(receipt.get("receipt_id", "") or "") != receipt_id:
        raise HTTPException(
            status_code=400,
            detail="handoff response receipt_id mismatch",
        )
    if str(receipt.get("content_hash", "") or "") != receipt_content_hash:
        raise HTTPException(
            status_code=400,
            detail="handoff response receipt content_hash mismatch",
        )
    try:
        from nth_dao.execution_receipt import verify_receipt
    except ImportError as exc:
        raise HTTPException(
            status_code=503,
            detail="receipt verifier unavailable",
        ) from exc
    if not verify_receipt(receipt):
        raise HTTPException(
            status_code=400,
            detail="handoff response receipt failed signature/content verification",
        )
    if str(receipt.get("signer_did", "") or "") != str(stmt.get("author_did", "")):
        raise HTTPException(
            status_code=400,
            detail="handoff response receipt signer_did mismatch",
        )
    if str(receipt.get("goal_id", "") or "") != str(stmt.get("mission_id", "")):
        raise HTTPException(
            status_code=400,
            detail="handoff response receipt goal_id mismatch",
        )
    if not _receipt_payload_binds_handoff_response(receipt, stmt):
        raise HTTPException(
            status_code=400,
            detail="handoff response receipt does not bind target/replacement",
        )


def _verified_handoff_projection(request: Request) -> Optional[Any]:
    """Return a HandoffProjection folded from the verified spine.

    Cached by spine head hash so read paths do not rebuild the projection on
    every /missions or /handoffs request.
    """
    events = _verified_spine_events(request)
    if events is None:
        return None
    spine = _state_spine(request)
    head = getattr(spine, "head_hash", "") if spine is not None else ""
    authz_sig = _handoff_authz_cache_signature(request)
    cache = getattr(spine, "_v2_handoff_projection_cache", None) if spine is not None else None
    if cache is not None and cache[0] == (head, authz_sig):
        return cache[1]
    from nth_dao.runtime import HandoffProjection

    proj = HandoffProjection(
        responder_authorizer=_handoff_responder_authorizer(request, events),
    )
    for event in events:
        proj.apply(event)
    if spine is not None:
        spine._v2_handoff_projection_cache = ((head, authz_sig), proj)
    return proj


def _mission_handoff_events(
    request: Optional[Request], mission_id: str,
) -> List[Dict[str, Any]]:
    """Replay signed handoff capsules for one Mission into timeline rows."""
    if request is None or not mission_id:
        return []
    req_state = getattr(request, "state", None)
    cache = getattr(req_state, "_v2_mission_handoff_events", None) if req_state is not None else None
    if cache is None:
        cache = {}
        try:
            proj = _verified_handoff_projection(request)
        except HTTPException as exc:
            cache[mission_id] = [{
                "id": f"handoff-warning:{mission_id}",
                "kind": "warning",
                "label": "Handoff evidence unavailable",
                "detail": str(getattr(exc, "detail", "") or exc),
                "at": _iso_now(),
                "status": "warning",
                "agent_did": None,
            }]
            if req_state is not None:
                setattr(req_state, "_v2_mission_handoff_events", cache)
            return list(cache.get(mission_id, []))
        if proj is not None:
            try:
                for rec in proj.all():
                    view = _mission_handoff_record_to_view(rec)

                    cache.setdefault(rec.mission_id, []).append(view)
            except (RuntimeError, TypeError, ValueError) as exc:
                logger.warning("mission handoff replay failed: %s", exc)
        if req_state is not None:
            setattr(req_state, "_v2_mission_handoff_events", cache)
    return list(cache.get(mission_id, []))


def _emit_mission_evidence(
    request: Request,
    event_type: str,
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    """Persist a signed receipt and append the matching Mission EventBus fact.

    Mission mutations must not become invisible just because the evidence layer
    is temporarily unavailable, so this is fail-soft and returns the IDs it did
    manage to write. The mutation endpoints still log every evidence failure.
    """
    event_payload = _json_safe(dict(payload or {}))
    if not isinstance(event_payload, dict):
        event_payload = {}
    evidence: Dict[str, Any] = {}
    identity = _state_node_identity(request)
    signer = identity if identity is not None and getattr(identity, "can_sign", False) else None
    receipt_store = _state_receipts_store(request)
    if signer is not None and receipt_store is not None:
        try:
            from nth_dao.execution_receipt import TimelineEntry, now_ms

            receipt_payload = dict(event_payload)
            receipt_payload["event_type"] = event_type
            signer_did = str(signer.as_did())
            receipt = receipt_store.sign_and_save(
                [TimelineEntry(
                    timestamp=now_ms(),
                    type="nth.mission_event",
                    payload=receipt_payload,
                )],
                signer,
                goal_id=str(event_payload.get("mission_id", "") or ""),
            )
            evidence["receipt_id"] = receipt.get("receipt_id", "")
            evidence["receipt_hash"] = receipt.get("content_hash", "")
            event_payload["receipt_id"] = evidence["receipt_id"]
            event_payload["receipt_hash"] = evidence["receipt_hash"]
            event_payload["receipt_signer_did"] = signer_did
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            logger.warning(
                "mission receipt write failed for %s %s: %s",
                event_type,
                event_payload.get("mission_id", ""),
                exc,
            )
    bus = _state_event_bus(request)
    if bus is not None:
        try:
            event = bus.emit(event_type, event_payload, identity=signer)
            evidence["event_id"] = getattr(event, "event_id", "")
            evidence["event_hash"] = getattr(event, "event_hash", "")
            evidence["event_seq"] = getattr(event, "seq", 0)
            evidence["event_timestamp"] = getattr(event, "timestamp", "")
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            logger.warning(

                "mission EventBus emit failed for %s %s: %s",
                event_type,
                event_payload.get("mission_id", ""),
                exc,
            )
    return evidence

def _expected_pubkey_from_did(expected_did: str) -> str:
    if not expected_did:
        return ""
    try:
        from nth_dao.did_key import decode_ed25519_did_key_hex

        return decode_ed25519_did_key_hex(expected_did)
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"expected agent DID is not a valid did:key: {expected_did!r}") from exc


def _verify_agent_receipt(
    *,
    agent_id: str,
    expected_did: str,
    receipt: Dict[str, Any],
) -> None:
    """Fail closed unless ``receipt`` verifies and belongs to the agent.

    A local child process is not a trusted persistence authority. It
    may be buggy, compromised, or merely running an older protocol.
    Before a hub writes agent-supplied evidence into ``team_receipts``
    the receipt must self-verify, and when the routing layer knows the
    target DID it must match ``signer_did`` exactly.
    """
    from nth_dao.execution_receipt import verify_receipt

    signer_did = str(receipt.get("signer_did", "") or "")
    if expected_did and signer_did != expected_did:
        raise ValueError(
            f"receipt signer_did does not match agent {agent_id}: "
            f"{signer_did!r} != {expected_did!r}"
        )
    expected_pubkey = _expected_pubkey_from_did(expected_did)
    if not verify_receipt(receipt, expected_pubkey_hex=expected_pubkey):
        raise ValueError(
            f"agent response receipt failed signature/content verification "
            f"for agent {agent_id}"
        )


def _agent_link_receipt_payload(receipt: Dict[str, Any]) -> Dict[str, Any]:
    """Extract the single signed ask payload used for AgentLink recovery."""
    timeline = receipt.get("timeline")
    if not isinstance(timeline, list):
        raise ValueError("receipt timeline is malformed")
    matches = [
        entry.get("payload")
        for entry in timeline
        if isinstance(entry, dict)
        and entry.get("type") == "nth.a2a_ask_executed"
        and isinstance(entry.get("payload"), dict)
    ]
    if len(matches) != 1:
        raise ValueError(
            "AgentLink reconciliation requires exactly one signed ask entry"
        )
    return dict(matches[0])


def _persist_agent_response_receipt(
    request: Request,
    agent_id: str,
    expected_did: str,
    content: Any,
) -> Optional[Dict[str, str]]:
    """Persist a signed receipt carried in a successful agent response.

    Child stdout events are still useful, but they are not a reliable
    persistence boundary for every backend. If the hub returns a 200
    response containing result.receipt, the audit evidence must already
    be verified and on disk before the HTTP response is handed back to
    the UI.
    """
    return _persist_agent_response_receipt_to_store(
        _state_receipts_store(request),
        agent_id,
        expected_did,
        content,
    )


def _persist_agent_response_receipt_to_store(
    receipts: Any,
    agent_id: str,
    expected_did: str,
    content: Any,
) -> Optional[Dict[str, str]]:
    """Verify and persist a receipt from an agent response.

    This store-level helper lets background channel dispatch reuse the
    exact same receipt gate as browser-driven /ask without holding a
    FastAPI Request object as the persistence authority.
    """
    if not isinstance(content, dict):
        return None
    result = content.get("result")
    if not isinstance(result, dict):
        return None
    receipt = result.get("receipt")
    if receipt is None:
        return None
    if not isinstance(receipt, dict):
        raise HTTPException(
            status_code=502,
            detail="agent response receipt is malformed",
        )
    try:
        _verify_agent_receipt(
            agent_id=agent_id, expected_did=expected_did, receipt=receipt,
        )
    except ValueError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    if receipts is None:
        raise HTTPException(
            status_code=500,
            detail="receipt store unavailable; cannot persist agent response receipt",
        )
    receipt_id = str(receipt.get("receipt_id", "") or "?")
    content_hash = str(receipt.get("content_hash", "") or "")
    try:
        path = receipts.save(receipt)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        safe_exc = _redact_local_paths(str(exc))
        logger.exception(
            "v2_api: failed to persist response receipt for agent %s (id=%s)",
            agent_id,
            receipt_id,
        )
        raise HTTPException(
            status_code=500,
            detail=f"agent response receipt could not be persisted: {safe_exc}",
        ) from exc
    logger.info(
        "v2_api: persisted response receipt for agent %s (id=%s, path=%s)",
        agent_id,
        receipt_id,
        path,
    )
    return {
        "nth_receipt_id": receipt_id,
        "nth_receipt_content_hash": content_hash,
    }


_AGENT_AUTH_READINESS_TIMEOUT_S = 3.0
_AGENT_AUTH_READINESS_RETRY_S = 0.25


async def _forward_local_agent_with_readiness_retry(
    forward: Callable[[], Tuple[int, bytes]],
) -> Tuple[int, Any]:
    """Retry only the child's transient pre-cap-token authorization state."""
    import asyncio

    deadline = time.monotonic() + _AGENT_AUTH_READINESS_TIMEOUT_S
    while True:
        status, raw = await asyncio.to_thread(forward)
        content = _decode_or_passthrough(raw)
        if status != 401:
            return status, content
        error = content.get("error") if isinstance(content, dict) else None
        not_ready = (
            isinstance(error, dict)
            and error.get("code") == "not-yet-authorized"
        )
        remaining = deadline - time.monotonic()
        if not not_ready or remaining <= 0:
            return status, content
        await asyncio.sleep(min(_AGENT_AUTH_READINESS_RETRY_S, remaining))


async def _drive_supervised_agent_ask(
    request: Request,
    did: str,
    payload: Dict[str, Any],
) -> Tuple[int, Any, Any, Optional[Dict[str, str]]]:
    """Drive one live supervised agent via /a2a/ask.

    This is the non-streaming core behind Mission step execution. The browser
    never receives or forwards a child cap_token; the hub injects the stored
    token and persists the child response receipt before returning.
    """
    import urllib.error
    import urllib.request

    sup = _state_supervisor(request)
    if sup is None:
        raise HTTPException(status_code=503, detail="agent supervisor unavailable")
    matching = [
        r for r in sup.list_agents()
        if (
            r.did == did
            and r.a2a_port is not None
            and r.alive
        )
    ]
    if not matching:
        raise HTTPException(
            status_code=404,
            detail=f"no live supervised agent for did={did!r} with an a2a_port",
        )
    rec = matching[0]

    store = _state_cap_tokens_store(request)
    token_id = getattr(rec, "cap_token_id", None)
    token = store.get(token_id) if (token_id and store is not None) else None
    from nth_dao.cap_token import CAP_A2A_MESSAGE_SEND, encode_authorization_header

    if not _cap_token_usable(
        token,
        store,
        required_capabilities=[CAP_A2A_MESSAGE_SEND],
    ):
        token = _refresh_supervised_agent_cap_token(
            request,
            rec,
            previous_token=token if isinstance(token, dict) else None,
        )

    payload = _with_backend_ask_timeout(payload, getattr(rec, "kind", None))
    body_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    if len(body_bytes) > 1024 * 1024:
        raise HTTPException(status_code=413, detail="body exceeds 1MB A2A cap")

    url = f"http://127.0.0.1:{rec.a2a_port}/a2a/ask"
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Content-Length": str(len(body_bytes)),
        "Authorization": f"CapToken {encode_authorization_header(token)}",
    }
    forward_timeout = _a2a_forward_timeout(
        "ask", body_bytes, backend_kind=getattr(rec, "kind", None),
    )

    def _do_forward() -> Tuple[int, bytes]:
        with _work_scope_lease(request, rec):
            req = urllib.request.Request(
                url, data=body_bytes, headers=headers, method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=forward_timeout) as resp:  # noqa: S310
                    return resp.status, _read_local_a2a_body(resp)
            except urllib.error.HTTPError as http_exc:
                return http_exc.code, _read_local_a2a_body(http_exc)

    try:
        resp_status, content = (
            await _forward_local_agent_with_readiness_retry(_do_forward)
        )
    except WorkScopeBusy as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (
        urllib.error.URLError,
        TimeoutError,
        OSError,
        A2AResponseTooLarge,
    ) as exc:
        raise HTTPException(
            status_code=502,
            detail=f"agent-ask proxy failed at {url}: {exc}",
        )
    receipt_meta: Optional[Dict[str, str]] = None
    if resp_status == 200:
        receipt_meta = _persist_agent_response_receipt(
            request, rec.agent_id, rec.did, content,
        )
        content = _bound_agent_result_projection(content)
    return resp_status, content, rec, receipt_meta


# NOTE: prev_content_hash lookup goes through the canonical
# ``ReceiptStore.head_content_hash(signer_did)`` method
# (execution_receipt.py:844) which has documented tie-breaking
# semantics. Review pass#2 fix C1 2026-06-10: the earlier
# `_compute_prev_hash` helper duplicated that logic with a
# subtly-wrong sort (it sorted by issued_at + receipt_id; uuid4
# fallback would chain to a random receipt under timestamp ties).
# Delegating to head_content_hash also pulls in any future
# chain_heads.json index for free when ReceiptStore gets one.


def _state_blackboard(request: Request) -> Optional[Any]:
    """Pull live Blackboard from app.state if present, else None.

    WebState attaches itself at ``app.state.nth`` (see __init__.py
    line 632). Each WebState has a ``blackboard`` attr that is the
    canonical instance — the one POSTs from /api/tasks etc. write
    to. Using that directly means /api/v2/processes reflects the
    same operational truth as the v1 dashboard.

    Review-of-review fix (2026-06-10): the previous version
    silently returned None on AttributeError, making a mis-wired
    server look healthy (every endpoint just falls back to seed
    indefinitely). Log at warning level so the operator sees the
    misconfiguration in stdout/logs immediately. """
    try:
        return request.app.state.nth.blackboard
    except AttributeError:
        logger.warning(
            "v2_api: app.state.nth.blackboard unavailable — "
            "serving seed data. WebState may not be initialised.",
        )
        return None


# Phase 3a/3b: agent supervisor accessor + spawn request model.
# Module-level lock that serialises the first-access build of
# app.state.v2_supervisor. Cheap to allocate, lives for the
# process lifetime, and only contended on cold start.
_SUPERVISOR_BUILD_LOCK = threading.Lock()
_AGENT_LINK_BUILD_LOCK = threading.Lock()


# H-1 fix (review round Phase 4 R1): per-method proxy timeout. The
# original 2s blanket was fine for /ping + /a2a/echo (instant) but
# silently broke the /a2a/ask path with the claude-code backend
# (the CLI takes ~30s on cold sessions). Methods not in this map
# inherit ``_A2A_DEFAULT_TIMEOUT_S`` — keeps the snappy default for
# wire-test calls while letting ``ask`` honour its real backend cost.
_A2A_DEFAULT_TIMEOUT_S = 2.0
_A2A_TIMEOUT_SLACK_S = 5.0
_A2A_MAX_FORWARD_TIMEOUT_S = _env_float(
    "NTH_A2A_MAX_FORWARD_TIMEOUT_S",
    360.0,
    minimum=35.0,
    maximum=900.0,
)
_HERMES_ASK_TIMEOUT_S = min(
    _env_float(
        "NTH_HERMES_ASK_TIMEOUT_S",
        300.0,
        minimum=30.0,
        maximum=300.0,
    ),
    max(30.0, _A2A_MAX_FORWARD_TIMEOUT_S - _A2A_TIMEOUT_SLACK_S),
)
_HERMES_FORWARD_TIMEOUT_S = min(
    _HERMES_ASK_TIMEOUT_S + _A2A_TIMEOUT_SLACK_S,
    _A2A_MAX_FORWARD_TIMEOUT_S,
)
_CODEX_ASK_TIMEOUT_S = min(
    _env_float(
        "NTH_CODEX_ASK_TIMEOUT_S",
        240.0,
        minimum=60.0,
        maximum=300.0,
    ),
    max(60.0, _A2A_MAX_FORWARD_TIMEOUT_S - _A2A_TIMEOUT_SLACK_S),
)
_CODEX_FORWARD_TIMEOUT_S = min(
    _CODEX_ASK_TIMEOUT_S + _A2A_TIMEOUT_SLACK_S,
    _A2A_MAX_FORWARD_TIMEOUT_S,
)
_A2A_METHOD_TIMEOUTS: Dict[str, float] = {
    "ask": 65.0,    # claude-code backend default is 60s + 5s slack
    # Phase 5.2: streaming variant gets a longer window because the
    # caller may keep the connection open while the model generates.
    # 125s = 120s backend allowance + 5s for hub round-trip overhead.
    "ask-stream": 125.0,
}
_A2A_BACKEND_METHOD_TIMEOUTS: Dict[Tuple[str, str], float] = {
    # Hermes provider queues can exceed 170s in local field tests. The
    # child adapter accepts caller timeout_s up to 300s, so the hub must
    # keep its own forward window above that backend cutoff.
    ("hermes", "ask"): _HERMES_FORWARD_TIMEOUT_S,
    ("hermes", "ask-stream"): _HERMES_FORWARD_TIMEOUT_S,
    # Codex CLI defaults to 90s. It can cold-start slowly, so do not
    # inherit the Claude-sized 65s floor when the supervisor knows the
    # child is a Codex agent.
    ("codex", "ask"): _CODEX_FORWARD_TIMEOUT_S,
    ("codex", "ask-stream"): _CODEX_FORWARD_TIMEOUT_S,
}
_CHANNEL_DISPATCH_DEFAULT_ASK_TIMEOUT_S = 120.0
_CHANNEL_DISPATCH_ASK_TIMEOUTS: Dict[str, float] = {
    "hermes": _HERMES_ASK_TIMEOUT_S,
    "codex": _CODEX_ASK_TIMEOUT_S,
    "claude-code": 120.0,
    "mock": 30.0,
}


def _backend_ask_timeout(backend_kind: str | None) -> float:
    """Return the child execution timeout for one supervised backend."""

    return _CHANNEL_DISPATCH_ASK_TIMEOUTS.get(
        str(backend_kind or "").strip().lower(),
        _CHANNEL_DISPATCH_DEFAULT_ASK_TIMEOUT_S,
    )


def _with_backend_ask_timeout(
    payload: Dict[str, Any],
    backend_kind: str | None,
) -> Dict[str, Any]:
    """Copy an ask payload and apply the server policy when it has no timeout."""

    normalized = dict(payload)
    normalized.setdefault("timeout_s", _backend_ask_timeout(backend_kind))
    return normalized


def _channel_dispatch_kind_allowed(backend_kind: str | None) -> bool:
    """Return whether a backend kind may auto-reply in channels.

    Empty ``NTH_CHANNEL_AGENT_KINDS`` keeps the historical behavior: every
    live supervised channel member may receive messages. The desktop launcher
    narrows this to ``codex,mock`` so restored Hermes agents can stay in old
    channels without turning every message into a 300-second provider wait.
    """
    allowed = {item.lower() for item in _env_csv("NTH_CHANNEL_AGENT_KINDS")}
    if not allowed:
        return True
    return str(backend_kind or "").lower() in allowed


def _channel_dispatch_ask_timeout(backend_kind: str | None) -> float:
    return _CHANNEL_DISPATCH_ASK_TIMEOUTS.get(
        str(backend_kind or ""),
        _CHANNEL_DISPATCH_DEFAULT_ASK_TIMEOUT_S,
    )


def _a2a_forward_timeout(
    method: str,
    body_bytes: bytes,
    *,
    backend_kind: str | None = None,
) -> float:
    """Return the hub->child timeout for an A2A method.

    The per-method map is the generic minimum. When the supervisor knows the
    child's backend kind, backend-specific floors may raise that minimum so
    slow-but-healthy providers are not killed by a hub timeout before their own
    backend timeout fires. For model-backed methods, callers may request a
    larger ``timeout_s`` in the JSON body; the proxy adds a small round-trip
    slack and clamps to a hard ceiling so one request cannot pin a worker
    indefinitely.
    """
    base = _A2A_METHOD_TIMEOUTS.get(method, _A2A_DEFAULT_TIMEOUT_S)
    if backend_kind:
        base = max(
            base,
            _A2A_BACKEND_METHOD_TIMEOUTS.get((str(backend_kind), method), base),
        )
    if method not in {"ask", "ask-stream"}:
        return base
    try:
        payload = json.loads(body_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return base
    if not isinstance(payload, dict):
        return base
    requested = payload.get("timeout_s")
    if isinstance(requested, bool) or not isinstance(requested, (int, float)):
        return base
    try:
        requested_f = float(requested)
    except (OverflowError, ValueError):
        return _A2A_MAX_FORWARD_TIMEOUT_S
    if requested_f <= 0 or requested_f != requested_f:
        return base
    return min(
        max(base, requested_f + _A2A_TIMEOUT_SLACK_S),
        _A2A_MAX_FORWARD_TIMEOUT_S,
    )


def _state_supervisor(request: Request) -> Optional[Any]:
    """Return the lazy-built per-app agent supervisor.

    The supervisor is constructed on first access so a test that
    only hits read endpoints doesn't pay the cost of spinning up
    a SubprocessRunner. Stored on app.state.v2_supervisor — same
    pattern as v2_decisions_store.

    L-2 fix (review round Phase 3b R1): the check-then-set is
    serialised by ``_SUPERVISOR_BUILD_LOCK`` with a double-checked
    pattern (cheap path: attribute lookup, no lock; slow path:
    lock + re-check + build). Two concurrent first-requests on a
    multi-worker deployment can no longer each construct a
    supervisor and clobber the first one — the second waits at
    the lock and sees the populated attribute on re-check.

    Phase 3c (2026-06-11): the lazy build now wires the
    workspace-scoped ``cap_token_dir`` and a ``receipt_persistor``
    closure that forwards child-signed receipts into the hub's
    ReceiptStore. Without these the supervisor falls back to
    Phase 3b semantics (cap_token issued + audited, but never
    delivered to the child; receipts INFO-logged + dropped). """
    state = request.app.state
    sup = getattr(state, "v2_supervisor", None)
    if sup is not None:
        return sup
    with _SUPERVISOR_BUILD_LOCK:
        sup = getattr(state, "v2_supervisor", None)
        if sup is None:
            from .agent_supervisor import build_default_supervisor

            # Capture workspace-scoped cap_token dir if available.
            # When the workspace isn't bootstrapped (early dev
            # state), the supervisor still works for Phase 3a/3b
            # semantics — it just skips the file-delivery path.
            cap_token_dir: Optional[Path] = None
            workspace = _state_workspace(request)
            if workspace is not None:
                cap_token_dir = workspace / "sandbox" / "agents"

            # Receipt persistor closure — looks up state.receipts
            # FRESH each call so a hub that bootstraps the receipts
            # store AFTER the supervisor is built (rare but
            # possible) still works.
            def _receipt_persistor(
                agent_id: str, receipt: Dict[str, Any],
            ) -> None:
                receipts = getattr(state.nth, "receipts", None)
                if receipts is None:
                    logger.warning(
                        "v2_api: agent %s signed a receipt but "
                        "state.nth.receipts is unavailable — "
                        "dropping",
                        agent_id,
                    )
                    return
                expected_did = ""
                try:
                    sup_for_lookup = getattr(state, "v2_supervisor", None)
                    rec = (
                        sup_for_lookup.get(agent_id)
                        if sup_for_lookup is not None else None
                    )
                    expected_did = str(getattr(rec, "did", "") or "")
                except Exception as exc:  # noqa: BLE001
                    logger.debug(
                        "v2_api: could not look up DID for receipt from agent %s: %s",
                        agent_id,
                        exc,
                    )

                _verify_agent_receipt(
                    agent_id=agent_id,
                    expected_did=expected_did,
                    receipt=receipt,
                )
                receipts.save(receipt)

            # Phase 3d: decision_raiser closure — inserts the
            # child-proposed decision into the in-process
            # decisions store. The store is the same dict the
            # GET /api/v2/decisions endpoint reads from, so a
            # raised decision is immediately visible to the
            # operator's v2 console without a refresh push.
            #
            # The hub fills the fields the child doesn't (or
            # shouldn't) supply:
            #   id              — uniqueness + format is a hub concern
            #   proposer_did    — looked up from the supervisor's
            #                     record (the child knows its own DID
            #                     but routing through the agent_id key
            #                     keeps the v2 API consistent)
            #   proposer_label  — same, derived from AgentRecord.label
            #   rationale       — schema requires it; default to a
            #                     stock string so the schema validates
            #                     even when the child doesn't bother
            #   source          — stamps "type": "agent" so the v2
            #                     console can render the right badge
            #   raised_at       — server-side clock
            def _decision_raiser(
                agent_id: str, decision: Dict[str, Any],
            ) -> None:
                # Walk-through bug fix (2026-06-11): if the operator
                # hasn't hit GET /api/v2/decisions yet, the lazy
                # store doesn't exist — but a child can still raise
                # before the UI fetches. Lazy-build here too so the
                # decision-raise wire works even on a freshly-built
                # supervisor whose decisions endpoint hasn't been
                # touched. Mirrors _decisions_store's seed pattern.
                store = _decision_store_for_state(state)
                supervisor = getattr(state, "v2_supervisor", None)
                rec = supervisor.get(agent_id) if supervisor is not None else None
                proposer_did = rec.did if rec is not None else ""
                proposer_label = (
                    rec.label if rec is not None and rec.label
                    else agent_id[:8]
                )

                decision_id = decision.get("id")
                if not isinstance(decision_id, str) or not decision_id:
                    decision_id = f"agent-{agent_id[:8]}-{os.urandom(4).hex()}"
                decision["id"] = decision_id
                # H-1 fix (review round Phase 3d R1): attribution
                # is the HUB's authority to stamp. Using setdefault
                # would let a child emit a decision claiming
                # proposer_did=<someone-else> and the hub would
                # honour the lie. Today the child is our own
                # trusted dummy_agent, but the moment a third-
                # party agent ships (Phase 4+) this becomes a real
                # impersonation vector. Direct assignment wins.
                # ``rationale`` keeps setdefault — it's CONTENT
                # (the child's explanation of why), not attribution.
                decision.setdefault(
                    "rationale",
                    f"Decision raised by supervised agent {proposer_label}",
                )
                decision["proposer_did"] = proposer_did
                decision["proposer_label"] = proposer_label
                decision["source"] = {
                    "type": "agent", "agent_id": agent_id,
                }
                decision["raised_at"] = _iso_now()
                if hasattr(store, "put"):
                    store.put(decision)
                else:
                    store[decision_id] = decision

            sup = build_default_supervisor(
                cap_token_dir=cap_token_dir,
                receipt_persistor=_receipt_persistor,
                decision_raiser=_decision_raiser,
                # 切片B:spawn 的 agent 拿到同一 workspace,其 claim 方法
                # 才够得到市场 feed/claim(与 announce/open 同一份)。
                workspace=workspace,
            )
            state.v2_supervisor = sup
            logger.info(
                "v2_api: built default agent supervisor "
                "(cap_token_dir=%s, persistor=on)",
                cap_token_dir,
            )
            # Phase 3e: one-shot recovery sweep. Picks up any
            # last_receipt.json files left behind by a prior hub
            # run that crashed between the child writing and the
            # parent reading from the pipe. Idempotent — no-op
            # when the dir doesn't exist or is empty.
            try:
                recovered = sup.recover_orphaned_receipts()
                if recovered:
                    logger.info(
                        "v2_api: recovered %d orphaned receipt(s) "
                        "from prior agent dirs",
                        recovered,
                    )
            except Exception as exc:  # noqa: BLE001
                # Recovery failure must not block the supervisor
                # build — the hub can still spawn new agents even
                # if it can't read the old receipts.
                logger.warning(
                    "v2_api: receipt recovery sweep failed: %s "
                    "— continuing without recovered receipts",
                    exc,
                )
            # Persistent restore: respawn durable local agents from the
            # private roster. A per-row failure is logged below and must not
            # prevent the supervisor from being created.
            try:
                _restore_persistent_agents(request, sup)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "v2_api: persistent-agent restore failed: %s", exc)
            try:
                _auto_prepare_supervised_agents(request, sup)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "v2_api: auto-agent preparation failed: %s", exc)
            try:
                recovered_dispatches = _recover_incomplete_channel_dispatches(
                    getattr(state.nth, "groups", None),
                )
                if recovered_dispatches:
                    logger.warning(
                        "v2_api: marked %d stale channel dispatch(es) "
                        "failed after hub restart",
                        recovered_dispatches,
                    )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "v2_api: channel dispatch recovery failed: %s", exc,
                )
    return sup


def _overlay_live_backend_status(
    statuses: Dict[str, Dict[str, Any]],
    request: Request,
) -> Dict[str, Dict[str, Any]]:
    """Project a supervised provider probe onto static backend metadata.

    ``backend_runtime_status`` answers whether the local transport can launch.
    A successful supervised ask separately verifies the configured provider.
    """
    try:
        supervisor = _state_supervisor(request)
        records = supervisor.list_agents() if supervisor is not None else []
    except (AttributeError, RuntimeError, OSError, TypeError, ValueError) as exc:
        logger.debug("v2_api: live backend status unavailable: %s", exc)
        return statuses

    for kind, status in list(statuses.items()):
        if not isinstance(status, dict):
            continue
        live = [
            record for record in records
            if str(getattr(record, "kind", "")) == kind
            and bool(getattr(record, "alive", False))
        ]
        if not live:
            continue
        states = {
            str(getattr(record, "provider_state", "unknown") or "unknown")
            for record in live
        }
        checked = sorted(
            str(getattr(record, "provider_checked_at", "") or "")
            for record in live
            if str(getattr(record, "provider_checked_at", "") or "")
        )
        projected = dict(status)
        if "ready" in states:
            projected.update(
                provider_state="ready",
                provider_verified=True,
                last_provider_check_at=checked[-1] if checked else "",
            )
            if kind == "hermes":
                projected.update(
                    runtime="provider-verified",
                    detail="A live supervised Hermes A2A ask succeeded.",
                )
        elif "degraded" in states:
            projected.update(
                provider_state="degraded",
                provider_verified=False,
                last_provider_check_at=checked[-1] if checked else "",
            )
            if kind == "hermes":
                projected.update(
                    runtime="provider-degraded",
                    detail="A live supervised Hermes A2A ask failed or timed out.",
                )
        statuses[kind] = projected
    return statuses


def _state_agent_link(request: Request) -> Any:
    """Return the app-scoped Bot-style AgentLink manager."""
    state = request.app.state
    manager = getattr(state, "agent_link_manager", None)
    if manager is not None:
        return manager
    with _AGENT_LINK_BUILD_LOCK:
        manager = getattr(state, "agent_link_manager", None)
        if manager is None:
            from .agent_link import AgentLinkManager, AgentLinkStore

            manager = AgentLinkManager(
                AgentLinkStore(_state_workspace(request)),
                max_pending_per_agent=4,
            )
            state.agent_link_manager = manager
    return manager


def _agent_link_request_hash(
    prompt: str,
    timeout_s: Any = None,
    *,
    channel_id: str = "",
    request_message_id: str = "",
) -> str:
    """Hash dispatch identity without persisting the prompt itself.

    The idempotency key identifies a retry; this digest binds that retry to
    the exact request context. Keeping only the digest prevents a reused key
    from silently returning a result for a different prompt.
    """
    material = {
        "prompt": str(prompt),
        "timeout_s": timeout_s,
        "channel_id": str(channel_id or ""),
        "request_message_id": str(request_message_id or ""),
    }
    encoded = json.dumps(
        material,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _agent_link_prompt_hash(prompt: str) -> str:
    """Return the non-reversible digest used to bind an AgentLink receipt."""
    return hashlib.sha256(str(prompt).encode("utf-8")).hexdigest()


def _validate_agent_link_timeout(raw: Any) -> Optional[float]:
    """Validate the public AgentLink timeout contract before enqueueing."""
    if raw is None:
        return None
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise HTTPException(status_code=400, detail="timeout_s must be a number")
    value = float(raw)
    if value != value or value in (float("inf"), float("-inf")):
        raise HTTPException(status_code=400, detail="timeout_s must be finite")
    if value < 5 or value > 300:
        raise HTTPException(
            status_code=400,
            detail="timeout_s must be between 5 and 300 seconds",
        )
    return value


def _make_cap_issuer(node_identity: Any, cap_tokens_store: Any):
    """构造 spawn/恢复共用的 cap_token 签发闭包(node 签发、落审计store)。"""
    from nth_dao.cap_token import (
        CAP_A2A_MESSAGE_SEND, CAP_NTH_RECEIPT_SIGN, KNOWN_CAPABILITIES,
        sign_cap_token,
    )

    def _issue(subject_did: str, requested_caps: List[str]) -> Dict[str, Any]:
        caps: List[str] = [CAP_NTH_RECEIPT_SIGN, CAP_A2A_MESSAGE_SEND]
        for c in requested_caps:
            if c in KNOWN_CAPABILITIES and c not in caps:
                caps.append(c)
        token = sign_cap_token(
            issuer=node_identity, subject_did=subject_did, capabilities=caps
        )
        cap_tokens_store.record(token)
        return token

    return _issue


def _cap_token_usable(
    token: Any,
    cap_tokens_store: Any,
    *,
    required_capabilities: List[str],
) -> bool:
    """Return True only when a stored cap_token is currently usable."""
    if not isinstance(token, dict) or cap_tokens_store is None:
        return False
    try:
        from nth_dao.cap_token import verify_cap_token

        revoked = cap_tokens_store.revoked_set()
        ok, _reason = verify_cap_token(
            token,
            revoked_ids=revoked,
            required_capabilities=required_capabilities,
        )
        return bool(ok)
    except Exception as exc:  # noqa: BLE001 - listing/proxy must stay robust
        logger.warning("v2_api: cap_token usability check failed: %s", exc)
        return False


def _refresh_supervised_agent_cap_token(
    request: Request,
    rec: Any,
    *,
    previous_token: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Issue and deliver a fresh local cap_token for a supervised agent."""
    identity = _state_node_identity(request)
    cap_tokens_store = _state_cap_tokens_store(request)
    sup = _state_supervisor(request)
    if (
        identity is None
        or not getattr(identity, "can_sign", False)
        or cap_tokens_store is None
        or sup is None
    ):
        raise HTTPException(
            status_code=503,
            detail=(
                "cannot refresh expired agent cap_token: node signer, "
                "cap_token store, or supervisor is unavailable"
            ),
        )

    from nth_dao.cap_token import (
        CAP_A2A_MESSAGE_SEND, CAP_NTH_RECEIPT_SIGN, KNOWN_CAPABILITIES,
        sign_cap_token,
    )

    caps: List[str] = [CAP_NTH_RECEIPT_SIGN, CAP_A2A_MESSAGE_SEND]
    for cap in list(getattr(rec, "capabilities", []) or []):
        if cap in KNOWN_CAPABILITIES and cap not in caps:
            caps.append(cap)

    scope_model_allowlist = None
    if isinstance(previous_token, dict):
        old_scope = previous_token.get("scope_model_allowlist")
        if isinstance(old_scope, list):
            scope_model_allowlist = [str(item) for item in old_scope]

    token = sign_cap_token(
        issuer=identity,
        subject_did=str(getattr(rec, "did", "") or ""),
        capabilities=caps,
        scope_model_allowlist=scope_model_allowlist,
    )
    cap_tokens_store.record(token)
    try:
        refreshed_id = sup.refresh_cap_token(str(rec.agent_id), token)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=500,
            detail=f"failed to deliver refreshed cap_token: {exc}",
        ) from exc
    if not refreshed_id:
        raise HTTPException(
            status_code=404,
            detail=(
                "agent disappeared while refreshing cap_token; "
                "reload agents and try again"
            ),
        )
    logger.info(
        "v2_api: refreshed cap_token for agent %s did=%s token_id=%s",
        getattr(rec, "agent_id", "?"),
        str(getattr(rec, "did", ""))[:24],
        refreshed_id,
    )
    return token


def _env_csv(name: str) -> List[str]:
    raw = os.environ.get(name, "")
    return [part.strip() for part in raw.split(",") if part.strip()]


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() not in {"0", "false", "no", "off"}


def _auto_prepare_supervised_agents(request: Request, sup: Any) -> None:
    """Optionally spawn local agents and join them to startup channels.

    Normal API tests and library embeds should not unexpectedly start
    subprocesses. The desktop launcher enables this through environment
    variables for the operator's one-click workflow.
    """
    kinds = _env_csv("NTH_AUTO_AGENTS")
    if not kinds:
        return
    ws = _state_workspace(request)
    node_identity = _state_node_identity(request)
    cap_tokens_store = _state_cap_tokens_store(request)
    if (
        ws is None or node_identity is None
        or not getattr(node_identity, "can_sign", False)
        or cap_tokens_store is None
    ):
        logger.warning(
            "v2_api: NTH_AUTO_AGENTS requested but signer/cap store "
            "is unavailable; skipping auto agent preparation",
        )
        return

    from .agent_roster import AgentRoster
    from .dummy_agent import KNOWN_BACKEND_KINDS, backend_runtime_status

    statuses = backend_runtime_status()
    issuer = _make_cap_issuer(node_identity, cap_tokens_store)
    persist = _env_bool("NTH_AUTO_AGENT_PERSIST", True)
    roster = AgentRoster(ws) if persist else None
    default_caps = ["a2a:message_send"]
    label_prefix = os.environ.get("NTH_AUTO_AGENT_LABEL_PREFIX", "auto").strip()
    label_prefix = label_prefix or "auto"

    existing_by_kind: Dict[str, Any] = {}
    try:
        for rec in sup.list_agents():
            kind = str(getattr(rec, "kind", "") or "")
            if (
                kind
                and bool(getattr(rec, "alive", False))
                and getattr(rec, "cap_token_id", None)
            ):
                existing_by_kind.setdefault(kind, rec)
    except Exception as exc:  # noqa: BLE001
        logger.warning("v2_api: could not inspect supervisor agents: %s", exc)

    prepared: List[Any] = []
    seen: set[str] = set()
    for raw_kind in kinds:
        kind = raw_kind.strip()
        if not kind or kind in seen:
            continue
        seen.add(kind)
        if kind not in KNOWN_BACKEND_KINDS:
            logger.warning(
                "v2_api: ignoring unknown NTH_AUTO_AGENTS kind %r", kind,
            )
            continue
        status = statuses.get(kind, {})
        if not status.get("ready"):
            logger.warning(
                "v2_api: auto agent %s not prepared because backend is not ready: %s",
                kind,
                status.get("detail") or status.get("warning") or "not ready",
            )
            continue
        rec = existing_by_kind.get(kind)
        if rec is None:
            identity_file: Optional[str] = None
            if roster is not None:
                identity_file = roster.allocate_identity_file()
            try:
                rec = sup.spawn(
                    kind=kind,
                    label=f"{label_prefix}-{kind}",
                    capabilities=default_caps,
                    cap_token_issuer=issuer,
                    identity_file=identity_file,
                )
                if roster is not None and identity_file:
                    roster.add(
                        identity_file=identity_file,
                        kind=rec.kind,
                        label=rec.label,
                        capabilities=default_caps,
                        did=rec.did,
                    )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "v2_api: auto agent %s preparation failed: %s", kind, exc,
                )
                continue
        prepared.append(rec)

    join_channels = _env_csv("NTH_AUTO_AGENT_JOIN_CHANNELS")
    if not join_channels or not prepared:
        if prepared:
            logger.info(
                "v2_api: prepared %d auto agent(s); no startup channel join requested",
                len(prepared),
            )
        return

    join_kinds = set(_env_csv("NTH_AUTO_AGENT_JOIN_KINDS"))
    groups = getattr(request.app.state.nth, "groups", None)
    if groups is None:
        logger.warning(
            "v2_api: auto agent channel join requested but group manager "
            "is unavailable",
        )
        return
    joined = 0
    for rec in prepared:
        kind = str(getattr(rec, "kind", "") or "")
        if join_kinds and kind not in join_kinds:
            continue
        did = str(getattr(rec, "did", "") or "")
        if not did:
            continue
        for channel_id in join_channels:
            try:
                groups.add_channel_member(channel_id, agent_id=did, added_by="")
                joined += 1
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "v2_api: auto agent %s join %s failed: %s",
                    did[:24],
                    channel_id,
                    exc,
                )
    logger.info(
        "v2_api: prepared %d auto agent(s), joined %d channel membership(s)",
        len(prepared),
        joined,
    )


def _restore_persistent_agents(request: Request, sup: Any) -> None:
    """Respawn durable local agents from ``<workspace>/agents/roster.json``.

    The roster is operator-editable runtime state, so every ``identity_file``
    read from it is validated against ``AgentRoster`` before the supervisor is
    allowed to load a key from disk.
    """
    ws = _state_workspace(request)
    node_identity = _state_node_identity(request)
    cap_tokens_store = _state_cap_tokens_store(request)
    if (
        ws is None or node_identity is None
        or not getattr(node_identity, "can_sign", False)
        or cap_tokens_store is None
    ):
        return
    from .agent_roster import AgentRoster
    roster = AgentRoster(ws)
    entries = roster.migrate_legacy_slots()
    if not entries:
        return
    selected = [entry for entry in entries if entry.get("enabled", True) is not False]
    issuer = _make_cap_issuer(node_identity, cap_tokens_store)
    restored = 0
    for e in selected:
        idf = e.get("identity_file")
        if not isinstance(idf, str) or not idf:
            continue
        if not roster.is_owned_identity_file(idf):
            logger.warning(
                "v2_api: ignoring unsafe persistent-agent identity_file for did=%s",
                str(e.get("did", "?"))[:24],
            )
            continue
        if not Path(idf).is_file():
            continue
        try:
            from .agent_supervisor import resolve_work_scope

            workdir_value = e.get("project_workdir")
            scope = resolve_work_scope(
                str(workdir_value) if workdir_value else None,
                str(e.get("work_access", "workspace-write")),
            )
            previous_revision = str(e.get("work_revision", "") or "")
            if (
                previous_revision and scope.revision
                and previous_revision != scope.revision
            ):
                logger.warning(
                    "v2_api: persistent Agent work scope revision changed "
                    "for did=%s (%s -> %s)",
                    str(e.get("did", "?"))[:24],
                    previous_revision[:12],
                    scope.revision[:12],
                )
            sup.spawn(
                kind=str(e.get("kind", "mock")),
                label=str(e.get("label", "")),
                capabilities=list(e.get("capabilities") or []),
                cap_token_issuer=issuer,
                identity_file=idf,
                work_scope=scope,
            )
            restored += 1
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "v2_api: restore agent failed (did=%s): %s",
                str(e.get("did", "?"))[:24],
                exc,
            )
    if restored:
        logger.info("v2_api: restored %d persistent agent(s) from roster", restored)


class SpawnAgentBody(_Model):
    """POST /api/v2/agents/spawn request body."""

    kind: str = Field(
        ...,
        description=(
            "Backend kind label. One of: 'mock', 'claude-code', "
            "'codex', 'hermes'. Phase 3g/4 debt R1: validated at the "
            "HTTP boundary against ``dummy_agent.KNOWN_BACKEND_KINDS`` "
            "so a typo (e.g. 'clude-code') 422s here instead of "
            "silently being demoted to mock by the child's "
            "fallback path."
        ),
    )

    @field_validator("kind")
    @classmethod
    def _validate_kind(cls, v: str) -> str:
        # Lazy import — avoids a top-level dummy_agent import cycle
        # (dummy_agent is the child runtime; v2_api is the hub). The
        # constant lives next to ``_resolve_ask_backend`` so the
        # single source of truth is co-located with the dispatcher.
        from nth_dao.web.dummy_agent import KNOWN_BACKEND_KINDS
        if v not in KNOWN_BACKEND_KINDS:
            raise ValueError(
                f"unknown backend kind {v!r}; must be one of "
                f"{sorted(KNOWN_BACKEND_KINDS)!r}. The child's "
                "fallback to ``mock`` for unknown kinds is defensive "
                "only — operator input should fail clearly here."
            )
        return v

    label: str = Field(
        default="",
        description="Human-readable name; defaults to kind if empty.",
    )
    capabilities: List[str] = Field(
        default_factory=list,
        description=(
            "Capabilities the spawned agent should be granted via its "
            "cap_token. Unknown caps (not in cap_token.KNOWN_CAPABILITIES) "
            "are silently dropped; nth:receipt_sign is always added so "
            "the agent can sign receipts even with an empty request."
        ),
    )
    scope_model_allowlist: Optional[List[str]] = Field(
        default=None,
        description=(
            "Phase 6b: optional per-token model scope for "
            "`params['model']` overrides on `/a2a/ask` and "
            "`/a2a/ask-stream`. Wire-field name matches the signed "
            "token body (`scope_model_allowlist`) so HTTP request "
            "and on-disk audit record use the same vocabulary "
            "(I-8 R2 fix). Semantics by value:\n"
            "  • null   — token carries no per-token model scope; "
            "the A2A handler defers to the backend's MODEL_ALLOWLIST.\n"
            "  • []     — token forbids all `params['model']` "
            "OVERRIDES. NOTE (I-2 R2): this does NOT restrict the "
            "backend's DEFAULT_MODEL — peers asking with no "
            "`params['model']` still get the operator-chosen default. "
            "Use `_AskBackend.DEFAULT_MODEL` to set the cost floor.\n"
            "  • [...]  — token allows only these models. Combined "
            "with the backend's MODEL_ALLOWLIST as an intersection "
            "(the token scope can narrow, never widen).\n"
            "Operators issue different lists to different peers to "
            "give per-peer cost ceilings instead of one operator-wide "
            "policy."
        ),
    )
    persist: bool = Field(
        default=True,
        description=(
            "Persist the local agent in <workspace>/agents/roster.json and "
            "store its private identity under agents/identities. On hub "
            "restart the agent is respawned with the same DID. Stop removes "
            "the roster row so it will not be restored. false keeps the "
            "legacy ephemeral behavior."
        ),
    )
    project_workdir: Optional[str] = Field(
        default=None,
        description=(
            "Absolute project root assigned to this Agent. null uses the "
            "operator's NTH_AGENT_WORKDIR; an empty effective value uses an "
            "isolated per-Agent sandbox."
        ),
    )
    work_access: str = Field(
        default="workspace-write",
        description="Filesystem policy: read-only or workspace-write.",
    )
    @field_validator("work_access")
    @classmethod
    def _validate_work_access(cls, value: str) -> str:
        normalized = str(value or "").strip().lower()
        if normalized not in {"read-only", "workspace-write"}:
            raise ValueError("work_access must be read-only or workspace-write")
        return normalized


class AnnounceTaskBody(_Model):
    """POST /api/v2/market/announce 请求体:往任务市场发一条公告。"""

    title: str = Field(..., description="任务标题(必填)。")
    description: str = Field(default="", description="任务详述。")
    listing_type: str = Field(default="task")
    capability_set: List[str] = Field(
        default_factory=list,
        description="认领方需具备的能力(空=无能力门槛,任意 agent 可认领)。",
    )
    reward_minor: int = Field(
        default=0, ge=0,
        description="赏金,整数最小单位(禁 float,与 receipt 经济字段一致)。",
    )
    reward_asset: str = Field(default="credit", description="赏金资产类型。")
    context: str = Field(default="general", description="任务上下文/分类。")
    mission_id: str = Field(default="", description="关联的上层 Mission(可选)。")
    not_after: int = Field(
        default=0, ge=0,
        description="过期时间(epoch ms);0=不过期。",
    )


class AnnounceTradeOfferBody(_Model):
    """Optional discovery metadata for one already-signed Trade Offer."""

    capability_set: List[str] = Field(default_factory=list, max_length=32)
    availability_summary: Dict[str, Any] = Field(default_factory=dict)
    discovery_ttl_seconds: int = Field(
        default=24 * 60 * 60,
        ge=60,
        le=24 * 60 * 60,
    )


class MarketResourceLegBody(_Model):
    """Declarative resource input for the human-facing Market publisher."""

    model_config = {"extra": "forbid"}
    leg_id: str = Field(min_length=1, max_length=64)
    category: str = Field(default="other", min_length=1, max_length=32)
    resource_type: str = Field(min_length=1, max_length=160)
    resource_id: str = Field(min_length=3, max_length=512)
    quantity: str = Field(default="1", min_length=1, max_length=80)
    unit: str = Field(default="item", min_length=1, max_length=80)
    profile_rule_id: str = Field(default="", max_length=190)
    profile_digest: str = Field(default="", max_length=71)
    attributes: Dict[str, Any] = Field(default_factory=dict)


class MarketResourceProfileImportBody(_Model):
    """One already-signed declarative Resource Profile document."""

    model_config = {"extra": "forbid"}
    document: Dict[str, Any]


class MarketResourceProfileRecognitionBody(_Model):
    """Explicit local recognition decision with retry-safe request identity."""

    model_config = {"extra": "forbid"}
    accepted: bool
    idempotency_key: str = Field(
        min_length=16,
        max_length=128,
        pattern=r"^[A-Za-z0-9._:-]+$",
    )


class MarketTradeRuleRefBody(_Model):
    """Exact optional Trade Rule Package reference selected by the publisher."""

    model_config = {"extra": "forbid"}
    rule_id: str = Field(min_length=3, max_length=160)
    digest: str = Field(min_length=71, max_length=71)


class PublishMarketOfferBody(_Model):
    """Console-authored input that this node converts into a signed TradeOffer."""

    model_config = {"extra": "forbid"}
    idempotency_key: str = Field(min_length=16, max_length=128)
    intent: str = Field(default="provide", min_length=1, max_length=16)
    category: str = Field(default="other", min_length=1, max_length=32)
    title: str = Field(min_length=1, max_length=160)
    summary: str = Field(default="", max_length=2_000)
    provides: List[MarketResourceLegBody] = Field(min_length=1, max_length=8)
    requests: List[MarketResourceLegBody] = Field(default_factory=list, max_length=8)
    rule_refs: List[MarketTradeRuleRefBody] = Field(
        default_factory=list,
        max_length=32,
    )
    capability_set: List[str] = Field(default_factory=list, max_length=32)
    offer_validity_seconds: int = Field(
        default=30 * 24 * 60 * 60,
        ge=60 * 60,
        le=365 * 24 * 60 * 60,
    )
    discovery_ttl_seconds: int = Field(
        default=24 * 60 * 60,
        ge=60,
        le=24 * 60 * 60,
    )


class ImportTradeRulePackageBody(_Model):
    """Operator-selected peer for an exact Order-bound Rule Package import."""
    model_config = {"extra": "forbid"}
    peer_url: str = Field(min_length=1, max_length=2048)


class AnnounceStepBody(_Model):
    """POST .../missions/{mid}/steps/{sid}/announce 请求体:把 mission step
    发成可认领的市场 Task(Mission↔Task 之桥)。能力/标题/描述取自 step,
    赏金由操作员在发布时设定。"""
    reward_minor: int = Field(
        default=0, ge=0, description="赏金,整数最小单位(禁 float)。"
    )
    reward_asset: str = Field(default="credit", description="赏金资产类型。")


class ClaimTaskBody(_Model):
    """POST /api/v2/market/{ann_id}/claim 请求体:操作员选某个 supervised
    agent 去认领。hub 给该 agent 按需铸 cap_token(能力=任务所需),派发给
    agent,由 agent 用**自己的私钥**签认领收据(谁干谁签)。"""

    agent_did: str = Field(
        ..., description="去认领的 supervised agent 的 DID(与 ask 同款按 DID 寻址)。"
    )


# ─────────────────────────────────────────────────────────────
# Phase 3e: small helpers shared by the A2A POST proxy
# ─────────────────────────────────────────────────────────────


def _proxy_ssestream(
    *,
    url: str,
    body_bytes: bytes,
    req_headers: Dict[str, str],
    forward_timeout: float,
) -> Any:
    """Phase 5.2f (deferred backlog, refactored to httpx + native
    async): forward an SSE response from the child to the operator's
    browser.

    Replaces the old daemon-thread + ``urllib`` + ``queue.Queue``
    bridge with a single async generator using ``httpx.AsyncClient``.
    Key wins:

      • Native consumer-cancel handling. When the operator's browser
        disconnects, FastAPI cancels the async generator → the
        ``async with client.stream(...)`` block exits → httpx closes
        the upstream connection in finally → no urllib leak. The old
        5s consumer-gone timeout + bounded queue + sentinel
        choreography is gone (it was *our* invention to bridge sync
        IO into async; httpx does this natively).
      • One coroutine per request instead of one daemon thread.
        Sub-100KB memory + no GIL ping-pong.
      • Backpressure for free: the async generator yields one chunk
        at a time; if the StreamingResponse can't push it downstream
        the coroutine blocks, which back-pressures the upstream
        ``aiter_bytes`` iterator, which back-pressures the
        provider's TCP window — the right behavior, no extra code.

    Preserved invariants from the original:
      • Error envelope on non-200 upstream: emits one terminal
        ``data: {"error": {"code": "upstream-<N>", "message": <text>}}``
        event then closes.
      • 4KB cap on upstream error body so a misbehaving child can't
        blast a multi-MB blob into the operator's browser buffer.
      • SSE-correct response headers (``no-cache`` / ``Connection:
        close`` / ``X-Accel-Buffering: no``).

    Deleted invariant (no longer needed):
      • The old consumer-gone timeout test (5s queue-full bailout)
        is irrelevant — there is no queue and no thread to leak.
    """
    import httpx
    from starlette.responses import StreamingResponse

    # 4KB cap matches the old M-2 / L-2 fix on error-body reads —
    # a misbehaving child can't blast multi-MB error blobs through.
    _ERR_BODY_CAP = 4096

    def _error_event(code: str, message: str) -> bytes:
        return (
            b"data: "
            + json.dumps({"error": {"code": code, "message": message}}).encode(
                "utf-8",
            )
            + b"\n\n"
        )

    async def _gen():
        try:
            async with httpx.AsyncClient(timeout=forward_timeout) as client:
                async with client.stream(
                    "POST", url, content=body_bytes, headers=req_headers,
                ) as resp:
                    if resp.status_code != 200:
                        body = bytearray()
                        async for chunk in resp.aiter_bytes():
                            remaining = _ERR_BODY_CAP - len(body)
                            if remaining <= 0:
                                break
                            body.extend(chunk[:remaining])
                        yield _error_event(
                            f"upstream-{resp.status_code}",
                            bytes(body).decode(
                                "utf-8", errors="replace",
                            ),
                        )
                        return
                    # aiter_bytes yields each chunk httpx receives. No
                    # forced 1KB read size — we hand them up the SSE
                    # pipe at whatever granularity the child emitted,
                    # preserving event boundaries.
                    streamed = 0
                    async for chunk in resp.aiter_bytes():
                        if streamed + len(chunk) > _MAX_LOCAL_A2A_HTTP_RESPONSE_BYTES:
                            yield _error_event(
                                "response-too-large",
                                (
                                    "streamed A2A response exceeds "
                                    f"{_MAX_LOCAL_A2A_HTTP_RESPONSE_BYTES} bytes; "
                                    "return a summary and artifact reference"
                                ),
                            )
                            return
                        streamed += len(chunk)
                        yield chunk
        except httpx.TimeoutException as exc:
            yield _error_event(
                "proxy-failed", f"TimeoutException: {exc}",
            )
        except httpx.HTTPError as exc:
            yield _error_event(
                "proxy-failed", f"{type(exc).__name__}: {exc}",
            )
        except OSError as exc:
            # Realistic socket-layer failures that escape httpx's
            # wrappers (Windows ConnectionAbortedError, etc.) still
            # need a clean envelope.
            yield _error_event(
                "proxy-failed", f"{type(exc).__name__}: {exc}",
            )

    return StreamingResponse(
        _gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "close",
            # Hint to browsers / proxies not to buffer.
            "X-Accel-Buffering": "no",
        },
    )


def _sanitize_replacement_chars(value: Any) -> Any:
    """Remove U+FFFD from child diagnostics without changing JSON shape."""
    if isinstance(value, str):
        if (
            "claude CLI crashed with ACCESS_VIOLATION" in value
            and "0xC0000005" in value
        ):
            return (
                "RuntimeError: claude CLI crashed with ACCESS_VIOLATION "
                "(0xC0000005) - known Windows + piped-stdout quirk in "
                "claude.exe. Use kind=mock for this agent until a ConPTY "
                "wrapper lands."
            )
        return value.replace("\ufffd", "-")
    if isinstance(value, list):
        return [_sanitize_replacement_chars(v) for v in value]
    if isinstance(value, dict):
        return {k: _sanitize_replacement_chars(v) for k, v in value.items()}
    return value


def _decode_or_passthrough(raw: bytes) -> Any:
    """Decode JSON bytes; on failure return ``{raw_text: <str>}``
    so the caller still gets SOMETHING readable instead of a 500.
    """
    try:
        return _sanitize_replacement_chars(json.loads(raw.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError):
        # Truncate for safety — a 1MB binary blob in the JSON
        # response would be wasteful.
        text = raw[:1024].decode("utf-8", errors="replace")
        return {
            "raw_text_preview": _sanitize_replacement_chars(text),
            "raw_length": len(raw),
            "note": "child returned non-JSON; preview truncated to 1KB",
        }


_MAX_LOCAL_A2A_HTTP_RESPONSE_BYTES = 2 * 1024 * 1024


class A2AResponseTooLarge(RuntimeError):
    """A supervised child exceeded the bounded hub response envelope."""


def _read_local_a2a_body(
    response: Any, *, limit: int = _MAX_LOCAL_A2A_HTTP_RESPONSE_BYTES,
) -> bytes:
    """Read at most one bounded local A2A response into hub memory."""
    raw = response.read(limit + 1)
    if len(raw) > limit:
        raise A2AResponseTooLarge(
            f"local A2A response exceeds {limit} bytes; return a summary and artifact reference"
        )
    return raw


def _bound_agent_result_projection(content: Any) -> Any:
    """Bound a successful Agent response after its full receipt is verified."""
    if not isinstance(content, dict):
        return content
    result = content.get("result")
    if not isinstance(result, dict) or "response" not in result:
        return content
    from .agent_link import bound_agent_response

    response, truncated = bound_agent_response(result.get("response", ""))
    if not truncated and not result.get("response_truncated"):
        return content
    bounded_result = dict(result)
    bounded_result["response"] = response
    bounded_result["response_truncated"] = True
    bounded = dict(content)
    bounded["result"] = bounded_result
    return bounded


def _state_cap_tokens_store(request: Request) -> Optional[Any]:
    """CapTokenStore from app.state.nth.cap_tokens. Returns None if
    the workspace hasn't been bootstrapped (mirrors the pattern of
    _state_receipts_store + _state_node_identity)."""
    try:
        return request.app.state.nth.cap_tokens
    except AttributeError:
        return None


def _state_workspace(request: Request) -> Optional[Path]:
    """Pull the active workspace path from app.state if present.

    Same observability note as _state_blackboard above. """
    try:
        return Path(request.app.state.nth.workspace)
    except (AttributeError, TypeError):
        logger.warning(
            "v2_api: app.state.nth.workspace unavailable — "
            "disk readers will fall through to repo fixtures.",
        )
        return None


def _state_trade_offer_store(request: Request) -> Optional[Any]:
    try:
        return request.app.state.nth.trade_offers
    except AttributeError:
        return None


def _state_trade_rule_package_store(request: Request) -> Optional[Any]:
    try:
        return request.app.state.nth.trade_rule_packages
    except AttributeError:
        return None


def _state_trade_execution_coordinator(request: Request) -> Optional[Any]:
    try:
        return request.app.state.nth.trade_execution_coordinator
    except AttributeError:
        return None


def _state_trade_proposal_audit(request: Request) -> Optional[Any]:
    try:
        return request.app.state.nth.trade_proposal_audit
    except AttributeError:
        return None


def _state_trade_proposal_delivery_limiter(request: Request) -> Optional[Any]:
    try:
        return request.app.state.nth.trade_proposal_delivery_limiter
    except AttributeError:
        return None


def _state_trade_proposal_delivery_global_limiter(
    request: Request,
) -> Optional[Any]:
    try:
        return request.app.state.nth.trade_proposal_delivery_global_limiter
    except AttributeError:
        return None


def _state_trade_order_intake(request: Request) -> Optional[Any]:
    try:
        return request.app.state.nth.trade_order_intake
    except AttributeError:
        return None


def _state_trade_order_audit(request: Request) -> Optional[Any]:
    try:
        return request.app.state.nth.trade_order_audit
    except AttributeError:
        return None


def _state_trade_order_audit_outbox(request: Request) -> Optional[Any]:
    try:
        return request.app.state.nth.trade_order_audit_outbox
    except AttributeError:
        return None


def _state_trade_order_dispatch(request: Request) -> Optional[Any]:
    try:
        return request.app.state.nth.trade_order_dispatch
    except AttributeError:
        return None


def _state_trade_order_dispatch_store(request: Request) -> Optional[Any]:
    try:
        return request.app.state.nth.trade_order_dispatch_store
    except AttributeError:
        return None


def _state_trade_order_delivery_limiter(request: Request) -> Optional[Any]:
    try:
        return request.app.state.nth.trade_order_delivery_limiter
    except AttributeError:
        return None


def _state_trade_order_delivery_global_limiter(
    request: Request,
) -> Optional[Any]:
    try:
        return request.app.state.nth.trade_order_delivery_global_limiter
    except AttributeError:
        return None


def _state_trade_rule_recognition_audit(
    request: Request,
) -> Optional[Any]:
    try:
        return request.app.state.nth.trade_rule_recognition_audit
    except AttributeError:
        return None


def _state_trade_rule_recognition_policy_audit(
    request: Request,
) -> Optional[Any]:
    try:
        return request.app.state.nth.trade_rule_recognition_policy_audit
    except AttributeError:
        return None


_CANONICAL_UTC_QUERY = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{6}))?Z$"
)


def _parse_canonical_utc_query(value: str | None) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 35:
        raise ValueError("at must be a canonical UTC RFC3339 timestamp")
    match = _CANONICAL_UTC_QUERY.fullmatch(value)
    if match is None or match.group(2) == "000000":
        raise ValueError("at must be a canonical UTC RFC3339 timestamp")
    fraction = match.group(2)
    try:
        return datetime.strptime(
            match.group(1) + (f".{fraction}" if fraction else ""),
            "%Y-%m-%dT%H:%M:%S.%f" if fraction else "%Y-%m-%dT%H:%M:%S",
        ).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValueError("at must be a real UTC RFC3339 timestamp") from exc


def _load_trade_rule_package(request: Request, digest: str) -> Any:
    from nth_dao.trade_rules import RulePackageError

    store = _state_trade_rule_package_store(request)
    if store is None:
        raise HTTPException(
            status_code=503,
            detail="trade rule package store unavailable",
        )
    try:
        package = store.load(digest)
    except ValueError as exc:
        logger.warning(
            "Trade Rule Package lookup rejected %s: %s",
            digest,
            exc,
        )
        raise HTTPException(
            status_code=400,
            detail="trade rule package digest is invalid",
        ) from exc
    except RulePackageError as exc:
        logger.error(
            "Trade Rule Package integrity failure for %s (%s): %s",
            digest,
            type(exc).__name__,
            exc,
        )
        raise HTTPException(
            status_code=503,
            detail="trade rule package integrity failure",
        ) from exc
    if package is None:
        raise HTTPException(
            status_code=404,
            detail="trade rule package not found",
        )
    return package


def _trade_rule_package_catalog_item(
    package: Any,
    *,
    include_manifest: bool,
    import_audit: Dict[str, Any],
    provenance_sources: tuple[str, ...],
) -> Dict[str, Any]:
    """Project verified Package metadata without exposing resource bodies.

    ``RulePackageStore.load`` has already replayed the publisher signature and
    every declared resource digest.  The projection deliberately says nothing
    about social trust or execution authority; those are separate, current
    local-policy decisions.
    """

    document = package.manifest.to_dict()
    resources = document["resources"]
    result: Dict[str, Any] = {
        "package_digest": package.digest,
        "rule_id": document["rule_id"],
        "version": document["version"],
        "publisher_did": document["publisher_did"],
        "summary": document["summary"],
        "applies_to": list(document["applies_to"]),
        "families": list(document["families"]),
        "published_at": document["published_at"],
        "not_after": document["not_after"],
        "execution": {
            "mode": document["execution"]["mode"],
            "permissions": list(document["execution"]["permissions"]),
        },
        "required_capabilities": list(document["required_capabilities"]),
        "resource_count": len(resources),
        "resource_bytes": sum(len(payload) for payload in package.resources.values()),
        "dependency_count": len(document["dependencies"]),
        "conflict_count": len(document["conflicts"]),
        "verification": {
            "status": "verified-cache",
            "publisher_signature": True,
            "resource_digests": True,
        },
        "import_audit": import_audit,
        "provenance": {
            "status": "explicit" if provenance_sources else "unclassified",
            "sources": list(provenance_sources),
        },
        "trust": {
            "status": "not-evaluated",
            "advisory": True,
            "execution_authorized": False,
        },
    }
    if include_manifest:
        result["manifest"] = document
    return result


def _validated_trade_rule_package_import_binding(
    event_type: str,
    payload: Any,
) -> tuple[str, str, str, tuple[str, str, str, str]]:
    """Return a verified semantic binding from one import-audit payload."""

    expected_actions = {
        "trade.rule-package.import.proposed": "verified-cache-import-proposed",
        "trade.rule-package.imported": "verified-cache-import",
    }
    expected_fields = {
        "import_id",
        "order_digest",
        "offer_digest",
        "package_digest",
        "rule_id",
        "package_publisher_did",
        "source_origin",
        "action",
    }
    if event_type not in expected_actions:
        raise RuntimeError("Trade Rule Package import audit type is invalid")
    if not isinstance(payload, dict) or set(payload) != expected_fields:
        raise RuntimeError("Trade Rule Package import audit payload is invalid")
    order_digest = payload.get("order_digest")
    offer_digest = payload.get("offer_digest")
    package_digest = payload.get("package_digest")
    import_id = payload.get("import_id")
    rule_id = payload.get("rule_id")
    publisher_did = payload.get("package_publisher_did")
    source_origin = payload.get("source_origin")
    try:
        from nth_dao.did_key import is_did_key

        parsed_origin = urlsplit(source_origin) if isinstance(source_origin, str) else None
        valid_origin = bool(
            parsed_origin is not None
            and parsed_origin.scheme in {"http", "https"}
            and parsed_origin.hostname
            and not parsed_origin.username
            and not parsed_origin.password
            and parsed_origin.path == ""
            and not parsed_origin.query
            and not parsed_origin.fragment
            and source_origin
            == f"{parsed_origin.scheme}://{parsed_origin.netloc}"
        )
    except (TypeError, ValueError):
        valid_origin = False
    if (
        not isinstance(order_digest, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", order_digest) is None
        or not isinstance(offer_digest, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", offer_digest) is None
        or not isinstance(package_digest, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", package_digest) is None
        or not isinstance(import_id, str)
        or re.fullmatch(r"[0-9a-f]{64}", import_id) is None
        or not isinstance(rule_id, str)
        or not 3 <= len(rule_id) <= 160
        or not isinstance(publisher_did, str)
        or not is_did_key(publisher_did)
        or not valid_origin
        or payload.get("action") != expected_actions[event_type]
        or import_id != _trade_rule_package_import_id(
            order_digest=order_digest,
            package_digest=package_digest,
        )
    ):
        raise RuntimeError("Trade Rule Package import audit binding is invalid")
    return (
        order_digest,
        package_digest,
        import_id,
        (offer_digest, rule_id, publisher_did, source_origin),
    )


def _trade_rule_package_import_audit_records(
    events: tuple[Any, ...],
) -> Dict[str, Dict[str, Dict[str, tuple[str, str, str, str]]]]:
    """Parse one verified Spine snapshot into immutable import bindings."""

    states: Dict[str, Dict[str, Dict[str, tuple[str, str, str, str]]]] = {}
    for event in events:
        if event.type not in {
            "trade.rule-package.import.proposed",
            "trade.rule-package.imported",
        }:
            continue
        _order_digest, package_digest, import_id, binding = (
            _validated_trade_rule_package_import_binding(
                event.type,
                event.payload,
            )
        )
        state = states.setdefault(
            package_digest,
            {"proposed": {}, "anchored": {}},
        )
        target = "proposed" if event.type.endswith(".proposed") else "anchored"
        if import_id in state[target]:
            raise RuntimeError(
                "Trade Rule Package import audit contains a duplicate semantic event"
            )
        state[target][import_id] = binding
    return states


def _trade_rule_package_import_audit_index_from_records(
    states: Dict[str, Dict[str, Dict[str, tuple[str, str, str, str]]]],
) -> Dict[str, Dict[str, Any]]:
    """Derive bounded UI summaries from already-verified import bindings."""

    output: Dict[str, Dict[str, Any]] = {}
    for package_digest, state in states.items():
        proposed = state["proposed"]
        anchored = state["anchored"]
        if anchored.keys() - proposed.keys():
            raise RuntimeError(
                "Trade Rule Package import audit is missing its write-ahead intent"
            )
        for import_id in anchored.keys() & proposed.keys():
            if anchored[import_id] != proposed[import_id]:
                raise RuntimeError(
                    "Trade Rule Package import audit binding conflicts across stages"
                )
        incomplete = proposed.keys() - anchored.keys()
        status = (
            "mixed"
            if anchored and incomplete
            else "incomplete"
            if incomplete
            else "anchored"
            if anchored
            else "not-applicable"
        )
        output[package_digest] = {
            "status": status,
            "proposed_count": len(proposed),
            "anchored_count": len(anchored),
            "incomplete_count": len(incomplete),
        }
    return output


def _trade_rule_package_import_audit_index(spine: Any) -> Dict[str, Dict[str, Any]]:
    """Build a bounded semantic summary from one verified Spine snapshot."""

    return _trade_rule_package_import_audit_index_from_records(
        _trade_rule_package_import_audit_records(spine.verified_snapshot())
    )


def _no_trade_rule_package_import_audit() -> Dict[str, Any]:
    return {
        "status": "not-applicable",
        "proposed_count": 0,
        "anchored_count": 0,
        "incomplete_count": 0,
    }


def _load_public_trade_rule_package(
    request: Request,
    *,
    offer_digest: str,
    package_digest: str,
) -> Any:
    """Resolve one package only through a currently public local Offer."""

    from nth_dao.trade_rules import OfferStoreError, RulePackageError

    _require_trade_offer_digest(offer_digest)
    _require_trade_offer_digest(package_digest)
    _require_trade_offer_public_read_budget(request)
    offer_store = _state_trade_offer_store(request)
    package_store = _state_trade_rule_package_store(request)
    identity = _state_node_identity(request)
    if offer_store is None or package_store is None or identity is None:
        raise HTTPException(status_code=503, detail="trade package service unavailable")
    try:
        feed = _state_market_feed(request)
        announcement = feed.find_live_trade_offer_announcement(offer_digest)
        if announcement is None:
            raise HTTPException(status_code=404, detail="announced Offer not found")
        feed.require_listing_binding(announcement)
        offer = offer_store.get(offer_digest)
        if offer is None or offer.publisher_did != identity.as_did():
            raise HTTPException(status_code=404, detail="announced Offer not found")
        _verify_trade_offer_spine_anchors(request, offer_store)
        roots = sorted({
            item["digest"] for item in offer.to_dict()["rule_refs"]
        })
        pending = list(roots)
        visited: set[str] = set()
        while pending:
            current = pending.pop(0)
            if current in visited:
                continue
            visited.add(current)
            if len(visited) > 128:
                raise HTTPException(
                    status_code=503,
                    detail="announced Rule Package dependency closure exceeds limit",
                )
            package = package_store.load(current)
            if package is None:
                if current == package_digest:
                    raise HTTPException(
                        status_code=503,
                        detail="announced Rule Package dependency is unavailable",
                    )
                # One unavailable sibling branch must not suppress an exact,
                # intact package from the same signed Offer. Readiness still
                # fails closed later when the complete rule set is resolved.
                continue
            if current == package_digest:
                return package, offer
            dependencies = package.manifest.to_dict()["dependencies"]
            pending.extend(sorted(
                item["digest"]
                for item in dependencies
                if item["digest"] not in visited
            ))
    except HTTPException:
        raise
    except (OfferStoreError, RulePackageError, OSError, RuntimeError, ValueError) as exc:
        raise HTTPException(
            status_code=503,
            detail="public Rule Package integrity verification failed",
        ) from exc
    raise HTTPException(
        status_code=404,
        detail="Rule Package is not referenced by the announced Offer",
    )


def _fetch_trade_rule_package_from_peer(
    peer_url: str,
    *,
    offer_digest: str,
    package_digest: str,
    offer_publisher_did: str,
    timeout_seconds: float = 15.0,
) -> Any:
    """Fetch one exact package bundle over a DNS-pinned bounded connection."""

    from nth_dao.trade_rules import (
        MAX_RULE_PACKAGE_BUNDLE_BYTES,
        parse_rule_package_bundle,
    )
    from nth_dao.web.market_federation_poll import _urllib_get_bytes_pinned

    normalized = _normalize_configured_fed_peer(peer_url)
    path = (
        "/api/v2/trade/federation/offers/"
        f"{quote(offer_digest, safe='')}/rule-packages/"
        f"{quote(package_digest, safe='')}"
    )
    url = normalized + path
    raw = _call_operator_trade_peer_with_fallback(
        normalized,
        lambda resolved_ip, remaining: _urllib_get_bytes_pinned(
            url,
            resolved_ip,
            timeout_s=remaining,
            max_bytes=MAX_RULE_PACKAGE_BUNDLE_BYTES,
        ),
        timeout_seconds=timeout_seconds,
    )
    return parse_rule_package_bundle(
        raw,
        expected_offer_digest=offer_digest,
        expected_package_digest=package_digest,
        expected_offer_publisher_did=offer_publisher_did,
    )


def _fetch_trade_rule_recognition_proof_from_peer(
    peer_url: str,
    *,
    offer_digest: str,
    package: Any,
    offer_publisher_did: str,
    timeout_seconds: float = 15.0,
) -> Any:
    """Fetch one bounded observed Recognition graph over a pinned connection."""

    from nth_dao.trade_rules import (
        MAX_TRADE_JSON_BYTES,
        parse_rule_recognition_proof_bundle,
    )
    from nth_dao.web.market_federation_poll import _urllib_get_bytes_pinned

    normalized = _normalize_configured_fed_peer(peer_url)
    path = (
        "/api/v2/trade/federation/offers/"
        f"{quote(offer_digest, safe='')}/rule-packages/"
        f"{quote(package.digest, safe='')}/recognition-proof"
    )
    raw = _call_operator_trade_peer_with_fallback(
        normalized,
        lambda resolved_ip, remaining: _urllib_get_bytes_pinned(
            normalized + path,
            resolved_ip,
            timeout_s=remaining,
            max_bytes=MAX_TRADE_JSON_BYTES,
        ),
        timeout_seconds=timeout_seconds,
    )
    return parse_rule_recognition_proof_bundle(
        raw,
        package=package,
        expected_offer_digest=offer_digest,
        expected_offer_publisher_did=offer_publisher_did,
    )


def _fetch_trade_rule_recognition_proof_pages_from_peer(
    peer_url: str,
    *,
    offer_digest: str,
    package: Any,
    offer_publisher_did: str,
    timeout_seconds: float = 15.0,
) -> Any:
    """Fetch one complete proof page set from one DNS-pinned peer address."""

    from nth_dao.trade_rules import (
        MAX_RULE_RECOGNITION_PROOF_PAGE_BYTES,
        VerifiedRuleRecognitionProofPage,
        parse_rule_recognition_proof_pages,
    )
    from nth_dao.web.market_federation_poll import _urllib_get_bytes_pinned

    normalized = _normalize_configured_fed_peer(peer_url)
    path = (
        "/api/v2/trade/federation/offers/"
        f"{quote(offer_digest, safe='')}/rule-packages/"
        f"{quote(package.digest, safe='')}/recognition-proof-pages/"
    )

    def fetch_all(
        resolved_ip: str,
        remaining_seconds: float,
    ) -> tuple[bytes, ...]:
        deadline = time.monotonic() + remaining_seconds

        def fetch_page(page_index: int) -> bytes:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    "Rule Recognition proof page fetch deadline exceeded"
                )
            return _urllib_get_bytes_pinned(
                normalized + path + str(page_index),
                resolved_ip,
                timeout_s=remaining,
                max_bytes=MAX_RULE_RECOGNITION_PROOF_PAGE_BYTES,
            )

        first_raw = fetch_page(0)
        first_page = VerifiedRuleRecognitionProofPage.from_json(
            first_raw,
            package=package,
            expected_offer_digest=offer_digest,
            expected_offer_publisher_did=offer_publisher_did,
        )
        return (first_raw,) + tuple(
            fetch_page(page_index)
            for page_index in range(1, first_page.page_count)
        )

    raw_pages = _call_operator_trade_peer_with_fallback(
        normalized,
        fetch_all,
        timeout_seconds=timeout_seconds,
    )
    return parse_rule_recognition_proof_pages(
        raw_pages,
        package=package,
        expected_offer_digest=offer_digest,
        expected_offer_publisher_did=offer_publisher_did,
    )


def _parse_rule_recognition_proof_document(
    raw: bytes,
    *,
    package: Any,
    offer_digest: str,
    offer_publisher_did: str,
    now: datetime,
) -> Any:
    """Verify either a legacy bundle or one v2 page under one binding."""

    from nth_dao.trade_rules import (
        RULE_RECOGNITION_PROOF_PAGE_KIND,
        VerifiedRuleRecognitionProofPage,
        parse_rule_recognition_proof_bundle,
        parse_trade_json,
    )

    document = parse_trade_json(raw)
    if document.get("kind") == RULE_RECOGNITION_PROOF_PAGE_KIND:
        return VerifiedRuleRecognitionProofPage.from_dict(
            document,
            package=package,
            expected_offer_digest=offer_digest,
            expected_offer_publisher_did=offer_publisher_did,
            now=now,
        )
    return parse_rule_recognition_proof_bundle(
        document,
        package=package,
        expected_offer_digest=offer_digest,
        expected_offer_publisher_did=offer_publisher_did,
        now=now,
    )


def _load_order_bound_recognition_import_contexts(
    request: Request,
    *,
    order_digest: str,
    package_digests: tuple[str, ...],
) -> tuple[Path, Any, tuple[Any, ...], str, str]:
    """Resolve audited Recognition contexts with one shared Order lookup."""

    from nth_dao.trade_rules import TradeOffer, offer_digest

    _require_trade_offer_digest(order_digest)
    if not package_digests:
        raise HTTPException(status_code=400, detail="package digests are required")
    for package_digest in package_digests:
        _require_trade_offer_digest(package_digest)
    order_audit = _state_trade_order_audit(request)
    recognition_audit = _state_trade_rule_recognition_audit(request)
    package_store = _state_trade_rule_package_store(request)
    workspace = _state_workspace(request)
    spine = _state_spine(request)
    if (
        order_audit is None
        or recognition_audit is None
        or package_store is None
        or workspace is None
        or spine is None
    ):
        raise HTTPException(
            status_code=503,
            detail="Rule Recognition import unavailable",
        )
    record = order_audit.get_accepted(order_digest)
    if record is None:
        raise HTTPException(status_code=404, detail="Trade Order not found")
    order_document = record.order.to_dict()
    bindings = {
        item["digest"]: item["rule_id"]
        for item in order_document["rule_bindings"]
    }
    resolver = _OrderAuditedRulePackageResolver(
        package_store,
        spine,
        order_digest,
        workspace,
    )
    packages = []
    for package_digest in package_digests:
        if package_digest not in bindings:
            raise HTTPException(
                status_code=409,
                detail="Rule Package is not bound by this Trade Order",
            )
        package = resolver.load(package_digest)
        if package is None:
            raise HTTPException(
                status_code=409,
                detail=(
                    "Rule Package must be imported and audit-verified before "
                    "its Recognition evidence"
                ),
            )
        if package.manifest.rule_id != bindings[package_digest]:
            raise HTTPException(
                status_code=503,
                detail="Order-bound Rule Package identity is inconsistent",
            )
        packages.append(package)
    source_offer = TradeOffer.from_dict(order_document["snapshot"]["offer"])
    return (
        workspace,
        recognition_audit,
        tuple(packages),
        offer_digest(source_offer),
        source_offer.publisher_did,
    )


def _load_order_bound_recognition_import_context(
    request: Request,
    *,
    order_digest: str,
    package_digest: str,
) -> tuple[Path, Any, Any, str, str]:
    """Resolve one exact audited Order/Offer/Package import boundary."""

    workspace, recognition_audit, packages, source_offer_digest, publisher = (
        _load_order_bound_recognition_import_contexts(
            request,
            order_digest=order_digest,
            package_digests=(package_digest,),
        )
    )
    return (
        workspace,
        recognition_audit,
        packages[0],
        source_offer_digest,
        publisher,
    )


def _trade_rule_recognition_import_status_page(
    *,
    events: tuple[Any, ...],
    proof_store: Any,
    package: Any,
    order_digest: str,
    source_offer_digest: str,
    offer_publisher_did: str,
    limit: int,
) -> dict[str, Any]:
    """Project one bounded status page from a caller-verified Spine snapshot."""

    from nth_dao.trade_rules import (
        EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORT_PROPOSED,
        RuleRecognitionProofBundleRejected,
        RuleRecognitionProofImportError,
        recognition_proof_import_payload,
        recognition_proof_import_states,
    )

    states = recognition_proof_import_states(
        events,
        package_digest=package.digest,
        order_digest=order_digest,
    )
    items = []
    for state in states[-limit:]:
        evidence_status = "verified"
        try:
            raw = proof_store.get(state.payload["proof_digest"])
            proposed_at = datetime.fromtimestamp(
                state.proposed_event.ts_ms / 1000,
                tz=timezone.utc,
            )
            proof = _parse_rule_recognition_proof_document(
                raw,
                package=package,
                offer_digest=source_offer_digest,
                offer_publisher_did=offer_publisher_did,
                now=proposed_at,
            )
            expected = recognition_proof_import_payload(
                proof,
                event_type=EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORT_PROPOSED,
                order_digest=order_digest,
                offer_digest=source_offer_digest,
                source_origin=state.payload["source_origin"],
            )
            if expected != state.payload:
                evidence_status = "binding-mismatch"
        except (
            RuleRecognitionProofBundleRejected,
            RuleRecognitionProofImportError,
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
        ):
            evidence_status = "missing-or-corrupt"
        item = {
            "import_id": state.payload["import_id"],
            "status": (
                "completed" if state.completed_event is not None else "pending"
            ),
            "proof_digest": state.payload["proof_digest"],
            "observer_did": state.payload["observer_did"],
            "observed_heads_digest": state.payload["observed_heads_digest"],
            "source_origin": state.payload["source_origin"],
            "statement_count": len(state.payload["statement_digests"]),
            "evidence_status": evidence_status,
            "proposal_event_id": state.proposed_event.event_id,
            "completion_event_id": (
                state.completed_event.event_id
                if state.completed_event is not None
                else None
            ),
        }
        if state.payload["protocol_version"] == "2":
            item.update({
                "proof_protocol_version": "2",
                "observation_digest": state.payload["observation_digest"],
                "page_index": state.payload["page_index"],
                "page_count": state.payload["page_count"],
                "total_statement_count": state.payload["statement_count"],
                "statement_set_digest": state.payload["statement_set_digest"],
            })
        items.append(item)
    return {
        "order_digest": order_digest,
        "package_digest": package.digest,
        "total": len(states),
        "returned": len(items),
        "items": items,
    }


def _import_trade_rule_recognition_proof_singleflight(
    workspace: Path,
    coordinator: Any,
    *,
    order_digest: str,
    package: Any,
    peer_url: str,
    offer_digest: str,
    offer_publisher_did: str,
) -> tuple[Any, tuple[Any, ...], int, Any, bool]:
    """Thin HTTP adapter around the protocol-layer import transaction."""

    from nth_dao.trade_rules import (
        RuleRecognitionProofImportCoordinator,
        RuleRecognitionProofSetImportCommit,
    )

    source_origin = _trade_rule_package_source_origin(peer_url)
    service = RuleRecognitionProofImportCoordinator(workspace, coordinator)
    try:
        committed = service.import_or_recover(
            order_digest=order_digest,
            package=package,
            offer_digest=offer_digest,
            offer_publisher_did=offer_publisher_did,
            source_origin=source_origin,
            fetch_proof=lambda: _fetch_trade_rule_recognition_proof_from_peer(
                peer_url,
                offer_digest=offer_digest,
                package=package,
                offer_publisher_did=offer_publisher_did,
            ),
        )
    except urllib.error.HTTPError as exc:
        if exc.code not in {404, 409, 413, 422, 503}:
            raise
        committed = service.import_pages_or_recover(
            order_digest=order_digest,
            package=package,
            offer_digest=offer_digest,
            offer_publisher_did=offer_publisher_did,
            source_origin=source_origin,
            fetch_proof_set=lambda: (
                _fetch_trade_rule_recognition_proof_pages_from_peer(
                    peer_url,
                    offer_digest=offer_digest,
                    package=package,
                    offer_publisher_did=offer_publisher_did,
                )
            ),
        )
    if isinstance(committed, RuleRecognitionProofSetImportCommit):
        return (
            committed.proof_set,
            committed.imported,
            committed.reconciled_anchor_count,
            committed.page_audits,
            True,
        )
    return (
        committed.proof,
        committed.imported,
        committed.reconciled_anchor_count,
        committed.audit,
        False,
    )


def _trade_rule_recognition_import_response(
    *,
    proof: Any,
    imported: tuple[Any, ...],
    reconciled_anchor_count: int,
    import_audit: dict[str, Any],
    offer_digest: str,
    package: Any,
) -> dict[str, Any]:
    proof_digest = "sha256:" + hashlib.sha256(
        proof.canonical_bytes
    ).hexdigest()
    return {
        "status": "imported" if imported else "already-observed",
        "offer_digest": offer_digest,
        "package_digest": package.digest,
        "proof_digest": proof_digest,
        "observed_heads_digest": proof.observed_heads_digest,
        "import_id": import_audit["import_id"],
        "source_origin": import_audit["source_origin"],
        "import_proposal_event_id": import_audit["proposal_event_id"],
        "import_completion_event_id": import_audit["completion_event_id"],
        "observed_statement_count": proof.statement_count,
        "imported_statement_count": len(imported),
        "reconciled_anchor_count": reconciled_anchor_count,
        "imported_recognition_digests": [
            result.statement.digest for result in imported
        ],
        "audit_event_ids": [result.event.event_id for result in imported],
        "global_freshness_proven": False,
        "issuer_trust_granted": False,
        "local_policy_changed": False,
        "execution_authority_granted": False,
        "warning": (
            "The signed chains are observed evidence, not proof that a newer "
            "revocation does not exist. Import may affect advisory evaluation "
            "only for issuers already trusted by local policy."
        ),
    }


def _trade_rule_recognition_page_import_response(
    *,
    proof_set: Any,
    imported: tuple[Any, ...],
    reconciled_anchor_count: int,
    page_audits: tuple[dict[str, str], ...],
    offer_digest: str,
    package: Any,
) -> dict[str, Any]:
    return {
        "status": "imported" if imported else "already-observed",
        "proof_protocol_version": "2",
        "offer_digest": offer_digest,
        "package_digest": package.digest,
        "proof_digests": list(proof_set.proof_digests),
        "observation_digest": proof_set.observation_digest,
        "observed_heads_digest": proof_set.graph_heads_digest,
        "page_count": len(proof_set.pages),
        "page_imports": list(page_audits),
        "observed_statement_count": len(proof_set.statements),
        "imported_statement_count": len(imported),
        "reconciled_anchor_count": reconciled_anchor_count,
        "imported_recognition_digests": [
            result.statement.digest for result in imported
        ],
        "audit_event_ids": [result.event.event_id for result in imported],
        "global_freshness_proven": False,
        "issuer_trust_granted": False,
        "local_policy_changed": False,
        "execution_authority_granted": False,
        "warning": (
            "The signed chains are observed evidence, not proof that a newer "
            "revocation does not exist. Import may affect advisory evaluation "
            "only for issuers already trusted by local policy."
        ),
    }


class TradeRulePackageImportBusy(RuntimeError):
    """Another process is currently importing the same content digest."""


class TradeRulePackageImportAuditError(RuntimeError):
    """The package cache is valid but its signed import audit is incomplete."""


_TRADE_RULE_PACKAGE_IMPORT_MAX_CONCURRENCY = 2


@contextmanager
def _trade_rule_package_import_slot(workspace: Path) -> Iterator[None]:
    """Reserve one crash-safe import slot shared by all local processes."""

    slot_root = workspace / "trade" / "rule_package_import_slots"
    for index in range(_TRADE_RULE_PACKAGE_IMPORT_MAX_CONCURRENCY):
        lock = InterProcessLock(slot_root / str(index), timeout=0.0)
        try:
            lock.acquire()
        except TimeoutError:
            continue
        try:
            yield
        finally:
            lock.release()
        return
    raise TradeRulePackageImportBusy(
        "Trade Rule Package import concurrency is full"
    )


def _trade_rule_package_import_id(
    *,
    order_digest: str,
    package_digest: str,
) -> str:
    """Return the stable semantic key for one Order-bound package import."""

    document = {
        "order_digest": order_digest,
        "package_digest": package_digest,
    }
    return hashlib.sha256(
        json.dumps(
            document,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()


def _trade_rule_package_source_origin(peer_url: str) -> str:
    """Return one canonical origin without retaining peer URL paths."""

    parsed = urlsplit(peer_url)
    return canonical_recognition_source_origin(
        f"{parsed.scheme}://{parsed.netloc}"
    )


def _trade_rule_package_import_audit_state(
    spine: Any,
    *,
    order_digest: str,
    package_digest: str,
) -> str:
    """Return anchored, incomplete, or not-imported from verified Spine data."""

    return _trade_rule_package_import_audit_state_from_records(
        _trade_rule_package_import_audit_records(spine.verified_snapshot()),
        order_digest=order_digest,
        package_digest=package_digest,
    )


def _trade_rule_package_import_audit_state_from_records(
    records: Dict[str, Dict[str, Dict[str, tuple[str, str, str, str]]]],
    *,
    order_digest: str,
    package_digest: str,
) -> str:
    """Resolve one Order/Package state without replaying the Spine again."""

    expected_import_id = _trade_rule_package_import_id(
        order_digest=order_digest,
        package_digest=package_digest,
    )
    state = records.get(package_digest, {"proposed": {}, "anchored": {}})
    proposed = state["proposed"]
    anchored = state["anchored"]
    if anchored.keys() - proposed.keys():
        raise RuntimeError(
            "Trade Rule Package import audit is missing its write-ahead intent"
        )
    for import_id in anchored.keys() & proposed.keys():
        if anchored[import_id] != proposed[import_id]:
            raise RuntimeError(
                "Trade Rule Package import audit binding conflicts across stages"
            )
    if expected_import_id in anchored:
        return "anchored"
    if expected_import_id in proposed:
        return "incomplete"
    # A package cache is global. If its first import crashed after the
    # write-ahead event, a different Order must not make that same cache
    # executable before any import receives a final signed anchor.
    if proposed and not anchored:
        return "package-incomplete"
    if anchored:
        return "package-anchored"
    return "not-imported"


class _OrderAuditedRulePackageResolver:
    """Block a Package whose signed import intent lacks its final anchor."""

    def __init__(
        self,
        store: Any,
        spine: Any,
        order_digest: str,
        workspace: Path,
    ) -> None:
        self._store = store
        self._spine = spine
        self._order_digest = order_digest
        self._workspace = workspace
        self._audit_token: tuple[int, int, int, int, int, str] | None = None
        self._audit_records: Any = None

    def load(self, package_digest: str) -> Any:
        lock = InterProcessLock(
            _trade_rule_package_import_lock_target(
                self._workspace,
                package_digest,
            ),
            timeout=5.0,
        )
        try:
            lock.acquire()
        except TimeoutError as exc:
            raise RuntimeError("Trade Rule Package import is busy") from exc
        try:
            package = self._store.load(package_digest)
            if package is None:
                return None
            sources = self._store.provenance_sources(package_digest)
            current_token = self._spine.storage_token()
            if self._audit_records is None or current_token != self._audit_token:
                token, events = self._spine.verified_snapshot_with_token()
                self._audit_records = _trade_rule_package_import_audit_records(events)
                self._audit_token = token
            state = _trade_rule_package_import_audit_state_from_records(
                self._audit_records,
                order_digest=self._order_digest,
                package_digest=package_digest,
            )
            if state in {"incomplete", "package-incomplete"}:
                raise RuntimeError("Trade Rule Package import audit is incomplete")
            if not sources:
                raise RuntimeError("Trade Rule Package provenance is unclassified")
            if "local" not in sources and state not in {
                "anchored",
                "package-anchored",
            }:
                raise RuntimeError(
                    "federated Trade Rule Package lacks a signed import anchor"
                )
            return package
        finally:
            lock.release()


def _trade_order_rule_package_resolver(
    request: Request,
    order_digest: str,
) -> Any:
    """Return the single fail-closed Package resolver for one Order."""

    package_store = _state_trade_rule_package_store(request)
    spine = _state_spine(request)
    workspace = _state_workspace(request)
    if package_store is None:
        raise RuntimeError("Trade Rule Package store is unavailable")
    if spine is None or workspace is None:
        raise RuntimeError("Trade Rule Package import audit is unavailable")
    return _OrderAuditedRulePackageResolver(
        package_store,
        spine,
        order_digest,
        workspace,
    )


def _trade_rule_package_import_lock_target(
    workspace: Path,
    package_digest: str,
) -> Path:
    if re.fullmatch(r"sha256:[0-9a-f]{64}", package_digest) is None:
        raise RuntimeError("Trade Rule Package digest is invalid")
    return (
        workspace
        / "trade"
        / "rule_package_imports"
        / package_digest.removeprefix("sha256:")
    )


def _import_trade_rule_package_singleflight(
    workspace: Path,
    package_store: Any,
    spine: Any,
    *,
    order_digest: str,
    peer_url: str,
    offer_digest: str,
    offer_publisher_did: str,
    package_digest: str,
    expected_rule_id: str,
) -> tuple[Any, bool, Any, bool]:
    """Fetch, install, and audit one package under one cross-process lease.

    Package storage and the append-only Spine are separate durable stores, so
    they cannot be committed atomically.  Holding the import lease across both
    writes and using a stable Spine semantic key makes the only partial state
    (cached package without audit) explicitly retryable and self-healing.
    """

    lock_target = _trade_rule_package_import_lock_target(workspace, package_digest)
    lock = InterProcessLock(lock_target, timeout=35.0)
    try:
        lock.acquire()
    except TimeoutError as exc:
        raise TradeRulePackageImportBusy(
            "another process is importing this Trade Rule Package"
        ) from exc
    try:
        with _trade_rule_package_import_slot(workspace):
            package = package_store.load(package_digest)
            if package is None:
                package = _fetch_trade_rule_package_from_peer(
                    peer_url,
                    offer_digest=offer_digest,
                    package_digest=package_digest,
                    offer_publisher_did=offer_publisher_did,
                )
            if package.manifest.rule_id != expected_rule_id:
                from nth_dao.trade_rules import RulePackageBundleRejected

                raise RulePackageBundleRejected(
                    "Rule Package rule_id does not match the signed Order binding"
                )
            document = package.manifest.to_dict()
            import_id = _trade_rule_package_import_id(
                order_digest=order_digest,
                package_digest=package.digest,
            )
            source_origin = _trade_rule_package_source_origin(peer_url)
            try:
                spine.append_unique(
                    "trade.rule-package.import.proposed",
                    {
                        "import_id": import_id,
                        "order_digest": order_digest,
                        "offer_digest": offer_digest,
                        "package_digest": package.digest,
                        "rule_id": document["rule_id"],
                        "package_publisher_did": document["publisher_did"],
                        "source_origin": source_origin,
                        "action": "verified-cache-import-proposed",
                    },
                    unique_payload_fields=("import_id",),
                )
            except (OSError, RuntimeError, TypeError, ValueError) as exc:
                raise TradeRulePackageImportAuditError(
                    "signed Trade Rule Package import intent could not be persisted"
                ) from exc

            result = package_store.install(
                package.manifest,
                package.resources,
                source="federated",
            )
            package = result.package
            installed = result.installed

            try:
                audit_event, audit_created = spine.append_unique(
                    "trade.rule-package.imported",
                    {
                        "import_id": import_id,
                        "order_digest": order_digest,
                        "offer_digest": offer_digest,
                        "package_digest": package.digest,
                        "rule_id": document["rule_id"],
                        "package_publisher_did": document["publisher_did"],
                        "source_origin": source_origin,
                        "action": "verified-cache-import",
                    },
                    unique_payload_fields=("import_id",),
                )
            except (OSError, RuntimeError, TypeError, ValueError) as exc:
                raise TradeRulePackageImportAuditError(
                    "signed Trade Rule Package import audit is incomplete"
                ) from exc
            return package, installed, audit_event, audit_created
    finally:
        lock.release()


def _trade_offer_chain_to_wire(view: Any) -> Dict[str, Any]:
    return {
        "publisher_did": view.publisher_did,
        "offer_id": view.offer_id,
        "status": view.status,
        "revision_count": len(view.all_digests),
        "all_digests": list(view.all_digests),
        "root_digests": list(view.root_digests),
        "canonical_digests": list(view.canonical_digests),
        "canonical_head_digest": view.canonical_head_digest,
        "fork_digests": list(view.fork_digests),
        "orphan_digests": list(view.orphan_digests),
        "invalid_digests": list(view.invalid_digests),
    }


def _encode_trade_offer_cursor(view: Any) -> str:
    from nth_dao.b64u import b64u_encode
    from nth_dao.canonical_json import canonical_json

    return b64u_encode(
        canonical_json(
            {
                "publisher_did": view.publisher_did,
                "offer_id": view.offer_id,
            }
        )
    )


def _decode_trade_offer_cursor(value: str) -> tuple[str, str]:
    from nth_dao.b64u import b64u_decode

    if not isinstance(value, str) or not 1 <= len(value) <= 1_024:
        raise ValueError("trade offer cursor is invalid")
    try:
        document = json.loads(b64u_decode(value).decode("utf-8"))
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("trade offer cursor is invalid") from exc
    if (
        not isinstance(document, dict)
        or set(document) != {"publisher_did", "offer_id"}
        or not isinstance(document["publisher_did"], str)
        or not 1 <= len(document["publisher_did"]) <= 256
        or not isinstance(document["offer_id"], str)
        or not 1 <= len(document["offer_id"]) <= 256
    ):
        raise ValueError("trade offer cursor is invalid")
    return document["publisher_did"], document["offer_id"]


def _complete_decision(
    store: Any,
    decision_id: str,
    action: str,
    *,
    receipt_id: str = "",
) -> None:
    from .decision_store import DecisionNotFound

    try:
        if hasattr(store, "complete"):
            store.complete(decision_id, action, receipt_id=receipt_id)
        else:
            store.pop(decision_id, None)
    except DecisionNotFound:
        raise HTTPException(
            status_code=404,
            detail=f"decision {decision_id!r} is no longer pending",
        ) from None
    except Exception as exc:  # noqa: BLE001
        logger.exception("decision outcome persistence failed: %s", exc)
        raise HTTPException(
            status_code=500,
            detail="decision outcome could not be persisted",
        ) from exc


def _find_persisted_decision_receipt(
    receipts_store: Any,
    *,
    decision_id: str,
    signer_pubkey_hex: str,
) -> Optional[Dict[str, Any]]:
    """Find one valid receipt proving this decision was already approved."""

    from nth_dao.execution_receipt import verify_receipt

    matches: List[Dict[str, Any]] = []
    for receipt_id in receipts_store.list_ids():
        receipt = receipts_store.load(receipt_id)
        if not isinstance(receipt, dict):
            continue
        if str(receipt.get("receipt_id") or "") != receipt_id:
            continue
        timeline = receipt.get("timeline")
        if not isinstance(timeline, list) or not any(
            isinstance(entry, dict)
            and entry.get("type") == "nth.decision_approved"
            and isinstance(entry.get("payload"), dict)
            and entry["payload"].get("decision_id") == decision_id
            for entry in timeline
        ):
            continue
        if verify_receipt(
            receipt,
            expected_pubkey_hex=signer_pubkey_hex,
        ):
            matches.append(receipt)
    if len(matches) > 1:
        raise HTTPException(
            status_code=409,
            detail=(
                f"decision {decision_id!r} has multiple valid approval "
                "receipts; resolve the receipt-chain conflict manually"
            ),
        )
    return matches[0] if matches else None


def _decision_receipt_summary(
    receipt: Dict[str, Any],
    *,
    decision: Dict[str, Any],
    decision_id: str,
    goal_id: str,
    prev_content_hash: str,
) -> Dict[str, Any]:
    return {
        "id": receipt.get("receipt_id", ""),
        "signer_did": receipt.get("signer_did", ""),
        "signer_label": "you",
        "goal_id": goal_id,
        "content_hash": receipt.get("content_hash", ""),
        "prev_content_hash": prev_content_hash,
        "has_cap_token": bool(receipt.get("authorizing_cap_token")),
        "summary": decision.get("title", decision_id),
        "issued_at": receipt.get("issued_at", ""),
    }


def _decision_payload_hash(decision: Dict[str, Any]) -> str:
    """Hash the exact JSON-compatible decision projection stored by SQLite."""

    encoded = json.dumps(
        decision,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _fresh_verified_decision_spine(request: Request) -> Tuple[Any, List[Any]]:
    """Return a freshly verified Spine for a security-sensitive write."""

    spine = _state_spine(request)
    if spine is None:
        raise HTTPException(
            status_code=503,
            detail="signed Spine unavailable; decision remains pending",
        )
    try:
        ok, why = spine.verify_chain()
        if not ok:
            raise HTTPException(
                status_code=503,
                detail=f"spine integrity check failed: {why}",
            )
        events = list(spine.read_all())
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.exception("decision Spine verification failed: %s", exc)
        raise HTTPException(
            status_code=503,
            detail="signed Spine could not be verified; decision remains pending",
        ) from exc
    return spine, events


def _record_decision_outcome(
    request: Request,
    decision: Dict[str, Any],
    *,
    action: str,
    receipt: Optional[Dict[str, Any]] = None,
) -> Any:
    """Idempotently append one signed Decision outcome to the Spine."""

    if action not in {"approved", "rejected", "deferred"}:
        raise ValueError(f"unsupported decision action: {action}")
    identity = _state_node_identity(request)
    if identity is None or not getattr(identity, "can_sign", False):
        raise HTTPException(
            status_code=503,
            detail="signer identity unavailable; cannot audit decision outcome",
        )
    decision_id = str(decision.get("id") or "")
    event_type = f"decision.{action}"
    receipt_id = str((receipt or {}).get("receipt_id") or "")
    receipt_hash = str((receipt or {}).get("content_hash") or "")
    payload = {
        "decision_id": decision_id,
        "decision_payload_hash": _decision_payload_hash(decision),
        "proposer_did": str(decision.get("proposer_did") or ""),
        "mission_id": str(decision.get("mission_id") or ""),
        "receipt_id": receipt_id,
        "receipt_content_hash": receipt_hash,
    }

    spine, events = _fresh_verified_decision_spine(request)
    for event in events:
        event_payload = getattr(event, "payload", None)
        if not isinstance(event_payload, dict):
            continue
        if event_payload.get("decision_id") != decision_id:
            continue
        if not str(getattr(event, "type", "")).startswith("decision."):
            continue
        if (
            event.type != event_type
            or event_payload.get("decision_payload_hash")
            != payload["decision_payload_hash"]
            or event_payload.get("receipt_id") != receipt_id
            or event_payload.get("receipt_content_hash") != receipt_hash
        ):
            raise HTTPException(
                status_code=409,
                detail=(
                    f"decision {decision_id!r} already has a conflicting "
                    "signed outcome in the Spine"
                ),
            )
        return event

    try:
        return spine.append(event_type, payload)
    except Exception as exc:  # noqa: BLE001
        logger.exception("decision Spine append failed: %s", exc)
        raise HTTPException(
            status_code=500,
            detail="decision outcome could not be written to the signed Spine",
        ) from exc


def _ensure_no_signed_decision_outcome(
    request: Request,
    decision_id: str,
) -> None:
    """Fail before creating a receipt when the Spine already resolved it."""

    _spine, events = _fresh_verified_decision_spine(request)
    for event in events:
        payload = getattr(event, "payload", None)
        if (
            isinstance(payload, dict)
            and payload.get("decision_id") == decision_id
            and str(getattr(event, "type", "")).startswith("decision.")
        ):
            raise HTTPException(
                status_code=409,
                detail=(
                    f"decision {decision_id!r} already has a signed outcome "
                    "in the Spine"
                ),
            )


def _resolve_decision(
    decision_id: str,
    request: Request,
    *,
    sign: bool,
    action: str,
) -> Dict[str, Any]:
    """Serialize one decision outcome across threads and hub processes."""

    if sign != (action == "approved"):
        raise ValueError(
            "approved decisions require a receipt; rejected/deferred "
            "decisions must not create one"
        )
    workspace = _state_workspace(request)
    if workspace is None:
        raise HTTPException(status_code=503, detail="decision workspace unavailable")
    # The receipt chain is signer-scoped, not decision-scoped. Serializing
    # only equal IDs would let two different approvals read the same chain
    # head and create a fork.
    lock_target = workspace / "decisions" / "resolution"
    try:
        with InterProcessLock(lock_target, timeout=30.0):
            return _resolve_decision_locked(
                decision_id,
                request,
                sign=sign,
                action=action,
            )
    except TimeoutError as exc:
        raise HTTPException(
            status_code=409,
            detail=f"decision {decision_id!r} is already being resolved",
        ) from exc


def _resolve_decision_locked(
    decision_id: str,
    request: Request,
    *,
    sign: bool,
    action: str,
) -> Dict[str, Any]:
    """Shared body for approve / reject / defer.

    sign=True  → build a TimelineEntry from the decision's
                 preview_receipt + a synthetic approval entry,
                 chain-link to the signer's previous content_hash,
                 sign with state.node_identity, save via
                 state.receipts. Return the ReceiptSummary.
    sign=False → just remove. Return {removed: True}.

    Phase 2 caveats (documented for future hardening):
      - No cap_token enforcement: anyone reaching 127.0.0.1 can hit
        these. v1 already has the same posture for /api/cap_tokens/issue
        which uses the console_token; the v2 routes are anonymous on
        the local-only bind so this is the same trust model in
        practice. Phase 3 will add cap_token gating.
      - Decision resolution is serialized across hub processes. A receipt
        saved before queue completion is detected and reused on retry.
      - Mission_id mapping: when the decision carries one, use it as
        ``goal_id`` so the receipt links to the mission. Else use
        the decision id itself.
    """
    # Lazy imports — execution_receipt module is heavy.
    from nth_dao.execution_receipt import (
        TimelineEntry, extract_prev_content_hash,
    )

    store = _decisions_store(request)
    decision = store.get(decision_id)
    if decision is None:
        raise HTTPException(
            status_code=404,
            detail=f"decision {decision_id!r} not found in queue "
                   "(already resolved, or never existed)",
        )

    if not sign:
        # reject / defer — no receipt, just remove.
        audit_event = _record_decision_outcome(
            request,
            decision,
            action=action,
        )
        _complete_decision(store, decision_id, action)
        return {
            "decision_id": decision_id,
            "removed": True,
            "signed": False,
            "audit_signed": True,
            "audit_event_id": audit_event.event_id,
        }

    # sign=True path
    identity = _state_node_identity(request)
    if identity is None or not getattr(identity, "can_sign", False):
        raise HTTPException(
            status_code=503,
            detail="signer identity unavailable; cannot sign receipt. "
                   "Bootstrap the workspace identity first.",
        )

    # Review fix #4 2026-06-10: previously a missing receipts_store
    # let sign_receipt run and then SKIPPED save (the receipts_store
    # is None check before save() was a silent-discard, not a
    # fail-closed). The UI got back signed=True but nothing landed
    # on disk — silent data loss. Treat the missing store the same
    # as a missing signer: 503 BEFORE we sign anything.
    receipts_store = _state_receipts_store(request)
    if receipts_store is None:
        raise HTTPException(
            status_code=503,
            detail="receipt store unavailable; cannot persist receipt. "
                   "Bootstrap the workspace receipts dir first.",
        )

    goal_id = decision.get("mission_id") or decision_id
    existing_receipt = _find_persisted_decision_receipt(
        receipts_store,
        decision_id=decision_id,
        signer_pubkey_hex=str(getattr(identity, "pubkey_hex", "") or ""),
    )
    if existing_receipt is not None:
        audit_event = _record_decision_outcome(
            request,
            decision,
            action="approved",
            receipt=existing_receipt,
        )
        _complete_decision(
            store,
            decision_id,
            "approved",
            receipt_id=str(existing_receipt.get("receipt_id", "")),
        )
        return {
            "decision_id": decision_id,
            "removed": True,
            "signed": True,
            "audit_signed": True,
            "recovered": True,
            "audit_event_id": audit_event.event_id,
            "receipt": _decision_receipt_summary(
                existing_receipt,
                decision=decision,
                decision_id=decision_id,
                goal_id=goal_id,
                prev_content_hash=extract_prev_content_hash(existing_receipt),
            ),
        }
    _ensure_no_signed_decision_outcome(request, decision_id)

    # Build the timeline.
    # Required: at least one substantive entry beyond chain_link.
    # Pull the decision's preview_receipt as the payload of an
    # `nth.decision_approved` entry — this lets verify_receipt see
    # exactly what the user authorised.
    now_ms = int(time.time() * 1000)
    preview = decision.get("preview_receipt") or {}
    timeline = [
        TimelineEntry(
            timestamp=now_ms,
            type="nth.decision_approved",
            payload={
                "decision_id": decision_id,
                "title": decision.get("title", ""),
                "impact": decision.get("impact", ""),
                "preview_kind": preview.get("kind", ""),
                "preview": preview,
            },
        ),
    ]

    try:
        receipt = receipts_store.sign_and_save(
            timeline,
            identity,
            goal_id=goal_id,
        )
    except Exception as exc:
        logger.exception("v2_api: receipt sign-and-save failed: %s", exc)
        raise HTTPException(
            status_code=500,
            detail=f"signed receipt could not be persisted: {exc}",
        )

    audit_event = _record_decision_outcome(
        request,
        decision,
        action="approved",
        receipt=receipt,
    )

    # Remove the decision from the queue only after the receipt has
    # landed on disk.
    _complete_decision(
        store,
        decision_id,
        "approved",
        receipt_id=str(receipt.get("receipt_id", "")),
    )

    # Shape matches ReceiptSummary so the frontend can splice it
    # into its receipts state without a /api/v2/receipts refetch.
    summary = _decision_receipt_summary(
        receipt,
        decision=decision,
        decision_id=decision_id,
        goal_id=goal_id,
        prev_content_hash=extract_prev_content_hash(receipt),
    )
    return {
        "decision_id": decision_id,
        "removed": True,
        "signed": True,
        "audit_signed": True,
        "audit_event_id": audit_event.event_id,
        "receipt": summary,
    }


class CreateChannelBody(BaseModel):
    """新建频道入参(收编自 8765 群聊)。"""

    name: str
    topic: str = ""
    created_by: str = "admin"


class ChannelMessageBody(BaseModel):
    """Channel message input with optional explicit Agent recipients."""

    agent_id: str = "admin"
    body: str = ""
    target_agent_dids: List[str] = Field(default_factory=list, max_length=16)
    attachment_ids: List[str] = Field(default_factory=list, max_length=8)
    reply_to_message_id: str = Field(default="", max_length=64)

    @field_validator("target_agent_dids")
    @classmethod
    def _validate_target_agent_dids(cls, value: List[str]) -> List[str]:
        normalized: List[str] = []
        for raw in value:
            did = str(raw).strip()
            if not did.startswith("did:") or len(did) > 512:
                raise ValueError("target_agent_dids must contain valid DID strings")
            if did not in normalized:
                normalized.append(did)
        return normalized

    @field_validator("attachment_ids")
    @classmethod
    def _validate_attachment_ids(cls, value: List[str]) -> List[str]:
        normalized: List[str] = []
        for raw in value:
            attachment_id = str(raw).strip()
            if not re.fullmatch(r"[0-9a-f]{24}", attachment_id):
                raise ValueError("attachment_ids must contain 24-character hex ids")
            if attachment_id not in normalized:
                normalized.append(attachment_id)
        return normalized


_CHANNEL_MESSAGE_MAX_CHARS = 100_000
_CHANNEL_ATTACHMENT_MAX_BYTES = 25 * 1024 * 1024


def _channel_attachment_dir(request: Request, channel_id: str) -> Path:
    workspace = _state_workspace(request)
    if workspace is None:
        raise HTTPException(status_code=503, detail="workspace unavailable")
    return workspace / "channel_attachments" / safe_id(channel_id)


def _channel_attachment_paths(
    request: Request,
    channel_id: str,
    attachment_id: str,
) -> Tuple[Path, Path]:
    root = _channel_attachment_dir(request, channel_id)
    return root / f"{attachment_id}.bin", root / f"{attachment_id}.json"


def _channel_attachment_public(record: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "attachment_id": str(record.get("attachment_id") or ""),
        "filename": str(record.get("filename") or "attachment"),
        "media_type": str(record.get("media_type") or "application/octet-stream"),
        "size": int(record.get("size") or 0),
        "sha256": str(record.get("sha256") or ""),
        "created_at": str(record.get("created_at") or ""),
    }


def _load_channel_attachment(
    request: Request,
    channel_id: str,
    attachment_id: str,
) -> Optional[Dict[str, Any]]:
    if not re.fullmatch(r"[0-9a-f]{24}", attachment_id):
        return None
    data_path, metadata_path = _channel_attachment_paths(
        request, channel_id, attachment_id,
    )
    record = safe_load_json(metadata_path, fallback=None)
    if not isinstance(record, dict) or not data_path.is_file():
        return None
    if record.get("attachment_id") != attachment_id:
        return None
    if record.get("channel_id") != channel_id:
        return None
    return record


def _write_channel_attachment(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f"{path.name}.", suffix=".tmp", dir=str(path.parent),
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _channel_message_to_wire(message: Any) -> Dict[str, Any]:
    """Project stored channel messages into the v2 UI contract.

    The storage model keeps receipt linkage inside ``metadata`` so the
    append-only message shape stays stable. The UI should not have to know
    that internal nesting, so the v2 projection exposes the common receipt
    fields at top level while preserving the original metadata for audit
    inspection and future clients.
    """
    data = message.to_dict()
    meta = data.get("metadata")
    if not isinstance(meta, dict):
        return data
    receipt_id = meta.get("nth_receipt_id")
    receipt_hash = meta.get("nth_receipt_content_hash")
    dispatch_phase = meta.get("dispatch_phase")
    request_message_id = meta.get("request_message_id")
    status_source = meta.get("status_source")
    if receipt_id:
        data.setdefault("nth_receipt_id", str(receipt_id))
    if receipt_hash:
        data.setdefault("nth_receipt_content_hash", str(receipt_hash))
    if dispatch_phase:
        data.setdefault("dispatch_phase", str(dispatch_phase))
    if request_message_id:
        data.setdefault("request_message_id", str(request_message_id))
    if status_source:
        data.setdefault("status_source", str(status_source))
    attachments = meta.get("attachments")
    if isinstance(attachments, list):
        data.setdefault(
            "attachments",
            [item for item in attachments if isinstance(item, dict)],
        )
    return data


class JoinChannelBody(BaseModel):
    """把一个 agent 加进频道成员的入参。"""

    agent_id: str


class ForeignClaimBody(BaseModel):
    """跨 DAO 认领提交体(XDAO-2):外部 agent 预签的认领产物。"""

    cap_token: Dict[str, Any]
    receipt: Dict[str, Any]
    model_config = {"extra": "forbid"}


class ForeignClaimByKeyBody(ForeignClaimBody):
    """Anonymous foreign claim addressed by signed-body content hash."""

    federation_key: str


class FederatedClaimBody(BaseModel):
    """跨 DAO 认领·本地编排入参(XDAO-3)。source_peer 刻意**不**收 —— 来源
    取自本节点联邦缓存(可信、已配置的 peer),防被诱导转投到攻击者节点。"""

    announcement_id: str
    federation_key: str = ""
    agent_did: str


class FederationPeerBody(BaseModel):
    """Operator-managed seed peer for task federation discovery."""

    peer_url: str
    action: str = "add"


class FederationDiscoverBody(BaseModel):
    """Discover nearby DAO nodes and optionally import them as seed peers."""

    actor_id: str = "admin"
    timeout_seconds: float = Field(default=2.0, ge=0.5, le=6.0)
    add: bool = True
    refresh: bool = True


class FederationHelloBody(BaseModel):
    """Permissionless reverse-discovery hint; identity is verified by fetch."""

    peer_url: str = Field(min_length=1, max_length=2048)
    did: str = Field(min_length=1, max_length=512)


class DisputeStatementBody(BaseModel):
    """争议声明提交体(Phase 4c):当事方**预签**的争议声明(open/evidence/resolve)。

    statement 是自包含、自验证的签名 dict;服务端 record_dispute 验签后落 spine。"""

    statement: Dict[str, Any]


class HandoffStatementBody(BaseModel):
    """A pre-signed handoff capsule or response.

    The server verifies and persists the statement but does not author it. A
    valid signature proves the source of a claim, not that the claim is true.
    """

    statement: Dict[str, Any]


class CapRequestBody(BaseModel):
    """能力授予请求提交体(授权收件箱):requester **预签**的 cap.request。"""

    statement: Dict[str, Any]


class CapDecisionBody(BaseModel):
    """审批决议入参(拒绝时可带原因)。"""

    reason: str = ""


class AcceptBody(BaseModel):
    """验收入参:确认哪个 agent 完成了任务。"""

    completer_did: str


class SocialTargetBody(BaseModel):
    """社交动作入参(关注/好友):只需关系对象 DID;发起方=本节点身份,服务端签名。"""

    target_did: str


# 频道 agent 派发的全局并发上限:防公网刷消息时 daemon 线程爆炸(审查
# 发现的隐患①)。在飞达上限时新派发被丢弃并告警,而非无限堆线程。
_CHANNEL_DISPATCH_MAX = 16
_CHANNEL_DISPATCH_SEM = threading.BoundedSemaphore(_CHANNEL_DISPATCH_MAX)
_CHANNEL_DISPATCH_RETRIES = 8
_CHANNEL_DISPATCH_RETRY_SLEEP_S = 0.25
_CHANNEL_DISPATCH_ERROR_COOLDOWN_S = 300.0
# A provider failure must not permanently disable routing.  Keep the longer
# error-post cooldown separate from the short half-open window: after this
# backoff, the next user instruction becomes a real recovery probe.
_CHANNEL_DISPATCH_PROVIDER_RECOVERY_COOLDOWN_S = 15.0
_CHANNEL_DISPATCH_ERROR_LOCK = threading.Lock()
_CHANNEL_DISPATCH_ERROR_UNTIL: Dict[Tuple[str, str], float] = {}
_CHANNEL_DISPATCH_PROVIDER_RECOVERY_UNTIL: Dict[Tuple[str, str], float] = {}
_CHANNEL_DISPATCH_IN_FLIGHT: set[Tuple[str, str]] = set()
_CHANNEL_DISPATCH_PHASE_RECEIVED = "received"
_CHANNEL_DISPATCH_PHASE_PROCESSING = "processing"
_CHANNEL_DISPATCH_PHASE_QUEUED = "queued"
_CHANNEL_DISPATCH_PHASE_EXECUTING = "executing"
_CHANNEL_DISPATCH_PHASE_COMPLETED = "completed"
_CHANNEL_DISPATCH_PHASE_FAILED = "failed"


def _channel_dispatch_error_in_cooldown(
    channel_id: str, did: str, *, now: Optional[float] = None,
) -> bool:
    """Return True when a channel agent is temporarily muted after failure."""
    ts = time.time() if now is None else float(now)
    key = (str(channel_id), str(did))
    with _CHANNEL_DISPATCH_ERROR_LOCK:
        until = _CHANNEL_DISPATCH_ERROR_UNTIL.get(key)
        if until is None:
            return False
        if until > ts:
            return True
        _CHANNEL_DISPATCH_ERROR_UNTIL.pop(key, None)
        return False


def _channel_dispatch_note_error(
    channel_id: str, did: str, *, now: Optional[float] = None,
) -> bool:
    """Record a dispatch failure.

    Returns True when the failure should be posted to the channel. Repeated
    failures during the cooldown are logged but not surfaced again, so a broken
    backend cannot drown out healthy agent collaboration.
    """
    ts = time.time() if now is None else float(now)
    key = (str(channel_id), str(did))
    with _CHANNEL_DISPATCH_ERROR_LOCK:
        until = _CHANNEL_DISPATCH_ERROR_UNTIL.get(key)
        if until is not None and until > ts:
            return False
        _CHANNEL_DISPATCH_ERROR_UNTIL[key] = ts + _CHANNEL_DISPATCH_ERROR_COOLDOWN_S
        _CHANNEL_DISPATCH_PROVIDER_RECOVERY_UNTIL[key] = (
            ts + _CHANNEL_DISPATCH_PROVIDER_RECOVERY_COOLDOWN_S
        )
        return True


def _channel_dispatch_clear_error(channel_id: str, did: str) -> None:
    key = (str(channel_id), str(did))
    with _CHANNEL_DISPATCH_ERROR_LOCK:
        _CHANNEL_DISPATCH_ERROR_UNTIL.pop(key, None)
        _CHANNEL_DISPATCH_PROVIDER_RECOVERY_UNTIL.pop(key, None)


def _channel_dispatch_provider_recovery_in_cooldown(
    channel_id: str, did: str, *, now: Optional[float] = None,
) -> bool:
    """Return True while a degraded provider is still backing off.

    Once the window expires, the next channel instruction is allowed to
    probe the provider again.  A successful probe clears the window; another
    failure starts a fresh backoff.
    """
    ts = time.time() if now is None else float(now)
    key = (str(channel_id), str(did))
    with _CHANNEL_DISPATCH_ERROR_LOCK:
        until = _CHANNEL_DISPATCH_PROVIDER_RECOVERY_UNTIL.get(key)
        if until is None:
            return False
        if until > ts:
            return True
        _CHANNEL_DISPATCH_PROVIDER_RECOVERY_UNTIL.pop(key, None)
        return False


def _redact_local_paths(text: str) -> str:
    """Remove local filesystem paths before returning text to the UI."""
    home = str(Path.home())
    if home:
        text = re.sub(
            re.escape(home) + r"(?:[\\/][^\s'\"<>]+)*",
            "<local-path>",
            text,
            flags=re.IGNORECASE,
        )
    text = re.sub(r"[A-Za-z]:\\[^\s'\"<>]+", "<local-path>", text)
    text = re.sub(r"/(?:Users|home)/[^\s'\"<>]+", "<local-path>", text)
    return text


def _channel_dispatch_public_error(exc: Exception) -> str:
    """Build the human-facing channel error without subprocess log spam."""
    text = str(exc).strip()
    for marker in (" Tail:", "\nTail:", "\r\nTail:", "Tail:"):
        if marker in text:
            text = text.split(marker, 1)[0].strip()
            break
    text = " ".join(text.split())
    text = _redact_local_paths(text)
    if text.startswith("backend-timeout:"):
        message = f"agent error: {text}"
        return message[:417] + "..." if len(message) > 420 else message
    message = f"agent error: {type(exc).__name__}: {text}"
    if len(message) > 420:
        message = message[:417] + "..."
    return message


def _channel_dispatch_is_provider_failure(exc: Exception) -> bool:
    """Return True for failures that should degrade provider routing."""
    if isinstance(exc, (TimeoutError, OSError, ConnectionError)):
        return True
    text = str(exc).lower()
    return any(
        marker in text
        for marker in (
            "backend-timeout",
            "backend-failed",
            "provider unavailable",
            "provider queue",
        )
    )


def _a2a_http_error_message(
    status_code: int,
    content: Any,
    *,
    backend_kind: str = "",
) -> str:
    """Return a compact public message for a child A2A HTTP failure."""
    if isinstance(content, dict):
        error = content.get("error")
        if isinstance(error, dict):
            code = str(error.get("code") or f"http-{status_code}")
            message = str(error.get("message") or "").strip()
            if code == "backend-timeout":
                for marker in (" Tail:", "\nTail:", "\r\nTail:", "Tail:"):
                    if marker in message:
                        message = message.split(marker, 1)[0].strip()
                        break
                message = " ".join(message.split())
                kind = str(backend_kind or "").strip().lower()
                if kind == "hermes":
                    hint = (
                        "Hermes may still be queued. Try again, set "
                        "NTH_HERMES_ASK_TIMEOUT_S up to 300, or configure a "
                        "faster Hermes model."
                    )
                elif kind == "codex":
                    hint = (
                        "Codex may be queued or out of usage. Retry, check "
                        "Codex usage, or set NTH_CODEX_MODEL to a model "
                        "supported by the installed CLI."
                    )
                else:
                    hint = (
                        "The selected Agent provider may still be queued. "
                        "Retry or configure a faster provider."
                    )
                return f"backend-timeout: {message or hint}. {hint}"
            if message:
                return f"a2a ask HTTP {status_code}: {code}: {message}"
            return f"a2a ask HTTP {status_code}: {code}"
    blob = (
        json.dumps(content, ensure_ascii=False)
        if isinstance(content, dict) else str(content)
    )
    return f"a2a ask HTTP {status_code}: {blob[:1000]}"


def _channel_dispatch_try_begin(channel_id: str, did: str) -> bool:
    """Reserve a channel-agent dispatch slot.

    This is separate from the global semaphore: the semaphore bounds total
    system pressure, while this guard prevents repeated user messages from
    launching concurrent calls into the same backend before the first one has
    succeeded or failed.
    """
    ts = time.time()
    key = (str(channel_id), str(did))
    with _CHANNEL_DISPATCH_ERROR_LOCK:
        until = _CHANNEL_DISPATCH_ERROR_UNTIL.get(key)
        if until is not None:
            if until > ts:
                return False
            _CHANNEL_DISPATCH_ERROR_UNTIL.pop(key, None)
        if key in _CHANNEL_DISPATCH_IN_FLIGHT:
            return False
        _CHANNEL_DISPATCH_IN_FLIGHT.add(key)
        return True


def _channel_dispatch_end(channel_id: str, did: str) -> None:
    key = (str(channel_id), str(did))
    with _CHANNEL_DISPATCH_ERROR_LOCK:
        _CHANNEL_DISPATCH_IN_FLIGHT.discard(key)


def _post_channel_dispatch_status(
    groups: Any,
    channel_id: str,
    did: str,
    request_message_id: str,
    phase: str,
    body: str,
    *,
    metadata: Optional[Dict[str, Any]] = None,
) -> bool:
    """Persist one durable, non-streaming channel workflow status.

    Statuses are ordinary channel messages, so polling clients, offline
    readers, and the append-only audit trail observe the same lifecycle.
    ``request_message_id`` binds every status to the user's instruction.
    """
    status_actor = _channel_dispatch_status_actor(groups, channel_id, fallback=did)
    status_metadata: Dict[str, Any] = {
        "channel_dispatch": True,
        "dispatch_phase": phase,
        "request_message_id": request_message_id,
        "agent_did": did,
        "status_source": "hub",
        "status_actor_id": status_actor,
    }
    if metadata:
        status_metadata.update(metadata)
    try:
        _post_channel_message(
            groups,
            channel_id,
            sender_id=status_actor,
            body=body,
            kind="system",
            reply_to=request_message_id,
            metadata=status_metadata,
        )
        return True
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "channel dispatch status post failed for %s/%s (%s): %s",
            channel_id, did, phase, exc,
        )
    return False


def _channel_dispatch_status_actor(
    groups: Any,
    channel_id: str,
    *,
    fallback: str = "admin",
) -> str:
    """Choose a real channel principal for Hub-authored status messages."""
    candidates: List[str] = []
    try:
        channel = groups.get_channel(channel_id)
    except Exception:  # noqa: BLE001
        channel = None
    if channel is None:
        # Legacy embedders may not expose get_channel(). Preserve their
        # historical sender semantics; current GroupManager takes the safe
        # principal path below.
        return str(fallback or "admin")
    if channel is not None:
        candidates.append(str(getattr(channel, "created_by", "") or ""))
        candidates.extend(str(item) for item in (channel.member_ids or []))
    candidates.append("admin")

    membership = getattr(groups, "membership", None)
    for candidate in candidates:
        if not candidate:
            continue
        if membership is None:
            return candidate
        try:
            config = membership.load_config()
            if (
                not config.admin_ids
                and not config.member_ids
            ) or membership.has_permission(candidate, "send_messages"):
                return candidate
        except Exception:  # noqa: BLE001
            continue
    return candidates[0] if candidates and candidates[0] else "admin"


def _post_channel_message(
    groups: Any,
    channel_id: str,
    *,
    sender_id: str,
    body: str,
    kind: str,
    reply_to: str,
    metadata: Optional[Dict[str, Any]],
) -> None:
    """Write a channel message across old and current GroupManager APIs.

    Older embedders accept only ``metadata``. The fallback is deliberately
    narrow: a TypeError from message validation or storage is re-raised, while
    only an unknown keyword-argument error uses the legacy signature.
    """
    post_message = groups.post_message
    try:
        signature = inspect.signature(post_message)
    except (TypeError, ValueError):
        signature = None
    if signature is not None:
        parameters = signature.parameters.values()
        accepts_kwargs = any(
            parameter.kind is inspect.Parameter.VAR_KEYWORD
            for parameter in parameters
        )
        supports_current = accepts_kwargs or all(
            name in signature.parameters
            for name in ("kind", "reply_to", "metadata")
        )
        if not supports_current:
            logger.warning(
                "channel message API is legacy; reply_to/kind are carried "
                "only in metadata",
            )
            post_message(
                channel_id,
                sender_id=sender_id,
                body=body,
                metadata=metadata,
            )
            return
    try:
        post_message(
            channel_id,
            sender_id=sender_id,
            body=body,
            kind=kind,
            reply_to=reply_to,
            metadata=metadata,
        )
    except TypeError as exc:
        # Signature inspection can be unavailable for extension/proxy
        # objects. Only that unknown-signature case gets the old fallback;
        # a normal Python callable's business TypeError must propagate.
        if signature is not None or "unexpected keyword argument" not in str(exc):
            raise
        groups.post_message(
            channel_id,
            sender_id=sender_id,
            body=body,
            metadata=metadata,
        )


def _post_channel_dispatch_not_started(
    groups: Any,
    channel_id: str,
    did: str,
    request_message_id: str,
    reason: str,
    *,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """Persist an accepted-but-not-started dispatch as a terminal failure."""
    _post_channel_dispatch_status(
        groups,
        channel_id,
        did,
        request_message_id,
        _CHANNEL_DISPATCH_PHASE_FAILED,
        reason,
        metadata=metadata,
    )


def _recover_incomplete_channel_dispatches(
    groups: Any,
    link_jobs: Any = (),
) -> int:
    """Close stale channel dispatches left by a hub restart.

    The instruction itself is already durable, but the worker thread is not.
    Replaying an arbitrary prompt after a crash could duplicate side effects,
    so recovery fails the stale dispatch explicitly instead of guessing that
    the remote provider did not execute it.
    """
    channels_dir = getattr(groups, "channels_dir", None)
    if not isinstance(channels_dir, Path) or not channels_dir.exists():
        return 0
    recovered = 0
    suffix = ".messages.jsonl"
    channel_entries: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for path in channels_dir.glob(f"*{suffix}"):
        channel_id = path.name[:-len(suffix)]
        try:
            messages = groups.list_messages(channel_id, actor_id="")
        except (OSError, RuntimeError, ValueError) as exc:
            logger.warning(
                "channel dispatch recovery could not read %s: %s",
                channel_id,
                exc,
            )
            continue
        by_request: Dict[str, Dict[str, Any]] = {}
        for message in messages:
            metadata = getattr(message, "metadata", {})
            if not isinstance(metadata, dict) or not metadata.get("channel_dispatch"):
                continue
            request_id = str(metadata.get("request_message_id", "") or "")
            if not request_id:
                continue
            phase = str(metadata.get("dispatch_phase", "") or "")
            entry = by_request.setdefault(
                request_id,
                {"terminal": False, "pending": False, "agent_did": ""},
            )
            if phase in {
                _CHANNEL_DISPATCH_PHASE_COMPLETED,
                _CHANNEL_DISPATCH_PHASE_FAILED,
            }:
                entry["terminal"] = True
            elif phase in {
                _CHANNEL_DISPATCH_PHASE_RECEIVED,
                _CHANNEL_DISPATCH_PHASE_PROCESSING,
                _CHANNEL_DISPATCH_PHASE_QUEUED,
                _CHANNEL_DISPATCH_PHASE_EXECUTING,
            }:
                entry["pending"] = True
            if metadata.get("agent_did"):
                entry["agent_did"] = str(metadata["agent_did"])
        for request_id, entry in by_request.items():
            channel_entries[(channel_id, request_id)] = entry

        for request_id, entry in by_request.items():
            if not entry["pending"] or entry["terminal"]:
                continue
            if _post_channel_dispatch_status(
                groups,
                channel_id,
                str(entry["agent_did"] or "admin"),
                request_id,
                _CHANNEL_DISPATCH_PHASE_FAILED,
                "Hub restarted before the agent result was recorded; "
                "the instruction was not replayed.",
                metadata={"recovery": "hub-restart"},
            ):
                recovered += 1
                entry["terminal"] = True

    for job in tuple(link_jobs or ()):
        if str(getattr(job, "state", "")) != "delivery_unknown":
            continue
        channel_id = str(getattr(job, "channel_id", "") or "")
        request_id = str(getattr(job, "request_message_id", "") or "")
        if not channel_id or not request_id:
            continue
        entry = channel_entries.get((channel_id, request_id), {})
        if entry.get("terminal"):
            continue
        if _post_channel_dispatch_status(
            groups,
            channel_id,
            str(getattr(job, "agent_did", "") or "admin"),
            request_id,
            _CHANNEL_DISPATCH_PHASE_FAILED,
            "Hub restarted before the agent result was recorded; "
            "delivery outcome is unknown and the instruction was not replayed.",
            metadata={
                "recovery": "agent-link-delivery-unknown",
                "link_job_id": str(getattr(job, "job_id", "") or ""),
            },
        ):
            recovered += 1
            channel_entries[(channel_id, request_id)] = {
                "terminal": True,
                "pending": False,
                "agent_did": str(getattr(job, "agent_did", "") or ""),
            }
    return recovered


def _channel_ask_and_reply(
    groups,
    auth_token,
    did,
    a2a_port,
    channel_id,
    prompt,
    receipts_store: Any = None,
    agent_id: str = "",
    backend_kind: str = "",
    request_message_id: str = "",
    link_job_id: str = "",
    supervisor: Any = None,
    semaphore_acquired: bool = True,
    request: Optional[Request] = None,
    work_record: Any = None,
):
    """P2 后台:问一个 agent 的 /a2a/ask,把回复回帖到频道。best-effort。

    用 agent 自己的 spawn cap_token 作 Authorization(与 claim/ask 同款注入);
    回帖经 groups.post_message 内部 API(不走 HTTP 端点)→ 不会再触发派发,
    天然杜绝 agent→agent 死循环。

    配额由调用方 acquire、本函数 finally 归还(每个 in-flight 槽位一进一出)。
    """
    import urllib.error
    import urllib.request

    from nth_dao.cap_token import encode_authorization_header

    outcome: Any = {"error": "agent dispatch failed"}
    try:
        body_bytes = json.dumps(
            {
                "prompt": prompt,
                "timeout_s": _channel_dispatch_ask_timeout(backend_kind),
                **(
                    {"agent_link_job_id": link_job_id}
                    if link_job_id else {}
                ),
            },
            ensure_ascii=False,
        ).encode("utf-8")
        url = f"http://127.0.0.1:{a2a_port}/a2a/ask"
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Content-Length": str(len(body_bytes)),
            "Authorization": f"CapToken {encode_authorization_header(auth_token)}",
        }
        timeout = _a2a_forward_timeout(
            "ask", body_bytes, backend_kind=backend_kind,
        )
        content: Any = {}
        lease = (
            _work_scope_lease(request, work_record)
            if request is not None and work_record is not None
            else nullcontext()
        )
        with lease:
            _post_channel_dispatch_status(
                groups,
                channel_id,
                did,
                request_message_id,
                _CHANNEL_DISPATCH_PHASE_EXECUTING,
                "Hub started the Agent provider call.",
                metadata={"link_job_id": link_job_id} if link_job_id else None,
            )
            for attempt in range(1, _CHANNEL_DISPATCH_RETRIES + 1):
                req = urllib.request.Request(
                    url, data=body_bytes, headers=headers, method="POST"
                )
                try:
                    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                        raw = _read_local_a2a_body(resp)
                    content = _decode_or_passthrough(raw)
                    break
                except urllib.error.HTTPError as exc:
                    raw = _read_local_a2a_body(exc) if exc.fp else b""
                    content = _decode_or_passthrough(raw)
                    blob = (
                        json.dumps(content, ensure_ascii=False)
                        if isinstance(content, dict) else str(content)
                    )
                    if (
                        exc.code == 401
                        and "not-yet-authorized" in blob
                        and attempt < _CHANNEL_DISPATCH_RETRIES
                    ):
                        time.sleep(_CHANNEL_DISPATCH_RETRY_SLEEP_S)
                        continue
                    raise RuntimeError(
                        _a2a_http_error_message(
                            exc.code, content, backend_kind=backend_kind,
                        )
                    ) from exc
        reply = ""
        reply_metadata: Dict[str, Any] = {}
        if isinstance(content, dict):
            receipt_meta = _persist_agent_response_receipt_to_store(
                receipts_store, agent_id or did, did, content,
            )
            if receipt_meta:
                reply_metadata.update(receipt_meta)
            result = content.get("result")
            if isinstance(result, dict):
                reply = str(result.get("response") or "")
        reply = reply.strip()
        from .agent_link import bound_agent_response

        reply, response_truncated = bound_agent_response(reply)
        if reply:
            reply_metadata.update({
                "channel_dispatch": True,
                "dispatch_phase": _CHANNEL_DISPATCH_PHASE_COMPLETED,
                "request_message_id": request_message_id,
                "agent_did": did,
            })
            if response_truncated:
                reply_metadata["response_truncated"] = True
            if link_job_id:
                reply_metadata["link_job_id"] = link_job_id
            _post_channel_message(
                groups,
                channel_id,
                sender_id=did,
                body=reply,
                kind="text",
                reply_to=request_message_id,
                metadata=reply_metadata or None,
            )
            if supervisor is not None and agent_id:
                try:
                    supervisor.mark_provider_state(agent_id, "ready")
                except Exception as state_exc:  # noqa: BLE001
                    logger.warning(
                        "channel provider state update failed for %s: %s",
                        did,
                        state_exc,
                    )
            _channel_dispatch_clear_error(channel_id, did)
            outcome = {
                "response": reply,
                "receipt_id": str(
                    reply_metadata.get("nth_receipt_id", "") or ""
                ),
            }
            if response_truncated:
                outcome["response_truncated"] = True
        else:
            raise RuntimeError("agent returned an empty response")
    except Exception as exc:  # noqa: BLE001
        logger.warning("channel agent dispatch failed for %s: %s", did, exc)
        if (
            supervisor is not None
            and agent_id
            and _channel_dispatch_is_provider_failure(exc)
        ):
            try:
                supervisor.mark_provider_state(agent_id, "degraded")
            except Exception as state_exc:  # noqa: BLE001
                logger.warning(
                    "channel provider degradation update failed for %s: %s",
                    did,
                    state_exc,
                )
        should_post_detail = _channel_dispatch_note_error(channel_id, did)
        if not should_post_detail:
            logger.info(
                "channel agent dispatch error suppressed during cooldown for %s in %s",
                did,
                channel_id,
            )
            message = "agent failed again during the current cooldown; retry later."
        else:
            message = _channel_dispatch_public_error(exc)
        _post_channel_dispatch_status(
            groups,
            channel_id,
            did,
            request_message_id,
            _CHANNEL_DISPATCH_PHASE_FAILED,
            message,
            metadata={"link_job_id": link_job_id} if link_job_id else None,
        )
        outcome = {"error": message}
    finally:
        if semaphore_acquired:
            _CHANNEL_DISPATCH_SEM.release()  # 归还在飞配额
    return outcome


_CHANNEL_AGENT_MENTION_TOKEN_RE = re.compile(
    r"@(?P<agent>did:key:[A-Za-z0-9]+|[\w][\w./-]{0,127})(?=$|[\s,;:])",
    re.IGNORECASE,
)
_CHANNEL_AGENT_KIND_ALIASES = {
    "chatgpt": "codex",
    "codex": "codex",
    "codex/chatgpt": "codex",
    "chatgpt/codex": "codex",
    "claude": "claude-code",
    "claude-code": "claude-code",
    "hermes": "hermes",
}


def _channel_message_target_dids(message: Any) -> List[str]:
    metadata = getattr(message, "metadata", None)
    if not isinstance(metadata, dict):
        return []
    raw_targets = metadata.get("target_agent_dids")
    if not isinstance(raw_targets, list):
        return []
    return list(dict.fromkeys(
        str(item).strip()
        for item in raw_targets
        if str(item).strip().startswith("did:")
    ))


def _channel_message_mentions(message: Any) -> List[str]:
    """Parse the optional routing header at the start of a message.

    Mentions elsewhere are ordinary message content.  This is important for
    programming tasks containing decorators such as ``@dataclass`` and for
    quoted social handles.  Multiple leading recipients may be separated by
    whitespace, punctuation, or the word ``and``.
    """
    body = str(getattr(message, "body", "") or "")
    text = body.lstrip()
    cursor = 0
    mentions: List[str] = []
    while cursor < len(text) and text[cursor] == "@":
        match = _CHANNEL_AGENT_MENTION_TOKEN_RE.match(text, cursor)
        if match is None:
            break
        mentions.append(match.group("agent").strip())
        cursor = match.end()
        separator = re.match(r"[\s,;:]+", text[cursor:])
        if separator is None:
            break
        cursor += separator.end()
        conjunction = re.match(r"and\s+(?=@)", text[cursor:], re.IGNORECASE)
        if conjunction is not None:
            cursor += conjunction.end()
        if cursor >= len(text) or text[cursor] != "@":
            break
    return list(dict.fromkeys(mentions))


def _channel_message_target_kind(message: Any) -> str:
    """Return the first provider alias explicitly addressed with an at-sign."""
    for mention in _channel_message_mentions(message):
        kind = _CHANNEL_AGENT_KIND_ALIASES.get(mention.casefold())
        if kind:
            return kind
    return ""


def _channel_mention_key(value: str) -> str:
    return re.sub(r"[\s_]+", "-", value.strip().casefold())


def _channel_provider_primary_key(
    record: Any,
) -> Tuple[int, int, int, int, str, str]:
    """Rank duplicate provider instances for a single alias mention.

    Provider aliases such as ``@hermes`` address one primary instance.  A
    deliberate fan-out must use ``@all`` or multiple explicit Agent mentions.
    The ordering is deterministic so retries keep targeting the same healthy
    process until its observable state changes.
    """
    provider_state = str(getattr(record, "provider_state", "unknown") or "unknown")
    provider_rank = {"ready": 2, "unknown": 1, "degraded": 0}.get(
        provider_state,
        0,
    )
    return (
        int(bool(getattr(record, "alive", False))),
        int(
            bool(getattr(record, "a2a_ready", False))
            and isinstance(getattr(record, "a2a_port", None), int)
        ),
        int(bool(getattr(record, "cap_token_id", None))),
        provider_rank,
        str(getattr(record, "started_at", "") or ""),
        str(getattr(record, "agent_id", "") or ""),
    )


def _resolve_channel_message_target_dids(
    message: Any,
    records: List[Any],
    members: set,
) -> Tuple[set, List[str], bool]:
    """Resolve explicit metadata or mentions to channel-member DIDs.

    The boolean indicates whether the message explicitly selected a target.
    An empty DID set with targeted=True means all. Unknown mentions are
    returned separately so dispatch fails visibly instead of widening an
    intended private instruction to every channel Agent.
    """
    explicit = set(_channel_message_target_dids(message))
    if explicit:
        return explicit, [], True

    mentions = _channel_message_mentions(message)
    if not mentions:
        return set(), [], False
    if any(mention.casefold() == "all" for mention in mentions):
        return set(), [], True

    resolved: set = set()
    unresolved: List[str] = []
    for mention in mentions:
        folded = mention.casefold()
        alias_kind = _CHANNEL_AGENT_KIND_ALIASES.get(folded)
        if alias_kind:
            provider_matches = [
                rec for rec in records
                if str(getattr(rec, "did", "") or "") in members
                and str(getattr(rec, "kind", "") or "") == alias_kind
                and _channel_dispatch_kind_allowed(alias_kind)
            ]
            if provider_matches:
                primary = max(provider_matches, key=_channel_provider_primary_key)
                resolved.add(str(getattr(primary, "did", "") or ""))
            else:
                unresolved.append(mention)
            continue

        matches: set = set()
        for rec in records:
            did = str(getattr(rec, "did", "") or "")
            if did not in members:
                continue
            kind = str(getattr(rec, "kind", "") or "")
            if not _channel_dispatch_kind_allowed(kind):
                continue
            if mention.startswith("did:"):
                if did == mention:
                    matches.add(did)
                continue
            agent_id = str(getattr(rec, "agent_id", "") or "")
            label = str(getattr(rec, "label", "") or "")
            if _channel_mention_key(mention) in {
                _channel_mention_key(agent_id),
                _channel_mention_key(label),
            }:
                matches.add(did)
        if matches:
            resolved.update(matches)
        else:
            unresolved.append(mention)
    return resolved, unresolved, True


def _maybe_dispatch_to_channel_agents(request: Request, channel_id: str, message) -> None:
    """P2:频道收到**人类**消息后,派发给频道里可驱动的 agent 成员,各自回帖。

    可驱动 = supervisor 里 alive + 有 a2a_port + 有 cap_token、且 did 在频道
    member_ids 里。防环:作者本身是可驱动 agent(它的回帖)→ 不派发。
    整体 try 兜底:派发失败绝不影响发消息本身。
    """
    try:
        # groups 挂在 app.state.nth;supervisor 挂在 app.state(见
        # _state_supervisor)。两者 state 对象不同,别搞混。
        groups = getattr(request.app.state.nth, "groups", None)
        sup = getattr(request.app.state, "v2_supervisor", None)  # 只用已构建的
        if groups is None:
            return
        channel = groups.get_channel(channel_id)
        if channel is None:
            return
        if sup is None:
            _post_channel_dispatch_not_started(
                groups,
                channel_id,
                str(getattr(message, "sender_id", "") or "admin"),
                str(getattr(message, "message_id", "") or ""),
                "No online Agent is available; instruction was not started.",
                metadata={"agent_did": ""},
            )
            return
        members = set(channel.member_ids or [])
        store = _state_cap_tokens_store(request)
        records = list(sup.list_agents())
        requested_dids, unresolved_mentions, explicitly_targeted = (
            _resolve_channel_message_target_dids(message, records, members)
        )
        if unresolved_mentions:
            rendered = ", ".join(f"@{name}" for name in unresolved_mentions)
            _post_channel_dispatch_not_started(
                groups,
                channel_id,
                str(getattr(message, "sender_id", "") or "admin"),
                str(getattr(message, "message_id", "") or ""),
                f"No channel Agent matches {rendered}; instruction was not started.",
                metadata={
                    "agent_did": "",
                    "unresolved_mentions": unresolved_mentions,
                },
            )
            return

        receipts_store = _state_receipts_store(request)
        targets: List[Tuple[Any, str, int, str, str, Any]] = []
        driver_dids: set = set()
        degraded_dids: List[str] = []
        from nth_dao.cap_token import CAP_A2A_MESSAGE_SEND

        for rec in records:
            did = getattr(rec, "did", "") or ""
            port = getattr(rec, "a2a_port", None)
            tok_id = getattr(rec, "cap_token_id", None)
            backend_kind = getattr(rec, "kind", "") or ""
            if not _channel_dispatch_kind_allowed(backend_kind):
                continue
            if did not in members or not isinstance(port, int) or not tok_id:
                continue
            if requested_dids and did not in requested_dids:
                continue
            try:
                alive = bool(rec.to_agent_entry().get("alive"))
            except Exception:  # noqa: BLE001
                alive = False
            if not alive:
                continue
            if not bool(getattr(rec, "a2a_ready", True)):
                continue
            if getattr(rec, "provider_state", "unknown") == "degraded":
                # Circuit-breaker half-open path: do not route repeatedly
                # during the backoff, but allow the first later instruction
                # to probe a provider that may have recovered.
                if _channel_dispatch_provider_recovery_in_cooldown(
                    channel_id, did,
                ):
                    degraded_dids.append(did)
                    continue
            driver_dids.add(did)
            try:
                auth = store.get(tok_id) if store is not None else None
            except (OSError, ValueError, TypeError) as exc:
                logger.warning("channel cap_token read failed for %s: %s", did, exc)
                continue
            if not _cap_token_usable(
                auth,
                store,
                required_capabilities=[CAP_A2A_MESSAGE_SEND],
            ):
                try:
                    auth = _refresh_supervised_agent_cap_token(
                        request,
                        rec,
                        previous_token=auth if isinstance(auth, dict) else None,
                    )
                except HTTPException as exc:
                    logger.warning(
                        "channel cap_token refresh failed for %s: %s",
                        did,
                        exc.detail,
                    )
                    continue
            targets.append((
                auth,
                did,
                port,
                getattr(rec, "agent_id", "") or "",
                backend_kind,
                rec,
            ))

        # 防环:消息作者本身就是可驱动 agent → 这是 agent 的回帖,不再派发。
        if message.sender_id in driver_dids:
            return
        if targets and requested_dids:
            ready_dids = {target[1] for target in targets}
            for unavailable_did in sorted(requested_dids - ready_dids):
                _post_channel_dispatch_status(
                    groups,
                    channel_id,
                    unavailable_did,
                    str(getattr(message, "message_id", "") or ""),
                    _CHANNEL_DISPATCH_PHASE_FAILED,
                    "Selected Agent is not ready; instruction was not started for it.",
                    metadata={"target_agent_dids": [unavailable_did]},
                )
        if not targets:
            degraded = bool(degraded_dids)
            target_description = (
                "Mentioned Agent" if explicitly_targeted else "Agent"
            )
            _post_channel_dispatch_not_started(
                groups,
                channel_id,
                str(getattr(message, "sender_id", "") or "admin"),
                str(getattr(message, "message_id", "") or ""),
                (
                    "Agent provider is recovering after a previous failure; "
                    f"retry after the {int(_CHANNEL_DISPATCH_PROVIDER_RECOVERY_COOLDOWN_S)}s "
                    "recovery window."
                    if degraded else
                    f"No ready {target_description} with a usable capability token is available; "
                    "instruction was not started."
                ),
                metadata={
                    "agent_did": degraded_dids[0] if len(degraded_dids) == 1 else "",
                    "provider_state": "degraded" if degraded else "unknown",
                    "target_agent_dids": sorted(requested_dids),
                    "explicitly_targeted": explicitly_targeted,
                },
            )
            return

        try:
            link_manager = _state_agent_link(request)
        except (OSError, RuntimeError, ValueError, TypeError) as exc:
            logger.warning("channel AgentLink unavailable: %s", exc)
            _post_channel_dispatch_not_started(
                groups,
                channel_id,
                str(getattr(message, "sender_id", "") or "admin"),
                str(getattr(message, "message_id", "") or ""),
                "Agent link is unavailable; instruction was not started.",
                metadata={"agent_did": "", "link_error": type(exc).__name__},
            )
            return

        for auth, did, port, agent_id, backend_kind, work_record in targets:
            # 并发封顶:抢一个在飞槽位,抢不到就丢弃这条派发(不堆线程)。
            # 槽位由 _channel_ask_and_reply 的 finally 归还。
            request_message_id = str(getattr(message, "message_id", "") or "")
            try:
                job_ref: Dict[str, str] = {}

                def run_channel_link(
                    *,
                    auth=auth,
                    did=did,
                    port=port,
                    agent_id=agent_id,
                    backend_kind=backend_kind,
                    work_record=work_record,
                    request_message_id=request_message_id,
                    job_ref=job_ref,
                ):
                    if not _CHANNEL_DISPATCH_SEM.acquire(blocking=False):
                        message_text = (
                            "Agent capacity is full; instruction was not started."
                        )
                        _post_channel_dispatch_status(
                            groups,
                            channel_id,
                            did,
                            request_message_id,
                            _CHANNEL_DISPATCH_PHASE_FAILED,
                            message_text,
                            metadata={"link_job_id": job_ref.get("job_id", "")},
                        )
                        return {"error": message_text}
                    return _channel_ask_and_reply(
                        groups,
                        auth,
                        did,
                        port,
                        channel_id,
                        message.body,
                        receipts_store,
                        agent_id,
                        backend_kind,
                        request_message_id,
                        job_ref.get("job_id", ""),
                        sup,
                        semaphore_acquired=True,
                        request=request,
                        work_record=work_record,
                    )

                link_job = link_manager.submit(
                    agent_id=agent_id,
                    agent_did=did,
                    idempotency_key=request_message_id,
                    request_hash=_agent_link_request_hash(
                        message.body,
                        _channel_dispatch_ask_timeout(backend_kind),
                        channel_id=channel_id,
                        request_message_id=request_message_id,
                    ),
                    prompt_sha256=_agent_link_prompt_hash(message.body),
                    channel_id=channel_id,
                    request_message_id=request_message_id,
                    worker=run_channel_link,
                    autostart=False,
                )
            except Exception as exc:  # noqa: BLE001
                _post_channel_dispatch_status(
                    groups,
                    channel_id,
                    did,
                    request_message_id,
                    _CHANNEL_DISPATCH_PHASE_FAILED,
                    "Agent inbox is unavailable; instruction was not started.",
                    metadata={"link_error": type(exc).__name__},
                )
                logger.warning(
                    "channel AgentLink submission failed for %s: %s", did, exc,
                )
                continue
            job_ref["job_id"] = link_job.job_id
            _post_channel_dispatch_status(
                groups,
                channel_id,
                did,
                request_message_id,
                _CHANNEL_DISPATCH_PHASE_QUEUED,
                "Hub queued the instruction for this Agent.",
                metadata={"link_job_id": link_job.job_id},
            )
            try:
                link_manager.start(did)
            except Exception as exc:  # noqa: BLE001
                try:
                    link_manager.store.transition(
                        link_job.job_id,
                        "failed",
                        error=f"Agent inbox could not start: {type(exc).__name__}",
                    )
                except Exception:
                    logger.exception(
                        "channel AgentLink start failure could not be persisted for %s",
                        did,
                    )
                _post_channel_dispatch_status(
                    groups,
                    channel_id,
                    did,
                    request_message_id,
                    _CHANNEL_DISPATCH_PHASE_FAILED,
                    "Agent inbox could not start; instruction was not processed.",
                    metadata={"link_job_id": link_job.job_id},
                )
    except Exception as exc:  # noqa: BLE001
        logger.warning("channel dispatch hook failed: %s", exc)


_FED_POLLER_LOCK = threading.Lock()
_FED_CONFIG_LOCK = threading.RLock()
_FED_CONFIG_LOCK_STATE = threading.local()
_FED_IDENTITY_INIT_LOCK = threading.Lock()
_FED_HELLO_LIMITER_LOCK = threading.Lock()
_TRADE_PACKAGE_SERVE_BYTES_PER_SOURCE = 64 * 1024 * 1024
_TRADE_PACKAGE_SERVE_BYTES_GLOBAL = 256 * 1024 * 1024
_TRADE_PACKAGE_SERVE_WINDOW_SECONDS = 60.0
_TRADE_PACKAGE_SERVE_MAX_CONCURRENCY = 2
_TRADE_PACKAGE_SERVE_REQUESTS_PER_SOURCE = 12
_TRADE_PACKAGE_SERVE_REQUESTS_GLOBAL = 48
# 单个联邦 digest 的 ref 上限(serve 侧防无界响应;超出由拉方带 since 翻页)。
_FED_DIGEST_PAGE = 500


def _fed_peers_file(ws: Optional[Path]) -> Optional[Path]:
    if ws is None:
        return None
    return ws / "federation" / "peers.json"


def _fed_peer_metadata_file(ws: Optional[Path]) -> Optional[Path]:
    """Return the local cache of identity cards verified for seed peers.

    ``peers.json`` remains a list of URLs for wire/backward compatibility.
    Verification metadata lives beside it, so older callers and existing
    workspaces do not need a schema migration.
    """
    if ws is None:
        return None
    return ws / "federation" / "peers_meta.json"


def _fed_peer_transaction_file(ws: Optional[Path]) -> Optional[Path]:
    if ws is None:
        return None
    return ws / "federation" / "peer_registry.txn.json"


def _state_trade_execution_dispatch(request: Request) -> Optional[Any]:
    try:
        return request.app.state.nth.trade_execution_dispatch
    except AttributeError:
        return None


def _state_trade_execution_dispatch_store(request: Request) -> Optional[Any]:
    try:
        return request.app.state.nth.trade_execution_dispatch_store
    except AttributeError:
        return None


def _state_trade_execution_receipt_delivery_limiter(
    request: Request,
) -> Optional[Any]:
    try:
        return request.app.state.nth.trade_execution_receipt_delivery_limiter
    except AttributeError:
        return None


def _state_trade_execution_receipt_delivery_global_limiter(
    request: Request,
) -> Optional[Any]:
    try:
        return (
            request.app.state.nth
            .trade_execution_receipt_delivery_global_limiter
        )
    except AttributeError:
        return None


def _state_trade_receipt_review_coordinator(
    request: Request,
) -> Optional[Any]:
    try:
        return request.app.state.nth.trade_receipt_review_coordinator
    except AttributeError:
        return None


def _state_trade_receipt_review_store(request: Request) -> Optional[Any]:
    try:
        return request.app.state.nth.trade_receipt_reviews
    except AttributeError:
        return None


def _state_trade_receipt_review_dispatch(request: Request) -> Optional[Any]:
    try:
        return request.app.state.nth.trade_receipt_review_dispatch
    except AttributeError:
        return None


def _state_trade_receipt_review_dispatch_store(
    request: Request,
) -> Optional[Any]:
    try:
        return request.app.state.nth.trade_receipt_review_dispatch_store
    except AttributeError:
        return None


def _state_trade_receipt_review_delivery_limiter(
    request: Request,
) -> Optional[Any]:
    try:
        return request.app.state.nth.trade_receipt_review_delivery_limiter
    except AttributeError:
        return None


def _state_trade_receipt_review_delivery_global_limiter(
    request: Request,
) -> Optional[Any]:
    try:
        return (
            request.app.state.nth
            .trade_receipt_review_delivery_global_limiter
        )
    except AttributeError:
        return None


def _state_trade_dispute_statement_audit(request: Request) -> Optional[Any]:
    try:
        return request.app.state.nth.trade_dispute_statement_audit
    except AttributeError:
        return None


def _state_trade_dispute_statement_store(request: Request) -> Optional[Any]:
    try:
        return request.app.state.nth.trade_dispute_statements
    except AttributeError:
        return None


def _state_trade_dispute_statement_dispatch(request: Request) -> Optional[Any]:
    try:
        return request.app.state.nth.trade_dispute_statement_dispatch
    except AttributeError:
        return None


def _state_trade_dispute_statement_dispatch_store(
    request: Request,
) -> Optional[Any]:
    try:
        return request.app.state.nth.trade_dispute_statement_dispatch_store
    except AttributeError:
        return None


def _state_trade_dispute_statement_intake_journal(
    request: Request,
) -> Optional[Any]:
    try:
        return request.app.state.nth.trade_dispute_statement_intake_journal
    except AttributeError:
        return None


def _state_trade_dispute_statement_delivery_limiter(
    request: Request,
) -> Optional[Any]:
    try:
        return request.app.state.nth.trade_dispute_statement_delivery_limiter
    except AttributeError:
        return None


def _state_trade_dispute_statement_delivery_global_limiter(
    request: Request,
) -> Optional[Any]:
    try:
        return (
            request.app.state.nth
            .trade_dispute_statement_delivery_global_limiter
        )
    except AttributeError:
        return None


def _state_trade_dispute_statement_fetch_journal(
    request: Request,
) -> Optional[Any]:
    try:
        return request.app.state.nth.trade_dispute_statement_fetch_journal
    except AttributeError:
        return None


def _state_trade_dispute_statement_fetch_outbox(
    request: Request,
) -> Optional[Any]:
    try:
        return request.app.state.nth.trade_dispute_statement_fetch_outbox
    except AttributeError:
        return None


def _state_trade_dispute_statement_fetch_limiter(
    request: Request,
) -> Optional[Any]:
    try:
        return request.app.state.nth.trade_dispute_statement_fetch_limiter
    except AttributeError:
        return None


def _state_trade_dispute_statement_fetch_global_limiter(
    request: Request,
) -> Optional[Any]:
    try:
        return request.app.state.nth.trade_dispute_statement_fetch_global_limiter
    except AttributeError:
        return None


def _trade_dispute_statement_fetch_coordinator(
    request: Request,
    *,
    order_digest: str,
    journal: Any,
    statement_store: Any,
    identity: Any,
    spine: Any,
    package_resolver: Any,
) -> Any:
    """Return one bounded order-scoped responder with reusable verify caches."""

    from nth_dao.trade_rules import TradeDisputeStatementFetchCoordinator

    state = request.app.state.nth
    lock = getattr(
        state,
        "trade_dispute_statement_fetch_coordinator_lock",
        None,
    )
    coordinators = getattr(
        state,
        "trade_dispute_statement_fetch_coordinators",
        None,
    )
    if lock is None or coordinators is None:
        raise RuntimeError("trade Dispute Statement fetch cache unavailable")
    with lock:
        now_mono = time.monotonic()
        coordinator_ttl = float(
            getattr(
                state,
                "trade_dispute_statement_fetch_coordinator_ttl_seconds",
                300.0,
            )
        )
        for cached_order_digest, cached_coordinator in tuple(coordinators.items()):
            last_used = float(
                getattr(cached_coordinator, "web_cache_last_used", now_mono)
            )
            if now_mono - last_used >= coordinator_ttl:
                coordinators.pop(cached_order_digest, None)
        coordinator = coordinators.get(order_digest)
        if coordinator is not None and (
            coordinator.journal is journal
            and coordinator.statement_store is statement_store
            and coordinator.responder_identity is identity
            and coordinator.spine is spine
        ):
            coordinator.web_cache_last_used = now_mono
            coordinators.move_to_end(order_digest)
            return coordinator
        if coordinator is not None:
            coordinators.pop(order_digest, None)
        coordinator = TradeDisputeStatementFetchCoordinator(
            journal,
            statement_store,
            responder_identity=identity,
            spine=spine,
            package_resolver=package_resolver,
            cache_max_bytes=int(
                getattr(
                    state,
                    "trade_dispute_statement_fetch_cache_bytes_per_coordinator",
                    2 * 1024 * 1024,
                )
            ),
        )
        coordinator.web_cache_last_used = now_mono
        coordinators[order_digest] = coordinator
        coordinators.move_to_end(order_digest)
        max_coordinators = int(
            getattr(
                state,
                "trade_dispute_statement_fetch_max_coordinators",
                8,
            )
        )
        while len(coordinators) > max_coordinators:
            coordinators.popitem(last=False)
        return coordinator


def _learned_fed_peer_store(ws: Optional[Path]):
    if ws is None:
        return None
    from nth_dao.discovery.federation_registry import LearnedPeerStore

    return LearnedPeerStore(ws)


def _read_learned_fed_peer_records(ws: Optional[Path]) -> List[Any]:
    store = _learned_fed_peer_store(ws)
    if store is None:
        return []
    try:
        return store.active()
    except (OSError, TimeoutError, ValueError) as exc:
        logger.warning("fed: learned peer registry read failed: %s", exc)
        return []


def _read_learned_fed_peers(ws: Optional[Path]) -> List[str]:
    return [record.peer_url for record in _read_learned_fed_peer_records(ws)]


def _federation_hello_limiter(request: Request):
    state = request.app.state
    limiter = getattr(state, "market_fed_hello_limiter", None)
    if limiter is not None:
        return limiter
    with _FED_HELLO_LIMITER_LOCK:
        limiter = getattr(state, "market_fed_hello_limiter", None)
        if limiter is None:
            from nth_dao.web.rate_limit import PersistentRateLimiter, RateLimiter

            ws = _state_workspace(request)
            limiter = (
                PersistentRateLimiter(
                    ws / "federation" / "hello_rate_limit.json",
                    max_per_window=12,
                    window_seconds=60.0,
                    max_tracked_keys=4096,
                )
                if ws is not None
                else RateLimiter(
                    max_per_window=12,
                    window_seconds=60.0,
                    max_tracked_keys=4096,
                )
            )
            state.market_fed_hello_limiter = limiter
    return limiter


def _trade_offer_read_limiter(request: Request):
    """Apply a cheap process-local gate before any persistent limiter I/O."""
    state = request.app.state
    limiter = getattr(state, "trade_offer_fed_read_limiter", None)
    if limiter is not None:
        return limiter
    with _FED_HELLO_LIMITER_LOCK:
        limiter = getattr(state, "trade_offer_fed_read_limiter", None)
        if limiter is None:
            from nth_dao.web.rate_limit import RateLimiter

            limiter = RateLimiter(
                max_per_window=120,
                window_seconds=60.0,
                max_tracked_keys=4_096,
            )
            state.trade_offer_fed_read_limiter = limiter
    return limiter


def _trade_offer_read_global_limiter(request: Request):
    """Bound aggregate exact Offer reads across all network sources."""
    state = request.app.state
    limiter = getattr(state, "trade_offer_fed_read_global_limiter", None)
    if limiter is not None:
        return limiter
    with _FED_HELLO_LIMITER_LOCK:
        limiter = getattr(state, "trade_offer_fed_read_global_limiter", None)
        if limiter is None:
            from nth_dao.web.rate_limit import PersistentRateLimiter, RateLimiter

            workspace = _state_workspace(request)
            limiter = (
                PersistentRateLimiter(
                    workspace
                    / "trade"
                    / "rate_limits"
                    / "offer_read_global.json",
                    max_per_window=300,
                    window_seconds=60.0,
                    max_tracked_keys=4,
                )
                if workspace is not None
                else RateLimiter(
                    max_per_window=300,
                    window_seconds=60.0,
                    max_tracked_keys=4,
                )
            )
            state.trade_offer_fed_read_global_limiter = limiter
    return limiter


def _require_trade_offer_public_read_budget(request: Request) -> None:
    """Apply the shared per-source and aggregate public Offer read budget."""

    try:
        source_decision = _trade_offer_read_limiter(request).check(
            _federation_hello_client_key(request)
        )
        if not source_decision.allowed:
            retry_after = max(
                1, int(source_decision.retry_after_seconds) + 1
            )
            raise HTTPException(
                status_code=429,
                detail="Trade Offer federation read rate exceeded",
                headers={"Retry-After": str(retry_after)},
            )
        global_decision = _trade_offer_read_global_limiter(request).check(
            "global"
        )
    except HTTPException:
        raise
    except (OSError, TimeoutError, ValueError) as exc:
        raise HTTPException(
            status_code=503,
            detail="Trade Offer read budget is temporarily unavailable",
        ) from exc
    if not global_decision.allowed:
        retry_after = max(1, int(global_decision.retry_after_seconds) + 1)
        raise HTTPException(
            status_code=429,
            detail="Trade Offer federation read rate exceeded",
            headers={"Retry-After": str(retry_after)},
        )


def _trade_rule_package_byte_limiter(request: Request):
    state = request.app.state
    limiter = getattr(state, "trade_rule_package_byte_limiter", None)
    if limiter is not None:
        return limiter
    with _FED_HELLO_LIMITER_LOCK:
        limiter = getattr(state, "trade_rule_package_byte_limiter", None)
        if limiter is None:
            from nth_dao.web.rate_limit import (
                PersistentRateBudgetLimiter,
                RateBudgetLimiter,
            )

            workspace = _state_workspace(request)
            limiter = (
                PersistentRateBudgetLimiter(
                    workspace
                    / "trade"
                    / "rate_limits"
                    / "rule_package_bytes.json",
                    max_cost_per_window=_TRADE_PACKAGE_SERVE_BYTES_PER_SOURCE,
                    window_seconds=_TRADE_PACKAGE_SERVE_WINDOW_SECONDS,
                    max_tracked_keys=4096,
                )
                if workspace is not None
                else RateBudgetLimiter(
                    max_cost_per_window=_TRADE_PACKAGE_SERVE_BYTES_PER_SOURCE,
                    window_seconds=_TRADE_PACKAGE_SERVE_WINDOW_SECONDS,
                    max_tracked_keys=4096,
                )
            )
            state.trade_rule_package_byte_limiter = limiter
    return limiter


def _trade_rule_package_request_limiter(request: Request):
    state = request.app.state
    limiter = getattr(state, "trade_rule_package_request_limiter", None)
    if limiter is not None:
        return limiter
    with _FED_HELLO_LIMITER_LOCK:
        limiter = getattr(state, "trade_rule_package_request_limiter", None)
        if limiter is None:
            from nth_dao.web.rate_limit import PersistentRateLimiter, RateLimiter

            workspace = _state_workspace(request)
            limiter = (
                PersistentRateLimiter(
                    workspace
                    / "trade"
                    / "rate_limits"
                    / "rule_package_requests.json",
                    max_per_window=_TRADE_PACKAGE_SERVE_REQUESTS_PER_SOURCE,
                    window_seconds=_TRADE_PACKAGE_SERVE_WINDOW_SECONDS,
                    max_tracked_keys=4096,
                )
                if workspace is not None
                else RateLimiter(
                    max_per_window=_TRADE_PACKAGE_SERVE_REQUESTS_PER_SOURCE,
                    window_seconds=_TRADE_PACKAGE_SERVE_WINDOW_SECONDS,
                    max_tracked_keys=4096,
                )
            )
            state.trade_rule_package_request_limiter = limiter
    return limiter


def _trade_rule_package_global_request_limiter(request: Request):
    state = request.app.state
    limiter = getattr(state, "trade_rule_package_global_request_limiter", None)
    if limiter is not None:
        return limiter
    with _FED_HELLO_LIMITER_LOCK:
        limiter = getattr(state, "trade_rule_package_global_request_limiter", None)
        if limiter is None:
            from nth_dao.web.rate_limit import PersistentRateLimiter, RateLimiter

            workspace = _state_workspace(request)
            limiter = (
                PersistentRateLimiter(
                    workspace
                    / "trade"
                    / "rate_limits"
                    / "rule_package_requests_global.json",
                    max_per_window=_TRADE_PACKAGE_SERVE_REQUESTS_GLOBAL,
                    window_seconds=_TRADE_PACKAGE_SERVE_WINDOW_SECONDS,
                    max_tracked_keys=4,
                )
                if workspace is not None
                else RateLimiter(
                    max_per_window=_TRADE_PACKAGE_SERVE_REQUESTS_GLOBAL,
                    window_seconds=_TRADE_PACKAGE_SERVE_WINDOW_SECONDS,
                    max_tracked_keys=4,
                )
            )
            state.trade_rule_package_global_request_limiter = limiter
    return limiter


def _require_trade_rule_package_request_budget(request: Request) -> None:
    try:
        source = _trade_rule_package_request_limiter(request).check(
            _federation_hello_client_key(request)
        )
        if not source.allowed:
            raise HTTPException(
                status_code=429,
                detail="Trade Rule Package request budget exceeded",
                headers={
                    "Retry-After": str(max(1, int(source.retry_after_seconds) + 1))
                },
            )
        global_result = _trade_rule_package_global_request_limiter(request).check(
            "global"
        )
    except HTTPException:
        raise
    except (OSError, TimeoutError, ValueError) as exc:
        raise HTTPException(
            status_code=503,
            detail="Trade Rule Package request budget is temporarily unavailable",
        ) from exc
    if not global_result.allowed:
        raise HTTPException(
            status_code=429,
            detail="Trade Rule Package request budget exceeded",
            headers={
                "Retry-After": str(
                    max(1, int(global_result.retry_after_seconds) + 1)
                )
            },
        )


def _trade_rule_package_global_byte_limiter(request: Request):
    state = request.app.state
    limiter = getattr(state, "trade_rule_package_global_byte_limiter", None)
    if limiter is not None:
        return limiter
    with _FED_HELLO_LIMITER_LOCK:
        limiter = getattr(state, "trade_rule_package_global_byte_limiter", None)
        if limiter is None:
            from nth_dao.web.rate_limit import (
                PersistentRateBudgetLimiter,
                RateBudgetLimiter,
            )

            workspace = _state_workspace(request)
            limiter = (
                PersistentRateBudgetLimiter(
                    workspace
                    / "trade"
                    / "rate_limits"
                    / "rule_package_bytes_global.json",
                    max_cost_per_window=_TRADE_PACKAGE_SERVE_BYTES_GLOBAL,
                    window_seconds=_TRADE_PACKAGE_SERVE_WINDOW_SECONDS,
                    max_tracked_keys=4,
                )
                if workspace is not None
                else RateBudgetLimiter(
                    max_cost_per_window=_TRADE_PACKAGE_SERVE_BYTES_GLOBAL,
                    window_seconds=_TRADE_PACKAGE_SERVE_WINDOW_SECONDS,
                    max_tracked_keys=4,
                )
            )
            state.trade_rule_package_global_byte_limiter = limiter
    return limiter


def _require_trade_rule_package_byte_budget(request: Request, byte_count: int) -> None:
    try:
        source = _trade_rule_package_byte_limiter(request).check(
            _federation_hello_client_key(request),
            byte_count,
        )
        if not source.allowed:
            raise HTTPException(
                status_code=429,
                detail="Trade Rule Package byte budget exceeded",
                headers={
                    "Retry-After": str(max(1, int(source.retry_after_seconds) + 1))
                },
            )
        global_result = _trade_rule_package_global_byte_limiter(request).check(
            "global",
            byte_count,
        )
    except HTTPException:
        raise
    except (OSError, TimeoutError, ValueError) as exc:
        raise HTTPException(
            status_code=503,
            detail="Trade Rule Package byte budget is temporarily unavailable",
        ) from exc
    if not global_result.allowed:
        raise HTTPException(
            status_code=429,
            detail="Trade Rule Package byte budget exceeded",
            headers={
                "Retry-After": str(
                    max(1, int(global_result.retry_after_seconds) + 1)
                )
            },
        )


def _trade_rule_package_serve_semaphore(request: Request):
    state = request.app.state
    semaphore = getattr(state, "trade_rule_package_serve_semaphore", None)
    if semaphore is not None:
        return semaphore
    with _FED_HELLO_LIMITER_LOCK:
        semaphore = getattr(state, "trade_rule_package_serve_semaphore", None)
        if semaphore is None:
            semaphore = threading.BoundedSemaphore(
                _TRADE_PACKAGE_SERVE_MAX_CONCURRENCY
            )
            state.trade_rule_package_serve_semaphore = semaphore
    return semaphore


def _cached_rule_recognition_proof_bytes(
    request: Request,
    *,
    cache_key: tuple[str, str, tuple[str, ...]],
    build: Callable[[], bytes],
) -> bytes:
    """Keep a signed observation byte-stable for one short HTTP cache window."""

    state = request.app.state
    guard = getattr(state, "trade_rule_recognition_proof_cache_lock", None)
    if guard is None:
        guard = threading.Lock()
        state.trade_rule_recognition_proof_cache_lock = guard
    with guard:
        now_mono = time.monotonic()
        cache = getattr(state, "trade_rule_recognition_proof_cache", None)
        if not isinstance(cache, dict):
            cache = {}
            state.trade_rule_recognition_proof_cache = cache
        for key, entry in tuple(cache.items()):
            if (
                not isinstance(entry, tuple)
                or len(entry) != 2
                or not isinstance(entry[0], (int, float))
                or entry[0] <= now_mono
            ):
                cache.pop(key, None)
        cached = cache.get(cache_key)
        if (
            isinstance(cached, tuple)
            and len(cached) == 2
            and isinstance(cached[1], bytes)
        ):
            return cached[1]
        raw = build()
        if not isinstance(raw, bytes):
            raise TypeError("Recognition proof builder must return bytes")
        if len(cache) >= 128:
            oldest = min(cache, key=lambda item: cache[item][0])
            cache.pop(oldest, None)
        cache[cache_key] = (now_mono + 30.0, raw)
        return raw


def _cached_rule_recognition_proof_pages(
    request: Request,
    *,
    cache_key: tuple[str, str, tuple[str, ...]],
    build: Callable[[], tuple[bytes, ...]],
) -> tuple[bytes, ...]:
    """Cache one complete signed page set as a byte-stable observation."""

    from nth_dao.trade_rules import (
        MAX_RULE_RECOGNITION_PROOF_PAGE_BYTES,
        MAX_RULE_RECOGNITION_PROOF_PAGE_SET_BYTES,
        MAX_RULE_RECOGNITION_PROOF_PAGES,
    )

    state = request.app.state
    guard = getattr(
        state,
        "trade_rule_recognition_proof_page_cache_lock",
        None,
    )
    if guard is None:
        with _FED_HELLO_LIMITER_LOCK:
            guard = getattr(
                state,
                "trade_rule_recognition_proof_page_cache_lock",
                None,
            )
            if guard is None:
                guard = threading.Lock()
                state.trade_rule_recognition_proof_page_cache_lock = guard
    with guard:
        now_mono = time.monotonic()
        cache = getattr(
            state,
            "trade_rule_recognition_proof_page_cache",
            None,
        )
        if not isinstance(cache, dict):
            cache = {}
            state.trade_rule_recognition_proof_page_cache = cache
        for key, entry in tuple(cache.items()):
            if (
                not isinstance(entry, tuple)
                or len(entry) != 3
                or not isinstance(entry[0], (int, float))
                or entry[0] <= now_mono
                or not isinstance(entry[1], tuple)
                or not entry[1]
                or any(not isinstance(raw, bytes) for raw in entry[1])
                or not isinstance(entry[2], int)
                or entry[2] < 0
                or entry[2] != sum(len(raw) for raw in entry[1])
            ):
                cache.pop(key, None)
        cached = cache.get(cache_key)
        if (
            isinstance(cached, tuple)
            and len(cached) == 3
            and isinstance(cached[1], tuple)
            and all(isinstance(raw, bytes) for raw in cached[1])
        ):
            return cached[1]
        raw_pages = build()
        if (
            not isinstance(raw_pages, tuple)
            or not 1 <= len(raw_pages) <= MAX_RULE_RECOGNITION_PROOF_PAGES
            or any(
                not isinstance(raw, bytes)
                or len(raw) > MAX_RULE_RECOGNITION_PROOF_PAGE_BYTES
                for raw in raw_pages
            )
        ):
            raise TypeError("Recognition proof page builder returned invalid pages")
        total_bytes = sum(len(raw) for raw in raw_pages)
        if total_bytes > MAX_RULE_RECOGNITION_PROOF_PAGE_SET_BYTES:
            raise ValueError("Recognition proof page set exceeds its byte limit")
        while cache and (
            len(cache) >= 32
            or sum(
                entry[2] for entry in cache.values()
            )
            + total_bytes
            > MAX_RULE_RECOGNITION_PROOF_PAGE_SET_BYTES
        ):
            oldest = min(cache, key=lambda item: cache[item][0])
            cache.pop(oldest, None)
        cache[cache_key] = (now_mono + 30.0, raw_pages, total_bytes)
        return raw_pages


def _rule_recognition_federation_disclosure_enabled(
    request: Request,
) -> bool:
    """Require explicit operator consent before relaying Recognition claims."""

    override = getattr(
        request.app.state,
        "nth_rule_recognition_federation_enabled",
        None,
    )
    if override is not None:
        return override is True
    return os.environ.get(
        "NTH_FEDERATE_RULE_RECOGNITIONS",
        "",
    ).strip() == "1"


def _rule_recognition_federation_issuer_allowlist(
    request: Request,
) -> frozenset[str]:
    override = getattr(
        request.app.state,
        "nth_rule_recognition_federation_issuers",
        None,
    )
    if override is not None:
        if isinstance(override, (set, frozenset, tuple, list)):
            return frozenset(
                value.strip()
                for value in override
                if isinstance(value, str) and value.strip()
            )
        return frozenset()
    return frozenset(
        value.strip()
        for value in os.environ.get(
            "NTH_FEDERATE_RULE_RECOGNITION_ISSUERS",
            "",
        ).split(",")
        if value.strip()
    )


def _trade_rule_package_etag(offer_digest: str, package_digest: str) -> str:
    material = f"{offer_digest}\x00{package_digest}".encode("ascii")
    return f'"sha256:{hashlib.sha256(material).hexdigest()}"'


def _trade_rule_package_wire_cost_upper_bound(package: Any) -> int:
    """Conservatively price Bundle bytes before signature and base64 work."""

    manifest_bytes = len(package.manifest.canonical_bytes)
    resource_bytes = sum(
        (len(payload) * 4 + 2) // 3
        for payload in package.resources.values()
    )
    # Each resource entry is under 256 bytes excluding its encoded payload.
    # Four KiB covers the fixed Bundle fields and signed binding document.
    return manifest_bytes + resource_bytes + (len(package.resources) * 256) + 4096


def _if_none_match_matches(request: Request, etag: str) -> bool:
    values = request.headers.get("if-none-match", "")
    for item in values.split(","):
        candidate = item.strip()
        if candidate == "*" or candidate == etag:
            return True
        if candidate.startswith("W/") and candidate[2:].strip() == etag:
            return True
    return False


def _federation_hello_global_limiter(request: Request):
    """Bound aggregate identity-card preflights across all source addresses."""
    state = request.app.state
    limiter = getattr(state, "market_fed_hello_global_limiter", None)
    if limiter is not None:
        return limiter
    with _FED_HELLO_LIMITER_LOCK:
        limiter = getattr(state, "market_fed_hello_global_limiter", None)
        if limiter is None:
            from nth_dao.web.rate_limit import PersistentRateLimiter, RateLimiter

            ws = _state_workspace(request)
            limiter = (
                PersistentRateLimiter(
                    ws / "federation" / "hello_global_rate_limit.json",
                    max_per_window=120,
                    window_seconds=60.0,
                    max_tracked_keys=4,
                )
                if ws is not None
                else RateLimiter(
                    max_per_window=120,
                    window_seconds=60.0,
                    max_tracked_keys=4,
                )
            )
            state.market_fed_hello_global_limiter = limiter
    return limiter


def _foreign_claim_limiter(request: Request):
    """Bound anonymous claim verification per network source."""
    state = request.app.state
    limiter = getattr(state, "market_fed_foreign_claim_limiter", None)
    if limiter is not None:
        return limiter
    with _FED_HELLO_LIMITER_LOCK:
        limiter = getattr(state, "market_fed_foreign_claim_limiter", None)
        if limiter is None:
            from nth_dao.web.rate_limit import PersistentRateLimiter, RateLimiter

            ws = _state_workspace(request)
            limiter = (
                PersistentRateLimiter(
                    ws / "federation" / "foreign_claim_rate_limit.json",
                    max_per_window=30,
                    window_seconds=60.0,
                    max_tracked_keys=4096,
                )
                if ws is not None
                else RateLimiter(
                    max_per_window=30,
                    window_seconds=60.0,
                    max_tracked_keys=4096,
                )
            )
            state.market_fed_foreign_claim_limiter = limiter
    return limiter


def _foreign_claim_global_limiter(request: Request):
    """Bound aggregate anonymous claim verification across source IPs."""
    state = request.app.state
    limiter = getattr(state, "market_fed_foreign_claim_global_limiter", None)
    if limiter is not None:
        return limiter
    with _FED_HELLO_LIMITER_LOCK:
        limiter = getattr(state, "market_fed_foreign_claim_global_limiter", None)
        if limiter is None:
            from nth_dao.web.rate_limit import PersistentRateLimiter, RateLimiter

            ws = _state_workspace(request)
            limiter = (
                PersistentRateLimiter(
                    ws / "federation" / "foreign_claim_global_rate_limit.json",
                    max_per_window=120,
                    window_seconds=60.0,
                    max_tracked_keys=4,
                )
                if ws is not None
                else RateLimiter(
                    max_per_window=120,
                    window_seconds=60.0,
                    max_tracked_keys=4,
                )
            )
            state.market_fed_foreign_claim_global_limiter = limiter
    return limiter


def _federation_hello_client_key(request: Request) -> str:
    """Resolve the rate-limit key without trusting spoofable proxy headers."""
    direct = (
        str(request.client.host).strip()
        if request.client is not None and request.client.host
        else "anonymous"
    )
    trusted: set[str] = set()
    for raw in os.environ.get("NTH_TRUSTED_PROXY_IPS", "").split(","):
        candidate = raw.strip()
        if not candidate:
            continue
        try:
            trusted.add(str(ipaddress.ip_address(candidate)))
        except ValueError:
            logger.warning("ignoring invalid NTH_TRUSTED_PROXY_IPS entry")
    try:
        normalized_direct = str(ipaddress.ip_address(direct))
    except ValueError:
        normalized_direct = direct
    if normalized_direct not in trusted:
        return normalized_direct
    forwarded = request.headers.get("x-forwarded-for", "").split(",", 1)[0].strip()
    try:
        return str(ipaddress.ip_address(forwarded))
    except ValueError:
        return normalized_direct


def _market_fed_announce_self(request: Request):
    """Build a poller callback for reverse discovery, or disable honestly."""
    base_url = str(
        getattr(request.app.state, "nth_public_base_url", "") or ""
    ).strip()
    identity = _state_node_identity(request)
    did = (
        identity.as_did()
        if identity is not None and hasattr(identity, "as_did")
        else ""
    )
    if not base_url or not did:
        return None
    try:
        from nth_dao.discovery.federation_registry import normalize_learned_peer_url

        base_url = normalize_learned_peer_url(base_url)
    except ValueError:
        # LAN HTTP advertisements are handled by LAN/mDNS discovery. Reverse
        # internet federation only advertises HTTPS endpoints.
        return None

    def announce(peers: List[str]) -> Dict[str, str]:
        from .market_federation_poll import announce_peer_hello

        return announce_peer_hello(peers, peer_url=base_url, did=did)

    return announce


_MAX_FED_DISCOVERY_CANDIDATES = 32
_MAX_FED_SEED_PEERS = 128
_MAX_FED_CONFIG_BYTES = 512 * 1024
_MAX_OPERATOR_TRADE_PEER_ADDRESSES = 8


class FederationSeedCapacityError(ValueError):
    """Raised when approved operator seed persistence reaches its bound."""


class FederationSeedConfigError(ValueError):
    """Raised when a damaged seed registry must not be overwritten."""


@contextmanager
def _fed_config_guard(ws: Optional[Path]) -> Iterator[None]:
    """Serialize one peer-registry transaction across threads and processes."""

    transaction = _fed_peer_transaction_file(ws)
    lock_key = str(transaction) if transaction is not None else "<unavailable>"
    with _FED_CONFIG_LOCK:
        held = getattr(_FED_CONFIG_LOCK_STATE, "held", set())
        if lock_key in held:
            yield
            return
        next_held = set(held)
        next_held.add(lock_key)
        _FED_CONFIG_LOCK_STATE.held = next_held
        try:
            if transaction is None:
                yield
            else:
                try:
                    with InterProcessLock(transaction, timeout=10.0):
                        yield
                except TimeoutError as exc:
                    raise FederationSeedConfigError(
                        "federation peer registry is busy",
                    ) from exc
        finally:
            remaining = set(getattr(_FED_CONFIG_LOCK_STATE, "held", set()))
            remaining.discard(lock_key)
            _FED_CONFIG_LOCK_STATE.held = remaining


def _normalize_configured_fed_peer(url: str) -> str:
    """Validate and normalize an operator-configured federation seed URL.

    Seed peers are explicit operator input, so local/LAN http URLs are allowed
    for development and two-PC testing. Automatically gossiped peers remain
    restricted by market_federation_poll._is_safe_gossip_url before use.
    """
    from nth_dao.plugins.federation_trust import normalize_federation_peer_url

    return normalize_federation_peer_url(str(url or ""))


def _resolve_operator_trade_peer_ips(url: str) -> tuple[str, ...]:
    """Resolve every safe pinned address for an operator-selected peer.

    DNS is validated as one set before any connection is attempted, so a host
    cannot mix a public/LAN address with loopback or other unsafe answers.  The
    explicit ``localhost`` name is the sole hostname allowed to resolve to
    loopback; IPv4 is preferred there because NTH DAO binds to 127.0.0.1 by
    default, while bounded connection fallback still supports IPv6-only peers.
    """

    parsed = urlsplit(url)
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise ValueError("trade peer URL must include a host")

    def allowed_non_loopback(
        address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    ) -> bool:
        return not (
            address.is_loopback
            or address.is_unspecified
            or address.is_multicast
            or address.is_link_local
            or address.is_reserved
        )

    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if not literal.is_loopback and not allowed_non_loopback(literal):
            raise ValueError("trade peer IP is not routable")
        return (str(literal),)

    try:
        infos = socket.getaddrinfo(host, parsed.port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError("trade peer host cannot be resolved") from exc
    addresses: list[str] = []
    localhost = host == "localhost"
    for info in infos:
        try:
            address = ipaddress.ip_address(info[4][0])
        except (IndexError, TypeError, ValueError) as exc:
            raise ValueError("trade peer returned an invalid DNS address") from exc
        if localhost:
            if not address.is_loopback:
                raise ValueError(
                    "localhost trade peer must resolve only to loopback"
                )
        elif address.is_loopback:
            raise ValueError(
                "trade peer DNS must not redirect a hostname to loopback"
            )
        elif not allowed_non_loopback(address):
            raise ValueError("trade peer DNS includes an unsafe address")
        addresses.append(str(address))
    if not addresses:
        raise ValueError("trade peer host has no usable address")
    unique = list(dict.fromkeys(addresses))
    if len(unique) > _MAX_OPERATOR_TRADE_PEER_ADDRESSES:
        raise ValueError("trade peer DNS returned too many addresses")
    if localhost:
        unique.sort(key=lambda item: (ipaddress.ip_address(item).version != 4, item))
    return tuple(unique)


def _resolve_operator_trade_peer_ip(url: str) -> str:
    """Compatibility projection of the first validated pinned address."""

    return _resolve_operator_trade_peer_ips(url)[0]


def _call_operator_trade_peer_with_fallback(
    url: str,
    operation: Callable[[str, float], Any],
    *,
    timeout_seconds: float,
) -> Any:
    """Try bounded addresses under one shared monotonic deadline."""

    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
    ):
        raise ValueError("timeout_seconds must be finite and positive")
    deadline = time.monotonic() + float(timeout_seconds)
    last_error: OSError | None = None
    for resolved_ip in _resolve_operator_trade_peer_ips(url):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("trade peer request deadline exceeded")
        try:
            return operation(resolved_ip, remaining)
        except urllib.error.HTTPError:
            # A reached HTTP server gave a definitive protocol response.
            raise
        except OSError as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    raise ConnectionError("trade peer has no dialable address")


def _post_trade_order_delivery_to_peer(
    peer_url: str,
    document: dict[str, Any],
    *,
    timeout_seconds: float = 15.0,
) -> tuple[int, dict[str, Any]]:
    """Verify the destination DID, then POST over the same pinned address."""

    from nth_dao.did_key import is_did_key

    normalized = _normalize_configured_fed_peer(peer_url)
    recipient_did = document.get("recipient_did")
    if not isinstance(recipient_did, str) or not is_did_key(recipient_did):
        raise ValueError("Order delivery recipient_did is invalid")
    url = normalized + "/api/v2/trade/federation/orders"

    return _post_json_to_verified_trade_peer(
        normalized,
        url,
        document,
        expected_did=recipient_did,
        identity_field="Order recipient_did",
        timeout_seconds=timeout_seconds,
        max_response_bytes=256 * 1024,
    )


def _post_json_to_verified_trade_peer(
    normalized_peer: str,
    url: str,
    document: dict[str, Any],
    *,
    expected_did: str,
    identity_field: str,
    timeout_seconds: float,
    max_response_bytes: int,
) -> tuple[int, dict[str, Any]]:
    """Challenge one pinned peer identity before sending signed trade JSON."""

    from .market_federation_poll import _urllib_post_json_pinned_raw
    from nth_dao.did_key import is_did_key

    if not isinstance(expected_did, str) or not is_did_key(expected_did):
        raise ValueError(f"{identity_field} is invalid")

    def verify_and_post(
        resolved_ip: str,
        remaining_seconds: float,
    ) -> tuple[int, bytes]:
        started = time.monotonic()
        challenge = secrets.token_hex(32)
        identity_url = (
            normalized_peer
            + "/.well-known/nth-dao/identity.json"
            + f"?challenge={challenge}"
        )
        raw_card = _open_federation_identity_card(
            identity_url,
            min(remaining_seconds, 3.0),
            resolved_ip,
        )
        try:
            card = json.loads(raw_card.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("trade peer returned an invalid identity card") from exc
        metadata, identity_error = _verify_federation_identity_card(
            normalized_peer,
            card,
            expected_challenge=challenge,
        )
        if metadata is None:
            raise ValueError(
                f"trade peer identity verification failed: {identity_error}"
            )
        if not hmac.compare_digest(
            str(metadata.get("did") or ""),
            expected_did,
        ):
            raise ValueError(
                f"trade peer identity does not match {identity_field}"
            )
        post_timeout = remaining_seconds - (time.monotonic() - started)
        if post_timeout <= 0:
            raise TimeoutError("trade peer request deadline exceeded")
        return _urllib_post_json_pinned_raw(
            url,
            resolved_ip,
            document,
            timeout_s=post_timeout,
            max_bytes=max_response_bytes,
        )

    status, raw = _call_operator_trade_peer_with_fallback(
        normalized_peer,
        verify_and_post,
        timeout_seconds=timeout_seconds,
    )
    try:
        response = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("trade peer returned invalid JSON") from exc
    if not isinstance(response, dict):
        raise ValueError("trade peer returned a non-object response")
    return status, response


def _post_trade_execution_receipt_delivery_to_peer(
    peer_url: str,
    order_digest: str,
    document: dict[str, Any],
    *,
    timeout_seconds: float = 15.0,
) -> tuple[int, dict[str, Any]]:
    """Verify the destination DID, then POST over the same pinned address."""

    from nth_dao.did_key import is_did_key

    if re.fullmatch(r"sha256:[0-9a-f]{64}", order_digest) is None:
        raise ValueError("order_digest is invalid")
    normalized = _normalize_configured_fed_peer(peer_url)
    recipient_did = document.get("recipient_did")
    if not isinstance(recipient_did, str) or not is_did_key(recipient_did):
        raise ValueError("Receipt delivery recipient_did is invalid")
    url = (
        normalized
        + f"/api/v2/trade/federation/orders/{order_digest}"
        + "/execution-receipts"
    )

    return _post_json_to_verified_trade_peer(
        normalized,
        url,
        document,
        expected_did=recipient_did,
        identity_field="Receipt recipient_did",
        timeout_seconds=timeout_seconds,
        max_response_bytes=256 * 1024,
    )


def _post_trade_receipt_review_delivery_to_peer(
    peer_url: str,
    order_digest: str,
    execution_id: str,
    document: dict[str, Any],
    *,
    timeout_seconds: float = 15.0,
) -> tuple[int, dict[str, Any]]:
    """Verify the execution peer DID, then POST a signed Review."""

    from nth_dao.did_key import is_did_key

    if re.fullmatch(r"sha256:[0-9a-f]{64}", order_digest) is None:
        raise ValueError("order_digest is invalid")
    if re.fullmatch(
        r"nth-trade-execution-sha256:[0-9a-f]{64}",
        execution_id,
    ) is None:
        raise ValueError("execution_id is invalid")
    normalized = _normalize_configured_fed_peer(peer_url)
    recipient_did = document.get("recipient_did")
    if not isinstance(recipient_did, str) or not is_did_key(recipient_did):
        raise ValueError("Review delivery recipient_did is invalid")
    url = (
        normalized
        + f"/api/v2/trade/federation/orders/{order_digest}"
        + f"/execution-receipts/{execution_id}/reviews"
    )

    return _post_json_to_verified_trade_peer(
        normalized,
        url,
        document,
        expected_did=recipient_did,
        identity_field="Review recipient_did",
        timeout_seconds=timeout_seconds,
        max_response_bytes=256 * 1024,
    )


def _post_trade_dispute_statement_delivery_to_peer(
    peer_url: str,
    order_digest: str,
    execution_id: str,
    review_id: str,
    document: dict[str, Any],
    *,
    timeout_seconds: float = 15.0,
) -> tuple[int, dict[str, Any]]:
    """Verify the counterparty DID, then POST one signed claim."""

    from nth_dao.did_key import is_did_key

    if re.fullmatch(r"sha256:[0-9a-f]{64}", order_digest) is None:
        raise ValueError("order_digest is invalid")
    if re.fullmatch(
        r"nth-trade-execution-sha256:[0-9a-f]{64}",
        execution_id,
    ) is None:
        raise ValueError("execution_id is invalid")
    if re.fullmatch(
        r"nth-trade-review-sha256:[0-9a-f]{64}",
        review_id,
    ) is None:
        raise ValueError("review_id is invalid")
    normalized = _normalize_configured_fed_peer(peer_url)
    recipient_did = document.get("recipient_did")
    if not isinstance(recipient_did, str) or not is_did_key(recipient_did):
        raise ValueError("Statement delivery recipient_did is invalid")
    url = (
        normalized
        + f"/api/v2/trade/federation/orders/{order_digest}"
        + f"/execution-receipts/{execution_id}/reviews/{review_id}"
        + "/dispute-statements"
    )

    return _post_json_to_verified_trade_peer(
        normalized,
        url,
        document,
        expected_did=recipient_did,
        identity_field="Statement recipient_did",
        timeout_seconds=timeout_seconds,
        max_response_bytes=256 * 1024,
    )


def _post_trade_dispute_statement_fetch_to_peer(
    peer_url: str,
    order_digest: str,
    execution_id: str,
    review_id: str,
    document: dict[str, Any],
    *,
    timeout_seconds: float = 15.0,
) -> tuple[int, dict[str, Any]]:
    """Verify the responder DID, then POST one signed Fetch Request."""

    from nth_dao.did_key import is_did_key

    if re.fullmatch(r"sha256:[0-9a-f]{64}", order_digest) is None:
        raise ValueError("order_digest is invalid")
    if (
        re.fullmatch(
            r"nth-trade-execution-sha256:[0-9a-f]{64}",
            execution_id,
        )
        is None
    ):
        raise ValueError("execution_id is invalid")
    if (
        re.fullmatch(
            r"nth-trade-review-sha256:[0-9a-f]{64}",
            review_id,
        )
        is None
    ):
        raise ValueError("review_id is invalid")
    normalized = _normalize_configured_fed_peer(peer_url)
    responder_did = document.get("responder_did")
    if not isinstance(responder_did, str) or not is_did_key(responder_did):
        raise ValueError("fetch responder_did is invalid")
    url = (
        normalized
        + f"/api/v2/trade/federation/orders/{order_digest}"
        + f"/execution-receipts/{execution_id}/reviews/{review_id}"
        + "/dispute-statements/fetch"
    )
    return _post_json_to_verified_trade_peer(
        normalized,
        url,
        document,
        expected_did=responder_did,
        identity_field="fetch responder_did",
        timeout_seconds=timeout_seconds,
        max_response_bytes=512 * 1024,
    )


def _federation_url_from_discovered_peer(peer: Any) -> str:
    """Extract a dialable HTTP federation base URL from a LAN/mDNS peer.

    Identity discovery and market federation are adjacent but not identical:
    a peer can publish a DID without publishing an HTTP endpoint reachable by
    this node. We import only explicit HTTP(S) URLs and never guess ports from
    source_addr, because UDP discovery ports are not HTTP service ports.
    """
    metadata = getattr(peer, "metadata", {}) or {}
    if isinstance(metadata, dict):
        for key in ("federation_url", "http_url", "api_url", "base_url"):
            try:
                return _normalize_configured_fed_peer(str(metadata.get(key, "")))
            except ValueError:
                continue
    try:
        return _normalize_configured_fed_peer(str(getattr(peer, "ws_url", "") or ""))
    except ValueError:
        return ""


def _resolve_safe_discovered_federation_ip(
    url: str,
    *,
    resolve: Callable[..., list] = socket.getaddrinfo,
) -> Optional[str]:
    """Resolve a LAN-discovered URL once and return a safe pinned address."""
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"}:
            return None
        host = (parsed.hostname or "").strip().lower().rstrip(".")
    except (TypeError, ValueError):
        return None
    if (
        not host
        or host == "localhost"
        or host.endswith(".localhost")
        or host.endswith(".local")
    ):
        return None

    def allowed(address: Any) -> bool:
        return not (
            address.is_loopback
            or address.is_unspecified
            or address.is_multicast
            or address.is_link_local
            or address.is_reserved
        )

    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        return str(literal) if allowed(literal) else None
    try:
        infos = resolve(host, None)
    except Exception:  # noqa: BLE001
        return None
    if not infos:
        return None
    addresses: List[str] = []
    for info in infos:
        try:
            address = ipaddress.ip_address(info[4][0])
        except (ValueError, IndexError, TypeError):
            return None
        if not allowed(address):
            return None
        addresses.append(str(address))
    return addresses[0] if addresses else None


def _is_safe_discovered_federation_url(url: str) -> bool:
    """Reject DNS aliases for self/metadata before identity-card fetch."""

    return _resolve_safe_discovered_federation_ip(url) is not None


def _discovered_source_ip(source_addr: str) -> Optional[str]:
    """Parse the network source attached by LAN/mDNS discovery."""
    raw = str(source_addr or "").strip()
    if not raw:
        return None
    try:
        host = urlsplit(f"//{raw}").hostname or raw
        return str(ipaddress.ip_address(host))
    except (TypeError, ValueError):
        return None

def _open_federation_identity_card(
    url: str,
    timeout_seconds: float,
    resolved_ip: str = "",
) -> bytes:
    """Compatibility wrapper around the reviewed federation trust kernel."""

    from nth_dao.plugins.federation_trust import open_federation_identity_card

    return open_federation_identity_card(url, timeout_seconds, resolved_ip)


def _verify_federation_identity_card(
    peer_url: str,
    card: Any,
    *,
    expected_challenge: str | None = None,
) -> tuple[Optional[Dict[str, Any]], str]:
    """Compatibility wrapper around the reviewed federation trust kernel."""

    from nth_dao.plugins.federation_trust import verify_federation_identity_card

    return verify_federation_identity_card(
        peer_url,
        card,
        expected_challenge=expected_challenge,
    )


def _fetch_and_verify_federation_identity(
    peer_url: str,
    *,
    timeout_seconds: float,
    expected_did: str = "",
    resolved_ip: str = "",
) -> tuple[Optional[Dict[str, Any]], str]:
    """Fetch and verify the signed card published by one discovered peer."""
    try:
        normalized_peer = _normalize_configured_fed_peer(peer_url)
        card_url = f"{normalized_peer}/.well-known/nth-dao/identity.json"
        if resolved_ip:
            raw = _open_federation_identity_card(
                card_url, timeout_seconds, resolved_ip,
            )
        else:
            raw = _open_federation_identity_card(card_url, timeout_seconds)
        card = json.loads(raw.decode("utf-8"))
    except (OSError, urllib.error.URLError, TimeoutError, UnicodeError,
            json.JSONDecodeError, ValueError) as exc:
        return None, f"identity card fetch failed: {type(exc).__name__}: {exc}"
    metadata, error = _verify_federation_identity_card(normalized_peer, card)
    if metadata is not None and expected_did:
        if not hmac.compare_digest(
            str(metadata.get("did") or ""), str(expected_did).strip(),
        ):
            return None, "identity card did does not match discovery record"
    return metadata, error


_FED_GOSSIP_IDENTITY_SUCCESS_TTL_S = 300.0
_FED_GOSSIP_IDENTITY_FAILURE_TTL_S = 30.0
_FED_GOSSIP_IDENTITY_CACHE_MAX = 256
_FEDERATION_CYCLE_BUDGET_DEFAULT_S = 30.0


def _market_fed_cycle_budget_s() -> float:
    return _env_float(
        "NTH_FED_CYCLE_BUDGET_S",
        _FEDERATION_CYCLE_BUDGET_DEFAULT_S,
        minimum=5.0,
        maximum=120.0,
    )


def _market_fed_gossip_identity_verifier(
    request: Request,
    *,
    persist_learned: bool = False,
) -> Callable[..., Optional[str]]:
    """Return a bounded-TTL verifier for URLs learned through gossip."""
    state = request.app.state
    with _FED_IDENTITY_INIT_LOCK:
        cache = getattr(state, "market_fed_identity_cache", None)
        if cache is None:
            cache = {}
            state.market_fed_identity_cache = cache
        lock = getattr(state, "market_fed_identity_cache_lock", None)
        if lock is None:
            lock = threading.RLock()
            state.market_fed_identity_cache_lock = lock
        inflight = getattr(state, "market_fed_identity_inflight", None)
        if inflight is None:
            inflight = {}
            state.market_fed_identity_inflight = inflight

    def verify(peer_url: str, resolved_ip: str = "") -> Optional[str]:
        try:
            normalized = _normalize_configured_fed_peer(peer_url)
        except ValueError:
            return False
        if not resolved_ip:
            try:
                parsed = urlsplit(normalized)
                if parsed.scheme == "https":
                    from .market_federation_poll import _resolve_safe_gossip_ip

                    resolved_ip = _resolve_safe_gossip_ip(normalized) or ""
                    if not resolved_ip:
                        return False
            except (TypeError, ValueError):
                return False
        now = time.monotonic()
        cache_key = (normalized, resolved_ip)
        timeout = _env_float(
            "NTH_FED_IDENTITY_TIMEOUT_S",
            2.0,
            minimum=0.5,
            maximum=3.0,
        )

        def persist_verified(metadata: Dict[str, Any]) -> None:
            ws = _state_workspace(request)
            try:
                if persist_learned:
                    store = _learned_fed_peer_store(ws)
                    if store is not None:
                        store.upsert_verified(
                            normalized, metadata, resolved_ip=resolved_ip,
                        )
                elif normalized in _read_fed_peers(ws):
                    with _fed_config_guard(ws):
                        persisted = _read_fed_peer_metadata(ws, strict=True)
                        if persisted.get(normalized) == metadata:
                            return
                        persisted[normalized] = metadata
                        _write_fed_peer_config_transaction(
                            ws,
                            _read_fed_peer_file(ws, strict=True),
                            persisted,
                        )
            except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
                logger.warning(
                    "fed: verified peer metadata persistence failed %s: %s",
                    normalized,
                    exc,
                )

        def is_local_identity(metadata: Dict[str, Any]) -> bool:
            if not persist_learned:
                return False
            local_identity = _state_node_identity(request)
            local_did = (
                local_identity.as_did()
                if local_identity is not None and hasattr(local_identity, "as_did")
                else ""
            )
            peer_did = str(metadata.get("did") or "")
            return bool(
                local_did
                and peer_did
                and hmac.compare_digest(local_did, peer_did)
            )

        cached_result: Optional[bool] = None
        cached_metadata: Any = None
        with lock:
            cached = cache.get(cache_key)
            if cached is not None and cached["expires_at"] > now:
                cached_result = bool(cached["ok"])
                cached_metadata = cached.get("metadata")
            if cached_result is not None:
                event = None
                owner = False
            else:
                event = inflight.get(cache_key)
                owner = event is None
                if owner:
                    event = threading.Event()
                    inflight[cache_key] = event

        if cached_result is not None:
            if cached_result and isinstance(cached_metadata, dict):
                if is_local_identity(cached_metadata):
                    return None
                persist_verified(cached_metadata)
                did = cached_metadata.get("did")
                return did if isinstance(did, str) else None
            return None

        if not owner:
            assert event is not None
            event.wait(timeout + 0.25)
            with lock:
                cached = cache.get(cache_key)
                ok = bool(
                    cached is not None
                    and cached["expires_at"] > time.monotonic()
                    and cached["ok"]
                )
                metadata = cached.get("metadata") if cached is not None else None
            if ok and isinstance(metadata, dict):
                if is_local_identity(metadata):
                    return None
                persist_verified(metadata)
                did = metadata.get("did")
                return did if isinstance(did, str) else None
            return None

        assert event is not None
        try:
            try:
                metadata, error = _fetch_and_verify_federation_identity(
                    normalized,
                    timeout_seconds=timeout,
                    resolved_ip=resolved_ip,
                )
            except Exception as exc:  # noqa: BLE001
                metadata = None
                error = f"{type(exc).__name__}: {exc}"
            ok = metadata is not None
            if ok and metadata is not None and is_local_identity(metadata):
                ok = False
                error = "refusing to learn this node as a peer"
            if not ok:
                logger.warning(
                    "fed: rejected gossip peer identity %s: %s", normalized, error,
                )
            if ok and metadata is not None:
                persist_verified(metadata)
            with lock:
                cache[cache_key] = {
                    "ok": ok,
                    "metadata": metadata if ok else None,
                    "expires_at": now + (
                        _FED_GOSSIP_IDENTITY_SUCCESS_TTL_S
                        if ok else _FED_GOSSIP_IDENTITY_FAILURE_TTL_S
                    ),
                }
                if len(cache) > _FED_GOSSIP_IDENTITY_CACHE_MAX:
                    oldest = min(
                        cache,
                        key=lambda key: cache[key]["expires_at"],
                    )
                    cache.pop(oldest, None)
            if ok and metadata is not None:
                did = metadata.get("did")
                return did if isinstance(did, str) else None
            return None
        finally:
            with lock:
                inflight.pop(cache_key, None)
                event.set()

    return verify


def _read_fed_peer_metadata(
    ws: Optional[Path],
    *,
    strict: bool = False,
) -> Dict[str, Dict[str, Any]]:
    try:
        with _fed_config_guard(ws):
            if not _recover_fed_peer_config_transaction(ws, strict=strict):
                return {}
            return _read_fed_peer_metadata_unlocked(ws, strict=strict)
    except FederationSeedConfigError:
        if strict:
            raise
        logger.warning("federation peer metadata is temporarily busy")
        return {}
def _read_fed_peer_metadata_unlocked(
    ws: Optional[Path],
    *,
    strict: bool,
) -> Dict[str, Dict[str, Any]]:
    mf = _fed_peer_metadata_file(ws)
    if mf is None or not mf.exists():
        return {}
    try:
        if mf.stat().st_size > _MAX_FED_CONFIG_BYTES:
            message = "federation peer metadata exceeds the byte limit"
            if strict:
                raise FederationSeedConfigError(message)
            logger.warning(message)
            return {}
        data = json.loads(mf.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        if strict:
            raise FederationSeedConfigError(
                "federation peer metadata is unreadable",
            ) from exc
        return {}
    if not isinstance(data, dict):
        if strict:
            raise FederationSeedConfigError(
                "federation peer metadata must be an object",
            )
        return {}
    if len(data) > _MAX_FED_SEED_PEERS and strict:
        raise FederationSeedConfigError(
            "federation peer metadata exceeds seed capacity",
        )
    allowed_fields = {
        "peer_url", "identity_url", "did", "pubkey_hex",
        "verified_at", "card_kind", "federation_protocol",
    }
    out: Dict[str, Dict[str, Any]] = {}
    for raw_url, raw_meta in list(data.items())[:_MAX_FED_SEED_PEERS]:
        if not isinstance(raw_url, str) or not isinstance(raw_meta, dict):
            if strict:
                raise FederationSeedConfigError(
                    "federation peer metadata contains a malformed entry",
                )
            continue
        try:
            peer_url = _normalize_configured_fed_peer(raw_url)
        except ValueError as exc:
            if strict:
                raise FederationSeedConfigError(
                    "federation peer metadata contains an invalid URL",
                ) from exc
            continue
        if strict and (
            set(raw_meta) - allowed_fields
            or any(
                not isinstance(value, str)
                or len(value) > _MAX_FED_IDENTITY_HEX * 4
                for value in raw_meta.values()
            )
        ):
            raise FederationSeedConfigError(
                "federation peer metadata contains invalid fields",
            )
        meta = {
            key: value for key, value in raw_meta.items()
            if key in allowed_fields
            and isinstance(value, str)
            and len(value) <= _MAX_FED_IDENTITY_HEX * 4
        }
        if meta.get("peer_url") == peer_url and meta.get("did"):
            out[peer_url] = meta
        elif strict:
            raise FederationSeedConfigError(
                "federation peer metadata identity binding is malformed",
            )
    return out


def _public_fed_peer_hints(ws: Optional[Path]) -> List[str]:
    """Return only verified public URLs for the anonymous peer graph.

    Operator seeds may be loopback, RFC1918, or internal hostnames for local
    testing. Those belong in the authenticated status view, not in gossip.
    """
    from nth_dao.did_key import DIDKeyError, decode_ed25519_did_key_hex
    from nth_dao.discovery.federation_registry import normalize_learned_peer_url

    hints = _read_learned_fed_peers(ws)
    metadata = _read_fed_peer_metadata(ws)
    for raw_seed in _read_fed_peers(ws):
        item = metadata.get(raw_seed)
        if not isinstance(item, dict):
            continue
        try:
            seed = normalize_learned_peer_url(raw_seed)
            claimed = normalize_learned_peer_url(str(item.get("peer_url") or ""))
            pubkey_hex = decode_ed25519_did_key_hex(str(item.get("did") or ""))
        except (DIDKeyError, ValueError):
            continue
        if seed != claimed:
            continue
        if pubkey_hex != str(item.get("pubkey_hex") or "").lower():
            continue
        if item.get("identity_url") != (
            f"{seed}/.well-known/nth-dao/identity.json"
        ):
            continue
        if (
            item.get("card_kind") != _FED_IDENTITY_CARD_KIND
            or item.get("federation_protocol") != "nth-dao-federation-v1"
        ):
            continue
        hints.append(seed)
    return list(dict.fromkeys(hints))


def _write_fed_peer_metadata(
    ws: Optional[Path], metadata: Dict[str, Dict[str, Any]],
) -> None:
    mf = _fed_peer_metadata_file(ws)
    if mf is None:
        raise RuntimeError("workspace unavailable")
    normalized = _normalize_fed_peer_metadata(metadata, strict=False)
    mf.parent.mkdir(parents=True, exist_ok=True)
    tmp = mf.with_suffix(mf.suffix + ".tmp")
    tmp.write_text(
        json.dumps(normalized, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(tmp, mf)


def _normalize_fed_peer_metadata(
    metadata: Dict[str, Dict[str, Any]],
    *,
    strict: bool,
) -> Dict[str, Dict[str, Any]]:
    if not isinstance(metadata, dict):
        raise FederationSeedConfigError("federation peer metadata must be an object")
    allowed_fields = {
        "peer_url", "identity_url", "did", "pubkey_hex",
        "verified_at", "card_kind", "federation_protocol",
    }
    normalized: Dict[str, Dict[str, Any]] = {}
    for raw_url, raw_meta in metadata.items():
        if not isinstance(raw_url, str):
            if strict:
                raise FederationSeedConfigError(
                    "federation peer metadata contains a non-string URL",
                )
            continue
        try:
            peer_url = _normalize_configured_fed_peer(raw_url)
        except ValueError as exc:
            if strict:
                raise FederationSeedConfigError(
                    "federation peer metadata contains an invalid URL",
                ) from exc
            continue
        if not isinstance(raw_meta, dict):
            if strict:
                raise FederationSeedConfigError(
                    "federation peer metadata contains a malformed entry",
                )
            continue
        if strict and (
            set(raw_meta) - allowed_fields
            or any(
                not isinstance(value, str)
                or len(value) > _MAX_FED_IDENTITY_HEX * 4
                for value in raw_meta.values()
            )
        ):
            raise FederationSeedConfigError(
                "federation peer metadata contains invalid fields",
            )
        item = {
            key: value for key, value in raw_meta.items()
            if key in allowed_fields
            and isinstance(value, str)
            and len(value) <= _MAX_FED_IDENTITY_HEX * 4
        }
        if item.get("peer_url") == peer_url and item.get("did"):
            normalized[peer_url] = item
        elif strict:
            raise FederationSeedConfigError(
                "federation peer metadata identity binding is malformed",
            )
    if len(normalized) > _MAX_FED_SEED_PEERS:
        raise FederationSeedCapacityError(
            f"federation seed capacity is limited to {_MAX_FED_SEED_PEERS}",
        )
    return normalized


def _discovered_peer_to_wire(peer: Any) -> Dict[str, Any]:
    metadata = getattr(peer, "metadata", {}) or {}
    return {
        "agent_id": str(getattr(peer, "agent_id", "") or ""),
        "label": str(getattr(peer, "label", "") or ""),
        "did": str(getattr(peer, "did", "") or ""),
        "capabilities": list(getattr(peer, "capabilities", []) or []),
        "groups": list(getattr(peer, "groups", []) or []),
        "ws_url": str(getattr(peer, "ws_url", "") or ""),
        "source_addr": str(getattr(peer, "source_addr", "") or ""),
        "federation_peer_url": _federation_url_from_discovered_peer(peer),
        "metadata": dict(metadata) if isinstance(metadata, dict) else {},
    }


def _require_federation_actor(request: Request, actor_id: str) -> None:
    actor = str(actor_id or "").strip()
    if not actor:
        raise HTTPException(status_code=400, detail="actor_id is required")
    membership = getattr(request.app.state.nth, "membership", None)
    if membership is None:
        raise HTTPException(status_code=503, detail="membership unavailable")
    try:
        role = membership.load_config().role_for(actor)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=403, detail="actor is not a team member") from exc
    role_value = getattr(role, "value", str(role or ""))
    if role_value == "guest":
        raise HTTPException(status_code=403, detail="actor is not a team member")


def _discover_market_federation_peers(
    request: Request,
    *,
    actor_id: str,
    timeout_seconds: float,
) -> tuple[List[Dict[str, Any]], List[str]]:
    """Run local discovery backends and return peer rows plus soft errors."""
    peers: List[Any] = []
    errors: List[str] = []
    identity = _state_node_identity(request)
    pubkey_hex = (
        getattr(identity, "pubkey_hex", "") if identity is not None else ""
    ) or ""
    did = identity.as_did() if identity is not None and hasattr(identity, "as_did") else ""
    psk = os.environ.get("NTH_DISCOVERY_PSK", "").strip()

    try:
        from nth_dao.discovery import LANDiscovery, configured_discovery_port

        lan = LANDiscovery(
            agent_id=actor_id,
            pubkey_hex=pubkey_hex,
            did=did,
            psk=psk,
            port=configured_discovery_port(),
        )
        peers.extend(lan.discover(timeout=timeout_seconds))
    except Exception as exc:  # noqa: BLE001
        errors.append(f"udp:{type(exc).__name__}:{exc}")

    try:
        from nth_dao.discovery import MDNSDiscovery, mdns_available

        if MDNSDiscovery is not None and mdns_available():
            mdns = MDNSDiscovery(agent_id=actor_id, pubkey_hex=pubkey_hex, did=did)
            peers.extend(mdns.discover(timeout=timeout_seconds))
    except ImportError as exc:
        errors.append(f"mdns:unavailable:{exc}")
    except Exception as exc:  # noqa: BLE001
        errors.append(f"mdns:{type(exc).__name__}:{exc}")

    by_key: Dict[str, Dict[str, Any]] = {}
    for peer in peers:
        row = _discovered_peer_to_wire(peer)
        key = (
            row["federation_peer_url"]
            or row["did"]
            or row["source_addr"]
            or row["agent_id"]
        )
        if not key or key in by_key:
            continue
        by_key[key] = row
    rows = list(by_key.values())
    if len(rows) > _MAX_FED_DISCOVERY_CANDIDATES:
        errors.append(
            f"discovery:candidate limit reached ({_MAX_FED_DISCOVERY_CANDIDATES})"
        )
        rows = rows[:_MAX_FED_DISCOVERY_CANDIDATES]
    return rows, errors


def _read_fed_peer_file(
    ws: Optional[Path],
    *,
    strict: bool = False,
) -> List[str]:
    try:
        with _fed_config_guard(ws):
            if not _recover_fed_peer_config_transaction(ws, strict=strict):
                return []
            return _read_fed_peer_file_unlocked(ws, strict=strict)
    except FederationSeedConfigError:
        if strict:
            raise
        logger.warning("federation seed registry is temporarily busy")
        return []


def _read_fed_peer_file_unlocked(
    ws: Optional[Path],
    *,
    strict: bool,
) -> List[str]:
    pf = _fed_peers_file(ws)
    if pf is None or not pf.exists():
        return []
    try:
        if pf.stat().st_size > _MAX_FED_CONFIG_BYTES:
            message = "federation seed registry exceeds the byte limit"
            if strict:
                raise FederationSeedConfigError(message)
            logger.warning(message)
            return []
        data = json.loads(pf.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        if strict:
            raise FederationSeedConfigError(
                "federation seed registry is unreadable",
            ) from exc
        return []
    if not isinstance(data, list):
        if strict:
            raise FederationSeedConfigError(
                "federation seed registry must be an array",
            )
        return []
    out: List[str] = []
    if len(data) > _MAX_FED_SEED_PEERS:
        if strict:
            raise FederationSeedConfigError(
                "federation seed registry exceeds seed capacity",
            )
        logger.warning(
            "federation seed registry contains more than %d peers; ignoring overflow",
            _MAX_FED_SEED_PEERS,
        )
    for item in data[:_MAX_FED_SEED_PEERS]:
        if not isinstance(item, str):
            if strict:
                raise FederationSeedConfigError(
                    "federation seed registry contains a non-string peer",
                )
            continue
        try:
            normalized = _normalize_configured_fed_peer(item)
        except ValueError as exc:
            if strict:
                raise FederationSeedConfigError(
                    "federation seed registry contains an invalid peer URL",
                ) from exc
            continue
        if normalized in out:
            if strict:
                raise FederationSeedConfigError(
                    "federation seed registry contains duplicate peers",
                )
            continue
        out.append(normalized)
    return out


def _write_fed_peer_file(ws: Optional[Path], peers: List[str]) -> None:
    pf = _fed_peers_file(ws)
    if pf is None:
        raise RuntimeError("workspace unavailable")
    normalized: List[str] = []
    seen: set = set()
    for peer in peers:
        p = _normalize_configured_fed_peer(peer)
        if p not in seen:
            seen.add(p)
            normalized.append(p)
    if len(normalized) > _MAX_FED_SEED_PEERS:
        raise FederationSeedCapacityError(
            f"federation seed capacity is limited to {_MAX_FED_SEED_PEERS}",
        )
    pf.parent.mkdir(parents=True, exist_ok=True)
    tmp = pf.with_suffix(pf.suffix + ".tmp")
    tmp.write_text(
        json.dumps(normalized, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(tmp, pf)


def _recover_fed_peer_config_transaction(
    ws: Optional[Path],
    *,
    strict: bool,
) -> bool:
    """Replay one durable seed/metadata transaction after an interrupted write."""

    transaction = _fed_peer_transaction_file(ws)
    if transaction is None or not transaction.exists():
        return True
    with _fed_config_guard(ws):
        if not transaction.exists():
            return True
        try:
            if transaction.stat().st_size > _MAX_FED_CONFIG_BYTES:
                raise FederationSeedConfigError(
                    "federation peer transaction exceeds the byte limit",
                )
            raw = json.loads(transaction.read_text(encoding="utf-8"))
            if not isinstance(raw, dict) or set(raw) != {"version", "peers", "metadata"}:
                raise FederationSeedConfigError(
                    "federation peer transaction is malformed",
                )
            if raw["version"] != 1 or not isinstance(raw["peers"], list):
                raise FederationSeedConfigError(
                    "federation peer transaction version or peers are invalid",
                )
            if any(not isinstance(item, str) for item in raw["peers"]):
                raise FederationSeedConfigError(
                    "federation peer transaction peers must be strings",
                )
            peers = [_normalize_configured_fed_peer(item) for item in raw["peers"]]
            if len(peers) > _MAX_FED_SEED_PEERS or peers != list(dict.fromkeys(peers)):
                raise FederationSeedConfigError(
                    "federation peer transaction peers are invalid",
                )
            metadata = _normalize_fed_peer_metadata(raw["metadata"], strict=True)
            _write_fed_peer_file(ws, peers)
            _write_fed_peer_metadata(ws, metadata)
            transaction.unlink(missing_ok=True)
            return True
        except (
            OSError,
            UnicodeError,
            json.JSONDecodeError,
            TypeError,
            ValueError,
        ) as exc:
            if strict:
                if isinstance(exc, FederationSeedConfigError):
                    raise
                raise FederationSeedConfigError(
                    "federation peer transaction cannot be recovered",
                ) from exc
            logger.warning("federation peer transaction recovery deferred: %s", exc)
            return False


def _write_fed_peer_config_transaction(
    ws: Optional[Path],
    peers: List[str],
    metadata: Dict[str, Dict[str, Any]],
) -> None:
    """Atomically journal and apply the two-file operator seed registry."""

    with _fed_config_guard(ws):
        transaction = _fed_peer_transaction_file(ws)
        if transaction is None:
            raise RuntimeError("workspace unavailable")
        normalized_peers: List[str] = []
        for peer in peers:
            if not isinstance(peer, str):
                raise FederationSeedConfigError(
                    "federation seed registry contains a non-string peer",
                )
            normalized = _normalize_configured_fed_peer(peer)
            if normalized not in normalized_peers:
                normalized_peers.append(normalized)
        if len(normalized_peers) > _MAX_FED_SEED_PEERS:
            raise FederationSeedCapacityError(
                f"federation seed capacity is limited to {_MAX_FED_SEED_PEERS}",
            )
        normalized_metadata = _normalize_fed_peer_metadata(metadata, strict=True)
        transaction.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(transaction, {
            "version": 1,
            "peers": normalized_peers,
            "metadata": normalized_metadata,
        })
        _write_fed_peer_file(ws, normalized_peers)
        _write_fed_peer_metadata(ws, normalized_metadata)
        transaction.unlink(missing_ok=True)


def _read_fed_peers(ws: Optional[Path]) -> List[str]:
    """联邦 peer 列表(去重保序):NTH_FED_PEERS(逗号分隔)+ 可选
    ``<ws>/federation/peers.json``(字符串数组)。各 peer 是对端 hub 的
    base URL(如 https://xxx.trycloudflare.com)。"""
    peers: List[str] = [
        p.strip() for p in os.environ.get("NTH_FED_PEERS", "").split(",")
        if p.strip()
    ]
    peers += _read_fed_peer_file(ws)
    seen: set = set()
    out: List[str] = []
    for p in peers:
        try:
            normalized = _normalize_configured_fed_peer(p)
        except ValueError:
            continue
        if normalized not in seen:
            seen.add(normalized)
            out.append(normalized)
    return out


_FED_RUNTIME_PREFERENCES = frozenset({"legacy", "plugin", "suspended"})
_MAX_FED_RUNTIME_PREFERENCE_BYTES = 4096


def _fed_runtime_preference_file(ws: Optional[Path]) -> Optional[Path]:
    if ws is None:
        return None
    return ws / ".nth" / "plugin-host" / "federation-runtime.json"


def _fed_runtime_owner_target(ws: Optional[Path]) -> Optional[Path]:
    if ws is None:
        return None
    return ws / ".nth" / "plugin-host" / "federation-runtime-owner"


def _claim_market_fed_runtime_owner(
    state: Any,
    ws: Optional[Path],
    *,
    timeout_s: float = 0.05,
) -> bool:
    """Hold an OS lock for the lifetime of this process-owned runtime."""
    if getattr(state, "market_fed_runtime_owner_lock", None) is not None:
        return True
    target = _fed_runtime_owner_target(ws)
    if target is None:
        return False
    owner_lock = InterProcessLock(target, timeout=timeout_s, poll=0.01)
    try:
        owner_lock.acquire()
    except TimeoutError:
        return False
    state.market_fed_runtime_owner_lock = owner_lock
    return True


def _release_market_fed_runtime_owner(state: Any) -> None:
    owner_lock = getattr(state, "market_fed_runtime_owner_lock", None)
    state.market_fed_runtime_owner_lock = None
    if owner_lock is not None:
        owner_lock.release()


def _read_fed_runtime_preference(ws: Optional[Path]) -> str:
    """Read the operator-selected runtime, defaulting old workspaces to legacy."""
    path = _fed_runtime_preference_file(ws)
    if path is None:
        return "legacy"
    try:
        if path.exists() and path.stat().st_size > _MAX_FED_RUNTIME_PREFERENCE_BYTES:
            logger.warning("federation runtime preference is oversized; failing closed")
            return "suspended"
        document = safe_load_json(path, fallback=None)
    except OSError as exc:
        logger.warning(
            "federation runtime preference unavailable (%s)",
            type(exc).__name__,
        )
        return "suspended"
    if document is None:
        # ``safe_load_json`` returns the fallback for malformed JSON as well
        # as a missing file. Only absence preserves the legacy compatibility
        # default; a present but unreadable preference must fail closed.
        try:
            return "suspended" if path.exists() else "legacy"
        except OSError:
            return "suspended"
    if (
        not isinstance(document, dict)
        or type(document.get("version")) is not int
        or document.get("version") != 1
    ):
        logger.warning("invalid federation runtime preference; failing closed")
        return "suspended"
    mode = document.get("mode")
    if not isinstance(mode, str) or mode not in _FED_RUNTIME_PREFERENCES:
        logger.warning("unknown federation runtime preference; failing closed")
        return "suspended"
    return str(mode)


def _write_fed_runtime_preference(ws: Optional[Path], mode: str) -> None:
    if mode not in _FED_RUNTIME_PREFERENCES:
        raise ValueError("invalid federation runtime preference")
    path = _fed_runtime_preference_file(ws)
    if path is None:
        raise RuntimeError("workspace unavailable")
    path.parent.mkdir(parents=True, exist_ok=True)
    with InterProcessLock(path, timeout=2.0):
        atomic_write_json(path, {"version": 1, "mode": mode})


def _initialize_fed_runtime_preference(state: Any, ws: Optional[Path]) -> str:
    """Synchronize process state with the cross-process preference file."""
    mode = _read_fed_runtime_preference(ws)
    state.market_fed_runtime_preference = mode
    plugin_enabled = False
    nth_state = getattr(state, "nth", None)
    host = getattr(nth_state, "plugin_host", None)
    if host is not None:
        from nth_dao.plugins.builtin import FEDERATION_DISCOVERY_PLUGIN_ID

        try:
            plugin_enabled = (
                host.status(FEDERATION_DISCOVERY_PLUGIN_ID).state == "enabled"
            )
        except KeyError:
            plugin_enabled = False
    state.market_fed_plugin_suspended = mode == "suspended" or (
        mode == "plugin" and not plugin_enabled
    )
    return mode


def _launch_market_fed_poller(
    request: Request, cache: Any, ws: Optional[Path],
) -> None:
    """Start one lifecycle-owned federation poller under the caller's lock."""
    state = request.app.state
    interval = _env_float(
        "NTH_FED_POLL_INTERVAL_S", 20.0, minimum=1.0, maximum=3600.0,
    )
    stop_event = threading.Event()
    if not _claim_market_fed_runtime_owner(state, ws):
        logger.warning(
            "federation runtime is owned by another process; poller not started",
        )
        return
    mode = _initialize_fed_runtime_preference(state, ws)
    binding = _enabled_federation_plugin_binding(request)
    if mode == "suspended" or (mode == "plugin" and binding is None):
        _release_market_fed_runtime_owner(state)
        return
    if mode == "legacy":
        binding = None
    try:
        if binding is not None:
            thread = _start_plugin_market_fed_poller(
                binding,
                cache,
                stop_event=stop_event,
                interval_s=interval,
                principal="local-system:federation-poller",
            )
            mode = "plugin"
        else:
            thread = _start_legacy_market_fed_poller(
                request,
                cache,
                ws,
                stop_event=stop_event,
                interval_s=interval,
            )
            mode = "legacy"
    except Exception:
        _release_market_fed_runtime_owner(state)
        raise

    state.market_fed_poller_stop_event = stop_event
    state.market_fed_poller_thread = thread
    state.market_fed_poller_started = True
    state.market_fed_poller_mode = mode
    logger.info(
        "nth market federation %s poller started (%d peers, %.0fs)",
        mode,
        len(set(_read_fed_peers(ws)) | set(_read_learned_fed_peers(ws))),
        interval,
    )


def _start_legacy_market_fed_poller(
    request: Request,
    cache: Any,
    ws: Optional[Path],
    *,
    stop_event: threading.Event,
    interval_s: float,
):
    """Start the pre-plugin compatibility poller."""
    from .market_federation_poll import start_poller

    return start_poller(
        lambda: _read_fed_peers(ws),
        cache,
        get_untrusted_peers=lambda: _read_learned_fed_peers(ws),
        announce_self=_market_fed_announce_self(request),
        stop_event=stop_event,
        interval_s=interval_s,
        verify_gossip_peer=_market_fed_gossip_identity_verifier(
            request, persist_learned=True,
        ),
        verify_seed_peer=_market_fed_gossip_identity_verifier(request),
        max_duration_s=_market_fed_cycle_budget_s(),
    )


def _start_plugin_market_fed_poller(
    binding: Any,
    cache: Any,
    *,
    stop_event: threading.Event,
    interval_s: float,
    principal: str,
):
    """Invoke the enabled discovery capability until revoked or stopped."""
    from nth_dao.plugins import InvocationAuthority, PluginHostError, PluginSchemaError
    from nth_dao.plugins.builtin import FEDERATION_DISCOVERY_CAPABILITY_ID

    authority = InvocationAuthority(
        principal=principal,
        capability_ids=frozenset({FEDERATION_DISCOVERY_CAPABILITY_ID}),
    )

    def run() -> None:
        try:
            while not stop_event.is_set():
                try:
                    result = binding.invoke({}, authority=authority)
                    known_peers = int(result.get("known_peers", 0))
                    if known_peers <= 0:
                        break
                except (PluginHostError, PluginSchemaError) as exc:
                    cache.mark_error(type(exc).__name__, peer_count=0)
                    logger.warning(
                        "federation plugin poller stopped (%s)",
                        type(exc).__name__,
                    )
                    break
                except (OSError, RuntimeError, TypeError, ValueError) as exc:
                    cache.mark_error(type(exc).__name__, peer_count=0)
                    logger.warning(
                        "federation plugin cycle failed (%s)",
                        type(exc).__name__,
                    )
                if stop_event.wait(interval_s):
                    break
        finally:
            stop_event.set()

    thread = threading.Thread(
        target=run,
        name="nth-market-federation-plugin",
        daemon=True,
    )
    thread.start()
    return thread


def _enabled_federation_plugin_binding(request: Request):
    """Resolve the built-in federation capability only while enabled."""
    from nth_dao.plugins import PluginDependencyError
    from nth_dao.plugins.builtin import (
        FEDERATION_DISCOVERY_CAPABILITY_ID,
        FEDERATION_DISCOVERY_PLUGIN_ID,
    )

    nth_state = getattr(request.app.state, "nth", None)
    host = getattr(nth_state, "plugin_host", None)
    if host is None:
        return None
    try:
        if host.status(FEDERATION_DISCOVERY_PLUGIN_ID).state != "enabled":
            return None
        return host.resolve_one(FEDERATION_DISCOVERY_CAPABILITY_ID)
    except (KeyError, PluginDependencyError):
        return None


def _stop_market_fed_poller(
    state: Any,
    *,
    timeout_s: float = 10.0,
    release_owner: bool = True,
) -> bool:
    """Stop one poller; retain ownership state if its thread is still alive."""
    stop_event = getattr(state, "market_fed_poller_stop_event", None)
    if stop_event is not None and hasattr(stop_event, "set"):
        stop_event.set()
    thread = getattr(state, "market_fed_poller_thread", None)
    if thread is not None and hasattr(thread, "join"):
        thread.join(timeout=timeout_s)
    if thread is not None and hasattr(thread, "is_alive") and thread.is_alive():
        logger.warning("federation poller did not stop in time")
        return False
    state.market_fed_poller_started = False
    state.market_fed_poller_stop_event = None
    state.market_fed_poller_thread = None
    state.market_fed_poller_mode = ""
    if release_owner:
        _release_market_fed_runtime_owner(state)
    return True


def _clear_finished_market_fed_poller(state: Any) -> None:
    """Clear a stopped poller only after its thread has really exited."""
    if not getattr(state, "market_fed_poller_started", False):
        return
    stop_event = getattr(state, "market_fed_poller_stop_event", None)
    if stop_event is None or not hasattr(stop_event, "is_set"):
        return
    if not stop_event.is_set():
        return
    thread = getattr(state, "market_fed_poller_thread", None)
    if thread is not None and hasattr(thread, "is_alive") and thread.is_alive():
        return
    state.market_fed_poller_started = False
    state.market_fed_poller_stop_event = None
    state.market_fed_poller_thread = None
    state.market_fed_poller_mode = ""
    _release_market_fed_runtime_owner(state)


def _state_market_fed_cache(request: Request):
    """Return the cache and ensure configured federation is running."""
    state = request.app.state
    _clear_finished_market_fed_poller(state)
    ws = _state_workspace(request)
    _initialize_fed_runtime_preference(state, ws)
    has_peers = bool(_read_fed_peers(ws) or _read_learned_fed_peers(ws))
    cache = getattr(state, "market_fed_cache", None)
    if not has_peers:
        return cache
    if getattr(state, "market_fed_plugin_suspended", False):
        return cache
    if cache is not None and getattr(state, "market_fed_poller_started", False):
        return cache
    with _FED_POLLER_LOCK:
        cache = getattr(state, "market_fed_cache", None)
        if cache is None:
            from .market_federation_poll import FederationCache

            cache = FederationCache()
            state.market_fed_cache = cache
        if not getattr(state, "market_fed_poller_started", False):
            _launch_market_fed_poller(request, cache, ws)
    return cache


def _require_trade_offer_digest(digest: str) -> None:
    """Reject malformed Offer digests before cache or filesystem access."""

    if re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
        raise HTTPException(
            status_code=400,
            detail="digest must be a lowercase sha256 digest",
        )


def _verified_cached_trade_offer(
    request: Request,
    digest: str,
) -> tuple[Any, List[Dict[str, Any]], Dict[str, Any], Dict[str, Any], Any]:
    """Reverify one volatile federated Offer and every retained binding.

    This is the single trust boundary used by both inspection and durable
    import.  It deliberately returns a signed claim plus discovery evidence;
    it does not grant trust, acceptance, or execution authority.
    """
    from nth_dao.market import (
        NTH_TRADE_OFFER_ANNOUNCEMENT_KIND_V1,
        VerifiedTradeOfferHeadProof,
        announcement_federation_key,
        verify_trade_offer_announcement_binding,
    )
    from nth_dao.trade_rules import offer_digest

    _require_trade_offer_digest(digest)
    cache = _state_market_fed_cache(request)
    if cache is None:
        raise HTTPException(status_code=404, detail="remote offer not found")
    try:
        cached_offers = cache.trade_offer_snapshot(digest)
    except (AttributeError, TypeError, ValueError, RuntimeError) as exc:
        raise HTTPException(
            status_code=503,
            detail="federation cache integrity check failed",
        ) from exc

    verified_offer: Any = None
    verified_chain: Optional[tuple[bytes, ...]] = None
    discoveries: List[Dict[str, Any]] = []
    evidence_candidates: List[tuple[Dict[str, Any], Any]] = []
    try:
        for entry in cached_offers:
            if not isinstance(entry, dict):
                raise ValueError("cached Trade Offer entry is invalid")
            announcement = entry.get("ann")
            if (
                getattr(announcement, "kind", "")
                != NTH_TRADE_OFFER_ANNOUNCEMENT_KIND_V1
                or getattr(announcement, "offer_digest", "") != digest
                or announcement.is_expired()
            ):
                continue
            raw_proof = entry.get("trade_offer_head_proof")
            if not isinstance(raw_proof, VerifiedTradeOfferHeadProof):
                raise ValueError("verified Trade Offer head proof is missing")
            proof = VerifiedTradeOfferHeadProof.from_dict(raw_proof.to_dict())
            if proof.announcement.to_dict() != announcement.to_dict():
                raise ValueError("cached Trade Offer head claim mismatch")
            proof_offers = proof.offers
            candidate = proof_offers[-1]
            candidate_chain = tuple(
                offer.canonical_bytes for offer in proof_offers
            )
            if offer_digest(candidate) != digest:
                raise ValueError("cached Trade Offer digest mismatch")
            ok, reason = verify_trade_offer_announcement_binding(
                candidate,
                announcement,
            )
            if not ok:
                raise ValueError(reason)
            source_did = str(entry.get("source_did") or "")
            if source_did != announcement.effective_authority_did():
                raise ValueError("cached Trade Offer source DID mismatch")
            if source_did != candidate.publisher_did:
                raise ValueError("cached Trade Offer publisher DID mismatch")
            federation_key = str(entry.get("federation_key") or "")
            if federation_key != announcement_federation_key(announcement):
                raise ValueError("cached Trade Offer federation key mismatch")
            if (
                verified_offer is not None
                and verified_offer.canonical_bytes != candidate.canonical_bytes
            ):
                raise ValueError("one digest resolved to conflicting Offers")
            if verified_chain is not None and verified_chain != candidate_chain:
                raise ValueError("one digest resolved to conflicting head proofs")
            verified_offer = candidate
            verified_chain = candidate_chain
            discoveries.append(
                {
                    "announcement_id": announcement.announcement_id,
                    "federation_key": federation_key,
                    "source_peer": str(entry.get("source") or ""),
                    "source_did": source_did,
                    "stale": bool(entry.get("stale", False)),
                    "last_verified_ms": int(entry.get("last_verified_ms") or 0),
                }
            )
            evidence_candidates.append(
                (
                    {
                        "announcement": announcement.to_dict(),
                        "federation_key": federation_key,
                        "source_peer": str(entry.get("source") or ""),
                        "source_did": source_did,
                        "stale": bool(entry.get("stale", False)),
                        "last_verified_ms": int(entry.get("last_verified_ms") or 0),
                    },
                    proof,
                )
            )
    except (AttributeError, TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=503,
            detail="cached Trade Offer verification failed",
        ) from exc
    if verified_offer is None or verified_chain is None or not discoveries:
        raise HTTPException(status_code=404, detail="remote offer not found")
    discoveries.sort(
        key=lambda item: (
            item["source_did"],
            item["source_peer"],
            item["announcement_id"],
        )
    )
    ranked_evidence = sorted(
        evidence_candidates,
        key=lambda candidate: (
            candidate[0]["stale"],
            -candidate[0]["last_verified_ms"],
            candidate[0]["source_did"],
            candidate[0]["source_peer"],
            candidate[0]["federation_key"],
        ),
    )
    evidence, verified_proof = ranked_evidence[0]
    from nth_dao.canonical_json import canonical_json

    auditable_evidence: List[Dict[str, Any]] = []
    observed_sources: set[tuple[str, str]] = set()
    for candidate, _candidate_proof in ranked_evidence:
        source_key = (candidate["source_did"], candidate["source_peer"])
        if source_key in observed_sources:
            continue
        proposed = [*auditable_evidence, candidate]
        if (
            len(proposed) > _MAX_TRADE_OFFER_DISCOVERY_EVIDENCE
            or len(canonical_json({"discoveries": proposed}))
            > _MAX_TRADE_OFFER_DISCOVERY_EVIDENCE_BYTES
        ):
            continue
        auditable_evidence.append(candidate)
        observed_sources.add(source_key)
    if not auditable_evidence or evidence not in auditable_evidence:
        raise HTTPException(
            status_code=503,
            detail="Trade Offer discovery evidence exceeds the audit budget",
        )
    proof_offers = verified_proof.offers
    head_claim = {
        "publisher_claim_verified": True,
        "disclosed_chain_complete": True,
        "globally_latest_proven": False,
        "head_revision": proof_offers[-1].to_dict()["revision"],
        "chain_length": len(proof_offers),
        "chain_digests": [offer_digest(item) for item in proof_offers],
        "claimed_at_ms": verified_proof.announcement.published_at_ms,
        "expires_at_ms": verified_proof.announcement.not_after,
    }
    return (
        verified_offer,
        discoveries,
        evidence,
        auditable_evidence,
        head_claim,
        verified_proof,
    )


def _ensure_market_fed_cache_for_update(request: Request):
    """Create the federation cache and start the poller after peer edits."""
    state = request.app.state
    with _FED_POLLER_LOCK:
        cache = getattr(state, "market_fed_cache", None)
        if cache is None:
            from .market_federation_poll import FederationCache

            cache = FederationCache()
            state.market_fed_cache = cache
        ws = _state_workspace(request)
        _initialize_fed_runtime_preference(state, ws)
        peers = _read_fed_peers(ws)
        learned_peers = _read_learned_fed_peers(ws)
        if (
            (peers or learned_peers)
            and not getattr(state, "market_fed_plugin_suspended", False)
            and not getattr(
                state, "market_fed_poller_started", False
            )
        ):
            _launch_market_fed_poller(request, cache, ws)
    return cache


def _discover_and_import_market_federation(
    request: Request,
    *,
    actor_id: str,
    timeout_seconds: float,
    add: bool = True,
    refresh: bool = False,
) -> Dict[str, Any]:
    """Discover, verify, and optionally persist nearby federation peers."""

    ws = _state_workspace(request)
    if ws is None:
        raise RuntimeError("workspace unavailable")
    discovered, errors = _discover_market_federation_peers(
        request,
        actor_id=actor_id,
        timeout_seconds=timeout_seconds,
    )
    urls: List[str] = []
    verified_rows: List[Dict[str, Any]] = []
    skipped_rows: List[Dict[str, Any]] = []
    verified_metadata: Dict[str, Dict[str, Any]] = {}
    for discovered_row in discovered:
        row = dict(discovered_row)
        url = str(row.get("federation_peer_url") or "")
        if not url:
            row["identity_verified"] = False
            row["identity_error"] = "peer did not advertise an HTTP federation URL"
            skipped_rows.append(row)
            continue
        resolved_ip = _resolve_safe_discovered_federation_ip(url)
        if not resolved_ip:
            row["identity_verified"] = False
            row["identity_error"] = (
                "discovered federation URL targets a local or invalid address"
            )
            skipped_rows.append(row)
            continue
        resolved_address = ipaddress.ip_address(resolved_ip)
        if resolved_address.is_private:
            source_ip = _discovered_source_ip(str(row.get("source_addr") or ""))
            if source_ip != str(resolved_address):
                row["identity_verified"] = False
                row["identity_error"] = (
                    "private federation URL does not match discovery source"
                )
                skipped_rows.append(row)
                continue
        identity_meta, identity_error = _fetch_and_verify_federation_identity(
            url,
            timeout_seconds=min(float(timeout_seconds), 3.0),
            expected_did=str(row.get("did") or ""),
            resolved_ip=resolved_ip,
        )
        if identity_meta is None:
            row["identity_verified"] = False
            row["identity_error"] = identity_error
            skipped_rows.append(row)
            continue
        row["identity_verified"] = True
        row["identity_url"] = identity_meta["identity_url"]
        row["peer_did"] = identity_meta["did"]
        row["pubkey_prefix"] = identity_meta["pubkey_hex"][:16]
        verified_rows.append(row)
        verified_metadata[url] = identity_meta
        if url not in urls:
            urls.append(url)

    imported: List[str] = []
    if add and (urls or verified_rows):
        with _fed_config_guard(ws):
            file_peers = _read_fed_peer_file(ws, strict=True)
            merged = list(file_peers)
            for url in urls:
                if url not in merged:
                    merged.append(url)
                    imported.append(url)
            original_metadata = _read_fed_peer_metadata(ws, strict=True)
            metadata = dict(original_metadata)
            metadata.update(verified_metadata)
            if imported or metadata != original_metadata:
                _write_fed_peer_config_transaction(ws, merged, metadata)

    cache = _ensure_market_fed_cache_for_update(request)
    if refresh and (_read_fed_peers(ws) or _read_learned_fed_peers(ws)):
        from .market_federation_poll import federate_once

        peers = _read_fed_peers(ws)
        try:
            entries = federate_once(
                peers,
                untrusted_peers=_read_learned_fed_peers(ws),
                verify_gossip_peer=_market_fed_gossip_identity_verifier(
                    request, persist_learned=True,
                ),
                verify_seed_peer=_market_fed_gossip_identity_verifier(request),
                max_duration_s=_market_fed_cycle_budget_s(),
            )
            cache.replace_all(
                entries,
                peer_count=len(set(peers) | set(_read_learned_fed_peers(ws))),
            )
        except Exception as exc:  # noqa: BLE001
            cache.mark_error(
                type(exc).__name__,
                peer_count=len(set(peers) | set(_read_learned_fed_peers(ws))),
            )

    status = _market_fed_status(request)
    status["discovered"] = True
    status["discovered_peers"] = verified_rows + skipped_rows
    status["imported_peers"] = imported
    status["skipped_peers"] = skipped_rows
    status["discovery_errors"] = errors
    status["identity_verified_peers"] = [
        row["federation_peer_url"] for row in verified_rows
        if row.get("identity_verified")
    ]
    request.app.state.market_fed_last_discovery = dict(status)
    return status


def activate_market_federation_plugin(app: FastAPI) -> bool:
    """Switch federation polling to the enabled Trust Kernel capability.

    Returns ``True`` when a plugin poller is running. An enabled plugin with
    no configured or learned peers is valid and returns ``False``.
    """
    request = Request({"type": "http", "app": app})
    state = app.state
    with _FED_POLLER_LOCK:
        ws = _state_workspace(request)
        _initialize_fed_runtime_preference(state, ws)
        _clear_finished_market_fed_poller(state)
        if not _claim_market_fed_runtime_owner(state, ws):
            raise RuntimeError(
                "federation runtime is owned by another workspace process"
            )
        existing_mode = str(getattr(state, "market_fed_poller_mode", "") or "")
        if (
            existing_mode == "plugin"
            and getattr(state, "market_fed_poller_started", False)
        ):
            state.market_fed_plugin_suspended = False
            return True
        if getattr(state, "market_fed_poller_started", False):
            if not _stop_market_fed_poller(state, release_owner=False):
                raise RuntimeError(
                    "existing federation poller did not stop; plugin activation aborted"
                )
        state.market_fed_plugin_suspended = False
        if _enabled_federation_plugin_binding(request) is None:
            raise RuntimeError("federation plugin is not enabled")
        _write_fed_runtime_preference(ws, "plugin")
        state.market_fed_runtime_preference = "plugin"
        if not (_read_fed_peers(ws) or _read_learned_fed_peers(ws)):
            return False
        cache = getattr(state, "market_fed_cache", None)
        if cache is None:
            from .market_federation_poll import FederationCache

            cache = FederationCache()
            state.market_fed_cache = cache
        _launch_market_fed_poller(request, cache, ws)
        if getattr(state, "market_fed_poller_mode", "") != "plugin":
            raise RuntimeError("federation plugin poller did not start")
        return True


def claim_market_federation_runtime_owner(app: FastAPI) -> None:
    """Reserve this workspace runtime before mutating PluginHost state."""
    request = Request({"type": "http", "app": app})
    with _FED_POLLER_LOCK:
        ws = _state_workspace(request)
        if not _claim_market_fed_runtime_owner(app.state, ws):
            raise RuntimeError(
                "federation runtime is owned by another workspace process"
            )


def abandon_market_federation_runtime_owner(app: FastAPI) -> None:
    """Release a reservation that never became a running poller."""
    with _FED_POLLER_LOCK:
        if not getattr(app.state, "market_fed_poller_started", False):
            _release_market_fed_runtime_owner(app.state)


def suspend_market_federation_plugin(app: FastAPI) -> bool:
    """Stop plugin polling and forbid implicit legacy fallback this process."""
    state = app.state
    with _FED_POLLER_LOCK:
        ws = _state_workspace(Request({"type": "http", "app": app}))
        if not _claim_market_fed_runtime_owner(state, ws):
            raise RuntimeError(
                "federation runtime is owned by another workspace process"
            )
        state.market_fed_plugin_suspended = True
        try:
            _write_fed_runtime_preference(ws, "suspended")
        except Exception:
            _stop_market_fed_poller(state)
            raise
        state.market_fed_runtime_preference = "suspended"
        return _stop_market_fed_poller(state)


def start_market_federation_runtime(app: FastAPI) -> None:
    """Start poll and LAN discovery runtimes without requiring the UI."""
    request = Request({"type": "http", "app": app})
    _state_market_fed_cache(request)
    if not _env_bool("NTH_LAN_DISCOVERY", False):
        return
    state = app.state
    thread = getattr(state, "market_fed_discovery_thread", None)
    if thread is not None and thread.is_alive():
        return
    stop_event = threading.Event()
    interval = _env_float(
        "NTH_FED_DISCOVERY_INTERVAL_S", 30.0, minimum=5.0, maximum=3600.0,
    )
    timeout_seconds = _env_float(
        "NTH_FED_DISCOVERY_TIMEOUT_S", 1.25, minimum=0.5, maximum=6.0,
    )

    def run_discovery() -> None:
        while not stop_event.is_set():
            try:
                _discover_and_import_market_federation(
                    request,
                    actor_id="admin",
                    timeout_seconds=timeout_seconds,
                    add=False,
                    refresh=False,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("background federation discovery failed: %s", exc)
            stop_event.wait(interval)

    thread = threading.Thread(
        target=run_discovery,
        name="nth-market-federation-discovery",
        daemon=True,
    )
    state.market_fed_discovery_stop_event = stop_event
    state.market_fed_discovery_thread = thread
    thread.start()

def stop_market_federation_runtime(app: FastAPI) -> None:
    """Signal and briefly join the lifecycle-owned federation thread."""
    state = app.state
    discovery_stop = getattr(state, "market_fed_discovery_stop_event", None)
    if discovery_stop is not None and hasattr(discovery_stop, "set"):
        discovery_stop.set()
    discovery_thread = getattr(state, "market_fed_discovery_thread", None)
    if discovery_thread is not None and hasattr(discovery_thread, "join"):
        discovery_thread.join(timeout=10.0)
    if (
        discovery_thread is not None
        and hasattr(discovery_thread, "is_alive")
        and discovery_thread.is_alive()
    ):
        logger.warning("federation discovery thread did not stop in time")
    else:
        state.market_fed_discovery_stop_event = None
        state.market_fed_discovery_thread = None
    _stop_market_fed_poller(state)


def _market_announcement_compatibility_status(
    workspace: Optional[Path], identity: Any,
) -> Dict[str, Any]:
    """Summarize legacy records that cannot be authority-safe federated."""
    empty = {
        "v1_records": 0,
        "federation_ready_v1_records": 0,
        "requires_publisher_resign": 0,
    }
    if workspace is None or identity is None or not hasattr(identity, "as_did"):
        return empty
    feed_path = workspace / "market_feed" / "announcements.jsonl"
    if not feed_path.exists():
        return empty
    from nth_dao.market.announcement import NTH_ANNOUNCEMENT_KIND_V1
    from nth_dao.market.feed import MarketFeed

    source_did = identity.as_did()
    v1_records = 0
    federation_ready = 0
    for announcement in MarketFeed(workspace).poll(
        -1, include_expired=True,
    ).announcements:
        if announcement.kind != NTH_ANNOUNCEMENT_KIND_V1:
            continue
        v1_records += 1
        if announcement.effective_authority_did() == source_did:
            federation_ready += 1
    return {
        "v1_records": v1_records,
        "federation_ready_v1_records": federation_ready,
        "requires_publisher_resign": v1_records - federation_ready,
    }


def _lan_federation_runtime_status(app: FastAPI) -> Dict[str, Any]:
    """Return configuration and live publication state for LAN federation."""
    public_peer_url = str(
        getattr(app.state, "nth_public_base_url", "") or ""
    )
    publish_enabled = _env_bool("NTH_LAN_PUBLISH", True)
    discovery_enabled = _env_bool("NTH_LAN_DISCOVERY", False)
    configured = bool(
        public_peer_url and publish_enabled and discovery_enabled
    )
    try:
        from nth_dao.discovery import mdns_available

        mdns_transport_available = bool(mdns_available())
    except (ImportError, RuntimeError):
        mdns_transport_available = False
    nth_state = getattr(app.state, "nth", None)
    mdns_publisher_active = bool(
        getattr(nth_state, "mdns_responder", None)
    )
    udp_responder = getattr(nth_state, "lan_udp_responder", None)
    udp_running = getattr(udp_responder, "is_running", None)
    udp_publisher_active = bool(
        udp_running() if callable(udp_running) else udp_responder
    )
    publisher_active = mdns_publisher_active or udp_publisher_active
    # UDP discovery is implemented with the Python standard library. Runtime
    # bind failures are reflected by publisher_active rather than availability.
    transport_available = True
    diagnostics: List[str] = []
    try:
        from nth_dao.discovery import configured_discovery_port

        udp_port = configured_discovery_port()
    except (ImportError, ValueError) as exc:
        udp_port = 0
        diagnostics.append(str(exc))
    if not public_peer_url:
        diagnostics.append(
            "This node is local-only. Restart with "
            "`python -m nth_dao.web --lan` so peers can dial its signed "
            "federation feed."
        )
    if not publish_enabled:
        diagnostics.append(
            "LAN publication is disabled (NTH_LAN_PUBLISH=0)."
        )
    if not discovery_enabled:
        diagnostics.append(
            "Background LAN discovery is disabled (NTH_LAN_DISCOVERY is not 1)."
        )
    if configured and not publisher_active:
        diagnostics.append(
            "LAN publication is configured but neither UDP nor mDNS is active; "
            "check the server log and local firewall."
        )
    return {
        "public_peer_url": public_peer_url,
        "lan_federation_configured": configured,
        "lan_federation_ready": bool(
            configured and transport_available and publisher_active
        ),
        "lan_publish_enabled": publish_enabled,
        "lan_discovery_enabled": discovery_enabled,
        "lan_transport_available": transport_available,
        "lan_publisher_active": publisher_active,
        "lan_udp_publisher_active": udp_publisher_active,
        "lan_udp_port": udp_port,
        "lan_mdns_publisher_active": mdns_publisher_active,
        "lan_mdns_available": mdns_transport_available,
        "lan_diagnostics": diagnostics,
    }


def _market_fed_status(request: Request) -> Dict[str, Any]:
    _clear_finished_market_fed_poller(request.app.state)
    ws = _state_workspace(request)
    runtime_preference = _initialize_fed_runtime_preference(
        request.app.state,
        ws,
    )
    cache = getattr(request.app.state, "market_fed_cache", None)
    status = (
        cache.status()
        if cache is not None and hasattr(cache, "status")
        else {
            "cached_announcements": 0,
            "last_refresh_ms": 0,
            "last_error": "",
            "last_peer_count": 0,
        }
    )
    seed_peers = _read_fed_peers(ws)
    learned_records = _read_learned_fed_peer_records(ws)
    learned_peers = [record.peer_url for record in learned_records]
    peers = list(dict.fromkeys(seed_peers + learned_peers))
    lan_runtime = _lan_federation_runtime_status(request.app)
    last_discovery = getattr(
        request.app.state, "market_fed_last_discovery", {},
    )
    if not isinstance(last_discovery, dict):
        last_discovery = {}
    env_peers: List[str] = []
    for item in os.environ.get("NTH_FED_PEERS", "").split(","):
        if not item.strip():
            continue
        try:
            env_peers.append(_normalize_configured_fed_peer(item))
        except ValueError:
            continue
    return {
        "peers": peers,
        "seed_peers": seed_peers,
        "learned_peers": {
            record.peer_url: {
                "did": record.did,
                "pubkey_prefix": record.pubkey_hex[:16],
                "last_verified_ms": record.last_verified_ms,
                "expires_at_ms": record.expires_at_ms,
            }
            for record in learned_records
        },
        **lan_runtime,
        "reverse_discovery_enabled": _market_fed_announce_self(request) is not None,
        "file_peers": _read_fed_peer_file(ws),
        "env_peers": env_peers,
        "verified_peers": {
            peer_url: {
                "did": str(meta.get("did") or ""),
                "pubkey_prefix": str(meta.get("pubkey_hex") or "")[:16],
                "verified_at": str(meta.get("verified_at") or ""),
                "identity_url": str(meta.get("identity_url") or ""),
            }
            for peer_url, meta in _read_fed_peer_metadata(ws).items()
        },
        "poller_started": bool(
            getattr(request.app.state, "market_fed_poller_started", False)
        ),
        "poller_mode": str(
            getattr(request.app.state, "market_fed_poller_mode", "") or ""
        ),
        "plugin_suspended": bool(
            getattr(request.app.state, "market_fed_plugin_suspended", False)
        ),
        "runtime_preference": runtime_preference,
        "announcement_compatibility": _market_announcement_compatibility_status(
            ws,
            _state_node_identity(request),
        ),
        "discovered": bool(last_discovery.get("discovered", False)),
        "identity_verified_peers": list(
            last_discovery.get("identity_verified_peers") or []
        ),
        "discovered_peers": list(last_discovery.get("discovered_peers") or []),
        "imported_peers": list(last_discovery.get("imported_peers") or []),
        "skipped_peers": list(last_discovery.get("skipped_peers") or []),
        "discovery_errors": list(last_discovery.get("discovery_errors") or []),
        **status,
    }


def register_v2_routes(app: FastAPI) -> None:
    """Attach the /api/v2/* read endpoints to ``app``.

    Idempotent via a marker on ``app.state`` (P1 fix 2026-06-10).
    FastAPI silently accepts duplicate routes; without the guard,
    every create_app() — uvicorn --reload, tests, multi-worker —
    would re-register each handler, doubling the routing table
    each cycle. The marker survives reloads only via the running
    process; across full restarts the routes are fresh.

    Routes MUST be registered before the catch-all ``/{path:path}``
    SPA fallback in __init__.py so /api/v2/... matches first. """
    if getattr(app.state, "v2_routes_registered", False):
        logger.debug("v2_api: register_v2_routes called twice — skipping")
        return
    app.state.v2_routes_registered = True

    # Commerce is kept in a focused route module so its signed protocol and
    # no-real-money boundary do not become entangled with the large console
    # projection module.
    from .commerce_api import register_commerce_routes

    register_commerce_routes(
        app,
        sensitive_read_guard=_require_console_bearer_for_sensitive_read,
    )

    # Load durable AgentLink state before requests arrive. The store converts
    # interrupted accepted/processing jobs to delivery_unknown; project those
    # outcomes back into their originating channels exactly once.
    try:
        from .agent_link import AgentLinkManager, AgentLinkStore

        workspace = Path(app.state.nth.workspace)
        manager = getattr(app.state, "agent_link_manager", None)
        if manager is None:
            manager = AgentLinkManager(
                AgentLinkStore(workspace),
                max_pending_per_agent=4,
                max_jobs=1000,
            )
            app.state.agent_link_manager = manager
        recovered = _recover_incomplete_channel_dispatches(
            getattr(app.state.nth, "groups", None),
            manager.store.all(),
        )
        if recovered:
            logger.warning(
                "v2_api: projected %d interrupted AgentLink job(s) to channels",
                recovered,
            )
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as exc:
        logger.warning("v2_api: AgentLink startup recovery failed: %s", exc)

    @app.get("/api/v2/identity")
    def v2_identity(request: Request) -> Dict[str, Any]:
        identity = _state_node_identity(request)
        if identity is None or not hasattr(identity, "as_did"):
            raise HTTPException(status_code=503, detail="node identity unavailable")
        from nth_dao.agent_code import code_for_pubkey

        pubkey_hex = str(getattr(identity, "pubkey_hex", "") or "")
        return {
            "agent_id": str(getattr(identity, "agent_id", "") or "admin"),
            "did": str(identity.as_did()),
            "code": code_for_pubkey(pubkey_hex),
        }

    # ── 频道(收编自 8765 群聊,P1)────────────────────────────────
    # 复用 app.state.nth.groups(GroupManager,已挂在 state 上),不重造
    # 后端。GroupManager 抛 PermissionError → 403、ValueError → 404/400。
    def _groups(request: Request):
        g = getattr(request.app.state.nth, "groups", None)
        if g is None:
            raise HTTPException(status_code=503, detail="group manager unavailable")
        return g

    @app.get("/api/v2/channels")
    def v2_channels(request: Request, actor_id: str = "") -> List[Dict[str, Any]]:
        """列频道。actor_id 留空时只看公开频道(私有频道需成员身份)。"""
        groups = _groups(request)
        channels = groups.list_channels(actor_id=actor_id)
        tasks_by_channel: Dict[str, List[Any]] = {}
        try:
            for task in groups.list_tasks():
                if task.channel_id and task.channel_id != "general":
                    tasks_by_channel.setdefault(task.channel_id, []).append(task)
        except (OSError, TypeError, ValueError) as exc:
            logger.warning("channel task scope projection failed: %s", exc)
        dao_records: List[Any] = []
        try:
            registry = getattr(request.app.state.nth, "group_registry", None)
            if registry is not None:
                dao_records = sorted(
                    registry.list_all(),
                    key=lambda record: len(str(getattr(record, "slug", "") or "")),
                    reverse=True,
                )
        except (OSError, TypeError, ValueError) as exc:
            logger.warning("channel DAO scope projection failed: %s", exc)

        projected: List[Dict[str, Any]] = []
        for channel in channels:
            row = channel.to_dict()
            metadata = dict(row.get("metadata") or {})
            if not any(
                metadata.get(key)
                for key in ("task_id", "mission_id", "process_id")
            ):
                linked_tasks = tasks_by_channel.get(channel.channel_id, [])
                if linked_tasks:
                    task = max(
                        linked_tasks,
                        key=lambda item: str(
                            getattr(item, "updated_at", "")
                            or getattr(item, "created_at", "")
                        ),
                    )
                    metadata["task_id"] = str(getattr(task, "task_id", "") or "")
                    metadata["task_label"] = str(getattr(task, "title", "") or "")
            if not any(metadata.get(key) for key in ("dao_id", "scope_dao")):
                matched_record = next(
                    (
                        record for record in dao_records
                        if channel.channel_id.startswith(
                            f"dao-{getattr(record, 'slug', '')}-"
                        )
                    ),
                    None,
                )
                if matched_record is not None:
                    metadata["dao_id"] = str(
                        getattr(matched_record, "slug", "") or ""
                    )
                    metadata["dao_label"] = str(
                        getattr(matched_record, "display_name", "") or ""
                    )
                else:
                    metadata["dao_id"] = "home"
                    metadata["dao_label"] = "NTH DAO"
            row["metadata"] = metadata
            projected.append(row)
        return projected

    @app.post("/api/v2/channels")
    def v2_channel_create(
        body: CreateChannelBody, request: Request,
    ) -> Dict[str, Any]:
        """新建频道。"""
        name = body.name.strip()
        if not name:
            raise HTTPException(status_code=400, detail="name must not be empty")
        if len(name) > 80 or len(body.topic) > 200:
            raise HTTPException(status_code=400, detail="name/topic too long")
        g = _groups(request)
        # 幂等防冲(对抗审查发现):create_channel 无条件覆写 channel.json,
        # 同名重建会冲掉已加入的成员 + topic。先查存在 → 有则原样返回,
        # 绝不重建。get_channel(name) 与 create 用同一 _safe_id,id 一致。
        existing = g.get_channel(name)
        if existing is not None:
            return existing.to_dict()
        try:
            ch = g.create_channel(
                name=name,
                created_by=body.created_by.strip() or "admin",
                topic=body.topic.strip(),
                metadata={"dao_id": "home", "dao_label": "NTH DAO"},
            )
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return ch.to_dict()

    @app.get("/api/v2/channels/{channel_id}")
    def v2_channel_get(channel_id: str, request: Request) -> Dict[str, Any]:
        ch = _groups(request).get_channel(channel_id)
        if ch is None:
            raise HTTPException(status_code=404, detail="channel not found")
        return ch.to_dict()

    @app.post("/api/v2/channels/{channel_id}/attachments")
    async def v2_channel_attachment_upload(
        channel_id: str,
        request: Request,
        filename: str = "",
        actor_id: str = "admin",
    ) -> Dict[str, Any]:
        groups = _groups(request)
        channel = groups.get_channel(channel_id)
        if channel is None:
            raise HTTPException(status_code=404, detail="channel not found")
        actor = actor_id.strip() or "admin"
        if actor not in set(channel.member_ids or []):
            raise HTTPException(status_code=403, detail="actor must be a channel member")
        declared_length = request.headers.get("content-length", "").strip()
        if declared_length:
            try:
                if int(declared_length) > _CHANNEL_ATTACHMENT_MAX_BYTES:
                    raise HTTPException(status_code=413, detail="attachment exceeds 25 MB")
            except ValueError:
                raise HTTPException(status_code=400, detail="invalid content-length")
        content = bytearray()
        async for chunk in request.stream():
            content.extend(chunk)
            if len(content) > _CHANNEL_ATTACHMENT_MAX_BYTES:
                raise HTTPException(status_code=413, detail="attachment exceeds 25 MB")

        raw_filename = filename.strip() or request.headers.get("x-filename", "").strip()
        normalized_filename = Path(raw_filename.replace("\\", "/")).name
        normalized_filename = "".join(
            character for character in normalized_filename
            if ord(character) >= 32 and character not in {"\x7f"}
        ).strip()
        if not normalized_filename:
            normalized_filename = "attachment"
        normalized_filename = normalized_filename[:180]
        attachment_id = hashlib.sha256(os.urandom(32)).hexdigest()[:24]
        data_path, metadata_path = _channel_attachment_paths(
            request, channel_id, attachment_id,
        )
        content_bytes = bytes(content)
        record = {
            "attachment_id": attachment_id,
            "channel_id": channel_id,
            "filename": normalized_filename,
            "media_type": (
                request.headers.get("content-type", "application/octet-stream")
                or "application/octet-stream"
            )[:200],
            "size": len(content_bytes),
            "sha256": hashlib.sha256(content_bytes).hexdigest(),
            "uploaded_by": actor,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        _write_channel_attachment(data_path, content_bytes)
        atomic_write_json(metadata_path, record)
        return _channel_attachment_public(record)

    @app.get("/api/v2/channels/{channel_id}/attachments/{attachment_id}")
    def v2_channel_attachment_download(
        channel_id: str,
        attachment_id: str,
        request: Request,
        actor_id: str = "admin",
    ) -> FileResponse:
        groups = _groups(request)
        channel = groups.get_channel(channel_id)
        if channel is None:
            raise HTTPException(status_code=404, detail="channel not found")
        actor = actor_id.strip() or "admin"
        if actor not in set(channel.member_ids or []):
            raise HTTPException(status_code=403, detail="actor must be a channel member")
        record = _load_channel_attachment(request, channel_id, attachment_id)
        if record is None:
            raise HTTPException(status_code=404, detail="attachment not found")
        data_path, _ = _channel_attachment_paths(request, channel_id, attachment_id)
        return FileResponse(
            data_path,
            media_type=str(record.get("media_type") or "application/octet-stream"),
            filename=str(record.get("filename") or "attachment"),
        )

    @app.get("/api/v2/channels/{channel_id}/messages")
    def v2_channel_messages(
        channel_id: str,
        request: Request,
        actor_id: str = "",
        limit: int = 100,
        before_message_id: str = "",
    ) -> List[Dict[str, Any]]:
        g = _groups(request)
        if g.get_channel(channel_id) is None:
            raise HTTPException(status_code=404, detail="channel not found")
        capped = min(max(limit, 1), 500)
        messages = g.list_messages(channel_id, actor_id=actor_id)
        if before_message_id:
            try:
                end = next(
                    index for index, item in enumerate(messages)
                    if item.message_id == before_message_id
                )
            except StopIteration:
                raise HTTPException(
                    status_code=404,
                    detail="before_message_id not found in channel",
                )
            messages = messages[:end]
        return [
            _channel_message_to_wire(m)
            for m in messages[-capped:]
        ]

    @app.post("/api/v2/channels/{channel_id}/messages")
    def v2_channel_post(
        channel_id: str, body: ChannelMessageBody, request: Request,
    ) -> Dict[str, Any]:
        """频道发消息。返回落盘后的 Message。

        P2 将在此挂"频道消息→派发给成员 agent→回帖"的监听(带防环:
        只对人类作者的消息触发,不对 agent 回帖再触发)。
        """
        text = body.body.strip()
        if not text and not body.attachment_ids:
            raise HTTPException(
                status_code=400,
                detail="body or attachment_ids must be provided",
            )
        if len(text) > _CHANNEL_MESSAGE_MAX_CHARS:
            raise HTTPException(
                status_code=400,
                detail=f"body too long (max {_CHANNEL_MESSAGE_MAX_CHARS})",
            )
        groups = _groups(request)
        channel = groups.get_channel(channel_id)
        if channel is None:
            raise HTTPException(status_code=404, detail="channel not found")
        target_agent_dids = list(body.target_agent_dids)
        if target_agent_dids:
            non_members = sorted(
                set(target_agent_dids) - set(channel.member_ids or []),
            )
            if non_members:
                raise HTTPException(
                    status_code=403,
                    detail="target Agent must be a member of this channel",
                )
        reply_to = body.reply_to_message_id.strip()
        if reply_to:
            known_message_ids = {
                item.message_id for item in groups.list_messages(channel_id, actor_id="")
            }
            if reply_to not in known_message_ids:
                raise HTTPException(
                    status_code=400,
                    detail="reply_to_message_id does not belong to this channel",
                )
        attachments: List[Dict[str, Any]] = []
        for attachment_id in body.attachment_ids:
            record = _load_channel_attachment(request, channel_id, attachment_id)
            if record is None:
                raise HTTPException(
                    status_code=400,
                    detail=f"attachment {attachment_id!r} does not belong to this channel",
                )
            attachments.append(_channel_attachment_public(record))
        message_metadata: Dict[str, Any] = {}
        if target_agent_dids:
            message_metadata["target_agent_dids"] = target_agent_dids
        if attachments:
            message_metadata["attachments"] = attachments
        try:
            msg = groups.post_message(
                channel_id,
                sender_id=body.agent_id.strip() or "admin",
                body=text,
                reply_to=reply_to,
                metadata=message_metadata or None,
            )
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc))
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        # P2:人类消息→派发给频道里可驱动的 agent 成员→回帖(后台、防环)。
        if text:
            _maybe_dispatch_to_channel_agents(request, channel_id, msg)
        return _channel_message_to_wire(msg)

    @app.post("/api/v2/channels/{channel_id}/join")
    def v2_channel_join(
        channel_id: str, body: JoinChannelBody, request: Request,
    ) -> Dict[str, Any]:
        """把一个 agent 加进频道成员列表(P3 的'频道加 agent'入口)。"""
        agent_id = body.agent_id.strip()
        if not agent_id:
            raise HTTPException(status_code=400, detail="agent_id must not be empty")
        try:
            ch = _groups(request).add_channel_member(
                channel_id, agent_id=agent_id, added_by="",
            )
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc))
        return ch.to_dict()

    @app.get("/api/v2/decisions", response_model=List[DecisionM])
    def v2_decisions(request: Request) -> List[Dict[str, Any]]:
        # The durable queue shrinks as the user approves, rejects, or defers.
        return list(_decisions_store(request).values())

    @app.post("/api/v2/decisions/{decision_id}/approve")
    def v2_decisions_approve(
        decision_id: str,
        request: Request,
    ) -> Dict[str, Any]:
        """Sign + persist a receipt for ``decision_id``, then remove
        it from the queue. Returns the new ReceiptSummary so the
        frontend can update its chain_head without a refetch.

        Failure modes:
          404 — id not in queue (already resolved, never existed)
          503 — signer identity not available (fail closed; we
                NEVER return an unsigned receipt)
          500 — receipt save failed AFTER signing (unexpected;
                the decision is NOT removed so the user can retry) """
        return _resolve_decision(
            decision_id, request, sign=True, action="approved",
        )

    @app.post("/api/v2/decisions/{decision_id}/reject")
    def v2_decisions_reject(
        decision_id: str,
        request: Request,
    ) -> Dict[str, Any]:
        """Drop the decision from the queue. No receipt is signed —
        rejection is non-actionable. Returns {removed: true}. """
        return _resolve_decision(
            decision_id, request, sign=False, action="rejected",
        )

    @app.post("/api/v2/decisions/{decision_id}/defer")
    def v2_decisions_defer(
        decision_id: str,
        request: Request,
    ) -> Dict[str, Any]:
        """Drop the decision from the queue. Phase 3 will move it to
        a "deferred" bucket with a follow-up timer; Phase 2 just
        removes it. """
        return _resolve_decision(
            decision_id, request, sign=False, action="deferred",
        )

    @app.get("/api/v2/missions", response_model=List[MissionSummaryM])
    def v2_missions(request: Request) -> List[Dict[str, Any]]:
        store = getattr(request.app.state.nth, "missions", None)
        if store is None:
            raise HTTPException(status_code=503, detail="mission store unavailable")
        try:
            missions = store.list_all()
        except Exception as exc:  # noqa: BLE001
            logger.warning("v2_missions: list_all failed: %s", exc)
            raise HTTPException(
                status_code=500, detail="mission store read failed",
            ) from exc
        return [_mission_to_summary(m, request) for m in missions]

    @app.post("/api/v2/missions", response_model=MissionSummaryM)
    def v2_missions_create(
        body: CreateMissionBody, request: Request,
    ) -> Dict[str, Any]:
        """真正创建并落盘一个 mission(含 steps)。此前"+ New mission"是纯
        前端假动作(m-local- id、不落库、刷新即失)——这条让它真正进
        state.missions,从而能被 GET 读、被 Mission↔Task 桥用。

        新 mission 默认 status=planning(空步骤天然是规划态);加了步骤、
        开始执行后才进 active。POST 动作端点,auth 开启受控。
        """
        from nth_dao.orchestration.mission import Mission

        store = getattr(request.app.state.nth, "missions", None)
        if store is None:
            raise HTTPException(status_code=503, detail="mission store unavailable")
        title = body.title.strip()
        if not title:
            raise HTTPException(status_code=400, detail="title must not be empty")
        # 输入封顶(落盘 + 后续可能 announce 进 feed)。
        if (
            len(title) > 200
            or len(body.goal) > 2000
            or len(body.driver) > 128
            or len(body.driver_did) > 256
        ):
            raise HTTPException(status_code=400, detail="title/goal/driver too long")
        if len(body.steps) > 64:
            raise HTTPException(status_code=400, detail="too many steps (max 64)")
        step_dicts: List[Dict[str, Any]] = []
        for s in body.steps:
            desc = s.description.strip()
            if not desc:
                continue
            if len(desc) > 500:
                raise HTTPException(
                    status_code=400, detail="step description too long (max 500)"
                )
            if len(s.required_capabilities) > 16:
                raise HTTPException(
                    status_code=400, detail="too many capabilities on a step")
            step_dicts.append({
                "description": desc,
                "required_capabilities": [
                    c.strip() for c in s.required_capabilities if c.strip()
                ],
            })
        m = Mission.new(
            title=title,
            goal=body.goal.strip(),
            owner=body.driver.strip(),
            owner_did=body.driver_did.strip(),  # 留存 driver 的密码学身份
            steps=step_dicts,
        )
        try:
            store.create(m)
        except Exception as exc:  # noqa: BLE001
            logger.exception("v2_missions_create: store.create failed: %s", exc)
            raise HTTPException(status_code=500, detail=f"create failed: {exc}")
        _emit_mission_evidence(request, MISSION_CREATED, {
            "mission_id": m.id,
            "title": m.title,
            "goal": m.goal,
            "status": m.status,
            "driver_label": getattr(m, "owner", "") or "",
            "driver_did": getattr(m, "owner_did", "") or "",
            "steps_total": len(getattr(m, "steps", []) or []),
        })
        return _mission_to_summary(m, request)

    @app.post(
        "/api/v2/missions/{mission_id}/activate",
        response_model=MissionSummaryM,
    )
    def v2_mission_activate(
        mission_id: str, request: Request,
    ) -> Dict[str, Any]:
        """把 mission 从 planning/paused 推进到 active(开始执行)。

        补齐"创建后卡在 planning"的最后一环:此前没有任何动作能把 mission
        移出 planning。空 mission(0 步)不能启动——没活可干。已 active 则
        幂等返回;终态(completed/failed/cancelled)拒。落盘持久。
        """
        from nth_dao.orchestration.mission import MissionStatus, MissionStep, StepStatus
        from nth_dao.util.io import InterProcessLock, safe_id

        store = getattr(request.app.state.nth, "missions", None)
        if store is None:
            raise HTTPException(status_code=503, detail="mission store unavailable")
        created_bootstrap_step: Optional[str] = None
        assigned_bootstrap_step = False
        lock_root = Path(getattr(store, "root", Path("missions")))
        lock_path = lock_root / f".activate-{safe_id(mission_id)}"
        try:
            with InterProcessLock(lock_path):
                m = store.get(mission_id)
                if m is None:
                    raise HTTPException(status_code=404, detail="mission not found")
                if m.status == MissionStatus.ACTIVE.value:
                    return _mission_to_summary(m, request)  # idempotent
                if m.status not in (
                    MissionStatus.PLANNING.value, MissionStatus.PAUSED.value,
                ):
                    raise HTTPException(
                        status_code=409,
                        detail=(
                            f"mission is '{m.status}'; only planning/paused can "
                            f"be activated"
                        ),
                    )
                if not m.steps:
                    basis = (getattr(m, "goal", "") or getattr(m, "title", "")).strip()
                    description = basis[:500] or "Initial mission work"
                    digest = hashlib.sha256(
                        f"{m.id}\n{description}".encode("utf-8")
                    ).hexdigest()[:8]
                    step = MissionStep(
                        id=f"boot{digest}",
                        description=description,
                    )
                    driver_did = str(getattr(m, "owner_did", "") or "").strip()
                    if driver_did:
                        step.status = StepStatus.CLAIMED.value
                        step.assignee = driver_did
                        step.add_note(
                            "bootstrap step assigned to mission driver",
                            "system",
                        )
                        assigned_bootstrap_step = True
                    m.steps.append(step)
                    created_bootstrap_step = step.id
                m.status = MissionStatus.ACTIVE.value
                store.save(m)
        except Exception as exc:  # noqa: BLE001
            if isinstance(exc, HTTPException):
                raise
            logger.exception("v2_mission_activate: save failed: %s", exc)
            raise HTTPException(status_code=500, detail=f"activate failed: {exc}")
        if created_bootstrap_step:
            _emit_mission_evidence(
                request,
                MISSION_STEP_BOOTSTRAPPED,
                {
                    "mission_id": m.id,
                    "step_id": created_bootstrap_step,
                    "step_status": (
                        StepStatus.CLAIMED.value
                        if assigned_bootstrap_step
                        else StepStatus.TODO.value
                    ),
                    "driver_did": getattr(m, "owner_did", "") or "",
                    "status": m.status,
                    "bootstrap": True,
                },
            )
            if assigned_bootstrap_step:
                _emit_mission_evidence(
                    request,
                    MISSION_STEP_CLAIMED,
                    {
                        "mission_id": m.id,
                        "step_id": created_bootstrap_step,
                        "step_status": StepStatus.CLAIMED.value,
                        "claimant_did": getattr(m, "owner_did", "") or "",
                        "status": m.status,
                        "bootstrap": True,
                    },
                )
        _emit_mission_evidence(
            request,
            MISSION_ACTIVATED,
            {
                "mission_id": m.id,
                "status": m.status,
                "driver_label": getattr(m, "owner", "") or "",
                "driver_did": getattr(m, "owner_did", "") or "",
                "steps_total": len(getattr(m, "steps", []) or []),
            },
        )
        return _mission_to_summary(m, request)

    @app.post(
        "/api/v2/missions/{mission_id}/steps/{step_id}/run",
        response_model=MissionSummaryM,
    )
    async def v2_mission_step_run(
        mission_id: str,
        step_id: str,
        body: RunMissionStepBody,
        request: Request,
    ) -> Dict[str, Any]:
        """Run one Mission step through its assigned local A2A agent.

        The step execution contract is deliberately modest:
          * todo/handed_off/blocked steps are atomically claimed first;
          * claimed/active/needs_review steps may only be run by their
            current assignee (or by the mission driver when unassigned);
          * a successful agent response must carry a verifiable receipt before
            the step can become done;
          * backend failures become a visible blocked state instead of a
            silent no-op.
        """
        from nth_dao.orchestration.mission import StepStatus
        from nth_dao.orchestration.mission_store import (
            ClaimConflict,
            MissionNotFound,
            StepNotFound,
        )

        store = getattr(request.app.state.nth, "missions", None)
        if store is None:
            raise HTTPException(status_code=503, detail="mission store unavailable")
        mission = store.get(mission_id)
        if mission is None:
            raise HTTPException(status_code=404, detail="mission not found")
        step = mission.get_step(step_id)
        if step is None:
            raise HTTPException(status_code=404, detail="step not found")

        agent_did = (
            body.agent_did.strip()
            or str(getattr(step, "assignee", "") or "").strip()
            or str(getattr(mission, "owner_did", "") or "").strip()
        )
        if not agent_did:
            raise HTTPException(
                status_code=409,
                detail="step has no assigned agent; pick a live agent first",
            )
        if step.assignee and step.assignee != agent_did:
            raise HTTPException(
                status_code=409,
                detail=f"step is assigned to {step.assignee}, not {agent_did}",
            )

        claim_event = False
        try:
            if step.status in {
                StepStatus.TODO.value,
                StepStatus.HANDED_OFF.value,
                StepStatus.BLOCKED.value,
            }:
                store.try_claim(
                    mission_id=mission_id,
                    step_id=step_id,

                    agent_id=agent_did,
                    capabilities=None,
                )
                claim_event = True
            elif step.status in {
                StepStatus.CLAIMED.value,
                StepStatus.NEEDS_REVIEW.value,
            }:
                store.update_step(
                    mission_id=mission_id,
                    step_id=step_id,
                    status=StepStatus.ACTIVE.value,
                    assignee=agent_did,
                    note="agent run started",
                    note_author=agent_did,
                    expect_status=step.status,
                    expect_assignee_in=[agent_did, ""],
                )
            elif step.status == StepStatus.ACTIVE.value:
                store.update_step(
                    mission_id=mission_id,
                    step_id=step_id,
                    note="agent run retried",
                    note_author=agent_did,
                    expect_status=StepStatus.ACTIVE.value,
                    expect_assignee_in=[agent_did],
                )
            else:
                raise HTTPException(
                    status_code=409,
                    detail=f"step is '{step.status}' and cannot be run",
                )
        except (MissionNotFound, StepNotFound) as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ClaimConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

        if claim_event:
            _emit_mission_evidence(request, MISSION_STEP_CLAIMED, {
                "mission_id": mission_id,
                "step_id": step_id,
                "step_status": StepStatus.ACTIVE.value,
                "claimant_did": agent_did,
                "status": StepStatus.ACTIVE.value,
            })

        latest = store.get(mission_id)
        active_step = latest.get_step(step_id) if latest is not None else None
        if latest is None or active_step is None:
            raise HTTPException(status_code=404, detail="step disappeared")
        prompt = body.prompt.strip()
        if not prompt:
            prompt = (
                "You are executing one NTH DAO Mission step.\n"
                f"Mission: {latest.title}\n"
                f"Goal: {latest.goal}\n"
                f"Step: {active_step.description}\n\n"
                "Return a concise result, include what you checked, and name "
                "any remaining risk."
            )
        if len(prompt) > 20000:
            raise HTTPException(status_code=413, detail="prompt too large")

        def mark_step_blocked(error_text: str) -> None:
            try:
                store.update_step(
                    mission_id=mission_id,
                    step_id=step_id,
                    status=StepStatus.BLOCKED.value,
                    note=f"agent run failed: {error_text[:240]}",
                    note_author=agent_did,
                    expect_assignee_in=[agent_did],
                )
            except (ClaimConflict, OSError, RuntimeError, TypeError, ValueError) as update_exc:
                logger.warning(
                    "mission step failure visibility update failed for %s/%s: %s",
                    mission_id,
                    step_id,
                    update_exc,
                )
            _emit_mission_evidence(request, MISSION_STEP_BLOCKED, {
                "mission_id": mission_id,
                "step_id": step_id,
                "step_status": StepStatus.BLOCKED.value,
                "agent_did": agent_did,
                "status": StepStatus.BLOCKED.value,
                "response_preview": error_text[:240],
            })

        try:
            resp_status, content, _rec, receipt_meta = await _drive_supervised_agent_ask(
                request,
                agent_did,
                {"prompt": prompt},
            )
        except HTTPException as exc:
            error_text = str(exc.detail)
            try:
                store.update_step(
                    mission_id=mission_id,
                    step_id=step_id,
                    status=StepStatus.BLOCKED.value,
                    note=f"agent run failed: {error_text[:240]}",
                    note_author=agent_did,
                    expect_assignee_in=[agent_did],
                )
            except (ClaimConflict, OSError, RuntimeError, TypeError, ValueError) as update_exc:
                logger.warning(
                    "mission step failure visibility update failed for %s/%s: %s",
                    mission_id,
                    step_id,
                    update_exc,
                )
            _emit_mission_evidence(request, MISSION_STEP_BLOCKED, {
                "mission_id": mission_id,
                "step_id": step_id,
                "step_status": StepStatus.BLOCKED.value,
                "agent_did": agent_did,
                "status": StepStatus.BLOCKED.value,
                "response_preview": error_text[:240],
            })
            raise

        if resp_status != 200:
            error_text = _a2a_http_error_message(
                resp_status,
                content,
                backend_kind=str(getattr(_rec, "kind", "") or ""),
            )
            try:
                store.update_step(
                    mission_id=mission_id,
                    step_id=step_id,
                    status=StepStatus.BLOCKED.value,
                    note=f"agent run failed: {error_text[:240]}",
                    note_author=agent_did,
                    expect_assignee_in=[agent_did],
                )
            except (ClaimConflict, OSError, RuntimeError, TypeError, ValueError) as update_exc:
                logger.warning(
                    "mission step failure visibility update failed for %s/%s: %s",
                    mission_id,
                    step_id,
                    update_exc,
                )
            _emit_mission_evidence(request, MISSION_STEP_BLOCKED, {
                "mission_id": mission_id,
                "step_id": step_id,
                "step_status": StepStatus.BLOCKED.value,
                "agent_did": agent_did,
                "status": StepStatus.BLOCKED.value,
                "response_preview": error_text[:240],
            })
            raise HTTPException(status_code=502, detail=error_text)

        if not receipt_meta:
            error_text = "agent response carried no verifiable receipt"
            store.update_step(
                mission_id=mission_id,
                step_id=step_id,
                status=StepStatus.BLOCKED.value,
                note=error_text,
                note_author=agent_did,
                expect_assignee_in=[agent_did],
            )
            _emit_mission_evidence(request, MISSION_STEP_BLOCKED, {
                "mission_id": mission_id,
                "step_id": step_id,
                "step_status": StepStatus.BLOCKED.value,
                "agent_did": agent_did,
                "status": StepStatus.BLOCKED.value,
                "response_preview": error_text,
            })
            raise HTTPException(status_code=502, detail=error_text)

        result = content.get("result") if isinstance(content, dict) else None
        if not isinstance(result, dict):
            mark_step_blocked("agent response missing result")
            raise HTTPException(status_code=502, detail="agent response missing result")
        response_text = str(result.get("response") or "").strip()
        if not response_text:
            mark_step_blocked("agent response was empty")
            raise HTTPException(status_code=502, detail="agent response was empty")
        stored_response = response_text[:20000]
        output = {
            "content": stored_response,
            "response_truncated": len(response_text) > len(stored_response),
            "backend": str(result.get("backend") or ""),
            "model": str(result.get("model") or ""),
            "receipt_id": receipt_meta.get("nth_receipt_id", ""),
            "receipt_content_hash": receipt_meta.get("nth_receipt_content_hash", ""),
        }

        current = store.get_step(mission_id, step_id)
        if current is None:
            raise HTTPException(status_code=404, detail="step disappeared")
        ok, reason = current.evaluate(output)
        if ok:
            status = StepStatus.DONE.value
            note = "agent run completed"
            event_type = MISSION_STEP_COMPLETED
            review_trail = None
        else:
            status = StepStatus.NEEDS_REVIEW.value
            note = f"acceptance failed: {reason}"
            event_type = MISSION_STEP_NEEDS_REVIEW
            review_trail = {
                "ts": datetime.now().isoformat(),
                "by": agent_did,
                "output": output,
                "reason": reason,
            }

        try:
            store.update_step(
                mission_id=mission_id,
                step_id=step_id,
                status=status,
                output=output,
                note=note,
                note_author=agent_did,
                expect_assignee_in=[agent_did],
                append_review_trail=review_trail,
            )
        except ClaimConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

        _emit_mission_evidence(request, event_type, {
            "mission_id": mission_id,
            "step_id": step_id,
            "step_status": status,
            "agent_did": agent_did,
            "status": status,
            "agent_response_receipt_id": receipt_meta.get("nth_receipt_id", ""),
            "agent_response_receipt_hash": receipt_meta.get(
                "nth_receipt_content_hash", ""
            ),
            "response_preview": response_text[:240],
            "acceptance_reason": reason,
        })
        refreshed = store.get(mission_id)
        if refreshed is None:
            raise HTTPException(status_code=404, detail="mission disappeared")
        return _mission_to_summary(refreshed, request)

    @app.get("/api/v2/processes", response_model=List[ProcessCardM])
    def v2_processes(request: Request) -> List[Dict[str, Any]]:
        return _read_processes_from_blackboard(_state_blackboard(request))

    @app.post("/api/v2/processes", response_model=ProcessCardM)
    def v2_process_create(
        body: CreateProcessBody, request: Request,
    ) -> Dict[str, Any]:
        """Create a Blackboard-backed process card.

        The v2 UI treats Blackboard as the human-visible work state
        board. This endpoint makes the ``+ New process`` button real:
        the card persists through refresh and is visible to agents via
        the existing Blackboard provider instead of living only in
        React state.
        """
        blackboard = _state_blackboard(request)
        if blackboard is None:
            raise HTTPException(status_code=503, detail="blackboard unavailable")
        metadata: Dict[str, Any] = {
            "workflow": body.workflow,
            "auto": body.auto,
            "current_agent": body.current_agent,
            "created_by": "admin",
        }
        for key in ("next_agent", "cap_token_id", "amount"):
            value = getattr(body, key)
            if value:
                metadata[key] = value
        try:
            entry = blackboard.post(
                topic=body.title,
                author="admin",
                scope="shared",
                status=_PROCESS_STAGE_TO_BLACKBOARD[body.stage],
                content=body.subtitle,
                metadata=metadata,
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("v2_process_create: blackboard write failed: %s", exc)
            raise HTTPException(
                status_code=500,
                detail=f"process create failed: {exc}",
            ) from exc
        return _blackboard_entry_to_process_card(entry)

    @app.get("/api/v2/receipts", response_model=List[ReceiptSummaryM])
    def v2_receipts(request: Request) -> List[Dict[str, Any]]:
        return _read_receipts_from_disk(_state_workspace(request))

    @app.get("/api/v2/receipts/{receipt_id}")
    def v2_receipt_detail(receipt_id: str, request: Request) -> Dict[str, Any]:
        """Return the raw signed receipt material for UI inspection."""
        _require_console_bearer_for_sensitive_read(request)
        receipts = _state_receipts_store(request)
        if receipts is None:
            raise HTTPException(status_code=503, detail="receipt store unavailable")
        receipt = receipts.load(receipt_id)
        if receipt is None:
            raise HTTPException(status_code=404, detail="receipt not found")
        if not isinstance(receipt, dict):
            raise HTTPException(status_code=500, detail="receipt store returned invalid data")
        return _receipt_detail_to_wire(receipt)

    @app.get("/api/v2/rules")
    def v2_rules(request: Request) -> List[Dict[str, Any]]:
        """Return local automation Rules, never Trade Rule Packages.

        The automation-rule persistence API is not implemented yet.  Returning
        Trade Package digests here violated the frontend ``Rule`` contract and
        made installed Skills appear as malformed automation policies.
        """

        return []

    @app.get("/api/v2/trade/rule-packages")
    async def v2_trade_rule_package_catalog(
        request: Request,
        response: Response,
        cursor: str = "",
        limit: int = 100,
    ) -> Dict[str, Any]:
        """List locally cached, fully reverified Trade Rule Packages."""

        from nth_dao.trade_rules import RulePackageError

        _require_console_bearer_for_sensitive_read(request)
        if isinstance(limit, bool) or not 1 <= limit <= 200:
            raise HTTPException(status_code=400, detail="limit must be in 1..200")
        if cursor and re.fullmatch(r"sha256:[0-9a-f]{64}", cursor) is None:
            raise HTTPException(
                status_code=400,
                detail="cursor must be a lowercase sha256 digest",
            )
        store = _state_trade_rule_package_store(request)
        spine = _state_spine(request)
        if store is None or spine is None:
            raise HTTPException(
                status_code=503,
                detail="trade rule package store or signed Spine unavailable",
            )

        def _catalog() -> tuple[list[Dict[str, Any]], str]:
            import_audits = _trade_rule_package_import_audit_index(spine)
            packages, next_cursor = store.list_page(
                after=cursor or None,
                limit=limit,
            )
            provenance = store.provenance_sources_many(
                tuple(package.digest for package in packages)
            )
            return [
                _trade_rule_package_catalog_item(
                    package,
                    include_manifest=False,
                    import_audit=import_audits.get(
                        package.digest,
                        _no_trade_rule_package_import_audit(),
                    ),
                    provenance_sources=provenance[package.digest],
                )
                for package in packages
            ], next_cursor or ""

        try:
            items, next_cursor = await run_in_threadpool(_catalog)
        except (RulePackageError, OSError, RuntimeError) as exc:
            logger.warning("Trade Rule Package catalog failed closed: %s", exc)
            raise HTTPException(
                status_code=503,
                detail="trade rule package catalog integrity failure",
            ) from exc
        response.headers["Cache-Control"] = "no-store"
        return {
            "items": items,
            "next_cursor": next_cursor,
            "cache_only": True,
            "execution_authorized": False,
        }

    @app.get("/api/v2/trade/rule-packages/{package_digest}")
    async def v2_trade_rule_package_detail(
        package_digest: str,
        request: Request,
        response: Response,
    ) -> Dict[str, Any]:
        """Inspect one exact Package manifest without returning resource bytes."""

        _require_console_bearer_for_sensitive_read(request)
        if re.fullmatch(r"sha256:[0-9a-f]{64}", package_digest) is None:
            raise HTTPException(
                status_code=400,
                detail="package_digest must be a lowercase sha256 digest",
            )
        package = await run_in_threadpool(
            _load_trade_rule_package,
            request,
            package_digest,
        )
        response.headers["Cache-Control"] = "no-store"
        spine = _state_spine(request)
        store = _state_trade_rule_package_store(request)
        if spine is None or store is None:
            raise HTTPException(
                status_code=503,
                detail="trade rule package store or signed Spine unavailable",
            )
        import_audits = await run_in_threadpool(
            _trade_rule_package_import_audit_index,
            spine,
        )
        provenance_sources = await run_in_threadpool(
            store.provenance_sources,
            package.digest,
        )
        return _trade_rule_package_catalog_item(
            package,
            include_manifest=True,
            import_audit=import_audits.get(
                package.digest,
                _no_trade_rule_package_import_audit(),
            ),
            provenance_sources=provenance_sources,
        )

    @app.post(
        "/api/v2/trade/rule-packages/{package_digest}/recognitions"
    )
    async def v2_trade_rule_recognition_record(
        package_digest: str,
        request: Request,
    ) -> Dict[str, Any]:
        """Persist and audit one already-signed Recognition statement."""

        from nth_dao.trade_rules import (
            RuleRecognitionAuditError,
            RuleRecognitionAuditIntegrityError,
            RuleRecognitionStoreBusy,
            RuleRecognitionStoreCapacity,
            RuleRecognitionStoreError,
            TradeRuleRecognition,
            TradeRuleRecognitionRejected,
        )

        content_type = request.headers.get("content-type", "").split(";", 1)[0]
        if content_type.strip().lower() != "application/json":
            raise HTTPException(
                status_code=415,
                detail=(
                    "trade rule recognition requires Content-Type application/json"
                ),
            )
        coordinator = _state_trade_rule_recognition_audit(request)
        if coordinator is None:
            raise HTTPException(
                status_code=503,
                detail=(
                    "signed Spine unavailable; unaudited Recognition "
                    "persistence is disabled"
                ),
            )
        package = _load_trade_rule_package(request, package_digest)
        raw_body = await request.body()

        def _record() -> Any:
            return coordinator.record(
                TradeRuleRecognition.from_json(raw_body),
                package=package,
            )

        try:
            result = await run_in_threadpool(_record)
        except TradeRuleRecognitionRejected as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except RuleRecognitionAuditIntegrityError as exc:
            raise HTTPException(
                status_code=503,
                detail=f"Recognition cross-log integrity failure: {exc}",
            ) from exc
        except RuleRecognitionStoreCapacity as exc:
            raise HTTPException(status_code=507, detail=str(exc)) from exc
        except RuleRecognitionStoreBusy as exc:
            raise HTTPException(
                status_code=503,
                detail=str(exc),
                headers={"Retry-After": "1"},
            ) from exc
        except (RuleRecognitionStoreError, RuleRecognitionAuditError) as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        return {
            "recognition_digest": result.statement.digest,
            "recognition": result.statement.to_dict(),
            "store_created": result.store_created,
            "anchor_created": result.anchor_created,
            "audit_event_id": result.event.event_id,
        }

    @app.get(
        "/api/v2/trade/rule-packages/{package_digest}/recognitions"
    )
    def v2_trade_rule_recognition_list(
        package_digest: str,
        request: Request,
    ) -> Dict[str, Any]:
        from nth_dao.trade_rules import (
            RuleRecognitionStoreBusy,
            RuleRecognitionStoreError,
        )

        coordinator = _state_trade_rule_recognition_audit(request)
        if coordinator is None:
            raise HTTPException(
                status_code=503,
                detail="signed Recognition audit unavailable",
            )
        package = _load_trade_rule_package(request, package_digest)
        try:
            statements = coordinator.store.list_for_package(package)
            ok, reason = coordinator.verify_anchors(package=package)
        except RuleRecognitionStoreBusy as exc:
            raise HTTPException(
                status_code=503,
                detail=str(exc),
                headers={"Retry-After": "1"},
            ) from exc
        except RuleRecognitionStoreError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        if not ok:
            raise HTTPException(
                status_code=503,
                detail=f"Recognition cross-log integrity failure: {reason}",
            )
        return {
            "package_digest": package.digest,
            "items": [statement.to_dict() for statement in statements],
        }

    @app.post("/api/v2/trade/rule-packages/{package_digest}/recognitions/reconcile")
    def v2_trade_rule_recognition_reconcile(
        package_digest: str,
        request: Request,
        limit: int = 100,
    ) -> Dict[str, Any]:
        from nth_dao.trade_rules import (
            RuleRecognitionAuditError,
            RuleRecognitionAuditIntegrityError,
            RuleRecognitionStoreError,
        )

        coordinator = _state_trade_rule_recognition_audit(request)
        if coordinator is None:
            raise HTTPException(
                status_code=503,
                detail="signed Recognition audit unavailable",
            )
        package = _load_trade_rule_package(request, package_digest)
        try:
            result = coordinator.reconcile(
                package=package,
                limit=limit,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except RuleRecognitionAuditIntegrityError as exc:
            raise HTTPException(
                status_code=503,
                detail=f"Recognition cross-log integrity failure: {exc}",
            ) from exc
        except (RuleRecognitionStoreError, RuleRecognitionAuditError) as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        return {
            "scanned": result.scanned,
            "anchored": result.anchored,
            "verified_anchored": result.verified_anchored,
            "failed": result.failed,
            "remaining": result.remaining,
            "has_more": result.has_more,
            "blocked_digest": result.blocked_digest,
            "error_code": result.error_code,
            "error_message": result.error_message,
        }

    @app.post("/api/v2/trade/recognition-policy")
    async def v2_trade_rule_recognition_policy_record(
        request: Request,
    ) -> Dict[str, Any]:
        """Persist and Spine-anchor one already-signed local trust policy."""

        from nth_dao.trade_rules import (
            RuleRecognitionPolicyAuditError,
            RuleRecognitionPolicyAuditIntegrityError,
            RuleRecognitionPolicyStoreBusy,
            RuleRecognitionPolicyStoreCapacity,
            RuleRecognitionPolicyStoreError,
            TradeRuleRecognitionPolicy,
            TradeRuleRecognitionPolicyRejected,
        )

        _require_console_bearer_for_governance_mutation(request)
        _enforce_recognition_policy_mutation_limit(
            request,
            operation="record",
        )
        content_type = request.headers.get("content-type", "").split(";", 1)[0]
        if content_type.strip().lower() != "application/json":
            raise HTTPException(
                status_code=415,
                detail=(
                    "trade rule recognition policy requires "
                    "Content-Type application/json"
                ),
            )
        coordinator = _state_trade_rule_recognition_policy_audit(request)
        if coordinator is None:
            raise HTTPException(
                status_code=503,
                detail=(
                    "signed Spine unavailable; unaudited Recognition "
                    "policy persistence is disabled"
                ),
            )
        raw_body = await request.body()
        try:
            policy = await run_in_threadpool(
                TradeRuleRecognitionPolicy.from_json,
                raw_body,
            )
        except TradeRuleRecognitionPolicyRejected as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        try:
            result = await run_in_threadpool(coordinator.record, policy)
        except TradeRuleRecognitionPolicyRejected as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except RuleRecognitionPolicyAuditIntegrityError as exc:
            raise _recognition_policy_service_error(
                operation="record",
                code="recognition-policy-integrity-failed",
                message="Recognition policy integrity check failed",
                exc=exc,
            ) from exc
        except RuleRecognitionPolicyStoreCapacity as exc:
            raise _recognition_policy_service_error(
                operation="record",
                code="recognition-policy-capacity-exceeded",
                message="Recognition policy storage capacity exceeded",
                exc=exc,
                status_code=507,
            ) from exc
        except RuleRecognitionPolicyStoreBusy as exc:
            raise _recognition_policy_service_error(
                operation="record",
                code="recognition-policy-store-busy",
                message="Recognition policy store is busy",
                exc=exc,
                retry_after="1",
            ) from exc
        except (
            RuleRecognitionPolicyStoreError,
            RuleRecognitionPolicyAuditError,
        ) as exc:
            raise _recognition_policy_service_error(
                operation="record",
                code="recognition-policy-unavailable",
                message="Recognition policy service is unavailable",
                exc=exc,
            ) from exc
        return {
            "policy_digest": result.policy.digest,
            "policy": result.policy.to_dict(),
            "store_created": result.store_created,
            "anchor_created": result.anchor_created,
            "audit_event_id": result.event.event_id,
        }

    @app.get("/api/v2/trade/recognition-policy")
    def v2_trade_rule_recognition_policy_list(
        request: Request,
        limit: int = 100,
        before_sequence: int | None = None,
    ) -> Dict[str, Any]:
        """Read a bounded, Spine-verified local policy history."""

        from nth_dao.trade_rules import (
            RuleRecognitionPolicyAuditError,
            RuleRecognitionPolicyAuditIntegrityError,
            RuleRecognitionPolicyStoreBusy,
            RuleRecognitionPolicyStoreError,
        )

        _require_console_bearer_for_sensitive_read(request)
        if isinstance(limit, bool) or not 1 <= limit <= 500:
            raise HTTPException(status_code=400, detail="limit must be in 1..500")
        if (
            before_sequence is not None
            and (
                isinstance(before_sequence, bool)
                or before_sequence < 1
            )
        ):
            raise HTTPException(
                status_code=400,
                detail="before_sequence must be a positive integer",
            )
        coordinator = _state_trade_rule_recognition_policy_audit(request)
        if coordinator is None:
            raise HTTPException(
                status_code=503,
                detail="signed Recognition policy audit unavailable",
            )
        try:
            policies = coordinator.verified_policies()
        except RuleRecognitionPolicyAuditIntegrityError as exc:
            raise _recognition_policy_service_error(
                operation="list",
                code="recognition-policy-integrity-failed",
                message="Recognition policy integrity check failed",
                exc=exc,
            ) from exc
        except RuleRecognitionPolicyStoreBusy as exc:
            raise _recognition_policy_service_error(
                operation="list",
                code="recognition-policy-store-busy",
                message="Recognition policy store is busy",
                exc=exc,
                retry_after="1",
            ) from exc
        except (
            RuleRecognitionPolicyStoreError,
            RuleRecognitionPolicyAuditError,
        ) as exc:
            raise _recognition_policy_service_error(
                operation="list",
                code="recognition-policy-unavailable",
                message="Recognition policy service is unavailable",
                exc=exc,
            ) from exc
        head = policies[-1] if policies else None
        eligible = [
            policy
            for policy in policies
            if (
                before_sequence is None
                or policy.to_dict()["sequence"] < before_sequence
            )
        ]
        page = list(reversed(eligible[-limit:]))
        has_more = len(eligible) > len(page)
        next_before_sequence = (
            page[-1].to_dict()["sequence"] if has_more and page else None
        )
        return {
            "node_did": coordinator.policy_store.node_did,
            "head_digest": head.digest if head is not None else None,
            "head": head.to_dict() if head is not None else None,
            "items": [policy.to_dict() for policy in page],
            "has_more": has_more,
            "next_before_sequence": next_before_sequence,
        }

    @app.post("/api/v2/trade/recognition-policy/reconcile")
    def v2_trade_rule_recognition_policy_reconcile(
        request: Request,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """Recover exact store-first policy revisions into the Spine."""

        from nth_dao.trade_rules import (
            RuleRecognitionPolicyAuditError,
            RuleRecognitionPolicyAuditIntegrityError,
            RuleRecognitionPolicyStoreBusy,
            RuleRecognitionPolicyStoreError,
        )

        _require_console_bearer_for_governance_mutation(request)
        _enforce_recognition_policy_mutation_limit(
            request,
            operation="reconcile",
        )
        coordinator = _state_trade_rule_recognition_policy_audit(request)
        if coordinator is None:
            raise HTTPException(
                status_code=503,
                detail="signed Recognition policy audit unavailable",
            )
        try:
            result = coordinator.reconcile(limit=limit)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except RuleRecognitionPolicyAuditIntegrityError as exc:
            raise _recognition_policy_service_error(
                operation="reconcile",
                code="recognition-policy-integrity-failed",
                message="Recognition policy integrity check failed",
                exc=exc,
            ) from exc
        except RuleRecognitionPolicyStoreBusy as exc:
            raise _recognition_policy_service_error(
                operation="reconcile",
                code="recognition-policy-store-busy",
                message="Recognition policy store is busy",
                exc=exc,
                retry_after="1",
            ) from exc
        except (
            RuleRecognitionPolicyStoreError,
            RuleRecognitionPolicyAuditError,
        ) as exc:
            raise _recognition_policy_service_error(
                operation="reconcile",
                code="recognition-policy-unavailable",
                message="Recognition policy service is unavailable",
                exc=exc,
            ) from exc
        return {
            "scanned": result.scanned,
            "anchored": result.anchored,
            "failed": result.failed,
            "remaining": result.remaining,
            "has_more": result.remaining > 0,
            "blocked_digest": result.blocked_digest,
            "error_message": result.error_message,
        }

    @app.get("/api/v2/trade/rule-packages/{package_digest}/recognition-evaluation")
    def v2_trade_rule_recognition_policy_evaluate(
        package_digest: str,
        request: Request,
        at: str | None = None,
    ) -> Dict[str, Any]:
        """Project local trust without granting package execution authority."""

        from nth_dao.trade_rules import (
            RuleRecognitionPolicyAuditError,
            RuleRecognitionPolicyAuditIntegrityError,
            RuleRecognitionPolicyStoreBusy,
            RuleRecognitionPolicyStoreError,
        )

        _require_console_bearer_for_sensitive_read(request)
        _load_trade_rule_package(request, package_digest)
        try:
            moment = _parse_canonical_utc_query(at)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        coordinator = _state_trade_rule_recognition_policy_audit(request)
        if coordinator is None:
            raise HTTPException(
                status_code=503,
                detail="signed Recognition policy audit unavailable",
            )
        try:
            result = coordinator.evaluate(package_digest, at=moment)
        except RuleRecognitionPolicyAuditIntegrityError as exc:
            raise _recognition_policy_service_error(
                operation="evaluate",
                code="recognition-policy-integrity-failed",
                message="Recognition policy integrity check failed",
                exc=exc,
            ) from exc
        except RuleRecognitionPolicyStoreBusy as exc:
            raise _recognition_policy_service_error(
                operation="evaluate",
                code="recognition-policy-store-busy",
                message="Recognition policy store is busy",
                exc=exc,
                retry_after="1",
            ) from exc
        except (
            RuleRecognitionPolicyStoreError,
            RuleRecognitionPolicyAuditError,
        ) as exc:
            raise _recognition_policy_service_error(
                operation="evaluate",
                code="recognition-policy-unavailable",
                message="Recognition policy service is unavailable",
                exc=exc,
            ) from exc
        policy_document = result.policy.to_dict()
        return {
            "package_digest": package_digest,
            "policy_digest": result.policy.digest,
            "policy_sequence": policy_document["sequence"],
            "advisory": True,
            "execution_authorized": False,
            "snapshot": asdict(result.snapshot),
        }

    @app.post("/api/v2/trade/offers")
    async def v2_trade_offer_publish(request: Request) -> Dict[str, Any]:
        """Persist one already-signed Offer published by this node."""
        _require_console_bearer_for_sensitive_read(request)
        from nth_dao.trade_rules import (
            InspectedTradeOffer,
            OfferStoreBusyError,
            OfferStoreCapacityError,
            OfferStoreCorruptionError,
            OfferStoreCryptoUnavailableError,
            OfferStoreError,
            OfferStoreValidationError,
        )
        from nth_dao.util.io import InterProcessLock

        store = _state_trade_offer_store(request)
        workspace = _state_workspace(request)
        if store is None or workspace is None:
            raise HTTPException(status_code=503, detail="trade offer store unavailable")
        content_type = request.headers.get("content-type", "").split(";", 1)[0]
        if content_type.strip().lower() != "application/json":
            raise HTTPException(
                status_code=415,
                detail="trade offer requires Content-Type application/json",
            )
        identity = _state_node_identity(request)
        if identity is None or not getattr(identity, "can_sign", False):
            raise HTTPException(status_code=503, detail="signing identity unavailable")
        source_id = identity.as_did()
        if _state_spine(request) is None:
            raise HTTPException(status_code=503, detail="signed Spine unavailable")
        transaction_lock_path = _trade_offer_store_spine_transaction_lock_path(
            workspace
        )
        try:
            raw_body = await request.body()

            def _verify_and_publish() -> Any:
                # Parse exact transport bytes in the worker. Letting
                # FastAPI/json.loads build a dict first would collapse
                # duplicate keys before the signed-document validator sees
                # them. Signature verification, lock waits, and fsync are all
                # blocking work and must not run on the ASGI event loop.
                inspected = InspectedTradeOffer.from_json(raw_body)
                if inspected.publisher_did != source_id:
                    raise PermissionError(
                        "publisher_did must match this node; use the verified "
                        "federation import endpoint for remote Offers"
                    )
                with InterProcessLock(transaction_lock_path):
                    return _persist_local_trade_offer_locked(
                        request,
                        store,
                        inspected,
                        source_id=source_id,
                    )

            result, audit_event_id, audit_warning = await run_in_threadpool(
                _verify_and_publish
            )
        except (ValueError, TypeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except TimeoutError as exc:
            raise HTTPException(
                status_code=503,
                detail="Trade Offer Store/Spine transaction is busy",
                headers={"Retry-After": "1"},
            ) from exc
        except OfferStoreCryptoUnavailableError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except OfferStoreBusyError as exc:
            raise HTTPException(
                status_code=503,
                detail=str(exc),
                headers={"Retry-After": "1"},
            ) from exc
        except OfferStoreValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except OfferStoreCapacityError as exc:
            raise HTTPException(status_code=507, detail=str(exc)) from exc
        except OfferStoreCorruptionError as exc:
            raise HTTPException(
                status_code=503,
                detail=f"trade offer store integrity failure: {exc}",
            ) from exc
        except OfferStoreError as exc:
            raise HTTPException(
                status_code=503, detail=f"trade offer persistence failed: {exc}"
            ) from exc
        if audit_warning:
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "trade-offer-audit-incomplete",
                    "message": audit_warning,
                    "offer_digest": result.digest,
                    "retryable": True,
                },
                headers={"Retry-After": "1"},
            )
        return {
            "digest": result.digest,
            "appended": result.appended,
            "classification": result.classification,
            "entry_hash": result.entry_hash,
            "chain": _trade_offer_chain_to_wire(result.chain),
            "audit_event_id": audit_event_id,
            "audit_warning": audit_warning,
        }

    @app.post("/api/v2/market/offers")
    async def v2_market_offer_publish(
        body: PublishMarketOfferBody,
        request: Request,
    ) -> Dict[str, Any]:
        """Build, sign, persist, and announce one local TradeOffer.

        This is the human-console convenience boundary. The strict
        ``/trade/offers`` endpoint remains the route for already-signed Agent
        documents. No private key or caller-supplied proof crosses this API.
        """
        _require_console_bearer_for_sensitive_read(request)
        from nth_dao.trade_rules import (
            OfferStoreBusyError,
            OfferStoreCapacityError,
            OfferStoreCorruptionError,
            OfferStoreCryptoUnavailableError,
            OfferStoreError,
            OfferStoreValidationError,
            offer_body,
            sign_offer,
        )

        store = _state_trade_offer_store(request)
        workspace = _state_workspace(request)
        identity = _state_node_identity(request)
        if store is None or workspace is None:
            raise HTTPException(status_code=503, detail="trade offer store unavailable")
        if identity is None or not getattr(identity, "can_sign", False):
            raise HTTPException(status_code=503, detail="signing identity unavailable")
        if _state_spine(request) is None:
            raise HTTPException(status_code=503, detail="signed Spine unavailable")
        source_id = identity.as_did()
        transaction_lock_path = _trade_offer_store_spine_transaction_lock_path(
            workspace
        )

        def _build_publish_and_announce() -> tuple[Any, Any, str, str, Any, bool]:
            (
                offer_id,
                provides,
                requests,
                rule_refs,
                extensions,
                capabilities,
            ) = (
                _market_offer_material(body, publisher_did=source_id)
            )
            _validate_local_market_profile_references(
                extensions,
                workspace=workspace,
            )
            title = body.title.strip()
            summary = body.summary.strip()

            with InterProcessLock(transaction_lock_path):
                chain = store.chain(source_id, offer_id)
                head_digest = chain.canonical_head_digest
                if head_digest:
                    offer = store.get(head_digest)
                    if offer is None:
                        raise RuntimeError("canonical Trade Offer head disappeared")
                    document = offer.to_dict()
                    if not _same_market_offer_material(
                        document,
                        title=title,
                        summary=summary,
                        provides=provides,
                        requests=requests,
                        rule_refs=rule_refs,
                        extensions=extensions,
                    ):
                        raise MarketPublishConflict(
                            "idempotency_key is already bound to different Offer content"
                        )
                elif chain.all_digests:
                    raise MarketPublishConflict(
                        "idempotency_key is bound to a non-canonical Offer chain"
                    )
                else:
                    published = datetime.now(timezone.utc).replace(microsecond=0)
                    expires = published + timedelta(
                        seconds=body.offer_validity_seconds
                    )
                    published_at = published.isoformat().replace("+00:00", "Z")
                    offer = sign_offer(
                        identity,
                        offer_body(
                            offer_id=offer_id,
                            publisher_did=source_id,
                            title=title,
                            summary=summary,
                            provides=provides,
                            requests=requests,
                            rule_refs=rule_refs,
                            published_at=published_at,
                            not_after=expires.isoformat().replace("+00:00", "Z"),
                            extensions=extensions,
                        ),
                        created=published_at,
                    )
                result, audit_event_id, audit_warning = (
                    _persist_local_trade_offer_locked(
                        request,
                        store,
                        offer,
                        source_id=source_id,
                    )
                )
            if audit_warning:
                if audit_warning == "existing offer provenance is not local-operator":
                    raise MarketPublishConflict(audit_warning)
                raise MarketPublishAuditError(result.digest, audit_warning)

            availability = {
                "market_category": body.category.strip().lower(),
                "market_intent": body.intent.strip().lower(),
                "provides_count": len(provides),
                "requests_count": len(requests),
            }
            try:
                announcement, announcement_published = (
                    _ensure_local_trade_offer_announcement(
                        request,
                        store,
                        offer,
                        result.digest,
                        capability_set=capabilities,
                        availability_summary=availability,
                        discovery_ttl_seconds=body.discovery_ttl_seconds,
                        match_capability_set=True,
                        match_availability_summary=True,
                    )
                )
            except MarketPublishConflict:
                raise
            except MarketPublishExpired:
                raise
            except (
                OfferStoreError,
                OSError,
                PermissionError,
                RuntimeError,
                TimeoutError,
                TypeError,
                ValueError,
            ) as exc:
                raise MarketPublishDiscoveryError(result.digest, str(exc)) from exc
            return (
                result,
                offer,
                audit_event_id,
                audit_warning,
                announcement,
                announcement_published,
            )

        try:
            (
                result,
                offer,
                audit_event_id,
                audit_warning,
                announcement,
                announcement_published,
            ) = await run_in_threadpool(_build_publish_and_announce)
        except MarketPublishConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except MarketPublishAuditError as exc:
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "trade-offer-audit-incomplete",
                    "message": str(exc),
                    "offer_digest": exc.digest,
                    "offer_persisted": True,
                    "announcement_published": False,
                    "retryable": True,
                },
                headers={"Retry-After": "1"},
            ) from exc
        except MarketPublishExpired as exc:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "trade-offer-expired",
                    "message": str(exc),
                    "offer_digest": exc.digest,
                    "offer_id": exc.offer_id,
                    "offer_persisted": True,
                    "retryable": False,
                    "new_idempotency_key_required": True,
                },
            ) from exc
        except MarketPublishDiscoveryError as exc:
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "trade-offer-discovery-incomplete",
                    "message": str(exc),
                    "offer_digest": exc.digest,
                    "offer_persisted": True,
                    "retryable": True,
                },
                headers={"Retry-After": "1"},
            ) from exc
        except (ValueError, TypeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except TimeoutError as exc:
            raise HTTPException(
                status_code=503,
                detail="Trade Offer Store/Spine transaction is busy",
                headers={"Retry-After": "1"},
            ) from exc
        except OfferStoreCryptoUnavailableError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except OfferStoreBusyError as exc:
            raise HTTPException(
                status_code=503,
                detail=str(exc),
                headers={"Retry-After": "1"},
            ) from exc
        except OfferStoreValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except OfferStoreCapacityError as exc:
            raise HTTPException(status_code=507, detail=str(exc)) from exc
        except OfferStoreCorruptionError as exc:
            raise HTTPException(
                status_code=503,
                detail=f"trade offer store integrity failure: {exc}",
            ) from exc
        except OfferStoreError as exc:
            raise HTTPException(
                status_code=503,
                detail=f"trade offer persistence failed: {exc}",
            ) from exc
        return {
            "digest": result.digest,
            "offer": offer.to_dict(),
            "appended": result.appended,
            "classification": result.classification,
            "audit_event_id": audit_event_id,
            "announcement": _market_announcement_to_wire(announcement),
            "announcement_published": announcement_published,
            "warning": (
                "Published as a signed discovery claim. This does not prove "
                "availability, ownership, fairness, or execution authority."
            ),
        }

    @app.post(
        "/api/v2/trade/federation/proposals",
        status_code=202,
    )
    async def v2_trade_proposal_receive(request: Request) -> Dict[str, Any]:
        """Retain one signed Proposal delivery; this is not acceptance."""

        from nth_dao.trade_rules import (
            TradeProposalAuditError,
            TradeProposalDelivery,
            TradeProposalDeliveryRejected,
            TradeProposalInboxBusy,
            TradeProposalInboxCapacity,
            TradeProposalInboxCorruption,
            TradeProposalInboxError,
            TradeProposalInboxRejected,
        )

        content_type = request.headers.get("content-type", "").split(";", 1)[0]
        if content_type.strip().lower() != "application/json":
            raise HTTPException(
                status_code=415,
                detail="trade Proposal delivery requires Content-Type application/json",
            )
        limiter = _state_trade_proposal_delivery_limiter(request)
        global_limiter = _state_trade_proposal_delivery_global_limiter(request)
        coordinator = _state_trade_proposal_audit(request)
        identity = _state_node_identity(request)
        offer_store = _state_trade_offer_store(request)
        package_store = _state_trade_rule_package_store(request)
        if limiter is None or global_limiter is None:
            raise HTTPException(
                status_code=503,
                detail="trade Proposal delivery rate limiter unavailable",
            )
        if (
            coordinator is None
            or identity is None
            or not getattr(identity, "can_sign", False)
            or offer_store is None
            or package_store is None
        ):
            raise HTTPException(
                status_code=503,
                detail="signed trade Proposal receiver unavailable",
            )
        client_key = (
            str(request.client.host).strip()
            if request.client is not None and request.client.host
            else "anonymous"
        )
        try:
            decision = await run_in_threadpool(limiter.check, client_key)
        except (OSError, TimeoutError, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Proposal delivery budget is unavailable",
            ) from exc
        if not decision.allowed:
            retry_after = max(1, int(decision.retry_after_seconds) + 1)
            raise HTTPException(
                status_code=429,
                detail="trade Proposal delivery rate exceeded",
                headers={"Retry-After": str(retry_after)},
            )
        try:
            global_decision = await run_in_threadpool(
                global_limiter.check,
                "global",
            )
        except (OSError, TimeoutError, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail="global trade Proposal delivery budget is unavailable",
            ) from exc
        if not global_decision.allowed:
            retry_after = max(
                1,
                int(global_decision.retry_after_seconds) + 1,
            )
            raise HTTPException(
                status_code=429,
                detail="global trade Proposal delivery rate exceeded",
                headers={"Retry-After": str(retry_after)},
            )
        raw_body = await request.body()
        recipient_did = identity.as_did()
        received_at = datetime.now(timezone.utc)

        def _receive() -> Any:
            # Parsing exact bytes preserves duplicate-key rejection before
            # signature verification. All crypto, locks, fsync, and Spine
            # scans stay off the ASGI event loop.
            delivery = TradeProposalDelivery.from_json(raw_body)
            return coordinator.receive(
                delivery,
                recipient_did=recipient_did,
                offer_resolver=offer_store,
                rule_resolver=package_store,
                at=received_at,
            )

        try:
            result = await run_in_threadpool(_receive)
        except TradeProposalDeliveryRejected as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except TradeProposalInboxRejected as exc:
            raise HTTPException(
                status_code=409,
                detail=f"Proposal does not match receiver state: {exc}",
            ) from exc
        except TradeProposalInboxBusy as exc:
            raise HTTPException(
                status_code=503,
                detail=str(exc),
                headers={"Retry-After": "1"},
            ) from exc
        except TradeProposalInboxCapacity as exc:
            raise HTTPException(status_code=507, detail=str(exc)) from exc
        except (TradeProposalInboxCorruption, TradeProposalInboxError) as exc:
            logger.warning("trade Proposal inbox persistence failed: %s", exc)
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "trade-proposal-inbox-unavailable",
                    "message": "Proposal receiver persistence is unavailable",
                },
            ) from exc
        except TradeProposalAuditError as exc:
            logger.warning("trade Proposal Spine projection failed: %s", exc)
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "trade-proposal-audit-incomplete",
                    "message": "Proposal was retained but its audit projection is incomplete",
                    "retryable_without_resubmission": True,
                },
                headers={"Retry-After": "1"},
            ) from exc
        return {
            "status": "retained-unaccepted",
            "proposal_digest": result.inbox.digest,
            "inbox_appended": result.inbox.appended,
            "audit_event_id": result.event.event_id,
            "audit_anchor_created": result.anchor_created,
        }

    def _trade_proposal_view(view: Any, *, include_document: bool) -> Dict[str, Any]:
        from nth_dao.trade_rules import proposal_digest

        proposal = view.proposal
        document = proposal.to_dict()
        result = {
            "proposal_digest": proposal_digest(proposal),
            "offer_digest": document["offer_digest"],
            "offer_id": document["offer_id"],
            "offer_revision": document["offer_revision"],
            "maker_did": document["maker_did"],
            "taker_did": document["taker_did"],
            "created_at": document["created_at"],
            "not_after": document["not_after"],
            "rule_bindings_count": len(document["rule_bindings"]),
            "status": "retained-unaccepted",
            "audit_verified": view.audit_verified,
            "audit_event_id": view.event.event_id if view.event else "",
        }
        if include_document:
            result["proposal"] = document
        return result

    @app.get("/api/v2/trade/proposals")
    def v2_trade_proposal_list(
        request: Request,
        cursor: str = "",
        limit: int = 100,
    ) -> Dict[str, Any]:
        """List retained inbound negotiation claims with audit status."""

        from nth_dao.trade_rules import (
            TradeProposalAuditError,
            TradeProposalInboxError,
        )

        _require_console_bearer_for_sensitive_read(request)
        coordinator = _state_trade_proposal_audit(request)
        if coordinator is None:
            raise HTTPException(
                status_code=503,
                detail="signed trade Proposal receiver unavailable",
            )
        try:
            views, next_cursor = coordinator.list_received(
                limit=limit,
                after=cursor or None,
            )
        except (TradeProposalAuditError, TradeProposalInboxError) as exc:
            raise HTTPException(
                status_code=503,
                detail=f"Proposal audit integrity failure: {exc}",
            ) from exc
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {
            "items": [
                _trade_proposal_view(view, include_document=False)
                for view in views
            ],
            "next_cursor": next_cursor or "",
        }

    @app.get("/api/v2/trade/proposals/{digest}")
    def v2_trade_proposal_get(
        digest: str,
        request: Request,
    ) -> Dict[str, Any]:
        """Return one exact signed Proposal and its local audit status."""

        from nth_dao.trade_rules import (
            TradeProposalAuditError,
            TradeProposalInboxError,
        )

        _require_console_bearer_for_sensitive_read(request)
        coordinator = _state_trade_proposal_audit(request)
        if coordinator is None:
            raise HTTPException(
                status_code=503,
                detail="signed trade Proposal receiver unavailable",
            )
        try:
            view = coordinator.get_received(digest)
        except (TradeProposalAuditError, TradeProposalInboxError) as exc:
            raise HTTPException(
                status_code=503,
                detail=f"Proposal audit integrity failure: {exc}",
            ) from exc
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if view is None:
            raise HTTPException(status_code=404, detail="Proposal not found")
        return _trade_proposal_view(view, include_document=True)

    @app.post("/api/v2/trade/proposals/{digest}/accept")
    async def v2_trade_proposal_accept(
        digest: str,
        request: Request,
    ) -> Dict[str, Any]:
        """Sign, retain, and deliver an accepted Order to its taker."""

        from nth_dao.trade_rules import (
            ORDER_ID_PREFIX,
            RuleResolutionPolicy,
            TradeAgreementRejected,
            TradeOrderAuditBusy,
            TradeOrderAuditCapacity,
            TradeOrderAuditError,
            TradeOrderDispatchBusy,
            TradeOrderDispatchCapacity,
            TradeOrderDispatchError,
            TradeOrderIntakeReceipt,
            TradeOrderRejected,
            create_trade_acceptance,
            create_trade_order,
            create_trade_order_delivery,
            proposal_digest,
            resolve_canonical_offer_rules,
            verify_trade_order_intake_receipt,
            verify_trade_proposal_under_local_state,
        )

        _require_console_bearer_for_sensitive_read(request)
        if re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
            raise HTTPException(
                status_code=400,
                detail="digest must be a lowercase sha256 digest",
            )
        try:
            body = await request.json()
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=400, detail="invalid JSON body") from exc
        if not isinstance(body, dict) or not set(body).issubset(
            {"target_url", "maker_policy"}
        ):
            raise HTTPException(
                status_code=400,
                detail="body accepts only target_url and maker_policy",
            )
        target_url = body.get("target_url")
        if (
            not isinstance(target_url, str)
            or not target_url.strip()
            or len(target_url) > 2_048
        ):
            raise HTTPException(status_code=400, detail="target_url is required")
        try:
            target_url = _normalize_configured_fed_peer(target_url)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        coordinator = _state_trade_proposal_audit(request)
        identity = _state_node_identity(request)
        offer_store = _state_trade_offer_store(request)
        package_store = _state_trade_rule_package_store(request)
        order_audit = _state_trade_order_audit(request)
        order_dispatch = _state_trade_order_dispatch(request)
        order_store = getattr(request.app.state.nth, "trade_order_store", None)
        if (
            coordinator is None
            or identity is None
            or not getattr(identity, "can_sign", False)
            or offer_store is None
            or package_store is None
            or order_audit is None
            or order_dispatch is None
            or order_store is None
        ):
            raise HTTPException(
                status_code=503,
                detail="signed trade acceptance runtime unavailable",
            )
        try:
            view = await run_in_threadpool(coordinator.get_received, digest)
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail="Proposal audit integrity failure",
            ) from exc
        if view is None:
            raise HTTPException(status_code=404, detail="Proposal not found")
        if not view.audit_verified:
            raise HTTPException(
                status_code=409,
                detail="Proposal audit anchor is not verified",
            )

        proposal = view.proposal
        proposal_document = proposal.to_dict()
        if proposal_document["maker_did"] != identity.as_did():
            raise HTTPException(
                status_code=403,
                detail="local identity is not the Proposal maker",
            )
        expected_order_id = (
            ORDER_ID_PREFIX
            + proposal_digest(proposal).removeprefix("sha256:")
        )
        moment = datetime.now(timezone.utc).replace(microsecond=0)
        created_at = moment.isoformat().replace("+00:00", "Z")
        now_ms = int(moment.timestamp() * 1_000)

        def _accept_locally() -> tuple[Any, Any]:
            order = order_store.get(expected_order_id)
            if order is None:
                ok, reason = verify_trade_proposal_under_local_state(
                    proposal,
                    offer_store,
                    package_store,
                    at=moment,
                )
                if not ok:
                    raise TradeAgreementRejected(reason)
                offer = offer_store.get(proposal_document["offer_digest"])
                if offer is None:
                    raise TradeAgreementRejected(
                        "Proposal Offer bytes are unavailable"
                    )
                raw_policy = body.get("maker_policy")
                if raw_policy is None:
                    policy = RuleResolutionPolicy(
                        accepted_package_digests=frozenset(
                            binding["digest"]
                            for binding in proposal_document["rule_bindings"]
                        )
                    )
                else:
                    policy = RuleResolutionPolicy.from_dict(raw_policy)
                resolution = resolve_canonical_offer_rules(
                    proposal_document["maker_did"],
                    proposal_document["offer_id"],
                    offer_store,
                    package_store,
                    policy,
                    at=moment,
                )
                acceptance = create_trade_acceptance(
                    identity,
                    proposal=proposal,
                    resolution=resolution,
                    offer=offer,
                    offer_resolver=offer_store,
                    created_at=created_at,
                    now=moment,
                )
                order = create_trade_order(
                    offer=offer,
                    proposal=proposal,
                    acceptance=acceptance,
                )
            if order.order_id != expected_order_id:
                raise TradeOrderRejected(
                    "retained Order does not match Proposal identity"
                )
            audit = order_audit.accept(order, now_ms=now_ms)
            return order, audit

        try:
            order, local_audit = await run_in_threadpool(_accept_locally)
            delivery = create_trade_order_delivery(
                identity,
                order=order,
                created_at=created_at,
                not_after=(moment + timedelta(minutes=5)).isoformat().replace(
                    "+00:00", "Z"
                ),
                now=moment,
            )
        except (TradeOrderAuditBusy,) as exc:
            raise HTTPException(
                status_code=503,
                detail="trade acceptance runtime is busy",
                headers={"Retry-After": "1"},
            ) from exc
        except TradeOrderAuditCapacity as exc:
            raise HTTPException(
                status_code=507,
                detail="trade acceptance storage capacity exceeded",
            ) from exc
        except (
            TradeAgreementRejected,
            TradeOrderRejected,
            TradeOrderAuditError,
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
        ) as exc:
            raise HTTPException(
                status_code=409,
                detail=f"Proposal cannot be accepted: {exc}",
            ) from exc

        def _acknowledged_response(acknowledgement: Any) -> Dict[str, Any]:
            return {
                "status": "accepted-and-delivered",
                "order": order.to_dict(),
                "order_digest": local_audit.record.order_digest,
                "local_audit_event_id": local_audit.record.event_id,
                "delivery_digest": acknowledgement.delivery_digest,
                "remote_intake_receipt": acknowledgement.receipt.to_dict(),
                "remote_intake_receipt_digest": (
                    acknowledgement.receipt_digest
                ),
                "remote_audit_event_id": acknowledgement.remote_event_id,
                "acknowledgement_persisted": True,
            }

        try:
            existing_acknowledgement = await run_in_threadpool(
                order_dispatch.recover_acknowledgement,
                local_audit.record.order_digest,
            )
            if existing_acknowledgement is not None:
                await run_in_threadpool(order_audit.finalize, local_audit)
                return _acknowledged_response(existing_acknowledgement)
            pending_dispatch = await run_in_threadpool(
                order_dispatch.prepare,
                delivery,
                target_url=target_url,
                now_ms=now_ms,
            )
            delivery = pending_dispatch.delivery
        except TradeOrderDispatchCapacity as exc:
            raise HTTPException(
                status_code=507,
                detail="trade Order dispatch storage capacity exceeded",
            ) from exc
        except (TradeOrderDispatchBusy, TradeOrderDispatchError) as exc:
            raise HTTPException(
                status_code=503,
                detail=f"trade Order dispatch persistence failed: {exc}",
                headers={"Retry-After": "1"},
            ) from exc

        async def _note_dispatch_failure(message: str) -> None:
            try:
                await run_in_threadpool(
                    order_dispatch.failed,
                    local_audit.record.order_digest,
                    error=message,
                )
            except (OSError, RuntimeError, TypeError, ValueError) as exc:
                logger.warning(
                    "unable to record failed trade Order dispatch: %s", exc
                )

        try:
            peer_status, peer_body = await run_in_threadpool(
                _post_trade_order_delivery_to_peer,
                target_url,
                delivery.to_dict(),
            )
        except (OSError, TimeoutError, ValueError, urllib.error.URLError) as exc:
            await _note_dispatch_failure(str(exc))
            raise HTTPException(
                status_code=502,
                detail=(
                    "signed Order is retained locally but delivery to the "
                    f"taker failed: {exc}"
                ),
            ) from exc
        if not 200 <= peer_status < 300:
            await _note_dispatch_failure(f"peer returned HTTP {peer_status}")
            raise HTTPException(
                status_code=502,
                detail=(
                    "signed Order is retained locally but the taker rejected "
                    f"delivery with HTTP {peer_status}"
                ),
            )
        try:
            receipt = TradeOrderIntakeReceipt.from_dict(
                peer_body["intake_receipt"]
            )
            peer_event_id = peer_body["audit_event_id"]
            ok, reason = verify_trade_order_intake_receipt(
                receipt,
                delivery=delivery,
                receiver_did=proposal_document["taker_did"],
                audit_event_id=peer_event_id,
                at=datetime.now(timezone.utc),
            )
            if not ok:
                raise ValueError(reason)
        except (KeyError, TypeError, ValueError) as exc:
            await _note_dispatch_failure(f"invalid receipt: {exc}")
            raise HTTPException(
                status_code=502,
                detail=f"taker returned an invalid signed intake receipt: {exc}",
            ) from exc
        try:
            acknowledgement = await run_in_threadpool(
                order_dispatch.acknowledge,
                delivery,
                receipt,
                target_url=target_url,
                remote_event_id=peer_event_id,
            )
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail=(
                    "remote receipt verified but local acknowledgement "
                    "persistence is incomplete"
                ),
                headers={"Retry-After": "1"},
            ) from exc
        try:
            finalized = await run_in_threadpool(
                order_audit.finalize,
                local_audit,
            )
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail=(
                    "remote receipt is durable but local audit cleanup failed"
                ),
                headers={"Retry-After": "1"},
            ) from exc
        if not finalized:
            raise HTTPException(
                status_code=503,
                detail="remote receipt verified but local audit work disappeared",
                headers={"Retry-After": "1"},
            )
        return _acknowledged_response(acknowledgement)

    @app.post("/api/v2/trade/proposals/reconcile")
    async def v2_trade_proposal_reconcile(
        request: Request,
        cursor: str = "",
        limit: int = 500,
    ) -> Dict[str, Any]:
        """Retry signed inbox-to-Spine projection without peer resubmission."""

        from nth_dao.trade_rules import (
            TradeProposalAuditError,
            TradeProposalInboxError,
        )

        _require_console_bearer_for_sensitive_read(request)
        coordinator = _state_trade_proposal_audit(request)
        if coordinator is None:
            raise HTTPException(
                status_code=503,
                detail="signed trade Proposal receiver unavailable",
            )
        try:
            result = await run_in_threadpool(
                coordinator.reconcile,
                limit=limit,
                after=cursor or None,
            )
        except (TradeProposalAuditError, TradeProposalInboxError) as exc:
            raise HTTPException(
                status_code=503,
                detail=f"Proposal audit reconciliation failed: {exc}",
                headers={"Retry-After": "1"},
            ) from exc
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {
            "scanned": result.scanned,
            "anchored": result.anchored,
            "verified_anchored": result.verified_anchored,
            "failed": result.failed,
            "failure_digests": list(result.failure_digests),
            "failures": [
                {
                    "digest": failure.digest,
                    "error_code": failure.error_code,
                    "message": failure.message,
                }
                for failure in result.failures
            ],
            "next_cursor": result.next_cursor or "",
            "has_more": result.has_more,
        }

    @app.get("/api/v2/trade/proposal-reconciliation/status")
    def v2_trade_proposal_reconciliation_status(
        request: Request,
    ) -> Dict[str, Any]:
        """Return authenticated operator metrics for inbox-to-Spine lag."""

        from nth_dao.trade_rules import (
            TradeProposalAuditError,
            TradeProposalInboxError,
        )

        _require_console_bearer_for_sensitive_read(request)
        coordinator = _state_trade_proposal_audit(request)
        if coordinator is None:
            raise HTTPException(
                status_code=503,
                detail="signed trade Proposal receiver unavailable",
            )
        try:
            metrics = coordinator.pending_metrics()
        except (TradeProposalAuditError, TradeProposalInboxError) as exc:
            raise HTTPException(
                status_code=503,
                detail=f"Proposal audit metrics failed: {exc}",
                headers={"Retry-After": "1"},
            ) from exc
        return {
            "active_records": metrics.active_records,
            "pending_anchors": metrics.pending_anchors,
            "oldest_pending_age_seconds": metrics.oldest_pending_age_seconds,
            "measured_at": metrics.measured_at,
        }

    @app.post(
        "/api/v2/trade/federation/orders",
        status_code=202,
    )
    async def v2_trade_order_receive(request: Request) -> Dict[str, Any]:
        """Retain one accepted agreement; this is not delivery or payment."""

        from nth_dao.trade_rules import (
            TradeOrderAuditBusy,
            TradeOrderAuditCapacity,
            TradeOrderAuditError,
            TradeOrderConflict,
            TradeOrderDelivery,
            TradeOrderDeliveryRejected,
            TradeOrderStoreBusy,
            TradeOrderStoreCapacity,
        )

        content_type = request.headers.get("content-type", "").split(";", 1)[0]
        if content_type.strip().lower() != "application/json":
            raise HTTPException(
                status_code=415,
                detail="trade Order delivery requires Content-Type application/json",
            )
        limiter = _state_trade_order_delivery_limiter(request)
        global_limiter = _state_trade_order_delivery_global_limiter(request)
        intake = _state_trade_order_intake(request)
        if limiter is None or global_limiter is None:
            raise HTTPException(
                status_code=503,
                detail="trade Order delivery rate limiter unavailable",
            )
        if intake is None:
            raise HTTPException(
                status_code=503,
                detail="signed trade Order receiver unavailable",
            )
        client_key = (
            str(request.client.host).strip()
            if request.client is not None and request.client.host
            else "anonymous"
        )
        try:
            decision = await run_in_threadpool(limiter.check, client_key)
        except (OSError, TimeoutError, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Order delivery budget is unavailable",
            ) from exc
        if not decision.allowed:
            retry_after = max(1, int(decision.retry_after_seconds) + 1)
            raise HTTPException(
                status_code=429,
                detail="trade Order delivery rate exceeded",
                headers={"Retry-After": str(retry_after)},
            )
        try:
            global_decision = await run_in_threadpool(
                global_limiter.check,
                "global",
            )
        except (OSError, TimeoutError, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail="global trade Order delivery budget is unavailable",
            ) from exc
        if not global_decision.allowed:
            retry_after = max(
                1,
                int(global_decision.retry_after_seconds) + 1,
            )
            raise HTTPException(
                status_code=429,
                detail="global trade Order delivery rate exceeded",
                headers={"Retry-After": str(retry_after)},
            )
        raw_body = await request.body()
        received_at = datetime.now(timezone.utc)

        def _receive() -> Any:
            delivery = TradeOrderDelivery.from_json(raw_body)
            return intake.receive(delivery, at=received_at)

        try:
            result = await run_in_threadpool(_receive)
        except TradeOrderDeliveryRejected as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except TradeOrderConflict as exc:
            raise HTTPException(
                status_code=409,
                detail="Order conflicts with a retained accepted agreement",
            ) from exc
        except (TradeOrderAuditBusy, TradeOrderStoreBusy) as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Order receiver is busy",
                headers={"Retry-After": "1"},
            ) from exc
        except (TradeOrderAuditCapacity, TradeOrderStoreCapacity) as exc:
            raise HTTPException(
                status_code=507,
                detail="trade Order receiver capacity exceeded",
            ) from exc
        except (
            TradeOrderAuditError,
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
        ) as exc:
            logger.warning("trade Order durable acceptance failed: %s", exc)
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "trade-order-acceptance-incomplete",
                    "message": "Order acknowledgement is incomplete",
                    "safe_to_redeliver": True,
                },
                headers={"Retry-After": "1"},
            ) from exc
        order_document = result.delivery.order.to_dict()
        return {
            "status": "accepted-agreement-retained",
            "order_id": order_document["order_id"],
            "order_digest": result.audit.record.order_digest,
            "delivery_digest": result.delivery_digest,
            "order_store_created": result.audit.cache_created,
            "audit_anchor_created": result.audit.anchor_created,
            "audit_event_id": result.audit.record.event_id,
            "intake_receipt": result.receipt.to_dict(),
            "intake_receipt_digest": result.receipt_digest,
            "delivery_or_payment_proven": False,
        }

    @app.post(
        "/api/v2/trade/federation/orders/{order_digest}/execution-receipts",
        status_code=202,
    )
    async def v2_trade_execution_receipt_receive(
        order_digest: str,
        request: Request,
    ) -> Dict[str, Any]:
        """Re-verify and retain one remote execution claim for a local Order."""

        from nth_dao.trade_rules import (
            JsonSchema202012Validator,
            TradeExecutionAuditBusy,
            TradeExecutionAuditCapacity,
            TradeExecutionAuditError,
            TradeExecutionReceiptConflict,
            TradeExecutionReceiptDelivery,
            TradeExecutionReceiptDeliveryRejected,
            TradeExecutionReceiptIntakeCoordinator,
            TradeExecutionReceiptRejected,
            TradeExecutionReceiptStoreBusy,
            TradeExecutionReceiptStoreCapacity,
            TradeOrderAuditError,
        )

        if re.fullmatch(r"sha256:[0-9a-f]{64}", order_digest) is None:
            raise HTTPException(
                status_code=400,
                detail="order_digest must be a lowercase sha256 digest",
            )
        content_type = request.headers.get("content-type", "").split(";", 1)[0]
        if content_type.strip().lower() != "application/json":
            raise HTTPException(
                status_code=415,
                detail=(
                    "trade Execution Receipt delivery requires "
                    "Content-Type application/json"
                ),
            )
        limiter = _state_trade_execution_receipt_delivery_limiter(request)
        global_limiter = (
            _state_trade_execution_receipt_delivery_global_limiter(request)
        )
        order_audit = _state_trade_order_audit(request)
        execution_coordinator = _state_trade_execution_coordinator(request)
        identity = _state_node_identity(request)
        package_store = _state_trade_rule_package_store(request)
        state = request.app.state.nth
        runtime = (
            getattr(state, "trade_executor_policy", None),
            getattr(state, "trade_execution_adapter_resolver", None),
            getattr(state, "trade_execution_adapter_policy", None),
            getattr(state, "trade_execution_content_resolver", None),
        )
        if limiter is None or global_limiter is None:
            raise HTTPException(
                status_code=503,
                detail="trade Execution Receipt rate limiter unavailable",
            )
        client_key = (
            str(request.client.host).strip()
            if request.client is not None and request.client.host
            else "anonymous"
        )
        try:
            decision = await run_in_threadpool(limiter.check, client_key)
            global_decision = await run_in_threadpool(
                global_limiter.check,
                "global",
            )
        except (OSError, TimeoutError, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Execution Receipt budget is unavailable",
            ) from exc
        if not decision.allowed or not global_decision.allowed:
            retry_after = max(
                1,
                int(
                    max(
                        decision.retry_after_seconds,
                        global_decision.retry_after_seconds,
                    )
                )
                + 1,
            )
            raise HTTPException(
                status_code=429,
                detail="trade Execution Receipt delivery rate exceeded",
                headers={"Retry-After": str(retry_after)},
            )
        if (
            order_audit is None
            or execution_coordinator is None
            or identity is None
            or not getattr(identity, "can_sign", False)
            or package_store is None
            or any(item is None for item in runtime)
        ):
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "execution-receipt-intake-not-configured",
                    "message": (
                        "local execution policy, Adapter, and content "
                        "verification must be configured before intake"
                    ),
                },
            )
        try:
            order_view = await run_in_threadpool(
                order_audit.get_accepted,
                order_digest,
            )
        except (TradeOrderAuditError, OSError, RuntimeError, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Order audit integrity failure",
            ) from exc
        if order_view is None:
            raise HTTPException(status_code=404, detail="Trade Order not found")
        order = order_view.order
        try:
            package_resolver = _trade_order_rule_package_resolver(
                request,
                order_digest,
            )
        except RuntimeError as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Rule Package audit resolver unavailable",
            ) from exc
        raw_body = await request.body()
        received_at = datetime.now(timezone.utc)
        schema_validator = getattr(
            state,
            "trade_execution_schema_validator",
            None,
        ) or JsonSchema202012Validator()

        def _receive_execution_receipt() -> Any:
            intake = TradeExecutionReceiptIntakeCoordinator(
                execution_coordinator,
                receiver_identity=identity,
                package_resolver=package_resolver,
                verifier_policy=runtime[0],
                adapter_resolver=runtime[1],
                adapter_policy=runtime[2],
                content_resolver=runtime[3],
                schema_validator=schema_validator,
            )
            delivery = TradeExecutionReceiptDelivery.from_json(
                raw_body,
                order=order,
            )
            return intake.receive(
                delivery,
                order=order,
                at=received_at,
            )

        try:
            result = await run_in_threadpool(_receive_execution_receipt)
        except TradeExecutionReceiptDeliveryRejected as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except TradeExecutionReceiptRejected as exc:
            logger.info(
                "remote execution Receipt rejected by local policy: %s",
                type(exc).__name__,
            )
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "execution-receipt-policy-rejected",
                    "message": (
                        "Receipt could not be verified under local execution policy"
                    ),
                },
            ) from exc
        except TradeExecutionReceiptConflict as exc:
            raise HTTPException(
                status_code=409,
                detail="Receipt conflicts with retained signed bytes",
            ) from exc
        except (TradeExecutionAuditBusy, TradeExecutionReceiptStoreBusy) as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Execution Receipt receiver is busy",
                headers={"Retry-After": "1"},
            ) from exc
        except (
            TradeExecutionAuditCapacity,
            TradeExecutionReceiptStoreCapacity,
        ) as exc:
            raise HTTPException(
                status_code=507,
                detail="trade Execution Receipt receiver capacity exceeded",
            ) from exc
        except (
            TradeExecutionAuditError,
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
        ) as exc:
            logger.warning(
                "trade Execution Receipt durable intake failed: %s",
                type(exc).__name__,
            )
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "execution-receipt-intake-incomplete",
                    "message": "Receipt acknowledgement is incomplete",
                    "safe_to_redeliver": True,
                },
                headers={"Retry-After": "1"},
            ) from exc
        receipt_document = result.audit.receipt.to_dict()
        return {
            "status": "execution-receipt-retained-verified",
            "order_digest": order_digest,
            "execution_id": receipt_document["execution_id"],
            "receipt_digest": result.audit.record.receipt_digest,
            "delivery_digest": result.delivery_digest,
            "receipt_store_created": result.audit.store_created,
            "audit_anchor_created": result.audit.anchor_created,
            "audit_event_id": result.audit.record.event_id,
            "acknowledgement": result.acknowledgement.to_dict(),
            "acknowledgement_digest": result.acknowledgement_digest,
            "claim_verified_under_local_policy": True,
            "delivery_or_payment_proven": False,
        }

    @app.post(
        "/api/v2/trade/federation/orders/{order_digest}/"
        "execution-receipts/{execution_id}/reviews",
        status_code=202,
    )
    async def v2_trade_receipt_review_receive(
        order_digest: str,
        execution_id: str,
        request: Request,
    ) -> Dict[str, Any]:
        """Re-verify and retain one counterparty-signed Receipt Review."""

        from nth_dao.trade_rules import (
            JsonSchema202012Validator,
            TradeExecutionReceiptStoreBusy,
            TradeExecutionReceiptStoreError,
            TradeOrderAuditError,
            TradeReceiptReviewAuditError,
            TradeReceiptReviewConflict,
            TradeReceiptReviewDelivery,
            TradeReceiptReviewDeliveryRejected,
            TradeReceiptReviewIntakeCoordinator,
            TradeReceiptReviewOutboxBusy,
            TradeReceiptReviewOutboxCapacity,
            TradeReceiptReviewRejected,
            TradeReceiptReviewStoreBusy,
            TradeReceiptReviewStoreCapacity,
        )

        if re.fullmatch(r"sha256:[0-9a-f]{64}", order_digest) is None:
            raise HTTPException(
                status_code=400,
                detail="order_digest must be a lowercase sha256 digest",
            )
        if re.fullmatch(
            r"nth-trade-execution-sha256:[0-9a-f]{64}",
            execution_id,
        ) is None:
            raise HTTPException(status_code=400, detail="execution_id is invalid")
        content_type = request.headers.get("content-type", "").split(";", 1)[0]
        if content_type.strip().lower() != "application/json":
            raise HTTPException(
                status_code=415,
                detail=(
                    "trade Receipt Review delivery requires "
                    "Content-Type application/json"
                ),
            )
        limiter = _state_trade_receipt_review_delivery_limiter(request)
        global_limiter = (
            _state_trade_receipt_review_delivery_global_limiter(request)
        )
        order_audit = _state_trade_order_audit(request)
        review_coordinator = _state_trade_receipt_review_coordinator(request)
        receipt_store = getattr(
            request.app.state.nth,
            "trade_execution_receipts",
            None,
        )
        identity = _state_node_identity(request)
        package_store = _state_trade_rule_package_store(request)
        state = request.app.state.nth
        adapter_resolver = getattr(
            state,
            "trade_execution_adapter_resolver",
            None,
        )
        content_resolver = getattr(
            state,
            "trade_execution_content_resolver",
            None,
        )
        if limiter is None or global_limiter is None:
            raise HTTPException(
                status_code=503,
                detail="trade Receipt Review rate limiter unavailable",
            )
        client_key = (
            str(request.client.host).strip()
            if request.client is not None and request.client.host
            else "anonymous"
        )
        try:
            decision = await run_in_threadpool(limiter.check, client_key)
            global_decision = await run_in_threadpool(
                global_limiter.check,
                "global",
            )
        except (OSError, TimeoutError, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Receipt Review budget is unavailable",
            ) from exc
        if not decision.allowed or not global_decision.allowed:
            retry_after = max(
                1,
                int(
                    max(
                        decision.retry_after_seconds,
                        global_decision.retry_after_seconds,
                    )
                )
                + 1,
            )
            raise HTTPException(
                status_code=429,
                detail="trade Receipt Review delivery rate exceeded",
                headers={"Retry-After": str(retry_after)},
            )
        if (
            order_audit is None
            or review_coordinator is None
            or receipt_store is None
            or identity is None
            or not getattr(identity, "can_sign", False)
            or package_store is None
            or adapter_resolver is None
            or content_resolver is None
        ):
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "receipt-review-intake-not-configured",
                    "message": (
                        "local Rule Package, Adapter, and content resolvers "
                        "must be configured before Review intake"
                    ),
                },
            )
        try:
            order_view = await run_in_threadpool(
                order_audit.get_accepted,
                order_digest,
            )
        except (TradeOrderAuditError, OSError, RuntimeError, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Order audit integrity failure",
            ) from exc
        if order_view is None:
            raise HTTPException(status_code=404, detail="Trade Order not found")
        order = order_view.order
        try:
            receipt = await run_in_threadpool(
                receipt_store.get,
                execution_id,
                order=order,
            )
        except TradeExecutionReceiptStoreBusy as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Execution Receipt store is busy",
                headers={"Retry-After": "1"},
            ) from exc
        except TradeExecutionReceiptStoreError as exc:
            raise HTTPException(
                status_code=409,
                detail="trade Execution Receipt integrity conflict",
            ) from exc
        if receipt is None:
            raise HTTPException(
                status_code=404,
                detail="Trade Execution Receipt not found",
            )
        try:
            package_resolver = _trade_order_rule_package_resolver(
                request,
                order_digest,
            )
        except RuntimeError as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Rule Package audit resolver unavailable",
            ) from exc
        raw_body = await request.body()
        received_at = datetime.now(timezone.utc)
        schema_validator = getattr(
            state,
            "trade_execution_schema_validator",
            None,
        ) or JsonSchema202012Validator()

        def _receive_review() -> Any:
            delivery = TradeReceiptReviewDelivery.from_json(
                raw_body,
                receipt=receipt,
                order=order,
            )
            if delivery.review.to_dict()["execution_id"] != execution_id:
                raise TradeReceiptReviewDeliveryRejected(
                    "Review execution_id does not match request path"
                )
            intake = TradeReceiptReviewIntakeCoordinator(
                review_coordinator,
                receiver_identity=identity,
                package_resolver=package_resolver,
                adapter_resolver=adapter_resolver,
                content_resolver=content_resolver,
                schema_validator=schema_validator,
            )
            return intake.receive(
                delivery,
                receipt=receipt,
                order=order,
                at=received_at,
            )

        try:
            result = await run_in_threadpool(_receive_review)
        except TradeReceiptReviewDeliveryRejected as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except TradeReceiptReviewRejected as exc:
            logger.info(
                "remote Receipt Review rejected during replay: %s",
                type(exc).__name__,
            )
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "receipt-review-policy-rejected",
                    "message": (
                        "Review claim could not be replayed from its "
                        "signed policy snapshots"
                    ),
                },
            ) from exc
        except TradeReceiptReviewConflict as exc:
            raise HTTPException(
                status_code=409,
                detail="Review conflicts with retained signed bytes",
            ) from exc
        except (TradeReceiptReviewStoreBusy, TradeReceiptReviewOutboxBusy) as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Receipt Review receiver is busy",
                headers={"Retry-After": "1"},
            ) from exc
        except (
            TradeReceiptReviewStoreCapacity,
            TradeReceiptReviewOutboxCapacity,
        ) as exc:
            raise HTTPException(
                status_code=507,
                detail="trade Receipt Review receiver capacity exceeded",
            ) from exc
        except (
            TradeReceiptReviewAuditError,
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
        ) as exc:
            logger.warning(
                "trade Receipt Review durable intake failed: %s",
                type(exc).__name__,
            )
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "receipt-review-intake-incomplete",
                    "message": "Review acknowledgement is incomplete",
                    "safe_to_redeliver": True,
                },
                headers={"Retry-After": "1"},
            ) from exc
        review_document = result.audit.review.to_dict()
        return {
            "status": "receipt-review-retained-verified",
            "order_digest": order_digest,
            "execution_id": execution_id,
            "review_id": review_document["review_id"],
            "review_digest": result.delivery.to_dict()["review_digest"],
            "delivery_digest": result.delivery_digest,
            "review_store_created": result.audit.store_created,
            "audit_anchor_created": result.audit.anchor_created,
            "audit_event_id": result.audit.event.event_id,
            "acknowledgement": result.acknowledgement.to_dict(),
            "acknowledgement_digest": result.acknowledgement_digest,
            "claim_replayed_from_signed_policy_snapshots": True,
            "delivery_quality_or_payment_proven": False,
        }

    @app.post(
        "/api/v2/trade/federation/orders/{order_digest}/"
        "execution-receipts/{execution_id}/reviews/{review_id}/"
        "dispute-statements",
        status_code=202,
    )
    async def v2_trade_dispute_statement_receive(
        order_digest: str,
        execution_id: str,
        review_id: str,
        request: Request,
    ) -> Dict[str, Any]:
        """Re-verify and retain one destination-bound signed dispute claim."""

        from nth_dao.trade_rules import (
            TradeDisputeStatementAuditError,
            TradeDisputeStatementDelivery,
            TradeDisputeStatementDeliveryRejected,
            TradeDisputeStatementIntakeCoordinator,
            TradeDisputeStatementIntakeJournalCapacity,
            TradeDisputeStatementIntakeJournalError,
            TradeDisputeStatementDependencyError,
            TradeDisputeStatementRejected,
            TradeDisputeStatementResolutionError,
            TradeDisputeStatementStoreBusy,
            TradeDisputeStatementStoreCapacity,
            TradeDisputeStatementStoreError,
            TradeExecutionReceiptStoreBusy,
            TradeExecutionReceiptStoreError,
            TradeOrderAuditError,
            TradeReceiptReviewConflict,
            TradeReceiptReviewStoreBusy,
            TradeReceiptReviewStoreError,
        )

        if re.fullmatch(r"sha256:[0-9a-f]{64}", order_digest) is None:
            raise HTTPException(
                status_code=400,
                detail="order_digest must be a lowercase sha256 digest",
            )
        if re.fullmatch(
            r"nth-trade-execution-sha256:[0-9a-f]{64}",
            execution_id,
        ) is None:
            raise HTTPException(status_code=400, detail="execution_id is invalid")
        if re.fullmatch(
            r"nth-trade-review-sha256:[0-9a-f]{64}",
            review_id,
        ) is None:
            raise HTTPException(status_code=400, detail="review_id is invalid")
        content_type = request.headers.get("content-type", "").split(";", 1)[0]
        if content_type.strip().lower() != "application/json":
            raise HTTPException(
                status_code=415,
                detail=(
                    "trade Dispute Statement delivery requires "
                    "Content-Type application/json"
                ),
            )

        limiter = _state_trade_dispute_statement_delivery_limiter(request)
        global_limiter = (
            _state_trade_dispute_statement_delivery_global_limiter(request)
        )
        if limiter is None or global_limiter is None:
            raise HTTPException(
                status_code=503,
                detail="trade Dispute Statement rate limiter unavailable",
            )
        client_key = (
            str(request.client.host).strip()
            if request.client is not None and request.client.host
            else "anonymous"
        )
        try:
            decision = await run_in_threadpool(limiter.check, client_key)
            global_decision = await run_in_threadpool(
                global_limiter.check,
                "global",
            )
        except (OSError, TimeoutError, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Dispute Statement budget is unavailable",
            ) from exc
        if not decision.allowed or not global_decision.allowed:
            retry_after = max(
                1,
                int(
                    max(
                        decision.retry_after_seconds,
                        global_decision.retry_after_seconds,
                    )
                )
                + 1,
            )
            raise HTTPException(
                status_code=429,
                detail="trade Dispute Statement delivery rate exceeded",
                headers={"Retry-After": str(retry_after)},
            )

        state = request.app.state.nth
        order_audit = _state_trade_order_audit(request)
        receipt_store = getattr(state, "trade_execution_receipts", None)
        review_store = _state_trade_receipt_review_store(request)
        statement_audit = _state_trade_dispute_statement_audit(request)
        intake_journal = _state_trade_dispute_statement_intake_journal(request)
        identity = _state_node_identity(request)
        package_store = _state_trade_rule_package_store(request)
        if (
            order_audit is None
            or receipt_store is None
            or review_store is None
            or statement_audit is None
            or intake_journal is None
            or identity is None
            or not getattr(identity, "can_sign", False)
            or package_store is None
        ):
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "dispute-statement-intake-not-configured",
                    "message": (
                        "local signed Order, Receipt, Review, Rule Package, "
                        "Spine, and identity state are required before "
                        "Dispute Statement intake"
                    ),
                },
            )

        try:
            order_view = await run_in_threadpool(
                order_audit.get_accepted,
                order_digest,
            )
        except (TradeOrderAuditError, OSError, RuntimeError, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Order audit integrity failure",
            ) from exc
        if order_view is None:
            raise HTTPException(status_code=404, detail="Trade Order not found")
        order = order_view.order
        try:
            receipt = await run_in_threadpool(
                receipt_store.get,
                execution_id,
                order=order,
            )
        except TradeExecutionReceiptStoreBusy as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Execution Receipt store is busy",
                headers={"Retry-After": "1"},
            ) from exc
        except TradeExecutionReceiptStoreError as exc:
            raise HTTPException(
                status_code=409,
                detail="trade Execution Receipt integrity conflict",
            ) from exc
        if receipt is None:
            raise HTTPException(
                status_code=404,
                detail="Trade Execution Receipt not found",
            )
        try:
            review = await run_in_threadpool(
                review_store.get,
                review_id,
                receipt=receipt,
                order=order,
            )
        except TradeReceiptReviewStoreBusy as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Receipt Review store is busy",
                headers={"Retry-After": "1"},
            ) from exc
        except TradeReceiptReviewConflict as exc:
            raise HTTPException(
                status_code=409,
                detail="Receipt Review has contradictory signed candidates",
            ) from exc
        except TradeReceiptReviewStoreError as exc:
            raise HTTPException(
                status_code=409,
                detail="trade Receipt Review integrity conflict",
            ) from exc
        if review is None:
            raise HTTPException(status_code=404, detail="Trade Receipt Review not found")
        try:
            package_resolver = _trade_order_rule_package_resolver(
                request,
                order_digest,
            )
        except RuntimeError as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Rule Package audit resolver unavailable",
            ) from exc

        raw_body = await request.body()
        received_at = datetime.now(timezone.utc)

        def _receive_statement() -> Any:
            delivery = TradeDisputeStatementDelivery.from_json(
                raw_body,
                review=review,
                receipt=receipt,
                order=order,
            )
            statement_document = delivery.statement.to_dict()
            if statement_document["review_id"] != review_id:
                raise TradeDisputeStatementDeliveryRejected(
                    "Dispute Statement review_id does not match request path"
                )
            intake = TradeDisputeStatementIntakeCoordinator(
                statement_audit,
                receiver_identity=identity,
                package_resolver=package_resolver,
                journal=intake_journal,
            )
            return intake.receive(
                delivery,
                review=review,
                receipt=receipt,
                order=order,
                at=received_at,
            )

        try:
            result = await run_in_threadpool(_receive_statement)
        except TradeDisputeStatementDeliveryRejected as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except (
            TradeDisputeStatementDependencyError,
            TradeDisputeStatementResolutionError,
        ) as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Dispute Statement dependency is unavailable",
                headers={"Retry-After": "1"},
            ) from exc
        except TradeDisputeStatementRejected as exc:
            logger.info(
                "remote Dispute Statement rejected during signed replay: %s",
                type(exc).__name__,
            )
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "dispute-statement-policy-rejected",
                    "message": (
                        "Dispute Statement claim could not be replayed from "
                        "its signed Order, Receipt, Review, and Rule Package"
                    ),
                },
            ) from exc
        except TradeDisputeStatementStoreBusy as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Dispute Statement receiver is busy",
                headers={"Retry-After": "1"},
            ) from exc
        except (
            TradeDisputeStatementStoreCapacity,
            TradeDisputeStatementIntakeJournalCapacity,
        ) as exc:
            raise HTTPException(
                status_code=507,
                detail="trade Dispute Statement receiver capacity exceeded",
            ) from exc
        except TradeDisputeStatementStoreError as exc:
            raise HTTPException(
                status_code=409,
                detail="trade Dispute Statement integrity conflict",
            ) from exc
        except (
            TradeDisputeStatementAuditError,
            TradeDisputeStatementIntakeJournalError,
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
        ) as exc:
            logger.warning(
                "trade Dispute Statement durable intake failed: %s",
                type(exc).__name__,
            )
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "dispute-statement-intake-incomplete",
                    "message": "Dispute Statement acknowledgement is incomplete",
                    "safe_to_redeliver": True,
                },
                headers={"Retry-After": "1"},
            ) from exc

        statement_document = result.audit.statement.to_dict()
        return {
            "status": "dispute-statement-retained-verified",
            "order_digest": order_digest,
            "execution_id": execution_id,
            "review_id": review_id,
            "dispute_id": statement_document["dispute_id"],
            "statement_id": statement_document["statement_id"],
            "statement_digest": result.delivery.to_dict()["statement_digest"],
            "delivery_digest": result.delivery_digest,
            "statement_store_created": result.audit.store_created,
            "audit_anchor_created": result.audit.anchor_created,
            "audit_event_id": result.audit.event.event_id,
            "acknowledgement": result.acknowledgement.to_dict(),
            "acknowledgement_digest": result.acknowledgement_digest,
            "claim_replayed_from_signed_context": True,
            "claim_adjudicated_or_proven_true": False,
        }

    @app.post(
        "/api/v2/trade/federation/orders/{order_digest}/"
        "execution-receipts/{execution_id}/reviews/{review_id}/"
        "dispute-statements/fetch"
    )
    async def v2_trade_dispute_statement_fetch_respond(
        order_digest: str,
        execution_id: str,
        review_id: str,
        request: Request,
    ) -> Dict[str, Any]:
        """Serve one exact retained Statement to an authorized counterparty."""

        from nth_dao.trade_rules import (
            TradeDisputeStatementDependencyError,
            TradeDisputeStatementFetchAuditError,
            TradeDisputeStatementFetchInProgress,
            TradeDisputeStatementFetchJournalBusy,
            TradeDisputeStatementFetchJournalCapacity,
            TradeDisputeStatementFetchJournalError,
            TradeDisputeStatementFetchNotFound,
            TradeDisputeStatementFetchRequest,
            TradeDisputeStatementFetchRequestRejected,
            TradeDisputeStatementFetchResponseRejected,
            TradeDisputeStatementFetchRetryLater,
            TradeDisputeStatementFetchServiceError,
            TradeDisputeStatementFetchReplayConflict,
            TradeDisputeStatementStoreBusy,
            TradeDisputeStatementStoreCapacity,
            TradeDisputeStatementStoreError,
            preflight_trade_dispute_statement_fetch_request,
            verify_trade_dispute_statement_fetch_audit_event,
        )

        content_type = request.headers.get("content-type", "").split(";", 1)[0]
        if content_type.strip().lower() != "application/json":
            raise HTTPException(
                status_code=415,
                detail=(
                    "trade Dispute Statement fetch requires "
                    "Content-Type application/json"
                ),
            )

        limiter = _state_trade_dispute_statement_fetch_limiter(request)
        global_limiter = _state_trade_dispute_statement_fetch_global_limiter(request)
        if limiter is None or global_limiter is None:
            raise HTTPException(
                status_code=503,
                detail="trade Dispute Statement fetch budget unavailable",
            )
        client_key = (
            str(request.client.host).strip()
            if request.client is not None and request.client.host
            else "anonymous"
        )
        try:
            decision = await run_in_threadpool(limiter.check, client_key)
            global_decision = await run_in_threadpool(
                global_limiter.check,
                "global",
            )
        except (OSError, TimeoutError, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Dispute Statement fetch budget unavailable",
            ) from exc
        if not decision.allowed or not global_decision.allowed:
            retry_after = max(
                1,
                int(
                    max(
                        decision.retry_after_seconds,
                        global_decision.retry_after_seconds,
                    )
                )
                + 1,
            )
            raise HTTPException(
                status_code=429,
                detail="trade Dispute Statement fetch rate exceeded",
                headers={"Retry-After": str(retry_after)},
            )

        statement_store = _state_trade_dispute_statement_store(request)
        journal = _state_trade_dispute_statement_fetch_journal(request)
        identity = _state_node_identity(request)
        spine = _state_spine(request)
        if (
            statement_store is None
            or journal is None
            or identity is None
            or not getattr(identity, "can_sign", False)
            or spine is None
        ):
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "dispute-statement-fetch-not-configured",
                    "message": (
                        "local signed Order, Receipt, Review, Statement, "
                        "journal, Spine, and identity state are required"
                    ),
                },
            )
        raw_body = await request.body()
        received_at = datetime.now(timezone.utc)
        try:
            preflight_document = await run_in_threadpool(
                preflight_trade_dispute_statement_fetch_request,
                raw_body,
                order_digest=order_digest,
                execution_id=execution_id,
                review_id=review_id,
                responder_did=identity.as_did(),
                at=received_at,
            )
        except TradeDisputeStatementFetchRequestRejected as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        try:
            order, receipt, review = await _load_trade_dispute_review(
                request,
                order_digest=order_digest,
                execution_id=execution_id,
                review_id=review_id,
            )
        except HTTPException as exc:
            if exc.status_code != 404:
                raise
            raise HTTPException(
                status_code=404,
                detail="requested Trade Dispute Statement context is unavailable",
            ) from exc
        try:
            package_resolver = _trade_order_rule_package_resolver(
                request,
                order_digest,
            )
        except RuntimeError as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Rule Package audit resolver unavailable",
            ) from exc

        def _serve_statement() -> Any:
            fetch_request = TradeDisputeStatementFetchRequest.from_dict(
                preflight_document,
                review=review,
                receipt=receipt,
                order=order,
            )
            coordinator = _trade_dispute_statement_fetch_coordinator(
                request,
                order_digest=order_digest,
                journal=journal,
                statement_store=statement_store,
                identity=identity,
                spine=spine,
                package_resolver=package_resolver,
            )
            return coordinator.receive(
                fetch_request,
                review=review,
                receipt=receipt,
                order=order,
                at=received_at,
            )

        try:
            result = await run_in_threadpool(_serve_statement)
        except TradeDisputeStatementFetchRequestRejected as exc:
            raise HTTPException(
                status_code=404,
                detail="requested Trade Dispute Statement context is unavailable",
            ) from exc
        except TradeDisputeStatementFetchNotFound as exc:
            raise HTTPException(
                status_code=404,
                detail="requested Trade Dispute Statement is unavailable",
            ) from exc
        except TradeDisputeStatementFetchInProgress as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Dispute Statement fetch is already processing",
                headers={"Retry-After": "1"},
            ) from exc
        except TradeDisputeStatementFetchRetryLater as exc:
            raise HTTPException(
                status_code=429,
                detail="trade Dispute Statement fetch retry floor is active",
                headers={"Retry-After": "1"},
            ) from exc
        except TradeDisputeStatementFetchJournalBusy as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Dispute Statement fetch journal is busy",
                headers={"Retry-After": "1"},
            ) from exc
        except (
            TradeDisputeStatementFetchJournalCapacity,
            TradeDisputeStatementStoreCapacity,
        ) as exc:
            raise HTTPException(
                status_code=507,
                detail="trade Dispute Statement fetch capacity exceeded",
            ) from exc
        except TradeDisputeStatementFetchReplayConflict as exc:
            raise HTTPException(
                status_code=409,
                detail="trade Dispute Statement fetch replay conflict",
            ) from exc
        except TradeDisputeStatementStoreBusy as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Dispute Statement store is busy",
                headers={"Retry-After": "1"},
            ) from exc
        except TradeDisputeStatementDependencyError as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Dispute Statement dependency is unavailable",
                headers={"Retry-After": "1"},
            ) from exc
        except TradeDisputeStatementStoreError as exc:
            raise HTTPException(
                status_code=409,
                detail="trade Dispute Statement integrity conflict",
            ) from exc
        except (
            TradeDisputeStatementFetchAuditError,
            TradeDisputeStatementFetchJournalError,
            TradeDisputeStatementFetchResponseRejected,
            TradeDisputeStatementFetchServiceError,
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
        ) as exc:
            logger.warning(
                "trade Dispute Statement fetch failed durably: %s",
                type(exc).__name__,
            )
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "dispute-statement-fetch-incomplete",
                    "message": "signed Statement fetch is incomplete",
                    "safe_to_retry": True,
                },
                headers={"Retry-After": "1"},
            ) from exc
        try:
            audit_event = await run_in_threadpool(
                spine.reconcile_append,
                result.audit_event_id,
            )
            if audit_event is None:
                raise RuntimeError("fetch disclosure audit event is missing")
            audit_ok, audit_reason = verify_trade_dispute_statement_fetch_audit_event(
                audit_event,
                result.request,
                result.response,
                review=review,
                receipt=receipt,
                order=order,
            )
            if not audit_ok:
                raise RuntimeError(
                    f"fetch disclosure audit event is invalid: {audit_reason}"
                )
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            logger.warning(
                "trade Dispute Statement fetch audit readback failed: %s",
                type(exc).__name__,
            )
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "dispute-statement-fetch-audit-unavailable",
                    "message": "signed Statement fetch audit is unavailable",
                    "safe_to_retry": True,
                },
                headers={"Retry-After": "1"},
            ) from exc
        return {
            "status": "dispute-statement-fetched",
            "order_digest": order_digest,
            "execution_id": execution_id,
            "review_id": review_id,
            "request_digest": result.request_digest,
            "response_digest": result.response_digest,
            "response": result.response.to_dict(),
            "audit_event_id": result.audit_event_id,
            "audit_event": audit_event.to_dict(),
            "replayed": result.replayed,
            "retained_by_responder": True,
            "imported_by_requester": False,
            "claim_adjudicated_or_proven_true": False,
        }

    def _trade_order_audit_view(
        view: Any,
        *,
        include_document: bool,
        pending_dispatch: Any = None,
        acknowledgement: Any = None,
        execution: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        from nth_dao.trade_rules import trade_order_digest

        order = view.order
        document = order.to_dict()
        result = {
            "order_digest": trade_order_digest(order),
            "order_id": document["order_id"],
            "proposal_digest": document["proposal_digest"],
            "acceptance_digest": document["acceptance_digest"],
            "offer_digest": document["offer_digest"],
            "maker_did": document["maker_did"],
            "taker_did": document["taker_did"],
            "created_at": document["created_at"],
            "audit_status": "anchored",
            "audit_event_id": view.event.event_id,
            "audit_attempts": 0,
            "last_error_code": "",
            "delivery_or_payment_proven": False,
            "dispatch_pending": pending_dispatch is not None,
            "dispatch_target_url": (
                pending_dispatch.target_url if pending_dispatch else ""
            ),
            "dispatch_attempts": (pending_dispatch.attempts if pending_dispatch else 0),
            "dispatch_last_error": (
                pending_dispatch.last_error if pending_dispatch else ""
            ),
            "dispatch_updated_at_ms": (
                pending_dispatch.updated_at_ms if pending_dispatch else 0
            ),
            "dispatch_generation": (
                pending_dispatch.generation if pending_dispatch else 0
            ),
            "dispatch_superseded_deliveries": (
                len(pending_dispatch.superseded_delivery_digests)
                if pending_dispatch
                else 0
            ),
            "remote_acknowledged": acknowledgement is not None,
            "remote_receipt_digest": (
                acknowledgement.receipt_digest if acknowledgement else ""
            ),
            "remote_audit_event_id": (
                acknowledgement.remote_event_id if acknowledgement else ""
            ),
            "remote_received_at": (
                acknowledgement.receipt.to_dict()["received_at"]
                if acknowledgement
                else ""
            ),
        }
        if include_document:
            result["order"] = document
            if execution is not None:
                result["execution"] = execution
        return result

    def _trade_execution_runtime_health(request: Request) -> Any:
        from nth_dao.trade_rules import TradeExecutionRuntimeHealth

        health = getattr(request.app.state.nth, "trade_execution_health", None)
        if isinstance(health, TradeExecutionRuntimeHealth):
            return health
        return TradeExecutionRuntimeHealth(
            status="unavailable",
            receipt_persistence_available=False,
            error_code="runtime-health-invalid",
        )

    def _record_trade_execution_history_health(
        request: Request,
        *,
        available: bool,
    ) -> None:
        from nth_dao.trade_rules import TradeExecutionRuntimeHealth

        state = request.app.state.nth
        lock = getattr(state, "trade_execution_health_lock", None)
        if lock is None:
            return
        with lock:
            current = _trade_execution_runtime_health(request)
            if available:
                if (
                    current.error_code
                    == "receipt-history-verification-failed"
                    and not current.recovery_pending
                ):
                    state.trade_execution_health = TradeExecutionRuntimeHealth(
                        status="healthy",
                        receipt_persistence_available=True,
                    )
                return
            if current.status == "unavailable":
                return
            state.trade_execution_health = TradeExecutionRuntimeHealth(
                status="degraded",
                receipt_persistence_available=(
                    current.receipt_persistence_available
                ),
                recovery_pending=current.recovery_pending,
                error_code="receipt-history-verification-failed",
            )

    def _trade_execution_history_view(
        request: Request,
        order: Any,
        *,
        limit: int = 100,
        before_seq: int | None = None,
    ) -> Dict[str, Any]:
        from nth_dao.trade_rules import execution_receipt_digest

        health = _trade_execution_runtime_health(request)
        coordinator = _state_trade_execution_coordinator(request)
        unavailable = {
            "status": "unavailable",
            "items": [],
            "has_more": False,
            "next_cursor": None,
            "error_code": "receipt-history-unavailable",
        }
        if (
            coordinator is None
            or not health.receipt_persistence_available
            or not callable(getattr(coordinator, "history", None))
        ):
            return unavailable
        try:
            history = coordinator.history(
                order,
                limit=limit,
                before_seq=before_seq,
            )
            items = []
            receipt_digests = []
            for item in history.items:
                document = item.receipt.to_dict()
                operation = document["operation"]
                adapter = document["adapter"]
                receipt_digest = execution_receipt_digest(
                    item.receipt,
                    order=order,
                )
                receipt_digests.append(receipt_digest)
                items.append({
                    "execution_id": document["execution_id"],
                    "receipt_digest": receipt_digest,
                    "audit_event_id": item.event.event_id,
                    "audit_seq": item.event.seq,
                    "executor_did": document["executor_did"],
                    "executor_role": document["executor_role"],
                    "operation_id": operation["operation_id"],
                    "hook_name": operation["hook_name"],
                    "side_effect": operation["side_effect"],
                    "adapter_id": adapter["adapter_id"],
                    "adapter_version": adapter["adapter_version"],
                    "execution_mode": adapter["execution_mode"],
                    "outcome": document["outcome"],
                    "started_at": document["started_at"],
                    "completed_at": document["completed_at"],
                })
            dispatch_states: Dict[str, Any] = {}
            dispatch_state_error = False
            dispatch_store = _state_trade_execution_dispatch_store(request)
            if dispatch_store is not None and receipt_digests:
                try:
                    dispatch_states = dispatch_store.get_states(
                        tuple(receipt_digests)
                    )
                except (OSError, RuntimeError, TypeError, ValueError) as exc:
                    dispatch_state_error = True
                    logger.warning(
                        "trade execution dispatch projection unavailable (%s)",
                        type(exc).__name__,
                    )
            for item in items:
                federation = {
                    "federation_status": (
                        "unavailable" if dispatch_state_error else "local-only"
                    ),
                    "dispatch_target_url": "",
                    "dispatch_attempts": 0,
                    "dispatch_last_error": "",
                    "dispatch_generation": 0,
                    "dispatch_superseded_deliveries": 0,
                    "remote_acknowledgement_digest": "",
                    "remote_receiver_did": "",
                    "remote_audit_event_id": "",
                    "remote_received_at": "",
                }
                pending, acknowledgement = dispatch_states.get(
                    item["receipt_digest"],
                    (None, None),
                )
                if acknowledgement is not None:
                    ack_document = acknowledgement.acknowledgement.to_dict()
                    federation.update({
                        "federation_status": (
                            "acknowledged-pending-anchor"
                            if pending is not None
                            else "acknowledged"
                        ),
                        "dispatch_target_url": acknowledgement.target_url,
                        "dispatch_attempts": (
                            pending.attempts if pending is not None else 0
                        ),
                        "dispatch_last_error": (
                            pending.last_error if pending is not None else ""
                        ),
                        "dispatch_generation": acknowledgement.generation,
                        "dispatch_superseded_deliveries": len(
                            acknowledgement.superseded_delivery_digests
                        ),
                        "remote_acknowledgement_digest": (
                            acknowledgement.acknowledgement_digest
                        ),
                        "remote_receiver_did": ack_document["receiver_did"],
                        "remote_audit_event_id": (
                            acknowledgement.remote_event_id
                        ),
                        "remote_received_at": ack_document["received_at"],
                    })
                elif pending is not None:
                    federation.update({
                        "federation_status": "pending",
                        "dispatch_target_url": pending.target_url,
                        "dispatch_attempts": pending.attempts,
                        "dispatch_last_error": pending.last_error,
                        "dispatch_generation": pending.generation,
                        "dispatch_superseded_deliveries": len(
                            pending.superseded_delivery_digests
                        ),
                    })
                item.update(federation)
            _record_trade_execution_history_health(
                request,
                available=True,
            )
            return {
                "status": "available",
                "items": items,
                "has_more": history.has_more,
                "next_cursor": history.next_cursor,
                "error_code": "",
            }
        except Exception as exc:  # noqa: BLE001 - history isolation boundary
            logger.warning(
                "trade execution history unavailable (%s)",
                type(exc).__name__,
            )
            _record_trade_execution_history_health(
                request,
                available=False,
            )
            return {
                **unavailable,
                "error_code": "receipt-history-verification-failed",
            }

    def _trade_order_execution_view(
        request: Request,
        order: Any,
        *,
        order_digest: str,
    ) -> Dict[str, Any]:
        from nth_dao.trade_rules import (
            project_trade_order_execution,
            unavailable_trade_order_execution_projection,
        )

        identity = _state_node_identity(request)
        local_did = (
            identity.as_did()
            if identity is not None and callable(getattr(identity, "as_did", None))
            else None
        )
        state = request.app.state.nth
        history_view = _trade_execution_history_view(request, order)
        health = _trade_execution_runtime_health(request)
        moment = datetime.now(timezone.utc)
        try:
            package_resolver = _trade_order_rule_package_resolver(
                request,
                order_digest,
            )
            projection = project_trade_order_execution(
                order,
                package_resolver,
                local_did=local_did,
                coordinator_health=health,
                executor_policy=getattr(state, "trade_executor_policy", None),
                adapter_resolver=getattr(
                    state, "trade_execution_adapter_resolver", None
                ),
                adapter_policy=getattr(
                    state, "trade_execution_adapter_policy", None
                ),
                content_resolver=getattr(
                    state, "trade_execution_content_resolver", None
                ),
                at=moment,
            )
        except Exception as exc:  # noqa: BLE001 - optional projection isolation boundary
            logger.warning(
                "trade execution projection unavailable (%s)",
                type(exc).__name__,
            )
            projection = unavailable_trade_order_execution_projection(
                order_digest=order_digest,
                local_did=local_did,
                coordinator_health=health,
                error_code="projection-failed",
                at=moment,
            )
        projection["history"] = history_view
        return projection

    @app.get("/api/v2/trade/orders")
    def v2_trade_order_list(
        request: Request,
        cursor: str = "",
        limit: int = 100,
    ) -> Dict[str, Any]:
        """List retained accepted agreements and local audit state."""

        from nth_dao.trade_rules import TradeOrderAuditError

        _require_console_bearer_for_sensitive_read(request)
        if isinstance(limit, bool) or not 1 <= limit <= 500:
            raise HTTPException(status_code=400, detail="limit must be in 1..500")
        if cursor and re.fullmatch(r"sha256:[0-9a-f]{64}", cursor) is None:
            raise HTTPException(
                status_code=400,
                detail="cursor must be a lowercase sha256 digest",
            )
        coordinator = _state_trade_order_audit(request)
        dispatch_store = _state_trade_order_dispatch_store(request)
        if coordinator is None or dispatch_store is None:
            raise HTTPException(
                status_code=503,
                detail="trade Order audit coordinator unavailable",
            )
        try:
            records = coordinator.list_accepted(
                limit=limit + 1,
                after=cursor or None,
            )
            page = records[:limit]
            dispatch_states = dispatch_store.get_states(tuple(
                record.event.payload["order_digest"] for record in page
            ))
            return {
                "items": [
                    _trade_order_audit_view(
                        record,
                        include_document=False,
                        pending_dispatch=dispatch_states[
                            record.event.payload["order_digest"]
                        ][0],
                        acknowledgement=dispatch_states[
                            record.event.payload["order_digest"]
                        ][1],
                    )
                    for record in page
                ],
                "next_cursor": (
                    page[-1].event.payload["order_digest"]
                    if len(records) > limit and page
                    else ""
                ),
            }
        except (TradeOrderAuditError, OSError, RuntimeError, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Order audit integrity failure",
            ) from exc

    @app.post("/api/v2/trade/orders/reconcile")
    async def v2_trade_order_reconcile(
        request: Request,
        limit: int = 100,
        acknowledgement_cursor: str = "",
        receipt_acknowledgement_cursor: str = "",
        review_acknowledgement_cursor: str = "",
    ) -> Dict[str, Any]:
        """Retry Order Store/Spine projection without peer resubmission."""

        from nth_dao.trade_rules import (
            TradeExecutionAuditBusy,
            TradeOrderAuditBusy,
            TradeOrderAuditError,
        )

        _require_console_bearer_for_sensitive_read(request)
        if isinstance(limit, bool) or not 1 <= limit <= 1_000:
            raise HTTPException(status_code=400, detail="limit must be in 1..1000")
        if acknowledgement_cursor and re.fullmatch(
            r"sha256:[0-9a-f]{64}", acknowledgement_cursor
        ) is None:
            raise HTTPException(
                status_code=400,
                detail="acknowledgement_cursor must be a lowercase sha256 digest",
            )
        if receipt_acknowledgement_cursor and re.fullmatch(
            r"sha256:[0-9a-f]{64}", receipt_acknowledgement_cursor
        ) is None:
            raise HTTPException(
                status_code=400,
                detail=(
                    "receipt_acknowledgement_cursor must be a lowercase sha256 digest"
                ),
            )
        if review_acknowledgement_cursor and re.fullmatch(
            r"sha256:[0-9a-f]{64}", review_acknowledgement_cursor
        ) is None:
            raise HTTPException(
                status_code=400,
                detail=(
                    "review_acknowledgement_cursor must be a lowercase sha256 digest"
                ),
            )
        coordinator = _state_trade_order_audit(request)
        dispatch_coordinator = _state_trade_order_dispatch(request)
        receipt_dispatch_coordinator = _state_trade_execution_dispatch(request)
        review_coordinator = _state_trade_receipt_review_coordinator(request)
        review_dispatch_coordinator = (
            _state_trade_receipt_review_dispatch(request)
        )
        if (
            coordinator is None
            or dispatch_coordinator is None
            or receipt_dispatch_coordinator is None
            or review_coordinator is None
            or review_dispatch_coordinator is None
        ):
            raise HTTPException(
                status_code=503,
                detail="trade Order audit coordinator unavailable",
            )
        try:
            result = await run_in_threadpool(coordinator.reconcile, limit=limit)
            dispatch_result = await run_in_threadpool(
                dispatch_coordinator.reconcile,
                limit=limit,
                after=acknowledgement_cursor or None,
            )
            receipt_dispatch_result = await run_in_threadpool(
                receipt_dispatch_coordinator.reconcile,
                limit=limit,
                after=receipt_acknowledgement_cursor or None,
            )
            review_result = await run_in_threadpool(
                review_coordinator.reconcile,
                limit=limit,
            )
            review_dispatch_result = await run_in_threadpool(
                review_dispatch_coordinator.reconcile,
                limit=limit,
                after=review_acknowledgement_cursor or None,
            )
            from nth_dao.web import _advance_trade_execution_recovery

            execution_result = await run_in_threadpool(
                _advance_trade_execution_recovery,
                request.app.state.nth,
                limit=limit,
            )
        except (TradeExecutionAuditBusy, TradeOrderAuditBusy) as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Order audit reconciliation is busy",
                headers={"Retry-After": "1"},
            ) from exc
        except (TradeOrderAuditError, OSError, RuntimeError, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Order audit reconciliation failed",
                headers={"Retry-After": "1"},
            ) from exc
        return {
            "scanned": result.scanned,
            "anchored": result.anchored,
            "verified_anchored": result.verified_anchored,
            "blocked": result.blocked,
            "failed": result.failed,
            "acknowledgements_scanned": dispatch_result.scanned,
            "acknowledgements_anchored": dispatch_result.anchored,
            "dispatches_completed": dispatch_result.completed,
            "acknowledgement_failures": dispatch_result.failed,
            "acknowledgement_next_cursor": dispatch_result.next_cursor,
            "acknowledgement_has_more": dispatch_result.has_more,
            "receipt_acknowledgements_scanned": (
                receipt_dispatch_result.scanned
            ),
            "receipt_acknowledgements_anchored": (
                receipt_dispatch_result.anchored
            ),
            "receipt_dispatches_completed": (
                receipt_dispatch_result.completed
            ),
            "receipt_acknowledgement_failures": (
                receipt_dispatch_result.failed
            ),
            "receipt_acknowledgement_next_cursor": (
                receipt_dispatch_result.next_cursor
            ),
            "receipt_acknowledgement_has_more": (
                receipt_dispatch_result.has_more
            ),
            "reviews_scanned": review_result.scanned,
            "reviews_anchored": review_result.anchored,
            "reviews_verified_anchored": review_result.verified_anchored,
            "review_conflicts": review_result.conflicted,
            "review_failures": review_result.failed,
            "review_recovery_next_cursor": review_result.next_cursor,
            "review_recovery_has_more": review_result.has_more,
            "review_acknowledgements_scanned": (
                review_dispatch_result.scanned
            ),
            "review_acknowledgements_anchored": (
                review_dispatch_result.anchored
            ),
            "review_dispatches_completed": (
                review_dispatch_result.completed
            ),
            "review_acknowledgement_failures": (
                review_dispatch_result.failed
            ),
            "review_acknowledgement_next_cursor": (
                review_dispatch_result.next_cursor
            ),
            "review_acknowledgement_has_more": (
                review_dispatch_result.has_more
            ),
            "executions_scanned": execution_result.scanned,
            "executions_anchored": execution_result.anchored,
            "execution_failures": execution_result.failed,
            "execution_recovery_pending": request.app.state.nth.trade_execution_health.recovery_pending,
        }

    @app.get("/api/v2/trade/orders/{order_digest}")
    def v2_trade_order_get(
        order_digest: str,
        request: Request,
    ) -> Dict[str, Any]:
        """Return one exact accepted agreement and its audit status."""

        from nth_dao.trade_rules import TradeOrderAuditError

        _require_console_bearer_for_sensitive_read(request)
        if re.fullmatch(r"sha256:[0-9a-f]{64}", order_digest) is None:
            raise HTTPException(
                status_code=400,
                detail="order_digest must be a lowercase sha256 digest",
            )
        coordinator = _state_trade_order_audit(request)
        dispatch_store = _state_trade_order_dispatch_store(request)
        if coordinator is None or dispatch_store is None:
            raise HTTPException(
                status_code=503,
                detail="trade Order audit coordinator unavailable",
            )
        try:
            record = coordinator.get_accepted(order_digest)
            if record is None:
                raise HTTPException(status_code=404, detail="Trade Order not found")
            pending_dispatch, acknowledgement = dispatch_store.get_state(
                order_digest
            )
            return _trade_order_audit_view(
                record,
                include_document=True,
                pending_dispatch=pending_dispatch,
                acknowledgement=acknowledgement,
                execution=_trade_order_execution_view(
                    request,
                    record.order,
                    order_digest=record.event.payload["order_digest"],
                ),
            )
        except HTTPException:
            raise
        except (TradeOrderAuditError, OSError, RuntimeError, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Order audit integrity failure",
            ) from exc

    @app.post(
        "/api/v2/trade/orders/{order_digest}/rule-packages/{package_digest}/import"
    )
    async def v2_trade_order_rule_package_import(
        order_digest: str,
        package_digest: str,
        body: ImportTradeRulePackageBody,
        request: Request,
    ) -> Dict[str, Any]:
        """Fetch, verify, and cache one exact Order-bound Trade Skill."""

        from nth_dao.trade_rules import (
            OfferRejected,
            RulePackageBusyError,
            RulePackageCapacityError,
            RulePackageError,
            RulePackageBundleRejected,
            TradeOffer,
            TradeOrderAuditError,
            offer_digest,
        )

        _require_console_bearer_for_sensitive_read(request)
        _require_trade_offer_digest(order_digest)
        _require_trade_offer_digest(package_digest)
        coordinator = _state_trade_order_audit(request)
        package_store = _state_trade_rule_package_store(request)
        workspace = _state_workspace(request)
        if coordinator is None or package_store is None or workspace is None:
            raise HTTPException(status_code=503, detail="trade package import unavailable")
        try:
            record = coordinator.get_accepted(order_digest)
            if record is None:
                raise HTTPException(status_code=404, detail="Trade Order not found")
            order_document = record.order.to_dict()
            bindings = {
                item["digest"]: item["rule_id"]
                for item in order_document["rule_bindings"]
            }
            if package_digest not in bindings:
                raise HTTPException(
                    status_code=409,
                    detail="Rule Package is not bound by this Trade Order",
                )
            source_offer = TradeOffer.from_dict(
                order_document["snapshot"]["offer"]
            )
            source_offer_digest = offer_digest(source_offer)
            normalized_peer = _normalize_configured_fed_peer(body.peer_url)
            spine = _state_spine(request)
            if spine is None:
                raise HTTPException(
                    status_code=503,
                    detail="signed Spine unavailable",
                )
            package, installed, audit_event, audit_created = await run_in_threadpool(
                _import_trade_rule_package_singleflight,
                workspace,
                package_store,
                spine,
                order_digest=order_digest,
                peer_url=normalized_peer,
                offer_digest=source_offer_digest,
                offer_publisher_did=source_offer.publisher_did,
                package_digest=package_digest,
                expected_rule_id=bindings[package_digest],
            )
        except HTTPException:
            raise
        except (RulePackageBundleRejected, OfferRejected, TypeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except RulePackageCapacityError as exc:
            raise HTTPException(status_code=507, detail=str(exc)) from exc
        except RulePackageBusyError as exc:
            raise HTTPException(
                status_code=503,
                detail="trade package store is busy",
                headers={"Retry-After": "1"},
            ) from exc
        except TradeRulePackageImportBusy as exc:
            raise HTTPException(
                status_code=503,
                detail=str(exc),
                headers={"Retry-After": "1"},
            ) from exc
        except TradeRulePackageImportAuditError as exc:
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "trade-rule-package-audit-incomplete",
                    "message": str(exc),
                    "package_digest": package_digest,
                    "retryable": True,
                },
                headers={"Retry-After": "1"},
            ) from exc
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
            raise HTTPException(
                status_code=502,
                detail="Trade Rule Package peer fetch failed",
            ) from exc
        except (RulePackageError, TradeOrderAuditError, RuntimeError) as exc:
            raise HTTPException(
                status_code=503,
                detail="Trade Rule Package import integrity check failed",
            ) from exc
        document = package.manifest.to_dict()
        return {
            "status": "installed" if installed else "already-installed",
            "installed": installed,
            "offer_digest": source_offer_digest,
            "package_digest": package.digest,
            "rule_id": document["rule_id"],
            "version": document["version"],
            "publisher_did": document["publisher_did"],
            "audit_event_id": audit_event.event_id,
            "audit_created": audit_created,
            "resource_count": len(package.resources),
            "resource_bytes": sum(len(item) for item in package.resources.values()),
            "trust_granted": False,
            "execution_authority_granted": False,
            "warning": (
                "Signature and content digests were verified. Installation is a local "
                "cache action; it does not recognize, trust, or execute the Trade Skill."
            ),
        }

    @app.post(
        "/api/v2/trade/orders/{order_digest}/rule-packages/"
        "{package_digest}/recognitions/import"
    )
    async def v2_trade_order_rule_recognition_import(
        order_digest: str,
        package_digest: str,
        body: ImportTradeRulePackageBody,
        request: Request,
    ) -> Dict[str, Any]:
        """Import observed Recognition evidence for one Order-bound Package."""

        from nth_dao.trade_rules import (
            OfferRejected,
            RulePackageError,
            RuleRecognitionAuditError,
            RuleRecognitionProofBundleRejected,
            RuleRecognitionStoreCapacity,
            RuleRecognitionStoreError,
            TradeOrderAuditError,
        )

        _require_console_bearer_for_sensitive_read(request)
        try:
            (
                workspace,
                recognition_audit,
                package,
                source_offer_digest,
                offer_publisher_did,
            ) = _load_order_bound_recognition_import_context(
                request,
                order_digest=order_digest,
                package_digest=package_digest,
            )
            normalized_peer = _normalize_configured_fed_peer(body.peer_url)
            (
                proof,
                imported,
                reconciled_anchor_count,
                import_audit,
                paged,
            ) = await run_in_threadpool(
                _import_trade_rule_recognition_proof_singleflight,
                workspace,
                recognition_audit,
                order_digest=order_digest,
                package=package,
                peer_url=normalized_peer,
                offer_digest=source_offer_digest,
                offer_publisher_did=offer_publisher_did,
            )
        except HTTPException:
            raise
        except (
            RuleRecognitionProofBundleRejected,
            OfferRejected,
            TypeError,
            ValueError,
        ) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except RuleRecognitionStoreCapacity as exc:
            raise HTTPException(status_code=507, detail=str(exc)) from exc
        except TradeRuleRecognitionImportBusy as exc:
            raise HTTPException(
                status_code=503,
                detail=str(exc),
                headers={"Retry-After": "1"},
            ) from exc
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
            raise HTTPException(
                status_code=502,
                detail="Rule Recognition peer fetch failed",
            ) from exc
        except (
            RulePackageError,
            RuleRecognitionAuditError,
            RuleRecognitionStoreError,
            TradeOrderAuditError,
            RuntimeError,
        ) as exc:
            raise HTTPException(
                status_code=503,
                detail="Rule Recognition import integrity check failed",
            ) from exc
        if paged:
            return _trade_rule_recognition_page_import_response(
                proof_set=proof,
                imported=imported,
                reconciled_anchor_count=reconciled_anchor_count,
                page_audits=import_audit,
                offer_digest=source_offer_digest,
                package=package,
            )
        return _trade_rule_recognition_import_response(
            proof=proof,
            imported=imported,
            reconciled_anchor_count=reconciled_anchor_count,
            import_audit=import_audit,
            offer_digest=source_offer_digest,
            package=package,
        )

    @app.get(
        "/api/v2/trade/orders/{order_digest}/rule-packages/"
        "{package_digest}/recognitions/imports"
    )
    def v2_trade_order_rule_recognition_import_status(
        order_digest: str,
        package_digest: str,
        request: Request,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """Inspect bounded import recovery state and retained proof evidence."""

        from nth_dao.trade_rules import (
            RulePackageError,
            RuleRecognitionAuditError,
            RuleRecognitionProofImportError,
            RuleRecognitionProofStore,
            TradeOrderAuditError,
        )

        _require_console_bearer_for_sensitive_read(request)
        if isinstance(limit, bool) or not 1 <= limit <= 100:
            raise HTTPException(status_code=400, detail="limit must be in 1..100")
        try:
            (
                workspace,
                recognition_audit,
                package,
                source_offer_digest,
                offer_publisher_did,
            ) = _load_order_bound_recognition_import_context(
                request,
                order_digest=order_digest,
                package_digest=package_digest,
            )
            events = recognition_audit.spine.verified_snapshot()
            proof_store = RuleRecognitionProofStore(workspace)
            return _trade_rule_recognition_import_status_page(
                events=events,
                proof_store=proof_store,
                package=package,
                order_digest=order_digest,
                source_offer_digest=source_offer_digest,
                offer_publisher_did=offer_publisher_did,
                limit=limit,
            )
        except HTTPException:
            raise
        except (
            RulePackageError,
            RuleRecognitionAuditError,
            RuleRecognitionProofImportError,
            TradeOrderAuditError,
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
        ) as exc:
            raise HTTPException(
                status_code=503,
                detail="Rule Recognition import status unavailable",
            ) from exc

    @app.get(
        "/api/v2/trade/orders/{order_digest}/recognitions/imports"
    )
    def v2_trade_order_rule_recognition_import_status_batch(
        order_digest: str,
        request: Request,
        package_digest: List[str] = Query(default=[]),
        limit: int = 100,
    ) -> Dict[str, Any]:
        """Inspect multiple package statuses from one verified Spine snapshot."""

        from nth_dao.trade_rules import (
            RulePackageError,
            RuleRecognitionAuditError,
            RuleRecognitionProofImportError,
            RuleRecognitionProofStore,
            TradeOrderAuditError,
        )

        _require_console_bearer_for_sensitive_read(request)
        if isinstance(limit, bool) or not 1 <= limit <= 100:
            raise HTTPException(status_code=400, detail="limit must be in 1..100")
        digests = tuple(package_digest)
        if not 1 <= len(digests) <= 64:
            raise HTTPException(
                status_code=400,
                detail="package_digest must contain 1..64 entries",
            )
        if len(set(digests)) != len(digests):
            raise HTTPException(
                status_code=400,
                detail="package_digest entries must be unique",
            )
        try:
            (
                workspace,
                recognition_audit,
                packages,
                source_offer_digest,
                offer_publisher_did,
            ) = _load_order_bound_recognition_import_contexts(
                request,
                order_digest=order_digest,
                package_digests=digests,
            )
            events = recognition_audit.spine.verified_snapshot()
            proof_store = RuleRecognitionProofStore(workspace)
            items = [
                _trade_rule_recognition_import_status_page(
                    events=events,
                    proof_store=proof_store,
                    package=package,
                    order_digest=order_digest,
                    source_offer_digest=source_offer_digest,
                    offer_publisher_did=offer_publisher_did,
                    limit=limit,
                )
                for package in packages
            ]
            return {
                "order_digest": order_digest,
                "package_count": len(items),
                "items": items,
            }
        except HTTPException:
            raise
        except (
            RulePackageError,
            RuleRecognitionAuditError,
            RuleRecognitionProofImportError,
            TradeOrderAuditError,
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
        ) as exc:
            raise HTTPException(
                status_code=503,
                detail="Rule Recognition batch status unavailable",
            ) from exc

    @app.post(
        "/api/v2/trade/orders/{order_digest}/rule-packages/"
        "{package_digest}/recognitions/imports/repair"
    )
    async def v2_trade_order_rule_recognition_import_repair(
        order_digest: str,
        package_digest: str,
        request: Request,
    ) -> Dict[str, Any]:
        """Restore exact signed proof bytes committed by an import event."""

        from nth_dao.trade_rules import (
            EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORT_PROPOSED,
            RulePackageError,
            RuleRecognitionAuditError,
            RuleRecognitionProofBundleRejected,
            RuleRecognitionProofImportError,
            RuleRecognitionProofStore,
            RuleRecognitionStoreError,
            TradeCanonicalJSONError,
            TradeOrderAuditError,
            parse_trade_json,
            recognition_proof_import_payload,
            recognition_proof_import_states,
            trade_canonical_json,
        )

        _require_console_bearer_for_sensitive_read(request)
        media_type = request.headers.get("content-type", "").split(";", 1)[0]
        if media_type.strip().lower() != "application/json":
            raise HTTPException(
                status_code=415,
                detail="Recognition proof repair requires Content-Type application/json",
            )
        try:
            (
                workspace,
                recognition_audit,
                package,
                source_offer_digest,
                offer_publisher_did,
            ) = _load_order_bound_recognition_import_context(
                request,
                order_digest=order_digest,
                package_digest=package_digest,
            )
            raw_body = await request.body()
            canonical = trade_canonical_json(parse_trade_json(raw_body))
            proof_digest = "sha256:" + hashlib.sha256(canonical).hexdigest()
            states = recognition_proof_import_states(
                recognition_audit.spine.verified_snapshot(),
                package_digest=package.digest,
                order_digest=order_digest,
            )
            matching = [
                state
                for state in states
                if state.payload["proof_digest"] == proof_digest
            ]
            if len(matching) != 1:
                raise HTTPException(
                    status_code=409,
                    detail="Proof is not committed by exactly one matching import",
                )
            state = matching[0]
            proposed_at = datetime.fromtimestamp(
                state.proposed_event.ts_ms / 1000,
                tz=timezone.utc,
            )
            proof = _parse_rule_recognition_proof_document(
                canonical,
                package=package,
                offer_digest=source_offer_digest,
                offer_publisher_did=offer_publisher_did,
                now=proposed_at,
            )
            expected = recognition_proof_import_payload(
                proof,
                event_type=EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORT_PROPOSED,
                order_digest=order_digest,
                offer_digest=source_offer_digest,
                source_origin=state.payload["source_origin"],
            )
            if expected != state.payload:
                raise HTTPException(
                    status_code=409,
                    detail="Proof does not match its audited import binding",
                )
            repaired = RuleRecognitionProofStore(workspace).repair_exact(
                proof,
                expected_digest=state.payload["proof_digest"],
            )
            if state.completed_event is not None:
                recognition_audit.verify_proof_import_evidence(package=package)
                return {
                    "status": "repaired" if repaired else "already-intact",
                    "proof_repaired": repaired,
                    "import_id": state.payload["import_id"],
                    "proof_digest": state.payload["proof_digest"],
                    "completion_event_id": state.completed_event.event_id,
                }
            (
                proof,
                imported,
                reconciled,
                import_audit,
                paged,
            ) = await run_in_threadpool(
                _import_trade_rule_recognition_proof_singleflight,
                workspace,
                recognition_audit,
                order_digest=order_digest,
                package=package,
                peer_url=state.payload["source_origin"],
                offer_digest=source_offer_digest,
                offer_publisher_did=offer_publisher_did,
            )
            if paged:
                response = _trade_rule_recognition_page_import_response(
                    proof_set=proof,
                    imported=imported,
                    reconciled_anchor_count=reconciled,
                    page_audits=import_audit,
                    offer_digest=source_offer_digest,
                    package=package,
                )
            else:
                response = _trade_rule_recognition_import_response(
                    proof=proof,
                    imported=imported,
                    reconciled_anchor_count=reconciled,
                    import_audit=import_audit,
                    offer_digest=source_offer_digest,
                    package=package,
                )
            response["proof_repaired"] = repaired
            return response
        except HTTPException:
            raise
        except (
            RuleRecognitionProofBundleRejected,
            TradeCanonicalJSONError,
            TypeError,
            ValueError,
        ) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except (
            RulePackageError,
            RuleRecognitionAuditError,
            RuleRecognitionProofImportError,
            RuleRecognitionStoreError,
            TradeOrderAuditError,
            OSError,
            RuntimeError,
        ) as exc:
            raise HTTPException(
                status_code=503,
                detail="Rule Recognition proof repair failed",
            ) from exc

    async def _load_trade_order_execution_receipt(
        request: Request,
        *,
        order_digest: str,
        execution_id: str,
    ) -> tuple[Any, Any]:
        from nth_dao.trade_rules import (
            TradeExecutionReceiptStoreBusy,
            TradeExecutionReceiptStoreError,
            TradeOrderAuditError,
        )

        if re.fullmatch(r"sha256:[0-9a-f]{64}", order_digest) is None:
            raise HTTPException(
                status_code=400,
                detail="order_digest must be a lowercase sha256 digest",
            )
        if re.fullmatch(
            r"nth-trade-execution-sha256:[0-9a-f]{64}",
            execution_id,
        ) is None:
            raise HTTPException(status_code=400, detail="execution_id is invalid")
        order_audit = _state_trade_order_audit(request)
        receipt_store = getattr(
            request.app.state.nth,
            "trade_execution_receipts",
            None,
        )
        if order_audit is None or receipt_store is None:
            raise HTTPException(
                status_code=503,
                detail="trade execution history runtime unavailable",
            )
        try:
            order_view = await run_in_threadpool(
                order_audit.get_accepted,
                order_digest,
            )
        except (TradeOrderAuditError, OSError, RuntimeError, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Order audit integrity failure",
            ) from exc
        if order_view is None:
            raise HTTPException(status_code=404, detail="Trade Order not found")
        try:
            receipt = await run_in_threadpool(
                receipt_store.get,
                execution_id,
                order=order_view.order,
            )
        except TradeExecutionReceiptStoreBusy as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Execution Receipt store is busy",
                headers={"Retry-After": "1"},
            ) from exc
        except TradeExecutionReceiptStoreError as exc:
            raise HTTPException(
                status_code=409,
                detail="trade Execution Receipt integrity conflict",
            ) from exc
        if receipt is None:
            raise HTTPException(
                status_code=404,
                detail="Trade Execution Receipt not found",
            )
        return order_view.order, receipt

    @app.get(
        "/api/v2/trade/orders/{order_digest}/execution-receipts"
    )
    def v2_trade_order_execution_receipts(
        order_digest: str,
        request: Request,
        limit: int = 100,
        before_seq: int | None = None,
    ) -> Dict[str, Any]:
        """Page backward through CAS/Spine-verified execution Receipts."""

        from nth_dao.trade_rules import TradeOrderAuditError

        _require_console_bearer_for_sensitive_read(request)
        if re.fullmatch(r"sha256:[0-9a-f]{64}", order_digest) is None:
            raise HTTPException(
                status_code=400,
                detail="order_digest must be a lowercase sha256 digest",
            )
        if isinstance(limit, bool) or not 1 <= limit <= 500:
            raise HTTPException(status_code=400, detail="limit must be in 1..500")
        if before_seq is not None and before_seq < 0:
            raise HTTPException(
                status_code=400,
                detail="before_seq must be a non-negative integer",
            )
        coordinator = _state_trade_order_audit(request)
        if coordinator is None:
            raise HTTPException(
                status_code=503,
                detail="trade Order audit coordinator unavailable",
            )
        try:
            record = coordinator.get_accepted(order_digest)
            if record is None:
                raise HTTPException(status_code=404, detail="Trade Order not found")
            return _trade_execution_history_view(
                request,
                record.order,
                limit=limit,
                before_seq=before_seq,
            )
        except HTTPException:
            raise
        except (TradeOrderAuditError, OSError, RuntimeError, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Order audit integrity failure",
            ) from exc

    @app.post(
        "/api/v2/trade/orders/{order_digest}/execution-receipts/{execution_id}/deliver"
    )
    async def v2_trade_execution_receipt_deliver(
        order_digest: str,
        execution_id: str,
        request: Request,
    ) -> Dict[str, Any]:
        """Durably deliver one locally signed Receipt to the other party."""

        from nth_dao.trade_rules import (
            TradeExecutionReceiptAcknowledgement,
            TradeExecutionReceiptDeliveryRejected,
            TradeExecutionReceiptDispatchBusy,
            TradeExecutionReceiptDispatchCapacity,
            TradeExecutionReceiptDispatchError,
            TradeExecutionReceiptStoreBusy,
            TradeExecutionReceiptStoreError,
            TradeOrderAuditError,
            create_trade_execution_receipt_delivery,
            execution_receipt_digest,
            verify_trade_execution_receipt_delivery,
        )

        _require_console_bearer_for_sensitive_read(request)
        if re.fullmatch(r"sha256:[0-9a-f]{64}", order_digest) is None:
            raise HTTPException(
                status_code=400,
                detail="order_digest must be a lowercase sha256 digest",
            )
        if re.fullmatch(
            r"nth-trade-execution-sha256:[0-9a-f]{64}",
            execution_id,
        ) is None:
            raise HTTPException(status_code=400, detail="execution_id is invalid")
        try:
            body = await request.json()
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=400, detail="invalid JSON body") from exc
        if not isinstance(body, dict) or set(body) != {"target_url"}:
            raise HTTPException(
                status_code=400,
                detail="body requires only target_url",
            )
        try:
            target_url = _normalize_configured_fed_peer(body["target_url"])
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        order_audit = _state_trade_order_audit(request)
        dispatch = _state_trade_execution_dispatch(request)
        dispatch_store = _state_trade_execution_dispatch_store(request)
        receipt_store = getattr(
            request.app.state.nth,
            "trade_execution_receipts",
            None,
        )
        identity = _state_node_identity(request)
        if (
            order_audit is None
            or dispatch is None
            or dispatch_store is None
            or receipt_store is None
            or identity is None
            or not getattr(identity, "can_sign", False)
        ):
            raise HTTPException(
                status_code=503,
                detail="trade Execution Receipt dispatch runtime unavailable",
            )
        try:
            order_view = await run_in_threadpool(
                order_audit.get_accepted,
                order_digest,
            )
        except (TradeOrderAuditError, OSError, RuntimeError, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Order audit integrity failure",
            ) from exc
        if order_view is None:
            raise HTTPException(status_code=404, detail="Trade Order not found")
        order = order_view.order
        try:
            receipt = await run_in_threadpool(
                receipt_store.get,
                execution_id,
                order=order,
            )
        except TradeExecutionReceiptStoreBusy as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Execution Receipt store is busy",
                headers={"Retry-After": "1"},
            ) from exc
        except TradeExecutionReceiptStoreError as exc:
            raise HTTPException(
                status_code=409,
                detail="trade Execution Receipt integrity conflict",
            ) from exc
        if receipt is None:
            raise HTTPException(
                status_code=404,
                detail="Trade Execution Receipt not found",
            )
        receipt_digest = execution_receipt_digest(receipt, order=order)

        def _acknowledged_response(acknowledgement: Any) -> Dict[str, Any]:
            document = acknowledgement.acknowledgement.to_dict()
            return {
                "status": "execution-receipt-delivered",
                "order_digest": acknowledgement.order_digest,
                "execution_id": execution_id,
                "receipt_digest": acknowledgement.receipt_digest,
                "delivery_digest": acknowledgement.delivery_digest,
                "acknowledgement": document,
                "acknowledgement_digest": (
                    acknowledgement.acknowledgement_digest
                ),
                "remote_audit_event_id": acknowledgement.remote_event_id,
                "remote_received_at": document["received_at"],
                "acknowledgement_persisted": True,
                "delivery_or_payment_proven": False,
            }

        try:
            existing_ack = await run_in_threadpool(
                dispatch.recover_acknowledgement,
                receipt_digest,
            )
            if existing_ack is not None:
                return _acknowledged_response(existing_ack)
            pending = await run_in_threadpool(
                dispatch_store.get_pending,
                receipt_digest,
            )
        except (TradeExecutionReceiptDispatchBusy,) as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Execution Receipt dispatch is busy",
                headers={"Retry-After": "1"},
            ) from exc
        except TradeExecutionReceiptDispatchError as exc:
            raise HTTPException(
                status_code=503,
                detail=f"dispatch recovery failed: {exc}",
                headers={"Retry-After": "1"},
            ) from exc

        moment = datetime.now(timezone.utc).replace(microsecond=0)
        now_ms = int(moment.timestamp() * 1_000)
        created_at = moment.isoformat().replace("+00:00", "Z")
        try:
            if pending is not None:
                if pending.target_url != target_url:
                    raise TradeExecutionReceiptDispatchError(
                        "pending dispatch targets a different peer"
                    )
                ok, reason = verify_trade_execution_receipt_delivery(
                    pending.delivery,
                    order=order,
                    recipient_did=pending.delivery.to_dict()["recipient_did"],
                    at=moment,
                )
                if ok:
                    delivery = pending.delivery
                elif "expired" in reason:
                    replacement = create_trade_execution_receipt_delivery(
                        identity,
                        receipt=receipt,
                        order=order,
                        created_at=created_at,
                        not_after=(moment + timedelta(minutes=5)).isoformat().replace(
                            "+00:00", "Z"
                        ),
                        now=moment,
                    )
                    pending = await run_in_threadpool(
                        dispatch.renew_expired,
                        replacement,
                        order=order,
                        target_url=target_url,
                        now_ms=now_ms,
                    )
                    delivery = pending.delivery
                else:
                    raise TradeExecutionReceiptDispatchError(
                        f"pending delivery is not usable: {reason}"
                    )
            else:
                delivery = create_trade_execution_receipt_delivery(
                    identity,
                    receipt=receipt,
                    order=order,
                    created_at=created_at,
                    not_after=(moment + timedelta(minutes=5)).isoformat().replace(
                        "+00:00", "Z"
                    ),
                    now=moment,
                )
                pending = await run_in_threadpool(
                    dispatch.prepare,
                    delivery,
                    order=order,
                    target_url=target_url,
                    now_ms=now_ms,
                )
                if pending.acknowledged:
                    existing_ack = await run_in_threadpool(
                        dispatch.recover_acknowledgement,
                        receipt_digest,
                    )
                    if existing_ack is None:
                        raise TradeExecutionReceiptDispatchError(
                            "acknowledged dispatch state disappeared"
                        )
                    return _acknowledged_response(existing_ack)
                delivery = pending.delivery
        except TradeExecutionReceiptDeliveryRejected as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except TradeExecutionReceiptDispatchCapacity as exc:
            raise HTTPException(
                status_code=507,
                detail="trade Execution Receipt dispatch capacity exceeded",
            ) from exc
        except (TradeExecutionReceiptDispatchBusy,) as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Execution Receipt dispatch is busy",
                headers={"Retry-After": "1"},
            ) from exc
        except TradeExecutionReceiptDispatchError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

        async def _note_failure(message: str) -> None:
            try:
                await run_in_threadpool(
                    dispatch.failed,
                    receipt_digest,
                    error=message,
                )
            except (OSError, RuntimeError, TypeError, ValueError) as exc:
                logger.warning(
                    "unable to record failed Execution Receipt dispatch: %s",
                    type(exc).__name__,
                )

        try:
            peer_status, peer_body = await run_in_threadpool(
                _post_trade_execution_receipt_delivery_to_peer,
                target_url,
                order_digest,
                delivery.to_dict(),
            )
        except (OSError, TimeoutError, ValueError, urllib.error.URLError) as exc:
            await _note_failure(str(exc))
            raise HTTPException(
                status_code=502,
                detail=(
                    "signed Receipt is retained locally but peer delivery "
                    f"failed: {exc}"
                ),
            ) from exc
        if not 200 <= peer_status < 300:
            await _note_failure(f"peer returned HTTP {peer_status}")
            raise HTTPException(
                status_code=502,
                detail=(
                    "signed Receipt is retained locally but the peer "
                    f"rejected delivery with HTTP {peer_status}"
                ),
            )
        try:
            acknowledgement = TradeExecutionReceiptAcknowledgement.from_dict(
                peer_body["acknowledgement"]
            )
            peer_event_id = peer_body["audit_event_id"]
        except (KeyError, TypeError, ValueError) as exc:
            await _note_failure(f"invalid acknowledgement: {exc}")
            raise HTTPException(
                status_code=502,
                detail="peer returned an invalid signed acknowledgement",
            ) from exc
        try:
            retained = await run_in_threadpool(
                dispatch.acknowledge,
                delivery,
                acknowledgement,
                order=order,
                target_url=target_url,
                remote_event_id=peer_event_id,
            )
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail=(
                    "remote acknowledgement verified but local persistence "
                    "is incomplete"
                ),
                headers={"Retry-After": "1"},
            ) from exc
        return _acknowledged_response(retained)

    @app.get(
        "/api/v2/trade/orders/{order_digest}/execution-receipts/{execution_id}/reviews"
    )
    async def v2_trade_receipt_review_get(
        order_digest: str,
        execution_id: str,
        request: Request,
    ) -> Dict[str, Any]:
        """Return the one counterparty Review and its federation state."""

        from nth_dao.trade_rules import (
            TradeReceiptReviewConflict,
            TradeReceiptReviewDispatchError,
            TradeReceiptReviewStoreBusy,
            TradeReceiptReviewStoreError,
            execution_receipt_digest,
            receipt_review_digest,
            receipt_review_id,
        )

        _require_console_bearer_for_sensitive_read(request)
        order, receipt = await _load_trade_order_execution_receipt(
            request,
            order_digest=order_digest,
            execution_id=execution_id,
        )
        order_document = order.to_dict()
        receipt_document = receipt.to_dict()
        reviewer_role = (
            "taker"
            if receipt_document["executor_role"] == "maker"
            else "maker"
        )
        reviewer_did = order_document[f"{reviewer_role}_did"]
        review_id = receipt_review_id(
            receipt_digest=execution_receipt_digest(receipt, order=order),
            reviewer_did=reviewer_did,
        )
        store = _state_trade_receipt_review_store(request)
        dispatch_store = _state_trade_receipt_review_dispatch_store(request)
        if store is None or dispatch_store is None:
            raise HTTPException(
                status_code=503,
                detail="trade Receipt Review runtime unavailable",
            )
        try:
            review = await run_in_threadpool(
                store.get,
                review_id,
                receipt=receipt,
                order=order,
            )
        except TradeReceiptReviewConflict:
            try:
                conflict = await run_in_threadpool(
                    store.conflict_status,
                    review_id,
                    receipt=receipt,
                    order=order,
                )
            except (OSError, RuntimeError, TypeError, ValueError) as exc:
                raise HTTPException(
                    status_code=503,
                    detail="trade Receipt Review conflict state unavailable",
                ) from exc
            return {
                "status": "conflicted",
                "review_id": review_id,
                "review": None,
                "retained_review_digests": list(
                    conflict.retained_review_digests
                ),
                "federation": {"status": "blocked-by-conflict"},
            }
        except TradeReceiptReviewStoreBusy as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Receipt Review store is busy",
                headers={"Retry-After": "1"},
            ) from exc
        except TradeReceiptReviewStoreError as exc:
            raise HTTPException(
                status_code=409,
                detail="trade Receipt Review integrity conflict",
            ) from exc
        if review is None:
            return {
                "status": "not-reviewed",
                "review_id": review_id,
                "review": None,
                "retained_review_digests": [],
                "federation": {"status": "local-only"},
            }
        digest = receipt_review_digest(
            review,
            receipt=receipt,
            order=order,
        )
        try:
            pending, acknowledgement = await run_in_threadpool(
                dispatch_store.get_state,
                digest,
            )
        except TradeReceiptReviewDispatchError as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Receipt Review dispatch state unavailable",
            ) from exc
        federation: Dict[str, Any] = {
            "status": "local-only",
            "target_url": "",
            "attempts": 0,
            "last_error": "",
            "generation": 0,
            "superseded_deliveries": 0,
            "acknowledgement_digest": "",
            "remote_receiver_did": "",
            "remote_audit_event_id": "",
            "remote_received_at": "",
        }
        if acknowledgement is not None:
            ack_document = acknowledgement.acknowledgement.to_dict()
            federation.update({
                "status": (
                    "acknowledged-pending-anchor"
                    if pending is not None
                    else "acknowledged"
                ),
                "target_url": acknowledgement.target_url,
                "attempts": pending.attempts if pending is not None else 0,
                "last_error": (
                    pending.last_error if pending is not None else ""
                ),
                "generation": acknowledgement.generation,
                "superseded_deliveries": len(
                    acknowledgement.superseded_delivery_digests
                ),
                "acknowledgement_digest": (
                    acknowledgement.acknowledgement_digest
                ),
                "remote_receiver_did": ack_document["receiver_did"],
                "remote_audit_event_id": acknowledgement.remote_event_id,
                "remote_received_at": ack_document["received_at"],
            })
        elif pending is not None:
            federation.update({
                "status": "pending",
                "target_url": pending.target_url,
                "attempts": pending.attempts,
                "last_error": pending.last_error,
                "generation": pending.generation,
                "superseded_deliveries": len(
                    pending.superseded_delivery_digests
                ),
            })
        return {
            "status": "reviewed",
            "review_id": review_id,
            "review_digest": digest,
            "review": review.to_dict(),
            "retained_review_digests": [digest],
            "federation": federation,
        }

    @app.post(
        "/api/v2/trade/orders/{order_digest}/execution-receipts/{execution_id}/reviews",
        status_code=201,
    )
    async def v2_trade_receipt_review_create(
        order_digest: str,
        execution_id: str,
        request: Request,
    ) -> Dict[str, Any]:
        """Re-run a Receipt locally, sign a Review, and durably audit it."""

        from nth_dao.trade_rules import (
            JsonSchema202012Validator,
            RuleResolutionPolicy,
            TradeReceiptReviewAuditError,
            TradeReceiptReviewConflict,
            TradeReceiptReviewOutboxBusy,
            TradeReceiptReviewOutboxCapacity,
            TradeReceiptReviewRejected,
            TradeReceiptReviewStoreBusy,
            TradeReceiptReviewStoreCapacity,
            create_trade_receipt_review,
            receipt_review_digest,
        )

        _require_console_bearer_for_sensitive_read(request)
        try:
            body = await request.json()
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=400, detail="invalid JSON body") from exc
        if not isinstance(body, dict) or set(body) != {
            "decision",
            "reason_codes",
        }:
            raise HTTPException(
                status_code=400,
                detail="body requires only decision and reason_codes",
            )
        order, receipt = await _load_trade_order_execution_receipt(
            request,
            order_digest=order_digest,
            execution_id=execution_id,
        )
        identity = _state_node_identity(request)
        coordinator = _state_trade_receipt_review_coordinator(request)
        state = request.app.state.nth
        package_store = _state_trade_rule_package_store(request)
        adapter_resolver = getattr(
            state,
            "trade_execution_adapter_resolver",
            None,
        )
        adapter_policy = getattr(
            state,
            "trade_execution_adapter_policy",
            None,
        )
        content_resolver = getattr(
            state,
            "trade_execution_content_resolver",
            None,
        )
        if (
            identity is None
            or not getattr(identity, "can_sign", False)
            or coordinator is None
            or package_store is None
            or adapter_resolver is None
            or adapter_policy is None
            or content_resolver is None
        ):
            raise HTTPException(
                status_code=503,
                detail="trade Receipt Review signing runtime unavailable",
            )
        order_document = order.to_dict()
        receipt_document = receipt.to_dict()
        reviewer_role = (
            "taker"
            if receipt_document["executor_role"] == "maker"
            else "maker"
        )
        if identity.as_did() != order_document[f"{reviewer_role}_did"]:
            raise HTTPException(
                status_code=403,
                detail="only the Receipt counterparty can sign its Review",
            )
        policy_document = (
            order_document["snapshot"]["proposal"]["taker_policy"]
            if reviewer_role == "taker"
            else order_document["snapshot"]["acceptance"]["maker_policy"]
        )
        verifier_policy = RuleResolutionPolicy.from_dict(policy_document)
        try:
            package_resolver = _trade_order_rule_package_resolver(
                request,
                order_digest,
            )
        except RuntimeError as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Rule Package audit resolver unavailable",
            ) from exc
        moment = datetime.now(timezone.utc)
        if moment.microsecond == 0:
            moment = moment.replace(microsecond=1)
        reviewed_at = moment.isoformat(timespec="microseconds").replace("+00:00", "Z")
        schema_validator = (
            getattr(
                state,
                "trade_execution_schema_validator",
                None,
            )
            or JsonSchema202012Validator()
        )

        def _create_and_record_review() -> Any:
            review = create_trade_receipt_review(
                identity,
                receipt=receipt,
                order=order,
                package_resolver=package_resolver,
                verifier_policy=verifier_policy,
                adapter_resolver=adapter_resolver,
                adapter_policy=adapter_policy,
                content_resolver=content_resolver,
                schema_validator=schema_validator,
                decision=body["decision"],
                reason_codes=body["reason_codes"],
                reviewed_at=reviewed_at,
                now=moment,
            )
            return coordinator.record(
                review,
                receipt=receipt,
                order=order,
                verifier_policy=verifier_policy,
                adapter_policy=adapter_policy,
                observed_at_ms=int(moment.timestamp() * 1_000),
            )

        try:
            result = await run_in_threadpool(_create_and_record_review)
        except TradeReceiptReviewRejected as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except TradeReceiptReviewConflict as exc:
            raise HTTPException(
                status_code=409,
                detail="Review conflicts with retained signed bytes",
            ) from exc
        except (TradeReceiptReviewStoreBusy, TradeReceiptReviewOutboxBusy) as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Receipt Review store is busy",
                headers={"Retry-After": "1"},
            ) from exc
        except (
            TradeReceiptReviewStoreCapacity,
            TradeReceiptReviewOutboxCapacity,
        ) as exc:
            raise HTTPException(
                status_code=507,
                detail="trade Receipt Review capacity exceeded",
            ) from exc
        except (
            TradeReceiptReviewAuditError,
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
        ) as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Receipt Review persistence is incomplete",
                headers={"Retry-After": "1"},
            ) from exc
        digest = receipt_review_digest(
            result.review,
            receipt=receipt,
            order=order,
        )
        return {
            "status": "review-signed",
            "review_id": result.review.review_id,
            "review_digest": digest,
            "review": result.review.to_dict(),
            "review_store_created": result.store_created,
            "audit_anchor_created": result.anchor_created,
            "audit_event_id": result.event.event_id,
            "is_counterparty_claim": True,
            "delivery_quality_or_payment_proven": False,
        }

    async def _load_trade_dispute_review(
        request: Request,
        *,
        order_digest: str,
        execution_id: str,
        review_id: str,
    ) -> tuple[Any, Any, Any]:
        from nth_dao.trade_rules import (
            TradeReceiptReviewConflict,
            TradeReceiptReviewStoreBusy,
            TradeReceiptReviewStoreError,
        )

        if re.fullmatch(
            r"nth-trade-review-sha256:[0-9a-f]{64}",
            review_id,
        ) is None:
            raise HTTPException(status_code=400, detail="review_id is invalid")
        order, receipt = await _load_trade_order_execution_receipt(
            request,
            order_digest=order_digest,
            execution_id=execution_id,
        )
        store = _state_trade_receipt_review_store(request)
        if store is None:
            raise HTTPException(
                status_code=503,
                detail="trade Receipt Review store unavailable",
            )
        try:
            review = await run_in_threadpool(
                store.get,
                review_id,
                receipt=receipt,
                order=order,
            )
        except TradeReceiptReviewStoreBusy as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Receipt Review store is busy",
                headers={"Retry-After": "1"},
            ) from exc
        except TradeReceiptReviewConflict as exc:
            raise HTTPException(
                status_code=409,
                detail="Receipt Review has contradictory signed candidates",
            ) from exc
        except TradeReceiptReviewStoreError as exc:
            raise HTTPException(
                status_code=409,
                detail="trade Receipt Review integrity conflict",
            ) from exc
        if review is None:
            raise HTTPException(status_code=404, detail="Trade Receipt Review not found")
        return order, receipt, review

    @app.get(
        "/api/v2/trade/orders/{order_digest}/execution-receipts/"
        "{execution_id}/reviews/{review_id}/dispute-statements"
    )
    async def v2_trade_dispute_statement_list(
        order_digest: str,
        execution_id: str,
        review_id: str,
        request: Request,
        limit: int = 100,
        after: str | None = None,
        include_graph: bool = False,
    ) -> Dict[str, Any]:
        """List verified signed claims for one exact disputed Review."""

        from nth_dao.trade_rules import (
            EVENT_TRADE_DISPUTE_STATEMENT_RETAINED,
            TradeDisputeStatementAuditError,
            TradeDisputeStatementDependencyError,
            TradeDisputeStatementRejected,
            TradeDisputeStatementResolutionError,
            TradeDisputeStatementStoreBusy,
            TradeDisputeStatementStoreCapacity,
            TradeDisputeStatementStoreError,
            validate_trade_dispute_statement_audit_event,
            validate_trade_dispute_statement_audit_payload,
        )

        _require_console_bearer_for_sensitive_read(request)
        if isinstance(limit, bool) or not 1 <= limit <= 500:
            raise HTTPException(status_code=400, detail="limit must be in 1..500")
        if after is not None and re.fullmatch(
            r"v1:[0-9a-f]{64}:[0-9a-f]{64}",
            after,
        ) is None:
            raise HTTPException(status_code=400, detail="after cursor is invalid")
        if include_graph and after is not None:
            raise HTTPException(
                status_code=400,
                detail="include_graph is available only for the first page",
            )
        order, receipt, review = await _load_trade_dispute_review(
            request,
            order_digest=order_digest,
            execution_id=execution_id,
            review_id=review_id,
        )
        store = _state_trade_dispute_statement_store(request)
        audit = _state_trade_dispute_statement_audit(request)
        if store is None or audit is None:
            raise HTTPException(
                status_code=503,
                detail="trade Dispute Statement runtime unavailable",
            )
        try:
            package_resolver = _trade_order_rule_package_resolver(
                request,
                order_digest,
            )
        except RuntimeError as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Rule Package audit resolver unavailable",
            ) from exc

        try:
            graph = None
            if include_graph:
                page, graph = await run_in_threadpool(
                    store.page_and_graph_for_review,
                    review=review,
                    receipt=receipt,
                    order=order,
                    package_resolver=package_resolver,
                    limit=limit,
                )
            else:
                page = await run_in_threadpool(
                    store.list_for_review,
                    review=review,
                    receipt=receipt,
                    order=order,
                    package_resolver=package_resolver,
                    limit=limit,
                    after=after,
                )
        except TradeDisputeStatementStoreBusy as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Dispute Statement store is busy",
                headers={"Retry-After": "1"},
            ) from exc
        except TradeDisputeStatementDependencyError as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Dispute Statement dependency is unavailable",
                headers={"Retry-After": "1"},
            ) from exc
        except TradeDisputeStatementStoreCapacity as exc:
            raise HTTPException(
                status_code=507,
                detail="trade Dispute Statement graph capacity exceeded",
            ) from exc
        except TradeDisputeStatementStoreError as exc:
            raise HTTPException(
                status_code=409,
                detail="trade Dispute Statement integrity conflict",
            ) from exc
        spine = audit.spine
        projection_state = request.app.state.nth

        def _stable_audit_events() -> tuple[Any, ...]:
            with projection_state.trade_dispute_statement_projection_lock:
                current = spine.storage_token()
                if (
                    projection_state.trade_dispute_statement_projection_token
                    == current
                ):
                    return (
                        projection_state
                        .trade_dispute_statement_projection_events
                    )
                token, snapshot = spine.verified_snapshot_with_token()
                events = tuple(
                    event
                    for event in snapshot
                    if event.type == EVENT_TRADE_DISPUTE_STATEMENT_RETAINED
                )
                projection_state.trade_dispute_statement_projection_token = token
                projection_state.trade_dispute_statement_projection_events = events
                return events

        try:
            events = await run_in_threadpool(_stable_audit_events)
            anchors: dict[str, list[Any]] = {}
            for event in events:
                if event.author_did != spine.signer_did:
                    raise TradeDisputeStatementAuditError(
                        "Trade Dispute Statement Spine author is unauthorized"
                    )
                payload = validate_trade_dispute_statement_audit_payload(
                    event.payload
                )
                anchors.setdefault(payload["statement_digest"], []).append(event)
            projected: list[Dict[str, Any]] = []
            for digest, statement in zip(
                page.statement_digests,
                page.statements,
                strict=True,
            ):
                matching = anchors.get(digest, [])
                if len(matching) > 1:
                    raise TradeDisputeStatementAuditError(
                        "duplicate Trade Dispute Statement Spine anchors"
                    )
                audit_event_id = ""
                audit_status = "retained-pending-audit"
                if matching:
                    event = matching[0]
                    validate_trade_dispute_statement_audit_event(
                        event,
                        expected_author_did=spine.signer_did,
                        statement=statement,
                        review=review,
                        receipt=receipt,
                        order=order,
                        package_resolver=package_resolver,
                    )
                    audit_event_id = event.event_id
                    audit_status = "anchored"
                projected.append(
                    {
                        "statement_digest": digest,
                        "statement": statement.to_dict(),
                        "claim_status": "signed-unadjudicated-claim",
                        "audit_status": audit_status,
                        "audit_event_id": audit_event_id,
                    }
                )
        except TradeDisputeStatementResolutionError as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Dispute Statement dependency is unavailable",
                headers={"Retry-After": "1"},
            ) from exc
        except TradeDisputeStatementRejected as exc:
            raise HTTPException(
                status_code=409,
                detail="trade Dispute Statement audit projection is invalid",
            ) from exc
        except (
            OSError,
            RuntimeError,
            TradeDisputeStatementAuditError,
            TypeError,
            ValueError,
        ) as exc:
            raise HTTPException(
                status_code=409,
                detail="trade Dispute Statement audit projection is invalid",
            ) from exc
        result = {
            "status": "dispute-statements-listed",
            "order_digest": order_digest,
            "execution_id": execution_id,
            "review_id": review_id,
            "items": projected,
            "snapshot_token": page.snapshot_token,
            "next_cursor": page.next_cursor,
            "graph_endpoint": request.url.path + "/graph",
            "claims_adjudicated_or_proven_true": False,
        }
        if graph is not None:
            result["graph"] = graph.to_dict(max_items=500)
        return result

    @app.get(
        "/api/v2/trade/orders/{order_digest}/execution-receipts/"
        "{execution_id}/reviews/{review_id}/dispute-statements/graph"
    )
    async def v2_trade_dispute_statement_graph(
        order_digest: str,
        execution_id: str,
        review_id: str,
        request: Request,
    ) -> Dict[str, Any]:
        """Project locally retained ancestry without adjudicating claims."""

        from nth_dao.trade_rules import (
            TradeDisputeStatementDependencyError,
            TradeDisputeStatementStoreBusy,
            TradeDisputeStatementStoreCapacity,
            TradeDisputeStatementStoreError,
        )

        _require_console_bearer_for_sensitive_read(request)
        order, receipt, review = await _load_trade_dispute_review(
            request,
            order_digest=order_digest,
            execution_id=execution_id,
            review_id=review_id,
        )
        store = _state_trade_dispute_statement_store(request)
        if store is None:
            raise HTTPException(
                status_code=503,
                detail="trade Dispute Statement runtime unavailable",
            )
        try:
            package_resolver = _trade_order_rule_package_resolver(
                request,
                order_digest,
            )
        except RuntimeError as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Rule Package audit resolver unavailable",
            ) from exc
        try:
            graph = await run_in_threadpool(
                store.graph_for_review,
                review=review,
                receipt=receipt,
                order=order,
                package_resolver=package_resolver,
            )
        except TradeDisputeStatementStoreBusy as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Dispute Statement store is busy",
                headers={"Retry-After": "1"},
            ) from exc
        except TradeDisputeStatementStoreCapacity as exc:
            raise HTTPException(
                status_code=507,
                detail="trade Dispute Statement graph capacity exceeded",
            ) from exc
        except TradeDisputeStatementDependencyError as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Dispute Statement dependency is unavailable",
                headers={"Retry-After": "1"},
            ) from exc
        except TradeDisputeStatementStoreError as exc:
            raise HTTPException(
                status_code=409,
                detail="trade Dispute Statement graph integrity conflict",
            ) from exc
        return {
            "status": "dispute-statement-graph-projected",
            "order_digest": order_digest,
            "execution_id": execution_id,
            "review_id": review_id,
            "graph": graph.to_dict(max_items=500),
            "claims_adjudicated_or_proven_true": False,
        }

    @app.post(
        "/api/v2/trade/orders/{order_digest}/execution-receipts/"
        "{execution_id}/reviews/{review_id}/dispute-statements",
        status_code=201,
    )
    async def v2_trade_dispute_statement_create(
        order_digest: str,
        execution_id: str,
        review_id: str,
        request: Request,
        response: Response,
    ) -> Dict[str, Any]:
        """Sign, retain, and audit one local party claim without executing it."""

        from nth_dao.trade_rules import (
            TradeDisputeStatementAuditError,
            TradeDisputeStatementDependencyError,
            TradeDisputeStatementRejected,
            TradeDisputeStatementResolutionError,
            TradeDisputeStatementParentError,
            TradeDisputeStatementStoreBusy,
            TradeDisputeStatementStoreCapacity,
            TradeDisputeStatementStoreError,
            create_trade_dispute_statement,
            trade_dispute_statement_digest,
        )

        _require_console_bearer_for_sensitive_read(request)
        try:
            body = await request.json()
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=400, detail="invalid JSON body") from exc
        allowed = {
            "statement_type",
            "parent_statement_digests",
            "reason_codes",
            "claim",
            "evidence",
            "rule_action",
        }
        if (
            not isinstance(body, dict)
            or "statement_type" not in body
            or not set(body).issubset(allowed)
        ):
            raise HTTPException(
                status_code=400,
                detail=(
                    "body requires statement_type and permits only "
                    "parent_statement_digests, reason_codes, claim, evidence, "
                    "and rule_action"
                ),
            )
        order, receipt, review = await _load_trade_dispute_review(
            request,
            order_digest=order_digest,
            execution_id=execution_id,
            review_id=review_id,
        )
        identity = _state_node_identity(request)
        coordinator = _state_trade_dispute_statement_audit(request)
        store = _state_trade_dispute_statement_store(request)
        if (
            identity is None
            or not getattr(identity, "can_sign", False)
            or coordinator is None
            or store is None
        ):
            raise HTTPException(
                status_code=503,
                detail="trade Dispute Statement signing runtime unavailable",
            )
        order_document = order.to_dict()
        if identity.as_did() not in {
            order_document["maker_did"],
            order_document["taker_did"],
        }:
            raise HTTPException(
                status_code=403,
                detail="only an Order party can sign a Dispute Statement",
            )
        try:
            package_resolver = _trade_order_rule_package_resolver(
                request,
                order_digest,
            )
        except RuntimeError as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Rule Package audit resolver unavailable",
            ) from exc

        _trade_dispute_idempotency_key(request)

        def _create_statement(created_at_value: str, moment: datetime) -> Any:
            try:
                return create_trade_dispute_statement(
                    identity,
                    review=review,
                    receipt=receipt,
                    order=order,
                    statement_type=body["statement_type"],
                    parent_statement_digests=body.get(
                        "parent_statement_digests", ()
                    ),
                    reason_codes=body.get("reason_codes", ()),
                    claim=body.get("claim"),
                    evidence=body.get("evidence", ()),
                    rule_action=body.get("rule_action"),
                    package_resolver=package_resolver,
                    created_at=created_at_value,
                    now=moment,
                )
            except TradeDisputeStatementResolutionError as exc:
                raise TradeDisputeStatementDependencyError(
                    "trade Dispute Statement dependency is unavailable"
                ) from exc

        preflight_moment = datetime.now(timezone.utc)
        if preflight_moment.microsecond == 0:
            preflight_moment = preflight_moment.replace(microsecond=1)
        preflight_created_at = preflight_moment.isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z")

        def _preflight_statement() -> None:
            statement = _create_statement(
                preflight_created_at,
                preflight_moment,
            )
            if statement.to_dict()["parent_statement_digests"]:
                store.assert_complete_parent_chain(
                    statement,
                    review=review,
                    receipt=receipt,
                    order=order,
                    package_resolver=package_resolver,
                )

        try:
            await run_in_threadpool(_preflight_statement)
        except TradeDisputeStatementDependencyError as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Dispute Statement dependency is unavailable",
                headers={"Retry-After": "1"},
            ) from exc
        except TradeDisputeStatementRejected as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except TradeDisputeStatementParentError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except TradeDisputeStatementStoreBusy as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Dispute Statement store is busy",
                headers={"Retry-After": "1"},
            ) from exc
        except TradeDisputeStatementStoreCapacity as exc:
            raise HTTPException(
                status_code=507,
                detail="trade Dispute Statement graph capacity exceeded",
            ) from exc
        except TradeDisputeStatementStoreError as exc:
            raise HTTPException(
                status_code=409,
                detail="trade Dispute Statement integrity conflict",
            ) from exc
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Dispute Statement preflight failed",
                headers={"Retry-After": "1"},
            ) from exc
        try:
            (
                operation_id,
                request_digest,
                creation_moment,
                created_at,
                reservation_created,
            ) = (
                _reserve_trade_dispute_statement_creation(
                    request,
                    body=body,
                    order_digest=order_digest,
                    execution_id=execution_id,
                    review_id=review_id,
                    author_did=identity.as_did(),
                )
            )
        except TradeDisputeStatementCreateConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except HTTPException:
            raise
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Dispute Statement idempotency reservation failed",
                headers={"Retry-After": "1"},
            ) from exc
        observed_at_ms = int(creation_moment.timestamp() * 1_000)

        async def _audit_creation_failure(
            reason_code: str,
        ) -> None:
            try:
                await run_in_threadpool(
                    _record_trade_dispute_statement_creation_failure,
                    request,
                    operation_id=operation_id,
                    request_digest=request_digest,
                    reason_code=reason_code,
                )
            except (OSError, RuntimeError, TypeError, ValueError) as exc:
                raise HTTPException(
                    status_code=503,
                    detail=(
                        "trade Dispute Statement failure audit is incomplete"
                    ),
                    headers={"Retry-After": "1"},
                ) from exc

        def _create_and_record_statement() -> Any:
            statement = _create_statement(created_at, creation_moment)
            if statement.to_dict()["parent_statement_digests"]:
                store.assert_complete_parent_chain(
                    statement,
                    review=review,
                    receipt=receipt,
                    order=order,
                    package_resolver=package_resolver,
                )
            return coordinator.record(
                statement,
                review=review,
                receipt=receipt,
                order=order,
                package_resolver=package_resolver,
                observed_at_ms=observed_at_ms,
            )

        try:
            result = await run_in_threadpool(_create_and_record_statement)
        except TradeDisputeStatementDependencyError as exc:
            await _audit_creation_failure("dependency-unavailable")
            raise HTTPException(
                status_code=503,
                detail="trade Dispute Statement dependency is unavailable",
                headers={"Retry-After": "1"},
            ) from exc
        except TradeDisputeStatementRejected as exc:
            await _audit_creation_failure("statement-rejected")
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except TradeDisputeStatementParentError as exc:
            await _audit_creation_failure("parent-chain-unavailable")
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except TradeDisputeStatementStoreBusy as exc:
            await _audit_creation_failure("store-busy")
            raise HTTPException(
                status_code=503,
                detail="trade Dispute Statement store is busy",
                headers={"Retry-After": "1"},
            ) from exc
        except TradeDisputeStatementStoreCapacity as exc:
            await _audit_creation_failure("store-capacity")
            raise HTTPException(
                status_code=507,
                detail="trade Dispute Statement capacity exceeded",
            ) from exc
        except TradeDisputeStatementStoreError as exc:
            await _audit_creation_failure("store-integrity-conflict")
            raise HTTPException(
                status_code=409,
                detail="trade Dispute Statement integrity conflict",
            ) from exc
        except (
            TradeDisputeStatementAuditError,
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
        ) as exc:
            await _audit_creation_failure("persistence-incomplete")
            raise HTTPException(
                status_code=503,
                detail="trade Dispute Statement persistence is incomplete",
                headers={"Retry-After": "1"},
            ) from exc
        digest = trade_dispute_statement_digest(
            result.statement,
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=package_resolver,
        )
        if not result.store_created:
            response.status_code = 200
        return {
            "status": "dispute-statement-signed",
            "order_digest": order_digest,
            "execution_id": execution_id,
            "review_id": review_id,
            "dispute_id": result.statement.dispute_id,
            "statement_id": result.statement.statement_id,
            "statement_digest": digest,
            "statement": result.statement.to_dict(),
            "statement_store_created": result.store_created,
            "audit_anchor_created": result.anchor_created,
            "audit_event_id": result.event.event_id,
            "operation_id": operation_id,
            "reservation_created": reservation_created,
            "claim_status": "signed-unadjudicated-claim",
            "claim_adjudicated_or_proven_true": False,
        }

    @app.post(
        "/api/v2/trade/orders/{order_digest}/execution-receipts/"
        "{execution_id}/reviews/{review_id}/dispute-statements/fetch"
    )
    async def v2_trade_dispute_statement_fetch(
        order_digest: str,
        execution_id: str,
        review_id: str,
        request: Request,
    ) -> Dict[str, Any]:
        """Fetch and verify one exact remote Statement without importing it."""

        from nth_dao.trade_rules import (
            TradeDisputeStatementFetchOutboxBusy,
            TradeDisputeStatementFetchOutboxCapacity,
            TradeDisputeStatementFetchOutboxConflict,
            TradeDisputeStatementFetchOutboxError,
            TradeDisputeStatementFetchRequestRejected,
            TradeDisputeStatementFetchResponse,
            create_trade_dispute_statement_fetch_request,
            trade_dispute_statement_fetch_request_digest,
            trade_dispute_statement_fetch_response_digest,
            verify_trade_dispute_statement_fetch_audit_event,
            verify_trade_dispute_statement_fetch_response,
        )
        from nth_dao.spine import SpineEvent

        _require_console_bearer_for_sensitive_read(request)
        try:
            body = await request.json()
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=400, detail="invalid JSON body") from exc
        if not isinstance(body, dict) or set(body) != {
            "target_url",
            "statement_digest",
        }:
            raise HTTPException(
                status_code=400,
                detail="body requires only target_url and statement_digest",
            )
        statement_digest = body.get("statement_digest")
        if (
            not isinstance(statement_digest, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", statement_digest) is None
        ):
            raise HTTPException(
                status_code=400,
                detail="statement_digest is invalid",
            )
        try:
            target_url = _normalize_configured_fed_peer(body["target_url"])
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        order, receipt, review = await _load_trade_dispute_review(
            request,
            order_digest=order_digest,
            execution_id=execution_id,
            review_id=review_id,
        )
        identity = _state_node_identity(request)
        if identity is None or not getattr(identity, "can_sign", False):
            raise HTTPException(
                status_code=503,
                detail="local signing identity unavailable",
            )
        requester_did = identity.as_did()
        order_document = order.to_dict()
        if requester_did == order_document["maker_did"]:
            responder_did = order_document["taker_did"]
        elif requester_did == order_document["taker_did"]:
            responder_did = order_document["maker_did"]
        else:
            raise HTTPException(
                status_code=403,
                detail="local identity is not a party to this Trade Order",
            )

        moment = datetime.now(timezone.utc)
        if moment.microsecond == 0:
            moment = moment.replace(microsecond=1)
        created_at = moment.isoformat(timespec="microseconds").replace(
            "+00:00",
            "Z",
        )
        not_after = (
            (moment + timedelta(minutes=5))
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        )
        try:
            candidate_request = create_trade_dispute_statement_fetch_request(
                identity,
                review=review,
                receipt=receipt,
                order=order,
                statement_digest=statement_digest,
                responder_did=responder_did,
                created_at=created_at,
                not_after=not_after,
                now=moment,
            )
        except TradeDisputeStatementFetchRequestRejected as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        outbox = _state_trade_dispute_statement_fetch_outbox(request)
        if outbox is None:
            raise HTTPException(
                status_code=503,
                detail="trade Dispute Statement fetch outbox unavailable",
            )
        observed_at_ns = time.time_ns()
        try:
            outbox_record, outbox_created = await run_in_threadpool(
                outbox.reserve,
                target_url,
                candidate_request,
                observed_at_ns=observed_at_ns,
            )
            (
                fetch_request,
                retained_response,
                retained_audit_event,
            ) = await run_in_threadpool(
                outbox_record.resolve,
                review=review,
                receipt=receipt,
                order=order,
            )
        except TradeDisputeStatementFetchOutboxBusy as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Dispute Statement fetch outbox is busy",
                headers={"Retry-After": "1"},
            ) from exc
        except TradeDisputeStatementFetchOutboxCapacity as exc:
            raise HTTPException(
                status_code=507,
                detail="trade Dispute Statement fetch outbox capacity exceeded",
            ) from exc
        except (
            TradeDisputeStatementFetchOutboxConflict,
            TradeDisputeStatementFetchOutboxError,
            OSError,
            TypeError,
            ValueError,
        ) as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Dispute Statement fetch outbox is inconsistent",
            ) from exc

        replayed_from_outbox = outbox_record.completed
        if replayed_from_outbox:
            if retained_response is None or retained_audit_event is None:
                raise HTTPException(
                    status_code=503,
                    detail="trade Dispute Statement fetch outbox is incomplete",
                )
            peer_status = 200
            peer_body = {
                "request_digest": outbox_record.request_digest,
                "response_digest": outbox_record.response_digest,
                "audit_event_id": outbox_record.audit_event_id,
                "audit_event": retained_audit_event.to_dict(),
                "response": retained_response.to_dict(),
            }
        else:
            try:
                outbox_record = await run_in_threadpool(
                    outbox.mark_attempt,
                    outbox_record,
                    updated_at_ns=time.time_ns(),
                )
                peer_status, peer_body = await run_in_threadpool(
                    _post_trade_dispute_statement_fetch_to_peer,
                    target_url,
                    order_digest,
                    execution_id,
                    review_id,
                    fetch_request.to_dict(),
                )
            except (OSError, TimeoutError, ValueError, urllib.error.URLError) as exc:
                try:
                    await run_in_threadpool(
                        outbox.note_failure,
                        outbox_record,
                        updated_at_ns=time.time_ns(),
                        error=type(exc).__name__,
                    )
                except TradeDisputeStatementFetchOutboxError:
                    logger.warning(
                        "unable to persist requester fetch failure",
                        exc_info=True,
                    )
                raise HTTPException(
                    status_code=502,
                    detail="signed Dispute Statement fetch request failed",
                ) from exc
            if not 200 <= peer_status < 300:
                try:
                    await run_in_threadpool(
                        outbox.note_failure,
                        outbox_record,
                        updated_at_ns=time.time_ns(),
                        error=f"peer-http-{peer_status}",
                    )
                except TradeDisputeStatementFetchOutboxError:
                    logger.warning(
                        "unable to persist requester fetch rejection",
                        exc_info=True,
                    )
                raise HTTPException(
                    status_code=502,
                    detail="trade peer rejected the signed Statement fetch",
                )
        try:
            response_document = peer_body["response"]
            remote_request_digest = peer_body["request_digest"]
            remote_response_digest = peer_body["response_digest"]
            remote_audit_event_id = peer_body["audit_event_id"]
            audit_event = SpineEvent.from_dict(peer_body["audit_event"])
            response = TradeDisputeStatementFetchResponse.from_dict(
                response_document,
                request=fetch_request,
                review=review,
                receipt=receipt,
                order=order,
            )
            request_digest = trade_dispute_statement_fetch_request_digest(
                fetch_request,
                review=review,
                receipt=receipt,
                order=order,
            )
            response_digest = trade_dispute_statement_fetch_response_digest(
                response,
                request=fetch_request,
                review=review,
                receipt=receipt,
                order=order,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=502,
                detail="trade peer returned an invalid signed fetch response",
            ) from exc
        verification_at = datetime.now(timezone.utc)
        if replayed_from_outbox:
            verification_at = datetime.fromisoformat(
                response.to_dict()["served_at"].replace("Z", "+00:00")
            )
        response_ok, _reason = verify_trade_dispute_statement_fetch_response(
            response,
            request=fetch_request,
            review=review,
            receipt=receipt,
            order=order,
            at=verification_at,
        )
        audit_ok, _audit_reason = verify_trade_dispute_statement_fetch_audit_event(
            audit_event,
            fetch_request,
            response,
            review=review,
            receipt=receipt,
            order=order,
        )
        if (
            not response_ok
            or not audit_ok
            or not isinstance(remote_request_digest, str)
            or not hmac.compare_digest(remote_request_digest, request_digest)
            or not isinstance(remote_response_digest, str)
            or not hmac.compare_digest(remote_response_digest, response_digest)
            or not isinstance(remote_audit_event_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", remote_audit_event_id) is None
            or not hmac.compare_digest(
                remote_audit_event_id,
                audit_event.event_id,
            )
        ):
            raise HTTPException(
                status_code=502,
                detail="trade peer returned an invalid signed fetch binding",
            )
        if not replayed_from_outbox:
            try:
                outbox_record, _completed = await run_in_threadpool(
                    outbox.complete,
                    outbox_record,
                    response,
                    audit_event,
                    updated_at_ns=time.time_ns(),
                )
            except TradeDisputeStatementFetchOutboxBusy as exc:
                raise HTTPException(
                    status_code=503,
                    detail="verified fetch response could not be persisted",
                    headers={"Retry-After": "1"},
                ) from exc
            except TradeDisputeStatementFetchOutboxCapacity as exc:
                raise HTTPException(
                    status_code=507,
                    detail="verified fetch response exceeds outbox capacity",
                ) from exc
            except (
                TradeDisputeStatementFetchOutboxConflict,
                TradeDisputeStatementFetchOutboxError,
            ) as exc:
                raise HTTPException(
                    status_code=503,
                    detail="verified fetch response persistence conflicted",
                ) from exc
        return {
            "status": "dispute-statement-fetched-verified",
            "order_digest": order_digest,
            "execution_id": execution_id,
            "review_id": review_id,
            "statement_digest": statement_digest,
            "request": fetch_request.to_dict(),
            "request_digest": request_digest,
            "response": response.to_dict(),
            "response_digest": response_digest,
            "remote_audit_event_id": remote_audit_event_id,
            "remote_audit_event": audit_event.to_dict(),
            "remote_audit_event_verified": True,
            "remote_audit_chain_verified": False,
            "source_url": target_url,
            "outbox_operation_id": outbox_record.operation_id,
            "outbox_generation": outbox_record.generation,
            "outbox_created": outbox_created,
            "replayed_from_outbox": replayed_from_outbox,
            "imported": False,
            "claim_adjudicated_or_proven_true": False,
        }

    @app.post(
        "/api/v2/trade/orders/{order_digest}/execution-receipts/"
        "{execution_id}/reviews/{review_id}/dispute-statements/"
        "{statement_digest}/deliver"
    )
    async def v2_trade_dispute_statement_deliver(
        order_digest: str,
        execution_id: str,
        review_id: str,
        statement_digest: str,
        request: Request,
    ) -> Dict[str, Any]:
        """Durably deliver one locally authored signed claim."""

        from nth_dao.trade_rules import (
            TradeDisputeStatementAcknowledgement,
            TradeDisputeStatementDeliveryRejected,
            TradeDisputeStatementDispatchBusy,
            TradeDisputeStatementDispatchCapacity,
            TradeDisputeStatementDispatchError,
            TradeDisputeStatementStoreBusy,
            TradeDisputeStatementStoreError,
            create_trade_dispute_statement_delivery,
            verify_trade_dispute_statement_acknowledgement,
            verify_trade_dispute_statement_delivery,
        )

        _require_console_bearer_for_sensitive_read(request)
        if re.fullmatch(r"sha256:[0-9a-f]{64}", statement_digest) is None:
            raise HTTPException(
                status_code=400,
                detail="statement_digest is invalid",
            )
        try:
            body = await request.json()
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=400, detail="invalid JSON body") from exc
        if not isinstance(body, dict) or set(body) != {"target_url"}:
            raise HTTPException(
                status_code=400,
                detail="body requires only target_url",
            )
        try:
            target_url = _normalize_configured_fed_peer(body["target_url"])
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        order, receipt, review = await _load_trade_dispute_review(
            request,
            order_digest=order_digest,
            execution_id=execution_id,
            review_id=review_id,
        )
        statement_store = _state_trade_dispute_statement_store(request)
        dispatch_store = _state_trade_dispute_statement_dispatch_store(request)
        dispatch = _state_trade_dispute_statement_dispatch(request)
        identity = _state_node_identity(request)
        if (
            statement_store is None
            or dispatch_store is None
            or dispatch is None
            or identity is None
            or not getattr(identity, "can_sign", False)
        ):
            raise HTTPException(
                status_code=503,
                detail="trade Dispute Statement dispatch runtime unavailable",
            )
        try:
            package_resolver = _trade_order_rule_package_resolver(
                request,
                order_digest,
            )
            statement = await run_in_threadpool(
                statement_store.get,
                statement_digest,
                review=review,
                receipt=receipt,
                order=order,
                package_resolver=package_resolver,
            )
        except TradeDisputeStatementStoreBusy as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Dispute Statement store is busy",
                headers={"Retry-After": "1"},
            ) from exc
        except TradeDisputeStatementStoreError as exc:
            raise HTTPException(
                status_code=409,
                detail="trade Dispute Statement integrity conflict",
            ) from exc
        except RuntimeError as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Rule Package audit resolver unavailable",
            ) from exc
        if statement is None:
            raise HTTPException(status_code=404, detail="Dispute Statement not found")
        if statement.to_dict()["author_did"] != identity.as_did():
            raise HTTPException(
                status_code=403,
                detail="only the local Statement author can deliver this claim",
            )

        def _acknowledged_response(record: Any) -> Dict[str, Any]:
            acknowledgement = record.acknowledgement.to_dict()
            return {
                "status": "dispute-statement-delivered",
                "order_digest": order_digest,
                "execution_id": execution_id,
                "review_id": review_id,
                "statement_digest": statement_digest,
                "delivery": record.delivery.to_dict(),
                "delivery_digest": record.delivery_digest,
                "acknowledgement": acknowledgement,
                "acknowledgement_digest": record.acknowledgement_digest,
                "remote_audit_event_id": record.remote_event_id,
                "remote_received_at": acknowledgement["received_at"],
                "generation": record.generation,
                "attempts": record.attempts,
                "acknowledgement_persisted": True,
                "claim_adjudicated_or_proven_true": False,
            }

        try:
            existing_ack = await run_in_threadpool(
                dispatch.recover_acknowledgement,
                statement_digest,
            )
            if existing_ack is not None:
                if existing_ack.target_url != target_url:
                    raise HTTPException(
                        status_code=409,
                        detail=(
                            "Dispute Statement was acknowledged by a different "
                            "peer target"
                        ),
                    )
                return _acknowledged_response(existing_ack)
            pending = await run_in_threadpool(
                dispatch_store.get,
                statement_digest,
            )
        except TradeDisputeStatementDispatchBusy as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Dispute Statement dispatch is busy",
                headers={"Retry-After": "1"},
            ) from exc
        except TradeDisputeStatementDispatchError as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Dispute Statement dispatch recovery failed",
                headers={"Retry-After": "1"},
            ) from exc

        moment = datetime.now(timezone.utc)
        if moment.microsecond == 0:
            moment += timedelta(microseconds=1)
        now_ms = int(moment.timestamp() * 1_000)
        created_at = moment.isoformat(timespec="microseconds").replace(
            "+00:00", "Z"
        )
        try:
            if pending is not None:
                if pending.target_url != target_url:
                    raise TradeDisputeStatementDispatchError(
                        "pending dispatch targets a different peer"
                    )
                ok, reason = verify_trade_dispute_statement_delivery(
                    pending.delivery,
                    review=review,
                    receipt=receipt,
                    order=order,
                    recipient_did=pending.delivery.to_dict()["recipient_did"],
                    at=moment,
                )
                if ok:
                    delivery = pending.delivery
                elif "expired" in reason:
                    replacement = create_trade_dispute_statement_delivery(
                        identity,
                        statement=statement,
                        review=review,
                        receipt=receipt,
                        order=order,
                        package_resolver=package_resolver,
                        created_at=created_at,
                        not_after=(moment + timedelta(minutes=5)).isoformat(
                            timespec="microseconds"
                        ).replace("+00:00", "Z"),
                        now=moment,
                    )
                    pending = await run_in_threadpool(
                        dispatch_store.replace_expired,
                        replacement,
                        review=review,
                        receipt=receipt,
                        order=order,
                        target_url=target_url,
                        now_ms=now_ms,
                    )
                    delivery = pending.delivery
                else:
                    raise TradeDisputeStatementDispatchError(
                        f"pending delivery is not usable: {reason}"
                    )
            else:
                delivery = create_trade_dispute_statement_delivery(
                    identity,
                    statement=statement,
                    review=review,
                    receipt=receipt,
                    order=order,
                    package_resolver=package_resolver,
                    created_at=created_at,
                    not_after=(moment + timedelta(minutes=5)).isoformat(
                        timespec="microseconds"
                    ).replace("+00:00", "Z"),
                    now=moment,
                )
                pending = await run_in_threadpool(
                    dispatch_store.prepare,
                    delivery,
                    review=review,
                    receipt=receipt,
                    order=order,
                    target_url=target_url,
                    now_ms=now_ms,
                )
            pending, lease_token = await run_in_threadpool(
                dispatch_store.acquire_send_lease,
                statement_digest,
            )
            delivery = pending.delivery
        except TradeDisputeStatementDeliveryRejected as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except TradeDisputeStatementDispatchCapacity as exc:
            raise HTTPException(
                status_code=507,
                detail="trade Dispute Statement dispatch capacity exceeded",
            ) from exc
        except TradeDisputeStatementDispatchBusy as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Dispute Statement dispatch is busy",
                headers={"Retry-After": "1"},
            ) from exc
        except TradeDisputeStatementDispatchError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

        async def _note_failure(message: str) -> None:
            try:
                await run_in_threadpool(
                    dispatch_store.note_failure,
                    statement_digest,
                    error=message,
                    lease_token=lease_token,
                )
            except (OSError, RuntimeError, TypeError, ValueError) as exc:
                logger.warning(
                    "unable to record failed Dispute Statement dispatch: %s",
                    type(exc).__name__,
                )

        try:
            peer_status, peer_body = await run_in_threadpool(
                _post_trade_dispute_statement_delivery_to_peer,
                target_url,
                order_digest,
                execution_id,
                review_id,
                delivery.to_dict(),
            )
        except (OSError, TimeoutError, ValueError, urllib.error.URLError) as exc:
            await _note_failure(f"{type(exc).__name__}: {exc}")
            raise HTTPException(
                status_code=502,
                detail=(
                    "signed Dispute Statement is retained locally but peer "
                    "delivery failed"
                ),
            ) from exc
        if not 200 <= peer_status < 300:
            await _note_failure(f"peer returned HTTP {peer_status}")
            raise HTTPException(
                status_code=502,
                detail=(
                    "signed Dispute Statement is retained locally but the peer "
                    "rejected delivery"
                ),
            )
        try:
            acknowledgement = TradeDisputeStatementAcknowledgement.from_dict(
                peer_body["acknowledgement"]
            )
            peer_event_id = peer_body["audit_event_id"]
        except (KeyError, TypeError, ValueError) as exc:
            await _note_failure("peer returned an invalid acknowledgement")
            raise HTTPException(
                status_code=502,
                detail="peer returned an invalid signed acknowledgement",
            ) from exc
        acknowledgement_ok, _acknowledgement_reason = (
            verify_trade_dispute_statement_acknowledgement(
                acknowledgement,
                delivery=delivery,
                review=review,
                receipt=receipt,
                order=order,
                at=datetime.now(timezone.utc),
            )
        )
        acknowledgement_document = acknowledgement.to_dict()
        if (
            not acknowledgement_ok
            or not isinstance(peer_event_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", peer_event_id) is None
            or acknowledgement_document["audit_event_id"] != peer_event_id
        ):
            await _note_failure(
                "peer returned an invalid acknowledgement binding"
            )
            raise HTTPException(
                status_code=502,
                detail="peer returned an invalid signed acknowledgement",
            )
        try:
            retained = await run_in_threadpool(
                dispatch.acknowledge,
                statement_digest,
                acknowledgement,
                remote_event_id=peer_event_id,
                lease_token=lease_token,
            )
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            try:
                await run_in_threadpool(
                    dispatch_store.release_send_lease,
                    statement_digest,
                    lease_token=lease_token,
                )
            except (OSError, RuntimeError, TypeError, ValueError):
                pass
            recovery_worker = getattr(
                request.app.state.nth,
                "trade_dispute_statement_recovery_worker",
                None,
            )
            if recovery_worker is not None:
                try:
                    queued = recovery_worker.wake(
                        statement_digest,
                        urgent_for_s=5.0,
                    )
                    if not queued:
                        logger.warning(
                            "trade Dispute Statement targeted recovery queue is full"
                        )
                except (RuntimeError, TypeError, ValueError) as wake_exc:
                    logger.warning(
                        "trade Dispute Statement targeted recovery wake failed (%s)",
                        type(wake_exc).__name__,
                    )
            raise HTTPException(
                status_code=503,
                detail=(
                    "remote acknowledgement verified but local persistence "
                    "is incomplete"
                ),
                headers={"Retry-After": "1"},
            ) from exc
        return _acknowledged_response(retained)

    @app.post(
        "/api/v2/trade/orders/{order_digest}/execution-receipts/"
        "{execution_id}/reviews/{review_id}/deliver"
    )
    async def v2_trade_receipt_review_deliver(
        order_digest: str,
        execution_id: str,
        review_id: str,
        request: Request,
    ) -> Dict[str, Any]:
        """Durably deliver one locally signed Review to its executor."""

        from nth_dao.trade_rules import (
            RuleResolutionPolicy,
            TradeReceiptReviewAcknowledgement,
            TradeReceiptReviewAuditError,
            TradeReceiptReviewConflict,
            TradeReceiptReviewDeliveryRejected,
            TradeReceiptReviewDispatchBusy,
            TradeReceiptReviewDispatchCapacity,
            TradeReceiptReviewDispatchError,
            TradeReceiptReviewOutboxBusy,
            TradeReceiptReviewOutboxCapacity,
            TradeReceiptReviewOutboxError,
            TradeReceiptReviewStoreBusy,
            TradeReceiptReviewStoreError,
            create_trade_receipt_review_delivery,
            receipt_review_digest,
            verify_trade_receipt_review_delivery,
        )

        _require_console_bearer_for_sensitive_read(request)
        if re.fullmatch(
            r"nth-trade-review-sha256:[0-9a-f]{64}",
            review_id,
        ) is None:
            raise HTTPException(status_code=400, detail="review_id is invalid")
        try:
            body = await request.json()
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=400, detail="invalid JSON body") from exc
        if not isinstance(body, dict) or set(body) != {"target_url"}:
            raise HTTPException(
                status_code=400,
                detail="body requires only target_url",
            )
        try:
            target_url = _normalize_configured_fed_peer(body["target_url"])
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        order, receipt = await _load_trade_order_execution_receipt(
            request,
            order_digest=order_digest,
            execution_id=execution_id,
        )
        review_store = _state_trade_receipt_review_store(request)
        dispatch = _state_trade_receipt_review_dispatch(request)
        dispatch_store = _state_trade_receipt_review_dispatch_store(request)
        coordinator = _state_trade_receipt_review_coordinator(request)
        identity = _state_node_identity(request)
        if (
            review_store is None
            or dispatch is None
            or dispatch_store is None
            or coordinator is None
            or identity is None
            or not getattr(identity, "can_sign", False)
        ):
            raise HTTPException(
                status_code=503,
                detail="trade Receipt Review dispatch runtime unavailable",
            )
        try:
            review = await run_in_threadpool(
                review_store.get,
                review_id,
                receipt=receipt,
                order=order,
            )
        except TradeReceiptReviewStoreBusy as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Receipt Review store is busy",
                headers={"Retry-After": "1"},
            ) from exc
        except TradeReceiptReviewStoreError as exc:
            raise HTTPException(
                status_code=409,
                detail="trade Receipt Review integrity conflict",
            ) from exc
        if review is None:
            raise HTTPException(status_code=404, detail="Receipt Review not found")
        if review.to_dict()["execution_id"] != execution_id:
            raise HTTPException(
                status_code=409,
                detail="Receipt Review does not match execution_id",
            )
        review_digest = receipt_review_digest(
            review,
            receipt=receipt,
            order=order,
        )
        try:
            policy_snapshots = await run_in_threadpool(
                coordinator.policy_snapshots,
                review_digest,
            )
            if policy_snapshots is None:
                review_document = review.to_dict()
                order_document = order.to_dict()
                policy_document = (
                    order_document["snapshot"]["proposal"]["taker_policy"]
                    if review_document["reviewer_role"] == "taker"
                    else order_document["snapshot"]["acceptance"]["maker_policy"]
                )
                verifier_policy = RuleResolutionPolicy.from_dict(
                    policy_document
                )
                adapter_policy = getattr(
                    request.app.state.nth,
                    "trade_execution_adapter_policy",
                    None,
                )
                if adapter_policy is None:
                    raise TradeReceiptReviewOutboxError(
                        "legacy Review has no recoverable Adapter Policy snapshot"
                    )
                await run_in_threadpool(
                    coordinator.record,
                    review,
                    receipt=receipt,
                    order=order,
                    verifier_policy=verifier_policy,
                    adapter_policy=adapter_policy,
                )
                policy_snapshots = await run_in_threadpool(
                    coordinator.policy_snapshots,
                    review_digest,
                )
            if policy_snapshots is None:
                raise TradeReceiptReviewOutboxError(
                    "Receipt Review policy snapshots are unavailable"
                )
            verifier_policy, adapter_policy = policy_snapshots
        except TradeReceiptReviewOutboxBusy as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Receipt Review audit outbox is busy",
                headers={"Retry-After": "1"},
            ) from exc
        except TradeReceiptReviewOutboxCapacity as exc:
            raise HTTPException(
                status_code=507,
                detail="trade Receipt Review audit outbox capacity exceeded",
            ) from exc
        except TradeReceiptReviewAuditError as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Receipt Review audit recovery is incomplete",
                headers={"Retry-After": "1"},
            ) from exc
        except TradeReceiptReviewConflict as exc:
            raise HTTPException(
                status_code=409,
                detail="Receipt Review conflicts with retained signed bytes",
            ) from exc
        except (TradeReceiptReviewOutboxError, TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=409,
                detail=(
                    "Receipt Review policy snapshots are unavailable or invalid"
                ),
            ) from exc

        def _acknowledged_response(acknowledgement: Any) -> Dict[str, Any]:
            document = acknowledgement.acknowledgement.to_dict()
            return {
                "status": "receipt-review-delivered",
                "order_digest": acknowledgement.order_digest,
                "execution_id": execution_id,
                "review_id": review_id,
                "review_digest": acknowledgement.review_digest,
                "delivery_digest": acknowledgement.delivery_digest,
                "acknowledgement": document,
                "acknowledgement_digest": (
                    acknowledgement.acknowledgement_digest
                ),
                "remote_audit_event_id": acknowledgement.remote_event_id,
                "remote_received_at": document["received_at"],
                "acknowledgement_persisted": True,
                "delivery_quality_or_payment_proven": False,
            }

        try:
            existing_ack = await run_in_threadpool(
                dispatch.recover_acknowledgement,
                review_digest,
            )
            if existing_ack is not None:
                if existing_ack.target_url != target_url:
                    raise HTTPException(
                        status_code=409,
                        detail=(
                            "Receipt Review was acknowledged by a different peer target"
                        ),
                    )
                return _acknowledged_response(existing_ack)
            pending, _ack = await run_in_threadpool(
                dispatch_store.get_state,
                review_digest,
            )
        except TradeReceiptReviewDispatchBusy as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Receipt Review dispatch is busy",
                headers={"Retry-After": "1"},
            ) from exc
        except TradeReceiptReviewDispatchError as exc:
            raise HTTPException(
                status_code=503,
                detail=f"dispatch recovery failed: {exc}",
                headers={"Retry-After": "1"},
            ) from exc

        moment = datetime.now(timezone.utc).replace(microsecond=0)
        now_ms = int(moment.timestamp() * 1_000)
        created_at = moment.isoformat().replace("+00:00", "Z")
        try:
            if pending is not None:
                if pending.target_url != target_url:
                    raise TradeReceiptReviewDispatchError(
                        "pending dispatch targets a different peer"
                    )
                ok, reason = verify_trade_receipt_review_delivery(
                    pending.delivery,
                    receipt=receipt,
                    order=order,
                    recipient_did=(
                        pending.delivery.to_dict()["recipient_did"]
                    ),
                    at=moment,
                )
                if ok:
                    delivery = pending.delivery
                elif "expired" in reason:
                    replacement = create_trade_receipt_review_delivery(
                        identity,
                        review=review,
                        receipt=receipt,
                        order=order,
                        verifier_policy=pending.delivery.verifier_policy,
                        adapter_policy=pending.delivery.adapter_policy,
                        created_at=created_at,
                        not_after=(moment + timedelta(minutes=5)).isoformat().replace(
                            "+00:00", "Z"
                        ),
                        now=moment,
                    )
                    pending = await run_in_threadpool(
                        dispatch.renew_expired,
                        replacement,
                        receipt=receipt,
                        order=order,
                        target_url=target_url,
                        now_ms=now_ms,
                    )
                    delivery = pending.delivery
                else:
                    raise TradeReceiptReviewDispatchError(
                        f"pending delivery is not usable: {reason}"
                    )
            else:
                delivery = create_trade_receipt_review_delivery(
                    identity,
                    review=review,
                    receipt=receipt,
                    order=order,
                    verifier_policy=verifier_policy,
                    adapter_policy=adapter_policy,
                    created_at=created_at,
                    not_after=(moment + timedelta(minutes=5)).isoformat().replace(
                        "+00:00", "Z"
                    ),
                    now=moment,
                )
                pending = await run_in_threadpool(
                    dispatch.prepare,
                    delivery,
                    receipt=receipt,
                    order=order,
                    target_url=target_url,
                    now_ms=now_ms,
                )
                if pending.acknowledged:
                    existing_ack = await run_in_threadpool(
                        dispatch.recover_acknowledgement,
                        review_digest,
                    )
                    if existing_ack is None:
                        raise TradeReceiptReviewDispatchError(
                            "acknowledged dispatch state disappeared"
                        )
                    return _acknowledged_response(existing_ack)
                delivery = pending.delivery
        except TradeReceiptReviewDeliveryRejected as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except TradeReceiptReviewDispatchCapacity as exc:
            raise HTTPException(
                status_code=507,
                detail="trade Receipt Review dispatch capacity exceeded",
            ) from exc
        except TradeReceiptReviewDispatchBusy as exc:
            raise HTTPException(
                status_code=503,
                detail="trade Receipt Review dispatch is busy",
                headers={"Retry-After": "1"},
            ) from exc
        except TradeReceiptReviewDispatchError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

        async def _note_failure(message: str) -> None:
            try:
                await run_in_threadpool(
                    dispatch.failed,
                    review_digest,
                    error=message,
                )
            except (OSError, RuntimeError, TypeError, ValueError) as exc:
                logger.warning(
                    "unable to record failed Receipt Review dispatch: %s",
                    type(exc).__name__,
                )

        try:
            peer_status, peer_body = await run_in_threadpool(
                _post_trade_receipt_review_delivery_to_peer,
                target_url,
                order_digest,
                execution_id,
                delivery.to_dict(),
            )
        except (OSError, TimeoutError, ValueError, urllib.error.URLError) as exc:
            await _note_failure(str(exc))
            raise HTTPException(
                status_code=502,
                detail=(
                    f"signed Review is retained locally but peer delivery failed: {exc}"
                ),
            ) from exc
        if not 200 <= peer_status < 300:
            await _note_failure(f"peer returned HTTP {peer_status}")
            raise HTTPException(
                status_code=502,
                detail=(
                    "signed Review is retained locally but the peer "
                    f"rejected delivery with HTTP {peer_status}"
                ),
            )
        try:
            acknowledgement = TradeReceiptReviewAcknowledgement.from_dict(
                peer_body["acknowledgement"]
            )
            peer_event_id = peer_body["audit_event_id"]
        except (KeyError, TypeError, ValueError) as exc:
            await _note_failure(f"invalid acknowledgement: {exc}")
            raise HTTPException(
                status_code=502,
                detail="peer returned an invalid signed acknowledgement",
            ) from exc
        try:
            retained = await run_in_threadpool(
                dispatch.acknowledge,
                delivery,
                acknowledgement,
                receipt=receipt,
                order=order,
                target_url=target_url,
                remote_event_id=peer_event_id,
            )
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail=(
                    "remote acknowledgement verified but local persistence "
                    "is incomplete"
                ),
                headers={"Retry-After": "1"},
            ) from exc
        return _acknowledged_response(retained)

    @app.get("/api/v2/trade/offers")
    def v2_trade_offer_list(
        request: Request,
        cursor: str = "",
        limit: int = 100,
    ) -> Dict[str, Any]:
        """Return lifecycle projections; conflicts are visible, never hidden."""
        from nth_dao.trade_rules import (
            OfferStoreBusyError,
            OfferStoreCryptoUnavailableError,
            OfferStoreError,
        )

        if isinstance(limit, bool) or not 1 <= limit <= 500:
            raise HTTPException(status_code=400, detail="limit must be in 1..500")
        try:
            after_key = _decode_trade_offer_cursor(cursor) if cursor else None
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        store = _state_trade_offer_store(request)
        if store is None:
            raise HTTPException(status_code=503, detail="trade offer store unavailable")
        try:
            views = store.list_chains()
            _verify_trade_offer_spine_anchors(request, store)
            if after_key is not None:
                views = tuple(
                    view
                    for view in views
                    if (view.publisher_did, view.offer_id) > after_key
                )
            selected = views[:limit + 1]
            page = selected[:limit]
            return {
                "items": [
                _trade_offer_chain_to_wire(view)
                    for view in page
                ],
                "next_cursor": (
                    _encode_trade_offer_cursor(page[-1])
                    if len(selected) > limit and page
                    else ""
                ),
            }
        except (OfferStoreBusyError, OfferStoreCryptoUnavailableError) as exc:
            raise HTTPException(
                status_code=503,
                detail=str(exc),
                headers={"Retry-After": "1"},
            ) from exc
        except OfferStoreError as exc:
            raise HTTPException(
                status_code=503,
                detail=f"trade offer store integrity failure: {exc}",
            ) from exc

    @app.get("/api/v2/trade/offers/{digest}")
    def v2_trade_offer_get(
        digest: str, request: Request,
    ) -> Dict[str, Any]:
        """Return one exact content-addressed signed offer."""
        from nth_dao.trade_rules import (
            OfferStoreBusyError,
            OfferStoreCryptoUnavailableError,
            OfferStoreError,
        )

        store = _state_trade_offer_store(request)
        if store is None:
            raise HTTPException(status_code=503, detail="trade offer store unavailable")
        try:
            record = store.get_record(digest)
            _verify_trade_offer_spine_anchors(request, store)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except (OfferStoreBusyError, OfferStoreCryptoUnavailableError) as exc:
            raise HTTPException(
                status_code=503,
                detail=str(exc),
                headers={"Retry-After": "1"},
            ) from exc
        except OfferStoreError as exc:
            raise HTTPException(
                status_code=503,
                detail=f"trade offer store integrity failure: {exc}",
            ) from exc
        if record is None:
            raise HTTPException(status_code=404, detail="trade offer not found")
        identity = _state_node_identity(request)
        local_did = (
            identity.as_did()
            if identity is not None and hasattr(identity, "as_did")
            else ""
        )
        historically_local = (
            record.source_kind == "local-operator"
            and record.source_id == record.offer.publisher_did
        )
        currently_local = (
            bool(local_did) and record.offer.publisher_did == local_did
        )
        authority = (
            "local-publisher"
            if historically_local or currently_local
            else "remote-publisher"
        )
        return {
            "digest": digest,
            "offer": record.offer.to_dict(),
            "resource_descriptors": _market_offer_descriptor_inspection(
                record.offer,
                workspace=_state_workspace(request),
            ),
            "discoveries": [],
            "verification": {
                "offer_signature_valid": True,
                "announcement_binding_valid": None,
                "source_did_bound": None,
                "recent_source_verified": None,
                "head_chain_valid": None,
                "publisher_head_claim_valid": None,
            },
            "authority": authority,
            "storage_provenance": {
                "source_kind": record.source_kind,
                "source_id": record.source_id,
            },
            "head_claim": None,
            "actionable": False,
            "warning": (
                "A valid signature proves authorship, not availability, fairness, "
                "ownership, or settlement. Create a new bilateral Agreement "
                "before execution."
            ),
        }

    @app.post("/api/v2/trade/offers/{digest}/announce")
    def v2_trade_offer_announce(
        digest: str,
        body: AnnounceTradeOfferBody,
        request: Request,
    ) -> Dict[str, Any]:
        """Publish one idempotent discovery hint for a local signed Offer."""
        _require_console_bearer_for_sensitive_read(request)
        from nth_dao.trade_rules import OfferStoreError

        store = _state_trade_offer_store(request)
        identity = _state_node_identity(request)
        if store is None or _state_workspace(request) is None:
            raise HTTPException(status_code=503, detail="trade storage unavailable")
        if identity is None or not getattr(identity, "can_sign", False):
            raise HTTPException(status_code=503, detail="signing identity unavailable")
        try:
            offer = store.get(digest)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except OfferStoreError as exc:
            raise HTTPException(
                status_code=503,
                detail="trade offer store integrity check failed",
            ) from exc
        if offer is None:
            raise HTTPException(status_code=404, detail="trade offer not found")
        try:
            announcement, published = _ensure_local_trade_offer_announcement(
                request,
                store,
                offer,
                digest,
                capability_set=body.capability_set,
                availability_summary=body.availability_summary,
                discovery_ttl_seconds=body.discovery_ttl_seconds,
                match_capability_set="capability_set" in body.model_fields_set,
                match_availability_summary=(
                    "availability_summary" in body.model_fields_set
                ),
            )
        except MarketPublishExpired as exc:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "trade-offer-expired",
                    "message": str(exc),
                    "offer_digest": exc.digest,
                    "offer_id": exc.offer_id,
                    "retryable": False,
                },
            ) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except TimeoutError as exc:
            raise HTTPException(
                status_code=503,
                detail="Trade Offer announcement is busy",
                headers={"Retry-After": "1"},
            ) from exc
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {
            "announcement": _market_announcement_to_wire(announcement),
            "published": published,
        }

    @app.get("/api/v2/trade/federation/offers/{digest}")
    def v2_trade_offer_federation_get(
        digest: str,
        request: Request,
    ) -> Dict[str, Any]:
        """Serve an exact Offer only while this node publicly announces it."""
        from nth_dao.trade_rules import OfferStoreError

        store = _state_trade_offer_store(request)
        workspace = _state_workspace(request)
        if store is None or workspace is None:
            raise HTTPException(status_code=503, detail="trade storage unavailable")
        _require_trade_offer_public_read_budget(request)
        try:
            feed = _state_market_feed(request)
            announcement = feed.find_live_trade_offer_announcement(digest)
            if announcement is None:
                raise HTTPException(
                    status_code=404,
                    detail="announced offer not found",
                )
            offer = store.get(digest)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(
                status_code=503,
                detail="Trade Offer public index is temporarily unavailable",
            ) from exc
        except OfferStoreError as exc:
            raise HTTPException(
                status_code=503,
                detail="trade offer store integrity check failed",
            ) from exc
        if offer is None:
            raise HTTPException(status_code=404, detail="announced offer not found")
        _verify_trade_offer_spine_anchors(request, store)
        try:
            feed.require_listing_binding(announcement)
        except ValueError:
            raise HTTPException(status_code=404, detail="announced offer not found")
        return offer.to_dict()

    @app.get(
        "/api/v2/trade/federation/offers/{offer_digest}/rule-packages/{package_digest}"
    )
    def v2_trade_rule_package_federation_get(
        offer_digest: str,
        package_digest: str,
        request: Request,
    ) -> Any:
        """Serve one verified package bundle through a live local Offer."""

        from fastapi.responses import Response
        from nth_dao.trade_rules import (
            RulePackageBundleRejected,
            build_rule_package_bundle,
            rule_package_bundle_bytes,
            sign_offer_package_binding,
        )

        _require_trade_rule_package_request_budget(request)
        semaphore = _trade_rule_package_serve_semaphore(request)
        if not semaphore.acquire(blocking=False):
            raise HTTPException(
                status_code=503,
                detail="Trade Rule Package encoder is busy",
                headers={"Retry-After": "1"},
            )
        try:
            package, offer = _load_public_trade_rule_package(
                request,
                offer_digest=offer_digest,
                package_digest=package_digest,
            )
            etag = _trade_rule_package_etag(offer_digest, package_digest)
            response_headers = {
                "ETag": etag,
                "X-NTH-Offer-Digest": offer_digest,
                "X-NTH-Package-Digest": package_digest,
                "Cache-Control": "public, max-age=300",
            }
            if _if_none_match_matches(request, etag):
                return Response(status_code=304, headers=response_headers)
            _require_trade_rule_package_byte_budget(
                request,
                _trade_rule_package_wire_cost_upper_bound(package),
            )
            try:
                binding = sign_offer_package_binding(
                    _state_node_identity(request),
                    offer_digest=offer_digest,
                    package_digest=package.digest,
                    created=offer.to_dict()["published_at"],
                )
                raw = rule_package_bundle_bytes(build_rule_package_bundle(
                    package,
                    offer_package_binding=binding,
                ))
            except RulePackageBundleRejected as exc:
                raise HTTPException(
                    status_code=503,
                    detail="public Rule Package bundle verification failed",
                ) from exc
            response_headers["Content-Length"] = str(len(raw))
            return Response(
                content=raw,
                media_type="application/vnd.nth-dao.trade-rule-package+json",
                headers=response_headers,
            )
        finally:
            semaphore.release()

    @app.get(
        "/api/v2/trade/federation/offers/{offer_digest}/rule-packages/"
        "{package_digest}/recognition-proof"
    )
    def v2_trade_rule_recognition_federation_get(
        offer_digest: str,
        package_digest: str,
        request: Request,
    ) -> Any:
        """Serve audited observed Recognition chains for one public Package."""

        from fastapi.responses import Response
        from nth_dao.trade_rules import (
            RuleRecognitionAuditError,
            RuleRecognitionProofBundleRejected,
            RuleRecognitionStoreError,
            build_rule_recognition_proof_bundle,
            sign_offer_package_binding,
            trade_canonical_json,
        )

        if not _rule_recognition_federation_disclosure_enabled(request):
            raise HTTPException(
                status_code=404,
                detail="Rule Recognition federation disclosure is disabled",
            )
        issuer_allowlist = _rule_recognition_federation_issuer_allowlist(
            request
        )
        if not issuer_allowlist:
            raise HTTPException(
                status_code=404,
                detail="Rule Recognition federation issuer allowlist is empty",
            )
        _require_trade_rule_package_request_budget(request)
        semaphore = _trade_rule_package_serve_semaphore(request)
        if not semaphore.acquire(blocking=False):
            raise HTTPException(
                status_code=503,
                detail="Trade Rule Recognition proof encoder is busy",
                headers={"Retry-After": "1"},
            )
        try:
            package, offer = _load_public_trade_rule_package(
                request,
                offer_digest=offer_digest,
                package_digest=package_digest,
            )
            coordinator = _state_trade_rule_recognition_audit(request)
            if coordinator is None:
                raise HTTPException(
                    status_code=503,
                    detail="signed Recognition audit unavailable",
                )
            try:
                statements = coordinator.verified_statements(
                    package=package,
                )
                if "*" not in issuer_allowlist:
                    statements = tuple(
                        statement
                        for statement in statements
                        if statement.to_dict()["issuer_did"]
                        in issuer_allowlist
                    )
                binding = sign_offer_package_binding(
                    _state_node_identity(request),
                    offer_digest=offer_digest,
                    package_digest=package.digest,
                    created=offer.to_dict()["published_at"],
                )
                identity = _state_node_identity(request)
                raw = _cached_rule_recognition_proof_bytes(
                    request,
                    cache_key=(
                        offer_digest,
                        package_digest,
                        tuple(statement.digest for statement in statements),
                    ),
                    build=lambda: trade_canonical_json(
                        build_rule_recognition_proof_bundle(
                            package,
                            statements,
                            offer_package_binding=binding,
                            observer_identity=identity,
                        )
                    ),
                )
            except (
                RuleRecognitionAuditError,
                RuleRecognitionProofBundleRejected,
                RuleRecognitionStoreError,
                RuntimeError,
                TypeError,
                ValueError,
            ) as exc:
                raise HTTPException(
                    status_code=503,
                    detail=(
                        "public Rule Recognition proof integrity verification failed"
                    ),
                ) from exc
            etag = f'"sha256:{hashlib.sha256(raw).hexdigest()}"'
            response_headers = {
                "ETag": etag,
                "X-NTH-Offer-Digest": offer_digest,
                "X-NTH-Package-Digest": package_digest,
                "X-NTH-Recognition-Semantics": "observed-not-globally-fresh",
                "X-NTH-Recognition-Disclosure": "operator-enabled",
                "X-NTH-Trust-Granted": "false",
                "X-NTH-Execution-Authorized": "false",
                "Cache-Control": "public, max-age=30",
            }
            if _if_none_match_matches(request, etag):
                return Response(status_code=304, headers=response_headers)
            _require_trade_rule_package_byte_budget(request, len(raw))
            response_headers["Content-Length"] = str(len(raw))
            return Response(
                content=raw,
                media_type=(
                    "application/vnd.nth-dao.trade-rule-recognition-proof+json"
                ),
                headers=response_headers,
            )
        finally:
            semaphore.release()

    @app.get(
        "/api/v2/trade/federation/offers/{offer_digest}/rule-packages/"
        "{package_digest}/recognition-proof-pages/{page_index}"
    )
    def v2_trade_rule_recognition_federation_page_get(
        offer_digest: str,
        package_digest: str,
        page_index: int,
        request: Request,
    ) -> Any:
        """Serve one page from a cached, signed Recognition observation."""

        from fastapi.responses import Response
        from nth_dao.trade_rules import (
            MAX_RULE_RECOGNITION_PROOF_PAGES,
            RuleRecognitionAuditError,
            RuleRecognitionProofBundleRejected,
            RuleRecognitionStoreError,
            build_rule_recognition_proof_pages,
            parse_trade_json,
            sign_offer_package_binding,
            trade_canonical_json,
        )

        if not 0 <= page_index < MAX_RULE_RECOGNITION_PROOF_PAGES:
            raise HTTPException(
                status_code=404,
                detail="Rule Recognition proof page not found",
            )
        if not _rule_recognition_federation_disclosure_enabled(request):
            raise HTTPException(
                status_code=404,
                detail="Rule Recognition federation disclosure is disabled",
            )
        issuer_allowlist = _rule_recognition_federation_issuer_allowlist(
            request
        )
        if not issuer_allowlist:
            raise HTTPException(
                status_code=404,
                detail="Rule Recognition federation issuer allowlist is empty",
            )
        _require_trade_rule_package_request_budget(request)
        semaphore = _trade_rule_package_serve_semaphore(request)
        if not semaphore.acquire(blocking=False):
            raise HTTPException(
                status_code=503,
                detail="Trade Rule Recognition proof encoder is busy",
                headers={"Retry-After": "1"},
            )
        try:
            package, offer = _load_public_trade_rule_package(
                request,
                offer_digest=offer_digest,
                package_digest=package_digest,
            )
            coordinator = _state_trade_rule_recognition_audit(request)
            if coordinator is None:
                raise HTTPException(
                    status_code=503,
                    detail="signed Recognition audit unavailable",
                )
            try:
                statements = coordinator.verified_statements(package=package)
                if "*" not in issuer_allowlist:
                    statements = tuple(
                        statement
                        for statement in statements
                        if statement.to_dict()["issuer_did"]
                        in issuer_allowlist
                    )
                identity = _state_node_identity(request)
                binding = sign_offer_package_binding(
                    identity,
                    offer_digest=offer_digest,
                    package_digest=package.digest,
                    created=offer.to_dict()["published_at"],
                )
                raw_pages = _cached_rule_recognition_proof_pages(
                    request,
                    cache_key=(
                        offer_digest,
                        package_digest,
                        tuple(statement.digest for statement in statements),
                    ),
                    build=lambda: tuple(
                        trade_canonical_json(page)
                        for page in build_rule_recognition_proof_pages(
                            package,
                            statements,
                            offer_package_binding=binding,
                            observer_identity=identity,
                        )
                    ),
                )
            except (
                RuleRecognitionAuditError,
                RuleRecognitionProofBundleRejected,
                RuleRecognitionStoreError,
                RuntimeError,
                TypeError,
                ValueError,
            ) as exc:
                raise HTTPException(
                    status_code=503,
                    detail=(
                        "public Rule Recognition proof integrity verification failed"
                    ),
                ) from exc
            if page_index >= len(raw_pages):
                raise HTTPException(
                    status_code=404,
                    detail="Rule Recognition proof page not found",
                )
            raw = raw_pages[page_index]
            page = parse_trade_json(raw)
            etag = f'"sha256:{hashlib.sha256(raw).hexdigest()}"'
            response_headers = {
                "ETag": etag,
                "X-NTH-Offer-Digest": offer_digest,
                "X-NTH-Package-Digest": package_digest,
                "X-NTH-Recognition-Observation-Digest": page[
                    "observation_digest"
                ],
                "X-NTH-Recognition-Page-Index": str(page_index),
                "X-NTH-Recognition-Page-Count": str(len(raw_pages)),
                "X-NTH-Recognition-Semantics": "observed-not-globally-fresh",
                "X-NTH-Recognition-Disclosure": "operator-enabled",
                "X-NTH-Trust-Granted": "false",
                "X-NTH-Execution-Authorized": "false",
                "Cache-Control": "public, max-age=30",
            }
            if _if_none_match_matches(request, etag):
                return Response(status_code=304, headers=response_headers)
            _require_trade_rule_package_byte_budget(request, len(raw))
            response_headers["Content-Length"] = str(len(raw))
            return Response(
                content=raw,
                media_type=(
                    "application/vnd.nth-dao.trade-rule-recognition-proof-page+json"
                ),
                headers=response_headers,
            )
        finally:
            semaphore.release()

    @app.get("/api/v2/trade/federation/offers/{digest}/head-proof")
    def v2_trade_offer_federation_head_proof_get(
        digest: str,
        request: Request,
    ) -> Dict[str, Any]:
        """Serve a bounded signed revision chain for one live head claim."""

        from nth_dao.market import (
            MAX_TRADE_OFFER_HEAD_PROOF_REVISIONS,
            build_trade_offer_head_proof,
        )
        from nth_dao.trade_rules import OfferStoreError, offer_digest

        store = _state_trade_offer_store(request)
        workspace = _state_workspace(request)
        if store is None or workspace is None:
            raise HTTPException(status_code=503, detail="trade storage unavailable")
        _require_trade_offer_digest(digest)
        _require_trade_offer_public_read_budget(request)
        try:
            for _attempt in range(3):
                before = store.integrity_fingerprint()
                feed = _state_market_feed(request)
                announcement = feed.find_live_trade_offer_announcement(digest)
                if announcement is None:
                    raise HTTPException(
                        status_code=404,
                        detail="announced Offer head not found",
                    )
                feed.require_listing_binding(announcement)
                head_record = store.get_record(digest)
                if head_record is None:
                    raise HTTPException(
                        status_code=404,
                        detail="announced Offer head not found",
                    )
                view, head = store.canonical_snapshot(
                    head_record.offer.publisher_did,
                    head_record.offer.offer_id,
                )
                if (
                    not view.is_canonical
                    or head is None
                    or offer_digest(head) != digest
                ):
                    raise HTTPException(
                        status_code=404,
                        detail="announced Offer is not the canonical head",
                    )
                if len(view.canonical_digests) > (
                    MAX_TRADE_OFFER_HEAD_PROOF_REVISIONS
                ):
                    raise HTTPException(
                        status_code=409,
                        detail="canonical Offer chain exceeds the proof limit",
                    )
                chain = []
                for chain_digest in view.canonical_digests:
                    offer = store.get(chain_digest)
                    if offer is None:
                        raise HTTPException(
                            status_code=503,
                            detail="canonical Offer chain is incomplete",
                        )
                    chain.append(offer)
                _verify_trade_offer_spine_anchors(request, store)
                proof = build_trade_offer_head_proof(announcement, chain)
                if before == store.integrity_fingerprint():
                    return proof
            raise HTTPException(
                status_code=503,
                detail="Trade Offer chain changed during proof generation",
                headers={"Retry-After": "1"},
            )
        except HTTPException:
            raise
        except OfferStoreError as exc:
            raise HTTPException(
                status_code=503,
                detail="trade offer store integrity check failed",
            ) from exc
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail=f"Trade Offer head proof unavailable: {exc}",
            ) from exc

    @app.get("/api/v2/trade/federation/cached-offers/{digest}")
    def v2_trade_offer_federation_cached_get(
        digest: str,
        request: Request,
    ) -> Dict[str, Any]:
        """Inspect a verified remote Offer without importing its authority."""
        _require_console_bearer_for_sensitive_read(request)
        (
            verified_offer,
            discoveries,
            _evidence,
            _auditable_evidence,
            head_claim,
            _head_proof,
        ) = _verified_cached_trade_offer(request, digest)
        store = _state_trade_offer_store(request)
        storage_provenance = None
        if store is not None:
            try:
                record = store.get_record(digest)
                if record is not None:
                    _verify_trade_offer_spine_anchors(request, store)
                    storage_provenance = {
                        "source_kind": record.source_kind,
                        "source_id": record.source_id,
                    }
            except HTTPException:
                raise
            except (OSError, RuntimeError, TypeError, ValueError) as exc:
                raise HTTPException(
                    status_code=503,
                    detail=f"local Trade Offer provenance unavailable: {exc}",
                ) from exc
        return {
            "digest": digest,
            "offer": verified_offer.to_dict(),
            "resource_descriptors": _market_offer_descriptor_inspection(
                verified_offer,
                workspace=_state_workspace(request),
            ),
            "discoveries": discoveries,
            "verification": {
                "offer_signature_valid": True,
                "announcement_binding_valid": True,
                "source_did_bound": True,
                "recent_source_verified": any(
                    not item["stale"] for item in discoveries
                ),
                "head_chain_valid": True,
                "publisher_head_claim_valid": True,
            },
            "authority": "remote-publisher",
            "storage_provenance": storage_provenance,
            "head_claim": head_claim,
            "actionable": False,
            "warning": (
                "A valid signature proves authorship, not availability, "
                "fairness, ownership, or settlement. Create a new bilateral "
                "Agreement before execution."
            ),
        }

    @app.post("/api/v2/trade/federation/cached-offers/{digest}/import")
    def v2_trade_offer_federation_cached_import(
        digest: str,
        request: Request,
    ) -> Dict[str, Any]:
        """Durably retain one reverified remote Offer without trusting it."""
        _require_console_bearer_for_sensitive_read(request)
        _require_trade_offer_digest(digest)
        from nth_dao.trade_rules import (
            OfferStoreBusyError,
            OfferStoreCapacityError,
            OfferStoreCorruptionError,
            OfferStoreCryptoUnavailableError,
            OfferStoreError,
            OfferStoreValidationError,
            offer_digest,
        )
        from nth_dao.util.io import InterProcessLock

        store = _state_trade_offer_store(request)
        workspace = _state_workspace(request)
        spine = _state_spine(request)
        local_identity = _state_node_identity(request)
        if store is None or workspace is None:
            raise HTTPException(status_code=503, detail="trade offer store unavailable")
        if (
            spine is None
            or local_identity is None
            or not getattr(local_identity, "can_sign", False)
        ):
            raise HTTPException(
                status_code=503,
                detail="signed Spine or node identity unavailable",
            )
        local_did = local_identity.as_did()
        lock_path = (
            workspace / "trade" / "offers" / ".locks"
            / f"federation-import-{digest[7:]}.lock"
        )
        transaction_lock_path = _trade_offer_store_spine_transaction_lock_path(
            workspace
        )
        try:
            with (
                InterProcessLock(lock_path),
                InterProcessLock(transaction_lock_path),
            ):
                proposal = _verified_trade_offer_import_proposal(
                    request,
                    digest,
                )
                proposal_event = None
                if proposal is None:
                    (
                        verified_offer,
                        discoveries,
                        discovery_evidence,
                        discovery_evidence_set,
                        _head_claim,
                        head_proof,
                    ) = _verified_cached_trade_offer(request, digest)
                    discovery_source_count = len(discovery_evidence_set)
                    proposal_source_id = local_did
                    offers = head_proof.offers
                else:
                    (
                        offers,
                        discovery_evidence,
                        discovery_source_count,
                        proposal_event,
                        head_proof,
                    ) = proposal
                    verified_offer = offers[-1]
                    proposal_source_id = proposal_event.author_did

                existing_records = {
                    offer_digest(offer): store.get_record(offer_digest(offer))
                    for offer in offers
                }
                for offer in offers:
                    offer_record = existing_records[offer_digest(offer)]
                    if offer_record is None:
                        continue
                    compatible_local = (
                        offer_record.source_kind == "local-operator"
                        and offer_record.source_id == offer.publisher_did
                    )
                    compatible_federated = (
                        offer_record.source_kind == "federation-cache"
                        and offer_record.source_id == proposal_source_id
                    )
                    if not (compatible_local or compatible_federated):
                        raise HTTPException(
                            status_code=409,
                            detail=(
                                "offer already exists with incompatible "
                                "import provenance"
                            ),
                        )

                if proposal is None and any(
                    record is None for record in existing_records.values()
                ):
                    proposal_event = spine.append(
                        "trade.offer.import.proposed",
                        {
                            "offer_digest": digest,
                            "offer": verified_offer.to_dict(),
                            "head_proof": head_proof.to_dict(),
                            "source_kind": "federation-cache",
                            "source_id": local_did,
                            "discovery": discovery_evidence,
                            "discoveries": discovery_evidence_set,
                            "discovery_sources": discovery_source_count,
                        },
                    )
                    proposal_source_id = proposal_event.author_did
                results = []
                anchors = []
                for offer in offers:
                    result = store.publish(
                        offer,
                        source_kind="federation-cache",
                        source_id=proposal_source_id,
                    )
                    existing_anchor = _find_trade_offer_spine_anchor(
                        request,
                        result,
                    )
                    if existing_anchor is None:
                        if (
                            result.source_kind != "federation-cache"
                            or proposal_event is None
                        ):
                            raise RuntimeError(
                                "existing Trade Offer lacks a recoverable Spine anchor"
                            )
                        existing_anchor = spine.append(
                            "trade.offer.imported",
                            {
                                "seq": result.seq,
                                "offer_digest": result.digest,
                                "head_offer_digest": digest,
                                "entry_hash": result.entry_hash,
                                "publisher_did": offer.publisher_did,
                                "offer_id": offer.offer_id,
                                "source_kind": result.source_kind,
                                "source_id": result.source_id,
                                "completion_did": local_did,
                                "discovery": discovery_evidence,
                                "proposal_event_id": proposal_event.event_id,
                            },
                        )
                    results.append(result)
                    anchors.append(existing_anchor)
                _verify_trade_offer_spine_anchors(request, store)
                head_index = next(
                    index for index, result in enumerate(results)
                    if result.digest == digest
                )
                result = results[head_index]
                existing_anchor = anchors[head_index]
        except HTTPException:
            raise
        except TimeoutError as exc:
            raise HTTPException(
                status_code=503,
                detail="Trade Offer import is busy",
                headers={"Retry-After": "1"},
            ) from exc
        except OfferStoreCryptoUnavailableError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except OfferStoreBusyError as exc:
            raise HTTPException(
                status_code=503,
                detail=str(exc),
                headers={"Retry-After": "1"},
            ) from exc
        except OfferStoreValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except OfferStoreCapacityError as exc:
            raise HTTPException(status_code=507, detail=str(exc)) from exc
        except OfferStoreCorruptionError as exc:
            raise HTTPException(
                status_code=503,
                detail=f"trade offer store integrity failure: {exc}",
            ) from exc
        except OfferStoreError as exc:
            raise HTTPException(
                status_code=503,
                detail=f"trade offer persistence failed: {exc}",
            ) from exc
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            logger.warning("federated Trade Offer import failed: %s", exc)
            raise HTTPException(
                status_code=503,
                detail="federated Trade Offer could not be durably imported",
            ) from exc
        return {
            "digest": result.digest,
            "appended": result.appended,
            "persisted": True,
            "classification": result.classification,
            "entry_hash": result.entry_hash,
            "source_kind": result.source_kind,
            "source_id": result.source_id,
            "audit_event_id": existing_anchor.event_id,
            "audit_event_ids": [anchor.event_id for anchor in anchors],
            "imported_revisions": len(results),
            "appended_revisions": sum(
                1 for imported_result in results if imported_result.appended
            ),
            "discovery_sources": discovery_source_count,
            "trusted": False,
            "actionable": False,
            "warning": (
                "Saved locally as a signed claim. This does not accept the "
                "Offer, trust its publisher, reserve assets, or authorize execution."
            ),
        }

    @app.get("/api/v2/market/open")
    def v2_market_open(
        request: Request,
        context: str = "",
        capability: str = "",
        listing_type: str = "",
        min_reward: int = 0,
        q: str = "",
    ) -> List[Dict[str, Any]]:
        """任务广场(发现态):列出 feed 里未认领、未过期的开放任务公告。

        数据源是 nth_dao.market 的 A2A 任务市场(MarketFeed + ClaimStore),
        此前完全没接进 UI——而"发现可认领的活"正是 A2A 协调底座的核心面。
        这是读路径(安全方法,匿名可读,与其他 v2 读端点一致);认领是状态
        变更动作,另设受控端点。

        分类/检索(任务多时按能力/喜好/价值挑选):
          context     — 按类别精确过滤(公告的 context 字段)。
          capability  — 只留 capability_set 含该能力的(与认领同套归一,
                        避免"筛得到却认不了")。
          min_reward  — 赏金下限(整数最小单位)。
          q           — 标题/详述子串搜索(大小写不敏感)。
        多个条件取交集。空=不过滤。
        """
        from nth_dao.market.vocabulary import normalize_capability

        ws = _state_workspace(request)
        if ws is None:
            return []
        want_cap = normalize_capability(capability) if capability.strip() else ""
        want_ctx = context.strip()
        try:
            want_listing = (
                _normalize_market_listing_type(listing_type)
                if listing_type.strip() else ""
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        ql = q.strip().lower()
        # 自审修复:MarketFeed/ClaimStore 的构造会 mkdir。读端点(且匿名)
        # 不该有文件系统副作用——否则任何一次只读 GET 都会在从不用市场的
        # 节点工作区里凭空造出 market_feed/ 与 market_claims/。feed 日志不
        # 存在 ⇒ 还没有任何公告 ⇒ 直接返回 [],不触碰磁盘。
        out: List[Dict[str, Any]] = []

        def _passes(ann: Any) -> bool:
            if want_ctx and ann.context != want_ctx:
                return False
            if want_cap:
                have = {normalize_capability(c) for c in ann.capability_set}
                if want_cap not in have:
                    return False
            if want_listing and _market_announcement_listing_type(ann) != want_listing:
                return False
            if min_reward and ann.reward_minor < min_reward:
                return False
            if ql and ql not in ann.title.lower() and ql not in ann.description.lower():
                return False
            return True

        # 本地 open 集合(Phase 2d:事实源可切 feed→spine,默认 feed,fail-safe
        # 回退;口径与原逻辑一致。见 _market_local_open)。
        out.extend(_market_local_open(request, _passes))

        # 联邦合并(FED-2):对端发现到的公告(已双层验签)。本地优先去重;
        # 同套筛选;标 federated + source_peer。认领权威在主 DAO,这里只做发现。
        cache = _state_market_fed_cache(request)
        if cache is not None:
            local_keys = {d["federation_key"] for d in out}
            for federation_key, entry in cache.snapshot().items():
                if federation_key in local_keys:
                    continue
                ann = entry["ann"]
                if not _passes(ann):
                    continue
                d = _market_announcement_to_wire(ann)
                d["claimed"] = False
                d["federated"] = True
                d["source_peer"] = entry.get("source", "")
                d["federation_key"] = federation_key
                d["federation_stale"] = bool(entry.get("stale", False))
                d["federation_verified_at_ms"] = int(
                    entry.get("last_verified_ms") or 0
                )
                out.append(d)
        return out

    @app.get("/api/v2/market/search")
    def v2_market_search(
        request: Request,
        q: str = "",
        category: str = "",
        intent: str = "",
        context: str = "",
        capability: str = "",
        min_value: int = 0,
        value_asset: str = "",
        source: str = "",
        offset: int = 0,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """Return a bounded human-facing projection over signed discoveries.

        This endpoint does not create a new market fact or weaken the source
        protocols. Callers must resolve the exact Task announcement or Offer
        digest before claiming, negotiating, or executing anything.
        """
        normalized_category = category.strip().lower()
        normalized_intent = intent.strip().lower()
        normalized_source = source.strip().lower()
        if normalized_category and normalized_category not in _MARKET_SEARCH_CATEGORIES:
            raise HTTPException(
                status_code=400,
                detail=(
                    "category must be tasks, products, services, digital-assets, "
                    "exchanges, or other"
                ),
            )
        if normalized_intent and normalized_intent not in _MARKET_SEARCH_INTENTS:
            raise HTTPException(
                status_code=400,
                detail="intent must be request, provide, or exchange",
            )
        if normalized_source not in {"", "local", "federated"}:
            raise HTTPException(
                status_code=400,
                detail="source must be local or federated",
            )
        if isinstance(offset, bool) or not 0 <= offset <= 10_000:
            raise HTTPException(status_code=400, detail="offset must be in 0..10000")
        if isinstance(limit, bool) or not 1 <= limit <= 500:
            raise HTTPException(status_code=400, detail="limit must be in 1..500")
        if isinstance(min_value, bool) or min_value < 0:
            raise HTTPException(status_code=400, detail="min_value must be non-negative")
        normalized_asset = value_asset.strip()
        if len(normalized_asset) > 64:
            raise HTTPException(status_code=400, detail="value_asset is too long")
        if min_value > 0 and not normalized_asset:
            raise HTTPException(
                status_code=400,
                detail="value_asset is required when min_value is used",
            )
        if len(q) > 200 or len(context) > 128 or len(capability) > 128:
            raise HTTPException(status_code=400, detail="market search filter is too long")
        rows = v2_market_open(
            request=request,
            context=context,
            capability=capability,
            min_reward=0,
            q=q,
        )
        unfiltered = [_market_search_entry(row) for row in rows]
        if normalized_source:
            unfiltered = [
                entry
                for entry in unfiltered
                if entry["source"] == normalized_source
            ]
        facets: Dict[str, int] = {}
        for entry in unfiltered:
            entry_category = str(entry["category"])
            facets[entry_category] = facets.get(entry_category, 0) + 1
            if (
                entry["market_intent"] == "exchange"
                and entry_category != "exchanges"
            ):
                facets["exchanges"] = facets.get("exchanges", 0) + 1

        entries = [
            entry
            for entry in unfiltered
            if (
                not normalized_category
                or (
                    normalized_category == "exchanges"
                    and entry["market_intent"] == "exchange"
                )
                or entry["category"] == normalized_category
            )
            and (
                not normalized_intent
                or entry["market_intent"] == normalized_intent
            )
            and int(entry["value"]["amount_minor"]) >= min_value
            and (
                not normalized_asset
                or entry["value"]["asset"] == normalized_asset
            )
        ]
        entries.sort(
            key=lambda entry: (
                -int(entry["published_at_ms"]),
                str(entry["entry_id"]),
            )
        )
        total = len(entries)
        page = entries[offset : offset + limit]
        return {
            "items": page,
            "count": total,
            "offset": offset,
            "truncated": offset + len(page) < total,
            "facets": [
                {"category": name, "count": count}
                for name, count in sorted(
                    facets.items(), key=lambda item: (-item[1], item[0])
                )
            ],
            "projection_only": True,
            "warning": (
                "Search entries are local projections of signed discovery "
                "claims, not proof of availability, ownership, fairness, or "
                "execution authority."
            ),
        }

    @app.get("/api/v2/market/categories")
    def v2_market_categories(
        request: Request,
        listing_type: str = "",
    ) -> List[Dict[str, Any]]:
        """任务广场的类别分面:列出未认领公告里出现过的 context + 计数,
        给前端做"按类别筛选"的 chips。空 feed → []。涌现式分类(无固定
        词表),贴去中心化:类别由发布者的 context 自然长出来。"""
        from nth_dao.market.claim import ClaimStore
        from nth_dao.market.feed import MarketFeed

        ws = _state_workspace(request)
        if ws is None or not (
            ws / "market_feed" / "announcements.jsonl"
        ).exists():
            return []
        try:
            wanted_listing = (
                _normalize_market_listing_type(listing_type)
                if listing_type.strip()
                else ""
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        feed = MarketFeed(ws)
        claims = ClaimStore(ws)
        counts: Dict[str, int] = {}
        for ann in feed.poll(since_seq=-1, limit=500).announcements:
            if claims.is_unavailable(ann.announcement_id):
                continue
            if (
                wanted_listing
                and _market_announcement_listing_type(ann) != wanted_listing
            ):
                continue
            counts[ann.context] = counts.get(ann.context, 0) + 1
        return sorted(
            ({"context": k, "count": v} for k, v in counts.items()),
            key=lambda x: (-x["count"], x["context"]),
        )

    @app.get("/api/v2/market/resource-profiles")
    def v2_market_resource_profiles(
        request: Request,
        limit: int = Query(default=100, ge=1, le=200),
        cursor: str = "",
    ) -> Dict[str, Any]:
        """List verified local Resource Profiles and explicit recognition."""
        from nth_dao.market.resource_profile import (
            ResourceProfilePolicy,
            ResourceProfileRejected,
            ResourceProfileStore,
        )

        _require_console_bearer_for_sensitive_read(request)
        workspace = _state_workspace(request)
        if workspace is None:
            raise HTTPException(status_code=503, detail="workspace unavailable")
        store = ResourceProfileStore(workspace)
        policy = ResourceProfilePolicy(workspace)
        if cursor and re.fullmatch(r"sha256:[0-9a-f]{64}", cursor) is None:
            raise HTTPException(
                status_code=400,
                detail="cursor must be a lowercase sha256 digest",
            )
        try:
            accepted = policy.accepted_digests(strict=True)
            profiles, next_cursor, total = store.list_page(
                after=cursor or None,
                limit=limit,
            )
        except (OSError, ResourceProfileRejected, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail=f"Resource Profile store unavailable: {exc}",
            ) from exc
        return {
            "items": [
                _market_resource_profile_to_wire(
                    profile,
                    recognized=profile.digest in accepted,
                )
                for profile in profiles
            ],
            "count": total,
            "returned": len(profiles),
            "next_cursor": next_cursor or "",
            "truncated": bool(next_cursor),
            "warning": (
                "Signature verification proves provenance only. Local "
                "recognition never grants execution or payment authority."
            ),
        }
    @app.post("/api/v2/market/resource-profiles/import")
    def v2_market_resource_profile_import(
        body: MarketResourceProfileImportBody,
        request: Request,
    ) -> Dict[str, Any]:
        """Verify and cache one signed, declarative Profile document."""
        from nth_dao.market.resource_profile import (
            ResourceProfile,
            ResourceProfilePolicy,
            ResourceProfileRejected,
            ResourceProfileStore,
        )
        _require_console_bearer_for_governance_mutation(request)
        _enforce_recognition_policy_mutation_limit(
            request,
            operation="resource-profile-import",
        )
        workspace = _state_workspace(request)
        spine = _state_spine(request)
        if workspace is None or spine is None:
            raise HTTPException(
                status_code=503,
                detail="workspace or signed Spine unavailable",
            )
        try:
            profile = ResourceProfile.from_dict(body.document)
        except (TypeError, ValueError, ResourceProfileRejected) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        store = ResourceProfileStore(workspace)
        try:
            stored, installed = store.install_with_status(profile)
        except (OSError, ResourceProfileRejected, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail=f"Resource Profile persistence failed: {exc}",
            ) from exc
        document = stored.to_dict()
        payload = {
            "profile_digest": stored.digest,
            "profile_id": document["profile_id"],
            "profile_version": document["version"],
            "publisher_did": document["publisher_did"],
            "action": "verified-local-import",
        }
        try:
            event, audit_created = spine.append_unique(
                "market.resource-profile.imported",
                payload,
                unique_payload_fields=("profile_digest",),
            )
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail=(
                    "Resource Profile was verified and may be cached, but its "
                    "signed audit is incomplete; retry the same import"
                ),
            ) from exc
        try:
            accepted = ResourceProfilePolicy(workspace).accepted_digests(strict=True)
        except (OSError, ResourceProfileRejected, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail=f"Resource Profile policy unavailable: {exc}",
            ) from exc
        return {
            "profile": _market_resource_profile_to_wire(
                stored,
                recognized=stored.digest in accepted,
            ),
            "installed": installed,
            "audit_event_id": event.event_id,
            "audit_created": audit_created,
        }
    @app.post(
        "/api/v2/market/resource-profiles/{profile_digest}/recognition",
    )
    def v2_market_resource_profile_recognition(
        profile_digest: str,
        body: MarketResourceProfileRecognitionBody,
        request: Request,
    ) -> Dict[str, Any]:
        """Apply one explicit local recognition decision with signed audit."""
        from nth_dao.market.resource_profile import (
            ResourceProfilePolicy,
            ResourceProfileRejected,
            ResourceProfileStore,
        )
        _require_console_bearer_for_governance_mutation(request)
        _enforce_recognition_policy_mutation_limit(
            request,
            operation="resource-profile-recognition",
        )
        workspace = _state_workspace(request)
        spine = _state_spine(request)
        if workspace is None or spine is None:
            raise HTTPException(
                status_code=503,
                detail="workspace or signed Spine unavailable",
            )
        store = ResourceProfileStore(workspace)
        try:
            profile = store.load(profile_digest)
        except (OSError, ResourceProfileRejected, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if profile is None:
            raise HTTPException(status_code=404, detail="Resource Profile not found")
        operation_id = hashlib.sha256(
            (
                "nth-resource-profile-recognition-v1\0"
                + body.idempotency_key
            ).encode("ascii")
        ).hexdigest()
        proposal_payload = {
            "operation_id": operation_id,
            "profile_digest": profile.digest,
            "accepted": body.accepted,
            "action": "local-recognition-proposed",
        }
        try:
            spine.append_unique(
                "market.resource-profile.recognition.proposed",
                proposal_payload,
                unique_payload_fields=("operation_id",),
            )
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=409,
                detail=f"recognition operation conflicts or cannot be audited: {exc}",
            ) from exc
        policy = ResourceProfilePolicy(workspace)
        try:
            changed = policy.set_accepted(profile.digest, body.accepted)
        except (OSError, ResourceProfileRejected, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail=f"Resource Profile recognition persistence failed: {exc}",
            ) from exc
        completed_payload = {
            "operation_id": operation_id,
            "profile_digest": profile.digest,
            "accepted": body.accepted,
            "action": "local-recognition-applied",
        }
        try:
            event, audit_created = spine.append_unique(
                "market.resource-profile.recognition.applied",
                completed_payload,
                unique_payload_fields=("operation_id",),
            )
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail=(
                    "Recognition may already be applied but its completion "
                    "audit is incomplete; retry with the same idempotency key"
                ),
            ) from exc
        return {
            "profile": _market_resource_profile_to_wire(
                profile,
                recognized=body.accepted,
            ),
            "changed": changed,
            "operation_id": operation_id,
            "audit_event_id": event.event_id,
            "audit_created": audit_created,
        }

    @app.get("/api/v2/market/reconcile")
    def v2_market_reconcile(request: Request) -> Dict[str, Any]:
        """新旧事实源对账(Phase 2d):feed+ClaimStore 的 open 集 vs spine 投影。

        切读前的"双跑对账"诊断:``in_sync=true`` 才宜把 NTH_MARKET_READ_SOURCE
        切到 spine。``active_source`` 标注当前生效源。spine/feed 缺失 → available=false。
        """
        from nth_dao.market.claim import ClaimStore
        from nth_dao.market.feed import MarketFeed
        from nth_dao.market.reconcile import reconcile_market

        ws = _state_workspace(request)
        spine = _state_spine(request)
        source = os.environ.get("NTH_MARKET_READ_SOURCE", "feed").strip().lower()
        if ws is None or spine is None or not (
            ws / "market_feed" / "announcements.jsonl"
        ).exists():
            return {
                "available": False, "active_source": source,
                "reason": "spine or market feed unavailable",
            }
        rep = reconcile_market(MarketFeed(ws), ClaimStore(ws), spine)
        rep["available"] = True
        rep["active_source"] = source
        return rep
    @app.post("/api/v2/market/{announcement_id}/accept")
    def v2_market_accept(
        announcement_id: str, body: AcceptBody, request: Request,
    ) -> Dict[str, Any]:
        """发布方验收:确认 completer 交付了任务,记 market.acceptance(交付证明,
        信誉据此从"承接"升级为"交付")。token-gated。

        校验:本节点是该公告**发布方**(只能验收自己发的活)+ completer 已**认领**
        该公告(没接过的不能被验收)。
        """
        from nth_dao.market.acceptance import sign_acceptance
        from nth_dao.market.claim import ClaimStore
        from nth_dao.market.feed import MarketFeed
        from nth_dao.market.projection import EVENT_MARKET_ACCEPTANCE
        spine = _state_spine(request)
        identity = _state_node_identity(request)
        ws = _state_workspace(request)
        if spine is None or ws is None or identity is None or not getattr(
            identity, "can_sign", False
        ):
            raise HTTPException(
                status_code=503, detail="spine / identity / workspace unavailable"
            )
        if not (ws / "market_feed" / "announcements.jsonl").exists():
            raise HTTPException(status_code=404, detail="announcement not found")
        ann = MarketFeed(ws).get(announcement_id)
        if ann is None:
            raise HTTPException(status_code=404, detail="announcement not found")
        if ann.publisher_did != identity.as_did():
            raise HTTPException(
                status_code=403, detail="only the publisher can accept this task"
            )
        if body.completer_did == ann.publisher_did:
            # 防 self-dealing:发布方不能给"自己认领自己发的活"验收刷分。
            raise HTTPException(
                status_code=400, detail="publisher cannot accept their own claim"
            )
        claim = ClaimStore(ws).get(announcement_id, announcement=ann)
        if not claim or claim.get("claimant_did") != body.completer_did:
            raise HTTPException(
                status_code=409, detail="completer has not claimed this task"
            )
        stmt = sign_acceptance(
            publisher=identity,
            announcement_id=announcement_id,
            completer_did=body.completer_did,
        )
        ev = spine.append(EVENT_MARKET_ACCEPTANCE, stmt)
        return {
            "accepted": True, "announcement_id": announcement_id,
            "completer_did": body.completer_did, "seq": ev.seq,
        }
    @app.post("/api/v2/market/announce")
    def v2_market_announce(
        body: AnnounceTaskBody, request: Request,
    ) -> Dict[str, Any]:
        """发布一条任务公告到市场 feed(本节点签名)。让"任务广场"非空。
        这是 publish 路径——browse(/market/open)与 claim 都依赖有公告可
        发现。发布者=本节点身份(operator 代表本 DAO 发活)。POST 状态变更
        动作,auth 开启时受控(不吃匿名旁路)。
        """
        from nth_dao.market.announcement import sign_announcement
        from nth_dao.market.feed import MarketFeed
        from nth_dao.market.publication_policy import (
            reject_private_publication_data,
        )
        if not body.title.strip():
            raise HTTPException(status_code=400, detail="title must not be empty")
        # 输入上限(对抗审查补):公告会被签名并追加进 append-only feed
        # (近似账本、无内置清理),不设限则一条超大 description/能力表就是
        # 永久膨胀。在落盘前于 HTTP 边界封顶,给清晰 400。
        try:
            listing_type = _normalize_market_listing_type(body.listing_type)
            if listing_type != "task":
                raise ValueError(
                    "market/announce accepts Tasks only; products, services, "
                    "and exchanges must use a signed Trade Offer"
                )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        if len(body.title) > 200:
            raise HTTPException(status_code=400, detail="title too long (max 200)")
        if len(body.description) > 4000:
            raise HTTPException(
                status_code=400, detail="description too long (max 4000)"
            )
        if len(body.capability_set) > 32:
            raise HTTPException(
                status_code=400, detail="too many capabilities (max 32)"
            )
        if any(len(c) > 100 for c in body.capability_set):
            raise HTTPException(
                status_code=400, detail="capability name too long (max 100)"
            )
        if (
            len(body.reward_asset) > 32
            or len(body.context) > 64
            or len(body.mission_id) > 128
        ):
            raise HTTPException(
                status_code=400, detail="reward_asset/context/mission_id too long"
            )
        try:
            reject_private_publication_data(
                {
                    "title": body.title,
                    "description": body.description,
                    "capability_set": body.capability_set,
                    "context": body.context,
                },
                label="market_task",
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        ws = _state_workspace(request)
        if ws is None:
            raise HTTPException(status_code=503, detail="workspace unavailable")
        identity = _state_node_identity(request)
        if identity is None or not getattr(identity, "can_sign", False):
            raise HTTPException(
                status_code=503,
                detail=(
                    "node identity unavailable; cannot sign announcement. "
                    "Bootstrap the workspace identity first (install pynacl)."
                ),
            )
        try:
            ann = sign_announcement(
                publisher=identity,
                title=body.title.strip(),
                capability_set=list(body.capability_set or []),
                context=body.context or "general",
                input_schema={_MARKET_LISTING_TYPE_FIELD: listing_type},
                reward_minor=int(body.reward_minor),
                reward_asset=body.reward_asset or "credit",
                mission_id=body.mission_id or "",
                description=body.description or "",
                not_after=int(body.not_after or 0),
            )
        except (ValueError, TypeError) as exc:
            raise HTTPException(
                status_code=400, detail=f"announce rejected: {exc}",
            )
        try:
            # publish 会先验签再落盘(feed 里永远只有可独立验证的公告)。
            # Phase 2b:同时影子双写进 spine(单例;缺失则只写 feed)。spine
            # 失败不阻断发布(MarketFeed.publish 内部 best-effort)。
            MarketFeed(ws, spine=_state_spine(request)).publish(ann)
        except ValueError as exc:
            raise HTTPException(
                status_code=400, detail=f"publish rejected: {exc}",
            )
        return ann.to_dict()
    # ── 任务市场联邦传输层(FED-1:serve 侧)─────────────────────────
    # federation.py 已把数据模型/验签/信任模型做好;这里只把它包成 HTTP。
    # 两个端点都匿名可读(只暴露本就可发现的公告摘要/全文,与 market/open
    # 一致)。信任模型:digest 是不可信提示(带 source 签名=provenance),
    # 全文带 publisher_sig 才是权威 —— 拉方两层都验。
    @app.get("/api/v2/commerce/federation/listings/{digest}")
    def v2_commerce_fed_listing(digest: str, request: Request) -> Dict[str, Any]:
        """Serve one content-addressed, seller-signed listing."""
        from nth_dao.commerce.listing import ListingRejected, ListingStore
        ws = _state_workspace(request)
        if ws is None:
            raise HTTPException(status_code=503, detail="workspace unavailable")
        try:
            listing = ListingStore(ws).get(digest)
        except ListingRejected:
            raise HTTPException(status_code=404, detail="listing not found")
        if listing is None:
            raise HTTPException(status_code=404, detail="listing not found")
        return listing.to_dict()

    @app.get("/api/v2/market/federation/digest")
    def v2_market_fed_digest(
        request: Request, since: int = -1,
    ) -> Dict[str, Any]:
        """返回本节点 feed 的签名摘要(provenance),供对端发现。
        ``since`` = 上次的 high_seq 游标(增量);每页封顶 _FED_DIGEST_PAGE 条,
        响应有界。拉方带 since=high_seq 翻下一页直到 refs 空。
        """
        ws = _state_workspace(request)
        identity = _state_node_identity(request)
        if ws is None or identity is None or not getattr(identity, "can_sign", False):
            raise HTTPException(
                status_code=503, detail="node identity/workspace unavailable"
            )
        # 没 feed 文件 = 没活可联邦;返回签名的空 digest,绝不 mkdir
        # (避免被对端轮询时在从不发活的节点凭空造 market_feed/)。
        if not (ws / "market_feed" / "announcements.jsonl").exists():
            from nth_dao.b64u import b64u_encode
            from nth_dao.canonical_json import canonical_json
            from nth_dao.execution_receipt import now_ms
            from nth_dao.market.federation import FeedDigest
            empty = FeedDigest(
                source_did=identity.as_did(), generated_at_ms=now_ms(),
                high_seq=-1, refs=[],
            )
            empty.digest_sig = b64u_encode(
                identity.sign(canonical_json(empty.signing_body()))
            )
            return empty.to_dict()
        from nth_dao.market.feed import MarketFeed
        from nth_dao.market.claim import ClaimStore
        from nth_dao.market.federation import build_digest
        claims = (
            ClaimStore(ws)
            if (ws / "market_claims").exists()
            else None
        )
        return build_digest(
            MarketFeed(ws),
            identity,
            since_seq=since,
            limit=_FED_DIGEST_PAGE,
            is_open=(
                (lambda ann: not claims.is_unavailable(ann.announcement_id))
                if claims is not None
                else None
            ),
        ).to_dict()
    @app.get("/api/v2/market/federation/pull")
    def v2_market_fed_pull(
        request: Request, keys: str = "", ids: str = "",
    ) -> List[Dict[str, Any]]:
        """Pull verified full records by content key, with legacy ID fallback.
        ``keys`` is canonical because it is transport-safe and binds the signed
        body. ``ids`` remains available for pre-content-key digest clients.
        """
        ws = _state_workspace(request)
        if ws is None or not (
            ws / "market_feed" / "announcements.jsonl"
        ).exists():
            return []
        key_list = [s.strip() for s in keys.split(",") if s.strip()][:200]
        id_list = [s.strip() for s in ids.split(",") if s.strip()][:200]
        if not key_list and not id_list:
            return []
        from nth_dao.market.claim import ClaimStore
        from nth_dao.market.feed import MarketFeed
        from nth_dao.market.federation import (
            pull_announcements,
            pull_announcements_by_keys,
        )
        claims = (
            ClaimStore(ws)
            if (ws / "market_claims").exists()
            else None
        )
        feed = MarketFeed(ws)
        pulled = pull_announcements_by_keys(feed, key_list)
        if id_list:
            pulled.extend(pull_announcements(feed, id_list))
        seen = set()
        result: List[Dict[str, Any]] = []
        from nth_dao.market.announcement import announcement_federation_key
        for ann in pulled:
            key = announcement_federation_key(ann)
            if key in seen or (
                claims is not None and claims.is_unavailable(ann.announcement_id)
            ):
                continue
            seen.add(key)
            result.append(ann.to_dict())
        return result
    @app.get("/api/v2/market/federation/peers")
    def v2_market_fed_peers(request: Request) -> Dict[str, Any]:
        """Public verified peer hints for transitive discovery."""
        return {"peers": _public_fed_peer_hints(_state_workspace(request))}
    @app.get("/api/v2/market/federation/status")
    def v2_market_fed_status(request: Request) -> Dict[str, Any]:
        """Operator-facing federation discovery status."""
        if bool(getattr(request.app.state, "nth_require_console_auth", False)):
            _require_console_bearer_for_sensitive_read(request)
        ws = _state_workspace(request)
        if _read_fed_peers(ws) or _read_learned_fed_peers(ws):
            _state_market_fed_cache(request)
        return _market_fed_status(request)
    @app.post("/api/v2/market/federation/hello")
    def v2_market_fed_hello(
        body: FederationHelloBody, request: Request,
    ) -> Dict[str, Any]:
        """Learn a public DAO only after pinned signed-card verification."""
        from nth_dao.did_key import is_did_key
        client_key = _federation_hello_client_key(request)
        try:
            global_decision = _federation_hello_global_limiter(request).check(
                "all-clients",
            )
            decisions = (global_decision,)
            if global_decision.allowed:
                decisions += (
                    _federation_hello_limiter(request).check(client_key),
                )
        except (OSError, TimeoutError, ValueError) as exc:
            logger.warning("federation hello limiter unavailable: %s", exc)
            raise HTTPException(
                status_code=503,
                detail="federation hello is temporarily unavailable",
            )
        denied = [decision for decision in decisions if not decision.allowed]
        if denied:
            retry_after = max(item.retry_after_seconds for item in denied)
            raise HTTPException(
                status_code=429,
                detail="federation hello rate limit exceeded",
                headers={"Retry-After": str(max(1, int(retry_after)))},
            )
        if not is_did_key(body.did):
            raise HTTPException(
                status_code=400,
                detail="federation hello requires a valid Ed25519 did:key",
            )
        try:
            from nth_dao.discovery.federation_registry import (
                LearnedPeerCapacityError,
                normalize_learned_peer_url,
            )
            from .market_federation_poll import _resolve_safe_gossip_ip
            peer_url = normalize_learned_peer_url(body.peer_url)
            resolved_ip = _resolve_safe_gossip_ip(peer_url)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        if not resolved_ip:
            raise HTTPException(
                status_code=400,
                detail="federation hello peer is not a public HTTPS endpoint",
            )
        local_identity = _state_node_identity(request)
        local_did = (
            local_identity.as_did()
            if local_identity is not None and hasattr(local_identity, "as_did")
            else ""
        )
        if local_did and hmac.compare_digest(local_did, body.did):
            raise HTTPException(status_code=409, detail="cannot learn this node as a peer")
        metadata, error = _fetch_and_verify_federation_identity(
            peer_url,
            timeout_seconds=_env_float(
                "NTH_FED_IDENTITY_TIMEOUT_S",
                2.0,
                minimum=0.5,
                maximum=3.0,
            ),
            expected_did=body.did,
            resolved_ip=resolved_ip,
        )
        if metadata is None:
            logger.warning(
                "fed: peer hello identity rejected for %s: %s",
                peer_url,
                error,
            )
            raise HTTPException(
                status_code=400,
                detail="federation hello identity could not be verified",
            )
        store = _learned_fed_peer_store(_state_workspace(request))
        if store is None:
            raise HTTPException(status_code=503, detail="workspace unavailable")
        try:
            record = store.upsert_verified(
                peer_url, metadata, resolved_ip=resolved_ip,
            )
        except LearnedPeerCapacityError as exc:
            logger.warning("fed: peer hello admission capacity rejected: %s", exc)
            raise HTTPException(
                status_code=429,
                detail="federation peer admission capacity is full",
                headers={"Retry-After": "3600"},
            )
        except (OSError, TimeoutError, ValueError) as exc:
            logger.warning("fed: peer hello persistence failed: %s", exc)
            raise HTTPException(
                status_code=503,
                detail="federation peer registry is temporarily unavailable",
            )
        _ensure_market_fed_cache_for_update(request)
        return {
            "learned": True,
            "peer_url": record.peer_url,
            "did": record.did,
            "expires_at_ms": record.expires_at_ms,
        }
    @app.post("/api/v2/market/federation/peers")
    def v2_market_fed_peer_update(
        body: FederationPeerBody, request: Request,
    ) -> Dict[str, Any]:
        """Add or remove an operator-managed seed peer URL."""
        _require_federation_operator(request)
        ws = _state_workspace(request)
        if ws is None:
            raise HTTPException(status_code=503, detail="workspace unavailable")
        try:
            peer = _normalize_configured_fed_peer(body.peer_url)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        action = (body.action or "add").strip().lower()
        if action not in {"add", "remove"}:
            raise HTTPException(
                status_code=400,
                detail="action must be add or remove",
            )
        with _fed_config_guard(ws):
            try:
                file_peers = _read_fed_peer_file(ws, strict=True)
                metadata = _read_fed_peer_metadata(ws, strict=True)
            except FederationSeedConfigError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            if action == "add":
                if peer not in file_peers:
                    file_peers.append(peer)
            else:
                file_peers = [p for p in file_peers if p != peer]
            try:
                if action == "remove":
                    metadata.pop(peer, None)
                _write_fed_peer_config_transaction(ws, file_peers, metadata)
            except (FederationSeedCapacityError, FederationSeedConfigError) as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            except (OSError, RuntimeError, ValueError) as exc:
                raise HTTPException(status_code=500, detail=str(exc))
        cache = _ensure_market_fed_cache_for_update(request)
        if action == "remove":
            cache.evict_source(peer)
        if not (_read_fed_peers(ws) or _read_learned_fed_peers(ws)):
            cache.replace_all({}, peer_count=0)
            stop_event = getattr(
                request.app.state, "market_fed_poller_stop_event", None,
            )
            if stop_event is not None and hasattr(stop_event, "set"):
                stop_event.set()
        status = _market_fed_status(request)
        status["updated"] = True
        status["peer_url"] = peer
        status["action"] = action
        return status
    @app.post("/api/v2/market/federation/discover")
    def v2_market_fed_discover(
        body: FederationDiscoverBody, request: Request,
    ) -> Dict[str, Any]:
        """Discover nearby DAO nodes and import their market federation URLs.
        This bridges identity discovery (LAN/mDNS Agent/DID records) to market
        federation (HTTP digest + pull). Only peers that publish an explicit
        HTTP(S) federation URL and pass signed identity-card preflight are
        imported; DID-only or unverifiable peers remain visible in
        ``discovered_peers`` but are skipped for task/product federation.
        """
        if body.add or body.refresh:
            _require_federation_operator(request)
        ws = _state_workspace(request)
        if ws is None:
            raise HTTPException(status_code=503, detail="workspace unavailable")
        actor_id = body.actor_id.strip()
        _require_federation_actor(request, actor_id)
        try:
            return _discover_and_import_market_federation(
                request,
                actor_id=actor_id,
                timeout_seconds=float(body.timeout_seconds),
                add=body.add,
                refresh=body.refresh,
            )
        except (FederationSeedCapacityError, FederationSeedConfigError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except (OSError, RuntimeError, ValueError) as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.post("/api/v2/market/federation/refresh")
    def v2_market_fed_refresh(request: Request) -> Dict[str, Any]:
        """Synchronously pull configured federation peers once."""
        _require_federation_operator(request)
        ws = _state_workspace(request)
        peers = _read_fed_peers(ws)
        learned_peers = _read_learned_fed_peers(ws)
        cache = _ensure_market_fed_cache_for_update(request)
        if not (peers or learned_peers):
            cache.replace_all({}, peer_count=0)
            status = _market_fed_status(request)
            status["refreshed"] = True
            return status
        from .market_federation_poll import FederationCycleReport, federate_once

        try:
            report = FederationCycleReport()
            entries = federate_once(
                peers,
                untrusted_peers=learned_peers,
                verify_gossip_peer=_market_fed_gossip_identity_verifier(
                    request, persist_learned=True,
                ),
                verify_seed_peer=_market_fed_gossip_identity_verifier(request),
                max_duration_s=_market_fed_cycle_budget_s(),
                cycle_report=report,
            )
            completed_sources = report.completed_sources or {
                str(entry.get("source") or "").rstrip("/")
                for entry in entries.values()
                if isinstance(entry, dict) and entry.get("source")
            }
            cache.apply_cycle(
                entries,
                completed_sources=completed_sources,
                peer_count=len(set(peers) | set(learned_peers)),
            )
        except Exception as exc:  # noqa: BLE001
            cache.mark_error(
                str(exc), peer_count=len(set(peers) | set(learned_peers)),
            )
            raise HTTPException(
                status_code=502,
                detail=f"federation refresh failed: {exc}",
            )
        status = _market_fed_status(request)
        status["refreshed"] = True
        return status

    def _v2_market_claim_foreign(
        announcement_id: str, body: ForeignClaimBody, request: Request,
    ) -> Dict[str, Any]:
        """跨 DAO 认领·来源 DAO 侧(XDAO-2):接受外部 agent 预签的
        ClaimReceipt,``record_foreign_claim`` 逐项验签 + CAS 落盘。

        本节点是该公告的**认领权威**(公告在本地 feed)。外部 agent 在它自己
        的节点签好收据后 POST 到这里落地。匿名(crypto-authorized):授权全靠
        验签,不吃本节点 console token(外部节点没有)。中间件已对本路径放行。
        """
        from nth_dao.market.claim import (
            ClaimConflict, ClaimRejected, ClaimStore, record_foreign_claim,
        )
        from nth_dao.market.feed import MarketFeed

        try:
            global_decision = _foreign_claim_global_limiter(request).check(
                "all-clients",
            )
            decisions = (global_decision,)
            if global_decision.allowed:
                decisions += (
                    _foreign_claim_limiter(request).check(
                        _federation_hello_client_key(request),
                    ),
                )
        except (OSError, TimeoutError, ValueError) as exc:
            logger.warning("foreign claim limiter unavailable: %s", exc)
            raise HTTPException(
                status_code=503,
                detail="foreign claim verification is temporarily unavailable",
            )
        denied = [decision for decision in decisions if not decision.allowed]
        if denied:
            retry_after = max(item.retry_after_seconds for item in denied)
            raise HTTPException(
                status_code=429,
                detail="foreign claim rate limit exceeded",
                headers={"Retry-After": str(max(1, int(retry_after)))},
            )

        ws = _state_workspace(request)
        if ws is None or not (
            ws / "market_feed" / "announcements.jsonl"
        ).exists():
            raise HTTPException(status_code=404, detail="announcement not found")
        feed = MarketFeed(ws)
        announcement = feed.get(announcement_id, include_expired=True)
        identity = _state_node_identity(request)
        node_did = (
            identity.as_did()
            if identity is not None and hasattr(identity, "as_did")
            else ""
        )
        if (
            announcement is None
            or not node_did
            or not getattr(identity, "can_sign", False)
            or announcement.effective_authority_did() != node_did
        ):
            raise HTTPException(
                status_code=409,
                detail="this node is not the signed authority for the announcement",
            )
        try:
            outcome = record_foreign_claim(
                feed, ClaimStore(ws), announcement_id,
                body.cap_token, body.receipt,
                # Phase 2c:跨 DAO 认领发生在本 hub 进程 → 影子双写 market.claim
                # 进 hub 的 spine 单例(缺失则只 CAS,不阻断)。
                spine=_state_spine(request),
            )
        except ClaimConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        except ClaimRejected as exc:
            raise HTTPException(
                status_code=403, detail=f"{exc.reason}: {exc.detail}")
        from nth_dao.market.claim_ack import sign_authority_claim_ack

        try:
            authority_ack = sign_authority_claim_ack(
                authority=identity,
                announcement=announcement,
                claim_record=outcome.claim_record,
            )
        except (TypeError, ValueError) as exc:
            logger.error("failed to sign authority claim acknowledgement: %s", exc)
            raise HTTPException(
                status_code=503,
                detail="claim was recorded but its authority acknowledgement is unavailable",
            )
        return {
            "claimed": True,
            "announcement_id": announcement_id,
            "claimant_did": outcome.claim_record.get("claimant_did", ""),
            "receipt_id": outcome.claim_record.get("receipt_id", ""),
            "foreign": True,
            "authority_ack_id": authority_ack["ack_id"],
            "authority_ack": authority_ack,
        }

    @app.post("/api/v2/market/federation/claim-foreign")
    def v2_market_claim_foreign_by_key(
        body: ForeignClaimByKeyBody, request: Request,
    ) -> Dict[str, Any]:
        """Record a foreign claim addressed by signed-body content hash."""
        from nth_dao.market.feed import MarketFeed

        ws = _state_workspace(request)
        if ws is None or not (
            ws / "market_feed" / "announcements.jsonl"
        ).exists():
            raise HTTPException(status_code=404, detail="announcement not found")
        announcement = MarketFeed(ws).get_by_federation_key(
            body.federation_key,
            include_expired=True,
        )
        if announcement is None:
            raise HTTPException(status_code=404, detail="announcement not found")
        return _v2_market_claim_foreign(
            announcement.announcement_id,
            ForeignClaimBody(cap_token=body.cap_token, receipt=body.receipt),
            request,
        )

    @app.post("/api/v2/market/{announcement_id}/claim-foreign")
    def v2_market_claim_foreign(
        announcement_id: str, body: ForeignClaimBody, request: Request,
    ) -> Dict[str, Any]:
        """Legacy transport-safe ID route; content-key route is canonical."""
        return _v2_market_claim_foreign(announcement_id, body, request)

    # ── 争议 / 审计 / 治理(Phase 4c:把 spine 投影接进 HTTP)──────────────
    # 写:接受当事方**预签**的争议声明,record_dispute 落 hub spine。走正常鉴权
    #   (公网 hub auth 开时 token-gated;不新开匿名写口)。
    # 读:对 hub spine verify_chain 后回放投影(GET 走 /api/v2 匿名读旁路)。

    @app.post("/api/v2/disputes")
    def v2_dispute_record(
        body: DisputeStatementBody, request: Request,
    ) -> Dict[str, Any]:
        """记录一条已签争议声明(open/evidence/resolve)到 hub spine。

        crypto-authorized:声明自带 signer 签名,record_dispute 验签后落盘,验不过
        → 400。仲裁**授权**(谁有权 resolve)不在此拦,由读端按当前治理策略标注
        (未授权的 resolve 记入可审计但不被采信)。
        """
        from nth_dao.dispute import record_dispute

        spine = _state_spine(request)
        if spine is None:
            raise HTTPException(
                status_code=503, detail="spine unavailable; cannot record dispute"
            )
        try:
            ev = record_dispute(spine, body.statement)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        stmt = body.statement
        return {
            "recorded": True,
            "dispute_id": str(stmt.get("dispute_id", "")),
            "type": str(stmt.get("type", "")),
            "seq": ev.seq,
        }

    @app.get("/api/v2/disputes")
    def v2_disputes_list(request: Request) -> List[Dict[str, Any]]:
        """列出本节点 spine 上的争议(DisputeProjection 回放)。匿名读。

        已裁决的标 ``arbiter_authorized``:据**当前治理策略**判定裁决者是否有权
        (闭合 Phase 3 缺口)。policy 未立宪时为 None(无从判定)。
        """
        from nth_dao.dispute import DisputeProjection
        from nth_dao.governance import (
            ACTION_DISPUTE_RESOLVE, PolicyProjection, can,
        )

        events = _verified_spine_events(request)
        if events is None:
            return []
        dproj = DisputeProjection()
        gproj = PolicyProjection()
        for ev in events:
            dproj.apply(ev)
            gproj.apply(ev)
        out: List[Dict[str, Any]] = []
        for rec in dproj.all():
            authorized = None
            if rec.status == "resolved" and gproj.established and rec.arbiter_did:
                authorized = can(
                    gproj.policy, rec.arbiter_did, ACTION_DISPUTE_RESOLVE).allowed
            out.append({
                "dispute_id": rec.dispute_id,
                "announcement_id": rec.announcement_id,
                "opener_did": rec.opener_did,
                "status": rec.status,
                "ruling": rec.ruling,
                "arbiter_did": rec.arbiter_did,
                "arbiter_authorized": authorized,
                "statement_count": len(rec.statements),
            })
        return out

    @app.post("/api/v2/handoffs")
    def v2_handoff_record(
        body: HandoffStatementBody, request: Request,
    ) -> Dict[str, Any]:
        """Record a pre-signed HandoffCapsule to the signed spine.

        Crypto-authorized: the capsule carries its author DID and signature.
        The server only verifies and persists it; validity is not correctness.
        """
        from nth_dao.runtime import record_handoff

        spine = _state_spine(request)
        if spine is None:
            raise HTTPException(
                status_code=503, detail="spine unavailable; cannot record handoff"
            )
        try:
            ev = record_handoff(spine, body.statement)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        stmt = body.statement
        return {
            "recorded": True,
            "capsule_hash": str(stmt.get("capsule_hash", "")),
            "mission_id": str(stmt.get("mission_id", "")),
            "seq": ev.seq,
            "event_hash": ev.content_hash,
        }

    @app.post("/api/v2/handoffs/responses")
    def v2_handoff_response_record(
        body: HandoffStatementBody, request: Request,
    ) -> Dict[str, Any]:
        """Record a signed refutation or supersession for a handoff capsule."""
        from nth_dao.runtime import (
            record_handoff_response,
            verify_handoff_response,
        )

        spine = _state_spine(request)
        if spine is None:
            raise HTTPException(
                status_code=503,
                detail="spine unavailable; cannot record handoff response",
            )
        ok, why = verify_handoff_response(body.statement)
        if not ok:
            raise HTTPException(
                status_code=400,
                detail=f"invalid handoff response: {why}",
            )
        _require_handoff_response_target_known(request, body.statement)
        _validate_handoff_response_receipt_binding(request, body.statement)
        try:
            ev = record_handoff_response(spine, body.statement)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        stmt = body.statement
        return {
            "recorded": True,
            "response_hash": str(stmt.get("response_hash", "")),
            "target_capsule_hash": str(stmt.get("target_capsule_hash", "")),
            "response_type": str(stmt.get("response_type", "")),
            "seq": ev.seq,
            "event_hash": ev.content_hash,
        }

    @app.get("/api/v2/handoffs/{capsule_hash}/review_packet")
    def v2_handoff_review_packet(
        capsule_hash: str, request: Request,
    ) -> Dict[str, Any]:
        """Return the minimal agent-facing review packet for one handoff."""
        proj = _verified_handoff_projection(request)
        if proj is None:
            raise HTTPException(
                status_code=503,
                detail="handoff projection unavailable; cannot build review packet",
            )
        rec = next(
            (row for row in proj.all() if row.capsule_hash == capsule_hash),
            None,
        )
        if rec is None:
            raise HTTPException(
                status_code=404,
                detail=f"handoff capsule not found: {capsule_hash}",
            )
        evidence = list(rec.capsule.get("evidence", []))
        evidence_verification = _handoff_evidence_verification(evidence)
        return _handoff_review_packet(rec, evidence_verification)

    @app.get("/api/v2/handoffs")
    def v2_handoffs_list(
        request: Request, mission_id: str = "", include_details: bool = False,
    ) -> List[Dict[str, Any]]:
        """List handoff capsules from verified spine replay.

        The returned status is a projection over signed capsule response
        events; it is not a statement that the capsule's diagnosis is true.
        """
        proj = _verified_handoff_projection(request)
        if proj is None:
            return []
        records = proj.for_mission(mission_id) if mission_id else proj.all()
        out: List[Dict[str, Any]] = []
        for rec in records:
            capsule = rec.capsule
            row = {
                "capsule_hash": rec.capsule_hash,
                "mission_id": rec.mission_id,
                "step_id": str(capsule.get("step_id", "")),
                "finding": str(capsule.get("finding", "")),
                "root_cause_hypothesis": str(
                    capsule.get("root_cause_hypothesis", "")),
                "verification_status": str(
                    capsule.get("verification_status", "")),
                "author_did": rec.author_did,
                "status": rec.status,
                "evidence_count": len(list(capsule.get("evidence", []))),
                "test_count": len(list(capsule.get("tests", []))),
                "risk_count": len(list(capsule.get("risks", []))),
                "refutation_count": len(rec.refutations),
                "superseded_by": rec.superseded_by,
            }
            if include_details:
                evidence = list(capsule.get("evidence", []))
                evidence_verification = _handoff_evidence_verification(evidence)
                row.update({
                    "evidence": evidence,
                    "evidence_verification": evidence_verification,
                    "review_packet": _handoff_review_packet(
                        rec, evidence_verification),
                    "changed_files": list(capsule.get("changed_files", [])),
                    "tests": list(capsule.get("tests", [])),
                    "next_actions": list(capsule.get("next_actions", [])),
                    "risks": list(capsule.get("risks", [])),
                    "refutations": rec.refutations,
                    "supersessions": rec.supersessions,
                })
            out.append(row)
        return out

    @app.get("/api/v2/market/{announcement_id}/evidence")
    def v2_market_evidence(
        announcement_id: str, request: Request,
    ) -> Dict[str, Any]:
        """回放一条公告的证据链(audit.reconstruct_evidence)。匿名读、逐项重验。"""
        from nth_dao.audit import reconstruct_evidence

        events = _verified_spine_events(request)
        if events is None:
            return {
                "announcement_id": announcement_id,
                "all_verified": True, "items": [],
            }
        chain = reconstruct_evidence(events, announcement_id)
        return {
            "announcement_id": announcement_id,
            "all_verified": chain.all_verified,
            "items": [
                {
                    "seq": i.seq, "type": i.type, "author_did": i.author_did,
                    "ts_ms": i.ts_ms, "verified": i.verified, "summary": i.summary,
                }
                for i in chain.items
            ],
        }

    @app.get("/api/v2/governance/policy")
    def v2_governance_policy(request: Request) -> Dict[str, Any]:
        """当前生效治理策略(PolicyProjection 回放 governance 事件)。匿名读。"""
        from nth_dao.governance import PolicyProjection

        events = _verified_spine_events(request)
        empty = {"roles": {}, "grants": {}, "constraints": {}}
        if events is None:
            return {
                "established": False, "version": 0,
                "founder_did": "", "policy": empty,
            }
        gproj = PolicyProjection()
        for ev in events:
            gproj.apply(ev)
        return {
            "established": gproj.established,
            "version": gproj.version,
            "founder_did": gproj.founder_did,
            "policy": gproj.policy.to_dict(),
        }

    def _reputation_record_dict(r) -> Dict[str, Any]:
        return {
            "did": r.did, "score": r.score,
            "tasks_claimed": r.tasks_claimed,
            "tasks_accepted": r.tasks_accepted,
            "tasks_published": r.tasks_published,
            "disputed_claims": r.disputed_claims,
        }

    @app.get("/api/v2/reputation")
    def v2_reputation(request: Request) -> List[Dict[str, Any]]:
        """从 spine 派生的可验证信誉(ReputationProjection 回放,top 排序)。匿名读。

        贡献直接从签名的 market.claim/announce 数出,dispute 减分 —— 非中心打分,
        任何节点回放同一日志得同一信誉。
        """
        from nth_dao.reputation_spine import ReputationProjection

        events = _verified_spine_events(request)
        if events is None:
            return []
        proj = ReputationProjection()
        for ev in events:
            proj.apply(ev)
        return [_reputation_record_dict(r) for r in proj.top(100)]

    @app.get("/api/v2/reputation/{did}")
    def v2_reputation_one(did: str, request: Request) -> Dict[str, Any]:
        """单个 DID 的可验证信誉。匿名读。"""
        from nth_dao.reputation_spine import ReputationProjection

        events = _verified_spine_events(request)
        proj = ReputationProjection()
        for ev in (events or []):
            proj.apply(ev)
        return _reputation_record_dict(proj.get(did))

    # ── 授权收件箱(consent 层):cap-token 授予请求 ──────────────────────
    # 写(请求/批准/拒绝)走正常鉴权(公网 hub token-gated);列读匿名,但**不**
    # 泄露已签发的 cap_token 全文(bearer 凭据),只给 token_id/时效等元数据。

    def _cap_projection(request: Request):
        from nth_dao.authz import CapRequestProjection

        events = _verified_spine_events(request)
        if events is None:
            return None
        proj = CapRequestProjection()
        for ev in events:
            proj.apply(ev)
        return proj

    @app.post("/api/v2/cap-requests")
    def v2_cap_request(body: CapRequestBody, request: Request) -> Dict[str, Any]:
        """记录一条 requester 预签的能力授予请求(cap.request)到 hub spine。"""
        from nth_dao.authz import record_cap_request
        spine = _state_spine(request)
        if spine is None:
            raise HTTPException(
                status_code=503, detail="spine unavailable; cannot record request"
            )
        try:
            ev = record_cap_request(spine, body.statement)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {
            "recorded": True,
            "request_id": str(body.statement.get("request_id", "")),
            "seq": ev.seq,
        }

    @app.get("/api/v2/cap-requests")
    def v2_cap_requests_list(request: Request) -> List[Dict[str, Any]]:
        """列出授予请求(CapRequestProjection 回放)。匿名读。

        ⚠️ 已批准项只回 token_id / 时效**元数据**,**不**回 cap_token 全文 ——
        全文是 bearer 凭据,匿名读泄露即等于把能力发给所有人。
        """
        proj = _cap_projection(request)
        if proj is None:
            return []
        out: List[Dict[str, Any]] = []
        for rec in proj.all():
            item: Dict[str, Any] = {
                "request_id": rec.request_id,
                "requester_did": rec.requester_did,
                "capabilities": rec.capabilities,
                "reason": rec.reason,
                "scope": rec.scope,
                "status": rec.status,
                "decided_by_did": rec.decided_by_did,
                "decided_at_ms": rec.decided_at_ms,
            }
            if rec.cap_token:   # 只元数据,绝不回全文 token
                item["token_id"] = rec.cap_token.get("token_id", "")
                item["token_not_after"] = rec.cap_token.get("not_after", 0)
            out.append(item)
        return out

    @app.post("/api/v2/cap-requests/{request_id}/approve")
    def v2_cap_approve(request_id: str, request: Request) -> Dict[str, Any]:
        """批准:本节点签发 cap_token 给 requester,记 cap.grant。token-gated。

        授权(谁能批)= 操作员(写口受 console auth);未来可叠治理 can()。
        """
        from nth_dao.authz import grant_cap_request

        spine = _state_spine(request)
        identity = _state_node_identity(request)
        if spine is None or identity is None or not getattr(
            identity, "can_sign", False
        ):
            raise HTTPException(
                status_code=503, detail="spine or signer identity unavailable"
            )
        proj = _cap_projection(request)
        rec = proj.get(request_id) if proj else None
        if rec is None:
            raise HTTPException(status_code=404, detail="request not found")
        if rec.status != "pending":
            raise HTTPException(
                status_code=409, detail=f"request already {rec.status}")
        token = grant_cap_request(
            spine,
            issuer=identity,
            request_id=request_id,
            requester_did=rec.requester_did,
            capabilities=rec.capabilities,
            scope=rec.scope,
        )
        return {
            "granted": True, "request_id": request_id,
            "token_id": token.get("token_id", ""),
            "subject_did": token.get("subject_did", ""),
        }

    @app.post("/api/v2/cap-requests/{request_id}/deny")
    def v2_cap_deny(
        request_id: str, body: CapDecisionBody, request: Request,
    ) -> Dict[str, Any]:
        """拒绝:记 cap.deny(决策者身份在案)。token-gated。"""
        from nth_dao.authz import deny_cap_request

        spine = _state_spine(request)
        identity = _state_node_identity(request)
        if spine is None or identity is None or not getattr(
            identity, "can_sign", False
        ):
            raise HTTPException(
                status_code=503, detail="spine or signer identity unavailable"
            )
        proj = _cap_projection(request)
        rec = proj.get(request_id) if proj else None
        if rec is None:
            raise HTTPException(status_code=404, detail="request not found")
        if rec.status != "pending":
            raise HTTPException(
                status_code=409, detail=f"request already {rec.status}")
        deny_cap_request(
            spine, decider=identity, request_id=request_id, reason=body.reason
        )
        return {"denied": True, "request_id": request_id}

    # ── 社交层(Phase 社交):关注(单向)/ 好友(双向需确认)─────────────────
    # 发起方=本节点身份(operator 即本节点,与 accept/approve 同),服务端用
    # node_identity 签名后落 spine。写口 token-gated;读匿名回放 SocialProjection。

    def _social_projection(request: Request):
        from nth_dao.social import SocialProjection

        events = _verified_spine_events(request)
        if events is None:
            return None
        proj = SocialProjection()
        for ev in events:
            proj.apply(ev)
        return proj

    def _ensure_social_poller(request: Request) -> None:
        """配了联邦 peer 时,惰性起一次社交语句拉取 poller(把别人发给我的
        关注/好友请求/接受拉进本地 spine)。没配 peer → 零开销。单次起,双检锁。"""
        state = request.app.state
        if getattr(state, "social_fed_started", False):
            return
        ws = _state_workspace(request)
        if not _read_fed_peers(ws):
            return
        identity = _state_node_identity(request)
        if identity is None or not hasattr(identity, "as_did"):
            return
        with _FED_POLLER_LOCK:
            if getattr(state, "social_fed_started", False):
                return
            from .social_federation_poll import start_social_poller

            try:
                interval = float(os.environ.get("NTH_FED_POLL_INTERVAL_S", "20"))
            except ValueError:
                interval = 20.0
            # 只捕获 app(进程级稳定单例),**不**把 per-request 的 request 关进
            # 常驻线程闭包(否则泄漏请求对象、且语义错位)。
            app_ref = request.app
            self_did = identity.as_did()

            def _get_spine():
                try:
                    return app_ref.state.nth.spine
                except AttributeError:
                    return None

            start_social_poller(
                get_self_did=lambda: self_did,
                get_peers=lambda: _read_fed_peers(ws),
                get_spine=_get_spine,
                interval_s=interval,
            )
            state.social_fed_started = True
            logger.info(
                "nth social federation poller started (%d peers, %.0fs)",
                len(_read_fed_peers(ws)), interval,
            )

    def _record_social_action(
        request: Request, statement_type: str, target_did: str,
    ) -> Dict[str, Any]:
        from nth_dao.social import record_social, sign_social_statement

        spine = _state_spine(request)
        identity = _state_node_identity(request)
        if spine is None or identity is None or not getattr(
            identity, "can_sign", False
        ):
            raise HTTPException(
                status_code=503, detail="spine or signer identity unavailable"
            )
        try:
            stmt = sign_social_statement(
                signer=identity, statement_type=statement_type, target_did=target_did
            )
            ev = record_social(spine, stmt)
        except ValueError as exc:   # 自指 / target 空 / 签名无效
            raise HTTPException(status_code=400, detail=str(exc))
        return {
            "recorded": True, "type": statement_type,
            "target_did": target_did, "seq": ev.seq,
        }

    @app.post("/api/v2/social/follow")
    def v2_social_follow(body: SocialTargetBody, request: Request) -> Dict[str, Any]:
        """本节点关注 target_did(单向、免对方确认)。token-gated。"""
        from nth_dao.social import FOLLOW

        return _record_social_action(request, FOLLOW, body.target_did)

    @app.post("/api/v2/social/unfollow")
    def v2_social_unfollow(body: SocialTargetBody, request: Request) -> Dict[str, Any]:
        """取消关注。token-gated。"""
        from nth_dao.social import UNFOLLOW

        return _record_social_action(request, UNFOLLOW, body.target_did)

    @app.post("/api/v2/social/friend/request")
    def v2_social_friend_request(
        body: SocialTargetBody, request: Request,
    ) -> Dict[str, Any]:
        """向 target_did 发好友请求(需对方 accept 才成好友)。token-gated。"""
        from nth_dao.social import FRIEND_REQUEST

        return _record_social_action(request, FRIEND_REQUEST, body.target_did)

    @app.post("/api/v2/social/friend/accept")
    def v2_social_friend_accept(
        body: SocialTargetBody, request: Request,
    ) -> Dict[str, Any]:
        """接受 target_did 的好友请求 → 互为好友。token-gated。"""
        from nth_dao.social import FRIEND_ACCEPT

        return _record_social_action(request, FRIEND_ACCEPT, body.target_did)

    @app.post("/api/v2/social/friend/decline")
    def v2_social_friend_decline(
        body: SocialTargetBody, request: Request,
    ) -> Dict[str, Any]:
        """拒绝 target_did 的好友请求。token-gated。"""
        from nth_dao.social import FRIEND_DECLINE

        return _record_social_action(request, FRIEND_DECLINE, body.target_did)

    @app.post("/api/v2/social/friend/remove")
    def v2_social_friend_remove(
        body: SocialTargetBody, request: Request,
    ) -> Dict[str, Any]:
        """解除与 target_did 的好友关系(或撤回未决请求)。token-gated。"""
        from nth_dao.social import FRIEND_REMOVE

        return _record_social_action(request, FRIEND_REMOVE, body.target_did)

    @app.post("/api/v2/social/block")
    def v2_social_block(body: SocialTargetBody, request: Request) -> Dict[str, Any]:
        """屏蔽 target_did(#3,**静默**):清除既有所有边 + 之后拒收其任何社交语句。
        屏蔽决定纯本地、**不外发**,被屏蔽方无从察觉(隐形拉黑)。token-gated。"""
        from nth_dao.social import BLOCK

        return _record_social_action(request, BLOCK, body.target_did)

    @app.post("/api/v2/social/unblock")
    def v2_social_unblock(body: SocialTargetBody, request: Request) -> Dict[str, Any]:
        """解除屏蔽 target_did(不恢复旧关系,需重新关注/加好友)。静默、token-gated。"""
        from nth_dao.social import UNBLOCK

        return _record_social_action(request, UNBLOCK, body.target_did)

    @app.get("/api/v2/social/me")
    def v2_social_me(request: Request) -> Dict[str, Any]:
        """本节点社交名册:关注/粉丝/好友 + 待我确认的好友请求(进收件箱)。匿名读。"""
        _ensure_social_poller(request)   # 看名册时确保联邦拉取在跑(配了 peer 才起)
        identity = _state_node_identity(request)
        me = identity.as_did() if identity and hasattr(identity, "as_did") else ""
        proj = _social_projection(request)
        if proj is None or not me:
            return {
                "did": me, "following": [], "followers": [], "friends": [],
                "pending_incoming": [], "pending_outgoing": [], "blocked": [],
            }
        return {
            "did": me,
            "following": proj.following(me),
            "followers": proj.followers(me),
            "friends": proj.friends(me),
            "pending_incoming": proj.pending_incoming(me),
            "pending_outgoing": proj.pending_outgoing(me),
            "blocked": proj.blocked(me),
        }

    @app.get("/api/v2/social/{did}")
    def v2_social_one(did: str, request: Request) -> Dict[str, Any]:
        """从本节点视角看与某 DID 的关系 + 该 DID 的公开关注/好友计数。匿名读。"""
        identity = _state_node_identity(request)
        me = identity.as_did() if identity and hasattr(identity, "as_did") else ""
        proj = _social_projection(request)
        if proj is None:
            return {
                "did": did, "relationship": {}, "followers_count": 0,
                "friends_count": 0,
            }
        return {
            "did": did,
            "relationship": proj.relationship(me, did) if me else {},
            "followers_count": len(proj.followers(did)),
            "friends_count": len(proj.friends(did)),
        }

    @app.get("/api/v2/social/federation/pull")
    def v2_social_fed_pull(
        request: Request, since: int = -1,
    ) -> List[Dict[str, Any]]:
        """本节点**自己签发**(actor==self)的社交语句,供对端拉取后按 target 收件。
        匿名读(语句自带签名,拉方 ingest 时逐条验签 + 只收发给自己的)。

        ``since`` = 上次 seq 游标(增量);每页封顶 500,拉方带 since 翻页。
        只暴露本节点自己的出边(关注/好友请求/接受),不转发他人语句。
        """
        spine = _state_spine(request)
        identity = _state_node_identity(request)
        if spine is None or identity is None or not hasattr(identity, "as_did"):
            return []
        from nth_dao.social.federation import local_social_statements

        return local_social_statements(
            spine, identity.as_did(), since_seq=since, limit=500
        )

    @app.post("/api/v2/market/federated/claim")
    async def v2_market_federated_claim(
        body: FederatedClaimBody, request: Request,
    ) -> Any:
        """跨 DAO 认领·本地 hub 编排(XDAO-3):把 XDAO-1/2 串成一键。

        联邦发现的外部任务 → 本地 agent ``claim-sign`` 自签 cap_token+收据 →
        转投到公告**主 DAO** 的 ``/claim-foreign`` 落 CAS → 回传结果。
        来源取自本节点**联邦缓存**(已配置 peer,SSRF-safe),不信请求体。
        """
        import asyncio
        import urllib.error
        import urllib.request

        from nth_dao.cap_token import encode_authorization_header

        sup = _state_supervisor(request)
        if sup is None:
            raise HTTPException(status_code=503, detail="agent supervisor unavailable")
        matching = [
            r for r in sup.list_agents()
            if (
                r.did == body.agent_did
                and r.a2a_port is not None
                and r.alive
            )
        ]
        if not matching:
            raise HTTPException(
                status_code=404,
                detail=f"no live supervised agent did={body.agent_did!r}",
            )
        rec = matching[0]
        # 公告全文 + 来源:取自联邦缓存(已双层验签 + 来源=配置 peer)。
        cache = _state_market_fed_cache(request)
        snapshot = cache.snapshot() if cache is not None else {}
        requested_key = body.federation_key.strip()
        entry = snapshot.get(requested_key) if requested_key else None
        if entry is None and requested_key:
            raise HTTPException(
                status_code=404,
                detail="federated announcement key is not in cache",
            )
        if entry is None and body.announcement_id:
            matches = [
                candidate for candidate in snapshot.values()
                if candidate.get("ann") is not None
                and candidate["ann"].announcement_id == body.announcement_id
            ]
            if len(matches) > 1:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "announcement_id is ambiguous across federation peers; "
                        "refresh Tasks and retry with federation_key"
                    ),
                )
            if len(matches) == 1:
                entry = matches[0]
        if entry is None:
            raise HTTPException(
                status_code=404,
                detail="federated announcement not in cache (refresh Tasks first)",
            )
        if entry.get("stale") is True:
            raise HTTPException(
                status_code=409,
                detail=(
                    "federated announcement is stale and non-actionable; "
                    "refresh its source before claiming"
                ),
            )
        ann = entry["ann"]
        if ann.announcement_id != body.announcement_id:
            raise HTTPException(
                status_code=409,
                detail="federation_key does not match announcement_id",
            )
        source_peer = str(entry.get("source") or "").rstrip("/")
        source_did = str(entry.get("source_did") or "")
        if not source_peer:
            raise HTTPException(
                status_code=409, detail="unknown source peer for this announcement"
            )
        if not source_did or source_did != ann.effective_authority_did():
            raise HTTPException(
                status_code=409,
                detail="federated announcement authority binding is invalid",
            )
        source_resolved_ip = ""
        try:
            source_scheme = urlsplit(source_peer).scheme
            if source_scheme == "https":
                from .market_federation_poll import _resolve_safe_gossip_ip

                source_resolved_ip = _resolve_safe_gossip_ip(source_peer) or ""
                if not source_resolved_ip:
                    raise ValueError("source peer did not resolve to a public IP")
            fresh_metadata, fresh_error = _fetch_and_verify_federation_identity(
                source_peer,
                timeout_seconds=_env_float(
                    "NTH_FED_IDENTITY_TIMEOUT_S",
                    2.0,
                    minimum=0.5,
                    maximum=3.0,
                ),
                expected_did=source_did,
                resolved_ip=source_resolved_ip,
            )
        except (OSError, TimeoutError, ValueError) as exc:
            logger.warning("fresh federation claim identity check failed: %s", exc)
            fresh_metadata = None
            fresh_error = type(exc).__name__
        if fresh_metadata is None:
            logger.warning(
                "fresh federation claim identity rejected for %s: %s",
                source_peer,
                fresh_error,
            )
            raise HTTPException(
                status_code=409,
                detail="source peer identity changed; refresh federation before claiming",
            )

        # 调用方鉴权:agent 自己的 spawn cap_token(与 ask/claim 同款注入)。
        store = _state_cap_tokens_store(request)
        token_id = getattr(rec, "cap_token_id", None)
        auth_token = (
            store.get(token_id) if (token_id and store is not None) else None
        )
        if not isinstance(auth_token, dict):
            raise HTTPException(
                status_code=409,
                detail=f"agent {body.agent_did!r} has no cap_token; re-spawn it",
            )
        auth_hdr = f"CapToken {encode_authorization_header(auth_token)}"
        timeout = _A2A_METHOD_TIMEOUTS.get("claim", _A2A_DEFAULT_TIMEOUT_S)

        def _post(url: str, payload: Dict[str, Any], *, auth: bool, to: float):
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            headers = {
                "Content-Type": "application/json; charset=utf-8",
                "Content-Length": str(len(data)),
                "Accept": "application/json",
            }
            if auth:
                headers["Authorization"] = auth_hdr
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=to) as resp:  # noqa: S310
                    return resp.status, _read_local_a2a_body(resp)
            except urllib.error.HTTPError as exc:
                return exc.code, _read_local_a2a_body(exc)
        # 1) 本地 agent claim-sign(自签 cap_token + ClaimReceipt)。
        sign_url = f"http://127.0.0.1:{rec.a2a_port}/a2a/claim-sign"
        try:
            s_status, s_body = await asyncio.to_thread(
                _post, sign_url, {"announcement": ann.to_dict()},
                auth=True, to=timeout,
            )
        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
            A2AResponseTooLarge,
        ) as exc:
            raise HTTPException(status_code=502, detail=f"claim-sign dispatch failed: {exc}")
        s_content = _decode_or_passthrough(s_body)
        if s_status != 200 or not isinstance(s_content, dict):
            return JSONResponse(
                status_code=s_status if s_status >= 400 else 502, content=s_content
            )
        result = s_content.get("result") or {}
        cap_token, receipt = result.get("cap_token"), result.get("receipt")
        if not isinstance(cap_token, dict) or not isinstance(receipt, dict):
            raise HTTPException(
                status_code=502, detail="agent claim-sign returned no cap_token/receipt"
            )

        # 2) Address the source claim by signed-body hash. Legacy IDs may
        # contain URL delimiters and are never interpolated into the path.
        fwd_url = f"{source_peer}/api/v2/market/federation/claim-foreign"
        try:
            from nth_dao.market.announcement import announcement_federation_key

            foreign_payload = {
                "federation_key": announcement_federation_key(ann),
                "cap_token": cap_token,
                "receipt": receipt,
            }
            if source_resolved_ip:
                from .market_federation_poll import _urllib_post_json_pinned_raw

                f_status, f_body = await asyncio.to_thread(
                    _urllib_post_json_pinned_raw,
                    fwd_url,
                    source_resolved_ip,
                    foreign_payload,
                    timeout_s=15.0,
                )
            else:
                f_status, f_body = await asyncio.to_thread(
                    _post, fwd_url, foreign_payload,
                    auth=False, to=15.0,
                )
        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
            ValueError,
            A2AResponseTooLarge,
        ) as exc:
            raise HTTPException(
                status_code=502, detail=f"forward to source peer failed: {exc}"
            )
        foreign_content = _decode_or_passthrough(f_body)
        if 200 <= f_status < 300:
            if not isinstance(foreign_content, dict) or foreign_content.get(
                "claimed"
            ) is not True:
                raise HTTPException(
                    status_code=502,
                    detail="source peer returned an invalid claim result",
                )
            authority_ack = foreign_content.get("authority_ack")
            from nth_dao.market.claim_ack import (
                AuthorityClaimAckStore,
                verify_authority_claim_ack,
            )
            from nth_dao.market.announcement import announcement_federation_key

            ok, reason = verify_authority_claim_ack(
                authority_ack,
                expected_authority_did=source_did,
                expected_federation_key=announcement_federation_key(ann),
                expected_claimant_did=body.agent_did,
                expected_claim_receipt=receipt,
            )
            if not ok:
                raise HTTPException(
                    status_code=502,
                    detail=f"source authority claim acknowledgement is invalid: {reason}",
                )
            ws = _state_workspace(request)
            if ws is None:
                raise HTTPException(
                    status_code=503,
                    detail="workspace unavailable; cannot persist source claim acknowledgement",
                )
            try:
                AuthorityClaimAckStore(ws).save(authority_ack)
            except (OSError, TimeoutError, ValueError) as exc:
                logger.warning("cannot persist source authority claim ack: %s", exc)
                raise HTTPException(
                    status_code=503,
                    detail="source claim acknowledgement could not be persisted",
                )
            foreign_content["authority_ack_id"] = authority_ack["ack_id"]
        return JSONResponse(status_code=f_status, content=foreign_content)

    @app.post("/api/v2/market/{announcement_id}/claim")
    async def v2_market_claim(
        announcement_id: str, body: ClaimTaskBody, request: Request,
    ) -> Any:
        """认领闭环(切片B):操作员选一个 supervised agent 去认领这条任务。

        hub 不持有 agent 私钥,故认领必须由 agent 自己签(谁干谁签)。流程:
        校验 agent 活着 → 读公告拿能力 → 给 agent **按需铸** cap_token
        (subject=agent DID、能力=任务所需)→ 派发到 agent /a2a/claim(用
        agent 自己的 spawn cap_token 做调用方鉴权)→ agent 用自己私钥
        claim_announcement 并签 ClaimReceipt → 原样回传(含 409 冲突/403 拒)。
        """
        import urllib.error
        import urllib.request

        from nth_dao.cap_token import (
            CAP_NTH_RECEIPT_SIGN, encode_authorization_header, sign_cap_token,
        )
        from nth_dao.market.feed import MarketFeed

        sup = _state_supervisor(request)
        if sup is None:
            raise HTTPException(status_code=503, detail="agent supervisor unavailable")
        matching = [
            r for r in sup.list_agents()
            if r.did == body.agent_did
            and r.a2a_port is not None
            and r.alive
        ]
        if not matching:
            raise HTTPException(
                status_code=404,
                detail=(
                    f"no live supervised agent did={body.agent_did!r} with an a2a_port"
                ),
            )
        rec = matching[0]
        agent_did = body.agent_did

        ws = _state_workspace(request)
        if ws is None:
            raise HTTPException(status_code=503, detail="workspace unavailable")
        if not (ws / "market_feed" / "announcements.jsonl").exists():
            raise HTTPException(status_code=404, detail="market feed is empty")
        ann = MarketFeed(ws).get(announcement_id, include_expired=True)
        if ann is None:
            raise HTTPException(status_code=404, detail="announcement not found")

        identity = _state_node_identity(request)
        if identity is None or not getattr(identity, "can_sign", False):
            raise HTTPException(
                status_code=503,
                detail="node identity unavailable; cannot mint claim cap_token",
            )
        # 按需铸:subject=agent DID、能力=任务所需(claim_announcement 两侧归一)。
        # 对抗审查加固(2026-06-14):
        #  ① 能力来自公告,而公告由**发布方**控制(联邦场景可能是远端、不可
        #     信)。只铸自由格式的**市场技能**,显式剔除保留作用域(nth:/a2a:),
        #     防一条声明特权 scope 的公告让 hub 把特权铸进本节点 agent 的 token。
        #     正常公告(仅市场技能)不受影响;滥用公告会在 claim 端因能力不足
        #     被拒(fail-closed),恰为正确行为。
        #  2. Bind scope_task_id to the ClaimReceipt's complete goal_id so
        #     this token cannot authorize another receipt or task.
        #  ③ 短 TTL(5min):单次认领立即用,最小权限。
        market_caps = [
            c for c in (ann.capability_set or [])
            if isinstance(c, str) and c.strip()
            and not c.strip().lower().startswith(("nth:", "a2a:"))
        ]
        claim_token = sign_cap_token(
            issuer=identity,
            subject_did=agent_did,
            # 无能力门槛的公告(permissionless)给一个惰性占位,满足"非空"约束;
            # claim_announcement 对空 need_skills 任意 have 都通过,占位无副作用。
            capabilities=[
                *(market_caps or ["task:open"]), CAP_NTH_RECEIPT_SIGN,
            ],
            scope_task_id=f"market:claim:{announcement_id}",
            ttl_ms=300_000,
        )
        store = _state_cap_tokens_store(request)
        if store is not None:
            # 审计:记入 cap_token store(可吊销)。失败不阻断认领,只告警。
            try:
                store.record(claim_token)
            except Exception as exc:  # noqa: BLE001
                logger.warning("v2_market_claim: cap_token record failed: %s", exc)

        # 调用方鉴权:用 agent 自己的 spawn cap_token(与 ask 同款注入)。
        token_id = getattr(rec, "cap_token_id", None)
        auth_token = (
            store.get(token_id) if (token_id and store is not None) else None
        )
        if not isinstance(auth_token, dict):
            raise HTTPException(
                status_code=409,
                detail=(
                    f"agent {body.agent_did!r} has no cap_token; re-spawn it "
                    "so the hub can drive it"
                ),
            )

        body_bytes = json.dumps(
            {"announcement_id": announcement_id, "cap_token": claim_token},
            ensure_ascii=False,
        ).encode("utf-8")
        url = f"http://127.0.0.1:{rec.a2a_port}/a2a/claim"
        req_headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Content-Length": str(len(body_bytes)),
            "Authorization": f"CapToken {encode_authorization_header(auth_token)}",
        }
        forward_timeout = _A2A_METHOD_TIMEOUTS.get("claim", _A2A_DEFAULT_TIMEOUT_S)

        def _do_forward() -> Tuple[int, bytes]:
            req = urllib.request.Request(
                url, data=body_bytes, headers=req_headers, method="POST",
            )
            try:
                with urllib.request.urlopen(  # noqa: S310
                    req, timeout=forward_timeout,
                ) as resp:
                    return resp.status, _read_local_a2a_body(resp)
            except urllib.error.HTTPError as http_exc:
                return http_exc.code, _read_local_a2a_body(http_exc)

        try:
            resp_status, content = (
                await _forward_local_agent_with_readiness_retry(_do_forward)
            )
        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
            A2AResponseTooLarge,
        ) as exc:
            raise HTTPException(
                status_code=502,
                detail=f"claim dispatch failed at {url}: {exc}",
            )
        # 目标↔市场回流:认领成功(200 + result.claimed)→ 把对应 mission
        # step 标 CLAIMED + 记 assignee。best-effort,不影响认领本身的结果。
        if resp_status == 200 and isinstance(content, dict):
            result = content.get("result")
            if isinstance(result, dict) and result.get("claimed"):
                mission_id = getattr(ann, "mission_id", "") or ""
                agent_receipt_id = str(result.get("receipt_id", "") or "")
                reflect = _reflect_claim_to_mission(
                    request, ann, announcement_id, agent_did, agent_receipt_id,
                )
                if mission_id:
                    reason = str(reflect.get("reason") or "reflect_failed")
                    result["mission_id"] = mission_id
                    result["mission_reflected"] = bool(reflect.get("reflected"))
                    result["mission_reflect_reason"] = reason
                    if reason in {"reflected", "already_same_claimant"}:
                        result["visibility_status"] = "ok"
                        result["visibility_warnings"] = []
                    else:
                        result["visibility_status"] = "failed"
                        result["visibility_warnings"] = [f"linked_mission_{reason}"]
                    content["result"] = result
                else:
                    visible = _ensure_claim_execution_visible(
                        request, ann, announcement_id, agent_did,
                        str(result.get("receipt_id", "") or ""),
                    )
                    result.update(visible)
                    content["result"] = result
        return JSONResponse(status_code=resp_status, content=content)

    @app.post("/api/v2/missions/{mission_id}/steps/{step_id}/announce")
    def v2_mission_step_announce(
        mission_id: str,
        step_id: str,
        body: AnnounceStepBody,
        request: Request,
    ) -> Dict[str, Any]:
        """Mission↔Task 之桥:把一个 mission step 发成可认领的市场 Task。

        能力/标题/描述取自 step,赏金由操作员设定,公告带 mission_id 回链。
        announcement_id 由 (mission_id, step_id) 确定性派生 → 幂等:重复发
        同一 step 不会在广场上变两条(已发则直接返回原条)。本节点签名。
        """
        from nth_dao.market.feed import MarketFeed
        from nth_dao.orchestration.market_coordinator import (
            announce_step, announcement_id_for,
        )
        from nth_dao.orchestration.mission import StepStatus

        store = getattr(request.app.state.nth, "missions", None)
        if store is None:
            raise HTTPException(status_code=503, detail="mission store unavailable")
        mission = store.get(mission_id)
        if mission is None:
            raise HTTPException(status_code=404, detail="mission not found")
        step = mission.get_step(step_id)
        if step is None:
            raise HTTPException(status_code=404, detail="step not found")
        ws = _state_workspace(request)
        if ws is None:
            raise HTTPException(status_code=503, detail="workspace unavailable")
        identity = _state_node_identity(request)
        if identity is None or not getattr(identity, "can_sign", False):
            raise HTTPException(
                status_code=503,
                detail="node identity unavailable; cannot sign announcement.",
            )
        feed = MarketFeed(ws)
        aid = announcement_id_for(mission_id, step_id)
        # 幂等:这个 step 已经发过就直接返回,不重复 append 同 id 的行。
        existing = feed.get(aid, include_expired=True)
        if existing is not None:
            d = existing.to_dict()
            d["already_announced"] = True
            return d
        # 状态闸(对抗审查补):只有 TODO(未开工、可认领)的 step 能发上市场。
        # 否则会把已认领/进行中/已完成/失败的 step 重新挂出去让人认领重做——
        # 语义错误。已发过的走上面的幂等分支,不受此限。
        if step.status != StepStatus.TODO.value:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"step is '{step.status}'; only 'todo' steps can be "
                    f"announced to the market"
                ),
            )
        try:
            ann = announce_step(
                feed, step,
                publisher=identity,
                mission_id=mission_id,
                reward_minor=int(body.reward_minor),
                reward_asset=body.reward_asset or "credit",
            )
        except (ValueError, TypeError) as exc:
            raise HTTPException(
                status_code=400, detail=f"announce rejected: {exc}",
            )
        _emit_mission_evidence(request, MISSION_STEP_ANNOUNCED, {
            "mission_id": mission_id,
            "step_id": step_id,
            "step_status": step.status,
            "announcement_id": aid,
            "driver_did": getattr(mission, "owner_did", "") or "",
            "reward_minor": int(body.reward_minor),
            "reward_asset": body.reward_asset or "credit",
        })
        d = ann.to_dict()
        d["already_announced"] = False
        return d

    @app.get("/api/v2/agents", response_model=List[AgentEntryM])
    def v2_agents(request: Request) -> List[Dict[str, Any]]:
        # Phase 3a: prepend supervised agents (kind=local, live) ahead
        # of the disk-backed list so the UI surfaces them first.
        # The supervisor view is the source-of-truth for "agents I
        # spawned this session"; disk reflects identities written by
        # other parts of the stack.
        sup = _state_supervisor(request)
        # Phase G: join cap_token scope on supervised agents so the
        # frontend can render a "scoped: <models>" badge inline with
        # the agent card. Pre-resolve the store once outside the loop
        # to keep the per-agent overhead at one ``store.get(id)``
        # dict-lookup-plus-disk-read.
        cap_tokens_store = _state_cap_tokens_store(request)
        from nth_dao.cap_token import CAP_A2A_MESSAGE_SEND

        supervised: List[Dict[str, Any]] = []
        if sup is not None:
            try:
                for rec in sup.list_agents():
                    entry = rec.to_agent_entry()
                    entry["ask_timeout_s"] = _backend_ask_timeout(rec.kind)
                    if not _has_console_bearer(request):
                        # The Agents summary is anonymously readable on LAN
                        # deployments. Never disclose a local filesystem path
                        # to unauthenticated peers; scope_id/revision are enough
                        # for public status and cross-node coordination.
                        entry.pop("work_scope_root", None)
                    # Phase G: try to surface the agent's cap_token
                    # scope_model_allowlist into the listing. Failures
                    # are swallowed (store missing, token deleted, etc.)
                    # — the UI is happier rendering the agent without
                    # scope info than seeing the whole listing 500.
                    if (
                        cap_tokens_store is not None
                        and rec.cap_token_id
                    ):
                        try:
                            tok = cap_tokens_store.get(rec.cap_token_id)
                        except Exception:  # noqa: BLE001
                            tok = None
                        if (
                            isinstance(tok, dict)
                            and "scope_model_allowlist" in tok
                        ):
                            entry["scope_model_allowlist"] = (
                                tok["scope_model_allowlist"]
                            )
                        entry["has_active_cap"] = _cap_token_usable(
                            tok,
                            cap_tokens_store,
                            required_capabilities=[CAP_A2A_MESSAGE_SEND],
                        )
                    else:
                        entry["has_active_cap"] = False
                    supervised.append(entry)
            except Exception as exc:  # noqa: BLE001
                logger.warning("v2_api: supervisor list_agents failed: %s", exc)
        disk = _read_agents_from_disk(_state_workspace(request))
        # Dedup by did so a hub restart that re-reads a supervised
        # agent's identity from disk doesn't double-render it.
        seen_dids = {a["did"] for a in supervised}
        merged = supervised + [a for a in disk if a.get("did") not in seen_dids]
        return merged

    @app.get("/api/v2/agents/backends/status")
    def v2_agent_backend_status(request: Request) -> Dict[str, Any]:
        """Return local backend readiness without exposing secrets or paths."""
        from nth_dao.web.dummy_agent import backend_runtime_status

        statuses = {
            kind: {
                **status,
                "ask_timeout_s": _backend_ask_timeout(kind),
            }
            for kind, status in backend_runtime_status().items()
            if kind != "mock" or _env_bool("NTH_ENABLE_TEST_BACKENDS", False)
        }
        return {"backends": _overlay_live_backend_status(statuses, request)}

    @app.post("/api/v2/agents/{did}/link", status_code=202)
    async def v2_agent_link_submit(did: str, request: Request) -> Dict[str, Any]:
        """Submit a Bot-style asynchronous request to one supervised agent."""
        import asyncio

        # This endpoint makes the Hub spend delegated Agent authority. Do not
        # let an anonymous caller or a narrowly-scoped CapToken turn it into
        # an implicit confused-deputy action.
        _require_console_bearer_for_sensitive_read(request)
        try:
            payload = await request.json()
        except (ValueError, TypeError) as exc:
            raise HTTPException(status_code=400, detail="body must be JSON") from exc
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="body must be a JSON object")
        prompt = payload.get("prompt")
        if not isinstance(prompt, str) or not prompt.strip():
            raise HTTPException(status_code=400, detail="prompt is required")
        if len(prompt.encode("utf-8")) > 1024 * 1024:
            raise HTTPException(status_code=413, detail="prompt exceeds 1MB cap")

        supervisor = _state_supervisor(request)
        if supervisor is None:
            raise HTTPException(status_code=503, detail="agent supervisor unavailable")
        records = [
            record for record in supervisor.list_agents()
            if (
                record.did == did
                and record.a2a_port is not None
                and record.alive
            )
        ]
        if not records:
            raise HTTPException(
                status_code=404,
                detail=f"no live supervised agent for did={did!r}",
            )
        record = records[0]
        idempotency_key = str(payload.get("idempotency_key", "") or "").strip()
        if not idempotency_key:
            raise HTTPException(
                status_code=400,
                detail="idempotency_key is required for AgentLink requests",
            )
        if len(idempotency_key) > 200:
            raise HTTPException(status_code=400, detail="idempotency_key is too long")
        worker_payload = {"prompt": prompt}
        if "timeout_s" in payload:
            timeout_s = _validate_agent_link_timeout(payload["timeout_s"])
            worker_payload["timeout_s"] = timeout_s
        request_hash = _agent_link_request_hash(
            prompt,
            worker_payload.get("timeout_s"),
        )

        job_ref: Dict[str, str] = {}

        def run_agent_link() -> Dict[str, Any]:
            worker_payload["agent_link_job_id"] = job_ref.get("job_id", "")
            status, content, _record, receipt_meta = asyncio.run(
                _drive_supervised_agent_ask(request, did, worker_payload)
            )
            if status != 200:
                raise RuntimeError(
                    _a2a_http_error_message(
                        status,
                        content,
                        backend_kind=str(getattr(record, "kind", "") or ""),
                    )
                )
            result = content.get("result") if isinstance(content, dict) else None
            if not isinstance(result, dict):
                raise RuntimeError("agent returned a malformed result")
            response = str(result.get("response", "") or "").strip()
            if not response:
                raise RuntimeError("agent returned an empty response")
            return {
                "response": response,
                "receipt_id": str(
                    (receipt_meta or {}).get("nth_receipt_id", "") or ""
                ),
            }

        try:
            job = _state_agent_link(request).submit(
                agent_id=str(getattr(record, "agent_id", "") or ""),
                agent_did=did,
                worker=run_agent_link,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                prompt_sha256=_agent_link_prompt_hash(prompt),
                autostart=False,
            )
        except Exception as exc:  # noqa: BLE001
            from .agent_link import (
                AgentLinkBusy,
                AgentLinkStoreFull,
                IdempotencyConflict,
            )

            if isinstance(exc, AgentLinkBusy):
                raise HTTPException(status_code=429, detail=str(exc)) from exc
            if isinstance(exc, IdempotencyConflict):
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            if isinstance(exc, AgentLinkStoreFull):
                raise HTTPException(status_code=507, detail=str(exc)) from exc
            raise HTTPException(
                status_code=503,
                detail=f"agent link unavailable: {type(exc).__name__}",
            ) from exc
        job_ref["job_id"] = job.job_id
        try:
            _state_agent_link(request).start(did)
        except Exception as exc:  # noqa: BLE001
            try:
                _state_agent_link(request).store.transition(
                    job.job_id,
                    "failed",
                    error="AgentLink worker could not be started.",
                )
            except (KeyError, OSError, RuntimeError, TypeError, ValueError):
                logger.exception(
                    "failed to persist AgentLink start failure for %s",
                    job.job_id,
                )
            raise HTTPException(
                status_code=503,
                detail=f"agent link could not start: {type(exc).__name__}",
            ) from exc
        return {
            "job_id": job.job_id,
            "agent_did": job.agent_did,
            "state": job.state,
        }

    @app.get("/api/v2/agents/{did}/link/{job_id}")
    def v2_agent_link_status(
        did: str, job_id: str, request: Request,
    ) -> Dict[str, Any]:
        """Read one asynchronous AgentLink job without exposing prompts."""
        _require_console_bearer_for_sensitive_read(request)
        job = _state_agent_link(request).get(job_id)
        if job is None or job.agent_did != did:
            raise HTTPException(status_code=404, detail="AgentLink job not found")
        return job.to_dict()

    @app.post("/api/v2/agents/{did}/link/{job_id}/reconcile")
    async def v2_agent_link_reconcile(
        did: str, job_id: str, request: Request,
    ) -> Dict[str, Any]:
        """Reconcile an uncertain job from a verified signed Agent receipt.

        This is deliberately a local-console operation for now. A future
        remote transport may authenticate the same body with an agent
        capability token, but must preserve these exact evidence checks.
        """
        _require_console_bearer_for_sensitive_read(request)
        try:
            payload = await request.json()
        except (ValueError, TypeError) as exc:
            raise HTTPException(status_code=400, detail="body must be JSON") from exc
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="body must be a JSON object")
        receipt = payload.get("receipt")
        response = payload.get("response")
        if not isinstance(receipt, dict):
            raise HTTPException(status_code=400, detail="receipt must be an object")
        if not isinstance(response, str) or not response.strip():
            raise HTTPException(status_code=400, detail="response is required")
        response = response.strip()
        if len(response.encode("utf-8")) > 100_000:
            raise HTTPException(status_code=413, detail="response exceeds 100KB cap")

        manager = _state_agent_link(request)
        job = manager.get(job_id)
        if job is None or job.agent_did != did:
            raise HTTPException(status_code=404, detail="AgentLink job not found")
        if job.state not in {"delivery_unknown", "completed_unverified", "completed"}:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"AgentLink job is {job.state}; only uncertain or completed "
                    "unverified jobs can be reconciled"
                ),
            )
        if not job.prompt_sha256:
            raise HTTPException(
                status_code=409,
                detail="AgentLink job has no prompt hash and cannot be reconciled",
            )

        try:
            _verify_agent_receipt(
                agent_id=job.agent_id,
                expected_did=job.agent_did,
                receipt=receipt,
            )
            receipt_payload = _agent_link_receipt_payload(receipt)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        receipt_id = str(receipt.get("receipt_id", "") or "")
        if not receipt_id:
            raise HTTPException(status_code=422, detail="receipt is missing receipt_id")
        if receipt_payload.get("method") != "ask":
            raise HTTPException(status_code=422, detail="receipt is not an ask receipt")
        if str(receipt_payload.get("agent_link_job_id", "") or "") != job.job_id:
            raise HTTPException(
                status_code=422,
                detail="receipt is not bound to this AgentLink job",
            )
        if str(receipt_payload.get("request_sha256", "") or "") != job.prompt_sha256:
            raise HTTPException(
                status_code=422,
                detail="receipt prompt hash does not match the AgentLink job",
            )
        response_hash = hashlib.sha256(response.encode("utf-8")).hexdigest()
        if str(receipt_payload.get("response_sha256", "") or "") != response_hash:
            raise HTTPException(
                status_code=422,
                detail="receipt response hash does not match the supplied response",
            )

        receipts = _state_receipts_store(request)
        if receipts is None:
            raise HTTPException(status_code=503, detail="receipt store unavailable")
        try:
            reconciled = manager.reconcile_completed(
                job_id,
                response=response,
                receipt_id=receipt_id,
                persist_receipt=lambda: receipts.save(receipt),
            )
        except (OSError, RuntimeError, TypeError, ValueError, KeyError) as exc:
            from .agent_link import AgentLinkConflict

            if isinstance(exc, AgentLinkConflict):
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            logger.exception("AgentLink reconciliation failed for %s", job_id)
            raise HTTPException(
                status_code=500,
                detail=f"AgentLink reconciliation could not be persisted: {type(exc).__name__}",
            ) from exc
        return reconciled.to_dict()

    @app.post(
        "/api/v2/agents/spawn",
        status_code=201,
        response_model=SpawnResponseM,
    )
    def v2_agents_spawn(
        body: SpawnAgentBody,
        request: Request,
    ) -> Dict[str, Any]:
        """Phase 3b: ask the supervisor to bring up a new agent and
        issue a cap_token bound to the child's freshly-generated DID.

        Sequence:
          1. Child process starts, generates Ed25519 keypair, emits
             ``agent_started`` event with its W3C did:key. Supervisor
             blocks until that handshake event arrives (≤10s).
          2. Hub signs a cap_token with ``state.node_identity`` as
             issuer + the child's did as subject_did. The token grants
             ``nth:receipt_sign`` plus any KNOWN_CAPABILITIES the
             client requested.
          3. Cap_token is persisted via ``state.cap_tokens`` for
             audit + revocation.
          4. AgentRecord stamped with ``cap_token_id``.

        Failure modes:
          503 — supervisor / node_identity / cap_token store missing.
                Fail-closed: we never bring up an unauthorised agent.
          500 — runner spawn or cap_token issuance failed AFTER the
                child started. Supervisor has already torn the child
                down before this point.
          429 — live-agent ceiling reached (NTH_MAX_LIVE_AGENTS).
        """
        from .agent_supervisor import AgentCapacityExceeded

        sup = _state_supervisor(request)
        if sup is None:
            raise HTTPException(
                status_code=503,
                detail="agent supervisor unavailable",
            )
        identity = _state_node_identity(request)
        if identity is None or not getattr(identity, "can_sign", False):
            raise HTTPException(
                status_code=503,
                detail=(
                    "signer identity unavailable; cannot issue cap_token "
                    "for spawned agent. Bootstrap the workspace identity first."
                ),
            )
        cap_tokens_store = _state_cap_tokens_store(request)
        if cap_tokens_store is None:
            raise HTTPException(
                status_code=503,
                detail=(
                    "cap_token store unavailable; cannot record issued "
                    "token. Bootstrap the workspace cap_tokens dir first."
                ),
            )

        # Closures over identity + store. The supervisor calls this
        # AFTER the child has reported its DID, so subject_did is the
        # child's real W3C did:key.
        from nth_dao.cap_token import (
            CAP_A2A_MESSAGE_SEND, CAP_NTH_RECEIPT_SIGN, KNOWN_CAPABILITIES,
            sign_cap_token,
        )

        # Phase 6b: capture the request's scope_model_allowlist into
        # the closure so the supervisor-level signature doesn't need
        # to know about per-token model scope. None passes through to
        # sign_cap_token unchanged (field omitted from the token,
        # legacy-compatible).
        requested_model_allowlist = body.scope_model_allowlist

        def _issue_cap_token(
            subject_did: str, requested_caps: List[str],
        ) -> Dict[str, Any]:
            # Filter to KNOWN_CAPABILITIES so a typo (e.g. "nth:rceipt_sign")
            # doesn't end up as an issued cap that no verifier recognises.
            # CAP_NTH_RECEIPT_SIGN is always included — without it the
            # child can't sign anything, defeating Phase 3b's purpose.
            # CAP_A2A_MESSAGE_SEND is also always included (2026-06-13):
            # the hub's /api/v2/agents/{did}/ask[-stream] proxy injects
            # this agent's cap_token to drive the child; without the
            # a2a:message_send scope the child fails-closed (403) and the
            # v2 console "Run task" panel can't talk to it. Granting it by
            # default makes every spawned agent immediately drivable.
            caps: List[str] = [CAP_NTH_RECEIPT_SIGN, CAP_A2A_MESSAGE_SEND]
            for c in requested_caps:
                if c in KNOWN_CAPABILITIES and c not in caps:
                    caps.append(c)
            token = sign_cap_token(
                issuer=identity,
                subject_did=subject_did,
                capabilities=caps,
                scope_model_allowlist=requested_model_allowlist,
            )
            try:
                cap_tokens_store.record(token)
            except Exception as exc:
                # Audit-store failure is fatal: the operator's
                # revocation/audit trail must be consistent.
                logger.exception(
                    "v2_api: cap_token audit-record failed for %s: %s",
                    subject_did, exc,
                )
                raise
            return token

        # Persistent by default: allocate an owned identity path and pass it
        # to the child. First run creates the key; later restarts load the
        # same key and therefore keep the same DID. Non-persistent agents keep
        # the legacy ephemeral identity behavior.
        identity_file: Optional[str] = None
        roster = None
        if body.persist:
            ws = _state_workspace(request)
            if ws is not None:
                from .agent_roster import AgentRoster

                roster = AgentRoster(ws)
                identity_file = roster.allocate_identity_file()
        try:
            from .agent_supervisor import resolve_work_scope

            scope = resolve_work_scope(body.project_workdir, body.work_access)
            record = sup.spawn(
                kind=body.kind,
                label=body.label,
                capabilities=body.capabilities,
                cap_token_issuer=_issue_cap_token,
                identity_file=identity_file,
                work_scope=scope,
            )
        except AgentCapacityExceeded as exc:
            # 2026-06-14 审查补:达到运行态 agent 上限。这是"暂时容量不足"
            # 而非客户端错误或服务端故障 → 429 Too Many Requests,带可读
            # 提示(可调 NTH_MAX_LIVE_AGENTS)。fail-closed:此前未起子进程。
            logger.warning("v2_api: spawn rejected — at capacity: %s", exc)
            raise HTTPException(
                status_code=429,
                detail=f"spawn rejected: {exc}",
            )
        except ValueError as exc:
            # 6B-5 fix (Phase 6b deferred backlog): bad input to
            # sign_cap_token (e.g. non-string scope_model_allowlist
            # entry, scope_task_id format error) propagates from
            # the issuer closure as ValueError. That's a CLIENT
            # error — operator gave us junk — and belongs on the
            # 400 path, not the 500 path which implies "we broke".
            # Keeps the spawn-fail semantics aligned with how the
            # other write endpoints (e.g. /api/cap_tokens/issue)
            # already classify ValueError as bad-request.
            logger.info(
                "v2_api: spawn rejected — bad request: %s", exc,
            )
            raise HTTPException(
                status_code=400,
                detail=f"spawn rejected: {exc}",
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("v2_api: spawn failed: %s", exc)
            raise HTTPException(
                status_code=500,
                detail=f"spawn failed: {exc}",
            )
        # Register after successful spawn. If roster persistence fails, the
        # current agent remains running; only restart restore is degraded.
        if roster is not None and identity_file:
            try:
                roster.add(
                    identity_file=identity_file, kind=record.kind,
                    label=record.label, capabilities=body.capabilities,
                    did=record.did,
                    project_workdir=record.work_scope.root,
                    work_access=record.work_scope.access,
                    work_revision=record.work_scope.revision,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "v2_api: agent spawned but roster persist failed: %s", exc
                )
        return {
            "agent_id": record.agent_id,
            "did": record.did,
            "kind": record.kind,
            "label": record.label,
            "pid": record.pid,
            "cap_token_id": record.cap_token_id,
            "a2a_port": record.a2a_port,
            "agent": record.to_agent_entry(),
        }

    @app.post("/api/v2/agents/{agent_id}/stop")
    def v2_agents_stop(
        agent_id: str,
        request: Request,
    ) -> Dict[str, Any]:
        """Stop a supervised agent.

        Persistent agents are disabled in the private roster. Their identity
        material is retained for audit, recovery, or an explicit future
        re-enable action; stopping an Agent never deletes files.
        """
        sup = _state_supervisor(request)
        if sup is None:
            raise HTTPException(
                status_code=503,
                detail="agent supervisor unavailable",
            )
        # Capture the DID before stop() removes the supervisor record.
        rec = sup.get(agent_id)
        did = getattr(rec, "did", "") if rec is not None else ""
        ok = sup.stop(agent_id)
        if not ok:
            raise HTTPException(
                status_code=404,
                detail=f"agent {agent_id!r} not under supervision",
            )
        if did:
            try:
                ws = _state_workspace(request)
                if ws is not None:
                    from .agent_roster import AgentRoster

                    roster = AgentRoster(ws)
                    roster.disable_by_did(did, reason="operator-stop")
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "v2_api: agent stopped but roster disable failed: %s", exc
                )
        return {"agent_id": agent_id, "stopped": True}

    @app.get("/api/v2/agents/{did}/ping")
    def v2_agents_ping(did: str, request: Request) -> Dict[str, Any]:
        """Phase 3d: A2A proxy — forward a GET /ping to the
        supervised agent identified by ``did``. The hub looks up
        the agent's ``a2a_port`` from the supervisor, then makes a
        localhost-only HTTP call to ``127.0.0.1:<port>/ping`` and
        returns whatever the child answered (typically the agent's
        identity card + uptime).

        Status codes:
          404 — no supervised agent with that DID, OR the agent
                exists but has no a2a_port (bind failed in child).
          502 — the child's HTTP server didn't answer within 2s.
          503 — supervisor unavailable.

        Phase 3e will generalize to a JSON-RPC POST /a2a forwarder
        with method + body. For now /ping is enough to prove the
        wire works end-to-end. """
        import urllib.error
        import urllib.request

        sup = _state_supervisor(request)
        if sup is None:
            raise HTTPException(
                status_code=503,
                detail="agent supervisor unavailable",
            )
        matching = [
            r for r in sup.list_agents()
            if (
                r.did == did
                and r.a2a_port is not None
                and r.alive
            )
        ]
        if not matching:
            raise HTTPException(
                status_code=404,
                detail=(
                    f"no live supervised agent for did={did!r} with "
                    "an a2a_port. Verify the agent is up via "
                    "GET /api/v2/agents."
                ),
            )
        rec = matching[0]
        url = f"http://127.0.0.1:{rec.a2a_port}/ping"
        try:
            with urllib.request.urlopen(url, timeout=2.0) as resp:  # noqa: S310
                if resp.status != 200:
                    raise HTTPException(
                        status_code=502,
                        detail=(
                            f"child returned HTTP {resp.status} from /ping at {url}"
                        ),
                    )
                raw = _read_local_a2a_body(resp)
        except urllib.error.URLError as exc:
            raise HTTPException(
                status_code=502,
                detail=f"A2A proxy could not reach {url}: {exc}",
            )
        except (TimeoutError, OSError, A2AResponseTooLarge) as exc:
            raise HTTPException(
                status_code=502,
                detail=f"A2A proxy timed out / failed at {url}: {exc}",
            )
        # H-2 fix (review round Phase 3d R1): malformed responses
        # (non-UTF-8 bytes, invalid JSON) used to bubble up as 500
        # because the decode + parse happened outside the
        # urllib-error try/except. A misbehaving / mis-coded child
        # is an UPSTREAM failure; surface it as 502 so the
        # operator's debugging starts at the right layer.
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HTTPException(
                status_code=502,
                detail=(
                    f"A2A proxy received malformed response from "
                    f"{url}: {type(exc).__name__}: {exc}"
                ),
            )
        return data

    @app.post("/api/v2/agents/{did}/a2a/{method}")
    async def v2_agents_a2a(
        did: str, method: str, request: Request,
    ) -> Any:
        """Phase 3e: A2A JSON-RPC-style POST forwarder.

        Body is forwarded verbatim to the child's ``POST /a2a/<method>``
        endpoint. The ``Authorization`` header (carrying the
        caller's ``CapToken``) is passed through so the child can
        validate it. The child's response — body + status — is
        returned to the caller as-is.

        Status codes:
          404 — no live supervised agent for ``did`` with an
                a2a_port, OR (forwarded) the child rejects the
                method as unknown.
          401/403 — (forwarded) the child rejected the caller's
                    auth header.
          413 — body exceeds the hub's 1MB forward cap.
          502 — child returned malformed bytes or didn't answer.
          503 — supervisor unavailable.

        The hub does NOT validate the cap_token itself — that's the
        child's job and keeps the trust boundary at one place.
        Phase 3f may add hub-side scope validation as a fast-path
        before the proxy forward. """
        import urllib.error
        import urllib.request

        sup = _state_supervisor(request)
        if sup is None:
            raise HTTPException(
                status_code=503,
                detail="agent supervisor unavailable",
            )
        matching = [
            r for r in sup.list_agents()
            if (
                r.did == did
                and r.a2a_port is not None
                and r.alive
            )
        ]
        if not matching:
            raise HTTPException(
                status_code=404,
                detail=(f"no live supervised agent for did={did!r} with an a2a_port"),
            )
        rec = matching[0]

        # H-2 fix (review round Phase 3e R1): check Content-Length
        # BEFORE awaiting the body so a 1GB POST is rejected at the
        # header layer instead of fully buffered into hub memory.
        # Falls through to await body() to enforce the cap when
        # Content-Length is absent / malformed (Starlette will have
        # parsed the body already in that case, but bounds-checking
        # after is the safety net).
        cl_header = request.headers.get("Content-Length")
        if cl_header is not None:
            try:
                claimed_length = int(cl_header)
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail=f"Content-Length is not an integer: {cl_header!r}",
                )
            if claimed_length > 1024 * 1024:
                raise HTTPException(
                    status_code=413,
                    detail=(f"Content-Length {claimed_length} exceeds 1MB A2A cap"),
                )
        body_bytes = await request.body()
        if len(body_bytes) > 1024 * 1024:
            raise HTTPException(
                status_code=413,
                detail=(f"body length {len(body_bytes)} exceeds 1MB A2A cap"),
            )

        url = f"http://127.0.0.1:{rec.a2a_port}/a2a/{method}"
        req_headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Content-Length": str(len(body_bytes)),
        }
        # Pass the caller's auth through so the child can verify
        # against its own cap_token's issuer_did.
        auth = request.headers.get("Authorization")
        if auth:
            req_headers["Authorization"] = auth

        # H-1 fix (review round Phase 4 R1): use the per-method
        # timeout so slow backends (claude-code, future Hermes,
        # etc.) aren't capped at the snappy default that was sized
        # for /ping + /echo. Unknown methods inherit the default.
        forward_timeout = _a2a_forward_timeout(
            method, body_bytes, backend_kind=getattr(rec, "kind", None),
        )

        # Phase 5.2: SSE streaming proxy. We dispatch to a separate
        # forwarder because the buffered path uses ``asyncio.to_thread``
        # for a one-shot call, while the streaming path needs a
        # queue-bridged async generator so the operator's browser
        # sees deltas as they arrive at the hub.
        if method == "ask-stream":
            return _proxy_ssestream(
                url=f"http://127.0.0.1:{rec.a2a_port}/a2a/{method}",
                body_bytes=body_bytes,
                req_headers=req_headers,
                forward_timeout=forward_timeout,
            )

        def _do_forward() -> Tuple[int, bytes]:
            req = urllib.request.Request(
                url, data=body_bytes, headers=req_headers, method="POST",
            )
            try:
                with urllib.request.urlopen(  # noqa: S310
                    req, timeout=forward_timeout,
                ) as resp:
                    return resp.status, _read_local_a2a_body(resp)
            except urllib.error.HTTPError as http_exc:
                # Child returned non-2xx — forward status + body.
                return http_exc.code, _read_local_a2a_body(http_exc)

        try:
            resp_status, content = (
                await _forward_local_agent_with_readiness_retry(_do_forward)
            )
        except urllib.error.URLError as exc:
            raise HTTPException(
                status_code=502,
                detail=f"A2A proxy could not reach {url}: {exc}",
            )
        except (TimeoutError, OSError, A2AResponseTooLarge) as exc:
            raise HTTPException(
                status_code=502,
                detail=f"A2A proxy timed out / failed at {url}: {exc}",
            )

        if resp_status == 200:
            _persist_agent_response_receipt(request, rec.agent_id, rec.did, content)
            content = _bound_agent_result_projection(content)
        return JSONResponse(status_code=resp_status, content=content)

    async def _agent_ask(did: str, method: str, request: Request) -> Any:
        """UI 集成（2026-06-13）：hub 侧"代操作员驱动任务"端点。

        根因修复：原 ``/api/v2/agents/{did}/a2a/{method}`` 代理把调用方的
        Authorization **原样透传**。浏览器没有签名私钥、产不出 ``CapToken``
        头，子端校验 → 401，于是 UI 里"任务流程/流式输出"永远跑不通。

        本端点反过来：浏览器只需 console 认证（操作员），**由 hub 加载该
        spawn 出来的 agent 自己的 cap_token（落盘在 team_cap_tokens/）、
        注入 ``Authorization: CapToken <...>``**，再代理到子端
        ``/a2a/ask`` 或 ``/a2a/ask-stream``。签名材料留在 hub，浏览器不碰。

        method ∈ {"ask", "ask-stream"}。ask-stream 走 SSE 流式代理，UI 实时
        看到 delta。
        """
        import urllib.error
        import urllib.request

        sup = _state_supervisor(request)
        if sup is None:
            raise HTTPException(status_code=503, detail="agent supervisor unavailable")
        matching = [
            r for r in sup.list_agents()
            if (
                r.did == did
                and r.a2a_port is not None
                and r.alive
            )
        ]
        if not matching:
            raise HTTPException(
                status_code=404,
                detail=f"no live supervised agent for did={did!r} with an a2a_port",
            )
        rec = matching[0]
        from nth_dao.cap_token import CAP_A2A_MESSAGE_SEND

        token_store = _state_cap_tokens_store(request)
        existing_token_id = getattr(rec, "cap_token_id", None)
        existing_token = (
            token_store.get(existing_token_id)
            if (existing_token_id and token_store is not None) else None
        )
        if not _cap_token_usable(
            existing_token,
            token_store,
            required_capabilities=[CAP_A2A_MESSAGE_SEND],
        ):
            refreshed = _refresh_supervised_agent_cap_token(
                request,
                rec,
                previous_token=(
                    existing_token if isinstance(existing_token, dict) else None
                ),
            )
            rec.cap_token_id = str(refreshed.get("token_id") or "")

        # 加载该 agent 自己的 cap_token 并注入（keystone）。
        token_id = getattr(rec, "cap_token_id", None)
        if not token_id:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"agent {did!r} has no cap_token — re-spawn it with "
                    "capabilities=['a2a:message_send'] so the hub can drive it."
                ),
            )
        store = _state_cap_tokens_store(request)
        token = store.get(token_id) if store is not None else None
        if not isinstance(token, dict):
            raise HTTPException(
                status_code=409,
                detail=f"cap_token {token_id!r} not found in store for agent {did!r}",
            )
        from nth_dao.cap_token import encode_authorization_header

        body_bytes = await request.body()
        if len(body_bytes) > 1024 * 1024:
            raise HTTPException(status_code=413, detail="body exceeds 1MB A2A cap")

        url = f"http://127.0.0.1:{rec.a2a_port}/a2a/{method}"
        req_headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Content-Length": str(len(body_bytes)),
            "Authorization": f"CapToken {encode_authorization_header(token)}",
        }
        forward_timeout = _a2a_forward_timeout(
            method, body_bytes, backend_kind=getattr(rec, "kind", None),
        )

        if method == "ask-stream":
            return _proxy_ssestream(
                url=url, body_bytes=body_bytes,
                req_headers=req_headers, forward_timeout=forward_timeout,
            )

        def _do_forward() -> Tuple[int, bytes]:
            req = urllib.request.Request(
                url, data=body_bytes, headers=req_headers, method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=forward_timeout) as resp:  # noqa: S310
                    return resp.status, _read_local_a2a_body(resp)
            except urllib.error.HTTPError as http_exc:
                return http_exc.code, _read_local_a2a_body(http_exc)

        try:
            resp_status, content = (
                await _forward_local_agent_with_readiness_retry(_do_forward)
            )
        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
            A2AResponseTooLarge,
        ) as exc:
            raise HTTPException(
                status_code=502,
                detail=f"agent-ask proxy failed at {url}: {exc}",
            )
        if resp_status == 200:
            _persist_agent_response_receipt(request, rec.agent_id, rec.did, content)
            content = _bound_agent_result_projection(content)
            result = content.get("result") if isinstance(content, dict) else None
            response_text = (
                str(result.get("response") or "").strip()
                if isinstance(result, dict) else ""
            )
            if response_text:
                try:
                    sup.mark_provider_state(rec.agent_id, "ready")
                except Exception as state_exc:  # noqa: BLE001
                    logger.warning(
                        "v2_api: direct provider state update failed for %s: %s",
                        rec.did,
                        state_exc,
                    )
        return JSONResponse(
            status_code=resp_status,
            content=content,
        )

    @app.post("/api/v2/agents/{did}/ask")
    async def v2_agents_ask(did: str, request: Request) -> Any:
        return await _agent_ask(did, "ask", request)

    @app.post("/api/v2/agents/{did}/ask-stream")
    async def v2_agents_ask_stream(did: str, request: Request) -> Any:
        return await _agent_ask(did, "ask-stream", request)

    @app.post("/api/v2/agents/{did}/summarize")
    async def v2_agents_summarize(did: str, request: Request) -> Any:
        """温层(2026-06-14):把一段对话原文压成一条**签名摘要**,服务端
        make + verify。body ``{messages:[{message_id,sender_id/sender_label,
        body}...], conversation_id?, instruction?}``。

        驱动方式同 ``_agent_ask``(hub 注入该 agent 自己的 cap_token),但
        prompt = 对话规范转录;拿回 response+receipt 后用 ``verify_summary``
        判"确由该 agent、为这段确切原文而签"。返回 SummaryRecord 形状。
        签名/验签都在服务端(JS 做不了加密)。
        """
        import asyncio
        import hashlib
        import json as _json
        import urllib.error
        import urllib.request

        from nth_dao.cap_token import encode_authorization_header
        from nth_dao.conversation.summary import (
            DEFAULT_INSTRUCTION, canonical_transcript, summary_prompt,
            verify_summary,
        )

        sup = _state_supervisor(request)
        if sup is None:
            raise HTTPException(status_code=503, detail="agent supervisor unavailable")
        matching = [
            r for r in sup.list_agents()
            if (
                r.did == did
                and r.a2a_port is not None
                and r.alive
            )
        ]
        if not matching:
            raise HTTPException(
                status_code=404, detail=f"no live supervised agent for did={did!r}"
            )
        rec = matching[0]
        from nth_dao.cap_token import CAP_A2A_MESSAGE_SEND

        token_store = _state_cap_tokens_store(request)
        existing_token_id = getattr(rec, "cap_token_id", None)
        existing_token = (
            token_store.get(existing_token_id)
            if (existing_token_id and token_store is not None) else None
        )
        if not _cap_token_usable(
            existing_token,
            token_store,
            required_capabilities=[CAP_A2A_MESSAGE_SEND],
        ):
            refreshed = _refresh_supervised_agent_cap_token(
                request,
                rec,
                previous_token=(
                    existing_token if isinstance(existing_token, dict) else None
                ),
            )
            rec.cap_token_id = str(refreshed.get("token_id") or "")
        token_id = getattr(rec, "cap_token_id", None)
        store = _state_cap_tokens_store(request)
        token = store.get(token_id) if (token_id and store is not None) else None
        if not isinstance(token, dict):
            raise HTTPException(
                status_code=409, detail=f"agent {did!r} has no usable cap_token"
            )

        try:
            payload = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="body must be JSON")
        messages = payload.get("messages")
        if not isinstance(messages, list) or not messages:
            raise HTTPException(status_code=400, detail="messages (non-empty list) required")
        if len(messages) > 500:
            raise HTTPException(
                status_code=413,
                detail="too many messages for one summary (max 500); chunk client-side",
            )
        conversation_id = str(payload.get("conversation_id") or "")
        instruction = str(payload.get("instruction") or DEFAULT_INSTRUCTION)
        transcript = canonical_transcript(messages)
        prompt = summary_prompt(transcript, instruction)

        body_bytes = _json.dumps({"prompt": prompt}).encode("utf-8")
        # 审查修复:转录可能很大(N 条长消息),封顶 prompt 大小,既防 DoS
        # 也避开子端 /a2a/ask 的 1MB 上限。超了让前端分块再摘要。
        if len(body_bytes) > 256 * 1024:
            raise HTTPException(
                status_code=413,
                detail="transcript too large for one summary (max 256KB); chunk client-side",
            )
        url = f"http://127.0.0.1:{rec.a2a_port}/a2a/ask"
        req_headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Authorization": f"CapToken {encode_authorization_header(token)}",
        }
        timeout = _A2A_METHOD_TIMEOUTS.get("ask", _A2A_DEFAULT_TIMEOUT_S)

        def _forward() -> Tuple[int, bytes]:
            req = urllib.request.Request(
                url, data=body_bytes, headers=req_headers, method="POST"
            )
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                    return resp.status, _read_local_a2a_body(resp)
            except urllib.error.HTTPError as e:
                return e.code, (_read_local_a2a_body(e) if e.fp else b"")

        try:
            status, raw = await asyncio.get_event_loop().run_in_executor(
                None, _forward,
            )
        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
            A2AResponseTooLarge,
        ) as exc:
            raise HTTPException(
                status_code=502,
                detail=f"summarize proxy failed at {url}: {exc}",
            ) from exc
        try:
            data = _json.loads(raw.decode("utf-8", "replace") or "{}")
        except Exception:
            data = {}
        if status != 200 or "not-yet-authorized" in _json.dumps(data):
            raise HTTPException(
                status_code=(status if status != 200 else 502),
                detail=f"summarize drive failed: {str(data)[:160]}",
            )
        result = data.get("result", data) if isinstance(data, dict) else {}
        summary_text = str(result.get("response", ""))
        receipt = result.get("receipt")
        ok, reason = verify_summary(
            receipt,
            summary_text=summary_text,
            messages=messages,
            expected_signer=did,
            instruction=instruction,
        )
        from .agent_link import bound_agent_response

        projected_summary, summary_truncated = bound_agent_response(summary_text)
        return {
            "conversation_id": conversation_id,
            "covered_message_ids": [str(m.get("message_id", "")) for m in messages],
            "transcript_sha256": hashlib.sha256(transcript.encode("utf-8")).hexdigest(),
            "summary_text": projected_summary,
            "summary_truncated": summary_truncated,
            "agent_did": did,
            "instruction": instruction,
            "verified": ok,
            "reason": reason,
            "receipt": receipt,
        }

    @app.get("/api/v2/cap_tokens", response_model=List[CapTokenSummaryM])
    def v2_cap_tokens(request: Request) -> List[Dict[str, Any]]:
        return _read_cap_tokens_from_disk(_state_workspace(request))

    @app.get("/api/v2/conversations")
    def v2_conversations() -> List[Dict[str, Any]]:
        return []

    @app.get("/api/v2/messages/{conv_id}")
    def v2_messages(conv_id: str) -> List[Dict[str, Any]]:
        del conv_id
        return []

    @app.get("/api/v2/health")
    def v2_health() -> Dict[str, Any]:
        prefix = "/api/v2/"
        endpoints = sorted({
            route.path[len(prefix):]  # type: ignore[attr-defined]
            for route in app.routes
            if getattr(route, "path", "").startswith(prefix)
            and getattr(route, "path", "") != "/api/v2/health"
        })
        lan_runtime = _lan_federation_runtime_status(app)
        return {
            "ok": True,
            "phase": 1,
            "endpoints": endpoints,
            "federation": {
                "public_peer_url": lan_runtime["public_peer_url"],
                "lan_configured": lan_runtime["lan_federation_configured"],
                "lan_publish_enabled": lan_runtime["lan_publish_enabled"],
                "lan_discovery_enabled": lan_runtime["lan_discovery_enabled"],
                "transport_available": lan_runtime["lan_transport_available"],
                "publisher_active": lan_runtime["lan_publisher_active"],
                "lan_ready": lan_runtime["lan_federation_ready"],
            },
        }

    logger.info("v2_api: registered /api/v2/* live endpoints")
