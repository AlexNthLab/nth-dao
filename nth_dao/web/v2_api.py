"""
v2 console read endpoints — Phase 1 of the local-hub design.

The v2 frontend (``frontend/src/v2/``) currently sources every view
from ``mock.ts``. This module is the wire that flips that single
seed file into a real HTTP API so the same UI can render either
mock data OR live disk state — depending on which the hub finds.

╔═══════════════════════════ DRIFT WATCH ═══════════════════════════╗
║  The ``_seed_*`` functions below MUST stay structurally aligned   ║
║  with the corresponding ``mock*`` exports in                      ║
║  ``frontend/src/v2/mock.ts`` (same ids, same titles, same DIDs,   ║
║  same array ordering). When the hub is unreachable the v2 console ║
║  uses mock.ts; when the hub is up but a single endpoint fails the ║
║  UI mixes live + mock for OTHER endpoints. If the two seeds drift ║
║  the user sees different decisions / processes / agents depending ║
║  on which side answered.                                          ║
║                                                                   ║
║  Timestamps are allowed to drift (mock.ts uses Date.now() to keep ║
║  "5m ago" labels fresh; Python uses datetime.now() each request)  ║
║  — those generate different values by design, fine.               ║
║                                                                   ║
║  Phase 2: extract a single seed.json at frontend/src/v2/seed.json ║
║  that both sides import, eliminating the drift class entirely.    ║
║  Tracking: review pass#1 finding N1 (2026-06-10).                 ║
╚═══════════════════════════════════════════════════════════════════╝

Design contract (matches ``frontend/src/v2/types-v2.ts`` exactly):

    GET /api/v2/identity        → IdentityHeader
    GET /api/v2/decisions       → Decision[]
    GET /api/v2/missions        → MissionSummary[]
    GET /api/v2/processes       → ProcessCard[]
    GET /api/v2/receipts        → ReceiptSummary[]
    GET /api/v2/rules           → Rule[]
    GET /api/v2/agents          → AgentEntry[]
    GET /api/v2/cap_tokens      → CapTokenSummary[]
    GET /api/v2/conversations   → Conversation[]
    GET /api/v2/messages/{cid}  → ChatMessage[]

Data sources (per endpoint):

  - ``processes``: tries ``team_layer/blackboard/`` first via the
    existing :class:`Blackboard.list` API; falls back to the seed
    when the dir is empty. This is the FIRST endpoint that proves
    "v2 UI shows real blackboard" — the user's stated Phase 1 goal.
  - ``receipts``: scans ``team_receipts/`` for JSON files when
    present.
  - ``cap_tokens``: scans ``team_cap_tokens/``.
  - ``agents``: reads ``team_agents/`` then falls back to seed.
  - all other endpoints: serve the seed until Phase 2 lands real
    backends.

The seed is intentionally a near-exact translation of the v2
``mock.ts`` so that a user starting the hub with empty disk sees
the same UI they saw under HMR-only. Once Blackboard / receipts /
agents have real entries the live data takes priority.

Phase boundaries (per the local-hub plan, 2026-06-10):
  Phase 1 (this file)      — READ-only API surface
  Phase 2                  — POST / WS for decisions, missions,
                             cap_tokens, receipt signing
  Phase 3                  — supervised agent runtime: multiple
                             backends, A2A routing, real receipts

This module deliberately does NOT register the routes itself —
``__init__.py`` calls :func:`register_v2_routes` once the rest of
the app is wired so the catch-all ``/{path:path}`` route stays
last in the routing table.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# Seed data — structurally aligned with frontend/src/v2/mock.ts
# (review fix N1, 2026-06-10). IDs, titles, DIDs, ordering all
# match the TypeScript exports so a side-by-side comparison
# stays consistent. Timestamps are deliberately allowed to drift
# (mock.ts uses Date.now() to keep "5m ago" labels fresh; here
# we generate fresh ISO strings each request).
# ─────────────────────────────────────────────────────────────

# DID aliases — match mock.ts top-of-file constants for parity.
_HELPER_A = "did:key:z6MkqHKGkA1NXG2DWjsa7GAgrn4D7Dm57GwjeFm568311A"
_HELPER_B = "did:key:z6MkpQ8eF1xRzL3tJyN5sWvD9XbA2C7uYkP4hM8kT6f3B"
_OPERATOR_DID = "did:key:z6MkmRxmBi9p9ziBz2JzBwd8Y5iMzzhPXAi95MPZiLEJJqjL"


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _iso_offset(seconds: float) -> str:
    """ISO timestamp at `now + seconds` (negative for past). """
    return datetime.fromtimestamp(
        datetime.now(timezone.utc).timestamp() + seconds, timezone.utc,
    ).isoformat()


def _seed_identity() -> Dict[str, Any]:
    return {
        "agent_id": "admin",
        "did": _OPERATOR_DID,
        "code": "a3ff-62eb",
    }


def _seed_decisions() -> List[Dict[str, Any]]:
    """Mirrors mock.ts mockDecisions (3 entries: dec-001 to dec-003).

    Ordering matches: dec-001 first = Sign payment mandate (medium),
    NOT the prior Cross-DAO vote ordering — drift fix N1. """
    return [
        {
            "id": "dec-001",
            "title": "Sign payment mandate to Acme Cloud — ¥3,500",
            "rationale": (
                "Monthly compute bill for the launch infrastructure. Within "
                "budget envelope of ¥5,000/mo set in mission charter. Acme "
                "is in the verified vendor list. No anomaly in the invoice "
                "amount versus last 3 months."
            ),
            "impact": "medium",
            "proposer_did": _HELPER_A,
            "proposer_label": "billing-helper",
            "mission_id": "mission-launch-2026",
            "preview_receipt": {
                "kind": "nth-execution-receipt-v1",
                "signer_did": _HELPER_A,
                "goal_id": "mission-launch-2026",
                "timeline": [
                    {
                        "timestamp": 1717840800000,
                        "type": "nth.mandate_signed",
                        "payload": {
                            "vendor": "acme-cloud",
                            "amount_cny": 3500,
                            "mandate_id": "mandate-2026-06-09-001",
                        },
                    },
                ],
            },
            "raised_at": "2026-06-09T18:42:00Z",
            "cap_expires_at": "2026-06-10T02:42:00Z",
        },
        {
            "id": "dec-002",
            "title": "Delegate code-refactor task to helper-B for 4 hours",
            "rationale": (
                "Backlog item BL-1247 hit blocker. helper-B specialises in "
                "refactoring with a 92% acceptance rate on similar tasks in "
                "the last 30 days. Requested cap_token: a2a:message_send + "
                "nth:receipt_sign, scope_task_id=task-bl-1247, ttl=4h."
            ),
            "impact": "low",
            "proposer_did": _HELPER_A,
            "proposer_label": "planner",
            "preview_receipt": {
                "kind": "nth-cap-token-v1",
                "subject_did": _HELPER_B,
                "capabilities": ["a2a:message_send", "nth:receipt_sign"],
                "scope_task_id": "task-bl-1247",
                "ttl_ms": 14_400_000,
            },
            "raised_at": "2026-06-09T17:15:00Z",
        },
        {
            "id": "dec-003",
            "title": "Cross-DAO vote: ratify governance proposal in mumolawos",
            "rationale": (
                "Outside your home DAO — voting in mumolawos consortium on "
                "proposal MGV-2026-07: adopt motebit execution-ledger@1.0 "
                "as wire-format standard. Aligns with our DESIGN_TRADE_OFFS "
                "§2 commitment. Other 4 founders have signed. Your vote "
                "tips quorum."
            ),
            "impact": "high",
            "proposer_did": _OPERATOR_DID,
            "proposer_label": "self-prompt",
            "preview_receipt": {
                "kind": "nth-vote-receipt-v1",
                "proposal_id": "MGV-2026-07",
                "vote": "yes",
                "cross_dao": "mumolawos",
            },
            "raised_at": "2026-06-09T14:08:00Z",
        },
    ]


def _seed_missions() -> List[Dict[str, Any]]:
    """Mirrors mock.ts mockMissions — 2 entries. """
    return [
        {
            "id": "mission-launch-2026",
            "title": "NTH DAO 1.0 launch",
            "goal": "Ship 1.0 with announce + post-mortem doc",
            "status": "active",
            "steps_total": 3,
            "steps_done": 1,
            "steps_in_progress": 1,
            "driver_label": "billing-helper",
            "driver_did": _HELPER_A,
            "cap_token_id": "cap-bnHs82Lq",
            "started_at": "2026-06-08T09:00:00Z",
            "next_actionable": "Send draft to early users for review",
        },
        {
            "id": "mission-refactor-billing",
            "title": "Refactor billing module",
            "goal": "Replace BL-1247 + companion fixtures",
            "status": "active",
            "steps_total": 5,
            "steps_done": 0,
            "steps_in_progress": 2,
            "driver_label": "code-helper",
            "driver_did": _HELPER_B,
            "cap_token_id": "cap-3xQ1pTaM",
            "started_at": "2026-06-09T15:30:00Z",
            "next_actionable": "Extract pricing service from monolith",
        },
    ]


def _seed_processes() -> List[Dict[str, Any]]:
    """Mirrors mock.ts mockProcesses — 5 orders ord-1240 to ord-1248. """
    return [
        {
            "id": "ord-1247",
            "title": "Order #1247",
            "subtitle": "2× Mechanical keyboard · Tokyo",
            "workflow": "shopping",
            "stage": "in_progress",
            "current_agent": "fulfillment-bot",
            "next_agent": "shipping-bot",
            "cap_token_id": "cap-bnHs82Lq",
            "amount": "¥3,400",
            "updated_at": _iso_offset(-22 * 60),
            "auto": True,
        },
        {
            "id": "ord-1248",
            "title": "Order #1248",
            "subtitle": "1× Standing desk · Osaka",
            "workflow": "shopping",
            "stage": "received",
            "current_agent": "intake-bot",
            "next_agent": "fulfillment-bot",
            "cap_token_id": "cap-bnHs82Lq",
            "amount": "¥8,900",
            "updated_at": _iso_offset(-4 * 60),
            "auto": True,
        },
        {
            "id": "ord-1246",
            "title": "Order #1246",
            "subtitle": "1× Cable kit · Kyoto",
            "workflow": "shopping",
            "stage": "done",
            "current_agent": "shipping-bot",
            "amount": "¥240",
            "updated_at": _iso_offset(-2 * 3600),
            "auto": True,
        },
        {
            "id": "ord-1244",
            "title": "Order #1244 — refund request",
            "subtitle": "Customer claims damaged on arrival",
            "workflow": "support",
            "stage": "awaiting_external",
            "current_agent": "support-bot",
            "next_agent": "refund-bot",
            "cap_token_id": "cap-supportLong",
            "amount": "¥1,200",
            "updated_at": _iso_offset(-35 * 60),
            "auto": True,
        },
        {
            "id": "ord-1240",
            "title": "Order #1240 — chargeback flagged",
            "subtitle": "Bank dispute received, needs manual review",
            "workflow": "support",
            "stage": "blocked",
            "current_agent": "support-bot",
            "cap_token_id": "cap-supportLong",
            "amount": "¥4,500",
            "updated_at": _iso_offset(-12 * 3600),
            "auto": False,
        },
    ]


def _seed_receipts() -> List[Dict[str, Any]]:
    """Mirrors mock.ts mockReceipts — 2 entries. """
    return [
        {
            "id": "rcpt-aaa1",
            "signer_did": _HELPER_A,
            "signer_label": "billing-helper",
            "goal_id": "mission-launch-2026",
            "content_hash": "0a9c0bf3e89b6901cdab12345678cafe...",
            "prev_content_hash": "",
            "has_cap_token": True,
            "summary": "Drafted launch announcement v1",
            "issued_at": "2026-06-09T11:20:00Z",
        },
        {
            "id": "rcpt-aaa2",
            "signer_did": _HELPER_A,
            "signer_label": "billing-helper",
            "goal_id": "mission-launch-2026",
            "content_hash": "a7f8ab3c5b93c83a...",
            "prev_content_hash": "0a9c0bf3e89b6901cdab12345678cafe...",
            "has_cap_token": True,
            "summary": "Sent to 3 early users",
            "issued_at": "2026-06-09T13:45:00Z",
        },
    ]


def _seed_rules() -> List[Dict[str, Any]]:
    """Mirrors mock.ts mockRules — 4 entries rule-001 to rule-004. """
    return [
        {
            "id": "rule-001",
            "title": "Auto-pack and ship orders under ¥5,000",
            "when": "New order received, amount < ¥5,000, item in stock",
            "then": (
                "fulfillment-bot packs → shipping-bot dispatches → "
                "notification-bot mails tracking number"
            ),
            "workflow": "shopping",
            "cap_token_id": "cap-bnHs82Lq",
            "status": "active",
            "fired_30d": 87,
            "updated_at": "2026-05-15T10:00:00Z",
        },
        {
            "id": "rule-002",
            "title": "Auto-refund within 30 days of purchase",
            "when": "Refund request received, within 30d, no fraud flag",
            "then": (
                "support-bot confirms → refund-bot processes → "
                "ledger-bot reconciles"
            ),
            "workflow": "support",
            "cap_token_id": "cap-supportLong",
            "status": "active",
            "fired_30d": 12,
            "updated_at": "2026-05-20T14:30:00Z",
        },
        {
            "id": "rule-003",
            "title": "Hold chargebacks for manual review",
            "when": "Bank chargeback notification received",
            "then": "Raise Decision (do not auto-process)",
            "workflow": "support",
            "cap_token_id": "cap-supportLong",
            "status": "active",
            "fired_30d": 1,
            "updated_at": "2026-05-22T09:15:00Z",
        },
        {
            "id": "rule-004",
            "title": "Auto-sign vendor invoices from verified vendors",
            "when": (
                "Mandate request from vendor in verified-list, amount "
                "< ¥10,000"
            ),
            "then": "mandate-bot signs → ledger-bot records",
            "workflow": "finance",
            "cap_token_id": "cap-financeLong",
            "status": "draft",
            "fired_30d": 0,
            "updated_at": "2026-06-08T18:00:00Z",
        },
    ]


def _seed_agents() -> List[Dict[str, Any]]:
    """Mirrors mock.ts mockAgents — 5 entries. """
    return [
        {
            "did": _HELPER_A,
            "code": "7e3a-91b2",
            "label": "billing-helper",
            "source": "local",
            "capabilities": ["nth-dao.chat", "nth-dao.mandate"],
            "last_seen": _iso_offset(-5 * 60),
            "has_active_cap": True,
        },
        {
            "did": _HELPER_B,
            "code": "1f9c-44de",
            "label": "code-helper",
            "source": "local",
            "capabilities": ["nth-dao.chat", "nth-dao.tasks"],
            "last_seen": _iso_offset(-30 * 60),
            "has_active_cap": True,
        },
        {
            "did": "did:key:z6MkrTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
            "code": "a3d8-c5fa",
            "label": "Alice (Acme Cloud rep)",
            "source": "contact",
            "capabilities": ["nth-dao.chat", "nth-dao.mandate"],
            "last_seen": _iso_offset(-2 * 86400),
            "has_active_cap": False,
        },
        {
            "did": "did:key:z6Mk5p1H3kT9YqXqMpL7Wm2N6bV8jK4cD5fE3hQ9rZxAtPq",
            "code": "62b1-08e4",
            "label": "mumolawos-coordinator",
            "source": "lan",
            "capabilities": [
                "nth-dao.chat",
                "nth-dao.dao-management",
                "nth-dao.governance",
                "nth-dao.a2a-protocol",
            ],
            "last_seen": _iso_offset(-12 * 60),
            "has_active_cap": False,
        },
        {
            "did": "did:key:z6MkjyN3aP2qLkR8wEsTvB4nMc6dF9gXuYhAvKkH7tQ4rPsM",
            "code": "ff04-7c3b",
            "label": "fulfillment-bot",
            "source": "local",
            "capabilities": ["nth-dao.chat", "nth-dao.tasks"],
            "last_seen": _iso_offset(-90),
            "has_active_cap": True,
        },
    ]


def _seed_cap_tokens() -> List[Dict[str, Any]]:
    """Mirrors mock.ts mockCapTokens — 2 entries cap-bnHs82Lq, cap-3xQ1pTaM. """
    now_ms = int(time.time() * 1000)
    return [
        {
            "token_id": "cap-bnHs82Lq",
            "subject_did": _HELPER_A,
            "subject_label": "billing-helper",
            "capabilities": ["a2a:message_send", "nth:receipt_sign"],
            "scope_task_id": "mission-launch-2026",
            "not_before": now_ms - 9 * 3600_000,
            "not_after": now_ms + 3 * 3600_000,
            "revoked": False,
            "use_count": 12,
        },
        {
            "token_id": "cap-3xQ1pTaM",
            "subject_did": _HELPER_B,
            "subject_label": "code-helper",
            "capabilities": [
                "a2a:message_send",
                "a2a:task_split",
                "nth:receipt_sign",
            ],
            "scope_task_id": "task-bl-1247",
            "not_before": now_ms - 2 * 3600_000,
            "not_after": now_ms + 2 * 3600_000,
            "revoked": False,
            "use_count": 4,
        },
    ]


def _seed_conversations() -> List[Dict[str, Any]]:
    """Mirrors mock.ts mockConversations — 4 entries. """
    return [
        {
            "id": "ch-general",
            "title": "#general",
            "subtitle": "Home DAO · 4 members",
            "last_preview": (
                "billing-helper: Acme invoice queued for your "
                "approval — see Decisions"
            ),
            "last_at": _iso_offset(-8 * 60),
            "unread": 1,
            "kind": "channel",
        },
        {
            "id": "dm-billing-helper",
            "title": "DM: billing-helper",
            "subtitle": "Direct line to your AI accountant",
            "last_preview": (
                "I drafted the launch announcement. Receipt id 0a9c0bf3…"
            ),
            "last_at": _iso_offset(-22 * 60),
            "unread": 0,
            "kind": "dm",
        },
        {
            "id": "dm-code-helper",
            "title": "DM: code-helper",
            "subtitle": "Refactor sessions",
            "last_preview": (
                "Pricing service extracted. Tests pass. Ready for review."
            ),
            "last_at": _iso_offset(-4 * 3600),
            "unread": 0,
            "kind": "dm",
        },
        {
            "id": "ch-launch",
            "title": "#launch",
            "subtitle": "Home DAO · 3 members",
            "last_preview": "you: shipping it Friday. final QA tonight.",
            "last_at": _iso_offset(-86400),
            "unread": 0,
            "kind": "channel",
        },
    ]


def _seed_messages(conv_id: str) -> List[Dict[str, Any]]:
    """Mirrors mock.ts mockChatMessages — ch-general + dm-billing-helper
    have content, dm-code-helper + ch-launch are empty. """
    if conv_id == "ch-general":
        return [
            {
                "message_id": "m-1",
                "sender_id": "admin",
                "sender_label": "you",
                "body": "morning. anyone seen the Acme invoice come through?",
                "created_at": _iso_offset(-45 * 60),
            },
            {
                "message_id": "m-2",
                "sender_id": _HELPER_A,
                "sender_label": "billing-helper",
                "body": (
                    "Yes — landed at 09:42. ¥3,500. Within your vendor "
                    "allowlist. I queued it as a Decision so you can "
                    "approve when ready."
                ),
                "created_at": _iso_offset(-8 * 60),
                "nth_receipt_id": "0a9c0bf3e89b6901cdab12345678cafe",
            },
        ]
    if conv_id == "dm-billing-helper":
        return [
            {
                "message_id": "m-10",
                "sender_id": "admin",
                "sender_label": "you",
                "body": "draft the launch announcement, low-key tone please",
                "created_at": _iso_offset(-80 * 60),
            },
            {
                "message_id": "m-11",
                "sender_id": _HELPER_A,
                "sender_label": "billing-helper",
                "body": (
                    "Drafted v1. Receipt id 0a9c0bf3… signed under your "
                    "cap_token cap-bnHs82Lq. Want me to ping 3 early users?"
                ),
                "created_at": _iso_offset(-22 * 60),
                "nth_receipt_id": "0a9c0bf3e89b6901cdab12345678cafe",
            },
        ]
    return []


# ─────────────────────────────────────────────────────────────
# Disk readers — overlay seed when real data is present.
# Each guarded by a try/except so a single broken disk entry
# can't take down the API.
# ─────────────────────────────────────────────────────────────

def _project_root() -> Path:
    """Repo root — nth_dao/web/v2_api.py → ../.. is the repo dir."""
    return Path(__file__).resolve().parent.parent.parent


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
    "current_agent": lambda e, m: e.author,           # BB.author → UI.current_agent
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


def _workspace_only_mode() -> bool:
    """Honour ``NTH_V2_WORKSPACE_ONLY=true`` env flag.

    Review fix N3 (2026-06-10): the repo-fixture fallback in
    ``_candidate_dirs`` is useful for dev/demo but actively wrong
    for users who deliberately deleted their workspace data and
    expect a clean slate. The flag opts out of the fallback so
    the disk readers see ONLY the workspace path. Accepts the
    case-insensitive truthy strings "true"/"1"/"yes"/"on". """
    raw = os.environ.get("NTH_V2_WORKSPACE_ONLY", "").strip().lower()
    return raw in {"true", "1", "yes", "on"}


def _candidate_dirs(workspace: Optional[Path], subdir: str) -> List[Path]:
    """Return prioritized candidate paths for a disk-store dir.

    Review fix C5 (2026-06-10): the previous version hardcoded the
    repo root, but WebState persists data under ``workspace`` (the
    default of which is ``~/.nth-dao/workspaces/default``). The
    correct read order is:
      1. workspace/{subdir}    — live data the running app wrote
      2. <repo>/{subdir}       — pre-workspace layout / dev fixtures
         (SKIPPED when NTH_V2_WORKSPACE_ONLY=true)

    Both are checked; first NON-EMPTY result wins. Without the env
    flag, deleted workspace data resurrects from repo fixtures —
    intentional for the dev workflow, opt-out for production via
    NTH_V2_WORKSPACE_ONLY (see review fix N3 2026-06-10). """
    out: List[Path] = []
    if workspace:
        out.append(workspace / subdir)
    if not _workspace_only_mode():
        out.append(_project_root() / subdir)
    return out


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
            break  # First non-empty source wins (_candidate_dirs order).
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
    next_actionable: Optional[str] = None


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
# The decision queue is in-process: a dict on ``app.state`` seeded
# from ``_seed_decisions()`` on first access. Mutations (approve /
# reject / defer remove the id) live in process memory. Receipts
# go to disk via ``state.receipts`` (the existing ReceiptStore).
#
# Phase 3 will replace the in-memory store with a real persistent
# decision queue and add cap_token-gated authorization. For Phase
# 2 the hub is 127.0.0.1-only and treats POST as operator-privileged
# (same posture as v1's /api/cap_tokens/issue path).
# ─────────────────────────────────────────────────────────────


def _decisions_store(request: Request) -> Dict[str, Dict[str, Any]]:
    """Lazy per-app singleton — keyed by decision id.

    Thread-safety (S4 note 2026-06-10): the check-then-set on
    ``v2_decisions_store`` is NOT atomic — two concurrent first
    requests could both build a fresh store and the second one
    would clobber the first. The Phase 2 hub is single-user
    local-bound, so the TOCTOU is academic; uvicorn's default
    single-worker config also serialises requests within the
    asyncio event loop. Phase 3 (multi-user / multi-worker) MUST
    move this to a process-shared store (SQLite / Redis) with
    proper locking. """
    state = request.app.state
    store = getattr(state, "v2_decisions_store", None)
    if store is None:
        store = {d["id"]: d for d in _seed_decisions()}
        state.v2_decisions_store = store
    return store


def _state_node_identity(request: Request) -> Optional[Any]:
    """Signing identity from app.state.nth (set up in __init__.py
    by _bootstrap). Returns None if not initialised — endpoints
    handling that case must fail closed (503), never return an
    unsigned receipt. """
    try:
        return request.app.state.nth.node_identity
    except AttributeError:
        return None


def _state_receipts_store(request: Request) -> Optional[Any]:
    """ReceiptStore from app.state.nth.receipts. Returns None if
    state isn't wired. """
    try:
        return request.app.state.nth.receipts
    except AttributeError:
        return None


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


# H-1 fix (review round Phase 4 R1): per-method proxy timeout. The
# original 2s blanket was fine for /ping + /a2a/echo (instant) but
# silently broke the /a2a/ask path with the claude-code backend
# (the CLI takes ~30s on cold sessions). Methods not in this map
# inherit ``_A2A_DEFAULT_TIMEOUT_S`` — keeps the snappy default for
# wire-test calls while letting ``ask`` honour its real backend cost.
_A2A_DEFAULT_TIMEOUT_S = 2.0
_A2A_METHOD_TIMEOUTS: Dict[str, float] = {
    "ask": 65.0,    # claude-code backend default is 60s + 5s slack
    # Phase 5.2: streaming variant gets a longer window because the
    # caller may keep the connection open while the model generates.
    # 125s = 120s backend allowance + 5s for hub round-trip overhead.
    "ask-stream": 125.0,
}


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
                store = getattr(state, "v2_decisions_store", None)
                if store is None:
                    store = {d["id"]: d for d in _seed_decisions()}
                    state.v2_decisions_store = store
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
                store[decision_id] = decision

            sup = build_default_supervisor(
                cap_token_dir=cap_token_dir,
                receipt_persistor=_receipt_persistor,
                decision_raiser=_decision_raiser,
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
    return sup


class SpawnAgentBody(_Model):
    """POST /api/v2/agents/spawn request body. """
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


class AnnounceTaskBody(_Model):
    """POST /api/v2/market/announce 请求体:往任务市场发一条公告。"""
    title: str = Field(..., description="任务标题(必填)。")
    description: str = Field(default="", description="任务详述。")
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


class AnnounceStepBody(_Model):
    """POST .../missions/{mid}/steps/{sid}/announce 请求体:把 mission step
    发成可认领的市场 Task(Mission↔Task 之桥)。能力/标题/描述取自 step,
    赏金由操作员在发布时设定。"""
    reward_minor: int = Field(
        default=0, ge=0, description="赏金,整数最小单位(禁 float)。")
    reward_asset: str = Field(default="credit", description="赏金资产类型。")


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
                        # aread reads remaining body fully; cap below.
                        body = await resp.aread()
                        yield _error_event(
                            f"upstream-{resp.status_code}",
                            body[:_ERR_BODY_CAP].decode(
                                "utf-8", errors="replace",
                            ),
                        )
                        return
                    # aiter_bytes yields each chunk httpx receives. No
                    # forced 1KB read size — we hand them up the SSE
                    # pipe at whatever granularity the child emitted,
                    # preserving event boundaries.
                    async for chunk in resp.aiter_bytes():
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


def _decode_or_passthrough(raw: bytes) -> Any:
    """Decode JSON bytes; on failure return ``{raw_text: <str>}``
    so the caller still gets SOMETHING readable instead of a 500.
    """
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        # Truncate for safety — a 1MB binary blob in the JSON
        # response would be wasteful.
        text = raw[:1024].decode("utf-8", errors="replace")
        return {
            "raw_text_preview": text,
            "raw_length": len(raw),
            "note": "child returned non-JSON; preview truncated to 1KB",
        }


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


def _resolve_decision(
    decision_id: str,
    request: Request,
    *,
    sign: bool,
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
      - Decision store is in-process. A hub restart resets the queue
        from seed. Persisting is Phase 3 (or whenever a real backend
        emits decisions instead of seeding them).
      - Mission_id mapping: when the decision carries one, use it as
        ``goal_id`` so the receipt links to the mission. Else use
        the decision id itself.
    """
    # Lazy imports — execution_receipt module is heavy.
    from nth_dao.execution_receipt import (
        TimelineEntry, sign_receipt,
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
        store.pop(decision_id, None)
        return {
            "decision_id": decision_id,
            "removed": True,
            "signed": False,
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

    signer_did = identity.as_did() if hasattr(identity, "as_did") else ""
    try:
        prev_hash = receipts_store.head_content_hash(signer_did)
    except Exception as ex:
        logger.warning("v2_api: head_content_hash failed: %s", ex)
        prev_hash = ""

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

    goal_id = decision.get("mission_id") or decision_id
    receipt = sign_receipt(
        timeline,
        identity,
        goal_id=goal_id,
        prev_content_hash=prev_hash,
    )

    # Save BEFORE removing the decision: if save fails the user
    # should be able to retry the same approval. (receipts_store
    # is guaranteed non-None here by the 503 guard above.)
    #
    # Chain-gap caveat (review pass#2 note 2026-06-10): if save
    # fails mid-batch (5 approves in a row, #3 fails) the chain
    # has a gap — receipt #4's prev_content_hash points to #2.
    # ``verify_receipt_chain`` still accepts this because every
    # prev pointer resolves within the on-disk set, but the
    # operator's audit log will show 4 receipts where they
    # expected 5. Documenting; not fixing in Phase 2.
    try:
        receipts_store.save(receipt)
    except Exception as exc:
        logger.exception("v2_api: receipts_store.save failed: %s", exc)
        raise HTTPException(
            status_code=500,
            detail=f"signed receipt could not be persisted: {exc}",
        )

    # Remove the decision from the queue only after the receipt has
    # landed on disk.
    store.pop(decision_id, None)

    # Shape matches ReceiptSummary so the frontend can splice it
    # into its receipts state without a /api/v2/receipts refetch.
    summary: Dict[str, Any] = {
        "id": receipt.get("receipt_id", ""),
        "signer_did": receipt.get("signer_did", ""),
        "signer_label": "you",
        "goal_id": goal_id,
        "content_hash": receipt.get("content_hash", ""),
        "prev_content_hash": prev_hash,
        "has_cap_token": bool(receipt.get("authorizing_cap_token")),
        "summary": decision.get("title", decision_id),
        "issued_at": receipt.get("issued_at", ""),
    }
    return {
        "decision_id": decision_id,
        "removed": True,
        "signed": True,
        "receipt": summary,
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

    @app.get("/api/v2/identity")
    def v2_identity() -> Dict[str, Any]:
        return _seed_identity()

    @app.get("/api/v2/decisions", response_model=List[DecisionM])
    def v2_decisions(request: Request) -> List[Dict[str, Any]]:
        # Phase 2: served from the mutable in-memory store so the
        # queue shrinks as the user approves / rejects / defers.
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
        return _resolve_decision(decision_id, request, sign=True)

    @app.post("/api/v2/decisions/{decision_id}/reject")
    def v2_decisions_reject(
        decision_id: str,
        request: Request,
    ) -> Dict[str, Any]:
        """Drop the decision from the queue. No receipt is signed —
        rejection is non-actionable. Returns {removed: true}. """
        return _resolve_decision(decision_id, request, sign=False)

    @app.post("/api/v2/decisions/{decision_id}/defer")
    def v2_decisions_defer(
        decision_id: str,
        request: Request,
    ) -> Dict[str, Any]:
        """Drop the decision from the queue. Phase 3 will move it to
        a "deferred" bucket with a follow-up timer; Phase 2 just
        removes it. """
        return _resolve_decision(decision_id, request, sign=False)

    @app.get("/api/v2/missions", response_model=List[MissionSummaryM])
    def v2_missions() -> List[Dict[str, Any]]:
        # TODO Phase 2: load via nth_dao.orchestration.mission_store
        return _seed_missions()

    @app.get("/api/v2/processes", response_model=List[ProcessCardM])
    def v2_processes(request: Request) -> List[Dict[str, Any]]:
        live = _read_processes_from_blackboard(_state_blackboard(request))
        return live if live else _seed_processes()

    @app.get("/api/v2/receipts", response_model=List[ReceiptSummaryM])
    def v2_receipts(request: Request) -> List[Dict[str, Any]]:
        live = _read_receipts_from_disk(_state_workspace(request))
        return live if live else _seed_receipts()

    @app.get("/api/v2/rules")
    def v2_rules() -> List[Dict[str, Any]]:
        # No disk source yet — rules editor is Phase 2.
        return _seed_rules()

    @app.get("/api/v2/market/open")
    def v2_market_open(
        request: Request,
        context: str = "",
        capability: str = "",
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
        from nth_dao.market.claim import ClaimStore
        from nth_dao.market.feed import MarketFeed
        from nth_dao.market.vocabulary import normalize_capability

        ws = _state_workspace(request)
        if ws is None:
            return []
        want_cap = normalize_capability(capability) if capability.strip() else ""
        want_ctx = context.strip()
        ql = q.strip().lower()
        # 自审修复:MarketFeed/ClaimStore 的构造会 mkdir。读端点(且匿名)
        # 不该有文件系统副作用——否则任何一次只读 GET 都会在从不用市场的
        # 节点工作区里凭空造出 market_feed/ 与 market_claims/。feed 日志不
        # 存在 ⇒ 还没有任何公告 ⇒ 直接返回 [],不触碰磁盘。
        if not (ws / "market_feed" / "announcements.jsonl").exists():
            return []
        try:
            feed = MarketFeed(ws)
            claims = ClaimStore(ws)
        except OSError as e:  # noqa: BLE001
            logger.debug("v2_market_open: market store unavailable: %s", e)
            return []
        # poll(since_seq=-1) 默认已跳过过期;再排掉已认领的 → 只剩"可认领"。
        # 上限 500 防一次性读爆;FIFO(老→新),展示前翻成"新→老"更贴发现
        # 板直觉。注:开放公告超 500 时最新的会被截断,留待分页(切片后续)。
        pr = feed.poll(since_seq=-1, limit=500)
        out: List[Dict[str, Any]] = []
        for ann in pr.announcements:
            if claims.is_claimed(ann.announcement_id):
                continue
            if want_ctx and ann.context != want_ctx:
                continue
            if want_cap:
                have = {normalize_capability(c) for c in ann.capability_set}
                if want_cap not in have:
                    continue
            if min_reward and ann.reward_minor < min_reward:
                continue
            if ql and ql not in ann.title.lower() and ql not in ann.description.lower():
                continue
            d = ann.to_dict()
            d["claimed"] = False
            out.append(d)
        out.reverse()  # 新→老
        return out

    @app.get("/api/v2/market/categories")
    def v2_market_categories(request: Request) -> List[Dict[str, Any]]:
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
        feed = MarketFeed(ws)
        claims = ClaimStore(ws)
        counts: Dict[str, int] = {}
        for ann in feed.poll(since_seq=-1, limit=500).announcements:
            if claims.is_claimed(ann.announcement_id):
                continue
            counts[ann.context] = counts.get(ann.context, 0) + 1
        return sorted(
            ({"context": k, "count": v} for k, v in counts.items()),
            key=lambda x: (-x["count"], x["context"]),
        )

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

        if not body.title.strip():
            raise HTTPException(status_code=400, detail="title must not be empty")
        # 输入上限(对抗审查补):公告会被签名并追加进 append-only feed
        # (近似账本、无内置清理),不设限则一条超大 description/能力表就是
        # 永久膨胀。在落盘前于 HTTP 边界封顶,给清晰 400。
        if len(body.title) > 200:
            raise HTTPException(status_code=400, detail="title too long (max 200)")
        if len(body.description) > 4000:
            raise HTTPException(
                status_code=400, detail="description too long (max 4000)")
        if len(body.capability_set) > 32:
            raise HTTPException(
                status_code=400, detail="too many capabilities (max 32)")
        if any(len(c) > 100 for c in body.capability_set):
            raise HTTPException(
                status_code=400, detail="capability name too long (max 100)")
        if (
            len(body.reward_asset) > 32
            or len(body.context) > 64
            or len(body.mission_id) > 128
        ):
            raise HTTPException(
                status_code=400, detail="reward_asset/context/mission_id too long")
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
            MarketFeed(ws).publish(ann)
        except ValueError as exc:
            raise HTTPException(
                status_code=400, detail=f"publish rejected: {exc}",
            )
        return ann.to_dict()

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
        d = ann.to_dict()
        d["already_announced"] = False
        return d

    @app.get("/api/v2/agents", response_model=List[AgentEntryM])
    def v2_agents(request: Request) -> List[Dict[str, Any]]:
        # Phase 3a: prepend supervised agents (kind=local, live) ahead
        # of the disk-or-seed list so the UI surfaces them first.
        # The supervisor view is the source-of-truth for "agents I
        # spawned this session"; disk reflects identities written by
        # other parts of the stack; seed is the fallback for demo.
        sup = _state_supervisor(request)
        # Phase G: join cap_token scope on supervised agents so the
        # frontend can render a "scoped: <models>" badge inline with
        # the agent card. Pre-resolve the store once outside the loop
        # to keep the per-agent overhead at one ``store.get(id)``
        # dict-lookup-plus-disk-read.
        cap_tokens_store = _state_cap_tokens_store(request)
        supervised: List[Dict[str, Any]] = []
        if sup is not None:
            try:
                for rec in sup.list_agents():
                    entry = rec.to_agent_entry()
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
                    supervised.append(entry)
            except Exception as exc:  # noqa: BLE001
                logger.warning("v2_api: supervisor list_agents failed: %s", exc)
        disk = _read_agents_from_disk(_state_workspace(request))
        base = disk if disk else _seed_agents()
        # Dedup by did so a hub restart that re-reads a supervised
        # agent's identity from disk doesn't double-render it.
        seen_dids = {a["did"] for a in supervised}
        merged = supervised + [a for a in base if a.get("did") not in seen_dids]
        return merged

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

        try:
            record = sup.spawn(
                kind=body.kind,
                label=body.label,
                capabilities=body.capabilities,
                cap_token_issuer=_issue_cap_token,
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
        """Phase 3a: stop a supervised agent. Idempotent — repeated
        stops return 404 to avoid masking client retry logic. """
        sup = _state_supervisor(request)
        if sup is None:
            raise HTTPException(
                status_code=503,
                detail="agent supervisor unavailable",
            )
        ok = sup.stop(agent_id)
        if not ok:
            raise HTTPException(
                status_code=404,
                detail=f"agent {agent_id!r} not under supervision",
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
            if r.did == did and r.a2a_port is not None and r.alive
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
                            f"child returned HTTP {resp.status} from "
                            f"/ping at {url}"
                        ),
                    )
                raw = resp.read()
        except urllib.error.URLError as exc:
            raise HTTPException(
                status_code=502,
                detail=f"A2A proxy could not reach {url}: {exc}",
            )
        except (TimeoutError, OSError) as exc:
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
            if r.did == did and r.a2a_port is not None and r.alive
        ]
        if not matching:
            raise HTTPException(
                status_code=404,
                detail=(
                    f"no live supervised agent for did={did!r} with "
                    "an a2a_port"
                ),
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
                    detail=(
                        f"Content-Length {claimed_length} exceeds "
                        "1MB A2A cap"
                    ),
                )
        body_bytes = await request.body()
        if len(body_bytes) > 1024 * 1024:
            raise HTTPException(
                status_code=413,
                detail=(
                    f"body length {len(body_bytes)} exceeds 1MB "
                    "A2A cap"
                ),
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

        # Run the blocking urllib call on the threadpool so we
        # don't block the event loop while waiting up to 2s for
        # the child to reply.
        import asyncio

        # H-1 fix (review round Phase 4 R1): use the per-method
        # timeout so slow backends (claude-code, future Hermes,
        # etc.) aren't capped at the snappy default that was sized
        # for /ping + /echo. Unknown methods inherit the default.
        forward_timeout = _A2A_METHOD_TIMEOUTS.get(
            method, _A2A_DEFAULT_TIMEOUT_S,
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
                    return resp.status, resp.read()
            except urllib.error.HTTPError as http_exc:
                # Child returned non-2xx — forward status + body.
                return http_exc.code, http_exc.read()

        try:
            resp_status, resp_body = await asyncio.to_thread(_do_forward)
        except urllib.error.URLError as exc:
            raise HTTPException(
                status_code=502,
                detail=f"A2A proxy could not reach {url}: {exc}",
            )
        except (TimeoutError, OSError) as exc:
            raise HTTPException(
                status_code=502,
                detail=f"A2A proxy timed out / failed at {url}: {exc}",
            )

        return JSONResponse(
            status_code=resp_status,
            content=_decode_or_passthrough(resp_body),
        )

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
            if r.did == did and r.a2a_port is not None and r.alive
        ]
        if not matching:
            raise HTTPException(
                status_code=404,
                detail=f"no live supervised agent for did={did!r} with an a2a_port",
            )
        rec = matching[0]

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
        forward_timeout = _A2A_METHOD_TIMEOUTS.get(method, _A2A_DEFAULT_TIMEOUT_S)

        if method == "ask-stream":
            return _proxy_ssestream(
                url=url, body_bytes=body_bytes,
                req_headers=req_headers, forward_timeout=forward_timeout,
            )

        import asyncio

        def _do_forward() -> Tuple[int, bytes]:
            req = urllib.request.Request(
                url, data=body_bytes, headers=req_headers, method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=forward_timeout) as resp:  # noqa: S310
                    return resp.status, resp.read()
            except urllib.error.HTTPError as http_exc:
                return http_exc.code, http_exc.read()

        try:
            resp_status, resp_body = await asyncio.to_thread(_do_forward)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise HTTPException(
                status_code=502,
                detail=f"agent-ask proxy failed at {url}: {exc}",
            )
        return JSONResponse(
            status_code=resp_status,
            content=_decode_or_passthrough(resp_body),
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
            if r.did == did and r.a2a_port is not None and r.alive
        ]
        if not matching:
            raise HTTPException(
                status_code=404,
                detail=f"no live supervised agent for did={did!r}")
        rec = matching[0]
        token_id = getattr(rec, "cap_token_id", None)
        store = _state_cap_tokens_store(request)
        token = store.get(token_id) if (token_id and store is not None) else None
        if not isinstance(token, dict):
            raise HTTPException(
                status_code=409, detail=f"agent {did!r} has no usable cap_token")

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
                detail="too many messages for one summary (max 500); chunk client-side")
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
                detail="transcript too large for one summary (max 256KB); chunk client-side")
        url = f"http://127.0.0.1:{rec.a2a_port}/a2a/ask"
        req_headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Authorization": f"CapToken {encode_authorization_header(token)}",
        }
        timeout = _A2A_METHOD_TIMEOUTS.get("ask", _A2A_DEFAULT_TIMEOUT_S)

        def _forward() -> Tuple[int, bytes]:
            req = urllib.request.Request(
                url, data=body_bytes, headers=req_headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                    return resp.status, resp.read()
            except urllib.error.HTTPError as e:
                return e.code, (e.read() if e.fp else b"")

        status, raw = await asyncio.get_event_loop().run_in_executor(None, _forward)
        try:
            data = _json.loads(raw.decode("utf-8", "replace") or "{}")
        except Exception:
            data = {}
        if status != 200 or "not-yet-authorized" in _json.dumps(data):
            raise HTTPException(
                status_code=(status if status != 200 else 502),
                detail=f"summarize drive failed: {str(data)[:160]}")
        result = data.get("result", data) if isinstance(data, dict) else {}
        summary_text = str(result.get("response", ""))
        receipt = result.get("receipt")
        ok, reason = verify_summary(
            receipt, summary_text=summary_text, messages=messages,
            expected_signer=did, instruction=instruction)
        return {
            "conversation_id": conversation_id,
            "covered_message_ids": [str(m.get("message_id", "")) for m in messages],
            "transcript_sha256": hashlib.sha256(transcript.encode("utf-8")).hexdigest(),
            "summary_text": summary_text,
            "agent_did": did,
            "instruction": instruction,
            "verified": ok,
            "reason": reason,
            "receipt": receipt,
        }

    @app.get("/api/v2/cap_tokens", response_model=List[CapTokenSummaryM])
    def v2_cap_tokens(request: Request) -> List[Dict[str, Any]]:
        live = _read_cap_tokens_from_disk(_state_workspace(request))
        return live if live else _seed_cap_tokens()

    @app.get("/api/v2/conversations")
    def v2_conversations() -> List[Dict[str, Any]]:
        return _seed_conversations()

    @app.get("/api/v2/messages/{conv_id}")
    def v2_messages(conv_id: str) -> List[Dict[str, Any]]:
        return _seed_messages(conv_id)

    # Health probe so the frontend can tell whether the hub is up
    # before falling back to mock data.
    # P8 fix 2026-06-10: derive the endpoint list from app.routes so
    # adding a new route doesn't require remembering to also update
    # the health response.
    @app.get("/api/v2/health")
    def v2_health() -> Dict[str, Any]:
        prefix = "/api/v2/"
        eps = sorted({
            r.path[len(prefix):]  # type: ignore[attr-defined]
            for r in app.routes
            if getattr(r, "path", "").startswith(prefix)
            and getattr(r, "path", "") != "/api/v2/health"
        })
        return {"ok": True, "phase": 1, "endpoints": eps}

    logger.info("v2_api: registered /api/v2/* read endpoints (Phase 1)")
