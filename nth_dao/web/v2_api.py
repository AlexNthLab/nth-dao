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
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

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


class SpawnResponseM(_Model):
    """POST /api/v2/agents/spawn response shape. Phase 3b will add
    a ``cap_token`` field carrying the cap_token issued at spawn. """
    agent_id: str
    did: str
    kind: str
    label: str
    pid: Optional[int] = None
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


# Phase 3a: agent supervisor accessor + spawn request model
def _state_supervisor(request: Request) -> Optional[Any]:
    """Return the lazy-built per-app agent supervisor.

    The supervisor is constructed on first access so a test that
    only hits read endpoints doesn't pay the cost of spinning up
    a SubprocessRunner. Stored on app.state.v2_supervisor — same
    pattern as v2_decisions_store.

    Thread-safety note: the check-then-set is not atomic. Two
    concurrent first-requests could each construct a supervisor
    and the second would clobber the first (orphaning the first
    supervisor's subprocess pool — real leak risk in a hot
    cold-start race). Same hub-single-user assumption as
    _decisions_store applies: uvicorn's default single worker
    serialises requests within asyncio. Phase 3 multi-worker
    deployments must move this to module-level construction or
    add a one-time-init lock. """
    state = request.app.state
    sup = getattr(state, "v2_supervisor", None)
    if sup is None:
        from .agent_supervisor import build_default_supervisor
        sup = build_default_supervisor()
        state.v2_supervisor = sup
        logger.info("v2_api: built default agent supervisor")
    return sup


class SpawnAgentBody(_Model):
    """POST /api/v2/agents/spawn request body. """
    kind: str = Field(
        ...,
        description="Backend kind label, e.g. 'mock', 'claude-code'.",
    )
    label: str = Field(
        default="",
        description="Human-readable name; defaults to kind if empty.",
    )
    capabilities: List[str] = Field(
        default_factory=list,
        description="Advertised capabilities (e.g. ['nth-dao.chat']).",
    )


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

    @app.get("/api/v2/agents", response_model=List[AgentEntryM])
    def v2_agents(request: Request) -> List[Dict[str, Any]]:
        # Phase 3a: prepend supervised agents (kind=local, live) ahead
        # of the disk-or-seed list so the UI surfaces them first.
        # The supervisor view is the source-of-truth for "agents I
        # spawned this session"; disk reflects identities written by
        # other parts of the stack; seed is the fallback for demo.
        sup = _state_supervisor(request)
        supervised: List[Dict[str, Any]] = []
        if sup is not None:
            try:
                for rec in sup.list_agents():
                    supervised.append(rec.to_agent_entry())
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
        """Phase 3a: ask the supervisor to bring up a new agent.
        Returns the AgentEntry the freshly-spawned agent will be
        rendered as. Phase 3b will additionally issue a cap_token
        and attach it before returning. """
        sup = _state_supervisor(request)
        if sup is None:
            raise HTTPException(
                status_code=503,
                detail="agent supervisor unavailable",
            )
        try:
            record = sup.spawn(
                kind=body.kind,
                label=body.label,
                capabilities=body.capabilities,
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
