"""A2A Protocol JSON-RPC handler — L1-2 (2026-06-08).

Implements the **minimum viable** A2A RPC surface so that NTH DAO
nodes can receive A2A tasks from any spec-conforming consumer
(LangChain / Cohere / Salesforce / PayPal / SAP A2A clients, etc).

═══════════════════════════════════════════════════════════════════
Wire format alignment
═══════════════════════════════════════════════════════════════════

The A2A protocol is defined by ``a2aproject/A2A`` ``specification/a2a.proto``.
Although the proto uses google.api.http for REST bindings, the
community SDKs (and a2aprotocol.ai's landing page) advertise a
JSON-RPC 2.0 envelope. We honour the JSON-RPC convention because
that's what real A2A clients send.

Methods implemented:
  * ``message/send`` — create a Task or append a message to an
    existing context. Returns a Task object.
  * ``tasks/get`` — fetch a Task by id. Returns a Task object.
  * ``tasks/cancel`` — mark a Task as canceled. Returns a Task object.

Data model (subset of a2a.proto):

  Task:
    id: string
    context_id: string
    status: TaskStatus { state: TaskState; timestamp: int }
    artifacts: [Artifact]
    history: [Message]
    metadata: object

  Message:
    message_id: string
    context_id: string
    task_id: string
    role: ROLE_USER | ROLE_AGENT
    parts: [Part]

  Part: { kind: "text" | "data" | "file"; ... }

═══════════════════════════════════════════════════════════════════
Integration with L1-1 receipts
═══════════════════════════════════════════════════════════════════

Every accepted ``message/send`` call also emits a signed execution
receipt (per motebit execution-ledger@1.0). The receipt's
``timeline`` records:

  * one ``goal_started`` entry when the Task is created
  * one ``nth.post_message`` entry per inbound message
  * one ``goal_completed`` entry when state transitions to completed

The receipt_id is stored on the Task's ``metadata.nth_receipt_id``.
This is how NTH provides 工作量证明 for A2A: a third party with the
Task can look up the receipt, verify the signature chain, and prove
the agent really did the work.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from threading import RLock
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from nth_dao.a2a_mission_bridge import (
    META_TASK_MISSION_ID,
    create_mission_from_subtasks,
    enrich_task_with_mission,
    link_existing_mission_to_task,
)
from nth_dao.execution_receipt import (
    ReceiptStore,
    TYPE_GOAL_COMPLETED,
    TYPE_GOAL_STARTED,
    TYPE_NTH_POST_MESSAGE,
    TYPE_STEP_STARTED,
    TimelineEntry,
    now_ms,
    sign_receipt,
)

if TYPE_CHECKING:
    from nth_dao.identity import AgentIdentity
    from nth_dao.orchestration.mission_store import MissionStore

logger = logging.getLogger("nth_dao.a2a_rpc")


# ─── A2A wire constants ──────────────────────────────────────────────


# TaskState enum values, verbatim from a2a.proto
TASK_STATE_UNSPECIFIED = "TASK_STATE_UNSPECIFIED"
TASK_STATE_SUBMITTED = "TASK_STATE_SUBMITTED"
TASK_STATE_WORKING = "TASK_STATE_WORKING"
TASK_STATE_COMPLETED = "TASK_STATE_COMPLETED"
TASK_STATE_FAILED = "TASK_STATE_FAILED"
TASK_STATE_CANCELED = "TASK_STATE_CANCELED"
TASK_STATE_INPUT_REQUIRED = "TASK_STATE_INPUT_REQUIRED"
TASK_STATE_REJECTED = "TASK_STATE_REJECTED"
TASK_STATE_AUTH_REQUIRED = "TASK_STATE_AUTH_REQUIRED"

TERMINAL_STATES = frozenset({
    TASK_STATE_COMPLETED,
    TASK_STATE_FAILED,
    TASK_STATE_CANCELED,
    TASK_STATE_REJECTED,
})

ROLE_USER = "ROLE_USER"
ROLE_AGENT = "ROLE_AGENT"

# JSON-RPC 2.0 error codes (RFC + A2A extensions)
JSONRPC_PARSE_ERROR = -32700
JSONRPC_INVALID_REQUEST = -32600
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_INVALID_PARAMS = -32602
JSONRPC_INTERNAL_ERROR = -32603

# A2A application errors (custom range)
A2A_TASK_NOT_FOUND = -32001
A2A_TASK_TERMINAL = -32002
# L1-3 (2026-06-08): cap-token scope rejection. Returned when the
# caller's CapToken either lacks the capability for the requested
# method OR has a scope_task_id that doesn't match the targeted task.
A2A_FORBIDDEN_BY_CAP = -32003


# MA-2 (review fix 2026-06-08): the receipt-emission path catches
# only KNOWN-RECOVERABLE exceptions. Things outside this tuple
# (MemoryError, SystemExit, KeyboardInterrupt, asyncio.CancelledError,
# etc.) propagate so the runtime can do the right thing — silently
# swallowing them would hide genuine emergencies.
#
# What IS recoverable:
#   * OSError — disk full, permission denied, network FS hiccup
#   * ValueError — receipt envelope rejected by ReceiptStore validation,
#     timestamp out-of-range, etc.
#   * RuntimeError — AgentIdentity cannot sign (PyNaCl unavailable
#     mid-flight, key wiped, etc.)
#   * TypeError — canonical_json rejects a value that snuck into the
#     timeline (a previous version of the code accepted floats; we
#     now catch the rejection rather than crashing the request)
_RECOVERABLE_RECEIPT_EMIT_ERRORS: tuple = (
    OSError, ValueError, RuntimeError, TypeError,
)


# ─── RPC envelope helpers ────────────────────────────────────────────


def _rpc_result(req_id: Any, result: Any) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _rpc_error(
    req_id: Any, code: int, message: str, data: Any = None,
) -> Dict[str, Any]:
    err: Dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


# ─── Task store ──────────────────────────────────────────────────────


class TaskStore:
    """In-memory A2A task store.

    Concurrency: protected by an RLock. Reads and writes are atomic
    at the dict level. Persisted-to-disk variant TBD — for v1 a task
    lives only in the running process. The signed receipt IS persisted
    (via ReceiptStore), so the work-proof story survives restart even
    if the task itself does not.
    """

    def __init__(self) -> None:
        self._tasks: Dict[str, Dict[str, Any]] = {}
        self._lock = RLock()

    def create(
        self,
        *,
        context_id: str,
        initial_message: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Create a new Task with state=SUBMITTED and one history entry."""
        task_id = uuid.uuid4().hex
        # Stamp the message with our IDs
        initial_message = dict(initial_message)
        initial_message["task_id"] = task_id
        initial_message["context_id"] = context_id
        if not initial_message.get("message_id"):
            initial_message["message_id"] = uuid.uuid4().hex

        task = {
            "id": task_id,
            "context_id": context_id,
            "status": {
                "state": TASK_STATE_SUBMITTED,
                "timestamp": now_ms(),
            },
            "artifacts": [],
            "history": [initial_message],
            "metadata": {},
        }
        with self._lock:
            self._tasks[task_id] = task
        return task

    def get(self, task_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._tasks.get(task_id)

    def append_message(
        self, task_id: str, message: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Append a message to an existing task's history."""
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return None
            msg = dict(message)
            msg["task_id"] = task_id
            msg["context_id"] = task["context_id"]
            if not msg.get("message_id"):
                msg["message_id"] = uuid.uuid4().hex
            task["history"].append(msg)
            return task

    def set_state(
        self, task_id: str, state: str,
    ) -> Optional[Dict[str, Any]]:
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return None
            task["status"] = {
                "state": state,
                "timestamp": now_ms(),
            }
            return task

    def all_ids(self) -> List[str]:
        with self._lock:
            return list(self._tasks.keys())

    def set_metadata_key(
        self, task_id: str, key: str, value: Any,
    ) -> Optional[Dict[str, Any]]:
        """Set ``task.metadata[key] = value`` under the lock.

        F1 fix (2026-06-08): writing to the task dict directly from
        the handler was unsafe — handlers run on FastAPI's default
        thread pool, so an unprotected mutation could race with a
        concurrent ``append_message`` or ``set_state`` call to the
        same task. All writes that touch a stored task MUST go
        through a TaskStore method holding the RLock.
        """
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return None
            task.setdefault("metadata", {})[key] = value
            return task


# ─── RPC handler ─────────────────────────────────────────────────────


class A2ARPCHandler:
    """Dispatch JSON-RPC requests to A2A method implementations.

    Each handler returns the JSON-RPC response dict. Errors map to
    JSON-RPC 2.0 error envelopes — the HTTP layer always returns 200
    with a structured body, per JSON-RPC convention.
    """

    def __init__(
        self,
        *,
        task_store: TaskStore,
        receipt_store: Optional[ReceiptStore],
        identity: Optional["AgentIdentity"],
        principal: Optional[Dict[str, Any]] = None,
        mission_store: Optional["MissionStore"] = None,
    ) -> None:
        self.tasks = task_store
        self.receipts = receipt_store
        self.identity = identity
        # L1-4 (2026-06-08): the Mission ↔ A2A Task bridge. When
        # absent the handler degrades cleanly — message/send still
        # works, just without subtask-split or mission enrichment.
        self.missions = mission_store
        # L1-3 (2026-06-08): principal is the auth-resolved caller.
        #   {"type": "console"}  → operator full access (no per-method
        #                          cap check; pre-existing contract)
        #   {"type": "cap_token", "token": <dict>} → check each method
        #                          against the token's capabilities +
        #                          scope on every dispatch
        #   {"type": "anonymous"}/None → treated as console for now;
        #                          require_console_auth=False mode.
        self.principal = principal or {"type": "console"}

    # L1-3 method → required-capability map. Keys are the JSON-RPC
    # method strings; values are the cap-string from
    # ``nth_dao.cap_token``. Lookups outside this map mean "method
    # not gated by any cap-token capability" — currently empty.
    _METHOD_CAP_MAP = {
        "message/send": "a2a:message_send",
        "tasks/get":    "a2a:task_get",
        "tasks/cancel": "a2a:task_cancel",
        # R5 (review fix 2026-06-08): tasks/split now requires its
        # OWN capability ``a2a:task_split``. Reusing message_send
        # would let a helper Agent delegated "send messages to task X"
        # also restructure X into a 50-step Mission — explicit
        # over-grant. Issuers must consciously grant task_split.
        "tasks/split":  "a2a:task_split",
    }

    def _check_principal_for_method(
        self,
        req_id: Any,
        method: str,
        params: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Return None when the principal may invoke ``method`` (with
        these ``params``); otherwise return a JSON-RPC error envelope
        the caller should short-circuit with.

        Console principals always allow. Cap-token principals are
        checked against the method's required capability AND the
        token's ``scope_task_id`` if a task target is implied by
        ``params``.
        """
        ptype = self.principal.get("type", "")
        if ptype == "console" or ptype == "anonymous":
            return None
        if ptype != "cap_token":
            return _rpc_error(
                req_id, A2A_FORBIDDEN_BY_CAP,
                f"unknown principal type {ptype!r}",
            )

        token = self.principal.get("token") or {}
        token_caps = set(token.get("capabilities") or [])
        # R3 (review fix 2026-06-08): deny-by-default. A method NOT
        # in ``_METHOD_CAP_MAP`` was previously silently allowed for
        # any cap_token principal — meaning a maintainer who adds a
        # new method without registering it here would create a
        # privilege-escalation path. The safe default for delegated
        # principals is DENY when the requested method has no
        # explicit capability requirement on file.
        #
        # The unknown-method case still falls through to
        # JSONRPC_METHOD_NOT_FOUND for the SAME error UX as before
        # (the request is still rejected) — we just route via
        # A2A_FORBIDDEN_BY_CAP first when a delegated principal asks
        # for it.
        needed_cap = self._METHOD_CAP_MAP.get(method)
        if needed_cap is None:
            return _rpc_error(
                req_id, A2A_FORBIDDEN_BY_CAP,
                f"method {method!r} is not callable via cap_token "
                f"(no capability mapping registered)",
                data={
                    "token_id": token.get("token_id", ""),
                    "callable_methods": sorted(self._METHOD_CAP_MAP.keys()),
                },
            )
        if needed_cap not in token_caps:
            return _rpc_error(
                req_id, A2A_FORBIDDEN_BY_CAP,
                f"cap_token missing required capability "
                f"{needed_cap!r} for method {method!r}",
                data={
                    "token_id": token.get("token_id", ""),
                    "granted": sorted(token_caps),
                },
            )

        # Scope check: pull the task_id implied by the request, if
        # any, and confirm it matches the token's scope (or scope is
        # unrestricted).
        scope_task_id = str(token.get("scope_task_id", "") or "")
        if scope_task_id:
            implied_task_id = ""
            if method == "message/send":
                msg = params.get("message")
                if isinstance(msg, dict):
                    implied_task_id = str(msg.get("task_id", "") or "")
                    # For NEW tasks (no task_id in the message), the
                    # task hasn't been minted yet. A scoped token
                    # cannot create new tasks — that would defeat the
                    # scope. Reject.
                    if not implied_task_id:
                        return _rpc_error(
                            req_id, A2A_FORBIDDEN_BY_CAP,
                            f"cap_token is scoped to task "
                            f"{scope_task_id!r}; cannot create a "
                            f"new task",
                            data={"token_id": token.get("token_id", "")},
                        )
            elif method in ("tasks/get", "tasks/cancel"):
                implied_task_id = str(params.get("id", "") or "")
            if implied_task_id and implied_task_id != scope_task_id:
                return _rpc_error(
                    req_id, A2A_FORBIDDEN_BY_CAP,
                    f"cap_token scoped to task {scope_task_id!r}; "
                    f"request targets task {implied_task_id!r}",
                    data={"token_id": token.get("token_id", "")},
                )

        return None

    # ── public dispatch entry ─────────────────────────────────────

    def handle(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Process a single JSON-RPC request.

        Returns the JSON-RPC 2.0 response envelope. Never raises —
        any exception becomes an INTERNAL_ERROR response so the
        client always sees structured JSON.
        """
        req_id = payload.get("id")  # may be None for notifications
        if payload.get("jsonrpc") != "2.0":
            return _rpc_error(
                req_id, JSONRPC_INVALID_REQUEST,
                'jsonrpc must be "2.0"',
            )
        method = payload.get("method", "")
        if not isinstance(method, str) or not method:
            return _rpc_error(
                req_id, JSONRPC_INVALID_REQUEST,
                "method must be a non-empty string",
            )
        params = payload.get("params") or {}
        if not isinstance(params, dict):
            return _rpc_error(
                req_id, JSONRPC_INVALID_PARAMS,
                "params must be an object",
            )

        # L1-3 (2026-06-08): authorize the method + scope BEFORE
        # dispatching. ``_check_principal_for_method`` returns None
        # iff the caller is allowed; otherwise it returns the
        # already-formed JSON-RPC error envelope.
        denial = self._check_principal_for_method(req_id, method, params)
        if denial is not None:
            return denial

        try:
            if method == "message/send":
                return self._message_send(req_id, params)
            if method == "tasks/get":
                return self._tasks_get(req_id, params)
            if method == "tasks/cancel":
                return self._tasks_cancel(req_id, params)
            if method == "tasks/split":
                return self._tasks_split(req_id, params)
            return _rpc_error(
                req_id, JSONRPC_METHOD_NOT_FOUND,
                f"unknown method: {method}",
                data={
                    "supported_methods": [
                        "message/send", "tasks/get",
                        "tasks/cancel", "tasks/split",
                    ],
                },
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("A2A RPC handler failed for method=%s", method)
            return _rpc_error(
                req_id, JSONRPC_INTERNAL_ERROR,
                "internal error processing request",
                data={"exc_type": type(exc).__name__},
            )

    # ── method: message/send ──────────────────────────────────────

    def _message_send(
        self, req_id: Any, params: Dict[str, Any],
    ) -> Dict[str, Any]:
        """A2A ``message/send``: create a Task or append to an existing one."""
        message = params.get("message")
        if not isinstance(message, dict):
            return _rpc_error(
                req_id, JSONRPC_INVALID_PARAMS,
                "params.message is required and must be an object",
            )

        parts = message.get("parts")
        if not isinstance(parts, list) or not parts:
            return _rpc_error(
                req_id, JSONRPC_INVALID_PARAMS,
                "message.parts must be a non-empty array",
            )
        if message.get("role") not in (ROLE_USER, ROLE_AGENT):
            return _rpc_error(
                req_id, JSONRPC_INVALID_PARAMS,
                f"message.role must be {ROLE_USER!r} or {ROLE_AGENT!r}",
            )

        # Branch: existing Task (by task_id) or new context
        target_task_id = message.get("task_id") or ""
        if target_task_id:
            existing = self.tasks.get(target_task_id)
            if existing is None:
                return _rpc_error(
                    req_id, A2A_TASK_NOT_FOUND,
                    f"task {target_task_id} not found",
                )
            if existing["status"]["state"] in TERMINAL_STATES:
                return _rpc_error(
                    req_id, A2A_TASK_TERMINAL,
                    f"task {target_task_id} is terminal "
                    f"({existing['status']['state']}); cannot append",
                )
            task = self.tasks.append_message(target_task_id, message)
            # Update state to WORKING since a new message arrived.
            # MED-7 fix 2026-06-10: assert dropped under `python -O`;
            # explicit guard so a regression in append_message that
            # returns None surfaces a clear ValueError instead of an
            # opaque AttributeError downstream.
            if task is None:
                raise ValueError(
                    f"append_message returned None for task "
                    f"{target_task_id!r} despite existence check",
                )
            task = self.tasks.set_state(target_task_id, TASK_STATE_WORKING)
            # F2 (2026-06-08): use ``step_started`` not ``goal_started``
            # for messages appended to an existing task — the goal is
            # already in progress; this message is the next step.
            self._emit_receipt_for_message(
                task, message, is_new_task=False,
            )
            return _rpc_result(req_id, task)

        # New context — generate IDs
        context_id = message.get("context_id") or uuid.uuid4().hex
        task = self.tasks.create(
            context_id=context_id, initial_message=message,
        )
        self._emit_receipt_for_message(
            task, task["history"][0], is_new_task=True,
        )
        return _rpc_result(req_id, task)

    # ── method: tasks/get ─────────────────────────────────────────

    def _tasks_get(
        self, req_id: Any, params: Dict[str, Any],
    ) -> Dict[str, Any]:
        task_id = str(params.get("id", "") or "")
        if not task_id:
            return _rpc_error(
                req_id, JSONRPC_INVALID_PARAMS,
                "params.id is required",
            )
        task = self.tasks.get(task_id)
        if task is None:
            return _rpc_error(
                req_id, A2A_TASK_NOT_FOUND,
                f"task {task_id} not found",
            )
        # L1-4: if the task is linked to a Mission, enrich the
        # response with the Mission's progress snapshot. Pure
        # view-time enrichment — the on-disk Task is unchanged.
        if self.missions is not None:
            enriched = dict(task)
            enriched["metadata"] = dict(enriched.get("metadata", {}))
            enrich_task_with_mission(enriched, self.missions)
            return _rpc_result(req_id, enriched)
        return _rpc_result(req_id, task)

    # ── method: tasks/split (L1-4) ────────────────────────────────

    def _tasks_split(
        self, req_id: Any, params: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Split a Task into a structured Mission with subtasks.

        Params:
            id: existing Task ID to split
            subtasks: list of strings — one description per step
            title: optional Mission title (defaults to "A2A Task <id>")
            goal: optional high-level goal (defaults to first subtask)

        The Mission is created with the supplied subtasks as steps;
        the Task gets ``metadata.nth_mission_id`` set so future
        ``tasks/get`` enrich the response with Mission progress.

        If the Task is already linked to a Mission, the request is
        rejected — the consumer should call ``tasks/get`` to read
        the existing Mission first, then decide whether to extend
        it via the NTH-side Mission API (out of band of A2A).
        """
        if self.missions is None:
            return _rpc_error(
                req_id, JSONRPC_INVALID_PARAMS,
                "tasks/split unavailable: mission store not wired",
            )
        task_id = str(params.get("id", "") or "")
        if not task_id:
            return _rpc_error(
                req_id, JSONRPC_INVALID_PARAMS,
                "params.id is required",
            )
        subtasks = params.get("subtasks")
        if not isinstance(subtasks, list) or not subtasks:
            return _rpc_error(
                req_id, JSONRPC_INVALID_PARAMS,
                "params.subtasks must be a non-empty array of "
                "step description strings",
            )
        task = self.tasks.get(task_id)
        if task is None:
            return _rpc_error(
                req_id, A2A_TASK_NOT_FOUND,
                f"task {task_id} not found",
            )
        existing = task.get("metadata", {}).get(META_TASK_MISSION_ID, "")
        if existing:
            return _rpc_error(
                req_id, JSONRPC_INVALID_PARAMS,
                f"task {task_id} already linked to mission "
                f"{existing}; use NTH-side Mission API to extend",
            )

        title = str(
            params.get("title", "")
            or f"A2A Task {task_id}"
        )
        goal = str(
            params.get("goal", "")
            or (subtasks[0] if subtasks else "(unspecified)")
        )
        try:
            mission = create_mission_from_subtasks(
                mission_store=self.missions,
                owner="admin",
                task_id=task_id,
                title=title,
                goal=goal,
                subtasks=subtasks,
            )
        except (ValueError, TypeError) as exc:
            return _rpc_error(
                req_id, JSONRPC_INVALID_PARAMS,
                f"subtask validation failed: {exc}",
            )

        # Link the Task → Mission
        updated = self.tasks.set_metadata_key(
            task_id, META_TASK_MISSION_ID, mission.id,
        )
        if updated is not None:
            task = updated

        # Enrich the response with the freshly-built Mission summary
        # so the consumer sees the split result in one call.
        enriched = dict(task)
        enriched["metadata"] = dict(enriched.get("metadata", {}))
        enrich_task_with_mission(enriched, self.missions)
        return _rpc_result(req_id, enriched)

    # ── method: tasks/cancel ──────────────────────────────────────

    def _tasks_cancel(
        self, req_id: Any, params: Dict[str, Any],
    ) -> Dict[str, Any]:
        task_id = str(params.get("id", "") or "")
        if not task_id:
            return _rpc_error(
                req_id, JSONRPC_INVALID_PARAMS,
                "params.id is required",
            )
        task = self.tasks.get(task_id)
        if task is None:
            return _rpc_error(
                req_id, A2A_TASK_NOT_FOUND,
                f"task {task_id} not found",
            )
        if task["status"]["state"] in TERMINAL_STATES:
            # Idempotent cancel — already terminal, just return current
            return _rpc_result(req_id, task)
        task = self.tasks.set_state(task_id, TASK_STATE_CANCELED)
        self._emit_receipt_for_cancel(task)
        return _rpc_result(req_id, task)

    # ── receipt emission (L1-1 integration) ───────────────────────

    def _emit_receipt_for_message(
        self,
        task: Dict[str, Any],
        message: Dict[str, Any],
        *,
        is_new_task: bool,
    ) -> None:
        """Sign a receipt for this message and link it to the task.

        F2 (2026-06-08): ``is_new_task=True`` → first timeline entry
        is ``goal_started`` (the task is born); ``is_new_task=False``
        → first entry is ``step_started`` (the goal already exists,
        this message is a step inside it). Emitting goal_started
        twice for the same goal_id would confuse motebit consumers
        building task-state machines off the timeline.

        MA-2 (2026-06-08): only recoverable exceptions are caught
        and converted into a metadata error marker; anything outside
        ``_RECOVERABLE_RECEIPT_EMIT_ERRORS`` propagates and the JSON-
        RPC layer maps it to ``-32603 internal error``.
        """
        if self.identity is None or self.receipts is None:
            return

        # MA-2: write through the store's lock-protected setter and
        # refresh ``task["metadata"]`` so the JSON-RPC response carries
        # the latest values. Both success and failure paths use this.
        def _mark(key: str, value: Any) -> None:
            updated = self.tasks.set_metadata_key(task["id"], key, value)
            if updated is not None:
                task["metadata"] = updated["metadata"]

        try:
            # Build a minimal timeline — leading event then
            # nth.post_message. Future iterations may build richer
            # timelines as the task progresses through tool calls.
            leading_type = (
                TYPE_GOAL_STARTED if is_new_task else TYPE_STEP_STARTED
            )
            timeline = [
                TimelineEntry(
                    timestamp=now_ms(),
                    type=leading_type,
                    payload={
                        "task_id": task["id"],
                        "context_id": task["context_id"],
                    },
                ),
                TimelineEntry(
                    timestamp=now_ms(),
                    type=TYPE_NTH_POST_MESSAGE,
                    payload={
                        "message_id": message.get("message_id", ""),
                        "role": message.get("role", ""),
                        "parts_count": len(message.get("parts", [])),
                    },
                ),
            ]
            receipt = sign_receipt(
                timeline, self.identity, goal_id=task["id"],
            )
            self.receipts.save(receipt)
            # F1 (2026-06-08): metadata write goes through the store's
            # lock-protected setter, not a direct dict mutation.
            _mark("nth_receipt_id", receipt["receipt_id"])
        except _RECOVERABLE_RECEIPT_EMIT_ERRORS as exc:
            # MA-2: ERROR level — a missing receipt breaks the
            # 工作量证明 chain, which is the entire point of L1-1.
            # That's not a warning; that's something the operator
            # needs to know about.
            logger.error(
                "receipt emission failed for task %s (%s): %s",
                task["id"], type(exc).__name__, exc,
            )
            # MA-2: leave a marker so a consumer reading the task can
            # distinguish "no receipt yet, will appear later" from
            # "we tried to emit a receipt and it broke".
            _mark("nth_receipt_error", True)
            _mark("nth_receipt_error_class", type(exc).__name__)

    def _emit_receipt_for_cancel(self, task: Dict[str, Any]) -> None:
        """MA-2 (2026-06-08): same exception-narrowing + metadata-marker
        treatment as ``_emit_receipt_for_message``. A cancel receipt
        is what proves to a consumer "this task was canceled, here's
        the signed end-of-life"; if emission breaks, the marker tells
        a consumer to treat the canceled state as untrusted."""
        if self.identity is None or self.receipts is None:
            return

        def _mark(key: str, value: Any) -> None:
            updated = self.tasks.set_metadata_key(task["id"], key, value)
            if updated is not None:
                task["metadata"] = updated["metadata"]

        try:
            timeline = [
                TimelineEntry(
                    timestamp=now_ms(),
                    type=TYPE_GOAL_COMPLETED,
                    payload={
                        "task_id": task["id"],
                        "result": "canceled",
                    },
                ),
            ]
            receipt = sign_receipt(
                timeline, self.identity, goal_id=task["id"],
            )
            self.receipts.save(receipt)
            _mark("nth_cancel_receipt_id", receipt["receipt_id"])
        except _RECOVERABLE_RECEIPT_EMIT_ERRORS as exc:
            logger.error(
                "cancel-receipt emission failed for task %s (%s): %s",
                task["id"], type(exc).__name__, exc,
            )
            _mark("nth_receipt_error", True)
            _mark("nth_receipt_error_class", type(exc).__name__)
