"""A2A Protocol JSON-RPC endpoint — L1-2 (2026-06-08).

What this suite proves:

  1. JSON-RPC 2.0 envelope discipline: every response has
     ``jsonrpc=="2.0"``; success has ``result``, failure has ``error``
     (never both, never neither); ``id`` mirrors request.
  2. ``message/send`` creates a Task in TASK_STATE_SUBMITTED with the
     submitted message in history, and accepts a follow-up message
     against the same task_id.
  3. ``tasks/get`` retrieves by id; returns A2A_TASK_NOT_FOUND for
     unknowns.
  4. ``tasks/cancel`` flips state to TASK_STATE_CANCELED and is
     idempotent against terminal tasks.
  5. Bad requests return JSON-RPC errors with structured codes:
     -32700 parse, -32600 invalid request, -32601 method not found,
     -32602 invalid params, -32603 internal.
  6. Receipt integration: every accepted message emits a signed
     receipt (motebit interop), persisted to ReceiptStore, with the
     receipt_id stamped on task.metadata.nth_receipt_id. The receipt
     itself verifies against the node's pubkey.
  7. Auth: /api/a2a/rpc is gated by console_token like the rest of
     /api/* — bypassing the gate would let any LAN attacker drain
     work from this node.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from nth_dao.a2a_rpc import (
    A2A_TASK_NOT_FOUND,
    A2A_TASK_TERMINAL,
    JSONRPC_INVALID_PARAMS,
    JSONRPC_INVALID_REQUEST,
    JSONRPC_METHOD_NOT_FOUND,
    JSONRPC_PARSE_ERROR,
    ROLE_USER,
    TASK_STATE_CANCELED,
    TASK_STATE_SUBMITTED,
    TASK_STATE_WORKING,
)
from nth_dao.execution_receipt import verify_receipt
from nth_dao.identity import crypto_available
from nth_dao.web import create_app


pytestmark = pytest.mark.skipif(
    not crypto_available(),
    reason="A2A RPC receipt emission requires PyNaCl",
)


@pytest.fixture
def client(tmp_path, monkeypatch) -> TestClient:
    monkeypatch.setenv("NTH_LAN_PUBLISH", "0")
    test_client = TestClient(create_app(tmp_path, require_console_auth=False))
    try:
        yield test_client
    finally:
        test_client.close()


@pytest.fixture
def auth_client(tmp_path, monkeypatch):
    """A separate fixture for tests that need the console gate ON
    (to prove /api/a2a/rpc is gated)."""
    monkeypatch.setenv("NTH_LAN_PUBLISH", "0")
    test_client = TestClient(create_app(tmp_path, require_console_auth=True))
    token = test_client.app.state.nth_console_token
    try:
        yield test_client, token
    finally:
        test_client.close()


def _rpc(method: str, params=None, req_id="r1") -> dict:
    payload = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        payload["params"] = params
    return payload


def _user_text_message(text: str = "hello", **overrides) -> dict:
    msg = {
        "role": ROLE_USER,
        "parts": [{"kind": "text", "text": text}],
    }
    msg.update(overrides)
    return msg


# ===== JSON-RPC envelope discipline =====


def test_response_envelope_is_jsonrpc_2_0(client):
    resp = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {"message": _user_text_message()}),
    )
    body = resp.json()
    assert body["jsonrpc"] == "2.0"
    assert body["id"] == "r1"
    assert "result" in body and "error" not in body


def test_response_id_mirrors_request_id(client):
    resp = client.post(
        "/api/a2a/rpc",
        json=_rpc("tasks/get", {"id": "no-such-task"}, req_id=42),
    )
    body = resp.json()
    assert body["id"] == 42
    assert body["error"]["code"] == A2A_TASK_NOT_FOUND


def test_invalid_jsonrpc_version_rejected(client):
    bad = {"jsonrpc": "1.0", "id": 1, "method": "message/send", "params": {}}
    body = client.post("/api/a2a/rpc", json=bad).json()
    assert body["error"]["code"] == JSONRPC_INVALID_REQUEST


def test_missing_method_rejected(client):
    bad = {"jsonrpc": "2.0", "id": 1}
    body = client.post("/api/a2a/rpc", json=bad).json()
    assert body["error"]["code"] == JSONRPC_INVALID_REQUEST


def test_unknown_method_returns_method_not_found(client):
    body = client.post(
        "/api/a2a/rpc",
        json=_rpc("nonexistent/method", {}),
    ).json()
    assert body["error"]["code"] == JSONRPC_METHOD_NOT_FOUND
    # Helpful data: list of supported methods
    assert "supported_methods" in body["error"].get("data", {})


def test_non_dict_body_returns_invalid_request(client):
    """A2A consumers sometimes send arrays for batch — we don't
    support batch in v1 and reject cleanly with -32600."""
    resp = client.post("/api/a2a/rpc", json=[1, 2, 3])
    body = resp.json()
    assert body["error"]["code"] == JSONRPC_INVALID_REQUEST


def test_malformed_json_returns_parse_error(client):
    resp = client.post(
        "/api/a2a/rpc",
        content=b"{not-json,,,",
        headers={"Content-Type": "application/json"},
    )
    body = resp.json()
    assert body["error"]["code"] == JSONRPC_PARSE_ERROR


# ===== message/send =====


def test_message_send_creates_task_in_submitted_state(client):
    body = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {"message": _user_text_message()}),
    ).json()
    task = body["result"]
    assert task["status"]["state"] == TASK_STATE_SUBMITTED
    assert task["id"]
    assert task["context_id"]
    assert len(task["history"]) == 1
    assert task["history"][0]["role"] == ROLE_USER
    assert task["history"][0]["task_id"] == task["id"]


def test_message_send_with_existing_task_id_appends_and_works(client):
    # Create
    first = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {"message": _user_text_message("first")}),
    ).json()["result"]
    task_id = first["id"]

    # Append
    second = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {
            "message": _user_text_message("second", task_id=task_id),
        }),
    ).json()["result"]
    assert second["id"] == task_id
    assert len(second["history"]) == 2
    assert second["status"]["state"] == TASK_STATE_WORKING


def test_message_send_to_unknown_task_id_returns_404(client):
    body = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {
            "message": _user_text_message(task_id="nope"),
        }),
    ).json()
    assert body["error"]["code"] == A2A_TASK_NOT_FOUND


def test_message_send_missing_message_returns_invalid_params(client):
    body = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {}),
    ).json()
    assert body["error"]["code"] == JSONRPC_INVALID_PARAMS


def test_message_send_empty_parts_array_rejected(client):
    body = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {
            "message": {"role": ROLE_USER, "parts": []},
        }),
    ).json()
    assert body["error"]["code"] == JSONRPC_INVALID_PARAMS


def test_message_send_invalid_role_rejected(client):
    body = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {
            "message": {
                "role": "ROLE_ROOT",  # not a valid A2A role
                "parts": [{"kind": "text", "text": "hi"}],
            },
        }),
    ).json()
    assert body["error"]["code"] == JSONRPC_INVALID_PARAMS


# ===== tasks/get =====


def test_tasks_get_returns_existing_task(client):
    task_id = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {"message": _user_text_message()}),
    ).json()["result"]["id"]
    body = client.post(
        "/api/a2a/rpc",
        json=_rpc("tasks/get", {"id": task_id}),
    ).json()
    assert body["result"]["id"] == task_id


def test_tasks_get_missing_id_returns_invalid_params(client):
    body = client.post(
        "/api/a2a/rpc",
        json=_rpc("tasks/get", {}),
    ).json()
    assert body["error"]["code"] == JSONRPC_INVALID_PARAMS


def test_tasks_get_unknown_returns_task_not_found(client):
    body = client.post(
        "/api/a2a/rpc",
        json=_rpc("tasks/get", {"id": "nope"}),
    ).json()
    assert body["error"]["code"] == A2A_TASK_NOT_FOUND


# ===== tasks/cancel =====


def test_tasks_cancel_flips_state_to_canceled(client):
    task_id = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {"message": _user_text_message()}),
    ).json()["result"]["id"]
    body = client.post(
        "/api/a2a/rpc",
        json=_rpc("tasks/cancel", {"id": task_id}),
    ).json()
    assert body["result"]["status"]["state"] == TASK_STATE_CANCELED


def test_tasks_cancel_is_idempotent_on_terminal_tasks(client):
    """Calling cancel on an already-canceled task returns the current
    state without an error — idempotent semantics."""
    task_id = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {"message": _user_text_message()}),
    ).json()["result"]["id"]
    client.post(
        "/api/a2a/rpc",
        json=_rpc("tasks/cancel", {"id": task_id}),
    )
    body2 = client.post(
        "/api/a2a/rpc",
        json=_rpc("tasks/cancel", {"id": task_id}),
    ).json()
    assert "result" in body2
    assert body2["result"]["status"]["state"] == TASK_STATE_CANCELED


def test_send_to_canceled_task_returns_terminal_error(client):
    task_id = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {"message": _user_text_message()}),
    ).json()["result"]["id"]
    client.post(
        "/api/a2a/rpc",
        json=_rpc("tasks/cancel", {"id": task_id}),
    )
    body = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {
            "message": _user_text_message(task_id=task_id),
        }),
    ).json()
    assert body["error"]["code"] == A2A_TASK_TERMINAL


# ===== L1-1 ↔ L1-2 receipt integration =====


def test_each_message_emits_a_signed_receipt(client):
    """The whole 工作量证明 story: every accepted message must
    produce a signed motebit-compatible receipt that verifies against
    the node's pubkey."""
    task = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {"message": _user_text_message()}),
    ).json()["result"]
    receipt_id = task["metadata"]["nth_receipt_id"]
    assert receipt_id, "receipt_id missing from task.metadata"

    # Fetch the receipt from the store and verify it
    store = client.app.state.nth.receipts
    receipt = store.load(receipt_id)
    assert receipt is not None, (
        f"receipt {receipt_id} not persisted to disk"
    )
    # Pubkey of the node — bind verification to it
    node_pk = client.app.state.nth.node_identity.pubkey_hex
    assert verify_receipt(receipt, expected_pubkey_hex=node_pk), (
        "the receipt emitted by /api/a2a/rpc does not verify against "
        "the node's own pubkey — receipts are useless if they don't "
        "actually bind to the agent"
    )


def test_receipt_links_to_task_id_via_goal_id(client):
    task = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {"message": _user_text_message()}),
    ).json()["result"]
    rid = task["metadata"]["nth_receipt_id"]
    receipt = client.app.state.nth.receipts.load(rid)
    assert receipt["goal_id"] == task["id"], (
        f"receipt goal_id ({receipt['goal_id']}) must match task.id "
        f"({task['id']}); without this link the receipt is unverifiable "
        f"as proof of THIS task's execution"
    )


def test_receipt_timeline_starts_with_goal_started(client):
    """motebit convention: the first entry of a receipt timeline
    should be ``goal_started``. We embed task_id + context_id in its
    payload so a consumer reading just that one entry knows what
    the receipt is about."""
    task = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {"message": _user_text_message()}),
    ).json()["result"]
    rid = task["metadata"]["nth_receipt_id"]
    receipt = client.app.state.nth.receipts.load(rid)
    first = receipt["timeline"][0]
    assert first["type"] == "goal_started"
    assert first["payload"]["task_id"] == task["id"]


# ===== auth gating =====


# ===== F1 + F2 (review fixes) =====


def test_f2_appended_message_receipt_uses_step_started_not_goal_started(
    client,
):
    """F2 (2026-06-08): emitting goal_started for every message in a
    task confuses any consumer building a state machine off the
    timeline ('did the goal start 5 times?'). The first message gets
    goal_started; subsequent messages on the SAME task get
    step_started."""
    # First message → goal_started
    task1 = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {"message": _user_text_message()}),
    ).json()["result"]
    rid1 = task1["metadata"]["nth_receipt_id"]
    receipt1 = client.app.state.nth.receipts.load(rid1)
    assert receipt1["timeline"][0]["type"] == "goal_started"

    # Second message → step_started (goal already exists)
    task2 = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {
            "message": _user_text_message("second", task_id=task1["id"]),
        }),
    ).json()["result"]
    rid2 = task2["metadata"]["nth_receipt_id"]
    assert rid2 != rid1, "second message should produce a new receipt"
    receipt2 = client.app.state.nth.receipts.load(rid2)
    assert receipt2["timeline"][0]["type"] == "step_started", (
        f"appended-message receipt's first entry must be step_started; "
        f"got {receipt2['timeline'][0]['type']!r}. Producing "
        f"goal_started for the Nth message implies the goal restarted, "
        f"which it didn't."
    )


def test_f1_concurrent_message_sends_dont_lose_metadata(client):
    """F1 (2026-06-08): the metadata write in receipt emission used
    to happen on a task dict held outside the store's lock. A
    concurrent ``append_message`` from another thread could observe
    a partially-updated metadata dict or lose a write.

    We don't have multi-thread chaos in pytest, but we CAN verify the
    invariant: after N sequential sends to the SAME task, every send
    has stamped its receipt_id, and the final dict in the store has
    SOME receipt_id (not None). If the lock-protected write is wired
    correctly this passes trivially; if someone reverts to direct
    mutation, future concurrency tests will start failing.
    """
    first = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {"message": _user_text_message()}),
    ).json()["result"]
    task_id = first["id"]
    last_rid = first["metadata"]["nth_receipt_id"]

    for i in range(5):
        followup = client.post(
            "/api/a2a/rpc",
            json=_rpc("message/send", {
                "message": _user_text_message(
                    f"msg{i}", task_id=task_id,
                ),
            }),
        ).json()["result"]
        rid = followup["metadata"]["nth_receipt_id"]
        assert rid, f"send #{i} returned task without receipt_id"
        assert rid != last_rid, f"send #{i} reused receipt_id"
        last_rid = rid

    # And the canonical store reflects the last write
    store_task = client.app.state.nth.a2a_tasks.get(task_id)
    assert store_task["metadata"]["nth_receipt_id"] == last_rid


# ===== MA-2 (review fix): narrowed receipt-emission exception handling =====


def test_ma2_recoverable_oserror_marks_task_but_request_still_succeeds(
    client, monkeypatch,
):
    """A recoverable OSError (e.g. disk full) on ``receipts.save``
    must NOT take down the whole JSON-RPC request — the Task should
    still come back to the consumer with state=SUBMITTED, but the
    ``metadata.nth_receipt_error`` marker tells them the receipt is
    missing so they can refuse to trust the work-proof chain.

    Pre-MA2 the same case logged at WARNING and left the task with
    NO indication that the receipt was missing — a consumer pinged
    `task.metadata.nth_receipt_id` and got KeyError, conflating it
    with "no receipt yet, retry later"."""
    def boom_save(_receipt):
        raise OSError("disk full")
    monkeypatch.setattr(
        client.app.state.nth.receipts, "save", boom_save,
    )

    resp = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {"message": _user_text_message()}),
    )
    assert resp.status_code == 200
    body = resp.json()
    # The Task itself still comes back — receipt failure is a
    # sub-step, not the request
    assert "result" in body, body
    task = body["result"]
    # And the error marker is visible
    assert task["metadata"].get("nth_receipt_error") is True
    assert task["metadata"].get("nth_receipt_error_class") == "OSError"
    # And the success field is absent (no receipt was actually saved)
    assert "nth_receipt_id" not in task["metadata"]


def test_ma2_recoverable_runtimeerror_in_sign_is_caught(
    client, monkeypatch,
):
    """If the identity loses its signing capability mid-flight (rare
    but possible with key rotation), sign_receipt raises RuntimeError.
    That's recoverable — mark the task and let the consumer continue."""
    def boom_sign(_payload):
        raise RuntimeError("key wiped")
    monkeypatch.setattr(
        client.app.state.nth.node_identity, "sign", boom_sign,
    )

    body = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {"message": _user_text_message()}),
    ).json()
    assert "result" in body
    task = body["result"]
    assert task["metadata"].get("nth_receipt_error") is True
    assert task["metadata"].get("nth_receipt_error_class") == "RuntimeError"


def test_ma2_non_recoverable_memoryerror_propagates_to_jsonrpc_error(
    client, monkeypatch,
):
    """The contract: things outside the recoverable tuple must
    propagate, and the JSON-RPC layer maps them to -32603 internal
    error. A consumer SHOULD NOT see a "successful" Task when the
    underlying system is genuinely broken (memory exhausted).

    Pre-MA2 the bare ``except Exception`` would have swallowed even
    MemoryError, returning a task with a stale metadata error marker
    — but no clear signal to the consumer that the runtime is in
    trouble."""
    def boom_save(_receipt):
        raise MemoryError("out of memory")
    monkeypatch.setattr(
        client.app.state.nth.receipts, "save", boom_save,
    )

    body = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {"message": _user_text_message()}),
    ).json()
    # The outer JSON-RPC handler catches Exception and returns
    # -32603. The consumer sees a structured error, not a
    # Task-shaped lie.
    assert "error" in body
    assert body["error"]["code"] == -32603


def test_ma2_cancel_receipt_failure_also_marks_metadata(
    client, monkeypatch,
):
    """Symmetric coverage on the cancel path: cancel-receipt save
    failure must also write the error marker so a consumer reading
    the canceled Task can detect the missing proof."""
    # Create a task first (successful path)
    task = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {"message": _user_text_message()}),
    ).json()["result"]
    task_id = task["id"]
    # Now break cancel-time receipt emission
    def boom_save(_receipt):
        raise OSError("disk full")
    monkeypatch.setattr(
        client.app.state.nth.receipts, "save", boom_save,
    )
    body = client.post(
        "/api/a2a/rpc",
        json=_rpc("tasks/cancel", {"id": task_id}),
    ).json()
    assert "result" in body
    canceled = body["result"]
    assert canceled["status"]["state"] == TASK_STATE_CANCELED
    assert canceled["metadata"].get("nth_receipt_error") is True
    assert (
        canceled["metadata"].get("nth_receipt_error_class") == "OSError"
    )


def test_a2a_rpc_endpoint_requires_console_token(auth_client):
    """When console_auth is on, /api/a2a/rpc must reject unauthenticated
    POSTs. Otherwise a LAN attacker can drain work + receipts from us."""
    client, token = auth_client
    # No Authorization header
    resp = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {"message": _user_text_message()}),
    )
    assert resp.status_code == 401
    # With token — accepted
    resp = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {"message": _user_text_message()}),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert "result" in resp.json()
