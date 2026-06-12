"""Capability delegation tokens — L1-3 (2026-06-08).

What this suite proves:

  1. Token wire format is byte-stable: canonical_json of the body
     (excluding sig) produces the same bytes every time, so a Rust
     port verifies identically.
  2. Sign → verify round-trip passes; tamper → fails.
  3. Time bounds enforced (not_before / not_after).
  4. Revocation: an admin revoking a token_id makes verify reject.
  5. Capability sufficiency: missing the required cap → reject.
  6. Scope match: token bound to task A cannot operate on task B.
  7. Store: atomic write, path-traversal rejected, revoked.json
     persists.
  8. A2A RPC integration: a cap_token presented in
     ``Authorization: CapToken …`` is accepted by middleware,
     handler narrowly allows ONLY the granted methods, scope_task_id
     blocks new-task creation AND cross-task addressing.
  9. Console principal still has full access (no regression on the
     existing Bearer flow).
 10. Endpoints: issue / revoke / audit-get all require console
     principal; a cap_token holder CANNOT mint further tokens
     (delegation is not transitive).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from nth_dao.a2a_rpc import (
    A2A_FORBIDDEN_BY_CAP,
    TASK_STATE_SUBMITTED,
)
from nth_dao.cap_token import (
    AUTH_SCHEME_CAP_TOKEN,
    CAP_A2A_MESSAGE_SEND,
    CAP_A2A_TASK_CANCEL,
    CAP_A2A_TASK_GET,
    DEFAULT_TTL_MS,
    MAX_TTL_MS,
    REJECT_CAP_INSUFFICIENT,
    REJECT_EXPIRED,
    REJECT_NOT_YET_VALID,
    REJECT_REVOKED,
    REJECT_SCOPE_MISMATCH,
    REJECT_SIG_INVALID,
    CapTokenStore,
    decode_authorization_value,
    encode_authorization_header,
    sign_cap_token,
    verify_cap_token,
)
from nth_dao.execution_receipt import now_ms
from nth_dao.identity import AgentIdentity, crypto_available
from nth_dao.web import create_app


pytestmark = pytest.mark.skipif(
    not crypto_available(),
    reason="cap_token requires PyNaCl",
)


# ─── helpers ─────────────────────────────────────────────────────────


@pytest.fixture
def admin() -> AgentIdentity:
    return AgentIdentity.generate(label="admin")


@pytest.fixture
def helper() -> AgentIdentity:
    return AgentIdentity.generate(label="helper")


def _rpc(method, params=None, req_id="r1"):
    payload = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        payload["params"] = params
    return payload


def _user_msg(text="hello", **overrides):
    msg = {"role": "ROLE_USER", "parts": [{"kind": "text", "text": text}]}
    msg.update(overrides)
    return msg


# ─── token sign/verify ────────────────────────────────────────────────


def test_sign_then_verify_roundtrip(admin, helper):
    tok = sign_cap_token(
        issuer=admin,
        subject_did=helper.as_did(),
        capabilities=[CAP_A2A_MESSAGE_SEND],
    )
    ok, reason = verify_cap_token(tok)
    assert ok, reason
    assert reason == ""


def test_capabilities_are_sorted_and_deduplicated(admin, helper):
    """Wire-form determinism: canonical_json signing requires the
    capabilities array to be byte-stable. Sorting + dedup at sign
    time means re-signing with the same logical set produces the
    same body bytes."""
    tok = sign_cap_token(
        issuer=admin, subject_did=helper.as_did(),
        capabilities=[
            "a2a:task_get", "a2a:message_send",
            "a2a:message_send",  # duplicate
        ],
    )
    assert tok["capabilities"] == ["a2a:message_send", "a2a:task_get"]


def test_sign_rejects_empty_capabilities(admin, helper):
    with pytest.raises(ValueError):
        sign_cap_token(
            issuer=admin, subject_did=helper.as_did(), capabilities=[],
        )


def test_sign_rejects_non_did_key_subject(admin):
    with pytest.raises(ValueError):
        sign_cap_token(
            issuer=admin,
            subject_did="not-a-did",
            capabilities=[CAP_A2A_MESSAGE_SEND],
        )


def test_sign_rejects_ttl_above_max(admin, helper):
    with pytest.raises(ValueError):
        sign_cap_token(
            issuer=admin, subject_did=helper.as_did(),
            capabilities=[CAP_A2A_MESSAGE_SEND],
            ttl_ms=MAX_TTL_MS + 1,
        )


def test_verify_rejects_tampered_capabilities(admin, helper):
    tok = sign_cap_token(
        issuer=admin, subject_did=helper.as_did(),
        capabilities=[CAP_A2A_MESSAGE_SEND],
    )
    tok["capabilities"].append("nth:add_member")
    ok, reason = verify_cap_token(tok)
    assert not ok
    assert reason == REJECT_SIG_INVALID


def test_verify_rejects_signature_under_wrong_key(admin, helper):
    """Sign with attacker, claim to be admin — verify rejects."""
    attacker = AgentIdentity.generate(label="attacker")
    tok = sign_cap_token(
        issuer=attacker, subject_did=helper.as_did(),
        capabilities=[CAP_A2A_MESSAGE_SEND],
    )
    # Swap the issuer DID to claim it's from admin — sig now doesn't
    # match the claimed pubkey
    tok["issuer_did"] = admin.as_did()
    ok, reason = verify_cap_token(tok)
    assert not ok


def test_verify_rejects_expired_token(admin, helper):
    tok = sign_cap_token(
        issuer=admin, subject_did=helper.as_did(),
        capabilities=[CAP_A2A_MESSAGE_SEND],
        ttl_ms=1_000,
    )
    far_future = tok["not_after"] + 60_000
    ok, reason = verify_cap_token(tok, now_ms_override=far_future)
    assert not ok
    assert reason == REJECT_EXPIRED


def test_verify_rejects_not_yet_valid_token(admin, helper):
    tok = sign_cap_token(
        issuer=admin, subject_did=helper.as_did(),
        capabilities=[CAP_A2A_MESSAGE_SEND],
    )
    far_past = tok["not_before"] - 60_000
    ok, reason = verify_cap_token(tok, now_ms_override=far_past)
    assert not ok
    assert reason == REJECT_NOT_YET_VALID


def test_verify_rejects_revoked_token(admin, helper):
    tok = sign_cap_token(
        issuer=admin, subject_did=helper.as_did(),
        capabilities=[CAP_A2A_MESSAGE_SEND],
    )
    ok, reason = verify_cap_token(
        tok, revoked_ids={tok["token_id"]},
    )
    assert not ok
    assert reason == REJECT_REVOKED


def test_verify_rejects_capability_insufficient(admin, helper):
    tok = sign_cap_token(
        issuer=admin, subject_did=helper.as_did(),
        capabilities=[CAP_A2A_TASK_GET],
    )
    ok, reason = verify_cap_token(
        tok, required_capabilities=[CAP_A2A_MESSAGE_SEND],
    )
    assert not ok
    assert reason == REJECT_CAP_INSUFFICIENT


def test_verify_accepts_when_token_has_more_caps_than_needed(
    admin, helper,
):
    tok = sign_cap_token(
        issuer=admin, subject_did=helper.as_did(),
        capabilities=[
            CAP_A2A_MESSAGE_SEND, CAP_A2A_TASK_GET, CAP_A2A_TASK_CANCEL,
        ],
    )
    ok, _ = verify_cap_token(
        tok, required_capabilities=[CAP_A2A_MESSAGE_SEND],
    )
    assert ok


def test_verify_rejects_scope_task_mismatch(admin, helper):
    tok = sign_cap_token(
        issuer=admin, subject_did=helper.as_did(),
        capabilities=[CAP_A2A_MESSAGE_SEND],
        scope_task_id="task-A",
    )
    ok, reason = verify_cap_token(
        tok, required_task_id="task-B",
    )
    assert not ok
    assert reason == REJECT_SCOPE_MISMATCH


def test_unrestricted_token_passes_any_task_scope_check(admin, helper):
    """Empty scope_task_id means 'no task scope' — verification
    should accept regardless of required_task_id."""
    tok = sign_cap_token(
        issuer=admin, subject_did=helper.as_did(),
        capabilities=[CAP_A2A_MESSAGE_SEND],
        scope_task_id="",
    )
    ok, _ = verify_cap_token(tok, required_task_id="any-task")
    assert ok


# ─── authorization header codec ──────────────────────────────────────


def test_encode_decode_roundtrip_preserves_token(admin, helper):
    tok = sign_cap_token(
        issuer=admin, subject_did=helper.as_did(),
        capabilities=[CAP_A2A_MESSAGE_SEND],
    )
    encoded = encode_authorization_header(tok)
    decoded = decode_authorization_value(encoded)
    assert decoded == tok


def test_decode_garbage_returns_none():
    """Middleware must not raise on a malformed CapToken header —
    fail-closed silently and return 401."""
    assert decode_authorization_value("not-valid-base64!!!") is None
    assert decode_authorization_value("aGVsbG8=") is None  # valid b64
                                                            # but not JSON


# ─── store ───────────────────────────────────────────────────────────


def test_store_record_then_get_roundtrips(tmp_path, admin, helper):
    store = CapTokenStore(tmp_path)
    tok = sign_cap_token(
        issuer=admin, subject_did=helper.as_did(),
        capabilities=[CAP_A2A_MESSAGE_SEND],
    )
    path = store.record(tok)
    assert path.exists()
    assert store.get(tok["token_id"]) == tok


def test_store_revoke_persists_across_loads(tmp_path, admin, helper):
    store = CapTokenStore(tmp_path)
    tok = sign_cap_token(
        issuer=admin, subject_did=helper.as_did(),
        capabilities=[CAP_A2A_MESSAGE_SEND],
    )
    store.record(tok)
    assert store.revoke(tok["token_id"]) is True
    # Idempotent: second revoke returns False, set unchanged
    assert store.revoke(tok["token_id"]) is False
    # And a fresh store over the same dir sees it
    store2 = CapTokenStore(tmp_path)
    assert tok["token_id"] in store2.revoked_set()


def test_store_rejects_path_traversal_in_token_id(tmp_path):
    store = CapTokenStore(tmp_path)
    fake = {"token_id": "../escape", "kind": "x"}
    with pytest.raises(ValueError):
        store.record(fake)


def test_store_get_rejects_path_traversal(tmp_path):
    store = CapTokenStore(tmp_path)
    assert store.get("../../etc/passwd") is None


# ─── A2A RPC integration ─────────────────────────────────────────────


@pytest.fixture
def client(tmp_path, monkeypatch) -> TestClient:
    monkeypatch.setenv("NTH_LAN_PUBLISH", "0")
    return TestClient(create_app(tmp_path, require_console_auth=True))


def _console_headers(client) -> dict:
    return {"Authorization": f"Bearer {client.app.state.nth_console_token}"}


def _captoken_headers(tok: dict) -> dict:
    return {
        "Authorization": (
            f"{AUTH_SCHEME_CAP_TOKEN} "
            f"{encode_authorization_header(tok)}"
        ),
    }


def test_console_principal_still_has_full_access(client):
    """Regression: existing Bearer flow MUST keep working — adding
    CapToken support cannot weaken the console path."""
    resp = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {"message": _user_msg()}),
        headers=_console_headers(client),
    )
    assert resp.status_code == 200
    assert "result" in resp.json()


def test_no_auth_still_returns_401(client):
    resp = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {"message": _user_msg()}),
    )
    assert resp.status_code == 401


def test_cap_token_with_message_send_cap_is_accepted(client):
    """End-to-end: admin issues a token via /api/cap_tokens/issue
    granting a2a:message_send; helper presents it; A2A RPC accepts."""
    # First, who is admin? Use the node's own identity as both
    # issuer (via the console-issue endpoint) and... actually the
    # subject can be anyone. Generate a helper DID outside the node.
    helper_ident = AgentIdentity.generate(label="ext-helper")

    issue = client.post(
        "/api/cap_tokens/issue",
        json={
            "subject_did": helper_ident.as_did(),
            "capabilities": [CAP_A2A_MESSAGE_SEND],
        },
        headers=_console_headers(client),
    )
    assert issue.status_code == 200, issue.text
    tok = issue.json()["token"]

    resp = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {"message": _user_msg()}),
        headers=_captoken_headers(tok),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "result" in body
    assert body["result"]["status"]["state"] == TASK_STATE_SUBMITTED


def test_cap_token_without_required_cap_is_denied(client):
    """A token that grants only tasks/get must not allow message/send."""
    helper_ident = AgentIdentity.generate(label="ext-helper")
    issue = client.post(
        "/api/cap_tokens/issue",
        json={
            "subject_did": helper_ident.as_did(),
            "capabilities": [CAP_A2A_TASK_GET],
        },
        headers=_console_headers(client),
    )
    tok = issue.json()["token"]

    body = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {"message": _user_msg()}),
        headers=_captoken_headers(tok),
    ).json()
    assert body["error"]["code"] == A2A_FORBIDDEN_BY_CAP
    assert "a2a:message_send" in body["error"]["message"]


def test_scoped_token_cannot_create_new_task(client):
    """注意力集中 contract: a token bound to task X cannot mint
    NEW tasks (which would escape the scope). The handler must
    refuse message/send without a target task_id."""
    helper_ident = AgentIdentity.generate(label="ext-helper")
    issue = client.post(
        "/api/cap_tokens/issue",
        json={
            "subject_did": helper_ident.as_did(),
            "capabilities": [CAP_A2A_MESSAGE_SEND],
            "scope_task_id": "task-existing-123",
        },
        headers=_console_headers(client),
    )
    tok = issue.json()["token"]

    body = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {"message": _user_msg()}),
        headers=_captoken_headers(tok),
    ).json()
    assert body["error"]["code"] == A2A_FORBIDDEN_BY_CAP
    assert "cannot create a new task" in body["error"]["message"]


def test_scoped_token_can_append_to_its_bound_task_only(client):
    """The token bound to task X CAN append to task X but NOT to
    a different task."""
    # 1) Create the bound task with the console (full-trust)
    seed = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {"message": _user_msg("seed")}),
        headers=_console_headers(client),
    ).json()["result"]
    bound_task_id = seed["id"]

    # 2) And a second task — the off-limits one
    other = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {"message": _user_msg("other")}),
        headers=_console_headers(client),
    ).json()["result"]
    other_task_id = other["id"]

    # 3) Mint a cap_token bound to the FIRST task
    helper_ident = AgentIdentity.generate(label="bound-helper")
    issue = client.post(
        "/api/cap_tokens/issue",
        json={
            "subject_did": helper_ident.as_did(),
            "capabilities": [CAP_A2A_MESSAGE_SEND, CAP_A2A_TASK_GET],
            "scope_task_id": bound_task_id,
        },
        headers=_console_headers(client),
    )
    tok = issue.json()["token"]

    # 4) Appending to the bound task is allowed
    ok = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {
            "message": _user_msg("step", task_id=bound_task_id),
        }),
        headers=_captoken_headers(tok),
    ).json()
    assert "result" in ok, ok
    assert ok["result"]["id"] == bound_task_id

    # 5) Targeting the OTHER task is denied
    denied = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {
            "message": _user_msg("intrude", task_id=other_task_id),
        }),
        headers=_captoken_headers(tok),
    ).json()
    assert denied["error"]["code"] == A2A_FORBIDDEN_BY_CAP
    assert "scoped to task" in denied["error"]["message"]


def test_revoked_cap_token_is_rejected_at_middleware(client):
    """Revoking a token must take effect within one request cycle —
    the next call from the holder bounces at middleware level."""
    helper_ident = AgentIdentity.generate(label="rev-helper")
    issue = client.post(
        "/api/cap_tokens/issue",
        json={
            "subject_did": helper_ident.as_did(),
            "capabilities": [CAP_A2A_MESSAGE_SEND],
        },
        headers=_console_headers(client),
    )
    tok = issue.json()["token"]
    # Token works first
    ok = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {"message": _user_msg()}),
        headers=_captoken_headers(tok),
    )
    assert ok.status_code == 200
    # Revoke
    client.post(
        "/api/cap_tokens/revoke",
        json={"token_id": tok["token_id"]},
        headers=_console_headers(client),
    )
    # Now the same token is dead
    dead = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {"message": _user_msg()}),
        headers=_captoken_headers(tok),
    )
    assert dead.status_code == 401
    assert "revoked" in dead.json()["detail"]


def test_cap_token_cannot_issue_further_cap_tokens(client):
    """Delegation is NOT transitive in v1 — a cap_token holder cannot
    mint additional tokens. Without this rule, a low-privilege helper
    could escalate by issuing themselves more powerful tokens."""
    helper_ident = AgentIdentity.generate(label="esc-helper")
    issue = client.post(
        "/api/cap_tokens/issue",
        json={
            "subject_did": helper_ident.as_did(),
            "capabilities": [CAP_A2A_MESSAGE_SEND],
        },
        headers=_console_headers(client),
    )
    tok = issue.json()["token"]

    # Use the cap_token to try to issue another cap_token
    sneaky = client.post(
        "/api/cap_tokens/issue",
        json={
            "subject_did": helper_ident.as_did(),
            "capabilities": [
                CAP_A2A_MESSAGE_SEND,
                CAP_A2A_TASK_CANCEL,
                "nth:add_member",
            ],
        },
        headers=_captoken_headers(tok),
    )
    assert sneaky.status_code == 403
    assert "console principal" in sneaky.json()["detail"]


def test_issue_endpoint_rejects_unknown_capability(client):
    """Typo-protection on the issue endpoint — minting a token with
    a typoed cap string would silently produce an unusable token,
    confusing the operator."""
    helper_ident = AgentIdentity.generate(label="typo-helper")
    resp = client.post(
        "/api/cap_tokens/issue",
        json={
            "subject_did": helper_ident.as_did(),
            "capabilities": ["a2a:mssage_send"],  # typo
        },
        headers=_console_headers(client),
    )
    assert resp.status_code == 400
    assert "unknown" in resp.json()["detail"].lower()


def test_r3_unknown_method_under_cap_token_is_denied_by_default(client):
    """R3 (review fix 2026-06-08): unmapped methods MUST be rejected
    when the principal is a cap_token. Without this, a future
    maintainer adding a new JSON-RPC method without updating
    _METHOD_CAP_MAP would silently make it callable by every
    valid cap_token holder."""
    helper_ident = AgentIdentity.generate(label="r3-helper")
    issue = client.post(
        "/api/cap_tokens/issue",
        json={
            "subject_did": helper_ident.as_did(),
            "capabilities": [CAP_A2A_MESSAGE_SEND],
        },
        headers=_console_headers(client),
    )
    tok = issue.json()["token"]

    body = client.post(
        "/api/a2a/rpc",
        json=_rpc("methods/never_existed", {}),
        headers=_captoken_headers(tok),
    ).json()
    assert body["error"]["code"] == A2A_FORBIDDEN_BY_CAP
    assert "not callable via cap_token" in body["error"]["message"]
    # The error data lists the callable methods so the consumer
    # can adjust their expectations.
    assert "callable_methods" in body["error"]["data"]


def test_r5_tasks_split_requires_its_own_capability(client):
    """R5 (review fix 2026-06-08): a cap_token granting only
    ``a2a:message_send`` must NOT be able to call tasks/split.
    Splitting restructures the task; it requires its own
    ``a2a:task_split`` capability."""
    # First create a task via console
    task = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {"message": _user_msg()}),
        headers=_console_headers(client),
    ).json()["result"]
    task_id = task["id"]

    # Mint a token with message_send ONLY
    helper_ident = AgentIdentity.generate(label="r5-helper")
    issue = client.post(
        "/api/cap_tokens/issue",
        json={
            "subject_did": helper_ident.as_did(),
            "capabilities": [CAP_A2A_MESSAGE_SEND],
            "scope_task_id": task_id,
        },
        headers=_console_headers(client),
    )
    tok = issue.json()["token"]

    # Try to split — must be denied for missing a2a:task_split
    body = client.post(
        "/api/a2a/rpc",
        json=_rpc("tasks/split", {
            "id": task_id, "subtasks": ["a", "b"],
        }),
        headers=_captoken_headers(tok),
    ).json()
    assert body["error"]["code"] == A2A_FORBIDDEN_BY_CAP
    assert "a2a:task_split" in body["error"]["message"]


def test_r5_token_with_explicit_task_split_cap_can_split(client):
    """The flip side: a token granting both message_send AND
    task_split CAN split. Confirms the new capability is wired
    correctly end-to-end."""
    task = client.post(
        "/api/a2a/rpc",
        json=_rpc("message/send", {"message": _user_msg()}),
        headers=_console_headers(client),
    ).json()["result"]
    task_id = task["id"]

    helper_ident = AgentIdentity.generate(label="r5-helper2")
    from nth_dao.cap_token import CAP_A2A_TASK_SPLIT
    issue = client.post(
        "/api/cap_tokens/issue",
        json={
            "subject_did": helper_ident.as_did(),
            "capabilities": [CAP_A2A_MESSAGE_SEND, CAP_A2A_TASK_SPLIT],
            "scope_task_id": task_id,
        },
        headers=_console_headers(client),
    )
    tok = issue.json()["token"]

    body = client.post(
        "/api/a2a/rpc",
        json=_rpc("tasks/split", {
            "id": task_id, "subtasks": ["plan", "execute"],
        }),
        headers=_captoken_headers(tok),
    ).json()
    assert "result" in body, body


def test_audit_endpoint_returns_persisted_token(client):
    helper_ident = AgentIdentity.generate(label="aud-helper")
    issue = client.post(
        "/api/cap_tokens/issue",
        json={
            "subject_did": helper_ident.as_did(),
            "capabilities": [CAP_A2A_MESSAGE_SEND],
        },
        headers=_console_headers(client),
    )
    token_id = issue.json()["token"]["token_id"]
    audit = client.get(
        f"/api/cap_tokens/{token_id}",
        headers=_console_headers(client),
    ).json()
    assert audit["token"]["token_id"] == token_id
    assert audit["revoked"] is False


# ─── Phase 6b: per-token model-scope allowlist ───────────────────────


def test_sign_omits_scope_model_allowlist_when_none(admin, helper):
    """Phase 6b: ``scope_model_allowlist=None`` (default) must NOT
    add the field to the token body. Old verifiers + tokens signed
    pre-6b stay bytes-identical."""
    tok = sign_cap_token(
        issuer=admin, subject_did=helper.as_did(),
        capabilities=[CAP_A2A_MESSAGE_SEND],
    )
    assert "scope_model_allowlist" not in tok


def test_sign_records_empty_scope_model_allowlist(admin, helper):
    """Phase 6b: an explicit empty list is the "forbid all overrides"
    case — must be on the wire (not coalesced to None), so a verifier
    can tell "deliberate ban" from "legacy / unspecified"."""
    tok = sign_cap_token(
        issuer=admin, subject_did=helper.as_did(),
        capabilities=[CAP_A2A_MESSAGE_SEND],
        scope_model_allowlist=[],
    )
    assert tok["scope_model_allowlist"] == []


def test_sign_dedupes_and_sorts_scope_model_allowlist(admin, helper):
    """Phase 6b: matches the existing ``capabilities`` shape — the
    canonical_json signing path needs the list byte-stable, so dedup
    + sort at sign time."""
    tok = sign_cap_token(
        issuer=admin, subject_did=helper.as_did(),
        capabilities=[CAP_A2A_MESSAGE_SEND],
        scope_model_allowlist=[
            "claude-haiku-4-5",
            "claude-sonnet-4-6",
            "claude-haiku-4-5",  # duplicate
        ],
    )
    assert tok["scope_model_allowlist"] == [
        "claude-haiku-4-5",
        "claude-sonnet-4-6",
    ]


def test_sign_rejects_non_string_scope_model_entry(admin, helper):
    """Phase 6b: each entry must be a non-empty string. ``[None]``,
    ``[42]``, ``[""]`` all fail loud at sign time so a typo doesn't
    silently get into the audit store."""
    for bad in [None, 42, ""]:
        with pytest.raises(ValueError, match="scope_model_allowlist"):
            sign_cap_token(
                issuer=admin, subject_did=helper.as_did(),
                capabilities=[CAP_A2A_MESSAGE_SEND],
                scope_model_allowlist=[bad],  # type: ignore[list-item]
            )


def test_sign_rejects_non_list_scope_model_allowlist(admin, helper):
    """Phase 6b: scope_model_allowlist MUST be a list (or None).
    Passing a frozenset / tuple / dict / str gets caught early."""
    for bad in [frozenset({"x"}), ("a", "b"), {"a": 1}, "single-string"]:
        with pytest.raises(ValueError, match="scope_model_allowlist"):
            sign_cap_token(
                issuer=admin, subject_did=helper.as_did(),
                capabilities=[CAP_A2A_MESSAGE_SEND],
                scope_model_allowlist=bad,  # type: ignore[arg-type]
            )


def test_sign_verify_roundtrip_preserves_scope_model_allowlist(admin, helper):
    """Phase 6b: signing with the field then verifying with the
    standard ``verify_cap_token`` still passes — the field rides in
    the canonical_json body so tampering would break the sig."""
    tok = sign_cap_token(
        issuer=admin, subject_did=helper.as_did(),
        capabilities=[CAP_A2A_MESSAGE_SEND],
        scope_model_allowlist=["claude-sonnet-4-6"],
    )
    ok, reason = verify_cap_token(tok)
    assert ok, reason
    assert tok["scope_model_allowlist"] == ["claude-sonnet-4-6"]


def test_verify_rejects_tampered_scope_model_allowlist(admin, helper):
    """Phase 6b: tampering the scope after signing breaks the sig —
    a peer can't widen their own model scope by editing the JSON."""
    tok = sign_cap_token(
        issuer=admin, subject_did=helper.as_did(),
        capabilities=[CAP_A2A_MESSAGE_SEND],
        scope_model_allowlist=["claude-haiku-4-5"],
    )
    tok["scope_model_allowlist"] = ["claude-opus-4-8"]  # tamper
    ok, reason = verify_cap_token(tok)
    assert not ok
    assert reason == REJECT_SIG_INVALID


def test_token_allows_model_legacy_token_defers(admin, helper):
    """Phase 6b helper: token without scope_model_allowlist → always
    OK from the per-token check (defer to backend's allowlist).
    Backward-compat for tokens issued before 6b."""
    from nth_dao.cap_token import token_allows_model
    tok = sign_cap_token(
        issuer=admin, subject_did=helper.as_did(),
        capabilities=[CAP_A2A_MESSAGE_SEND],
    )
    ok, reason = token_allows_model(tok, "claude-opus-4-8")
    assert ok, reason


def test_token_allows_model_empty_scope_rejects_any_override(admin, helper):
    """Phase 6b: explicit empty scope means "no overrides allowed",
    even tighter than backend's policy."""
    from nth_dao.cap_token import (
        REJECT_MODEL_NOT_IN_TOKEN_SCOPE, token_allows_model,
    )
    tok = sign_cap_token(
        issuer=admin, subject_did=helper.as_did(),
        capabilities=[CAP_A2A_MESSAGE_SEND],
        scope_model_allowlist=[],
    )
    ok, reason = token_allows_model(tok, "claude-sonnet-4-6")
    assert not ok
    assert reason == REJECT_MODEL_NOT_IN_TOKEN_SCOPE


def test_token_allows_model_in_scope(admin, helper):
    from nth_dao.cap_token import token_allows_model
    tok = sign_cap_token(
        issuer=admin, subject_did=helper.as_did(),
        capabilities=[CAP_A2A_MESSAGE_SEND],
        scope_model_allowlist=["claude-haiku-4-5"],
    )
    ok, reason = token_allows_model(tok, "claude-haiku-4-5")
    assert ok, reason


def test_token_allows_model_outside_scope(admin, helper):
    from nth_dao.cap_token import (
        REJECT_MODEL_NOT_IN_TOKEN_SCOPE, token_allows_model,
    )
    tok = sign_cap_token(
        issuer=admin, subject_did=helper.as_did(),
        capabilities=[CAP_A2A_MESSAGE_SEND],
        scope_model_allowlist=["claude-haiku-4-5"],
    )
    ok, reason = token_allows_model(tok, "claude-opus-4-8")
    assert not ok
    assert reason == REJECT_MODEL_NOT_IN_TOKEN_SCOPE


def test_token_allows_model_empty_request_defers(admin, helper):
    """Phase 6b: empty ``requested_model`` (caller didn't override)
    always returns OK — the per-token scope is for overrides only;
    the default-path always uses the backend's DEFAULT_MODEL."""
    from nth_dao.cap_token import token_allows_model
    tok = sign_cap_token(
        issuer=admin, subject_did=helper.as_did(),
        capabilities=[CAP_A2A_MESSAGE_SEND],
        scope_model_allowlist=[],  # most restrictive
    )
    ok, reason = token_allows_model(tok, "")
    assert ok, reason


def test_token_allows_model_malformed_scope_fails_closed(admin, helper):
    """Phase 6b: if somehow the scope field is the wrong type
    (e.g. parsed JSON with a non-list there), fail closed rather
    than open. The verifier's signature check should already catch
    tampered tokens, but defense-in-depth at the policy layer."""
    from nth_dao.cap_token import (
        REJECT_MODEL_NOT_IN_TOKEN_SCOPE, token_allows_model,
    )
    # Bypass sign_cap_token's input validation by building manually.
    tok = {
        "scope_model_allowlist": "not-a-list",  # malformed
    }
    ok, reason = token_allows_model(tok, "anything")
    assert not ok
    assert reason == REJECT_MODEL_NOT_IN_TOKEN_SCOPE


def test_sign_strips_whitespace_in_scope_model_entries(admin, helper):
    """6B-9 fix (Phase 6b R1): operator-supplied entries with leading
    or trailing whitespace get stripped at sign time. Without this,
    a typo like ``"claude-sonnet-4-6 "`` lands in the token verbatim
    and peer's ``params['model']="claude-sonnet-4-6"`` (correct, no
    space) silently fails the equality check. Strip + dedup catches
    both the whitespace AND the dup that strip might expose."""
    tok = sign_cap_token(
        issuer=admin, subject_did=helper.as_did(),
        capabilities=[CAP_A2A_MESSAGE_SEND],
        scope_model_allowlist=[
            "  claude-sonnet-4-6  ",  # leading + trailing space
            "claude-sonnet-4-6",       # bare → dup after strip
            "claude-haiku-4-5",
        ],
    )
    assert tok["scope_model_allowlist"] == [
        "claude-haiku-4-5",
        "claude-sonnet-4-6",
    ]


def test_sign_rejects_whitespace_only_scope_entry(admin, helper):
    """6B-9 (Phase 6b R1): a string that's only whitespace becomes
    empty after strip and gets rejected. Catches operators sending
    ``["   "]`` from a bad UI form."""
    with pytest.raises(ValueError, match="non-empty after strip"):
        sign_cap_token(
            issuer=admin, subject_did=helper.as_did(),
            capabilities=[CAP_A2A_MESSAGE_SEND],
            scope_model_allowlist=["   "],
        )


def test_two_layer_intersection_backend_can_narrow_token_scope() -> None:
    """6B-11 fix (Phase 6b R1): explicit proof that the per-token
    scope and the per-backend MODEL_ALLOWLIST stack as AND, not OR.

    Scenario:
      • Cap_token's ``scope_model_allowlist`` = ["claude-opus-4-8"]
        (token says "this peer can pick opus")
      • Backend's ``MODEL_ALLOWLIST`` = {"claude-sonnet-4-6",
        "claude-haiku-4-5"} (operator deployment says "no opus
        in this hub")

    Peer requests opus. Order of checks:
      1. ``token_allows_model(token, "opus")`` → True (token OK).
      2. Backend's ``_check_model_allowed("opus")`` → ValueError
         (backend forbids).

    The backend's policy MUST narrow the token's grant. Otherwise
    an operator who issued a permissive token could be surprised
    by their own deployment cap being bypassed.
    """
    from nth_dao.cap_token import token_allows_model
    from nth_dao.web.dummy_agent import _AskBackend

    token = {"scope_model_allowlist": ["claude-opus-4-8"]}
    ok, _reason = token_allows_model(token, "claude-opus-4-8")
    assert ok is True, "token scope should ALLOW opus in this scenario"

    class _BackendForbidsOpus(_AskBackend):
        name = "test-backend"
        MODEL_ALLOWLIST = frozenset({
            "claude-sonnet-4-6", "claude-haiku-4-5",
        })

    with pytest.raises(ValueError, match="not in test-backend"):
        _BackendForbidsOpus()._check_model_allowed("claude-opus-4-8")


def test_admin_issue_endpoint_persists_model_allowlist(client):
    """6B-13 fix (Phase 6b R1): the legacy admin endpoint
    ``POST /api/cap_tokens/issue`` was wired to accept
    ``scope_model_allowlist`` but had no test. Cover the path."""
    helper_ident = AgentIdentity.generate(label="scoped-admin-issue")
    issue = client.post(
        "/api/cap_tokens/issue",
        json={
            "subject_did": helper_ident.as_did(),
            "capabilities": [CAP_A2A_MESSAGE_SEND],
            "scope_model_allowlist": [
                "claude-haiku-4-5",
                "claude-sonnet-4-6",
            ],
        },
        headers=_console_headers(client),
    )
    assert issue.status_code == 200, issue.text
    tok = issue.json()["token"]
    assert tok["scope_model_allowlist"] == [
        "claude-haiku-4-5",
        "claude-sonnet-4-6",
    ]


def test_admin_issue_endpoint_omits_scope_when_not_provided(client):
    """6B-13 (Phase 6b R1): legacy admin endpoint with no
    ``scope_model_allowlist`` in the body produces a token without
    the field. Backward-compat with pre-6b admin scripts that don't
    know about this field."""
    helper_ident = AgentIdentity.generate(label="unscoped-admin-issue")
    issue = client.post(
        "/api/cap_tokens/issue",
        json={
            "subject_did": helper_ident.as_did(),
            "capabilities": [CAP_A2A_MESSAGE_SEND],
        },
        headers=_console_headers(client),
    )
    assert issue.status_code == 200, issue.text
    tok = issue.json()["token"]
    assert "scope_model_allowlist" not in tok
