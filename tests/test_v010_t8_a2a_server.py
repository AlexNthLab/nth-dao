"""v0.10 T-8: A2A JSON-RPC 2.0 server skeleton.

create_a2a_app builds a FastAPI app exposing:
  GET  /.well-known/agent.json   - serves the supplied Agent Card
  POST /a2a/jsonrpc              - JSON-RPC 2.0 endpoint

Method coverage:
  tasks/get                 implemented
  message/send, ...         stubbed -> -32601 with planned-release hint

Tests (16) cover:
  * Well-known path serves the agent card
  * JSON-RPC envelope validation (jsonrpc field, method field, parse errors)
  * tasks/get happy path returns rendered Task
  * tasks/get TaskNotFoundError (-32001) for unknown task id
  * tasks/get -32602 for missing params, params not object, missing taskId
  * tasks/get -32603 when no mission_store configured
  * stubbed methods (message/send) return -32601 with planned_for hint
  * unknown method returns -32601 with implemented/planned method lists
  * notifications (no id) get no response body (HTTP 204)
  * batch requests handled correctly (mixed real + notification)
  * batch of only notifications -> HTTP 204
  * empty batch -> -32600
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
from fastapi.testclient import TestClient

from nth_dao.a2a.agent_card import build_agent_card
from nth_dao.a2a.server import (
    A2A_METHODS_IMPLEMENTED,
    A2A_METHODS_PLANNED,
    A2A_TASK_NOT_FOUND,
    JSONRPC_INTERNAL_ERROR,
    JSONRPC_INVALID_PARAMS,
    JSONRPC_INVALID_REQUEST,
    JSONRPC_METHOD_NOT_FOUND,
    JSONRPC_PARSE_ERROR,
    create_a2a_app,
)


# ===== fixtures =====


@pytest.fixture
def agent_card() -> Dict[str, Any]:
    return build_agent_card(
        name="Test Agent",
        description="T-8 fixture",
        url="https://example.com/a2a",
        capabilities=["code_review"],
    )


class FakeMission:
    """Minimal stand-in for the orchestration Mission shape that
    a2a_task_from_mission can render."""

    def __init__(self, mission_id: str, **kw):
        self.mission_id = mission_id
        self._dict = {
            "mission_id": mission_id,
            "title": kw.pop("title", "Sample"),
            "status": kw.pop("status", "running"),
            "steps": kw.pop("steps", []),
            **kw,
        }

    def to_dict(self) -> Dict[str, Any]:
        return self._dict


class FakeMissionStore:
    """In-memory MissionStore stub - only needs the .get() shape."""

    def __init__(self, missions: Optional[List[FakeMission]] = None):
        self._missions: Dict[str, FakeMission] = {
            m.mission_id: m for m in (missions or [])
        }

    def get(self, mission_id: str) -> Optional[FakeMission]:
        return self._missions.get(mission_id)


class FaultyMissionStore:
    """MissionStore stub whose backend lookup fails unexpectedly."""

    def get(self, mission_id: str) -> Optional[FakeMission]:
        raise RuntimeError(f"backend exploded for {mission_id}")


@pytest.fixture
def store() -> FakeMissionStore:
    return FakeMissionStore([
        FakeMission("mission-001", title="Code review of PR #42"),
        FakeMission("mission-002", title="Deploy v0.10.0"),
    ])


@pytest.fixture
def client(agent_card, store) -> TestClient:
    # Voss V-25: tests use loopback so allow_unauthenticated=True is
    # the right posture; production deployments must supply
    # auth_callable instead.
    app = create_a2a_app(
        agent_card=agent_card, mission_store=store,
        allow_unauthenticated=True,
    )
    return TestClient(app)


def _rpc(client: TestClient, payload: Any):
    return client.post("/a2a/jsonrpc", json=payload)


# ===== T8-#1: well-known endpoint =====


def test_T8_01_well_known_serves_agent_card(client, agent_card):
    resp = client.get("/.well-known/agent.json")
    assert resp.status_code == 200
    body = resp.json()
    assert body["name"] == agent_card["name"]
    assert body["supportedInterfaces"][0]["url"] == agent_card["supportedInterfaces"][0]["url"]
    assert body["supportedInterfaces"][0]["protocolBinding"] == "HTTP+JSON"
    # All core A2A v1.0.1 required fields present.
    for field in ("supportedInterfaces", "capabilities", "skills"):
        assert field in body


def test_T8_01b_create_app_rejects_invalid_card():
    """The server should refuse to start with a malformed card -
    otherwise consumers fetch garbage from /.well-known/agent.json."""
    with pytest.raises(ValueError, match="invalid Agent Card"):
        create_a2a_app(
            agent_card={"not": "a card"}, allow_unauthenticated=True,
        )


# ===== T8-#2: JSON-RPC envelope validation =====


def test_T8_02_parse_error_for_invalid_json(client):
    resp = client.post("/a2a/jsonrpc", content=b"{not valid json", headers={
        "content-type": "application/json",
    })
    body = resp.json()
    assert body["error"]["code"] == JSONRPC_PARSE_ERROR
    assert body["id"] is None


def test_T8_02b_invalid_request_when_missing_jsonrpc_field(client):
    body = _rpc(client, {"method": "tasks/get", "id": 1, "params": {}}).json()
    assert body["error"]["code"] == JSONRPC_INVALID_REQUEST
    assert "jsonrpc" in body["error"]["message"]


def test_T8_02c_invalid_request_when_method_missing(client):
    body = _rpc(client, {"jsonrpc": "2.0", "id": 1, "params": {}}).json()
    assert body["error"]["code"] == JSONRPC_INVALID_REQUEST
    assert "method" in body["error"]["message"]


def test_T8_02d_invalid_request_when_payload_not_object(client):
    body = _rpc(client, "just a string").json()
    assert body["error"]["code"] == JSONRPC_INVALID_REQUEST


# ===== T8-#3: tasks/get happy path =====


def test_T8_03_tasks_get_returns_rendered_task(client):
    body = _rpc(client, {
        "jsonrpc": "2.0", "id": "rid-1",
        "method": "tasks/get", "params": {"id": "mission-001"},
    }).json()
    assert body["id"] == "rid-1"
    assert "error" not in body
    # a2a_task_from_mission renders mission_id into the task id field
    assert "id" in body["result"] or "taskId" in body["result"]


def test_T8_03b_tasks_get_accepts_legacy_taskId_alias(client):
    """A2A v0.x consumers may still send {"taskId": ...} - accept it."""
    body = _rpc(client, {
        "jsonrpc": "2.0", "id": 7,
        "method": "tasks/get", "params": {"taskId": "mission-002"},
    }).json()
    assert "error" not in body
    assert body["id"] == 7


# ===== T8-#4: tasks/get TaskNotFoundError =====


def test_T8_04_tasks_get_returns_task_not_found_for_unknown_id(client):
    body = _rpc(client, {
        "jsonrpc": "2.0", "id": 1,
        "method": "tasks/get", "params": {"id": "nope"},
    }).json()
    assert body["error"]["code"] == A2A_TASK_NOT_FOUND
    assert body["error"]["message"] == "TaskNotFoundError"
    assert body["error"]["data"]["taskId"] == "nope"


# ===== T8-#5: tasks/get param validation =====


def test_T8_05_tasks_get_invalid_params(client):
    # params is not an object
    body = _rpc(client, {
        "jsonrpc": "2.0", "id": 1, "method": "tasks/get",
        "params": ["wrong", "shape"],
    }).json()
    assert body["error"]["code"] == JSONRPC_INVALID_PARAMS

    # missing id
    body = _rpc(client, {
        "jsonrpc": "2.0", "id": 1, "method": "tasks/get", "params": {},
    }).json()
    assert body["error"]["code"] == JSONRPC_INVALID_PARAMS

    # empty id
    body = _rpc(client, {
        "jsonrpc": "2.0", "id": 1, "method": "tasks/get",
        "params": {"id": ""},
    }).json()
    assert body["error"]["code"] == JSONRPC_INVALID_PARAMS


# ===== T8-#6: no mission_store configured =====


def test_T8_06_tasks_get_without_mission_store(agent_card):
    app = create_a2a_app(
        agent_card=agent_card, mission_store=None,
        allow_unauthenticated=True,
    )
    with TestClient(app) as c:
        body = _rpc(c, {
            "jsonrpc": "2.0", "id": 1,
            "method": "tasks/get", "params": {"id": "anything"},
        }).json()
        assert body["error"]["code"] == JSONRPC_INTERNAL_ERROR
        assert "no mission store" in body["error"]["message"]


def test_T8_06b_tasks_get_store_exception_is_opaque(agent_card):
    app = create_a2a_app(
        agent_card=agent_card, mission_store=FaultyMissionStore(),
        allow_unauthenticated=True,
    )
    with TestClient(app) as c:
        body = _rpc(c, {
            "jsonrpc": "2.0", "id": 1,
            "method": "tasks/get", "params": {"id": "secret-task"},
        }).json()

    err = body["error"]
    assert err["code"] == JSONRPC_INTERNAL_ERROR
    assert "RuntimeError" not in err["message"]
    assert "backend exploded" not in err["message"]
    assert "secret-task" not in err["message"]
    assert err["message"].startswith("Mission store lookup failed (ref ")
    assert set(err["data"]) == {"ref"}
    assert isinstance(err["data"]["ref"], str)
    assert len(err["data"]["ref"]) == 12
    assert all(ch in "0123456789abcdef" for ch in err["data"]["ref"])


# ===== T8-#7: stubbed methods =====


def test_T8_07_stubbed_methods_return_method_not_found_with_planned_data(client):
    """Each method recognised by the A2A spec but not yet implemented
    returns -32601 with structured data so consumers can render an
    actionable error rather than retrying blindly."""
    body = _rpc(client, {
        "jsonrpc": "2.0", "id": 1,
        "method": "message/send", "params": {},
    }).json()
    assert body["error"]["code"] == JSONRPC_METHOD_NOT_FOUND
    assert body["error"]["data"]["method"] == "message/send"
    assert body["error"]["data"]["planned_for"] == "v0.11"
    assert "tasks/get" in body["error"]["data"]["implemented_methods"]


def test_T8_07b_every_planned_method_responds_consistently(client):
    """Every method registered in A2A_METHODS_PLANNED must yield the
    same shape (-32601 + planned_for) so consumers can rely on it."""
    for method, planned_for in A2A_METHODS_PLANNED.items():
        body = _rpc(client, {
            "jsonrpc": "2.0", "id": method,
            "method": method, "params": {},
        }).json()
        assert body["error"]["code"] == JSONRPC_METHOD_NOT_FOUND
        assert body["error"]["data"]["planned_for"] == planned_for
        assert body["id"] == method


# ===== T8-#8: unknown method =====


def test_T8_08_unknown_method_returns_method_not_found_with_lists(client):
    body = _rpc(client, {
        "jsonrpc": "2.0", "id": 1,
        "method": "tasks/teleport", "params": {},
    }).json()
    assert body["error"]["code"] == JSONRPC_METHOD_NOT_FOUND
    assert "tasks/get" in body["error"]["data"]["implemented_methods"]
    assert "message/send" in body["error"]["data"]["planned_methods"]


# ===== T8-#9: notifications =====


def test_T8_09_notification_returns_no_response_body(client):
    """JSON-RPC 2.0 spec: a request without an `id` field is a
    notification and the server MUST NOT return a response body."""
    resp = _rpc(client, {
        "jsonrpc": "2.0", "method": "tasks/get",
        "params": {"id": "mission-001"},
    })
    assert resp.status_code == 204
    assert resp.content == b""


def test_T8_09b_notification_for_unknown_method_also_silent(client):
    """Even when a notification triggers a method error, the spec
    requires no response."""
    resp = _rpc(client, {"jsonrpc": "2.0", "method": "no/such/thing"})
    assert resp.status_code == 204


def test_T8_09c_id_null_is_still_a_request_not_a_notification(client):
    """A literal null id is a REQUEST (the spec is explicit). Only
    OMITTING the id makes it a notification."""
    resp = _rpc(client, {
        "jsonrpc": "2.0", "id": None,
        "method": "tasks/get", "params": {"id": "mission-001"},
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] is None
    assert "result" in body


# ===== T8-#10: batch handling =====


def test_T8_10_batch_returns_array_of_responses(client):
    batch = [
        {"jsonrpc": "2.0", "id": 1, "method": "tasks/get",
         "params": {"id": "mission-001"}},
        {"jsonrpc": "2.0", "id": 2, "method": "tasks/get",
         "params": {"id": "nope"}},
    ]
    body = _rpc(client, batch).json()
    assert isinstance(body, list)
    assert len(body) == 2
    ids = sorted(r["id"] for r in body)
    assert ids == [1, 2]


def test_T8_10b_batch_strips_notifications_from_response(client):
    """A mixed batch returns responses ONLY for the non-notifications."""
    batch = [
        {"jsonrpc": "2.0", "id": 1, "method": "tasks/get",
         "params": {"id": "mission-001"}},
        {"jsonrpc": "2.0", "method": "tasks/get",
         "params": {"id": "mission-002"}},        # notification
    ]
    body = _rpc(client, batch).json()
    assert isinstance(body, list)
    assert len(body) == 1
    assert body[0]["id"] == 1


def test_T8_10c_batch_of_only_notifications_returns_204(client):
    batch = [
        {"jsonrpc": "2.0", "method": "tasks/get",
         "params": {"id": "mission-001"}},
        {"jsonrpc": "2.0", "method": "tasks/get",
         "params": {"id": "mission-002"}},
    ]
    resp = _rpc(client, batch)
    assert resp.status_code == 204


def test_T8_10d_empty_batch_returns_invalid_request(client):
    body = _rpc(client, []).json()
    assert body["error"]["code"] == JSONRPC_INVALID_REQUEST


# ===== T8-#11: facade re-export =====


def test_T8_11_facade_reexport():
    import nth_dao
    assert nth_dao.create_a2a_app is create_a2a_app
    assert nth_dao.A2A_METHODS_IMPLEMENTED == A2A_METHODS_IMPLEMENTED
    assert nth_dao.A2A_METHODS_PLANNED == A2A_METHODS_PLANNED
    assert nth_dao.A2A_TASK_NOT_FOUND == A2A_TASK_NOT_FOUND
    # Class re-export
    from nth_dao.a2a.server import JsonRpcError
    assert nth_dao.JsonRpcError is JsonRpcError
