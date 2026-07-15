from __future__ import annotations

import json
import hashlib
import time

from fastapi.testclient import TestClient

from nth_dao.web import create_app
from nth_dao.web.agent_supervisor import AgentRecord, AgentSupervisor, InMemoryRunner
from nth_dao.web.agent_link import AgentLinkManager, AgentLinkStore


def _signed_agent_link_receipt(identity, job_id: str, prompt: str, response: str):
    from nth_dao.execution_receipt import TimelineEntry, now_ms, sign_receipt

    return sign_receipt(
        [
            TimelineEntry(
                timestamp=now_ms(),
                type="nth.a2a_ask_executed",
                payload={
                    "method": "ask",
                    "backend": "mock",
                    "caller_did": "did:key:z6MkCaller",
                    "agent_did": identity.as_did(),
                    "agent_link_job_id": job_id,
                    "request_sha256": hashlib.sha256(
                        prompt.encode("utf-8")
                    ).hexdigest(),
                    "response_sha256": hashlib.sha256(
                        response.encode("utf-8")
                    ).hexdigest(),
                },
            )
        ],
        identity,
        goal_id="a2a:ask",
    )


def test_agent_link_submit_and_poll_does_not_persist_prompt(tmp_path, monkeypatch):
    import nth_dao.web.v2_api as v2_api

    app = create_app(workspace=tmp_path, require_console_auth=False)
    runner = InMemoryRunner()
    supervisor = AgentSupervisor(runner)
    record = AgentRecord(
        agent_id="link-agent",
        kind="mock",
        label="Link agent",
        did="did:key:z6MkLinkAgent",
        capabilities=[],
        started_at="now",
        last_seen="now",
        alive=True,
        a2a_ready=True,
        a2a_port=12345,
    )
    supervisor._agents[record.agent_id] = record  # type: ignore[attr-defined]
    runner._alive[record.agent_id] = True
    app.state.v2_supervisor = supervisor
    forwarded = {}

    async def fake_drive(_request, _did, _payload):
        forwarded.update(_payload)
        return 200, {
            "result": {"response": "link-ok"},
        }, record, {"nth_receipt_id": "receipt-link-1"}

    monkeypatch.setattr(v2_api, "_drive_supervised_agent_ask", fake_drive)
    client = TestClient(app)
    auth = {"Authorization": f"Bearer {app.state.nth_console_token}"}
    prompt = "secret prompt must stay outside the link job"
    unauthenticated = client.post(
        f"/api/v2/agents/{record.did}/link",
        json={"prompt": prompt, "idempotency_key": "unauthenticated"},
    )
    assert unauthenticated.status_code == 401
    submitted = client.post(
        f"/api/v2/agents/{record.did}/link",
        headers=auth,
        json={"prompt": prompt, "idempotency_key": "message-1"},
    )
    assert submitted.status_code == 202, submitted.text
    job_id = submitted.json()["job_id"]

    deadline = time.monotonic() + 2.0
    status = None
    while time.monotonic() < deadline:
        response = client.get(
            f"/api/v2/agents/{record.did}/link/{job_id}",
            headers=auth,
        )
        assert response.status_code == 200, response.text
        status = response.json()
        if status["state"] == "completed":
            break
        time.sleep(0.01)

    assert status is not None
    assert status["state"] == "completed"
    assert status["response"] == "link-ok"
    assert status["receipt_id"] == "receipt-link-1"
    assert forwarded["agent_link_job_id"] == job_id
    stored = next((tmp_path / "agent_links" / "jobs").glob("*.json"))
    assert prompt not in stored.read_text(encoding="utf-8")
    json.loads(stored.read_text(encoding="utf-8"))

    missing_key = client.post(
        f"/api/v2/agents/{record.did}/link",
        headers=auth,
        json={"prompt": "no key"},
    )
    assert missing_key.status_code == 400

    conflicting = client.post(
        f"/api/v2/agents/{record.did}/link",
        headers=auth,
        json={"prompt": "different prompt", "idempotency_key": "message-1"},
    )
    assert conflicting.status_code == 409, conflicting.text


def test_app_lifespan_closes_agent_link_and_supervisor(tmp_path):
    app = create_app(workspace=tmp_path, require_console_auth=False)
    calls = []

    class _Manager:
        def close(self):
            calls.append("link")

    class _Supervisor:
        def shutdown(self):
            calls.append("supervisor")

    app.state.agent_link_manager = _Manager()
    app.state.v2_supervisor = _Supervisor()
    with TestClient(app):
        pass
    assert calls == ["link", "supervisor"]


def test_agent_link_reconcile_requires_signed_binding(tmp_path):
    from nth_dao.execution_receipt import ReceiptStore
    from nth_dao.identity import AgentIdentity

    identity = AgentIdentity.generate(label="reconcile-agent")
    prompt = "recover this delivery"
    response = "recovered answer"
    first_store = AgentLinkStore(tmp_path)
    job = first_store.create(
        agent_id="reconcile-agent",
        agent_did=identity.as_did(),
        idempotency_key="reconcile-key",
        request_hash="request-context-hash",
        prompt_sha256=hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
    )
    # A fresh manager models a hub restart and converts the accepted record
    # into delivery_unknown before the operator attempts reconciliation.
    manager = AgentLinkManager(AgentLinkStore(tmp_path))
    app = create_app(workspace=tmp_path, require_console_auth=False)
    app.state.agent_link_manager = manager
    auth = {"Authorization": f"Bearer {app.state.nth_console_token}"}
    receipt = _signed_agent_link_receipt(identity, job.job_id, prompt, response)

    with TestClient(app) as client:
        bad = client.post(
            f"/api/v2/agents/{identity.as_did()}/link/{job.job_id}/reconcile",
            headers=auth,
            json={"receipt": receipt, "response": "tampered answer"},
        )
        assert bad.status_code == 422
        assert manager.get(job.job_id).state == "delivery_unknown"

        good = client.post(
            f"/api/v2/agents/{identity.as_did()}/link/{job.job_id}/reconcile",
            headers=auth,
            json={"receipt": receipt, "response": f"  {response}\n"},
        )
        assert good.status_code == 200, good.text
        assert good.json()["state"] == "completed"
        assert good.json()["receipt_id"] == receipt["receipt_id"]
        assert good.json()["response"] == response

        conflicting_receipt = _signed_agent_link_receipt(
            identity, job.job_id, prompt, "another answer",
        )
        conflict = client.post(
            f"/api/v2/agents/{identity.as_did()}/link/{job.job_id}/reconcile",
            headers=auth,
            json={"receipt": conflicting_receipt, "response": "another answer"},
        )
        assert conflict.status_code == 409
        assert AgentLinkStore(tmp_path).get(job.job_id).receipt_id == receipt["receipt_id"]

    persisted = ReceiptStore(tmp_path).load(receipt["receipt_id"])
    assert persisted is not None
    assert AgentLinkStore(tmp_path).get(job.job_id).state == "completed"
