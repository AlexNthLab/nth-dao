import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
import urllib.error
import urllib.request

import uvicorn
from fastapi.testclient import TestClient

from nth_dao.commerce.outbox import (
    CommerceAck,
    CommerceEnvelopeRejected,
    sign_envelope,
    verify_ack,
)
from nth_dao.commerce.order import OrderStore
from nth_dao.commerce.trade import TradeStore
from nth_dao.commerce.outbox import CommerceOutbox
from nth_dao.execution_receipt import now_ms
from nth_dao.identity import AgentIdentity
from nth_dao.web import create_app
from nth_dao.web import commerce_api
from nth_dao.web.rate_limit import RateLimiter
from nth_dao.util.io import atomic_write_json


def test_queued_action_attempts_delivery_after_durable_enqueue(tmp_path, monkeypatch):
    record = SimpleNamespace()
    state = SimpleNamespace(
        workspace=tmp_path,
        commerce_outbox=SimpleNamespace(
            claim=lambda message_id: record,
            get=lambda message_id: record,
        ),
    )
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(nth=state)))
    monkeypatch.setattr(
        commerce_api, "_queue_current",
        lambda *_args: {
            "message_id": "sha256:message", "status": "pending",
            "target_url": "https://peer.example",
        },
    )
    monkeypatch.setattr(
        commerce_api, "_dispatch_record",
        lambda got_state, got_record: {
            "message_id": "sha256:message", "status": "acknowledged",
        } if (got_state is state and got_record is record) else {},
    )

    result = commerce_api._queue_committed_response(
        request, "order-1", "did:key:zPeer", "https://peer.example",
    )

    assert result == {
        "message_id": "sha256:message", "status": "acknowledged",
        "target_url": "https://peer.example",
    }


def test_acknowledged_action_is_not_dispatched_twice(tmp_path, monkeypatch):
    state = SimpleNamespace(
        workspace=tmp_path,
        commerce_outbox=SimpleNamespace(get=lambda message_id: None),
    )
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(nth=state)))
    queued = {
        "message_id": "sha256:message", "status": "acknowledged",
        "target_url": "https://peer.example",
    }
    monkeypatch.setattr(commerce_api, "_queue_current", lambda *_args: queued)
    monkeypatch.setattr(
        commerce_api, "_dispatch_record",
        lambda *_args: (_ for _ in ()).throw(AssertionError("duplicate delivery")),
    )

    assert commerce_api._queue_committed_response(
        request, "order-1", "did:key:zPeer", "https://peer.example",
    ) == queued


def test_queued_action_reports_pending_when_reconciler_owns_delivery(
    tmp_path,
    monkeypatch,
):
    inflight = SimpleNamespace(status="inflight")
    state = SimpleNamespace(
        workspace=tmp_path,
        commerce_outbox=SimpleNamespace(
            claim=lambda _message_id: None,
            get=lambda _message_id: inflight,
        ),
    )
    request = SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(nth=state))
    )
    queued = {
        "message_id": "sha256:message",
        "status": "pending",
        "target_url": "https://peer.example",
    }
    monkeypatch.setattr(commerce_api, "_queue_current", lambda *_args: queued)

    assert commerce_api._queue_committed_response(
        request,
        "order-1",
        "did:key:zPeer",
        "https://peer.example",
    ) == {
        **queued,
        "error": "delivery is already in progress",
    }


def _free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _bind_peer(workspace, target, peer_app):
    peer = peer_app.state.nth.node_identity
    atomic_write_json(workspace / "federation" / "peers.json", [target])
    atomic_write_json(workspace / "federation" / "peers_meta.json", {
        target: {
            "did": peer.as_did(),
            "pubkey_hex": peer.pubkey_hex,
            "peer_url": target,
            "identity_url": f"{target}/.well-known/nth-dao/identity.json",
            "card_kind": "nth-dao-identity-card-v1",
            "federation_protocol": "nth-dao-federation-v1",
        },
    })


class _Server:
    def __init__(self, app, port):
        self.server = uvicorn.Server(uvicorn.Config(
            app, host="127.0.0.1", port=port, log_level="error",
        ))
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self):
        self.thread.start()
        for _ in range(200):
            if self.server.started:
                return self
            time.sleep(0.025)
        raise RuntimeError("test server did not start")

    def __exit__(self, *_args):
        self.server.should_exit = True
        self.thread.join(timeout=5)


class _ProcessServer:
    """Run one NTH DAO node in an independent Python process."""

    _BOOT = (
        "import sys, uvicorn;"
        "from pathlib import Path;"
        "from nth_dao.web import create_app;"
        "app=create_app(Path(sys.argv[1]), require_console_auth=False);"
        "uvicorn.run(app, host='127.0.0.1', port=int(sys.argv[2]), "
        "log_level='error', access_log=False)"
    )

    def __init__(self, workspace: Path, port: int) -> None:
        self.workspace = workspace
        self.port = port
        self.url = f"http://127.0.0.1:{port}"
        self.process = None
        self._log_handle = None
        self.log_path = workspace.parent / f"{workspace.name}-server.log"

    def start(self) -> None:
        if self.process is not None:
            raise RuntimeError("process server already started")
        env = {
            **os.environ,
            "NTH_LAN_PUBLISH": "0",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": str(Path(__file__).resolve().parents[1]),
        }
        self._log_handle = self.log_path.open("ab")
        creationflags = (
            subprocess.CREATE_NO_WINDOW
            if sys.platform == "win32"
            else 0
        )
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                self._BOOT,
                str(self.workspace),
                str(self.port),
            ],
            cwd=str(Path(__file__).resolve().parents[1]),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=self._log_handle,
            stderr=subprocess.STDOUT,
            creationflags=creationflags,
        )
        for _ in range(300):
            if self.process.poll() is not None:
                detail = self.log_path.read_text(
                    encoding="utf-8",
                    errors="replace",
                )
                raise RuntimeError(
                    f"node process exited {self.process.returncode}: {detail[-2000:]}"
                )
            try:
                _http_json(
                    f"{self.url}/.well-known/nth-dao/identity.json",
                )
                return
            except (OSError, urllib.error.URLError):
                time.sleep(0.025)
        raise RuntimeError(f"node process did not start on {self.url}")

    def stop(self) -> None:
        process = self.process
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        self.process = None
        if self._log_handle is not None:
            self._log_handle.close()
            self._log_handle = None

    def restart(self) -> None:
        self.stop()
        self.start()


def _bind_process_peer(workspace: Path, target_url: str, card: dict) -> None:
    atomic_write_json(workspace / "federation" / "peers.json", [target_url])
    atomic_write_json(workspace / "federation" / "peers_meta.json", {
        target_url: {
            "did": card["did"],
            "pubkey_hex": card["pubkey_hex"],
            "peer_url": target_url,
            "identity_url": (
                f"{target_url}/.well-known/nth-dao/identity.json"
            ),
            "card_kind": "nth-dao-identity-card-v1",
            "federation_protocol": "nth-dao-federation-v1",
        },
    })


def _http_json(url, *, payload=None):
    data = None
    headers = {}
    method = "GET"
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
        method = "POST"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def _await_process_delivery(
    queued,
    *,
    source_url,
    target_url,
    order_id,
    expected_state,
):
    """Require both remote state and the sender's durable ACK to converge."""

    assert queued["status"] in {"acknowledged", "pending"}
    deadline = time.monotonic() + 10.0
    last_state = ""
    pending_message_ids = set()
    while time.monotonic() < deadline:
        last_state = _http_json(
            f"{target_url}/api/v2/commerce/orders/{order_id}",
        )["state"]
        pending_message_ids = {
            item["envelope"]["message_id"]
            for item in _http_json(f"{source_url}/api/v2/commerce/outbox")
        }
        if (
            last_state == expected_state
            and queued["message_id"] not in pending_message_ids
        ):
            return
        _http_json(
            f"{source_url}/api/v2/commerce/outbox/dispatch",
            payload={},
        )
        time.sleep(0.05)
    raise AssertionError(
        f"commerce delivery did not durably converge to {expected_state}; "
        f"last state was {last_state}, pending={sorted(pending_message_ids)}"
    )


def test_dispatch_result_retries_transient_persistence_failure():
    acknowledged = SimpleNamespace(status="acknowledged", last_error="")

    class FlakyOutbox:
        def __init__(self):
            self.calls = 0

        def record_attempt(self, *_args, **_kwargs):
            self.calls += 1
            if self.calls == 1:
                raise OSError("simulated transient atomic-write failure")
            return acknowledged

        def get(self, _message_id):
            return SimpleNamespace(
                status="inflight",
                lease_id="active-lease",
                last_error="",
            )

    outbox = FlakyOutbox()
    stored, error = commerce_api._record_dispatch_attempt(
        SimpleNamespace(commerce_outbox=outbox),
        "sha256:" + "a" * 64,
        "active-lease",
        acknowledged_at_ms=1_900_000_000_000,
    )

    assert stored is True
    assert error == ""
    assert outbox.calls == 2


def test_dispatch_result_does_not_repeat_commit_unknown_acknowledgement():
    acknowledged = SimpleNamespace(
        status="acknowledged",
        lease_id="",
        last_error="",
    )

    class CommitUnknownOutbox:
        def __init__(self):
            self.calls = 0

        def record_attempt(self, *_args, **_kwargs):
            self.calls += 1
            raise OSError("response lost after durable commit")

        def get(self, _message_id):
            return acknowledged

    outbox = CommitUnknownOutbox()
    stored, error = commerce_api._record_dispatch_attempt(
        SimpleNamespace(commerce_outbox=outbox),
        "sha256:" + "b" * 64,
        "active-lease",
        acknowledged_at_ms=1_900_000_000_000,
    )

    assert stored is True
    assert error == ""
    assert outbox.calls == 1


def test_dispatch_result_does_not_double_count_commit_unknown_failure():
    pending = SimpleNamespace(
        status="pending",
        lease_id="",
        last_error="peer-network-error",
    )

    class CommitUnknownOutbox:
        def __init__(self):
            self.calls = 0

        def record_attempt(self, *_args, **_kwargs):
            self.calls += 1
            raise OSError("response lost after durable commit")

        def get(self, _message_id):
            return pending

    outbox = CommitUnknownOutbox()
    stored, error = commerce_api._record_dispatch_attempt(
        SimpleNamespace(commerce_outbox=outbox),
        "sha256:" + "c" * 64,
        "active-lease",
        error="peer-network-error",
    )

    assert stored is False
    assert error == "peer-network-error"
    assert outbox.calls == 1


def test_dispatch_result_commit_unknown_keeps_real_attempt_count_one(
    tmp_path,
    monkeypatch,
):
    source = AgentIdentity.generate()
    target = AgentIdentity.generate()
    envelope = sign_envelope(
        source,
        target_did=target.as_did(),
        payload={"order": {"id": "commit-unknown"}},
        created_at_ms=1_900_000_000_000,
    )
    outbox = CommerceOutbox(tmp_path)
    outbox.enqueue(envelope, target_url="https://seller.example")
    claimed = outbox.claim(
        envelope.message_id,
        now_ms_override=1_900_000_001_000,
    )
    assert claimed is not None
    real_record_attempt = outbox.record_attempt

    def commit_then_lose_response(*args, **kwargs):
        real_record_attempt(*args, **kwargs)
        raise OSError("response lost after durable commit")

    monkeypatch.setattr(outbox, "record_attempt", commit_then_lose_response)
    stored, error = commerce_api._record_dispatch_attempt(
        SimpleNamespace(commerce_outbox=outbox),
        envelope.message_id,
        claimed.lease_id,
        error="peer-network-error",
    )
    current = outbox.get(envelope.message_id)

    assert stored is False
    assert error == "peer-network-error"
    assert current is not None
    assert current.status == "pending"
    assert current.attempts == 1


def test_dispatch_result_does_not_retry_programming_errors():
    class BrokenOutbox:
        def record_attempt(self, *_args, **_kwargs):
            raise RuntimeError("programming contract broken")

    with pytest.raises(RuntimeError, match="programming contract broken"):
        commerce_api._record_dispatch_attempt(
            SimpleNamespace(commerce_outbox=BrokenOutbox()),
            "sha256:" + "d" * 64,
            "active-lease",
            acknowledged_at_ms=1_900_000_000_000,
        )


def _sync(source_app, target_client, order_id):
    source = source_app.state.nth
    target = target_client.app.state.nth
    order = source.commerce_orders.get(order_id)
    assert order is not None
    envelope = sign_envelope(
        source.node_identity,
        target_did=target.node_identity.as_did(),
        payload={
            "order": order.to_dict(),
            "trade_events": source.commerce_trades.get_events(order_id),
        },
        created_at_ms=now_ms(),
    )
    response = target_client.post(
        "/api/v2/commerce/federation/sync",
        json={"envelope": envelope.to_dict()},
    )
    assert response.status_code == 200, response.text
    assert response.json()["message_id"] == envelope.message_id
    ack = CommerceAck.from_dict(response.json()["ack"])
    assert verify_ack(ack) == (True, "ok")
    assert ack.receiver_did == target.node_identity.as_did()
    return response.json()


def _executing_order_pair(tmp_path):
    seller_app = create_app(tmp_path / "seller", require_console_auth=False)
    buyer_app = create_app(tmp_path / "buyer", require_console_auth=False)
    seller = TestClient(seller_app)
    buyer = TestClient(buyer_app)
    published = seller.post("/api/v2/commerce/listings", json={
        "listing_id": "routing-review", "title": "Routing review", "price_value": "2",
    }).json()
    intent = buyer.post("/api/v2/commerce/intents", json={
        "listing": published["listing"], "purpose": "exercise committed delivery semantics",
    }).json()["intent"]
    cart = seller.post("/api/v2/commerce/carts", json={
        "listing_digest": published["digest"], "intent": intent,
    }).json()["cart"]
    order = buyer.post("/api/v2/commerce/orders", json={
        "listing": published["listing"], "intent": intent, "cart": cart,
    }).json()["order"]
    _sync(buyer_app, seller, order["order_id"])
    return seller_app, buyer_app, seller, buyer, order["order_id"]


def test_delivery_rejects_bad_route_before_state_transition(tmp_path):
    seller_app, _buyer_app, seller, _buyer, order_id = _executing_order_pair(tmp_path)
    assert seller.get(f"/api/v2/commerce/orders/{order_id}").json()["state"] == "executing"

    response = seller.post(
        f"/api/v2/commerce/orders/{order_id}/delivery",
        json={
            "delivery": {"artifact_digest": "sha256:" + "d" * 64},
            "target_url": "https://not-configured.example",
        },
    )

    assert response.status_code == 400
    assert seller.get(f"/api/v2/commerce/orders/{order_id}").json()["state"] == "executing"
    assert len(seller_app.state.nth.commerce_trades.get_events(order_id)) == 1


def test_committed_delivery_reports_recoverable_queue_failure(tmp_path, monkeypatch):
    seller_app, buyer_app, seller, _buyer, order_id = _executing_order_pair(tmp_path)
    state = seller_app.state.nth
    target = "https://buyer.example"
    _bind_peer(state.workspace, target, buyer_app)

    def fail_enqueue(*_args, **_kwargs):
        raise CommerceEnvelopeRejected("simulated outbox failure")

    monkeypatch.setattr(state.commerce_outbox, "enqueue", fail_enqueue)
    response = seller.post(
        f"/api/v2/commerce/orders/{order_id}/delivery",
        json={
            "delivery": {"artifact_digest": "sha256:" + "e" * 64},
            "target_url": target,
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["order"]["state"] == "delivered"
    assert response.json()["queued"]["status"] == "pending"
    assert response.json()["queued"]["recoverable"] is True
    assert response.json()["queued"]["error"] == "delivery-persistence-error"


def test_committed_delivery_reports_recoverable_claim_failure(tmp_path, monkeypatch):
    seller_app, buyer_app, seller, _buyer, order_id = _executing_order_pair(tmp_path)
    state = seller_app.state.nth
    target = "https://buyer.example"
    _bind_peer(state.workspace, target, buyer_app)

    def fail_claim(*_args, **_kwargs):
        raise OSError("simulated claim lock failure")

    monkeypatch.setattr(state.commerce_outbox, "claim", fail_claim)
    response = seller.post(
        f"/api/v2/commerce/orders/{order_id}/delivery",
        json={
            "delivery": {"artifact_digest": "sha256:" + "c" * 64},
            "target_url": target,
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["order"]["state"] == "delivered"
    assert response.json()["queued"]["status"] == "pending"
    assert response.json()["queued"]["recoverable"] is True
    assert response.json()["queued"]["error"] == "delivery-persistence-error"
    assert state.commerce_outbox.pending()


def test_configured_peer_cannot_receive_another_did_order(tmp_path):
    seller_app, _buyer_app, seller, _buyer, order_id = _executing_order_pair(tmp_path)
    unrelated_app = create_app(tmp_path / "unrelated", require_console_auth=False)
    target = "https://unrelated.example"
    _bind_peer(seller_app.state.nth.workspace, target, unrelated_app)

    response = seller.post(
        f"/api/v2/commerce/orders/{order_id}/delivery",
        json={
            "delivery": {"artifact_digest": "sha256:" + "f" * 64},
            "target_url": target,
        },
    )

    assert response.status_code == 400
    assert "identity-bound" in response.text
    assert seller.get(f"/api/v2/commerce/orders/{order_id}").json()["state"] == "executing"


def test_sync_replay_returns_one_durable_signed_ack(tmp_path):
    seller_app, buyer_app, seller, _buyer, order_id = _executing_order_pair(tmp_path)
    source = buyer_app.state.nth
    target = seller_app.state.nth
    envelope = sign_envelope(
        source.node_identity,
        target_did=target.node_identity.as_did(),
        payload={
            "order": source.commerce_orders.get(order_id).to_dict(),
            "trade_events": source.commerce_trades.get_events(order_id),
        },
        created_at_ms=now_ms(),
    )
    first = seller.post(
        "/api/v2/commerce/federation/sync",
        json={"envelope": envelope.to_dict()},
    )
    second = seller.post(
        "/api/v2/commerce/federation/sync",
        json={"envelope": envelope.to_dict()},
    )

    assert first.status_code == second.status_code == 200
    assert first.json()["replay"] is second.json()["replay"] is True
    assert first.json()["ack"] == second.json()["ack"]
    assert len(list(target.commerce_inbox.root.glob("*.json"))) == 1

    stale = sign_envelope(
        source.node_identity,
        target_did=target.node_identity.as_did(),
        payload=envelope.payload,
        created_at_ms=1,
    )
    rejected = seller.post(
        "/api/v2/commerce/federation/sync",
        json={"envelope": stale.to_dict()},
    )
    assert rejected.status_code == 400
    assert "replay window" in rejected.text


def test_sync_trade_failure_does_not_publish_partial_order(tmp_path, monkeypatch):
    seller_app = create_app(tmp_path / "seller", require_console_auth=False)
    buyer_app = create_app(tmp_path / "buyer", require_console_auth=False)
    seller = TestClient(seller_app)
    buyer = TestClient(buyer_app)
    published = seller.post("/api/v2/commerce/listings", json={
        "listing_id": "atomic-sync", "title": "Atomic sync", "price_value": "1",
    }).json()
    intent = buyer.post("/api/v2/commerce/intents", json={
        "listing": published["listing"], "purpose": "fault injection",
    }).json()["intent"]
    cart = seller.post("/api/v2/commerce/carts", json={
        "listing_digest": published["digest"], "intent": intent,
    }).json()["cart"]
    order = buyer.post("/api/v2/commerce/orders", json={
        "listing": published["listing"], "intent": intent, "cart": cart,
    }).json()["order"]
    order_id = order["order_id"]
    source = buyer_app.state.nth
    target = seller_app.state.nth
    envelope = sign_envelope(
        source.node_identity,
        target_did=target.node_identity.as_did(),
        payload={
            "order": source.commerce_orders.get(order_id).to_dict(),
            "trade_events": source.commerce_trades.get_events(order_id),
        },
        created_at_ms=now_ms(),
    )

    monkeypatch.setattr(
        target.commerce_trades,
        "import_verified_events",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("fault injection before trade commit")
        ),
    )
    response = seller.post(
        "/api/v2/commerce/federation/sync",
        json={"envelope": envelope.to_dict()},
    )

    assert response.status_code == 409
    assert target.commerce_orders.get(order_id) is None
    assert target.commerce_trades.get_events(order_id) is None
    assert list(target.commerce_inbox.root.glob("*.json")) == []


def test_sync_order_failure_leaves_hidden_trade_and_retry_completes(
    tmp_path,
    monkeypatch,
):
    seller_app = create_app(tmp_path / "seller", require_console_auth=False)
    buyer_app = create_app(tmp_path / "buyer", require_console_auth=False)
    seller = TestClient(seller_app)
    buyer = TestClient(buyer_app)
    published = seller.post("/api/v2/commerce/listings", json={
        "listing_id": "retry-sync", "title": "Retry sync", "price_value": "1",
    }).json()
    intent = buyer.post("/api/v2/commerce/intents", json={
        "listing": published["listing"], "purpose": "order fault injection",
    }).json()["intent"]
    cart = seller.post("/api/v2/commerce/carts", json={
        "listing_digest": published["digest"], "intent": intent,
    }).json()["cart"]
    order = buyer.post("/api/v2/commerce/orders", json={
        "listing": published["listing"], "intent": intent, "cart": cart,
    }).json()["order"]
    order_id = order["order_id"]
    source = buyer_app.state.nth
    target = seller_app.state.nth
    envelope = sign_envelope(
        source.node_identity,
        target_did=target.node_identity.as_did(),
        payload={
            "order": source.commerce_orders.get(order_id).to_dict(),
            "trade_events": source.commerce_trades.get_events(order_id),
        },
        created_at_ms=now_ms(),
    )
    original_import = target.commerce_orders.import_verified
    monkeypatch.setattr(
        target.commerce_orders,
        "import_verified",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("fault injection before visible order commit")
        ),
    )
    failed = seller.post(
        "/api/v2/commerce/federation/sync",
        json={"envelope": envelope.to_dict()},
    )

    assert failed.status_code == 409
    assert target.commerce_orders.get(order_id) is None
    assert target.commerce_trades.get_events(order_id)
    assert target.commerce_provisional._path(order_id).exists()
    assert seller.get(f"/api/v2/commerce/orders/{order_id}").status_code == 404

    monkeypatch.setattr(target.commerce_orders, "import_verified", original_import)
    retried = seller.post(
        "/api/v2/commerce/federation/sync",
        json={"envelope": envelope.to_dict()},
    )
    assert retried.status_code == 200, retried.text
    assert target.commerce_orders.get(order_id) is not None
    assert not target.commerce_provisional._path(order_id).exists()
    assert retried.json()["state"] == "executing"


def test_dispatch_rejects_unsigned_message_id_echo(tmp_path, monkeypatch):
    seller_app, buyer_app, seller, _buyer, order_id = _executing_order_pair(tmp_path)
    target = "https://buyer.example"
    _bind_peer(seller_app.state.nth.workspace, target, buyer_app)
    queued = seller.post(
        f"/api/v2/commerce/orders/{order_id}/queue",
        json={
            "target_did": buyer_app.state.nth.node_identity.as_did(),
            "target_url": target,
        },
    ).json()

    class UnsignedEcho:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit):
            return json.dumps({"message_id": queued["message_id"]}).encode()

    monkeypatch.setattr(
        commerce_api._PEER_OPENER, "open", lambda *_args, **_kwargs: UnsignedEcho(),
    )
    result = seller.post("/api/v2/commerce/outbox/dispatch")

    assert result.status_code == 200
    assert result.json()[0]["status"] == "blocked"
    assert result.json()[0]["error"] == "peer-response-invalid"
    assert seller_app.state.nth.commerce_outbox.pending() == []
    assert seller_app.state.nth.commerce_outbox.blocked()
    visible = seller.get("/api/v2/commerce/outbox")
    assert visible.status_code == 200
    assert visible.json()[0]["status"] == "blocked"
    assert visible.json()[0]["envelope"]["message_id"] == queued["message_id"]


def test_http_retry_classification_blocks_4xx_but_retries_5xx(tmp_path, monkeypatch):
    seller_app, buyer_app, seller, _buyer, order_id = _executing_order_pair(tmp_path)
    target = "https://buyer.example"
    _bind_peer(seller_app.state.nth.workspace, target, buyer_app)
    queued = seller.post(
        f"/api/v2/commerce/orders/{order_id}/queue",
        json={
            "target_did": buyer_app.state.nth.node_identity.as_did(),
            "target_url": target,
        },
    ).json()

    def http_error(code):
        return urllib.error.HTTPError(target, code, "simulated", {}, None)

    monkeypatch.setattr(
        commerce_api._PEER_OPENER,
        "open",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(http_error(503)),
    )
    retryable = seller.post("/api/v2/commerce/outbox/dispatch")
    assert retryable.json()[0]["status"] == "pending"
    assert retryable.json()[0]["error"] == "peer-http-retryable"

    monkeypatch.setattr(
        commerce_api._PEER_OPENER,
        "open",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(http_error(401)),
    )
    permanent = seller.post("/api/v2/commerce/outbox/dispatch")
    assert permanent.json()[0]["status"] == "blocked"
    assert permanent.json()[0]["error"] == "peer-http-rejected"
    assert seller_app.state.nth.commerce_outbox.get(queued["message_id"]).status == "blocked"


def test_queue_retargets_pending_message_after_same_did_peer_migration(tmp_path):
    seller_app, buyer_app, seller, _buyer, order_id = _executing_order_pair(tmp_path)
    old_target = "https://buyer-old.example"
    new_target = "https://buyer-new.example"
    buyer_did = buyer_app.state.nth.node_identity.as_did()
    _bind_peer(seller_app.state.nth.workspace, old_target, buyer_app)
    first = seller.post(
        f"/api/v2/commerce/orders/{order_id}/queue",
        json={"target_did": buyer_did, "target_url": old_target},
    )
    assert first.status_code == 200

    _bind_peer(seller_app.state.nth.workspace, new_target, buyer_app)
    moved = seller.post(
        f"/api/v2/commerce/orders/{order_id}/queue",
        json={"target_did": buyer_did, "target_url": new_target},
    )
    assert moved.status_code == 200, moved.text
    assert moved.json()["message_id"] == first.json()["message_id"]
    record = seller_app.state.nth.commerce_outbox.get(moved.json()["message_id"])
    assert record.target_url == new_target
    assert record.route_history[-1]["previous_url"] == old_target
    assert record.route_history[-1]["target_did"] == buyer_did


def test_manual_dispatch_claims_each_record_immediately_before_delivery(
    tmp_path, monkeypatch,
):
    app = create_app(tmp_path, require_console_auth=False)
    state = app.state.nth
    target = AgentIdentity.generate()
    envelopes = [
        sign_envelope(
            state.node_identity,
            target_did=target.as_did(),
            payload={"order": {"id": f"manual-batch-{index}"}},
            created_at_ms=1_900_000_000_000 + index,
        )
        for index in range(2)
    ]
    for envelope in envelopes:
        state.commerce_outbox.enqueue(
            envelope,
            target_url="https://seller.example",
        )
    message_ids = {envelope.message_id for envelope in envelopes}
    observed_other_states = []

    def acknowledge(_state, record):
        current_id = record.envelope["message_id"]
        other_id = (message_ids - {current_id}).pop()
        observed_other_states.append(state.commerce_outbox.get(other_id).status)
        stored = state.commerce_outbox.record_attempt(
            current_id,
            acknowledged_at_ms=1_900_000_002_000,
            lease_id=record.lease_id,
        )
        return {"message_id": current_id, "status": stored.status}

    monkeypatch.setattr(commerce_api, "_dispatch_record", acknowledge)
    response = TestClient(app).post("/api/v2/commerce/outbox/dispatch")

    assert response.status_code == 200
    assert len(response.json()) == 2
    assert observed_other_states[0] == "pending"


def test_stale_dispatch_lease_cannot_overwrite_new_owner(tmp_path):
    current = SimpleNamespace(status="inflight")

    class LeaseTakenOutbox:
        def record_attempt(self, *_args, **_kwargs):
            raise CommerceEnvelopeRejected("outbox lease does not match active delivery")

        def get(self, _message_id):
            return current

    acknowledged, error = commerce_api._record_dispatch_attempt(
        SimpleNamespace(commerce_outbox=LeaseTakenOutbox()),
        "sha256:" + "1" * 64,
        "stale-lease",
        acknowledged_at_ms=1_900_000_000_000,
    )

    assert acknowledged is False
    assert error == "delivery-persistence-error"


def test_reconciler_delivers_when_offline_peer_starts_later(tmp_path):
    seller_app, buyer_app, seller, _buyer, order_id = _executing_order_pair(tmp_path)
    buyer_port = _free_port()
    target = f"http://127.0.0.1:{buyer_port}"
    _bind_peer(seller_app.state.nth.workspace, target, buyer_app)

    committed = seller.post(
        f"/api/v2/commerce/orders/{order_id}/delivery",
        json={
            "delivery": {"artifact_digest": "sha256:" + "9" * 64},
            "target_url": target,
        },
    )
    assert committed.status_code == 200, committed.text
    message_id = committed.json()["queued"]["message_id"]
    assert committed.json()["queued"]["status"] == "pending"
    assert seller_app.state.nth.commerce_outbox.get(message_id).attempts == 1

    with _Server(buyer_app, buyer_port), _Server(seller_app, _free_port()):
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            record = seller_app.state.nth.commerce_outbox.get(message_id)
            if record is not None and record.status == "acknowledged":
                break
            time.sleep(0.05)
        else:
            raise AssertionError("reconciler did not deliver after the peer started")

    record = seller_app.state.nth.commerce_outbox.get(message_id)
    assert record.status == "acknowledged"
    assert record.attempts == 2
    assert buyer_app.state.nth.commerce_trades.get_events(order_id)[-1]["new_state"] == "delivered"


def test_two_node_no_money_digital_service_loop(tmp_path):
    seller_app = create_app(tmp_path / "seller", require_console_auth=False)
    buyer_app = create_app(tmp_path / "buyer", require_console_auth=False)
    seller = TestClient(seller_app)
    buyer = TestClient(buyer_app)

    published = seller.post("/api/v2/commerce/listings", json={
        "listing_id": "review-v1",
        "title": "Adversarial code review",
        "description": "Deliver a signed findings report",
        "price_value": "7.5",
        "details": {"output": "markdown"},
        "capabilities": ["code_review"],
    })
    assert published.status_code == 200, published.text
    listing = published.json()["listing"]
    digest = published.json()["digest"]
    assert listing["price_currency"] == "NTH-TEST"
    assert listing["settlement_methods"] == ["manual:nth_test"]

    intent_response = buyer.post("/api/v2/commerce/intents", json={
        "listing": listing,
        "purpose": "Purchase one review without real money",
    })
    assert intent_response.status_code == 200, intent_response.text
    intent = intent_response.json()["intent"]

    cart_response = seller.post("/api/v2/commerce/carts", json={
        "listing_digest": digest,
        "intent": intent,
    })
    assert cart_response.status_code == 200, cart_response.text
    cart = cart_response.json()["cart"]
    cart_replay = seller.post("/api/v2/commerce/carts", json={
        "listing_digest": digest,
        "intent": intent,
    })
    assert cart_replay.status_code == 200
    assert cart_replay.json()["cart"] == cart

    checkout = buyer.post("/api/v2/commerce/orders", json={
        "listing": listing,
        "intent": intent,
        "cart": cart,
    })
    assert checkout.status_code == 200, checkout.text
    order_id = checkout.json()["order"]["order_id"]
    assert checkout.json()["order"]["state"] == "executing"
    checkout_replay = buyer.post("/api/v2/commerce/orders", json={
        "listing": listing,
        "intent": intent,
        "cart": cart,
    })
    assert checkout_replay.status_code == 200, checkout_replay.text
    assert checkout_replay.json()["order"]["order_id"] == order_id
    assert len(buyer_app.state.nth.commerce_orders.list_verified()) == 1

    assert _sync(buyer_app, seller, order_id)["state"] == "executing"
    delivered = seller.post(
        f"/api/v2/commerce/orders/{order_id}/delivery",
        json={"delivery": {"artifact_digest": "sha256:" + "d" * 64}},
    )
    assert delivered.status_code == 200, delivered.text
    assert delivered.json()["order"]["state"] == "delivered"

    assert _sync(seller_app, buyer, order_id)["state"] == "delivered"
    verified = buyer.post(
        f"/api/v2/commerce/orders/{order_id}/verify",
        json={"verdict": "pass", "result": {"checks": ["report-present"]}},
    )
    assert verified.status_code == 200, verified.text
    assert verified.json()["order"]["state"] == "verified"

    assert _sync(buyer_app, seller, order_id)["state"] == "verified"
    settled = buyer.post(
        f"/api/v2/commerce/orders/{order_id}/settle", json={},
    )
    assert settled.status_code == 200, settled.text
    assert settled.json()["order"]["state"] == "settled"
    duplicate_settlement = buyer.post(
        f"/api/v2/commerce/orders/{order_id}/settle", json={}
    )
    assert duplicate_settlement.status_code == 409
    assert "settlement-bad-state" in duplicate_settlement.text
    assert _sync(buyer_app, seller, order_id)["state"] == "settled"

    buyer_view = buyer.get(f"/api/v2/commerce/orders/{order_id}").json()
    seller_view = seller.get(f"/api/v2/commerce/orders/{order_id}").json()
    assert buyer_view["state"] == seller_view["state"] == "settled"
    assert buyer_view["events"] == seller_view["events"]
    assert buyer_view["settlement_method"] == "manual:nth_test"
    assert buyer_view["currency"] == "NTH-TEST"


def test_sync_rejects_wrong_target_tampering_and_real_money_listing(tmp_path):
    a_app = create_app(tmp_path / "a", require_console_auth=False)
    b_app = create_app(tmp_path / "b", require_console_auth=False)
    b = TestClient(b_app)
    envelope = sign_envelope(
        a_app.state.nth.node_identity,
        target_did=a_app.state.nth.node_identity.as_did(),
        payload={"order": {}, "trade_events": []},
        created_at_ms=now_ms(),
    )
    wrong_target = b.post(
        "/api/v2/commerce/federation/sync",
        json={"envelope": envelope.to_dict()},
    )
    assert wrong_target.status_code == 403

    tampered = envelope.to_dict()
    tampered["payload"] = {"order": {"forged": True}, "trade_events": []}
    bad_sig = b.post(
        "/api/v2/commerce/federation/sync", json={"envelope": tampered},
    )
    assert bad_sig.status_code == 400

    # The public API does not accept caller-selected currency or rail at all.
    published = b.post("/api/v2/commerce/listings", json={
        "listing_id": "safe",
        "title": "Safe service",
        "price_value": "1",
        "price_currency": "USDC",
        "settlement_methods": ["x402:usdc"],
    })
    assert published.status_code == 422

    seller = TestClient(a_app)
    signed = seller.post("/api/v2/commerce/listings", json={
        "listing_id": "signed", "title": "Signed service", "price_value": "1",
    }).json()["listing"]
    signed["title"] = "Tampered after signing"
    forged_authorization = b.post("/api/v2/commerce/intents", json={
        "listing": signed, "purpose": "must not authorize forged listing bytes",
    })
    assert forged_authorization.status_code == 400
    assert "signature" in forged_authorization.text


def test_anonymous_commerce_writes_are_bounded_and_rate_limited(tmp_path):
    app = create_app(tmp_path / "bounded", require_console_auth=True)
    client = TestClient(app)

    oversized = client.post(
        "/api/v2/commerce/carts",
        content=b'{"padding":"' + (b"x" * (256 * 1024)) + b'"}',
        headers={"Content-Type": "application/json"},
    )
    assert oversized.status_code == 413

    app.state.nth.commerce_cart_limiter = RateLimiter(
        max_per_window=1, window_seconds=60,
    )
    request = {
        "listing_digest": "sha256:" + "0" * 64,
        "intent": {},
    }
    assert client.post("/api/v2/commerce/carts", json=request).status_code == 404
    limited = client.post("/api/v2/commerce/carts", json=request)
    assert limited.status_code == 429
    assert int(limited.headers["Retry-After"]) >= 1


def test_private_order_and_outbox_reads_require_console_token(tmp_path):
    app = create_app(tmp_path / "private-reads", require_console_auth=True)
    client = TestClient(app)
    for path in ("/api/v2/commerce/orders", "/api/v2/commerce/outbox"):
        assert client.get(path).status_code == 401
        response = client.get(
            path,
            headers={"Authorization": f"Bearer {app.state.nth_console_token}"},
        )
        assert response.status_code == 200
        assert response.json() == []


def test_outbox_rechecks_peer_configuration_before_network_io(tmp_path, monkeypatch):
    app = create_app(tmp_path / "dispatch", require_console_auth=False)
    state = app.state.nth
    target = "https://seller.example"
    peer_identity = AgentIdentity.generate()
    atomic_write_json(state.workspace / "federation" / "peers.json", [target])
    atomic_write_json(state.workspace / "federation" / "peers_meta.json", {
        target: {
            "did": peer_identity.as_did(), "pubkey_hex": peer_identity.pubkey_hex,
            "peer_url": target,
            "identity_url": f"{target}/.well-known/nth-dao/identity.json",
            "card_kind": "nth-dao-identity-card-v1",
            "federation_protocol": "nth-dao-federation-v1",
        },
    })
    envelope = sign_envelope(
        state.node_identity,
        target_did=peer_identity.as_did(),
        payload={"order": {"id": "order-1"}, "trade_events": [{}]},
        created_at_ms=now_ms(),
    )
    state.commerce_outbox.enqueue(envelope, target_url=target)
    atomic_write_json(state.workspace / "federation" / "peers.json", [])

    import nth_dao.web.commerce_api as commerce_api

    def unexpected_network(*_args, **_kwargs):
        raise AssertionError("network must not run after peer removal")

    monkeypatch.setattr(commerce_api._PEER_OPENER, "open", unexpected_network)
    result = TestClient(app).post("/api/v2/commerce/outbox/dispatch")
    assert result.status_code == 200
    assert result.json()[0]["status"] == "blocked"
    assert state.commerce_outbox.get(envelope.message_id).status == "blocked"
    assert result.json()[0]["error"] == "target-policy-rejected"


def test_remote_checkout_uses_configured_peer_and_delivers_outbox(tmp_path):
    seller_app = create_app(tmp_path / "seller-http", require_console_auth=True)
    seller_client = TestClient(seller_app)
    listing_response = seller_client.post(
        "/api/v2/commerce/listings",
        headers={"Authorization": f"Bearer {seller_app.state.nth_console_token}"},
        json={
            "listing_id": "remote-review",
            "title": "Remote review",
            "price_value": "3",
        },
    )
    assert listing_response.status_code == 200, listing_response.text
    digest = listing_response.json()["digest"]

    port = _free_port()
    target = f"http://127.0.0.1:{port}"
    buyer_root = tmp_path / "buyer-http"
    buyer_app = create_app(buyer_root, require_console_auth=False)
    _bind_peer(buyer_root, target, seller_app)
    buyer = TestClient(buyer_app)
    with _Server(seller_app, port):
        request_body = {
            "target_url": target,
            "listing_digest": digest,
            "purpose": "one-click no-money checkout",
            "idempotency_key": "test-one-click-primary",
        }
        response = buyer.post("/api/v2/commerce/checkout/remote", json=request_body)
        replay = buyer.post("/api/v2/commerce/checkout/remote", json=request_body)
        collision = buyer.post("/api/v2/commerce/checkout/remote", json={
            **request_body, "purpose": "different request, same key",
        })
        second_purchase = buyer.post("/api/v2/commerce/checkout/remote", json={
            **request_body, "idempotency_key": "test-one-click-second-purchase",
        })
        missing_key = buyer.post("/api/v2/commerce/checkout/remote", json={
            key: value for key, value in request_body.items() if key != "idempotency_key"
        })
    assert response.status_code == 200, response.text
    assert replay.status_code == 200, replay.text
    assert collision.status_code == 409
    assert second_purchase.status_code == 200, second_purchase.text
    assert missing_key.status_code == 422
    result = response.json()
    assert result["delivery"]["status"] == "acknowledged"
    order_id = result["order"]["order_id"]
    assert replay.json()["order"]["order_id"] == order_id
    assert second_purchase.json()["order"]["order_id"] != order_id
    assert len(buyer_app.state.nth.commerce_orders.list_verified()) == 2
    assert len(seller_app.state.nth.commerce_orders.list_verified()) == 2
    assert seller_app.state.nth.commerce_orders.get(order_id) is not None
    assert seller_app.state.nth.commerce_trades.get_events(order_id)
    assert buyer_app.state.nth.commerce_outbox.pending() == []


def test_real_http_nodes_auto_replicate_complete_no_money_lifecycle(tmp_path):
    seller_root = tmp_path / "seller-live"
    buyer_root = tmp_path / "buyer-live"
    seller_app = create_app(seller_root, require_console_auth=False)
    buyer_app = create_app(buyer_root, require_console_auth=False)
    seller_url = f"http://127.0.0.1:{_free_port()}"
    buyer_url = f"http://127.0.0.1:{_free_port()}"
    _bind_peer(seller_root, buyer_url, buyer_app)
    _bind_peer(buyer_root, seller_url, seller_app)

    with _Server(seller_app, int(seller_url.rsplit(":", 1)[1])), _Server(
        buyer_app, int(buyer_url.rsplit(":", 1)[1]),
    ):
        published = _http_json(
            f"{seller_url}/api/v2/commerce/listings",
            payload={
                "listing_id": "live-review",
                "title": "Live two-node review",
                "price_value": "6",
            },
        )
        checkout = _http_json(
            f"{buyer_url}/api/v2/commerce/checkout/remote",
            payload={
                "target_url": seller_url,
                "listing_digest": published["digest"],
                "purpose": "exercise automatic HTTP replication",
                "idempotency_key": "live-two-node-checkout-0001",
            },
        )
        order_id = checkout["order"]["order_id"]
        assert checkout["delivery"]["status"] == "acknowledged"
        assert _http_json(
            f"{seller_url}/api/v2/commerce/orders/{order_id}",
        )["state"] == "executing"

        delivered = _http_json(
            f"{seller_url}/api/v2/commerce/orders/{order_id}/delivery",
            payload={
                "delivery": {
                    "summary": "Signed findings",
                    "artifact_digest": "sha256:" + "d" * 64,
                },
                "target_url": buyer_url,
            },
        )
        assert delivered["queued"]["status"] == "acknowledged"
        assert _http_json(
            f"{buyer_url}/api/v2/commerce/orders/{order_id}",
        )["state"] == "delivered"

        verified = _http_json(
            f"{buyer_url}/api/v2/commerce/orders/{order_id}/verify",
            payload={
                "verdict": "pass",
                "result": {"artifact_digest_verified": True},
                "target_url": seller_url,
            },
        )
        assert verified["queued"]["status"] == "acknowledged"
        assert _http_json(
            f"{seller_url}/api/v2/commerce/orders/{order_id}",
        )["state"] == "verified"

        settled = _http_json(
            f"{buyer_url}/api/v2/commerce/orders/{order_id}/settle",
            payload={"target_url": seller_url},
        )
        assert settled["queued"]["status"] == "acknowledged"
        seller_view = _http_json(
            f"{seller_url}/api/v2/commerce/orders/{order_id}",
        )
        buyer_view = _http_json(
            f"{buyer_url}/api/v2/commerce/orders/{order_id}",
        )

    assert buyer_view["state"] == seller_view["state"] == "settled"
    assert buyer_view["events"] == seller_view["events"]
    assert buyer_app.state.nth.commerce_outbox.pending() == []
    assert seller_app.state.nth.commerce_outbox.pending() == []


def test_two_process_nodes_complete_fifty_trades_across_restart(tmp_path):
    """Acceptance soak: two OS processes, durable restart, 50 full trades."""
    seller = _ProcessServer(tmp_path / "seller-process", _free_port())
    buyer = _ProcessServer(tmp_path / "buyer-process", _free_port())
    try:
        seller.start()
        buyer.start()
        seller_card = _http_json(
            f"{seller.url}/.well-known/nth-dao/identity.json",
        )
        buyer_card = _http_json(
            f"{buyer.url}/.well-known/nth-dao/identity.json",
        )
        _bind_process_peer(seller.workspace, buyer.url, buyer_card)
        _bind_process_peer(buyer.workspace, seller.url, seller_card)
        published = _http_json(
            f"{seller.url}/api/v2/commerce/listings",
            payload={
                "listing_id": "process-soak-review",
                "title": "Independent process review",
                "price_value": "1",
            },
        )

        for index in range(50):
            checkout_body = {
                "target_url": seller.url,
                "listing_digest": published["digest"],
                "purpose": f"independent process transaction {index}",
                "idempotency_key": f"process-soak-checkout-{index:04d}",
            }
            checkout = _http_json(
                f"{buyer.url}/api/v2/commerce/checkout/remote",
                payload=checkout_body,
            )
            order_id = checkout["order"]["order_id"]
            _await_process_delivery(
                checkout["delivery"],
                source_url=buyer.url,
                target_url=seller.url,
                order_id=order_id,
                expected_state="executing",
            )

            if index == 24:
                seller.restart()
                buyer.restart()
                replay = _http_json(
                    f"{buyer.url}/api/v2/commerce/checkout/remote",
                    payload=checkout_body,
                )
                assert replay["order"]["order_id"] == order_id

            delivery = _http_json(
                f"{seller.url}/api/v2/commerce/orders/{order_id}/delivery",
                payload={
                    "delivery": {
                        "artifact_digest": "sha256:" + f"{index:064x}",
                    },
                    "target_url": buyer.url,
                },
            )
            _await_process_delivery(
                delivery["queued"],
                source_url=seller.url,
                target_url=buyer.url,
                order_id=order_id,
                expected_state="delivered",
            )
            verification = _http_json(
                f"{buyer.url}/api/v2/commerce/orders/{order_id}/verify",
                payload={
                    "verdict": "pass",
                    "result": {"process_soak": index},
                    "target_url": seller.url,
                },
            )
            _await_process_delivery(
                verification["queued"],
                source_url=buyer.url,
                target_url=seller.url,
                order_id=order_id,
                expected_state="verified",
            )
            settlement = _http_json(
                f"{buyer.url}/api/v2/commerce/orders/{order_id}/settle",
                payload={"target_url": seller.url},
            )
            _await_process_delivery(
                settlement["queued"],
                source_url=buyer.url,
                target_url=seller.url,
                order_id=order_id,
                expected_state="settled",
            )
            assert _http_json(
                f"{seller.url}/api/v2/commerce/orders/{order_id}",
            )["state"] == "settled"
            assert _http_json(
                f"{buyer.url}/api/v2/commerce/orders/{order_id}",
            )["state"] == "settled"
    finally:
        buyer.stop()
        seller.stop()

    assert len(list((buyer.workspace / "commerce" / "orders").glob("*.json"))) == 50
    assert len(list((seller.workspace / "commerce" / "orders").glob("*.json"))) == 50


def test_dispute_refund_is_complete_signed_and_replicable(tmp_path):
    seller_app = create_app(tmp_path / "refund-seller", require_console_auth=False)
    buyer_app = create_app(tmp_path / "refund-buyer", require_console_auth=False)
    seller = TestClient(seller_app)
    buyer = TestClient(buyer_app)
    published = seller.post("/api/v2/commerce/listings", json={
        "listing_id": "refund-service", "title": "Refundable review", "price_value": "4",
    }).json()
    intent = buyer.post("/api/v2/commerce/intents", json={
        "listing": published["listing"], "purpose": "exercise dispute path",
    }).json()["intent"]
    cart = seller.post("/api/v2/commerce/carts", json={
        "listing_digest": published["digest"], "intent": intent,
    }).json()["cart"]
    order = buyer.post("/api/v2/commerce/orders", json={
        "listing": published["listing"], "intent": intent, "cart": cart,
    }).json()["order"]
    order_id = order["order_id"]
    _sync(buyer_app, seller, order_id)
    assert seller.post(
        f"/api/v2/commerce/orders/{order_id}/delivery",
        json={"delivery": {"summary": "incomplete"}},
    ).status_code == 200
    _sync(seller_app, buyer, order_id)
    assert buyer.post(
        f"/api/v2/commerce/orders/{order_id}/dispute",
        json={"reason": "missing artifact"},
    ).status_code == 200
    resolved = buyer.post(
        f"/api/v2/commerce/orders/{order_id}/resolve",
        json={"resolution": "refund", "rationale": "delivery incomplete"},
    )
    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["order"]["state"] == "refunded"
    settlement = resolved.json()["order"]["events"][-1]["details"]["settlement"]
    assert settlement["amount_minor"] == 0
    assert settlement["refunded_amount_minor"] == 4_000_000
    assert _sync(buyer_app, seller, order_id)["state"] == "refunded"


def test_fifty_transaction_replay_restart_ordering_and_tamper_matrix(tmp_path):
    seller_app = create_app(tmp_path / "matrix-seller", require_console_auth=False)
    buyer_app = create_app(tmp_path / "matrix-buyer", require_console_auth=False)
    seller = TestClient(seller_app)
    buyer = TestClient(buyer_app)
    published = seller.post("/api/v2/commerce/listings", json={
        "listing_id": "matrix-review",
        "title": "Matrix review",
        "price_value": "1",
    }).json()
    listing = published["listing"]
    digest = published["digest"]

    for index in range(50):
        intent_response = buyer.post("/api/v2/commerce/intents", json={
            "listing": listing,
            "purpose": f"matrix transaction {index}",
        })
        assert intent_response.status_code == 200
        intent = intent_response.json()["intent"]
        cart_response = seller.post("/api/v2/commerce/carts", json={
            "listing_digest": digest, "intent": intent,
        })
        assert cart_response.status_code == 200
        cart = cart_response.json()["cart"]
        checkout_body = {"listing": listing, "intent": intent, "cart": cart}
        checkout = buyer.post("/api/v2/commerce/orders", json=checkout_body)
        replay = buyer.post("/api/v2/commerce/orders", json=checkout_body)
        assert checkout.status_code == replay.status_code == 200
        order_id = checkout.json()["order"]["order_id"]
        assert replay.json()["order"]["order_id"] == order_id

        if index % 4 == 0:
            # Exact signed replay is idempotent.
            _sync(buyer_app, seller, order_id)
            _sync(buyer_app, seller, order_id)
        elif index % 4 == 1:
            # Reconstruct all file-backed stores as a process-restart proxy.
            for app in (buyer_app, seller_app):
                root = app.state.nth.workspace
                app.state.nth.commerce_orders = OrderStore(root)
                app.state.nth.commerce_trades = TradeStore(root)
                app.state.nth.commerce_outbox = CommerceOutbox(root)
            _sync(buyer_app, seller, order_id)
        elif index % 4 == 2:
            # Mutating signed bytes must fail without creating recipient state.
            source = buyer_app.state.nth
            envelope = sign_envelope(
                source.node_identity,
                target_did=seller_app.state.nth.node_identity.as_did(),
                payload={
                    "order": source.commerce_orders.get(order_id).to_dict(),
                    "trade_events": source.commerce_trades.get_events(order_id),
                }, created_at_ms=now_ms(),
            ).to_dict()
            envelope["payload"]["order"]["payload"]["amount_minor"] += 1
            rejected = seller.post(
                "/api/v2/commerce/federation/sync", json={"envelope": envelope},
            )
            assert rejected.status_code == 400
            _sync(buyer_app, seller, order_id)
        else:
            # A correctly signed envelope carrying only a suffix is invalid.
            source = buyer_app.state.nth
            events = source.commerce_trades.get_events(order_id)
            bad = sign_envelope(
                source.node_identity,
                target_did=seller_app.state.nth.node_identity.as_did(),
                payload={
                    "order": source.commerce_orders.get(order_id).to_dict(),
                    "trade_events": [events[0], events[0]],
                }, created_at_ms=now_ms(),
            )
            rejected = seller.post(
                "/api/v2/commerce/federation/sync",
                json={"envelope": bad.to_dict()},
            )
            assert rejected.status_code == 409
            _sync(buyer_app, seller, order_id)

        delivered = seller.post(
            f"/api/v2/commerce/orders/{order_id}/delivery",
            json={"delivery": {"artifact_digest": "sha256:" + f"{index:064x}"}},
        )
        assert delivered.status_code == 200
        _sync(seller_app, buyer, order_id)
        verified = buyer.post(
            f"/api/v2/commerce/orders/{order_id}/verify",
            json={"verdict": "pass", "result": {"matrix": index}},
        )
        assert verified.status_code == 200
        _sync(buyer_app, seller, order_id)
        settled = buyer.post(
            f"/api/v2/commerce/orders/{order_id}/settle", json={},
        )
        assert settled.status_code == 200
        _sync(buyer_app, seller, order_id)
        assert buyer.get(f"/api/v2/commerce/orders/{order_id}").json()["state"] == "settled"
        assert seller.get(f"/api/v2/commerce/orders/{order_id}").json()["state"] == "settled"
        assert len(buyer_app.state.nth.commerce_orders.list_verified()) == index + 1
        assert len(seller_app.state.nth.commerce_orders.list_verified()) == index + 1
