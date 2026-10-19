"""Console transfer stays local, evidence-bound and explicitly non-settling."""

from __future__ import annotations

import asyncio
import copy
import json
import os
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("nacl")
pytest.importorskip("fastapi")

from fastapi.testclient import TestClient
from test_market_source_receipt_delivery import _delivery, _prepare_source

from nth_dao.identity import AgentIdentity
from nth_dao.market.source_receipt_ack_return import (
    SOURCE_RECEIPT_ACK_RETURN_COMMITTED_EVENT,
)
from nth_dao.market.source_receipt_delivery import (
    SOURCE_RECEIPT_DELIVERY_ACKNOWLEDGED_EVENT,
    open_source_receipt_delivery_outbox,
)
from nth_dao.spine.log import SignedEventLog
from nth_dao.web import _FederationBodyLimitMiddleware, create_app

_SOURCE = "/api/v2/market/completion-proofs/source-receipt-acks"
_BASE = (
    "/api/v2/market/claim-intents/" + "a" * 32 + "/completion/source-receipt/deliveries"
)
_RETURN = _BASE + "/sha256:" + "b" * 64 + "/ack-return"


def _client(workspace, identity):
    app = create_app(workspace, require_console_auth=True)
    app.state.nth.node_identity = identity
    app.state.nth.spine = SignedEventLog(workspace / "spine.jsonl", identity)
    return TestClient(app), {
        "Authorization": "Bearer " + app.state.nth_console_token,
        "Content-Type": "application/json",
    }


def _setup(tmp_path):
    source, claimant, proof, _, original, receiver, now = _delivery(tmp_path)
    client, headers = _client(receiver.workspace, claimant)
    base = f"/api/v2/market/claim-intents/{proof['nonce']}/completion/source-receipt/deliveries"
    return source, claimant, original, receiver, now, client, headers, base


def test_rest_transfer_roundtrip_restart_and_exact_return_without_business_acceptance(
    tmp_path,
):
    source, claimant, original, receiver, now, client, headers, base = _setup(tmp_path)
    received = client.post(base, json=original.to_dict(), headers=headers)
    assert received.status_code == 200, received.text
    assert received.json()["ack"]["message_id"] == original.message_id
    route = base + f"/{original.message_id}/ack-return"
    prepared = client.post(route, json={"ttl_ms": 60_000}, headers=headers)
    assert prepared.status_code == 200, prepared.text
    returned = prepared.json()["envelope"]
    assert returned["recipient"] == source.as_did()
    for response in (received, prepared):
        assert not response.json()["accepted"] and not response.json()["settled"]
        assert response.json()["verification_scope"] == "transport_receipt_only"
    restarted, restarted_headers = _client(receiver.workspace, claimant)
    exported = restarted.get(route, headers=restarted_headers)
    assert exported.status_code == 200 and exported.json() == prepared.json()
    assert exported.headers.get("cache-control") == "no-store"
    assert (
        restarted.post(route, json={"ttl_ms": 1}, headers=restarted_headers).json()
        == prepared.json()
    )
    _prepare_source(tmp_path, source, original)
    outbox = open_source_receipt_delivery_outbox(tmp_path / "source", clock=lambda: now)
    outbox.enqueue(original)
    source_client, source_headers = _client(tmp_path / "source", source)
    accepted = source_client.post(_SOURCE, json=returned, headers=source_headers)
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["state"] == "delivered"
    assert accepted.json()["original_message_id"] == original.message_id
    assert not accepted.json()["accepted"] and not accepted.json()["settled"]
    assert (
        source_client.post(_SOURCE, json=returned, headers=source_headers).json()
        == accepted.json()
    )
    assert source_client.post(_SOURCE + "/reconcile", headers=source_headers).json()[
        "complete"
    ]
    assert outbox.get(original.message_id).state == "delivered"


@pytest.mark.parametrize(
    "method,path",
    [
        ("POST", _BASE),
        ("POST", _RETURN),
        ("GET", _RETURN),
        ("POST", _BASE + "/reconcile"),
        ("POST", _SOURCE),
        ("POST", _SOURCE + "/reconcile"),
    ],
)
def test_operator_required_before_body_consumption(method, path):
    async def exercise():
        messages = []

        async def forbidden(*args):
            pytest.fail("unauthorized body read or downstream execution")

        async def send(message):
            messages.append(message)

        scope = {
            "type": "http",
            "method": method,
            "path": path,
            "headers": [],
            "app": SimpleNamespace(
                state=SimpleNamespace(
                    nth_require_console_auth=True, nth_console_token="local"
                )
            ),
            "client": ("127.0.0.1", 1),
        }
        await _FederationBodyLimitMiddleware(forbidden)(scope, forbidden, send)
        assert messages[0]["status"] == 403

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "raw",
    [
        b'{"ttl_ms":1,"ttl_ms":2}',
        b'{"ttl_ms":NaN}',
        b"[]",
        b"{",
        b'{"ttl_ms":true}',
        b'{"ttl_ms":"1000"}',
        b'{"ttl_ms":0}',
        b'{"ttl_ms":604800001}',
        b'{"private_key":"not-accepted"}',
        b'{"recipient":"did:key:not-a-route"}',
    ],
)
def test_prepare_options_are_closed_and_strict(tmp_path, raw):
    _, _, original, receiver, _, client, headers, base = _setup(tmp_path)
    response = client.post(
        base + f"/{original.message_id}/ack-return", content=raw, headers=headers
    )
    assert response.status_code == 422, response.text
    assert not (receiver.workspace / ".nth/source_receipt_ack_return_outbox").exists()


@pytest.mark.parametrize("field", ["recipient", "signature"])
def test_mutated_signed_intake_cannot_create_observation_or_ack_return(tmp_path, field):
    _, _, original, receiver, _, client, headers, base = _setup(tmp_path)
    body = copy.deepcopy(original.to_dict())
    body[field] = (
        AgentIdentity.generate(label="other").as_did()
        if field == "recipient"
        else "00" * 64
    )
    response = client.post(base, json=body, headers=headers)
    assert response.status_code == 422, response.text
    assert not (receiver.workspace / ".nth/source_receipt_ack_return_outbox").exists()


def test_wrong_local_identity_and_missing_signer_fail_closed(tmp_path):
    _, _, original, _, _, client, headers, base = _setup(tmp_path)
    client.app.state.nth.node_identity = AgentIdentity.generate(label="other")
    assert (
        client.post(base, json=original.to_dict(), headers=headers).status_code == 422
    )
    client.app.state.nth.node_identity = None
    assert (
        client.post(base, json=original.to_dict(), headers=headers).status_code == 503
    )


@pytest.mark.parametrize("mode", ["declared", "streamed"])
@pytest.mark.parametrize(
    "path,limit", [(_BASE, 512 * 1024), (_RETURN, 4096), (_SOURCE, 512 * 1024)]
)
def test_body_limits_precede_json_parse(tmp_path, mode, path, limit):
    client, headers = _client(tmp_path, AgentIdentity.generate(label="local"))
    if mode == "declared":
        response = client.post(
            path, content=b"{}", headers={**headers, "Content-Length": str(limit + 1)}
        )
    else:
        response = client.post(
            path, content=iter([b"x" * limit, b"x"]), headers=headers
        )
    assert response.status_code == 413, response.text


def test_content_type_origin_and_selector_overrides_are_rejected(tmp_path):
    _, _, original, _, _, client, headers, base = _setup(tmp_path)
    route = base + f"/{original.message_id}/ack-return"
    assert (
        client.post(
            route, json={}, headers={**headers, "Origin": "https://foreign.example"}
        ).status_code
        == 403
    )
    assert (
        client.post(
            route, content=b"{}", headers={**headers, "Content-Type": "text/plain"}
        ).status_code
        == 415
    )
    assert client.post(route + "?now_ms=1", json={}, headers=headers).status_code == 422
    assert client.get(route + "?workspace=other", headers=headers).status_code == 422


def test_missing_committed_journal_cannot_be_recreated_by_rest(tmp_path):
    _, _, original, receiver, _, client, headers, base = _setup(tmp_path)
    assert (
        client.post(base, json=original.to_dict(), headers=headers).status_code == 200
    )
    route = base + f"/{original.message_id}/ack-return"
    prepared = client.post(route, json={}, headers=headers)
    assert prepared.status_code == 200
    event = receiver.spine.find_unique_event(
        SOURCE_RECEIPT_ACK_RETURN_COMMITTED_EVENT,
        payload_field="original_message_id",
        payload_value=original.message_id,
    )
    claim_id = event.payload["source_claim_id"]
    journal = (
        receiver.workspace
        / ".nth/source_receipt_ack_return_outbox"
        / claim_id
        / "outbox.journal.jsonl"
    )
    journal.rename(journal.with_name("preserved.jsonl"))
    for response in (
        client.get(route, headers=headers),
        client.post(route, json={}, headers=headers),
    ):
        assert response.status_code == 503
        assert response.json()["detail"] == {
            "code": "receipt-delivery-integrity-failed",
            "retryable": False,
        }
        assert "envelope" not in response.json()
    assert not journal.exists()


def test_source_reconcile_repairs_audit_without_new_remote_intake(
    tmp_path, monkeypatch
):
    source, _, original, _, now, client, headers, base = _setup(tmp_path)
    assert (
        client.post(base, json=original.to_dict(), headers=headers).status_code == 200
    )
    returned = client.post(
        base + f"/{original.message_id}/ack-return", json={}, headers=headers
    ).json()["envelope"]
    _prepare_source(tmp_path, source, original)
    outbox = open_source_receipt_delivery_outbox(tmp_path / "source", clock=lambda: now)
    outbox.enqueue(original)
    source_client, source_headers = _client(tmp_path / "source", source)
    append = SignedEventLog.append_unique

    def fail(self, event_type, *args, **kwargs):
        if event_type == SOURCE_RECEIPT_DELIVERY_ACKNOWLEDGED_EVENT:
            raise OSError("injected local path must not be returned")
        return append(self, event_type, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(SignedEventLog, "append_unique", fail)
        response = source_client.post(_SOURCE, json=returned, headers=source_headers)
        incomplete = source_client.post(_SOURCE + "/reconcile", headers=source_headers)
    assert response.status_code == 503 and "injected" not in response.text
    assert response.json()["detail"]["retryable"]
    assert incomplete.status_code == 200 and not incomplete.json()["complete"]
    assert (
        incomplete.json()["results"] == []
        and incomplete.json()["failures"][0]["retryable"]
    )
    repaired = source_client.post(_SOURCE + "/reconcile", headers=source_headers)
    assert repaired.status_code == 200 and repaired.json()["complete"]
    assert repaired.json()["results"][0]["original_message_id"] == original.message_id
    assert outbox.get(original.message_id).state == "delivered"


def test_return_export_before_prepare_is_read_only(tmp_path):
    _, _, original, receiver, _, client, headers, base = _setup(tmp_path)
    assert (
        client.post(base, json=original.to_dict(), headers=headers).status_code == 200
    )
    route = base + f"/{original.message_id}/ack-return"
    assert client.get(route, headers=headers).status_code == 404
    journal_paths = list(
        (receiver.workspace / ".nth/source_receipt_ack_return_outbox").glob(
            "*/outbox.journal.jsonl"
        )
    )
    assert journal_paths == []


@pytest.mark.parametrize("journal_kind", ["inbox", "outbox", "claim-intent"])
def test_get_preserves_torn_journals_until_explicit_recovery(tmp_path, journal_kind):
    from nth_dao.market.claim_intent import IntentTracker
    from nth_dao.market.source_receipt_ack_return import SourceReceiptAckReturnStore

    _, _, original, receiver, _, client, headers, base = _setup(tmp_path)
    assert (
        client.post(base, json=original.to_dict(), headers=headers).status_code == 200
    )
    route = base + f"/{original.message_id}/ack-return"
    prepared = client.post(route, json={}, headers=headers)
    assert prepared.status_code == 200
    store = SourceReceiptAckReturnStore(receiver)
    intent_dir = receiver.workspace / "federation/claim_intents"
    journal = {
        "inbox": receiver.inbox._cache_path,
        "outbox": store._path(Path("outbox.journal.jsonl")),
        "claim-intent": IntentTracker(intent_dir)._journal_path,
    }[journal_kind]
    prefix = journal.read_bytes()
    tail = b'{"event":"interrupted-test-tail"'
    with journal.open("ab") as stream:
        stream.write(tail)
    audit = (receiver.workspace / "spine.jsonl").read_bytes()

    for _ in range(2):
        exported = client.get(route, headers=headers)
        assert exported.status_code == 200, exported.text
        assert exported.json() == prepared.json()
        assert journal.read_bytes() == prefix + tail
        assert list(journal.parent.glob(journal.name + ".torn.*")) == []
        assert (receiver.workspace / "spine.jsonl").read_bytes() == audit

    recovered = client.post(route, json={}, headers=headers)
    assert recovered.status_code == 200 and recovered.json() == prepared.json()
    assert journal.read_bytes() == prefix


@pytest.mark.parametrize("prepared", [False, True])
def test_export_does_not_finish_interrupted_receipt_processing(
    tmp_path, monkeypatch, prepared
):
    from nth_dao.delivery.inbox import DeliveryInbox

    _, _, original, receiver, _, client, headers, base = _setup(tmp_path)

    def interrupted(*args, **kwargs):
        raise OSError("interrupted after durable result")

    with monkeypatch.context() as patch:
        patch.setattr(DeliveryInbox, "mark_processed", interrupted)
        assert (
            client.post(base, json=original.to_dict(), headers=headers).status_code
            == 503
        )
    assert [item.message_id for item in receiver.inbox.pending()] == [
        original.message_id
    ]
    route = base + f"/{original.message_id}/ack-return"
    if prepared:
        assert client.post(route, json={}, headers=headers).status_code == 200
    cache = receiver.inbox._cache_path.read_bytes()
    audit = (receiver.workspace / "spine.jsonl").read_bytes()

    response = client.get(route, headers=headers)

    assert response.status_code == (200 if prepared else 404)
    assert [item.message_id for item in receiver.inbox.pending()] == [
        original.message_id
    ]
    assert receiver.inbox._cache_path.read_bytes() == cache
    assert (receiver.workspace / "spine.jsonl").read_bytes() == audit
    reconciled = client.post(base + "/reconcile", headers=headers)
    assert reconciled.status_code == 200 and reconciled.json()["complete"]
    assert receiver.inbox.pending() == []


@pytest.mark.parametrize(
    "loss", ["prepared-return", "processed-result", "result-and-index"]
)
def test_committed_artifact_loss_is_not_an_ordinary_missing_return(tmp_path, loss):
    from nth_dao.market.source_receipt_ack_return import SourceReceiptAckReturnStore

    _, _, original, receiver, _, client, headers, base = _setup(tmp_path)
    assert (
        client.post(base, json=original.to_dict(), headers=headers).status_code == 200
    )
    route = base + f"/{original.message_id}/ack-return"
    assert client.post(route, json={}, headers=headers).status_code == 200
    store = SourceReceiptAckReturnStore(receiver)
    path = (
        store._prepared_path(original)
        if loss == "prepared-return"
        else receiver._result_path(original.message_id)
    )
    path.rename(path.with_name("preserved-artifact.json"))
    if loss == "result-and-index":
        receiver.inbox._cache_path.rename(
            receiver.inbox._cache_path.with_name("preserved-index.jsonl")
        )
    audit = (receiver.workspace / "spine.jsonl").read_bytes()
    journal = store._path(Path("outbox.journal.jsonl")).read_bytes()

    for response in (
        client.get(route, headers=headers),
        client.post(route, json={}, headers=headers),
    ):
        assert response.status_code == 503, response.text
        assert response.json()["detail"] == {
            "code": "receipt-delivery-integrity-failed",
            "retryable": False,
        }
        assert "envelope" not in response.json()
    assert not path.exists()
    assert (receiver.workspace / "spine.jsonl").read_bytes() == audit
    assert store._path(Path("outbox.journal.jsonl")).read_bytes() == journal


def test_interrupted_result_write_is_pending_not_missing_or_corrupt(
    tmp_path, monkeypatch
):
    _, _, original, receiver, _, client, headers, base = _setup(tmp_path)

    def interrupted(*args, **kwargs):
        raise OSError("interrupted before result persistence")

    with monkeypatch.context() as patch:
        patch.setattr(
            "nth_dao.market.source_receipt_delivery._write_delivery_bytes", interrupted
        )
        assert (
            client.post(base, json=original.to_dict(), headers=headers).status_code
            == 503
        )
    route = base + f"/{original.message_id}/ack-return"
    response = client.get(route, headers=headers)
    assert response.status_code == 409
    assert response.json()["detail"]["retryable"] is True
    assert not receiver._result_path(original.message_id).exists()
    assert client.post(base + "/reconcile", headers=headers).json()["complete"]


@pytest.mark.parametrize("committed", [False, True])
def test_audited_result_loss_overrides_interrupted_processed_marker(
    tmp_path, monkeypatch, committed
):
    from nth_dao.delivery.inbox import DeliveryInbox
    from nth_dao.delivery.outbox import DurableOutbox
    from nth_dao.market.source_receipt_ack_return import SourceReceiptAckReturnStore

    _, _, original, receiver, _, client, headers, base = _setup(tmp_path)

    def interrupted(*args, **kwargs):
        raise OSError("injected persistence interruption")

    with monkeypatch.context() as patch:
        patch.setattr(DeliveryInbox, "mark_processed", interrupted)
        assert (
            client.post(base, json=original.to_dict(), headers=headers).status_code
            == 503
        )
    route = base + f"/{original.message_id}/ack-return"
    with monkeypatch.context() as patch:
        if not committed:
            patch.setattr(DurableOutbox, "enqueue", interrupted)
        assert client.post(route, json={}, headers=headers).status_code == (
            200 if committed else 503
        )
    store = SourceReceiptAckReturnStore(receiver)
    assert store._audit(original.message_id) is not None
    assert (
        store._audit(
            original.message_id, event_type=SOURCE_RECEIPT_ACK_RETURN_COMMITTED_EVENT
        )
        is not None
    ) is committed
    assert [item.message_id for item in receiver.inbox.pending()] == [
        original.message_id
    ]
    result = receiver._result_path(original.message_id)
    result.rename(result.with_name("preserved-result.json"))
    audit = (receiver.workspace / "spine.jsonl").read_bytes()
    cache = receiver.inbox._cache_path.read_bytes()
    returned = store._prepared_path(original).read_bytes()

    for response in (
        client.get(route, headers=headers),
        client.post(route, json={}, headers=headers),
    ):
        assert response.status_code == 503, response.text
        assert response.json()["detail"] == {
            "code": "receipt-delivery-integrity-failed",
            "retryable": False,
        }
        assert "envelope" not in response.json()
    assert not result.exists()
    assert (receiver.workspace / "spine.jsonl").read_bytes() == audit
    assert receiver.inbox._cache_path.read_bytes() == cache
    assert store._prepared_path(original).read_bytes() == returned


def test_committed_return_still_defers_temporarily_unavailable_local_evidence(
    tmp_path, monkeypatch
):
    from nth_dao.market.source_receipt_delivery import (
        SourceReceiptDeliveryDeferred,
        SourceReceiptDeliveryReceiver,
    )

    _, _, original, _, _, client, headers, base = _setup(tmp_path)
    assert (
        client.post(base, json=original.to_dict(), headers=headers).status_code == 200
    )
    route = base + f"/{original.message_id}/ack-return"
    prepared = client.post(route, json={}, headers=headers)
    assert prepared.status_code == 200

    def unavailable(*args, **kwargs):
        raise SourceReceiptDeliveryDeferred(
            "local completion evidence is temporarily unavailable"
        )

    with monkeypatch.context() as patch:
        patch.setattr(SourceReceiptDeliveryReceiver, "_verify_local", unavailable)
        for response in (
            client.get(route, headers=headers),
            client.post(route, json={}, headers=headers),
        ):
            assert response.status_code == 409, response.text
            assert response.json()["detail"]["retryable"] is True
    assert client.get(route, headers=headers).json() == prepared.json()


@pytest.mark.parametrize(
    "artifact,mutation",
    [
        ("return", mutation)
        for mutation in (
            "signature",
            "noncanonical",
            "json",
            "nonobject",
            "encoding",
            "recipient",
            "nonce",
            "inner-signature",
            "oversize",
            "hardlink",
        )
    ]
    + [
        ("result", mutation)
        for mutation in (
            "signature",
            "noncanonical",
            "json",
            "nonobject",
            "encoding",
            "inner-signature",
            "observation",
            "oversize",
            "hardlink",
        )
    ],
)
def test_retained_corruption_is_server_integrity_failure_not_bad_input(
    tmp_path, artifact, mutation
):
    from test_market_source_receipt_delivery import _resign

    from nth_dao.canonical_json import canonical_json
    from nth_dao.market.source_receipt_ack_return import SourceReceiptAckReturnStore
    from nth_dao.market.source_receipt_delivery import _MAX_RESULT_BYTES

    _, claimant, original, receiver, _, client, headers, base = _setup(tmp_path)
    assert (
        client.post(base, json=original.to_dict(), headers=headers).status_code == 200
    )
    route = base + f"/{original.message_id}/ack-return"
    assert client.post(route, json={}, headers=headers).status_code == 200
    store = SourceReceiptAckReturnStore(receiver)
    path = (
        store._prepared_path(original)
        if artifact == "return"
        else receiver._result_path(original.message_id)
    )
    value = json.loads(path.read_bytes())
    if mutation == "noncanonical":
        raw = b" " + path.read_bytes()
    elif mutation == "json":
        raw = b"{"
    elif mutation == "nonobject":
        raw = b"[1]"
    elif mutation == "encoding":
        raw = b"\xff"
    elif mutation == "oversize":
        raw = b"x" * (_MAX_RESULT_BYTES + 1)
    elif mutation == "hardlink":
        os.link(path, path.with_name("test-retained-hardlink.json"))
        raw = path.read_bytes()
    else:
        if mutation == "signature":
            (value if artifact == "return" else value["envelope"])["signature"] = (
                "00" * 64
            )
        elif mutation == "inner-signature":
            (value["payload"]["ack"] if artifact == "return" else value["ack"])[
                "signature"
            ] = "00" * 64
            if artifact == "return":
                value = _resign(claimant, original.from_dict(value)).to_dict()
        elif mutation == "observation":
            value["observation_event_id"] = "0" * 64
        else:
            value = _resign(
                claimant,
                original.from_dict(value),
                **(
                    {"recipient": claimant.as_did()}
                    if mutation == "recipient"
                    else {"nonce": "a" * 32}
                ),
            ).to_dict()
        raw = canonical_json(value)
    path.write_bytes(raw)
    audit = (receiver.workspace / "spine.jsonl").read_bytes()
    journal = store._path(Path("outbox.journal.jsonl")).read_bytes()

    for response in (
        client.get(route, headers=headers),
        client.post(route, json={}, headers=headers),
    ):
        assert response.status_code == 503, response.text
        assert response.json()["detail"] == {
            "code": "receipt-delivery-integrity-failed",
            "retryable": False,
        }
        assert "envelope" not in response.json()
        assert response.headers["cache-control"] == "no-store"
    assert path.read_bytes() == raw
    assert (receiver.workspace / "spine.jsonl").read_bytes() == audit
    assert store._path(Path("outbox.journal.jsonl")).read_bytes() == journal


@pytest.mark.parametrize("stage", ["preparation", "commit"])
def test_valid_partial_return_is_pending_and_explicitly_recoverable(
    tmp_path, monkeypatch, stage
):
    from nth_dao.market.source_receipt_ack_return import (
        SOURCE_RECEIPT_ACK_RETURN_PREPARED_EVENT,
        SourceReceiptAckReturnStore,
    )

    _, _, original, receiver, _, client, headers, base = _setup(tmp_path)
    assert (
        client.post(base, json=original.to_dict(), headers=headers).status_code == 200
    )
    route = base + f"/{original.message_id}/ack-return"
    event_type = (
        SOURCE_RECEIPT_ACK_RETURN_PREPARED_EVENT
        if stage == "preparation"
        else SOURCE_RECEIPT_ACK_RETURN_COMMITTED_EVENT
    )
    append = SignedEventLog.append_unique

    def interrupted(log, kind, *args, **kwargs):
        if kind == event_type:
            raise OSError("injected audit interruption")
        return append(log, kind, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(SignedEventLog, "append_unique", interrupted)
        assert client.post(route, json={}, headers=headers).status_code == 503
    path = SourceReceiptAckReturnStore(receiver)._prepared_path(original)
    raw = path.read_bytes()
    audit = (receiver.workspace / "spine.jsonl").read_bytes()
    response = client.get(route, headers=headers)
    assert response.status_code == 409, response.text
    assert response.json()["detail"]["retryable"] is True
    assert path.read_bytes() == raw
    assert (receiver.workspace / "spine.jsonl").read_bytes() == audit
    repaired = client.post(route, json={}, headers=headers)
    assert repaired.status_code == 200
    assert repaired.json()["envelope"] == json.loads(raw)
    assert client.get(route, headers=headers).json() == repaired.json()


def test_unclassified_filesystem_missing_error_is_not_a_domain_404():
    from fastapi import HTTPException

    from nth_dao.web.source_receipt_delivery_api import _call

    def missing_storage():
        raise FileNotFoundError("storage vanished during IO")

    with pytest.raises(HTTPException) as caught:
        asyncio.run(_call(missing_storage))
    assert caught.value.status_code == 503
    assert caught.value.detail == {
        "code": "receipt-delivery-storage-unavailable",
        "retryable": True,
    }


def test_no_store_covers_success_guard_errors_and_integrity_failures(
    tmp_path, monkeypatch
):
    from nth_dao.market.source_receipt_ack_return import SourceReceiptAckReturnStore

    _, _, original, _, _, client, headers, base = _setup(tmp_path)
    route = base + f"/{original.message_id}/ack-return"

    def check(response, status):
        assert response.status_code == status, response.text
        assert response.headers.get_list("cache-control") == ["no-store"]

    check(client.get(route), 401)
    check(
        client.post(
            route, json={}, headers={**headers, "Origin": "https://foreign.example"}
        ),
        403,
    )
    check(client.get(route + "?clock=1", headers=headers), 422)
    check(
        client.post(
            route, content=b"{}", headers={**headers, "Content-Length": "4097"}
        ),
        413,
    )
    check(client.post(base, json=original.to_dict(), headers=headers), 200)
    check(client.get(route, headers=headers), 404)
    check(client.post(route, json={}, headers=headers), 200)
    check(client.get(route, headers=headers), 200)

    def unavailable(*args, **kwargs):
        raise RuntimeError("injected storage invariant failure")

    with monkeypatch.context() as patch:
        patch.setattr(SourceReceiptAckReturnStore, "get", unavailable)
        check(client.get(route, headers=headers), 503)

    layer = client.app.middleware_stack
    while not isinstance(layer, _FederationBodyLimitMiddleware):
        layer = layer.app
    assert layer._source_proof_slots.acquire(blocking=False)
    assert layer._source_proof_slots.acquire(blocking=False)
    try:
        check(client.get(route, headers=headers), 429)
    finally:
        layer._source_proof_slots.release()
        layer._source_proof_slots.release()


def test_unexpected_console_failure_is_not_cacheable_or_disclosed(
    tmp_path, monkeypatch
):
    client, headers = _client(tmp_path, AgentIdentity.generate(label="local"))

    def fail(*args, **kwargs):
        raise RuntimeError("private diagnostic must not be disclosed")

    monkeypatch.setattr("nth_dao.web.source_receipt_delivery_api._selectors", fail)
    response = TestClient(client.app, raise_server_exceptions=False).get(
        _RETURN, headers=headers
    )
    assert response.status_code == 500
    assert response.headers.get_list("cache-control") == ["no-store"]
    assert response.text == "Internal Server Error"
    with pytest.raises(RuntimeError, match="private diagnostic"):
        client.get(_RETURN, headers=headers)


@pytest.mark.parametrize("receipt_route", [False, True])
def test_cache_policy_is_scoped_and_replaces_conflicting_headers(receipt_route):
    from nth_dao.web.source_receipt_delivery_api import SourceReceiptNoStoreMiddleware

    async def exercise():
        messages = []

        async def send(message):
            messages.append(message)

        async def receive():
            pytest.fail("response policy consumed the request body")

        async def downstream(scope, receive, send):
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [
                        (b"Cache-Control", b"public, max-age=3600"),
                        (b"x-test", b"preserved"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": b"exact response"})

        await SourceReceiptNoStoreMiddleware(downstream)(
            {
                "type": "http",
                "method": "GET",
                "path": _RETURN if receipt_route else "/api/v2/health",
            },
            receive,
            send,
        )
        values = [
            value
            for name, value in messages[0]["headers"]
            if name.lower() == b"cache-control"
        ]
        assert values == ([b"no-store"] if receipt_route else [b"public, max-age=3600"])
        assert (b"x-test", b"preserved") in messages[0]["headers"]
        assert messages[1]["body"] == b"exact response"

    asyncio.run(exercise())


@pytest.mark.parametrize("route", [_BASE, _SOURCE])
@pytest.mark.parametrize(
    "body", [b'{"payload":{},"payload":{}}', b'{"payload":{"key":1,"key":2}}']
)
def test_envelope_duplicate_fields_are_rejected_before_domain_intake(
    tmp_path, route, body, monkeypatch
):
    from nth_dao.market.source_receipt_ack import SourceReceiptAckReceiver
    from nth_dao.market.source_receipt_delivery import SourceReceiptDeliveryReceiver

    client, headers = _client(tmp_path, AgentIdentity.generate(label="local"))
    monkeypatch.setattr(
        SourceReceiptDeliveryReceiver,
        "receive",
        lambda *a, **k: pytest.fail("domain called"),
    )
    monkeypatch.setattr(
        SourceReceiptAckReceiver,
        "receive",
        lambda *a, **k: pytest.fail("domain called"),
    )
    assert client.post(route, content=body, headers=headers).status_code == 422


@pytest.mark.parametrize("route", [_BASE + "/reconcile", _SOURCE + "/reconcile"])
def test_reconciliation_accepts_no_remote_body_or_clock(tmp_path, route):
    client, headers = _client(tmp_path, AgentIdentity.generate(label="local"))
    assert client.post(route, content=iter([b"x"]), headers=headers).status_code == 413
    assert client.post(route + "?accepted_at_ms=1", headers=headers).status_code == 422


def test_forged_return_cannot_close_original_source_outbox(tmp_path):
    source, _, original, _, now, client, headers, base = _setup(tmp_path)
    assert (
        client.post(base, json=original.to_dict(), headers=headers).status_code == 200
    )
    returned = client.post(
        base + f"/{original.message_id}/ack-return", json={}, headers=headers
    ).json()["envelope"]
    _prepare_source(tmp_path, source, original)
    outbox = open_source_receipt_delivery_outbox(tmp_path / "source", clock=lambda: now)
    outbox.enqueue(original)
    source_client, source_headers = _client(tmp_path / "source", source)
    returned["payload"]["ack"]["signature"] = "00" * 64
    rejected = source_client.post(_SOURCE, json=returned, headers=source_headers)
    assert rejected.status_code == 422 and not rejected.json()["detail"]["retryable"]
    assert outbox.get(original.message_id).state == "queued"


def test_unknown_claim_is_not_bootstrapped_and_no_plugins_are_invoked(
    tmp_path, monkeypatch
):
    from nth_dao.plugins import PluginHost

    _, _, original, _, _, client, headers, base = _setup(tmp_path)
    monkeypatch.setattr(
        PluginHost,
        "invoke",
        lambda *a, **k: pytest.fail("offline endpoint invoked a provider"),
    )
    unknown = base.replace(base.split("/")[5], "f" * 32)
    response = client.post(unknown, json=original.to_dict(), headers=headers)
    assert response.status_code == 409 and response.json()["detail"]["retryable"]
    assert (
        client.post(base, json=original.to_dict(), headers=headers).status_code == 200
    )
    assert (
        client.post(
            base + f"/{original.message_id}/ack-return", json={}, headers=headers
        ).status_code
        == 200
    )


@pytest.mark.parametrize("path", [_BASE, _RETURN, _SOURCE])
def test_receipt_requests_share_preparse_concurrency_budget(path):
    async def exercise():
        entered = 0
        occupied = asyncio.Event()
        release = asyncio.Event()

        async def downstream(*args):
            nonlocal entered
            entered += 1
            if entered == 2:
                occupied.set()
            await release.wait()

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def discard(message):
            pass

        middleware = _FederationBodyLimitMiddleware(downstream)
        scope = {
            "type": "http",
            "method": "POST",
            "path": path,
            "headers": [],
            "app": SimpleNamespace(
                state=SimpleNamespace(nth_require_console_auth=False)
            ),
            "client": ("127.0.0.1", 1),
        }
        first = asyncio.create_task(middleware(scope, receive, discard))
        second = asyncio.create_task(middleware(scope, receive, discard))
        try:
            await asyncio.wait_for(occupied.wait(), 2)
            messages = []

            async def send(message):
                messages.append(message)

            await middleware(scope, receive, send)
            assert entered == 2 and messages[0]["status"] == 429
        finally:
            release.set()
            await asyncio.gather(first, second)

    asyncio.run(exercise())


def _operator_scope(path):
    return {
        "type": "http",
        "method": "POST",
        "path": path,
        "headers": [],
        "app": SimpleNamespace(state=SimpleNamespace(nth_require_console_auth=False)),
        "client": ("127.0.0.1", 1),
    }


@pytest.mark.parametrize(
    "path", [_BASE, "/api/v2/market/completion-proofs/verify-source"]
)
def test_slow_uploads_expire_and_release_shared_slots(monkeypatch, path):
    from nth_dao import web

    monkeypatch.setattr(web, "_SOURCE_PROOF_BODY_IDLE_TIMEOUT_S", 0.05)
    monkeypatch.setattr(web, "_SOURCE_PROOF_BODY_TOTAL_TIMEOUT_S", 0.5)

    async def exercise():
        entered = 0
        waiting = asyncio.Event()
        never = asyncio.Event()
        middleware = _FederationBodyLimitMiddleware(downstream)

        async def slow_receive():
            nonlocal entered
            entered += 1
            if entered == 2:
                waiting.set()
            await never.wait()
            pytest.fail("slow upload unexpectedly released")

        async def empty_receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def request(scope, receive):
            messages = []

            async def send(message):
                messages.append(message)

            await middleware(scope, receive, send)
            return messages[0]["status"]

        tasks = [
            asyncio.create_task(request(_operator_scope(path), slow_receive))
            for _ in range(2)
        ]
        try:
            await asyncio.wait_for(waiting.wait(), 1)
            scope = {**_operator_scope(_RETURN), "method": "GET"}
            assert await request(scope, empty_receive) == 429
            assert await asyncio.wait_for(asyncio.gather(*tasks), 1) == [408, 408]
            assert await request(scope, empty_receive) == 200
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def downstream(scope, receive, send):
        await receive()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})

    asyncio.run(exercise())


def test_total_upload_deadline_bounds_a_continuous_trickle(monkeypatch):
    from nth_dao import web

    monkeypatch.setattr(web, "_SOURCE_PROOF_BODY_IDLE_TIMEOUT_S", 0.5)
    monkeypatch.setattr(web, "_SOURCE_PROOF_BODY_TOTAL_TIMEOUT_S", 0.1)

    async def exercise():
        chunks = 0
        messages = []

        async def receive():
            nonlocal chunks
            await asyncio.sleep(0.01)
            chunks += 1
            return {"type": "http.request", "body": b"x", "more_body": True}

        async def send(message):
            messages.append(message)

        async def downstream(scope, receive, send):
            while (await receive()).get("more_body"):
                pass
            pytest.fail("incomplete upload entered domain processing")

        await asyncio.wait_for(
            _FederationBodyLimitMiddleware(downstream)(
                _operator_scope(_BASE), receive, send
            ),
            1,
        )
        assert chunks > 0 and messages[0]["status"] == 408

    asyncio.run(exercise())


def test_upload_deadline_never_cancels_work_after_body_completion(monkeypatch):
    from nth_dao import web

    monkeypatch.setattr(web, "_SOURCE_PROOF_BODY_IDLE_TIMEOUT_S", 0.01)
    monkeypatch.setattr(web, "_SOURCE_PROOF_BODY_TOTAL_TIMEOUT_S", 0.02)

    async def exercise():
        async def receive():
            return {"type": "http.request", "body": b"{}", "more_body": False}

        messages = []

        async def send(message):
            messages.append(message)

        async def downstream(scope, receive, send):
            await receive()
            await asyncio.sleep(0.05)
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"{}"})

        await _FederationBodyLimitMiddleware(downstream)(
            _operator_scope(_BASE), receive, send
        )
        assert messages[0]["status"] == 200

    asyncio.run(exercise())


def test_real_console_stack_returns_408_before_domain_work(tmp_path, monkeypatch):
    import httpx

    from nth_dao import web

    client, headers = _client(tmp_path, AgentIdentity.generate(label="local"))
    monkeypatch.setattr(web, "_SOURCE_PROOF_BODY_IDLE_TIMEOUT_S", 0.02)
    monkeypatch.setattr(web, "_SOURCE_PROOF_BODY_TOTAL_TIMEOUT_S", 0.2)

    async def slow_body():
        await asyncio.sleep(0.5)
        yield b"{}"

    async def exercise():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=client.app), base_url="http://testserver"
        ) as session:
            response = await session.post(_BASE, headers=headers, content=slow_body())
            assert response.status_code == 408
            assert response.headers["connection"] == "close"
            assert response.headers.get_list("cache-control") == ["no-store"]
            assert (
                await session.post(_BASE, headers=headers, content=b"{}")
            ).status_code == 422

    asyncio.run(exercise())


def test_preparation_io_does_not_block_health(tmp_path, monkeypatch):
    import httpx

    from nth_dao.market.source_receipt_ack_return import SourceReceiptAckReturnStore

    _, _, original, _, _, client, headers, base = _setup(tmp_path)
    entered, release = threading.Event(), threading.Event()

    def held(*args, **kwargs):
        entered.set()
        if not release.wait(5):
            raise RuntimeError("worker blocked event loop")
        raise OSError("injected unavailable storage")

    monkeypatch.setattr(SourceReceiptAckReturnStore, "prepare", held)

    async def exercise():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=client.app), base_url="http://testserver"
        ) as session:
            pending = asyncio.create_task(
                session.post(
                    base + f"/{original.message_id}/ack-return",
                    json={},
                    headers=headers,
                )
            )
            try:
                assert await asyncio.to_thread(entered.wait, 3)
                health = await asyncio.wait_for(session.get("/api/v2/health"), 2)
                assert health.status_code == 200 and not pending.done()
            finally:
                release.set()
                result = await pending
            assert result.status_code == 503 and result.json()["detail"]["retryable"]

    asyncio.run(exercise())


_CONSOLE_VECTOR = json.loads(
    (
        Path(__file__).resolve().parents[1]
        / "nth_dao/market/vectors/source-receipt-console-v1.json"
    ).read_text(encoding="utf-8")
)


@pytest.mark.parametrize(
    "operation", _CONSOLE_VECTOR["operations"], ids=lambda value: value["name"]
)
def test_local_console_contract_vectors(operation):
    from nth_dao.web.source_receipt_delivery_api import source_receipt_request_limit

    path = operation["path"].format(nonce="a" * 32, message_id="sha256:" + "b" * 64)
    assert (
        source_receipt_request_limit(
            {"type": "http", "method": operation["method"], "path": path}
        )
        == operation["max_body_bytes"]
    )
    assert _CONSOLE_VECTOR["verification_scope"] == "transport_receipt_only"
    assert _CONSOLE_VECTOR["accepted"] is False and _CONSOLE_VECTOR["settled"] is False
    assert _CONSOLE_VECTOR["response_cache_control"] == "no-store"
    assert _CONSOLE_VECTOR["get_domain_state_transitions"] is False
    assert _CONSOLE_VECTOR["get_storage_recovery"] is False
    assert _CONSOLE_VECTOR["get_archive_index_migration"] is False


@pytest.mark.parametrize(
    "vector", _CONSOLE_VECTOR["errors"], ids=lambda value: value["condition"]
)
def test_local_console_error_contract_vectors(vector):
    from fastapi import HTTPException

    from nth_dao.delivery.inbox import DeliveryInboxCacheCorrupt
    from nth_dao.delivery.outbox import DeliveryOutboxCorrupt
    from nth_dao.market.source_receipt_delivery import (
        SourceReceiptDeliveryDeferred,
        SourceReceiptDeliveryNotRetained,
        SourceReceiptDeliveryRejected,
        SourceReceiptDeliveryResultPending,
        source_receipt_delivery_failure,
    )
    from nth_dao.web.source_receipt_delivery_api import _call

    error = {
        "not-retained": SourceReceiptDeliveryNotRetained,
        "pending": SourceReceiptDeliveryDeferred,
        "rejected": SourceReceiptDeliveryRejected,
        "storage": OSError,
        "corrupt": DeliveryOutboxCorrupt,
        "pending-result": SourceReceiptDeliveryResultPending,
        "corrupt-retained-result": DeliveryInboxCacheCorrupt,
    }[vector["condition"]]("synthetic local condition")

    def fail():
        raise error

    with pytest.raises(HTTPException) as caught:
        asyncio.run(_call(fail))
    assert caught.value.status_code == vector["status"]
    assert caught.value.detail == {
        "code": vector["code"],
        "retryable": vector["retryable"],
    }
    assert source_receipt_delivery_failure("", error).retryable is vector["retryable"]


def test_local_console_upload_default_contract():
    from nth_dao import web

    limits = _CONSOLE_VECTOR["body_read_limits"]
    assert limits["idle_timeout_s"] == web._SOURCE_PROOF_BODY_IDLE_TIMEOUT_S
    assert limits["total_timeout_s"] == web._SOURCE_PROOF_BODY_TOTAL_TIMEOUT_S
    assert limits["timeout_status"] == 408


@pytest.mark.parametrize("failure", ["runtime", "claim-journal", "observation"])
@pytest.mark.parametrize("boundary", ["batch", "rest"])
def test_unknown_failure_requires_operator_review_not_automatic_retry(
    failure, boundary
):
    from fastapi import HTTPException

    from nth_dao.market.claim_intent import IntentTrackerCorrupt
    from nth_dao.market.claimant_receipt_store import ClaimantReceiptCorrupt
    from nth_dao.market.source_receipt_delivery import source_receipt_delivery_failure
    from nth_dao.web.source_receipt_delivery_api import _call

    error = {
        "runtime": RuntimeError,
        "claim-journal": IntentTrackerCorrupt,
        "observation": ClaimantReceiptCorrupt,
    }[failure]("injected invariant failure")
    if boundary == "batch":
        assert not source_receipt_delivery_failure("", error).retryable
        return

    def fail():
        raise error

    with pytest.raises(HTTPException) as caught:
        asyncio.run(_call(fail))
    assert caught.value.status_code == 503
    assert caught.value.detail == {
        "code": "receipt-delivery-integrity-failed",
        "retryable": False,
    }


@pytest.mark.parametrize(
    "kind",
    ["io", "timeout", "inbox-capacity", "outbox-capacity", "pending", "evidence"],
)
def test_explicitly_recoverable_failures_keep_retry_permission(kind):
    from fastapi import HTTPException

    from nth_dao.delivery.inbox import DeliveryInboxFull
    from nth_dao.delivery.outbox import DeliveryOutboxFull
    from nth_dao.market.claim_evidence import ClaimEvidenceUnavailable
    from nth_dao.market.claimant_receipt_store import ClaimantReceiptPending
    from nth_dao.market.source_receipt_delivery import source_receipt_delivery_failure
    from nth_dao.web.source_receipt_delivery_api import _call

    error = {
        "io": OSError,
        "timeout": TimeoutError,
        "inbox-capacity": DeliveryInboxFull,
        "outbox-capacity": DeliveryOutboxFull,
        "pending": ClaimantReceiptPending,
        "evidence": ClaimEvidenceUnavailable,
    }[kind]("injected recoverable failure")
    assert source_receipt_delivery_failure("", error).retryable

    def fail():
        raise error

    with pytest.raises(HTTPException) as caught:
        asyncio.run(_call(fail))
    assert caught.value.status_code == (409 if kind in {"pending", "evidence"} else 503)
    assert caught.value.detail["retryable"] is True


@pytest.mark.parametrize(
    "headers",
    [
        [(b"authorization", b"Bearer \xff")],
        [(b"authorization", b"Bearer local"), (b"authorization", b"Bearer local")],
        [(b"authorization", b"Basic local")],
        [],
    ],
)
def test_malformed_console_credentials_fail_closed_without_comparison_errors(headers):
    scope = {
        "app": SimpleNamespace(
            state=SimpleNamespace(
                nth_require_console_auth=True,
                nth_console_token="local",
            )
        ),
        "headers": headers,
    }
    assert not _FederationBodyLimitMiddleware._source_proof_operator_authorized(scope)


def test_non_ascii_bearer_is_rejected_by_real_console_route(tmp_path):
    client, _ = _client(tmp_path, AgentIdentity.generate(label="local"))
    response = client.post(
        _BASE,
        content=b"{}",
        headers=[
            (b"authorization", b"Bearer \xff"),
            (b"content-type", b"application/json"),
        ],
    )
    assert response.status_code == 401


@pytest.mark.parametrize("expected", ["local", "local\u00ff", "local\ud800", ""])
def test_shared_console_bearer_check_handles_configured_text_without_type_errors(
    expected,
):
    from nth_dao.web.bearer import console_bearer_matches

    headers = [(b"authorization", b"Bearer local")]
    assert console_bearer_matches(headers, expected) is (expected == "local")
