"""Public mutable event views must never become trusted cache storage."""

from copy import deepcopy

import pytest

from nth_dao.canonical_json import canonical_json
from nth_dao.spine import GENESIS_PREV, SignedEventLog, sign_event, verify_event
from nth_dao.util.io import atomic_write_bytes
from tools.generate_intent_envelope_vectors import _test_identity


@pytest.mark.parametrize("surface", [
    "append", "append_unique", "append_unique_many", "verified_snapshot",
    "verified_snapshot_with_token", "get_verified_event", "find_unique_event", "reconcile_append",
])
def test_returned_events_cannot_mutate_verified_cache(tmp_path, surface):
    log = SignedEventLog(tmp_path / "isolation.spine.jsonl", _test_identity("spine-isolation-v1"))
    payload = {"id": "example", "nested": {"labels": ["original"]}}
    if surface == "append_unique":
        exposed, _ = log.append_unique("test.observation", payload, unique_payload_fields=("id",), ts_ms=1)
    elif surface == "append_unique_many":
        exposed, _ = log.append_unique_many("test.observation", (payload,), unique_payload_fields=("id",), ts_ms=1)[0]
    else:
        exposed = log.append("test.observation", payload, ts_ms=1)
    expected = deepcopy(exposed.to_dict())
    if surface == "verified_snapshot":
        exposed = log.verified_snapshot()[0]
    elif surface == "verified_snapshot_with_token":
        exposed = log.verified_snapshot_with_token()[1][0]
    elif surface == "get_verified_event":
        exposed = log.get_verified_event(exposed.event_id)
    elif surface == "find_unique_event":
        exposed = log.find_unique_event("test.observation", payload_field="id", payload_value="example")
    elif surface == "reconcile_append":
        exposed = log.reconcile_append(exposed.event_id)
    exposed.type = "modified.observation"
    exposed.payload["nested"]["labels"].append("modified")
    current = log.verified_snapshot()[0]
    assert current.to_dict() == expected
    assert verify_event(current) == (True, "ok")
    retry, created = log.append_unique("test.observation", payload, unique_payload_fields=("id",), ts_ms=2)
    assert not created and retry.to_dict() == expected
    assert len(log.verified_snapshot()) == 1


@pytest.mark.parametrize("batch", [False, True])
def test_append_snapshots_nested_caller_payload(tmp_path, batch):
    log = SignedEventLog(tmp_path / "input.spine.jsonl", _test_identity("spine-isolation-v1"))
    payload = {"id": "example", "nested": {"labels": ["original"]}}
    if batch:
        event, _ = log.append_unique_many("test.observation", (payload,), unique_payload_fields=("id",), ts_ms=1)[0]
    else:
        event = log.append("test.observation", payload, ts_ms=1)
    expected = deepcopy(event.to_dict())
    payload["nested"]["labels"].append("modified-after-append")
    assert event.to_dict() == expected
    assert log.verified_snapshot()[0].to_dict() == expected


def _nested_payload(depth):
    value = {"label": "original"}
    for _ in range(depth):
        value = {"child": value}
    return {"id": "deep", "value": value}


@pytest.mark.parametrize("depth", [470, 496, 550, 750])
@pytest.mark.parametrize("batch", [False, True])
def test_valid_deep_payload_returns_success_after_commit(tmp_path, depth, batch):
    log = SignedEventLog(tmp_path / "deep.spine.jsonl", _test_identity("spine-isolation-v1"))
    payload = _nested_payload(depth)
    expected = canonical_json(payload)
    if batch:
        event, created = log.append_unique_many("test.observation", (payload,), unique_payload_fields=("id",), ts_ms=1)[0]
        assert created
        retry, created = log.append_unique_many("test.observation", (payload,), unique_payload_fields=("id",), ts_ms=2)[0]
        assert not created and retry.event_id == event.event_id
    else:
        event = log.append("test.observation", payload, ts_ms=1)
    assert canonical_json(event.payload) == expected
    assert verify_event(event) == (True, "ok")
    assert len(list(log.read_all())) == 1
    assert log.verify_chain() == (True, "ok")


@pytest.mark.parametrize("surface", [
    "verified_snapshot", "verified_snapshot_with_token", "get_verified_event",
    "find_unique_event", "reconcile_append", "append_unique",
])
@pytest.mark.parametrize("cache_enabled", [True, False])
def test_valid_deep_history_is_readable_and_detached(tmp_path, monkeypatch, surface, cache_enabled):
    if not cache_enabled:
        monkeypatch.setattr("nth_dao.spine.log.MAX_SPINE_VERIFIED_CACHE_BYTES", 0)
    identity = _test_identity("spine-isolation-v1")
    event = sign_event(seq=0, prev_hash=GENESIS_PREV, event_type="test.observation",
                       payload=_nested_payload(550), identity=identity, ts_ms=1)
    path = tmp_path / "history.spine.jsonl"
    atomic_write_bytes(path, SignedEventLog._encode_event(event) + b"\n")
    log = SignedEventLog(path, identity)
    assert log.verify_chain() == (True, "ok")
    if surface == "verified_snapshot":
        exposed = log.verified_snapshot()[0]
    elif surface == "verified_snapshot_with_token":
        exposed = log.verified_snapshot_with_token()[1][0]
    elif surface == "find_unique_event":
        exposed = log.find_unique_event("test.observation", payload_field="id", payload_value="deep")
    elif surface == "append_unique":
        exposed, created = log.append_unique("test.observation", event.payload, unique_payload_fields=("id",), ts_ms=2)
        assert not created
    else:
        exposed = getattr(log, surface)(event.event_id)
    assert canonical_json(exposed.to_dict()) == canonical_json(event.to_dict())
    leaf = exposed.payload["value"]
    for _ in range(550):
        leaf = leaf["child"]
    leaf["label"] = "modified"
    assert canonical_json(log.get_verified_event(event.event_id).to_dict()) == canonical_json(event.to_dict())


@pytest.mark.parametrize("batch", [False, True])
def test_output_snapshot_failure_happens_before_any_append(tmp_path, monkeypatch, batch):
    log = SignedEventLog(tmp_path / "prepare.spine.jsonl", _test_identity("spine-isolation-v1"))
    log.append("test.observation", {"id": "retained"}, ts_ms=1)
    before = log.storage_token()
    original = log._snapshot_event

    def fail(event):
        if event.payload["id"] == "fail":
            raise ValueError("cannot prepare detached result")
        return original(event)

    monkeypatch.setattr(log, "_snapshot_event", fail)
    with pytest.raises(ValueError, match="detached result"):
        if batch:
            log.append_unique_many("test.observation", ({"id": "new"}, {"id": "fail"}), unique_payload_fields=("id",), ts_ms=2)
        else:
            log.append("test.observation", {"id": "fail"}, ts_ms=2)
    assert log.storage_token() == before
    assert not log._pending_path.exists()
    assert len(list(log.read_all())) == 1


@pytest.mark.parametrize("invalid", ["cycle", "too-deep", "float", "oversize"])
@pytest.mark.parametrize("batch", [False, True])
def test_invalid_snapshot_cannot_partially_write(tmp_path, invalid, batch):
    log = SignedEventLog(tmp_path / "invalid.spine.jsonl", _test_identity("spine-isolation-v1"))
    payload = {"id": "invalid"}
    if invalid == "cycle":
        payload["value"] = payload
    elif invalid == "too-deep":
        payload["value"] = _nested_payload(2000)
    elif invalid == "float":
        payload["value"] = 1.0
    else:
        payload["value"] = "x" * (1024 * 1024)
    before = log.storage_token()
    with pytest.raises(ValueError):
        if batch:
            log.append_unique_many("test.observation", ({"id": "valid"}, payload), unique_payload_fields=("id",), ts_ms=1)
        else:
            log.append("test.observation", payload, ts_ms=1)
    assert log.storage_token() == before
    assert not log._pending_path.exists()


def test_wire_snapshot_does_not_trust_custom_deepcopy(tmp_path):
    class SharedList(list):
        def __deepcopy__(self, memo):
            return self

    log = SignedEventLog(tmp_path / "subclass.spine.jsonl", _test_identity("spine-isolation-v1"))
    values = SharedList(["original"])
    event = log.append("test.observation", {"values": values}, ts_ms=1)
    values.append("modified")
    assert event.payload == {"values": ["original"]}
    assert log.verified_snapshot()[0].payload == event.payload


@pytest.mark.parametrize("batch", [False, True])
def test_append_intent_size_is_validated_before_writing_any_record(tmp_path, monkeypatch, batch):
    log = SignedEventLog(tmp_path / "intent-size.spine.jsonl", _test_identity("spine-isolation-v1"))
    log.append("test.observation", {"id": "retained"}, ts_ms=1)
    before = log.storage_token()
    monkeypatch.setattr("nth_dao.spine.log.MAX_SPINE_APPEND_INTENT_BYTES", 1000)
    payload = {"id": "escaped", "value": "\u0080" * 150}
    with pytest.raises(ValueError, match="append intent exceeds byte limit"):
        if batch:
            log.append_unique_many("test.observation", ({"id": "valid"}, payload),
                                   unique_payload_fields=("id",), ts_ms=2)
        else:
            log.append("test.observation", payload, ts_ms=2)
    assert log.storage_token() == before
    assert not log._pending_path.exists()
