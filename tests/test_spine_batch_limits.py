"""Batch byte admission must precede durable writes and unbounded copies."""

import tracemalloc
from pathlib import Path

import pytest

from nth_dao.canonical_json import canonical_json
from nth_dao.spine import SignedEventLog
import nth_dao.spine.log as log_module
from tools.generate_intent_envelope_vectors import _test_identity


def _log(path):
    return SignedEventLog(path, _test_identity("spine-batch-budget-v1"))


def _append(log, payloads):
    return log.append_unique_many("test.budget", payloads,
                                  unique_payload_fields=("id",), ts_ms=1)


def _cost(payloads, results):
    return (
        sum(len(canonical_json(payload)) for payload in payloads)
        + sum(len(SignedEventLog._encode_event(event)) + 1
              for event, created in results if created)
        + sum(len(SignedEventLog._encode_event(event)) for event, _ in results)
    )


@pytest.mark.parametrize("mode", ["new", "existing", "mixed", "duplicates"])
@pytest.mark.parametrize("text", ["x" * 100, "\u0080\U0001f680" * 100], ids=["ascii", "escaped"])
@pytest.mark.parametrize("delta", [0, -1])
def test_exact_batch_budget_boundary(tmp_path, monkeypatch, mode, text, delta):
    reference, subject = _log(tmp_path / "reference.jsonl"), _log(tmp_path / "subject.jsonl")
    payloads = ({"id": "one", "body": text}, {"id": "two", "body": text})
    if mode in ("existing", "mixed"):
        seed = payloads if mode == "existing" else payloads[:1]
        _append(reference, seed)
        _append(subject, seed)
    elif mode == "duplicates":
        payloads = (payloads[0], payloads[0], payloads[1])
    expected = _append(reference, payloads)
    budget = _cost(payloads, expected)
    monkeypatch.setattr(log_module, "MAX_SPINE_APPEND_BATCH_BYTES", budget + delta, raising=False)
    before = subject.storage_token()
    if delta < 0:
        with pytest.raises(ValueError, match="batch.*byte"):
            _append(subject, payloads)
        assert subject.storage_token() == before
        assert not subject._pending_path.exists()
    else:
        assert _append(subject, payloads) == expected
        retry = _append(subject, payloads)
        assert [event for event, _ in retry] == [event for event, _ in expected]
        assert all(not created for _, created in retry)
        assert subject.verify_chain() == (True, "ok")


def test_input_budget_stops_before_next_clone_or_later_payload(tmp_path, monkeypatch):
    log = _log(tmp_path / "input.jsonl")
    payload = {"id": "one", "body": "x" * 1024}
    monkeypatch.setattr(log_module, "MAX_SPINE_APPEND_BATCH_BYTES", len(canonical_json(payload)), raising=False)
    real_decode = log_module.json.loads
    decoded = []

    class MustNotRead(dict):
        def items(self):
            pytest.fail("input after the exceeded budget was traversed")

    def decode(data, *args, **kwargs):
        decoded.append(len(data))
        return real_decode(data, *args, **kwargs)

    def no_preparation(*_args, **_kwargs):
        pytest.fail("signing started before input byte admission")

    monkeypatch.setattr(log, "_prepare_append", no_preparation)
    monkeypatch.setattr(log_module.json, "loads", decode)
    with pytest.raises(ValueError, match="batch.*byte"):
        _append(log, (payload, payload, MustNotRead(id="unused")))
    assert decoded == [len(canonical_json(payload))]
    assert not log._path.exists() and not log._pending_path.exists()


def test_prepared_line_budget_rejects_before_result_copies(tmp_path, monkeypatch):
    reference, subject = _log(tmp_path / "reference.jsonl"), _log(tmp_path / "subject.jsonl")
    payloads = ({"id": "one"}, {"id": "two"})
    expected = _append(reference, payloads)
    budget = sum(len(canonical_json(payload)) for payload in payloads)
    budget += len(subject._encode_event(expected[0][0])) + 1
    monkeypatch.setattr(log_module, "MAX_SPINE_APPEND_BATCH_BYTES", budget, raising=False)

    def no_result(*_args):
        pytest.fail("result cloned after prepared bytes exceeded budget")

    monkeypatch.setattr(subject, "_snapshot_event", no_result)
    with pytest.raises(ValueError, match="batch.*byte"):
        _append(subject, payloads)
    assert not subject._path.exists() and not subject._pending_path.exists()


def test_duplicate_results_each_consume_budget_before_copy(tmp_path, monkeypatch):
    log = _log(tmp_path / "duplicate.jsonl")
    payload = {"id": "one", "body": "x" * 1024}
    existing = _append(log, (payload,))[0][0]
    budget = 2 * len(canonical_json(payload)) + len(log._encode_event(existing))
    monkeypatch.setattr(log_module, "MAX_SPINE_APPEND_BATCH_BYTES", budget, raising=False)
    real_snapshot, copied = log._snapshot_event, []

    def snapshot(event):
        copied.append(event.event_id)
        return real_snapshot(event)

    monkeypatch.setattr(log, "_snapshot_event", snapshot)
    before = log.storage_token()
    with pytest.raises(ValueError, match="batch.*byte"):
        _append(log, (payload, payload))
    assert copied == [existing.event_id]
    assert log.storage_token() == before


def test_repeated_large_inputs_have_bounded_preflight_allocation(tmp_path, monkeypatch):
    log = _log(tmp_path / "bounded.jsonl")
    body = "x" * 65536
    payloads = tuple({"id": str(i), "body": body} for i in range(1000))
    monkeypatch.setattr(log_module, "MAX_SPINE_APPEND_BATCH_BYTES", 256 * 1024, raising=False)
    tracemalloc.start()
    try:
        with pytest.raises(ValueError, match="batch.*byte"):
            _append(log, payloads)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    # Generous allocator headroom, but not a full 1000-payload clone.
    assert peak < 2 * 1024 * 1024
    assert not log._path.exists() and not log._pending_path.exists()


def test_batch_readback_uses_parts_and_bounded_reads(tmp_path, monkeypatch):
    log = _log(tmp_path / "chunked.jsonl")
    payloads = tuple({"id": str(i), "body": "x" * (600 * 1024)} for i in range(2))
    real_token, real_open = log._token_after_expected_append, Path.open
    requests = []

    class BoundedReader:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def fileno(self):
            return self.stream.fileno()

        def read(self, count=-1):
            requests.append(count)
            assert 0 <= count <= 1024 * 1024
            return self.stream.read(count)

    def open_stream(path, mode="r", *args, **kwargs):
        stream = real_open(path, mode, *args, **kwargs)
        return BoundedReader(stream) if path == log._path and mode == "rb" else stream

    def check_parts(token, parts):
        assert isinstance(parts, tuple)
        assert len(parts) == 4 and parts[1] == parts[3] == b"\n"
        with monkeypatch.context() as patch:
            patch.setattr(Path, "open", open_stream)
            return real_token(token, parts)

    monkeypatch.setattr(log, "_token_after_expected_append", check_parts)
    results = _append(log, payloads)
    assert all(created for _, created in results)
    assert requests and log._verified_cache_token == log.storage_token()
    assert log.verify_chain() == (True, "ok")


@pytest.mark.parametrize("tamper", ["prefix", "suffix", "newline", "extra"])
def test_chunked_readback_keeps_integrity_checks(tmp_path, monkeypatch, tamper):
    log = _log(tmp_path / "tamper.jsonl")
    _append(log, ({"id": "retained"},))
    real_readback = log._token_after_expected_append

    def corrupt(token, parts):
        raw = log._path.read_bytes()
        if tamper == "prefix":
            raw = raw.replace(b'retained', b'altered!')
        elif tamper == "suffix":
            raw = raw.replace(b'"two"', b'"bad"')
        elif tamper == "newline":
            raw = raw[:-1] + b" "
        else:
            raw += b"extra"
        log._path.write_bytes(raw)
        return real_readback(token, parts)

    monkeypatch.setattr(log, "_token_after_expected_append", corrupt)
    with pytest.raises(ValueError, match="prefix changed|bytes do not match"):
        _append(log, ({"id": "one"}, {"id": "two"}))
    assert log._verified_cache_token is None
