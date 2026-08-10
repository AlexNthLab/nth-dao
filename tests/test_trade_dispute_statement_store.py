from __future__ import annotations

import copy
import hashlib
import multiprocessing
import os
from datetime import datetime, timezone

import pytest

import nth_dao.trade_rules as trade_rules_api
import nth_dao.trade_rules.dispute_statement_store as store_module
from nth_dao.identity import AgentID, AgentIdentity
from nth_dao.trade_rules.agreement_conformance import generate_vectors
from nth_dao.trade_rules.agreement_order import TradeOrder
from nth_dao.trade_rules.canonical import trade_canonical_json
from nth_dao.trade_rules.dispute_statement import (
    TradeDisputeStatement,
    TradeDisputeStatementRejected,
    create_trade_dispute_statement,
)
from nth_dao.trade_rules.dispute_statement_store import (
    TradeDisputeStatementStore,
    TradeDisputeStatementStoreCapacity,
    TradeDisputeStatementStoreError,
    _canonical_timestamp_micros,
)
from nth_dao.trade_rules.execution_receipt import TradeExecutionReceipt
from nth_dao.trade_rules.package_store import build_rule_package
from nth_dao.trade_rules.receipt_review import TradeReceiptReview


class _StaticPackageResolver:
    def __init__(self, package):
        self.package = package
        self.loads = 0

    def load(self, digest):
        self.loads += 1
        return self.package if digest == self.package.digest else None


def _package_resolver(vectors):
    package = vectors["rule_package"]
    resources = {
        item["digest"]: bytes.fromhex(item["bytes_hex"])
        for item in package["resources"]
    }
    return _StaticPackageResolver(build_rule_package(package["manifest"], resources))


def _artifacts(vectors, *, review=None):
    order = TradeOrder.from_dict(vectors["order"])
    receipt = TradeExecutionReceipt.from_dict(
        vectors["execution_receipt"],
        order=order,
    )
    verified_review = TradeReceiptReview.from_dict(
        review or vectors["disputed_receipt_review"],
        receipt=receipt,
        order=order,
    )
    return order, receipt, verified_review


def _statement_digest(document):
    return "sha256:" + hashlib.sha256(trade_canonical_json(document)).hexdigest()


def _maker_identity() -> AgentIdentity:
    from nacl.signing import SigningKey

    signing_key = SigningKey(
        hashlib.sha256(b"NTH Trade Agreement v1 maker public seed").digest()
    )
    verify_key = signing_key.verify_key.encode()
    return AgentIdentity(
        agent_id=AgentID.from_pubkey(verify_key.hex()),
        label="public-conformance-only",
        _signing_key=signing_key.encode(),
        _verify_key=verify_key,
    )


def _put_statement_process(root, statement, review, receipt, order, output):
    try:
        _stored, created = TradeDisputeStatementStore(root).put(
            statement,
            review=review,
            receipt=receipt,
            order=order,
        )
        output.put(("ok", created))
    except Exception as exc:  # pragma: no cover - asserted in parent process
        output.put(("error", f"{type(exc).__name__}: {exc}"))


@pytest.fixture(scope="module")
def dispute_vectors():
    return generate_vectors()


def test_dispute_statement_store_is_idempotent_and_paginated(
    tmp_path,
    dispute_vectors,
):
    order, receipt, review = _artifacts(dispute_vectors)
    resolver = _package_resolver(dispute_vectors)
    store = TradeDisputeStatementStore(tmp_path)
    assert store.workspace_root.is_absolute()
    main = dispute_vectors["trade_dispute_statement"]
    future = dispute_vectors["trade_dispute_statement_signed_negative_cases"][0][
        "document"
    ]

    stored, created = store.put(
        main,
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=resolver,
    )
    assert created is True
    assert resolver.loads == 1
    retry, created = store.put(
        main,
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=resolver,
    )
    assert created is False
    assert retry == stored
    assert resolver.loads == 2
    future_statement, created = store.put(
        future,
        review=review,
        receipt=receipt,
        order=order,
    )
    assert created is True

    resolver.loads = 0
    first = store.list_for_review(
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=resolver,
        limit=1,
    )
    assert first.statements == (stored,)
    assert first.next_cursor is not None
    assert first.next_cursor.endswith(first.statement_digests[0].removeprefix("sha256:"))
    assert resolver.loads == 1
    second = store.list_for_review(
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=resolver,
        limit=1,
        after=first.next_cursor,
    )
    assert second.statements == (future_statement,)
    assert second.next_cursor is None
    assert resolver.loads == 1
    assert (
        store.get(
            first.statement_digests[0],
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=resolver,
        )
        == stored
    )

    with pytest.raises(
        TradeDisputeStatementStoreError,
        match="cursor is not in this Review",
    ):
        unknown_cursor = first.next_cursor.rsplit(":", 1)[0] + ":" + ("f" * 64)
        store.list_for_review(
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=resolver,
            after=unknown_cursor,
        )

    empty_store = TradeDisputeStatementStore(tmp_path / "empty")
    with pytest.raises(
        TradeDisputeStatementStoreError,
        match="pagination snapshot changed; restart listing",
    ):
        empty_store.list_for_review(
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=resolver,
            after=first.next_cursor,
        )


def test_dispute_store_reuses_verified_index_headers_between_pages(
    tmp_path,
    dispute_vectors,
    monkeypatch,
):
    order, receipt, review = _artifacts(dispute_vectors)
    resolver = _package_resolver(dispute_vectors)
    store = TradeDisputeStatementStore(tmp_path)
    store.put(
        dispute_vectors["trade_dispute_statement"],
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=resolver,
    )
    store.put(
        dispute_vectors["trade_dispute_statement_signed_negative_cases"][0][
            "document"
        ],
        review=review,
        receipt=receipt,
        order=order,
    )
    real_decode = store._record_from_payload
    decodes = 0

    def counted_decode(path, payload):
        nonlocal decodes
        decodes += 1
        return real_decode(path, payload)

    monkeypatch.setattr(store, "_record_from_payload", counted_decode)
    store.list_for_review(
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=resolver,
        limit=1,
    )
    assert decodes == 3

    decodes = 0
    store.list_for_review(
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=resolver,
        limit=1,
    )
    assert decodes == 1


def test_dispute_store_cached_index_still_detects_retimestamped_tamper(
    tmp_path,
    dispute_vectors,
):
    order, receipt, review = _artifacts(dispute_vectors)
    resolver = _package_resolver(dispute_vectors)
    store = TradeDisputeStatementStore(tmp_path)
    statement, _created = store.put(
        dispute_vectors["trade_dispute_statement"],
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=resolver,
    )
    store.list_for_review(
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=resolver,
    )
    path = store._path(_statement_digest(statement.to_dict()))
    metadata = path.stat()
    payload = bytearray(path.read_bytes())
    proof_index = payload.index(b'"proof_value":"') + len(b'"proof_value":"')
    payload[proof_index] = ord("A") if payload[proof_index] != ord("A") else ord("B")
    path.write_bytes(bytes(payload))
    os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))

    with pytest.raises(
        TradeDisputeStatementStoreError,
        match="content digest mismatch",
    ):
        store.list_for_review(
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=resolver,
        )


def test_dispute_store_normalizes_selected_file_disappearance(
    tmp_path,
    dispute_vectors,
    monkeypatch,
):
    order, receipt, review = _artifacts(dispute_vectors)
    resolver = _package_resolver(dispute_vectors)
    store = TradeDisputeStatementStore(tmp_path)
    statement, _created = store.put(
        dispute_vectors["trade_dispute_statement"],
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=resolver,
    )
    path = store._path(_statement_digest(statement.to_dict()))
    real_read_record = store._read_record

    def remove_then_read(selected_path):
        selected_path.unlink()
        return real_read_record(selected_path)

    monkeypatch.setattr(store, "_read_record", remove_then_read)
    with pytest.raises(
        TradeDisputeStatementStoreError,
        match="changed during listing",
    ):
        store.list_for_review(
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=resolver,
        )
    assert not path.exists()


def test_dispute_store_cursor_rejects_late_insert_without_silent_omission(
    tmp_path,
    dispute_vectors,
):
    order, receipt, review = _artifacts(dispute_vectors)
    resolver = _package_resolver(dispute_vectors)
    store = TradeDisputeStatementStore(tmp_path)
    main = dispute_vectors["trade_dispute_statement"]
    later = dispute_vectors["trade_dispute_statement_signed_negative_cases"][0][
        "document"
    ]
    for statement in (main, later):
        store.put(
            statement,
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=resolver if statement is main else None,
        )
    first = store.list_for_review(
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=resolver,
        limit=1,
    )
    template = dispute_vectors["trade_dispute_statement"]
    late_old = create_trade_dispute_statement(
        _maker_identity(),
        review=review,
        receipt=receipt,
        order=order,
        statement_type=template["statement_type"],
        reason_codes=template["reason_codes"],
        claim=template["claim"],
        evidence=template["evidence"],
        rule_action=template["rule_action"],
        package_resolver=resolver,
        created_at="2026-08-01T02:03:00Z",
        now=datetime(2026, 8, 1, 2, 10, tzinfo=timezone.utc),
    )
    store.put(
        late_old,
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=resolver,
    )

    with pytest.raises(
        TradeDisputeStatementStoreError,
        match="pagination snapshot changed; restart listing",
    ):
        store.list_for_review(
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=resolver,
            limit=10,
            after=first.next_cursor,
        )


def test_dispute_store_requires_exact_context_and_package(
    tmp_path,
    dispute_vectors,
):
    order, receipt, review = _artifacts(dispute_vectors)
    resolver = _package_resolver(dispute_vectors)
    store = TradeDisputeStatementStore(tmp_path)
    statement, _created = store.put(
        dispute_vectors["trade_dispute_statement"],
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=resolver,
    )
    digest_value = _statement_digest(statement.to_dict())

    with pytest.raises(
        TradeDisputeStatementRejected,
        match="requires an exact-digest package_resolver",
    ):
        store.get(
            digest_value,
            review=review,
            receipt=receipt,
            order=order,
        )

    alternate_review = dispute_vectors["trade_dispute_statement_signed_negative_cases"][
        1
    ]["signed_review"]
    other_order, other_receipt, other_review = _artifacts(
        dispute_vectors,
        review=alternate_review,
    )
    assert (
        store.list_for_review(
            review=other_review,
            receipt=other_receipt,
            order=other_order,
            package_resolver=resolver,
        ).statements
        == ()
    )


def test_dispute_store_get_reads_only_the_requested_record(
    tmp_path,
    dispute_vectors,
    monkeypatch,
):
    order, receipt, review = _artifacts(dispute_vectors)
    resolver = _package_resolver(dispute_vectors)
    store = TradeDisputeStatementStore(tmp_path)
    main = dispute_vectors["trade_dispute_statement"]
    other = dispute_vectors["trade_dispute_statement_signed_negative_cases"][0][
        "document"
    ]
    stored, _created = store.put(
        main,
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=resolver,
    )
    store.put(other, review=review, receipt=receipt, order=order)
    requested_digest = _statement_digest(stored.to_dict())
    requested_path = store._path(requested_digest)
    real_read = store._read_record
    reads = []

    def tracked_read(path):
        reads.append(path)
        return real_read(path)

    monkeypatch.setattr(store, "_read_record", tracked_read)
    assert store.get(
        requested_digest,
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=resolver,
    ) == stored
    assert reads == [requested_path]


def test_dispute_store_rechecks_file_sizes_before_each_write(
    tmp_path,
    dispute_vectors,
):
    order, receipt, review = _artifacts(dispute_vectors)
    resolver = _package_resolver(dispute_vectors)
    main = dispute_vectors["trade_dispute_statement"]
    other = dispute_vectors["trade_dispute_statement_signed_negative_cases"][0][
        "document"
    ]
    max_bytes = len(trade_canonical_json(main)) + len(trade_canonical_json(other))
    store = TradeDisputeStatementStore(tmp_path, max_bytes=max_bytes)
    stored, _created = store.put(
        main,
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=resolver,
    )
    path = store._path(_statement_digest(stored.to_dict()))
    path.write_bytes(path.read_bytes() + (b" " * 100))

    with pytest.raises(TradeDisputeStatementStoreCapacity, match="max_bytes"):
        store.put(other, review=review, receipt=receipt, order=order)
    assert len(list(store.root.glob("*.json"))) == 1


def test_dispute_store_rejects_future_statement_before_persistence(
    tmp_path,
    dispute_vectors,
):
    order, receipt, review = _artifacts(dispute_vectors)
    future = dispute_vectors["trade_dispute_statement_signed_negative_cases"][0][
        "document"
    ]
    store = TradeDisputeStatementStore(tmp_path)

    with pytest.raises(
        TradeDisputeStatementRejected,
        match="too far in the future",
    ):
        store.put(
            future,
            review=review,
            receipt=receipt,
            order=order,
            at=datetime(2026, 8, 1, 2, 4, tzinfo=timezone.utc),
            clock_skew_seconds=0,
        )
    assert list(store.root.glob("*.json")) == []

    _statement, created = store.put(
        future,
        review=review,
        receipt=receipt,
        order=order,
        at=datetime(2026, 8, 1, 2, 10, tzinfo=timezone.utc),
        clock_skew_seconds=0,
    )
    assert created is True


def test_dispute_store_enforces_count_and_byte_capacity(
    tmp_path,
    dispute_vectors,
):
    order, receipt, review = _artifacts(dispute_vectors)
    resolver = _package_resolver(dispute_vectors)
    main = dispute_vectors["trade_dispute_statement"]
    future = dispute_vectors["trade_dispute_statement_signed_negative_cases"][0][
        "document"
    ]

    count_store = TradeDisputeStatementStore(
        tmp_path / "count",
        max_statements=1,
    )
    count_store.put(
        future,
        review=review,
        receipt=receipt,
        order=order,
    )
    with pytest.raises(
        TradeDisputeStatementStoreCapacity,
        match="max_statements",
    ):
        count_store.put(
            main,
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=resolver,
        )

    byte_store = TradeDisputeStatementStore(
        tmp_path / "bytes",
        max_bytes=len(trade_canonical_json(future)),
    )
    byte_store.put(
        future,
        review=review,
        receipt=receipt,
        order=order,
    )
    with pytest.raises(
        TradeDisputeStatementStoreCapacity,
        match="max_bytes",
    ):
        byte_store.put(
            main,
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=resolver,
        )


def test_dispute_store_fails_closed_on_tamper_and_unknown_files(
    tmp_path,
    dispute_vectors,
):
    order, receipt, review = _artifacts(dispute_vectors)
    future = dispute_vectors["trade_dispute_statement_signed_negative_cases"][0][
        "document"
    ]
    store = TradeDisputeStatementStore(tmp_path)
    statement, _created = store.put(
        future,
        review=review,
        receipt=receipt,
        order=order,
    )
    digest_value = _statement_digest(statement.to_dict())
    tampered = copy.deepcopy(future)
    tampered["reason_codes"] = ["executor.changed-claim"]
    store._path(digest_value).write_bytes(trade_canonical_json(tampered))
    with pytest.raises(
        TradeDisputeStatementStoreError,
        match="content digest mismatch",
    ):
        store.get(
            digest_value,
            review=review,
            receipt=receipt,
            order=order,
        )

    clean = TradeDisputeStatementStore(tmp_path / "unknown")
    clean.put(
        future,
        review=review,
        receipt=receipt,
        order=order,
    )
    (clean.root / "operator-note.txt").write_text("note", encoding="utf-8")
    with pytest.raises(
        TradeDisputeStatementStoreError,
        match="unknown file",
    ):
        clean.list_for_review(
            review=review,
            receipt=receipt,
            order=order,
        )


def test_dispute_store_reconciliation_only_removes_explicit_temp_residue(
    tmp_path,
    dispute_vectors,
):
    order, receipt, review = _artifacts(dispute_vectors)
    future = dispute_vectors["trade_dispute_statement_signed_negative_cases"][0][
        "document"
    ]
    store = TradeDisputeStatementStore(tmp_path)
    statement, _created = store.put(
        future,
        review=review,
        receipt=receipt,
        order=order,
    )
    digest_value = _statement_digest(statement.to_dict())
    temporary_name = ("a" * 64) + ".json.orphan.tmp"
    temporary = store.root / temporary_name
    temporary.write_bytes(b"partial")

    inspected = store.reconcile()
    assert inspected.temporary_paths == (temporary_name,)
    assert inspected.removed_temporary_paths == ()
    assert temporary.exists()
    assert (
        store.get(
            digest_value,
            review=review,
            receipt=receipt,
            order=order,
        )
        == statement
    )

    cleaned = store.reconcile(cleanup_temporary=True)
    assert cleaned.removed_temporary_paths == (temporary_name,)
    assert not temporary.exists()
    assert (
        store.get(
            digest_value,
            review=review,
            receipt=receipt,
            order=order,
        )
        == statement
    )

    unknown = store.root / "do-not-delete.txt"
    unknown.write_text("operator data", encoding="utf-8")
    unrelated_temp = store.root / "operator-notes.tmp"
    unrelated_temp.write_text("operator temp", encoding="utf-8")
    report = store.reconcile(cleanup_temporary=True)
    assert report.unknown_paths == (
        "do-not-delete.txt",
        "operator-notes.tmp",
    )
    assert unknown.exists()
    assert unrelated_temp.exists()

    nested = store.root / "foreign" / temporary_name
    nested.parent.mkdir()
    nested.write_bytes(b"operator data")
    nested_report = store.reconcile(cleanup_temporary=True)
    assert "foreign" in nested_report.unknown_paths
    assert f"foreign/{temporary_name}" in nested_report.unknown_paths
    assert nested.exists()


def test_dispute_store_classifies_non_object_json_as_corrupt(
    tmp_path,
    dispute_vectors,
):
    order, receipt, review = _artifacts(dispute_vectors)
    store = TradeDisputeStatementStore(tmp_path)
    store.root.mkdir(parents=True)
    payload = b"[]"
    digest_value = store._statement_digest(payload)
    store._path(digest_value).write_bytes(payload)

    with pytest.raises(
        TradeDisputeStatementStoreError,
        match="not canonical",
    ):
        store.get(
            digest_value,
            review=review,
            receipt=receipt,
            order=order,
        )
    assert store.reconcile().corrupt_paths == (
        digest_value.removeprefix("sha256:") + ".json",
    )


def test_dispute_store_bounds_reads_before_parsing(
    tmp_path,
    dispute_vectors,
    monkeypatch,
):
    order, receipt, review = _artifacts(dispute_vectors)
    store = TradeDisputeStatementStore(tmp_path)
    store.root.mkdir(parents=True)
    payload = b'{"a":1}'
    digest_value = store._statement_digest(payload)
    store._path(digest_value).write_bytes(payload)
    monkeypatch.setattr(store_module, "MAX_TRADE_JSON_BYTES", 4)

    with pytest.raises(
        TradeDisputeStatementStoreError,
        match="exceeds byte limit",
    ):
        store.get(
            digest_value,
            review=review,
            receipt=receipt,
            order=order,
        )
    assert store.reconcile().corrupt_paths == (
        digest_value.removeprefix("sha256:") + ".json",
    )


def test_dispute_store_rejects_linked_storage_entries(
    tmp_path,
    dispute_vectors,
):
    order, receipt, review = _artifacts(dispute_vectors)
    future = dispute_vectors["trade_dispute_statement_signed_negative_cases"][0][
        "document"
    ]
    store = TradeDisputeStatementStore(tmp_path)
    store.root.mkdir(parents=True)
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    link = store.root / (("a" * 64) + ".json")
    try:
        os.symlink(outside, link)
    except OSError:
        pytest.skip("symlink creation is unavailable on this platform")

    with pytest.raises(TradeDisputeStatementStoreError, match="links"):
        store.put(
            future,
            review=review,
            receipt=receipt,
            order=order,
        )


def test_dispute_store_exact_retry_is_cross_process_safe(
    tmp_path,
    dispute_vectors,
):
    future = dispute_vectors["trade_dispute_statement_signed_negative_cases"][0][
        "document"
    ]
    context = multiprocessing.get_context("spawn")
    output = context.Queue()
    processes = [
        context.Process(
            target=_put_statement_process,
            args=(
                str(tmp_path),
                future,
                dispute_vectors["disputed_receipt_review"],
                dispute_vectors["execution_receipt"],
                dispute_vectors["order"],
                output,
            ),
        )
        for _index in range(6)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=60)
        assert process.exitcode == 0
    results = [output.get(timeout=5) for _process in processes]
    assert all(result[0] == "ok" for result in results), results
    assert sum(result[1] for result in results) == 1
    assert len(list((tmp_path / "trade" / "dispute_statements_v1").glob("*.json"))) == 1


def test_dispute_statement_store_is_public_api():
    assert trade_rules_api.TradeDisputeStatementStore is (TradeDisputeStatementStore)
    assert trade_rules_api.TradeDisputeStatement is TradeDisputeStatement


def test_dispute_store_orders_canonical_timestamps_by_actual_microseconds():
    whole = _canonical_timestamp_micros("2026-08-01T02:04:00Z")
    fractional = _canonical_timestamp_micros("2026-08-01T02:04:00.000001Z")
    later = _canonical_timestamp_micros("2026-08-01T02:04:01Z")

    assert whole < fractional < later
    with pytest.raises(TradeDisputeStatementStoreError, match="created_at"):
        _canonical_timestamp_micros("2026-08-01T02:04:00.000000Z")
    with pytest.raises(TradeDisputeStatementStoreError, match="created_at"):
        _canonical_timestamp_micros("2026-02-30T02:04:00Z")
