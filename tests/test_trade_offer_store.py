import hashlib
import json
import math
import multiprocessing
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import pytest

from nth_dao.identity import AgentIdentity, crypto_available
from nth_dao.canonical_json import canonical_json
from nth_dao.trade_rules import (
    offer_body,
    offer_digest,
    sign_offer,
)
from nth_dao.trade_rules.store import (
    MAX_STORED_LINE_BYTES,
    OfferStore,
    OfferStoreBusyError,
    OfferStoreCapacityError,
    OfferStoreCorruptionError,
    OfferStoreCryptoUnavailableError,
    OfferStoreError,
    OfferStoreValidationError,
)

pytestmark = pytest.mark.skipif(
    not crypto_available(), reason="Trade Offer signatures require PyNaCl"
)


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _leg(leg_id: str = "work") -> dict[str, str]:
    return {
        "leg_id": leg_id,
        "resource_type": "service",
        "resource_id": "urn:nthdao:test:work",
        "quantity": "1",
        "unit": "job",
        "descriptor_digest": _digest(b"work descriptor"),
    }


def _offer(
    identity: AgentIdentity,
    *,
    offer_id: str = "org.nthdao.test/store",
    revision: int = 1,
    previous_offer_digest: str | None = None,
    state: str = "active",
    day: int = 29,
):
    published_at = f"2026-07-{day:02d}T00:00:00Z"
    body = offer_body(
        offer_id=offer_id,
        revision=revision,
        previous_offer_digest=previous_offer_digest,
        state=state,
        publisher_did=identity.as_did(),
        title=f"Offer revision {revision}",
        summary="Signed store test.",
        provides=[_leg()],
        requests=[],
        rule_refs=[],
        published_at=published_at,
        not_after=f"2027-07-{day:02d}T00:00:00Z",
    )
    return sign_offer(
        identity,
        body,
        created=f"2026-07-{day:02d}T00:00:01Z",
    )


def _publish_in_process(root, document, result_queue):
    try:
        result = OfferStore(root).publish(document)
        result_queue.put(("ok", result.appended))
    except Exception as exc:  # pragma: no cover - reported to the parent process
        result_queue.put(("error", f"{type(exc).__name__}: {exc}"))


def test_publish_get_poll_and_idempotent_duplicate(tmp_path):
    store = OfferStore(tmp_path)
    identity = AgentIdentity.generate()
    offer = _offer(identity)

    first = store.publish(offer)
    duplicate = store.publish(offer.to_dict())

    assert first.appended is True
    assert first.classification == "canonical"
    assert duplicate.appended is False
    assert duplicate.classification == "duplicate"
    assert store.latest_seq() == 0
    assert store.get(first.digest).canonical_bytes == offer.canonical_bytes
    page = store.poll()
    assert [record.digest for record in page.records] == [first.digest]
    assert page.cursor == 0


def test_offer_log_binds_local_import_provenance(tmp_path):
    store = OfferStore(tmp_path)
    identity = AgentIdentity.generate()
    offer = _offer(identity)

    result = store.publish(
        offer,
        source_kind="federation-peer",
        source_id="did:key:zPeerHint",
        received_at_ms=123,
    )
    record = store.poll().records[0]

    assert record.entry_hash == result.entry_hash
    assert record.received_at_ms == 123
    assert record.source_kind == "federation-peer"
    assert record.source_id == "did:key:zPeerHint"


def test_revision_chain_projects_canonical_head_and_activity(tmp_path):
    store = OfferStore(tmp_path)
    identity = AgentIdentity.generate()
    first = _offer(identity)
    second = _offer(
        identity,
        revision=2,
        previous_offer_digest=offer_digest(first),
        day=30,
    )
    withdrawn = _offer(
        identity,
        revision=3,
        previous_offer_digest=offer_digest(second),
        state="withdrawn",
        day=31,
    )

    for offer in (first, second, withdrawn):
        result = store.publish(offer)
        assert result.classification == "canonical"

    view = store.chain(identity.as_did(), first.offer_id)
    assert view.canonical_digests == (
        offer_digest(first),
        offer_digest(second),
        offer_digest(withdrawn),
    )
    assert view.canonical_head_digest == offer_digest(withdrawn)
    assert store.canonical_head(
        identity.as_did(), first.offer_id
    ).canonical_bytes == withdrawn.canonical_bytes
    assert (
        store.canonical_head(
            identity.as_did(),
            first.offer_id,
            active_only=True,
            at=datetime(2026, 8, 1, tzinfo=timezone.utc),
        )
        is None
    )


def test_out_of_order_successor_is_incomplete_then_self_heals(tmp_path):
    store = OfferStore(tmp_path)
    identity = AgentIdentity.generate()
    first = _offer(identity)
    second = _offer(
        identity,
        revision=2,
        previous_offer_digest=offer_digest(first),
        day=30,
    )

    orphan = store.publish(second)
    assert orphan.classification == "incomplete"
    assert orphan.chain.orphan_digests == (offer_digest(second),)

    repaired = store.publish(first)
    assert repaired.classification == "canonical"
    assert repaired.chain.canonical_head_digest == offer_digest(second)


def test_competing_roots_are_retained_and_never_promoted(tmp_path):
    store = OfferStore(tmp_path)
    identity = AgentIdentity.generate()
    first = _offer(identity)
    competing = _offer(identity, day=30)

    store.publish(first)
    conflict = store.publish(competing)

    assert conflict.classification == "forked"
    assert set(conflict.chain.fork_digests) == {
        offer_digest(first),
        offer_digest(competing),
    }
    assert conflict.chain.canonical_head_digest is None
    assert store.get(offer_digest(first)) is not None
    assert store.get(offer_digest(competing)) is not None


def test_competing_successors_are_retained_as_fork(tmp_path):
    store = OfferStore(tmp_path)
    identity = AgentIdentity.generate()
    first = _offer(identity)
    second_a = _offer(
        identity,
        revision=2,
        previous_offer_digest=offer_digest(first),
        day=30,
    )
    second_b = _offer(
        identity,
        revision=2,
        previous_offer_digest=offer_digest(first),
        day=31,
    )

    for offer in (first, second_a, second_b):
        result = store.publish(offer)

    assert result.classification == "forked"
    assert set(result.chain.fork_digests) == {
        offer_digest(second_a),
        offer_digest(second_b),
    }
    assert result.chain.canonical_head_digest is None


def test_fork_marks_all_descendants_as_conflicted(tmp_path):
    store = OfferStore(tmp_path)
    identity = AgentIdentity.generate()
    first = _offer(identity)
    second_a = _offer(
        identity,
        revision=2,
        previous_offer_digest=offer_digest(first),
        day=30,
    )
    second_b = _offer(
        identity,
        revision=2,
        previous_offer_digest=offer_digest(first),
        day=31,
    )
    third_a = _offer(
        identity,
        revision=3,
        previous_offer_digest=offer_digest(second_a),
        day=31,
    )

    for offer in (first, second_a, second_b, third_a):
        result = store.publish(offer)

    assert result.classification == "forked"
    assert set(result.chain.fork_digests) == {
        offer_digest(second_a),
        offer_digest(second_b),
        offer_digest(third_a),
    }


def test_known_invalid_successor_is_retained_but_not_promoted(tmp_path):
    store = OfferStore(tmp_path)
    identity = AgentIdentity.generate()
    first = _offer(identity)
    withdrawn = _offer(
        identity,
        revision=2,
        previous_offer_digest=offer_digest(first),
        state="withdrawn",
        day=30,
    )
    revival = _offer(
        identity,
        revision=3,
        previous_offer_digest=offer_digest(withdrawn),
        day=31,
    )

    store.publish(first)
    store.publish(withdrawn)
    result = store.publish(revival)

    assert result.classification == "invalid"
    assert result.chain.invalid_digests == (offer_digest(revival),)
    assert result.chain.canonical_head_digest is None
    assert store.get(offer_digest(revival)) is not None


def test_invalid_signature_is_rejected_without_writing(tmp_path):
    store = OfferStore(tmp_path)
    identity = AgentIdentity.generate()
    document = _offer(identity).to_dict()
    document["title"] = "tampered"

    with pytest.raises(OfferStoreValidationError, match="signature"):
        store.publish(document)

    assert store.latest_seq() == -1


def test_corrupt_line_blocks_projection_and_new_writes(tmp_path):
    store = OfferStore(tmp_path)
    store.log_path.parent.mkdir(parents=True, exist_ok=True)
    store.log_path.write_bytes(b"{not-json}\n")
    identity = AgentIdentity.generate()

    with pytest.raises(OfferStoreCorruptionError, match="line 0"):
        store.poll()
    with pytest.raises(OfferStoreCorruptionError, match="line 0"):
        store.publish(_offer(identity))
    assert store.log_path.read_bytes() == b"{not-json}\n"


def test_duplicate_digest_in_log_is_an_integrity_failure(tmp_path):
    store = OfferStore(tmp_path)
    identity = AgentIdentity.generate()
    offer = _offer(identity)
    store.publish(offer)
    first_record = store.poll().records[0]
    duplicate_entry = store._entry_document(
        seq=1,
        previous_entry_hash=first_record.entry_hash,
        offer=offer,
        received_at_ms=1,
        source_kind="test",
        source_id="test-suite",
    )
    with store.log_path.open("ab") as stream:
        stream.write(canonical_json(duplicate_entry) + b"\n")

    with pytest.raises(OfferStoreCorruptionError, match="duplicates digest"):
        store.list_chains()


def test_checkpoint_detects_tail_rollback_that_would_revive_offer(tmp_path):
    store = OfferStore(tmp_path)
    identity = AgentIdentity.generate()
    first = _offer(identity)
    withdrawn = _offer(
        identity,
        revision=2,
        previous_offer_digest=offer_digest(first),
        state="withdrawn",
        day=30,
    )
    store.publish(first)
    store.publish(withdrawn)
    assert store.canonical_head(
        identity.as_did(), first.offer_id
    ).to_dict()["state"] == "withdrawn"

    lines = store.log_path.read_bytes().splitlines(keepends=True)
    store.log_path.write_bytes(lines[0])

    with pytest.raises(OfferStoreCorruptionError, match="truncated"):
        store.canonical_head(identity.as_did(), first.offer_id)


def test_existing_log_without_checkpoint_fails_closed(tmp_path):
    store = OfferStore(tmp_path)
    identity = AgentIdentity.generate()
    store.publish(_offer(identity))
    store.checkpoint_path.unlink()

    with pytest.raises(OfferStoreCorruptionError, match="checkpoint is missing"):
        store.list_chains()


def test_valid_fsynced_tail_rolls_checkpoint_forward_after_crash(tmp_path):
    store = OfferStore(tmp_path)
    identity = AgentIdentity.generate()
    first = _offer(identity)
    second = _offer(
        identity,
        revision=2,
        previous_offer_digest=offer_digest(first),
        day=30,
    )
    store.publish(first)
    first_record = store.poll().records[0]
    second_entry = store._entry_document(
        seq=1,
        previous_entry_hash=first_record.entry_hash,
        offer=second,
        received_at_ms=2,
        source_kind="test",
        source_id="test-suite",
    )
    store._append_locked(second_entry)

    recovered = OfferStore(tmp_path)
    view = recovered.chain(identity.as_did(), first.offer_id)

    assert view.status == "canonical"
    assert view.canonical_head_digest == offer_digest(second)
    checkpoint = json.loads(recovered.checkpoint_path.read_text("utf-8"))
    assert checkpoint["seq"] == 1
    assert checkpoint["entry_hash"] == second_entry["entry_hash"]


def test_poll_limit_does_not_skip_unreturned_records(tmp_path):
    store = OfferStore(tmp_path)
    identity = AgentIdentity.generate()
    digests = []
    for index in range(3):
        offer = _offer(
            identity,
            offer_id=f"org.nthdao.test/store-{index}",
        )
        digests.append(store.publish(offer).digest)

    first = store.poll(limit=2)
    second = store.poll(since_seq=first.cursor, limit=2)

    assert [record.digest for record in first.records] == digests[:2]
    assert [record.digest for record in second.records] == digests[2:]
    assert second.cursor == 2


def test_concurrent_duplicate_publish_appends_once(tmp_path):
    store = OfferStore(tmp_path)
    identity = AgentIdentity.generate()
    document = _offer(identity).to_dict()

    def publish_once(_):
        return OfferStore(tmp_path).publish(document)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(publish_once, range(16)))

    assert sum(result.appended for result in results) == 1
    assert store.latest_seq() == 0
    assert len(store.poll().records) == 1


def test_cross_process_duplicate_publish_appends_once(tmp_path):
    identity = AgentIdentity.generate()
    document = _offer(identity).to_dict()
    context = multiprocessing.get_context("spawn")
    result_queue = context.Queue()
    processes = [
        context.Process(
            target=_publish_in_process,
            args=(str(tmp_path), document, result_queue),
        )
        for _ in range(6)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=20)
        assert process.exitcode == 0

    results = [result_queue.get(timeout=5) for _ in processes]
    assert all(status == "ok" for status, _ in results), results
    assert sum(appended for _, appended in results) == 1
    store = OfferStore(tmp_path)
    assert store.latest_seq() == 0
    assert len(store.poll().records) == 1


def test_capacity_is_enforced_without_partial_append(tmp_path):
    store = OfferStore(tmp_path, max_records=1)
    identity = AgentIdentity.generate()
    store.publish(_offer(identity, offer_id="org.nthdao.test/first"))

    with pytest.raises(OfferStoreCapacityError, match="max_records"):
        store.publish(_offer(identity, offer_id="org.nthdao.test/second"))

    assert store.latest_seq() == 0


def test_byte_capacity_is_enforced_before_append(tmp_path):
    store = OfferStore(tmp_path, max_bytes=MAX_STORED_LINE_BYTES)
    identity = AgentIdentity.generate()
    store.publish(_offer(identity, offer_id="org.nthdao.test/first"))
    original = store.log_path.read_bytes()
    store.max_bytes = len(original)

    with pytest.raises(OfferStoreCapacityError, match="max_bytes"):
        store.publish(_offer(identity, offer_id="org.nthdao.test/second"))

    assert store.log_path.read_bytes() == original


def test_repeated_reads_reuse_verified_projection_cache(tmp_path):
    store = OfferStore(tmp_path)
    identity = AgentIdentity.generate()
    store.publish(_offer(identity))

    first = store.list_chains()
    second = store.list_chains()

    assert first is second


def test_external_log_change_invalidates_hot_cache(tmp_path):
    store = OfferStore(tmp_path)
    identity = AgentIdentity.generate()
    store.publish(_offer(identity))
    assert store.list_chains()
    with store.log_path.open("ab") as stream:
        stream.write(b"{broken}\n")

    with pytest.raises(OfferStoreCorruptionError):
        store.list_chains()


def test_get_rejects_noncanonical_digest(tmp_path):
    store = OfferStore(tmp_path)
    with pytest.raises(ValueError, match="sha256"):
        store.get("../identity.json")


def test_offer_rejected_type_is_not_accidentally_swallowed(tmp_path):
    store = OfferStore(tmp_path)
    with pytest.raises(TypeError, match="TradeOffer"):
        store.publish("not-an-offer")  # type: ignore[arg-type]


def test_forged_trade_offer_wrapper_is_reverified(tmp_path):
    store = OfferStore(tmp_path)
    forged = type("_Forged", (), {})()
    with pytest.raises(TypeError):
        store.publish(forged)  # type: ignore[arg-type]

    actual_forged = object.__new__(
        __import__(
            "nth_dao.trade_rules.offer", fromlist=["TradeOffer"]
        ).TradeOffer
    )
    object.__setattr__(actual_forged, "_canonical", b"{}")
    with pytest.raises(OfferStoreError):
        store.publish(actual_forged)


@pytest.mark.parametrize("value", [True, False, math.nan, math.inf, -math.inf])
def test_lock_timeout_rejects_non_finite_or_boolean_values(tmp_path, value):
    with pytest.raises(ValueError, match="finite positive"):
        OfferStore(tmp_path, lock_timeout=value)


def test_crypto_unavailable_is_not_reported_as_corruption(
    tmp_path, monkeypatch
):
    import nth_dao.trade_rules.signing as signing

    store = OfferStore(tmp_path)
    identity = AgentIdentity.generate()
    offer = _offer(identity)
    store.publish(offer)
    monkeypatch.setattr(signing, "_VerifyKey", None)

    restarted = OfferStore(tmp_path)
    with pytest.raises(OfferStoreCryptoUnavailableError, match="PyNaCl"):
        restarted.list_chains()
    with pytest.raises(OfferStoreCryptoUnavailableError, match="PyNaCl"):
        OfferStore(tmp_path / "other").publish(offer.to_dict())


def test_lock_contention_has_a_typed_busy_error(tmp_path):
    from nth_dao.util.io import InterProcessLock

    store = OfferStore(tmp_path, lock_timeout=0.05)
    store.publish(_offer(AgentIdentity.generate()))
    with InterProcessLock(store.lock_path, timeout=1):
        with pytest.raises(OfferStoreBusyError, match="busy"):
            store.list_chains()


def test_empty_store_reads_do_not_create_runtime_directories(tmp_path):
    workspace = tmp_path / "read-only-view"
    store = OfferStore(workspace)

    assert store.list_chains() == ()
    assert store.latest_seq() == -1
    assert not (workspace / "trade").exists()


def test_publish_rejects_unencodable_or_out_of_range_provenance(tmp_path):
    store = OfferStore(tmp_path)
    offer = _offer(AgentIdentity.generate())

    with pytest.raises(OfferStoreValidationError, match="source_id"):
        store.publish(offer, source_id="\ud800")
    with pytest.raises(OfferStoreValidationError, match="received_at_ms"):
        store.publish(offer, received_at_ms=1 << 63)

    assert store.latest_seq() == -1


def test_checkpoint_creation_failure_is_reported_as_store_error(
    tmp_path, monkeypatch
):
    import nth_dao.trade_rules.store as store_module

    store = OfferStore(tmp_path)
    monkeypatch.setattr(
        store_module.tempfile,
        "mkstemp",
        lambda **_kwargs: (_ for _ in ()).throw(OSError("read-only")),
    )

    with pytest.raises(OfferStoreError, match="checkpoint durability"):
        store.publish(_offer(AgentIdentity.generate()))


def test_fsynced_append_recovers_after_checkpoint_update_failure(
    tmp_path, monkeypatch
):
    store = OfferStore(tmp_path)
    real_write = store._write_checkpoint_locked

    def fail_committed_checkpoint(*, seq, entry_hash):
        if seq >= 0:
            raise OfferStoreError("injected checkpoint failure")
        return real_write(seq=seq, entry_hash=entry_hash)

    monkeypatch.setattr(store, "_write_checkpoint_locked", fail_committed_checkpoint)
    with pytest.raises(OfferStoreError, match="injected checkpoint"):
        store.publish(_offer(AgentIdentity.generate()))

    restarted = OfferStore(tmp_path)
    records = restarted.poll().records
    assert len(records) == 1
    assert restarted.latest_seq() == 0


def test_signed_import_anchors_bind_sequence_hash_and_offer_digest(tmp_path):
    store = OfferStore(tmp_path)
    identity = AgentIdentity.generate()
    offer = _offer(identity)
    result = store.publish(
        offer,
        source_kind="local-operator",
        source_id=identity.as_did(),
    )
    anchor = {
        "seq": result.seq,
        "entry_hash": result.entry_hash,
        "offer_digest": result.digest,
        "publisher_did": offer.publisher_did,
        "offer_id": offer.offer_id,
        "source_kind": "local-operator",
        "source_id": identity.as_did(),
    }

    assert store.verify_import_anchors([anchor]) == (True, "ok")
    forged = {**anchor, "entry_hash": "sha256:" + ("f" * 64)}
    ok, why = store.verify_import_anchors([forged])
    assert ok is False
    assert "mismatch" in why
