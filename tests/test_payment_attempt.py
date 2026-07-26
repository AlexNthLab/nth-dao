"""Adversarial tests for durable external payment work records."""

from __future__ import annotations

import json
import multiprocessing as mp
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from nth_dao.b64u import b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.commerce.payment_attempt import (
    STATE_BLOCKED,
    STATE_INFLIGHT,
    STATE_ORPHANED,
    STATE_PENDING,
    STATE_SETTLED,
    EVENT_ORPHAN_RECONCILED,
    PaymentAttemptExecutor,
    PaymentAttemptEvent,
    PaymentAttemptReconciler,
    PaymentAttemptRejected,
    PaymentAttemptStore,
    PaymentExecutorConfig,
    payment_attempt_event_hash,
    verify_payment_attempt,
)
from nth_dao.commerce.payment_witness import (
    FilePaymentAttemptHeadWitness,
    PaymentWitnessRejected,
)
from nth_dao.commerce.settlement import (
    FakePaymentRail,
    RailReceipt,
    SettlementFailed,
    SettlementIntent,
    X402SettlementAdapter,
    settlement_idempotency_key,
)
from nth_dao.identity import AgentIdentity
from nth_dao.commerce.trade import (
    STATE_SETTLED as TRADE_SETTLED,
    VERDICT_PASS,
    TradeStore,
    open_trade,
    record_verification,
    submit_delivery,
    trade_state,
)

pytest.importorskip("nacl")


def _payment_claim_worker(
    root: str,
    identity_path: str,
    attempt_id: str,
    start_event,
    result_queue,
) -> None:
    try:
        actor = AgentIdentity.load(identity_path)
        store = PaymentAttemptStore(root)
        start_event.wait(timeout=10)
        view = store.claim(
            attempt_id,
            actor=actor,
            lease_ms=300_000,
            now_ms_override=2_000,
        )
        result_queue.put(("won" if view is not None else "lost", ""))
    except BaseException as exc:
        result_queue.put(("error", f"{type(exc).__name__}: {exc}"))


def _payment_claim_crash_before_commit_worker(
    root: str,
    identity_path: str,
    attempt_id: str,
) -> None:
    actor = AgentIdentity.load(identity_path)
    store = PaymentAttemptStore(root)
    append_anchor = store._append_anchor

    def crash_before_commit(anchor) -> None:
        if anchor.phase == "committed" and anchor.seq == 1:
            os._exit(17)
        append_anchor(anchor)

    store._append_anchor = crash_before_commit
    store.claim(
        attempt_id,
        actor=actor,
        lease_ms=300_000,
        now_ms_override=2_000,
    )


def _intent(
    payer: AgentIdentity,
    *,
    trade_id: str = "trade-1",
    payee: AgentIdentity | None = None,
) -> SettlementIntent:
    return SettlementIntent(
        trade_id=trade_id,
        amount_minor=25,
        currency="USDC",
        payee_did=(payee or AgentIdentity.generate(label="payee")).as_did(),
        payer_did=payer.as_did(),
        memo="invoice-1",
    )


def _rewrite_as_legacy(
    store: PaymentAttemptStore,
    attempt_id: str,
    actor: AgentIdentity,
    *,
    legacy_error: str = "",
) -> list[dict]:
    path = store._path(attempt_id)
    document = json.loads(path.read_text(encoding="utf-8"))
    legacy_events = []
    for raw in document["events"]:
        legacy = json.loads(json.dumps(raw))
        legacy.pop("prev_event_hash")
        if legacy_error and legacy["type"] in {
            "payment_attempt_retry_scheduled",
            "payment_attempt_blocked",
        }:
            legacy["payload"]["error"] = legacy_error
            legacy["payload"].pop("error_code", None)
        legacy["signature"] = b64u_encode(
            actor.sign(
                canonical_json({
                    key: value
                    for key, value in legacy.items()
                    if key != "signature"
                })
            )
        )
        legacy_events.append(legacy)
    store._anchor_path(attempt_id).unlink()
    path.write_text(
        json.dumps({"attempt_id": attempt_id, "events": legacy_events}),
        encoding="utf-8",
    )
    return legacy_events


def _verified_trade(
    root,
    *,
    payer: AgentIdentity,
    payee: AgentIdentity,
    intent: SettlementIntent,
) -> TradeStore:
    verifier = AgentIdentity.generate(label="verifier")
    store = TradeStore(root)
    claim = {
        "announcement_id": intent.trade_id,
        "claimant_did": payee.as_did(),
        "publisher_did": payer.as_did(),
        "receipt_id": "receipt-1",
    }
    open_trade(
        store,
        authority=payer,
        claim_record=claim,
        verifier_did=verifier.as_did(),
        settler_did=payer.as_did(),
        terms={
            "amount_minor": intent.amount_minor,
            "currency": intent.currency,
            "payee_did": intent.payee_did,
        },
        now_ms_override=100,
    )
    submit_delivery(
        store,
        intent.trade_id,
        claimant=payee,
        delivery={"artifact_sha256": "abc", "execution_receipt_id": "receipt-1"},
        now_ms_override=200,
    )
    record_verification(
        store,
        intent.trade_id,
        verifier=verifier,
        verdict=VERDICT_PASS,
        result={"checks": "ok"},
        now_ms_override=300,
    )
    return store


def test_create_is_signed_idempotent_and_survives_restart(tmp_path) -> None:
    payer = AgentIdentity.generate(label="payer")
    intent = _intent(payer)
    store = PaymentAttemptStore(tmp_path)

    first = store.create(actor=payer, intent=intent, now_ms_override=1_000)
    second = store.create(actor=payer, intent=intent, now_ms_override=2_000)
    restarted = PaymentAttemptStore(tmp_path).get(first.attempt_id)

    assert second == first
    assert restarted == first
    assert first.attempt_id == settlement_idempotency_key(intent)
    assert first.state == STATE_PENDING
    events = store.get_events(first.attempt_id)
    assert events is not None and len(events) == 1
    assert verify_payment_attempt(events) == (True, "ok")


def test_create_rejects_non_payer_actor(tmp_path) -> None:
    payer = AgentIdentity.generate(label="payer")
    intruder = AgentIdentity.generate(label="intruder")
    with pytest.raises(PaymentAttemptRejected, match="payer DID"):
        PaymentAttemptStore(tmp_path).create(actor=intruder, intent=_intent(payer))


def test_verify_payment_attempt_preflights_large_in_memory_tree() -> None:
    oversized = [{"payload": [0] * 65_537}]
    assert verify_payment_attempt(oversized) == (
        False,
        "payment attempt exceeds JSON resource limits",
    )


def test_verify_payment_attempt_preflights_cycles_without_recursion() -> None:
    cyclic = []
    cyclic.append(cyclic)
    assert verify_payment_attempt(cyclic) == (
        False,
        "payment attempt exceeds JSON resource limits",
    )


def test_executor_rejects_adapter_id_lookalike(tmp_path) -> None:
    payer = AgentIdentity.generate(label="payer")

    class LookalikeAdapter:
        adapter_id = "x402-testnet"

        def settle(self, _intent):
            raise AssertionError("lookalike adapter must never execute")

    with pytest.raises(ValueError, match="exact X402SettlementAdapter"):
        PaymentAttemptExecutor(
            PaymentAttemptStore(tmp_path),
            TradeStore(tmp_path),
            actor=payer,
            adapter=LookalikeAdapter(),  # type: ignore[arg-type]
        )


def test_tampered_persisted_event_is_not_returned_as_state(tmp_path) -> None:
    payer = AgentIdentity.generate(label="payer")
    store = PaymentAttemptStore(tmp_path)
    view = store.create(actor=payer, intent=_intent(payer), now_ms_override=1_000)
    path = store._path(view.attempt_id)
    document = json.loads(path.read_text(encoding="utf-8"))
    document["events"][0]["payload"]["intent"]["amount_minor"] = 1
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(PaymentAttemptRejected, match="stored payment attempt"):
        store.get(view.attempt_id)


def test_outer_id_mismatch_and_oversized_file_fail_closed(tmp_path) -> None:
    payer = AgentIdentity.generate(label="payer")
    store = PaymentAttemptStore(tmp_path)
    view = store.create(actor=payer, intent=_intent(payer), now_ms_override=1_000)
    path = store._path(view.attempt_id)
    original = path.read_text(encoding="utf-8")
    document = json.loads(original)
    document["attempt_id"] = "nth-settlement:v1:sha256:" + "0" * 64
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(PaymentAttemptRejected, match="invalid shape"):
        store.get(view.attempt_id)

    path.write_text(" " * (1024 * 1024 + 1), encoding="utf-8")
    with pytest.raises(PaymentAttemptRejected, match="size limit"):
        store.get(view.attempt_id)


def test_invalid_utf8_and_oversized_head_journal_fail_closed(tmp_path) -> None:
    payer = AgentIdentity.generate(label="payer")
    store = PaymentAttemptStore(tmp_path)
    view = store.create(actor=payer, intent=_intent(payer), now_ms_override=1_000)
    path = store._path(view.attempt_id)
    path.write_bytes(b"\xff")
    with pytest.raises(PaymentAttemptRejected, match="unreadable"):
        store.get(view.attempt_id)

    store = PaymentAttemptStore(tmp_path / "head")
    view = store.create(actor=payer, intent=_intent(payer), now_ms_override=1_000)
    store._anchor_path(view.attempt_id).write_bytes(b"x" * (1024 * 1024 + 1))
    with pytest.raises(PaymentAttemptRejected, match="head journal exceeds"):
        store.get(view.attempt_id)


def test_legacy_attempt_migration_reverifies_and_reanchors(tmp_path) -> None:
    payer = AgentIdentity.generate(label="payer")
    store = PaymentAttemptStore(tmp_path)
    created = store.create(actor=payer, intent=_intent(payer), now_ms_override=1_000)
    _rewrite_as_legacy(store, created.attempt_id, payer)

    with pytest.raises(PaymentAttemptRejected, match="invalid shape"):
        store.get(created.attempt_id)
    migrated = store.migrate_legacy(created.attempt_id, actor=payer)

    assert migrated == created
    restarted = PaymentAttemptStore(tmp_path).get(created.attempt_id)
    assert restarted == created
    document = json.loads(store._path(created.attempt_id).read_text(encoding="utf-8"))
    assert set(document) == {"attempt_id", "events", "head_hash"}
    assert document["events"][0]["prev_event_hash"] == ""
    assert store._anchor_path(created.attempt_id).read_text(encoding="utf-8")


def test_legacy_attempt_migration_rejects_tampered_signature(tmp_path) -> None:
    payer = AgentIdentity.generate(label="payer")
    store = PaymentAttemptStore(tmp_path)
    created = store.create(actor=payer, intent=_intent(payer), now_ms_override=1_000)
    legacy = _rewrite_as_legacy(store, created.attempt_id, payer)
    legacy[0]["payload"]["intent"]["amount_minor"] = 1
    store._path(created.attempt_id).write_text(
        json.dumps({"attempt_id": created.attempt_id, "events": legacy}),
        encoding="utf-8",
    )

    with pytest.raises(PaymentAttemptRejected, match="signature invalid"):
        store.migrate_legacy(created.attempt_id, actor=payer)


def test_legacy_attempt_migration_rejects_wrong_actor(tmp_path) -> None:
    payer = AgentIdentity.generate(label="payer")
    intruder = AgentIdentity.generate(label="intruder")
    store = PaymentAttemptStore(tmp_path)
    created = store.create(actor=payer, intent=_intent(payer), now_ms_override=1_000)
    _rewrite_as_legacy(store, created.attempt_id, payer)

    with pytest.raises(PaymentAttemptRejected, match="actor, id, or sequence"):
        store.migrate_legacy(created.attempt_id, actor=intruder)


def test_current_attempt_missing_journal_cannot_be_blessed_as_migration(
    tmp_path,
) -> None:
    payer = AgentIdentity.generate(label="payer")
    store = PaymentAttemptStore(tmp_path)
    created = store.create(actor=payer, intent=_intent(payer), now_ms_override=1_000)
    store._anchor_path(created.attempt_id).unlink()

    with pytest.raises(PaymentAttemptRejected, match="no signed head journal"):
        store.migrate_legacy(created.attempt_id, actor=payer)


def test_legacy_error_text_is_redacted_during_migration(tmp_path) -> None:
    payer = AgentIdentity.generate(label="payer")
    store = PaymentAttemptStore(tmp_path)
    created = store.create(actor=payer, intent=_intent(payer), now_ms_override=1_000)
    claimed = store.claim(
        created.attempt_id,
        actor=payer,
        lease_ms=1_000,
        now_ms_override=2_000,
    )
    assert claimed is not None
    store.schedule_retry(
        created.attempt_id,
        actor=payer,
        lease_id=claimed.lease_id,
        error_code="provider-unavailable",
        retry_after_ms=500,
        now_ms_override=2_100,
    )
    _rewrite_as_legacy(
        store,
        created.attempt_id,
        payer,
        legacy_error="token=LEGACY-SECRET private-wallet-file",
    )

    migrated = store.migrate_legacy(created.attempt_id, actor=payer)
    assert migrated.last_error == "legacy-retry-error"
    persisted = store._path(created.attempt_id).read_bytes()
    assert b"LEGACY-SECRET" not in persisted
    assert b"private-wallet-file" not in persisted


def test_legacy_migration_recovers_when_main_write_failed_after_prepare(
    tmp_path,
    monkeypatch,
) -> None:
    import nth_dao.commerce.payment_attempt as payment_attempt_module

    payer = AgentIdentity.generate(label="payer")
    store = PaymentAttemptStore(tmp_path)
    created = store.create(actor=payer, intent=_intent(payer), now_ms_override=1_000)
    _rewrite_as_legacy(store, created.attempt_id, payer)
    atomic_write = payment_attempt_module.atomic_write_json
    failed = False

    def fail_once(*args, **kwargs):
        nonlocal failed
        if not failed:
            failed = True
            raise OSError("simulated migration main-write failure")
        return atomic_write(*args, **kwargs)

    monkeypatch.setattr(payment_attempt_module, "atomic_write_json", fail_once)
    with pytest.raises(OSError, match="migration main-write failure"):
        store.migrate_legacy(created.attempt_id, actor=payer)

    monkeypatch.setattr(payment_attempt_module, "atomic_write_json", atomic_write)
    migrated = PaymentAttemptStore(tmp_path).migrate_legacy(
        created.attempt_id,
        actor=payer,
    )
    assert migrated == created
    assert PaymentAttemptStore(tmp_path).get(created.attempt_id) == created


def test_event_chain_and_head_journal_detect_main_file_rollback(tmp_path) -> None:
    payer = AgentIdentity.generate(label="payer")
    store = PaymentAttemptStore(tmp_path)
    created = store.create(actor=payer, intent=_intent(payer), now_ms_override=1_000)
    claimed = store.claim(
        created.attempt_id,
        actor=payer,
        lease_ms=1_000,
        now_ms_override=2_000,
    )
    assert claimed is not None
    store.schedule_retry(
        created.attempt_id,
        actor=payer,
        lease_id=claimed.lease_id,
        error_code="provider-unavailable",
        retry_after_ms=500,
        now_ms_override=2_100,
    )

    path = store._path(created.attempt_id)
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["events"][0]["prev_event_hash"] == ""
    assert document["events"][1]["prev_event_hash"] == payment_attempt_event_hash(
        document["events"][0]
    )
    assert document["head_hash"] == payment_attempt_event_hash(document["events"][-1])

    # Simulate an attacker restoring an older, internally valid main document.
    document["events"] = document["events"][:1]
    document["head_hash"] = payment_attempt_event_hash(document["events"][-1])
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(PaymentAttemptRejected, match="rolled back"):
        store.get(created.attempt_id)


def test_prepared_anchor_recovers_main_write_before_commit_anchor(
    tmp_path, monkeypatch
) -> None:
    payer = AgentIdentity.generate(label="payer")
    intent = _intent(payer)
    attempt_id = settlement_idempotency_key(intent)
    store = PaymentAttemptStore(tmp_path)
    append_anchor = store._append_anchor
    failed = False

    def fail_first_commit(anchor):
        nonlocal failed
        if anchor.phase == "committed" and not failed:
            failed = True
            raise OSError("simulated crash after main write")
        append_anchor(anchor)

    monkeypatch.setattr(store, "_append_anchor", fail_first_commit)
    with pytest.raises(OSError, match="after main write"):
        store.create(actor=payer, intent=intent, now_ms_override=1_000)

    recovered = PaymentAttemptStore(tmp_path).get(attempt_id)
    assert recovered is not None
    assert recovered.state == STATE_PENDING


def test_tampered_head_journal_signature_fails_closed(tmp_path) -> None:
    payer = AgentIdentity.generate(label="payer")
    store = PaymentAttemptStore(tmp_path)
    created = store.create(actor=payer, intent=_intent(payer), now_ms_override=1_000)
    path = store._anchor_path(created.attempt_id)
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    records[0]["signature"] = "A" * len(records[0]["signature"])
    path.write_text(
        "".join(json.dumps(record) + "\n" for record in records),
        encoding="utf-8",
    )

    with pytest.raises(PaymentAttemptRejected, match="signature"):
        store.get(created.attempt_id)


def test_claim_lease_blocks_early_takeover_and_allows_expired_takeover(tmp_path) -> None:
    payer = AgentIdentity.generate(label="payer")
    store = PaymentAttemptStore(tmp_path)
    created = store.create(actor=payer, intent=_intent(payer), now_ms_override=1_000)

    first = store.claim(
        created.attempt_id,
        actor=payer,
        lease_ms=1_000,
        now_ms_override=2_000,
    )
    assert first is not None and first.state == STATE_INFLIGHT
    assert store.claim(
        created.attempt_id,
        actor=payer,
        lease_ms=1_000,
        now_ms_override=2_999,
    ) is None
    takeover = store.claim(
        created.attempt_id,
        actor=payer,
        lease_ms=1_000,
        now_ms_override=3_000,
    )
    assert takeover is not None
    assert takeover.lease_id != first.lease_id
    assert takeover.attempts == 2


def test_run_pending_skips_busy_prefix_without_preclaiming_due_work(tmp_path) -> None:
    payer = AgentIdentity.generate(label="payer")
    payee = AgentIdentity.generate(label="payee")
    store = PaymentAttemptStore(tmp_path)
    attempts = [
        store.create(
            actor=payer,
            intent=_intent(payer, trade_id=f"trade-{index}", payee=payee),
            now_ms_override=1_000,
        )
        for index in range(26)
    ]
    ordered = sorted(attempts, key=lambda item: item.attempt_id)
    for view in ordered[:25]:
        assert store.claim(
            view.attempt_id,
            actor=payer,
            lease_ms=300_000,
            now_ms_override=2_000,
        ) is not None

    results = PaymentAttemptExecutor(
        store,
        TradeStore(tmp_path),
        actor=payer,
        adapter=X402SettlementAdapter(FakePaymentRail()),
        config=PaymentExecutorConfig(retry_jitter_percent=0),
    ).run_pending(
        limit=1,
        now_ms_override=2_500,
    )
    assert [view.attempt_id for view in results] == [ordered[25].attempt_id]
    assert results[0].state == STATE_PENDING
    assert results[0].last_error == "settlement-trade-not-found"


def test_verifier_rejects_signed_claim_before_retry_due_time(tmp_path) -> None:
    payer = AgentIdentity.generate(label="payer")
    store = PaymentAttemptStore(tmp_path)
    created = store.create(actor=payer, intent=_intent(payer), now_ms_override=1_000)
    claimed = store.claim(
        created.attempt_id,
        actor=payer,
        lease_ms=1_000,
        now_ms_override=2_000,
    )
    assert claimed is not None
    store.schedule_retry(
        created.attempt_id,
        actor=payer,
        lease_id=claimed.lease_id,
        error_code="provider-unavailable",
        retry_after_ms=2_000,
        now_ms_override=2_100,
    )
    events = store.get_events(created.attempt_id)
    assert events is not None
    forged = PaymentAttemptEvent(
        attempt_id=created.attempt_id,
        seq=len(events),
        type="payment_attempt_claimed",
        actor_did=payer.as_did(),
        prev_state=STATE_PENDING,
        new_state=STATE_INFLIGHT,
        payload={
            "lease_id": "a" * 32,
            "lease_expires_at_ms": 5_000,
        },
        prev_event_hash=payment_attempt_event_hash(events[-1]),
        created_at_ms=4_000,
    )
    forged.signature = b64u_encode(payer.sign(canonical_json(forged.signing_body())))

    ok, reason = verify_payment_attempt([*events, forged.to_dict()])
    assert ok is False
    assert "before retry became due" in reason


def test_retry_backoff_is_exponential_bounded_and_deterministic(tmp_path) -> None:
    payer = AgentIdentity.generate(label="payer")
    store = PaymentAttemptStore(tmp_path)
    created = store.create(actor=payer, intent=_intent(payer), now_ms_override=1_000)
    claimed = store.claim(
        created.attempt_id,
        actor=payer,
        lease_ms=1_000,
        now_ms_override=2_000,
    )
    assert claimed is not None
    executor = PaymentAttemptExecutor(
        store,
        TradeStore(tmp_path),
        actor=payer,
        adapter=X402SettlementAdapter(FakePaymentRail()),
        config=PaymentExecutorConfig(
            retry_after_ms=1_000,
            retry_max_ms=5_000,
            retry_jitter_percent=20,
        ),
    )

    first = executor._retry_delay_ms(claimed)
    assert first == executor._retry_delay_ms(claimed)
    assert 800 <= first <= 1_200
    second = executor._retry_delay_ms(replace(claimed, attempts=2))
    assert 1_600 <= second <= 2_400
    capped = executor._retry_delay_ms(replace(claimed, attempts=50))
    assert 4_000 <= capped <= 5_000


def test_stale_worker_cannot_finalize_after_lease_takeover(tmp_path) -> None:
    payer = AgentIdentity.generate(label="payer")
    intent = _intent(payer)
    store = PaymentAttemptStore(tmp_path)
    created = store.create(actor=payer, intent=intent, now_ms_override=1_000)
    first = store.claim(
        created.attempt_id,
        actor=payer,
        lease_ms=1_000,
        now_ms_override=2_000,
    )
    takeover = store.claim(
        created.attempt_id,
        actor=payer,
        lease_ms=1_000,
        now_ms_override=3_000,
    )
    assert first is not None and takeover is not None
    settlement = X402SettlementAdapter(FakePaymentRail()).settle(intent).to_payload()

    with pytest.raises(PaymentAttemptRejected, match="lease"):
        store.record_settled(
            created.attempt_id,
            actor=payer,
            lease_id=first.lease_id,
            settlement=settlement,
            now_ms_override=3_100,
        )
    settled = store.record_settled(
        created.attempt_id,
        actor=payer,
        lease_id=takeover.lease_id,
        settlement=settlement,
        now_ms_override=3_100,
    )
    assert settled.state == STATE_SETTLED
    assert settled.settlement["proof"]["idempotency_key"] == created.attempt_id


def test_retry_and_block_are_signed_state_transitions(tmp_path) -> None:
    payer = AgentIdentity.generate(label="payer")
    store = PaymentAttemptStore(tmp_path)
    created = store.create(actor=payer, intent=_intent(payer), now_ms_override=1_000)
    claimed = store.claim(
        created.attempt_id,
        actor=payer,
        lease_ms=1_000,
        now_ms_override=2_000,
    )
    assert claimed is not None
    pending = store.schedule_retry(
        created.attempt_id,
        actor=payer,
        lease_id=claimed.lease_id,
        error_code="provider-unavailable",
        retry_after_ms=2_000,
        now_ms_override=2_100,
    )
    assert pending.state == STATE_PENDING
    assert pending.next_attempt_at_ms == 4_100
    assert store.claim(
        created.attempt_id,
        actor=payer,
        now_ms_override=4_099,
    ) is None
    reclaimed = store.claim(
        created.attempt_id,
        actor=payer,
        now_ms_override=4_100,
    )
    assert reclaimed is not None
    blocked = store.block(
        created.attempt_id,
        actor=payer,
        lease_id=reclaimed.lease_id,
        error_code="permanent-provider-rejection",
        now_ms_override=4_200,
    )
    assert blocked.state == STATE_BLOCKED
    assert store.claim(
        created.attempt_id,
        actor=payer,
        now_ms_override=5_000,
    ) is None


def test_executor_settles_trade_and_attempt_once(tmp_path) -> None:
    payer = AgentIdentity.generate(label="payer")
    payee = AgentIdentity.generate(label="payee")
    intent = _intent(payer, payee=payee)
    trade_store = _verified_trade(tmp_path, payer=payer, payee=payee, intent=intent)
    attempts = PaymentAttemptStore(tmp_path)
    created = attempts.create(actor=payer, intent=intent, now_ms_override=1_000)
    rail = FakePaymentRail()
    executor = PaymentAttemptExecutor(
        attempts,
        trade_store,
        actor=payer,
        adapter=X402SettlementAdapter(rail),
    )

    result = executor.run_once(created.attempt_id, now_ms_override=2_000)

    assert result is not None and result.state == STATE_SETTLED
    assert trade_state(trade_store, intent.trade_id) == TRADE_SETTLED
    assert len(rail.calls) == 1
    assert result.settlement["proof"]["idempotency_key"] == created.attempt_id


def test_executor_recovers_unknown_outcome_after_restart_without_second_pay(
    tmp_path,
) -> None:
    payer = AgentIdentity.generate(label="payer")
    payee = AgentIdentity.generate(label="payee")
    intent = _intent(payer, payee=payee)
    trade_store = _verified_trade(tmp_path, payer=payer, payee=payee, intent=intent)
    attempts = PaymentAttemptStore(tmp_path)
    created = attempts.create(actor=payer, intent=intent, now_ms_override=1_000)
    rail = FakePaymentRail(fail_after_commit=True, root=tmp_path)
    config = PaymentExecutorConfig(
        lease_ms=1_000,
        retry_after_ms=500,
        retry_jitter_percent=0,
        max_attempts=3,
    )
    first_executor = PaymentAttemptExecutor(
        attempts,
        trade_store,
        actor=payer,
        adapter=X402SettlementAdapter(rail),
        config=config,
    )

    pending = first_executor.run_once(created.attempt_id, now_ms_override=2_000)
    assert pending is not None and pending.state == STATE_PENDING
    assert pending.next_attempt_at_ms == 2_500
    assert len(rail.calls) == 1

    restarted_rail = FakePaymentRail(root=tmp_path)
    restarted_executor = PaymentAttemptExecutor(
        PaymentAttemptStore(tmp_path),
        TradeStore(tmp_path),
        actor=payer,
        adapter=X402SettlementAdapter(restarted_rail),
        config=config,
    )
    settled = restarted_executor.run_once(created.attempt_id, now_ms_override=2_500)
    assert settled is not None and settled.state == STATE_SETTLED
    assert len(rail.calls) == 1
    assert restarted_rail.calls == []


def test_executor_blocks_deterministic_rail_rejection(tmp_path) -> None:
    payer = AgentIdentity.generate(label="payer")
    payee = AgentIdentity.generate(label="payee")
    intent = _intent(payer, payee=payee)
    trade_store = _verified_trade(tmp_path, payer=payer, payee=payee, intent=intent)
    attempts = PaymentAttemptStore(tmp_path)
    created = attempts.create(actor=payer, intent=intent, now_ms_override=1_000)
    executor = PaymentAttemptExecutor(
        attempts,
        trade_store,
        actor=payer,
        adapter=X402SettlementAdapter(FakePaymentRail(fail=True)),
    )

    blocked = executor.run_once(created.attempt_id, now_ms_override=2_000)
    assert blocked is not None and blocked.state == STATE_BLOCKED
    assert "rail-declined" in blocked.last_error


def test_malformed_committed_receipt_is_orphaned_without_second_pay(tmp_path) -> None:
    payer = AgentIdentity.generate(label="payer")
    payee = AgentIdentity.generate(label="payee")
    intent = _intent(payer, payee=payee)
    trade_store = _verified_trade(tmp_path, payer=payer, payee=payee, intent=intent)
    attempts = PaymentAttemptStore(tmp_path)
    created = attempts.create(actor=payer, intent=intent, now_ms_override=1_000)

    class MalformedCommittedRail:
        rail_id = "malformed"
        network = "eip155:84532"

        def __init__(self) -> None:
            self.calls = 0
            self.receipt = None

        def lookup(self, *, idempotency_key):
            return self.receipt

        def pay(self, **kwargs):
            self.calls += 1
            self.receipt = RailReceipt(
                tx_ref="provider:payment-123",
                status="confirmed",
                proof={},
                idempotency_key=kwargs["idempotency_key"],
            )
            return self.receipt

    rail = MalformedCommittedRail()
    executor = PaymentAttemptExecutor(
        attempts,
        trade_store,
        actor=payer,
        adapter=X402SettlementAdapter(rail),
    )

    orphaned = executor.run_once(created.attempt_id, now_ms_override=2_000)
    assert orphaned is not None and orphaned.state == STATE_ORPHANED
    assert orphaned.last_error == "settlement-proof-missing"
    assert orphaned.provider_reference == "provider:payment-123"
    assert orphaned.evidence_digest.startswith("sha256:")
    assert executor.run_once(created.attempt_id, now_ms_override=3_000) is None
    assert rail.calls == 1

    events = attempts.get_events(created.attempt_id)
    assert events is not None
    payload = events[-1]["payload"]
    assert len(payload["lease_id"]) == 32
    assert payload["error_code"] == "settlement-proof-missing"
    assert payload["provider_reference"] == "provider:payment-123"
    assert payload["evidence_digest"] == orphaned.evidence_digest


def test_provider_exception_details_are_not_persisted(tmp_path) -> None:
    payer = AgentIdentity.generate(label="payer")
    payee = AgentIdentity.generate(label="payee")
    intent = _intent(payer, payee=payee)
    trade_store = _verified_trade(tmp_path, payer=payer, payee=payee, intent=intent)
    attempts = PaymentAttemptStore(tmp_path)
    created = attempts.create(actor=payer, intent=intent, now_ms_override=1_000)

    class SecretFailingRail:
        rail_id = "secret-failing"
        network = "eip155:84532"

        def lookup(self, **_kwargs):
            raise RuntimeError(
                "token=SUPERSECRET source=private-wallet-file"
            )

        def pay(self, **_kwargs):
            raise AssertionError("pay must not run after lookup failure")

    result = PaymentAttemptExecutor(
        attempts,
        trade_store,
        actor=payer,
        adapter=X402SettlementAdapter(SecretFailingRail()),
    ).run_once(created.attempt_id, now_ms_override=2_000)

    assert result is not None and result.state == STATE_PENDING
    assert result.last_error == "runtime-error"
    persisted = b"".join(
        path.read_bytes()
        for path in (tmp_path / "commerce").rglob("*")
        if path.is_file()
    )
    assert b"SUPERSECRET" not in persisted
    assert b"private-wallet-file" not in persisted


def test_untrusted_orphan_metadata_is_normalized_before_persistence(tmp_path) -> None:
    payer = AgentIdentity.generate(label="payer")
    payee = AgentIdentity.generate(label="payee")
    intent = _intent(payer, payee=payee)
    trade_store = _verified_trade(tmp_path, payer=payer, payee=payee, intent=intent)
    attempts = PaymentAttemptStore(tmp_path)
    created = attempts.create(actor=payer, intent=intent, now_ms_override=1_000)

    class UntrustedFailureRail:
        rail_id = "untrusted-failure"
        network = "eip155:84532"

        def lookup(self, **_kwargs):
            raise SettlementFailed(
                "INVALID REASON",
                "token=DO-NOT-PERSIST",
                payment_may_have_committed=True,
                provider_reference="tx-ok\nforged-log-line",
                evidence_digest="not-a-digest",
            )

        def pay(self, **_kwargs):
            raise AssertionError("pay must not run after lookup failure")

    orphaned = PaymentAttemptExecutor(
        attempts,
        trade_store,
        actor=payer,
        adapter=X402SettlementAdapter(UntrustedFailureRail()),
    ).run_once(created.attempt_id, now_ms_override=2_000)
    assert orphaned is not None and orphaned.state == STATE_ORPHANED
    assert orphaned.last_error == "internal-error"
    assert orphaned.provider_reference == ""
    assert orphaned.evidence_digest.startswith("sha256:")
    persisted = b"".join(
        path.read_bytes()
        for path in (tmp_path / "commerce" / "payment_attempts").glob("*.json")
    )
    assert b"DO-NOT-PERSIST" not in persisted
    assert b"forged-log-line" not in persisted


def test_x402_control_character_tx_ref_is_an_orphan_signal() -> None:
    payer = AgentIdentity.generate(label="payer")
    intent = _intent(payer)

    class ControlCharacterRail:
        rail_id = "control-character"
        network = "eip155:84532"

        def lookup(self, *, idempotency_key):
            return RailReceipt(
                tx_ref="tx-ok\nforged-log-line",
                status="confirmed",
                proof={"settled": True},
                idempotency_key=idempotency_key,
            )

        def pay(self, **_kwargs):
            raise AssertionError("lookup already returned a receipt")

    with pytest.raises(SettlementFailed) as error:
        X402SettlementAdapter(ControlCharacterRail()).settle(intent)
    assert error.value.reason == "settlement-receipt-invalid"
    assert error.value.payment_may_have_committed is True
    assert error.value.provider_reference == ""


def test_executor_retries_when_attempt_arrives_before_federated_trade(tmp_path) -> None:
    payer = AgentIdentity.generate(label="payer")
    payee = AgentIdentity.generate(label="payee")
    intent = _intent(payer, payee=payee)
    trade_store = TradeStore(tmp_path)
    attempts = PaymentAttemptStore(tmp_path)
    created = attempts.create(actor=payer, intent=intent, now_ms_override=1_000)
    rail = FakePaymentRail()
    config = PaymentExecutorConfig(
        lease_ms=1_000,
        retry_after_ms=500,
        retry_jitter_percent=0,
        max_attempts=3,
    )
    executor = PaymentAttemptExecutor(
        attempts,
        trade_store,
        actor=payer,
        adapter=X402SettlementAdapter(rail),
        config=config,
    )

    waiting = executor.run_once(created.attempt_id, now_ms_override=2_000)
    assert waiting is not None and waiting.state == STATE_PENDING
    assert "settlement-trade-not-found" in waiting.last_error
    assert rail.calls == []

    _verified_trade(tmp_path, payer=payer, payee=payee, intent=intent)
    settled = executor.run_once(created.attempt_id, now_ms_override=2_500)
    assert settled is not None and settled.state == STATE_SETTLED
    assert len(rail.calls) == 1


def test_executor_reports_no_work_when_another_worker_holds_lease(tmp_path) -> None:
    payer = AgentIdentity.generate(label="payer")
    attempts = PaymentAttemptStore(tmp_path)
    created = attempts.create(actor=payer, intent=_intent(payer), now_ms_override=1_000)
    claimed = attempts.claim(
        created.attempt_id,
        actor=payer,
        lease_ms=1_000,
        now_ms_override=2_000,
    )
    assert claimed is not None
    executor = PaymentAttemptExecutor(
        attempts,
        TradeStore(tmp_path),
        actor=payer,
        adapter=X402SettlementAdapter(FakePaymentRail()),
    )
    assert executor.run_once(created.attempt_id, now_ms_override=2_500) is None


def test_executor_recovers_after_trade_write_but_attempt_write_crash(
    tmp_path, monkeypatch
) -> None:
    payer = AgentIdentity.generate(label="payer")
    payee = AgentIdentity.generate(label="payee")
    intent = _intent(payer, payee=payee)
    trade_store = _verified_trade(tmp_path, payer=payer, payee=payee, intent=intent)
    attempts = PaymentAttemptStore(tmp_path)
    created = attempts.create(actor=payer, intent=intent, now_ms_override=1_000)
    rail = FakePaymentRail()
    config = PaymentExecutorConfig(lease_ms=1_000, retry_after_ms=0, max_attempts=3)
    executor = PaymentAttemptExecutor(
        attempts,
        trade_store,
        actor=payer,
        adapter=X402SettlementAdapter(rail),
        config=config,
    )
    original_record_settled = attempts.record_settled
    should_fail = True

    def fail_once(*args, **kwargs):
        nonlocal should_fail
        if should_fail:
            should_fail = False
            raise OSError("simulated payment-attempt write crash")
        return original_record_settled(*args, **kwargs)

    monkeypatch.setattr(attempts, "record_settled", fail_once)
    with pytest.raises(OSError, match="payment-attempt write crash"):
        executor.run_once(created.attempt_id, now_ms_override=2_000)
    assert trade_state(trade_store, intent.trade_id) == TRADE_SETTLED
    assert len(rail.calls) == 1

    recovered = PaymentAttemptExecutor(
        PaymentAttemptStore(tmp_path),
        TradeStore(tmp_path),
        actor=payer,
        adapter=X402SettlementAdapter(rail),
        config=config,
    ).run_once(created.attempt_id, now_ms_override=3_000)
    assert recovered is not None and recovered.state == STATE_SETTLED
    assert len(rail.calls) == 1


def test_concurrent_executors_claim_one_payment_attempt(tmp_path) -> None:
    payer = AgentIdentity.generate(label="payer")
    payee = AgentIdentity.generate(label="payee")
    intent = _intent(payer, payee=payee)
    trade_store = _verified_trade(tmp_path, payer=payer, payee=payee, intent=intent)
    attempts = PaymentAttemptStore(tmp_path)
    created = attempts.create(actor=payer, intent=intent, now_ms_override=1_000)
    rail = FakePaymentRail()
    executor = PaymentAttemptExecutor(
        attempts,
        trade_store,
        actor=payer,
        adapter=X402SettlementAdapter(rail),
    )

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _: executor.run_once(created.attempt_id), range(2)))

    final = attempts.get(created.attempt_id)
    assert final is not None and final.state == STATE_SETTLED
    assert len(rail.calls) == 1


def test_exactly_one_payment_claim_wins_across_processes(tmp_path) -> None:
    payer = AgentIdentity.generate(label="payer")
    identity_path = tmp_path / "payer.identity.json"
    payer.save(identity_path)
    store = PaymentAttemptStore(tmp_path)
    created = store.create(actor=payer, intent=_intent(payer), now_ms_override=1_000)
    ctx = mp.get_context("spawn")
    start_event = ctx.Event()
    result_queue = ctx.Queue()
    processes = [
        ctx.Process(
            target=_payment_claim_worker,
            args=(
                str(tmp_path),
                str(identity_path),
                created.attempt_id,
                start_event,
                result_queue,
            ),
        )
        for _ in range(6)
    ]
    for process in processes:
        process.start()
    start_event.set()
    for process in processes:
        process.join(timeout=30)

    assert all(process.exitcode == 0 for process in processes)
    results = [result_queue.get(timeout=5) for _ in processes]
    assert [row[0] for row in results].count("won") == 1
    assert [row[0] for row in results].count("lost") == 5
    assert [row for row in results if row[0] == "error"] == []
    events = PaymentAttemptStore(tmp_path).get_events(created.attempt_id)
    assert events is not None and len(events) == 2
    assert verify_payment_attempt(events) == (True, "ok")


def test_process_crash_after_main_write_recovers_from_prepared_anchor(tmp_path) -> None:
    payer = AgentIdentity.generate(label="payer")
    identity_path = tmp_path / "payer.identity.json"
    payer.save(identity_path)
    store = PaymentAttemptStore(tmp_path)
    created = store.create(actor=payer, intent=_intent(payer), now_ms_override=1_000)
    ctx = mp.get_context("spawn")
    process = ctx.Process(
        target=_payment_claim_crash_before_commit_worker,
        args=(str(tmp_path), str(identity_path), created.attempt_id),
    )
    process.start()
    process.join(timeout=30)

    assert process.exitcode == 17
    recovered = PaymentAttemptStore(tmp_path).get(created.attempt_id)
    assert recovered is not None and recovered.state == STATE_INFLIGHT
    events = PaymentAttemptStore(tmp_path).get_events(created.attempt_id)
    assert events is not None and verify_payment_attempt(events) == (True, "ok")


class _RepairableCommittedRail:
    rail_id = "repairable"
    network = "eip155:84532"

    def __init__(self) -> None:
        self.pay_calls = 0
        self.lookup_calls = 0
        self.receipt = None

    def lookup(self, *, idempotency_key):
        self.lookup_calls += 1
        return self.receipt

    def pay(self, **kwargs):
        self.pay_calls += 1
        self.receipt = RailReceipt(
            tx_ref="provider:repairable-123",
            status="confirmed",
            proof={},
            idempotency_key=kwargs["idempotency_key"],
        )
        return self.receipt

    def repair(self, idempotency_key: str) -> None:
        self.receipt = RailReceipt(
            tx_ref="provider:repairable-123",
            status="confirmed",
            proof={"provider_status": "settled"},
            idempotency_key=idempotency_key,
        )


def _orphaned_payment(tmp_path):
    payer = AgentIdentity.generate(label="payer")
    payee = AgentIdentity.generate(label="payee")
    intent = _intent(payer, payee=payee)
    trade_store = _verified_trade(
        tmp_path,
        payer=payer,
        payee=payee,
        intent=intent,
    )
    attempts = PaymentAttemptStore(tmp_path)
    created = attempts.create(actor=payer, intent=intent, now_ms_override=1_000)
    rail = _RepairableCommittedRail()
    orphaned = PaymentAttemptExecutor(
        attempts,
        trade_store,
        actor=payer,
        adapter=X402SettlementAdapter(rail),
    ).run_once(created.attempt_id, now_ms_override=2_000)
    assert orphaned is not None and orphaned.state == STATE_ORPHANED
    return payer, intent, trade_store, attempts, orphaned, rail


def test_orphan_reconciliation_uses_lookup_only_and_settles_both_records(
    tmp_path,
) -> None:
    payer, intent, trade_store, attempts, orphaned, rail = _orphaned_payment(
        tmp_path
    )
    rail.repair(orphaned.attempt_id)

    settled = PaymentAttemptReconciler(
        attempts,
        trade_store,
        actor=payer,
        adapter=X402SettlementAdapter(rail),
    ).reconcile_once(orphaned.attempt_id, now_ms_override=3_000)

    assert settled.state == STATE_SETTLED
    assert trade_state(trade_store, intent.trade_id) == TRADE_SETTLED
    assert rail.pay_calls == 1
    assert settled.provider_reference == ""
    assert settled.evidence_digest == ""
    events = attempts.get_events(orphaned.attempt_id)
    assert events is not None
    assert events[-1]["type"] == EVENT_ORPHAN_RECONCILED
    assert (
        events[-1]["payload"]["orphan_evidence_digest"]
        == orphaned.evidence_digest
    )
    assert verify_payment_attempt(events) == (True, "ok")


def test_orphan_reconciliation_missing_receipt_never_pays(tmp_path) -> None:
    payer, _intent_value, trade_store, attempts, orphaned, rail = (
        _orphaned_payment(tmp_path)
    )
    rail.receipt = None

    with pytest.raises(
        SettlementFailed,
        match="settlement-receipt-not-found",
    ):
        PaymentAttemptReconciler(
            attempts,
            trade_store,
            actor=payer,
            adapter=X402SettlementAdapter(rail),
        ).reconcile_once(orphaned.attempt_id, now_ms_override=3_000)

    assert attempts.get(orphaned.attempt_id).state == STATE_ORPHANED
    assert rail.pay_calls == 1


def test_orphan_reconciliation_invalid_receipt_keeps_orphaned_state(
    tmp_path,
) -> None:
    payer, _intent_value, trade_store, attempts, orphaned, rail = (
        _orphaned_payment(tmp_path)
    )

    with pytest.raises(SettlementFailed, match="settlement-proof-missing"):
        PaymentAttemptReconciler(
            attempts,
            trade_store,
            actor=payer,
            adapter=X402SettlementAdapter(rail),
        ).reconcile_once(orphaned.attempt_id, now_ms_override=3_000)

    assert attempts.get(orphaned.attempt_id).state == STATE_ORPHANED
    assert rail.pay_calls == 1


def test_orphan_reconciliation_recovers_after_trade_write_crash(
    tmp_path,
    monkeypatch,
) -> None:
    payer, intent, trade_store, attempts, orphaned, rail = _orphaned_payment(
        tmp_path
    )
    rail.repair(orphaned.attempt_id)
    original_record_reconciled = attempts.record_reconciled

    def fail_after_trade_write(*_args, **_kwargs):
        raise OSError("simulated reconciliation write crash")

    monkeypatch.setattr(attempts, "record_reconciled", fail_after_trade_write)
    reconciler = PaymentAttemptReconciler(
        attempts,
        trade_store,
        actor=payer,
        adapter=X402SettlementAdapter(rail),
    )
    with pytest.raises(OSError, match="reconciliation write crash"):
        reconciler.reconcile_once(orphaned.attempt_id, now_ms_override=3_000)

    assert trade_state(trade_store, intent.trade_id) == TRADE_SETTLED
    assert attempts.get(orphaned.attempt_id).state == STATE_ORPHANED
    lookups_after_crash = rail.lookup_calls
    monkeypatch.setattr(attempts, "record_reconciled", original_record_reconciled)

    recovered = reconciler.reconcile_once(
        orphaned.attempt_id,
        now_ms_override=4_000,
    )
    assert recovered.state == STATE_SETTLED
    assert rail.lookup_calls == lookups_after_crash
    assert rail.pay_calls == 1


def test_concurrent_orphan_reconciliation_appends_one_recovery_event(
    tmp_path,
) -> None:
    payer, _intent_value, trade_store, attempts, orphaned, rail = (
        _orphaned_payment(tmp_path)
    )
    rail.repair(orphaned.attempt_id)
    reconcilers = [
        PaymentAttemptReconciler(
            PaymentAttemptStore(tmp_path),
            TradeStore(tmp_path),
            actor=payer,
            adapter=X402SettlementAdapter(rail),
        )
        for _ in range(2)
    ]

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda reconciler: reconciler.reconcile_once(
                    orphaned.attempt_id
                ),
                reconcilers,
            )
        )

    assert all(result.state == STATE_SETTLED for result in results)
    assert rail.pay_calls == 1
    events = attempts.get_events(orphaned.attempt_id)
    assert events is not None
    assert sum(
        event["type"] == EVENT_ORPHAN_RECONCILED for event in events
    ) == 1


def test_external_witness_survives_restart_and_validates_current_head(
    tmp_path,
) -> None:
    payer = AgentIdentity.generate(label="payer")
    witness_root = tmp_path / "independent-witness"
    store = PaymentAttemptStore(
        tmp_path / "workspace",
        witness=FilePaymentAttemptHeadWitness(witness_root),
    )
    created = store.create(
        actor=payer,
        intent=_intent(payer),
        now_ms_override=1_000,
    )

    restarted = PaymentAttemptStore(
        tmp_path / "workspace",
        witness=FilePaymentAttemptHeadWitness(witness_root),
    )
    assert restarted.get(created.attempt_id) == created


def test_external_witness_rejects_oversized_file_before_decoding(tmp_path) -> None:
    witness = FilePaymentAttemptHeadWitness(tmp_path / "independent-witness")
    attempt_id = "nth-settlement:v1:sha256:" + "a" * 64
    witness._path(attempt_id).write_bytes(b"x" * (1024 * 1024 + 1))

    with pytest.raises(PaymentWitnessRejected, match="size limit"):
        witness.read(attempt_id)


def test_file_witness_inside_workspace_is_rejected(tmp_path) -> None:
    workspace = tmp_path / "workspace"
    with pytest.raises(ValueError, match="outside the workspace"):
        PaymentAttemptStore(
            workspace,
            witness=FilePaymentAttemptHeadWitness(
                workspace / "commerce" / "witness"
            ),
        )


def test_external_witness_detects_joint_main_and_local_journal_rollback(
    tmp_path,
) -> None:
    payer = AgentIdentity.generate(label="payer")
    workspace = tmp_path / "workspace"
    witness = FilePaymentAttemptHeadWitness(tmp_path / "independent-witness")
    store = PaymentAttemptStore(workspace, witness=witness)
    created = store.create(
        actor=payer,
        intent=_intent(payer),
        now_ms_override=1_000,
    )
    main_path = store._path(created.attempt_id)
    anchor_path = store._anchor_path(created.attempt_id)
    old_main = main_path.read_bytes()
    old_anchors = anchor_path.read_bytes()
    claimed = store.claim(
        created.attempt_id,
        actor=payer,
        now_ms_override=2_000,
    )
    assert claimed is not None and claimed.state == STATE_INFLIGHT

    main_path.write_bytes(old_main)
    anchor_path.write_bytes(old_anchors)

    with pytest.raises(PaymentAttemptRejected, match="external witness"):
        PaymentAttemptStore(workspace, witness=witness).get(created.attempt_id)


def test_external_witness_rejects_tampered_signed_anchor(tmp_path) -> None:
    payer = AgentIdentity.generate(label="payer")
    workspace = tmp_path / "workspace"
    witness_root = tmp_path / "independent-witness"
    witness = FilePaymentAttemptHeadWitness(witness_root)
    store = PaymentAttemptStore(workspace, witness=witness)
    created = store.create(
        actor=payer,
        intent=_intent(payer),
        now_ms_override=1_000,
    )
    witness_path = witness._path(created.attempt_id)
    lines = witness_path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[-1])
    record["head_hash"] = "sha256:" + ("0" * 64)
    lines[-1] = json.dumps(record, separators=(",", ":"))
    witness_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(PaymentAttemptRejected, match="signature invalid"):
        PaymentAttemptStore(workspace, witness=witness).get(created.attempt_id)


def test_external_witness_commit_failure_keeps_prepared_recovery_head(
    tmp_path,
) -> None:
    payer = AgentIdentity.generate(label="payer")
    workspace = tmp_path / "workspace"
    durable = FilePaymentAttemptHeadWitness(tmp_path / "independent-witness")

    class FailCommittedWitness:
        def append(self, attempt_id, anchor):
            if anchor["phase"] == "committed":
                raise PaymentWitnessRejected("simulated witness outage")
            durable.append(attempt_id, anchor)

        def read(self, attempt_id):
            return durable.read(attempt_id)

    store = PaymentAttemptStore(workspace, witness=FailCommittedWitness())
    intent = _intent(payer)
    with pytest.raises(PaymentAttemptRejected, match="witness outage"):
        store.create(actor=payer, intent=intent, now_ms_override=1_000)

    attempt_id = settlement_idempotency_key(intent)
    recovered = PaymentAttemptStore(workspace, witness=durable).get(attempt_id)
    assert recovered is not None and recovered.state == STATE_PENDING


def test_external_witness_prepare_failure_does_not_write_main_document(
    tmp_path,
) -> None:
    payer = AgentIdentity.generate(label="payer")
    workspace = tmp_path / "workspace"

    class UnavailableWitness:
        def append(self, _attempt_id, _anchor):
            raise PaymentWitnessRejected("witness unavailable")

        def read(self, _attempt_id):
            raise PaymentWitnessRejected("witness unavailable")

    intent = _intent(payer)
    store = PaymentAttemptStore(workspace, witness=UnavailableWitness())
    with pytest.raises(PaymentAttemptRejected, match="witness unavailable"):
        store.create(actor=payer, intent=intent, now_ms_override=1_000)

    assert not store._path(settlement_idempotency_key(intent)).exists()


def test_complete_local_anchor_without_newline_is_not_lost_on_append(
    tmp_path,
) -> None:
    payer = AgentIdentity.generate(label="payer")
    store = PaymentAttemptStore(tmp_path)
    created = store.create(
        actor=payer,
        intent=_intent(payer),
        now_ms_override=1_000,
    )
    anchor_path = store._anchor_path(created.attempt_id)
    anchor_path.write_bytes(anchor_path.read_bytes().rstrip(b"\n"))

    claimed = store.claim(
        created.attempt_id,
        actor=payer,
        now_ms_override=2_000,
    )

    assert claimed is not None and claimed.state == STATE_INFLIGHT
    assert anchor_path.read_bytes().endswith(b"\n")
    assert PaymentAttemptStore(tmp_path).get(created.attempt_id) == claimed


def test_torn_local_anchor_fails_closed_instead_of_being_skipped(
    tmp_path,
) -> None:
    payer = AgentIdentity.generate(label="payer")
    store = PaymentAttemptStore(tmp_path)
    created = store.create(
        actor=payer,
        intent=_intent(payer),
        now_ms_override=1_000,
    )
    anchor_path = store._anchor_path(created.attempt_id)
    anchor_path.write_bytes(anchor_path.read_bytes() + b'{"phase":"pre')

    with pytest.raises(PaymentAttemptRejected, match="malformed"):
        store.get(created.attempt_id)
    with pytest.raises(PaymentAttemptRejected, match="malformed"):
        store.claim(
            created.attempt_id,
            actor=payer,
            now_ms_override=2_000,
        )
