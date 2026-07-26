"""CS4 测试 —— 结算 adapter（manual + x402 testnet）+ 结算校验。

退出门槛（CS4）：
  - manual 与 x402 两种 adapter 都能把"按约定付款"产出成可嵌进签名
    事件的结算记录；
  - x402 adapter 不持私钥、把付款委托给注入的 PaymentRail；rail 失败
    时不留半条结算；rail 不给 tx_ref 时拒绝记录"无凭据真钱"；
  - settle_trade 闭环：adapter 付款 → record_settlement → SETTLED，整链
    仍可 verify_trade；
  - verify_settlement 用 **trade 约定的金额/币种/收款方** 校验，挡下
    settler 改小金额白嫖（amount-mismatch）等攻击。
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from nth_dao.cap_token import sign_cap_token, CAP_NTH_RECEIPT_SIGN
from nth_dao.identity import AgentIdentity
from nth_dao.util.io import atomic_write_json
from nth_dao.market import (
    MarketFeed, ClaimStore, claim_announcement, sign_announcement,
)
from nth_dao.commerce import (
    TradeStore,
    open_trade,
    submit_delivery,
    record_verification,
    trade_state,
    verify_trade,
    verify_trade_binding,
    TradeRejected,
    TradeConflict,
    STATE_VERIFIED,
    STATE_SETTLED,
    VERDICT_PASS,
    # CS4
    SettlementIntent,
    ManualSettlementAdapter,
    X402SettlementAdapter,
    FakePaymentRail,
    RailReceipt,
    SettlementFailed,
    settlement_idempotency_key,
    settle_trade,
    settlement_payload,
    verify_settlement,
    ADAPTER_MANUAL,
    ADAPTER_X402_TESTNET,
    REJECT_AMOUNT_MISMATCH,
    REJECT_AMOUNT_INVALID,
    REJECT_CURRENCY_MISMATCH,
    REJECT_PAYEE_MISMATCH,
    REJECT_PAYER_MISMATCH,
    REJECT_UNKNOWN_ADAPTER,
    REJECT_TX_REF_MISSING,
    REJECT_NETWORK_MISSING,
    REJECT_NETWORK_NOT_TESTNET,
    REJECT_PROOF_MISSING,
    REJECT_RECEIPT_INVALID,
    REJECT_RECEIPT_NOT_CONFIRMED,
    REJECT_RECEIPT_TOO_LARGE,
    REJECT_IDEMPOTENCY_KEY_MISMATCH,
    REJECT_INTENT_INVALID,
    REJECT_SCHEMA_INVALID,
    REJECT_SETTLED_AT_INVALID,
)

pytest.importorskip("nacl")


def _rail_pay(rail, intent, key):
    return rail.pay(
        payee_did=intent.payee_did,
        amount_minor=intent.amount_minor,
        currency=intent.currency,
        memo=intent.memo,
        idempotency_key=key,
    )


def test_settlement_idempotency_key_binds_immutable_payment_terms() -> None:
    base = {
        "trade_id": "trade-1",
        "amount_minor": 15,
        "currency": "USDC",
        "payee_did": "did:key:zPayee",
        "payer_did": "did:key:zPayer",
        "memo": "invoice-1",
    }
    key = settlement_idempotency_key(SettlementIntent(**base))
    assert key == settlement_idempotency_key(SettlementIntent(**base))
    assert key.startswith("nth-settlement:v1:sha256:")
    assert len(key) == len("nth-settlement:v1:sha256:") + 64

    mutations = {
        "trade_id": "trade-2",
        "amount_minor": 16,
        "currency": "NTH-TEST",
        "payee_did": "did:key:zOtherPayee",
        "payer_did": "did:key:zOtherPayer",
    }
    for field, value in mutations.items():
        changed = dict(base)
        changed[field] = value
        assert settlement_idempotency_key(SettlementIntent(**changed)) != key

    changed_memo = dict(base)
    changed_memo["memo"] = "presentation-only-retry-note"
    assert settlement_idempotency_key(SettlementIntent(**changed_memo)) == key


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("trade_id", ""),
        ("trade_id", ["not", "text"]),
        ("currency", None),
        ("payee_did", 123),
        ("payee_did", "agent-without-did"),
        ("payee_did", "did:key:zPayee with-space"),
        ("payer_did", object()),
        ("memo", "x" * 2049),
    ],
)
def test_settlement_intent_rejects_unstable_text_fields(field, value) -> None:
    data = {
        "trade_id": "trade-1",
        "amount_minor": 15,
        "currency": "USDC",
        "payee_did": "did:key:zPayee",
        "payer_did": "did:key:zPayer",
        "memo": "invoice-1",
    }
    data[field] = value
    with pytest.raises(SettlementFailed) as error:
        settlement_idempotency_key(SettlementIntent(**data))
    assert error.value.reason == REJECT_INTENT_INVALID


def test_fake_rail_lookup_and_pay_are_idempotent() -> None:
    rail = FakePaymentRail()
    intent = SettlementIntent(
        trade_id="trade-1",
        amount_minor=15,
        currency="USDC",
        payee_did="did:key:zPayee",
        payer_did="did:key:zPayer",
    )
    key = settlement_idempotency_key(intent)
    assert rail.lookup(idempotency_key=key) is None
    first = _rail_pay(rail, intent, key)
    second = _rail_pay(rail, intent, key)
    assert second is first
    assert rail.lookup(idempotency_key=key) is first
    assert len(rail.calls) == 1


def test_fake_rail_exposes_receipt_after_commit_response_failure() -> None:
    rail = FakePaymentRail(fail_after_commit=True)
    intent = SettlementIntent(
        trade_id="trade-1",
        amount_minor=15,
        currency="USDC",
        payee_did="did:key:zPayee",
    )
    key = settlement_idempotency_key(intent)
    with pytest.raises(SettlementFailed, match="rail-outcome-unknown"):
        _rail_pay(rail, intent, key)
    receipt = rail.lookup(idempotency_key=key)
    assert receipt is not None
    assert receipt.idempotency_key == key
    assert len(rail.calls) == 1


def test_fake_rail_rejects_oversized_persisted_receipt_before_json_decode(
    tmp_path,
) -> None:
    rail = FakePaymentRail(root=tmp_path)
    intent = SettlementIntent(
        trade_id="trade-oversized-receipt",
        amount_minor=15,
        currency="USDC",
        payee_did="did:key:zPayee",
        payer_did="did:key:zPayer",
    )
    key = settlement_idempotency_key(intent)
    path = rail._path(key)
    with path.open("wb") as handle:
        handle.write(b"{" + b"x" * (128 * 1024) + b"}")

    with pytest.raises(SettlementFailed, match="too large"):
        rail.lookup(idempotency_key=key)


def _claim(ann_id, claimant, publisher):
    return {
        "announcement_id": ann_id,
        "claimant_did": claimant.as_did(),
        "publisher_did": publisher.as_did(),
        "receipt_id": "rcpt-" + ann_id,
    }


def _to_verified(store, ann_id, *, claimant, publisher, verifier, settler):
    """把一笔 trade 推到 VERIFIED（结算前置态）。"""
    open_trade(store, authority=publisher, claim_record=_claim(ann_id, claimant, publisher),
               verifier_did=verifier.as_did(), settler_did=settler.as_did())
    submit_delivery(store, ann_id, claimant=claimant,
                    delivery={"artifact_sha256": "abc", "execution_receipt_id": "x"})
    record_verification(store, ann_id, verifier=verifier, verdict=VERDICT_PASS,
                        result={"checks": "ok"})
    assert trade_state(store, ann_id) == STATE_VERIFIED


# ─── manual adapter ──────────────────────────────────────────────


def test_manual_adapter_settle_trade_to_settled(tmp_path) -> None:
    """manual adapter 经 settle_trade 闭环到 SETTLED，整链可验。"""
    store = TradeStore(tmp_path)
    pub = AgentIdentity.generate(label="pub")
    claimant = AgentIdentity.generate(label="worker")
    verifier = AgentIdentity.generate(label="ver")
    settler = AgentIdentity.generate(label="settler")
    _to_verified(store, "ann-1", claimant=claimant, publisher=pub,
                 verifier=verifier, settler=settler)

    intent = SettlementIntent(trade_id="ann-1", amount_minor=10,
                              currency="NTH-TEST", payee_did=claimant.as_did(),
                              payer_did=pub.as_did())
    settle_trade(store, "ann-1", settler=settler,
                 adapter=ManualSettlementAdapter(), intent=intent)
    assert trade_state(store, "ann-1") == STATE_SETTLED
    ok, reason = verify_trade(store, "ann-1")
    assert ok, reason


# ─── x402 adapter（注入 FakePaymentRail，无真钱）─────────────────


def test_x402_adapter_pays_via_rail_and_settles(tmp_path) -> None:
    """x402 adapter 把付款委托给 rail，结果带 tx_ref/network/proof，
    且 rail 收到的金额/收款方正确。"""
    store = TradeStore(tmp_path)
    pub = AgentIdentity.generate(label="pub")
    claimant = AgentIdentity.generate(label="worker")
    verifier = AgentIdentity.generate(label="ver")
    settler = AgentIdentity.generate(label="settler")
    _to_verified(store, "ann-2", claimant=claimant, publisher=pub,
                 verifier=verifier, settler=settler)

    rail = FakePaymentRail()
    intent = SettlementIntent(trade_id="ann-2", amount_minor=1_000_000,
                              currency="USDC", payee_did=claimant.as_did(),
                              payer_did=pub.as_did(), memo="ann-2")
    settle_trade(store, "ann-2", settler=settler,
                 adapter=X402SettlementAdapter(rail), intent=intent)

    assert trade_state(store, "ann-2") == STATE_SETTLED
    # rail 收到正确金额 + 收款方（adapter 没篡改意图）
    assert rail.calls == [{
        "payee_did": claimant.as_did(), "amount_minor": 1_000_000,
        "currency": "USDC", "memo": "ann-2",
    }]
    # 结算事件里带链上凭据
    events = store.get_events("ann-2")
    settle_ev = events[-1]
    s = settle_ev["payload"]["settlement"]
    assert s["adapter_id"] == ADAPTER_X402_TESTNET
    assert s["tx_ref"].startswith("fake:")
    assert s["network"] == "eip155:84532"
    assert s["proof"]["settled"] is True
    ok, reason = verify_trade(store, "ann-2")
    assert ok, reason


def test_x402_rail_failure_leaves_no_settlement(tmp_path) -> None:
    """rail 拒付 → SettlementFailed 上抛，trade 停在 VERIFIED（不留半条）。"""
    store = TradeStore(tmp_path)
    pub = AgentIdentity.generate(label="pub")
    claimant = AgentIdentity.generate(label="worker")
    verifier = AgentIdentity.generate(label="ver")
    settler = AgentIdentity.generate(label="settler")
    _to_verified(store, "ann-3", claimant=claimant, publisher=pub,
                 verifier=verifier, settler=settler)

    rail = FakePaymentRail(fail=True)
    intent = SettlementIntent(trade_id="ann-3", amount_minor=5,
                              currency="USDC", payee_did=claimant.as_did(),
                              payer_did=pub.as_did())
    with pytest.raises(SettlementFailed):
        settle_trade(store, "ann-3", settler=settler,
                     adapter=X402SettlementAdapter(rail), intent=intent)
    assert trade_state(store, "ann-3") == STATE_VERIFIED  # 未推进


def test_x402_retry_recovers_unknown_rail_outcome_without_second_pay(
    tmp_path,
) -> None:
    store = TradeStore(tmp_path)
    pub = AgentIdentity.generate(label="pub")
    claimant = AgentIdentity.generate(label="worker")
    verifier = AgentIdentity.generate(label="ver")
    settler = AgentIdentity.generate(label="settler")
    _to_verified(
        store,
        "ann-unknown",
        claimant=claimant,
        publisher=pub,
        verifier=verifier,
        settler=settler,
    )
    rail = FakePaymentRail(fail_after_commit=True)
    adapter = X402SettlementAdapter(rail)
    intent = SettlementIntent(
        trade_id="ann-unknown",
        amount_minor=25,
        currency="USDC",
        payee_did=claimant.as_did(),
        payer_did=pub.as_did(),
    )

    with pytest.raises(SettlementFailed, match="rail-outcome-unknown"):
        settle_trade(
            store,
            "ann-unknown",
            settler=settler,
            adapter=adapter,
            intent=intent,
        )
    assert trade_state(store, "ann-unknown") == STATE_VERIFIED
    assert len(rail.calls) == 1

    settle_trade(
        store,
        "ann-unknown",
        settler=settler,
        adapter=adapter,
        intent=intent,
    )
    assert trade_state(store, "ann-unknown") == STATE_SETTLED
    assert len(rail.calls) == 1


def test_x402_retry_after_local_record_failure_does_not_pay_twice(
    tmp_path, monkeypatch
) -> None:
    import nth_dao.commerce.trade as trade_module

    store = TradeStore(tmp_path)
    pub = AgentIdentity.generate(label="pub")
    claimant = AgentIdentity.generate(label="worker")
    verifier = AgentIdentity.generate(label="ver")
    settler = AgentIdentity.generate(label="settler")
    _to_verified(
        store,
        "ann-record-failure",
        claimant=claimant,
        publisher=pub,
        verifier=verifier,
        settler=settler,
    )
    rail = FakePaymentRail()
    adapter = X402SettlementAdapter(rail)
    intent = SettlementIntent(
        trade_id="ann-record-failure",
        amount_minor=25,
        currency="USDC",
        payee_did=claimant.as_did(),
        payer_did=pub.as_did(),
    )
    original_record = trade_module.record_settlement
    should_fail = True

    def flaky_record(*args, **kwargs):
        nonlocal should_fail
        if should_fail:
            should_fail = False
            raise OSError("simulated durable trade write failure")
        return original_record(*args, **kwargs)

    monkeypatch.setattr(trade_module, "record_settlement", flaky_record)
    with pytest.raises(OSError, match="durable trade write failure"):
        settle_trade(
            store,
            "ann-record-failure",
            settler=settler,
            adapter=adapter,
            intent=intent,
        )
    assert trade_state(store, "ann-record-failure") == STATE_VERIFIED
    assert len(rail.calls) == 1

    settle_trade(
        store,
        "ann-record-failure",
        settler=settler,
        adapter=adapter,
        intent=intent,
    )
    assert trade_state(store, "ann-record-failure") == STATE_SETTLED
    assert len(rail.calls) == 1


def test_x402_retry_after_durable_settlement_returns_existing_event(
    tmp_path,
) -> None:
    store = TradeStore(tmp_path)
    pub = AgentIdentity.generate(label="pub")
    claimant = AgentIdentity.generate(label="worker")
    verifier = AgentIdentity.generate(label="ver")
    settler = AgentIdentity.generate(label="settler")
    _to_verified(
        store,
        "ann-response-loss",
        claimant=claimant,
        publisher=pub,
        verifier=verifier,
        settler=settler,
    )
    rail = FakePaymentRail()
    adapter = X402SettlementAdapter(rail)
    intent = SettlementIntent(
        trade_id="ann-response-loss",
        amount_minor=25,
        currency="USDC",
        payee_did=claimant.as_did(),
        payer_did=pub.as_did(),
    )

    first = settle_trade(
        store,
        "ann-response-loss",
        settler=settler,
        adapter=adapter,
        intent=intent,
    )
    retry = settle_trade(
        store,
        "ann-response-loss",
        settler=settler,
        adapter=adapter,
        intent=intent,
    )
    assert retry.to_dict() == first.to_dict()
    assert len(rail.calls) == 1
    assert len(store.get_events("ann-response-loss") or []) == 4


def test_x402_settled_retry_with_changed_intent_fails_closed(tmp_path) -> None:
    store = TradeStore(tmp_path)
    pub = AgentIdentity.generate(label="pub")
    claimant = AgentIdentity.generate(label="worker")
    verifier = AgentIdentity.generate(label="ver")
    settler = AgentIdentity.generate(label="settler")
    _to_verified(
        store,
        "ann-conflicting-retry",
        claimant=claimant,
        publisher=pub,
        verifier=verifier,
        settler=settler,
    )
    rail = FakePaymentRail()
    adapter = X402SettlementAdapter(rail)
    intent = SettlementIntent(
        trade_id="ann-conflicting-retry",
        amount_minor=25,
        currency="USDC",
        payee_did=claimant.as_did(),
        payer_did=pub.as_did(),
    )
    settle_trade(
        store,
        "ann-conflicting-retry",
        settler=settler,
        adapter=adapter,
        intent=intent,
    )
    changed = SettlementIntent(
        trade_id="ann-conflicting-retry",
        amount_minor=26,
        currency="USDC",
        payee_did=claimant.as_did(),
        payer_did=pub.as_did(),
    )
    with pytest.raises(SettlementFailed) as error:
        settle_trade(
            store,
            "ann-conflicting-retry",
            settler=settler,
            adapter=adapter,
            intent=changed,
        )
    assert error.value.reason == "settlement-bad-state"
    assert len(rail.calls) == 1


def test_x402_concurrent_settlement_attempts_with_different_memos_pay_once(
    tmp_path,
) -> None:
    store = TradeStore(tmp_path)
    pub = AgentIdentity.generate(label="pub")
    claimant = AgentIdentity.generate(label="worker")
    verifier = AgentIdentity.generate(label="ver")
    settler = AgentIdentity.generate(label="settler")
    _to_verified(
        store,
        "ann-concurrent",
        claimant=claimant,
        publisher=pub,
        verifier=verifier,
        settler=settler,
    )
    rail = FakePaymentRail()
    adapter = X402SettlementAdapter(rail)
    intents = [
        SettlementIntent(
            trade_id="ann-concurrent",
            amount_minor=25,
            currency="USDC",
            payee_did=claimant.as_did(),
            payer_did=pub.as_did(),
            memo=memo,
        )
        for memo in ("first presentation note", "changed retry note")
    ]
    assert settlement_idempotency_key(intents[0]) == settlement_idempotency_key(
        intents[1]
    )

    def settle_once(intent):
        try:
            return settle_trade(
                store,
                "ann-concurrent",
                settler=settler,
                adapter=adapter,
                intent=intent,
            )
        except (TradeConflict, TradeRejected) as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(settle_once, intents))

    assert any(hasattr(outcome, "to_dict") for outcome in outcomes)
    assert len(rail.calls) == 1
    assert trade_state(store, "ann-concurrent") == STATE_SETTLED
    assert len(store.get_events("ann-concurrent") or []) == 4


@pytest.mark.parametrize("payer_did", ["", "did:key:zAttacker"])
def test_x402_rejects_unbound_payer_before_rail_io(tmp_path, payer_did) -> None:
    store = TradeStore(tmp_path)
    pub = AgentIdentity.generate(label="pub")
    claimant = AgentIdentity.generate(label="worker")
    verifier = AgentIdentity.generate(label="ver")
    settler = AgentIdentity.generate(label="settler")
    _to_verified(
        store,
        "ann-payer-binding",
        claimant=claimant,
        publisher=pub,
        verifier=verifier,
        settler=settler,
    )
    rail = FakePaymentRail()

    with pytest.raises(SettlementFailed) as error:
        settle_trade(
            store,
            "ann-payer-binding",
            settler=settler,
            adapter=X402SettlementAdapter(rail),
            intent=SettlementIntent(
                trade_id="ann-payer-binding",
                amount_minor=25,
                currency="USDC",
                payee_did=claimant.as_did(),
                payer_did=payer_did,
            ),
        )

    assert error.value.reason == REJECT_PAYER_MISMATCH
    assert rail.lookups == []
    assert rail.calls == []


def test_x402_empty_tx_ref_rejected(tmp_path) -> None:
    """rail 返回空 tx_ref（声称付了但无链上引用）→ 拒绝记录假钱。"""
    class _NoRefRail:
        rail_id = "noref"
        network = "eip155:84532"

        def lookup(self, **_):
            return None

        def pay(self, **kwargs):
            from nth_dao.commerce import RailReceipt
            return RailReceipt(
                tx_ref="",
                status="confirmed",
                proof={"x": 1},
                idempotency_key=kwargs["idempotency_key"],
            )

    intent = SettlementIntent(trade_id="t", amount_minor=5,
                              currency="USDC", payee_did="did:key:zPayee")
    with pytest.raises(SettlementFailed) as ei:
        X402SettlementAdapter(_NoRefRail()).settle(intent)
    assert ei.value.reason == REJECT_TX_REF_MISSING


def test_x402_missing_network_is_rejected_before_rail_io() -> None:
    class _NoNetworkRail:
        rail_id = "no-network"
        network = ""

        def lookup(self, **_):
            raise AssertionError("lookup must not run with invalid rail config")

        def pay(self, **_):
            raise AssertionError("pay must not run with invalid rail config")

    intent = SettlementIntent(
        trade_id="t",
        amount_minor=5,
        currency="USDC",
        payee_did="did:key:zPayee",
    )
    with pytest.raises(SettlementFailed) as error:
        X402SettlementAdapter(_NoNetworkRail()).settle(intent)
    assert error.value.reason == REJECT_NETWORK_MISSING


@pytest.mark.parametrize("network", ["base-sepolia", "eip155:8453"])
def test_x402_rejects_legacy_or_mainnet_network_before_rail_io(
    network,
) -> None:
    class _UnsafeNetworkRail:
        rail_id = "unsafe-network"

        def __init__(self):
            self.network = network

        def lookup(self, **_):
            raise AssertionError("lookup must not run on an unsafe network")

        def pay(self, **_):
            raise AssertionError("pay must not run on an unsafe network")

    intent = SettlementIntent(
        trade_id="t",
        amount_minor=5,
        currency="USDC",
        payee_did="did:key:zPayee",
    )
    with pytest.raises(SettlementFailed) as error:
        X402SettlementAdapter(_UnsafeNetworkRail()).settle(intent)
    assert error.value.reason == REJECT_NETWORK_NOT_TESTNET


def test_verify_settlement_rejects_x402_mainnet_record() -> None:
    settlement = {
        "adapter_id": ADAPTER_X402_TESTNET,
        "amount_minor": 5,
        "currency": "USDC",
        "payee_did": "did:key:zPayee",
        "payer_did": "did:key:zPayer",
        "tx_ref": "tx-1",
        "network": "eip155:8453",
        "proof": {"settled": True},
        "settled_at_ms": 1,
    }
    ok, reason = verify_settlement(
        settlement,
        expected_amount_minor=5,
        expected_currency="USDC",
        expected_payee_did="did:key:zPayee",
    )
    assert not ok and reason == REJECT_NETWORK_NOT_TESTNET


def test_x402_rejects_receipt_bound_to_different_intent() -> None:
    class _WrongKeyRail:
        rail_id = "wrong-key"
        network = "eip155:84532"

        def lookup(self, **_):
            return None

        def pay(self, **_):
            from nth_dao.commerce import RailReceipt

            return RailReceipt(
                tx_ref="tx-1",
                status="confirmed",
                proof={"settled": True},
                idempotency_key="nth-settlement:v1:sha256:" + "0" * 64,
            )

    intent = SettlementIntent(
        trade_id="t",
        amount_minor=5,
        currency="USDC",
        payee_did="did:key:zPayee",
    )
    with pytest.raises(SettlementFailed) as error:
        X402SettlementAdapter(_WrongKeyRail()).settle(intent)
    assert error.value.reason == REJECT_IDEMPOTENCY_KEY_MISMATCH


@pytest.mark.parametrize("status", ["", "pending", "failed", "CONFIRMED"])
def test_x402_rejects_receipt_without_normalized_confirmation(status) -> None:
    class _UnconfirmedRail:
        rail_id = "unconfirmed"
        network = "eip155:84532"

        def lookup(self, **_):
            return None

        def pay(self, **kwargs):
            return RailReceipt(
                tx_ref="tx-unconfirmed",
                status=status,
                proof={"settled": False, "provider_status": "failed"},
                idempotency_key=kwargs["idempotency_key"],
            )

    intent = SettlementIntent(
        trade_id="unconfirmed",
        amount_minor=5,
        currency="USDC",
        payee_did="did:key:zPayee",
    )

    with pytest.raises(SettlementFailed) as error:
        X402SettlementAdapter(_UnconfirmedRail()).settle(intent)

    assert error.value.reason == REJECT_RECEIPT_NOT_CONFIRMED
    assert error.value.payment_may_have_committed is True


def test_x402_idempotency_key_does_not_count_as_provider_proof() -> None:
    class _EmptyProofRail:
        rail_id = "empty-proof"
        network = "eip155:84532"

        def lookup(self, **_):
            return None

        def pay(self, **kwargs):
            from nth_dao.commerce import RailReceipt

            return RailReceipt(
                tx_ref="tx-1",
                status="confirmed",
                proof={"idempotency_key": kwargs["idempotency_key"]},
                idempotency_key=kwargs["idempotency_key"],
            )

    intent = SettlementIntent(
        trade_id="t",
        amount_minor=5,
        currency="USDC",
        payee_did="did:key:zPayee",
    )
    with pytest.raises(SettlementFailed) as error:
        X402SettlementAdapter(_EmptyProofRail()).settle(intent)
    assert error.value.reason == REJECT_PROOF_MISSING


@pytest.mark.parametrize(
    ("proof", "reason"),
    [
        ({"payload": "x" * (64 * 1024 + 1)}, REJECT_RECEIPT_TOO_LARGE),
        ({"items": [0] * 4_097}, REJECT_RECEIPT_TOO_LARGE),
        ({"bad_unicode": "\ud800"}, REJECT_RECEIPT_INVALID),
    ],
)
def test_x402_preflights_untrusted_proof_before_canonical_encoding(
    proof,
    reason,
) -> None:
    class _ProofRail:
        rail_id = "proof-limit"
        network = "eip155:84532"

        def lookup(self, **_):
            return None

        def pay(self, **kwargs):
            return RailReceipt(
                tx_ref="tx-proof-limit",
                status="confirmed",
                proof=proof,
                idempotency_key=kwargs["idempotency_key"],
            )

    intent = SettlementIntent(
        trade_id="proof-limit",
        amount_minor=5,
        currency="USDC",
        payee_did="did:key:zPayee",
    )
    with pytest.raises(SettlementFailed) as error:
        X402SettlementAdapter(_ProofRail()).settle(intent)

    assert error.value.reason == reason
    assert error.value.payment_may_have_committed is True
    assert error.value.evidence_digest.startswith("sha256:")


def test_x402_rejects_excessive_proof_depth_before_recursive_encoding() -> None:
    nested = "leaf"
    for _ in range(34):
        nested = [nested]

    class _DeepProofRail:
        rail_id = "deep-proof"
        network = "eip155:84532"

        def lookup(self, **_):
            return None

        def pay(self, **kwargs):
            return RailReceipt(
                tx_ref="tx-deep-proof",
                status="confirmed",
                proof={"nested": nested},
                idempotency_key=kwargs["idempotency_key"],
            )

    intent = SettlementIntent(
        trade_id="deep-proof",
        amount_minor=5,
        currency="USDC",
        payee_did="did:key:zPayee",
    )
    with pytest.raises(SettlementFailed) as error:
        X402SettlementAdapter(_DeepProofRail()).settle(intent)
    assert error.value.reason == REJECT_RECEIPT_TOO_LARGE


def test_verify_settlement_enforces_same_proof_resource_limits() -> None:
    settlement = _good_x402_settlement()
    settlement["proof"] = {"payload": "x" * (64 * 1024 + 1)}

    ok, reason = verify_settlement(
        settlement,
        expected_amount_minor=1000,
        expected_currency="USDC",
        expected_payee_did="did:key:zPayee",
    )

    assert not ok
    assert reason == REJECT_RECEIPT_TOO_LARGE


def test_settle_trade_rejects_trade_id_mismatch(tmp_path) -> None:
    """intent.trade_id 与目标 trade_id 不符 → 拒（防把 A 单付款记到 B 单）。"""
    store = TradeStore(tmp_path)
    settler = AgentIdentity.generate(label="settler")
    intent = SettlementIntent(trade_id="OTHER", amount_minor=5,
                              currency="USDC", payee_did="did:key:zPayee")
    with pytest.raises(SettlementFailed):
        settle_trade(store, "ann-X", settler=settler,
                     adapter=ManualSettlementAdapter(), intent=intent)


# ─── verify_settlement：用约定条款挡攻击 ─────────────────────────


def _good_x402_settlement():
    rail = FakePaymentRail()
    intent = SettlementIntent(trade_id="t", amount_minor=1000,
                              currency="USDC", payee_did="did:key:zPayee",
                              payer_did="did:key:zPayer")
    return settlement_payload(X402SettlementAdapter(rail), intent)


def test_verify_settlement_happy(tmp_path) -> None:
    s = _good_x402_settlement()
    ok, reason = verify_settlement(
        s, expected_amount_minor=1000, expected_currency="USDC",
        expected_payee_did="did:key:zPayee", expected_payer_did="did:key:zPayer")
    assert ok, reason


@pytest.mark.parametrize(
    "settlement",
    [
        None,
        [],
        "not-an-object",
        {"adapter_id": ADAPTER_X402_TESTNET},
    ],
)
def test_verify_settlement_rejects_noncanonical_schema_without_raising(
    settlement,
) -> None:
    ok, reason = verify_settlement(
        settlement,
        expected_amount_minor=1000,
        expected_currency="USDC",
        expected_payee_did="did:key:zPayee",
    )
    assert not ok and reason == REJECT_SCHEMA_INVALID


def test_verify_settlement_rejects_unknown_fields() -> None:
    settlement = _good_x402_settlement()
    settlement["provider_dump"] = {"authorization": "must-not-be-accepted"}
    ok, reason = verify_settlement(
        settlement,
        expected_amount_minor=1000,
        expected_currency="USDC",
        expected_payee_did="did:key:zPayee",
    )
    assert not ok and reason == REJECT_SCHEMA_INVALID


@pytest.mark.parametrize(
    "settled_at_ms",
    [None, True, 0, -1, "not-a-time", 2**63],
)
def test_verify_settlement_rejects_invalid_settlement_time(
    settled_at_ms,
) -> None:
    settlement = _good_x402_settlement()
    settlement["settled_at_ms"] = settled_at_ms
    ok, reason = verify_settlement(
        settlement,
        expected_amount_minor=1000,
        expected_currency="USDC",
        expected_payee_did="did:key:zPayee",
    )
    assert not ok and reason == REJECT_SETTLED_AT_INVALID


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("payee_did", object()),
        ("payer_did", object()),
        ("payer_did", "not-a-did"),
        ("payer_did", "did:key:zBad space"),
    ],
)
def test_verify_settlement_rejects_invalid_did_field_types(field, value) -> None:
    settlement = _good_x402_settlement()
    settlement[field] = value
    ok, reason = verify_settlement(
        settlement,
        expected_amount_minor=1000,
        expected_currency="USDC",
        expected_payee_did="did:key:zPayee",
    )
    assert not ok and reason == REJECT_SCHEMA_INVALID


def test_verify_manual_settlement_rejects_external_rail_field_smuggling() -> None:
    settlement = settlement_payload(
        ManualSettlementAdapter(),
        SettlementIntent(
            trade_id="manual",
            amount_minor=10,
            currency="credit",
            payee_did="did:key:zPayee",
        ),
    )
    settlement["proof"] = {"provider": "smuggled"}
    ok, reason = verify_settlement(
        settlement,
        expected_amount_minor=10,
        expected_currency="credit",
        expected_payee_did="did:key:zPayee",
    )
    assert not ok and reason == REJECT_SCHEMA_INVALID


def test_verify_settlement_amount_mismatch_blocks_freeride(tmp_path) -> None:
    """settler 把金额改小想白嫖 → amount-mismatch 挡下。"""
    s = _good_x402_settlement()
    s["amount_minor"] = 1  # 篡改：该付 1000 只记 1
    ok, reason = verify_settlement(
        s, expected_amount_minor=1000, expected_currency="USDC",
        expected_payee_did="did:key:zPayee")
    assert not ok and reason == REJECT_AMOUNT_MISMATCH


def test_verify_settlement_bool_amount_rejected(tmp_path) -> None:
    """amount_minor=True 不能当 1 用（bool 不算 int）。"""
    s = _good_x402_settlement()
    s["amount_minor"] = True
    ok, reason = verify_settlement(
        s, expected_amount_minor=1, expected_currency="USDC",
        expected_payee_did="did:key:zPayee")
    assert not ok and reason == REJECT_AMOUNT_INVALID


def test_verify_settlement_currency_and_payee_and_adapter(tmp_path) -> None:
    base = _good_x402_settlement()

    s = dict(base)
    s["currency"] = "NTH-TEST"
    ok, reason = verify_settlement(
        s, expected_amount_minor=1000, expected_currency="USDC",
        expected_payee_did="did:key:zPayee")
    assert not ok and reason == REJECT_CURRENCY_MISMATCH

    s = dict(base)
    s["payee_did"] = "did:key:zAttacker"
    ok, reason = verify_settlement(
        s, expected_amount_minor=1000, expected_currency="USDC",
        expected_payee_did="did:key:zPayee")
    assert not ok and reason == REJECT_PAYEE_MISMATCH

    s = dict(base)
    s["adapter_id"] = "bribe"
    ok, reason = verify_settlement(
        s, expected_amount_minor=1000, expected_currency="USDC",
        expected_payee_did="did:key:zPayee")
    assert not ok and reason == REJECT_UNKNOWN_ADAPTER


def test_verify_settlement_x402_requires_onchain_proof(tmp_path) -> None:
    """x402 必须带 tx_ref + network + 非空 proof，缺一不可。"""
    base = _good_x402_settlement()

    s = dict(base)
    s["tx_ref"] = ""
    ok, reason = verify_settlement(
        s, expected_amount_minor=1000, expected_currency="USDC",
        expected_payee_did="did:key:zPayee")
    assert not ok and reason == REJECT_TX_REF_MISSING

    s = dict(base)
    s["network"] = ""
    ok, reason = verify_settlement(
        s, expected_amount_minor=1000, expected_currency="USDC",
        expected_payee_did="did:key:zPayee")
    assert not ok and reason == REJECT_NETWORK_MISSING

    s = dict(base)
    s["proof"] = {}
    ok, reason = verify_settlement(
        s, expected_amount_minor=1000, expected_currency="USDC",
        expected_payee_did="did:key:zPayee")
    assert not ok and reason == REJECT_PROOF_MISSING


def test_verify_settlement_payer_mismatch(tmp_path) -> None:
    """给了期望 payer 时，payer 不符也挡（payer-mismatch）。"""
    from nth_dao.commerce import REJECT_PAYER_MISMATCH
    s = _good_x402_settlement()
    ok, reason = verify_settlement(
        s, expected_amount_minor=1000, expected_currency="USDC",
        expected_payee_did="did:key:zPayee",
        expected_payer_did="did:key:zSomeoneElse")
    assert not ok and reason == REJECT_PAYER_MISMATCH


# ─── 审查修复 A：terms 让 verify_trade 自动核对结算金额 ──────────


def test_terms_make_verify_trade_catch_freeride(tmp_path) -> None:
    """开局签 terms(1000) 后，settler 记一条 amount=1 的结算想白嫖 ——
    record_settlement 仍会写入（它不验金额），但 verify_trade 自动用
    terms 核对，挡下（amount-mismatch）。这才真正闭合缺口。"""
    from nth_dao.commerce import record_settlement
    store = TradeStore(tmp_path)
    pub = AgentIdentity.generate(label="pub")
    claimant = AgentIdentity.generate(label="worker")
    verifier = AgentIdentity.generate(label="ver")
    settler = AgentIdentity.generate(label="settler")
    open_trade(store, authority=pub,
               claim_record=_claim("ann-t", claimant, pub),
               verifier_did=verifier.as_did(), settler_did=settler.as_did(),
               terms={"amount_minor": 1000, "currency": "USDC"})
    submit_delivery(store, "ann-t", claimant=claimant,
                    delivery={"artifact_sha256": "a", "execution_receipt_id": "x"})
    record_verification(store, "ann-t", verifier=verifier, verdict=VERDICT_PASS,
                        result={"ok": 1})
    # settler 手搓一条改小金额的结算（绕过 settle_trade 的 adapter）
    record_settlement(store, "ann-t", settler=settler, settlement={
        "adapter_id": ADAPTER_X402_TESTNET, "amount_minor": 1,
        "currency": "USDC", "payee_did": claimant.as_did(),
        "payer_did": pub.as_did(),
        "tx_ref": "fake:deadbeef", "network": "base-sepolia",
        "proof": {"settled": True},
        "settled_at_ms": 1,
    })
    assert trade_state(store, "ann-t") == STATE_SETTLED
    ok, reason = verify_trade(store, "ann-t")
    assert not ok and reason == REJECT_AMOUNT_MISMATCH


def test_terms_honest_settlement_passes_verify_trade(tmp_path) -> None:
    """开局签 terms 后，诚实按约定金额经 settle_trade 结算，verify_trade 过。"""
    store = TradeStore(tmp_path)
    pub = AgentIdentity.generate(label="pub")
    claimant = AgentIdentity.generate(label="worker")
    verifier = AgentIdentity.generate(label="ver")
    settler = AgentIdentity.generate(label="settler")
    open_trade(store, authority=pub,
               claim_record=_claim("ann-h", claimant, pub),
               verifier_did=verifier.as_did(), settler_did=settler.as_did(),
               terms={"amount_minor": 1000, "currency": "USDC"})
    submit_delivery(store, "ann-h", claimant=claimant,
                    delivery={"artifact_sha256": "a", "execution_receipt_id": "x"})
    record_verification(store, "ann-h", verifier=verifier, verdict=VERDICT_PASS,
                        result={"ok": 1})
    intent = SettlementIntent(trade_id="ann-h", amount_minor=1000,
                              currency="USDC", payee_did=claimant.as_did(),
                              payer_did=pub.as_did())
    settle_trade(store, "ann-h", settler=settler,
                 adapter=X402SettlementAdapter(FakePaymentRail()), intent=intent)
    ok, reason = verify_trade(store, "ann-h")
    assert ok, reason


# ─── 二轮审查修复：terms 必须钉死在签名公告 reward 上 ──────────


def _real_claim(tmp_path, *, reward_minor=1000, reward_asset="USDC"):
    """造一条真实市场链（公告 publisher 签 + 认领 claimant 签）。"""
    feed = MarketFeed(tmp_path)
    cstore = ClaimStore(tmp_path)
    issuer = AgentIdentity.generate(label="issuer")
    publisher = AgentIdentity.generate(label="publisher")
    worker = AgentIdentity.generate(label="worker")
    ann = sign_announcement(
        publisher=publisher, title="do work",
        capability_set=["test_execution"], reward_minor=reward_minor,
        reward_asset=reward_asset,
    )
    feed.publish(ann)
    out = claim_announcement(
        feed, cstore, ann.announcement_id, claimant=worker,
        cap_token=sign_cap_token(issuer=issuer, subject_did=worker.as_did(),
                                 capabilities=["test_execution", CAP_NTH_RECEIPT_SIGN]))
    return {"publisher": publisher, "worker": worker, "ann": ann,
            "claim_record": out.claim_record}


def test_binding_passes_when_terms_match_announcement_reward(tmp_path) -> None:
    s = _real_claim(tmp_path, reward_minor=1000, reward_asset="USDC")
    tstore = TradeStore(tmp_path)
    open_trade(tstore, authority=s["publisher"], claim_record=s["claim_record"],
               terms={"amount_minor": 1000, "currency": "USDC"})
    events = tstore.get_events(s["ann"].announcement_id)
    ok, reason = verify_trade_binding(events, announcement=s["ann"],
                                      claim_record=s["claim_record"])
    assert ok, reason


def test_binding_catches_opener_underpay_terms(tmp_path) -> None:
    """恶意开局方把 terms 压成 1（公告 reward=1000）—— verify_trade 会被
    骗过（terms 自洽），但 verify_trade_binding 把 terms 钉死在签名公告
    reward 上，识破（terms-reward-mismatch）。这才端到端闭合白嫖。"""
    from nth_dao.commerce.binding import REJECT_TERMS_REWARD_MISMATCH
    s = _real_claim(tmp_path, reward_minor=1000, reward_asset="USDC")
    tstore = TradeStore(tmp_path)
    open_trade(tstore, authority=s["publisher"], claim_record=s["claim_record"],
               terms={"amount_minor": 1, "currency": "USDC"})  # 压价
    events = tstore.get_events(s["ann"].announcement_id)
    ok, reason = verify_trade_binding(events, announcement=s["ann"],
                                      claim_record=s["claim_record"])
    assert not ok and reason == REJECT_TERMS_REWARD_MISMATCH


def test_binding_catches_terms_asset_swap(tmp_path) -> None:
    """terms 币种与公告 reward_asset 不符（公告 USDC、terms NTH-TEST）→ 拒。"""
    from nth_dao.commerce.binding import REJECT_TERMS_ASSET_MISMATCH
    s = _real_claim(tmp_path, reward_minor=1000, reward_asset="USDC")
    tstore = TradeStore(tmp_path)
    open_trade(tstore, authority=s["publisher"], claim_record=s["claim_record"],
               terms={"amount_minor": 1000, "currency": "NTH-TEST"})
    events = tstore.get_events(s["ann"].announcement_id)
    ok, reason = verify_trade_binding(events, announcement=s["ann"],
                                      claim_record=s["claim_record"])
    assert not ok and reason == REJECT_TERMS_ASSET_MISMATCH


# ─── 三轮审查修复：payee 绑 claimant / terms 不可选规避 / credit ──


def test_binding_catches_payee_redirect(tmp_path) -> None:
    """开局方把 terms.payee 指到第三方（非 claimant）—— 钱不进 worker
    口袋。verify_trade 只核对 settlement.payee==terms.payee（自洽）会被骗，
    binding 把 payee 钉到真 claimant 上识破（terms-payee-mismatch）。"""
    from nth_dao.commerce.binding import REJECT_TERMS_PAYEE_MISMATCH
    s = _real_claim(tmp_path, reward_minor=1000, reward_asset="USDC")
    attacker = AgentIdentity.generate(label="attacker")
    tstore = TradeStore(tmp_path)
    open_trade(tstore, authority=s["publisher"], claim_record=s["claim_record"],
               terms={"amount_minor": 1000, "currency": "USDC",
                      "payee_did": attacker.as_did()})  # 改收款方
    events = tstore.get_events(s["ann"].announcement_id)
    ok, reason = verify_trade_binding(events, announcement=s["ann"],
                                      claim_record=s["claim_record"])
    assert not ok and reason == REJECT_TERMS_PAYEE_MISMATCH


def test_require_terms_blocks_paid_task_without_terms(tmp_path) -> None:
    """有偿任务不签 terms 想规避金额约束 —— require_terms=True 时硬失败。
    默认（require_terms=False）保留旧 provenance-only 语义不破坏 CS2。"""
    from nth_dao.commerce.binding import REJECT_TERMS_REQUIRED
    s = _real_claim(tmp_path, reward_minor=1000, reward_asset="USDC")
    tstore = TradeStore(tmp_path)
    open_trade(tstore, authority=s["publisher"], claim_record=s["claim_record"])  # 无 terms
    events = tstore.get_events(s["ann"].announcement_id)
    # 默认：仍通过（provenance-only，向后兼容）
    ok, _ = verify_trade_binding(events, announcement=s["ann"],
                                 claim_record=s["claim_record"])
    assert ok
    # 严格：有偿无 terms → 拒
    ok, reason = verify_trade_binding(events, announcement=s["ann"],
                                      claim_record=s["claim_record"],
                                      require_terms=True)
    assert not ok and reason == REJECT_TERMS_REQUIRED


def test_require_terms_allows_free_task_without_terms(tmp_path) -> None:
    """免费任务（reward_minor=0）即便 require_terms=True 也无需 terms。"""
    s = _real_claim(tmp_path, reward_minor=0, reward_asset="credit")
    tstore = TradeStore(tmp_path)
    open_trade(tstore, authority=s["publisher"], claim_record=s["claim_record"])
    events = tstore.get_events(s["ann"].announcement_id)
    ok, reason = verify_trade_binding(events, announcement=s["ann"],
                                      claim_record=s["claim_record"],
                                      require_terms=True)
    assert ok, reason


def test_credit_task_settles_via_manual(tmp_path) -> None:
    """credit 计价任务可经 manual adapter 结算（credit ∈ SUPPORTED）。"""
    intent = SettlementIntent(trade_id="t", amount_minor=10,
                              currency="credit", payee_did="did:key:zPayee")
    s = settlement_payload(ManualSettlementAdapter(), intent)
    ok, reason = verify_settlement(
        s, expected_amount_minor=10, expected_currency="credit",
        expected_payee_did="did:key:zPayee")
    assert ok, reason


def test_open_trade_rejects_malformed_terms(tmp_path) -> None:
    """terms 给了但畸形（空/零/负/bool 金额、空币种）→ 开局当场拒，
    不签进链（防 -1 哨兵静默 brick 这笔 trade）。"""
    store = TradeStore(tmp_path)
    pub = AgentIdentity.generate(label="pub")
    claimant = AgentIdentity.generate(label="worker")
    for bad in ({}, {"amount_minor": 0, "currency": "USDC"},
                {"amount_minor": -5, "currency": "USDC"},
                {"amount_minor": True, "currency": "USDC"},
                {"amount_minor": 10, "currency": ""}):
        with pytest.raises(TradeRejected):
            open_trade(store, authority=pub,
                       claim_record=_claim("ann-bad-" + str(id(bad)), claimant, pub),
                       terms=bad)


# ─── 审查修复 B：settle_trade 付款前预检（防双付）──────────────


def test_settle_trade_rejects_before_paying_when_not_verified(tmp_path) -> None:
    """trade 不在 VERIFIED 时，settle_trade 在**付款前**就拒 —— rail 没被
    调用（无双付风险）。"""
    store = TradeStore(tmp_path)
    pub = AgentIdentity.generate(label="pub")
    claimant = AgentIdentity.generate(label="worker")
    verifier = AgentIdentity.generate(label="ver")
    settler = AgentIdentity.generate(label="settler")
    # 只开到 EXECUTING（未交付未验收）
    open_trade(store, authority=pub,
               claim_record=_claim("ann-b", claimant, pub),
               verifier_did=verifier.as_did(), settler_did=settler.as_did())
    rail = FakePaymentRail()
    intent = SettlementIntent(trade_id="ann-b", amount_minor=5,
                              currency="USDC", payee_did=claimant.as_did())
    with pytest.raises(SettlementFailed):
        settle_trade(store, "ann-b", settler=settler,
                     adapter=X402SettlementAdapter(rail), intent=intent)
    assert rail.calls == []  # 关键：付款前就拦下，rail 未被调


def test_settle_trade_rejects_forged_verified_event_before_rail_io(tmp_path) -> None:
    store = TradeStore(tmp_path)
    pub = AgentIdentity.generate(label="pub")
    claimant = AgentIdentity.generate(label="worker")
    verifier = AgentIdentity.generate(label="ver")
    settler = AgentIdentity.generate(label="settler")
    open_trade(
        store,
        authority=pub,
        claim_record=_claim("ann-forged-verification", claimant, pub),
        verifier_did=verifier.as_did(),
        settler_did=settler.as_did(),
        terms={
            "amount_minor": 5,
            "currency": "USDC",
            "payee_did": claimant.as_did(),
        },
    )
    submit_delivery(
        store,
        "ann-forged-verification",
        claimant=claimant,
        delivery={"artifact_sha256": "a", "execution_receipt_id": "x"},
    )
    events = store.get_events("ann-forged-verification") or []
    forged = dict(events[-1])
    forged.update({
        "seq": 2,
        "type": "verification_recorded",
        "actor_did": verifier.as_did(),
        "prev_state": "delivered",
        "new_state": "verified",
        "payload": {"verdict": "pass", "result": {"forged": True}},
        "event_sig": "invalid",
    })
    events.append(forged)
    atomic_write_json(
        store._path("ann-forged-verification"),
        {"trade_id": "ann-forged-verification", "events": events},
    )
    rail = FakePaymentRail()
    intent = SettlementIntent(
        trade_id="ann-forged-verification",
        amount_minor=5,
        currency="USDC",
        payee_did=claimant.as_did(),
        payer_did=pub.as_did(),
    )

    with pytest.raises(SettlementFailed, match="event-sig-invalid"):
        settle_trade(
            store,
            "ann-forged-verification",
            settler=settler,
            adapter=X402SettlementAdapter(rail),
            intent=intent,
        )
    assert rail.lookups == []
    assert rail.calls == []


def test_settle_trade_rejects_wrong_settler_before_paying(tmp_path) -> None:
    """非绑定 settler 调 settle_trade → 付款前拒，rail 未被调。"""
    store = TradeStore(tmp_path)
    pub = AgentIdentity.generate(label="pub")
    claimant = AgentIdentity.generate(label="worker")
    verifier = AgentIdentity.generate(label="ver")
    settler = AgentIdentity.generate(label="settler")
    intruder = AgentIdentity.generate(label="intruder")
    _to_verified(store, "ann-w", claimant=claimant, publisher=pub,
                 verifier=verifier, settler=settler)
    rail = FakePaymentRail()
    intent = SettlementIntent(trade_id="ann-w", amount_minor=5,
                              currency="USDC", payee_did=claimant.as_did())
    with pytest.raises(SettlementFailed):
        settle_trade(store, "ann-w", settler=intruder,
                     adapter=X402SettlementAdapter(rail), intent=intent)
    assert rail.calls == []


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("amount_minor", 999, REJECT_AMOUNT_MISMATCH),
        ("currency", "NTH-TEST", REJECT_CURRENCY_MISMATCH),
        ("payee_did", "did:key:zAttacker", REJECT_PAYEE_MISMATCH),
    ],
)
def test_settle_trade_rejects_intent_that_conflicts_with_signed_terms_before_pay(
    tmp_path, field, value, reason
) -> None:
    store = TradeStore(tmp_path)
    pub = AgentIdentity.generate(label="pub")
    claimant = AgentIdentity.generate(label="worker")
    verifier = AgentIdentity.generate(label="ver")
    settler = AgentIdentity.generate(label="settler")
    open_trade(
        store,
        authority=pub,
        claim_record=_claim("ann-terms-preflight", claimant, pub),
        verifier_did=verifier.as_did(),
        settler_did=settler.as_did(),
        terms={
            "amount_minor": 1_000,
            "currency": "USDC",
            "payee_did": claimant.as_did(),
        },
    )
    submit_delivery(
        store,
        "ann-terms-preflight",
        claimant=claimant,
        delivery={"artifact_sha256": "a", "execution_receipt_id": "x"},
    )
    record_verification(
        store,
        "ann-terms-preflight",
        verifier=verifier,
        verdict=VERDICT_PASS,
        result={"ok": 1},
    )
    intent_data = {
        "trade_id": "ann-terms-preflight",
        "amount_minor": 1_000,
        "currency": "USDC",
        "payee_did": claimant.as_did(),
        "payer_did": pub.as_did(),
    }
    intent_data[field] = value
    rail = FakePaymentRail()

    with pytest.raises(SettlementFailed) as error:
        settle_trade(
            store,
            "ann-terms-preflight",
            settler=settler,
            adapter=X402SettlementAdapter(rail),
            intent=SettlementIntent(**intent_data),
        )
    assert error.value.reason == reason
    assert rail.calls == []
    assert trade_state(store, "ann-terms-preflight") == STATE_VERIFIED


def test_verify_settlement_manual_needs_no_txref(tmp_path) -> None:
    """manual（无真钱）不要求 tx_ref/network/proof。"""
    intent = SettlementIntent(trade_id="t", amount_minor=10,
                              currency="NTH-TEST", payee_did="did:key:zPayee")
    s = settlement_payload(ManualSettlementAdapter(), intent)
    assert s["adapter_id"] == ADAPTER_MANUAL and s["tx_ref"] == ""
    ok, reason = verify_settlement(
        s, expected_amount_minor=10, expected_currency="NTH-TEST",
        expected_payee_did="did:key:zPayee")
    assert ok, reason
