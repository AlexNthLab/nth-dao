"""Commerce CS4 settlement adapters.

Earlier commerce stages accepted a free-form settlement dictionary. CS4 adds
typed settlement intents, adapter results, and independent verification
against the immutable trade terms.

``X402SettlementAdapter`` never owns private keys or broadcasts directly. An
injected ``PaymentRail`` owns provider credentials and side effects. The
built-in fake rail is deterministic, has no keys, and moves no real funds.
Only explicitly allowlisted test networks are accepted.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, Protocol, Tuple, runtime_checkable

from nth_dao.canonical_json import canonical_json
from nth_dao.execution_receipt import now_ms
from nth_dao.util.io import InterProcessLock, atomic_write_json

# Adapter identifiers
ADAPTER_MANUAL = "manual"
ADAPTER_X402_TESTNET = "x402-testnet"
KNOWN_ADAPTERS = frozenset({ADAPTER_MANUAL, ADAPTER_X402_TESTNET})

# Supported currencies use positive integer minor units.
# USDC uses 1e-6 units. NTH-TEST and credit are internal no-money units.
SUPPORTED_CURRENCIES = frozenset({"USDC", "NTH-TEST", "credit"})

# Stable rejection codes
REJECT_UNKNOWN_ADAPTER = "settlement-unknown-adapter"
REJECT_AMOUNT_INVALID = "settlement-amount-invalid"
REJECT_AMOUNT_MISMATCH = "settlement-amount-mismatch"
REJECT_CURRENCY_UNSUPPORTED = "settlement-currency-unsupported"
REJECT_CURRENCY_MISMATCH = "settlement-currency-mismatch"
REJECT_PAYEE_MISMATCH = "settlement-payee-mismatch"
REJECT_PAYER_MISMATCH = "settlement-payer-mismatch"
REJECT_TX_REF_MISSING = "settlement-tx-ref-missing"
REJECT_NETWORK_MISSING = "settlement-network-missing"
REJECT_NETWORK_NOT_TESTNET = "settlement-network-not-testnet"
REJECT_PROOF_MISSING = "settlement-proof-missing"
REJECT_RECEIPT_INVALID = "settlement-receipt-invalid"
REJECT_RECEIPT_NOT_CONFIRMED = "settlement-receipt-not-confirmed"
REJECT_RECEIPT_TOO_LARGE = "settlement-receipt-too-large"
REJECT_RECEIPT_NOT_FOUND = "settlement-receipt-not-found"
REJECT_IDEMPOTENCY_KEY_MISMATCH = "settlement-idempotency-key-mismatch"
REJECT_INTENT_INVALID = "settlement-intent-invalid"
REJECT_SCHEMA_INVALID = "settlement-schema-invalid"
REJECT_SETTLED_AT_INVALID = "settlement-settled-at-invalid"
REJECT_TRADE_MISMATCH = "settlement-trade-mismatch"
REJECT_TRADE_NOT_FOUND = "settlement-trade-not-found"
REJECT_BAD_STATE = "settlement-bad-state"
REJECT_WRONG_SETTLER = "settlement-wrong-settler"

_SETTLEMENT_IDEMPOTENCY_KIND = "nth/commerce-settlement-intent@1"
_MAX_NETWORK_CHARS = 128
_MAX_TX_REF_CHARS = 512
_MAX_PROOF_BYTES = 64 * 1024
_MAX_PROOF_DEPTH = 32
_MAX_PROOF_NODES = 4_096
_MAX_PROVIDER_REFERENCE_CHARS = 256
_MAX_FAKE_RAIL_RECEIPT_BYTES = 128 * 1024
_MAX_SETTLEMENT_FUTURE_SKEW_MS = 5 * 60 * 1000
_SETTLEMENT_PAYLOAD_FIELDS = frozenset({
    "adapter_id",
    "amount_minor",
    "currency",
    "payee_did",
    "payer_did",
    "tx_ref",
    "network",
    "proof",
    "settled_at_ms",
})
X402_TEST_NETWORKS = frozenset({
    "eip155:84532",  # Base Sepolia
    "eip155:11155111",  # Ethereum Sepolia
    "eip155:421614",  # Arbitrum Sepolia
    "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",  # Solana Devnet
    "stellar:testnet",
    "aptos:2",
    "hedera:testnet",
    "tvm:-3",
})
RAIL_RECEIPT_CONFIRMED = "confirmed"
_FAKE_RAIL_LOCKS: Dict[str, threading.RLock] = {}
_FAKE_RAIL_LOCK_GUARD = threading.Lock()


def _fake_rail_thread_lock(path: Path) -> threading.RLock:
    with _FAKE_RAIL_LOCK_GUARD:
        return _FAKE_RAIL_LOCKS.setdefault(str(path), threading.RLock())


class SettlementFailed(Exception):
    """Settlement failed because of rail, configuration, or input errors."""

    def __init__(
        self,
        reason: str,
        detail: str = "",
        *,
        payment_may_have_committed: bool = False,
        provider_reference: str = "",
        evidence_digest: str = "",
    ) -> None:
        self.reason = reason
        self.detail = detail
        self.payment_may_have_committed = payment_may_have_committed
        self.provider_reference = provider_reference
        self.evidence_digest = evidence_digest
        super().__init__(f"{reason}: {detail}" if detail else reason)


# Type-safe coercion for untrusted settlement fields.


def _safe_int(value: Any) -> Optional[int]:
    """Accept integers but reject bool, which is an int subclass."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


def _safe_str(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _is_wire_token(value: str, max_chars: int) -> bool:
    return (
        1 <= len(value) <= max_chars
        and all(0x21 <= ord(character) <= 0x7E for character in value)
    )


class _ProofLimitExceeded(ValueError):
    pass


def _proof_encoded_size(proof: Any) -> int:
    """Bound tree resources before invoking the recursive JSON encoder."""
    if type(proof) is not dict:
        raise TypeError("proof must be a plain JSON object")
    stack = [(proof, 0)]
    seen_containers: set[int] = set()
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > _MAX_PROOF_NODES:
            raise _ProofLimitExceeded("proof has too many JSON nodes")
        if value is None or type(value) in {bool, int}:
            if type(value) is int and value.bit_length() > _MAX_PROOF_BYTES * 4:
                raise _ProofLimitExceeded("proof integer is too large")
            continue
        if type(value) is str:
            if len(value) > _MAX_PROOF_BYTES:
                raise _ProofLimitExceeded("proof string is too large")
            continue
        if type(value) not in {dict, list}:
            raise TypeError("proof contains a non-JSON value")
        container_id = id(value)
        if container_id in seen_containers:
            raise TypeError("proof contains a repeated or cyclic container")
        seen_containers.add(container_id)
        if depth >= _MAX_PROOF_DEPTH and value:
            raise _ProofLimitExceeded("proof is nested too deeply")
        if len(value) > _MAX_PROOF_NODES:
            raise _ProofLimitExceeded("proof container has too many entries")
        if type(value) is dict:
            for key, item in value.items():
                if type(key) is not str:
                    raise TypeError("proof object keys must be plain strings")
                if len(key) > _MAX_PROOF_BYTES:
                    raise _ProofLimitExceeded("proof key is too large")
                stack.append((item, depth + 1))
        else:
            stack.extend((item, depth + 1) for item in value)
    encoded = canonical_json({"proof": proof})
    if len(encoded) > _MAX_PROOF_BYTES:
        raise _ProofLimitExceeded("proof exceeds the encoded byte limit")
    return len(encoded)


def _positive_amount(value: Any) -> Optional[int]:
    """Accept positive integer amounts only."""
    iv = _safe_int(value)
    if iv is None or iv <= 0:
        return None
    return iv


# Intent and result


@dataclass
class SettlementIntent:
    """Immutable payment terms derived from the signed trade."""

    trade_id: str
    amount_minor: int
    currency: str
    payee_did: str
    payer_did: str = ""
    memo: str = ""

    def validate(self) -> None:
        text_fields = {
            "trade_id": (self.trade_id, 256, False),
            "currency": (self.currency, 32, False),
            "payee_did": (self.payee_did, 512, False),
            "payer_did": (self.payer_did, 512, True),
            "memo": (self.memo, 2048, True),
        }
        for name, (value, max_length, allow_empty) in text_fields.items():
            if not isinstance(value, str):
                raise SettlementFailed(
                    REJECT_INTENT_INVALID, f"{name} must be a string"
                )
            if (not allow_empty and not value) or len(value) > max_length:
                raise SettlementFailed(
                    REJECT_INTENT_INVALID,
                    f"{name} must contain 1..{max_length} characters"
                    if not allow_empty
                    else f"{name} must contain at most {max_length} characters",
                )
        for name, value in (
            ("payee_did", self.payee_did),
            ("payer_did", self.payer_did),
        ):
            if value and (
                not value.startswith("did:")
                or any(ch.isspace() for ch in value)
            ):
                raise SettlementFailed(
                    REJECT_INTENT_INVALID,
                    f"{name} must be a whitespace-free DID",
                )
        if _positive_amount(self.amount_minor) is None:
            raise SettlementFailed(
                REJECT_AMOUNT_INVALID,
                f"amount_minor must be a positive integer, got {self.amount_minor!r}",
            )
        if self.currency not in SUPPORTED_CURRENCIES:
            raise SettlementFailed(
                REJECT_CURRENCY_UNSUPPORTED,
                f"unsupported currency {self.currency!r}; expected one of "
                f"{sorted(SUPPORTED_CURRENCIES)}",
            )
        if not self.payee_did:
            raise SettlementFailed(
                REJECT_PAYEE_MISMATCH, "payee_did is empty"
            )


@dataclass
class SettlementResult:
    """Structured adapter result embedded in a signed settlement event."""

    adapter_id: str
    amount_minor: int
    currency: str
    payee_did: str
    payer_did: str = ""
    tx_ref: str = ""          # External transaction reference; empty for manual.
    network: str = ""         # CAIP-2, e.g. "eip155:84532" (manual is empty)
    proof: Dict[str, Any] = field(default_factory=dict)
    settled_at_ms: int = 0

    def to_payload(self) -> Dict[str, Any]:
        """Return the dictionary embedded by ``record_settlement``."""
        return {
            "adapter_id": self.adapter_id,
            "amount_minor": self.amount_minor,
            "currency": self.currency,
            "payee_did": self.payee_did,
            "payer_did": self.payer_did,
            "tx_ref": self.tx_ref,
            "network": self.network,
            "proof": dict(self.proof),
            "settled_at_ms": self.settled_at_ms,
        }


# Payment rail


@dataclass
class RailReceipt:
    """Normalized provider receipt returned by a trusted rail boundary.

    The rail maps provider-specific finality into ``status``. Only
    ``confirmed`` authorizes a settlement event; proof remains opaque evidence
    and is never interpreted as a substitute for the normalized status.
    """

    tx_ref: str
    status: str
    proof: Dict[str, Any] = field(default_factory=dict)
    idempotency_key: str = ""


def _receipt_evidence(receipt: Any) -> Tuple[str, str]:
    """Return bounded public correlation data without retaining provider data."""
    if type(receipt) is not RailReceipt:
        body = {"receipt_type": type(receipt).__name__[:128]}
        return "", "sha256:" + hashlib.sha256(canonical_json(body)).hexdigest()
    tx_ref = _safe_str(receipt.tx_ref)
    provider_reference = (
        tx_ref
        if _is_wire_token(tx_ref, _MAX_PROVIDER_REFERENCE_CHARS)
        else ""
    )
    idempotency_key = _safe_str(receipt.idempotency_key)
    body: Dict[str, Any] = {
        "receipt_type": type(receipt).__name__[:128],
        "tx_ref": provider_reference,
        "tx_ref_length": len(tx_ref),
        "idempotency_key": (
            idempotency_key
            if _is_wire_token(idempotency_key, 128)
            else ""
        ),
        "idempotency_key_length": len(idempotency_key),
        "status": _safe_str(receipt.status)[:128],
        "proof_type": type(receipt.proof).__name__[:128],
    }
    try:
        _proof_encoded_size(receipt.proof)
        proof_bytes = canonical_json({"proof": receipt.proof})
        body["proof_digest"] = "sha256:" + hashlib.sha256(proof_bytes).hexdigest()
    except (
        TypeError,
        ValueError,
        OverflowError,
        RecursionError,
        UnicodeError,
    ):
        if type(receipt.proof) in {dict, list}:
            body["proof_entries"] = len(receipt.proof)
    encoded = canonical_json(body)
    return provider_reference, "sha256:" + hashlib.sha256(encoded).hexdigest()


def _committed_receipt_failure(
    reason: str,
    detail: str,
    receipt: Any,
) -> SettlementFailed:
    provider_reference, evidence_digest = _receipt_evidence(receipt)
    return SettlementFailed(
        reason,
        detail,
        payment_may_have_committed=True,
        provider_reference=provider_reference,
        evidence_digest=evidence_digest,
    )


def settlement_idempotency_key(intent: SettlementIntent) -> str:
    """Bind one rail side effect to the immutable payment obligation.

    ``memo`` is deliberately excluded. It is presentation metadata and may
    change between retries; allowing it to alter this key would permit two
    provider payments for the same signed trade obligation.
    """
    intent.validate()
    body = {
        "kind": _SETTLEMENT_IDEMPOTENCY_KIND,
        "trade_id": intent.trade_id,
        "amount_minor": intent.amount_minor,
        "currency": intent.currency,
        "payee_did": intent.payee_did,
        "payer_did": intent.payer_did,
    }
    digest = hashlib.sha256(canonical_json(body)).hexdigest()
    return f"nth-settlement:v1:sha256:{digest}"


@runtime_checkable
class PaymentRail(Protocol):
    """Durable, idempotent boundary to an external payment provider.

    ``lookup`` must survive process restarts. ``pay`` must atomically deduplicate
    concurrent calls by ``idempotency_key`` and return a receipt carrying that
    exact key. If a provider commits a payment but loses the response, a later
    lookup must expose the committed receipt. Implementations own credentials and
    broadcasting; this module never handles payment private keys.
    """

    rail_id: str
    network: str

    def lookup(self, *, idempotency_key: str) -> Optional[RailReceipt]:
        ...

    def pay(
        self,
        *,
        payee_did: str,
        amount_minor: int,
        currency: str,
        memo: str,
        idempotency_key: str,
    ) -> RailReceipt:
        ...


class FakePaymentRail:
    """Deterministic no-money rail for tests.

    It owns no keys and performs no broadcast. Transaction references are
    derived from inputs, and calls are retained for assertions.
    """

    rail_id = "fake"
    network = "eip155:84532"

    def __init__(
        self,
        *,
        fail: bool = False,
        fail_after_commit: bool = False,
        root: str | Path | None = None,
    ) -> None:
        self._fail = fail
        self._fail_after_commit = fail_after_commit
        self._lock = threading.RLock()
        self._receipts: Dict[str, RailReceipt] = {}
        self._root = Path(root) / "commerce" / "fake_payment_rail" if root else None
        if self._root is not None:
            self._root.mkdir(parents=True, exist_ok=True)
        self.calls: list[Dict[str, Any]] = []
        self.lookups: list[str] = []

    def _path(self, idempotency_key: str) -> Path:
        if self._root is None:
            raise RuntimeError("persistent fake rail is not configured")
        digest = hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()
        return self._root / f"{digest}.json"

    @staticmethod
    def _load_receipt(path: Path, idempotency_key: str) -> Optional[RailReceipt]:
        try:
            with path.open("rb") as handle:
                raw = handle.read(_MAX_FAKE_RAIL_RECEIPT_BYTES + 1)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise SettlementFailed(
                "rail-receipt-unreadable", "stored fake rail receipt is unreadable"
            ) from exc
        if len(raw) > _MAX_FAKE_RAIL_RECEIPT_BYTES:
            raise SettlementFailed(
                "rail-receipt-unreadable", "stored fake rail receipt is too large"
            )
        try:
            value = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise SettlementFailed(
                "rail-receipt-unreadable", "stored fake rail receipt is unreadable"
            ) from exc
        if not isinstance(value, dict) or set(value) != {
            "tx_ref", "status", "proof", "idempotency_key"
        }:
            raise SettlementFailed(
                "rail-receipt-unreadable", "stored fake rail receipt has invalid fields"
            )
        receipt = RailReceipt(**value)
        if receipt.idempotency_key != idempotency_key:
            raise SettlementFailed(
                REJECT_IDEMPOTENCY_KEY_MISMATCH,
                "stored fake rail receipt has a different idempotency key",
            )
        return receipt

    def lookup(self, *, idempotency_key: str) -> Optional[RailReceipt]:
        with self._lock:
            self.lookups.append(idempotency_key)
            if self._root is not None:
                path = self._path(idempotency_key)
                with _fake_rail_thread_lock(path), InterProcessLock(path):
                    return self._load_receipt(path, idempotency_key)
            return self._receipts.get(idempotency_key)

    def pay(
        self,
        *,
        payee_did: str,
        amount_minor: int,
        currency: str,
        memo: str,
        idempotency_key: str,
    ) -> RailReceipt:
        if not idempotency_key:
            raise SettlementFailed(
                REJECT_IDEMPOTENCY_KEY_MISMATCH,
                "payment rail requires a non-empty idempotency key",
            )
        with self._lock:
            if self._root is not None:
                path = self._path(idempotency_key)
                with _fake_rail_thread_lock(path), InterProcessLock(path):
                    existing = self._load_receipt(path, idempotency_key)
                    if existing is not None:
                        return existing
                    return self._commit_payment(
                        payee_did=payee_did,
                        amount_minor=amount_minor,
                        currency=currency,
                        memo=memo,
                        idempotency_key=idempotency_key,
                        path=path,
                    )
            existing = self._receipts.get(idempotency_key)
            if existing is not None:
                return existing
            return self._commit_payment(
                payee_did=payee_did,
                amount_minor=amount_minor,
                currency=currency,
                memo=memo,
                idempotency_key=idempotency_key,
            )

    def _commit_payment(
        self,
        *,
        payee_did: str,
        amount_minor: int,
        currency: str,
        memo: str,
        idempotency_key: str,
        path: Path | None = None,
    ) -> RailReceipt:
        if self._fail:
            raise SettlementFailed("rail-declined", "FakePaymentRail fail mode")
        self.calls.append({
            "payee_did": payee_did,
            "amount_minor": amount_minor,
            "currency": currency,
            "memo": memo,
        })
        h = hashlib.sha256(idempotency_key.encode("ascii")).hexdigest()[:16]
        receipt = RailReceipt(
            tx_ref=f"fake:{h}",
            status=RAIL_RECEIPT_CONFIRMED,
            proof={"facilitator": "fake", "settled": True},
            idempotency_key=idempotency_key,
        )
        if path is None:
            self._receipts[idempotency_key] = receipt
        else:
            atomic_write_json(path, asdict(receipt))
        if self._fail_after_commit:
            raise SettlementFailed(
                "rail-outcome-unknown",
                "payment committed but the rail response was interrupted",
            )
        return receipt


# Settlement adapters


class SettlementAdapter(Protocol):
    """Settle an intent and return an independently verifiable result."""

    adapter_id: str

    def settle(self, intent: SettlementIntent) -> SettlementResult:
        ...


class ManualSettlementAdapter:
    """Record a signed, no-money manual settlement."""

    adapter_id = ADAPTER_MANUAL

    def settle(self, intent: SettlementIntent) -> SettlementResult:
        intent.validate()
        return SettlementResult(
            adapter_id=ADAPTER_MANUAL,
            amount_minor=intent.amount_minor,
            currency=intent.currency,
            payee_did=intent.payee_did,
            payer_did=intent.payer_did,
            tx_ref="",
            network="",
            proof={},
            settled_at_ms=now_ms(),
        )


class X402SettlementAdapter:
    """Delegate a test-network payment intent to an injected rail.

    This class owns no private keys and performs no direct broadcast. A rail
    receipt must carry a bounded transaction reference and provider proof.
    """

    adapter_id = ADAPTER_X402_TESTNET

    def __init__(self, rail: PaymentRail) -> None:
        self._rail = rail

    def _network(self) -> str:
        network = _safe_str(getattr(self._rail, "network", ""))
        if not network:
            raise SettlementFailed(
                REJECT_NETWORK_MISSING, "rail must declare its network before payment"
            )
        if not _is_wire_token(network, _MAX_NETWORK_CHARS):
            raise SettlementFailed(
                REJECT_RECEIPT_INVALID,
                "rail network identifier is not a bounded ASCII token",
            )
        if network not in X402_TEST_NETWORKS:
            raise SettlementFailed(
                REJECT_NETWORK_NOT_TESTNET,
                "x402-testnet requires an approved CAIP-2 test network",
            )
        return network

    def _result_from_receipt(
        self,
        intent: SettlementIntent,
        receipt: Any,
        *,
        network: str,
    ) -> SettlementResult:
        idempotency_key = settlement_idempotency_key(intent)
        if type(receipt) is not RailReceipt:
            raise _committed_receipt_failure(
                REJECT_RECEIPT_INVALID,
                "rail returned an object that is not a RailReceipt",
                receipt,
            )
        if receipt.idempotency_key != idempotency_key:
            raise _committed_receipt_failure(
                REJECT_IDEMPOTENCY_KEY_MISMATCH,
                "rail receipt is not bound to the requested payment intent",
                receipt,
            )
        if receipt.status != RAIL_RECEIPT_CONFIRMED:
            raise _committed_receipt_failure(
                REJECT_RECEIPT_NOT_CONFIRMED,
                "rail receipt is not in the confirmed terminal state",
                receipt,
            )
        tx_ref = _safe_str(receipt.tx_ref)
        if not tx_ref:
            # Never record a provider payment without a transaction reference.
            raise _committed_receipt_failure(
                REJECT_TX_REF_MISSING,
                "rail did not return a transaction reference",
                receipt,
            )
        if not _is_wire_token(tx_ref, _MAX_TX_REF_CHARS):
            raise _committed_receipt_failure(
                REJECT_RECEIPT_INVALID,
                "rail transaction reference is not a bounded ASCII token",
                receipt,
            )
        proof = dict(receipt.proof) if type(receipt.proof) is dict else {}
        try:
            _proof_encoded_size(proof)
        except _ProofLimitExceeded as exc:
            raise _committed_receipt_failure(
                REJECT_RECEIPT_TOO_LARGE,
                "rail proof exceeds the protocol resource limits",
                receipt,
            ) from exc
        except (
            TypeError,
            ValueError,
            OverflowError,
            RecursionError,
            UnicodeError,
        ) as exc:
            raise _committed_receipt_failure(
                REJECT_RECEIPT_INVALID,
                "rail proof is not canonical JSON",
                receipt,
            ) from exc
        proof_key = _safe_str(proof.get("idempotency_key"))
        if proof_key and proof_key != idempotency_key:
            raise _committed_receipt_failure(
                REJECT_IDEMPOTENCY_KEY_MISMATCH,
                "rail proof conflicts with its receipt idempotency key",
                receipt,
            )
        if not {key: value for key, value in proof.items() if key != "idempotency_key"}:
            raise _committed_receipt_failure(
                REJECT_PROOF_MISSING,
                "rail receipt does not contain provider settlement evidence",
                receipt,
            )
        proof["idempotency_key"] = idempotency_key
        return SettlementResult(
            adapter_id=ADAPTER_X402_TESTNET,
            amount_minor=intent.amount_minor,
            currency=intent.currency,
            payee_did=intent.payee_did,
            payer_did=intent.payer_did,
            tx_ref=tx_ref,
            network=network,
            proof=proof,
            settled_at_ms=now_ms(),
        )

    def lookup_settlement(
        self,
        intent: SettlementIntent,
    ) -> Optional[SettlementResult]:
        """Return a verified existing receipt without initiating payment."""
        intent.validate()
        network = self._network()
        idempotency_key = settlement_idempotency_key(intent)
        receipt = self._rail.lookup(idempotency_key=idempotency_key)
        if receipt is None:
            return None
        return self._result_from_receipt(intent, receipt, network=network)

    def settle(self, intent: SettlementIntent) -> SettlementResult:
        intent.validate()
        network = self._network()
        idempotency_key = settlement_idempotency_key(intent)
        receipt = self._rail.lookup(idempotency_key=idempotency_key)
        if receipt is None:
            receipt = self._rail.pay(
                payee_did=intent.payee_did,
                amount_minor=intent.amount_minor,
                currency=intent.currency,
                memo=intent.memo,
                idempotency_key=idempotency_key,
            )
        return self._result_from_receipt(intent, receipt, network=network)


def settlement_payload(
    adapter: SettlementAdapter, intent: SettlementIntent
) -> Dict[str, Any]:
    """Run an adapter and return a settlement event payload."""
    return adapter.settle(intent).to_payload()


def settle_trade(
    store: Any,
    trade_id: str,
    *,
    settler: Any,
    adapter: SettlementAdapter,
    intent: SettlementIntent,
    now_ms_override: int = 0,
) -> Any:
    """Preflight a verified trade, settle it, and record the signed result.

    Preflight validates the trade id, signed chain, state, terms, and settler
    before any rail call. The trade store's atomic transition catches a
    concurrent state change after preflight. A production money rail still
    requires an authorization/capture protocol to eliminate that residual
    time-of-check/time-of-use boundary.
    """
    # Delay imports to avoid coupling this module to facade import order.
    from nth_dao.commerce.trade import (
        EVENT_SETTLEMENT_RECORDED,
        STATE_SETTLED,
        STATE_VERIFIED,
        TradeEvent,
        _parties,
        _trade_terms,
        record_settlement,
        trade_state,
        verify_trade,
    )

    intent.validate()
    if intent.trade_id != trade_id:
        raise SettlementFailed(
            REJECT_TRADE_MISMATCH,
            f"intent.trade_id={intent.trade_id!r} != trade_id={trade_id!r}",
        )
    events = store.get_events(trade_id)
    if not events:
        raise SettlementFailed(REJECT_TRADE_NOT_FOUND, trade_id)
    ok, reason = verify_trade(store, trade_id)
    if not ok:
        raise SettlementFailed(
            reason,
            "stored trade failed verification before payment rail access",
        )
    parties = _parties(events)
    if settler.as_did() != parties.get("settler_did"):
        raise SettlementFailed(
            REJECT_WRONG_SETTLER,
            f"settler {settler.as_did()!r} is not the bound settlement actor "
            f"{parties.get('settler_did')!r}",
        )
    state = trade_state(store, trade_id)
    adapter_id = _safe_str(getattr(adapter, "adapter_id", ""))
    if state == STATE_SETTLED and adapter_id == ADAPTER_X402_TESTNET:
        expected_payer = _safe_str(parties.get("publisher_did"))
        if not expected_payer or intent.payer_did != expected_payer:
            raise SettlementFailed(
                REJECT_PAYER_MISMATCH,
                "x402 payer must match the publisher bound by the signed trade",
            )
        settled_events = store.get_events(trade_id) or []
        raw = (
            settled_events[-1]
            if settled_events and isinstance(settled_events[-1], dict)
            else {}
        )
        payload = raw.get("payload") if isinstance(raw, dict) else None
        settlement = payload.get("settlement") if isinstance(payload, dict) else None
        proof = settlement.get("proof") if isinstance(settlement, dict) else None
        key = settlement_idempotency_key(intent)
        if (
            raw.get("type") == EVENT_SETTLEMENT_RECORDED
            and isinstance(settlement, dict)
            and isinstance(proof, dict)
            and proof.get("idempotency_key") == key
            and settlement.get("adapter_id") == adapter_id
            and settlement.get("amount_minor") == intent.amount_minor
            and settlement.get("currency") == intent.currency
            and settlement.get("payee_did") == intent.payee_did
            and settlement.get("payer_did") == intent.payer_did
        ):
            ok, reason = verify_trade(store, trade_id)
            if not ok:
                raise SettlementFailed(
                    reason, "stored settlement failed signed trade verification"
                )
            return TradeEvent.from_dict(raw)
        raise SettlementFailed(
            REJECT_BAD_STATE,
            "trade is settled, but the stored settlement does not match this retry",
        )
    if state != STATE_VERIFIED:
        raise SettlementFailed(
            REJECT_BAD_STATE,
            f"trade must be {STATE_VERIFIED!r} before settlement; got {state!r}",
        )
    terms = _trade_terms(events)
    if terms is not None:
        expected_amount = _safe_int(terms.get("amount_minor"))
        expected_currency = _safe_str(terms.get("currency"))
        expected_payee = _safe_str(terms.get("payee_did"))
        if expected_amount != intent.amount_minor:
            raise SettlementFailed(
                REJECT_AMOUNT_MISMATCH,
                "payment intent amount does not match the signed trade terms",
            )
        if expected_currency != intent.currency:
            raise SettlementFailed(
                REJECT_CURRENCY_MISMATCH,
                "payment intent currency does not match the signed trade terms",
            )
        if expected_payee != intent.payee_did:
            raise SettlementFailed(
                REJECT_PAYEE_MISMATCH,
                "payment intent payee does not match the signed trade terms",
            )
    if adapter_id == ADAPTER_X402_TESTNET:
        expected_payer = _safe_str(parties.get("publisher_did"))
        if not expected_payer or intent.payer_did != expected_payer:
            raise SettlementFailed(
                REJECT_PAYER_MISMATCH,
                "x402 payer must match the publisher bound by the signed trade",
            )

    # Preflight succeeded: invoke the adapter, then record the result.
    payload = adapter.settle(intent).to_payload()
    return record_settlement(
        store, trade_id, settler=settler, settlement=payload,
        now_ms_override=now_ms_override,
    )


# Independent settlement verification


def verify_settlement(
    settlement: Any,
    *,
    expected_amount_minor: int,
    expected_currency: str,
    expected_payee_did: str,
    expected_payer_did: str = "",
) -> Tuple[bool, str]:
    """Verify a settlement against immutable expected trade terms.

    Expected values come from the signed trade, never from attacker-controlled
    settlement fields. Missing and malformed fields fail closed.
    """
    if type(settlement) is not dict or set(settlement) != _SETTLEMENT_PAYLOAD_FIELDS:
        return False, REJECT_SCHEMA_INVALID

    adapter_id = _safe_str(settlement.get("adapter_id"))
    if adapter_id not in KNOWN_ADAPTERS:
        return False, REJECT_UNKNOWN_ADAPTER

    amount = _positive_amount(settlement.get("amount_minor"))
    if amount is None:
        return False, REJECT_AMOUNT_INVALID
    if amount != expected_amount_minor:
        return False, REJECT_AMOUNT_MISMATCH

    currency = _safe_str(settlement.get("currency"))
    if currency not in SUPPORTED_CURRENCIES:
        return False, REJECT_CURRENCY_UNSUPPORTED
    if currency != expected_currency:
        return False, REJECT_CURRENCY_MISMATCH

    payee = _safe_str(settlement.get("payee_did"))
    if (
        not payee.startswith("did:")
        or len(payee) > 512
        or any(character.isspace() for character in payee)
    ):
        return False, REJECT_SCHEMA_INVALID
    if payee != expected_payee_did:
        return False, REJECT_PAYEE_MISMATCH

    raw_payer = settlement.get("payer_did")
    if type(raw_payer) is not str:
        return False, REJECT_SCHEMA_INVALID
    payer = raw_payer
    if (
        len(payer) > 512
        or (payer and not payer.startswith("did:"))
        or any(character.isspace() for character in payer)
    ):
        return False, REJECT_SCHEMA_INVALID
    if expected_payer_did:
        if payer != expected_payer_did:
            return False, REJECT_PAYER_MISMATCH

    settled_at_ms = _positive_amount(settlement.get("settled_at_ms"))
    if (
        settled_at_ms is None
        or settled_at_ms > now_ms() + _MAX_SETTLEMENT_FUTURE_SKEW_MS
    ):
        return False, REJECT_SETTLED_AT_INVALID

    # External-rail records require a transaction reference and provider proof.
    if adapter_id == ADAPTER_X402_TESTNET:
        if not payer:
            return False, REJECT_PAYER_MISMATCH
        tx_ref = _safe_str(settlement.get("tx_ref"))
        if not tx_ref:
            return False, REJECT_TX_REF_MISSING
        if not _is_wire_token(tx_ref, _MAX_TX_REF_CHARS):
            return False, REJECT_RECEIPT_INVALID
        network = _safe_str(settlement.get("network"))
        if not network:
            return False, REJECT_NETWORK_MISSING
        if not _is_wire_token(network, _MAX_NETWORK_CHARS):
            return False, REJECT_RECEIPT_INVALID
        if network not in X402_TEST_NETWORKS:
            return False, REJECT_NETWORK_NOT_TESTNET
        proof = settlement.get("proof")
        if type(proof) is not dict or not proof:
            return False, REJECT_PROOF_MISSING
        try:
            _proof_encoded_size(proof)
        except _ProofLimitExceeded:
            return False, REJECT_RECEIPT_TOO_LARGE
        except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError):
            return False, REJECT_RECEIPT_INVALID
    elif (
        settlement.get("tx_ref") != ""
        or settlement.get("network") != ""
        or type(settlement.get("proof")) is not dict
        or settlement.get("proof") != {}
    ):
        return False, REJECT_SCHEMA_INVALID

    return True, "ok"
