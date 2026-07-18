"""Buyer-signed, idempotent commerce order records."""

from __future__ import annotations

import re
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.did_key import decode_ed25519_did_key_hex, is_did_key
from nth_dao.execution_receipt import now_ms
from nth_dao.identity import _NACL_AVAILABLE
from nth_dao.util.io import InterProcessLock, atomic_write_json, safe_load_json
from nth_dao.commerce.listing import LISTING_TYPES
from nth_dao.commerce.money import ASSET_DECIMALS, MAX_MINOR_AMOUNT

try:
    from nacl.exceptions import BadSignatureError as _BadSignatureError
    from nacl.signing import VerifyKey as _VerifyKey
except ImportError:  # pragma: no cover
    _BadSignatureError = ValueError  # type: ignore[assignment,misc]
    _VerifyKey = None  # type: ignore[assignment]

PathLike = Union[str, Path]
NTH_ORDER_EVENT_KIND = "nth-order-event-v1"
EVENT_ORDER_CREATED = "order_created"
STATE_CREATED = "created"
_PAYMENT_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_LISTING_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SETTLEMENT_METHOD = re.compile(r"^[a-z][a-z0-9_]{0,15}:[a-z0-9][a-z0-9_]{0,31}$")
_MAX_ORDER_PAYLOAD_BYTES = 128 * 1024
_EVENT_FIELDS = frozenset({
    "order_id", "seq", "type", "actor_did", "prev_state", "new_state",
    "payload", "created_at_ms", "kind", "event_sig",
})
_ORDER_PAYLOAD_FIELDS = frozenset({
    "schema_version", "listing_id", "listing_digest", "listing_type",
    "buyer_did", "buyer_agent_did", "seller_did",
    "intent_mandate_digest", "cart_mandate_digest",
    "payment_mandate_digest", "payment_id", "items", "amount_minor",
    "currency", "settlement_method", "authorization_snapshot",
})
_AUTHORIZATION_SNAPSHOT_FIELDS = frozenset({"listing", "intent", "cart", "payment"})


class OrderRejected(ValueError):
    pass


class OrderConflict(RuntimeError):
    pass


@dataclass
class OrderEvent:
    order_id: str
    seq: int
    type: str
    actor_did: str
    prev_state: str
    new_state: str
    payload: Dict[str, Any] = field(default_factory=dict)
    created_at_ms: int = 0
    kind: str = NTH_ORDER_EVENT_KIND
    event_sig: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def signing_body(self) -> Dict[str, Any]:
        return {k: v for k, v in self.to_dict().items() if k != "event_sig"}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "OrderEvent":
        known = set(cls.__dataclass_fields__)  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})


def order_id_for_payment(payment_digest: str) -> str:
    if not isinstance(payment_digest, str) or not _PAYMENT_DIGEST.fullmatch(payment_digest):
        raise OrderRejected("invalid payment mandate digest")
    return f"nth-order-sha256:{payment_digest}"


def sign_order_event(actor: Any, event: OrderEvent) -> OrderEvent:
    if actor.as_did() != event.actor_did:
        raise OrderRejected("signer does not match actor_did")
    event.event_sig = b64u_encode(actor.sign(canonical_json(event.signing_body())))
    return event


def verify_order_event(event: OrderEvent) -> Tuple[bool, str]:
    if event.kind != NTH_ORDER_EVENT_KIND:
        return False, "wrong event kind"
    if not is_did_key(event.actor_did):
        return False, "invalid actor DID"
    if not _NACL_AVAILABLE or _VerifyKey is None:
        return False, "crypto unavailable"
    key_hex = decode_ed25519_did_key_hex(event.actor_did) or ""
    if not isinstance(event.event_sig, str) or not (1 <= len(event.event_sig) <= 128):
        return False, "event signature invalid"
    try:
        signature = b64u_decode(event.event_sig)
        if len(signature) != 64 or b64u_encode(signature) != event.event_sig:
            return False, "event signature invalid"
        _VerifyKey(bytes.fromhex(key_hex)).verify(
            canonical_json(event.signing_body()), signature
        )
    except (_BadSignatureError, TypeError, ValueError, UnicodeError):
        return False, "event signature invalid"
    return True, "ok"


_LOCKS: Dict[str, threading.RLock] = {}
_LOCK_GUARD = threading.Lock()


def _thread_lock(path: Path) -> threading.RLock:
    with _LOCK_GUARD:
        return _LOCKS.setdefault(str(path), threading.RLock())


class OrderStore:
    def __init__(self, root: PathLike) -> None:
        self.root = Path(root) / "commerce" / "orders"
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, order_id: str) -> Path:
        if not isinstance(order_id, str) or not order_id.startswith("nth-order-sha256:"):
            raise OrderRejected("invalid order_id")
        suffix = order_id.removeprefix("nth-order-sha256:")
        if not _PAYMENT_DIGEST.fullmatch(suffix):
            raise OrderRejected("invalid order_id")
        return self.root / f"{suffix}.json"

    def get_events(self, order_id: str) -> Optional[List[Dict[str, Any]]]:
        data = safe_load_json(self._path(order_id), fallback=None)
        if data is None:
            return None
        if not isinstance(data, dict) or not isinstance(data.get("events"), list):
            return []
        return data["events"]

    def get(self, order_id: str) -> Optional[OrderEvent]:
        """Return a verified order, or ``None`` for absent/invalid storage."""
        events = self.get_events(order_id)
        if not events:
            return None
        ok, _ = verify_order(events)
        if not ok:
            return None
        try:
            return OrderEvent.from_dict(events[0])
        except (TypeError, ValueError):
            return None


def _validate_created_payload(event: OrderEvent) -> Tuple[bool, str]:
    payload = event.payload
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        return False, "invalid order payload version"
    if set(payload) != _ORDER_PAYLOAD_FIELDS:
        return False, "order payload has missing or unknown fields"
    required_strings = (
        "listing_id", "listing_digest", "listing_type", "buyer_did",
        "buyer_agent_did", "seller_did", "intent_mandate_digest",
        "cart_mandate_digest", "payment_mandate_digest", "payment_id",
        "currency", "settlement_method",
    )
    if any(not isinstance(payload.get(key), str) or not payload[key] for key in required_strings):
        return False, "order payload missing required string"
    if event.actor_did != payload["buyer_did"]:
        return False, "order actor is not buyer"
    if not all(is_did_key(payload[key]) for key in ("buyer_did", "buyer_agent_did", "seller_did")):
        return False, "order payload contains invalid DID"
    if payload["listing_type"] not in LISTING_TYPES:
        return False, "invalid listing_type"
    if not _LISTING_DIGEST.fullmatch(payload["listing_digest"]):
        return False, "invalid listing_digest"
    for key in ("intent_mandate_digest", "cart_mandate_digest", "payment_mandate_digest"):
        if not _PAYMENT_DIGEST.fullmatch(payload[key]):
            return False, f"invalid {key}"
    if payload["currency"] not in ASSET_DECIMALS:
        return False, "unsupported order currency"
    if not _SETTLEMENT_METHOD.fullmatch(payload["settlement_method"]):
        return False, "invalid settlement_method"
    if event.order_id != order_id_for_payment(payload["payment_mandate_digest"]):
        return False, "order_id is not bound to payment mandate"
    amount = payload.get("amount_minor")
    if (
        isinstance(amount, bool)
        or not isinstance(amount, int)
        or not (0 < amount <= MAX_MINOR_AMOUNT)
    ):
        return False, "invalid amount_minor"
    items = payload.get("items")
    if (
        not isinstance(items, list)
        or len(items) != 1
        or not isinstance(items[0], dict)
    ):
        return False, "order v1 requires exactly one item"
    item = items[0]
    if (
        item.get("listing_id") != payload["listing_id"]
        or item.get("listing_digest") != payload["listing_digest"]
        or type(item.get("quantity")) is not int
        or item["quantity"] != 1
    ):
        return False, "order item is not bound to listing"
    try:
        if len(canonical_json(payload)) > _MAX_ORDER_PAYLOAD_BYTES:
            return False, "order payload too large"
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        return False, f"order payload is not canonical JSON: {exc}"
    return _validate_authorization_snapshot(event)


def _validate_authorization_snapshot(event: OrderEvent) -> Tuple[bool, str]:
    """Rebuild the seller/buyer authorization chain from signed evidence."""
    payload = event.payload
    snapshot = payload.get("authorization_snapshot")
    if not isinstance(snapshot, dict) or set(snapshot) != _AUTHORIZATION_SNAPSHOT_FIELDS:
        return False, "authorization snapshot has missing or unknown fields"
    if any(not isinstance(snapshot.get(key), dict) for key in _AUTHORIZATION_SNAPSHOT_FIELDS):
        return False, "authorization snapshot entries must be objects"

    from nth_dao.commerce.listing import (
        SignedListing,
        listing_digest,
        verify_listing,
    )
    from nth_dao.commerce.money import decimal_to_minor
    from nth_dao.mandate import (
        cart_mandate_digest,
        complete_triad_chain,
        intent_mandate_digest,
        payment_mandate_digest,
    )

    try:
        listing = SignedListing.from_dict(snapshot["listing"])
    except (TypeError, ValueError) as exc:
        return False, f"authorization listing malformed: {exc}"
    ok, reason = verify_listing(listing)
    if not ok:
        return False, f"authorization listing invalid: {reason}"

    intent = snapshot["intent"]
    cart = snapshot["cart"]
    payment = snapshot["payment"]
    created_at = datetime.fromtimestamp(event.created_at_ms / 1000, tz=timezone.utc)
    ok, reason = complete_triad_chain(intent, cart, payment, now=created_at)
    if not ok:
        return False, f"authorization mandate triad invalid: {reason}"

    intent_subject = intent.get("credentialSubject")
    cart_subject = cart.get("credentialSubject")
    payment_subject = payment.get("credentialSubject")
    if not all(isinstance(value, dict) for value in (
        intent_subject, cart_subject, payment_subject,
    )):
        return False, "authorization credentialSubject malformed"

    expected_digests = {
        "intent_mandate_digest": intent_mandate_digest(intent),
        "cart_mandate_digest": cart_mandate_digest(cart),
        "payment_mandate_digest": payment_mandate_digest(payment),
    }
    for key, expected in expected_digests.items():
        if payload.get(key) != expected:
            return False, f"authorization snapshot mismatch: {key}"

    expected_listing_digest = listing_digest(listing)
    bindings = {
        "listing_id": listing.listing_id,
        "listing_digest": expected_listing_digest,
        "listing_type": listing.listing_type,
        "buyer_did": intent.get("issuer"),
        "buyer_agent_did": intent_subject.get("id"),
        "seller_did": cart.get("issuer"),
        "payment_id": payment_subject.get("payment_id"),
        "items": cart_subject.get("items"),
        "settlement_method": payment_subject.get("settlement_choice"),
    }
    for key, expected in bindings.items():
        if payload.get(key) != expected:
            return False, f"authorization snapshot mismatch: {key}"

    if listing.seller_did != payload["seller_did"]:
        return False, "authorization listing seller mismatch"
    if payment_subject.get("id") != payload["seller_did"]:
        return False, "authorization payment counterparty mismatch"
    if not (listing.published_at_ms <= event.created_at_ms < listing.not_after_ms):
        return False, "authorization listing was not active when order was created"

    total = cart_subject.get("total")
    if not isinstance(total, dict):
        return False, "authorization cart total malformed"
    try:
        amount_minor = decimal_to_minor(
            total.get("value"), total.get("currency"), require_positive=True,
        )
        listing_minor = decimal_to_minor(
            listing.price_value, listing.price_currency, require_positive=True,
        )
    except ValueError as exc:
        return False, f"authorization amount invalid: {exc}"
    if (
        payload["amount_minor"] != amount_minor
        or amount_minor != listing_minor
        or payload["currency"] != total.get("currency")
        or payload["currency"] != listing.price_currency
    ):
        return False, "authorization amount does not match listing and cart"
    if payload["settlement_method"] not in listing.settlement_methods:
        return False, "authorization settlement method not accepted by listing"
    return True, "ok"


def verify_order(events: List[Dict[str, Any]]) -> Tuple[bool, str]:
    if not isinstance(events, list) or len(events) != 1 or not isinstance(events[0], dict):
        return False, "order must contain exactly one creation event"
    if set(events[0]) != _EVENT_FIELDS:
        return False, "order event has missing or unknown fields"
    try:
        event = OrderEvent.from_dict(events[0])
    except (TypeError, ValueError) as exc:
        return False, f"malformed order event: {exc}"
    if event.seq != 0 or event.type != EVENT_ORDER_CREATED:
        return False, "invalid creation event"
    if event.prev_state != "" or event.new_state != STATE_CREATED:
        return False, "invalid order state transition"
    if isinstance(event.created_at_ms, bool) or not isinstance(event.created_at_ms, int) or event.created_at_ms <= 0:
        return False, "invalid creation time"
    ok, reason = _validate_created_payload(event)
    if not ok:
        return False, reason
    return verify_order_event(event)


def create_order(
    store: OrderStore,
    authority: Any,
    *,
    payment_digest: str,
    payload: Dict[str, Any],
    now_ms_override: int = 0,
) -> OrderEvent:
    order_id = order_id_for_payment(payment_digest)
    if payload.get("payment_mandate_digest") != payment_digest:
        raise OrderRejected("payload payment digest mismatch")
    if authority.as_did() != payload.get("buyer_did"):
        raise OrderRejected("authority is not the buyer principal")
    path = store._path(order_id)
    with _thread_lock(path), InterProcessLock(path):
        existing = store.get_events(order_id)
        if path.exists() and existing is None:
            raise OrderConflict("stored order is unreadable; refuse to overwrite")
        if existing is not None:
            ok, reason = verify_order(existing)
            if not ok:
                raise OrderConflict(f"stored order is invalid: {reason}")
            event = OrderEvent.from_dict(existing[0])
            if event.payload != payload:
                raise OrderConflict("payment mandate already has a different order")
            return event
        event = OrderEvent(
            order_id=order_id,
            seq=0,
            type=EVENT_ORDER_CREATED,
            actor_did=authority.as_did(),
            prev_state="",
            new_state=STATE_CREATED,
            payload=payload,
            created_at_ms=now_ms_override or now_ms(),
        )
        sign_order_event(authority, event)
        ok, reason = verify_order([event.to_dict()])
        if not ok:
            raise OrderRejected(reason)
        atomic_write_json(path, {"order_id": order_id, "events": [event.to_dict()]})
        return event
