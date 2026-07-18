"""No-real-money digital-service commerce API.

The local node signs only as its own persistent DID. Remote replication uses
signed, content-bound envelopes; no endpoint accepts private key material.
"""

from __future__ import annotations

import json
import hashlib
import logging
import os
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List
from urllib.parse import urlsplit, urlunsplit

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from nth_dao.commerce.checkout import CheckoutRejected, create_order_from_mandates
from nth_dao.canonical_json import canonical_json
from nth_dao.commerce.listing import (
    LISTING_SERVICE,
    ListingRejected,
    SignedListing,
    listing_digest,
    sign_listing,
    verify_listing,
)
from nth_dao.commerce.listing_announcement import publish_listing_announcement
from nth_dao.commerce.order import OrderEvent, OrderRejected
from nth_dao.commerce.order_trade import open_commerce_trade
from nth_dao.commerce.outbox import (
    CommerceAck,
    CommerceEnvelope,
    CommerceEnvelopeRejected,
    sign_envelope,
    trade_chain_head,
    verify_ack,
    verify_envelope,
)
from nth_dao.commerce.projection import (
    CommerceProjectionRejected,
    list_order_views,
    project_order,
)
from nth_dao.commerce.settlement import (
    ManualSettlementAdapter,
    SettlementIntent,
    settle_trade,
)
from nth_dao.commerce.trade import (
    RESOLUTION_REFUND,
    RESOLUTION_SETTLE,
    RESOLUTION_SPLIT,
    TradeRejected,
    open_dispute,
    record_verification,
    resolve_dispute,
    submit_delivery,
)
from nth_dao.execution_receipt import now_ms
from nth_dao.did_key import decode_ed25519_did_key_hex
from nth_dao.mandate import (
    build_cart_mandate,
    build_intent_mandate,
    build_payment_mandate,
    cart_mandate_digest,
    cart_satisfies_intent,
    intent_mandate_digest,
    sign_cart_mandate,
    sign_intent_mandate,
    sign_payment_mandate,
    verify_intent_mandate,
)
from nth_dao.market.feed import MarketFeed
from nth_dao.util.io import InterProcessLock, atomic_write_json, safe_load_json

logger = logging.getLogger(__name__)

MVP_CURRENCY = "NTH-TEST"
MVP_SETTLEMENT_METHOD = "manual:nth_test"
_MAX_TTL_SECONDS = 86_400
_MAX_LISTING_DETAILS_BYTES = 64 * 1024
_MAX_ENVELOPE_AGE_MS = 30 * 24 * 60 * 60 * 1000
_MAX_ENVELOPE_FUTURE_SKEW_MS = 5 * 60 * 1000


class _StrictBody(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PublishListingBody(_StrictBody):
    listing_id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=4000)
    price_value: str = Field(min_length=1, max_length=96)
    details: Dict[str, Any] = Field(default_factory=dict)
    capabilities: List[str] = Field(default_factory=list, max_length=32)
    ttl_seconds: int = Field(default=86_400, ge=60, le=_MAX_TTL_SECONDS)


class IntentBody(_StrictBody):
    listing: Dict[str, Any]
    purpose: str = Field(default="purchase digital service", min_length=1, max_length=500)
    agent_did: str = ""
    ttl_seconds: int = Field(default=3600, ge=60, le=_MAX_TTL_SECONDS)


class CartBody(_StrictBody):
    listing_digest: str
    intent: Dict[str, Any]
    ttl_seconds: int = Field(default=3600, ge=60, le=_MAX_TTL_SECONDS)


class CheckoutBody(_StrictBody):
    listing: Dict[str, Any]
    intent: Dict[str, Any]
    cart: Dict[str, Any]
    ttl_seconds: int = Field(default=1800, ge=60, le=_MAX_TTL_SECONDS)
    target_url: str = Field(default="", max_length=2048)


class RemoteCheckoutBody(_StrictBody):
    target_url: str = Field(min_length=1, max_length=2048)
    listing_digest: str = Field(min_length=71, max_length=71)
    purpose: str = Field(default="purchase digital service", min_length=1, max_length=500)
    ttl_seconds: int = Field(default=1800, ge=60, le=_MAX_TTL_SECONDS)
    idempotency_key: str = Field(min_length=16, max_length=128)


class DeliveryBody(_StrictBody):
    delivery: Dict[str, Any]
    target_url: str = Field(default="", max_length=2048)


class VerificationBody(_StrictBody):
    verdict: str
    result: Dict[str, Any] = Field(default_factory=dict)
    target_url: str = Field(default="", max_length=2048)


class SettlementBody(_StrictBody):
    target_url: str = Field(default="", max_length=2048)


class DisputeBody(_StrictBody):
    reason: str = Field(min_length=1, max_length=4000)
    evidence: Dict[str, Any] = Field(default_factory=dict)
    target_url: str = Field(default="", max_length=2048)


class ResolveBody(_StrictBody):
    resolution: str
    rationale: str = Field(default="", max_length=4000)
    seller_amount_minor: int | None = Field(default=None, ge=0)
    target_url: str = Field(default="", max_length=2048)


class QueueBody(_StrictBody):
    target_did: str
    target_url: str = Field(min_length=1, max_length=2048)


class SyncBody(_StrictBody):
    envelope: Dict[str, Any]


def _state(request: Request) -> Any:
    state = getattr(request.app.state, "nth", None)
    if state is None:
        raise HTTPException(status_code=503, detail="NTH state unavailable")
    return state


def _identity(request: Request) -> Any:
    identity = getattr(_state(request), "node_identity", None)
    if identity is None or not getattr(identity, "can_sign", False):
        raise HTTPException(status_code=503, detail="signing identity unavailable")
    return identity


def _expiry(ttl_seconds: int) -> tuple[datetime, str]:
    issued = datetime.now(timezone.utc)
    return issued, (issued + timedelta(seconds=ttl_seconds)).isoformat()


def _assert_bounded_listing_details(value: Dict[str, Any]) -> None:
    try:
        if len(canonical_json(value)) > _MAX_LISTING_DETAILS_BYTES:
            raise HTTPException(status_code=413, detail="listing details exceed 64 KiB")
    except HTTPException:
        raise
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise HTTPException(status_code=400, detail="listing details are not canonical JSON") from exc


def _operation_lock(state: Any, namespace: str, value: str) -> InterProcessLock:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return InterProcessLock(
        Path(state.workspace) / "commerce" / "locks" / namespace / digest,
    )


def _stored_cart_for(state: Any, intent_digest: str, listing_digest_value: str) -> Dict[str, Any] | None:
    for cart in state.mandates.list_carts():
        subject = cart.get("credentialSubject")
        if not isinstance(subject, dict) or subject.get("intent_mandate_digest") != intent_digest:
            continue
        items = subject.get("items")
        if (
            isinstance(items, list) and len(items) == 1
            and isinstance(items[0], dict)
            and items[0].get("listing_digest") == listing_digest_value
        ):
            return cart
    return None


def _stored_payment_for(state: Any, buyer_did: str, cart_digest_value: str) -> Dict[str, Any] | None:
    for payment in state.mandates.list_payments():
        subject = payment.get("credentialSubject")
        if (
            payment.get("issuer") == buyer_did
            and isinstance(subject, dict)
            and subject.get("cart_mandate_digest") == cart_digest_value
            and subject.get("settlement_choice") == MVP_SETTLEMENT_METHOD
        ):
            return payment
    return None


def _payment_for_cart(
    state: Any,
    identity: Any,
    listing: SignedListing,
    cart: Dict[str, Any],
    *,
    ttl_seconds: int,
) -> Dict[str, Any]:
    digest = cart_mandate_digest(cart)
    with _operation_lock(state, "cart-checkout", f"{identity.as_did()}|{digest}"):
        existing = _stored_payment_for(state, identity.as_did(), digest)
        if existing is not None:
            return existing
        issued, expires = _expiry(ttl_seconds)
        payment = sign_payment_mandate(build_payment_mandate(
            identity.as_did(), listing.seller_did, digest,
            MVP_SETTLEMENT_METHOD, expires, issued_at=issued,
        ), identity, created_at=issued)
        state.mandates.save_payment(payment)
        return payment


def _listing_from(value: Dict[str, Any]) -> SignedListing:
    try:
        listing = SignedListing.from_dict(value)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"listing malformed: {exc}")
    return listing


def _assert_mvp_listing(listing: SignedListing) -> None:
    ok, reason = verify_listing(listing)
    if not ok:
        raise HTTPException(status_code=400, detail=f"listing signature rejected: {reason}")
    current = now_ms()
    if current < listing.published_at_ms:
        raise HTTPException(status_code=400, detail="listing is not published yet")
    if current >= listing.not_after_ms:
        raise HTTPException(status_code=400, detail="listing has expired")
    if listing.listing_type != LISTING_SERVICE:
        raise HTTPException(status_code=400, detail="MVP accepts digital services only")
    if listing.price_currency != MVP_CURRENCY:
        raise HTTPException(status_code=400, detail=f"MVP currency must be {MVP_CURRENCY}")
    if listing.settlement_methods != [MVP_SETTLEMENT_METHOD]:
        raise HTTPException(
            status_code=400,
            detail=f"MVP settlement method must be {MVP_SETTLEMENT_METHOD}",
        )


def _assert_mvp_order(order: OrderEvent) -> None:
    payload = order.payload
    if payload.get("listing_type") != LISTING_SERVICE:
        raise HTTPException(status_code=400, detail="MVP order must be a service")
    if payload.get("currency") != MVP_CURRENCY:
        raise HTTPException(status_code=400, detail="real-money order rejected")
    if payload.get("settlement_method") != MVP_SETTLEMENT_METHOD:
        raise HTTPException(status_code=400, detail="non-manual settlement rejected")


def _spine(request: Request, event_type: str, payload: Dict[str, Any]) -> str:
    spine = getattr(_state(request), "spine", None)
    if spine is None:
        return "spine unavailable"
    try:
        spine.append(event_type, payload)
        return ""
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        logger.warning("commerce spine projection failed for %s: %s", event_type, exc)
        return "audit projection failed"


def _configured_targets(workspace: Path) -> set[str]:
    values: set[str] = set()
    path = workspace / "federation" / "peers.json"
    try:
        raw = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
    except (OSError, UnicodeError, json.JSONDecodeError):
        raw = []
    candidates = [item for item in raw if isinstance(item, str)] if isinstance(raw, list) else []
    candidates.extend(
        item.strip()
        for item in os.environ.get("NTH_FED_PEERS", "").split(",")
        if item.strip()
    )
    for candidate in candidates:
        try:
            values.add(_normalize_target_url(candidate))
        except ValueError:
            logger.warning("ignored invalid commerce federation peer URL")
    return values


def _target_for_did(workspace: Path, target_did: str) -> str:
    """Resolve a DID only through operator-configured, identity-verified peers."""
    configured = _configured_targets(workspace)
    metadata = safe_load_json(
        workspace / "federation" / "peers_meta.json", fallback={},
    )
    if not isinstance(metadata, dict):
        return ""
    matches: set[str] = set()
    for raw_url, raw_meta in metadata.items():
        if not isinstance(raw_url, str) or not isinstance(raw_meta, dict):
            continue
        try:
            peer = _normalize_target_url(raw_url)
        except ValueError:
            continue
        if peer not in configured or raw_meta.get("did") != target_did:
            continue
        if raw_meta.get("peer_url") != peer:
            continue
        if raw_meta.get("identity_url") != f"{peer}/.well-known/nth-dao/identity.json":
            continue
        if (
            raw_meta.get("card_kind") != "nth-dao-identity-card-v1"
            or raw_meta.get("federation_protocol") != "nth-dao-federation-v1"
        ):
            continue
        try:
            expected_pubkey = decode_ed25519_did_key_hex(target_did)
        except ValueError:
            continue
        if not expected_pubkey or raw_meta.get("pubkey_hex") != expected_pubkey:
            continue
        matches.add(peer)
    return next(iter(matches)) if len(matches) == 1 else ""


def _preflight_response_target(
    request: Request,
    target_did: str,
    requested_url: str,
) -> str:
    workspace = Path(_state(request).workspace)
    verified_target = _target_for_did(workspace, target_did)
    if not requested_url.strip():
        return verified_target
    try:
        target = _normalize_target_url(requested_url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if target not in _configured_targets(workspace):
        raise HTTPException(
            status_code=400,
            detail="target_url is not a configured federation peer",
        )
    if not verified_target or target != verified_target:
        raise HTTPException(
            status_code=400,
            detail="target_url is not identity-bound to the response DID",
        )
    if target_did == _identity(request).as_did():
        raise HTTPException(status_code=400, detail="response target cannot be the local node")
    return target


def _queue_committed_response(
    request: Request,
    order_id: str,
    target_did: str,
    target: str,
) -> Dict[str, Any] | None:
    """Queue a response after the signed state transition is durable.

    At this point the local action is authoritative.  Transport failures must
    be reported as recoverable delivery state, never as an HTTP failure that
    invites the caller to repeat a non-repeatable state transition.
    """
    if not target:
        return None
    state = _state(request)
    try:
        queued = _queue_current(request, order_id, target_did, target)
    except (CommerceEnvelopeRejected, HTTPException, OSError, RuntimeError, TypeError, ValueError) as exc:
        detail = exc.detail if isinstance(exc, HTTPException) else str(exc)
        logger.warning("commerce action committed but queueing failed for %s: %s", order_id, detail)
        return {
            "message_id": "",
            "status": "pending",
            "target_url": target,
            "recoverable": True,
            "error": str(detail)[:200],
        }
    # Persist before transport, then make one bounded delivery attempt.  A
    # failed peer call leaves the signed envelope pending for the reconciler;
    # an already acknowledged idempotent envelope must not be sent again.
    if queued["status"] == "acknowledged":
        return queued
    try:
        record = state.commerce_outbox.claim(queued["message_id"])
    except (CommerceEnvelopeRejected, OSError, RuntimeError, TypeError, ValueError) as exc:
        logger.warning(
            "commerce action committed but delivery claim failed for %s: %s",
            order_id,
            exc,
        )
        return {
            **queued,
            "status": "pending",
            "recoverable": True,
            "error": str(exc)[:200],
        }
    if record is None:
        current = state.commerce_outbox.get(queued["message_id"])
        if current is not None and current.status == "acknowledged":
            return {**queued, "status": "acknowledged"}
        return {**queued, "status": "pending", "error": "delivery is already in progress"}
    try:
        return {**queued, **_dispatch_record(state, record)}
    except (CommerceEnvelopeRejected, OSError, RuntimeError, TypeError, ValueError) as exc:
        logger.warning("commerce action committed but dispatch failed for %s: %s", order_id, exc)
        return {
            **queued,
            "status": "pending",
            "recoverable": True,
            "error": str(exc)[:200],
        }


def _normalize_target_url(value: str) -> str:
    """Return an exact operator-configured HTTP origin, without URL tricks."""
    if not isinstance(value, str) or not value.strip() or len(value) > 2048:
        raise ValueError("invalid target URL")
    parsed = urlsplit(value.strip())
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("target URL must use http or https")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("target URL must not contain credentials")
    if not parsed.hostname or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("target URL must be an origin without path, query, or fragment")
    try:
        port = parsed.port
        host = parsed.hostname.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError) as exc:
        raise ValueError("target URL host or port is invalid") from exc
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc += f":{port}"
    return urlunsplit((parsed.scheme.lower(), netloc, "", "", ""))


class _RejectPeerRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code, "commerce peer redirect rejected", headers, fp,
        )


_PEER_OPENER = urllib.request.build_opener(_RejectPeerRedirect())


def _enforce_anonymous_limit(request: Request, limiter_name: str) -> None:
    limiter = getattr(_state(request), limiter_name, None)
    if limiter is None:
        raise HTTPException(status_code=503, detail="commerce rate limiter unavailable")
    client = request.client.host if request.client is not None else "unknown"
    decision = limiter.check(client or "unknown")
    if not decision.allowed:
        retry = max(1, int(decision.retry_after_seconds + 0.999))
        raise HTTPException(
            status_code=429,
            detail="commerce request rate limit exceeded",
            headers={"Retry-After": str(retry)},
        )


def _guard_sensitive_read(
    request: Request,
    guard: Callable[[Request], None] | None,
) -> None:
    if bool(getattr(request.app.state, "nth_require_console_auth", False)):
        if guard is None:
            raise HTTPException(status_code=503, detail="sensitive read guard unavailable")
        guard(request)


def _queue_current(request: Request, order_id: str, target_did: str, target_url: str) -> Dict[str, Any]:
    state = _state(request)
    identity = _identity(request)
    try:
        target = _normalize_target_url(target_url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if target not in _configured_targets(Path(state.workspace)):
        raise HTTPException(status_code=400, detail="target_url is not a configured federation peer")
    order = state.commerce_orders.get(order_id)
    if order is None:
        raise HTTPException(status_code=404, detail="order not found")
    if identity.as_did() not in {order.payload["buyer_did"], order.payload["seller_did"]}:
        raise HTTPException(status_code=403, detail="local node is not an order party")
    if target_did not in {order.payload["buyer_did"], order.payload["seller_did"]} or target_did == identity.as_did():
        raise HTTPException(status_code=400, detail="target DID must be the other order party")
    if _target_for_did(Path(state.workspace), target_did) != target:
        raise HTTPException(status_code=400, detail="target_url is not identity-bound to the target DID")
    envelope = sign_envelope(
        identity,
        target_did=target_did,
        payload={
            "order": order.to_dict(),
            "trade_events": state.commerce_trades.get_events(order_id) or [],
        },
        created_at_ms=now_ms(),
    )
    record = state.commerce_outbox.enqueue(envelope, target_url=target)
    return {
        "message_id": envelope.message_id,
        "status": record.status,
        "target_url": record.target_url,
    }


def _record_dispatch_attempt(
    state: Any,
    message_id: str,
    lease_id: str,
    *,
    acknowledged_at_ms: int = 0,
    error: str = "",
) -> tuple[bool, str]:
    """Persist one leased delivery result without reviving a stale worker."""
    try:
        record = state.commerce_outbox.record_attempt(
            message_id,
            acknowledged_at_ms=acknowledged_at_ms,
            error=error,
            lease_id=lease_id,
        )
    except (CommerceEnvelopeRejected, OSError, RuntimeError, TypeError, ValueError) as exc:
        try:
            current = state.commerce_outbox.get(message_id)
        except (CommerceEnvelopeRejected, OSError, RuntimeError, TypeError, ValueError):
            current = None
        if current is not None and current.status == "acknowledged":
            return True, ""
        logger.warning("commerce delivery result lost its lease for %s: %s", message_id, exc)
        return False, f"delivery result was not persisted: {exc}"[:200]
    return record.status == "acknowledged", str(record.last_error or "")[:200]


def _dispatch_record(state: Any, record: Any) -> Dict[str, Any]:
    message_id = str(record.envelope.get("message_id", ""))
    try:
        target = _normalize_target_url(record.target_url)
        if target not in _configured_targets(Path(state.workspace)):
            raise CommerceEnvelopeRejected("target is no longer a configured federation peer")
        envelope = CommerceEnvelope.from_dict(record.envelope)
        ok, reason = verify_envelope(envelope)
        if not ok:
            raise CommerceEnvelopeRejected(reason)
        local_did = state.node_identity.as_did()
        if envelope.source_did != local_did:
            raise CommerceEnvelopeRejected("outbox source is not the local node")
        if _target_for_did(Path(state.workspace), envelope.target_did) != target:
            raise CommerceEnvelopeRejected("target is not identity-bound to the envelope DID")
    except (CommerceEnvelopeRejected, ValueError, AttributeError) as exc:
        acknowledged, _persist_error = _record_dispatch_attempt(
            state,
            message_id,
            str(getattr(record, "lease_id", "")),
            error=str(exc),
        )
        if acknowledged:
            return {"message_id": message_id, "status": "acknowledged"}
        return {"message_id": message_id, "status": "pending", "error": str(exc)[:200]}
    url = target + "/api/v2/commerce/federation/sync"
    body = json.dumps(
        {"envelope": record.envelope}, ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with _PEER_OPENER.open(req, timeout=10.0) as response:  # noqa: S310 - operator-pinned peer
            if response.status < 200 or response.status >= 300:
                raise OSError(f"peer returned HTTP {response.status}")
            raw = response.read(65_536)
        result = json.loads(raw.decode("utf-8"))
        if not isinstance(result, dict):
            raise OSError("peer acknowledgement has the wrong shape")
        ack = CommerceAck.from_dict(result.get("ack"))
        ok, reason = verify_ack(ack)
        if not ok:
            raise OSError(f"peer acknowledgement signature rejected: {reason}")
        order_raw = envelope.payload.get("order")
        trade_events = envelope.payload.get("trade_events")
        if not isinstance(order_raw, dict) or not isinstance(trade_events, list):
            raise OSError("outbox envelope payload is malformed")
        if (
            ack.message_id != envelope.message_id
            or ack.order_id != order_raw.get("order_id")
            or ack.received_chain_head != trade_chain_head(trade_events)
            or ack.receiver_did != envelope.target_did
        ):
            raise OSError("peer acknowledgement binding rejected")
        acknowledged, persist_error = _record_dispatch_attempt(
            state,
            message_id,
            str(getattr(record, "lease_id", "")),
            acknowledged_at_ms=now_ms(),
        )
        if not acknowledged:
            return {
                "message_id": message_id,
                "status": "pending",
                "error": persist_error or "delivery acknowledgement was not persisted",
            }
        return {"message_id": message_id, "status": "acknowledged"}
    except (
        CommerceEnvelopeRejected,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        urllib.error.URLError,
    ) as exc:
        acknowledged, persist_error = _record_dispatch_attempt(
            state,
            message_id,
            str(getattr(record, "lease_id", "")),
            error=str(exc),
        )
        if acknowledged:
            return {"message_id": message_id, "status": "acknowledged"}
        return {
            "message_id": message_id,
            "status": "pending",
            "error": persist_error or str(exc)[:200],
        }


def _peer_json(
    target_url: str,
    path: str,
    *,
    payload: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    url = target_url.rstrip("/") + path
    data = None
    method = "GET"
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        method = "POST"
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with _PEER_OPENER.open(request, timeout=10.0) as response:  # noqa: S310 - exact configured peer
            raw = response.read(512 * 1024 + 1)
            if len(raw) > 512 * 1024:
                raise OSError("peer response too large")
    except (OSError, urllib.error.URLError) as exc:
        raise HTTPException(status_code=502, detail=f"commerce peer unavailable: {exc}")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=502, detail="commerce peer returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise HTTPException(status_code=502, detail="commerce peer returned the wrong shape")
    return value


def register_commerce_routes(
    app: FastAPI,
    *,
    sensitive_read_guard: Callable[[Request], None] | None = None,
) -> None:
    @app.post("/api/v2/commerce/listings")
    def publish_listing(body: PublishListingBody, request: Request) -> Dict[str, Any]:
        state = _state(request)
        identity = _identity(request)
        _assert_bounded_listing_details(body.details)
        created = now_ms()
        listing = sign_listing(identity, SignedListing(
            listing_id=body.listing_id,
            listing_type=LISTING_SERVICE,
            seller_did=identity.as_did(),
            title=body.title,
            description=body.description,
            price_value=body.price_value,
            price_currency=MVP_CURRENCY,
            settlement_methods=[MVP_SETTLEMENT_METHOD],
            details={**body.details, "fulfillment_type": "digital"},
            published_at_ms=created,
            not_after_ms=created + body.ttl_seconds * 1000,
        ))
        _assert_mvp_listing(listing)
        try:
            announcement = publish_listing_announcement(
                state.commerce_listings,
                MarketFeed(state.workspace, spine=getattr(state, "spine", None)),
                seller=identity,
                listing=listing,
                capability_set=body.capabilities,
            )
        except (ListingRejected, ValueError) as exc:
            raise HTTPException(status_code=400, detail=f"publish rejected: {exc}")
        digest = listing_digest(listing)
        warning = _spine(request, "commerce.listing.published", {
            "listing_digest": digest, "announcement_id": announcement.announcement_id,
        })
        return {"digest": digest, "listing": listing.to_dict(), "announcement": announcement.to_dict(), "warning": warning}

    @app.get("/api/v2/commerce/listings")
    def list_listings(request: Request) -> List[Dict[str, Any]]:
        store = _state(request).commerce_listings
        rows: List[Dict[str, Any]] = []
        for path in sorted(store.root.glob("*.json"), key=lambda item: item.stat().st_mtime_ns, reverse=True)[:1000]:
            digest = "sha256:" + path.stem
            listing = store.get(digest)
            if listing is not None:
                rows.append({"digest": digest, "listing": listing.to_dict(), "source": "local"})
        return rows

    @app.get("/api/v2/commerce/listings/{digest}")
    def get_listing(digest: str, request: Request) -> Dict[str, Any]:
        try:
            listing = _state(request).commerce_listings.get(digest)
        except ListingRejected:
            listing = None
        if listing is None:
            raise HTTPException(status_code=404, detail="listing not found")
        return {"digest": digest, "listing": listing.to_dict()}

    @app.post("/api/v2/commerce/intents")
    def issue_intent(body: IntentBody, request: Request) -> Dict[str, Any]:
        state = _state(request)
        identity = _identity(request)
        listing = _listing_from(body.listing)
        _assert_mvp_listing(listing)
        issued, expires = _expiry(body.ttl_seconds)
        try:
            intent = sign_intent_mandate(build_intent_mandate(
                identity.as_did(), body.agent_did or identity.as_did(), body.purpose,
                {
                    "max_amount": {"value": listing.price_value, "currency": MVP_CURRENCY},
                    "allowed_counterparties": [listing.seller_did],
                    "allowed_settlement_methods": [MVP_SETTLEMENT_METHOD],
                },
                expires, issued_at=issued,
            ), identity, created_at=issued)
            digest = state.mandates.save_intent(intent)
        except (RuntimeError, TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=f"intent rejected: {exc}")
        return {"digest": digest, "intent": intent}

    @app.post("/api/v2/commerce/carts")
    def issue_cart(body: CartBody, request: Request) -> Dict[str, Any]:
        _enforce_anonymous_limit(request, "commerce_cart_limiter")
        state = _state(request)
        identity = _identity(request)
        listing = state.commerce_listings.get(body.listing_digest)
        if listing is None:
            raise HTTPException(status_code=404, detail="listing not found")
        _assert_mvp_listing(listing)
        if listing.seller_did != identity.as_did():
            raise HTTPException(status_code=403, detail="local node is not listing seller")
        ok = verify_intent_mandate(body.intent)
        if not ok.ok:
            raise HTTPException(status_code=400, detail=f"intent rejected: {ok.reason}")
        intent_subject = body.intent.get("credentialSubject", {})
        intent_digest_value = intent_mandate_digest(body.intent)
        try:
            with _operation_lock(
                state, "intent-cart",
                f"{identity.as_did()}|{intent_digest_value}|{body.listing_digest}",
            ):
                cart = _stored_cart_for(
                    state, intent_digest_value, body.listing_digest,
                )
                if cart is None:
                    issued, expires = _expiry(body.ttl_seconds)
                    cart = sign_cart_mandate(build_cart_mandate(
                        identity.as_did(), str(intent_subject.get("id") or ""),
                        intent_digest_value,
                        [{
                            "description": listing.title,
                            "listing_id": listing.listing_id,
                            "listing_digest": body.listing_digest,
                            "quantity": 1,
                        }],
                        {"value": listing.price_value, "currency": MVP_CURRENCY},
                        [MVP_SETTLEMENT_METHOD], expires, issued_at=issued,
                    ), identity, created_at=issued)
                    compatible, reason = cart_satisfies_intent(cart, body.intent)
                    if not compatible:
                        raise ValueError(reason)
                    state.mandates.save_cart(cart)
                digest = cart_mandate_digest(cart)
        except (RuntimeError, TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=f"cart rejected: {exc}")
        return {"digest": digest, "cart": cart}

    @app.post("/api/v2/commerce/orders")
    def create_checkout(body: CheckoutBody, request: Request) -> Dict[str, Any]:
        state = _state(request)
        identity = _identity(request)
        listing = _listing_from(body.listing)
        _assert_mvp_listing(listing)
        target = _preflight_response_target(
            request, listing.seller_did, body.target_url,
        )
        try:
            state.mandates.save_intent(body.intent)
            state.mandates.save_cart(body.cart)
            payment = _payment_for_cart(
                state, identity, listing, body.cart,
                ttl_seconds=body.ttl_seconds,
            )
            order = create_order_from_mandates(
                state.commerce_orders,
                authority=identity,
                intent=body.intent,
                cart=body.cart,
                payment=payment,
                listing=listing,
            )
            _assert_mvp_order(order)
            open_commerce_trade(
                state.commerce_trades, state.commerce_orders, order.order_id,
                authority=identity,
            )
        except (CheckoutRejected, OrderRejected, RuntimeError, TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=f"checkout rejected: {exc}")
        warning = _spine(request, "commerce.order.created", {"order_id": order.order_id})
        queued = _queue_committed_response(
            request, order.order_id, listing.seller_did, target,
        )
        return {
            "order": project_order(state.commerce_orders, state.commerce_trades, order.order_id, viewer_did=identity.as_did()),
            "payment": payment,
            "queued": queued,
            "warning": warning,
        }

    @app.post("/api/v2/commerce/checkout/remote")
    def remote_checkout(body: RemoteCheckoutBody, request: Request) -> Dict[str, Any]:
        state = _state(request)
        identity = _identity(request)
        try:
            target = _normalize_target_url(body.target_url)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        if target not in _configured_targets(Path(state.workspace)):
            raise HTTPException(status_code=400, detail="target_url is not a configured federation peer")
        request_key = body.idempotency_key
        record_path = (
            Path(state.workspace) / "commerce" / "checkout_requests"
            / f"{hashlib.sha256(request_key.encode('utf-8')).hexdigest()}.json"
        )
        with _operation_lock(state, "remote-checkout", request_key):
            progress = safe_load_json(record_path, fallback={})
            if not isinstance(progress, dict):
                raise HTTPException(status_code=409, detail="checkout recovery record is corrupt")
            request_binding = {
                "target_url": target,
                "listing_digest": body.listing_digest,
                "purpose": body.purpose,
            }
            stored_binding = progress.get("request")
            if stored_binding is None:
                if progress:
                    raise HTTPException(status_code=409, detail="checkout recovery record has no request binding")
                progress["request"] = request_binding
                atomic_write_json(record_path, progress)
            elif stored_binding != request_binding:
                raise HTTPException(status_code=409, detail="idempotency key is already bound to another checkout")
            listing_raw = progress.get("listing")
            if not isinstance(listing_raw, dict):
                listing_raw = _peer_json(
                    target,
                    f"/api/v2/commerce/federation/listings/{body.listing_digest}",
                )
                progress["listing"] = listing_raw
                atomic_write_json(record_path, progress)
            listing = _listing_from(listing_raw)
            _assert_mvp_listing(listing)
            if listing_digest(listing) != body.listing_digest:
                raise HTTPException(status_code=400, detail="peer listing digest mismatch")
            if _target_for_did(Path(state.workspace), listing.seller_did) != target:
                raise HTTPException(
                    status_code=400,
                    detail="commerce peer is not identity-bound to the listing seller DID",
                )

            intent = progress.get("intent")
            if not isinstance(intent, dict):
                issued, expires = _expiry(body.ttl_seconds)
                try:
                    intent = sign_intent_mandate(build_intent_mandate(
                        identity.as_did(), identity.as_did(), body.purpose,
                        {
                            "max_amount": {"value": listing.price_value, "currency": MVP_CURRENCY},
                            "allowed_counterparties": [listing.seller_did],
                            "allowed_settlement_methods": [MVP_SETTLEMENT_METHOD],
                        }, expires, issued_at=issued,
                    ), identity, created_at=issued)
                    state.mandates.save_intent(intent)
                except (RuntimeError, TypeError, ValueError) as exc:
                    raise HTTPException(status_code=400, detail=f"intent rejected: {exc}")
                progress["intent"] = intent
                atomic_write_json(record_path, progress)

            cart = progress.get("cart")
            if not isinstance(cart, dict):
                cart_response = _peer_json(
                    target,
                    "/api/v2/commerce/carts",
                    payload={
                        "listing_digest": body.listing_digest,
                        "intent": intent,
                        "ttl_seconds": body.ttl_seconds,
                    },
                )
                cart = cart_response.get("cart")
                if not isinstance(cart, dict):
                    raise HTTPException(status_code=502, detail="commerce peer omitted signed cart")
                progress["cart"] = cart
                atomic_write_json(record_path, progress)
            try:
                state.mandates.save_cart(cart)
                payment = _payment_for_cart(
                    state, identity, listing, cart,
                    ttl_seconds=body.ttl_seconds,
                )
                progress["payment"] = payment
                atomic_write_json(record_path, progress)
                order = create_order_from_mandates(
                    state.commerce_orders,
                    authority=identity,
                    intent=intent,
                    cart=cart,
                    payment=payment,
                    listing=listing,
                )
                _assert_mvp_order(order)
                open_commerce_trade(
                    state.commerce_trades, state.commerce_orders, order.order_id,
                    authority=identity,
                )
            except (CheckoutRejected, OrderRejected, RuntimeError, TypeError, ValueError) as exc:
                raise HTTPException(status_code=400, detail=f"checkout rejected: {exc}")
            progress["order_id"] = order.order_id
            atomic_write_json(record_path, progress)
            delivery = _queue_committed_response(
                request, order.order_id, listing.seller_did, target,
            ) or {"message_id": "", "status": "pending", "error": "route unavailable"}
        warning = _spine(request, "commerce.order.created", {"order_id": order.order_id})
        return {
            "order": project_order(
                state.commerce_orders, state.commerce_trades, order.order_id,
                viewer_did=identity.as_did(),
            ),
            "intent": intent,
            "cart": cart,
            "payment": payment,
            "delivery": delivery,
            "warning": warning,
        }

    @app.get("/api/v2/commerce/orders")
    def list_orders(request: Request, role: str = "") -> List[Dict[str, Any]]:
        _guard_sensitive_read(request, sensitive_read_guard)
        state = _state(request)
        did = _identity(request).as_did()
        try:
            return list_order_views(
                state.commerce_orders, state.commerce_trades,
                viewer_did=did, role=role or None,
            )
        except CommerceProjectionRejected as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.get("/api/v2/commerce/orders/{order_id}")
    def get_order(order_id: str, request: Request) -> Dict[str, Any]:
        _guard_sensitive_read(request, sensitive_read_guard)
        state = _state(request)
        try:
            return project_order(
                state.commerce_orders, state.commerce_trades, order_id,
                viewer_did=_identity(request).as_did(),
            )
        except CommerceProjectionRejected as exc:
            raise HTTPException(status_code=404, detail=str(exc))

    @app.post("/api/v2/commerce/orders/{order_id}/delivery")
    def deliver(order_id: str, body: DeliveryBody, request: Request) -> Dict[str, Any]:
        state = _state(request)
        identity = _identity(request)
        order = state.commerce_orders.get(order_id)
        if order is None:
            raise HTTPException(status_code=404, detail="order not found")
        target_did = order.payload["buyer_did"]
        target = _preflight_response_target(request, target_did, body.target_url)
        try:
            event = submit_delivery(state.commerce_trades, order_id, claimant=identity, delivery=body.delivery)
        except TradeRejected as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        warning = _spine(request, "commerce.delivery.submitted", {"order_id": order_id, "event": event.to_dict()})
        queued = _queue_committed_response(request, order_id, target_did, target)
        return {"order": project_order(state.commerce_orders, state.commerce_trades, order_id, viewer_did=identity.as_did()), "queued": queued, "warning": warning}

    @app.post("/api/v2/commerce/orders/{order_id}/verify")
    def verify_delivery(order_id: str, body: VerificationBody, request: Request) -> Dict[str, Any]:
        state = _state(request)
        identity = _identity(request)
        order = state.commerce_orders.get(order_id)
        if order is None:
            raise HTTPException(status_code=404, detail="order not found")
        target_did = order.payload["seller_did"]
        target = _preflight_response_target(request, target_did, body.target_url)
        try:
            event = record_verification(
                state.commerce_trades, order_id, verifier=identity,
                verdict=body.verdict, result=body.result,
            )
        except TradeRejected as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        warning = _spine(request, "commerce.delivery.verified", {"order_id": order_id, "event": event.to_dict()})
        queued = _queue_committed_response(request, order_id, target_did, target)
        return {"order": project_order(state.commerce_orders, state.commerce_trades, order_id, viewer_did=identity.as_did()), "queued": queued, "warning": warning}

    @app.post("/api/v2/commerce/orders/{order_id}/settle")
    def settle(order_id: str, body: SettlementBody, request: Request) -> Dict[str, Any]:
        state = _state(request)
        identity = _identity(request)
        order = state.commerce_orders.get(order_id)
        if order is None:
            raise HTTPException(status_code=404, detail="order not found")
        _assert_mvp_order(order)
        target_did = order.payload["seller_did"]
        target = _preflight_response_target(request, target_did, body.target_url)
        try:
            event = settle_trade(
                state.commerce_trades, order_id, settler=identity,
                adapter=ManualSettlementAdapter(),
                intent=SettlementIntent(
                    trade_id=order_id,
                    amount_minor=order.payload["amount_minor"],
                    currency=MVP_CURRENCY,
                    payee_did=order.payload["seller_did"],
                    payer_did=order.payload["buyer_did"],
                    memo=f"NTH DAO manual settlement {order_id}",
                ),
            )
        except (TradeRejected, RuntimeError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        warning = _spine(request, "commerce.settlement.completed", {"order_id": order_id, "event": event.to_dict()})
        queued = _queue_committed_response(request, order_id, target_did, target)
        return {"order": project_order(state.commerce_orders, state.commerce_trades, order_id, viewer_did=identity.as_did()), "queued": queued, "warning": warning}

    @app.post("/api/v2/commerce/orders/{order_id}/dispute")
    def dispute(order_id: str, body: DisputeBody, request: Request) -> Dict[str, Any]:
        state = _state(request)
        identity = _identity(request)
        order = state.commerce_orders.get(order_id)
        if order is None:
            raise HTTPException(status_code=404, detail="order not found")
        target_did = (
            order.payload["seller_did"]
            if identity.as_did() == order.payload["buyer_did"]
            else order.payload["buyer_did"]
        )
        target = _preflight_response_target(request, target_did, body.target_url)
        try:
            event = open_dispute(
                state.commerce_trades, order_id, disputant=identity,
                reason=body.reason, evidence=body.evidence,
            )
        except TradeRejected as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        warning = _spine(request, "commerce.dispute.opened", {"order_id": order_id, "event": event.to_dict()})
        queued = _queue_committed_response(request, order_id, target_did, target)
        return {"order": project_order(state.commerce_orders, state.commerce_trades, order_id, viewer_did=identity.as_did()), "queued": queued, "warning": warning}

    @app.post("/api/v2/commerce/orders/{order_id}/resolve")
    def resolve(order_id: str, body: ResolveBody, request: Request) -> Dict[str, Any]:
        state = _state(request)
        identity = _identity(request)
        order = state.commerce_orders.get(order_id)
        if order is None:
            raise HTTPException(status_code=404, detail="order not found")
        _assert_mvp_order(order)
        target_did = order.payload["seller_did"]
        target = _preflight_response_target(request, target_did, body.target_url)
        total = order.payload["amount_minor"]
        if body.resolution == RESOLUTION_SETTLE:
            settlement = ManualSettlementAdapter().settle(SettlementIntent(
                trade_id=order_id,
                amount_minor=total,
                currency=MVP_CURRENCY,
                payee_did=order.payload["seller_did"],
                payer_did=order.payload["buyer_did"],
                memo=f"NTH DAO dispute settlement {order_id}",
            )).to_payload()
        elif body.resolution == RESOLUTION_REFUND:
            settlement = {
                "adapter_id": "manual",
                "amount_minor": 0,
                "currency": MVP_CURRENCY,
                "payee_did": order.payload["buyer_did"],
                "payer_did": order.payload["buyer_did"],
                "refunded_amount_minor": total,
                "settled_at_ms": now_ms(),
            }
        elif body.resolution == RESOLUTION_SPLIT:
            seller_amount = body.seller_amount_minor
            if seller_amount is None or not 0 < seller_amount < total:
                raise HTTPException(
                    status_code=400,
                    detail="split resolution requires seller_amount_minor between zero and the order total",
                )
            settlement = {
                "adapter_id": "manual",
                "amount_minor": seller_amount,
                "currency": MVP_CURRENCY,
                "payee_did": order.payload["seller_did"],
                "payer_did": order.payload["buyer_did"],
                "refunded_amount_minor": total - seller_amount,
                "settled_at_ms": now_ms(),
            }
        else:
            raise HTTPException(status_code=400, detail="unknown dispute resolution")
        try:
            event = resolve_dispute(
                state.commerce_trades, order_id, resolver=identity,
                resolution=body.resolution, rationale=body.rationale,
                settlement=settlement,
            )
        except TradeRejected as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        warning = _spine(request, "commerce.dispute.resolved", {"order_id": order_id, "event": event.to_dict()})
        queued = _queue_committed_response(request, order_id, target_did, target)
        return {"order": project_order(state.commerce_orders, state.commerce_trades, order_id, viewer_did=identity.as_did()), "queued": queued, "warning": warning}

    @app.post("/api/v2/commerce/orders/{order_id}/queue")
    def queue_order(order_id: str, body: QueueBody, request: Request) -> Dict[str, Any]:
        return _queue_current(request, order_id, body.target_did, body.target_url)

    @app.get("/api/v2/commerce/outbox")
    def outbox(request: Request) -> List[Dict[str, Any]]:
        _guard_sensitive_read(request, sensitive_read_guard)
        return [record.__dict__ for record in _state(request).commerce_outbox.pending(limit=500)]

    @app.post("/api/v2/commerce/outbox/dispatch")
    def dispatch(request: Request) -> List[Dict[str, Any]]:
        state = _state(request)
        return [
            _dispatch_record(state, record)
            for record in state.commerce_outbox.claim_pending(limit=100)
        ]

    @app.post("/api/v2/commerce/federation/sync")
    def sync(body: SyncBody, request: Request) -> Dict[str, Any]:
        _enforce_anonymous_limit(request, "commerce_sync_limiter")
        state = _state(request)
        identity = _identity(request)
        try:
            envelope = CommerceEnvelope.from_dict(body.envelope)
        except CommerceEnvelopeRejected as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        ok, reason = verify_envelope(envelope)
        if not ok:
            raise HTTPException(status_code=400, detail=f"envelope rejected: {reason}")
        if envelope.target_did != identity.as_did():
            raise HTTPException(status_code=403, detail="envelope targets another DID")
        received_at = now_ms()
        if envelope.created_at_ms > received_at + _MAX_ENVELOPE_FUTURE_SKEW_MS:
            raise HTTPException(status_code=400, detail="envelope timestamp is too far in the future")
        if envelope.created_at_ms < received_at - _MAX_ENVELOPE_AGE_MS:
            raise HTTPException(status_code=400, detail="envelope exceeded the 30-day replay window")
        order_raw = envelope.payload.get("order")
        trade_events = envelope.payload.get("trade_events")
        if not isinstance(order_raw, dict) or not isinstance(trade_events, list) or not trade_events:
            raise HTTPException(status_code=400, detail="sync payload requires order and trade_events")
        try:
            order = OrderEvent.from_dict(order_raw)
            chain_head = trade_chain_head(trade_events)
            _assert_mvp_order(order)
            if envelope.source_did not in {order.payload["buyer_did"], order.payload["seller_did"]}:
                raise HTTPException(status_code=403, detail="envelope source is not an order party")
            if identity.as_did() not in {order.payload["buyer_did"], order.payload["seller_did"]}:
                raise HTTPException(status_code=403, detail="local node is not an order party")
            existing_ack = state.commerce_inbox.get_ack(
                envelope, order_id=order.order_id, chain_head=chain_head,
            )
            if existing_ack is not None:
                return {
                    "message_id": envelope.message_id,
                    "order_id": order.order_id,
                    "state": project_order(
                        state.commerce_orders, state.commerce_trades,
                        order.order_id, viewer_did=identity.as_did(),
                    )["state"],
                    "ack": existing_ack.to_dict(),
                    "replay": True,
                }
            state.commerce_orders.import_verified(order)
            state.commerce_trades.import_verified_events(order.order_id, trade_events)
        except HTTPException:
            raise
        except (CommerceEnvelopeRejected, OrderRejected, TradeRejected, RuntimeError, TypeError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=f"sync rejected: {exc}")
        try:
            ack, created = state.commerce_inbox.acknowledge(
                envelope,
                order_id=order.order_id,
                chain_head=chain_head,
                identity=identity,
                received_at_ms=received_at,
            )
        except CommerceEnvelopeRejected as exc:
            raise HTTPException(status_code=409, detail=f"inbox receipt rejected: {exc}") from exc
        if created:
            _spine(request, "commerce.replication.accepted", {
                "order_id": order.order_id, "message_id": envelope.message_id,
            })
        return {
            "message_id": envelope.message_id,
            "order_id": order.order_id,
            "state": project_order(
                state.commerce_orders, state.commerce_trades,
                order.order_id, viewer_did=identity.as_did(),
            )["state"],
            "ack": ack.to_dict(),
            "replay": not created,
        }
