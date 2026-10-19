"""Operator-only, offline receipt transfer; no routing or funds authority."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.concurrency import run_in_threadpool
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from nth_dao.delivery.envelope import MAX_ENVELOPE_BYTES, MAX_TTL_MS, TransportEnvelope
from nth_dao.identity import AgentIdentity
from nth_dao.market.claim_evidence import ClaimEvidenceUnavailable
from nth_dao.market.claimant_receipt_store import (
    ClaimantReceiptMissing,
    ClaimantReceiptPending,
    ClaimantReceiptRejected,
)
from nth_dao.market.source_receipt_ack import (
    SourceReceiptAckReceiver,
    SourceReceiptAckResult,
)
from nth_dao.market.source_receipt_ack_return import SourceReceiptAckReturnStore
from nth_dao.market.source_receipt_delivery import (
    SourceReceiptDeliveryDeferred,
    SourceReceiptDeliveryNotRetained,
    SourceReceiptDeliveryReceiver,
    SourceReceiptDeliveryRejected,
    source_receipt_delivery_failure,
)
from nth_dao.spine.log import SignedEventLog

logger = logging.getLogger(__name__)
_CLAIM_BASE = (
    "/api/v2/market/claim-intents/{nonce}/completion/source-receipt/deliveries"
)
_SOURCE_BASE = "/api/v2/market/completion-proofs/source-receipt-acks"
_CLAIM_PATH = re.compile(
    r"/api/v2/market/claim-intents/[^/]+/completion/source-receipt/deliveries"
)
_RETURN_PATH = re.compile(_CLAIM_PATH.pattern + r"/[^/]+/ack-return")
_RESUME_PATH = re.compile(_CLAIM_PATH.pattern + r"/reconcile")
_NONCE = re.compile(r"[A-Za-z0-9]{16,64}\Z")
_MESSAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SCOPE = {
    "verification_scope": "transport_receipt_only",
    "accepted": False,
    "settled": False,
}
LocalContext = tuple[Path, AgentIdentity, SignedEventLog]


def source_receipt_request_limit(scope: dict) -> int | None:
    """Share route classification with pre-buffer auth, quotas and body limits."""
    if scope.get("type") != "http":
        return None
    path = str(scope.get("path") or "")
    method = scope.get("method")
    if method == "GET" and _RETURN_PATH.fullmatch(path):
        return 0
    if method != "POST":
        return None
    if _CLAIM_PATH.fullmatch(path) or path == _SOURCE_BASE:
        return MAX_ENVELOPE_BYTES
    if _RETURN_PATH.fullmatch(path):
        return 4 * 1024
    if _RESUME_PATH.fullmatch(path) or path == _SOURCE_BASE + "/reconcile":
        return 0
    return None


class SourceReceiptNoStoreMiddleware:
    """Apply the receipt cache policy outside authentication and body guards."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if source_receipt_request_limit(scope) is None:
            await self.app(scope, receive, send)
            return
        started = False

        async def send_no_store(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                headers = [
                    (name, value)
                    for name, value in message.get("headers", [])
                    if name.lower() != b"cache-control"
                ]
                message = {
                    **message,
                    "headers": [*headers, (b"cache-control", b"no-store")],
                }
            await send(message)

        try:
            await self.app(scope, receive, send_no_store)
        except Exception:
            # Preserve the server's default 500/logging contract without losing
            # the receipt policy to the outer ServerErrorMiddleware response.
            if not started:
                await PlainTextResponse("Internal Server Error", status_code=500)(
                    scope, receive, send_no_store
                )
            raise


class _PrepareBody(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    ttl_ms: int = Field(default=600_000, ge=1, le=MAX_TTL_MS)


def _unique_fields(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("non-JSON numeric constant")


async def _object_body(request: Request) -> dict:
    try:
        value = json.loads(
            (await request.body()).decode("utf-8"),
            object_pairs_hook=_unique_fields,
            parse_constant=_reject_constant,
        )
        if not isinstance(value, dict):
            raise TypeError("object required")
        return value
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise HTTPException(
            status_code=422, detail="invalid receipt delivery JSON"
        ) from exc


def _selectors(
    request: Request, nonce: str | None = None, message_id: str | None = None
) -> None:
    if request.query_params:
        raise HTTPException(
            status_code=422, detail="receipt delivery does not accept query overrides"
        )
    if nonce is not None and _NONCE.fullmatch(nonce) is None:
        raise HTTPException(status_code=422, detail="invalid claim nonce")
    if message_id is not None and _MESSAGE_ID.fullmatch(message_id) is None:
        raise HTTPException(
            status_code=422, detail="invalid original delivery message ID"
        )


async def _call(action: Callable[[], Any]) -> Any:
    try:
        return await run_in_threadpool(action)
    except (
        SourceReceiptDeliveryDeferred,
        ClaimEvidenceUnavailable,
        ClaimantReceiptMissing,
        ClaimantReceiptPending,
    ) as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "receipt-evidence-unavailable",
                "retryable": True,
            },
        ) from exc
    except (SourceReceiptDeliveryRejected, ClaimantReceiptRejected) as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "receipt-delivery-rejected",
                "retryable": False,
            },
        ) from exc
    except SourceReceiptDeliveryNotRetained as exc:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "receipt-delivery-not-retained",
                "retryable": False,
            },
        ) from exc
    except (
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
        OverflowError,
        RecursionError,
    ) as exc:
        logger.warning("receipt delivery unavailable (%s)", type(exc).__name__)
        failure = source_receipt_delivery_failure("", exc)
        raise HTTPException(
            status_code=503,
            detail={
                "code": "receipt-delivery-storage-unavailable"
                if failure.retryable
                else "receipt-delivery-integrity-failed",
                "retryable": failure.retryable,
            },
        ) from exc


def _source_result(result: SourceReceiptAckResult) -> dict:
    return {
        **_SCOPE,
        "message_id": result.message_id,
        "original_message_id": result.delivery.message_id,
        "state": result.delivery.state,
        "receiver_did": result.delivery.delivered_by,
    }


def _batch(batch: Any, project: Callable[[Any], dict]) -> dict:
    return {
        **_SCOPE,
        "complete": not batch.failures,
        "results": [project(item) for item in batch.results],
        "failures": [
            {
                "message_id": item.message_id,
                "error_code": item.error_code,
                "retryable": item.retryable,
            }
            for item in batch.failures
        ],
    }


def _claimant_result(result: Any) -> dict:
    return {
        **_SCOPE,
        "message_id": result.ack.message_id,
        "ack": result.ack.to_dict(),
        "observation": result.observation,
    }


def register_source_receipt_delivery_routes(
    app: FastAPI,
    *,
    operator_guard: Callable[[Request], None],
    json_guard: Callable[[Request], None],
    context_for: Callable[[Request], LocalContext],
) -> None:
    """Use this node's existing identity/Spine, never a supplied key or route."""

    def receiver(
        context: LocalContext, nonce: str, *, read_only: bool = False
    ) -> SourceReceiptDeliveryReceiver:
        workspace, identity, spine = context
        return SourceReceiptDeliveryReceiver(
            workspace, nonce=nonce, identity=identity, spine=spine, read_only=read_only
        )

    def source_receiver(context: LocalContext) -> SourceReceiptAckReceiver:
        workspace, identity, spine = context
        return SourceReceiptAckReceiver(workspace, identity=identity, spine=spine)

    def authorize(
        request: Request, nonce: str | None = None, message_id: str | None = None
    ) -> LocalContext:
        operator_guard(request)
        _selectors(request, nonce, message_id)
        if request.method == "POST":
            json_guard(request)
        return context_for(request)

    @app.post(_CLAIM_BASE)
    async def receive_delivery(nonce: str, request: Request) -> dict:
        context = authorize(request, nonce)
        body = await _object_body(request)

        def receive() -> dict:
            try:
                envelope = TransportEnvelope.from_dict(body)
            except (TypeError, ValueError, RecursionError) as exc:
                raise SourceReceiptDeliveryRejected(
                    "invalid delivery envelope"
                ) from exc
            return _claimant_result(receiver(context, nonce).receive(envelope))

        return await _call(receive)

    @app.post(_CLAIM_BASE + "/reconcile")
    async def resume_deliveries(nonce: str, request: Request) -> dict:
        context = authorize(request, nonce)
        if await request.body():
            raise HTTPException(
                status_code=400, detail="reconciliation requires an empty body"
            )
        return await _call(
            lambda: _batch(receiver(context, nonce).resume_pending(), _claimant_result)
        )

    @app.post(_CLAIM_BASE + "/{message_id}/ack-return")
    async def prepare_return(nonce: str, message_id: str, request: Request) -> dict:
        context = authorize(request, nonce, message_id)
        try:
            body = _PrepareBody.model_validate(await _object_body(request))
        except ValidationError as exc:
            raise HTTPException(
                status_code=422, detail="invalid ACK return preparation options"
            ) from exc
        envelope = await _call(
            lambda: SourceReceiptAckReturnStore(receiver(context, nonce)).prepare(
                message_id,
                ttl_ms=body.ttl_ms,
            )
        )
        return {**_SCOPE, "envelope": envelope.to_dict()}

    @app.get(_CLAIM_BASE + "/{message_id}/ack-return")
    async def export_return(nonce: str, message_id: str, request: Request) -> dict:
        context = authorize(request, nonce, message_id)
        envelope = await _call(
            lambda: SourceReceiptAckReturnStore(
                receiver(context, nonce, read_only=True)
            ).get(message_id)
        )
        return {**_SCOPE, "envelope": envelope.to_dict()}

    @app.post(_SOURCE_BASE)
    async def receive_ack(request: Request) -> dict:
        context = authorize(request)
        body = await _object_body(request)

        def receive() -> dict:
            try:
                envelope = TransportEnvelope.from_dict(body)
            except (TypeError, ValueError, RecursionError) as exc:
                raise SourceReceiptDeliveryRejected(
                    "invalid ACK return envelope"
                ) from exc
            return _source_result(source_receiver(context).receive(envelope))

        return await _call(receive)

    @app.post(_SOURCE_BASE + "/reconcile")
    async def resume_acks(request: Request) -> dict:
        context = authorize(request)
        if await request.body():
            raise HTTPException(
                status_code=400, detail="reconciliation requires an empty body"
            )
        return await _call(
            lambda: _batch(source_receiver(context).resume_pending(), _source_result)
        )
