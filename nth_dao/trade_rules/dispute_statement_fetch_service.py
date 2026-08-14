"""Context-aware responder service for signed Dispute Statement fetches."""

from __future__ import annotations

import hashlib
import secrets
import time
import logging
import threading
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from nth_dao.did_key import is_did_key
from nth_dao.spine import SignedEventLog
from nth_dao.trade_rules.agreement_order import TradeOrder
from nth_dao.trade_rules.canonical import trade_canonical_json
from nth_dao.trade_rules.dispute_statement_fetch_audit import (
    EVENT_TRADE_DISPUTE_STATEMENT_FETCH_SERVED,
    TradeDisputeStatementFetchAuditError,
    _audit_payload_from_verified,
    verify_trade_dispute_statement_fetch_audit_event,
)
from nth_dao.trade_rules.dispute_statement_fetch_journal import (
    TradeDisputeStatementFetchJournal,
    TradeDisputeStatementFetchJournalError,
    TradeDisputeStatementFetchJournalRecord,
)
from nth_dao.trade_rules.dispute_statement_retrieval import (
    DEFAULT_DISPUTE_STATEMENT_FETCH_CLOCK_SKEW_SECONDS,
    DEFAULT_MAX_DISPUTE_STATEMENT_FETCH_TTL_SECONDS,
    MAX_DISPUTE_STATEMENT_FETCH_SECONDS,
    TradeDisputeStatementFetchRequest,
    TradeDisputeStatementFetchRequestRejected,
    TradeDisputeStatementFetchResponse,
    TradeDisputeStatementFetchResponseRejected,
    _validate_response_observation,
    create_trade_dispute_statement_fetch_response,
)
from nth_dao.trade_rules.execution_receipt import TradeExecutionReceipt
from nth_dao.trade_rules.receipt_review import TradeReceiptReview
from nth_dao.trade_rules.transport_common import bounded_seconds, now_ns, timestamp_ns

logger = logging.getLogger(__name__)


class TradeDisputeStatementFetchServiceError(RuntimeError):
    """The responder could not complete an authenticated fetch."""


class TradeDisputeStatementFetchNotFound(TradeDisputeStatementFetchServiceError):
    """The exact requested Statement is not retained by this responder."""


class TradeDisputeStatementFetchInProgress(TradeDisputeStatementFetchServiceError):
    """Another worker still owns the bounded processing lease."""


class TradeDisputeStatementFetchRetryLater(TradeDisputeStatementFetchServiceError):
    """A previous failed lookup established a durable retry floor."""


@dataclass(frozen=True)
class TradeDisputeStatementFetchResult:
    request: TradeDisputeStatementFetchRequest
    request_digest: str
    response: TradeDisputeStatementFetchResponse
    response_digest: str
    audit_event_id: str
    replayed: bool


@dataclass(frozen=True)
class _VerifiedFetchInputs:
    order: TradeOrder
    receipt: TradeExecutionReceipt
    review: TradeReceiptReview
    request: TradeDisputeStatementFetchRequest
    cache_key: tuple[str, str, str, str]


def _utc_now(value: datetime | None) -> datetime:
    moment = value or datetime.now(timezone.utc)
    if (
        not isinstance(moment, datetime)
        or moment.tzinfo is None
        or moment.utcoffset() is None
    ):
        raise TradeDisputeStatementFetchRequestRejected(
            "at must be timezone-aware"
        )
    return moment.astimezone(timezone.utc)


def _format_timestamp_ns(value: int) -> str:
    seconds, nanoseconds = divmod(value, 1_000_000_000)
    base = datetime.fromtimestamp(seconds, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S"
    )
    if nanoseconds == 0:
        return base + "Z"
    return base + "." + f"{nanoseconds:09d}".rstrip("0") + "Z"


class TradeDisputeStatementFetchCoordinator:
    """Verify, reserve, retrieve, sign, persist, and replay one Fetch Response."""

    def __init__(
        self,
        journal: TradeDisputeStatementFetchJournal,
        statement_store: Any,
        *,
        responder_identity: Any,
        spine: SignedEventLog,
        package_resolver: Any,
        max_ttl_seconds: float = DEFAULT_MAX_DISPUTE_STATEMENT_FETCH_TTL_SECONDS,
        clock_skew_seconds: float = (
            DEFAULT_DISPUTE_STATEMENT_FETCH_CLOCK_SKEW_SECONDS
        ),
        processing_lease_seconds: float = 300.0,
        processing_wait_seconds: float = 30.0,
        retry_backoff_seconds: float = 1.0,
        processing_clock_ns: Callable[[], int] | None = None,
        verification_cache_entries: int = 64,
    ) -> None:
        if not isinstance(journal, TradeDisputeStatementFetchJournal):
            raise TypeError(
                "journal must be a TradeDisputeStatementFetchJournal"
            )
        if not callable(getattr(statement_store, "get", None)):
            raise TypeError("statement_store must expose get()")
        if not isinstance(spine, SignedEventLog):
            raise TypeError("spine must be a SignedEventLog")
        responder_did = responder_identity.as_did()
        if not isinstance(responder_did, str) or not is_did_key(responder_did):
            raise ValueError("responder_identity must expose an Ed25519 did:key")
        if not callable(getattr(responder_identity, "sign", None)):
            raise ValueError("responder_identity must support signing")
        if spine.signer_did != responder_did:
            raise ValueError("Spine signer must match fetch responder identity")
        max_ttl = bounded_seconds(
            max_ttl_seconds,
            label="max_ttl_seconds",
            error_type=ValueError,
            maximum=MAX_DISPUTE_STATEMENT_FETCH_SECONDS,
        )
        clock_skew = bounded_seconds(
            clock_skew_seconds,
            label="clock_skew_seconds",
            error_type=ValueError,
            maximum=MAX_DISPUTE_STATEMENT_FETCH_SECONDS,
        )
        processing_lease = bounded_seconds(
            processing_lease_seconds,
            label="processing_lease_seconds",
            error_type=ValueError,
            maximum=3_600.0,
        )
        if processing_lease <= 0:
            raise ValueError("processing_lease_seconds must be greater than zero")
        processing_wait = bounded_seconds(
            processing_wait_seconds,
            label="processing_wait_seconds",
            error_type=ValueError,
            maximum=MAX_DISPUTE_STATEMENT_FETCH_SECONDS,
        )
        retry_backoff = bounded_seconds(
            retry_backoff_seconds,
            label="retry_backoff_seconds",
            error_type=ValueError,
            maximum=MAX_DISPUTE_STATEMENT_FETCH_SECONDS,
        )
        if retry_backoff <= 0:
            raise ValueError("retry_backoff_seconds must be greater than zero")
        if processing_clock_ns is not None and not callable(processing_clock_ns):
            raise TypeError("processing_clock_ns must be callable")
        if (
            isinstance(verification_cache_entries, bool)
            or not isinstance(verification_cache_entries, int)
            or not 1 <= verification_cache_entries <= 1_024
        ):
            raise ValueError(
                "verification_cache_entries must be an integer between 1 and 1024"
            )
        self.journal = journal
        self.statement_store = statement_store
        self.responder_identity = responder_identity
        self.responder_did = responder_did
        self.spine = spine
        self.package_resolver = package_resolver
        self.max_ttl_seconds = max_ttl
        self.clock_skew_seconds = clock_skew
        self.processing_lease_seconds = processing_lease
        self.processing_wait_seconds = processing_wait
        self.retry_backoff_seconds = retry_backoff
        self.processing_clock_ns = processing_clock_ns or time.time_ns
        self.verification_cache_entries = verification_cache_entries
        self._verification_cache_lock = threading.Lock()
        self._verification_cache: OrderedDict[
            tuple[str, str, str, str], _VerifiedFetchInputs
        ] = OrderedDict()
        self._verification_inflight: dict[
            tuple[str, str, str, str], threading.Event
        ] = {}
        self._response_cache: OrderedDict[
            tuple[str, str, str, str, str], TradeDisputeStatementFetchResponse
        ] = OrderedDict()
        self._audit_cache_lock = threading.Lock()
        self._audit_cache: OrderedDict[
            tuple[str, str, str], tuple[int, int, int, int, int]
        ] = OrderedDict()

    def receive(
        self,
        request: TradeDisputeStatementFetchRequest | dict[str, Any],
        *,
        review: TradeReceiptReview | dict[str, Any],
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
        at: datetime | None = None,
    ) -> TradeDisputeStatementFetchResult:
        """Return a stable signed response or fail without anonymous lookup."""

        moment = _utc_now(at)
        verified_inputs = self._verify_inputs(
            request,
            review=review,
            receipt=receipt,
            order=order,
        )
        verified_order = verified_inputs.order
        verified_receipt = verified_inputs.receipt
        verified_review = verified_inputs.review
        verified_request = verified_inputs.request
        if verified_request.to_dict()["responder_did"] != self.responder_did:
            raise TradeDisputeStatementFetchRequestRejected(
                "fetch request is addressed to another responder"
            )
        verified_request.assert_observed_at(
            at=moment,
            max_ttl_seconds=self.max_ttl_seconds,
            clock_skew_seconds=self.clock_skew_seconds,
        )

        observed_at_ns = now_ns(
            moment,
            error_type=TradeDisputeStatementFetchRequestRejected,
        )
        retained, _created = self.journal.reserve(
            verified_request,
            observed_at_ns=observed_at_ns,
        )
        if retained.completed:
            return self._replay(
                retained,
                request=verified_request,
                verified_inputs=verified_inputs,
                review=verified_review,
                receipt=verified_receipt,
                order=verified_order,
                at=moment,
            )

        owner_token = secrets.token_hex(32)
        retained, acquired = self._acquire_processing(
            verified_request,
            owner_token=owner_token,
            at_floor_ns=observed_at_ns,
        )
        if retained.completed:
            replay_at = moment if at is not None else _utc_now(None)
            return self._replay(
                retained,
                request=verified_request,
                verified_inputs=verified_inputs,
                review=verified_review,
                receipt=verified_receipt,
                order=verified_order,
                at=replay_at,
            )
        if not acquired:
            raise TradeDisputeStatementFetchInProgress(
                "fetch processing lease is still active"
            )

        request_document = verified_request.to_dict()
        try:
            statement = self.statement_store.get(
                request_document["statement_digest"],
                review=verified_review,
                receipt=verified_receipt,
                order=verified_order,
                package_resolver=self.package_resolver,
            )
            if statement is None:
                self.journal.release_processing(
                    verified_request,
                    owner_token=owner_token,
                    at_ns=max(self.processing_clock_ns(), observed_at_ns),
                    retry_after_seconds=self.retry_backoff_seconds,
                )
                raise TradeDisputeStatementFetchNotFound(
                    "requested Trade Dispute Statement is not retained"
                )
            response_moment = moment if at is not None else _utc_now(None)
            served_ns = now_ns(
                response_moment,
                error_type=TradeDisputeStatementFetchResponseRejected,
            )
            response = create_trade_dispute_statement_fetch_response(
                self.responder_identity,
                request=verified_request,
                statement=statement,
                review=verified_review,
                receipt=verified_receipt,
                order=verified_order,
                served_at=_format_timestamp_ns(served_ns),
                now=response_moment,
                max_ttl_seconds=self.max_ttl_seconds,
                clock_skew_seconds=self.clock_skew_seconds,
            )
            completed, created = self.journal.complete(
                verified_request,
                response,
                owner_token=owner_token,
                updated_at_ns=max(self.processing_clock_ns(), observed_at_ns),
            )
        except TradeDisputeStatementFetchNotFound:
            raise
        except Exception:
            self._release_after_failure(
                verified_request,
                owner_token=owner_token,
                at_floor_ns=observed_at_ns,
            )
            raise
        if completed.response_bytes != response.canonical_bytes:
            raise TradeDisputeStatementFetchServiceError(
                "retained fetch response changed during completion"
            )
        self._remember_response(verified_inputs, response)
        audit_event_id = self._ensure_audit(
            verified_request,
            response,
            review=verified_review,
            receipt=verified_receipt,
            order=verified_order,
        )
        return self._result(
            verified_request,
            response,
            verified_review,
            verified_receipt,
            verified_order,
            audit_event_id=audit_event_id,
            replayed=not created,
        )

    @staticmethod
    def _wire_digest(value: Any, expected_type: type[Any]) -> str | None:
        try:
            if isinstance(value, expected_type):
                canonical = value.canonical_bytes
            elif isinstance(value, dict):
                canonical = trade_canonical_json(value)
            else:
                return None
        except (TypeError, ValueError, UnicodeError):
            return None
        return hashlib.sha256(canonical).hexdigest()

    def _input_cache_key(
        self,
        request: TradeDisputeStatementFetchRequest | dict[str, Any],
        *,
        review: TradeReceiptReview | dict[str, Any],
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
    ) -> tuple[str, str, str, str] | None:
        parts = (
            self._wire_digest(order, TradeOrder),
            self._wire_digest(receipt, TradeExecutionReceipt),
            self._wire_digest(review, TradeReceiptReview),
            self._wire_digest(request, TradeDisputeStatementFetchRequest),
        )
        if any(part is None for part in parts):
            return None
        return (parts[0], parts[1], parts[2], parts[3])  # type: ignore[return-value]

    @staticmethod
    def _verify_inputs_uncached(
        request: TradeDisputeStatementFetchRequest | dict[str, Any],
        *,
        review: TradeReceiptReview | dict[str, Any],
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
    ) -> _VerifiedFetchInputs:
        verified_order = (
            TradeOrder.from_json(order.canonical_bytes)
            if isinstance(order, TradeOrder)
            else TradeOrder.from_dict(order)
        )
        verified_receipt = (
            TradeExecutionReceipt.from_json(
                receipt.canonical_bytes,
                order=verified_order,
            )
            if isinstance(receipt, TradeExecutionReceipt)
            else TradeExecutionReceipt.from_dict(receipt, order=verified_order)
        )
        verified_review = (
            TradeReceiptReview.from_json(
                review.canonical_bytes,
                receipt=verified_receipt,
                order=verified_order,
            )
            if isinstance(review, TradeReceiptReview)
            else TradeReceiptReview.from_dict(
                review,
                receipt=verified_receipt,
                order=verified_order,
            )
        )
        verified_request = (
            TradeDisputeStatementFetchRequest.from_json(
                request.canonical_bytes,
                review=verified_review,
                receipt=verified_receipt,
                order=verified_order,
            )
            if isinstance(request, TradeDisputeStatementFetchRequest)
            else TradeDisputeStatementFetchRequest.from_dict(
                request,
                review=verified_review,
                receipt=verified_receipt,
                order=verified_order,
            )
        )
        cache_key = (
            hashlib.sha256(verified_order.canonical_bytes).hexdigest(),
            hashlib.sha256(verified_receipt.canonical_bytes).hexdigest(),
            hashlib.sha256(verified_review.canonical_bytes).hexdigest(),
            hashlib.sha256(verified_request.canonical_bytes).hexdigest(),
        )
        return _VerifiedFetchInputs(
            order=verified_order,
            receipt=verified_receipt,
            review=verified_review,
            request=verified_request,
            cache_key=cache_key,
        )

    def _verify_inputs(
        self,
        request: TradeDisputeStatementFetchRequest | dict[str, Any],
        *,
        review: TradeReceiptReview | dict[str, Any],
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
    ) -> _VerifiedFetchInputs:
        key = self._input_cache_key(
            request,
            review=review,
            receipt=receipt,
            order=order,
        )
        if key is None:
            return self._verify_inputs_uncached(
                request,
                review=review,
                receipt=receipt,
                order=order,
            )
        while True:
            with self._verification_cache_lock:
                cached = self._verification_cache.get(key)
                if cached is not None:
                    self._verification_cache.move_to_end(key)
                    return cached
                pending = self._verification_inflight.get(key)
                if pending is None:
                    pending = threading.Event()
                    self._verification_inflight[key] = pending
                    break
            pending.wait()
        try:
            verified = self._verify_inputs_uncached(
                request,
                review=review,
                receipt=receipt,
                order=order,
            )
            if verified.cache_key != key:
                raise TradeDisputeStatementFetchRequestRejected(
                    "fetch inputs changed during verification"
                )
        except BaseException:
            with self._verification_cache_lock:
                self._verification_inflight.pop(key).set()
            raise
        with self._verification_cache_lock:
            self._verification_cache[key] = verified
            self._verification_cache.move_to_end(key)
            while len(self._verification_cache) > self.verification_cache_entries:
                self._verification_cache.popitem(last=False)
            self._verification_inflight.pop(key).set()
        return verified

    def _remember_response(
        self,
        verified_inputs: _VerifiedFetchInputs,
        response: TradeDisputeStatementFetchResponse,
    ) -> None:
        key = verified_inputs.cache_key + (
            hashlib.sha256(response.canonical_bytes).hexdigest(),
        )
        with self._verification_cache_lock:
            self._response_cache[key] = response
            self._response_cache.move_to_end(key)
            while len(self._response_cache) > self.verification_cache_entries:
                self._response_cache.popitem(last=False)

    def _acquire_processing(
        self,
        request: TradeDisputeStatementFetchRequest,
        *,
        owner_token: str,
        at_floor_ns: int,
    ) -> tuple[TradeDisputeStatementFetchJournalRecord, bool]:
        deadline = time.monotonic() + self.processing_wait_seconds
        while True:
            lease_now = max(self.processing_clock_ns(), at_floor_ns)
            retained, acquired = self.journal.claim_processing(
                request,
                owner_token=owner_token,
                at_ns=lease_now,
                lease_seconds=self.processing_lease_seconds,
            )
            if acquired or retained.completed:
                return retained, acquired
            if (
                retained.processing_owner is None
                and retained.next_retry_at_ns > lease_now
            ):
                raise TradeDisputeStatementFetchRetryLater(
                    "fetch retry is temporarily rate limited"
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return retained, False
            time.sleep(min(0.01, remaining))

    def _release_after_failure(
        self,
        request: TradeDisputeStatementFetchRequest,
        *,
        owner_token: str,
        at_floor_ns: int,
    ) -> None:
        try:
            self.journal.release_processing(
                request,
                owner_token=owner_token,
                at_ns=max(self.processing_clock_ns(), at_floor_ns),
                retry_after_seconds=self.retry_backoff_seconds,
            )
        except TradeDisputeStatementFetchJournalError:
            logger.warning(
                "unable to release failed fetch processing lease; "
                "the bounded lease remains recoverable",
                exc_info=True,
            )

    def _replay(
        self,
        retained: TradeDisputeStatementFetchJournalRecord,
        *,
        request: TradeDisputeStatementFetchRequest,
        verified_inputs: _VerifiedFetchInputs,
        review: TradeReceiptReview,
        receipt: TradeExecutionReceipt,
        order: TradeOrder,
        at: datetime,
    ) -> TradeDisputeStatementFetchResult:
        if retained.request_bytes != request.canonical_bytes:
            raise TradeDisputeStatementFetchServiceError(
                "retained fetch request changed after verification"
            )
        if retained.response_bytes is None or retained.response_digest is None:
            raise TradeDisputeStatementFetchServiceError(
                "completed fetch journal record has no response"
            )
        response_key = verified_inputs.cache_key + (
            retained.response_digest.removeprefix("sha256:"),
        )
        with self._verification_cache_lock:
            response = self._response_cache.get(response_key)
            if response is not None:
                self._response_cache.move_to_end(response_key)
        if response is None:
            response = TradeDisputeStatementFetchResponse.from_json(
                retained.response_bytes,
                request=request,
                review=review,
                receipt=receipt,
                order=order,
            )
            self._remember_response(verified_inputs, response)
        elif response.canonical_bytes != retained.response_bytes:
            raise TradeDisputeStatementFetchServiceError(
                "cached fetch response does not match retained bytes"
            )
        _validate_response_observation(
            response.to_dict(),
            request,
            at=at,
            max_ttl_seconds=self.max_ttl_seconds,
            clock_skew_seconds=self.clock_skew_seconds,
        )
        audit_event_id = (
            self._resolve_existing_audit(
                retained.audit_event_id,
                request,
                response,
                review=review,
                receipt=receipt,
                order=order,
            )
            if retained.audit_event_id is not None
            else self._ensure_audit(
                request,
                response,
                review=review,
                receipt=receipt,
                order=order,
            )
        )
        return self._result(
            request,
            response,
            review,
            receipt,
            order,
            audit_event_id=audit_event_id,
            replayed=True,
        )

    def _ensure_audit(
        self,
        request: TradeDisputeStatementFetchRequest,
        response: TradeDisputeStatementFetchResponse,
        *,
        review: TradeReceiptReview,
        receipt: TradeExecutionReceipt,
        order: TradeOrder,
    ) -> str:
        payload = _audit_payload_from_verified(request, response)
        served_ms = timestamp_ns(
            payload["served_at"],
            label="served_at",
            error_type=TradeDisputeStatementFetchAuditError,
        ) // 1_000_000
        try:
            event, _created = self.spine.append_unique(
                EVENT_TRADE_DISPUTE_STATEMENT_FETCH_SERVED,
                payload,
                unique_payload_fields=("request_digest",),
                ts_ms=served_ms,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            raise TradeDisputeStatementFetchAuditError(
                f"unable to append fetch disclosure audit: {exc}"
            ) from exc
        try:
            record = self.journal.mark_audited(
                request,
                response,
                audit_event=event,
                spine=self.spine,
                review=review,
                receipt=receipt,
                order=order,
                updated_at_ns=self.processing_clock_ns(),
            )
        except TradeDisputeStatementFetchJournalError as exc:
            raise TradeDisputeStatementFetchAuditError(
                f"unable to persist verified fetch audit binding: {exc}"
            ) from exc
        if record.audit_event_id != event.event_id:
            raise TradeDisputeStatementFetchAuditError(
                "fetch journal retained a conflicting audit event"
            )
        self._remember_verified_audit(request, response, event.event_id)
        return event.event_id

    @staticmethod
    def _audit_cache_key(
        request: TradeDisputeStatementFetchRequest,
        response: TradeDisputeStatementFetchResponse,
        audit_event_id: str,
    ) -> tuple[str, str, str]:
        return (
            hashlib.sha256(request.canonical_bytes).hexdigest(),
            hashlib.sha256(response.canonical_bytes).hexdigest(),
            audit_event_id,
        )

    def _remember_verified_audit(
        self,
        request: TradeDisputeStatementFetchRequest,
        response: TradeDisputeStatementFetchResponse,
        audit_event_id: str,
    ) -> None:
        key = self._audit_cache_key(request, response, audit_event_id)
        try:
            token = self.spine.storage_token()
        except OSError:
            return
        with self._audit_cache_lock:
            self._audit_cache[key] = token
            self._audit_cache.move_to_end(key)
            while len(self._audit_cache) > self.verification_cache_entries:
                self._audit_cache.popitem(last=False)

    def _resolve_existing_audit(
        self,
        audit_event_id: str,
        request: TradeDisputeStatementFetchRequest,
        response: TradeDisputeStatementFetchResponse,
        *,
        review: TradeReceiptReview,
        receipt: TradeExecutionReceipt,
        order: TradeOrder,
    ) -> str:
        key = self._audit_cache_key(request, response, audit_event_id)
        with self._audit_cache_lock:
            try:
                token = self.spine.storage_token()
            except OSError as exc:
                raise TradeDisputeStatementFetchAuditError(
                    "unable to inspect persisted fetch audit event"
                ) from exc
            if self._audit_cache.get(key) == token:
                self._audit_cache.move_to_end(key)
                return audit_event_id
            try:
                event = self.spine.reconcile_append(audit_event_id)
            except (OSError, RuntimeError, ValueError) as exc:
                raise TradeDisputeStatementFetchAuditError(
                    "unable to resolve persisted fetch audit event"
                ) from exc
            if event is None:
                raise TradeDisputeStatementFetchAuditError(
                    "fetch journal references an absent Spine audit event"
                )
            ok, reason = verify_trade_dispute_statement_fetch_audit_event(
                event,
                request,
                response,
                review=review,
                receipt=receipt,
                order=order,
            )
            if not ok:
                raise TradeDisputeStatementFetchAuditError(reason)
            if self.spine.storage_token() == token:
                self._audit_cache[key] = token
                self._audit_cache.move_to_end(key)
                while len(self._audit_cache) > self.verification_cache_entries:
                    self._audit_cache.popitem(last=False)
            return event.event_id

    @staticmethod
    def _result(
        request: TradeDisputeStatementFetchRequest,
        response: TradeDisputeStatementFetchResponse,
        review: TradeReceiptReview,
        receipt: TradeExecutionReceipt,
        order: TradeOrder,
        *,
        audit_event_id: str,
        replayed: bool,
    ) -> TradeDisputeStatementFetchResult:
        return TradeDisputeStatementFetchResult(
            request=request,
            request_digest=(
                "sha256:" + hashlib.sha256(request.canonical_bytes).hexdigest()
            ),
            response=response,
            response_digest=(
                "sha256:" + hashlib.sha256(response.canonical_bytes).hexdigest()
            ),
            audit_event_id=audit_event_id,
            replayed=replayed,
        )


__all__ = [
    "TradeDisputeStatementFetchCoordinator",
    "TradeDisputeStatementFetchInProgress",
    "TradeDisputeStatementFetchNotFound",
    "TradeDisputeStatementFetchResult",
    "TradeDisputeStatementFetchRetryLater",
    "TradeDisputeStatementFetchServiceError",
]
