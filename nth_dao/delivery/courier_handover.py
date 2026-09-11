"""Courier handover — end-to-end sealed delivery through a carrier.

The design doc §九 success scenario, implemented as a single protocol
function the host calls on the recipient's side:

    sender seals → carrier carries (CourierStore) → recipient drains →
    open_courier_envelope (integrity + TTL + signature) →
    recipient.inbox.accept → recipient signs ACK →
    courier.hand_over (remove only after success) →
    ACK travels back by any transport → sender.outbox marks delivered

``process_handover`` is the recipient-side half: drain the carrier,
open/validate each envelope, admit to the inbox, hand over the
successfully-opened ones, and return the signed ACK envelopes that the
host then ships back via any delivery transport. Failures are
per-envelope (a hostile carrier cannot poison the batch), and the
carrier's journal is only mutated after each envelope is safely inside
the recipient's inbox.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from nth_dao.delivery.acknowledgement import DeliveryAck, sign_ack
from nth_dao.delivery.courier import (
    CourierEnvelopeRejected,
    open_courier_envelope,
)
from nth_dao.delivery.courier_store import CourierStore
from nth_dao.delivery.envelope import (
    envelope_digest,
)
from nth_dao.delivery.inbox import DeliveryInbox
from nth_dao.identity import AgentIdentity

logger = logging.getLogger("nth_dao.courier")


class CourierHandoverError(RuntimeError):
    """Raised when the handover itself fails (not per-envelope rejections)."""


def process_handover(
    carrier_store: CourierStore,
    *,
    recipient: AgentIdentity,
    identity_private: Any,
    inbox: DeliveryInbox,
    now_ms: Optional[int] = None,
    max_items: int = 64,
) -> Dict[str, Any]:
    """Drain the carrier for this recipient and admit everything valid.

    Returns a report:

        {"accepted": [DeliveryAck...],       # one signed ACK per admitted
         "rejected": [{"courier_id", "reason"}...],  # per-envelope failures
         "opened": [TransportEnvelope...]}   # validated envelopes

    The carrier pool is mutated only by ``hand_over`` — envelopes that fail
    validation stay on the carrier (the host may inspect/forward them);
    envelopes that succeed are removed and their ACKs returned.
    """

    recipient_did = recipient.as_did()
    now = now_ms
    accepted_acks: List[DeliveryAck] = []
    opened_envelopes: List[Any] = []
    rejected: List[Dict[str, str]] = []

    envelopes = carrier_store.drain_for(recipient_did, max_items=max_items)
    for courier in envelopes:
        courier_id = courier.get("courier_id", "")
        try:
            envelope = open_courier_envelope(
                courier,
                recipient_did=recipient_did,
                identity_private=identity_private,
                now_ms=now if now is not None else 0,
            )
        except CourierEnvelopeRejected as exc:
            logger.info("courier handover rejected %s: %s", courier_id, exc)
            rejected.append(
                {"courier_id": str(courier_id)[:128], "reason": str(exc)[:256]}
            )
            continue

        decision = inbox.accept(envelope, now_ms=now)
        if decision.accepted or decision.duplicate:
            received_ms = now if now is not None else envelope.created_at_ms
            ack = sign_ack(
                recipient,
                message_id=envelope.message_id,
                envelope_sha256=envelope_digest(envelope),
                received_at_ms=received_ms,
            )
            carrier_store.hand_over(courier)
            accepted_acks.append(ack)
            opened_envelopes.append(envelope)
        else:
            # inbox refused (replay/authorization/etc.) — keep on carrier,
            # report the reason; the host decides whether to inspect
            rejected.append(
                {"courier_id": str(courier_id)[:128], "reason": decision.reason[:256]}
            )

    return {
        "accepted": accepted_acks,
        "rejected": rejected,
        "opened": opened_envelopes,
    }


def ack_envelopes_from_report(
    report: Dict[str, Any],
    *,
    recipient: AgentIdentity,
    sender_did: str,
    now_ms: int,
) -> List[Any]:
    """Wrap the report's ACKs as signed delivery.ack envelopes addressed to
    the sender, ready for any outbound transport (design doc: the ACK
    travels back "by any transport")."""

    from nth_dao.delivery.envelope import sign_envelope

    envelopes: List[Any] = []
    for ack in report.get("accepted", []):
        envelopes.append(
            sign_envelope(
                recipient,
                kind="delivery.ack",
                recipient=sender_did,
                payload={"ack": ack.to_dict()},
                created_at_ms=now_ms,
                expires_at_ms=now_ms + 3_600_000,
            )
        )
    return envelopes


__all__ = [
    "CourierHandoverError",
    "ack_envelopes_from_report",
    "process_handover",
]
