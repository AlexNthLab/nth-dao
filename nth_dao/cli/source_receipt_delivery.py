"""Explicit offline source receipt packing, intake, and crash recovery."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import time
from collections.abc import Sequence
from pathlib import Path

from nth_dao.canonical_json import canonical_json
from nth_dao.delivery.acknowledgement import MAX_ACK_BYTES, DeliveryAck
from nth_dao.delivery.envelope import (
    MAX_ENVELOPE_BYTES,
    TransportEnvelope,
)
from nth_dao.delivery.outbox import DurableOutbox
from nth_dao.identity import AgentIdentity
from nth_dao.market.completion_flow import MAX_PORTABLE_COMPLETION_PROOF_BYTES
from nth_dao.market.source_completion_inbox import SourceCompletionInbox
from nth_dao.market.source_completion_receipt import (
    MAX_SOURCE_RECEIPT_RESPONSE_BYTES,
)
from nth_dao.market.source_receipt_delivery import (
    _MESSAGE_ID_RE,
    SOURCE_RECEIPT_DELIVERY_PREPARED_EVENT,
    SourceReceiptDeliveryReceiver,
    _checked_path,
    _receipt,
    _snapshot,
    _write_delivery_bytes,
    create_source_receipt_delivery,
    require_prepared_source_receipt_delivery,
    source_receipt_preparation_payload,
)
from nth_dao.spine.log import SignedEventLog
from nth_dao.util.io import InterProcessLock


def _unique_fields(pairs: list[tuple[str, object]]) -> dict:
    value: dict = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("delivery JSON repeats a field")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise ValueError(f"delivery JSON contains a non-JSON constant: {value}")


def _read(path: Path, maximum: int) -> dict:
    before = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
        raise ValueError("delivery input must be a bounded regular file")
    flags = (
        os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        after = path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode) or not stat.S_ISREG(after.st_mode)
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
            or (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
            or opened.st_size > maximum
        ):
            raise ValueError("delivery input changed or is not a bounded regular file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(maximum + 1)
    finally:
        os.close(fd)
    if len(raw) > maximum:
        raise ValueError("delivery JSON input exceeds size limit")
    value = json.loads(
        raw.decode("utf-8"), object_pairs_hook=_unique_fields,
        parse_constant=_reject_constant,
    )
    if not isinstance(value, dict):
        raise TypeError("delivery JSON input must be an object")
    return value


def _print(value: dict) -> None:
    # Escape the outer presentation only. Embedded canonical text survives
    # decoding exactly, including signed integers beyond JavaScript's range.
    print(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True))


def _outbox(workspace: Path) -> DurableOutbox:
    relative = Path(".nth/source_receipt_delivery_outbox")
    for name in ("outbox.journal.jsonl", "outbox.lock"):
        _checked_path(workspace, relative / name)
    return DurableOutbox(
        _checked_path(workspace, relative), retain_terminal_records=True, reject_links=True,
    )


def _spine(workspace: Path, relative: Path, identity: AgentIdentity) -> SignedEventLog:
    path = _checked_path(workspace, relative)
    _checked_path(workspace, relative.with_name(relative.name + ".append.pending"))
    InterProcessLock(path, reject_links=True).check_path()
    return SignedEventLog(path, identity, reject_links=True)


def _pack(args: argparse.Namespace, identity: AgentIdentity, proof: dict, response: dict,
          spine: SignedEventLog) -> TransportEnvelope:
    relative = Path(".nth/source_receipt_delivery_outbox")
    lock = _checked_path(args.workspace, relative / "preparation.lock")
    with InterProcessLock(lock, reject_links=True):
        now = int(time.time() * 1000)
        candidate = create_source_receipt_delivery(
            identity, proof, response, expected_source_did=args.source_did,
            expected_federation_key=args.federation_key, created_at_ms=now,
            expires_at_ms=now + args.ttl_seconds * 1000,
        )
        _, selected, _ = _receipt(candidate)
        retained = SourceCompletionInbox(
            args.workspace, source_did=identity.as_did(), spine=spine,
        ).get(proof["source_claim_id"], candidate.payload["completion_head_digest"][7:])
        if retained is None or canonical_json(retained["source_receipt_event"]) != canonical_json(selected):
            raise ValueError("selected receipt is not the source's audited retained receipt")
        directory = _checked_path(args.workspace, relative / "prepared" / selected["content_hash"])
        files = sorted(directory.iterdir()) if directory.exists() else []
        if len(files) > 32 or [path.name for path in files] != [f"{index:02d}.json" for index in range(len(files))]:
            raise ValueError("source delivery generation history is unsafe or incomplete")
        outbox = _outbox(args.workspace)
        previous = None
        generations = []
        for entry in files:
            path = _checked_path(args.workspace, relative / "prepared" / selected["content_hash"] / entry.name)
            generation = _snapshot(TransportEnvelope.from_dict(_read(path, MAX_ENVELOPE_BYTES)))
            _, event, _ = _receipt(generation)
            if event != selected or generation.sender_did != identity.as_did():
                raise ValueError("source delivery generation belongs to another receipt")
            if previous is not None and generation.created_at_ms < previous.expires_at_ms:
                raise ValueError("source delivery generations overlap")
            previous = generation
            generations.append(generation)
        renew_from = getattr(args, "renew_from", None)
        if renew_from is not None and not args.renew:
            raise ValueError("renew-from requires --renew")
        create_generation = previous is None
        envelope = previous
        if args.renew:
            if not isinstance(renew_from, str) or _MESSAGE_ID_RE.fullmatch(renew_from) is None:
                raise ValueError("renew requires --renew-from with a retained previous message ID")
            indexes = [index for index, item in enumerate(generations) if item.message_id == renew_from]
            if len(indexes) != 1:
                raise ValueError("renew-from does not identify one retained generation")
            index = indexes[0]
            predecessor = generations[index]
            if index + 1 < len(generations):
                # The predecessor is the operation key: an interrupted or
                # already completed renewal always reuses its exact child.
                envelope = generations[index + 1]
                create_generation = False
            else:
                if predecessor.expires_at_ms > now:
                    raise ValueError("renew requires the previous generation to expire")
                queued = outbox.get(predecessor.message_id)
                if queued is not None and queued.state == "delivered":
                    raise ValueError("a delivered receipt does not require renewal")
                create_generation = True
        if create_generation:
            if len(files) >= 32:
                raise ValueError("source delivery generation history is at capacity")
            envelope = candidate
            target = _checked_path(args.workspace, relative / "prepared" / selected["content_hash"] / f"{len(files):02d}.json")
            _write_delivery_bytes(args.workspace, target, canonical_json(envelope.to_dict()))
        assert envelope is not None
        spine.append_unique(
            SOURCE_RECEIPT_DELIVERY_PREPARED_EVENT,
            source_receipt_preparation_payload(envelope), unique_payload_fields=("message_id",),
        )
        require_prepared_source_receipt_delivery(
            envelope, workspace=args.workspace, identity=identity, spine=spine,
        )
        if outbox.get(envelope.message_id) is None:
            outbox.enqueue(envelope)
        return envelope


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    pack = commands.add_parser("pack", help="audit and queue one source receipt envelope; no network")
    receive = commands.add_parser("receive", help="verify, retain, and acknowledge an addressed envelope")
    resume = commands.add_parser("resume", help="resume only previously durable intake")
    export_ack = commands.add_parser("export-ack", help="reverify and export a retained result, even after expiry")
    export_envelope = commands.add_parser("export-envelope", help="reverify and export an existing source envelope")
    acknowledge = commands.add_parser("acknowledge", help="verify an ACK and close the source outbox record")
    for command in (pack, receive, resume, acknowledge, export_ack, export_envelope):
        command.add_argument("--workspace", type=Path, required=True)
        command.add_argument("--identity-file", type=Path, required=True)
        command.add_argument("--spine-file", type=Path, default=Path("spine/events.jsonl"))
    pack.add_argument("--proof-file", type=Path, required=True)
    pack.add_argument("--receipt-file", type=Path, required=True)
    pack.add_argument("--source-did", required=True)
    pack.add_argument("--federation-key", required=True)
    pack.add_argument("--ttl-seconds", type=int, default=600)
    pack.add_argument("--renew", action="store_true", help="explicitly create a new generation only after expiry")
    pack.add_argument("--renew-from", help="retained predecessor message ID; makes renewal retries idempotent")
    for command in (receive, resume, export_ack):
        command.add_argument("--nonce", required=True, help="local confirmed claim nonce, not a remote label")
    receive.add_argument("--envelope-file", type=Path, required=True)
    export_ack.add_argument("--message-id", required=True)
    export_envelope.add_argument("--message-id", required=True)
    acknowledge.add_argument("--ack-file", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if not args.identity_file.is_file():
            raise ValueError("signing identity file is missing; no key will be generated")
        identity = AgentIdentity.load(args.identity_file)
        if not identity.can_sign:
            raise ValueError("identity cannot sign")
        spine = _spine(args.workspace, args.spine_file, identity)
        if args.command == "pack":
            if not 1 <= args.ttl_seconds <= 604_800:
                raise ValueError("ttl-seconds must be between 1 and 604800")
            proof = _read(args.proof_file, MAX_PORTABLE_COMPLETION_PROOF_BYTES)
            response = _read(args.receipt_file, MAX_SOURCE_RECEIPT_RESPONSE_BYTES)
            envelope = _pack(args, identity, proof, response, spine)
            _print(envelope.to_dict())
        elif args.command == "export-envelope":
            queued = _outbox(args.workspace).get(args.message_id)
            if queued is None:
                raise ValueError("source delivery envelope is not retained")
            envelope = require_prepared_source_receipt_delivery(
                TransportEnvelope.from_dict(json.loads(queued.envelope_json)),
                workspace=args.workspace, identity=identity,
                spine=spine,
            )
            _print(envelope.to_dict())
        elif args.command == "acknowledge":
            ack = DeliveryAck.from_dict(_read(args.ack_file, MAX_ACK_BYTES))
            outbox = _outbox(args.workspace)
            queued = outbox.get(ack.message_id)
            if queued is None:
                raise ValueError("ack for unknown source receipt delivery")
            require_prepared_source_receipt_delivery(
                TransportEnvelope.from_dict(json.loads(queued.envelope_json)),
                workspace=args.workspace, identity=identity, spine=spine,
            )
            delivered = outbox.handle_ack(ack, allow_expired=True)
            spine.append_unique(
                "market.claim.completion.source_receipt.delivery.acknowledged",
                {
                    "message_id": delivered.message_id,
                    "envelope_sha256": delivered.envelope_sha256,
                    "receiver_did": delivered.delivered_by,
                    "verification_scope": "transport_receipt_only",
                    "accepted": False, "settled": False,
                },
                unique_payload_fields=("message_id",),
            )
            _print({
                "message_id": delivered.message_id, "state": delivered.state,
                "receiver_did": delivered.delivered_by,
                "verification_scope": "transport_receipt_only",
                "accepted": False, "settled": False,
            })
        else:
            envelope = (
                TransportEnvelope.from_dict(_read(args.envelope_file, MAX_ENVELOPE_BYTES))
                if args.command == "receive" else None
            )
            receiver = SourceReceiptDeliveryReceiver(
                args.workspace, nonce=args.nonce, identity=identity,
                spine=spine,
            )
            if envelope is not None or args.command == "export-ack":
                result = (
                    receiver.receive(envelope) if envelope is not None
                    else receiver.get_ack(args.message_id)
                )
                _print({"ack": result.ack.to_dict(), "observation": result.observation})
            else:
                batch = receiver.resume_pending()
                _print({"resumed": [
                    {"ack": result.ack.to_dict(), "observation": result.observation}
                    for result in batch.results
                ], "failed": [
                    {"message_id": item.message_id, "error_code": item.error_code, "reason": item.reason}
                    for item in batch.failures
                ]})
                if batch.failures:
                    return 1
    except (OSError, TypeError, ValueError, RuntimeError, TimeoutError, RecursionError) as exc:
        print(f"source receipt delivery failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
