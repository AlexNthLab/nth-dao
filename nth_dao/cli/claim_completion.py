"""Agent-owned completion signing and offline verification of shared proofs."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from nth_dao.canonical_json import canonical_json
from nth_dao.identity import AgentIdentity
from nth_dao.market.claim_evidence import resolve_confirmed_claim_evidence
from nth_dao.market.completion_flow import (
    MAX_PORTABLE_COMPLETION_PROOF_BYTES,
    record_local_mission_completion,
    verify_portable_completion_proof,
)
from nth_dao.market.mission_completion import receipt_digest
from nth_dao.market.source_completion_receipt import (
    MAX_SOURCE_RECEIPT_EVENT_BYTES,
    MAX_SOURCE_RECEIPT_RESPONSE_BYTES,
    verify_source_completion_receipt,
)


def _unique_json_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("JSON repeats a field")
        document[key] = value
    return document


def _read_json_object(path: Path, max_bytes: int) -> dict:
    with path.open("rb") as stream:
        raw = stream.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError("JSON input exceeds size limit")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_json_fields)
    if not isinstance(value, dict):
        raise TypeError("JSON input must be an object")
    return value


def _receipt_from_file(value: dict) -> tuple[dict, object]:
    """Accept a bare event or the operator REST response that carries it."""
    if "source_receipt_event" not in value:
        if len(canonical_json(value)) > MAX_SOURCE_RECEIPT_EVENT_BYTES:
            raise ValueError("source receipt event exceeds size limit")
        return value, None
    event = value["source_receipt_event"]
    chain = value.get("source_rotation_chain")
    if not isinstance(event, dict) or not isinstance(chain, list):
        raise TypeError("source response lacks a receipt event or rotation chain")
    if len(canonical_json(event)) > MAX_SOURCE_RECEIPT_EVENT_BYTES:
        raise ValueError("source receipt event exceeds size limit")
    payload = event.get("payload")
    if not isinstance(payload, dict) or value.get("audit_event_id") != event.get("content_hash"):
        raise ValueError("source response audit event ID differs from its event")
    if not payload.keys() <= value.keys() or canonical_json({
        field: value[field] for field in payload
    }) != canonical_json(payload):
        raise ValueError("source response fields differ from the signed event")
    return event, chain


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    record = commands.add_parser("record", help="sign a finished local Mission as its claimant")
    record.add_argument("--workspace", type=Path, required=True)
    record.add_argument("--identity-file", type=Path, required=True)
    record.add_argument("--nonce", required=True)
    record.add_argument("--mission-id", required=True)
    record.add_argument(
        "--resolve-fork", action="store_true",
        help="sign a merge of every locally verified completion head",
    )
    verify = commands.add_parser("verify", help="verify a transferred signed proof")
    verify_receipt = commands.add_parser(
        "verify-receipt", help="verify a source-signed receipt against a complete proof",
    )
    for command in (verify, verify_receipt):
        command.add_argument("--proof-file", type=Path, required=True)
        command.add_argument("--source-did", required=True)
        command.add_argument("--federation-key", required=True)
    verify_receipt.add_argument("--receipt-event-file", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "record":
            if not args.identity_file.is_file():
                raise ValueError("identity file is missing")
            identity = AgentIdentity.load(args.identity_file)
            evidence, created = record_local_mission_completion(
                args.workspace, args.nonce, args.mission_id, identity,
                resolve_fork=args.resolve_fork,
            )
            source_claim_id = resolve_confirmed_claim_evidence(
                args.workspace, args.nonce,
            )["authority_ack"]["ack_id"]
            print(json.dumps({
                "nonce": args.nonce,
                "source_claim_id": source_claim_id,
                "nonce_authenticated": False,
                "created": created,
                "outcome": evidence["completion_record"]["outcome"],
                "revision": evidence["completion_record"].get("revision", 0),
                "evidence_digest": receipt_digest(evidence),
            }, sort_keys=True))
        else:
            proof = _read_json_object(
                args.proof_file, MAX_PORTABLE_COMPLETION_PROOF_BYTES,
            )
            if args.command == "verify":
                valid, reason = verify_portable_completion_proof(
                    proof, expected_source_did=args.source_did,
                    expected_federation_key=args.federation_key,
                )
                print(json.dumps({
                    "verified": valid, "reason": reason,
                    "source_claim_id": proof.get("source_claim_id") if valid else None,
                    "nonce_authenticated": False,
                }, sort_keys=True))
            else:
                response = _read_json_object(
                    args.receipt_event_file, MAX_SOURCE_RECEIPT_RESPONSE_BYTES,
                )
                event, rotation_chain = _receipt_from_file(response)
                valid, reason = verify_source_completion_receipt(
                    proof, event, expected_source_did=args.source_did,
                    expected_federation_key=args.federation_key,
                    rotation_chain=rotation_chain,
                )
                print(json.dumps({
                    "receipt_verified": valid, "reason": reason,
                    "verification_scope": "source_statement_and_proof_binding",
                    "audit_inclusion_verified": False,
                    "source_retention_verified": False,
                    "source_claim_id": proof.get("source_claim_id") if valid else None,
                    "completion_head_digest": (
                        event["payload"]["completion_head_digest"] if valid else None
                    ),
                    "nonce_authenticated": False,
                    "accepted": False,
                    "settled": False,
                }, sort_keys=True))
            return 0 if valid else 1
    except (OSError, UnicodeError, ValueError, TypeError, RuntimeError, TimeoutError, RecursionError) as exc:
        print(f"claim completion failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
