"""Agent-owned completion signing and offline verification of shared proofs."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from nth_dao.identity import AgentIdentity
from nth_dao.market.claim_evidence import resolve_confirmed_claim_evidence
from nth_dao.market.completion_flow import (
    MAX_PORTABLE_COMPLETION_PROOF_BYTES,
    build_portable_completion_proof_with_pins,
    record_local_mission_completion,
    verify_portable_completion_proof,
)
from nth_dao.market.mission_completion import receipt_digest
from nth_dao.market.source_completion_receipt import (
    MAX_SOURCE_RECEIPT_RESPONSE_BYTES,
    extract_source_completion_receipt,
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
    verify_receipt_local = commands.add_parser(
        "verify-receipt-local",
        help="verify against a local confirmed claim; writable lock/index space required",
        description=(
            "Verify a source receipt against local signed claim evidence. "
            "This may create lock files or refresh derived indexes; use a writable workspace. "
            "No signed protocol evidence is added."
        ),
    )
    verify_receipt_local.add_argument("--workspace", type=Path, required=True)
    verify_receipt_local.add_argument("--nonce", required=True)
    verify_receipt_local.add_argument("--receipt-event-file", type=Path, required=True)
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
            if args.command == "verify-receipt-local":
                response = _read_json_object(
                    args.receipt_event_file, MAX_SOURCE_RECEIPT_RESPONSE_BYTES,
                )
                event, rotation_chain = extract_source_completion_receipt(response)
                payload = event.get("payload")
                if not isinstance(payload, dict):
                    raise ValueError("source receipt completion head is invalid")
                head_digest = payload.get("completion_head_digest")
                if not isinstance(head_digest, str):
                    raise ValueError("source receipt completion head is invalid")
                built = build_portable_completion_proof_with_pins(
                    args.workspace, args.nonce,
                    head_digest=head_digest,
                )
                if built is None:
                    raise ValueError("matching local completion head is unavailable")
                proof, source_did, federation_key = built
            else:
                proof = _read_json_object(
                    args.proof_file, MAX_PORTABLE_COMPLETION_PROOF_BYTES,
                )
                source_did = args.source_did
                federation_key = args.federation_key
            if args.command == "verify":
                valid, reason = verify_portable_completion_proof(
                    proof, expected_source_did=source_did,
                    expected_federation_key=federation_key,
                )
                print(json.dumps({
                    "verified": valid, "reason": reason,
                    "source_claim_id": proof.get("source_claim_id") if valid else None,
                    "nonce_authenticated": False,
                }, sort_keys=True))
            else:
                if args.command != "verify-receipt-local":
                    response = _read_json_object(
                        args.receipt_event_file, MAX_SOURCE_RECEIPT_RESPONSE_BYTES,
                    )
                    event, rotation_chain = extract_source_completion_receipt(response)
                valid, reason = verify_source_completion_receipt(
                    proof, event, expected_source_did=source_did,
                    expected_federation_key=federation_key,
                    rotation_chain=rotation_chain,
                )
                result = {
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
                }
                if args.command == "verify-receipt-local":
                    result["pins_from_local_claim"] = True
                print(json.dumps(result, sort_keys=True))
            return 0 if valid else 1
    except (OSError, UnicodeError, ValueError, TypeError, RuntimeError, TimeoutError, RecursionError) as exc:
        print(f"claim completion failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
