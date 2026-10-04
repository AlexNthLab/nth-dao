"""Agent-owned completion signing and offline verification of shared proofs."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from nth_dao.identity import AgentIdentity
from nth_dao.market.claim_evidence import resolve_confirmed_claim_evidence
from nth_dao.market.completion_flow import (
    MAX_PORTABLE_COMPLETION_PROOF_BYTES,
    record_local_mission_completion, verify_portable_completion_proof,
)
from nth_dao.market.mission_completion import receipt_digest


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
    verify.add_argument("--proof-file", type=Path, required=True)
    verify.add_argument("--source-did", required=True)
    verify.add_argument("--federation-key", required=True)
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
            with args.proof_file.open("rb") as stream:
                raw = stream.read(MAX_PORTABLE_COMPLETION_PROOF_BYTES + 1)
            if len(raw) > MAX_PORTABLE_COMPLETION_PROOF_BYTES:
                raise ValueError("portable proof exceeds size limit")
            proof = json.loads(raw.decode("utf-8"))
            valid, reason = verify_portable_completion_proof(
                proof, expected_source_did=args.source_did,
                expected_federation_key=args.federation_key,
            )
            print(json.dumps({
                "verified": valid, "reason": reason,
                "source_claim_id": proof.get("source_claim_id") if valid else None,
                "nonce_authenticated": False,
            }, sort_keys=True))
            return 0 if valid else 1
    except (OSError, UnicodeError, ValueError, RuntimeError, TimeoutError, RecursionError) as exc:
        print(f"claim completion failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
