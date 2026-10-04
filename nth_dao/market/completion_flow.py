"""Agent-owned completion production and portable, pinned proof verification."""

from __future__ import annotations

import hashlib
import re
import stat
import time
from pathlib import Path
from typing import Any

from nth_dao.canonical_json import canonical_json
from nth_dao.did_key import is_did_key
from nth_dao.execution_receipt import TimelineEntry, sign_receipt
from nth_dao.identity import AgentIdentity
from nth_dao.market.announcement import (
    TaskAnnouncement, announcement_federation_key, verify_announcement,
)
from nth_dao.market.claim_evidence import resolve_confirmed_claim_evidence
from nth_dao.market.claim import CLAIM_STATUS_CLAIMED, ClaimStore
from nth_dao.market.claim_intent import verify_claim_intent
from nth_dao.market.completion_store import ClaimCompletionStore, CompletionEvidenceConflict
from nth_dao.market.mission_completion import (
    CompletionLineageError, MissionCompletionRejected, receipt_digest,
    resolve_completion_lineage, sign_mission_completion, verify_mission_completion,
)
from nth_dao.market.feed import MarketFeed
from nth_dao.market.source_identity import source_identity_precedes
from nth_dao.orchestration.mission import MissionStatus, StepStatus
from nth_dao.orchestration.mission_store import MissionStore


_NONCE_RE = re.compile(r"[A-Za-z0-9]{16,64}\Z")
# The store accepts 32 envelopes of up to 512 KiB each. Leave bounded room
# for the signed announcement, claim receipt, intent, and authority ACK too.
MAX_PORTABLE_COMPLETION_PROOF_BYTES = 20 * 1024 * 1024
_MAX_REVISIONS = 32
_PROOF_FIELDS = frozenset({
    "kind", "version", "nonce", "source_claim_id", "announcement", "intent", "claim_receipt",
    "authority_ack", "completion_chain",
})


class SourceCompletionEvidenceUnavailable(RuntimeError):
    """Required local source evidence is absent, not proof-invalid."""


def record_local_mission_completion(
    workspace: Path, nonce: str, mission_id: str, claimant: AgentIdentity,
    *, resolve_fork: bool = False,
) -> tuple[dict[str, Any], bool]:
    """A claimant process signs only its own finished local Mission snapshot."""
    workspace = Path(workspace)
    if not claimant.can_sign:
        raise MissionCompletionRejected("claimant identity cannot sign")
    evidence = resolve_confirmed_claim_evidence(workspace, nonce)
    claimant_did = claimant.as_did()
    if evidence["intent"]["claimant_did"] != claimant_did:
        raise MissionCompletionRejected("identity is not the confirmed claimant")
    store = MissionStore(str(workspace / "missions"))
    mission = store.get(mission_id)
    if mission is None:
        raise MissionCompletionRejected("local mission is missing")
    if mission.owner_did != claimant_did:
        raise MissionCompletionRejected("claimant is not the mission owner")
    if not isinstance(mission.metadata, dict):
        raise MissionCompletionRejected("mission metadata is invalid")
    claimed_mission_id = evidence["claim_receipt"]["timeline"][0]["payload"]["mission_id"]
    if claimed_mission_id:
        if claimed_mission_id != mission_id:
            raise MissionCompletionRejected("mission differs from signed claim")
    elif mission.metadata.get("source_announcement_id") != evidence["intent"]["announcement_id"]:
        raise MissionCompletionRejected("mission does not bind the claimed announcement")
    if mission.status == MissionStatus.COMPLETED.value and mission.is_finished():
        outcome, event_type = "succeeded", "nth.task_completed"
    elif mission.status == MissionStatus.FAILED.value and any(
        step.status == StepStatus.FAILED.value for step in mission.steps
    ):
        outcome, event_type = "failed", "nth.task_failed"
    else:
        raise MissionCompletionRejected("mission has no terminal result")

    snapshot_digest = receipt_digest(mission.to_dict())
    completion_store = ClaimCompletionStore(workspace)
    heads = completion_store.heads(nonce)
    if len(heads) > 1 and not resolve_fork:
        raise CompletionEvidenceConflict("completion fork requires explicit claimant resolution")
    predecessor = heads[0][1] if len(heads) == 1 else None
    if predecessor is not None:
        prior_record = predecessor["completion_record"]
        prior_events = predecessor["execution_receipt"]["timeline"]
        if (
            prior_record["outcome"] == outcome
            and prior_record["mission_id"] == mission_id
            and any(
                isinstance(event, dict)
                and isinstance(event.get("payload"), dict)
                and event["payload"].get("mission_snapshot_digest") == snapshot_digest
                and event.get("type") == event_type
                for event in prior_events
            )
        ):
            return predecessor, False
    revision = max((head["completion_record"].get("revision", 0)
                    for _, head in heads), default=-1) + 1
    supersedes = heads[0][0] if len(heads) == 1 else ""
    merge_parents = sorted(digest for digest, _ in heads) if len(heads) > 1 else None
    now = int(time.time() * 1000)
    accepted_at = evidence["authority_ack"]["accepted_at_ms"]
    if now < accepted_at:
        raise MissionCompletionRejected("local clock precedes claim acknowledgement")
    execution = sign_receipt(
        [TimelineEntry(
            timestamp=now, type=event_type,
            payload={"mission_id": mission_id, "mission_snapshot_digest": snapshot_digest},
        )],
        claimant, goal_id=f"mission:{mission_id}",
    )
    record = sign_mission_completion(
        claimant, announcement_id=evidence["intent"]["announcement_id"],
        mission_id=mission_id, claim_receipt=evidence["claim_receipt"],
        authority_ack=evidence["authority_ack"], execution_receipt=execution,
        outcome=outcome, completed_at_ms=now,
        revision=revision, supersedes_digest=supersedes,
        supersedes_digests=merge_parents,
    )
    current = store.get(mission_id)
    if current is None or receipt_digest(current.to_dict()) != snapshot_digest:
        raise MissionCompletionRejected("mission changed while preparing completion")
    return completion_store.record(nonce, record, execution)


def build_portable_completion_proof(
    workspace: Path, nonce: str, *, head_digest: str | None = None,
) -> dict[str, Any] | None:
    """Export signed evidence for the current or an exact retained historical head."""
    built = build_portable_completion_proof_with_pins(
        workspace, nonce, head_digest=head_digest,
    )
    return built[0] if built is not None else None


def build_portable_completion_proof_with_pins(
    workspace: Path, nonce: str, *, head_digest: str | None = None,
) -> tuple[dict[str, Any], str, str] | None:
    """Export a proof and its pins from one locally verified claim snapshot."""
    workspace = Path(workspace)
    chain, evidence = ClaimCompletionStore(workspace).load_chain_with_claim(
        nonce, head_digest=head_digest,
    )
    if not chain:
        return None
    if evidence is None:
        raise ValueError("confirmed claim snapshot is unavailable")
    proof = {
        "kind": "nth-market-claim-completion-proof",
        "version": 2 if any(item["completion_record"]["version"] == 3 for item in chain) else 1,
        "nonce": nonce, "source_claim_id": evidence["authority_ack"]["ack_id"],
        "announcement": evidence["announcement"],
        "intent": evidence["intent"], "claim_receipt": evidence["claim_receipt"],
        "authority_ack": evidence["authority_ack"], "completion_chain": chain,
    }
    if len(canonical_json(proof)) > MAX_PORTABLE_COMPLETION_PROOF_BYTES:
        raise ValueError("portable completion proof exceeds disclosure limit")
    return proof, evidence["source_did"], evidence["federation_key"]


def verify_portable_completion_proof(
    proof: Any, *, expected_source_did: str, expected_federation_key: str,
    now_ms: int | None = None,
) -> tuple[bool, str]:
    """Verify transferred evidence against source pins obtained out of band.

    A self-signed announcement is not a trust root. Both expected values are
    mandatory and must come from the recipient's trusted market context.
    """
    if not expected_source_did or not expected_federation_key:
        return False, "trusted source DID and federation key are required"
    if not isinstance(proof, dict) or frozenset(proof) != _PROOF_FIELDS:
        return False, "portable proof schema is invalid"
    try:
        if len(canonical_json(proof)) > MAX_PORTABLE_COMPLETION_PROOF_BYTES:
            return False, "portable proof exceeds size limit"
        if (proof["kind"] != "nth-market-claim-completion-proof"
                or type(proof["version"]) is not int or proof["version"] not in (1, 2)):
            return False, "portable proof kind or version is invalid"
        nonce = proof["nonce"]
        if not isinstance(nonce, str) or _NONCE_RE.fullmatch(nonce) is None:
            return False, "portable proof nonce is invalid"
        source_claim_id = proof["source_claim_id"]
        if (
            not isinstance(source_claim_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", source_claim_id) is None
            or not isinstance(proof["authority_ack"], dict)
            or source_claim_id != proof["authority_ack"].get("ack_id")
        ):
            return False, "source claim identifier is invalid"
        announcement = TaskAnnouncement.from_dict(proof["announcement"])
        valid, reason = verify_announcement(announcement)
        if not valid:
            return False, f"signed announcement is invalid: {reason}"
        if (
            announcement.effective_authority_did() != expected_source_did
            or announcement_federation_key(announcement) != expected_federation_key
        ):
            return False, "signed announcement differs from pinned source"
        intent = proof["intent"]
        if not isinstance(intent, dict):
            return False, "claim intent is invalid"
        valid, reason = verify_claim_intent(intent, now_ms=intent.get("created_at_ms"))
        if not valid:
            return False, f"claim intent is invalid: {reason}"
        if intent["nonce"] != nonce or intent["announcement_id"] != announcement.announcement_id:
            return False, "claim intent differs from the signed announcement"
        claim_receipt = proof["claim_receipt"]
        if not isinstance(claim_receipt, dict):
            return False, "claim receipt is invalid"
        timeline = claim_receipt.get("timeline")
        if not isinstance(timeline, list) or len(timeline) != 1 or not isinstance(timeline[0], dict):
            return False, "claim receipt timeline is invalid"
        claim_event = timeline[0].get("payload")
        token = claim_receipt.get("authorizing_cap_token")
        if (
            not isinstance(claim_event, dict) or not isinstance(token, dict)
            or token.get("token_id") != intent["cap_token_id"]
            or claim_event.get("cap_token_id") != intent["cap_token_id"]
            or claim_event.get("claimant_did") != intent["claimant_did"]
            or claim_event.get("announcement_id") != announcement.announcement_id
        ):
            return False, "claim receipt differs from the signed intent"
        chain = proof["completion_chain"]
        if not isinstance(chain, list) or not 1 <= len(chain) <= _MAX_REVISIONS:
            return False, "completion lineage is invalid"
        prior_digest = ""
        prior_record: dict[str, Any] | None = None
        graph: dict[str, dict[str, Any]] = {}
        presented_order: list[str] = []
        for index, envelope in enumerate(chain):
            if (
                not isinstance(envelope, dict)
                or set(envelope) != {"version", "nonce", "completion_record", "execution_receipt"}
                or type(envelope["version"]) is not int
                or envelope["version"] != 1
                or envelope["nonce"] != nonce
            ):
                return False, "completion envelope is invalid"
            record = envelope["completion_record"]
            if not isinstance(record, dict) or not isinstance(envelope["execution_receipt"], dict):
                return False, "completion evidence is invalid"
            if record.get("announcement_id") != announcement.announcement_id or record.get("claimant_did") != intent["claimant_did"]:
                return False, "completion does not bind the claim"
            claimed_mission = claim_event.get("mission_id")
            if claimed_mission and record.get("mission_id") != claimed_mission:
                return False, "completion mission differs from signed claim"
            valid, reason = verify_mission_completion(
                record, claim_receipt=claim_receipt,
                authority_ack=proof["authority_ack"],
                execution_receipt=envelope["execution_receipt"],
                expected_authority_did=expected_source_did,
                expected_federation_key=expected_federation_key,
                now_ms=now_ms,
            )
            if not valid:
                return False, f"completion evidence is invalid: {reason}"
            digest = receipt_digest(envelope)
            if digest in graph:
                return False, "completion lineage repeats an envelope"
            graph[digest] = envelope
            presented_order.append(digest)
            if proof["version"] == 1:
                if index == 0:
                    if record["version"] != 1:
                        return False, "completion lineage has no v1 root"
                elif (
                    record["version"] != 2
                    or record["revision"] != index
                    or record["supersedes_digest"] != prior_digest
                    or record["completed_at_ms"] < prior_record["completed_at_ms"]
                ):
                    return False, "completion revision link is invalid"
            prior_digest = digest
            prior_record = record
        if proof["version"] == 2:
            try:
                order, heads = resolve_completion_lineage(graph)
            except CompletionLineageError as exc:
                return False, str(exc)
            if order != presented_order or len(heads) != 1 or heads[0] != presented_order[-1]:
                return False, "completion merge is unresolved or noncanonical"
        return True, "ok"
    except (AttributeError, IndexError, KeyError, TypeError, ValueError, OverflowError, RecursionError, UnicodeError):
        return False, "portable proof encoding or binding is invalid"


def verify_source_claim_completion(
    workspace: Path, proof: Any, *, source_did: str,
    now_ms: int | None = None, strict_source_evidence: bool = False,
) -> tuple[bool, str]:
    """Check transferred evidence against this source's own signed CAS claim.

    This authenticates a claimant statement. It does not retain, accept, or
    settle the work, and the source DID must come from the local host identity.
    Strict callers distinguish absent source evidence from invalid proof.
    """
    if not isinstance(source_did, str) or not is_did_key(source_did):
        return False, "local source identity is unavailable"
    if not isinstance(proof, dict):
        return False, "portable proof schema is invalid"
    ack = proof.get("authority_ack")
    announcement_body = proof.get("announcement")
    if not isinstance(ack, dict) or not isinstance(announcement_body, dict):
        return False, "portable proof source binding is invalid"
    federation_key = ack.get("federation_key")
    if not isinstance(federation_key, str):
        return False, "portable proof federation key is invalid"
    workspace = Path(workspace)
    def unavailable(reason: str) -> tuple[bool, str]:
        if strict_source_evidence:
            raise SourceCompletionEvidenceUnavailable(reason)
        return False, reason

    feed_path = workspace / "market_feed" / "announcements.jsonl"
    try:
        feed_path.stat()
    except FileNotFoundError:
        return unavailable("source announcement is not retained locally")
    announcement = MarketFeed(workspace).get_signed_historical_by_federation_key(
        federation_key,
    )
    if announcement is None:
        return unavailable("source announcement is not retained locally")
    if announcement.to_dict() != announcement_body:
        return False, "proof does not match this source's signed announcement"
    historical_source_did = announcement.effective_authority_did()
    if not source_identity_precedes(workspace, historical_source_did, source_did):
        return False, "source identity is not linked to the signed announcement"
    valid, reason = verify_portable_completion_proof(
        proof, expected_source_did=historical_source_did,
        expected_federation_key=announcement_federation_key(announcement),
        now_ms=now_ms,
    )
    if not valid:
        return False, reason
    claim_root = workspace / "market_claims"
    try:
        claim_root_mode = claim_root.lstat().st_mode
    except FileNotFoundError:
        return unavailable("source claim is not retained and verified locally")
    if not stat.S_ISDIR(claim_root_mode):
        return unavailable("source claim is not retained and verified locally")
    claim = ClaimStore(workspace).get(
        announcement.announcement_id, announcement=announcement, strict_read=True,
    )
    if claim is None:
        return unavailable("source claim is not retained and verified locally")
    if claim.get("status") != CLAIM_STATUS_CLAIMED:
        return False, "source claim is not retained and verified locally"
    if (
        claim.get("claimant_did") != proof["intent"]["claimant_did"]
        or claim.get("receipt") != proof["claim_receipt"]
        or ack.get("claim_record_hash")
        != hashlib.sha256(canonical_json(claim)).hexdigest()
    ):
        return False, "portable proof differs from the source CAS claim"
    return True, "ok"


__all__ = [
    "SourceCompletionEvidenceUnavailable",
    "MAX_PORTABLE_COMPLETION_PROOF_BYTES",
    "record_local_mission_completion", "build_portable_completion_proof",
    "build_portable_completion_proof_with_pins",
    "verify_portable_completion_proof", "verify_source_claim_completion",
]
