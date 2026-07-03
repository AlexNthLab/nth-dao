"""Signed execution receipts: L1 work-proof primitive.

This module implements the wire format and signing rules for NTH DAO
execution receipts. The format is aligned with motebit's
``execution-ledger@1.0`` model: a receipt is a signed timeline of typed
execution entries, so a third party can verify what an agent claimed to do
without trusting the local filesystem or the NTH DAO process.

Why this is separate from ``agent_ledger``:

* ``agent_ledger`` is a long-lived per-agent reputation stream.
* an execution receipt is a per-goal signed artifact.
* receipt canonicalization signs a newline-joined timeline digest, while the
  agent ledger has different reducer and storage semantics.

Per-entry canonical JSON:

* keys sorted lexicographically;
* no whitespace between JSON tokens;
* all three fields present: ``payload``, ``timestamp``, ``type``;
* nested objects sorted by the same canonical JSON rules.

Content hash:

1. canonicalize each timeline entry individually;
2. join the canonical entry bytes with ``\n``;
3. compute SHA-256 over the resulting UTF-8 bytes;
4. encode the digest as lowercase 64-character hex.

Signature:

* the signing input is the raw 32-byte SHA-256 digest, not the hex string;
* the signature is Ed25519;
* the wire encoding is base64url without padding.

NTH wraps the signed timeline core in an envelope:

``kind``, ``receipt_id``, ``goal_id``, ``signer_did``,
``signer_pubkey_hex``, and ``issued_at`` are discovery metadata. The signature
covers ``content_hash``; ``content_hash`` covers ``timeline``. A verifier must
cross-check metadata such as ``signer_did`` against the signed core and any
external trust material it relies on.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.did_key import decode_ed25519_did_key_hex, is_did_key
from nth_dao.identity import _NACL_AVAILABLE

try:
    from nacl.signing import VerifyKey as _VerifyKey
except ImportError:
    _VerifyKey = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from nth_dao.identity import AgentIdentity

logger = logging.getLogger("nth_dao.execution_receipt")


# ─── motebit-base event type vocabulary ──────────────────────────────
# Quoted verbatim from execution-ledger-v1.md §4.

TYPE_GOAL_STARTED = "goal_started"
TYPE_PLAN_CREATED = "plan_created"
TYPE_STEP_STARTED = "step_started"
TYPE_TOOL_INVOKED = "tool_invoked"
TYPE_TOOL_RESULT = "tool_result"
TYPE_STEP_COMPLETED = "step_completed"
TYPE_STEP_FAILED = "step_failed"
TYPE_STEP_DELEGATED = "step_delegated"
TYPE_PLAN_COMPLETED = "plan_completed"
TYPE_PLAN_FAILED = "plan_failed"
TYPE_GOAL_COMPLETED = "goal_completed"

MOTEBIT_BASE_TYPES = frozenset({
    TYPE_GOAL_STARTED, TYPE_PLAN_CREATED, TYPE_STEP_STARTED,
    TYPE_TOOL_INVOKED, TYPE_TOOL_RESULT, TYPE_STEP_COMPLETED,
    TYPE_STEP_FAILED, TYPE_STEP_DELEGATED, TYPE_PLAN_COMPLETED,
    TYPE_PLAN_FAILED, TYPE_GOAL_COMPLETED,
})

# NTH-specific extensions, namespaced under ``nth.`` per motebit's
# convention for non-base types ("Implementations MAY define
# additional values using a namespaced format").
TYPE_NTH_POST_MESSAGE = "nth.post_message"
TYPE_NTH_ADD_MEMBER = "nth.add_member"
TYPE_NTH_VOTE = "nth.vote"
TYPE_NTH_DAO_CREATED = "nth.dao_created"
TYPE_NTH_MANDATE_SIGNED = "nth.mandate_signed"
# Phase B (DESIGN_TRADE_OFFS §1 D1 follow-through, 2026-06-08):
# the per-signer chain link. When present, MUST be the FIRST
# timeline entry. Its payload carries the prior receipt's
# content_hash so a chain walk can verify no receipt was silently
# dropped from a public history without re-signing the entire
# chain forward (which would re-stamp every issued_at and is
# trivially detectable by an external snapshot of the chain head).
TYPE_NTH_CHAIN_LINK = "nth.chain_link"

NTH_EXTENSION_TYPES = frozenset({
    TYPE_NTH_POST_MESSAGE, TYPE_NTH_ADD_MEMBER, TYPE_NTH_VOTE,
    TYPE_NTH_DAO_CREATED, TYPE_NTH_MANDATE_SIGNED,
    TYPE_NTH_CHAIN_LINK,
})

# Wire versioning per motebit convention (``family/version@major.minor``)
NTH_RECEIPT_SPEC = "nth-dao/execution-receipt@1.0"
MOTEBIT_COMPATIBLE = "motebit/execution-ledger@1.0"
NTH_RECEIPT_KIND = "nth-execution-receipt-v1"


# ─── timeline entry ──────────────────────────────────────────────────


@dataclass(frozen=True)
class TimelineEntry:
    """One timeline entry per motebit execution-ledger@1.0 §3.1.

    Attributes:
        timestamp: Unix epoch milliseconds (integer). Motebit pins
            integer ms (e.g. ``1710288000000``), NOT float seconds —
            float precision would make signatures non-portable across
            float-naive verifiers.
        type: Event type identifier. Either a motebit base type (see
            ``MOTEBIT_BASE_TYPES``) or an NTH-namespaced extension.
        payload: Arbitrary JSON-serializable dict. Keys may be in any
            order — canonical_json sorts them at sign time. Avoid
            float values inside (canonical_json rejects floats per the
            project-wide rule, same one that motebit also enforces).
    """

    timestamp: int
    type: str
    payload: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Defence in depth — both contract violations would silently
        # produce signatures that no motebit verifier accepts.
        if not isinstance(self.timestamp, int):
            raise TypeError(
                f"timestamp must be int (epoch ms); got "
                f"{type(self.timestamp).__name__}"
            )
        if self.timestamp < 0:
            raise ValueError(f"timestamp must be non-negative; got {self.timestamp}")
        if not isinstance(self.type, str) or not self.type:
            raise ValueError("type must be a non-empty string")
        if not isinstance(self.payload, dict):
            raise TypeError("payload must be a dict")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "type": self.type,
            "payload": dict(self.payload),  # defensive copy
        }


def now_ms() -> int:
    """Current Unix time in integer milliseconds.

    Helper for callers that don't want to import ``time`` themselves
    and risk drifting between ms/seconds/ns by mistake.

    MA-1 (review fix 2026-06-08): use ``time.time_ns() // 1_000_000``
    rather than ``int(time.time() * 1000)``. On Windows ``time.time()``
    has ~15 ms resolution; back-to-back ``now_ms()`` calls in the same
    receipt emission produced identical timestamps, which the motebit
    spec allows ("entries with equal timestamps MUST preserve insertion
    order") but a precise source is preferable — ``time_ns()`` is
    nanosecond-resolution on every platform Python supports.
    """
    return time.time_ns() // 1_000_000


# ─── canonical content hash ──────────────────────────────────────────


def _hash_and_dicts(
    timeline: List[TimelineEntry],
) -> "tuple[str, bytes, List[Dict[str, Any]]]":
    """Internal one-pass helper: hash the timeline AND return both
    the digest representations + the per-entry dicts.

    MA-3 (review fix 2026-06-08): the previous flow asked
    ``compute_content_hash`` to do ``entry.to_dict()`` per entry
    purely for hashing, and then ``sign_receipt`` re-built the same
    per-entry dicts for the output payload — two passes for what is
    a single producer side. Returning the dicts alongside the hash
    lets ``sign_receipt`` reuse the work.

    Returns:
        (hex_str, raw_32_byte_digest, entry_dicts)

        * ``hex_str``: 64-char lowercase hex (the public wire form)
        * ``raw_32_byte_digest``: the SHA-256 output bytes — exactly
          what motebit-spec §6 signs; avoids a ``bytes.fromhex`` round
          trip
        * ``entry_dicts``: the per-entry Python dicts the caller can
          slot directly into the receipt envelope's ``timeline`` field

    Raises:
        ValueError if the timeline is empty.
    """
    if not timeline:
        raise ValueError(
            "cannot hash empty timeline; receipts require at least "
            "one entry (motebit recommends starting with goal_started)"
        )
    entry_dicts: List[Dict[str, Any]] = [e.to_dict() for e in timeline]
    per_entry: List[bytes] = [canonical_json(d) for d in entry_dicts]
    joined = b"\n".join(per_entry)
    h = hashlib.sha256(joined)
    return h.hexdigest(), h.digest(), entry_dicts


def compute_content_hash(timeline: List[TimelineEntry]) -> str:
    """Compute the motebit-spec content_hash for a timeline.

    Steps (per execution-ledger@1.0 §5):
      1. Canonicalize each entry: sort keys, no whitespace, UTF-8.
      2. Join the per-entry canonical bytes with ``\\n`` (U+000A).
      3. SHA-256 the joined bytes.
      4. Lowercase hex.

    The result is byte-stable across implementations: a Rust port
    that follows the same recipe will compute the same hash, which is
    the whole point of having a wire spec.

    Public API contract: returns the 64-char hex string. Internal
    callers that ALSO need the raw 32-byte digest (e.g. ``sign_receipt``,
    which must sign the digest per spec §6) should call the
    private ``_hash_and_dicts`` helper instead — that's the only
    spot in the codebase where a single canonicalization pass is
    actually visible.

    Raises:
        ValueError if the timeline is empty — an empty receipt is
        meaningless and the spec implies at least one entry (goal must
        have a ``goal_started`` event minimum).
    """
    hex_str, _, _ = _hash_and_dicts(timeline)
    return hex_str


# ─── base64url helpers: CR-1 fix (2026-06-08) ────────────────────────
# Shared codec lives in ``nth_dao.b64u`` to prevent the per-module
# drift that motivated this refactor. Keep the local names for
# call-site readability without re-implementing the bodies.

_b64u = b64u_encode
_b64u_decode = b64u_decode


# ─── build + sign ────────────────────────────────────────────────────


def sign_receipt(
    timeline: List[TimelineEntry],
    identity: "AgentIdentity",
    *,
    goal_id: str = "",
    receipt_id: str = "",
    prev_content_hash: str = "",
    authorizing_cap_token: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a signed execution receipt over ``timeline``.

    The signature input is the **32-byte raw hash digest** (NOT the
    hex string) per motebit execution-ledger@1.0 §6 — implementations
    that sign the hex string produce sigs no motebit verifier accepts.

    Args:
        timeline: ordered list of ``TimelineEntry`` rows. Caller is
            responsible for ordering — typically by ``timestamp``.
            The spec says "Entries with equal timestamps MUST preserve
            insertion order" so we trust the caller's list order
            after the timestamp sort.
        identity: the signing ``AgentIdentity``. Must have a private
            key (``identity.can_sign``); raises if not.
        goal_id: caller-supplied opaque ID linking this receipt to
            the goal/mission/task it terminates. Empty string is OK
            for ad-hoc receipts.
        receipt_id: caller-supplied UUID. If empty, a fresh uuid4 is
            minted. The receipt_id is for discovery only — it is NOT
            covered by ``sig``.
        prev_content_hash: Phase B (chain link, DESIGN_TRADE_OFFS §1
            D1 follow-through). When non-empty, a ``nth.chain_link``
            entry is **prepended** to the timeline carrying this
            value in its payload. Because the prepended entry
            participates in ``_hash_and_dicts``, it ends up signed.
            Empty string = genesis receipt (no prior receipt for
            this signer).
        authorizing_cap_token: C2 (DESIGN_TRADE_OFFS §2). When
            present, the signing identity is interpreted as an
            **ephemeral delegated subject**, and ``verify_receipt``
            walks the cap_token chain back to the issuer's root
            authority. The cap_token MUST: list this signer as
            ``subject_did``, include ``nth:receipt_sign`` in
            capabilities, and have ``not_after >= issued_at``.
            Implementation only attaches the field; semantic
            validation is the verifier's job.

    Returns:
        A dict matching the NTH-execution-receipt-v1 envelope (see
        module docstring for shape). When ``authorizing_cap_token``
        is supplied, the envelope grows an ``authorizing_cap_token``
        field (verbatim copy); when ``prev_content_hash`` is non-
        empty, the timeline grows a leading ``nth.chain_link`` entry.

    Raises:
        RuntimeError if the identity cannot sign.
        ValueError if prev_content_hash is non-empty but not 64-hex.
    """
    # Phase B: prepend the chain link entry IF the caller is signing
    # a non-genesis receipt. The link participates in canonicalization
    # so the prev pointer is signature-protected.
    if prev_content_hash:
        if (
            len(prev_content_hash) != 64
            or not all(c in "0123456789abcdef" for c in prev_content_hash)
        ):
            raise ValueError(
                f"prev_content_hash must be 64-char lowercase hex; "
                f"got {prev_content_hash!r}"
            )
        chain_link_entry = TimelineEntry(
            timestamp=timeline[0].timestamp if timeline else now_ms(),
            type=TYPE_NTH_CHAIN_LINK,
            payload={"prev_content_hash": prev_content_hash},
        )
        timeline = [chain_link_entry, *timeline]

    # MA-3 (review fix 2026-06-08): single canonicalization pass.
    # ``_hash_and_dicts`` produces the hex, the raw 32-byte digest,
    # and the per-entry dicts in one walk over the timeline.
    content_hash, digest_bytes, entry_dicts = _hash_and_dicts(timeline)
    sig_bytes = identity.sign(digest_bytes)
    sig_b64 = _b64u(sig_bytes)

    envelope: Dict[str, Any] = {
        "kind": NTH_RECEIPT_KIND,
        "spec": NTH_RECEIPT_SPEC,
        "compatible_with": MOTEBIT_COMPATIBLE,
        "receipt_id": receipt_id or uuid.uuid4().hex,
        "goal_id": goal_id,
        "signer_did": identity.as_did(),
        "signer_pubkey_hex": identity.pubkey_hex,
        # Review pass#2 fix C2 2026-06-10: was naive local time.
        # head_content_hash sorts receipts by this string to find
        # the chain head — DST shifts / timezone changes / cross-
        # machine sync could silently reorder the chain. UTC-aware
        # ISO is unambiguous and the field is still 'display only'.
        "issued_at": datetime.now(timezone.utc).isoformat(),
        # ── motebit core (what gets verified) ─────────────────────
        "timeline": entry_dicts,
        "content_hash": content_hash,
        "sig": sig_b64,
    }
    # C2: attach cap_token verbatim. Note it lives OUTSIDE the
    # signed body (it's not part of ``timeline`` or ``content_hash``)
    # because the cap_token has its own internal signature — making
    # it part of THIS receipt's content_hash would create a chicken-
    # and-egg dependency between the two signing operations. The
    # cap_token's authority over this receipt is enforced by
    # ``verify_receipt`` checking that ``subject_did`` matches
    # ``signer_did``, which IS inside the signed body via
    # ``signer_pubkey_hex`` → did:key reconstruction.
    if authorizing_cap_token is not None:
        envelope["authorizing_cap_token"] = dict(authorizing_cap_token)
    return envelope


# ─── verify ──────────────────────────────────────────────────────────


def verify_receipt(
    receipt: Dict[str, Any],
    *,
    expected_pubkey_hex: str = "",
) -> bool:
    """Verify a receipt's content_hash + signature.

    A receipt is valid iff ALL of:
      1. ``timeline`` is well-formed (list of entries with the three
         required fields, types correct).
      2. Recomputed ``content_hash`` matches the stored one (binds
         the timeline to its claimed hash).
      3. Signature verifies under the pubkey derived from
         ``signer_did`` (binds the agent to the timeline).
      4. If ``expected_pubkey_hex`` is supplied, the pubkey derived
         from ``signer_did`` matches it (belt-and-braces for callers
         that already know the agent's pubkey via another channel).

    Returns False on any failure rather than raising — verification
    is a yes/no operation and callers should not need to handle a
    bouquet of exceptions to ask "is this receipt good?". If you
    need to KNOW why a verification failed, run with logger at
    DEBUG.
    """
    if not _NACL_AVAILABLE or _VerifyKey is None:
        return False

    timeline_data = receipt.get("timeline")
    if not isinstance(timeline_data, list) or not timeline_data:
        logger.debug("receipt has no timeline")
        return False
    try:
        timeline = [
            TimelineEntry(
                timestamp=int(e["timestamp"]),
                type=str(e["type"]),
                payload=dict(e.get("payload", {})),
            )
            for e in timeline_data
        ]
    except (KeyError, TypeError, ValueError) as exc:
        logger.debug("receipt timeline malformed: %s", exc)
        return False

    try:
        recomputed = compute_content_hash(timeline)
    except Exception as exc:  # noqa: BLE001
        logger.debug("compute_content_hash failed: %s", exc)
        return False
    claimed_hash = receipt.get("content_hash", "")
    if recomputed != claimed_hash:
        logger.debug(
            "content_hash mismatch: recomputed %s vs claimed %s",
            recomputed, claimed_hash,
        )
        return False

    sig_b64 = receipt.get("sig", "")
    if not sig_b64:
        return False
    try:
        sig_bytes = _b64u_decode(sig_b64)
    except Exception as exc:  # noqa: BLE001
        logger.debug("sig base64url decode failed: %s", exc)
        return False

    did = receipt.get("signer_did", "")
    if not did or not is_did_key(did):
        logger.debug("signer_did missing or not did:key")
        return False
    pubkey_hex = decode_ed25519_did_key_hex(did) or ""
    if not pubkey_hex:
        return False
    if (
        expected_pubkey_hex
        and pubkey_hex.lower() != expected_pubkey_hex.lower()
    ):
        logger.debug(
            "signer_did pubkey %s != expected %s",
            pubkey_hex[:16], expected_pubkey_hex[:16],
        )
        return False

    # Cross-check the envelope's ``signer_pubkey_hex`` against the DID-
    # derived pubkey. They MUST agree — disagreement means the
    # envelope is internally inconsistent, even if technically both
    # fields parse.
    envelope_pk = str(receipt.get("signer_pubkey_hex", "")).lower()
    if envelope_pk and envelope_pk != pubkey_hex.lower():
        logger.debug(
            "envelope pubkey %s != DID-derived pubkey %s",
            envelope_pk[:16], pubkey_hex[:16],
        )
        return False

    # Sign input = raw 32-byte hash digest (NOT the hex string)
    digest_bytes = bytes.fromhex(claimed_hash)
    try:
        _VerifyKey(bytes.fromhex(pubkey_hex)).verify(digest_bytes, sig_bytes)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Ed25519 verify failed: %s", exc)
        return False

    # C2 (DESIGN_TRADE_OFFS §2): if an authorizing_cap_token is
    # attached, walk the chain back to the issuer's root authority.
    # If verification of the chain fails, the WHOLE receipt fails —
    # an unverifiable chain is worse than no chain.
    #
    # E2 (audit fix 2026-06-08): the field MUST be a dict if
    # present. A non-dict value (string / list / int / bool) is
    # malformed envelope and verify_receipt's contract is to
    # return False rather than raise; without this guard the
    # downstream ``cap_token.get(...)`` calls would crash through
    # the no-raise boundary.
    cap_tok = receipt.get("authorizing_cap_token")
    if cap_tok is not None:
        if not isinstance(cap_tok, dict):
            logger.debug(
                "authorizing_cap_token must be a dict; got %s",
                type(cap_tok).__name__,
            )
            return False
        if not _verify_cap_token_chain_for_receipt(
            receipt=receipt,
            cap_token=cap_tok,
            signer_pubkey_hex=pubkey_hex,
        ):
            return False

    return True


def _verify_cap_token_chain_for_receipt(
    *,
    receipt: Dict[str, Any],
    cap_token: Dict[str, Any],
    signer_pubkey_hex: str,
) -> bool:
    """C2 chain verifier: the receipt's signer is an ephemeral
    subject; the cap_token transfers authority from the user's root
    DID to that subject. Per DESIGN_TRADE_OFFS §2:

      1. cap_token's own Ed25519 signature verifies under its
         ``issuer_did``'s pubkey.
      2. cap_token's ``subject_did`` corresponds to the receipt's
         signer pubkey.
      3. cap_token's ``not_after >= receipt issued_at`` (NB: time
         comparison in milliseconds; receipt.issued_at is ISO
         string so we parse).
      4. cap_token's ``capabilities`` contains ``nth:receipt_sign``.
      5. If cap_token's ``scope_task_id`` is non-empty, it equals
         the receipt's ``goal_id``.
      6. **Revocation is NOT consulted here** (DESIGN_TRADE_OFFS
         §2 normative semantic: signing at time T was legal if
         cap_token was within its time bounds, regardless of
         post-T revocation).

    The first failed check returns False; later checks are skipped.
    """
    # Local imports to keep the module-load graph shallow.
    from datetime import datetime as _dt
    from nth_dao.cap_token import (
        CAP_NTH_RECEIPT_SIGN,
        verify_cap_token,
    )

    # Check 1 + 2: cap_token internal validity + subject-pubkey link.
    # ``verify_cap_token`` runs the full 5-check pipeline (shape /
    # time / revocation / capability / signature). Two adjustments
    # to honour D7's "non-retroactive" normative:
    #   * Pass ``revoked_ids=set()`` so revocation is NOT consulted.
    #   * Pass ``now_ms_override=receipt_ms`` so the time-bound check
    #     verifies the cap was valid AT THE TIME THE RECEIPT WAS
    #     SIGNED, not at the time of verification (years later).
    #     Without this override, verify_cap_token would reject any
    #     receipt whose cap_token has since expired — directly
    #     contradicting D7.
    issued_at_str = receipt.get("issued_at", "")
    if not issued_at_str:
        logger.debug("receipt missing issued_at; cannot time-anchor cap chain")
        return False
    try:
        receipt_ms = int(_dt.fromisoformat(issued_at_str).timestamp() * 1000)
    except (ValueError, TypeError) as exc:
        logger.debug("receipt issued_at unparseable: %s", exc)
        return False

    ok, reason = verify_cap_token(
        cap_token, revoked_ids=set(),
        required_capabilities=[CAP_NTH_RECEIPT_SIGN],
        now_ms_override=receipt_ms,
    )
    if not ok:
        logger.debug("cap_token internal verify failed: %s", reason)
        return False

    # Cross-check that the cap_token's subject_did derives the SAME
    # pubkey the receipt was actually signed by.
    subject_did = str(cap_token.get("subject_did", "") or "")
    if not subject_did or not is_did_key(subject_did):
        logger.debug("cap_token subject_did missing or not did:key")
        return False
    subject_pubkey_hex = decode_ed25519_did_key_hex(subject_did) or ""
    if subject_pubkey_hex.lower() != signer_pubkey_hex.lower():
        logger.debug(
            "cap_token subject %s != receipt signer %s",
            subject_pubkey_hex[:16], signer_pubkey_hex[:16],
        )
        return False

    # Check 3: time bound — receipt issued_at must fall before
    # cap_token's not_after.
    issued_at_str = receipt.get("issued_at", "")
    if not issued_at_str:
        logger.debug("receipt missing issued_at; cannot time-check cap chain")
        return False
    try:
        receipt_ms = int(_dt.fromisoformat(issued_at_str).timestamp() * 1000)
    except (ValueError, TypeError) as exc:
        logger.debug("receipt issued_at unparseable: %s", exc)
        return False
    # E3 (audit fix 2026-06-08): this is a deliberate
    # defense-in-depth BACKSTOP that duplicates the time-bound
    # check already enforced inside the verify_cap_token call
    # above (with now_ms_override=receipt_ms). Per current
    # verify_cap_token contract the inner check ALREADY rejects
    # receipt_ms > not_after; this conditional would only fire
    # if a future refactor of verify_cap_token silently changed
    # its time semantics. Keeping the redundancy here makes that
    # regression caught at the consuming side, not at the
    # cap_token unit-test boundary.
    not_after = int(cap_token.get("not_after", 0))
    if not_after and receipt_ms > not_after:
        logger.debug(
            "receipt signed AFTER cap_token not_after (%d > %d) "
            "— BACKSTOP fired; verify_cap_token's inner check "
            "should have caught this first. Investigate "
            "verify_cap_token's contract drift.",
            receipt_ms, not_after,
        )
        return False

    # Check 5: scope_task_id, if set, must equal receipt goal_id.
    scope_task_id = str(cap_token.get("scope_task_id", "") or "")
    if scope_task_id:
        receipt_goal_id = str(receipt.get("goal_id", "") or "")
        if scope_task_id != receipt_goal_id:
            logger.debug(
                "cap_token scope_task_id %r != receipt goal_id %r",
                scope_task_id, receipt_goal_id,
            )
            return False

    return True


# ─── Phase B: chain integrity ────────────────────────────────────────


def extract_prev_content_hash(receipt: Dict[str, Any]) -> str:
    """Return the prev_content_hash recorded in this receipt's chain
    link, or empty string for genesis receipts.

    The chain link is the FIRST timeline entry of type
    ``nth.chain_link`` (or absent for genesis). Per Phase B
    convention (sign_receipt prepends), a chain_link entry NOT at
    position 0 is malformed.
    """
    timeline = receipt.get("timeline") or []
    if not timeline:
        return ""
    first = timeline[0]
    if first.get("type") != TYPE_NTH_CHAIN_LINK:
        return ""
    payload = first.get("payload") or {}
    return str(payload.get("prev_content_hash", "") or "")


def verify_receipt_chain(receipts: List[Dict[str, Any]]) -> bool:
    """Verify that ``receipts`` form a coherent chain.

    All receipts must:
      * pass individual ``verify_receipt`` checks
      * share the same ``signer_did`` (one chain per signer)
      * be linkable: exactly one genesis (empty prev_content_hash),
        each non-genesis receipt's prev_content_hash matches the
        content_hash of exactly one earlier receipt in the input,
        no orphans, no two receipts share the same prev pointer

    Use this when a consumer has captured a snapshot of someone's
    receipts and wants to confirm no entry has been silently
    dropped. Note: as long as the signer controls their keypair,
    they CAN re-sign the whole chain forward with a different
    history — chain integrity rules out third-party tampering
    and *post-hoc* omission, not self-rewrite. See
    DESIGN_TRADE_OFFS §1 for the honest framing.
    """
    if not receipts:
        return False
    signers = {r.get("signer_did", "") for r in receipts}
    if len(signers) != 1 or "" in signers:
        logger.debug("receipts must share one non-empty signer_did")
        return False
    # Individual receipt validity
    for r in receipts:
        if not verify_receipt(r):
            logger.debug(
                "receipt %s failed individual verify",
                r.get("receipt_id", "?")[:8],
            )
            return False
    # Build a hash→receipt map and find genesis
    by_hash = {r["content_hash"]: r for r in receipts}
    if len(by_hash) != len(receipts):
        logger.debug("chain has duplicate content_hash values")
        return False
    genesis: List[Dict[str, Any]] = []
    prev_pointers: List[str] = []
    for r in receipts:
        prev = extract_prev_content_hash(r)
        if not prev:
            genesis.append(r)
        else:
            prev_pointers.append(prev)
    if len(genesis) != 1:
        logger.debug(
            "chain must have exactly one genesis; found %d",
            len(genesis),
        )
        return False
    # Every prev pointer must resolve to one of the other receipts'
    # content_hash, and no two receipts may share the same prev.
    if len(set(prev_pointers)) != len(prev_pointers):
        logger.debug("chain has a fork (two receipts share a prev pointer)")
        return False
    for prev in prev_pointers:
        if prev not in by_hash:
            logger.debug("chain has an orphan prev pointer %s", prev[:16])
            return False
    return True


# ─── persistent store ────────────────────────────────────────────────


class ReceiptStore:
    """File-backed receipt store at ``<workspace>/team_receipts/``.

    Each receipt is written atomically as ``{receipt_id}.json`` via
    write-temp + rename (POSIX guarantees atomicity for same-FS
    renames; Windows ``os.replace`` provides the same).

    The store is intentionally a flat directory rather than a date-
    sharded tree — for the volumes NTH DAO sees (chat-scale, not
    web-scale), the directory enumeration cost is dominated by
    serialization, not by ``readdir`` traversal. Add sharding when
    we cross 10k receipts per workspace.
    """

    SUFFIX = ".json"

    def __init__(self, workspace: Path) -> None:
        self.root = Path(workspace) / "team_receipts"
        self.root.mkdir(parents=True, exist_ok=True)

    def save(self, receipt: Dict[str, Any]) -> Path:
        """Persist a signed receipt. Returns the final file path.

        Atomic: writes to ``{id}.json.tmp`` then ``os.replace``. A
        crash mid-write leaves either the old file (or no file) and
        a possibly-orphaned ``.tmp`` that's easy to spot.
        """
        rid = str(receipt.get("receipt_id", "") or "")
        if not rid:
            raise ValueError("receipt is missing receipt_id")
        # MI-1 (review fix 2026-06-08): allow only [A-Za-z0-9-]. This
        # is stricter than a path-traversal check — it incidentally
        # rejects ``..``, ``/`` and ``\`` because none of those satisfy
        # ``isalnum or '-'``, but the primary intent is "ids must be
        # plain identifiers", not "only block traversal". Document the
        # constraint accurately so a future maintainer doesn't relax
        # it thinking they're just trimming a path-traversal guard.
        if not all(c.isalnum() or c == "-" for c in rid):
            raise ValueError(
                f"receipt_id must be alphanumeric (or dash); got {rid!r}"
            )
        path = self.root / (rid + self.SUFFIX)
        tmp = path.with_suffix(self.SUFFIX + ".tmp")
        tmp.write_text(
            json.dumps(receipt, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        os.replace(str(tmp), str(path))
        return path

    def load(self, receipt_id: str) -> Optional[Dict[str, Any]]:
        """Return the receipt dict, or None if not found."""
        if not all(c.isalnum() or c == "-" for c in receipt_id):
            return None
        path = self.root / (receipt_id + self.SUFFIX)
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def list_ids(self) -> List[str]:
        """Enumerate stored receipt IDs (no specific order)."""
        return [p.stem for p in self.root.glob("*" + self.SUFFIX)]

    def __contains__(self, receipt_id: str) -> bool:
        return self.load(receipt_id) is not None

    def head_content_hash(self, signer_did: str) -> str:
        """Phase B: return the content_hash of the latest receipt
        signed by ``signer_did``, suitable to pass as
        ``prev_content_hash`` when minting the next receipt.

        Implementation: linear scan over the store. For workspaces
        with <10k receipts this is fast; if the count grows past
        that, the natural V1.x optimisation is to maintain a
        ``chain_heads.json`` index updated atomically alongside
        ``save()``. We deliberately ship the simple version first
        so the correctness of the chain link semantics gets
        battle-tested before the index introduces a second source
        of truth.

        Returns an empty string when ``signer_did`` has no
        receipts on file — appropriate for the genesis case.

        Tie-breaking: if two receipts by the same signer have the
        same ``issued_at`` (rare but possible under millisecond
        clock resolution), the one with the lexicographically
        greatest ``content_hash`` wins. This is arbitrary but
        deterministic; a chain with multiple "heads" indicates a
        fork the caller should resolve before extending it.
        """
        latest_issued = ""
        latest_hash = ""
        for rid in self.list_ids():
            rec = self.load(rid)
            if rec is None:
                continue
            if rec.get("signer_did", "") != signer_did:
                continue
            issued = str(rec.get("issued_at", ""))
            content_hash = str(rec.get("content_hash", ""))
            if (
                issued > latest_issued
                or (issued == latest_issued and content_hash > latest_hash)
            ):
                latest_issued = issued
                latest_hash = content_hash
        return latest_hash
