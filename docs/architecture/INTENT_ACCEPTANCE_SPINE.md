# Intent Acceptance Spine Anchors

Status: opt-in Host SDK bridge. No background worker, REST route, UI promotion,
federation publication, plugin signing capability or execution is enabled.

The local [acceptance journal](INTENT_ACCEPTANCE.md) is the source of committed
observations. `IntentAcceptanceSpineBridge` signs hash-only `intent.accepted`
anchors through an explicitly supplied `SignedEventLog`. It does not accept a
request or re-run a policy callback. Anchoring an expired historical envelope
does not renew its authorization.

## Trust Boundary

- The Host supplies the store, node log and a pinned `audience_did`.
- The log signer must be that audience, not the envelope's original signer.
- Every selected record is re-read from fully verified journal history.
- All selected records must belong to that audience. A mixed-audience page is
  rejected before any append; use one canonical journal per node audience.
- Existing and returned anchors must bind the exact observation and expected
  node signer. A valid signature by a different node does not suffice.
- Audience, type, time and signature checks use the same detached event snapshot.
  A concurrent change to the caller's mutable event cannot switch the signer
  between the identity check and signature verification.
- No identity file is read, generated, exported or transmitted by this bridge.
  The Host explicitly supplies an already configured signing log.

The node signature attests that the node recorded a historical acceptance. It
does not prove the original Host policy was correct, that a user consented, that
the envelope is currently authorized, or that referenced content is available.
It is not an IntentMandate, execution receipt or payment approval.

## Payload v1

The closed `org.nth-dao.intent-acceptance-anchor.v1` payload contains:

- audience DID;
- signed envelope digest and Host context digest;
- acceptance sequence and original acceptance time;
- current and previous local observation digests;
- fixed `authority=none`, `commit_authority=false`, `executable=false`.

The observation digest is recomputed from the exact local `record.audit` shape.
The anchor excludes source text, draft JSON, scope ID, original signer, nonce,
attachments and policy contents. Hashes, timing and the audience DID still allow
correlation. Hash-only is data minimization, not anonymity or encryption.

The event uses the existing Spine canonical hash/signature format. Its timestamp
is at least the acceptance time and at least 1, as required by Spine. Acceptance
sequence starts at 1; Spine sequence starts at 0 and counts all node events.
They are different orders: backfill can anchor a later acceptance first. Consumers
must follow the observation predecessor links, not infer journal order from
Spine position. The validator checks a single observation's hash, not a complete
remote journal chain or the contents behind its digests.

## Recovery and Idempotency

The journal itself is the durable work list. There is no separate mutable
outbox acknowledgement or persisted success cursor that can drift from Spine.

```python
from nth_dao.plugins import IntentAcceptanceSpineBridge

bridge = IntentAcceptanceSpineBridge(
    store, spine, audience_did=reviewed_node_did,
)
page = bridge.reconcile(limit=100)
while page.has_more:
    page = bridge.reconcile(after_sequence=page.next_sequence, limit=100)
```

Construction does not project anything. `reconcile()` reads one verified
point-in-time journal snapshot and releases all SQLite locks before Spine I/O.
It anchors at most 100 records. `append_unique_many()` serializes across node
processes and uses both envelope and observation digests as independent unique
keys. Duplicate or conflicting anchors fail closed, including an identical
payload signed by another node. Returned IDs are verified again.

The bridge supplies `append_unique_many(validate_event=...)` with a trusted Host
validator. Existing matching events and proposed new events are checked under
the same thread/process write locks as deduplication and appending. Validation
of all selected events finishes before the first new write. There is no separate
unlocked preflight window. Wire payload equality distinguishes `false` from `0`.
`SpineSemanticConflict` remains a `ValueError` for existing callers and identifies
duplicate or conflicting keys without exposing storage paths in bridge errors.

This validator is not a plugin execution hook. It receives detached events,
returns `None` or raises, and must not perform I/O, reenter the log or acquire
other stores. Its mutations cannot alter cached, proposed or returned events.

This is **not a transaction across two stores**. A failure can leave a valid
Spine prefix while every source observation remains in the journal. On I/O
failure, an append may already be durable: recover and replay the same page.
Spine's existing durable append-intent recovery completes uncertain writes;
exact retries return the existing event IDs without signing duplicate events.
Validation, signer and conflict failures need inspection, not blind retries.
Raw storage error text and local paths are not copied into bridge diagnostics.

Spine also preserves append identities when record writing succeeds but readback,
cache refresh or process-lock release fails. `SpineAppendOutcomeUnknown.event_id`
identifies the last possibly committed record; `event_ids` includes this call's
completed batch prefix and any uncertain current record. Plain `append()` callers
must reconcile the returned ID instead of blindly appending again. Semantic batch
callers can recover and replay the same keys. No-new-write failures remain ordinary
I/O errors, and integrity failures remain validation errors, not retry advice.
Tracking begins when an append intent may be durable, so a second lock-release
error cannot hide an earlier uncertain write's identity.

`next_sequence` is a pagination hint, not a durable acknowledgement or evidence
that earlier rows are anchored. Advance it only after a successful call. Restart
recovery can always begin at zero. `has_more=false` describes the captured page,
not later appends by another writer. No automatic polling is installed.

## Limits and Verification

All journal reads still verify bounded complete history. Spine integrity scans
add their own cost. Pagination bounds newly projected records, not total
verification cost or wall-clock latency. Filesystem replacement by a local owner,
power-loss certification and policy-database atomicity remain outside this SDK.
No pruning, repair, reset or deletion of source observations is performed.

Tests cover concurrent bridge instances and processes, interrupted writes, a
child exiting after durable append but before response, delayed projection of
expired envelopes, wrong signers, corrupt journals, duplicate/conflicting anchors,
mixed audiences and backfill order. Deterministic test-only vectors include
re-signed malformed payloads. Python and an independent Node/Noble consumer
check the profile; this is not a general Spine or governance certification.
Spine public reads and writes now detach nested input/output views from the
verified event cache. Mutation tests cover every public event-returning surface
so a consumer cannot accidentally change the cache by modifying its own view.
Copies use the JSON wire representation rather than recursive `deepcopy`, so
previously valid deeply nested events remain readable. Payload validation and
all detached return values are prepared before a batch starts writing. Encoded
append-intent sizes are checked at their planned log offsets too; invalid input,
oversized append intents or result-copy failures cannot leave a newly written
prefix. Existing payload/line size limits and the signed wire format are unchanged. Tests cover
deep history with caches enabled and disabled, concurrent signer replacement,
conflicting writers, validator isolation and preparation failures.

Spine batches additionally enforce `MAX_SPINE_APPEND_BATCH_BYTES` (8 MiB), alongside
the 1,000-item count limit. The cumulative charge is canonical UTF-8 bytes for every
input, ASCII-encoded new records including newlines, and ASCII-encoded returned
events without newlines. Existing matches and repeated input IDs still consume
input/result budget. Each charge is checked before retaining the next snapshot,
prepared record or return view. Overflow rejects the entire new batch before its
first append; Spine does not silently split it. A Host may explicitly select a
smaller page, preserving its semantic keys and source cursor recovery rules.

This is an operational batch limit, not a wire-format migration, physical memory
ceiling or sandbox for arbitrary in-process Python objects. Admitted records still
need signing, validator and append-intent scratch space. Python object overhead,
verified history, caller allocations and temporary encoding of a single oversized
input are outside this aggregate budget; Hosts must bound requests before decoding.
Record readback now checks the existing byte parts with reads of at most 1 MiB,
without concatenating and rereading a second full-batch buffer. Tests exercise
exact byte boundaries, non-ASCII expansion, duplicates, existing/new mixtures,
bounded preflight allocation and unchanged prefix/suffix tamper rejection.

Regenerate with `python -m tools.generate_intent_acceptance_anchor_vectors`.
Run `python -m pytest -q tests/test_intent_acceptance_audit.py
tests/test_intent_acceptance_anchor_conformance.py` on one command line. Node
uses the existing locked dependencies under `tests/conformance`.

Next: integrate trusted membership/role/revocation policy and a pinned reviewed
draft before enabling any acceptance endpoint or solver proposal flow. Remote
anchor publication and retrieval of the private evidence remain separate,
explicitly reviewed boundaries.
