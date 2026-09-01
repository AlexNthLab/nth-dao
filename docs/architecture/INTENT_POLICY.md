# Intent Acceptance Policy Snapshot

Status: implemented Host SDK policy primitive and node-local append-only policy
store; no REST route, UI, solver, or business promotion is enabled.

`IntentAcceptancePolicySnapshot` is the deterministic policy gate between an
untrusted signed `IntentEnvelope` and the local acceptance journal. It binds one
audience DID and scope to an exact reviewed draft, current membership and
revocation source digests, accepted member roles, direct signer DIDs, solver
classes, automation ceilings, and a bounded validity interval.

The snapshot answers only this question:

> May this direct DID signer record acceptance of this exact reviewed draft,
> under this exact local policy snapshot, at this revision head?

It cannot answer whether the draft is true or wise. It cannot delegate authority,
invoke a solver, create a Task/Mission/Agreement, enable a plugin, spend funds,
or execute an operation. Its fixed boundary is
`authority=intent-draft-acceptance`, `commit_authority=false`, and
`executable=false`.

## Trust Boundary

This object is **Host-owned local trusted state**, not a remote assertion and not
a signed governance protocol. The Host must construct it from a separately
authenticated membership/governance source. Its `membership_digest` and
`revocation_digest` pin the exact source snapshots used, but hashes do not prove
those sources were correct or authorized. Operators must retain and verify the
referenced source artifacts independently.

The object is immutable after construction and has a canonical content digest.
`resolve()` returns an `IntentAcceptanceContext` whose `authorization_digest`
equals that content digest. Only `IntentAcceptanceStore.accept_governed()` may
persist a nonempty value; it obtains the current snapshot from an
`IntentPolicyStore` bound to the same canonical workspace under the shared
coordination lock, and requires an externally retained policy audit tail before
head selection. `verify_governed_history()` separately proves that each
governed journal row still dereferences to retained canonical policy bytes and
recomputes its authorization context. The journal context hash and optional
Spine anchor therefore bind the exact retained policy observation used at
acceptance time. Older journal rows remain readable with an empty
`authorization_digest`; empty means **legacy/unbound**, not equivalent
authorization. The legacy `accept()` API rejects nonempty authorization digests.

Do not populate policy fields from the received envelope. In particular, the
Host selects the current policy, expected signer DID, scope, and reviewed draft
independently. The journal supplies one trusted clock reading to both policy and
envelope verification, then rechecks both validity windows at the insert
boundary.

## Membership And Revocation

The v1 local profile supports direct Ed25519 `did:key` members with roles
`owner`, `admin`, or `member`. Each entry is explicitly `active` or `revoked`
and has its own bounded solver-class set and `A0`/`A1` ceiling. A signer must be
present, active, and in `allowed_acceptance_roles`; denial raises
`IntentPolicyDenied` and consumes no journal nonce.

Policy revisions form a content-addressed chain. Successors must preserve the
audience and scope, increment the revision by one, bind the previous policy
digest, and not predate the predecessor. Revoked DIDs are monotonic: a successor
cannot remove or reactivate one. Key replacement requires a new DID entry while
the old DID stays revoked. Delegation and threshold governance are intentionally
outside this local v1 profile.

## Persistence And Concurrency

`IntentPolicyStore` retains canonical snapshots in a bounded, append-only SQLite
database. Records form a second hash-linked audit chain and carry cumulative
payload bytes. Complete histories are verified at open and during explicit
audit; indexed `current()`, `get()`, and `publish()` hot paths read only the
relevant scope head and global tail. `current()` means the latest contiguous
chain head, while `effective_at()` returns that head only during its validity
window. A policy must already be effective when published; scheduled future
publication is intentionally unsupported in v1. Publishing a successor and
`IntentAcceptanceStore.accept_governed()` use the same cross-process policy lock,
so an acceptance cannot commit while another process replaces its selected
head. Exact retries resolve the current head again. The store rejects skipped or
forked revisions and removal or reactivation of a revoked DID.

The policy store still does not authenticate or lock an external governance or
membership database. Source ingestion must finish before publishing a snapshot,
and the source artifacts named by `membership_digest` and `revocation_digest`
remain separately retained evidence. This boundary, plus the absence of a
signed governance protocol, is why no remote acceptance endpoint or UI is
enabled.

SQLite triggers prevent accidental update or deletion; they are not a security
boundary against a workspace owner who rewrites the database. The audit chain
detects interior mutation. Detecting deletion of a valid suffix requires the
operator to retain its audit tail outside the database and pass it to
`verify_history(expected_tail_digest=...)`, or to anchor that tail in Spine.

## Limits And Evidence

- at most 64 direct members;
- at most 16 solver classes per member;
- policy lifetime at most 31 days;
- canonical document at most 512 KiB;
- safe-integer millisecond timestamps;
- exact closed fields, canonical DIDs, sorted unique members/roles/classes;
- exact reviewed-draft, membership, revocation, predecessor, and policy hashes.

The envelope conformance corpus includes the observation-only
`authorization_digest` expected-context field. A separate checked-in Intent
policy corpus validates canonical bytes, content digests, direct-member
resolution, and successor/revocation semantics in Python and an independent
Node consumer. This field is not copied into, or signed by, the envelope; it is
the Host's auditable, locally dereferenceable policy observation.

Run:

```text
python -m pytest -q tests/test_intent_policy.py tests/test_intent_policy_concurrency.py tests/test_intent_policy_conformance.py tests/test_intent_envelope_conformance.py tests/test_intent_acceptance.py
```
