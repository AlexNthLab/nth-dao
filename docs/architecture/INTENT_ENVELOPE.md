# Intent Envelope v1

Status: implemented protocol primitive with an explicit local journal,
not an enabled business workflow.

An envelope states that a direct DID signer accepts an exact reviewed draft for
proposal work. It is not an IntentMandate, a capability grant, an execution
request, a payment instruction, proof of human consent, or proof that a claim is
true. Source-kind labels do not authenticate a human or agent. All attachments
remain unverified metadata claims. Constraints inside a draft are signed text,
not a substitute for a future deterministic policy gate.

## Placement and API

`nth_dao.plugins.intent_envelope` is a Host-owned protocol module next to the
resolver wire contract, not an invokable provider. Its API is also exported by
`nth_dao.plugins`:

- `build_intent_envelope_body(...)` validates and snapshots explicit input. It
  never loads a key or signs. It requires outcomes and no open clarifications.
- `intent_envelope_signing_bytes(body)` supports caller/client-side signing.
- `sign_intent_envelope(body, signer=...)` signs with an explicitly supplied
  local identity. It verifies the result, including the public/private key match.
- `verify_intent_envelope(envelope, expected=..., now_ms=...)` checks structure,
  draft semantics, signature, current time, and trusted Host expectations. It
  returns a detached snapshot or raises `IntentEnvelopeError`. Missing crypto
  support raises a pointed `ImportError`; there is no unsigned fallback.
- `intent_envelope_digest(envelope)` validates structure/signature and hashes
  the complete signed artifact. It permits expired historical envelopes and
  is NOT a live authorization or current-head check.

The builder does not clear clarifications or manufacture outcomes. The literal
resolver always asks for clarification, so its unchanged output cannot pass
acceptance. A caller must explicitly review/revise the draft first. Any source
change also requires a newly bound resolve request; accepting a draft does not
silently rewrite that source. Draft constraints, outcomes, risks, assumptions,
and attachments are bound inside `draft_json`, not duplicated in writable fields.

## Signed Wire Profile

Checked-in closed schemas and vectors live under `nth_dao/plugins/vectors/`:

- `intent-envelope-body-schema-v1.json`
- `intent-envelope-schema-v1.json`
- `intent-envelope-wire-cases-v1.json`

The body has `format=org.nth-dao.intent-envelope`, `version="1"`,
`purpose=draft-acceptance`, `authority=none`, `commit_authority=false`, and
`executable=false`. Unknown fields are rejected, not ignored. The draft uses the
existing canonical `IntentDraft` v1 format. Its exact source request digest is
recomputed, as is its full draft content address.

Other body fields:

| Field | v1 constraint |
| --- | --- |
| `signer_did`, `audience_did` | Canonical Ed25519 `did:key`; no wildcard or implicit delegation. |
| `scope_id` | Exact bounded ASCII identifier selected by the Host. |
| `draft_json`, `draft_digest` | Exact canonical draft and its prefixed SHA-256 address. |
| `solver_classes` | Sorted, unique list of 1..16 exact selectors; no wildcard or permissions. |
| `automation_ceiling` | `A0` or `A1`, no higher than either draft or Host ceiling. |
| `issued_at_ms`, `expires_at_ms` | Safe integers; positive TTL at most 24 hours. |
| `nonce` | 16 bytes as lowercase hex; caller must generate with cryptographic randomness. |
| `revision`, `previous_digest` | Positive safe integer; genesis is 1 with empty predecessor; later revisions bind a signed-artifact hash. |

An envelope is bounded to 262,144 canonical UTF-8 bytes; the embedded draft
retains its 131,072-byte bound and existing field/list limits. This v1 profile is
deliberately bounded. Future execution scopes or automation modes require an
explicit protocol/policy change, not an ignored extension field.

Envelope field counts/names are checked before generic schema validation or
serialization. Diagnostics never echo unknown field names or nested draft
contents; malformed-input errors suppress raw exception chains. The returned
JSON snapshot is revalidated so a change during serialization cannot bypass the
closed schema. These checks do not replace a future HTTP body-size limit before
JSON parsing at the transport boundary.

Signing bytes are the ASCII bytes `NTH-DAO:IntentEnvelope:v1`, one zero byte,
then NTH canonical JSON of the body. Ed25519 produces the separate `signature`
field as exactly 128 lowercase hex characters. The signature is excluded from
the signing body and included in the envelope's content digest. This is an NTH
signature profile, not a W3C Data Integrity or VC proof suite. No interoperability
with those proof suites is claimed. Fixed object keys are ASCII; JSON text is
UTF-8, integers are safe integers, and floats are forbidden. At JSON ingestion,
number tokens must use decimal integer syntax: no fraction or exponent, even
when a token such as `1000.0`, `1e3`, or a rounded fraction would become an integer
in JavaScript. Integer range and field bounds are checked after token validation.
Whitespace outside the signed canonical form remains acceptable; strings that
contain numeric-looking text are not number tokens. This does not change the
shared NTH canonical serializer or the signing bytes of existing valid envelopes.

The strict NTH profile requires canonical, non-identity, prime-order curve points
for both the public key A and signature point R, and `0 <= S < L`. It rejects
small-order, mixed-order, off-curve, and noncanonical points. Successful default
OpenSSL or ZIP215 verification alone is not sufficient. Python uses PyNaCl's
libsodium operations plus an explicit `[L-1]P + P = 0` subgroup check to cover
older libsodium point-validation behavior. The independent Node consumer uses
pinned Noble point validation, `isTorsionFree`, and `zip215: false` verification.
See the [libsodium point-validation notes](https://libsodium.gitbook.io/doc/advanced/point-arithmetic)
and [Noble verification documentation](https://github.com/paulmillr/noble-curves).
This narrows only the new IntentEnvelope profile, not other NTH signed protocols.

## Verification Versus Acceptance

`IntentAcceptanceContext` must be assembled from trusted local policy and
state, never by copying received fields. The Host chooses the currently
authorized direct signer, its audience DID, scope ID, reviewed draft digest,
next revision and current predecessor digest, allowed solver classes, and
automation ceiling. It may also carry a Host-observed `authorization_digest`;
new governed acceptance uses the exact content address produced by the
[Intent policy snapshot](INTENT_POLICY.md), while empty identifies legacy
unbound state. This observation field is persisted and audited by the journal
but is not a field signed inside IntentEnvelope v1. The verifier compares the
envelope-bound expectations and checks
`issued_at_ms <= now_ms < expires_at_ms` against a trusted clock. It applies no
implicit clock-skew grace period. Both verification and hashing are repeatable.

**There is no persistent replay prevention in this primitive.** A nonce and an
expiry are signed bindings, not a consumed request. The current functions do
not write a revision chain, check historical predecessor continuity, consume a
nonce, invoke a solver, emit audit events, or create a Task/Mission/Agreement.
They must not be wired directly into any effectful endpoint.

The separate Host-owned [local acceptance journal](INTENT_ACCEPTANCE.md) now
provides SQLite-atomic nonce/revision checks and local audit persistence. It
does not change these pure verification functions or provide governance,
Spine federation, REST/UI promotion, solver execution, or payment authority.

Before enabling business promotion, the next implementation must:

1. Pin a reviewed draft and resolve current membership/role/delegation policy.
2. Verify the signed envelope against that trusted context and clock.
3. Atomically check the accepted predecessor, require revision + 1, enforce
   nonce uniqueness in signer/audience/scope, and persist the immutable envelope
   with recoverable append-only audit. Define retry idempotency and fork behavior.
4. Ensure revocation, key rotation, and concurrent acceptance fail closed; recheck
   relevant policy at the durable acceptance boundary.
5. Expose a visible diff and an explicit caller-side signature. Only then enable
   proposal generation under a bounded Host-selected solver, still not execution.

Real payments and irreversible actions continue to require the separate signed
mandate chain, reviewed adapters, and deterministic policy/commit gates.

## Verification Evidence

Install locked test-only Node dependencies with
`npm ci --prefix tests/conformance --ignore-scripts` (Node >=22.13).
Missing dependencies fail conformance; there is no permissive fallback. The
package lock is included in release CI; Noble is not a Python runtime dependency.
Run `python -m pytest -q tests/test_intent_envelope.py
tests/test_intent_envelope_conformance.py` on one command line. Regenerate the
public test-only vectors with `python -m tools.generate_intent_envelope_vectors`.
The generator derives disposable keys from public test labels. It never reads
an identity file or exports a private key; those identities must never be trusted
outside conformance tests.

The independent Node consumer checks the closed v1 schemas, canonical bytes,
Ed25519 signatures, embedded draft/source binding, time, and expected context.
Expected context is validated as a closed object with bounded, sorted, unique
solver-class arrays before exact set membership checks. It is a trusted Host
input, not an authority declaration that a remote sender can choose.
The consumer checks original number tokens through native
[`JSON.parse` source context](https://tc39.es/proposal-json-parse-with-source/),
and fails at startup when this facility is missing. It never falls back to
`Number.isSafeInteger` alone. Raw JSON vectors preserve decimal, exponent,
rounded-fraction, and invalid-number inputs for both implementations, including
trusted context and clock fields. The native parser, not a handwritten JSON
tokenizer, retains responsibility for JSON grammar and string escaping.
Python verifies a fresh Node-generated signature in the reverse direction too.
Re-signed malformed bodies test semantic rejection independently of cryptographic
rejection. Unicode byte/character limits and trailing-control identifiers are
regressions, not just happy-path vectors. This is conformance for this bounded
profile and corpus, not a general JSON Schema implementation, exhaustive proof,
UI integration test, or certification of every Ed25519 implementation.
