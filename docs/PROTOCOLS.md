# NTH DAO Wire Protocols (v1)

This is the protocol-level spec — what's on the wire, what's in the files —
so a Rust / Go / TypeScript implementation can interop with the Python
reference. If you're consuming `nth_dao` as a Python library, you don't need
this document.

All `bytes` payloads are encoded as hex strings in JSON form.
All signatures are Ed25519 over `canonical_json(payload_without_sig)`.
"canonical JSON" means `json.dumps(d, sort_keys=True, separators=(",", ":"),
ensure_ascii=False)` then UTF-8 encoded.

---

## 1. Identity

A NTH DAO agent identity is an Ed25519 keypair plus a stable `agent_id`.

When the agent_id is "cryptographic" (`AgentID.is_cryptographic = True`)
it is derived as:

    agent_id = SHA-256(pubkey_bytes).hex()[:12]

Plain `agent_id`s (no derivation) are also allowed for legacy use; they
have no cryptographic backing and rely on operator trust.

### identity.json

```json
{
    "agent_id":      "9c50edd2373f",
    "label":         "Alice's laptop",
    "is_cryptographic": true,
    "pubkey":        "<64 hex chars = 32 bytes>",
    "fingerprint":   "<sha256(pubkey || agent_id)[:16] hex>",
    "metadata":      { ... },
    "private_key":   "<64 hex chars = 32 bytes>"
}
```

`private_key` MUST be readable only by the file owner. The Python
reference implementation enforces this via `chmod 0o600` on POSIX and
`icacls /grant ... /inheritance:r` on Windows; failures emit a logger
warning.

**Load-time validation**: an implementation MUST verify that
`Ed25519SigningKey(private_key).verify_key.encode() == pubkey`. If not,
refuse to load (the file has been tampered with).

---

## 2. Gossip (WebSocket P2P)

### Handshake (challenge-response)

Both sides MUST have a crypto identity (PyNaCl / Ed25519 equivalent).

```
client → server: { "type": "hello", "agent_id": "<id>", "pubkey_hex": "<hex>" }
server → client: { "type": "challenge", "nonce": "<32 hex chars>" }
client → server: { "type": "challenge_response",
                   "agent_id": "<id>",
                   "sig": "<hex sig of canonical_json({\"nonce\": <nonce>})>" }
server: verify sig under client's claimed pubkey; if fail, close 1008.
server → client: { "type": "welcome",
                   "agent_id": "<server id>",
                   "pubkey_hex": "<server pubkey>",
                   "channels":   [...],
                   "server_challenge": "<32 hex chars>" }
```

After welcome, both sides treat the connection as authenticated. The
server pins (agent_id → pubkey_hex) in its trust anchor map for the
duration; the client adds the server to its own map (TOFU).

### Reject conditions (server)
- Missing `agent_id` or `pubkey_hex` in hello → close 1008.
- A peer claims an `agent_id` that's already in the trust map under a
  *different* pubkey → close 1008 ("pubkey mismatch with trust anchor").
- `challenge_response.sig` doesn't verify under claimed pubkey → 1008.
- Handshake doesn't complete within 8 seconds → close.

### Gossip message envelope

```json
{
    "type":    "gossip",
    "message": { ... ChannelMessage ... }
}
```

Where `ChannelMessage` is:

```json
{
    "msg_id":       "<hex>",
    "channel":      "team" | "group:<name>" | "dm:<a>--<b>",
    "from_agent":   "<author agent_id>",
    "content":      "...",
    "content_type": "text" | "markdown" | "json",
    "reply_to":     "<msg_id or '' >",
    "mentions":     ["<agent_id>", ...],
    "timestamp":    "<ISO 8601>",
    "metadata":     { ... },
    "sig":          "<hex sig over canonical_json(message_without_sig)>"
}
```

### Receive validation (peer)

For every incoming `gossip` envelope, in order:

1. **Dedup**: drop if `msg_id` is in recent-seen LRU (default cache 1000).
2. **Timestamp window**: drop if `now - timestamp > 600s` (replay) or
   `timestamp - now > 60s` (clock skew tolerance).
3. **Trust anchor lookup**: find the pubkey for `from_agent` —
   - direct lookup in pinned `trusted_pubkeys`, OR
   - transitive lookup via `TrustGraph.trusted_pubkey_for(from_agent,
     max_depth=2)` if `trust_graph` is configured.
4. **Signature**: verify `sig` over `canonical_json(message − sig)` under
   that pubkey. **Verification failure MUST drop the message** —
   never `pass`, never relay.
5. **Persist**: append the message to local `team_messages/<channel>/...jsonl`.
6. **Relay**: forward the original envelope to every other connected peer
   (`exclude` the peer we received it from).

---

## 3. Endorsements & Revocations (Web-of-Trust)

### Endorsement

```json
{
    "endorser_pubkey":  "<hex>",
    "subject_pubkey":   "<hex>",
    "subject_agent_id": "<id>",
    "depth_allowed":    1..5,
    "context":          "general" | "code_review" | ...,
    "issued_at":        "<ISO>",
    "expires_at":       "<ISO>",
    "sig":              "<hex over canonical_json(endorsement − sig)>"
}
```

Stored append-only at `team_trust/endorsements.jsonl`.

`depth_allowed` is a hop-budget cap: when verifying transitive trust,
the subject of this endorsement can re-endorse at most
`depth_allowed - 1` further hops.

### Revocation

```json
{
    "endorser_pubkey":         "<hex>",
    "subject_pubkey":          "<hex>",
    "subject_agent_id":        "<id>",
    "endorsement_issued_at":   "<ISO matching the endorsement>",
    "reason":                  "...",
    "revoked_at":              "<ISO>",
    "sig":                     "<hex over canonical_json(revocation − sig)>"
}
```

Stored append-only at `team_trust/revocations.jsonl`. To take effect:

1. Signature MUST verify under `endorser_pubkey`.
2. A matching `endorsement` MUST exist locally — otherwise the revocation
   is dropped (preventing pre-emptive DoS revocations of endorsements
   that don't exist).

### BFS resolution

Roots are pinned in `team_trust/roots.json`:

```json
{ "<agent_id>": "<pubkey_hex>", ... }
```

To check `is_trusted(agent_id, pubkey, max_depth=N)`:

1. If `(agent_id, pubkey)` is in roots → trusted (depth 0).
2. BFS from each root; at each hop, follow non-revoked, non-expired
   endorsements; subject's further-hop budget is
   `min(remaining_budget, endorser.depth_allowed - 1)`.
3. Stop when target found or hop budget exhausted.

Max absolute depth is capped at `MAX_PROPAGATION_DEPTH = 5` even if the
caller passes a larger value.

---

## 4. Signed Team Config

`team.json` (one per workspace):

```json
{
    "team_id":      "<short id>",
    "team_name":    "...",
    "join_policy":  "open" | "approval" | "invite_only" | "token",
    "join_token":   "...",
    "admin_ids":    [...],
    "member_ids":   [...],
    "roles":        { "<agent_id>": "owner|admin|member|guest" },
    "created_at":   "<ISO>",
    "metadata":     { ... },
    "owner_pubkey":   "<hex>",       // optional; if set, file is signed
    "owner_sig":      "<hex>",       // sig over canonical_json(cfg − owner_sig)
    "sig_updated_at": "<ISO>"
}
```

When `owner_pubkey` is non-empty, `owner_sig` MUST verify. A reader that
sees an invalid signature MUST treat the file as if it didn't exist
(empty TeamConfig) — this is what prevents git-sync poisoning.

The signature is over the dict with `owner_sig` removed (the
"signable dict"), encoded as canonical JSON.

---

## 5. Invitations

A signed bundle that lets a new agent bootstrap into a team with one
scan / paste / link.

URL form: `nthdao+invite://<base64url(json_payload)>`

Payload:

```json
{
    "team_id":      "...",
    "team_name":    "...",
    "owner_pubkey": "<hex>",
    "issuer":       "<owner agent_id>",
    "issued_at":    "<ISO>",
    "expires_at":   "<ISO>",
    "join_token":   "...",       // for JoinPolicy.TOKEN
    "ws_url":       "ws://host:9876",  // optional bootstrap peer
    "psk":          "...",       // optional LAN discovery PSK
    "sig":          "<hex over canonical_json(payload − sig)>"
}
```

Validation:
1. `expires_at` must be in the future.
2. `sig` must verify under `owner_pubkey`.
3. Payload after base64-decode must be JSON object, ≤ 2048 bytes.

---

## 6. LAN Discovery (UDP)

Default port `9877` on the local subnet. JSON over UDP. Single-packet only
(MAX_MESSAGE_BYTES = 4096).

### Query

```json
{
    "type":    "nth-dao-query",
    "v":       1,
    "from":    "<querier agent_id>",
    "wants":   ["python", ...],   // empty = match anyone
    "nonce":   "<16 hex chars>",
    "psk_tag": "<hmac_sha256(psk, nonce).hex() or ''>"
}
```

### Hello (response)

```json
{
    "type":         "nth-dao-hello",
    "v":            1,
    "agent_id":     "<responder id>",
    "label":        "...",
    "capabilities": [...],
    "groups":       [...],
    "ws_url":       "ws://host:9876",
    "pubkey_hex":   "<hex>",
    "metadata":     { ... },
    "nonce":        "<echoes the query nonce>",
    "psk_tag":      "<HMAC-SHA256(psk, nonce).hex() or ''>",
    "ts":           <epoch float>
}
```

### Responder rules
- Drop queries with `v != 1`, wrong `type`, or `from == own agent_id`.
- If `psk` is configured, drop queries whose `psk_tag` doesn't match
  `HMAC-SHA256(psk, nonce)` under constant-time comparison.
- If `wants` is non-empty and not a subset of own capabilities, don't
  respond.

### Querier rules
- Drop hellos with mismatched `nonce`, wrong `v`, wrong `type`.
- If `psk` is configured, drop hellos whose `psk_tag` doesn't match.
- Deduplicate by `agent_id`.
- Tolerate `ConnectionResetError` on `recvfrom` (Windows ICMP
  unreachable bleed-through).

---

## 7. Marketplace Order

`team_marketplace/<order_id>.json`:

```json
{
    "order_id":    "<hex>",
    "creator":     "<agent_id>",
    "title":       "...",
    "description": "...",
    "context":     "general" | "code_review" | ...,
    "reward":      <float>,
    "deadline":    "<ISO or '' >",
    "tags":        [...],
    "requirements": {
        "min_reputation": <float>,
        "capabilities":   [...]
    },
    "status":      "open"|"claimed"|"in_progress"|"submitted"|"completed"|"failed"|"cancelled"|"disputed"|"expired",
    "claimant":    "<agent_id or '' >",
    "submission_proof": "...",
    "submission_at":    "<ISO>",
    "rating":      <float 0-5>,
    "feedback":    "...",
    "created_at":  "<ISO>",
    "claimed_at":  "<ISO>",
    "completed_at": "<ISO>",
    "timeline":    [{ "action": "...", "actor": "...", "timestamp": "...", ... }, ...],
    "creator_sig":  "<hex>",     // signed at create
    "claimant_sig": "<hex>"      // signed at claim
}
```

Credit transactions logged append-only at
`team_marketplace/<agent>_credits.ledger.jsonl`, one line per movement:

```json
{
    "ts":             "<ISO>",
    "agent_id":       "...",
    "kind":           "escrow_lock|escrow_refund_cancel|escrow_refund_expired",
    "delta":          <signed float>,
    "balance_before": <float>,
    "order_id":       "..."
}
```

---

## 8. Mission

`missions/<mission_id>.json`:

```json
{
    "id":          "<hex>",
    "title":       "...",
    "goal":        "...",
    "status":      "planning"|"active"|"paused"|"completed"|"failed"|"cancelled",
    "owner":       "<agent_id>",
    "scope":       "shared"|"group:<g>"|"private:<id>",
    "steps":       [ MissionStep, ... ],
    "deadline":    "<ISO or '' >",
    "priority":    "low"|"normal"|"high"|"critical",
    "tags":        [...],
    "metadata":    { ... },
    "created_at":  "<ISO>",
    "updated_at":  "<ISO>",
    "completed_at": "<ISO or null>"
}
```

`MissionStep`:

```json
{
    "id":          "<hex>",
    "description": "...",
    "status":      "todo"|"claimed"|"active"|"done"|"failed"|"handed_off"|"blocked",
    "required_capabilities": [...],
    "inputs":      { ... },
    "output":      { ... } | null,
    "depends_on":  ["<step_id>", ...],
    "assignee":    "<agent_id>",
    "previous_assignees": [...],
    "created_at":  "<ISO>",
    "updated_at":  "<ISO>",
    "completed_at": "<ISO or null>",
    "notes":       ["[<ISO>] <author>: <text>", ...]
}
```

### Claim rules (atomic)

- Implementations MUST acquire an exclusive file lock (POSIX `fcntl.LOCK_EX`
  or Windows `msvcrt.LK_NBLCK` on `<mission_id>.json.lock`) before
  read-modify-write.
- A `try_claim(mission_id, step_id, agent_id, capabilities)` MUST:
  1. Reject if step status ∉ {`todo`, `handed_off`, `blocked`}.
  2. Reject if step.assignee is non-empty AND ≠ agent_id (handed_off
     with a specific recipient only allows that recipient to claim).
  3. Reject if step.required_capabilities ⊄ agent.capabilities.
  4. Otherwise transition step → `active`, assignee = agent_id, add a
     note, save.
- Concurrent claimers MUST observe exactly-once semantics: one winner,
  all others receive a `ClaimConflict` (Python) / equivalent error.

### Terminal state rules

- All steps `done` (or `handed_off`) → mission `completed`.
- Any step `failed` AND no remaining actionable step (i.e. no step
  satisfies its `depends_on` set and is still `open`) → mission `failed`.
- Otherwise PLANNING → ACTIVE on first non-TODO step transition.

---

## 9. Mission Template + Review (v0.9.3)

### 9.1 Why this layer

A `Mission` instance is one-shot — once claimed, completed, archived, it stops
existing as a workable unit. A `MissionTemplate` is the reusable *recipe* a
mission is built from: the same template can be instantiated by many agents,
in many teams, over many years, and each instantiation produces a fresh,
locked Mission.

This is the "decentralized App Store" layer in the project vision (cf.
`README.md`'s 3-layer mission story).

### 9.2 Alignment with industry standards

| Standard | We align with |
|----------|--------------|
| **cargo-crev** Proof model | Templates and reviews are append-only, signed-by-author payloads. |
| **F-Droid** metadata layout | One file per template version + a derived index. |
| **TUF** wire format | `_template_index.json.version` is monotonic; `meta` field name preserved; `delegations` placeholder reserved. |
| **Argo WorkflowTemplate** | 5-value `template_type` enum. |
| **GitHub Actions** `action.yml` | `inputs` / `outputs` field naming (description / type / required / default / values). |
| **Nix `flake.lock`** | `Mission.template_lock` snapshots `publisher_sig` at instantiation. |
| **W3C did:key** | `publisher_did` field (simplified `did:key:<pubkey>` form). |

No third-party dependency is introduced. These alignments are about
**vocabulary and on-disk layout**, not runtime. Future adapters that
translate to or from these ecosystems should be small (≤ 100 LOC each).

### 9.3 On-disk layout

```
missions/
├── templates/
│   ├── <template_id>-v<version>.json    # one file per (template_id, version)
│   └── ...
├── reviews/
│   ├── <template_id>-v<version>.jsonl   # signed reviews, append-only
│   └── ...
├── _template_index.json                 # derived index, F-Droid + TUF style
├── _review_index.json                   # aggregated stats per (template, version)
├── <mission_instance_id>.json           # active missions (Layer 1)
└── archive/
    └── YYYY-MM/
        └── <mission_instance_id>.json   # terminal missions older than N days
```

### 9.4 MissionTemplate

```json
{
    "template_id":            "code-review",
    "version":                "1.0.0",
    "publisher_pubkey":       "<hex Ed25519>",
    "publisher_did":          "did:key:<short>",
    "name":                   "Code Review",
    "description":            "...",
    "template_type":          "agent_task | agent_chain | agent_dag | agent_review | human_in_loop",
    "category":               "code_review",
    "tags":                   ["python", "security"],
    "required_capabilities":  ["code_review"],
    "inputs": {
        "diff_url": {
            "description":  "PR diff URL",
            "type":         "string | int | float | bool | enum | json",
            "required":     true,
            "default":      "",
            "values":       ["low", "med", "high"]    // only for type=enum
        }
    },
    "outputs": { /* same shape as inputs */ },
    "steps": [
        {
            "id":                     "review",
            "description":            "...",
            "required_capabilities":  ["code_review"],
            "depends_on":             [],
            "inputs_from": {
                "diff_url": "input:diff_url"   // simple sourcing: input:NAME
            }
        }
    ],
    "suggested_reward":           5.0,
    "suggested_deadline_hours":   24,
    "created_at":                 "<ISO>",
    "deprecated":                 false,
    "deprecated_reason":          "",
    "supersedes":                 ["code-review-v0.9.0"],
    "delegations":                [],                  // TUF placeholder, unused in v0.9.3
    "credentials_required":       [],                  // W3C VC placeholder, unused
    "legal_jurisdiction":         "",                  // Layer 3 placeholder, unused
    "publisher_sig":              "<hex sig over canonical_json(template - publisher_sig)>"
}
```

**Validation rules**:
- `version` MUST be valid semver (`MAJOR.MINOR.PATCH[-prerelease][+meta]`).
- Re-publishing the same `(template_id, version)` without `allow_overwrite=True` fails.
- `publisher_sig` MUST verify under `publisher_pubkey` before persistence.
- `deprecated=true` blocks `instantiate()`; only the original publisher can
  flip the flag (verified via pubkey equality, then re-sign).

### 9.5 Index file (`_template_index.json`)

TUF-style derived state, rebuilt on every publish. Never authored by hand.
This index is not a trust anchor; consumers must verify each template file's
`publisher_sig` before instantiation.

```json
{
    "version":      42,                    // monotonic; bumped each rebuild
    "generated_at": "<ISO>",
    "meta": {
        "code-review-v1.0.0.json": {
            "template_id":      "code-review",
            "version":          "1.0.0",
            "publisher_pubkey": "<hex>",
            "deprecated":       false,
            "category":         "code_review"
        }
    },
    "by_category":    { "code_review": ["code-review@1.0.0", ...] },
    "by_publisher":   { "<pubkey_prefix>": ["code-review@1.0.0", ...] },
    "by_capability":  { "code_review":   ["code-review@1.0.0", ...] }
}
```

### 9.6 Mission instance with template lock

```json
{
    "id":                "abc123",
    "title":             "...",
    "goal":              "...",
    "status":            "active",
    "owner":             "bob",
    "scope":             "shared",
    "steps":             [ ... ],
    "template_id":       "code-review",
    "template_version":  "1.0.0",
    "template_lock": {
        "publisher_pubkey":  "<hex>",
        "publisher_sig":     "<hex>",        // snapshot at instantiation
        "template_type":     "agent_task",
        "category":          "code_review",
        "instantiated_at":   "<ISO>"
    },
    "owner_did":             "",            // Layer 3 placeholder, unused
    "legal_jurisdiction":    "",
    "governing_arbiter":     "",
    "credentials_required":  []
}
```

The lock prevents "supply-chain swaps": if Alice publishes v1.0.0, Bob
instantiates it, then Alice republishes a different v1.0.0 (illegal under
our rules but theoretically possible after a hand-edit), Bob's mission
still verifies against the snapshot.

### 9.7 MissionReview

```json
{
    "review_id":          "<hex>",
    "reviewer_pubkey":    "<hex>",
    "reviewer_agent_id":  "carol",
    "template_id":        "code-review",
    "template_version":   "1.0.0",
    "mission_id":         "abc123",
    "score":              4.5,
    "feedback":           "...",
    "metadata":           { },
    "created_at":         "<ISO>",
    "reviewer_sig":       "<hex sig over canonical_json(review - reviewer_sig)>"
}
```

**Persistence**: one line per review in `reviews/<template_id>-v<version>.jsonl`.
Append-only; never deleted. Bad-signature entries are dropped silently at read
time with a `logger.warning`.

**Dedupe at read**: when `only_latest_per_reviewer=True`, the per-
`(reviewer_pubkey, mission_id)` tuple keeps only the highest `created_at`.
The raw ledger preserves every submission for audit.

**Self-review rejection**: the mission's `owner` MAY NOT review their own
mission (`ValueError`). This is enforced at the `review_mission` API, not at
the data layer.

### 9.8 Aggregation (`_review_index.json`)

Derived; rebuilt on every `append`. Field names:

```json
{
    "code-review@1.0.0": {
        "template_id":       "code-review",
        "version":           "1.0.0",
        "install_count":     12,
        "review_count":      14,
        "average_rating":    4.21,
        "weighted_average":  4.45,      // EWMA, recent reviews weighted (alpha=0.3)
        "unique_reviewers":  9,
        "min_rating":        1.0,
        "max_rating":        5.0,
        "last_review_at":    "<ISO>"
    }
}
```

### 9.9 Browse semantics

`browse_templates(category=..., tags=..., min_average_rating=..., sort_by=...)`:

- Templates with **zero reviews** are returned regardless of `min_average_rating`
  so that newcomers are still discoverable. Once they have ≥ 1 review,
  `min_average_rating` applies.
- `sort_by="rating"` is `(has_reviews, weighted_average, review_count)` desc.
- `sort_by="recent"` is `created_at` desc.
- `sort_by="popularity"` is `(install_count, review_count)` desc.
- `include_deprecated=False` by default; deprecated templates are hidden.

### 9.10 Archive + history

`archive_completed(older_than_days=30)`:
- Moves missions whose `status ∈ {completed, failed, cancelled}` and whose
  `completed_at / updated_at / created_at` is older than the cutoff into
  `archive/YYYY-MM/`.
- Atomic per file (`InterProcessLock` then write-dst-then-unlink-src).
- Default 30-day window; callers can pass `older_than_days=0` to archive all
  terminal missions immediately.

`my_history(agent_id, since=, include_archive=True, limit=)`:
- Returns missions where `agent_id` matches `owner`, any current `assignee`,
  or appears in any step's `previous_assignees`.
- Walks `archive/` by default.
- Sorted by `completed_at` desc; still-active missions bubble to the front.

### 9.11 Future-compatibility reserved fields

These fields appear in v0.9.3 on-disk format with empty defaults; no
behavior is attached to them yet. Stable now means a v0.9.4+ release can
populate them without breaking on-disk format.

| Field | Future use |
|------|-----------|
| `MissionTemplate.delegations`        | TUF-style key delegation chains |
| `MissionTemplate.credentials_required` | W3C VC types the claimant must hold |
| `MissionTemplate.legal_jurisdiction` | Layer 3 arbitration |
| `Mission.owner_did`                  | DID-key owner ID |
| `Mission.legal_jurisdiction`         | Layer 3 arbitration |
| `Mission.governing_arbiter`          | Layer 3 third-party judge |
| `Mission.credentials_required`       | per-mission VC gating |

---

## 10. Capability Tokens (cap_token)

`nth-cap-token-v1` is the wire format for delegated authority. The hub
issues a signed token to a child agent at spawn; the child presents the
token to peer agents over A2A; peers verify the token before honoring
the request.

### 10.1 Body

`kind`, `spec` are version pins. `issuer_did` signed; `subject_did` is
the bearer. Phase 6 added `scope_model_allowlist` for per-token model
governance.

```json
{
  "kind": "nth-cap-token-v1",
  "spec": "nth-dao/cap-token@1.0",
  "token_id": "<32-hex>",
  "issuer_did": "did:key:z6Mk...",
  "subject_did": "did:key:z6Mk...",
  "capabilities": ["a2a:message_send", "nth:receipt_sign"],
  "scope_task_id": "",
  "scope_dao": "",
  "scope_model_allowlist": ["claude-sonnet-4-6"],
  "not_before": 1717000000000,
  "not_after": 1717003600000,
  "nonce": "<32-hex>",
  "sig": "<base64url-of-Ed25519-sig>"
}
```

- `token_id` — alphanumeric + dash. Doubles as a filename in
  `<workspace>/team_cap_tokens/<token_id>.json` for audit. Reject any
  other characters at issuance.
- `capabilities` — sorted, deduplicated, non-empty. Each entry follows
  `verb:noun` naming (e.g. `a2a:message_send`, `nth:receipt_sign`).
  Unknown entries (not in `KNOWN_CAPABILITIES`) are accepted on the
  wire but the v2 spawn endpoint filters them at issuance.
- `scope_task_id` / `scope_dao` — empty string = "no scope", an
  explicit value pins the token to that one task / DAO.
- **`scope_model_allowlist`** *(Phase 6b)* — `null` field absent on
  the wire = "no per-token model scope, defer to backend". When
  present:
    - `[]` empty list = "token forbids all `params['model']`
      OVERRIDES" (does NOT restrict the backend's `DEFAULT_MODEL`
      — see §12.3).
    - Non-empty list = "token allows only these models", strings
      stripped + deduped + sorted at sign time.
- `not_before` / `not_after` — milliseconds since epoch. `not_after`
  capped at 1 week (`MAX_TTL_MS = 604_800_000`) to bound delegation
  reach.
- `nonce` — 32-hex, freshly minted per token. Prevents collision
  attacks against the audit store.

### 10.2 Signature

Compute over `canonical_json(body_without_sig)`:

    sig = Ed25519_sign(issuer_privkey, canonical_json(body_minus_sig))
    body["sig"] = b64url_encode(sig)

Verify the inverse. The verifier's check order is shape → time bounds
→ revocation → required capabilities → scope → signature. Time bounds
and revocation are cheap so they fail fast; the signature check (most
expensive) runs last.

### 10.3 Authorization Header Envelope

Peers present the token in the `Authorization` header of their
`/a2a/<method>` request:

    Authorization: CapToken <b64url(canonical_json(body))>

The scheme is `CapToken` (not `Bearer`) so middleware can distinguish
cap_tokens from the operator's console Bearer token at the HTTP layer.

---

## 11. Execution Receipts (`nth-execution-receipt-v1`)

A receipt is a signed timeline of typed entries. The hub recovers them
on startup and persists them via the receipt store. Verifiers replay
the timeline + cross-check against the `authorizing_cap_token` chain.

### 11.1 Envelope

```json
{
  "kind": "nth-execution-receipt-v1",
  "spec": "nth-dao/execution-receipt@1.0",
  "compatible_with": "motebit/execution-ledger@1.0",
  "receipt_id": "<32-hex>",
  "goal_id": "a2a:ask",
  "signer_did": "did:key:z6Mk...",
  "signer_pubkey_hex": "<64-hex>",
  "issued_at": "2026-06-12T03:14:15.926+00:00",
  "timeline": [ … ],
  "content_hash": "<64-hex>",
  "sig": "<base64url-of-Ed25519-sig>",
  "authorizing_cap_token": { … }       // optional
}
```

- `signer_did` — the agent that signed. Pubkey is reconstructible from
  the DID; `signer_pubkey_hex` is supplied redundantly so a verifier
  can cross-check without parsing the DID.
- `issued_at` — UTC-aware ISO 8601. Used for chain head sorting only;
  signature does NOT cover this field (so a verifier with skew gets
  the same content_hash).
- `content_hash` — SHA-256 hex of the serialized timeline (NOT the
  envelope). Used as the signature input AS-RAW-BYTES (`bytes.fromhex`)
  per motebit §6 — implementations that sign the hex string produce
  sigs no motebit verifier accepts.
- `authorizing_cap_token` — when present, verifier walks back to the
  issuer's root authority. Lives OUTSIDE the signed body because the
  cap_token has its own signature; nesting them would create a
  chicken-and-egg sig dependency.

### 11.2 Timeline Entries

Each entry has three fields:

```json
{
  "timestamp": 1717000123456,
  "type": "<entry-kind>",
  "payload": { … }
}
```

Three entry kinds are defined:

- **`nth.agent_attestation`** *(Phase 3c)* — emitted once at agent
  start when the cap_token first lands. Payload pins `agent_id`,
  `kind`, `did`, `cap_token_id`, `cap_token_caps`, `a2a_port`, plus a
  `claim` string. Proves "I, this agent, hold the cap_token above
  and am alive at this timestamp."

- **`nth.a2a_ask_executed`** *(Phase D)* — emitted by the child on
  successful `/a2a/ask` or `/a2a/ask-stream`. Payload:

    ```json
    {
      "method": "ask" | "ask-stream",
      "backend": "claude-code" | "codex" | "hermes" | "mock",
      "caller_did":      "did:key:z6Mk…",
      "agent_did":       "did:key:z6Mk…",
      "requested_model": "claude-sonnet-4-6" | "",
      "resolved_model":  "claude-sonnet-4-6" | "",
      "input_tokens":    7,
      "output_tokens":   1,
      "started_at_ms":   1717000123456,
      "ended_at_ms":     1717000128456,
      "elapsed_ms":      5000,
      "stop_reason":     "end_turn" | "",
      "cap_token_id":    "<32-hex>"
    }
    ```

  `resolved_model` is the receipt's cost-accountability anchor — it
  records exactly which model was billed regardless of what the caller
  asked for. Backends that don't surface a model field (mock) carry
  `""` here.

- **`nth.chain_link`** *(Phase B)* — prepended automatically by
  `sign_receipt` when `prev_content_hash` is non-empty. Payload is
  just `{"prev_content_hash": "<64-hex>"}`. The chain link participates
  in the content_hash so the linkage is signature-protected.

### 11.3 content_hash Algorithm

```
for each entry in timeline:
    canonical_entry = canonical_json(entry.to_dict())
sha256.update(canonical_entry)
content_hash = sha256.hexdigest()
sig = Ed25519_sign(signer_privkey, sha256.digest())  // RAW 32 BYTES
```

The signature input is **the 32-byte raw digest**, not the hex string.
Multiple round-trip tests across Rust + TS verifiers have caught
implementations that signed the hex.

---

## 12. A2A Method Surface (`POST /a2a/<method>`)

Each running agent serves an HTTP loop on `127.0.0.1:<random-port>`.
The `/ping` GET is unauthenticated and returns the agent's identity
card. Everything else is `POST /a2a/<method>` with `Authorization:
CapToken <…>`.

### 12.1 Methods

| Method        | Required cap            | Returns                          |
|---------------|-------------------------|----------------------------------|
| `echo`        | `a2a:message_send`      | `{result: {received_params, …}}` |
| `ask`         | `a2a:message_send`      | `{result: {response, model, …}}` |
| `ask-stream`  | `a2a:message_send`      | SSE: `data: {delta}` lines + `done` |

Methods not in the table return `401 method-unknown` — auth runs
before dispatch and rejects any method whose required cap isn't
defined. (The dispatcher carries a defensive `404 method-not-found`
fallback that is unreachable in current code but kept as a belt-and-
suspenders guard.)

### 12.2 Auth + Scope Order (every method)

1. **Parse `Authorization`.** Must be `CapToken <b64url-canonical>`.
   Bad scheme → 401 `bad-scheme`.
2. **Verify cap_token** (`verify_cap_token`). Time bounds → revocation
   → required capability → signature. Failures map to 401 / 403 with
   the `REJECT_*` reason string.
3. **`_enforce_token_model_scope(token, params)`** *(Phase 6b)*. Runs
   for ALL methods (`ask`, `ask-stream`, `echo`, and any future
   methods). If `params['model']` is present and the token's
   `scope_model_allowlist` is `[]` or doesn't contain the requested
   model → 403 `model-not-in-token-scope`. Cheap inline check; fails
   before paying SDK init / subprocess spawn.
4. **Method dispatch.**

### 12.3 Two-Layer Model Policy (Phase 6)

```
peer request
  └─ A2A handler
     ├─ Phase 6b: cap_token.scope_model_allowlist gate  ← per-token scope
     └─ backend.ask()
        ├─ Phase 6a: backend.MODEL_ALLOWLIST gate        ← per-backend policy
        └─ provider call
```

- The cap_token scope is the *per-token* answer: "is this peer
  allowed to ask for this model?"
- The backend allowlist is the *per-deployment* answer: "is this
  model in our operator's hub-wide policy?"
- Both must pass. The cap_token scope can only **narrow**, never
  widen. An operator who issues a permissive token can't bypass
  their own deployment cap.
- **Important asymmetry**: both gates check `params['model']`
  OVERRIDES only. The backend's `DEFAULT_MODEL` (used when caller
  omits the field) is unconditionally trusted — operators wanting a
  true cost floor must set `DEFAULT_MODEL` to the cheapest model
  AND set `scope_model_allowlist=[]` on the issued tokens so peers
  can neither pick a model nor escape the default.

### 12.4 Response Shape — `ask`

```json
{
  "result": {
    "method": "ask",
    "backend": "claude-code",
    "model": "claude-sonnet-4-6",   // Phase D: resolved model
    "response": "PONG",
    "caller_did": "did:key:z6Mk…",
    "agent_did": "did:key:z6Mk…"
  }
}
```

The `model` field surfaces the same value as the receipt's
`resolved_model`. Operators can correlate the response with the
signed audit record by matching `(agent_did, model, received_at)`.

### 12.5 Response Shape — `ask-stream` (SSE)

```
HTTP/1.1 200 OK
Content-Type: text/event-stream; charset=utf-8
Cache-Control: no-cache
Connection: close

data: {"delta":"hello"}

data: {"delta":" world"}

data: {"done":true,"input_tokens":7,"output_tokens":2,"model":"…","caller_did":"…","agent_did":"…"}
```

Errors mid-stream emit a final `data: {"error": {...}}` event then
close the connection. A receipt for the stream is signed on clean
completion only; partial / errored streams produce no receipt because
there's no canonical "what was billed" answer for a failed run.

### 12.6 Receipt Emission

After a successful `ask` or `ask-stream`, the child signs a
`nth.a2a_ask_executed` receipt (§11.2), emits it via the NDJSON
stderr-event stream as:

```json
{"event": "receipt_signed", "agent_id": "…", "receipt": { … }}
```

The supervisor's persistor closure picks it up off the child's stdout
and writes to the workspace receipt store. Receipt signing is
best-effort: a failure to sign logs an error but does NOT block the
response to the caller — the LLM response is the user-facing value,
and the supervisor's recovery sweep covers rare missed signings.

---

*Last updated for nth-dao v0.10.0 (Phase D, 2026-06-12).*
