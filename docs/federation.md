# NTH DAO Federation Discovery

Federation lets independently operated NTH DAO nodes discover signed tasks,
services, product listings, and exact signed Trade Offer v2 documents without
a central market index. It is an overlay network, not magic zero-configuration
global discovery: every new network needs at least one reachable bootstrap
seed.

## Mental Model

- **Operator seed**: a URL explicitly configured by the local operator.
- **Learned peer**: a public HTTPS URL learned from a seed or peer and accepted
  only after its signed identity card is fetched and verified.
- **Feed digest**: a signed, compact hint describing available announcements.
- **Full announcement**: a signed task, service, product, or exchange discovery
  record fetched on demand. Its publisher signature is the authority for its
  content.
- **Trade Offer document**: the exact content-addressed, independently signed
  Trade Offer fetched for an exchange announcement and rebound to that hint.
- **Peer hello**: a reverse-discovery hint sent by a newcomer to its seeds. The
  receiver fetches the newcomer's identity card itself before learning it.

A signature proves who authored a statement. It does not prove that a peer is
honest, competent, reputable, or suitable for a transaction. Governance and
trust policy remain separate layers.

## Bootstrap

Configure one or more reachable seed hubs:

```powershell
$env:NTH_FED_PEERS = "https://seed-a.example,https://seed-b.example"
python -m nth_dao.web
```

Alternatively, manage seeds from Market's Federation panel or store a JSON string array
at `<workspace>/federation/peers.json`.

For a node to become reachable from the wider federation, configure the exact
public HTTPS URL served by that node:

```powershell
$env:NTH_PUBLIC_BASE_URL = "https://dao-alice.example"
python -m nth_dao.web
```

The URL is included in the node's signed identity card. The background poller
sends a bounded peer hello to configured seeds. The poller starts with the
server lifespan, so headless nodes do not need a browser visit to join the
peer graph. A seed does not trust the POST
body: it resolves the hostname, rejects private/reserved addresses, pins the
connection to the validated IP, fetches the identity card, verifies DID:key,
public key, signature, and URL binding, and only then stores the peer.

Private LAN nodes may use UDP or mDNS discovery with an optional PSK. Plain
HTTP is accepted for explicit LAN/operator seeds, but automatically learned
internet peers and reverse hello require HTTPS.

### Same-LAN startup

Each computer must listen on a LAN-reachable address and advertise that
address. Installing NTH DAO on two computers is not enough by itself.

Windows desktop launcher:

```powershell
.\tools\start_nth_dao.ps1
```

macOS or Linux:

```bash
python -m nth_dao.web --lan
```

UDP discovery is built into the core. The optional LAN extra adds mDNS as a
second discovery path:

```bash
pip install -e ".[lan]"
```

Opening **Market / Discover** performs one bounded discovery pass and imports only peers
whose DID:key identity card, public key, signature, and advertised URL all
verify. The manual **Discover nearby DAOs** action repeats the scan and shows
diagnostics. Local firewalls must allow inbound TCP on the configured NTH DAO
port (8080 by default) and UDP discovery traffic (9877 by default) on the
private network. Set the same `NTH_LAN_DISCOVERY_PORT` on every node when a
different UDP port is required. mDNS also needs local multicast when the
optional extra is installed.

LAN mode exposes signed federation and read-only discovery surfaces to the
subnet. Console bearer tokens are injected only for loopback browser clients,
never into HTML served to another computer.

## Durable Peer Graph

Verified gossip peers are stored in
`<workspace>/federation/learned_peers.json`. They are:

- kept separate from operator seeds;
- deduplicated by DID;
- bounded to 128 records by default;
- expired after 24 hours without successful verification;
- limited to four identities per resolved IPv4 /24 or IPv6 /64;
- written atomically under an inter-process lock;
- treated as untrusted candidates after every restart.

Persistence never upgrades a learned peer into a trusted seed. Before a
learned peer can supply a feed in a later cycle, DNS is checked again, the HTTP
connection is pinned to that result, and its signed identity card is verified
again. Identity-cache entries are keyed by both URL and resolved IP.

## Feed Synchronization

For every accepted peer, the market poller performs:

1. `GET /api/v2/market/federation/digest?since=<cursor>`
2. Verify the digest source DID and signature.
3. Select announcement IDs and fetch them in bounded batches from
   `GET /api/v2/market/federation/pull?ids=...`. Every response batch must
   contain exactly the requested selectors; omissions, duplicates, and extras
   invalidate the complete source snapshot.
4. Verify every full announcement's publisher signature.
5. For an exchange hint, fetch its bounded head-proof bundle from the fixed
   digest route. Verify every signed Offer revision from genesis, every
   predecessor edge, the exact announced head, and the announcement lifetime.
6. Merge unexpired records into the local read-only federation cache.

After the first complete source snapshot, normal poller cycles continue from
the last verified sequence cursor and merge only newly signed records. Once
60 seconds have elapsed since a source's last complete snapshot, the next
successful poll for that source deliberately resets to `since=-1` and
reconciles a complete open-set snapshot. This full pass is required to observe
claims, withdrawals, feed restoration, and other absences that an append-only
cursor cannot express. A peer identity change also discards its cursor and
forces a full pass. Manual **Refresh** always performs a full reconciliation.

The console may inspect the exact remote Trade Offer head retained with an
exchange announcement. The complete disclosed revision chain is isolated from
the network response and verified again when read. It remains a volatile read
model until the operator selects **Save locally**, and it never becomes local
authority for the Offer.

Remote records are not copied into the local authoritative feed and therefore
are not re-announced as local work. Claims return to the announcement's source
DAO, which remains the single CAS authority for that listing.

### Federated Claim Lifecycle

After a claim is locally confirmed, a claimant can retain its own signed
Mission completion statement with an execution receipt using the operator-only
`POST /api/v2/market/claim-intents/{nonce}/completion/record` endpoint. The
node verifies the complete retained claim/authority-ACK/execution chain before
writing an immutable content-addressed bundle. The claimant can create that
signature locally with `nth-claim-completion record --workspace WORKSPACE
--identity-file AGENT_KEY --nonce NONCE --mission-id MISSION_ID`; the server
never signs on its behalf. A later signed v2 record may supersede the head by
digest and sequence, retaining the old outcome. Concurrent v1 roots or v2
branches fail closed until the claimant explicitly uses `record --resolve-fork`
to sign a v3 merge naming every verified head. The competing signed statements
remain in the portable proof; no branch is silently discarded. `GET` on
the same path without `/record` returns a re-verified summary. Operator-only
`GET .../completion/proof` exports the current bounded portable proof; the
operator may supply `?head_digest=sha256:<64 lowercase hex characters>` to
export the exact signed ancestry for a retained historical head. This does
not treat the selected head as the current outcome. A different node
can run `nth-claim-completion verify --proof-file PROOF --source-did DID
--federation-key KEY`, using pins independently obtained from its trusted
market listing. Copying both pins from the proof would not establish trust.
The source-signed `source_claim_id` (ACK ID), not the claimant-local nonce, is
the deduplication key for transferred proofs: the current source ACK does not
sign the Intent nonce. Rewrapping a valid claim under another local nonce must
not create another accepted source claim, reputation event, or payment.
REST and CLI completion summaries expose this stable ID and explicitly report
`nonce_authenticated: false`. Source-side nonce authentication requires a
future ACK wire version, not a local verifier shortcut.
This is explicit/manual transfer, not automatic federation delivery. Neither
route accepts work or authorizes settlement.

A source operator can submit that transferred proof to
`POST /api/v2/market/completion-proofs/verify-source` as
`{"proof": <portable-proof>}`. The route is console-principal-only (or
loopback-only in an explicitly unauthenticated development app). Authorization
is checked before parsing the bounded request body, and concurrent checks are
limited. It pins the source DID to this node's identity or a locally retained
dual-signed predecessor chain, looks up the exact locally retained signed
announcement, verifies the full proof, and compares the
source-signed ACK's claim-record hash to the locally retained CAS winner. A
self-signed announcement included in the transferred proof is not sufficient.
Historical proof lookup checks the announcement signature but does not require
its linked Offer to remain today's active chain head; ordinary discovery and
new claims still enforce that live listing policy. Missing source evidence
returns an unverified result; unreadable or corrupt local evidence returns 503
rather than accusing the claimant of presenting a mismatched proof.
The first historical lookup streams the append-only feed under the same lock
used for appends. A derived byte-offset index speeds subsequent requests, but
each hit rereads the original row, checks its content hash and federation key,
and verifies its signature. A corrupt unrelated row cannot hide a valid target;
an absent target in a corrupt feed is not reported as a clean miss.

Planned source-key rotation requires signatures from both the old and new
identity before the old key is retired. Local Python callers can use
`nth_dao.market.record_source_identity_rotation(workspace, old_identity,
new_identity)` to append that evidence; no private key is sent to the server
or included in the rotation record. This does not change the active node key,
team owner, or agent identity. A key lost before this dual-signature step
cannot be made a trusted predecessor by self-declaration or by the current
guardian module alone; a separate anchored recovery flow is still required.
Malformed complete rows are logged and ignored only when the required
dual-signed chain remains intact. A missing chain, valid fork, cycle, oversized
history, or truncated tail still fails closed.
The response identifies the source claim and the checked completion head, but
reports `recorded: false`, `accepted: false`, `settled: false`, and
`nonce_authenticated: false`. The source does not retain the proof, issue an
acceptance, know whether another signed head exists elsewhere, or move funds.
This is a verification preflight for a later bilateral delivery/inbox protocol.

For an explicit, operator-controlled import, submit the same bounded proof to
`POST /api/v2/market/completion-proofs/record-source`. This verifies the
historical announcement and the local CAS claim again, retains canonical
proof bytes under `federation/inbox/<source_claim_id>/<head_sha256_hex>.json`,
and appends one source-signed `market.claim.completion.received` Spine event.
Both the full source-signed ACK ID and the full completion head digest identify
the statement. An exact retry is idempotent, including after a lost response
or an interrupted audit append; an unaudited blob is never reported as
recorded. Operator-only
`GET /api/v2/market/completion-proofs/source/<source_claim_id>/<head_sha256_hex>`
rechecks the retained proof, source claim, and matching signed audit event.
The inbox has bounded per-claim storage and
does not silently replace a different statement with the same semantic key.
POST and GET responses recompute the lineage across locally retained signed
proofs for that claim. `lineage_state: unresolved_fork` means competing heads
exist at the signed-record level, even if historical nonce aliases also
exist; `has_duplicate_signed_head` reports those aliases independently.
`single_retained_head_digest` is then null. A single retained head is
only a local inventory observation, not a global or adjudicated outcome. The
inbox rejects a second proof wrapper around the same signed completion record
before persistence. Historical duplicate wrappers remain readable as
`duplicate_signed_head` with no single-head assertion; they are not treated
as independent claimant-signed results and are never silently discarded. An
already retained but unaudited historical alias can be resolved only by the
explicit digest-pinned reconcile operation, which signs its receipt and then
reports the duplicate state. New aliases are rejected before persistence.
`outcome` field describes the submitted head alone. Missing local source
evidence returns 503 (verification unavailable), while an invalid proof
returns 422. Windows inbox filenames use extended paths and a non-overwriting
write-through move. POSIX publishers fsync newly created directory ancestors
before the proof and the target directory after publication. Both paths still
verify the audit/file pair after recovery; a failed publication is not audited
as received.
Every read compares the local proof set with the verified source-signed Spine
receipt set. A missing audited proof makes the claim unavailable; it cannot
silently erase a previously observed fork. A valid proof blob left by an
interrupted audit is `pending_audit`, not recorded. Other recorded proofs remain
readable but have no single-head assertion while it is pending; new unrelated
proofs are held until it is reconciled. An operator can explicitly retry the
exact original proof, or POST to
`/api/v2/market/completion-proofs/source/<source_claim_id>/<head_sha256_hex>/reconcile`
with `expected_proof_digest=sha256:<canonical-proof-sha256>` and an empty body.
The latter verifies the retained proof again before signing the receipt event.
Source-proof GET is reverified against current files and signed audit rather
than served from a potentially stale cache. Per Web process, at most one such
GET and two total source-proof operations run concurrently; excess requests
receive HTTP 429. Multiple server processes do not share this admission budget.
The result still reports `nonce_authenticated: false`, `accepted: false`, and
`settled: false`. It is a source receipt of a claimant statement, not an
acknowledgement to the claimant, a work review, a reputation decision, or a
payment instruction. Automated bilateral transport and acknowledgement remain
future protocol work. The local audit payload has a versioned structural vector
at `nth_dao/market/vectors/source-completion-received-v1.json`. The fixed
signed event and rotation fixture at
`nth_dao/market/vectors/source-completion-receipt-crypto-v1.json` is verified
by both Python and Node tests. It covers signature interoperability, not audit
inclusion, source retention, or the full claimant-proof binding.
The source response also includes `source_receipt_event`, the exact signed
Spine event behind `audit_event_id`, and `source_rotation_chain`, an exact
dual-signed path from the announcement authority to the event signer (empty
when no rotation occurred). An operator may transfer that event with
the original portable proof and verify it offline using
`nth-claim-completion verify-receipt --proof-file PROOF --receipt-event-file
EVENT --source-did DID --federation-key KEY`. Supply both pins independently;
never take them from the transferred proof or event. The verifier requires
the event signer to equal the pinned source DID or be reachable through a
continuous, bounded, dual-signed rotation path. It also validates the complete
proof and binds every signed audit payload field to that proof. The rotation
chain is evidence, not a trust root. `receipt_verified` means that the pinned
source signed this statement and its signed payload binds the supplied proof;
it is not cryptographic
proof that the event ever entered Spine or that its disk still retains the
blob, nor evidence of acceptance or settlement. The CLI explicitly reports
`audit_inclusion_verified: false` and `source_retention_verified: false`.
The CLI accepts either the bare signed event or the complete
source REST response. In the latter case it checks the wrapper's audit ID and
every mirrored signed payload field against the signed event, but does not trust the wrapper's
unsigned status flags. A rotated signer requires the response's verified
`source_rotation_chain`; a bare event alone cannot establish that link.
On the claimant node, `nth-claim-completion verify-receipt-local --workspace
WORKSPACE --nonce NONCE --receipt-event-file RESPONSE` reconstructs the
locally retained completion proof for the receipt's exact signed head, including
its verified ancestors after later revisions or a merge. It takes the source DID and
federation key from the confirmed local claim. It accepts a transferred
source REST response or bare event without letting either supply trust pins.
The head field is only an untrusted selector until the complete proof and
source signature are checked. Only the selected head's signed ancestry is read;
unrelated slot corruption cannot block that historical check, and a successful
check does not certify the whole slot. Missing or corrupt ancestors fail closed. This
manual check does not append signed protocol evidence, but local readers can
create lock files and refresh derived archive indexes. Use a writable workspace;
for a read-only archive, use `verify-receipt` with a previously exported proof
and independently retained source pins. A successful check is not a durable
claimant-side import, source retention proof, work acceptance, or payment
authorization.
For durable, explicitly operator-controlled observation, submit the source
REST response (or bare signed event for an unrotated source) to
`POST /api/v2/market/claim-intents/<nonce>/completion/source-receipt` as
`{"source_response": <response>}` on the claimant node. The node takes source
pins only from its locally confirmed claim, reconstructs the selected signed
completion ancestry, verifies the source signature and optional dual-signed
rotation path, then retains the normalized event and rotation evidence under
`federation/claim_completion_receipts/<source_claim_id>/`. A content hash in
the immutable filename detects replacement; a local signed
`market.claim.completion.source_receipt.observed` Spine event binds that exact
file and completion head. The import endpoint rejects duplicate JSON object
fields at every nesting level before model validation. Retention precedes
local audit. If the audit append
fails, the blob is pending rather than observed. The exact same response can
be retried. If that response is no longer available, an operator can POST to
`.../completion/source-receipt/reconcile` with the full `head_digest` and
`expected_response_digest=sha256:<canonical-retained-blob-hash>` and no body.
The operator-only `GET .../completion/source-receipt/pending?head_digest=...`
reverifies the retained bytes and returns that exact digest after a restart;
`pending: true` explicitly means no signed local observation exists yet.
Reconciliation rechecks the retained bytes against the local confirmed claim,
source signature, and digest before signing the observation. It cannot repair
a missing or altered blob by trusting a filename or an unverified status flag.
An already audited response is idempotent; a different source
event for the same head conflicts. Operator-only `GET` on the same path with
`?head_digest=sha256:<64 lowercase hex characters>` rechecks the retained
event, local audit, and historical local proof, including after a later
completion revision. Historical local observation signers remain valid after
node key rotation only when the workspace retains an unambiguous dual-signed
old-to-current DID chain in `market_feed/source_identity_rotations.jsonl`;
an absent, invalid, or forked chain fails closed. Recording such a chain does
not itself rotate the workspace identity or team ownership. Missing audited
files and changed content fail closed.
The local observation proves that this node verified and retained a source
statement at import time. It still does not prove source Spine inclusion,
ongoing source retention, work acceptance, settlement, or authenticated nonce.
The event payload shape is frozen in
`nth_dao/market/vectors/claimant-source-receipt-observed-v1.json`, including
fixed canonical JSON, SHA-256, and a signed event. Python verifies the event,
while the frontend conformance test independently checks its bytes and Ed25519
signature with WebCrypto. This cross-runtime check does not establish source
audit inclusion or independent third-party protocol interoperability.
The v2 Tasks "My claims" view can explicitly check the current signed
completion head, import a source-provided signed response as JSON or a file,
and reconcile a verified pending local blob. The completion summary exposes
`completion_head_digest` separately from `evidence_digest`; older servers may
omit the former, in which case the existing completion summary remains visible
but the source receipt controls are unavailable. The UI never fetches a peer's
operator-only receipt automatically and never treats an observed statement as
acceptance or settlement. Browser-side parsing only checks the selected claim
and head for a helpful early error; the original JSON text is submitted so the
server's duplicate-field rejection and signature checks see the actual input.
A timed-out write has an unknown outcome: the UI rechecks local verified
retention before offering another explicit operator action.
Team owner key drift is fail-closed for membership writes; rotating the owner
key requires a separate explicit migration and is not performed by receipt
observation or web bootstrap.
The retained proof includes a signed scoped capability token and claimant
metadata. Keep the workspace private; do not publish or sync the inbox as a
public Git artifact merely because its statements are signed.

A federated claim carries three claimant-signed public artifacts: a scoped
capability token, a Claim Receipt, and a short-lived Claim Intent. The local
hub verifies and retains the complete Claim Receipt by canonical content hash
before journaling the Intent as `pending` and before transport. The source DAO verifies
the Intent and its exact claimant, announcement, token, and Receipt bindings
before running the authoritative claim CAS. A pending Intent reserves nothing.

The claimant changes the local state to `confirmed` only after verifying and
persisting the source authority's signed Claim ACK. Deterministic source
rejections become `rejected`; transport failures and malformed or missing ACKs
remain `pending`. If the source committed the claim but the first response was
lost, a later request by the same claimant returns a signed ACK for the original
durable claim. The claimant reconciles that ACK only when its signed Receipt ID
and canonical hash match exactly one locally retained Intent binding. The new
Intent is rejected rather than being misreported as accepted.

The claimant also persists the verified source URL, source DID, federation key,
and Receipt binding before transport. A user can therefore ask the original
authority for the ACK even after the task has disappeared from the local
discovery cache. The recovery request re-resolves and pins the peer address,
re-verifies its signed identity card, and accepts only an ACK signed by that
pinned DID. Unsigned negative status responses are informational only: they do
not reject or otherwise mutate a local Intent.

Legacy v1 announcement identifiers are readable for migration but cannot bind
the current strict Claim Intent wire format. They must be re-signed by the
publisher before federated claim. The protocol does not weaken current ID
syntax to preserve legacy writes.

Trade Offer announcements are deliberately non-claimable. They advertise an
exact signed proposal for exchange; they do not create an Agreement, reserve
inventory or assets, prove current availability, or authorize settlement.
Local publishers expose only the active canonical head of an unforked Offer
chain. A remote publisher can still make a stale or dishonest signed claim, so
consumers must apply trust policy and obtain a new bilateral Agreement before
execution. An exchange announcement can live for at most 24 hours and never
past its Offer expiry; an active Offer must publish a new signed hint after that
discovery lease expires.

Announcement IDs are transport identifiers, not free-form labels. They use
only ASCII letters, digits, `.`, `_`, `:`, and `-`; path/query delimiters are
rejected before signing and again during verification. Federation cache keys
are content hashes of the complete signed body, so equal local IDs from two
DAOs do not collide.

Every successful poll is an open-set snapshot. A claimed, expired, withdrawn,
or otherwise absent announcement is removed from the read cache. An incomplete
digest sequence, malformed full record, or failed source refresh contributes no
actionable records for that source; partial pages are never published as a
complete view.

## Discovery Endpoints

| Endpoint | Purpose | Authentication |
|---|---|---|
| `GET /api/v2/market/federation/digest` | Signed compact feed pages | Public read |
| `GET /api/v2/market/federation/pull` | Full signed announcements by ID | Public read |
| `GET /api/v2/market/federation/peers` | Verified public hints; private operator seeds are omitted | Public read |
| `POST /api/v2/market/federation/hello` | Reverse-discovery candidate | Public, rate-limited, card-verified |
| `GET /api/v2/market/federation/status` | Operator discovery status | Console read |
| `POST /api/v2/market/federation/peers` | Add or remove operator seeds | Console write |
| `POST /api/v2/market/federation/discover` | Import verified LAN/mDNS peers | Member/console write |
| `POST /api/v2/market/federation/refresh` | Run one synchronous pull | Console write |
| `POST /api/v2/market/federation/claim-foreign` | Verify claimant token, Receipt, and Intent; run source-authority CAS | Public crypto-authorized write, rate-limited |
| `POST /api/v2/market/federation/claim-status` | Recover a signed ACK for a matching durable source claim | Public crypto-authorized read-by-proof, rate-limited |
| `POST /api/v2/market/federated/claim` | Sign locally, journal pending, route to the pinned source, and verify its ACK | Console write |
| `GET /api/v2/market/claim-intents` | Bounded local pending/confirmed/rejected/expired projection and Receipt storage usage | Console read |
| `POST /api/v2/market/claim-intents/{nonce}/reconcile` | Re-verify the retained source and recover a lost signed ACK | Console write |
| `GET /api/v2/market/claim-intents/{nonce}/completion` | Re-verified latest claimant completion statement | Console read |
| `POST /api/v2/market/claim-intents/{nonce}/completion/record` | Retain a claimant-signed root or linked revision | Console write |
| `GET /api/v2/market/claim-intents/{nonce}/completion/proof` | Explicitly export the full signed lineage for pinned offline verification | Console read |
| `POST /api/v2/market/completion-proofs/verify-source` | Check a transferred proof against this source's signed announcement and CAS claim; no retention or acceptance | Console write; bounded and operator-only |
| `POST /api/v2/market/completion-proofs/record-source` | Retain a verified proof and sign a source receipt event | Console write; bounded and operator-only |
| `POST /api/v2/market/claim-intents/{nonce}/completion/source-receipt` | Verify and durably observe a transferred source receipt against the claimant's local confirmed claim | Console write; bounded and operator-only |
| `GET /api/v2/market/claim-intents/{nonce}/completion/source-receipt?head_digest=sha256:{hex}` | Reverify one historical local source receipt and its signed observation | Console read; bounded and operator-only |
| `GET /api/v2/market/claim-intents/{nonce}/completion/source-receipt/pending?head_digest=sha256:{hex}` | Reverify a retained source receipt and return its exact digest and pending status without appending audit | Console read; bounded and operator-only |
| `POST /api/v2/market/claim-intents/{nonce}/completion/source-receipt/reconcile?head_digest=sha256:{hex}&expected_response_digest=sha256:{hex}` | Reverify and audit one pending locally retained receipt without the original remote response | Console write; empty body, bounded and operator-only |
| `GET /api/v2/market/completion-proofs/source/{source_claim_id}/{head_hex}` | Reverify an exact retained proof and return its signed source receipt event | Console read; bounded and operator-only |
| `POST /api/v2/market/completion-proofs/source/{source_claim_id}/{head_hex}/reconcile` | Explicitly audit a verified pending blob by its full proof digest | Console write; bounded and operator-only |
| `POST /api/v2/trade/offers/{digest}/announce` | Publish a discovery hint for this node's active canonical Offer | Console write |
| `GET /api/v2/trade/federation/offers/{digest}` | Exact signed Offer while locally announced | Public read |
| `GET /api/v2/trade/federation/offers/{digest}/head-proof` | Bounded complete disclosed revision chain for a live publisher head claim | Public read |
| `GET /api/v2/trade/federation/offers/{offer_digest}/rule-packages/{package_digest}/recognition-proof` | Legacy bounded Recognition proof bundle (v1) | Public read; operator disclosure required |
| `GET /api/v2/trade/federation/offers/{offer_digest}/rule-packages/{package_digest}/recognition-proof-pages/{page_index}` | One signed page from a byte-stable Recognition observation (v2) | Public read; operator disclosure required |
| `GET /api/v2/trade/federation/cached-offers/{digest}` | Reverify and inspect a volatile remote Offer cached with a discovery announcement | Console read |
| `POST /api/v2/trade/federation/cached-offers/{digest}/import` | Reverify and durably retain the complete disclosed signed revision chain as a non-authoritative claim | Console write; Bearer always required |
| `POST /api/v2/trade/federation/orders/{order_digest}/execution-receipts/{execution_id}/reviews/{review_id}/dispute-statements/fetch` | Return one exact retained Statement under a short-lived bilateral signed Fetch Request | Public transport; DID-signed, rate-limited, replay-journaled |
| `POST /api/v2/trade/orders/{order_digest}/execution-receipts/{execution_id}/reviews/{review_id}/dispute-statements/fetch` | Sign a Fetch Request, pin and authenticate the peer, and return the independently verified Response without importing it | Console write; Bearer required when console auth is enabled |

The local Claim Intent tracker keeps pending records in its active journal.
Its `claim-receipts/` directory retains signed Receipt bytes under their
SHA-256 content addresses, including after the corresponding terminal Intent
is archived. Each write requires the verified signed announcement and matches
the source authority's complete claim timeline. `load_receipt_by_hash()`
rechecks the hash and signature; the caller must still bind the result to the
Intent and authority ACK. New journal entries mark evidence retention, so a
missing committed blob is an integrity error; legacy hash-only records remain
explicitly unavailable. No evidence is reconstructed from a hash or unsigned
source response. Retaining a signed statement does not establish that the task
was completed or that its contents are true. A forwarded Receipt must use the
same capability token sent to the authority. The claimant preflight applies
the authority's five-minute Receipt clock window; if an unexpired Intent is
paired with an older Receipt, the claimant must sign a fresh Receipt before
retrying. This preflight cannot eliminate network delay or clock drift at the
authority. The local store defaults to 256
KiB per Receipt, 64 MiB total, and 4,096 files; all files, including crash
orphans, count toward the limits. A full Receipt store fails closed before
forwarding with HTTP 507; other tracker capacity failures use a distinct 507
detail. The console projection exposes `receipt_storage` file and byte usage
with the configured limits. Operators can explicitly run
`IntentTracker.verify_receipt_storage()` to check all committed active and
archived Receipt blobs, after archive integrity verification. This does not
audit unreferenced crash orphans, which are counted in capacity only. No
evidence is deleted automatically; operators must review and export retained
evidence before any deliberate retention-policy cleanup.
When terminal history reaches the configured capacity, it archives the oldest
terminal events in immutable, SHA-256-named segments before atomically
compacting the active journal. A rebuildable SQLite index keeps archived
nonce and Receipt replay checks on disk instead of loading all historical
bindings into memory. The index is committed before active-journal rows are
removed, so a crash can be recovered from the archive segments. On startup,
unchanged segments are checked by name and file metadata; operators can call
`IntentTracker.verify_archive_integrity()` to rehash every segment and
compare all bindings to the index. Archived nonces and Receipt bindings remain
reserved against replay. `GET /api/v2/market/claim-intents` and its `stats`
field describe the active window, not all historical claims; the archive is
retained locally for audit and is not exposed by this endpoint.

## Security Boundaries

- Automatically discovered URLs must use public HTTPS.
- DNS results are rejected if any selected target is private, loopback,
  link-local, multicast, reserved, or unspecified.
- Network connections for learned peers are pinned to the validated IP to
  reduce DNS-rebinding risk.
- Redirects are rejected while fetching identity cards.
- Identity cards, HTTP bodies, peer lists, graph breadth, cycle duration,
  learned-peer storage, and hello rates are bounded.
- Feed collection accepts at most 2,000 records per peer. The read cache
  accepts at most 10,000 records globally, 2,000 per source, and 64 MiB of
  canonical projected data. Exceeding a bound rejects the complete cycle;
  records are never silently truncated into a false open-set snapshot.
- Reverse hello is limited both per source address (12/minute) and per node
  (120/minute), with a locked cross-worker budget when a workspace is present.
- Exact Trade Offer and head-proof reads use a process-local source gate
  (120/minute) before a
  locked cross-worker global gate (300/minute). This ordering prevents rejected
  source floods from turning the persistent limiter into a disk-write amplifier.
- A malformed or unverifiable digest, identity card, or announcement fails
  closed.
- Durable remote-Offer import reuses the inspection verifier, serializes by
  exact Offer digest across processes, records `federation-cache` provenance,
  and writes a signed `trade.offer.import.proposed` intent containing the full
  verified head proof and evidence before mutating the Offer Store. An exact
  `trade.offer.imported` completion anchor is required for every disclosed
  revision before reporting success.
  These signed events contain the original signed discovery
  announcement, its recomputed federation key, source DID, source peer, and
  observation metadata, so later audit does not depend on the volatile cache.
  Read-time verification reparses the proposal Offer, verifies its signature
  and digest, and requires byte-for-byte equality with the Offer Store record.
  Digest syntax is rejected before any import lock path is constructed.
  A retry or restarted node repairs an interrupted import without the volatile
  federation cache, including when the completing node identity has rotated.
- Before a remote claim, the source identity card is fetched afresh and the
  claim POST is pinned to the same validated IP.
- Before a Dispute Statement Fetch Request is posted, the responder identity
  card is challenged on the same DNS-pinned address and must match the exact
  `responder_did`. The exact signed Request is persisted in a bounded requester
  outbox before transport and reused across concurrent and restarted retries;
  only signed expiry permits a new retained generation. The verified Response
  and standalone signed audit are committed before success and can be replayed
  offline after restart. The responder applies per-source and global limits,
  then verifies the bounded signed envelope before any Order/Receipt/Review
  lookup. Missing and unauthorized context return the same unavailable result.
  It journals nonce replay across processes and appends a signed disclosure
  audit. A successful requester response remains a verified retained transport
  observation until a separately authorized import exists.
  The returned signed audit event proves the responder authored that audit
  claim; without the full remote Spine it does not prove chain inclusion or
  durable remote retention.

Application checks are not a substitute for deployment controls. Public nodes
should still run behind an egress firewall or proxy that blocks private and
cloud-metadata destinations.

## Current Limits

- At least one bootstrap seed is required; there is no mandatory central
  directory and no DHT yet. Same-LAN mDNS can supply that first peer when both
  nodes use LAN mode; cross-network federation still needs a reachable seed.
- Nodes behind NAT need a tunnel, reverse proxy, or another externally
  reachable transport before internet peers can dial them.
- Self-signed DID:key identity prevents impersonation but not Sybil identities.
  Reputation, endorsements, governance policy, and transaction mandates must
  decide what a verified peer is allowed to do.
- The federation cache is a read model. Durable authoritative ownership stays
  with the source DAO.
- Remote Trade Offer documents remain volatile until an operator explicitly
  selects **Save locally**. That action retains the complete disclosed signed
  chain and its import provenance in local append-only storage; it does not make
  the remote publisher local, prove global latest revision, grant trust, or make
  the Offer actionable. Agreement creation remains a separate protocol step.
- A recent source verification means the signed snapshot was verified within
  the local two-minute cache TTL. It does not prove that the source is currently
  online or that the advertised resource is still available.
- A head proof establishes a complete signed chain from revision 1 to the head
  named by one short-lived publisher announcement. It cannot prove that the
  publisher has not withheld a later revision or that another peer has already
  observed one. Durable signed Offer tombstones and globally convergent
  latest-revision proofs remain future protocol work.
- Market discovery does not broadcast Agreements, Mandates, Receipts, payment,
  delivery, dispute outcomes, or settlement state. Separate bilateral signed
  routes can deliver selected execution records and fetch one exact Dispute
  Statement, but they are not searchable market feeds or global propagation.
- Withdrawal currently uses signed open-set absence, not durable tombstones.
  Nodes that need historical proof of withdrawal must retain their own audit
  events until a tombstone/revocation wire type is standardized.
Nearby discovery and operator-approved federation seeds have different trust
semantics. Background and initial UI scans only retain bounded in-memory
discovery results. A verified identity card proves key control, not trust; the
operator must explicitly approve a nearby URL before it is persisted as a seed
and polled. Approved seed persistence is bounded to 128 URLs.
