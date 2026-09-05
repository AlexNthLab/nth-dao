# Delivery Layer (Phase 0) — Implementation Notes

Status: implemented against the integration design doc (2026-07-26 审阅稿)
Scope: `nth_dao/delivery/` — transport-agnostic signed envelope delivery

## What This Is

The common protocol spine described in the integration design doc §5 and §9:
every domain event travels as a signed `TransportEnvelope` through pluggable
transports, is queued in a durable outbox, is validated by a fail-closed
inbox, and is routed by policy rather than a fixed fallback order.

```
Domain (channel / task / mission / market / mandate)
        │  business event → payload
        ▼
TransportEnvelope v1  (canonical JSON, Ed25519, content-addressed)
        │
   ┌────┴────────────────────────────────────────────┐
   │ DurableOutbox          DeliveryInbox            │
   │ JSONL journal,         size→sig→TTL→nonce→      │
   │ crash-safe, ACK-       dedup→authorize,         │
   │ terminal               persistent replay cache  │
   └────┬────────────────────────────────────────────┘
        ▼
DeliveryRouter  (policy-scored; no fixed fallback order)
        │
   ┌────┼──────────────────┬───────────────────────┐
   │ loopback-hub       │ loopback-mesh          │ file-bundle      │
   │ (central relay)    │ (federated broadcast)  │ (offline carry)  │
   └────────────────────┴────────────────────────┴──────────────────┘
```

## Module Map

| Module | Responsibility |
|---|---|
| `delivery/envelope.py` | `TransportEnvelope v1` — canonical JSON, content-addressed `message_id`, author signature, TTL, nonce, hop routing |
| `delivery/acknowledgement.py` | signed `DeliveryAck` bound to `message_id` + received wire digest |
| `delivery/outbox.py` | `DurableOutbox` — JSONL journal, fsync-per-event, crash recovery, ACK-terminal, bounded |
| `delivery/inbox.py` | `DeliveryInbox` — ordered fail-closed pipeline + persistent replay cache |
| `delivery/policy.py` | `RoutePolicy` — pure validated routing policy (centralized / decentralized / offline presets) |
| `delivery/router.py` | `DeliveryRouter` — deterministic scoring, fallback, health cooldowns |
| `delivery/transports/base.py` | `Transport` ABC + capabilities + health |
| `delivery/transports/loopback.py` | hub (central relay) / mesh (federated broadcast) in-process endpoints |
| `delivery/transports/file_bundle.py` | signed file-bundle exchange (USB / shared dir / manual carry) |

## Wire Contract (v1)

* Envelope serializes to `nth_dao.canonical_json` bytes; transports carry it
  opaquely and must not re-encode it.
* `message_id = sha256(canonical(content_body))` where `content_body` is the
  author-signed projection minus `signature`, minus `message_id` itself, and
  minus the mutable `routing.hop_count`. Identical content always yields the
  identical id; relays forwarding with `hop_count + 1` preserve it.
* The signature covers `signing_body` = everything author-owned **including**
  the `message_id` (the content address is signed) and excluding
  `routing.hop_count`.
* Relays may only change `routing.hop_count`, bounded by the signed
  `routing.hop_limit`; `forward_envelope` fails closed at the budget.
* ACKs are signed by the receiver and bind `message_id` + the exact wire
  digest received. Senders match ACKs by `message_id`; a forwarded copy
  legitimately acknowledges the same message identity.

### Limits (fail closed, all pinned by vectors/tests)

`MAX_PAYLOAD_BYTES=256 KiB`, `MAX_ENVELOPE_BYTES=512 KiB` (matches the
plugin transport wire limit), `MAX_PAYLOAD_DEPTH=16`, `MAX_TTL_MS=7 days`,
`MAX_CLOCK_SKEW_MS=5 min`, `MAX_HOP_LIMIT=16`, nonce 16–128 alnum,
`MAX_SAFE_INTEGER=2^53−1`.

## Design Decisions and Deviations

1. **Synchronous Transport interface.** The design doc §5.2 sketches an
   `async def` interface. The existing core (gossip, mission CAS, commerce
   outbox, plugin transport contract) is synchronous; introducing a second
   async boundary would create the exact "parallel system" §3 forbids.
   Async adapters can wrap the sync contract without protocol changes.
2. **Content address excludes `message_id` itself.** First draft derived
   `message_id` from a body that contained it — a non-converging self
   reference caught by tests. The address is derived from
   `content_body()`; the author then signs the address.
3. **One ACK rule, two binding fields.** The ACK binds what the receiver
   verified (wire digest) and what the sender matches (message_id). Digest
   equality against the sender's origin copy is deliberately NOT required:
   forwarded mesh copies differ in `hop_count` bytes.
4. **Router scores; policy decides.** No hardcoded "BLE → WS → Nostr"
   ladder (§8.2). Scoring: realtime preference (+4), privacy level (+1 per
   level), no external infrastructure (+2), healthy streak (+1); ties keep
   registration order. Failing transports cool down after 3 consecutive
   failures for 30 s (constants on `DeliveryRouter`).
5. **Journal-first persistence.** Outbox and inbox mutate memory only
   after the journal line is fsynced. A torn final line (crash mid-append)
   is ignored on reload; corruption anywhere else raises. Both journals are
   bounded with explicit compaction (`compact` / `compact_rejections`).
6. **Live cross-process dedup.** Inbox/outbox re-fold their journal when an
   mtime/size change from another process is observed, so dedup works
   across processes without a broker.
7. **bitchat borrowings, per design doc §四.** Controlled-flood prerequisites
   (hop TTL, content-addressed dedup, jitter budget left to transports),
   courier-style store-and-carry (file bundle is the v1 courier), and
   router-tiering are absorbed into the envelope + router contracts; no
   bitchat code is copied (Swift, public domain — patterns only).

## Threat Coverage Mapping (design doc §10 → mechanism)

| Threat | Mechanism |
|---|---|
| forged author / pubkey swap | Ed25519 verify against `sender_did` did:key |
| nonce replay, expiry | inbox pipeline steps 3–4, persistent cache |
| relay mutation of signed fields | signature covers author fields; only `hop_count` mutable |
| duplicate delivery across transports | `message_id` dedup in inbox; first signed ACK cancels outbox copies |
| ACK forgery | ACK signed by `receiver_did`; outbox verifies before terminal transition |
| oversized / deep flooding | byte + depth caps in envelope and inbox |
| crash between write and ack | journal-first + fsync; torn-tail recovery |
| clock skew attack | future-dated creation beyond 5 min rejected |
| local journal tampering | outbox content binding (`message_id` ⇄ wire digest) fails closed |

## Conformance

`delivery_envelope_v1` category in `nth_dao/conformance/vectors.json`
(6 vectors: canonical bytes, content address, wire digest, and the four
negative gates with pinned reason strings). A non-Python port is
wire-compatible when `run_all_vectors()` reports zero failures.

## Adversarial Review Record

Round 1 (pre-review) fixed: journal-first ordering for the replay cache,
journal size caps, expired-envelope enqueue rejection, and an in-function
import.

Round 2 (full-dimension hostile review) found and fixed 8 defects before
merge; each has a pinned regression test:

| # | Defect | Fix |
|---|---|---|
| A | `validate_envelope` raised (contract violation) on out-of-range integer timestamps instead of returning `(False, reason)` | gates converted to tuple returns; `now_ms` hardened against bool/oversize |
| B | `record_attempt` accepted attempts on already-DELIVERED records | `_require_live` rejects delivered records |
| C | `compact()` did not re-fold first — records another process enqueued were silently DROPPED | stat-based `_refold_if_changed` on outbox; compact/enqueue/get/pending re-fold before acting |
| D | inbox rejection journal grew without bound under a malformed-input flood | byte-budget auto-trim (75% of 4 MiB cap, newest kept) |
| E | file-bundle `poll` read a bundle into memory before its size check | stat-before-read |
| F | deterministic bundle temp filename — two same-content senders could collide mid-write | unique tmp name (pid + random), cleanup on failure |
| G | `version: true` (JSON bool == 1) passed the bundle version check | strict non-bool int check |
| H | inbox `_remember` mutated memory (eviction pop) BEFORE the durable write — a disk failure left memory diverged from the journal fold | peek-then-mutate: memory changes only after fsync |

Round 4 (reviewing the review fixes themselves) found and fixed 4 defects
in the round-2/3 fixes; each has a pinned regression test:

| # | Defect | Fix |
|---|---|---|
| Q | outbox `_append`, inbox `_remember`, and file-bundle `_append_imported` sampled their journal fingerprint AFTER releasing the cross-process lock — an append by another process inside that window was absorbed into "our" fingerprint and hidden from the re-fold check forever | fingerprint captured via `os.fstat` while STILL holding the lock (all three sites, plus `compact`) |
| R | inbox rejection-journal trim and `compact_rejections` used a deterministic temp name, and the flood-trim ran without the cross-process lock — concurrent trims could corrupt the temp file or drop lines | both paths locked, unique tmp names, failure cleanup |
| S | file-bundle `poll` had a stat-then-read gap: a courier swapping in a larger file between the two calls still got the big file read | post-read size re-check restored alongside the pre-read stat |
| T | `validate_ack` computed `canonical_json(ack.to_dict())` twice | computed once |

Round 3 (second full-dimension hostile review) found and fixed 5 further
defects plus one test-coverage gap; each has a pinned regression test:

| # | Defect | Fix |
|---|---|---|
| I | `compact()` re-folded OUTSIDE the cross-process lock — a TOCTOU window let another process's just-appended record be silently dropped by the `os.replace` | refold moved inside the lock; append-after-refold is now impossible |
| P | inbox `_remember` never updated `_journal_stat` after its own write, so every accept() re-folded the whole journal — O(n) per accept, O(n²) cumulative at cache scale | own-write stat refresh; re-folds now only happen for OTHER processes' appends |
| J | `routing.reply_to: null` (explicit JSON null) validated OK for foreign senders — two encodings of one semantic value | explicit null refused; absent-or-non-empty-string only |
| K | file-bundle import journal appended without the cross-process lock, and the imported set never re-folded — shared state dirs double-delivered | InterProcessLock + stat-based re-fold, mirroring inbox/outbox |
| L | inbox `seen()`/`entry_count()` returned stale answers in multi-process use | both re-fold on stat change |
| — | no test exercised the whole pipeline end to end | `tests/test_delivery_integration.py`: mesh, hub, and file-bundle pipelines with ACK-terminal delivery and the hostile paths |

Round 2 had fixed 8 defects (A–H, table above); round 1 fixed journal-first
ordering, journal size caps, expired-enqueue rejection, and an in-function
import.

## Not In Scope (per design doc Phase gating)

WebSocket gossip / HTTPS federation adapters (Phase 1), Nostr (Phase 2),
BLE spike (Phase 3), sealed Courier with X25519 (Phase 4), cross-node
claim semantics (Phase 5).
