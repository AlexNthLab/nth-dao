# Contributing

Contributions should move NTH DAO toward an AI-native Web3 DAO protocol layer
for humans and agents. See [VISION.md](VISION.md) for the product direction and
review priorities.

## Review Priorities

Prefer small, well-tested changes that strengthen:

- Agent and human identity
- DAO membership and admission
- groups, channels, and topics
- roles and permissions
- messages and announcements
- tasks, missions, and handoff
- discovery and append-only audit logs
- simple trust and reputation hints
- local-first, Git-syncable data formats

Large features such as P2P gossip, marketplaces, settlement, wallet flows,
token-gating, or global reputation are welcome as proposals, but should not
bypass the foundational identity, membership, permission, and audit layers.

## Required Quality Bar

Before a change is merged, it should:

- keep existing public APIs backward compatible unless a migration is explicit
- preserve attach, discovery, membership, and orchestration behavior
- include focused tests for new behavior and permission boundaries
- use local-first, file-backed, mergeable data when possible
- avoid introducing a required central service
- avoid adding required third-party dependencies to the core package

Optional dependencies should be exposed through extras such as `crypto`, `web`,
or future transport-specific extras.

## Naming Direction

The project name and import path are NTH DAO and `nth_dao`.

New examples, docs, and integrations must use:

```python
import nth_dao as nth
```

## Pull Request Checklist

- Does this change support the NTH DAO vision in `VISION.md`?
- Does it preserve membership approval and role/permission checks?
- Is every new persisted format documented by clear field names?
- Can files be synced or merged across decentralized nodes?
- Are failure modes explicit rather than silently ignored?
- Are tests included for the core behavior?

## Hard Rules (learned from the v0.9.1 review)

These rules came out of an independent code review that found six critical
and thirteen high-severity issues in v0.9.0. Don't recreate them.

### Language choice — IRON RULE

This rule is a long-term-maintenance decision and cannot be overridden by a
single PR. Every contribution must respect it.

**TypeScript / JavaScript MUST be used for:**

- User-facing UI (web dashboards, control panels, settings screens)
- Browser extensions and browser-side widgets
- Any management console served to end users
- Visualization widgets (kanban boards, trust graphs, mission timelines)
- Anything that runs inside a browser tab

**Python MUST be used for:**

- The core nth_dao protocol layer (everything in `nth_dao/`)
- All wire-protocol implementations (gossip, LAN discovery, identity, …)
- All agent backends and adapters (`team_layer/backends/`)
- Server-side HTTP / WebSocket endpoints (FastAPI under `nth_dao/web/`)
- CLI tools (CLI commands stay short — they shell out to Python modules)
- Tests for any of the above
- All examples / demos
- All data-handling scripts (ledger reducers, archive jobs, etc.)

**Why this rule:**

- The protocol layer is local-first and stdlib-only. Adding a TypeScript
  runtime dependency (Node / Bun) to the core would break that promise.
- UI velocity, ecosystem (React, Tailwind, …), and browser deployment are
  TypeScript's home turf. Python web frontends age badly.
- Two languages with crisp boundaries (HTTP/JSON between them) keep the
  blast radius small and the contributor pool wide.
- Long-term maintenance: the protocol layer changes slowly (years); UI
  changes weekly. Different cadences want different toolchains.

If a feature naturally straddles the line — e.g., an interactive CLI that
also exposes a web UI — split it: Python implements the data + transport,
TypeScript implements the visual surface, they talk JSON over HTTP. Never
embed React-in-Python or write the protocol in TS to share types.

### File I/O

- **All JSON writes go through `nth_dao.util.atomic_write_json()`.** Never
  use a bare `path.write_text(json.dumps(...))` — partial writes break
  cross-process readers.
- **All JSON reads go through `nth_dao.util.safe_load_json()`.** Bare
  `json.loads(path.read_text())` corrupts the caller on a malformed file;
  the util logs a warning and returns the fallback.
- **All filename construction goes through `nth_dao.util.safe_id()`.** Six
  modules used to roll their own version with subtly different allowed
  chars — that's a path-traversal foot-gun.
- **Cross-process writes that need read-modify-write semantics MUST hold
  `nth_dao.util.InterProcessLock`.** A `threading.RLock` is not enough;
  see `mission_store.try_claim()` for the canonical pattern.

### Wire protocols

- **Any new wire protocol carrying agent identity MUST be signed.** Use
  `AgentIdentity.sign_json()` over a canonical payload; verify with the
  *author's* trusted pubkey, never the relay/sender's connection pubkey.
- **Signature verification failure MUST drop the message.** Never `pass`
  on a failed verify — the gossip module's pre-fix `pass` let any peer
  forge any agent_id. Log at WARNING and `return`.
- **Token / secret comparisons use `hmac.compare_digest`.** Plain `==`
  leaks the length through timing side-channels.
- **Time-based payloads carry a `timestamp` and reject outside a replay
  window.** See `gossip.REPLAY_WINDOW_SECONDS = 600`.

### Concurrency

- **Mission steps are claimed via compare-and-swap.** Direct `update_step`
  without `expect_status` / `expect_assignee_in` is a race waiting to
  happen; use `MissionStore.try_claim()` or pass the CAS args.
- **Any background daemon thread MUST be daemon=True and handle stop**
  via a `threading.Event`. Don't busy-loop, don't `time.sleep` in a way
  that ignores shutdown.

### Errors

- **`except Exception: pass` is forbidden in non-test code.** Log at
  `logger.warning` or `logger.debug`; if recovery isn't possible, re-raise.

### Tests

- **Every fix to a previously-shipped bug gets a regression test.** See
  `tests/test_p0_fixes.py` for the pattern. Tests in this repo run on
  Python 3.10+ on POSIX and Windows; if your fix depends on platform
  behavior, the test must cover both or be `pytest.skipif`-guarded.
- **Cross-process behavior gets a `multiprocessing.spawn` test** (see
  `tests/test_concurrent_claim.py`). In-process `threading.Thread` is
  *not* the same thing.

### Optional dependencies

- **Core install must work with stdlib only.** Anything else goes in an
  extra: `[crypto]` (pynacl), `[lan]` (zeroconf), `[ux]` (qrcode), `[web]`
  (fastapi+uvicorn). Each module that uses an optional dep guards the
  import and raises a helpful `ImportError` pointing at the extra.
