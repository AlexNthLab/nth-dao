# NTH DAO

> AI-native Web3 DAO layer for humans and agents.

NTH DAO turns every shared mission into a living decentralized organization.
Humans and AI agents can join around a common vision, contribute ideas and
capabilities, coordinate through local-first groups, and build auditable trust
over time.

The Python import path is `nth_dao`. The former public package name has been
removed so new forks and installs converge on one identity.

See [MANIFESTO.md](MANIFESTO.md), [VISION.md](VISION.md),
[IMPLEMENTATION_GUIDE.md](IMPLEMENTATION_GUIDE.md), and
[CONTRIBUTING.md](CONTRIBUTING.md) for the DAO mission, roadmap, technical
direction, and merge criteria.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Zero deps](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](pyproject.toml)
[![Tests](https://img.shields.io/badge/tests-1067%20passing-brightgreen.svg)](tests/)

## What's New in 0.10.0b1 - Beta release

This beta previews the v0.10 protocol surface for testers and early
integrators:

- Signed `IntentMandate`, `CartMandate`, and `PaymentMandate`
  primitives, with Data Integrity style proof helpers.
- Mandate conformance vectors and EventBus mandate lifecycle events.
- A2A JSON-RPC server and Agent Card helpers for task lookup and
  capability discovery.
- Hardened action routing with pubkey lookup, explicit dev mode,
  TTL/nonce replay protection, signed requests, and signed responses.
- EventBus correction events, event subscriptions, and audited fault
  isolation.
- Mandate sidebar in the TypeScript frontend, plus browser Ed25519
  wallet support and Vitest coverage.
- Packaging fixes so `nth_dao.mandate` and the required `team_layer`
  runtime packages are included in distributions.

Validation for this beta: Python suite `1067 passed, 11 skipped`;
frontend Vitest `2 passed`; production frontend build passed.

## What's New in 0.9.6 - Unique group names, governance votes, chat-native collaboration UI

Three Python additions for the protocol layer, plus four TS panels for the
consumer chat app-inspired collaboration experience for agents and humans.

**Protocol additions (Python):**

- **`GroupRegistry` with workspace-unique slugs** - names normalize
  (`Frontend Team!` -> `frontend-team`); two groups can't share a slug
  within a workspace. Records are signed by the founder.
- **Policy-vote governance** - `PolicyChangeProposal` signed by a
  member; other members append signed yes/no/abstain votes; passes when
  > 50% of distinct member pubkeys vote yes. `apply_proposal` rebuilds
  the GroupRecord re-signed by an admin.
- **14 new web API endpoints** in `nth_dao/web/`: agent fuzzy search,
  LAN discovery proxy, add-by-DID, group CRUD + search, governance
  propose/vote. All write endpoints use "server prepares unsigned ->
  client signs locally -> client posts back" so private keys never
  cross the wire.

**UI additions (TS, per the iron rule):**

`frontend/src/panels/` - drop into your React app:

- `ContactsPanel` - search agents by name / capability; add by exact
  agent_id or did:key.
- `NearbyPanel`   - UDP LAN "people nearby", with optional pre-shared key.
- `GroupsPanel`   - list / search / create unique groups; color-coded
  policy badges.
- `GovernancePanel` - propose policy changes; vote yes/no/abstain.
- `ContactShell`  - top tab bar that hosts all four.
- `chat-panels.css`  - standalone styles, leaves existing styles untouched.

```tsx
import { ContactShell } from "./panels";

function App() {
  const { actorId, actorPubkeyHex, sign } = useWallet();
  return (
    <ContactShell
      actorId={actorId}
      actorPubkeyHex={actorPubkeyHex}
      sign={sign}
    />
  );
}
```

The host app supplies a `sign(payload)` helper from whatever wallet
infrastructure it has. Browse-only mode renders without signing.

## What's New in 0.9.5 - DID:key, AgentLedger, Guardian recovery, A2A boundary

Five additive deliverables, zero breaking changes:

- **W3C did:key alignment** - `AgentIdentity.as_did()` emits real
  `did:key:z...` strings (base58btc + multicodec 0xed 0x01). Pure stdlib
  encode/decode. `MissionTemplate.publisher_did` is now a usable DID.
- **`AgentLedger`** - per-pubkey-fingerprint append-only event ledger
  under `sidechain/agents/<fp>/`. Records step claim/complete/failed,
  handoffs given/received, reviews given/received, endorsements.
  Deterministic reducer folds events into `{missions_owned,
  steps_completed, success_rate, handoffs_*, templates_used, categories,
  total_token_cost}`. Step one toward the Achievements / signed
  contribution credentials layer.
- **Guardian-based social recovery** - N-of-M peers can collectively
  sign a `KeyReplacementProof` that re-binds an `agent_id` to a fresh
  pubkey. Owner publishes a signed `GuardianSet(pubkeys, threshold)`;
  losing the key no longer means losing the identity, provided you have
  trusted friends.
- **A2A boundary translation** - `nth_dao/a2a/translate.py` converts
  `MissionTemplate ↔ A2A Skill`, `Mission ↔ A2A Task`, assembles an
  AgentCard for `/.well-known/agent.json`. Pure data transformations
  only; the HTTP/JSON-RPC server lives in the separate
  `nth-dao-a2a-adapter` package (v0.10.0+).
- **Conformance vectors expanded** - 22 -> 31 vectors / 6 -> 11 categories.
  Channel messages, Invitations, TeamConfig, did:key, LAN psk_tag now
  have canonical-bytes coverage.

```python
# DID
print(alice.as_did())              # -> "did:key:z6Mk..."
restored = nth.AgentIdentity.from_did("did:key:z6Mk...")  # verify-only

# AgentLedger
al = nth.AgentLedger(workspace, identity=alice)
al.record_step_complete("m1", "s1", template_id="code-review",
                        category="code_review", token_cost=4000)
print(al.compute_stats())          # {"success_rate": 1.0, ...}

# Guardian recovery
gs = nth.publish_guardian_set(alice, [g1.pubkey, g2.pubkey, g3.pubkey], threshold=2)
proof = nth.begin_key_replacement(gs, new_alice.pubkey_hex, reason="laptop lost")
proof.signatures.append(nth.sign_replacement(g1, proof))
proof.signatures.append(nth.sign_replacement(g2, proof))
valid, reason = nth.verify_replacement(proof, gs)   # -> (True, "ok")

# A2A boundary
from nth_dao.a2a import agent_card_from, a2a_task_from_mission
card = agent_card_from(agent_did=alice.as_did(), name="Alice",
                       templates=[t], endpoint_url="https://alice.example/a2a")
task = a2a_task_from_mission(mission)  # ready to ship over JSON-RPC
```

## What's New in 0.9.4 - Sustainability sprint

No new protocol surface. We filled the six holes that prevented NTH DAO
from outliving its single maintainer:

- **`SECURITY.md` + key recovery** - `nth_dao.export_recovery_kit(identity,
  password)` and `import_recovery_kit(kit, password)`. libsodium
  `crypto_secretbox` + Argon2id. Lose your identity, restore from a
  passphrase-encrypted blob.
- **`docs/MIGRATIONS.md` + migration test runner** - forward-compat policy
  for 0.9.x, per-version delta, automated 0.9.0-fixture regression tests.
- **`nth-status` + `nth-metrics` CLI** - text/JSON workspace snapshot;
  Prometheus exposition-format `/metrics` HTTP endpoint. Pure stdlib.
- **`requirements/*.lock.txt`** - pinned transitive deps per extra
  (`crypto`, `ux`, `web`, `dev`). Reproducible builds.
- **`nth_dao/conformance/`** - 22 wire-protocol test vectors in 6 categories.
  A non-Python port is "wire-compatible" when it produces zero failures.
  See `docs/CONFORMANCE.md`.
- **`docs/research/A2A_ALIGNMENT.md`** - side-by-side vs Google's
  Agent2Agent protocol (Linux Foundation, 150+ orgs). Our protocol stays
  distinct; an A2A adapter is targeted for v0.10.0+.

```bash
# Status snapshot
nth-status --workspace ./my-team

# Prometheus metrics endpoint
nth-metrics --port 9090 --workspace ./my-team

# Backup an identity into a portable encrypted blob
python -c "import nth_dao as nth; \
    from nth_dao.identity import AgentIdentity; \
    ident = AgentIdentity.load('~/.nth/identity.json'); \
    print(nth.export_recovery_kit(ident, 'correct horse battery staple').to_json())" \
    > ~/secrets/alice.recovery.json
```

## What's New in 0.9.3 - Mission Template registry

This release lifts `MissionStore` from a one-shot quest board into a
reusable, signed, rateable template registry - the "decentralized App
Store" layer in the project vision.

```python
# Alice publishes a signed reusable template
template = nth.mint_template(
    alice_identity,
    template_id="code-review", version="1.0.0",
    name="Code Review",
    category="code_review", tags=["python", "security"],
    required_capabilities=["code_review"],
    inputs={"diff_url": nth.IOField(type="string", required=True,
                                     description="PR diff URL")},
    steps=[nth.StepSkeleton(id="review", description="...",
                             inputs_from={"diff_url": "input:diff_url"})],
    suggested_reward=5.0,
)
store.publish_template(template)

# Bob browses and instantiates the latest version
results = store.browse_templates(sort_by="rating")
mission = store.instantiate("code-review",
                            owner="bob",
                            inputs={"diff_url": "https://..."})

# Carol reviews Bob's completed mission; stats roll up automatically
store.review_mission(mission.id, reviewer=carol_identity, score=4.5,
                     feedback="caught 3 edge cases")

# Personal contribution view, walks archived missions too
for m in store.my_history("bob"):
    print(m.template_id, m.status)
```

Highlights:

- **`MissionTemplate`** - semver-versioned, publisher-signed, F-Droid-style
  one-file-per-version layout. Tampering invalidates signature; deprecation
  is publisher-only.
- **`MissionReview`** - signed, append-only `reviews/*.jsonl` ledger per
  template version. EWMA aggregation surfaces recent reviews while keeping
  historical record.
- **`template_lock`** - Nix-flake-lock-style snapshot of `publisher_sig` at
  instantiation time. A running mission stays reproducible even if the
  publisher republishes or deprecates.
- **`browse_templates`** - F-Droid-style discovery: filter by `category`,
  `tags`, `min_average_rating`; sort by `rating` / `recent` / `popularity`.
- **`archive_completed(older_than_days=30)`** - atomic move of terminal
  missions to `archive/YYYY-MM/`, keeps the active query path fast.
- **`my_history(agent_id)`** - walks active + archive; first step toward
  the AgentLedger / Achievement layer (v0.9.4+).
- **5 reserved fields** (`owner_did`, `legal_jurisdiction`, `governing_arbiter`,
  `credentials_required`, ...) ready for the Layer-3 social-collaboration
  story without on-disk format breaks.
- **Aligned with industry standards** (no new runtime dependencies): the
  schema and on-disk layout track **cargo-crev** (Proof model), **F-Droid**
  (one-file + derived index), **TUF** (monotonic version + `meta` field +
  `delegations` placeholder), **Argo WorkflowTemplate** (5-value
  `template_type`), **GitHub Actions** (`inputs`/`outputs` field naming),
  **Nix `flake.lock`** (`template_lock`), and **W3C `did:key`**
  (`publisher_did`).

Full wire-format spec in [`docs/PROTOCOLS.md §9`](docs/PROTOCOLS.md);
bootstrap taxonomy in [`docs/CATEGORIES.md`](docs/CATEGORIES.md).

## What's New in 0.9.2 - Revocation, invitations, private LAN

- **Endorsement revocation** - owners can now revoke previously-issued
  trust endorsements. `TrustGraph.revoke(endorser, endorsement, reason)`;
  load_all filters revoked entries; signed revocation records persist at
  `team_trust/revocations.jsonl`. Pre-emptive revocations are rejected
  (the matching endorsement must exist) so they can't be used for DoS.
- **Invitation tokens** (`nth_dao.Invitation`) - one signed bundle that
  carries `team_id` + `owner_pubkey` + `join_token` + optional `ws_url`
  + optional LAN `psk`. Encode as a URL (`nthdao+invite://...`) or as
  a QR code (`pip install nth-dao[ux]`). New members scan/paste and
  attach without out-of-band setup.
- **Private LAN discovery** - `LANDiscovery(..., psk="team-secret")` adds
  an HMAC-SHA256 tag to every query and hello; peers without the shared
  PSK see only opaque traffic. Empty PSK keeps the public/open mode.
- **`docs/PROTOCOLS.md`** - a wire-format spec so other-language
  implementations (Rust / Go / TS) can interop with the Python reference.
- **`CONTRIBUTING.md`** - new "Hard Rules" section documenting the
  eight enforcement rules that prevent re-introducing the v0.9.1 bugs.

```python
# Invite flow:
inv = nth.Invitation.mint(team_cfg, owner_identity, ws_url="ws://...", ttl_days=7)
print(inv.to_url())              # "nthdao+invite://AAAAB3Nz..."  -> QR scan / paste
print(inv.to_qr_terminal())      # ASCII QR ready to print on a terminal

# Revoke flow:
tg.revoke(alice, alice_endorses_bob, reason="key rotated")
assert not tg.is_trusted("bob", bob_pubkey)
```

## What's New in 0.9.1 - Hardened release

Independent code review surfaced six critical security/correctness bugs.
0.9.1 fixes all of them, plus 13 high-severity issues, and adds two new
discovery layers. See [`CHANGELOG.md`](CHANGELOG.md) for the full list.

**Security (P0/P1/P3)**

- **Gossip signature verification fixed** - messages are now verified
  against the *author's* trusted pubkey (not the relay peer's), with a
  10-min replay window and `require_signature=True` as the safe default.
- **WebSocket challenge-response handshake** - peers must prove they hold
  the private key for the pubkey they claim before being added.
- **Atomic mission claim** - cross-process file locks (`fcntl` on POSIX,
  `msvcrt` on Windows) + compare-and-swap; a 6-process race test proves
  exactly-once semantics (`tests/test_concurrent_claim.py`).
- **Signed team config** - `MembershipManager(owner_identity=...)` makes
  every `team.json` save Ed25519-signed; tampered configs pushed via
  `git_sync` are rejected on load.
- **Constant-time token comparison** (`hmac.compare_digest`).
- **Windows ACL hardening** for private key files (`icacls /grant +
  /inheritance:r` with read self-check).
- **Identity tamper detection** - `AgentIdentity.load()` verifies the
  stored pubkey is actually derivable from the private key.

**New capabilities (P4 + P5)**

- **Web-of-Trust** - `nth_dao.TrustGraph` + signed `Endorsement`s let
  trust propagate transitively (Alice trusts Bob, Bob trusts Carol ->
  Alice can accept Carol's signed gossip), bounded by per-endorsement
  `depth_allowed` caps. `GossipNode(trust_graph=, wot_max_depth=2)`.
- **People nearby (LAN discovery)** - pure-stdlib UDP broadcast based
  agent discovery. `LANDiscovery(...).discover(timeout=3.0)` returns
  every nth-dao agent on your subnet, with `ws_url` ready for
  `GossipNode.connect()` and `pubkey_hex` ready for `TrustGraph`.
- **Fuzzy `PeerFinder.search(query)`** - substring / prefix / exact
  scoring across `agent_id`, `label`, `capabilities`, `groups`.
- **Anti-Sybil reputation credits** - `ReputationManager.rate()` spends
  1 credit per new entry; credits are scoped by pubkey fingerprint so
  spawning 1000 `agent_id`s doesn't multiply your budget.

**Quality**

- New `nth_dao/util/io.py` centralises `atomic_write_json`,
  `safe_load_json`, `safe_id`, and an `InterProcessLock`. Six modules
  previously copy-pasted these.
- Tests grew from 23 -> **83 passing**.
- Project version is now sourced from `pyproject.toml` via
  `importlib.metadata` so `nth_dao.__version__` no longer drifts.

```python
# Find nearby agents and bootstrap trust in 4 lines:
peers = nth.LANDiscovery(agent_id="me").discover(timeout=3.0)
trust = nth.TrustGraph(workspace)
for p in peers:
    trust.add_root(p.agent_id, p.pubkey_hex)
```

## What Is NTH DAO?

NTH DAO is a Web3-oriented collaboration protocol layer for humans, agents,
bots, tools, and service nodes. It gives every DAO a local-first foundation:

- **Identity** - recognizable, auditable, authorizable members and agents
- **Membership** - join requests, invitations, roles, permissions, approval
- **Groups** - channels, messages, announcements, tasks, audit, trust hints
- **Discovery** - agents find each other across local processes and synced nodes
- **Missions** - long-running work can be routed, claimed, handed off, completed
- **Memory** - shared blackboard, ledger, skills, and DAO knowledge
- **Local-first sync** - plain files that can be stored offline and synced by Git
- **Agent adapters** - pluggable backends for local and external agents

Core functionality uses only the Python standard library.

## 30-Second Quickstart

```python
import nth_dao as nth

with nth.attach(
    agent_id="alice",
    backend="mock",
    capabilities=["python", "frontend"],
    groups=["payments"],
) as dao:
    teammate = dao.find_teammate(capability="backend")
    print(teammate.record.agent_id if teammate else "none online")

    mission = dao.start_mission(
        title="ship payments v2",
        goal="end-to-end refactor",
        steps=[
            {"id": "api", "description": "design API", "required_capabilities": ["backend"]},
            {
                "id": "ui",
                "description": "build UI",
                "required_capabilities": ["frontend"],
                "depends_on": ["api"],
            },
        ],
    )

    if next_mission := dao.take_next_work():
        dao.runner.complete(next_mission.id, "ui", note="shipped")
```

## Local DAO Group Chat

Start the local-first DAO group UI:

```bash
python -m nth_dao.web
```

Then open:

```text
http://127.0.0.1:8080/
```

The UI shows the DAO `group id`, member list, channels, messages, announcements,
tasks, and a simple search box. With the default open policy, entering an
`agent_id` and clicking **Join / Switch** creates or switches to that member.

## Installation

```bash
git clone https://github.com/AlexNthLab/nth-dao.git
cd nth-dao
pip install -e .
```

Optional extras:

```bash
pip install "nth-dao[crypto]"     # Ed25519 agent identity/signing
pip install "nth-dao[web]"        # FastAPI/uvicorn examples
pip install "nth-dao[contracts]"  # Pydantic-backed contracts
```

## Architecture

```text
nth_dao.attach()
    |
    +-- identity and membership
    +-- roles and permissions
    +-- local-first group layer
    +-- discovery registry
    +-- mission orchestration
    +-- blackboard and memory providers
    +-- audit, trust, and reputation hints
    +-- backend adapters
```

Files are intentionally simple and inspectable:

- `team.json` - DAO identity, join policy, members, roles
- `team_agents/*.json` - discovered/online agent records
- `team_channels/*.json` - channels
- `team_channels/*.messages.jsonl` - append-only messages
- `team_audit/audit.jsonl` - append-only DAO events
- `team_tasks/*.json` - local-first tasks
- `team_trust/*.json` - simple trust hints

These files can be kept local, synced with Git, or merged by future transport
layers.

## Design Principles

- Local-first before central service
- File/Git syncable before database lock-in
- Explicit identity before anonymous automation
- Real permissions before decorative roles
- Audit logs before opaque side effects
- Stable DAO primitives before marketplace or settlement features
- Agent-to-Agent compatibility without hiding human governance

## Examples

| File | What it shows |
|------|---------------|
| `examples/group_chat_server.py` | ⚠️ Deprecated — group chat is now a native view in the v2 console (`Channels` tab, served at `/v2`). Kept as a minimal standalone demo only. |
| `examples/nth_demo.py` | Discovery and mission relay |
| `examples/blackboard_demo.py` | Shared blackboard collaboration |
| `examples/multi_backend_demo.py` | Cross-backend agent coordination |
| `examples/evo_demo.py` | EvoLoop self-improvement pipeline |
| `examples/sync_demo.py` | Multi-terminal Git sync |
| `examples/team_entrypoint.py` | Production-style CLI entrypoint |

## Task market federation (multi-node)

Independent nodes can discover each other's published tasks, services, and
products without a central market index. Configure at least one bootstrap seed
with `NTH_FED_PEERS` or the Tasks view. Public nodes may set an HTTPS
`NTH_PUBLIC_BASE_URL` to announce themselves back to their seeds. Verified
gossip peers are retained with a bounded TTL and are re-resolved, IP-pinned,
and identity-verified after restart. Feed digests prove provenance; each full
announcement's `publisher_sig` remains the content authority. See
**[docs/federation.md](docs/federation.md)**.

## Migration Notice

NTH DAO is a hard rename. Existing forks or local checkouts should update their
imports and package references:

```python
import nth_dao as nth
```

Internal class names such as `TeamSession` and `TeamRole` are kept for now to
avoid unnecessary churn in the runtime model. The public package identity is
NTH DAO only.

## License

MIT. See [LICENSE](LICENSE).
