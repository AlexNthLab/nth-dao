# NTH DAO Federation Discovery

Federation lets independently operated NTH DAO nodes discover signed tasks,
services, and product listings without a central market index. It is an
overlay network, not magic zero-configuration global discovery: every new
network needs at least one reachable bootstrap seed.

## Mental Model

- **Operator seed**: a URL explicitly configured by the local operator.
- **Learned peer**: a public HTTPS URL learned from a seed or peer and accepted
  only after its signed identity card is fetched and verified.
- **Feed digest**: a signed, compact hint describing available announcements.
- **Full announcement**: the signed task, service, or product record fetched on
  demand. Its publisher signature is the authority for its content.
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

Alternatively, manage seeds from the Tasks view or store a JSON string array
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
   `GET /api/v2/market/federation/pull?ids=...`.
4. Verify every full announcement's publisher signature.
5. Merge unexpired records into the local read-only federation cache.

Remote records are not copied into the local authoritative feed and therefore
are not re-announced as local work. Claims return to the announcement's source
DAO, which remains the single CAS authority for that listing.

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

## Security Boundaries

- Automatically discovered URLs must use public HTTPS.
- DNS results are rejected if any selected target is private, loopback,
  link-local, multicast, reserved, or unspecified.
- Network connections for learned peers are pinned to the validated IP to
  reduce DNS-rebinding risk.
- Redirects are rejected while fetching identity cards.
- Identity cards, HTTP bodies, peer lists, graph breadth, cycle duration,
  learned-peer storage, and hello rates are bounded.
- Reverse hello is limited both per source address (12/minute) and per node
  (120/minute), with a locked cross-worker budget when a workspace is present.
- A malformed or unverifiable digest, identity card, or announcement fails
  closed.
- Before a remote claim, the source identity card is fetched afresh and the
  claim POST is pinned to the same validated IP.

Application checks are not a substitute for deployment controls. Public nodes
should still run behind an egress firewall or proxy that blocks private and
cloud-metadata destinations.

## Current Limits

- At least one bootstrap seed is required; there is no mandatory central
  directory and no DHT yet.
- Nodes behind NAT need a tunnel, reverse proxy, or another externally
  reachable transport before internet peers can dial them.
- Self-signed DID:key identity prevents impersonation but not Sybil identities.
  Reputation, endorsements, governance policy, and transaction mandates must
  decide what a verified peer is allowed to do.
- The federation cache is a read model. Durable authoritative ownership stays
  with the source DAO.
- Withdrawal currently uses signed open-set absence, not durable tombstones.
  Nodes that need historical proof of withdrawal must retain their own audit
  events until a tombstone/revocation wire type is standardized.
