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

Install the LAN extra on both nodes so mDNS is available:

```bash
pip install -e ".[lan]"
```

Opening **Tasks** performs one bounded discovery pass and imports only peers
whose DID:key identity card, public key, signature, and advertised URL all
verify. The manual **Discover nearby DAOs** action repeats the scan and shows
diagnostics. Local firewalls must allow inbound TCP on the configured NTH DAO
port (8080 by default) and mDNS/UDP traffic on the private network.

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
   `GET /api/v2/market/federation/pull?ids=...`.
4. Verify every full announcement's publisher signature.
5. For an exchange hint, fetch the exact Trade Offer from its fixed digest
   route, verify the Offer signature and digest, then verify every summary and
   lifetime binding again.
6. Merge unexpired records into the local read-only federation cache.

Remote records are not copied into the local authoritative feed and therefore
are not re-announced as local work. Claims return to the announcement's source
DAO, which remains the single CAS authority for that listing.

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
| `POST /api/v2/trade/offers/{digest}/announce` | Publish a discovery hint for this node's active canonical Offer | Console write |
| `GET /api/v2/trade/federation/offers/{digest}` | Exact signed Offer while locally announced | Public read |

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
- Exact Trade Offer reads use a process-local source gate (120/minute) before a
  locked cross-worker global gate (300/minute). This ordering prevents rejected
  source floods from turning the persistent limiter into a disk-write amplifier.
- A malformed or unverifiable digest, identity card, or announcement fails
  closed.
- Before a remote claim, the source identity card is fetched afresh and the
  claim POST is pinned to the same validated IP.

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
- Remote Trade Offer documents are verified during synchronization but are not
  yet retained as a local actionable Offer chain. Discovery therefore supports
  verified summary matching, not local full-document inspection or remote
  Agreement creation in this slice.
- Open-set absence removes withdrawn or superseded Offer announcements from
  the current projection, but there is no cross-node proof that a publisher
  has disclosed its latest revision. Durable signed Offer tombstones and
  revision-head proofs remain future protocol work.
- Trade Offer discovery does not federate Agreements, Mandates, Receipts,
  payment, delivery, dispute outcomes, or settlement state.
- Withdrawal currently uses signed open-set absence, not durable tombstones.
  Nodes that need historical proof of withdrawal must retain their own audit
  events until a tombstone/revocation wire type is standardized.
