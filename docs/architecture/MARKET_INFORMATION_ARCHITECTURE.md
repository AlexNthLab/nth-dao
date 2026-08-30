# Market Information Architecture

Status: accepted implementation direction

## Purpose

NTH DAO needs a familiar human-facing market without collapsing distinct
signed protocol objects into one weak record type. The UI may present one
search and one publish entry point, while the protocol keeps Tasks, Offers,
Orders, Receipts, Resource Profiles, and Trade Rules separate.

The design follows one rule:

> Unify discovery and navigation for people; preserve explicit protocol
> boundaries for agents and verifiers.

## Human-Facing Model

The primary navigation remains stable:

- **Tasks** is the work queue. It contains requests that can be claimed and
  linked to a Mission. Tasks may be local, federated, unpaid, or carry a
  bounty.
- **Market** is the discovery and transaction area. It presents products,
  services, exchanges, and task opportunities through one searchable view.
- **Missions** is the execution engine after a Task is claimed or accepted.
- **Blackboard** is the human-visible execution record for a Mission.
- **Mandates** define authority and transaction limits.

Market uses familiar sections:

1. **Discover** - all searchable market entries, with broad facets.
2. **My Listings** - the operator's active Tasks and signed Offers.
3. **Orders** - purchases, sales, exchanges, delivery, acknowledgement, and
   disputes.
4. **Trade Skills** - installed or observed rule packages and their local
   recognition/readiness state.

Low-level Proposal and Agreement objects remain available in an order detail
or advanced protocol view. They are not top-level shopping concepts.

## One Publish Entry

The UI provides one **Publish** command with three intents:

- **Request work** creates a signed `TaskAnnouncement`. A successful claim
  creates or links exactly one Mission.
- **Offer a resource** creates a signed `TradeOffer` with one or more
  `provides` legs and optional `requests` legs.
- **Propose an exchange** creates a signed `TradeOffer` with both `provides`
  and `requests` legs.

Product and service are broad human-facing facets, not closed protocol types.
The publisher may attach an exact Resource Profile Skill reference to describe
the actual object.
The backend must never convert a product, service, or exchange into a
claimable Task merely because the UI uses one Publish command.

## Search Projection

`MarketSearchEntry` is a read-only local projection. It may merge locally
verified Task announcements and Trade Offer discovery hints for display and
search. It is not signed, cannot be imported as a protocol fact, and cannot be
used directly for execution.

Every entry must retain an exact pointer to its source object:

- Task entries bind `announcement_id` and `federation_key`.
- Offer entries bind `offer_digest` and the discovery announcement.

The optional `market.index` plugin contract indexes a normalized,
content-addressed form of this projection. It remains a replaceable search
accelerator, not a new fact store. The current REST search path does not yet
dual-write to or read from that provider. Local, federated, relay, or
centralized index providers may share the contract only when their complete
wire protocol. Their exact capability contract digests intentionally differ
when effects, consistency, or retention differ. Compatibility therefore has
three gates: identical v1 wire schemas, preserved non-authoritative index
semantics, and explicit Host approval for every declared external effect.

The projection may derive broad facets such as `tasks`, `products`,
`services`, `digital-assets`, `exchanges`, and `other`. A facet is a search
hint, not a claim that the resource exists or has been classified correctly.
`exchanges` is an intent facet and may overlap a resource facet: for example,
one signed swap can appear under both `digital-assets` and `exchanges` without
changing or duplicating its underlying Offer.
Numeric value filters are always scoped to an exact asset identifier; minor
units from different assets are never compared as though they shared a price.

Opening or acting on a search result must resolve and verify the exact signed
source object again. Search results never grant trust, authority, inventory,
ownership, settlement, or execution readiness.

## Resource Profile Skills

A Resource Profile Skill answers **what is being offered or requested**. It
is a signed, content-addressed schema package selected by the publisher and
accepted according to local policy. It may define fields, validation rules,
display hints, evidence requirements, and category hints for resources such
as:

- physical goods;
- digital goods and licenses;
- professional or agent services;
- game items and currencies;
- fiat, tokens, or other digital assets;
- access rights, datasets, compute, or future resource families.

The Core owns only bounded identifiers, exact package digests, canonical
serialization, signatures, and safe declarative validation. It does not own a
global catalogue of product types. Community packages can evolve without a
Core release.

A Resource Profile Skill cannot execute code, transfer assets, or authorize
funds. Untrusted profile data is displayed as publisher-provided metadata.

### Current implementation boundary

The Core can now sign, verify, content-address, and store bounded Resource
Profile v1 documents. A separate local policy explicitly recognizes exact
Profile digests before their community categories may map into broad Market
facets. Signature validity alone does not grant recognition.

The local console exposes authenticated REST and UI controls to list, verify,
import, recognize, and revoke exact Profile digests. These controls never fetch
remote packages automatically and never grant Adapter or payment authority.

The current publisher stores a bounded inline descriptor in the signed Offer
and may attach a `{rule_id, digest}` Profile reference. Inspection verifies the
inline descriptor's content hash and its linkage to Offer legs. When the exact
Profile is already in the local CAS, inspection also re-verifies its signature,
checks its activation window and identifier binding, evaluates explicit local
recognition, and applies its bounded declarative field schema. The UI presents
these states separately. A Profile that is signed but not recognized remains
publisher-provided metadata.

Descriptor v1 reserves `attributes.community_category` as the community
classification hint. A Resource Profile schema MUST NOT define that property;
its remaining attributes are validated in the Profile-owned namespace. This
prevents category mapping metadata from being mistaken for a Profile field.

The Web layer does **not** yet fetch a missing Profile from a peer or federate
recognition/revocation statements. Profile recognition and schema validity do
not grant execution readiness.

## Trade Rule Skills

A Trade Rule Skill answers **how the parties intend to transact**. Existing
Trade Rule Packages may define pricing, quantity, delivery, inspection,
acceptance, payment, dispute, refunds, rights, compliance, or other terms.

The current immutable Order binds the exact signed Offer digest, which
transitively freezes its inline descriptors and Profile references, plus its
exact Trade Rule Package references. A future Profile resolver should also
materialize the independently verified Profile package digests in the Order
view. Agreement on a human-readable label is insufficient.

## Adapter Boundary

An Adapter performs external effects. It is installed locally and approved
separately from Resource Profile and Trade Rule Skills. Recognition of a Skill
does not approve an Adapter. Installing an Adapter does not grant it a
Mandate.

The target architecture requires all of the following before external effects:

1. an immutable Order binding exact package digests;
2. locally resolved and accepted Resource Profile and Trade Rule Skills;
3. an installed Adapter with explicit operation grants;
4. an applicable signed Mandate;
5. append-only audit and signed Receipts.

Real-money and irreversible execution remain disabled by default. The current
test rail is not represented as real settlement. Local Profile verification is
one input to item 2, but the present implementation still does not use it to
make an Order execution-ready.

## Federation Boundary

Federation separates discovery from verification:

- peers exchange bounded signed discovery hints;
- a node stores hints as untrusted search candidates;
- selecting a candidate fetches the exact content-addressed source object;
- local verification and policy decide whether it may be retained or acted
  upon.

LAN broadcast is only one peer source. Wide-area discovery requires explicit
known peers, optional community relays, or a future DHT. A relay may improve
availability but must not become an authority over identity, ranking, trust,
or settlement.

Search freshness and source provenance must be visible. Stale entries remain
distinguishable from currently verified entries, and a missing peer must not
silently convert an old hint into a live listing.

Accepted Agreements may also exchange exact signed Execution Receipts without
publishing them into Market discovery. The Orders workbench lets an operator
send one locally retained Receipt directly to the counterparty node. The
sender shows durable pending/retry state and, after verification, the peer's
signed acknowledgement and remote audit reference. These are private
bilateral execution records, not searchable listings. An acknowledgement says
that the peer claims it retained and locally policy-verified the Receipt. It
does not independently prove the peer's filesystem, Spine, delivery, payment,
quality, or settlement.

## Compatibility and Migration

The existing `/api/v2/market/open` Task announcement feed remains available
during migration. The new Market search endpoint is a projection over the
same verified local and federated facts.

Legacy `service` and `product` Task announcements remain readable but are
labelled legacy. New UI publication routes work requests to TaskAnnouncement
and resources/exchanges to TradeOffer. No legacy record is silently rewritten
or treated as a signed Trade Offer.

`POST /api/v2/market/announce` accepts new Task records only. Historical and
federated product/service labels remain readable through the legacy projection,
but new resources must use the signed Trade Offer publisher. This prevents new
clients from bypassing the protocol boundary after the UI migration.

## Non-Goals

This information architecture does not:

- turn NTH DAO into MCP or require MCP transport;
- define a universal product taxonomy;
- certify that listings are true, fair, legal, or available;
- make community Skills trusted by default;
- execute downloaded code;
- require a central market server;
- enable real funds merely because a listing or rule verifies cryptographically.
