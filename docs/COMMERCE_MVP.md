# No-Money Digital-Service Commerce MVP

This release implements a complete, local-first transaction rehearsal for
digital services. It is deliberately constrained to the non-monetary
`NTH-TEST` asset and the `manual:nth_test` settlement method. No endpoint in
this surface accepts a wallet, private key, real currency, or payment rail.

## Lifecycle

1. A seller publishes a signed service Listing.
2. The existing market federation carries its signed discovery summary.
3. A buyer selects the federated service in **Market**. The buyer node fetches
   and verifies the full Listing from the configured seller peer.
4. The buyer signs an Intent. The seller verifies it and returns a signed Cart.
5. The buyer verifies the Listing, Intent, and Cart, signs a PaymentMandate and
   one idempotent Order, then opens the Trade event chain.
6. A signed, content-addressed Outbox envelope replicates the Order and exact
   Trade prefix to the counterparty. Retries do not create duplicate orders.
7. The seller signs a delivery claim. The buyer sees its content and receipt
   digest, independently reviews it, and signs acceptance or rejection.
8. Acceptance can end in a signed manual `NTH-TEST` settlement. Either party
   may open a dispute; the bound resolver can record a full settlement or
   refund decision.

## Run two nodes

Each node must use a different workspace and port. Configure the other node as
an exact federation origin, for example:

```text
NTH_FED_PEERS=https://peer.example
```

For local testing, an explicit loopback HTTP origin is supported. Start the
console with `python -m nth_dao.web`, open `/v2.html`, and use **Market**.
Federated service rows provide a **Buy** action; manual peer URL and Listing
digest entry remains available for recovery and diagnostics.

## Security boundary

- A signature proves authorship and byte integrity. It does not prove that a
  service description, delivery, review, or dispute claim is true.
- Every order embeds and verifies its complete authorization snapshot.
- Every Trade transition re-verifies the stored chain before appending.
- Remote chains must extend the recipient's exact signed prefix. Forks,
  suffix-only updates, and modified bytes are rejected.
- Order records are limited to 160 KiB and complete Trade chains to 320 KiB so
  a valid local transition remains replicable inside the signed envelope.
- Anonymous Cart and federation sync routes have pre-buffer body limits and
  cross-process rate limits.
- Peer origins are operator-configured, rechecked before every dispatch, and
  HTTP redirects are rejected.
- Order and Outbox reads require the console Bearer token when console
  authentication is enabled.

## Persistence and recovery

Orders, Trade chains, checkout progress, and Outbox records are file-backed
under the active NTH workspace. A restart reconstructs views from signed
records. Failed network delivery remains pending and can be retried from the
Market workbench. An acknowledgement must be signed by the receiver DID and
bind the envelope's content-derived message ID, order ID, and Trade chain head
before the Outbox marks delivery complete.

## Not production payment

`NTH-TEST` is a protocol test unit, not a token, stored-value balance, or legal
tender. A `settled` state means that the authorized party signed a manual test
receipt. It does not prove payment, legal performance, or real-world delivery.
Real-money adapters remain outside this MVP and must not be enabled by changing
UI fields or request JSON.
