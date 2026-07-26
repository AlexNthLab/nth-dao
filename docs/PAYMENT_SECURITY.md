# Payment Security Boundary

NTH DAO payment code is an experimental, test-network coordination layer. It
is not a production wallet, custodian, escrow service, or mainnet payment
processor.

## Current Authority Model

The current `PaymentAttempt` implementation accepts exactly one authority
model:

- the attempt signer DID must equal `SettlementIntent.payer_did`;
- the same signer must be the Trade's signed `settler_did`;
- amount, currency, payee, payer, and the external idempotency key are verified
  again before a settlement event is accepted.

Delegated payment authority is intentionally unsupported. An Agent cannot pay
on behalf of a DAO merely because it has a role, group membership, a string
capability name, or access to the local process. Future delegation requires a
signed, revocable capability bound to:

- principal and delegate DID;
- Order and PaymentMandate digest;
- maximum amount and currency;
- payee or counterparty constraints;
- rail and network;
- validity window and nonce;
- optional N-of-M approval policy.

Until that object and its revocation checks exist, the payer principal must
sign payment-attempt state transitions directly.

## x402 Test-Network Boundary

`X402SettlementAdapter` is test-network only. It accepts the CAIP-2 identifiers
in `X402_TEST_NETWORKS` and rejects legacy names such as `base-sepolia` as well
as mainnet identifiers before calling `lookup()` or `pay()`.

The current `PaymentRail` contract supports only the immediate digital-service
special case:

1. durable `lookup(idempotency_key)`;
2. atomic, provider-side deduplication of `pay(..., idempotency_key)`;
3. a bounded receipt containing the same idempotency key, transaction
   reference, network, and provider evidence.

No production rail implementation ships with NTH DAO. `FakePaymentRail` is the
only bundled implementation and never handles credentials or broadcasts value.

A general production rail must not be fitted behind this two-method interface.
It needs separately signed and persisted `authorize`, `capture`, `refund`, and
`lookup` operations, plus webhook replay protection and reconciliation.

## Crash and Rollback Model

Payment attempts use:

- a signed event hash chain;
- an append-only local prepared/committed head journal;
- optional `PaymentAttemptHeadWitness` storage outside the workspace;
- leases and deterministic retry scheduling;
- provider lookup before every retry;
- an `orphaned` state when payment may have committed but evidence is invalid.

`PaymentAttemptReconciler` is lookup-only. It cannot call `PaymentRail.pay`.
It may move an orphaned attempt to settled only after validating an existing
provider receipt against the original intent and signed Trade.

Configure `FilePaymentAttemptHeadWitness` on independently backed-up or
remotely mounted storage. A witness inside the same workspace does not protect
against whole-workspace rollback. When configured, witness unavailability or
conflict fails closed; it never silently falls back to local-only validation.

## Remaining Production Blockers

- signed delegated payment capabilities and revocation;
- N-of-M treasury approval;
- authorization hold, capture, refund, and reversal state transitions;
- a reviewed real x402 v2 rail implementation;
- provider webhook signature and replay verification;
- independent remote transparency/witness service;
- testnet soak tests across two real nodes;
- mainnet threat model, limits, operator confirmation, and incident runbook.

Mainnet identifiers must remain rejected until all blockers relevant to the
selected rail are implemented and independently audited.
