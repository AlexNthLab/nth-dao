# NTH DAO Intent Plane

Status: protocol boundary; execution is intentionally deferred until the
plugin kernel and deterministic policy gate are stable.

## Principle

An intent is a request to explore possible outcomes. It is not authority to
act. A model may interpret language and propose alternatives, but only a
deterministic policy gate and an explicit signed authorization can cross an
irreversible boundary.

The generic intent plane does not replace the existing transaction
`IntentMandate`. The former is a reviewed draft and proposal process; the
latter delegates transaction authority and remains part of the signed
Intent/Cart/Payment mandate chain.

## Flow

```text
human or agent input
  -> unsigned IntentDraft
  -> clarification and visible diff
  -> signed IntentEnvelope
  -> one or more SolverProposal objects
  -> deterministic policy evaluation
  -> explicit proposal selection
  -> Task / Mission / Agreement
  -> transaction Mandates when required
  -> prepare / authorize / commit
  -> Receipt or Dispute
```

## Required Properties

### IntentDraft

- unsigned and visibly non-authoritative;
- records source text, assumptions, ambiguity, and requested clarification;
- has bounded size and content-addressed attachments;
- cannot be submitted directly to an executor.

### IntentEnvelope

- signed by the human, agent, or delegated authority accepting the draft;
- binds the accepted draft digest, scope, constraints, expiry, and nonce;
- names allowed solver classes but grants no commit authority;
- is append-only; revisions create a new envelope linked to the prior digest.

### SolverProposal

- identifies solver DID/plugin and input intent digest;
- separates facts, assumptions, estimates, risks, and requested permissions;
- binds evidence by content hash and source provenance;
- remains a claim, not a verified fact;
- can be rejected, refuted, or superseded.

### PolicyDecision

- produced by deterministic code, not a language model;
- records the policy version and every evaluated constraint;
- fails closed on unknown fields, unsupported assets, missing evidence, or
  ambiguous authority;
- cannot create permissions absent from the signed intent or host policy.

## Automation Levels

| Level | Behavior | Human interface |
| --- | --- | --- |
| `A0` | Observe and summarize only. | Optional display. |
| `A1` | Draft intents and proposals. | Review required. |
| `A2` | Execute reversible local actions. | Notification and undo window. |
| `A3` | Prepare external actions. | Explicit authorization required. |
| `A4` | Commit bounded recurring actions under a signed mandate. | Persistent control, limits, and revocation UI required. |

No profile or plugin may raise an automation level beyond the signed mandate
and host policy. High-risk authorization, exceptions, governance, and disputes
must remain inspectable even if routine low-risk flows become UI-light.

## Threat Model

- prompt injection inside source text or retrieved content;
- solver collusion or correlated model errors;
- stale evidence and changed external prices/state;
- confused deputy between intent, mandate, and executor;
- hidden permission expansion by a plugin;
- replay of an old accepted intent;
- a truthful signature over a false claim.

Mitigations include provenance labels, content-addressed evidence, nonce/TTL,
fresh deterministic checks before commit, independent solver options, bounded
capability grants, signed receipts, and a first-class dispute path.
