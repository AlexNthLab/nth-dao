# ADR 0001: Trust Kernel And Plugin Boundary

- Status: Accepted
- Date: 2026-08-20

## Context

NTH DAO already exposes replaceable agent, settlement, execution, discovery,
and storage-like components. They use unrelated registries and lifecycle
rules. Making every component dynamically replaceable would also let a plugin
replace the checks that constrain it.

## Decision

Keep identity custody, canonical/signature verification, mandate/capability
authorization, EventBus integrity, state-transition safety, receipt/dispute
verification, and plugin policy inside a small Trust Kernel.

Use versioned capability contracts for replaceable providers. The first host
accepts reviewed built-ins only. Third-party packages require a future isolated
runtime and signed distribution format.

## Consequences

- Existing backends and adapters are migrated behind the host incrementally.
- The kernel remains small enough for conformance testing and external
  implementations.
- Some duplicate registries remain temporarily; premature mass migration is
  explicitly rejected.
- Plugin freedom is constrained at irreversible and authoritative boundaries.
