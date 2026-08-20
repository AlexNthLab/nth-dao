# ADR 0002: External Effect Commit Protocol

- Status: Accepted
- Date: 2026-08-20

## Context

Cordis-style reversible registration is useful for runtime composition, but it
cannot undo money movement, remote messages, shipments, or destructive calls.

## Decision

External effects use an explicit observe/propose/prepare/authorize/commit/
receipt sequence. Commit requires an idempotency key, applicable mandate and
terms digests, executor identity, deadline, and deterministic preflight.
Compensation is a new signed action, never a fictional rollback.

## Consequences

- Host API v1 rejects all `irreversible` capability execution. T4 commit
  providers require a later isolated runtime and durable recovery protocol;
  being a reviewed built-in is not sufficient.
- Disable removes local routing but does not claim external effects vanished.
- Receipts and disputes remain kernel-verified protocol objects.
