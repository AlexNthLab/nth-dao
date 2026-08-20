# ADR 0003: Intent Is Not Authority

- Status: Accepted
- Date: 2026-08-20

## Context

Natural-language intent resolution is probabilistic and vulnerable to
ambiguity and prompt injection. The project already has a signed transaction
`IntentMandate` whose meaning is authorization, not interpretation.

## Decision

Introduce a separate generic intent plane. Resolvers create unsigned drafts;
solvers create signed claims; deterministic policy evaluates proposals; users
or delegated authorities explicitly select and authorize execution. Generic
intent objects never replace transaction mandates.

## Consequences

- Language models may suggest, but cannot grant capability or commit authority.
- UI-light automation remains possible only inside an existing bounded mandate.
- Every proposal supports rejection, refutation, and supersession.
