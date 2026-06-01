# Security Policy

NTH DAO is a decentralized agent-coordination protocol. Security is not a
feature — it is the substrate. This document covers what we promise, what
we know we do NOT guarantee, how to report a vulnerability, and how to
recover from common security incidents.

## Supported Versions

Only the latest minor release receives security fixes.

| Version | Supported |
|---------|-----------|
| 0.9.x   | ✅        |
| ≤ 0.8.x | ❌        |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Email `security@nth-dao.example` (placeholder — update to a real address
when the project has a maintainer email) with:

1. Affected version + commit hash
2. Steps to reproduce
3. Impact assessment (what an attacker can do)
4. Suggested fix if you have one

We commit to:
- Acknowledging within 5 business days
- Sharing a fix or mitigation timeline within 14 days
- Crediting you in `CHANGELOG.md` unless you prefer anonymity
- Coordinated disclosure: we publish the fix + advisory at the same time

## Threat Model

### What we defend against

- **Forged identities** — gossip / channel messages MUST verify against
  the *author's* trusted pubkey, never the relay/sender's connection pubkey.
- **Replay** — every wire payload carries a timestamp; messages outside
  `REPLAY_WINDOW_SECONDS = 600` are dropped.
- **Race conditions in mission claim** — cross-process file locks + CAS;
  exactly-once semantics verified by a 6-process spawn test.
- **Tampered `team.json` pushed via `git_sync`** — owner-signed config;
  invalid signature → empty config + WARNING log.
- **Timing side-channels on tokens** — `hmac.compare_digest` everywhere.
- **Sybil attacks on reputation** — per-pubkey anti-Sybil credits; new
  agent IDs sharing the same identity also share the budget.
- **Pre-emptive DoS revocations** — revocations require a matching
  endorsement to exist locally before they're accepted.
- **Private key files readable by other local users** — `chmod 0o600`
  on POSIX, `icacls /grant <user>:(F) /inheritance:r` on Windows.

### What we do NOT defend against

The following are explicitly out of scope. If you rely on NTH DAO, you
need to handle these in your deployment:

- **A malicious node already inside your trust web** — if Alice's
  identity is compromised, every agent that trusts Alice is exposed
  according to the depth their endorsement chain permits.
- **Network-level metadata leakage** — LAN discovery without a `psk` is
  plaintext UDP broadcast; gossip without TLS is plaintext WebSocket.
- **Compromised host OS** — if the OS root is compromised, identity.json
  is readable regardless of ACL.
- **Side-channel attacks on Ed25519** — we use PyNaCl which uses libsodium;
  libsodium's constant-time guarantees apply, but a co-tenant on the
  same physical machine may extract keys via cache attacks. Use a
  dedicated machine for high-value identities.
- **Denial-of-service against the gossip server** — there is no rate
  limit; an attacker who passes handshake can flood gossip. Front the
  server with a reverse proxy (nginx, Caddy) and rate-limit per IP.
- **Long-term cryptographic compromise of Ed25519** — when (not if)
  Ed25519 falls to quantum or analytic attack, every signed artifact in
  `team_trust/`, `templates/`, and `reviews/` becomes forgeable. We will
  publish a hybrid-key migration spec before that day.
- **The maintainer disappearing** — see `docs/CONTINUITY.md` (planned
  for v1.0). Fork freely; the protocol spec in `docs/PROTOCOLS.md` is
  intentionally implementable in any language.

## Key Management

### What can go wrong

A NTH DAO agent's authority comes from its Ed25519 private key in
`identity.json`. Lose the key, lose the agent. Concretely:

- Disk failure / accidental `rm` → identity is irrecoverable.
- Backup leaked → attacker becomes the agent.
- Same identity on two machines → either both share the key (mutual
  attack surface) or each has a different key under the same agent_id
  (signature verification breaks).

### What we provide today (v0.9.4)

**Encrypted recovery kits.** Export an identity into a password-protected
JSON blob that can be safely stored outside the agent's machine
(USB stick, password manager, etc.):

```python
from nth_dao.key_recovery import export_recovery_kit, import_recovery_kit
from nth_dao.identity import AgentIdentity

# On the live machine — export
ident = AgentIdentity.load("~/.nth/identity.json")
kit = export_recovery_kit(ident, password="my-strong-passphrase")
# kit is a small JSON object you can paste anywhere

# On a new machine — restore
ident_restored = import_recovery_kit(kit, password="my-strong-passphrase")
ident_restored.save("~/.nth/identity.json")
```

The kit uses libsodium's `crypto_secretbox` (XSalsa20 + Poly1305) with
key material derived via Argon2id (PyNaCl's `pwhash`). Password
strength matters: a 5-character passphrase is broken in seconds; a
6-word diceware passphrase is fine.

### What we will provide later

- **Guardian-based recovery** (v0.9.5+) — pre-designate N trusted peers;
  any M of them can collectively sign a `KeyReplacement` proof that
  re-binds your `agent_id` to a new pubkey. Backed by `Endorsement`
  semantics already in the trust layer.
- **Hierarchical Deterministic identities** (v1.0+) — derive child
  identities from a master seed à la BIP-32 so losing one child doesn't
  end the chain.

### Operational guidance

1. **Generate the identity on a clean machine and export a recovery kit
   immediately**. Do not put off the export.
2. **Store the recovery kit in two places** that fail independently:
   one offline (USB), one online but encrypted (password manager).
3. **Use a strong passphrase**. 6 random English words ≥ 70 bits entropy
   is the floor.
4. **Do not commit `identity.json` or recovery kits to Git**. The
   `.gitignore` excludes `*.key`, `*.pem`, `.env*`, and `credentials.json`
   by default. Recovery kits should be added there explicitly per project.
5. **Rotate proactively** if a kit is ever exposed: generate a new
   identity, have your team re-`add_root` you under the new pubkey, then
   delete the compromised identity from your local `~/.nth/`.

## Disclosure History

| Date | Version | CVE / Issue | Reporter |
|------|---------|-------------|----------|
| 2026-05-31 | 0.9.1 | Internal review — 6 critical bugs (gossip sig, mission CAS, ACL, etc.) | Independent reviewer (anonymous) |
| 2026-05-31 | 0.9.2 | Anti-tamper team config + WoT revocation + LAN PSK | Same reviewer |

Earlier vulnerabilities — see `CHANGELOG.md` for the full timeline.
