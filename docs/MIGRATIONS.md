# Migration Guide

NTH DAO commits to **forward-compatible on-disk formats within 0.9.x**.
That means: data created by 0.9.0 MUST load cleanly under 0.9.4 and any
later 0.9.x release. We will not delete required fields, rename existing
fields, or change the semantics of existing values without a major bump.

When 1.0 ships, we will publish a separate `0.9 → 1.0` migration runner.

## Tested compatibility matrix (v0.9.4)

| Created by | Loaded by | Outcome |
|-----------|-----------|---------|
| 0.9.0     | 0.9.4     | ✅ all fields preserved; new fields default-init |
| 0.9.1     | 0.9.4     | ✅ |
| 0.9.2     | 0.9.4     | ✅ |
| 0.9.3     | 0.9.4     | ✅ |
| 0.9.4     | 0.9.0     | ⚠️ extra fields are dropped at parse time; data not lost on re-save by 0.9.4 |
| 0.9.4     | 0.9.3     | ⚠️ same as above for the few new 0.9.4 fields (no breaking ones) |

The forward-compat tests are in `tests/test_migrations.py` and run on
every CI build.

## Changes per version

### v0.9.0 → v0.9.1 (security hardening, no schema changes)

Schema unchanged. Behavior changes:

- `MissionStore.try_claim()` now raises `ClaimConflict` on race instead
  of silently overwriting. Code that called `MissionStore.update_step`
  with a CAS still works.
- `gossip` messages signed under v0.9.0 are still valid; v0.9.1 added
  the requirement that *receivers* drop signatures that don't verify.
  Sending changed nothing.

### v0.9.1 → v0.9.2 (revocation + invitation + LAN PSK)

New optional artifacts. No existing field changed.

- New files (absent before, still optional):
  - `team_trust/revocations.jsonl` — empty if no revocations
  - LAN `LANDiscovery(psk=...)` — empty `psk` keeps the public/open mode
- New module: `nth_dao.invitation` — purely additive.

### v0.9.2 → v0.9.3 (Mission Template + Review)

**Mission file format gained 7 new fields**, all default-init safe:

- `template_id: Optional[str] = None`
- `template_version: Optional[str] = None`
- `template_lock: Dict[str, Any] = {}`
- `owner_did: str = ""`
- `legal_jurisdiction: str = ""`
- `governing_arbiter: str = ""`
- `credentials_required: List[str] = []`

A v0.9.2 mission loaded by v0.9.3 will have these as defaults. A v0.9.3
mission with these fields populated will lose them when parsed by v0.9.2
(unknown-field-tolerant) and dropped on re-save. **Use v0.9.3+ for any
workspace that holds template-instantiated missions.**

New optional directories that simply don't exist on v0.9.2 workspaces:
- `missions/templates/`
- `missions/reviews/`
- `missions/archive/`
- `missions/_template_index.json`
- `missions/_review_index.json`

### v0.9.3 → v0.9.4 (sustainability sprint)

No on-disk format changes. Pure additions:

- New module `nth_dao.key_recovery` — standalone, not persisted in workspace.
- New module `nth_dao.conformance` — bundled with the package, not in workspace.
- New CLI: `nth-status`, `nth-metrics`.
- New optional `requirements/*.lock.txt` for reproducible builds.

### Market announcement v1 → v2

Signed `nth-task-announcement-v1` records remain readable without rewriting
their signed bytes. V1 IDs may contain printable characters that are unsafe in
URL paths; federation therefore addresses full records and foreign claims by
`federation_key` (the SHA-256 hash of the signed body), not by raw ID.

V1 did not contain a signed claim-authority delegation. A node may federate a
v1 record only when the publisher DID is also the node DID. Other v1 records
remain locally readable but are not advertised, because treating the hosting
node as their claim authority would be impersonation. The operator status at
`GET /api/v2/market/federation/status` reports these as
`announcement_compatibility.requires_publisher_resign`. The original publisher
must reissue them as v2 with this node's DID in `authority_did`.

Claim files now use `sha256-<announcement-id-hash>.json`. Readers still accept
matching legacy filenames, while mismatched records at a colliding legacy path
are ignored. Stop all older NTH DAO processes before upgrading so one workspace
is not written concurrently by old and new claim-path implementations.

### Rule Recognition proof import v1 to paged v2

No rewrite is required. Existing protocol-version `"1"` bundle import events
and their content-addressed proof files remain valid and recoverable. New page
imports use protocol-version `"2"` events with page-set metadata; both versions
may coexist in one signed Spine and the same proof CAS directory. A pending v1
bundle is recovered as v1, while any pending v2 page causes recovery of its
complete observation from retained local pages before another network fetch.
Older binaries do not understand v2 import events and must not write the same
workspace after it has imported paged Recognition evidence.

## Migration runner

To verify a workspace from an older version loads cleanly:

```bash
python -m pytest tests/test_migrations.py -v
```

The runner walks `tests/migration_fixtures/<version>/` and asserts each
file loads under the current implementation without errors.

When you cut a new release, add a fixture for it:

```bash
# After bumping pyproject to 0.9.5:
mkdir -p tests/migration_fixtures/0.9.5
# Copy a few representative artifacts (anonymized!) from a real workspace:
cp missions/<id>.json tests/migration_fixtures/0.9.5/sample_mission.json
cp team.json tests/migration_fixtures/0.9.5/sample_team_config.json
# Run the migration test suite to confirm forward-compat:
pytest tests/test_migrations.py
```

## Hard rule for contributors

Before merging a PR that **adds** a field to an existing dataclass:
- ✅ Default value MUST be inert (`""`, `None`, `[]`, `{}`, `0`).
- ✅ `from_dict()` MUST tolerate the field being absent.
- ✅ Test that a v(N-1) fixture loads under the patched code.

Before merging a PR that **removes** or **renames** a field:
- ❌ This requires a major version bump (0.9.x → 1.0). Not allowed
  within the 0.9 line.

Before merging a PR that **changes the semantics** of a field:
- ❌ Same as removal — major bump only.

These rules are why the on-disk format has been stable for 7 months and
will stay stable for the lifetime of 0.9.
