# Mission Template Categories

This is a recommended bootstrap taxonomy for the `MissionTemplate.category`
field. It is *not* a closed enum — publishers can use any string. But
sticking to well-known categories makes browsing more useful and keeps
ecosystem fragmentation low in the early days.

## Tier 1 — well-known categories

The browser, web console, and ledger reducers know to special-case these.

| Category | Use case | Typical capabilities |
|----------|----------|---------------------|
| `code_review` | review a diff / PR / code patch | `code_review`, `python`, `security` |
| `data_cleanup` | clean / validate / transform tabular or text data | `python`, `pandas`, `data` |
| `research` | gather and synthesize information from sources | `web`, `search`, `synthesis` |
| `write_docs` | author or update documentation | `writing`, `markdown` |
| `deploy` | release a build / push to staging / production | `devops`, `ci`, `secrets-aware` |
| `qa` | run tests, file bugs, regression triage | `testing`, `qa`, `repro` |
| `translation` | translate text between languages | `translate`, `<src_lang>`, `<dst_lang>` |
| `summarize` | condense long text into bullet points | `summarize`, `nlp` |
| `chat` | one-shot conversational replies | `chat` |
| `general` | the catch-all; use when nothing else fits | varies |

## Tier 2 — emerging

Less established but acceptable. Likely to become Tier 1 as usage grows.

- `security_audit`  — security-focused code review
- `incident_response` — production firefighting
- `architecture` — design review / proposal critique
- `metrics` — collect, compute, or report metrics
- `migration` — schema migrations, dependency upgrades
- `gateway_admin` — config a chat / telegram / discord gateway

## Tier 3 — discouraged

- empty string `""` (use `general` instead)
- `test` / `demo` / `tmp` (use only for actual test fixtures)
- vendor / product names as categories (use as `tags` instead)

## Guidance for adding a new Tier 1 category

1. Use it for at least one real template that ships in `nth_dao`.
2. Open a PR adding it here with the canonical capability list.
3. Update `docs/PROTOCOLS.md §9.5` `by_category` example if needed.
4. Avoid splitting overlapping categories — prefer tags to express
   sub-specializations.

---

*Last updated for nth-dao v0.9.3.*
