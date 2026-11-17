# Developer Handoff — RFC 111, the canonical formatter, actually canonical

**Target**: `0.107.0`, slice A of two · **Level**: minor
**RFC**: `rfcs/done/111-date-rendering-policy.md` (Status: *Implemented, v0.73.0*)
**Policy document**: `docs/src/expert/i18n.md` §"Date / time rendering" (lines 44–49)
**Baseline**: `996cd22` / tag `0.106.0`

---

## 1. Purpose

RFC 111's Status line says *"`cesauth_core::util::format_unix_as_iso8601` is
the single formatter, **per-file legacy formatters removed**"*. The tree
disagrees in **fifteen** places. This slice makes the claim true, and
gates it so it cannot quietly stop being true again.

## 2. Why this matters

`i18n.md:46` is unambiguous: *"UTC ISO-8601 (RFC 3339) for every visible
timestamp, locale-independent"*, emitted by
`format_unix_as_iso8601(unix) -> String` in the `Z` form
(`2024-01-01T00:00:00Z`). Three things are true at once today:

1. **The audit viewer prints raw epoch integers under a header that says
   `時刻 (UTC)` / *"Time (UTC)"***. `pages/operator/audit.rs:372` renders
   `{e.ts}` — an `i64` — in the column whose key is
   `AuditViewerColTime`. The sibling screen in the same programme,
   `pages/operator/audit_chain.rs`, formats the same kind of value
   correctly at `:219` and `:230`. One audit family, two behaviours.
2. **Two per-file formatters survive and neither emits ISO-8601.**
   `pages/sessions.rs:209` and `pages/operator/clients.rs:82` both render
   `2024-01-01 00:00` — no `T`, no seconds, no `Z`. `sessions.rs`'s own
   comment says *"For now emit ISO-8601 which browsers render
   reasonably"* about a format that is not ISO-8601. Meanwhile
   `templates/security_center.rs:268-269` shows the **same session
   timestamps** through the canonical formatter, so the two security
   surfaces disagree with each other for one user's data.
3. **`0.106.0` made one header honest about its zone while its value
   stayed wrong.** That release keyed the clients table's column as
   `作成日時 (UTC)` / *"Created (UTC)"* on RFC 111's own grounds. The cell
   under it still renders `2024-01-01 00:00`. Half a fix is this slice's
   debt, and it was recorded as such at the time.

And the thing that should have caught all of it: `admin/tests.rs:520-562`
is a test module named `rfc_111` whose own comment opens *"**Every**
visible timestamp in cesauth goes through
`cesauth_core::util::format_unix_as_iso8601`"* — and whose four tests pin
the formatter's output in isolation and no caller at all. The universal
claim is in a comment; nothing asserts it. **That is what §9's gate is
for**, and it is the project's own recurring failure mode: a documented
rule with no enforcement.

## 3. Resolved decisions — do not re-open

- **D1. The format is settled: UTC ISO-8601, `Z` form, locale-independent.**
  RFC 111 decided it, `i18n.md:46` documents it, and `admin/tests.rs`'s
  `canonical_formatter_never_emits_offset_form` pins `Z` over `+00:00`.
  Do not propose a friendlier rendering in this slice.
- **D2. Relative times (*"3 hours ago"*), per-user timezones and
  locale-specific date separators are out.** RFC 111 §out-of-scope lists
  all three, and the per-user timezone question is ADR-013 Q1, which is
  the owner's. A row exists; this slice does not touch it.
- **D3. Every site goes through `format_unix_as_iso8601`. No new local
  helper, not even a one-line wrapper.** The point of the slice is that
  there is one formatter.
- **D4. The unreachable-today templates are converted too, not
  exempted.** Nine of the fifteen sites sit in files no backend route
  reaches (§4 names each). Exempting them by name would build a gate with
  nine holes on day one, and five of those files are the *parked
  implementations* whose CSR replacements still say *"not yet implemented
  (RFC 161)"* — they are the code that gets ported, not deleted.
- **D5. No API or wire change.** The JSON keeps sending `i64` seconds;
  this is presentation only. If you find yourself editing a serialised
  struct, stop and report.

## 4. Facts already measured — do not re-derive

**The fifteen sites.** Reproduce this census structurally before you
trust it (§5 asks you to), but these are the architect's figures:

**Live — reachable from a backend route today (5):**

| site | what it renders | how it is wrong |
|---|---|---|
| `pages/operator/audit.rs:372` | `{e.ts}` | raw epoch under `AuditViewerColTime` (*"Time (UTC)"*) |
| `pages/sessions.rs:209` (`format_ts`) | `created_at`, `last_seen_at` | per-file formatter, `2024-01-01 00:00` |
| `pages/operator/clients.rs:82` (`format_created_at`) | `created_at` | per-file formatter, same shape |
| `tenancy_console/subscription.rs:56` | `e.occurred_at` | raw epoch (`subscription_history_page`, live from `routes/admin/tenancy_console/subscription.rs:49`) |
| `tenancy_console/organizations.rs:128` | `o.created_at` | raw epoch (`organization_detail_page`, live from two routes) |

**Unreachable today — no backend route resolves their page fn (10):**

`admin/alerts.rs:81` (`raised_at`), `admin/config.rs:126` (`updated_at`),
`admin/overview.rs:99` (`e.ts`), `admin/overview.rs:129`
(`last_verified_at`), `admin/safety.rs:185` (`last_verified_at`),
`admin/cost.rs:88` (`previous_taken_at` — the only one that labels itself,
*"taken at unix {ts}"*), `tenancy_console/tenant_detail.rs:101` and `:102`
(`created_at`, `updated_at`), `tenancy_console/tenants.rs:40`
(`created_at`), `tenant_admin/subscription.rs:45` (`occurred_at`).

**Already conforming — leave alone:**
`pages/operator/audit_chain.rs:219,230`; `pages/security_center.rs:100`;
`templates/security_center.rs:268,269`; `backend/src/cron_status.rs`;
`core/src/admin/service/audit_export.rs`.

**Other measured facts:**

- `grep -rn "from_unix_timestamp" crates/` outside `core/src/util.rs` has
  **four** hits: the two per-file formatters, one doc comment in
  `i18n/mod.rs:671`, and `adapter-cloudflare/src/admin/metrics.rs:137`,
  which is **not a display site** (it builds an `OffsetDateTime` for
  bucket arithmetic). After this slice, the count under
  `crates/frontend/src` is **0**.
- **No existing test asserts a raw-epoch display.** The only epoch-shaped
  assertion in the tree is `tenant_admin/tests/mutation_forms.rs:158-169`,
  which asserts `name="expires_at" value="1735689600"` — a **form input
  value an operator types**, not rendered prose. It must keep its raw
  form, and it is the reason §9's vocabulary needs an input-field
  exemption.
- **No e2e spec asserts a timestamp**: `grep -rn "toISOString\|timestamp"
  e2e/specs/*.ts` → no output.
- `admin/tests.rs` fixtures already use `last_verified_at: Some(1_000_000)`
  and `created_at: 0`, and **no test asserts the rendered value**, so the
  conversions break nothing and the new assertions are additions.
- **Ceiling prediction: unchanged, all rows.** The format strings you
  delete (`"{:04}-{:02}-{:02} {:02}:{:02}"`) and the `"—"` fallbacks carry
  no Latin letters, so the matcher never counted them. If any ceiling row
  moves, something else changed — say so rather than adjusting the row.

## 5. Report-and-stop gates

**G1 — the gate's population, before you build the gate.** Submit a
census of every timestamp render site under `crates/frontend/src`,
derived **structurally** (parse the field declarations and the render
sites; do not grep for candidates and call it a population — the
architect's own `ts` matcher first returned 44 "raw bindings" that
included `pts`, `tstatus_url` and `role_assignments`). The submission
must carry:

1. The **vocabulary**: every `i64` field name you treat as a timestamp,
   and how you derived the list rather than hand-writing it.
2. The **census**: each site, live or unreachable, with its current
   state. Agreement with §4's fifteen is not required — **a different
   number with a method beats agreement without one**, and the last two
   slices both found an architect's count wrong that way.
3. The **exemptions**, each by name with a reason: at minimum the
   `expires_at` form-input values (`tenant_admin/forms/role_assignment_grant.rs`,
   `tenancy_console/forms/role_assignment_create.rs`), and anything else
   your parse flags that is not a rendered timestamp.

**Stop and submit G1 before writing §9's gate.** T1–T4 do **not** wait
for the ruling: the fifteen sites are named above and their conversion is
not what G1 decides. G1 decides what the *gate* may claim.

## 6. Change scope

| file | change |
|---|---|
| `crates/frontend/src/pages/operator/audit.rs` | T1 — format `e.ts` |
| `crates/frontend/src/pages/sessions.rs` | T2 — delete `format_ts`, call the canonical formatter, fix the comment (T4) |
| `crates/frontend/src/pages/operator/clients.rs` | T2 — delete `format_created_at`, call the canonical formatter |
| `crates/frontend/src/tenancy_console/{subscription,organizations}.rs` | T1 — format, live server-rendered |
| `crates/frontend/src/tenancy_console/{tenant_detail,tenants}.rs` | T1 — format, unreachable today (D4) |
| `crates/frontend/src/admin/{alerts,config,overview,safety,cost}.rs` | T1 — format, unreachable today (D4) |
| `crates/frontend/src/tenant_admin/subscription.rs` | T1 — format, unreachable today (D4) |
| `crates/frontend/src/admin/tests.rs` + the families' test modules | T5 — the caller assertions |
| `scripts/drift-scan.sh` | T6 — the gate (after G1) |
| `rfcs/done/111-date-rendering-policy.md` | T7 — the record |
| `docs/src/expert/i18n.md` | T7 — only if the Z/offset wording needs it; it currently reads correctly |

## 7. Explicit non-change scope

- **No `Cargo.toml`, no dependency.** `format_unix_as_iso8601` is already
  in `cesauth-core`, which every one of these files already depends on.
- **No serialised struct, no route, no query parameter.** 197 routes, 0
  added, 0 removed.
- **No deletion of the unreachable templates.** Whether those thirteen
  files (253 ceiling literals) are superseded duplicates to delete or
  parked implementations to port is a separate analysis the architect has
  rowed. Converting a timestamp in them costs one line; deciding their
  fate does not belong in this slice.
- **No i18n keys.** Timestamps are locale-independent by D1, so nothing
  here touches the catalog. Catalog stays at **314** arms.
- **No change to `adapter-cloudflare/src/admin/metrics.rs:137`** — not a
  display site.
- **No new local formatter, wrapper or helper** (D3).

## 8. Task detail worth stating explicitly

- **T2's two deletions are deletions.** Do not leave `format_ts` or
  `format_created_at` in place delegating to the canonical formatter; the
  Status line this slice is making true says *removed*.
- **`Option<i64>` sites keep their fallback.** `admin/overview.rs:129`,
  `admin/safety.rs:185` and `admin/cost.rs:88` match on an `Option`; the
  `None` arm stays exactly as it is (`never`, or the first-snapshot
  sentence). Only the `Some(ts)` arm changes.
- **`admin/cost.rs:88` loses the word `unix`.** Its sentence reads
  *"Previous baseline taken at unix {ts}."* Once the value is an ISO-8601
  string, *"unix"* is wrong. It is an English literal in an unconverted
  file, so rewrite it as *"Previous baseline taken at {ts}."* and expect
  that file's ceiling row to drop by **0** (the sentence is one counted
  literal either way) — verify rather than assume.
- **The server-rendered sites escape their values already**; an ISO-8601
  string needs no escaping change, but do not drop an existing
  `escape(...)` call on a neighbouring field while editing the line.
- **T4's comment.** `pages/sessions.rs:210-212` currently explains that
  it emits ISO-8601 "which browsers render reasonably". Replace it with
  what is true: the canonical formatter, named, with the reason the
  project uses UTC (`i18n.md` §"Date / time rendering"), and no claim
  about browsers.
- **T7's record has three parts**: (a) RFC 111's **Status** line, which
  must stop claiming per-file formatters were removed in v0.73.0 and say
  when it actually became true; (b) RFC 111's §Design and §Test strategy
  examples, which still show the **`+00:00`** form the canonical
  formatter does not emit (`admin/tests.rs` pins `Z` and calls the change
  an amendment, so the RFC body is the stale copy); (c)
  `admin/tests.rs:520-527`'s module comment, whose *"every visible
  timestamp"* claim becomes true only once §9's gate exists — point it at
  the gate rather than leaving a universal claim guarded by four unit
  tests.

## 9. Assert machine-checkable things mechanically

The gate goes in `scripts/drift-scan.sh`, after the i18n ceiling section
and before the negotiation gate, in the shape the negotiation gate
established (a pinned population, failure in both directions, every
exemption named in the script).

**Part A — the structural half, which is exact.** RFC 111's own
acceptance criterion, never built:

```bash
# zero `from_unix_timestamp` under crates/frontend/src, and zero
# hand-rolled date format strings
grep -rn "from_unix_timestamp" crates/frontend/src | wc -l   # want 0
grep -rnE '\{:0?4\}-\{:0?2\}' crates/frontend/src | wc -l    # want 0
```

**Part B — the census half, which needs G1's ruling.** Every render site
whose value is a timestamp field must pass through
`format_unix_as_iso8601`. Report in one line, the negotiation gate's
shape:

```
ℹ️   timestamp rendering: scanned N site(s) across M file(s) -- K formatted, E exempted by name, want N == K + E
```

and fail if (a) any scanned site is neither formatted nor exempted, or
(b) the scanned count moves off its pin. **Prove both directions fire
before you land it** — the negotiation gate was accepted last cut partly
because review could break it three ways and watch it catch all three,
and that is now the bar.

## 10. Required tests and evidence

The canonical host-test command, which is **12 `test result:` lines** —
quoted literally, not referenced:

```bash
cargo test -p cesauth-core \
           -p cesauth-adapter-test \
           -p cesauth-frontend \
           -p cesauth-backend \
           -p cesauth-adapter-cloudflare \
           --features cesauth-frontend/csr > 111-evidence/host-tests.log 2>&1

cargo test -p cesauth-migrate-test --test migration_chain > 111-evidence/migrate.log 2>&1
cargo check -p cesauth-backend --target wasm32-unknown-unknown > 111-evidence/wasm32.log 2>&1
cargo check -p cesauth-frontend --target wasm32-unknown-unknown --features csr > 111-evidence/csr-check.log 2>&1
bash scripts/route-contracts-check.sh > 111-evidence/route-contracts.log 2>&1
bash scripts/drift-scan.sh > 111-evidence/drift-scan.log 2>&1
```

Baseline to beat: host **1,732 / 0 / 4 across 12 lines**, migrate **39**,
**197 routes** with all seven coverage figures, ceiling **103 / 65 / 69,
0 violations**, negotiation **13 / 13**.

**T5 — the caller tests, which is the part the suite has never had.** One
assertion per family, each rendering a page with a fixture timestamp and
asserting the **rendered HTML** carries the formatted string:

- `1_704_067_200` → `2024-01-01T00:00:00Z` is the anchor `admin/tests.rs`
  already uses; reuse it so the two test modules agree.
- Cover, at minimum: one `admin/*` page, `tenancy_console/subscription.rs`,
  `tenancy_console/organizations.rs`, `tenant_admin/subscription.rs`.
  These are pure `fn … -> String`, so the assertion is direct.
- Assert the **negative** too, on at least one: the raw epoch digits must
  **not** appear (`assert!(!html.contains("1704067200"))`). A site that
  prints both would otherwise pass.

**The three CSR sites cannot have a caller test, and the report must say
so in one line rather than substituting one.** `pages/operator/audit.rs`,
`pages/sessions.rs` and `pages/operator/clients.rs` are Leptos components
needing a reactive runtime; the host suite cannot render them (this is
the same limit `clients.rs`'s own pure-helper split was built around).
Their coverage is §9's gate plus the existing formatter pins — state that
plainly.

**G2 — real HTTP, two requests, which is cheap here because two of the
live sites are server-rendered.** Under `wrangler dev --local` with the
`ADMIN_API_KEY` bootstrap path:

1. `GET` the tenancy-console subscription-history route and show the
   rendered cell carrying `…T…:…Z`.
2. `GET` the organization-detail route and show the same.

Full response headers in the log, the admin token redacted or absent —
and assert in the report that `grep -ciE "bearer|authorization"` over the
log is **0**, as the last four rounds have.

## 11. What must NOT be claimed

- **Not that RFC 111 is now enforced everywhere.** The gate covers
  `crates/frontend/src`. `crates/backend/src` and `crates/core/src` format
  timestamps too (`cron_status.rs`, `audit_export.rs`), and they are
  conforming today but **ungated**. Say which directory the gate reads.
- **Not that the unreachable templates are dead code.** They are
  unreachable *today*; five of them are the only implementations of
  screens whose CSR replacements say *"not yet implemented (RFC 161)"*.
- **Not that the display is now friendlier.** It is now *consistent and
  unambiguous*. `/me/security/sessions` changes from `2024-01-01 00:00`
  to `2024-01-01T00:00:00Z` for end users — a visible change, in both
  locales, that the release entry must name.
- **Not that no test needed updating** unless you verified it: §4 predicts
  none, and a prediction is not a measurement.

## 12. Prohibited shortcuts

- Do not run `cargo test --workspace --all-features`. It is not a
  superset of the canonical command: it adds binaries and silently drops
  everything behind `--features cesauth-frontend/csr`.
  `contributing.md:495-504` documents the exact symptom.
- Do not add a local wrapper to "keep the call sites short" (D3).
- Do not exempt a site from §9's gate to make it green. Exemptions are
  named in the script with reasons, ruled at G1, and the whole point of
  the census is that the population is derived rather than chosen.
- Do not adjust a ceiling row to match an unexpected count. Report it.
- Do not touch `ROADMAP.md`'s or `CHANGELOG.md`'s size — that is slice B,
  and it has its own handoff.

## 13. Acceptance criteria

1. All fifteen sites render through `format_unix_as_iso8601`; both
   per-file formatters are gone; `grep -rn "from_unix_timestamp"
   crates/frontend/src` is empty.
2. G1's census submitted and ruled before the gate landed.
3. `drift-scan` carries the gate, green, with both failure directions
   demonstrated in the report.
4. Host **≥ 1,732 / 0 / 4 across 12 lines** (new tests raise the first
   number; a lower one or a different line count is a signal), migrate
   **39**, **197 routes**, ceiling **103 / 65 / 69** with every row
   unchanged, negotiation **13 / 13**.
5. Two G2 requests, logged, token-free.
6. RFC 111's Status, its `+00:00` examples and `admin/tests.rs`'s module
   comment all corrected.

## 14. Known risks

- **The census matcher is the risk, not the conversion.** Three
  extractors in this programme have had three different blind spots, and
  the architect's first pass at this one over-matched `ts` inside unrelated
  identifiers. Derive the vocabulary; do not write it from memory.
- **`admin/cost.rs`'s sentence** is the one conversion that changes
  English prose, so it interacts with the i18n ceiling. Measure.
- **An `Option` arm is easy to convert twice** (formatting in both the
  `Some` arm and the surrounding `format!`). The negative assertion in
  T5 catches it.

## 15. Review request

Write `.git-exclude/review-request/111-formatter-census.md` for G1, then
`.git-exclude/review-request/111-formatter-report.md` for the
implementation, with evidence under `111-evidence/`. Report the
entry-point path only.
