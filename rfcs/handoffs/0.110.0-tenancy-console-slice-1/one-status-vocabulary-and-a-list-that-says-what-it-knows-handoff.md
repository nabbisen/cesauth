# Developer Handoff — one status vocabulary, and a list that says what it knows

**Target**: `0.110.0`, slice A of three · **Level**: minor
**Decided**: the owner ruled *"finish it"* for the tenancy console
(2026-11-23) and authorized the revised plan.
**Reads first**: `.git-exclude/reviewed/tenancy-console-design-decisions.md`
(D1–D6, settled — do not re-open) and
`.git-exclude/reviewed/tenancy-console-plan-self-review.md` §3 (the
order: this is slice 1 of three)
**Baseline**: `228eed1` / tag `0.109.0`

---

## 1. Purpose

Three things, all on live screens:

1. **The tenant list prints a Rust enum's `Debug` name to operators.**
   `pages/operator/tenancy.rs:107` is `<td>{format!("{:?}", t.status)}</td>`,
   so the cell reads `Active` / `Suspended` / `Pending` / `Deleted` —
   variant names, unkeyed, unlocalised, and silently re-worded by any
   future `rename`. The i18n ceiling cannot see it: it is a formatter,
   not a literal, which is how four slices of i18n work walked past it.
2. **The list drops two columns the data already carries** — `Created`
   and `Id` — which the superseded template had.
3. **A failed read renders as a confident sentence.**
   `routes/admin/tenancy_console/tenants.rs:21` is
   `repo.list_active().await.unwrap_or_default()`, and the component
   renders `TenancyTenantsEmpty` — *"No tenants are registered yet."* /
   「テナントがまだ登録されていません。」 — whenever the list is empty.
   **So a D1 outage tells an operator the deployment has no tenants.**
   That is D5's rule (*a value that could be real must never stand in
   for a value we do not have*) broken on a live screen, and it is worse
   than a plausible number because the sentence asserts a fact.

## 2. Resolved decisions — do not re-open

- **D6 (corrected here): one mapping per enum, in the catalog, and there
  are THREE enums, not the two D6 names.** Parsed from the types rather
  than from the old template's words:

  | enum | variants | where |
  |---|---|---|
  | `TenantStatus` | `Pending`, `Active`, `Suspended`, `Deleted` | `core/src/tenancy/types.rs:44` |
  | `SubscriptionLifecycle` | `Trial`, `Paid`, `Grace` | `core/src/billing/types.rs:119` |
  | `SubscriptionStatus` | `Active`, `PastDue`, `Cancelled`, `Expired` | `core/src/billing/types.rs:130` |

  **This slice mints the `TenantStatus` mapping only** — it is the only
  one with a live rendering today. The other two land with slice 2
  (tenant detail), which is where they are rendered; minting them now
  would be keys with no call site. D6's "two enums" was my error:
  I named them from the template's rendered words instead of parsing the
  types, which is the same mistake this programme has now made six
  times.
- **D5 applies to the list, not only to the overview's counters.** The
  route must stop swallowing the error, and the view must distinguish
  **three** states: *no tenants*, *could not read*, and *here they are*.
  The pattern already exists — `0.108.0`'s three-state column-check line
  on the chain screen — and this is its second use.
- **No new route, no new JSON field.** `Tenant` already carries `id`,
  `slug`, `display_name`, `status`, `created_at`, `updated_at`, and
  `page_json` serialises the whole struct (`"tenants": tenants`). The
  columns need **view** work only.
- **Timestamps go through the canonical formatter**
  (`cesauth_core::util::format_unix_as_iso8601`), which the
  timestamp-rendering gate will enforce the moment you add the column —
  expect its pinned **24 / 15** to move and report the new figure.
- **The overview's counters and the plan breakdown are NOT in this
  slice** (they are slice 3), and tenant detail is slice 2. If you find
  yourself in `routes/admin/tenancy_console/overview.rs`, stop.

## 3. One rename, and it is a disclosed surface change

`TenantRepository::list_active()` is
`SELECT … WHERE status != 'deleted'` — it returns **every non-deleted**
tenant, including `Pending` and `Suspended`. The name says the opposite
of what it does, and this slice is the one making those statuses visible,
so the name will start actively misleading the next reader of either call
site.

**Rename it `list_non_deleted`.** Sites: the trait
(`core/src/tenancy/ports.rs`), both adapters
(`adapter-cloudflare/src/tenancy/tenants.rs`,
`adapter-test/src/tenancy/tenants.rs`), and three callers —
`routes/admin/tenancy_console/tenants.rs`,
`routes/admin/tenancy_console/overview.rs`, **`routes/api_v1/tenants.rs`**
— plus tests. **Leave the four same-named methods on other traits
alone**: `plans::list_active` is `WHERE active = 1`, `session_index`,
`signing_keys` and `grants` are likewise correctly named for their own
semantics. Checked, not assumed.

**Disclose it**: `core::ports` traits are named in `contributing.md` as a
surface that may change between minor versions, so this is permitted and
must be stated in the report and the CHANGELOG.

## 4. Report-and-stop gate

**G1 — the key table.** Four `TenantStatus` values plus the list's new
third state, in both locales. For each, say **what an operator concludes**
— and for the three-state set, the hard one is the difference between
*"no tenants are registered"* and *"the list could not be read"*: the
first is a fact about the deployment, the second is a fact about this
request, and an operator seeing the wrong one takes the wrong action.

Submit it before touching the view. Everything else proceeds.

## 5. Change scope

| file | change |
|---|---|
| `crates/core/src/i18n/mod.rs`, `i18n/tests/lookup_completeness.rs` | T1 — G1's keys, both lists |
| `crates/core/src/i18n/…` (the mapping's home — your call, stated in the report) | T2 — `TenantStatus → MessageKey`, **exhaustive `match`, no `_` arm** |
| `crates/backend/src/routes/admin/tenancy_console/tenants.rs` | T3 — stop swallowing the error; serve a shape that distinguishes failure |
| `crates/frontend/src/pages/operator/tenancy.rs` | T4 — the keyed status cell, the two columns, the three states |
| `crates/core/src/tenancy/ports.rs`, both adapters, three callers, tests | T5 — the rename (§3) |
| `scripts/drift-scan.sh` | T6 — the timestamp-rendering pin, if the new column moves it |
| `docs/src/expert/route-contracts.md` | T7 — if `tenants.json`'s shape changes for T3 |

## 6. Task detail worth stating explicitly

- **T2's exhaustiveness is the point.** No `_ =>` arm anywhere in the
  mapping, so a fifth `TenantStatus` variant is a compile error rather
  than a blank cell. The audit-column gate's own design note
  (`0.108.0`) makes the same argument about a `match` versus a list.
- **T3's shape**: the simplest honest option is for `page_json` to
  **fail** (a 5xx) when the repository errors, and for the component's
  existing fetch-failure path to render — the same all-or-nothing choice
  D5 made for the counters. If you serve a partial success instead, say
  why in the report; do not invent a sentinel.
- **T4's status cell** renders `lookup(status_key(t.status), locale)`.
  `format!("{:?}", …)` must not survive anywhere in this file — and
  while you are here, grep the whole crate for `{:?}` in a view
  position and **report what you find** (do not fix other screens in
  this slice; slice 2 and 3 own their own).
- **The `Created` column** uses the canonical formatter. The `Id` column
  renders in a `<code>`, like the slug does.
- **Ceiling prediction**: `pages/operator/tenancy.rs` is pinned at **0**
  and must stay **0** — every new string goes through `lookup`. If it
  moves, something went in as a literal.

## 7. Required tests and evidence

The canonical host-test command, quoted literally — baseline
**1,779 / 0 / 4 across 12 lines**:

```bash
cargo test -p cesauth-core \
           -p cesauth-adapter-test \
           -p cesauth-frontend \
           -p cesauth-backend \
           -p cesauth-adapter-cloudflare \
           --features cesauth-frontend/csr > .git-exclude/review-request/0.110.0a-evidence/host-tests.log 2>&1

cargo test -p cesauth-migrate-test --test migration_chain > .git-exclude/review-request/0.110.0a-evidence/migrate.log 2>&1
cargo check -p cesauth-backend --target wasm32-unknown-unknown > .git-exclude/review-request/0.110.0a-evidence/wasm32.log 2>&1
cargo check -p cesauth-frontend --target wasm32-unknown-unknown --features csr > .git-exclude/review-request/0.110.0a-evidence/csr-check.log 2>&1
bash scripts/route-contracts-check.sh > .git-exclude/review-request/0.110.0a-evidence/route-contracts.log 2>&1
bash scripts/drift-scan.sh > .git-exclude/review-request/0.110.0a-evidence/drift-scan.log 2>&1
```

**Write evidence paths in full, as above** — `rfcs/handoffs/TEMPLATE.md`
§10 now requires it, after a bare path put 570 KB of logs in the tracked
tree at `0.109.0`.

**Cases that must exist:**

1. **Every `TenantStatus` variant maps to a distinct, non-empty value in
   both locales** — four variants × two locales, asserted, not spot-
   checked. (The completeness walk already covers "resolves to
   non-empty"; this asserts *distinct*, so two statuses can never read
   the same.)
2. **The three list states**, as pure functions where possible: empty
   list → the "no tenants" key; a repository error → the failure path;
   a populated list → rows. The error case is the one that does not
   exist today.
3. **The rename compiles everywhere and the double agrees** — the
   adapter-test implementation renamed too, not just the trait.
4. **No `{:?}` in a view position** in `pages/operator/tenancy.rs`,
   asserted by grep in the report rather than by a test.

**G2 — real HTTP, three requests** under `wrangler dev --local` (read
`contributing.md`'s note on the two local sqlite files first): the list
with two tenants of **different statuses** (showing the keyed words, the
`Created` column formatted, the `Id` column), in **both locales**, and —
the one that matters — **the same route with the tenants table dropped or
renamed**, showing the failure state rather than *"No tenants are
registered yet."* Full headers, token-free, `grep -ciE
"bearer|authorization"` → 0.

## 8. What must NOT be claimed

- **Not that the tenancy console is finished.** This is slice 1 of
  three; the overview still shows one counter and tenant detail still
  shows four links.
- **Not that the i18n ceiling proves the `{:?}` class is gone** — it
  cannot see formatters, which is the whole reason this defect survived.
  Say what the grep covered.
- **Not that `list_non_deleted` changes behaviour.** It is a rename; the
  SQL is untouched.

## 9. Acceptance criteria

1. No `format!("{:?}", …)` in a view position in
   `pages/operator/tenancy.rs`; status renders from an exhaustive
   `TenantStatus → MessageKey` mapping, both locales.
2. `Created` (canonical formatter) and `Id` columns present.
3. A repository failure is distinguishable from an empty list, on
   screen, in both locales — and the route no longer swallows the error.
4. `list_active` → `list_non_deleted` everywhere, disclosed.
5. G1 ruled before the view; G2's three requests captured, including the
   failure case.
6. Host **≥ 1,779 / 0 / 4 across 12 lines**, migrate **39**, **197
   routes**, `drift-scan` clean with `pages/operator/tenancy.rs` still
   **0**, audit column coverage **16 — 8/7/1**, and the
   timestamp-rendering pin updated if the new column moved it.

## 10. Known risks

- **The failure state is easy to half-build**: a route that returns 5xx
  and a component that renders "no tenants" for both is the same defect
  with extra steps. Test (2) is what catches it.
- **The rename crosses a public API route** (`api_v1/tenants.rs`). It is
  a rename, not a behaviour change, but it is the one place where a
  missed site would be visible to a caller rather than to the compiler —
  the compiler does catch it; the disclosure is what the report owes.

## 11. Review request

`.git-exclude/review-request/0.110.0a-keys.md` for G1, then
`.git-exclude/review-request/0.110.0a-report.md`, evidence under
`.git-exclude/review-request/0.110.0a-evidence/`. Report the entry-point
path only.
