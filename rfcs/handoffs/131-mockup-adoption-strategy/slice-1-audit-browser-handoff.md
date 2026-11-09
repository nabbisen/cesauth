# RFC 131 §0 slice 1 — the audit browser: a CSR component and the JSON endpoint it needs

**Governing RFC.** [`rfcs/accepted/131-mockup-adoption-strategy.md`](../../accepted/131-mockup-adoption-strategy.md)
§0, slice 1 of six. Carries [RFC 161](../../accepted/161-six-operator-pages-promise-data-and-render-none.md)
§6.3's dropped controls.

**Builds on.** `main` at tag **`0.94.0`** (`d90661d`).

**Target release.** **Minor** — RFC 181's default, **and it genuinely earns one**:
this slice adds `GET /admin/console/audit.json`, a new route surface. Expect the
`0.94.0` gates to say so (§6).

**Tier.** **P2.** Nothing errors. **An operator cannot browse or export the
audit log at all**, on the product's highest-privilege surface, and both halves
of the feature have existed and been tested for releases — only the call between
them was removed (`580eeba`).

**Scope: slice 1 only.** `ROADMAP.md`'s row groups slices 1–2. **I am narrowing
it deliberately**: each slice adds a route surface, a component and its wiring,
so bundling two doubles the review surface and blurs failure attribution.
RFC 131 §0's own table orders the six *"by what an operator loses without it"*
and puts the audit browser first. Slice 2 (chain status) follows as its own cut.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-11-09.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. The state today, verified rather than quoted

Every line below was checked against the tree at `d90661d`:

| | |
|---|---|
| `GET /admin/console/audit` | `lib.rs:290` → `routes::admin::console::audit::page`, whose **entire module is 704 bytes** and returns the Leptos shell and nothing else. Its own doc comment says a prior spec *"describ[ed] a search feature that was never built."* |
| `GET /admin/console/audit.json` | **does not exist.** This is the route the slice adds. |
| `POST /admin/console/audit/export` | `lib.rs:291` → `audit_export::export`, **101 lines, fully built and authorized** — `require_system_admin!(req, ctx, principal, AdminAction::ViewConsole)` at `:18`, CSRF handled, calls `export_audit` against `CloudflareAuditQuerySource`. **It works. Nothing renders a form that invokes it.** |
| `cesauth_core::admin::service::search_audit` | `service/mod.rs:182`. **No production caller** — the only callers are `adapter-test/src/admin/tests.rs` (×3) and a core unit test. This is the browse path, and it is the half with no caller. |
| `cesauth_frontend::admin::audit::audit_page` | **545 lines** (the ROADMAP says 546 — corrected). Re-exported at `admin.rs:37` and **called from nowhere.** |

## 2. `audit_page` is the specification, NOT the basis — and this is the owner's decision, not a preference

`audit_page` is **not a Leptos component.** It is a server-rendering function
with the signature

```rust
pub fn audit_page(principal: &AdminPrincipal, q: &AuditQuery, entries: &[AdminAuditEntry]) -> String
```

that `format!`s six sections: `render_nav`, `render_filter_form`,
`render_export_form`, `render_schema_note`, `render_results`, `render_pager`.

**Do not wire it up.** RFC 131 §0 records the owner's chosen path:

> **Owner's chosen path: finish the CSR migration** — build each component plus
> the JSON endpoint it needs. … Re-pointing the handlers at the existing server
> views was the alternative and **was declined**: it would re-create the two
> rendering paths this RFC exists to collapse.

So `audit_page` is **the most precise available specification of what this
screen must contain** — read all six of its section renderers and reproduce
their behaviour — and the new code is a CSR component under
`crates/frontend/src/pages/operator/`.

**Do not delete `audit_page` in this slice.** RFC 131 R4 says each slice deletes
its template, and that is right — but deleting a 545-line specification on the
strength of its own replacement's author judging parity is backwards. **State
parity per section** (§5.1) and leave the deletion to review. If parity is not
reached on some section, **say which** — a named gap is a correct outcome.

## 3. What to build

**1. `GET /admin/console/audit.json`.** Authorize, parse the query, call
`search_audit`, return JSON. Mirror the shape
`operator_json_api` already establishes for the console's other JSON routes, and
include the CSRF token the export form will need. `AuditQuery`'s fields are in
`core/src/admin/types.rs:503` — note `prefix` is **carried for backward
compatibility and ignored by the D1 backend**, per its own doc comment; do not
build UI for it.

**2. A CSR component** under `crates/frontend/src/pages/operator/`, routed in
`app.rs`, fetching that endpoint — filter form, results table, pager, and **the
export form that posts to the existing route**. The export backend already
works; this is the form that was missing.

**3. RFC 161 §6.3's two controls, on the page handler.** Both are missing from
`audit::page`, which calls `operator_json_api::shell` → `resolve_admin` —
**authentication only, no authorization call.** Add them to the page and the new
JSON route:

- **`ensure_role_allows(AdminAction::ViewConsole)`.** **Be precise about what
  this buys**: `core/src/admin/tests.rs`'s `every_role_may_view_console`
  asserts `role_allows(r, ViewConsole)` for **all four roles** (ReadOnly,
  Security, Operations, Super), so this check **denies nobody today.** It is
  defence in depth and an explicit gate for a future, more restricted role — not
  a live authorization hole. **Do not write it up as one**, and do not describe
  the console as currently unauthorized: it is authenticated.
- **The `AdminConsoleViewed` audit write.** `EventKind::AdminConsoleViewed`
  exists at `backend/src/audit.rs:165` with its string mapping
  `"admin_console_viewed"` at `:440`, **and those are its only two occurrences
  in the workspace — nothing emits it.** So today there is no record of who
  viewed the console. This one is a real missing record, and it is the half
  worth doing carefully.

## 4. Do not

- **Do not wire or delete `audit_page`** (§2).
- **Do not commit mock or fixture data** — RFC 131 §5, at any intermediate step.
- **Do not add CSS.** The CSR app's only stylesheet is `base.css` with one
  `.sr-only` rule (RFC 179); this component will render largely unstyled and
  **that is expected.** RFC 179 §8's import owns it. The RFC 179 census will
  rise — **report the new number, do not suppress it, and do not add names to
  `DECLARED_STYLED`.**
- **Do not change `audit_export::export`.** It works and is authorized.
- **Do not add a `prefix` filter to the UI** (§3.1 — the backend ignores it).
- **Do not reintroduce a `cmd | grep -q` / `| head` / `| awk '…exit'` pipe** into
  any script (RFC 182).
- **Do not touch the other five slices' surfaces.**

## 5. Evidence required

1. **The route the slice adds, named**, and the `0.94.0` route-surface census's
   new reading (§6).
2. **Parity, per section**, against `audit_page`'s six renderers — `nav`,
   `filter form`, `export form`, `schema note`, `results table`, `pager`. One
   row each: reproduced / deliberately different (with the reason) / not done.
3. **The audit write witnessed from the reader's side**, not just emitted:
   view the console, then show the `admin_console_viewed` row as an operator
   would see it. Asserting the enum variant exists is not asserting the caller
   writes it.
4. **`search_audit` has a production caller**, shown — that is slice 1's own
   acceptance criterion in RFC 131 §0.
5. **The export form actually exports**: drive it and show rows out. The backend
   is already proven; the form is what is new.
6. Host tests risen, **awk-summed over the full output**. `migration_chain` 35.
   `route-contracts-check.sh` and `drift-scan.sh` **exit 0** — and
   `route-contracts.md` gains a row for the new JSON route, or E1 will say so.
7. Worker bundle with `sha256sum` **and the gzip level**; it will grow.
8. **If `trunk` still cannot be installed**, say so and name exactly which
   browser-side claims are therefore `observed` rather than `exercised`. Do not
   silently substitute.

## 6. Expect the gates to report route growth — that is what they are for

`0.94.0` added a route-surface census and a level backstop. On this cut:

- the census will read something like
  `route surface vs 0.94.0: 195 pairs -- 1 added, 0 removed`;
- the backstop will read **minor**, and validate nothing — correct, because a
  minor needs no argument (RFC 181);
- `route-contracts-check.sh`'s count moves from **194**.

**None of that is a failure.** If instead the backstop reports a **patch
claim**, the version was bumped wrongly — stop.

## 7. Stop conditions

- Parity on a section needs data `search_audit` cannot return. Name it; do not
  invent a second query path.
- The JSON endpoint would need a `core` port change or a new trait method.
  That is an architecture change and it is not in this slice.
- `audit_page` turns out to render something whose backing data no longer exists
  (the schema note is the likely candidate). **Report it** — a stale
  specification is a finding.
- The `AdminConsoleViewed` write cannot be made on the page path without
  changing `operator_json_api::shell`'s contract for the other five consoles.
  Say so before changing a shared helper that four unbuilt slices will inherit.

## 8. Baselines at `d90661d` (tag `0.94.0`)

| | value | command |
|---|---|---|
| route pairs | **194** | `drift-scan.sh`'s census line |
| routes per `route-contracts-check.sh` | **194**, exit 0 | its `✅` line |
| E6 | `94 = 85 (65 + 0 + 20) + 9 + 0` | same |
| E7 | `156 = 8 + 31 + 117` | same |
| RFC 179 census | `136 = 1 + 135 + 0` | `stylesheet-presence.spec.ts` |
| host tests | **1,677 / 0 / 4**, 12 lines | canonical five-crate command |
| `migration_chain` | **35** | `cargo test -p cesauth-migrate-test` |
| `mdbook` | **82 pages** | `mdbook build docs` |
| Worker bundle | **890,182 B** gzip-default, sha256 `72ddadcbcaef5919` / `486dad37486fd16c` | `wrangler deploy --dry-run`; an **empty** `crates/frontend/dist/assets/` is needed and is sound because `LEPTOS_JS`/`LEPTOS_WASM` are hardcoded consts at `leptos_shell.rs:85-86` |
| `audit_page` | **545 lines**, no caller | `crates/frontend/src/admin/audit.rs` |
| `audit::page` module | **704 bytes**, shell only | `crates/backend/src/routes/admin/console/audit.rs` |
| `search_audit` | no production caller | `crates/core/src/admin/service/mod.rs:182` |
