# RFC 131 §0 slice 2 — chain status: wire up the reader that has never been called

**Governing RFC.** `rfcs/accepted/131-mockup-adoption-strategy.md` §0, slice 2.
**Target release.** **`0.97.0`, minor — earned**, not defaulted: it adds
`GET /admin/console/audit/chain.json`, a new route surface. Scope authorized by
the owner 2026-11-10; the ROADMAP row `0.97.0 — THE NEXT CUT` is the contract.
**Box.** Small. Most of this slice already exists and is unreachable.
**Two deliverables**: slice 2 (§3) and one defect fix (§4). They share a cut
because the second is small and the first is the cut in front of it.

---

## 1. The state today, verified at source rather than quoted

Checked 2026-11-10 against `816293f` (tag `0.96.0`). Re-check anything you
intend to rely on; do not re-derive what is below.

| thing | where | state |
|---|---|---|
| `GET /admin/console/audit/chain` | `lib.rs:293` → `audit_chain::page` | serves `operator_json_api::shell` and **nothing else** (`audit_chain.rs:36`) |
| `POST /admin/console/audit/chain/verify` | `lib.rs:294` → `audit_chain::verify_now` | **real, complete, CSRF-verified, role-checked** — and **no form anywhere in the workspace posts to it** |
| `read_status(env) -> AuditChainStatus` | `audit_chain.rs:76` | **finished, 30 lines, zero callers.** `cargo check -p cesauth-backend` prints `function read_status is never used` and has since `580eeba` |
| `AuditChainStatus` | `core/src/admin/types.rs:539` | 10 fields, already `#[derive(Serialize, Deserialize)]` |
| `audit_chain_status_page` | `frontend/src/admin/audit_chain.rs:26`, 280 lines, 6 tests | the specification. **No caller.** |
| `ConsoleAuditChain` | `frontend/src/pages/operator/console.rs:150` | **an honest 7-line stub** that says the screen is unimplemented and there is no way to trigger verification from it. Already routed at `app.rs:102`. |

**So this slice is wiring, not writing.** The data assembly, the type, its
serialization, the action route and its authorization all exist. What is missing
is the JSON endpoint and a component.

## 2. Resolved decisions — do not re-open

- **Strings are Japanese**, matching every other CSR page (`clients`, `console`,
  `tenancy`, and slice 1's `audit`). **The template is hardcoded *English*** —
  that is a pre-existing inconsistency in the operator console, not a
  requirement to copy. Do not translate the template's English into the
  component; write the Japanese the stub already uses as its register.
- **No message catalog.** `audit_chain_status_page` makes **zero** `lookup`
  calls, so unlike slice 1 there is no catalog coverage to preserve. Whether the
  CSR console adopts the catalog at all is an open product question on the
  ROADMAP and is **not** this slice's to settle.
- **`audit_chain_status_page` is not deleted this slice**, same discipline as
  slice 1: parity is recorded per block, and the deletion is review's call.
  Slice 1's deletion is itself still blocked — see §7.
- **`read_status` is reused, not rewritten.** If you believe it is wrong, say so
  and stop (§6); do not quietly replace it.

## 3. Deliverable A — slice 2

**A1. `GET /admin/console/audit/chain.json`.** Register it in `lib.rs` beside
`:293`. Follow **slice 1's module**, `routes/admin/console/audit.rs`, as the
shape to copy: `require_system_admin!(req, ctx, principal, AdminAction::ViewConsole)`,
then the payload. Deliberately **not** via `operator_json_api::shell` — slice 1's
module doc at `audit.rs:17-21` explains why and that reasoning carries.

Payload: the `AuditChainStatus` fields plus a `csrf_token`, because the
verify-now form needs one. `read_status` is private — make it `pub(crate)` or
call it from within its own module; either is fine, but say which.

**A2. RFC 161 §6.3's two controls on the page handler**, as slice 1 restored
them: `ensure_role_allows(AdminAction::ViewConsole)` and the
`EventKind::AdminConsoleViewed` write. `verify_now` **already has** the role
check (`audit_chain.rs:44`); `page` has neither. The audit write is best-effort —
a failed write must not block the render, and slice 1's comment says so at its
own site.

**A3. The component.** Replace the `ConsoleAuditChain` stub. Put it in its own
module, `frontend/src/pages/operator/audit_chain.rs`, mirroring slice 1's
`pages/operator/audit.rs`, and leave `console.rs`'s other seven stubs alone.
Four blocks, same order as the template:

1. **nav back** to the audit log (`audit_chain.rs:48`).
2. **summary** — the status badge, chain length, last verification, rows walked,
   and the growth hint. **The badge has five states** (`render_summary`,
   `:56-77`): no runs yet; chain valid; tamper at `seq=N`; chain-history
   mismatch (checkpoint disagrees, no single seq to name); verification failed.
   **Reproduce all five.** They are the whole point of the screen, and four of
   them are how an operator learns the audit log was tampered with.
3. **checkpoint** — including the cold-start empty state (`:111-115`) and the
   three consistency states.
4. **verify-now form** — `POST` to `/admin/console/audit/chain/verify` with the
   `csrf` hidden field, and the warning copy about a full re-walk. The route
   answers **302 to the page**, so the browser navigates and the component
   refetches; that is the intended flow, not a defect to work around.

Timestamps go through `cesauth_core::util::format_unix_as_iso8601` (RFC 111 /
ADR-013 §Q4) — do not format dates inline.

**A4. `route-contracts.md` gains a row** for the new route, or E1 fails the
build and tells you so.

## 4. Deliverable B — the export silently drops the operator's date range

**Live in shipped `0.95.0`. Found while scoping this slice.**

`pages/operator/audit.rs:246-252` renders exactly three hidden fields — `csrf`,
`subject`, `event`. `routes/admin/console/audit_export.rs:55-56` reads **`since`
and `until`**, as Unix seconds. The template's own export form sent five
(`subject`/`event`/`since`/`until`/`format`).

**Consequence**: an operator narrows to a period, sees that table, clicks
**Export CSV**, and downloads *everything* — with nothing on screen saying the
period was dropped. The export's own audit record builds its `filter=` string
from `event_exact` only, so the record does not show it either.

**Fix**: convert the two RFC 3339 filter inputs to Unix seconds and emit them as
`since`/`until` hidden fields. Use
`cesauth_core::admin::service::audit_pagination::parse_rfc3339_to_unix`
(`core/src/admin/service/audit_pagination.rs:126`, unconditional — no feature
gate, and the frontend crate already depends on core). **Do not write a second
date parser**; §6 covers what to do if it turns out not to compile under `csr`.
An empty or unparseable input omits the field, matching how the `.json` query
already treats an unset filter.

**Note for the report, not a question to answer here**: slice 1's own parity
table claimed the CSR export form carried *"the same four hidden fields plus
`csrf`"*. It does not. The architect accepted that claim and signed the tag on
it. State it plainly in your report; it is a review failure, not an implementer
one.

## 5. Evidence required

Slice 1's evidence shape held up well; keep it.

- **Host tests** for every pure helper you add, and for all five badge states and
  the checkpoint cold start. The canonical five-crate command, summed
  programmatically — never by hand-adding `test result:` lines.
- **Both new endpoints driven over real HTTP** against a running worker with
  local D1/KV: `chain.json` on a cold store (no checkpoint, no runs) **and**
  after a verification has run, so the empty states are exercised rather than
  argued. Then **post the verify-now form** and show the 302 and the changed
  status — this route has **never had a caller**, so this is its first exercise.
- **Deliverable B exercised**: two exports differing only by the period, with
  **different row counts**, and the `since`/`until` values that produced them.
  A test that only asserts the fields render is not enough — the point is that
  the server now receives them.
- **The dead-code warning count**: `cargo check -p cesauth-backend` prints **8**
  today; it should print **7** after A1. Report the number, and if it does not
  fall, that means `read_status` still has no caller and something is wrong.
- **Evidence terms** per RFC 000 §22, drawn honestly. `trunk` is still
  uninstallable (`libdeflate-sys` against GCC 16.2.1), so the component's own
  rendering is **`unknown`**, not `observed`. Say so; do not upgrade it.
- **Gate figures**, each with the command that produced it, against §8's
  baselines. Expect growth and report it rather than suppressing it: route
  surface **+1**, E5 **18 → 19**, E3 and E4 scanned counts **+1**, RFC 179
  census up, bundle up.
- **Bundle** with `sha256sum` beside `du -b` **and the gzip level**.

## 6. Report-and-stop gates

Stop and report; do not work around:

- `read_status` turns out to be wrong, stale, or to read a store that no longer
  exists. It has never run. **Finding that is a success for this slice**, not a
  failure — say what is wrong and stop.
- `parse_rfc3339_to_unix` does not compile for `wasm32` under the `csr` feature.
  Report it; **do not** duplicate the parser into the frontend.
- A full re-walk on the local chain does not complete, or the 302 does not
  arrive. A Worker has a wall-clock budget and `verify_chain_full` walks from
  genesis. **If this screen can make an operator trigger unbounded work, that is
  a finding worth more than the screen** — report the chain length you tested at
  and what happened.
- The `AdminConsoleViewed` write or the role check cannot be added without
  widening `operator_json_api::shell`'s contract. Slice 1 refused to widen it for
  exactly this reason.

## 7. Explicit non-change scope

- **`operations_page` / `operations.json`.** RFC 131 §0's parenthetical assigns
  `operations_page` to slice 2's cycle. **The architect narrowed that
  deliberately** — it is a second surface with its own dead reader (`CronRecord`)
  and its own already-registered CSRF-only `operations.json`, so it has its own
  row. Do not pull it in.
- **`audit_page`'s 545 lines.** Not deleted. It now blocks on a product question
  the owner has not answered (does the operator console carry `Locale::En`?).
- **The other six `console.rs` stubs**, slices 3–6, the Kani trial, and the 13
  compiler warnings — each has its own row.
- **Any change to `verify_chain_full` or the cron.** Both work.

## 8. Baselines at `816293f` (tag `0.96.0`)

| gate | value | command |
|---|---|---|
| host tests | **1,687 / 0 / 4**, 12 `test result:` lines | the canonical five-crate command |
| `migration_chain` | **35** | `cargo test -p cesauth-migrate-test` |
| `route-contracts-check.sh` | exit 0; E3 **47** = 0+2+0; GATE_42 **24**; NONCE **13**; E4 **217** = 193 (182+11) + 24 + 0; E5 **18**; E6 **94** = 85 (65+0+20) + 9 + 0; E7 **156** = 8 + 31 (5+26) + 117; ✅ **All 195 routes** | `./scripts/route-contracts-check.sh` |
| `drift-scan.sh` | exit 0, clean; route surface **195 pairs — 0 added, 0 removed** | `./scripts/drift-scan.sh` |
| RFC 179 census | **139** — static arithmetic only; the live run is still blocked by the `trunk` failure, so **the partition is not measured** and this handoff does not state one | `e2e/specs/stylesheet-presence.spec.ts` |
| mdbook | **82 pages** | `mdbook build docs` |
| backend warnings | **8** (`read_status`, `CronRecord`, six in `tenancy_console/overview.rs`) | `touch crates/backend/src/lib.rs && cargo check -p cesauth-backend` |
| Worker bundle | **893,683 B** gzip at default level (882,984 wasm + 10,699 `shim.js`), sha256 `34383dd60ccd8dd4…` / `34278883c9fabd74…` | `./node_modules/.bin/wrangler deploy --dry-run --outdir bundled/`, measured **after** the version bump |
| `cargo audit`, `cargo deny check advisories` | both exit 0 | — |

## 9. Review request

File the report at `.git-exclude/review-request/131-slice2-chain-status-report.md`
and name it to the architect. Include the parity table per block (nav, summary
with all five badge states, checkpoint with its three consistency states and the
cold start, verify-now form), and state explicitly which blocks are
**deliberately different** and why — slice 1's table did that well, and its one
false row is the reason §4 exists.
