# Developer Handoff — RFC 162, implementation

**Governing RFC.** `rfcs/done/162-two-console-pages-fetch-urls-nothing-serves.md`
**Builds on.** `main` at the 0.89.2 tag or later. Nothing to revert.

**Target release.** **Patch.** Number assigned at the cut, not here.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-10-30.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. Deliverable (0) first, and it is a report-and-stop

**Do not change a line until this is done and reported.** RFC 162 §3: the
mismatch is established from the route table and the fetch URLs; **the behaviour
is not.** Against `wrangler dev` + local D1:

1. `curl` `/admin/t/<slug>.json` and `/admin/tenancy/tenants/<tid>.json` with an
   admin bearer and **record the actual status and the first line of the body**.
   The prediction is that `:slug` / `:tid` capture the literal `"<x>.json"` and
   the HTML page handler answers — so you get `200` and HTML, not a 404. Record
   what actually happens.
2. Navigate **client-side** into the tenant-admin overview as a tenant owner —
   from a link, not a fresh load — and **record what the page shows.** RFC 158's
   walkthrough is how to get such a token.
3. **Hard-load the same URL** and record that it differs.

**If step 1 shows either URL is somehow served correctly, stop and report.** The
RFC's premise is then wrong and nothing gets fixed until that is explained.

I re-derived the static half at dispatch so you are not working from a quoted
census (RFC 162 §6's own lesson). **16 `.json` URLs the frontend references, 2
defective**, and they are the two the RFC names:

```
/admin/tenancy/tenants/{tid}.json   ->  GET /admin/tenancy/tenants/:tid    SWALLOWED by :tid
/admin/t/{slug}.json                ->  GET /admin/t/:slug                 SWALLOWED by :slug
```

The other fourteen resolve to an exact route. Note that
`/admin/t/:slug/organizations/new.json` **is** registered (`lib.rs:409`) and is
*not* a defect — see §3's trap, which I walked into myself.

## 2. Deliverable (1) — the two URLs

Assuming §1 confirms the mechanism: point both at the routes that exist.

- `crates/frontend/src/pages/tenant_admin/overview.rs:17` →
  `/admin/t/{slug}/detail.json` (`lib.rs:393`)
- `crates/frontend/src/pages/operator/tenancy.rs:129` →
  `/admin/tenancy/tenants/{tid}/detail.json` (`lib.rs:330`)

**Both pages discard the failure with `.ok()`.** Fixing the URL makes the happy
path work and leaves the silent-failure path exactly as it was. The project's
standing rule is that a `.ok()`-discarded secondary operation needs a witness
for what the caller sees when it fails — so **one test per page asserting what
renders when the fetch does not return the expected shape**, not just that it
renders when it does. If that is not reachable from the host (CSR components,
RFC 146 §2), say so in one line and assert the nearest pure thing instead.

## 3. Deliverable (2) — the inverse check, and the trap I hit building a prototype

*Every URL the frontend fetches has a route.* RFC 159's E4 asks whether a
handler is reachable; this asks whether a fetch is.

- **It must handle `format!`-built URLs**, because **both defects are in one** —
  a literal-only scan finds neither.
- **It must resolve the way a router does: literal segments before captures.**
  My first prototype took the first matching route instead of the most literal,
  and reported `/admin/t/:slug/organizations/new.json` as a third defect
  swallowed by `:oid`. It is not — the literal route is registered one line
  away. **I nearly handed you a false positive**, and a check that manufactures
  those is worse than no check, because the first one teaches everyone to pass
  `-E4_EXEMPT`-shaped flags. Rank candidate routes by number of capture
  segments, fewest first.
- **Its fires/does-not-fire pair must include exactly this shape:** a fetch path
  that is a *prefix of a real route plus a suffix*, which is what makes these
  two match a capture instead of 404ing. A probe that only tests a completely
  unrouted path does not exercise the defect class.
- **Print a coverage figure every run** — URLs scanned, resolved exactly,
  resolved via capture, unresolved — with the parts summing to the total. That
  is now the project's rule (RFC 159 §4.3), and the figure is what let me
  reconcile 16 = 14 + 2 + 0 in one read.
- **One home, no new workflow.** It belongs in `route-contracts-check.sh` beside
  E4, so the manifest stays at **13** and needs no edit.

## 4. Deliverable (3) — re-check the remaining fourteen *with the check*

RFC 162 §4.3: four of the sixteen were spot-checked by hand while the RFC was
written, and I re-derived all sixteen at dispatch. **Neither is the same as
checked by the thing that will keep checking.** Run it and report the figure.

## 5. `TenancyFormPlaceholder` — delete it, do not exempt it

`crates/frontend/src/pages/operator/tenancy.rs:190` builds a third broken URL
(`format!("{}.json", form_action)`, against form routes whose `.json`
companions RFC 157 deleted) and does not parse the response at all, only checks
`status() == 200`.

**It has no usage.** I verified at dispatch: `grep -rn TenancyFormPlaceholder
crates/` returns exactly one line — its own definition. It is dead frontend
code, RFC 159's class on the other side of the wire.

**Delete the component.** RFC 162 §5 is explicit that it must **not** be
exempted: an exemption whose first entry is dead code is how an exemption list
stops being read, which is the argument that settled RFC 159's tenth handler.
Deleting it is also what makes the new check pass honestly rather than by
permission.

## 6. Scope — four things that are not yours

1. **RFC 159's gate.** Finished and shipped in 0.89.2. Do not touch E4.
2. **RFC 161's six disconnected console pages** and RFC 131's slices. Adjacent,
   much larger, owner-approved on a separate track.
3. **The `.ok()` idiom elsewhere in the frontend.** Fix the two pages in §2;
   do not sweep the codebase for `.ok()`.
4. **`route-contracts.md` rendering columns.** RFC 161 §9(a) owns the
   documentation corrections; a row you touch here is a collision.

## 7. Gates

Full set, with counts and their commands. Baselines as of the 0.89.2 tag: host
tests **1,630** passed / 0 failed / 12 `test result` lines; `migration_chain`
**35**; registered routes **193**; E4 scanned **215** = 193 handlers (182+11) +
22 named + 0 unclassified; manifest **13**; Playwright **20**; bundle
**882,908 B** gzip at 33.7% of budget with full 64-character sha256 per module
and the parts reconciled.

**Host tests and the bundle will both move this time** — two frontend source
changes plus new tests plus a deleted component. That is expected; report the
new figures with their deltas and say which change accounts for each. A figure
that moves without an explanation is the finding, not the figure itself.

## 8. Back-fill

Propose the Status and Evidence lines in RFC 000 §22's terms. Deliverable (0)'s
observations are the evidence that decides between `exercised` and `observed` —
if you cannot complete the client-side navigation in step 2, say so plainly and
propose the weaker term rather than the stronger one.

Report into `.git-exclude/review-request/`.
