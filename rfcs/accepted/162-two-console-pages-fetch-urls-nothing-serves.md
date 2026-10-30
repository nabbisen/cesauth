# RFC 162 — Two console pages fetch URLs nothing serves

**Status.** **Accepted** 2026-10-30. **Next to dispatch — patch**: two wrong URLs
and a check, the same shape that made RFC 159's deletions-plus-a-gate a patch.
**0.89.2 is cut, so this is unblocked.** Patch number assigned at dispatch,
not here — pinning one to an undispatched RFC only creates churn when the order
changes, which it has once already.
**Deliverable (0) in §3 is a report-and-stop**: if `curl` shows either URL is
somehow served, this RFC's premise is wrong and nothing gets fixed until that
is explained.
**Tier.** **P1.** One of the two is the **tenant-admin overview** — the first
page a tenant's owner lands on, on the console RFC 158 spent four cycles making
reachable for the first time in the project's history. It asks for a URL no
route serves and **swallows the failure**, so the page renders without its
data and without an error.
**Size.** Small for the two URLs. The check in §4 is the lasting part.
**Touches.** `crates/frontend/src/pages/tenant_admin/overview.rs`,
`crates/frontend/src/pages/operator/tenancy.rs`, and a new or extended routing
check.
**Found by.** The architect, 2026-10-29, while verifying RFC 159's claim that
*"the frontend fetches five `.json` paths and all five are routed."* It fetches
**sixteen**, and two of them are not routed.

## 1. Summary

Two client-rendered console pages build a JSON URL that **no registered route
matches**, and both discard the resulting failure:

| Page | Fetches | Route that exists |
|---|---|---|
| `tenant_admin/overview.rs:17` — **tenant-admin overview** | `/admin/t/{slug}.json` | `/admin/t/:slug/detail.json` (`lib.rs:393`) |
| `operator/tenancy.rs:129` — system-admin tenant detail | `/admin/tenancy/tenants/{tid}.json` | `/admin/tenancy/tenants/:tid/detail.json` (`lib.rs:330`) |

**The same mistake, made twice, in the two pages that show one record's
detail** — and only in those two. The other six tenant-admin fetches
(`users.json`, `organizations.json`, `subscription.json`, `invitations.json`,
`organizations/new.json`, `memberships/new.json`) each match a registered route
exactly.

## 2. What is established — textually, which is why §3 is deliverable (0)

- **The URL set.** `grep -rho '"[^"]*\.json"' crates/frontend/src` plus the
  `format!`-built ones gives **16** distinct `.json` paths the frontend
  references. RFC 159 §2 said five; it had counted only the operator-console
  subset. The nine dead handlers that RFC found are still unreferenced by any
  of the sixteen, so **its conclusion is unaffected** — only its count was.
- **Neither URL is routed.** `grep -c '"/admin/t/:slug.json"'` and
  `'"/admin/tenancy/tenants/:tid.json"'` against `lib.rs` → **0** and **0**.
- **What they will match instead.** `/admin/t/:slug` (`lib.rs:392`) and
  `/admin/tenancy/tenants/:tid` (`lib.rs:329`) are both registered, and a
  path-segment capture takes the whole segment — so `/admin/t/acme.json`
  resolves `:slug` to the literal `"acme.json"`. **This is RFC 145 cycle 3's
  mechanism exactly**, where `path!("/admin/tenancy/tenants/:tid")` captured
  the literal `new`, and it is recorded in that cycle's own handler comment.
- **The failure is swallowed.** `overview.rs` does
  `r.json::<OverviewData>().await.ok()`; `tenancy.rs` the same. A parse failure
  becomes `None` — no error, no log, no status code the operator sees. **The
  page renders its empty branch.**
- **When it is visible.** Both paths are *also* server-rendered, so a hard load
  of `/admin/t/acme` returns the real HTML page. The broken fetch only runs on
  **client-side navigation** into the page, which is how the console's own
  links work. So the same URL behaves differently depending on how you
  arrived — which is worse than a plain failure, and is the specific thing the
  owner's standard rules out.

## 3. Deliverable (0): observe it before fixing it

**The mismatch is established from the route table and the fetch URLs. The
behaviour is not.** Before any change, against `wrangler dev` + local D1:

1. `curl` `/admin/t/<slug>.json` and `/admin/tenancy/tenants/<tid>.json` with
   an admin token and **record the actual status and body** — whether the
   `:slug`/`:tid` route answers with HTML, a 404, or something else.
2. Navigate **client-side** into the tenant-admin overview (from a link, not a
   fresh load) as a tenant owner — RFC 158's walkthrough shows how to get such
   a token — and **record what the page shows.**
3. Hard-load the same URL and record that it differs.

If step 1 shows the request is somehow served, this RFC's premise is wrong and
that is a report-and-stop.

## 4. Direction

1. **Point both fetches at the routes that exist** — `…/detail.json`. Two
   one-line changes, assuming §3 confirms the mechanism.
2. **Then the check, which is the point, and it is the inverse of RFC 159's.**
   RFC 159 guards *"every handler has a route"*; this one guards **"every URL
   the frontend fetches has a route."** A `.json` literal or `format!` template
   in `crates/frontend/src` whose path — with `{…}` segments treated as
   captures — matches no registration in `lib.rs` fails the build.
   - It must handle the `format!` forms, since **both defects are in
     `format!`-built URLs** and a literal-only scan finds neither.
   - Its fires/does-not-fire pair must include **exactly this shape**: a fetch
     whose path is a *prefix* of a real route plus a suffix, which is what makes
     these two match a capture instead of 404ing.
3. **Re-check the remaining fourteen** with the check rather than by eye. Four
   of the sixteen (`/me/security*`) were spot-checked by hand while writing
   this and matched; that is not the same as checked.

## 5. Not in scope

- **RFC 159's nine handlers.** Different direction, different RFC, already
  dispatched. **Its check and this one are siblings and may end up in the same
  script, but they are not the same check** and RFC 159's cycle was told not to
  build this one.
- **`TenancyFormPlaceholder`** (`operator/tenancy.rs:190`) builds a third
  broken URL — `format!("{}.json", form_action)` against form routes whose
  `.json` companions RFC 157 deleted — and its body does not parse the response
  at all, only checks `status() == 200`, with a comment saying so. **It has no
  usage**: `grep -rn TenancyFormPlaceholder` returns only its definition. So it
  is dead frontend code, RFC 159's class on the other side of the wire, and it
  is recorded here rather than fixed. If the check in §4 is built, it should
  **not** be exempted — deleting the component is the honest way to make it
  pass.
- The six placeholder pages of RFC 161.

## 6. The lesson worth keeping in the record

**This was found by checking a sentence I wrote.** RFC 159 §2 asserted that the
frontend fetches five `.json` paths and that all five are routed. I had
believed it enough to repeat it into a handoff. The grep that disproves it is
one command, and it also disproves the "all are routed" half — on the console
whose reachability the previous four cycles were about.

**Two RFCs in a row have now turned on a population I stated and had not
enumerated** — RFC 160 §4.8's `contains("constraint failed")`, and this. The
pattern is not carelessness about greps; it is **quoting a census instead of
re-running it**, and the fix is mechanical: a count that appears in an RFC gets
re-derived at the moment it is used to justify a decision, not when it was
first written.
