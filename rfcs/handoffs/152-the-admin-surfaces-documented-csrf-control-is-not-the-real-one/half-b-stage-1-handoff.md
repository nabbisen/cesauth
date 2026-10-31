# Developer Handoff — RFC 152 half B, stage 1: the 34 missing `csrf::verify` calls

**Governing RFC.** `rfcs/accepted/152-the-admin-surfaces-documented-csrf-control-is-not-the-real-one.md` §5 (half B), §6 (stage 2, **not this cycle**).
**Builds on.** `2b2c316` on `main` — tag `0.89.5`, 13/13 CI green.

**Target release.** **0.90.0 — minor.** **Trigger hit: a caller obligation
becomes a requirement.** Thirty-four admin `POST` endpoints begin requiring a
token that nothing sends today, so a request that succeeds before this release
fails after it. Under the `ROADMAP.md` §Versioning policy test that is a
**caller obligation** and an observable difference both; under
`contributing.md`'s level table it is not a fix of something broken — the
surfaces are defended today by `SameSite=Strict` — it is a **second layer added
on purpose**. Minor on either reading, and the owner authorised 0.90.0 as a
minor on 2026-10-30.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-10-31.**

**On 1.0:** not declared, not scoped, not dated. Nothing here is a 1.0
requirement.

---

## 1. What this cycle is, and what it is not

Half A (v0.86.3) made the document true: all 34 cells now read
`N/A (SameSite=Strict)`, and a host test pins the admin cookie string. **This
cycle adds the control the document originally claimed, and then makes the cells
say `required` and mean it.**

**Not in this cycle:** §6's `GET /admin/login` cookie-fixation defect. It is in
the same release (0.90.0) as **stage 2**, its own cycle, dispatched after this
one lands. Do not pre-empt it; `admin_login.rs` is out of scope here except
where stage 1's own changes touch it, which they should not.

## 2. The population — re-derived route-scoped, not directory-scoped

RFC 152 §2 warns that a directory-scoped grep answers the wrong question, and it
is right twice over: **two of the files are outside both surface directories.**
What I ran, and you should be able to reproduce:

```
# 36 POST rows on the two surfaces, and what their CSRF cell claims
awk -F'|' '/^\| POST/ && ($3 ~ /admin\/t\/|admin\/tenancy/) {gsub(/ /,"",$9); print $9}' \
    docs/src/expert/route-contracts.md | sort | uniq -c
#   34 N/A(SameSite=Strict)
#    2 required
```

Each of the 36 rows was then resolved through its `.post_async` registration in
`crates/backend/src/lib.rs` to the handler's module file, and that file checked
for `csrf::verify`. **All 36 resolved; none was unmatched.** Result:

- **2 routes verify** — `/admin/t/:slug/deletion-requests/:id/{cancel,execute}`,
  served from `crates/backend/src/routes/deletions.rs`
  (`admin_cancel`, `admin_execute`), which is **outside both surface
  directories**. These are the RFC 147 cycle-2 routes and they are the pattern
  to copy.
- **34 routes do not**, across **23 files**:

| file | routes |
|---|---|
| `admin/tenancy_console/forms/membership_add.rs` | 3 |
| `admin/tenancy_console/forms/membership_remove.rs` | 3 |
| `admin/tenant_admin/forms/membership_add.rs` | 3 |
| `admin/tenant_admin/forms/membership_remove.rs` | 3 |
| `admin/tenancy_console/forms/group_create.rs` | 2 |
| `admin/tenancy_console/tenant_detail.rs` | 2 |
| `routes/invitations.rs` | 2 |
| `admin/tenancy_console/forms/{group_delete,organization_create,organization_set_status,role_assignment_create,role_assignment_delete,subscription_set_plan,subscription_set_status,tenant_create,tenant_set_status,token_mint}.rs` | 1 each |
| `admin/tenant_admin/forms/{group_create,group_delete,organization_create,organization_set_status,role_assignment_grant,role_assignment_revoke}.rs` | 1 each |

**`routes/invitations.rs` is the second file outside both surface
directories** — `/admin/t/:slug/invitations` and `…/invitations/:id/revoke`.
A `forms/`-scoped or surface-directory-scoped sweep would miss it and
`tenant_detail.rs` both. **Work from the 36-row list, not from the directory
tree.**

## 3. The part the RFC did not size: how the token reaches the form

RFC 152 §5 sized this as *"~32 form templates … none of which currently takes a
token parameter"*. That is right about the templates and it understates the
problem, because **two renderers exist for these forms and only one of them has
any CSRF plumbing at all.**

Measured:

- **21 server-rendered form views** —
  `crates/frontend/src/tenant_admin/forms/*.rs` (8) and
  `crates/frontend/src/tenancy_console/forms/*.rs` (13). **None mentions `csrf`
  in any form** (`grep -rln csrf` over both directories returns 0 files). These
  are what the backend `form` handlers render today, via
  `render::html_response(|| …_form(…))`.
- **A CSR path that already does it correctly**, for two routes:
  `crates/frontend/src/pages/tenant_admin/forms.rs`'s generic `AdminCsrfForm`
  fetches `{ csrf_token }` from a `.json` endpoint, sets no cookie itself, and
  emits `<input type="hidden" name="csrf" …>`. `crates/frontend/src/app.rs`
  has CSR routes for exactly **two** of the 36 paths —
  `/admin/t/:slug/organizations/new` and `/admin/t/:slug/memberships/new`.
- **Four token-serving endpoints exist** on these surfaces
  (`tenant_admin/forms/group_create.rs::form_json`,
  `…/organization_create.rs::form_json`,
  `…/membership_add.rs::form_tenant_json`,
  `tenancy_console/tenant_detail.rs::page_json`), all delegating to
  `json_api::csrf_json()`, which mints, sets the cookie and returns the token.

**Two findings fall out of that measurement, and they are the reason this
section exists:**

1. **For two routes the browser already posts a CSRF token that nothing
   checks.** `AdminCsrfForm` sends `csrf` for `organizations/new` and
   `memberships/new`; their `submit` handlers never call `verify`. The control
   is three-quarters built and the last quarter is missing.
2. **`group_create::form_json` is served and fetched by nothing.** There is no
   CSR route for `/admin/t/:slug/organizations/:oid/groups/new`, so a token
   endpoint exists for a form no one reaches through that path. Not a defect to
   fix here — record it; it belongs with RFC 166's census.

### The decision, made rather than handed to you

**Give the 21 server-rendered views a CSRF token parameter. Do not migrate
these forms to the CSR path in this cycle.**

Why: the SSR views are what an operator actually reaches for 32 of the 34
routes today, so they are where the control has to live for the control to
exist. Migrating 21 forms to CSR would land a UI migration inside a security
fix, and the two-renderer duplication is RFC 131/141's subject, not this
cycle's. Record the duplication; do not resolve it here.

**Concretely, per form route:**

- The **GET `form` handler** mints a token (`crate::csrf::mint()`), appends
  `crate::csrf::set_cookie_header(&token)` to the response, and passes the token
  into the view. `deletions.rs::admin_list` (lines ~303-330) is the exact
  pattern — copy it.
- The **view** gains a `csrf: &str` parameter and emits
  `<input type="hidden" name="csrf" value="{escaped}">`, with `escape()` per the
  RFC 108 escape contract, as `tenant_admin/deletions.rs` already does.
- The **`submit` handler** reads `form.get("csrf")`, compares against
  `crate::csrf::extract_from_cookie_header(&cookie_header)` through
  `crate::csrf::verify`, and returns **400** on mismatch —
  `deletions.rs::admin_cancel` is the pattern.
- **The validation-error re-render must carry a fresh token.** Several `submit`
  handlers re-render their own form with an error message (e.g.
  `tenant_admin/forms/group_create.rs` on an empty slug). A re-render without a
  new token and cookie makes the operator's second attempt fail for a reason the
  page does not explain. **This is the easiest thing in this cycle to get wrong
  and the most user-visible if you do** — the owner's standard is explicit that
  users must not be confused, and "my corrected form was rejected" with no
  stated reason is exactly that.

### The field name

**Use `csrf` for all 34.** It is the dominant name in the codebase — the
generic `AdminCsrfForm`, `audit_export.rs`, `audit_chain.rs`, `me/sessions.rs`,
the TOTP templates and `magic_link/verify.rs` all use it. **Two sites use
`csrf_token`** instead: `deletions.rs`'s `admin_cancel`/`admin_execute` with
`tenant_admin/deletions.rs`'s view, and `invitations.rs`'s own rendered form.
Both pairs are internally consistent and work today. **Do not change them in
this cycle** — changing a working control for naming consistency is a risk with
no security return. Instead, make the inconsistency visible: see E6 below.

## 4. The gate — E6, so a 37th route cannot land without a check

`scripts/route-contracts-check.sh`, as a new section beside E4/E5, using the
**same comment-stripped `lib.rs` extractor the existing sections share**
(`LIB_RS_LIVE`) rather than a fourth private one — RFC 165's finding and
RFC 163's end state both point the same way, and a fourth extractor with a
fourth blind spot is how this project keeps finding the same bug.

E6 asserts, for **every** `POST` row in `route-contracts.md` whose CSRF cell
says `required`: the row's path resolves to a `.post_async` registration in
`lib.rs`, and the handler's module file contains `csrf::verify`. It must:

- **report its own coverage** — rows scanned, rows `required`, rows resolved,
  rows unresolved — and **fail on any unresolved row**, the way E4's census
  arithmetic closes on every run (RFC 159 §4.5);
- **assert a non-zero count**, so a matcher that stops matching fails loudly
  rather than passing vacuously (RFC 125 T5, and my own vacuous semver audit of
  2026-10-30 is the cautionary instance);
- **print the set of distinct CSRF form-field names** found across the
  verifying handlers, with the count. This is how the `csrf` / `csrf_token`
  split above stops being folklore: the number is in every build's output, and
  when someone unifies the names the figure drops to 1 on its own.

The workflow count stays at **14** — E6 goes inside the existing
`route-contracts.yml` gate, so the release-gate manifest's 13 release entries
are unchanged.

## 5. After the checks land, the document goes back

Revert the 34 CSRF cells in `docs/src/expert/route-contracts.md` from
`N/A (SameSite=Strict)` to **`required`**. Half A's cookie test and its
`SameSite=Strict` assertion **stay** — the cookie attribute is still a real
layer and still worth failing loudly when it changes. Two layers, both
documented, is the end state.

## 6. Tests

- **One test per verifying handler is not the ask.** What must exist: for a
  representative handler on each surface (`tenant_admin` and
  `tenancy_console`), a host test that a POST with **no** token is rejected with
  400, one with a **wrong** token is rejected with 400, and one with a matching
  token proceeds. Plus a test on one re-render path that the error response
  **carries a fresh token and a `set-cookie`** — the §3 trap.
- **The 34 as a population** are covered by E6, not by 34 tests. Say so
  explicitly in your report rather than implying per-route coverage.
- Full gate set per `contributing.md` §Running tests. Baselines at `2b2c316`
  (the `0.89.5` tag): host tests **1,636 passed / 0 failed / 12 lines**,
  `migration_chain` **35**, route-contracts **registered 193, E4
  `215 = 193 + 22 + 0`, E5 `16 = 16 + 0 + 0`**, Playwright **20**, manifest
  **13 release + 1 off-path = 14 workflows**, Worker bundle **882,948 B gzip**
  (`872,249` wasm + `10,699` shim). **These figures were measured at `2b2c316`**
  — cite that commit if you quote them, and expect the bundle to move: this
  cycle changes Rust, and the version bump at the cut moves it again.

## 7. What to report

- The 34 call sites, as a count with the command that produced it, and the
  **two** files outside the surface directories named explicitly.
- Which re-render paths existed and how each one now gets its fresh token.
- E6's coverage line, and the distinct-field-name figure it prints.
- Whether anything in the 34 could not take the pattern, and why — a handler
  that cannot read its form twice, a view with no obvious place for the input,
  anything. **One unresolvable site reported costs one line; one papered over
  costs the cycle's credibility.**
- The `AdminCsrfForm` routes: confirm the two CSR-rendered forms work after the
  change, since those post `csrf` from the `.json` endpoint rather than from an
  SSR-minted token and the cookie is set by a different response. **If that
  combination does not verify, say so — it is the one case where my design
  above is least certain**, and I would rather hear it than have it worked
  around.
- Surface-contract disclosure: any request shape that changes for a caller,
  even where correct.

## 8. Stop conditions

Stop and report rather than widening scope if:

- a form's token cannot be delivered without touching `app.rs` or migrating the
  form to CSR — that is the decision in §3 being wrong, and it is mine to
  revisit;
- E6 cannot resolve a row to a handler without a second extractor;
- the fix would require editing `admin_login.rs` (that is stage 2);
- the count of routes needing a check is not 34.
