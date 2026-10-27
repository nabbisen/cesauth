# Developer Handoff — RFC 145 cycle 3, the tenancy console's dead pages and the §4.2 gate

**Governing RFC.** `rfcs/accepted/145-admin-pages-answer-200-and-render-not-found.md`
— read **§11** (triage), **§13** (the compiler's worklist), and **§15**, which
accepts cycle 2 and **corrects my own route count**. §15.1 and §15.2 are
prerequisites for the gate, not background.

**Target release.** 0.86.2 — **and why that level: patch.** All 21 routes have a
template already present in `crates/frontend/src/tenancy_console/`; I checked
every one. Cycle 2's shape, third surface. No screen is designed.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-10-27.**

**This cycle closes RFC 145**, so it must satisfy RFC 000 §22: the RFC is
**P1** and cannot enter `done/` on `reviewed` alone. §9 says what that means
here, and §9 is written to be *constructible* this time — see §9.0.

---

## 1. Scope — 21 routes, measured

```
/admin/tenancy: client-declared GET rows 24   live 3   DEAD 21
  of the dead: 20 with no route at all, 1 param-shadowed
```

Whole-repo cross-check, which reconciles against cycle 2: **45** client-declared
GET rows (57 − 12 converted), **22** dead (34 − 12), being these 21 plus
`/admin/console/clients`, which **RFC 141 cycle 2 owns and is out of scope**.

| # | Route (GET) | Template |
|---|---|---|
| 1 | `/admin/tenancy/organizations/:oid` | `organizations::organization_detail_page` |
| 2 | `/admin/tenancy/organizations/:oid/status` | `forms::organization_set_status::form_page` |
| 3 | `/admin/tenancy/organizations/:oid/groups/new` | `forms::group_create::for_organization` |
| 4 | `/admin/tenancy/organizations/:oid/memberships/new` | `forms::membership_add::for_organization` |
| 5 | `/admin/tenancy/organizations/:oid/memberships/:uid/delete` | `forms::membership_remove::for_organization` |
| 6 | `/admin/tenancy/groups/:gid/delete` | `forms::group_delete::confirm_page` |
| 7 | `/admin/tenancy/groups/:gid/memberships/new` | `forms::membership_add::for_group` |
| 8 | `/admin/tenancy/groups/:gid/memberships/:uid/delete` | `forms::membership_remove::for_group` |
| 9 | `/admin/tenancy/role_assignments/:id/delete` | `forms::role_assignment_delete::confirm_page` |
| 10 | **`/admin/tenancy/tenants/new`** | `forms::tenant_create::tenant_create_form` — **see §2** |
| 11 | `/admin/tenancy/tenants/:tid/status` | `forms::tenant_set_status::form_page` |
| 12 | `/admin/tenancy/tenants/:tid/groups/new` | `forms::group_create::for_tenant` |
| 13 | `/admin/tenancy/tenants/:tid/memberships/new` | `forms::membership_add::for_tenant` |
| 14 | `/admin/tenancy/tenants/:tid/memberships/:uid/delete` | `forms::membership_remove::for_tenant` |
| 15 | `/admin/tenancy/tenants/:tid/organizations/new` | `forms::organization_create::organization_create_form` |
| 16 | `/admin/tenancy/tenants/:tid/subscription/history` | `subscription::subscription_history_page` |
| 17 | `/admin/tenancy/tenants/:tid/subscription/plan` | `forms::subscription_set_plan::form_page` |
| 18 | `/admin/tenancy/tenants/:tid/subscription/status` | `forms::subscription_set_status::form_page` |
| 19 | `/admin/tenancy/users/:uid/role_assignments` | `role_assignments::user_role_assignments_page` |
| 20 | `/admin/tenancy/users/:uid/role_assignments/new` | `forms::role_assignment_create::role_assignment_create_form` |
| 21 | `/admin/tenancy/users/:uid/tokens/new` | `forms::token_mint::form_page` |

**A proposal, not a measurement** — verify each before using it, as cycle 2 did.
The three **live** rows that stay `client` are `/admin/tenancy`,
`/admin/tenancy/tenants` and `/admin/tenancy/tenants/:tid`.

## 2. Route 10 is a different defect and must be reported separately

The other 20 have no client route at all, so the shell's fallback renders
`<NotFound/>`. **`/admin/tenancy/tenants/new` has no route of its own but is
captured by `path!("/admin/tenancy/tenants/:tid")`** — the literal `new` binds
to `:tid`. It therefore renders **the tenant-detail page for a tenant whose id
is the string `"new"`**: not a Not Found, a different and plausible-looking
page. A system admin trying to create a tenant is misled rather than informed.

Wiring it like the other 20 fixes the symptom — once the GET is `server` and
renders `tenant_create_form`, the client router never sees the path. **But the
shadow stays latent in `app.rs`**, and would return the moment anyone
re-declared the row `client`. Say in your report whether you also made `app.rs`
unambiguous, and why or why not. **The gate in §3 is what must catch the
latent case**, so do not treat wiring route 10 as closing it.

## 3. The §4.2 gate — the deliverable that outlives the cycle

A `client`-declared `GET` row whose path has no matching `path!()` route in
`crates/frontend/src/app.rs` **fails the check**.

**The hard part is "matching", and I got it wrong three times.** Use this; do
not re-derive it:

| Attempt | Rule I used | What it got wrong |
|---|---|---|
| 1 | a `:param` in `app.rs` matches any segment | **False live.** `path!(".../tenants/:tid")` swallowed the literal `new`, so route 10 scored live and the count came out 33 instead of 34 |
| 2 | "exact" = the `app.rs` route contains no params | **False dead.** `/admin/tenancy/tenants/:tid` is matched param-to-param by an identical route, and was reported dead |
| 3 | **exact = segment lists are equal; otherwise a param-over-literal match is a *shadow*, which counts as dead** | correct on all 45 rows, and reconciles with cycle 2's arithmetic |

So the check must distinguish **three** outcomes, not two: **exact** (pass),
**shadowed** (fail, and say so — the message must name the shadowing route),
and **absent** (fail).

**The fires/does-not-fire pair must cover all three**, because attempts 1 and 2
each passed a pair built only from the absent case:

1. a `client` row with **no** route → the check fails;
2. a `client` row **shadowed** by a param route → the check fails, naming the
   shadow;
3. a `client` row matched **param-to-param exactly** → the check **passes**.

A pair that only proves (1) proves nothing about the class that produced route
10. **This is the acceptance criterion for the gate, not a nice-to-have.**
E3's own history is why: RFC 145 §11.2 showed E3 passing on a wrapper-shaped
call for all 35 routes it was believed to cover.

**Sequencing:** the gate lands **last**, after the 21 are converted, or it
fails the tree while the triage is in progress.

## 4. Resolved decisions — do not re-open

- **Patch level.** If the triage forces a genuine screen build, **stop and
  report**; do not promote the release yourself.
- **Your handler must not call `set_render_nonce`** — `render::html_response`
  owns it (RFC 146). RFC 150 covers the seven responders outside that helper
  and is **0.86.3**, not yours.
- **Rows become `server` as you convert them**, so E3 guards each as it lands.
- **Do not run `cargo fix`** on these modules. It would delete the unused
  imports that *are* the compiler's report of this defect (RFC 145 §13.2).
  `-D warnings` stays off; after this cycle I re-measure and enable the two
  lints that carry signal.

## 5. Report-and-stop gates

- a route whose template does not fit, or needs arguments a fresh GET cannot
  supply — **report what it needs, do not invent a screen** (§11.3's precedent);
- a route that wants deletion rather than wiring, and whose `.json` companion
  has another consumer;
- a handler doing something other than returning the shell — cycle 1 found that
  and it became RFC 147;
- **any row in §1's table where my template is wrong.** Say which and why;
- **an evidence requirement in §9 you cannot construct.** See §9.0.

## 6. Explicit non-scope

`/admin/console/clients` (RFC 141 cycle 2) · the seven nonce-less responders
(RFC 150, 0.86.3) · the admin CSRF documentation (RFC 152 half A, 0.86.3) ·
`-D warnings` · how the screens *look* (RFC 131 R3).

## 7. Deliverable (0) — reproduce the classification

Before any code, reproduce **24 rows / 3 live / 21 dead** on `/admin/tenancy`
and **45 / 23 / 22** repo-wide, and confirm the three-way classification in §3
on all 45 rows. If any of my numbers is wrong, **say so and give the command** —
that outcome is as useful as agreement, and my count has now been wrong twice in
this RFC.

## 8. Required evidence

RFC 145 is **P1** and closes under RFC 000 §22. Deliver **`exercised`**.

### 8.0 Read this before §8.1 — the requirement is deliberately narrower than cycle 2's

Cycle 2's handoff asked for "a test per route asserting **the response** is the
real page". **That cannot be built on the host**: `worker::Response` wraps
`web_sys` with no host constructor, which RFC 146 §2 established with a probe.
**My handoff was wrong to ask**, cycle 2 substituted template-level tests
silently, and the consequence is that cycle 2's twelve tests do not guard the
wiring at all — a handler reverted to the shell still passes every one of them.

So, explicitly:

- **§8.1 is template-level and is only expected to guard template output.**
- **The wiring guard is E3 plus §3's new gate**, and those are what justify
  `exercised`.
- If any requirement below still cannot be constructed, **§5's last gate
  applies**: one line saying so beats a silent substitution.

### 8.1 A test per converted route

21 host tests, each calling the template function the handler now renders with
the arguments a fresh GET supplies, asserting a string **only that template
emits**. Never assert the *absence* of a shell marker — an empty body satisfies
that too.

### 8.2 The gate's three-way pair

§3's three cases, each demonstrated by actually making the check fail and pass.
Paste the output.

### 8.3 E3 on a route you did not pick

Revert one converted handler to `operator_json_api::shell(...)`, show
`route-contracts-check.sh` fails, restore it byte-identically, show it passes.
**Choose a `forms::*` handler**, not a top-level page — in cycle 2 I verified
`forms::group_delete::form` myself precisely because the cycle demonstrated
only a top-level one.

### 8.4 The warning count, re-measured

Command plus before and after. Cycle 2 moved **191 → 162**. State which
categories moved and which did not; `req`/`ctx` were untouched by cycle 2
because they belong to this surface, so they should move now.

### 8.5 The full gate set

All thirteen, with counts. **Take the host-test count with CI's exact command**
(`.github/workflows/test.yml:51-55`, five crates, **no `--lib`**) and **sum it
programmatically** — cycle 2 reported 1,561 against the true **1,568** by
dropping the 7 doc-tests, which is the exclusion RFC 136 C2-136 removed on
purpose.

## 9. What must not be claimed

- Not "every admin page now renders": `/admin/console/clients` remains, and it
  is RFC 141's. Say 21-of-21 of this cycle's scope, or say the number.
- Not that the gate "prevents a thirty-sixth" unless §8.2's three-way pair is
  in the report. Attempts 1 and 2 above would both have claimed that falsely.
- Not that route 10 is fixed in the same sense as the other 20 — §2.
- No count in prose without the command that produced it, and no derived total
  without checking it against its own parts.

## 10. Acceptance criteria

- 21 routes triaged, each into one of §4's three outcomes, each with a test.
- The §4.2 gate landing last, with the three-way fires/does-not-fire evidence.
- `route-contracts.md` rows updated to match what the code does.
- Deliverable (0) answered.
- All thirteen gates green, with counts.
- **A proposed `**Status**` line for RFC 145** under RFC 000 §22, naming the
  evidence term and the specific gate or test that justifies it. It will be
  read closely: cycle 2's proposal credited twelve tests that do not guard what
  they were said to guard.

## 11. Review request

Write the package to `.git-exclude/review-request/145-cycle3-report.md` and
give me the commit. I verify independently before anything is tagged.
