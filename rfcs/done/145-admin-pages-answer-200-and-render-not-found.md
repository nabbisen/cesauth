# RFC 145 — Thirty-five admin pages answer 200 and render "Not Found"

**Status.** **Done** — cycles 1–3 accepted; **shipped v0.85.1 (cycle 1), v0.86.1
(cycle 2), v0.86.2 (cycle 3)**. **`exercised`** (RFC 000 §22): the
`route-contracts-check.sh` gates — E3 (no `server`-declared handler reaches the
shell) and **§4.2** (no `client`-declared row is *absent* or *shadowed* in
`app.rs`) — run on every change and fail on a reversion of any of the 35 routes
converted. Demonstrated live for all three §4.2 outcomes and for E3 on both a
top-level page and a `forms::*` handler, and independently re-verified by the
architect on an absent route, a shadow shape that does not occur in the tree,
and a param-to-param exact match. The 12+21 template-level host tests
(cycles 2–3) additionally guard each converted template's rendered output but
**do not by themselves guard the wiring** — a handler reverted to the shell
passes them unchanged; E3 and §4.2 are what catch that.
**Tier.** P1 — one of the thirty-five is linked from a working console screen,
so an operator following the UI reaches a Not Found page.
**Size.** Medium. The triage is small per route; the count is what makes it
medium.
**Touches.** `crates/frontend/src/app.rs`, `docs/src/expert/route-contracts.md`,
`scripts/route-contracts-check.sh`, and whichever backend routes the triage
deletes.
**Depends on.** Nothing. Overlaps RFC 141 §4.1 and RFC 131 R3 — see §6.
**Found by.** The architect, 2026-10-25, while scoping RFC 141 cycle 2
immediately after the 0.85.0 cut.

## 1. Summary

**Thirty-five `GET` routes documented as client-rendered serve the Leptos shell,
and the client-side router has no route for any of them.** The router's
`fallback` renders `<NotFound/>`, so each one answers **HTTP 200** with a Not
Found page — after passing an admin authentication check.

`route-contracts.md` documents each of them with a view: "client list",
"client", a form. No code produces those views.

## 2. What is established

Every figure here carries the command that produced it.

**The counts.** Comparing `render=client` `GET` rows in
`docs/src/expert/route-contracts.md` against `path!("…")` in
`crates/frontend/src/app.rs`, matching `:param` segments positionally:

```
GET routes documented render=client:                60
frontend path!() routes:                            25
documented client routes with NO frontend route:    35
```

**All thirty-five reach the shell.** Resolving each route's `get_async` handler
in `lib.rs` to its function body: 24 call
`routes::admin::operator_json_api::shell`, and 11 — all under
`admin::tenant_admin::forms::` — call `admin::tenant_admin::json_api::shell`.
Both helpers are two-line wrappers that call
`crate::routes::leptos_shell::leptos_html_shell`
(`operator_json_api.rs:38`, `tenant_admin/json_api.rs:48`). **0 unresolved.**

**The fallback.** `crates/frontend/src/app.rs:57` —
`<Routes fallback=|| view! { <NotFound/> }>`. All 27 `path!(` occurrences in the
crate are in `app.rs`, there are **0** `<Route` declarations anywhere else, and
there is no `ParentRoute` or second `<Routes>`, so the route set is complete and
the fallback is what these thirty-five get.

**One of them is reachable by navigation.**
`crates/frontend/src/pages/operator/console.rs:106` renders
`<a href="/admin/console/tokens/new">` on the tokens console screen, which
works. `/admin/console/tokens/new` is one of the thirty-five. An operator who
follows the UI to issue a token lands on a Not Found page.

The other console nav links — `alerts`, `audit`, `config`, `cost`,
`operations`, `safety`, `tokens` — all have frontend routes and work.
`/admin/console/clients` is linked from nowhere
(`grep -rn 'href="/admin/console/clients'` → **0**).

**It is long-standing, and 0.85.0 added one.** Running the same comparison
against `git show 0.84.3:…`:

```
0.84.3: client-declared GETs 59, frontend routes 26, unmatched 34
0.85.0: client-declared GETs 60, frontend routes 25, unmatched 35
new in 0.85.0: ['/admin/console/clients']
```

The frontend count fell 26 → 25 because RFC 143 deleted the TOTP verify route,
which is the intended effect of that work and not part of this.

## 3. Why nothing caught it

Three gates look at this area and none of them can see it.

- **E3 (RFC 132)** asserts that a route **declared `server`** does not call
  `leptos_html_shell`. These routes are declared **`client`**, so E3 is silent
  by construction — correctly, for what E3 is.
- **The route-contracts check** compares *registered* routes against
  *documented* routes, in both directions. These routes are **registered and
  documented**, so both directions pass. Nothing compares the documented
  **render** column against the code that would have to exist for it to be true.
- **The compiler** sees a complete `app.rs` and complete handlers. A route
  nobody declared in the client router is not an error; it is a path the router
  was never asked about.

This is the same structural blind spot as RFC 141 §13's six unregistered
`page_json` handlers — a fact that lives in **neither** of the two sets a
bidirectional check compares — approached from the opposite side. There, a
handler existed and no route pointed at it. Here, a route exists and no
component answers it.

It is also the same *shape* as the defect RFC 143 fixed: an `<a href>` on a
working page pointing at something that does not render. That one returned a
bare 404; this one returns 200 and a Not Found view, which is harder to notice
because the status line says success.

## 4. Proposed design — triage, not a build

**This RFC does not propose building thirty-five screens.** It proposes
deciding, per route, which of three things it is — and then making the gate
able to tell.

1. **Triage each of the thirty-five into exactly one of:**
   - **(a) Implement** — the screen is wanted. It gets a component and an
     `app.rs` route.
   - **(b) Delete** — the route is not wanted. The handler, its registration,
     its `.json` companion if that has no other consumer, and its
     `route-contracts.md` row all go, together.
   - **(c) Re-declare** — the route is wanted but is not what the contract says
     it is. The row is corrected to what the code does.

   **"Leave it" is not an option**, because that is what produced thirty-five.

2. **Add the missing direction to `route-contracts-check.sh`:** a `GET` row
   declared `render=client` whose path has no matching `path!()` route in
   `app.rs` **fails the check**. This is the acceptance test — it is what stops
   a thirty-sixth, and without it the triage is a one-time cleanup of a
   renewable problem.

3. **Fix the reachable one first**, in its own commit:
   `/admin/console/tokens/new` is linked from a working screen and is therefore
   the only one with a user who can currently hit it.

**Sequencing.** The gate (2) must land **last**, or it fails the tree while the
triage is in progress. The gate's fires/does-not-fire pair is the evidence that
it can actually see the class.

## 5. Non-goals

- **Not styling**, and not RFC 131 R3's mockup-adoption programme. A screen
  this RFC implements is a working screen, not a designed one.
- **Not the six unregistered `page_json` handlers** — RFC 141 §13 owns those,
  and the two cleanups should not be merged into one cycle just because they
  share a root cause.
- **Not `POST` routes.** This is about pages that render.
- **Not a judgement that thirty-five screens are missing.** Some of these
  routes may be better deleted than built, and the triage is the point.

## 6. Relationship to work already in flight

- **RFC 141 §4.1's "console screen"** is `/admin/console/clients` — one of the
  thirty-five, and the one added by 0.85.0. **RFC 141 cycle 2 should implement
  it as option (a)**, which also removes it from this RFC's list. The two do not
  conflict; this RFC's list shrinks by one when cycle 2 lands.
- **RFC 131 R3** owns how screens look and the mockup view models (six of nine
  unused). That programme assumes the screens exist. For thirty-five of them
  they do not, which is worth knowing before R3 is scheduled.
- **RFC 141 §13's gate addition** and this RFC's §4.2 are two directions of one
  check. Whichever lands second should extend the first rather than add a
  parallel mechanism.

## 7. Testing strategy

- The gate in §4.2, with a **fires/does-not-fire pair**: it must fail on a tree
  where a `client`-declared row has no `app.rs` route, and pass once every row
  is resolved.
- For each route triaged **(a)**, whatever test its screen warrants — at
  minimum that the route resolves to a component rather than the fallback.
- For each route triaged **(b)**, the route count falls, and the expected
  figure is stated with its command.
- **No claim that a screen works because it renders.** If the browser suite
  cannot reach an authenticated admin screen, say so rather than describing a
  weaker test in stronger words.

## 8. Acceptance criteria

1. Each of the thirty-five is implemented, deleted, or re-declared, and the
   package says which and why for every one.
2. `route-contracts-check.sh` fails when a `client`-declared `GET` row has no
   matching `app.rs` route, with the fires/does-not-fire pair in evidence.
3. `/admin/console/tokens/new` either renders a working token-issuance screen or
   is no longer linked from the console.
4. The route count change is reported with its command.
5. No existing test is weakened.

## 9. Level

**Decided at handoff time, per the project's rule, and it is not uniform.**
Implementing a screen that the contract already promises is a **fix**. Deleting
a documented admin route **removes a surface** and is at least a **minor**, even
though nothing could have used it. If the triage deletes anything, the release
carrying it is a minor.

## 10. One thing the owner should know about 0.85.0

0.85.0's release notes say, of RFC 141: *"There is no console screen yet — this
release ships the API, and the screen is the RFC's second cycle."* That is
**true** — no screen renders — and the notes correctly declined to claim one.

What the notes do not say is that the release also added a **route** for that
screen, documented as a client-rendered "client list", which answers 200 with a
Not Found page. Nothing links to it, so no user can reach it by navigation, and
the API that RFC 141 actually delivered is unaffected. **No hotfix is proposed:**
thirty-four of the thirty-five predate 0.85.0, so this is a long-standing
condition that one route was added to, not a regression the release introduced.
The correction belongs in the next release's notes, which this RFC's work will
produce.

---

## 11. Triaged before dispatch (architect, 2026-10-25)

I triaged all thirty-five myself, because §4 requires a decision per route and an
implementer must inherit none of them. The triage changed the RFC's premise in
the project's favour, the same way RFC 143 §9 did, and for the same reason.

### 11.1 This is not thirty-five screens to build

**Thirty-four of the thirty-five already have a server-rendering template, in
their own backend module, already rendered by that module's own `POST` path.**

Measured by resolving each route's `get_async` handler to its module and looking
for a `cesauth_frontend` template that the module renders via
`render::html_response` or `Response::from_html`:

| Group | Count | Evidence |
|---|---|---|
| Template imported as a path (`use cesauth_frontend::tenancy_console::…`) and rendered by the `POST` | **27** | e.g. `tenancy_console/forms/group_create.rs:50` — `render::html_response(ui::for_tenant(…, Some("Slug and display name are required")))` |
| Template reached through `use cesauth_frontend as ui` | **5** | `console/tokens.rs:120` `ui::admin::token_new_form(&principal, Some(err))`; `console/config.rs:263` `ui::admin::config_edit_form(…)`; the three read pages' `organization_detail_page` / `role_assignments` / `subscription` imports |
| Read pages whose template is imported but rendered by neither GET nor POST | **2** | `tenancy_console/role_assignments.rs`, `tenant_admin/role_assignments.rs` |
| **No template found** | **1** | `/admin/t/:slug/deletion-requests` — `routes/deletions.rs` has **0** `cesauth_frontend` references |

My first pass reported 8 without a template. That was a false negative: the
regex matched only `use cesauth_frontend::<path>` and missed
`use cesauth_frontend as ui`. **Corrected by reading the files.** The figure is
34, not 27.

Those templates take an `Option<&str>` error argument — `Some(msg)` on a failed
submit, so **`None` renders the fresh form**. That is precisely the shape RFC 143
exploited.

### 11.2 The decision: implement all of them by server-rendering. Delete none.

**Every route is option (a), and the fix is RFC 143's, thirty-four more times:**
point the GET at the template its own module already renders, and change the
contract row's render column from **`client` to `server`**.

Deleting was the wrong answer and I had expected it to be the common one. The
capability, the template, its tests and its localization all exist; the only
missing wire is the GET handler's body. Deleting would discard working,
tested code to resolve a one-line omission.

**Two consequences worth stating plainly:**

- **§9 was wrong about the level.** It said deleting a documented admin route
  removes a surface, so a release carrying the triage is at least a minor.
  Nothing is deleted and no surface changes, so **this is a patch** — the same
  reasoning as RFC 143: restoring behaviour a template already implements.
- **The new gate in §4.2 becomes the smaller half of the work.** A route
  declared **`server`** is already covered by **E3**, which asserts that a
  `server`-declared route's handler does not call `leptos_html_shell`.
  Converting these rows to `server` puts all thirty-four under a gate **that
  already exists** and has a six-month record. §4.2's check is still worth
  adding, for the rows that legitimately stay `client` after this — but it
  guards a residue, not the class.

That is the strongest argument for converting rather than deleting: it moves
thirty-four routes from a class nothing checks into a class something already
checks.

### 11.3 Two exclusions

- **`/admin/console/clients` is excluded from RFC 145.** It has no template
  (`console/clients.rs` is JSON throughout) and **RFC 141 §4.1 cycle 2 owns
  it.** It is the one route of the thirty-five that genuinely needs a screen
  built. RFC 145's list is therefore **34**.
- **`/admin/t/:slug/deletion-requests` has no template anywhere.** It is in
  scope, but the implementer reports what it needs rather than inventing a
  template to match a contract row — the row may be the thing that is wrong.

### 11.4 Cycle split

Thirty-four routes is too much for one cycle, and the §4.2 gate cannot land
until the last row is resolved or it fails the tree.

Grouping the thirty-five by path prefix: **`/admin/console/*` 3**
(one of which is `clients`, excluded), **`/admin/t/:slug/* ` 12**,
**`/admin/tenancy/*` 20** — so RFC 145's scope is `2 + 12 + 20 = 34`, and the
cycles below are `3 + 11 + 20 = 34`.

- **Cycle 1 — the operator console and the only reachable defect.**
  `/admin/console/tokens/new` (linked from a working screen),
  `/admin/console/config/:bucket/edit`, and the
  `/admin/t/:slug/deletion-requests` question. Three routes, and it ends the
  only instance an operator can currently reach.
- **Cycle 2 — the eleven `/admin/t/:slug/…` tenant-admin routes.**
- **Cycle 3 — the twenty `/admin/tenancy/…` routes, plus the §4.2 gate** and
  its fires/does-not-fire pair.

Each cycle's routes become `server`-declared, so **E3 begins guarding them as
each cycle lands**, rather than everything waiting on cycle 3.

---

## 12. Cycle 1 landed, and it refuted §11.2's argument (2026-10-25)

Cycle 1 is accepted at `7fa8078`: `/admin/console/tokens/new` and
`/admin/console/config/:bucket/edit` render server-side, both rows now
`server`, route count **193**, every gate green. The reachable defect — the link
at `pages/operator/console.rs:106` — is fixed. Review:
`.git-exclude/reviewed/145-cycle1-review.md`.

### 12.1 E3 cannot see a shell call made through a wrapper

Building the fires/does-not-fire pair, the implementer reverted the handler to
the **exact** code it had before the cycle — `operator_json_api::shell(&req,
&ctx, "…")` — and **E3 passed**. A direct `leptos_html_shell` call fails it.

The cause is in the check itself: `fn_body_has_shell`
(`scripts/route-contracts-check.sh:211-219`) scans the target function's body
for the literal string `leptos_html_shell`. Both shell helpers —
`operator_json_api::shell` (`operator_json_api.rs:38`) and
`tenant_admin::json_api::shell` (`tenant_admin/json_api.rs:48`) — call it one
level down, and the resolver does not follow them.

**This makes §11.2 false.** I wrote that converting these rows to `server`
"moves thirty-four routes from a class nothing checks into a class something
already checks", and called it the strongest argument for converting rather than
deleting. **All thirty-five routes reach the shell through one of those two
wrappers** (§2: 24 and 11), so E3 would not have caught any of them, and will
not catch a regression back to the wrapper shape.

The conversions still fix the pages, and the decision to convert rather than
delete still holds on its other merits — the templates exist, are tested and are
localized. But the property I argued it on does not exist, and I argued it
without checking the check.

Worth noting what this sits beside: E3's resolver deliberately distinguishes
"resolved and clean" from "UNRESOLVED — hard failure", because C1-132 ruled that
a handler the check cannot find must never be silently treated as clean. A
wrapper it *can* find but does not follow falls into the same blind spot that
ruling exists to close.

### 12.2 Decision, revised: it lands in 0.85.1, ahead of cycles 2 and 3

My first decision was to fold this into cycle 3 with the §4.2 gate. **Reviewing
the schedule against the owner's philosophy changed it**, on a measurement:

```
server-declared GET rows: 7
  of which call a shell WRAPPER (E3 would newly fail these): 0
```

Teaching `fn_body_has_shell` to follow one level of indirection **fails nothing
today**. It is a check-only change, it costs nothing, and it begins actually
policing the two routes cycle 1 converted. Keeping a gate that is known blind
for two more releases *while relying on it* is the exact defect class this
project exists to remove — and I had scheduled it that way only because it was
discovered next to cycle-3 work, not because anything required it.

**Dispatched as its own item**, not a cycle:
`rfcs/handoffs/145-.../e3-wrapper-indirection-handoff.md`. A resolved call into
a function whose own body calls `leptos_html_shell` counts as a shell call, with
a fires/does-not-fire pair proving the wrapper shape is caught. §4.2's new gate
direction stays with cycle 3, where the last `client` row is resolved.

Never by touching `E3_EXEMPT`.

### 12.3 One route leaves RFC 145's scope

`/admin/t/:slug/deletion-requests` — the one route with no template (§11.3) —
turned out to be more than a missing template: its three sibling handlers write
audit events and redirect with success parameters without ever touching the
deletion-request repository, which is fully implemented and used by the sweep.
**That is now RFC 147**, which owns the route. **RFC 145's scope drops from 34
to 33**, and cycle 2 covers **10** tenant-admin routes rather than 11.

## 13. The compiler has been reporting this defect all along (2026-10-27)

Measuring the backend crate's warning count — to decide whether CI should
enforce `-D warnings`, a decision I own — turned up something about **this** RFC
instead.

```
$ cargo build -p cesauth-backend --tests 2>&1 | tail -3
warning: `cesauth-backend` (lib test) generated 191 warnings (run `cargo fix --lib -p cesauth-backend --tests` to apply 178 suggestions)
```

**191**, not the 198 recorded earlier — 0.86.0 moved it, which is itself a
reason the figure needs its command attached. Grouped by kind, the largest
classes are **not** style:

| Count | Warning |
|---|---|
| 19 / 19 / 16 | `unused variable: req` / `ctx` / `ctx_ta` |
| 15 / 15 | `unused import: crate::routes::admin::console::render` / `::auth` |
| 9 / 6 | `unused import: AdminAction` / `cesauth_frontend as ui` |

That shape is this RFC's defect, stated by rustc. `tenant_admin/users.rs:1-24`:

```rust
use cesauth_frontend::tenant_admin::users_page;          // the server template
use crate::routes::admin::console::render;               // the renderer
…
pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    …
    json_api::shell(&req, &ctx, &format!("Users — {} …")).await   // the Leptos shell
}
```

**The handler imports the server template and the renderer and uses neither**,
because it returns the shell instead — which is exactly "documented
`render=client`, serving the shell, with no route in `app.rs`". The compiler
has said so on every build.

### 13.1 A compiler-verified worklist for cycles 2 and 3

Imported-but-unused *page templates*, which is a census of the remaining scope:

```
$ cargo clippy -p cesauth-backend --tests 2>&1 \
    | grep -B1 -A3 "^warning: unused import" | grep -E "unused import|-->" \
    | paste - - | grep -iE "page|frontend" | sort -u
```

- **tenancy_console** (6 files): `tenancy_console_overview_page`, `tenants_page`,
  `tenant_detail_page` + `TenantDetailInput`, `organization_detail_page` +
  `OrganizationDetailInput`, `user_role_assignments_page` +
  `UserRoleAssignmentsInput`, `subscription_history_page`
- **tenant_admin** (5 files): `users_page`, `organizations_page`,
  `organization_detail_page`, `subscription_page`, `role_assignments_page` +
  `TenantUserRoleAssignmentsInput`
- **console** (7 files): `operations_page` + `CronPassDisplay`, and
  `cesauth_frontend as ui` in `alerts.rs`, `audit.rs`, `audit_chain.rs`,
  `cost.rs`, `overview.rs`, `safety.rs`

This corroborates §2's count from an independent direction and **tells the dev
team which template each route is supposed to render**, which the handoff would
otherwise have to derive by hand.

### 13.2 The warnings-gate decision, and why its order is not the obvious one

**Decision: do not enable `-D warnings` now, and do not run `cargo fix` on the
admin route modules before cycles 2 and 3 land.**

The reason is not that 191 is a large diff. It is that `cargo fix` would
**delete these imports** — it offers 178 such suggestions — and deleting them
destroys the compiler's own report of a P1 defect, converting a visible bug into
invisible dead code that no longer warns. **The imports should become used, by
wiring the server template, not removed.** Enabling the gate first creates
exactly the pressure to take the fast path.

The order is therefore:

1. **RFC 145 cycles 2 and 3** — the unused template imports become used, and
   the `req` / `ctx` / `ctx_ta` parameters with them. Most of the 191 should
   disappear as a *consequence* of the fix.
2. **Re-measure**, then enable `-D unused_imports -D unused_variables` for the
   backend crate — the two lints that carry defect signal — rather than a
   blanket `-D warnings`.
3. **Style lints separately** (`doc list item without indentation` and
   `overindented`, 45 between them) in one mechanical commit, then folded in.

A blanket `-D warnings` is rejected even at the end: it makes every future
lint-set change in a toolchain bump a release-blocking failure, and the
toolchain is pinned precisely so that bumps are deliberate events.

## 14. The route count, measured at dispatch (2026-10-27)

§12's arithmetic predicted **10** tenant-admin routes for cycle 2. Measured at
`f60aa2b` by matching every `client`-declared `GET` row in `route-contracts.md`
against `path!()` in `crates/frontend/src/app.rs`, treating a `:param` segment
as matching any one segment:

```
client-declared GET rows: 57   live: 24   DEAD: 33
dead by surface: {'admin/tenancy': 20, 'admin/t': 12, 'admin/console': 1}
```

The `admin/console` row is `/admin/console/clients`, excluded by §11.3, so this
RFC's remaining list is **32 — twelve here, twenty in cycle 3.**

**§12 is wrong and the measurement governs.** §12's figure was hand-counted on
2026-10-25; this one is mechanical and reproducible. Which two routes §12
missed is cycle 2's deliverable (0) rather than a guess recorded here — three
counts of mine in the last two cycles were wrong, and each was corrected by
somebody running the assertion instead of trusting the prose. **Writing a
reconciliation I have not performed would be the fourth.**

The cycle split therefore stands as **12 + 20**, not 10 + 20, and the
dispatched handoff carries the twelve with the template each should reach:
`handoffs/145-admin-pages-answer-200-and-render-not-found/cycle-2-handoff.md`.

## 15. Cycle 2 accepted, and §14's count was wrong (2026-10-27)

Cycle 2 landed at `dc09439` and is **accepted**. Twelve routes wired, all twelve
rows `server`-declared, no handler among them reaching a shell, two orphaned
`.json` companions deleted with zero consumers. Independently re-verified:
routes **190**, `migration_chain` **31**, backend warnings **191 → 162**,
clippy/drift clean, `+12 / −0` tests confirmed from the diff. Review:
`.git-exclude/reviewed/145-cycle2-review.md`.

**E3 guards the twelve, confirmed on a route the cycle did not demonstrate.** I
reverted `forms::group_delete::form` to `json_api::shell(...)` — a different
handler shape, resolved through the wrapper indirection §11.2 once got wrong —
and `route-contracts-check.sh` failed correctly, then passed again after a
byte-identical restore.

### 15.1 Dead routes are 34, not 33, and the extra one fails differently

§14's measurement was wrong because **my matcher let a `:param` segment match a
literal**. `path!("/admin/tenancy/tenants/:tid")` swallowed the literal `new`,
so I scored **`/admin/tenancy/tenants/new`** as live. It is not:
`tenancy_console::forms::tenant_create::form` serves `operator_json_api::shell`
and `app.rs` has no route of its own for that path.

**It is the only one of the 34 that does not render `<NotFound/>`.** It is
captured by `:tid` and renders the **tenant-detail page for a tenant whose id is
the string `"new"`**. A system admin trying to create a tenant is not told the
page is missing — they are shown a different, plausible page. On the owner's
standard that is the worse symptom, and this is its only instance.

**Cycle 3's scope is therefore 21, not 20**, and this route needs its own triage
line: it may want a real create screen, or `app.rs` may simply need a static
route ahead of the param.

### 15.2 This is a requirement on §4.2's gate, not a footnote

§4.2's check — a `client`-declared `GET` with no matching `app.rs` route fails —
**would have passed this route if written the way I wrote my script.** Matching
`:param` against a literal is the natural implementation and it is wrong here.

So the gate must:

- treat a **literal segment as taking precedence over a param**, as the router
  itself does, and flag a `client` row whose only match is a param that
  shadows a literal;
- include a **param-shadowed route in its fires/does-not-fire pair**, not only
  an absent one. A pair that proves the gate catches a missing route proves
  nothing about the shadowed class.

**Without both, §4.2 ships believing it covers a class it cannot see** — which
is exactly what §11.2 was wrong about for E3, one RFC earlier. That is twice now
in this RFC's history, so the pair is the acceptance criterion, not the check.

### 15.3 Two corrections to my own cycle-2 handoff

- **§9.1 asked for an impossible test.** It required a test asserting *the
  response*; `worker::Response` has no host constructor, as **RFC 146 §2
  established with a probe**. The cycle substituted template-level tests, which
  was correct, but silently — §6's report-and-stop gate covered the case. The
  twelve tests therefore guard the templates' output, **not the wiring**, and a
  handler reverted to the shell still passes all twelve. **E3 is the wiring
  guard.** RFC 145's eventual Status line must credit E3, because a reader who
  believes the twelve tests cover the wiring would be wrong.
- **The host-test count is 1,568**, not the 1,561 reported: the cycle's
  measurement omitted the 7 doc-tests, which is the exclusion
  **RFC 136 C2-136 removed from the canonical command** for precisely this
  reason. `+12 / −0` is correct and verified; only the total was off.

### 15.4 One finding outside scope, now RFC 152

The cycle reported that all 35 `POST` rows on both admin surfaces document CSRF
as `required` and no handler calls `csrf::verify` — correctly reported rather
than absorbed into a patch cycle. **Two figures in it needed correcting, one of
them mine.** It is **33 of 35**, not 35: `/admin/t/:slug/deletion-requests/:id/{cancel,execute}`
do verify, and they are the newest routes on either surface. I missed them
because I checked the two surface *directories*, while those routes are served
from `routes/deletions.rs` — a directory-scoped grep answering a route-scoped
question, which is an error this project has seen before. **The severity was
overstated**: the admin cookie is `SameSite=Strict`
(`admin_login.rs:77`), so no cross-site request carries it and there is no
exploitable path today. The real defect is a document naming the wrong control
while fourteen destructive operations rest on one unasserted cookie attribute.
**That is RFC 152.**

## 16. Cycle 3 scoped and dispatched (2026-10-27)

**21 routes, confirmed with a corrected matcher**, and the arithmetic now
reconciles end to end:

```
/admin/tenancy: client-declared GET rows 24   live 3   DEAD 21
                (20 with no route at all, 1 param-shadowed)
repo-wide:      rows 45   live 23   DEAD 22   = these 21 + /admin/console/clients
```

45 is 57 − 12 and 22 is 34 − 12, so cycle 2's conversions account for the whole
difference. **Every one of the 21 has a template already present** in
`crates/frontend/src/tenancy_console/` — checked per route, including
`tenant_create_form` for the shadowed route — so cycle 3 is **patch**, cycle
2's shape on a third surface. Handoff:
`handoffs/145-admin-pages-answer-200-and-render-not-found/cycle-3-handoff.md`.

### 16.1 The matcher was wrong three times, which is the gate's specification

§15.2 asked the gate to treat a literal as taking precedence over a param.
Writing the scope measurement produced a second, opposite error and then the
correct rule:

| Attempt | Rule | Failure |
|---|---|---|
| 1 | a `:param` matches any segment | **false live** — swallowed the literal `new`; count came out 33 |
| 2 | "exact" = the `app.rs` route has no params | **false dead** — `/admin/tenancy/tenants/:tid` is matched param-to-param by an identical route |
| 3 | **exact = segment lists equal; a param-over-literal match is a *shadow*, counted dead** | correct on all 45 rows |

So **the check has three outcomes, not two** — exact, shadowed, absent — and
its fires/does-not-fire evidence must cover all three. **Attempts 1 and 2 would
each have passed a pair built only from the absent case**, which is how a check
comes to be believed to cover a class it cannot see. That has now happened
twice in this RFC: once to E3 (§11.2) and once to my own matcher, in both
directions.

### 16.2 The cycle-2 handoff's mistake, not repeated

Cycle 2's §9.1 required a test asserting *the response*, which cannot be built
on the host (RFC 146 §2). Cycle 3's handoff states that the template tests are
expected to guard **template output only**, names E3 and the new gate as the
wiring guard, and repeats the report-and-stop instruction for any requirement
that still cannot be constructed. **The requirement was narrowed to something
true rather than left for the implementer to quietly work around.**
