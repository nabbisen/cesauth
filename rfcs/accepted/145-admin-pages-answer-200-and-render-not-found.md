# RFC 145 — Thirty-five admin pages answer 200 and render "Not Found"

**Status.** Accepted — approved by the owner 2026-10-25.
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
