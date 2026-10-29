# RFC 159 — Nine dead handlers no lint can see

**Status.** **Accepted** 2026-10-29. **Queued behind RFC 158's decision
stage** — RFC 158 is P1 (a 35-route administrative surface one tenant can open)
and this is P2 (nine functions nothing reaches). **Release unassigned**, for
the same reason RFC 158's is: §4's two deliverables are different sizes and the
per-page question in step 1 is answered by looking, not by scheduling.

**Implementation dispatched 2026-10-29**, after 0.89.1 was cut:
`handoffs/159-nine-dead-handlers-no-lint-can-see/implementation-handoff.md`.
**0.89.2, patch** — deleting dead code and adding a check, the same shape that
made RFC 157's twenty-nine deletions a patch.

**No decision stage, and §3's premise is why** — see §2.1. The per-page
archaeology §4 step 1 asks for was three greps, and doing it before paying for
a stage turned one design fork into zero.
**Tier.** P2. Nothing is broken and nothing is reachable. The value is the
check, not the deletions.
**Size.** Small for the nine; the check is the lasting part.
**Touches.** `crates/backend/src/routes/admin/console/{alerts,audit,audit_chain,cost,safety,config}.rs`,
`.../tenancy_console/{organizations,role_assignments,subscription}.rs`,
`scripts/route-contracts-check.sh` (or a sibling).
**Depends on.** RFC 157 (in flight) — **this is what RFC 157's gate cannot
see.**
**Found by.** The **dev team**, 2026-10-29, at RFC 157's deliverable (0),
reconciling a count I had labelled *"do not re-derive"*.

## 1. Summary

Nine `pub async fn … page_json(req: Request, ctx: RouteContext<D>)` handlers in
the admin tree are **registered by nothing, referenced by nothing, and
fetched by nothing** — and **no lint can see them**, because each uses both of
its parameters before doing nothing useful.

They were missed by RFC 157's census because `page_json` is also the name of
**eight routed** functions, so a bare-name test against `lib.rs` clears every
function sharing the name. RFC 157 named that weakness and then shipped a list
built with the test anyway.

## 2. What is established

The nine, each verified individually — real code (not a doc comment), **its
fully-qualified path absent from `lib.rs`**, zero calls in its own file
including its own tests, and a qualified-path grep returning **0** across the
crate:

```
admin::console::alerts::page_json                 alerts.rs:25
admin::console::audit::page_json                  audit.rs:43
admin::console::audit_chain::page_json            audit_chain.rs:35
admin::console::cost::page_json                   cost.rs:32
admin::console::safety::page_json                 safety.rs:26
admin::console::config::page_json                 config.rs:49
admin::tenancy_console::organizations::page_json  organizations.rs:50
admin::tenancy_console::role_assignments::page_json  role_assignments.rs:48
admin::tenancy_console::subscription::page_json   subscription.rs:53
```

**More orphaned than RFC 157's fifteen**, which are at least reached by their
own tests.

**No lint sees them.** `cargo build -p cesauth-backend --tests` reports 39
unused-variable sites and **none is in these nine files** — each passes `req`
and `ctx` onward, so `unused_variables` and `unused_imports` are both blind.
**RFC 157's gate will ship green over all nine.**

**Nothing is broken by the nine.** ~~The frontend fetches five `.json`
paths … and all five are routed.~~ **Corrected 2026-10-29**: it references
**sixteen**, this list was only the operator-console subset, and **two of the
sixteen are not routed** — see
[RFC 162](../proposed/162-two-console-pages-fetch-urls-nothing-serves.md),
which this count is how I found. None of the sixteen is one of the nine, so
**this RFC's conclusion is unaffected and only its count was wrong.** So the nine are dead, not broken, and there is no runtime
symptom to chase.

## 2.1 §3's premise is wrong: the six sit beside pages that render nothing

Established 2026-10-29 by the architect, doing §4 step 1's archaeology before
dispatching a stage for it. **§3 below is left as written** — it was the
reasoning that justified separating this RFC from 157, and it should stay
visible as a thing that was argued and then disproved.

§3 says the six `admin::console::*` handlers *"sit beside live,
`client`-declared Leptos pages"*, and that *"a `page_json` companion is exactly
the shape a CSR page would consume, so for these six 'nothing fetches it today'
is not 'nothing should'."* **The pages those six sit beside fetch nothing and
render nothing.** `crates/frontend/src/pages/operator/console.rs`'s own section
comment reads `// ─── Generic placeholder pages ───`, and each of the six
renders a heading, a back-link, and one sentence promising data that never
arrives. The fetch idiom — `gloo_net::http::Request::get` — is present in
`ConsoleOverview`, `ConsoleTokens` and `operator/tenancy.rs`, and **absent from
all six.**

**So the "wire it" branch does not exist.** There is no consumer to wire; the
handler and the page are two unconnected halves of an unbuilt feature, and
building the feature needs a route, a contract row, a data query and a design
that a dormant handler supplies none of.

**The other three are RFC 157's mechanical shape**, not a different question:
`admin::tenancy_console::{organizations,role_assignments,subscription}`'s
sibling `page` handlers are routed and server-rendered (`lib.rs:334-336`, RFC
145 cycle 3's work), so their `page_json` companions are dead for exactly the
reason RFC 157's fifteen were.

**All nine are therefore dead with no fork**, and §4 step 1 collapses into
step 2, which was always the point of this RFC.

**The pages are a separate matter and not this RFC's.** Six routed, reachable
operator pages that promise data and render none is a product-scope question —
build them, remove them, or say when — and it is
[RFC 161](../proposed/161-six-operator-pages-promise-data-and-render-none.md),
proposed, for the owner. **It does not block this RFC and this RFC does not
wait for it.**

## 3. Why these need a different question than RFC 157's fifteen

**Six of the nine sit beside live, `client`-declared Leptos pages** —
`/admin/console/{alerts,audit,audit/chain,cost,safety,config}` all have a
`path!()` route in `app.rs`. A `page_json` companion is **exactly the shape a
CSR page would consume**, so for these six *"nothing fetches it today"* is not
*"nothing should"*. Deleting them is plausible and so is wiring them, and
telling which needs looking at what each page renders and where it gets its
data — **frontend archaeology per page, not routing arithmetic.**

RFC 157's fifteen were companions to routes that are now server-rendered or
never existed; that triage was mechanical. **This one is not, which is why it
is a separate RFC rather than nine more rows on RFC 157's list.**

## 4. Direction

1. **Per page, establish where its data comes from.** If the Leptos component
   renders from the shell's embedded state, the `page_json` is dead and goes.
   If it was meant to fetch, say so and wire it — and then it needs a
   `route-contracts.md` row and a registration, which is a different change.
2. **Then the check, which is the point.** A handler-shaped
   `pub async fn` in `routes/` whose **qualified path** appears nowhere in
   `lib.rs` fails. Not a lint — a routing check, in `route-contracts-check.sh`'s
   family, with a named and dated exemption list.

   **It must not be built on a bare-name test.** That is precisely what hid
   these nine — and, a stop later, fourteen more. Match the qualified path, and
   **account for both forms of re-export**:

   - **brace** — `admin.rs:32`'s `pub use legacy::{create_user,
     revoke_session}`;
   - **renaming** — `oidc.rs:16`'s `pub use userinfo::handler as
     userinfo_handler` and `:20`'s `pub use introspect::handler as introspect`.

   **Established by getting it wrong in review:** a path test that handled only
   the brace form reported `oidc::{introspect,userinfo}::handler` as dead when
   both are routed. **That is the false-positive direction, which is the worse
   one for a gate** — it makes people write exemptions for things that are
   fine, and an exemption list that accumulates correct entries stops being
   read.

   **And its fires/does-not-fire pair must include a name-collision case** — a
   dead handler sharing a name with a routed one — because that is the class
   that produced this RFC and a pair without it proves nothing about it.

3. **Not the inverse check.** *"Every URL the frontend fetches has a route"*
   is RFC 162's, and it is a sibling of step 2's, not part of it. The two may
   share a script later; neither waits for the other.
4. **Then re-run RFC 157's census** with the routing check instead of the name
   test, and record the number it gives.

## 5. The lesson worth keeping in the record

RFC 157's premise was that **the compiler reports unrouted handlers** through
unused imports and variables. For the fifteen it did. For these nine it cannot,
and the difference is only whether the dead function happens to pass its
arguments along.

**A lint reports what the compiler notices, not what the program needs.**
RFC 145 §13 drew real value from reading warnings as defect signal — and the
nine are the boundary of that technique, found one cycle after it was
celebrated.
