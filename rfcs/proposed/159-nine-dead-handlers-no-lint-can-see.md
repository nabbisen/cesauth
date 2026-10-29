# RFC 159 — Nine dead handlers no lint can see

**Status.** **Proposed** — awaiting owner authorization.
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

**Nothing is broken.** The frontend fetches five `.json` paths —
`/admin/console.json`, `/admin/console/tokens.json`, `/admin/tenancy.json`,
`/admin/tenancy/tenants.json`, `/admin/tenancy/tenants/{tid}.json` — and **all
five are routed.** So the nine are dead, not broken, and there is no runtime
symptom to chase.

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
   these nine. Match the qualified path, and **account for re-exports**:
   `admin.rs:32`'s `pub use legacy::{create_user, revoke_session}` makes a
   naive path test report two routed functions as dead.

   **And its fires/does-not-fire pair must include a name-collision case** — a
   dead handler sharing a name with a routed one — because that is the class
   that produced this RFC and a pair without it proves nothing about it.

3. **Then re-run RFC 157's census** with the routing check instead of the name
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
