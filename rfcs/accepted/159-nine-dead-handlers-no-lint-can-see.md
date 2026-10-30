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

**Continuation complete 2026-10-30** (`132c3a0`): the tenth deleted, E4's
coverage asserted structurally, census **zero**. **Third cycle dispatched
2026-10-30** for §4.3 and §4.4, both found in review of that commit:
`handoffs/159-nine-dead-handlers-no-lint-can-see/cycle-3-handoff.md`.
**Cycle 3 complete 2026-10-30** (`8761f3a`): both met. **Cycle 4 complete
2026-10-30** (`233283d`): §4.5 met —
`handoffs/159-nine-dead-handlers-no-lint-can-see/cycle-4-handoff.md`.

**Complete. 0.89.2 ready to cut**, pending authorization. Evidence term for all
five sub-findings: **`exercised`** (RFC 000 §22) — ten dead handlers deleted and
the census re-run at **zero** with the finished check; the gate asserts
reachability by qualified path (both re-export shapes and the name-collision
case demonstrated), classification of **every** `pub async fn` in `routes/`
(215 scanned = 193 handlers + 22 named + 0 unclassified, the identity asserted
on every run as a failure distinct from a finding about `routes/`), one shared
comment-stripped view of `lib.rs` behind all four extractors that scan it (one
commented-out registration now fires both the dead-handler finding and the
stale-documentation warning), and its own remainder list (a
`NAMED_NON_HANDLERS` entry matching nothing is a named hard failure; fires on
both a deleted file and a renamed function). Host tests **1,630**/1,630
baseline, `migration_chain` **35**, manifest **13**, Playwright **20**, bundle
**882,908 B** gzip at 33.7% of budget. Re-run independently at review in all
four cycles.

**One finding deliberately not held for:** §4.5's property is unchecked on the
script's four sibling exemption lists, two of which carry entries —
[RFC 165](../proposed/165-the-gates-exemption-lists-are-unvalidated.md), against
the shipped gate, per the cycle-4 handoff's own statement that a further finding
which is not a false certification would not hold the tag a fourth time.
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
[RFC 162](../accepted/162-two-console-pages-fetch-urls-nothing-serves.md),
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
[RFC 161](../accepted/161-six-operator-pages-promise-data-and-render-none.md),
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

## 4.1 The census was not zero: a tenth, and its doc comment is why

The check's first run against the tree found one handler beyond the nine:
**`routes::admin::console::preview::handler`**. Verified in review —
`lib.rs:294` routes `POST /admin/console/config/:bucket/preview` to
`routes::admin::console::config::preview`, a **different function** in the
sibling file (`config.rs:77`, a real gated implementation); a qualified grep
for `preview::handler` returns zero; only `console.rs:41`'s `pub mod preview;`
keeps the file alive; `route-contracts.md:100` documents the live handler and
says nothing about this one.

**Why it survived**: `preview.rs`'s own doc comment says *"the route itself is
registered but returns 501 Not Implemented until the full implementation
ships."* **That is false** — the route is registered to `config::preview`, and
the implementation it was waiting for already landed there. A reader who opened
the file to check was told it was fine. RFC 138's described-vs-actual class,
inside one file.

**Decided: a tenth deletion**, the disposition RFC 157 gave its twenty-nine —
not an `E4_EXEMPT` entry, because an exemption list carrying entries that
should simply be deleted stops being read, which is §4's own argument against
false positives applied to its own escape hatch.

### 4.2 The check cannot see eleven live handlers, and says so to no one

Found in review by re-deriving the population the check's coverage claim rests
on:

```
pub async fn in routes/, non-test                     216
matched by the signature-shape regex                  183
unmatched                                              33
  … registered handlers in the me:: family             11
  … helpers and pure decision functions                22
```

The eleven — `me::security::{get_handler,get_json_handler}`,
`me::totp::{disable,enroll,verify,recover}`'s handlers — are all **registered**
(checked individually). They are invisible because the regex requires
`(req: Request, ctx: RouteContext<D>)` on one line, and that family is written
`(req: Request, env: worker::Env)` or across several lines.

**Nothing is wrong today; the gate is.** This RFC exists because a bare-name
test let nine dead handlers through. A qualified-path test that silently
excludes an entire signature family leaves a dead handler added to `me/totp/`
tomorrow exactly as invisible as those nine — and the check reports nothing,
not even that it examined 183 of 194.

**The requirement is that the covered population cannot shrink silently**: a
`pub async fn` in `routes/` must be either classified as a handler or named as
a non-handler with a reason, and anything else fails the check. The mechanism
is the implementer's choice. This is RFC 156's subject — *a gate that stops
covering something must fail* — one level in, in the gate RFC 156's successor
is adding.

### 4.3 The gate prints `0 unclassified` in the run where it found one

§4.2 is met: the check now asserts its own coverage, and a function matching
neither handler shape nor `NAMED_NON_HANDLERS` is a hard failure, demonstrated
by a fourth fires probe. One line of the delivered implementation undoes part of
that in the only run that matters.

The coverage line's `0 unclassified` is a **string literal**. The unclassified
block sets `exit_code=1` without exiting, so in a failing run the gate prints
the finding and then prints that there are none — verified in review:

```
❌  pub async fn(s) under routes/ matching NEITHER known handler signature shape NOR on NAMED_NON_HANDLERS:
    crates/backend/src/routes/admin/console/_probe_shape.rs:1 (fn weird_new_shape)
…
ℹ️   E4 coverage: scanned 216 pub async fn under routes/ -- 193 classified as handlers (182 RouteContext-shaped, 11 Env-shaped), 22 named non-handlers, 0 unclassified
```

**216 ≠ 193 + 22 + 0.** The figure does not reconcile against its own parts, and
the summary line is the one a maintainer greps for. No dead handler can ship
behind it — the build is red either way — so this is an honesty defect in the
gate's reporting, not a hole in the gate. **Requirement: print the count, and
make the four figures sum to the scanned total in every run, passing or
failing.**

### 4.4 A commented-out registration reads as live — and as documented

E4 decides liveness with `grep -qF "routes::<path>("` against `lib.rs`:
unanchored, comment-blind. Commenting out `lib.rs:285` — the one edit a developer
makes to disable a route — leaves `GET /admin/console.json` unserved, its
handler unreachable, and the gate reporting **exit 0, every handler reachable**.

**This is the defect the implementation cycle found and fixed on the other side
of the same resolver.** The `pub use` grep is `^pub use …`, anchored, which is
exactly why the renaming probe fires on a commented-out re-export. The `lib.rs`
grep never got the same treatment.

**The half that reaches users is not E4's.** The registered-route extraction
(RFC 027/125, `grep -E '\.(get|post|put|delete)_async\s*\("'`) is comment-blind
too: with that line commented the count stayed **193**, so `route-contracts.md`
is still required to document — and still credited with documenting — a route
the Worker does not serve. **A disabled route leaves the published contract
table asserting it exists, with every gate green.** One character of edit, a
documentation lie, no diagnostic.

Latent today, checked rather than assumed: zero commented-out `routes::` call
sites and zero commented-out `*_async("` registrations in `lib.rs`.

**Requirement: a line whose first non-whitespace is `//` is not a registration,
for both greps, from one shared step.** Whole lines only — `//` occurs inside
path and URL strings, and `lib.rs:523` registers the catch-all `"/*catchall"`,
which a naive `/* … */` stripper eats the file from.

**Not in scope here:** the third implementation of this same extraction,
`no_duplicate_route_registrations` in `lib.rs`'s own test module, which is blind
to whitespace as well as comments and so covers 105 of 193 routes. That is
[RFC 163](../proposed/163-two-route-extractors-two-blind-spots.md) — RFC 011's
deliverable, and a fork (two extractors or one) rather than a repair.

### 4.5 The list carrying the remainder can rot, and the figure that would have shown it was removed

§4.3 and §4.4 are met (`8761f3a`, CI 13/13, both probes re-run in review). One
regression arrived with them.

`e4_named_count` changed from the static length of `NAMED_NON_HANDLERS` to a
counter incremented when an entry is **matched during the scan**, on the stated
grounds that the matched count makes a stale entry "show up as the identity
failing to close". **It is the inverse.** With a matched count,
`scanned == handlers + named + unclassified` is a **tautology** — every scanned
function takes exactly one of the three branches — so a stale entry matches
nothing, increments nothing and moves no figure.

Verified in review by adding one stale entry,
`…/routes/admin/console/preview.rs::handler` — the file §4.1 deleted:

```
ℹ️   E4 coverage: scanned 215 … 22 named non-handlers, 0 unclassified
✅  All 193 routes are documented … and every handler-shaped fn in routes/ is reachable from lib.rs
exit 0
```

**The list holds 23 entries; the gate reports 22.** The counterfactual, with the
pre-cycle-3 static count restored in the identity, exits **1** with
`215 scanned != 193 handlers + 23 named(static) + 0 unclassified`. The static
figure was the detector; the matched figure cannot fail.

**A stale entry is a pre-authorised exemption**, not dead weight: delete or
rename a helper, leave its line, and the next `pub async fn` at that `file::fn`
is classified as a reviewed non-handler with nobody reviewing it. `handler` in a
`console/` file is the most re-creatable name in this codebase, and that exact
one existed until `132c3a0`.

**This is the RFC's own defect class for the third time.** RFC 157's bare-name
test could not see nine handlers; E4's first shape regex could not see eleven;
now the irreducible remainder can rot unobserved. Each time the mechanism was
sound and nobody was measuring its coverage. **That is the finding worth keeping
from this RFC, beyond the gate itself: a classifier is only as good as the
measurement of what it declines to classify.**

**Requirement: an entry matching nothing during a scan is a hard failure, named
as its own cause** — distinct from an unclassified function and from a dead
handler. Mechanism is the implementer's; restoring the static count is *not*
assumed to be the answer, since a sum that fails to close is the uninformative
version of the signal.

Latent at the time of review, checked: 22 static entries, 22 matched, every
entry's file present.

## 5. The lesson worth keeping in the record

RFC 157's premise was that **the compiler reports unrouted handlers** through
unused imports and variables. For the fifteen it did. For these nine it cannot,
and the difference is only whether the dead function happens to pass its
arguments along.

**A lint reports what the compiler notices, not what the program needs.**
RFC 145 §13 drew real value from reading warnings as defect signal — and the
nine are the boundary of that technique, found one cycle after it was
celebrated.
