# RFC 157 — Sixteen unrouted route handlers, and the gate they are blocking

**Status.** **Done** — **shipped v0.88.1**. All 29 unrouted handlers deleted,
the leftover imports §13.2 had preserved as evidence removed, and
`unused_imports`/`unused_variables` denied for `cesauth-backend`.
**Evidence**: **`exercised`** (RFC 000 §22) — `#![deny(unused_imports,
unused_variables)]` at `crates/backend/src/lib.rs:30`, demonstrated to fail
the build on a reintroduced unused import (by the cycle in
`tenant_admin/organizations.rs`, and by the architect in `sweep.rs`, a file the
cycle never touched) and to pass once restored byte-identically. The population
it guards is empty: re-derivation gives **126** handler-shaped functions under
`admin::` and **9** unrouted, all of them RFC 159's, remainder **0**.

**The mechanism is not the one this RFC specified, and the deviation is an
improvement.** §4 step 4 called for `-D unused_imports -D unused_variables` on
`clippy.yml`'s invocation. Run as written, a command-line `-D` on
`cargo clippy -p cesauth-backend` denies the lint in that crate's workspace
**dependencies** too and fails on `cesauth-core`'s pre-existing `ClientId`
warning — out of this RFC's scope. The crate attribute scopes correctly **and
travels with the source**, so a local `cargo build` enforces what CI does.
Recorded in `docs/src/expert/contributing.md`'s gate-set table, since it is the
one gate with no workflow of its own.

**Tier.** P2. Nothing is broken. This clears the last obstacle to a gate the
project decided it wanted in RFC 145 §13.2 and then could not turn on.
**Size.** Small: deletions, then one CI flag.
**Touches.** `crates/backend/src/routes/admin/**` (deletions),
`docs/src/expert/route-contracts.md` if any row goes with them,
`.github/workflows/clippy.yml`.
**Depends on.** RFC 145 (done) — this is its residue. **Supersedes RFC 145
§13.2's prohibition**, for the reason in §4.
**Found by.** The architect, 2026-10-28, doing the scoping pass §13.2 said was
owed. **I had deferred it four times.**

## 1. Summary

RFC 145 §13.2 decided: do not enable `-D warnings`, because `cargo fix` would
delete the unused imports that *were* the compiler's report of a P1 defect, and
the defect was unfixed. **Cycles 2 and 3 fixed it.** The prohibition's reason
has expired and the rule has not, which is how a conditional decision becomes a
permanent one that nobody revisits.

This RFC clears what remains and turns the gate on — narrowly.

## 2. What is established

**Two different warning populations, which §13.2 treated as one.**

```
$ cargo build -p cesauth-backend --tests     # rustc lints only
148 warning lines across the lib and lib-test targets
    97  unused import
    41  unused variable
    10  dead code (never used / never constructed)
```

**A figure-hygiene correction while I am here:** I have been quoting "191 →
162 → 143 warnings" as *the backend's* count. **143 is the `(lib test)`
target's summary alone**; the build emits 148 across `lib` and `lib test`. The
trend was real and the label was loose. `cargo clippy` adds a **separate**
population on top (`borrowed expression`, `doc list item`, `sort_by_key`), and
**that** is the population a blanket `-D warnings` would make hostage to a
toolchain bump — not these.

**Sixteen handler-shaped functions are routed by nothing.** Defined as a
`pub async fn` in `routes/` taking `req: Request, ctx: RouteContext`, whose
name appears nowhere in `lib.rs` — and `lib.rs` is the only router:

```
handler-shaped pub async fns in routes/: 218
not referenced in lib.rs at all:          16
    8  admin::tenancy_console    5  admin::tenant_admin
    2  admin::console            1  admin::auth
```

> **Corrected 2026-10-29, at deliverable (0): the population is fifteen, and
> the count missed nine others.** Both defects were in my measurement, which
> this RFC had labelled *"facts already measured — do not re-derive"* — a label
> that told the cycle not to check the thing that was wrong.
>
> **`admin::auth::list_tokens` does not exist.** It is a `///` line inside a
> ` ```ignore ` fenced example for the `require_system_admin!` macro
> (`routes/admin/auth.rs:161`). **My regex matched inside a doc comment** —
> the same bug this project corrected once before, in a cascade check whose
> regex matched `user_id` inside SQL comments.
>
> **And nine more real unrouted handlers were missed**, all named `page_json`,
> because the bare-name test sees that string in `lib.rs` (eight *routed*
> functions share the name) and clears every function with it. **This RFC
> named that weakness and then called the list built with it sound.** They are
> **RFC 159**.
>
> **Corrected again 2026-10-29 at a second deliverable (0) stop, and this is
> the authoritative count.** Derived from the tree rather than by checking
> named candidates, by the cycle and independently by me with matching results:
>
> ```
> real handler-shaped pub async fns under admin::   155
> unrouted by full qualified path                    38
>     this cycle's triage (15 approved + 14 found)   29
>     RFC 159's dashboard page_json set               9
> ```
>
> **38, not 24** — the 15 I first approved were missing **fourteen more** of
> the identical `form_json`/`confirm_json` shape, hidden by the same bare-name
> collision that hid the nine. **Of the 38, 23 are referenced nowhere in the
> crate at all and 15 only by their own tests.**
>
> **Whole-tree check: there are no unrouted handlers outside `admin::`.** My
> own first pass reported two in `oidc::`, which were false positives —
> `oidc.rs:16` and `:20` are **renaming** re-exports (`pub use userinfo::handler
> as userinfo_handler`) and my script resolved only brace re-exports.
>
> **My number was wrong three times** on this RFC: sixteen including a phantom,
> then fifteen missing nine, then fifteen missing fourteen. The count to cite
> is the derivation, not any figure I supplied.

Fifteen are `*_json` companions — `confirm_tenant_json`, `form_org_json`,
`confirm_group_json` and so on. Of the fifteen, **two are referenced nowhere in
the crate at all** (`console::tokens::new_form_json`,
`console::config::edit_form_json`); the other thirteen are reached only by
their own tests.

**This count is a lower bound, and the reason is worth recording.** The name
test under-counts when an unrouted function shares a name with a routed one, so
a path-based count gave **18**. The path test in turn over-counts where a
re-export exists — `admin.rs:32` has one. **Sixteen is sound; eighteen is
likely; the methods disagree for a known reason, which is more useful than
picking one.**

**The remaining unused imports are no longer defect signal.** §13.2's ten
`unused import: …console::render` sites were evidence that a handler imported
the server template and served the shell instead. Checked now:
`tenant_admin/organizations.rs` still calls `json_api::shell` — **and that
route is legitimately `client`**, live in `app.rs`, which the §4.2 gate
confirms by passing. So the import is a leftover, not a symptom. **The thing
§13.2 was protecting is gone.**

## 3. What is not established

That all sixteen should be deleted. Each `*_json` sibling was presumably
written for a Leptos page that was never wired, or whose GET became
server-rendered in RFC 145 — **cycle 2 deleted two of exactly this kind after
confirming no consumer.** The triage is the work: delete, or wire if a page
genuinely wants one. **"Leave it" is not available**, because that is what
produced sixteen.

## 4. Direction

1. **Triage the sixteen** (or eighteen — resolve the count first, both methods
   stated). Each is delete, or wire. A `route-contracts.md` row goes with any
   deletion that had one.
2. **Delete the leftover imports** in modules serving legitimately-`client`
   routes. **RFC 145 §13.2's prohibition on touching them is lifted here,
   explicitly and with its reason**: the defect whose evidence it preserved was
   fixed in v0.86.1 and v0.86.2.
3. **Re-measure**, with the command *and the target* named.
4. **Then enable `-D unused_imports -D unused_variables`** for the backend
   crate in `clippy.yml`, alongside the existing `-D clippy::correctness`.
5. **Blanket `-D warnings` stays rejected**, and now for a sharper reason than
   §13.2 gave: it would deny clippy's style population, which changes between
   toolchains, and the toolchain is pinned precisely so bumps are deliberate
   events. The two populations get two decisions.

**The gate is the point, not the tidiness.** Handlers routed by nothing
accumulated silently because nothing failed. That is the same sentence as
RFC 156's, one layer in.

### 4.1 The gate's blind spot, stated before it ships

**Neither lint can see a dead handler that uses its parameters.** Established
at deliverable (0): none of RFC 159's nine produces a warning, because each
passes `req` and `ctx` on to `operator_json_api::…` before doing nothing
useful with the result.

So this RFC's premise — *unused imports and variables are the compiler's
report of an unrouted handler* — **is incomplete, and the gate inherits that.**
It catches the residue that leaves parameters unused and is blind to the
residue that does not. **Recorded here rather than discovered after the gate
ships**, which is the one time in this programme that "a check that quietly
does less than it appears" has been caught in advance.

**What would close it** is a routing check, not a lint: a handler-shaped
`pub async fn` in `routes/` whose qualified path appears nowhere in `lib.rs`
fails. That is RFC 159's natural second deliverable and is not in this
cycle.

## 5. Open question for the owner

None. The triage judgement is the dev team's per route, the gate choice is
mine, and §13.2's expired prohibition is mine to lift since it was mine to
impose. **This is here for authorization, not for a decision.**
