# RFC 157 — Sixteen unrouted route handlers, and the gate they are blocking

**Status.** **Accepted** 2026-10-29. **Scheduled 0.88.1 — patch.** Deletions
and one CI flag; no capability changes. **Not dispatched yet**: RFC 153 is in
flight and its cycle was told explicitly not to delete any of these handlers as
a side-effect, so dispatching this concurrently would invite exactly the
collision that instruction prevents.
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

Fifteen are `*_json` companions — `confirm_tenant_json`, `form_org_json`,
`confirm_group_json` and so on — and one is `admin::auth::list_tokens`. Of the
sixteen, **three are referenced nowhere in the crate at all**
(`auth::list_tokens`, `console::tokens::new_form_json`,
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

**The gate is the point, not the tidiness.** Sixteen handlers routed by nothing
accumulated silently because nothing failed. That is the same sentence as
RFC 156's, one layer in.

## 5. Open question for the owner

None. The triage judgement is the dev team's per route, the gate choice is
mine, and §13.2's expired prohibition is mine to lift since it was mine to
impose. **This is here for authorization, not for a decision.**
