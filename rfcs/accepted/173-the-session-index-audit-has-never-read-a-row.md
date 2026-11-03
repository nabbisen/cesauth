# RFC 173 — The session-index audit has never read a row, and reports success daily

**Status.** **Accepted** 2026-11-03 by the owner, dispatched immediately —
ahead of the rest of the queue, per the RFC 170 review's own recommendation
(small, P1, found live in that job's first rehearsal). Proposed the same day
by the architect.
**Tier.** **P1.** A detection capability that has never run once, whose failure
path reports **success** to the operator-facing cron status surface, since
**2026-05-06** — six months. Not an exposure: nothing is newly reachable. What
is lost is the only signal this project has for a class that includes *"DO is
revoked but D1 still thinks active"* — a session the user's own page renders as
active, with a revoke button that does nothing.
**Size.** **Small**, and the one-line fix is the least of it. The failure path
and the status surface are the work; §4 says why.
**Touches.** `crates/backend/src/session_index_audit.rs`,
`crates/backend/src/lib.rs` (the cron recorder's success argument),
`.github/workflows/credentialed-flows.yml` (the third assertion the scope fence
was waiting for), tests. **No migration, no schema change.**
**Found by.** The dev team, 2026-11-03, in RFC 170's live rehearsal: triggering
`/__scheduled?cron=0+4+*+*+*` printed an unrelated error in the same cron pass,
and they flagged it rather than fixing it silently. **Everything past that
sentence is the architect's follow-through.**
**Relates to.** [RFC 170](../accepted/170-no-gate-can-drive-a-credentialed-flow.md)
(the capability that surfaced it on its first run, and whose third assertion
this is), [RFC 171](../accepted/171-the-arm-is-written-and-the-error-is-never-produced.md)
(a branch nothing produces; here it is a *success* nothing earns), and
[RFC 166](../accepted/166-reachability-stops-at-the-crate-boundary.md), whose
question — *does this definition have a caller?* — §5 turns around: the helper
that would have prevented this **has** callers, just not the one that needed it.

**On 1.0:** not declared, not scoped, not dated.

---

## 1. Summary

`crates/backend/src/session_index_audit.rs:165`:

```rust
.bind(&[limit.into()])          // limit: i64 = RECONCILE_BATCH_LIMIT = 1000
```

`wasm_bindgen`'s `JsValue: From<i64>` produces a JavaScript **BigInt**, which
D1's `bind()` rejects. Observed in RFC 170's rehearsal:

```
session_index_audit: D1 read failed ... D1_TYPE_ERROR: Type 'bigint' not supported for value '1000'
```

So `fetch_active_rows` fails on **every** run, and has since the module shipped
in `7d08dbf`, **2026-05-06**.

**This exact failure is documented, with its fix, at the top of
`crates/adapter-cloudflare/src/ports/repo.rs`** — *"Every integer bound here
**must** go through `d1_int()`, which does the `as f64` cast"*, under a heading
reading *"The `i64 -> JsValue` pitfall"*. §5 is about why that did not help.

## 2. The part that is worse than the bug

```rust
let rows = match fetch_active_rows(env, RECONCILE_BATCH_LIMIT).await {
    Ok(r) => r,
    Err(e) => {
        log::emit(… Level::Error … "session_index_audit: D1 read failed: {e:?}" …);
        return Ok(ReconcileStats::default());      // <-- Ok
    }
};
```

**The error path returns `Ok`.** And `lib.rs:108-115` records the cron pass from
exactly that:

```rust
let sia_result = session_index_audit::run(&env).await;
let processed_sia = sia_result.as_ref().map(|s| s.walked).unwrap_or(0);
… CronPassRecord::new("session_index_audit", …, sia_result.is_ok(), processed_sia, "apply",
                      sia_result.as_ref().err().map(…))
```

`is_ok()` is **true**, the error field is **`None`**, and `walked` is **0** —
`ReconcileStats::default()`. **So the operator-facing cron status has recorded a
successful session-index audit every day for six months, and the honest reading
of its numbers is indistinguishable from a healthy run over an empty table.**
Zero drift detected is also what a working detector reports when there is no
drift. There was no observable difference to notice.

## 3. What is actually lost

`cesauth_core::session_index::ReconcileOutcome`'s own doc comments:

- **`DoVanished`** — *"The user sees a phantom row in their list."*
- the revoked/active divergence — *"DO is revoked but D1 still thinks active …
  The user-facing page would render this as still-active and offer a no-op
  revoke button."*

**A user who tries to revoke a session and is shown that it is still active has
been told something false about their own account's security state.** The only
signal this project has for that condition is an audit event this cron has never
emitted. Whether drift is actually occurring is **unknown**, not zero — and that
distinction is the finding.

Detection-only was a deliberate choice (ADR-012 §Q1, *"operational visibility
comes first … watch for a few weeks before we wire up the destructive D1
mutations"*). **The weeks of watching never happened**, so the decision that was
supposed to follow them has no input.

## 4. Direction

**The one-line fix is necessary and not sufficient.** Three things:

1. **Bind through the `f64` cast.** `d1_int`'s body is
   `JsValue::from_f64(v as f64)`, and §5 is why the caller cannot simply call it.
2. **The failure path must not report success.** `fetch_active_rows`'s error
   must propagate, so `record_cron_pass` records `is_ok() == false` with the
   error string it already has a field for. The surrounding *"best-effort"*
   semantics are correct **per row** — a single DO query failure should log and
   continue, and the module doc says so — but a failure to read **any** row is
   not one row failing, it is the pass not happening.
3. **A witness, which is RFC 170's third assertion.** RFC 170's scope fence
   says *"a third assertion arrives only when a third finding needs one — and
   that finding's own RFC or handoff should say so"*. **This is that finding and
   this is it saying so.** The assertion is that the pass **walks rows**: seed
   an active `user_sessions` row, trigger the cron, assert the recorded pass has
   `processed > 0`. A `success` flag alone is exactly what six months of this
   looked like.

## 5. The generalisable finding: the guard was unreachable from the one place that needed it

`d1_int` is **`pub(crate)`** in `cesauth-adapter-cloudflare`. The pitfall is
documented in that crate, the helper lives in that crate, and **every integer
bind inside it goes through the helper correctly.** The single `.bind` site in
`cesauth-backend` that binds an integer could not use it, and is the one that is
broken.

Swept, so the class is counted rather than assumed — `grep -rn "\.bind(" `
`crates/backend/src` returns **four** sites: this one, and three binding a
`&str` (`tenant_admin/overview.rs:82`, `:97`, `api_v1/quota.rs:135`), which are
fine because strings are accepted. **One instance, not a family** — but it is
the only member of the family that exists outside the crate holding the cure.

**So the lesson is not "read the doc".** It is that a documented pitfall whose
remedy is `pub(crate)` has a blast radius of exactly the callers that cannot
reach it, and nothing in the project's gates asks whether an integer reaches
`bind()` without the cast. Two candidate shapes, neither decided here:

- **make the remedy reachable** — `pub` the helper (or a `D1Int` newtype that
  makes the raw `i64` path unrepresentable at the type level, which is the
  stronger version and the one RFC 172 §4.1's reasoning would favour);
- **gate it** — a check that every `.bind(&[…])` argument in the workspace is
  either a string-ish expression or passes through the cast. This is a
  `route-contracts-check.sh`-shaped census, and it belongs to RFC 171's family
  (*does the code reach the guard it documents?*) rather than here.

**Not folded into the fix.** A P1 whose repair is three lines should not wait on
a workspace census, and the census would be the second thing this project has
learned it needs from one `.bind` line.

## 6. What this RFC does not claim

- **No exposure.** Nothing is newly reachable and no credential is weakened.
  Drift, if it exists, has been invisible rather than created.
- **No count of actual drift.** It is unknown, by construction, and the fix's
  first green run is the first datum. **Do not let the repair's report state a
  drift figure as though it were historical.**
- **Nothing about repair.** ADR-012 §Q1's detection-only decision stands and is
  not revisited; this RFC restores the detection it already chose.
