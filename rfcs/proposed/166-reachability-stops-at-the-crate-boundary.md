# RFC 166 — Reachability stops at the crate boundary

**Status.** **Proposed** 2026-10-30. Awaiting nabbisen's acceptance.
**Tier.** **P1.** Not because anything is exposed, but because the thing it
measures went unmeasured for eleven releases while two dead-code sweeps ran past
it, and the cost was a shipped operator capability (RFC 161 §6).
**Size.** Medium. One check per layer; the hard part is the frontend layer, and
§4 says why.
**Touches.** `scripts/` (a new section in an existing release-gating script),
`docs/src/expert/contributing.md`.
**Found by.** The architect, 2026-10-30, re-reviewing RFC 161 at the owner's
request: the question *"is this service called by anything?"* answered **no**
for six of ten core services and nine of twelve frontend views, and no gate in
the project asks it.
**Relates to.** RFC 157 and RFC 159 (reachability inside `cesauth-backend`),
RFC 162 (every URL the frontend fetches has a route), RFC 156 (*a gate that
stops covering something must fail*), RFC 161 (the capability this cost),
RFC 131 (the programme that owns the repair).

**On 1.0:** not declared, not scoped, not dated.

---

## 1. Summary

Every reachability gate this project has stops at the `cesauth-backend` crate
boundary:

| Gate | Asks | Boundary |
|---|---|---|
| RFC 157's census | is this handler registered? (bare name) | `backend` |
| RFC 159's **E4** | is this handler reachable from `lib.rs` by qualified path? | `backend` |
| RFC 162 (accepted) | does every URL the frontend fetches have a route? | `frontend` → `backend` |
| RFC 165 §3 (accepted) | is every exemption entry still matched? | the gate's own lists |

**Nothing asks whether a `cesauth-core` service has a caller, or whether a
`cesauth-frontend` view does.** RFC 161 §6.2 measured the answer:

```
crates/core/src/admin/service/mod.rs      6 of 10 public services uncalled
crates/frontend/src/admin/                9 of 12 re-exported views uncalled
                                          1,746 lines + 496 lines of tests
```

All six uncalled services and all nine uncalled views belong to the same six
operator pages, disconnected by one commit in May and unnoticed since — **and
RFC 159's E4 could not have caught any of it, because all six handlers *are*
registered.** E4 asks whether the door is connected to the corridor; nobody
asked whether the corridor leads to a room.

## 2. What is established

1. **The compiler cannot see it.** Every one of these is `pub` in a library
   crate, so `dead_code` does not fire — the same reason RFC 157's premise
   failed for RFC 159's nine, one crate out. `cargo check`, clippy with
   `-D clippy::correctness`, and the thirteen release gates are all green over
   it today.
2. **The tests make it worse, not better.** `crates/frontend/src/admin/tests.rs`
   is 496 passing lines pinning views nothing renders. A test suite is a caller.
   **Any check must distinguish "called from production code" from "called from
   a test"**, or it will certify exactly the code this RFC is about.
3. **It is not confined to the admin console.** Six services and nine views are
   what RFC 161's scope covered. **This RFC states no total for the workspace**,
   because deriving one is deliverable (0) rather than something to quote.
4. **The cost is measured, not hypothetical.** RFC 161 §6.3/§6.4: a role check
   and an audit event dropped and unnoticed; RFC 141 C1-141 spent a cycle
   hardening the CSRF of a form that no page renders.

## 3. Deliverable (0) — count it before designing the check

Before any gate: for `cesauth-core` and `cesauth-frontend`, list every `pub fn`
/ `pub async fn` reachable from the crate root and report, per item, whether a
non-test caller exists anywhere in the workspace. **Report the number and the
list. Do not fix anything.**

Two reasons this is a stage and not a step. The number decides the shape: a
handful means a named allowlist is honest; hundreds means the check needs a
structural rule, as RFC 159 §4.2 found. And a large result is itself the finding
— it would mean the console is one instance of a general condition, which
changes what RFC 131 is scheduled against.

## 4. Direction, and the honest difficulty

1. **`core` is tractable.** It is a host-buildable library; a caller census over
   the workspace is greps plus a test-file exclusion. The exclusion is the
   subtle part (§2.2): `#[cfg(test)]` modules, `tests/` directories, and
   `crates/adapter-test` — which exists to be a test double and whose calls must
   not count as production callers.
2. **`frontend` is harder and must not be faked.** A Leptos component is
   "called" by appearing in a `view!` macro, by a `<Route view=…>` declaration,
   or not at all — and `app.rs`'s router is the real entry point, not any
   function. A check that only greps for `name(` will miss component usage and
   over-report. **If a sound frontend check cannot be built in one cycle, build
   the `core` half and say the frontend half is not covered** — per RFC 156, a
   gate that silently covers one of two layers is the defect, and per RFC 159
   §4.3 it must print what it did not examine.
3. **One home, no new workflow.** `drift-scan.yml` is already a release gate and
   already the home for "the repository contradicts itself"; this belongs beside
   RFC 164's link check. The manifest stays at **13**.
4. **A coverage figure, printed every run** — items scanned, called, uncalled,
   allowlisted — with the four reconciling, which is RFC 159 §4.3's rule now
   that the project has one.

## 5. What this does not claim

- Not that uncalled means deletable. Six of these services are wanted back
  (RFC 161 §9); the check's job is to make the disconnection **visible**, and
  an allowlist entry pointing at RFC 131 is the correct state for them until
  the slices land.
- Not a total for the workspace. §3 derives it; nothing here quotes one.
- Not that this would have caught RFC 162's defect, or RFC 159's. Three
  different questions at three boundaries; this is the third.
