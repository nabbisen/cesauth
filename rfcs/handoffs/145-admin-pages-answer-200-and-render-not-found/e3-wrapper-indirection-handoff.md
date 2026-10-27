# Developer Handoff — RFC 145, the E3 wrapper-indirection gap

**Governing RFC.** `rfcs/done/145-admin-pages-answer-200-and-render-not-found.md`
§12.1–12.2. **Not a cycle** — a standalone check-only item, ahead of cycles 2
and 3.

**Target release.** 0.85.1 — **and why that level:** **patch.** A gate begins
detecting what it was written to detect. No production code changes.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Found by** you, building cycle 1's
fires/does-not-fire pair.

---

## 1. Purpose

E3 asserts that a route documented `render=server` does not serve the Leptos
shell. It detects this by scanning the handler's own body for the literal
`leptos_html_shell` (`fn_body_has_shell`, `scripts/route-contracts-check.sh:211-219`).

Both shell helpers call it **one level down**:

- `routes/admin/operator_json_api.rs:38` — `operator_json_api::shell`
- `routes/admin/tenant_admin/json_api.rs:48` — `tenant_admin::json_api::shell`

So a handler that serves the shell through either wrapper **passes E3**. You
proved it by reverting `tokens::new_form` to its exact original and watching the
check pass (`evidence-145-cycle1/gap-wrapper-shaped-shell-not-caught.log`).

## 2. Why this matters more than its size

**All 35 of RFC 145's routes reach the shell through one of those two wrappers**
— 24 and 11 (RFC 145 §2). E3 therefore could not have caught any of them, and
would not catch a regression back to the wrapper shape on the two cycle 1 just
converted.

It also made an argument of mine false. RFC 145 §11.2 called "this moves them
into a class E3 already polices" the strongest reason to convert rather than
delete. It wasn't true. **The gate is the thing the project trusts when it
cannot check by hand**, and this one was reporting a guarantee it could not
provide.

## 3. Resolved decisions — do not re-open

**D1. Follow exactly one level of indirection.** A call in the handler's body to
a function whose **own** body calls `leptos_html_shell` counts as a shell call.
Not two levels, not transitively — one. Deeper chains are a report (§5.3), not a
recursion to build.

**D2. Resolve the callee with the mechanism already there.** The script resolves
`routes::<path>::<fn>` to a file by two shapes and distinguishes
resolved-clean / resolved-dirty / **UNRESOLVED (hard failure)**. Reuse it.

**D3. An unresolvable wrapper is a hard failure, not a pass.** This is C1-132's
standing ruling, in the script's own comment: a handler the check cannot find
must never be silently treated as clean. A *wrapper* it cannot find gets the
same treatment, and that is the whole reason this gap was invisible.

**D4. `E3_EXEMPT` is not touched.** RFC 132 §8 reserves that decision.

**D5. No production code changes.** If following wrappers makes a route fail,
that is a finding to report (§5.1) — not a handler to edit in this item.

## 4. Facts already measured — do not re-derive

| Fact | Command | Result |
|---|---|---|
| The detection is literal | read `route-contracts-check.sh:211-219` | `awk` over the target fn's body for `leptos_html_shell` |
| Both wrappers are one line deep | `operator_json_api.rs:38`, `tenant_admin/json_api.rs:48` | each calls `leptos_html_shell` directly |
| **Fixing this fails nothing today** | `server`-declared GET rows vs. wrapper use | **7** rows, **0** call a wrapper |
| The wrappers' share of RFC 145's routes | RFC 145 §2 | 24 + 11 = all 35 |

**That `0` is why this can land immediately.** Confirm it yourself before
starting; if it is not 0, §5.1 applies.

## 5. Report-and-stop gates

1. **A currently-passing `server` row now fails.** That is a true finding and a
   different piece of work. Report the route; change no handler.
2. **The resolver cannot resolve a wrapper** it needs to inspect. Per D3 that is
   a hard failure — report which wrapper and why, do not special-case it.
3. **A chain deeper than one level exists.** Report it. Do not add recursion.
4. **The route count moves from 193.** Nothing here should touch it.

## 6. Change scope

- `scripts/route-contracts-check.sh` only.
- Its comments: say what the check now follows and what it deliberately does
  not, so the next reader knows one level is a decision and not a limit nobody
  noticed.

## 7. Required tests and evidence

**A fires/does-not-fire pair for the wrapper shape specifically** — this is the
acceptance test, and the thing whose absence let the gap exist:

1. **Fires:** a tree where a `server`-declared row's handler calls
   `operator_json_api::shell` → the check **fails**, naming the route. Use the
   exact revert you already demonstrated.
2. **Fires, second wrapper:** the same for `tenant_admin::json_api::shell`, so
   the fix is not special-cased to the one you found.
3. **Does not fire:** the real tree → passes, **193** routes.
4. **Still fires on the direct call** — the pre-existing behaviour must not
   regress while adding the new one.
5. **UNRESOLVED still fails** (D3) — show it, however you can construct it.

Evidence under `.git-exclude/review-request/evidence-145-e3-wrapper/`, as
redirected output.

## 8. What must NOT be claimed

- **Not** that E3 now covers the admin console. It covers `server`-declared
  rows; 33 of RFC 145's routes are still `client` until cycles 2 and 3 convert
  them.
- **Not** that shell-serving is now impossible to miss. One level is followed by
  decision (D1); a two-level chain would still pass, and the comment must say so.

## 9. Acceptance criteria

1. A `server`-declared handler calling either wrapper fails E3, by name.
2. A direct `leptos_html_shell` call still fails it.
3. An unresolvable callee is still a hard failure.
4. The real tree passes with **193** routes and no `E3_EXEMPT` change.
5. All five evidence items in §7 are present.
6. No production code changed; no existing test weakened.

## 10. Review request

`.git-exclude/review-request/145-e3-wrapper-report.md`. Lead with the two
"fires" runs, since the gap was invisible for want of exactly those.
