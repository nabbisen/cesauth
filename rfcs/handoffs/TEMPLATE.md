# Developer Handoff — RFC NNN, <title>

<!--
Distilled from the handoffs actually run for RFCs 125, 127 and 130. Every
section below exists because its absence caused a real problem at least once.
Delete a section only when it genuinely does not apply — and say so, rather
than leaving it silently blank.

Scope of this document vs. its neighbours:
  RFC      — what to change and why; the decision record. Authoritative.
  Handoff  — how to implement and verify it safely. Never redefines the RFC.
  Task file (.git-exclude/tasks/dev-team/) — dispatch only: sequencing state,
             prior-cycle feedback, transient tree conditions. Not a summary of
             this file; duplication here is how the two drift apart.
-->

**Governing RFC.** `rfcs/accepted/NNN-slug.md` (link it once NNN is real)
**Target release.** vX.Y.Z
**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing / <the open item, and who owns it>

---

## 1. Purpose

One paragraph. What is true after this lands that is not true now.

## 2. Why this matters

The user- or operator-visible consequence, with file:line evidence. If the
answer is "nothing visible, it is hygiene", say that plainly — an honest P3
beats an inflated P0.

## 3. Resolved decisions — do not re-open

Every question the RFC left open that the architect has since settled, with
the ruling and one line of reasoning.

**An implementer must inherit no unresolved decisions.** If something here is
still open, name it and say who owns it — do not leave it implied.

## 4. Facts already measured — do not re-derive

Where the RFC contains measurements, point at them and say "treat as measured
ground." Add: *if any of this fails to reproduce on your run, that is a
finding — report it rather than working around it.*

Omit this section when the RFC contains no measurements.

## 5. Report-and-stop gates

For work whose design depends on an unknown. Each gate states what to measure,
and that the result must be reported **before** dependent work begins.

Never pin, adopt, or commit to a value nobody has verified. RFC 029 was marked
Implemented on a measurement that had stopped being true; that is what
produced the 4,568-hunk `cargo fmt` surprise.

Omit when there is nothing to measure.

## 6. Change scope

| # | Task | Files |
|---|---|---|
| T1 | … | … |

State the order explicitly when it matters, and why. Introduce any new gate
**last**, so it lands green rather than merged red.

## 7. Explicit non-change scope

The section that prevents scope creep. Name the tempting adjacent work and the
RFC that owns it. Be specific — "do not touch `ports::repo`; that is RFC 119"
beats "stay in scope."

Carry the standing rules: no `cargo fmt`; no route-string changes.

If a prior handoff's restriction is being **lifted**, say so and bound it
exactly. RFC 130 lifted RFC 127's `crates/backend/` ban for two constants and
one comment — nothing else.

## 8. Task detail worth stating explicitly

Only the tasks where the obvious approach is wrong, or the risk is invisible.
Skip anything self-evident from §6.

Worth stating whenever it applies:

- **Silent-failure risks.** A wrong value that still compiles. `path!("/me/securty")`
  compiles perfectly; the screen 404s in production.
- **Cascade errors.** Do not batch-fix from an error list where most entries
  will vanish once the root cause is fixed. Fixing a cascade at its symptom
  site is how genuine drift gets papered over.
- **Load-bearing names or values** that must match something elsewhere.

## 9. Assert machine-checkable things mechanically

Where an acceptance criterion can be checked by a command, give the command.
Anything a reviewer would otherwise eyeball is a thing a reviewer will miss.

```sh
# example: every constant resolves to a real file
```

## 10. Required tests and evidence

The full gate set as runnable commands with output redirection:

```sh
cargo test -p cesauth-core -p cesauth-adapter-test \
           -p cesauth-migrate-test -p cesauth-frontend  > evidence/cargo-test.log 2>&1
cargo check -p cesauth-backend --target wasm32-unknown-unknown > evidence/wasm32-check.log 2>&1
cargo check -p cesauth-frontend --features csr --target wasm32-unknown-unknown > evidence/csr-check.log 2>&1
cargo clippy -p cesauth-core -p cesauth-adapter-test -p cesauth-migrate-test \
             -p cesauth-frontend --all-targets -- -D clippy::correctness > evidence/cargo-clippy.log 2>&1
cargo deny check   > evidence/cargo-deny.log 2>&1
cargo audit        > evidence/cargo-audit.log 2>&1
bash scripts/route-contracts-check.sh > evidence/route-contracts.log 2>&1
bash scripts/drift-scan.sh            > evidence/drift-scan.log 2>&1
```

State the expected result for each. Current baseline: **1,233 passed, 0
failed**.

**New or changed gate → require a fires/does-not-fire pair.** Reintroduce the
defect, capture red; restore, capture green. A gate that cannot be shown to
fail is not a gate. This has been required four times and has caught something
real every time — including a script that reported `✅ All 0 routes are
documented` on an empty input.

**Evidence policy.** Every file under `evidence/` is redirected command output.
A hand-written summary line is not evidence and is rejected at review: the
v0.81.0 bundle shipped an 80-byte prose `cargo-fmt.log` asserting a clean run
that no stable `rustfmt` could have produced.

## 11. What must NOT be claimed

Where verification stops short of the real-world property, name the gap and
the honest wording. Build-time checks do not establish runtime behaviour: a
bundle can compile, be named correctly, be served, and still fail to mount.

Delete this section only when the tests genuinely prove the user-visible
outcome.

## 12. Prohibited shortcuts

- No `#[allow(...)]`, `#[cfg(...)]`, or feature gating to hide an error rather
  than fix it.
- No `continue-on-error: true`; no weakening a gate command until it passes.
- No merging a new gate red "to be fixed next release."
- No `cargo fmt` (house style — see `docs/src/expert/code-style.md`).
- No disabling a validator to silence its finding.

## 13. Acceptance criteria

Reference the RFC's numbered criteria rather than restating them. Name the one
or two that will be checked hardest.

If a criterion is expected to be unreachable, say so **here**, in advance —
RFC 127's criterion 3 was correctly reported unmet rather than quietly
relaxed, and that is the standard.

## 14. Known risks

From the RFC's risk table, plus anything implementation-specific.

Always include the escape hatch: **if the work turns out materially larger than
scoped, stop and report.** Re-scoping is the architect's call, not the
implementer's.

## 15. Review request

Write the package to `.git-exclude/review-request/`. It must include:

Implementation summary · changed files · any deviation from §6 · every log
from §10 · the §9 assertion output · the fires/does-not-fire pair · gate
results · what remains unverified (§11) · unresolved issues · requested review
focus.

Report the path only. The architect reads it there.
