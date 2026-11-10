# RFC 183 — Verus narrow pilot: one proof obligation on the TOTP truncation

**Status.** **Accepted 2026-11-09** — the owner's reply was *"RFC 183 is
accepted."* **Handoff deliberately HELD until `0.95.0` is tagged**: slice 1 is
with the dev team now, and this RFC's code (a `verification/` directory and a
drift check in `drift-scan.sh`) landing on `main` first would put work into
`0.95.0` that the scope the owner reviewed does not describe — the same hold
RFC 180 took until `0.92.7` existed. Proposed 2026-11-09. The owner installed
Verus locally
(`0.2026.07.27.31579f0`) and, told that moving it out of Category D was a
strategy decision, replied *"Agreed with your suggestion"* — the suggestion
being **a narrow pilot with a named target and RFC 124's time-boxed
adopt/defer/reject discipline**, not the "broad Verus" strategy §12 declined.
**This RFC moves Verus from Category D to Category C for one function only.**
**Tier.** **P3.** Nothing is broken. This is an assurance experiment.
**Size.** **Small, by mandate** — the same constraint RFC 124 sets on itself.
**Touches.** A new `verification/` directory, out-of-workspace like `fuzz/`,
**plus one drift check** (§4). **No production code changes.**
**Depends on.** Nothing. Deliberately — RFC 124 is blocked on RFC 120, and this
pilot is chosen so it is not.
**Relates to.** RFC 124 (Kani + TLA+, `proposed`, which names Verus as out of
scope). §5 is explicit that this RFC's verdict is **comparative against Kani**.
**Target release.** Not scheduled. Sequence-keyed after `0.95.0` (RFC 181 §7.1).

**Number note:** 182 is skipped. No RFC 182 exists, but
`rfcs/handoffs/182-the-release-gates-turn-a-match-into-a-miss/` already carries
that number, and reusing it would mislead.

---

## 1. The target, verified not chosen from memory

`crates/core/src/totp.rs:242-260`, `compute_code` — RFC 4226 §5.3 dynamic
truncation:

```rust
let result = mac.finalize().into_bytes();          // GenericArray<u8, U20>
let offset = (result[19] & 0x0f) as usize;         // 0..=15
let bin_code = ((result[offset]     & 0x7f) as u32) << 24
             | ((result[offset + 1] & 0xff) as u32) << 16
             | ((result[offset + 2] & 0xff) as u32) << 8
             |  (result[offset + 3] & 0xff) as u32;
```

**Two proof obligations**, both quantified over all 2^160 HMAC outputs:

1. **`offset + 3 < result.len()`** — no index can panic.
2. **`bin_code < 2^31`** — RFC 4226's requirement that the high bit be cleared,
   which is what `& 0x7f` is for and which nothing currently states.

## 2. Why this target and not the obvious one

**Verus is strong on** computed slice indices, masks, shifts, integer
overflow, loop invariants, and panic-freedom. **Weak on** strings, `async`,
trait objects, and external crates. This function is the former and touches none
of the latter: pure, total, no allocation, no `?`.

**`util::constant_time_eq_bytes` is deliberately NOT the target**, despite being
the obvious-looking pick and despite RFC 124 naming it for Kani. Its whole
purpose is a **timing** property, and **Verus cannot express or prove timing
properties at all.** Choosing it would produce a proof of the one thing about
that function nobody doubts, and say nothing about the thing that matters. Named
here so the pilot is not retargeted at it later for looking easy.

## 3. There is no bug today, and the honest reason it still matters

**The indices are safe in fact.** `& 0x0f` bounds `offset` to ≤ 15, the array is
20 bytes, so the maximum index is 18. **No defect is being reported.**

What is true:

- **The indices are runtime-checked.** `GenericArray` indexes through slice
  semantics, so `result[offset + 3]` is a bounds check, not a compile-time
  guarantee.
- **The invariant that makes it safe is unstated anywhere** — it lives in the
  `& 0x0f` and in RFC 4226, not in a type, an assertion or a comment that ties
  the mask to the bound.
- **It is on the live MFA path.** `routes/me/totp/verify.rs:343` →
  `verify_with_replay_protection` → `totp.rs:340`, which calls `compute_code`
  **once per candidate step in the skew window**. A panic there is a Worker
  panic on every TOTP verification attempt.
- **No test can close it.** The existing RFC 6238 vector tests
  (`totp/tests/rfc6238_vectors.rs`) check three known inputs. The property holds
  over 2^160 HMAC outputs; sampling cannot establish it, and a future change to
  the mask, the digest width, or the offset derivation would break it silently.

**That is the whole case: a cheap, total, provable property that tests can only
sample.** If the pilot cannot show value on this, it is unlikely to show it
anywhere in this codebase, which is itself a useful verdict.

## 4. The pilot's real risk: a proof about a copy that has drifted

Verus requires code inside its own `verus!{}` macro and its own toolchain, so
the pilot verifies a **copy** in `verification/`, exactly as `fuzz/` sits
out-of-workspace. **A copy that drifts from production verifies fiction**, and
this project has already paid for that class of mistake (RFC 171 Q1 found a
match arm the real adapter could never produce; the standing lesson is
*check the double agrees with the real adapter*).

**So the drift check is a deliverable, not a nicety.** The pilot is not
complete without a check that fails when the copy and
`crates/core/src/totp.rs`'s truncation block diverge — byte-comparison of the
extracted statements is sufficient and is the cheapest thing that works. It
belongs in `scripts/drift-scan.sh`, and **RFC 182's rule applies**: no
`cmd | grep -q`, no `| head`, no `awk … exit` pipe.

**If the drift check cannot be built cheaply, the honest verdict is reject** —
an unverifiable copy is worse than no proof, because it reads as assurance.

## 5. The verdict is comparative, and "reject" is a real outcome

RFC 124 already proposes **Kani** on small pure functions, and **a 20-byte array
is well within bounded model checking's reach** — Kani could very plausibly
discharge both obligations in §1 more cheaply, with no copy and no drift check,
because it works on unmodified Rust.

**So this pilot's question is not "can Verus prove it?" — it almost certainly
can. The question is whether Verus buys anything Kani does not, for this
codebase.** The deliverable is a written verdict of **adopt narrowly / defer /
reject**, and it must answer:

1. Did the proof find anything, or confirm what reading the code already showed?
2. What did the copy-plus-drift-check cost, in lines and in cycle time?
3. **Would Kani have done this without a copy?** If yes, say so plainly.
4. Does the `verus!{}` requirement mean adoption implies production annotation —
   and if so, is that acceptable given the Worker's `wasm32` build?

**A verdict of "reject Verus for this class, prefer Kani" is a success**, not a
failed pilot. A pilot that cannot reach that conclusion was designed to succeed.

## 6. Non-goals

- **No broad Verus.** Strategy §12 declined it and this RFC does not reopen it.
  One function.
- **No production code change**, and **no Verus in CI** — the toolchain is not
  pinned, is owner-installed, and the owner has said an upgrade is intended.
- **No second target**, however tempting once the harness exists. A second
  target is a second RFC with its own verdict.
- **Not a dependency of anything.** Like RFC 124, nothing is blocked on it.
- **No claim about timing, side channels, or the cryptography itself.**

## 7. Time-box and acceptance

**Five working days**, half RFC 124's budget because it is one function and one
tool rather than four functions and two tools.

Done when: the two obligations in §1 are discharged or shown not to hold; the
drift check exists and has been seen to fail on a forced divergence; and §5's
four questions are answered in writing with a verdict.

**Abandoned, with that recorded as the result, if** the toolchain cannot build
the harness within the box, or if the drift check cannot be made to work.
Neither is a reason to extend the box.

---

## 8. Outcome — ran 2026-11-10, reviewed the same day, `e124e4b`

**Verdict: reject Verus for this class. The comparative half is open, not
settled.** Report `.git-exclude/review-request/183-verus-pilot-report.md`,
review `.git-exclude/reviewed/183-verus-pilot-review.md`.

**Both obligations hold.** `verus verification/totp_truncation.rs` →
`3 verified, 0 errors` in 0.42s, at the owner's own installed
`0.2026.07.27.31579f0`. Neither obligation follows from the masks alone;
both needed an explicit `by (bit_vector)` lemma, placed outside the marked
region so the region stays byte-identical to production. No production code
was touched — `git diff 0.95.0..HEAD -- crates/core/src/totp.rs` is **0
bytes** — and the copy's marked region matches `totp.rs:253-257` with both
sides at sha256 `27017c36256f6371…`.

**The proof is not vacuous, and this is what proves it, not the count.**
Weakening `& 0x7f` to `& 0xff` fails the **postcondition**; weakening
`& 0x0f` to `& 0x1f` fails a **bounds precondition** — one failure per
obligation, reproduced independently at review. **The `3 verified, 0 errors`
string does not itself witness obligation 2**: deleting the `ensures`
entirely still prints `3 verified, 0 errors`, because the count is *(number
of `by (bit_vector)` blocks) + 1 for the function body*. Anyone citing this
pilot should cite the weakening pair, not the 3.

**§4's drift check was built, and fails loud in both directions.** Forced
one-character divergence → **exit 1** naming both files and printing both
blocks; production's anchor line broken → **exit 2** reporting `found 0`
rather than skipping silently. It is text-only by construction: it cannot
know whether anyone re-ran Verus, and it compares only the marked region, so
it would not notice a deleted postcondition. Both limits are recorded on the
ROADMAP row that will decide the file's fate.

**§5 Q2's cost, corrected at review** — the report's own figures understated
it by about a quarter, in the direction that *strengthens* the rejection:

| | reported | actual |
|---|---|---|
| `verification/totp_truncation.rs` | 42 lines | **51** (44 non-blank, 20 non-blank-non-comment) |
| `verification/README.md` | 45 lines | **52** |
| `scripts/drift-scan.sh` added | ~65 lines | **85** |
| total | 152 | **188** |

Engaged time ~2–2.5 hours against a five-working-day box.

**§5 Q3 is unanswered, not answered negatively.**
`cargo install --locked kani-verifier` was refused outright by the
implementer's sandbox policy; they reasoned in its place, per §7's own
fallback, and flagged honestly that a focused Kani harness would plausibly
still want the truncation step factored into its own `#[cfg(kani)]`-gated fn
to keep the model checker out of `hmac::Hmac<Sha1>`, with **no measured
number** for the state-space cost. So **"prefer Kani" is this RFC's
hypothesis, not its finding.** A ROADMAP row carries the trial, and either
outcome deletes `verification/` and this RFC's drift check.

**§5 Q4 remains open by design.** Whether `verus!{}`/`vstd` compile for
`wasm32-unknown-unknown` under the *normal* toolchain was not tested, because
testing it would have required the production change §2 forbids. It is moot
if Kani wins and decisive if in-production annotation is ever revisited.

**What this pilot actually bought**: not a bug — none was expected, and §3
said so — but the knowledge that Verus's cost for this class is a permanent
out-of-workspace copy plus 85 lines of gate that can only police the *text*,
with the re-run left to a human because §6 keeps Verus out of CI. That is
what the rejection rests on.
