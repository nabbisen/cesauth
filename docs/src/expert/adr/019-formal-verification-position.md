# ADR-019: Formal verification — narrow, one target at a time, verdict-bearing

**Status**: Accepted
**RFC**: RFC 124 (proposed), RFC 183 (accepted, shipped `0.96.0`)
**Date**: 2026-11-14

## Context

The project's position on mechanised proof was, until this ADR, **cited rather
than contained**. It lived in four places:

1. A **Category A–D taxonomy** and a `§12` that declined broad Verus, in an
   architect instruction **not tracked by git**. Nine in-repo documents cited
   it, including this book, five RFCs and `ROADMAP.md`. **Closed 2026-11-14**:
   both now live in
   [ADR-020](./020-security-assurance-posture.md), of which this ADR is a
   specialisation.
2. **ROADMAP narrative prose**, inside the `## Planned` section that is 93% of a
   file 4.5× over its own budget and whose planning narrative, by its own
   record, "was never pruned as items shipped". That note still described
   RFC 183 as `(proposed)` four releases after it shipped with a verdict.
3. **RFC 183 §8's outcome**, which is the only full account of what the Verus
   pilot established.
4. **RFC 124's `Proposed` status**, which names Kani + TLA+ and excludes Verus.

A position that must be assembled from four documents, one of them absent and
one of them stale, is not a position a maintainer can apply. The owner asked for
it to be written down from the view of long-term development and maintenance;
this ADR is that, and it **contains** the stance rather than pointing at it.

**This ADR decides nothing new.** Every ruling below is already evidenced by
RFC 183's outcome, the owner's instructions, or the Category taxonomy. Where
something is genuinely open, it says so rather than resolving it by consolidation.

## Decision

### 1. Formal verification is used narrowly, per named target, with a verdict

Mechanised proof is **not** a project-wide practice and **not** a CI gate. It is
applied as a **time-boxed pilot against one named target**, producing a written
verdict of **adopt narrowly / defer / reject**.

**"Reject" is a success.** RFC 183 §5 said so before it ran, and it then
rejected its own tool. A pilot that cannot reach rejection was designed to
succeed, which makes it an advertisement rather than an experiment.

### 2. The governing cost constraint

The owner, 2026-11-10:

> Be careful about what we should rely on verus on and let verus verify. Too
> wide range will cost insanely. It should start from minimal and be optimized
> every time.

So: **one target at a time, and the cost per target must fall, or the target is
not taken.** This is the constraint that scopes every row in this area, and it is
why the Kani trial may not grow beyond RFC 183's own two obligations.

### 3. Broad Verus stays declined; the narrow pilot was the exception

Broad Verus is **Category D** — recorded, no RFC, per
[ADR-020 §2](./020-security-assurance-posture.md), which this ADR does not
reopen. Verus moved out of Category D **only** in the
narrow-pilot shape the owner agreed to on 2026-11-09, which was RFC 183: one
function, five working days, comparative verdict.

### 4. What the Verus pilot established, and what it did not

**Verdict: reject Verus for this class.** Fully evidenced.

The cost, measured and corrected upward at review: **188 lines** (51 proof + 52
README + 85 of gate), a **permanent out-of-workspace copy** of production code,
a drift check that can police only the **text**, and a re-run left to a human
because Verus stays out of CI. That is what the rejection rests on — not a
failure to prove anything.

**Both obligations did hold.** `offset + 3 < 20` and `bin_code < 2^31` over all
2^160 HMAC outputs, each needing an explicit `by (bit_vector)` lemma; neither
follows from the masks alone.

**What witnesses that is the weakening pair, not the tool's output string.**
`verus` printed `3 verified, 0 errors` — and **deleting the `ensures` entirely
still prints `3 verified, 0 errors`**, because the count is *(number of
`by (bit_vector)` blocks) + 1 for the function body*. What actually witnesses
the obligations is that `& 0x7f → & 0xff` fails the **postcondition** and
`& 0x0f → & 0x1f` fails a **bounds precondition**, one failure per obligation.
**Anyone citing this pilot cites the weakening pair.** This is recorded in an ADR
because the wrong citation is the one that reads like evidence.

**"Prefer Kani" is a hypothesis, not a finding.** `cargo install --locked
kani-verifier` was refused outright by the implementing session's sandbox
policy — blocked, not skipped for cost — so the comparative half is
**unevidenced**. It is recorded as open rather than left to harden into a
decision nobody made.

### 5. Rules for any future target

Derived from RFC 183's own shape, which worked:

- **One named target, verified to exist at drafting** — not chosen from memory.
- **Pick for the tool's strengths, not for the function's fame.**
  `constant_time_eq_bytes` was explicitly *not* the target despite being the
  obvious pick: its property is **timing**, which Verus cannot express at all,
  so proving it would certify the one thing nobody doubts.
- **No production-code annotation** without its own decision. Needing it is a
  reportable finding.
- **If the tool needs a copy of production code, a drift check is a
  deliverable** — and if it cannot be built cheaply, the honest verdict is
  reject. This project has already paid for a divergent copy (RFC 171 Q1's dead
  match arm behind a green suite).
- **The verdict is comparative.** "Tool X proves it" is not a result; "X buys
  something Y does not, at this cost" is.
- **Out of CI.** A proof whose re-run is manual must say so, and the gate must
  not imply otherwise.

### 6. The pilot's residue, and who owns its fate

`verification/` (the proof copy and its README) and `drift-scan.sh`'s 85-line
RFC 183 section are **owned by the Kani-trial decision**, not by this ADR.
**Either outcome deletes them**: Kani replaces them, or mechanised proof is
rejected for this class and they have no owner. The RFC remains the record
either way.

Two known holes are shipped knowingly, severity low, because they are two-line
hardenings of files that may be deleted:

- The gate compares **only the marked region**, so a **deleted postcondition
  passes green** while the gate still reports that the proof is about the code
  that runs.
- The gate is wrapped in `if [[ -f "$VERUS_COPY" ]]`, so **deleting the copy
  makes the gate vanish silently** rather than failing.

### 7. Open, and named so it cannot harden into a decision

- **The Kani comparison is unmeasured** (RFC 183 §5 Q3). The open question needs
  a number, not a prediction: whether a Kani harness must factor the truncation
  step into its own `#[cfg(kani)]`-gated function to keep the model checker out
  of `hmac::Hmac<Sha1>`'s internals. If it must, that is new code in
  `crates/core`, which RFC 183 barred — and the trial must weigh that openly.
- **Whether `verus!{}` / `vstd` compile for `wasm32-unknown-unknown` under the
  normal toolchain** (§5 Q4) is untested, because testing it required the
  production change RFC 183 forbade. Moot if Kani wins; decisive if
  in-production annotation is ever revisited.
- **RFC 124's standing.** It remains `Proposed`, names Kani + TLA+, excludes
  Verus, and is **blocked on RFC 120, which has not shipped** — while the queued
  Kani trial does RFC 124's Kani half at a deliberately smaller scope with no
  dependency on RFC 120. **Two plans overlap for one piece of work**, and
  reconciling them is a scheduling decision, not a consolidation this ADR may
  make silently.

## Consequences

A maintainer can now answer "what is our position on formal verification?" from
one document in the book. **And as of ADR-020 the citation chain is closed**: the
taxonomy and the standing direction this ADR specialises are both in the
repository. The wider strategy stays private, and nothing tracked depends on
reading it.

**What this ADR does not do**: reopen strategy §12, authorise a second proof
target, change `verification/`'s fate, or say anything about 1.0 — which remains
undeclared and the owner's alone.

## See also

- RFC 183 — the Verus narrow pilot and its outcome (`rfcs/accepted/`)
- RFC 124 — Kani + TLA+ pilot, proposed (`rfcs/proposed/`)
- `verification/README.md` — the proof copy's own provenance
- ADR-010 — the audit hash chain, whose integrity work is the other half of this
  project's assurance posture
