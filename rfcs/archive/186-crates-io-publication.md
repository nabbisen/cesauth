# RFC 186 — crates.io publication: reserve the names now, publish later

**Status**: **Withdrawn, 2026-11-12** — the governing policy already existed at
`docs/src/expert/contributing.md` §Publishing to crates.io, decided 2026-09-10
and amended by an owner ruling 2026-10-30, and it decides this question the
other way with reasons. I did not read it before writing this RFC. The owner
accepted the RFC on my analysis; the analysis was wrong, so the acceptance was
obtained on a false premise and I did not act on it. **The live answer to the
owner's 2026-11-12 question is a dated note in that same `contributing.md`
section, not a new RFC.**

---

## Why this was withdrawn rather than amended

**1. It proposed as new a decision already taken, deliberately.**
`contributing.md:493` reads: *"The seven workspace crates are deliberately
**not** published and **not** reserved. That is a decision, not an oversight."*

**2. Its central claim is refuted by that policy.** This RFC's §2 said name
availability is *"the only element of this question with a first-come
property"* and worth closing for the price of six placeholder publishes. The
policy had already costed that and rejected it:

> Reserving names a project does not intend to use is discouraged on
> crates.io, and a placeholder buys a weaker claim than a real published crate
> — names are first-come-first-served, and **an unused name whose holder does
> not respond can be reassigned.** Treat reservation as brand assurance, not as
> a security control.

So a stub does not close the risk this RFC claimed it closes. The policy's own
answer to that risk is the opposite move: *"The real protection for it is
publishing it for real when there is a reason to, not holding it with a stub."*

**3. It would have reserved a name the project may never use.** The owner's
ruling of **2026-10-30** records that **`cesauth-core` may be renamed to
`cesauth`** — which is what the existing `0.0.0` reservation is holding. So
`cesauth-core` is plausibly a name that gets abandoned, and reserving it is
precisely the "name a project does not intend to use" case.

**4. Its §5.2 proposed writing down what "reasonable" means. That is already
written**, as five numbered criteria, better than my version — including one I
did not know (criterion 5, below).

**5. I quoted the pointer and did not follow it.** This RFC's §1 reproduces the
`Cargo.toml` comment verbatim, and that comment ends *"See
docs/src/expert/contributing.md."* The citation was in the evidence I used.

## What survives

Only the measurement, which stands and is recorded in `contributing.md`'s new
note: `cesauth` is registered (0.0.0, 2026-09-10, a 5,238-byte stub, 14
downloads); all six member names are unregistered as of 2026-11-12; crates.io
has no namespace reservation, so holding `cesauth` confers nothing over
`cesauth-core`. The last point is **consistent with** the existing policy, not
an argument against it — the policy already treats reservation as brand
assurance rather than control.

## The recurrence this is an instance of

Three memory rules exist for this and all three applied: *check an artifact
exists before a handoff names it*, *check if a rule is derived before calling
it a conflict*, and *verify the blocker before deferring a fix to it*. The
specific failure here is narrower and worth naming on its own: **I searched the
tree for the mechanism (`publish = false`, the names, the deps) and never
searched it for the policy.** `grep -n "crates.io" docs/` would have ended the
RFC before it was written.
