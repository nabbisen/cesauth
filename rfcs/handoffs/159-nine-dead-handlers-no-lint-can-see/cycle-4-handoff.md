# Developer Handoff — RFC 159, cycle 4 (the last one for 0.89.2)

**Governing RFC.** `rfcs/accepted/159-nine-dead-handlers-no-lint-can-see.md` — **§4.5**, new.
**Review.** `.git-exclude/reviewed/159-cycle-3-review.md`
**Builds on.** `8761f3a` on `main`. Nothing to revert.

**Target release.** **0.89.2 — patch**, unchanged. **This is the last cycle
before the cut** — see §4.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-10-30.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. §4.3 and §4.4 are met

I re-ran both probes and all three of last cycle's, read `$?` directly rather
than through a pipe, and the counts hold: `215 = 193 + 22 + 0` clean,
`216 = 193 + 22 + 1` with the unclassified probe, `216 = 194 + 22 + 0` with the
name-collision probe. §4.4 fires **both halves from the one edit** — E1's stale
documentation warning and E4's dead handler — which is what I asked for and is
the half that reaches users.

**Two things you did better than the handoff asked:**

- **The arithmetic mismatch is its own named failure** — *"this is a bug in the
  check itself, not a finding about `routes/`"*. I asked only that the figures
  sum. Separating the two causes in the message is the part that makes a red
  build readable.
- **You widened `LIB_RS_LIVE` to a fourth call site, said so, and said you had
  not probed it.** That is exactly right: the chunk parser feeding E3 has the
  identical defect class, since a commented-out registration's text still
  contains `.get_async(`. **I built the probe you skipped** — ran the parser
  against raw `lib.rs` and against the stripped view and counted records
  carrying a `routes::` reference: **193 both ways.** Your widening is
  behaviour-preserving. Flagging an unprobed widening beats either hiding it or
  guessing at it.

Your `/*catchall` guard also checks out independently: 676 lines → 468, 208
stripped, the literal present, and the stripped view's tail intact.

## 2. §4.5 — the stale-entry detector was removed, not added

One finding, and it is a regression this cycle introduced. Your rationale for
changing `e4_named_count`:

> *"using the run's own match count instead means a future stale entry shows up
> as the identity failing to close, not as a silently wrong 'named' figure."*

**It is the inverse.** With a matched count, `scanned == handlers + named +
unclassified` is a **tautology**: every scanned function takes exactly one of
the three branches, so the sum cannot fail except through a counting bug inside
the loop. A stale entry matches nothing, increments nothing, and moves no
figure.

**Probe.** I added one stale entry —
`crates/backend/src/routes/admin/console/preview.rs::handler`, the file this RFC
deleted one commit earlier — and ran the gate:

```
ℹ️   E4 coverage: scanned 215 … 22 named non-handlers, 0 unclassified
✅  All 193 routes are documented … and every handler-shaped fn in routes/ is reachable from lib.rs
exit 0
```

**The list holds 23 entries; the gate reports 22.** Then the counterfactual,
so I was not inventing a property the old figure never had — same stale entry,
pre-cycle-3 static count restored in the identity:

```
❌  E4 coverage arithmetic does not close: 215 scanned != 193 handlers + 23 named(static) + 0 unclassified
exit 1
```

The static count was the detector. You replaced it with one that cannot fail.

**Why this is not cosmetic.** A stale entry is a **pre-authorised exemption for
a future function at that path**: delete or rename a helper, leave its line
behind, and the next `pub async fn` written at that `file::fn` is classified as
a reviewed non-handler with nobody reviewing it. My probe entry is the live
example — `handler` in a `console/` file is the most re-creatable name in this
codebase, and that exact one existed until `132c3a0`.

**And it is this RFC's own defect class for the third time.** RFC 157's
bare-name test could not see nine handlers. E4's first shape regex could not see
eleven. Now the list carrying the irreducible remainder can rot without the
gate saying so. Each time the mechanism was sound and nobody was measuring its
*coverage*. That is the thing to be suspicious of in your own work here.

**Requirement:** an entry in `NAMED_NON_HANDLERS` that matches nothing during a
scan is a **hard failure, named as its own cause** — distinct from an
unclassified function and from a dead handler, so a reader of the red build
knows whether to edit the list or the code. **Mechanism is yours.** Do not
assume restoring the old static count is the answer: it detects a stale entry
only as a sum that fails to close, which is the uninformative version of the
same signal, and it was never a deliberate detector in the first place.

**Latent today, so no finding about the current list:** 22 static entries, 22
matched, every entry's file present. I checked before writing this.

**Evidence I want, three things:**

1. **Fires:** add a stale entry (use a path that does not exist, and say in the
   report which you used) → named hard failure, exit 1, with the figures still
   reconciling for the real functions. Removing it returns to `exit 0`.
2. **Does not fire:** clean tree, `exit 0`, `22 named`, identity closing.
3. **The real list is clean:** state the static entry count and the matched
   count as two separately-derived figures with their commands, and that every
   entry's file exists.

**One observation, explicitly not a requirement.** Your own by-value/by-reference
insight could shrink the list that can rot: *takes `req`/`ctx`/`env` by
reference* is itself a classifier, and would structurally cover roughly eighteen
of the twenty-two, leaving only the few with no request-shaped parameter at all
(`quota.rs::unwrap_storage` and the two `decide_*` functions). A smaller list
rots less. **Do not do this in this cycle** — it is a bigger change than the
requirement needs and 0.89.2 should not wait on it. If it looks right to you,
say so in the report and I will record it for its own cycle after the cut.

## 3. Scope

Unchanged from cycle 3, and the same three things stay out: RFC 011's
`no_duplicate_route_registrations` (RFC 163's, the owner's fork), block
comments / `patch_async` / deeper re-export chains, and RFC 161 / RFC 162 /
RFC 158 §5.5.

## 4. Gates, and why this is the last cycle

Full set again, with counts and their commands. Baselines: host tests **1,630**
passed / 0 failed / 12 `test result` lines; `migration_chain` **35**; registered
**193**; scanned **215**; handlers **193** (182+11); named **22**; unclassified
**0**; manifest **13**; Playwright **20**; bundle **882,908 B** gzip with full
64-character sha256 per module and the parts reconciled. Nothing in this cycle
touches Rust, so any movement in the test counts is a finding.

**This is the last cycle for 0.89.2.** Three cycles of review have each found a
coverage hole in the thing built to close a coverage hole, and that is a good
reason to be thorough and a bad reason to iterate forever. The requirement here
is three lines and a probe. If review of this cycle finds something further that
is not a false certification, it goes to a follow-up RFC against the shipped
gate rather than holding the tag again — and I will say so plainly rather than
quietly extending.

## 5. Back-fill

Propose the §4.5 Status and Evidence lines in RFC 000 §22's terms the way you
have the last three cycles. I will apply them, move the RFC to `done/`, and
write the CHANGELOG and ROADMAP entries at the cut.

Report into `.git-exclude/review-request/`.
