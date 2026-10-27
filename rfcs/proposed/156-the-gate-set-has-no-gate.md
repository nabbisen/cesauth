# RFC 156 — The gate set has no gate

**Status.** **Proposed** — awaiting owner authorization.
**Tier.** P2. Nothing is broken today. The gate set is correct and complete as
of this commit; **nothing keeps it that way, and a gate that stops running
fails silently by construction.**
**Size.** Small. One check, plus one decision about the fuzz job.
**Touches.** `.github/workflows/` (a new or extended job),
`docs/src/expert/` the gate-set chapter, `scripts/`.
**Depends on.** Nothing. **Continues RFC 138** (one-time parity) and **RFC 142**
(CI had never executed).
**Found by.** The architect, 2026-10-28, during RFC 000 §22's back-fill, while
determining RFC 035's evidence term.

## 1. Summary

RFC 035 added four CI workflows. RFC 138 aligned the documented gate set with
the workflows that existed. RFC 142 established that CI had never executed at
all. **None of them left behind anything that fails when a gate stops
running**, because the absence of a job is not a failure — it is twelve green
checks instead of thirteen, and nobody counts.

I know nobody counts, because **I did not.** I wrote *"all thirteen checks
green"* in four consecutive release records before checking, and the true
number for a release commit is **twelve**.

## 2. What is established

**Nothing asserts the workflow set.** `scripts/drift-scan.sh` scans
`.github/workflows` (`:23`) but only for stale *prose*; no check compares the
gates a release is believed to run against the gates that ran. RFC 138
delivered a one-time alignment and tool pinning, not a standing check — its §3
is written as an audit, and nothing in it is executable.

**Deleting a workflow file is silent.** Verified in the same session by
deleting a route registration to test a different gate: the route-contracts
check caught *that*, because something asserts the route set. Nothing plays
that role for the gate set.

**`fuzz.yml` is the live instance of the shape, though not of the worst
reading.** Its trigger is `pull_request` with path filters on
`crates/core/src/jwt/**` and `fuzz/**`, plus `workflow_dispatch`. **It
therefore runs on no push, and is absent from every release commit's check
set** — including every release in this programme.

> **A correction, because I got this wrong twice before checking.** Two cut
> records said the job *"has never run on `main`."* It has:
> `gh run list --workflow=fuzz.yml` returns three runs, including one on
> `main` on 2026-09-23 (success) and one on a branch on 2026-10-23 (success).
> **The true statement is narrower**: it does not run on a push, so no release
> commit is covered by it. I inferred "never" from the trigger block instead of
> asking the API, which is the same error as reading a function body without
> checking its callers.

**Why that job in particular matters.** RFC 005's own rationale:
`cesauth_core::jwt::signer::verify` is *"independently-implemented code that
processes potentially adversarial tokens on every request."* A 60-second
libFuzzer pass is cheap. Whether it belongs on the release path is a real
question — the answer may well be "no, put it on a schedule" — but **it is
currently neither, and that was not decided, it was inherited.**

## 3. What is not established

That any gate has actually gone missing. I checked the current set against the
documented one and they agree. **This RFC is about the absence of a witness,
not about a known loss** — which is the same distinction RFC 155 drew, and the
same one RFC 000 §22 exists to make legible.

## 4. Direction

**A release-time assertion, not a continuous one.** The cheap, honest version:
a job that fails if the set of workflows triggered for a commit does not match
a checked-in manifest of the expected release gate set. It needs the GitHub API
(`gh run list` or the checks API) and so it is naturally a release-time or
post-push check rather than a per-PR one.

**The manifest is the valuable artifact**, more than the check: a file that
says *these are the gates a release is required to pass*, which today exists
only as prose in a docs chapter and as my own recollection — demonstrably
unreliable, see §1.

**Two sub-decisions this RFC must make, not discover:**

1. **Does the fuzz job belong on the release path?** 60 seconds is nothing;
   but a fuzz run is non-deterministic and a release gate that can fail for
   reasons unrelated to the change is a bad release gate. **My inclination is a
   schedule** (nightly or weekly) **plus the existing PR path filter**, and
   explicitly *not* the release set — with the manifest recording that as a
   decision rather than an omission.
2. **What does the manifest do about `workflow_dispatch`-only jobs?** They are
   legitimate and must not be forced into the release set to satisfy a
   checker. The manifest needs a category for "exists, deliberately not on the
   release path", and the check must assert that category is non-empty only
   where a comment says why — the same discipline as `E3_EXEMPT`,
   `GATE_42_EXEMPT` and `NONCE_EXEMPT`.

## 5. Why P2 and not higher

No gate is missing, the twelve that run are the twelve that matter, and the
one job outside the set is a fuzz pass whose absence from a release is
defensible. **The cost is that none of those three sentences is checkable** —
they are my assertions, and this session has produced four corrections to my
own assertions about counts. That is worth one check and one manifest, and not
worth more.
