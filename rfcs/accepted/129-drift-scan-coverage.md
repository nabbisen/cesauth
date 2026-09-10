# RFC 129 — Drift-scan coverage: the `crates/` blind spot

**Status.** Accepted — approved by the owner 2026-09-10.
**Author.** Architect · **Date.** 2026-09-10
**Priority.** P2 — no user-visible impact; it protects the thing that protects
everything else.
**Target release.** 0.83.0, alongside RFC 131 R5.
**Number.** 129 was reserved during the RFC 126 sweep and never written. It has
been cited as the owner of this problem in three reviews since. This is that
document, finally.

---

## 1. Summary

`scripts/drift-scan.sh` carries four rules for the RFC 114 crate renames, and
every one of them excludes `crates/` — so the gate that exists to catch stale
names cannot see stale names in the source. RFC 126 disclosed this deliberately
and deferred it here. Two instances have since been caught **by hand**, both of
which would otherwise have shipped.

This RFC closes the blind spot, and — more usefully — makes drift-scan's
coverage a stated decision rather than an accident.

## 2. What is established

Current state, measured (`grep -rnE 'crates/worker|crates/ui|cesauth-worker|cesauth-ui' crates/`):

**25 hits across 24 files.** They are not one problem. They are three:

| Kind | Count | What it is | Fix |
|---|---:|---|---|
| **A — dead pointers** | 19 | `crates/worker/src/audit.rs`, `crates/ui/src/design_tokens.rs`, … A reader follows them and finds nothing | Rename to `crates/backend/` / `crates/frontend/` |
| **B — historical statements** | 6 | *"Originally part of `crates/ui/src/tenant_admin/tests.rs`. Split…"* — **true when written** | **Do not rename.** Rephrase (§5) |
| **C — an instruction that fails** | 1 | `crates/backend/Cargo.toml:19` — *"we can still run `cargo test -p cesauth-worker`"*. Copy it and it errors | Rename |

*(C is counted within A's 19; B is the disjoint 6.)*

**Kind B is the reason this needs an RFC rather than a sweep.** A blanket
rename would take six statements that are currently *true* and make them
*false* — replacing a stale pointer with a fabricated history. That is a worse
outcome than the defect.

**The two instances caught by hand**, both invisible to the gate:

1. RFC 131 R2a — `view_models/mod.rs` arrived from the mockup carrying
   *"View models and form contracts for cesauth-ui (RFC 029)"*. The implementer
   caught it while running an assertion for a different purpose.
2. RFC 134 C1-134 — `leptos_shell.rs`'s doc comment described a `dist/` layout
   that two conditions of that release had just falsified. Third staleness in
   that one comment across three cycles.

## 3. Why it matters

The failure mode is not the stale text. It is that **a gate reported clean
while the thing it guards was drifting**, which is the exact shape of every
serious defect this project has found recently: `cargo check` proved
compilation while the router panicked; `wrangler build` proved the Worker built
while `/` was shadowed; a 200 with headers proved the shell was served while
its own assets 404'd.

A rule that cannot see the largest directory in the repository is a rule that
reports what it can see and calls it clean.

## 4. Non-goals

- Not a general documentation sweep. RFC 126 did that for `docs/`; this is
  `crates/` and the scan's own coverage.
- Not adding `migrations/` to the scan. Migrations are immutable historical
  records, like ADRs — `0008_audit_chain.sql` cites
  `cesauth_worker::audit::EventKind` and that is **correct** for the version it
  describes. Stated so it is a decision, not an oversight.
- Not changing the four rules' patterns or their `docs/` exclusions.
- Not RFC 133, RFC 131, or anything in the assurance track.

## 5. The change

**D1 — Fix the 19 Kind A hits.** Mechanical: `crates/worker` →
`crates/backend`, `crates/ui` → `crates/frontend`, `cesauth-worker` →
`cesauth-backend`. Includes C's broken `cargo test -p` command.

**D2 — Rephrase the 6 Kind B statements so they are accurate *and* contain no
stale token.** Not by exclusion, not by an opt-out marker — by writing them
properly:

> *Originally part of the pre-RFC-114 UI crate's `tenant_admin/tests.rs`,
> before it was renamed to `crates/frontend`.*

The principle worth adopting: **source comments describe the code as it is
now.** Where one must reach for history, it can say so without spelling a path
that no longer resolves. The past belongs in ADRs, RFCs and the changelog,
which is exactly why those are the paths drift-scan excludes.

**D3 — Drop `crates/` from all four rules' exclusion lists.** Possible only
once D1 and D2 land; that is why the gate change goes last.

**D4 — Adopt RFC 126's deferred D5:** add `ROADMAP.md` to `SCAN_PATHS`. It was
gated on the Management-GUI scope contradiction, which the owner resolved on
2026-09-09 (console is first-class; the contradictory line is gone). Both items
widen the same gate, so they land together rather than resurrecting a `done/`
RFC to carry one line.

**D5 — Make the coverage explicit.** `SCAN_PATHS` is currently `crates`,
`docs`, `README.md`. Everything else is out by omission: `rfcs/`, `CHANGELOG.md`,
`migrations/`, `.github/`, `Makefile`, `wrangler.toml`, `scripts/`. Record in
the script which are deliberate and which are simply unconsidered — so the next
blind spot is a choice someone made rather than one nobody noticed.

Order: **D1 → D2 → D4 → D5 → D3.** The gate widens last, so it lands green.

## 6. A rule that gets stronger, not weaker

`drift-scan.sh`'s `cesauth-ui` rule carries a note: *"also the mockup's own
crate name if RFC 126 risk #2 materializes; re-scope this rule if the mockup is
adopted."*

It has materialized — R2a imported from that crate, and instance 1 above is
exactly this case. **The resolution is that the rule stands and covers more:** a
`cesauth-ui` reference in cesauth's source is wrong whether it means the crate
RFC 114 renamed or the mockup's own crate, because neither name belongs in this
tree. Remove the hedge from the rule's reason string and say that.

## 7. Testing strategy

1. `bash scripts/drift-scan.sh` clean after D1–D2, **before** D3 widens it.
2. **D3 fires:** plant `crates/ui` in a `crates/` source file, show red;
   remove, show green. The half that matters — the gate has never once fired
   inside `crates/`.
3. **D4 fires:** plant a stale phrase in `ROADMAP.md`, show red; remove, green.
4. The six Kind B statements still read as accurate history — a human reads
   them; no command can check this.
5. Full gate set green.

## 8. Risks

| Risk | Mitigation |
|---|---|
| A Kind B statement is renamed and becomes false | §5 D2 separates them explicitly, with the count and the classifying command in §2. The reviewer checks these six by eye |
| Dropping the exclusion surfaces hits §2 did not count | Then §2's measurement was wrong, which is a finding — report it rather than re-adding the exclusion |
| A legitimate future reference to the mockup is blocked | §6: that is the intended behaviour, not a false positive |
| The scan becomes slow enough to be skipped | It is `grep` over three paths; measure and record the runtime if it changes noticeably |

## 9. Acceptance criteria

1. Zero `crates/worker` / `cesauth-worker` / `cesauth-ui` references remain in
   `crates/`, and no `crates/ui` reference remains except as rephrased history
   containing no stale token — asserted by the §2 command returning empty.
2. The six historical statements are rephrased, accurate, and stale-token-free.
3. `crates/` is gone from all four rules' exclusion lists.
4. `ROADMAP.md` is in `SCAN_PATHS`.
5. Coverage is documented in the script: what is scanned, what is excluded and
   why, and what is out by omission.
6. Fires/does-not-fire pairs for D3 and D4, both halves each.
7. Full gate set green, drift-scan clean on the real tree.

## 10. Release level

**Patch.** Every item is a fix: stale text corrected, a gate's coverage
restored to what it was always meant to be. Nothing new becomes possible.

It ships inside **0.83.0**, which is a **minor** because RFC 131 R5 adds the
browser harness. Stated per `docs/src/expert/contributing.md`
§"Choosing the version level" — the release takes the higher level, and this
RFC is not the reason.

## 10a. What D4 surfaced, and my failure to measure it (C1-129)

**Added 2026-09-10**, from the implementation review.

§2 measured `crates/` and nothing else. **D4 was written without running a
single grep to see what putting `ROADMAP.md` in the scan paths would surface.**
It surfaces **eleven** hits across all five patterns — and one command would
have told me, so this RFC would have carried the ruling instead of needing a
correction cycle. Same class as RFC 134's acceptance criteria being written a
layer above the evidence, and precisely the "state the command behind the
number" discipline this project imposes everywhere else.

**The eleven are legitimate history**, read in context: per-release entries in
`ROADMAP.md`'s Shipped section. Three settle it beyond argument —

- `:781` quotes the README's false *"No management GUI"* claim, the very text
  RFC 012 corrected;
- `:1262` quotes a TODO that lived at `crates/worker/src/flash.rs:215`;
- `:154` describes RFC 126's fix by naming the patterns it fixed.

**A quotation cannot be rephrased without falsifying it**, so the technique that
worked for §5's six is unavailable. Exclusion is correct.

**Ruled: exclude `ROADMAP.md` on those five patterns only — per pattern, not per
file.** Every other pattern still scans it, which is what D4 actually buys.

**And the cost, recorded rather than inherited:** unlike `CHANGELOG.md`,
`ROADMAP.md` is **mixed** — historical entries *plus* forward-looking planning
sections, and the planning sections are exactly where a stale crate name would
be a real defect. Those are unprotected for these five patterns. The
`exclude_regex` mechanism matches file paths, not sections, so finer granularity
is not available today.

**Noted, not actioned:** that `ROADMAP.md` needs the same exclusion as
`CHANGELOG.md`, for the same reason, is evidence its Shipped section duplicates
`CHANGELOG.md`. Whether one file should hold both a plan and a release history
is a documentation-architecture question and belongs to neither this RFC nor
this cycle.

## 10b. The exclusion mechanism was inert for bare files (C1-129)

**Added 2026-09-10**, from the C1-129 review.

Adding `ROADMAP\.md` to the five `exclude_regex` fields did not turn the gate
green. The cause: `${line%%:*}` extracts a file path from a `grep -rn` line, but
grep emits **no filename prefix for a single non-directory path**, so for a
bare-file `SCAN_PATHS` entry the extraction silently yielded the **line number**
— `[[ 781 =~ ROADMAP\.md ]]` can never match. An exclusion that looks
configured and does nothing.

**Not environment-specific.** The implementer attributed it to this machine's
`ugrep`; GNU grep 3.12 behaves identically, verified. **CI was affected exactly
as much.** `README.md` has been in `SCAN_PATHS` since RFC 012, so any exclusion
targeting it would have failed silently on every platform for that whole time —
none ever did, so nothing was missed, but the mechanism was inert for bare files
from the day it was written.

**Fixed** by adding `-H` to the grep invocation, forcing the filename prefix
unconditionally. Incidentally fixes `--verbose` output for bare-file hits, which
previously showed `781:…` with no filename — ambiguous between `README.md` and
`ROADMAP.md`.

**And the class, which matters more than the instance.** This is the third time
in this programme that a check quietly did less than it appeared to: RFC 132's
E3 resolver returned "clean" when it could not locate a handler; RFC 134's smoke
gate proved the shell was served while its own assets 404'd; here an exclusion
field parsed a line number as a path. Each looked configured and was doing
nothing. The standing answer, applied all three times: **an extraction or
resolution that fails must fail loudly, never silently succeed.** A guard to
that effect lands with the release.

## 11. Open questions — resolved on acceptance

1. **Should `rfcs/` be scanned?** RFCs are decision records and legitimately
   describe superseded states in the past tense — the same argument that
   excludes ADRs. My recommendation is **no**, recorded under D5 as deliberate.
   Raising it because "RFCs are historical" is an assumption worth stating out
   loud rather than inheriting.
2. **`CHANGELOG.md`?** Same shape: released entries are immutable history.
   Recommendation: **no**, and record it.
