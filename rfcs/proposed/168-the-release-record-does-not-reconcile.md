# RFC 168 — The release rules are written and unenforced

**Status.** **Proposed** 2026-10-31. Awaiting nabbisen's acceptance.
**Tier.** P2. Nothing is broken. Three rules the project has already written
down have nothing that fails when they stop being true.
**Size.** Small — three checks in one existing script, plus two rubric
clarifications.
**Touches.** `scripts/drift-scan.sh`, `docs/src/expert/contributing.md`
§Cutting a release.
**Found by.** The architect, 2026-10-31, asked whether anything else on
versioning needed fixing. **Forward-looking only, at the owner's direction** —
*"You don't have to be too sensitive on the past versions. I care about ruling,
workflow and guidelines for the future."*
**Relates to.** RFC 028, RFC 151, RFC 156, RFC 163, RFC 164, RFC 165, RFC 166 —
the seventh instance of a documented rule with no gate.

**On 1.0:** not declared, not scoped, not dated.

---

## 1. Summary

`contributing.md` §Cutting a release is good. It states the tag format, the
level rubric with the 0.81.2 trap that taught it, and five things every release
must satisfy — including *"A tag exists **and** a CHANGELOG entry exists, for
the same version. Neither alone is a release"*, with the six historical
mismatches named and the ruling **"Do not add to this list."**

**Nothing checks any of it.** No workflow reads `CHANGELOG.md`; none compares
tags to entries; none compares a release's level to what it changed. The
thirteen release gates pass over every one of these rules.

**This RFC proposes no archaeology.** The six historical mismatches are already
recorded with a ruling, and the past releases are immutable artifacts. The
subject is the enforcement that keeps the rule true from here.

## 2. What is established

1. **The rules exist and are specific.** §Cutting a release's five bullets and
   the level table are written, worked-example-backed, and correct.
2. **The level test is a judgement with no backstop.** *"Was anything broken
   before, and is it now fixed?"* is the right question and cannot be
   mechanised — but some of its consequences can. A patch that adds a
   registered HTTP route has added capability by any reading, and the policy's
   own first minor trigger says so.
3. **It has been wrong before, both by judgement and by drift.** §Choosing the
   version level records 0.81.2 — cut as a patch, should have been 0.82.0,
   caught by hand. And across tags from 0.18.0, **five patch releases added
   seventeen registered routes** (0.79.1–0.79.6, during RFC 115 Phase C). No
   patch has ever added a migration, and the MSRV has never moved from `1.85`.
4. **Two rubric questions are unanswered**, and both are cheap to settle before
   they arise rather than during a cut: **§4.1** MSRV, and **§4.2** what a
   handoff must state about the level.

## 3. Direction — three checks, one home, forward-only

`drift-scan.yml` is already the gate for "the repository contradicts itself"
and is already taking RFC 164's link check and RFC 028's byte budgets. The
manifest stays at **13**.

1. **Reconciliation, both directions.** Every `X.Y.Z` tag has a `## [X.Y.Z]`
   CHANGELOG entry and vice versa. The two directions are named separately —
   "tagged, never documented" and "documented, never tagged" have different
   remedies. **The six historical mismatches are a named, dated exemption
   carrying `contributing.md`'s own "do not add to this list" as its reason**,
   and after RFC 165 §3 that entry is itself staleness-checked, so it cannot
   quietly grow.
2. **Level backstop at the cut.** A **patch** must not, versus the previous tag,
   add a registered route, add a migration, or change `rust-version`. It is a
   backstop and not a substitute for §2.2's judgement: it catches the drift
   case, not the 0.81.2 case.
3. **Both print their population.** Tags compared, entries compared,
   comparisons **performed**. This is a requirement, not a nicety: the first
   version of the audit behind this RFC reported *zero violations* because its
   loop never updated its `prev` variable, so it compared nothing and said so
   as success. A check that silently compares nothing is worse than no check.

## 4. Two rulings for the rubric

### 4.1 An MSRV bump is a minor

`rust-version` has never moved from `1.85`, so this has never arisen and can be
decided deliberately instead of discovered in a release note.

**Ruling: a `rust-version` increase is a minor.** It is the clearest possible
case of the test §Versioning policy now states — *who must change their code* —
because an operator on the old toolchain cannot build at all until they act.
Cargo does not enforce it and the ecosystem is split; this is the project's
rubric, consistent with its own stated test.

### 4.2 A handoff states the level and the trigger it hits

**Ruling: every dispatch handoff names the target level and which of the
policy's triggers the work hits — and "none, therefore a patch" is an argument
to be made, not a default.** The level is decided at dispatch, which is
established practice; what is new is that the *reason* is written where the
implementer and the reviewer both see it, instead of living in the architect's
head until the cut.

Cheap, and it closes the gap §2.2 leaves: a judgement call made in writing at
dispatch can be challenged by review, while the same call made silently at the
cut cannot.

## 5. What this does not claim

- Not that the six historical mismatches need fixing. They are recorded with a
  ruling; this RFC only stops the list growing.
- Not that the 0.79.x route additions were careless — five releases in one
  migration window, out of 115 tags, with every other trigger clean. The
  finding is that nothing noticed.
- Not that SemVer requires any of this. At `0.y.z` the spec imposes no rule
  (§4; its PATCH/MINOR/MAJOR requirements are scoped `x > 0`). This is the
  project's own rubric being held to account, which is the only account that
  matters before a 1.0.
- Not an audit of anything before 0.18.0, or of the past at all beyond §2.3's
  one measurement establishing that the rule drifts when unwatched.
