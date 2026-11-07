# RFC 168 — The release rules are written and unenforced

**Status.** **Accepted** 2026-10-31. **Patch.** **Its three checks are still
unbuilt as of `0.92.7` (2026-11-07), and §Enforcement note records what that
cost: two misleveled releases in the 0.92.x run, an unwritten minor trigger the
project has applied in both directions within four days, and §4.2's own ruling
broken by the architect's RFC 179 handoff.** **Sequenced immediately after
RFC 164** — both add sections to `scripts/drift-scan.sh`, and these two checks
guard **every remaining cut** in the authorized sequence, so catching a mistake
on 0.90.0 is worth more than catching one on 0.93.0. Its §4 rulings are already
in effect and recorded in `docs/src/expert/contributing.md` §Cutting a release;
only the three checks remain to build. **Soft dependency, not blocking:**
RFC 165 §3 brings §3.1's historical exemption under staleness checking, after
which the exemption cannot quietly grow.
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
the same version. Neither alone is a release"*, with (at the time of writing)
six historical mismatches named and the ruling **"Do not add to this list."**
**That count was itself wrong — it is ten, and RFC 165 §3's cycle found the
missing five** (§3 below).

**Nothing checks any of it.** No workflow reads `CHANGELOG.md`; none compares
tags to entries; none compares a release's level to what it changed. The
thirteen release gates pass over every one of these rules.

**This RFC proposes no archaeology beyond correcting that count.** The ten
historical mismatches are recorded with a ruling, and the past releases are
immutable artifacts. The subject is the enforcement that keeps the rule true
from here.

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
   remedies. **The ten historical mismatches are a named, dated exemption
   carrying `contributing.md`'s own "do not add to this list" as its reason**
   (corrected from six — see §3's implementation cycle), and after RFC 165 §3
   that entry is itself staleness-checked, so it cannot quietly grow.
2. **Level backstop at the cut.** A **patch** must not, versus the previous tag,
   add a registered route, add a migration, or change `rust-version`. It is a
   backstop and not a substitute for §2.2's judgement: it catches the drift
   case, not the 0.81.2 case.
3. **Both print their population.** Tags compared, entries compared,
   comparisons **performed**. This is a requirement, not a nicety: the first
   version of the audit behind this RFC reported *zero violations* because its
   loop never updated its `prev` variable, so it compared nothing and said so
   as success. A check that silently compares nothing is worse than no check.

## 3c. The check could not survive its own release (found 2026-11-03, cutting 0.91.2)

**Check 1 as first built failed on every release commit.** A cut writes the
`## [X.Y.Z]` entry in the same commit the tag will point at, so at that commit
the entry exists and the tag cannot — and the check read that as *"documented,
never tagged"*. The gate would have been red on every cut from here on, which
is the one state that makes a check worse than none: it trains whoever cuts the
next release to ignore it.

Found by the architect while cutting the release that added the check — the
first cut it had ever seen, and the first time the question *"what does this
check do during a cut?"* was asked of it. Neither the RFC nor the dispatching
handoff asked it, which is the lesson worth keeping: **a check that reads the
release record has to be run against the act of releasing**, not only against
the record at rest.

**The fix is scoped to exactly one version**: an untagged entry is permitted iff
it equals the `[workspace.package] version` in `Cargo.toml`. That is stricter
than exempting "the newest entry" — an entry for any other untagged version
still fails, and so does an entry written for a version nobody bumped to. If
the workspace version cannot be read the check exits 2 rather than silently
stopping to exempt. Negative-tested both ways.

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
to be made, not a default.**

> **Superseded in part by [RFC 181](./181-minor-is-the-default-release-level.md)
> (2026-11-07).** The requirement that the handoff state the level and its
> reasoning **stands**, and is now a field in `rfcs/handoffs/TEMPLATE.md` rather
> than only a ruling here — because this ruling was skipped by the architect's
> own RFC 179 handoff four days after acceptance. What is replaced is the
> default it guarded: **minor is now the default and needs no trigger; a patch
> is the claim that must be argued.** RFC 181 §4 also explains why that makes
> this RFC's own §4.2 check buildable for the first time — "did the minor
> increase, and if not is there a patch argument" is mechanical, where
> detecting caller obligation was not. The level is decided at dispatch, which is
established practice; what is new is that the *reason* is written where the
implementer and the reviewer both see it, instead of living in the architect's
head until the cut.

Cheap, and it closes the gap §2.2 leaves: a judgement call made in writing at
dispatch can be challenged by review, while the same call made silently at the
cut cannot.

## 5. What this does not claim

- Not that the ten historical mismatches need fixing. They are recorded with a
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

---

## Enforcement note, 2026-11-07 — the owner asked why seven patches, and two of them were misleveled

**The owner's question**, after `0.92.7` was tagged: *"Why 0.92.7? Why was it
not 0.93? I do not believe patch versions continue even seven times."*

**Audited against `ROADMAP.md` §Versioning policy, release by release.** The run
length is not itself the defect — seven internal-only releases would be
legitimate. **Two of the seven are not internal-only, and both hit a named
trigger**, so the instinct was correct and nothing in the project caught it,
because this RFC's three checks were never built.

| release | trigger | level cut | correct |
|---|---|---|---|
| 0.92.1 | **caller obligation.** RFC 172 made `POST /webauthn/register/start` resolve its subject from the **session**, where it previously required no cookie, no header and no token, and added `require_json_content_type`. Every existing caller must now hold a session and send the header, or break. | patch | **minor** |
| 0.92.2 | none | patch | patch |
| 0.92.3 | **a removed URL**, which §Versioning policy names outright. `POST /admin/console/config/log_level/preview` and `…/apply` were **registered in `lib.rs` at `0.92.2`** (`grep -c` = 2) and are gone at `0.92.3`; `route-contracts.md` rows went **194 → 192**. | patch | **minor** |
| 0.92.4 | none | patch | patch |
| 0.92.5 | new blocking CI gate (E7) — **see §6.1** | patch | unresolved |
| 0.92.6 | new blocking CI gate (colour contrast) — **§6.1** | patch | unresolved |
| 0.92.7 | new blocking CI gate (census) + a reporting step restored to blocking — **§6.1** | patch | unresolved |

Nothing else moved across the run: `wrangler.toml` vars (**35**) and sections
(**12**) unchanged, `cesauth-core` `pub mod` (**28**) unchanged, no migration
added, no route added, no permission slug added.

**0.92.1's available excuse, named and rejected.** Its own entry says *"Exposure
was none: nobody has deployed this tree."* True, and it is why the defect was
not an incident — but it is **not in the rubric**, and admitting it would make
every breaking change a patch until first deployment, which empties the policy
of content. The policy asks *who must change their code*, not *who has already
run it*. The mirror-image worked example in §Versioning policy is **exactly this
shape**: RFC 152 half B changed no document, but *"every scripted caller of
those 34 `POST` endpoints must start sending a token or break — correctly a
minor."*

**Why 0.92.1 was misread at the time:** the policy's *"security fixes that
preserve wire compatibility also count as patch"* clause was applied without
checking its condition. RFC 172 was a security fix and did **not** preserve wire
compatibility — it deleted a request field and added two preconditions.

### 6.1 The unwritten trigger, which is the real defect and is the owner's to settle

§Versioning policy's minor triggers are: a new route surface, a new schema
migration, a new public type or trait in `cesauth-core`, a new permission slug, a
new operator-visible configuration knob, a renamed/removed URL, and the
caller-obligation catch-all. **"A new blocking CI gate" is not among them.** Nor
is "new internal module surface."

But `0.82.0`'s own release note says, verbatim:

> **Minor**, not patch: RFC 134 and RFC 132 are each fixes on their own, but
> RFC 131 R2a adds new module surface and **RFC 134's smoke gate is new blocking
> CI capability** — a release mixing levels takes the higher one.

So the project has been applying a trigger **it never wrote down**, and
**inconsistently**: by it, `0.92.5`, `0.92.6` and `0.92.7` were each a minor,
because each added a blocking gate. And the architect has already applied it in
the **opposite** direction on work not yet shipped — **RFC 180 was dispatched
2026-11-07 as a minor** on exactly the R2a precedent (*"adds module surface"*),
though it adds no route, no `cesauth-core` type, no knob, and obliges no caller.
Its ten files land **dormant**; under the written rubric alone it is a **patch**.

**The architect's recommendation: drop the unwritten trigger, keep the single
written test.** A CI gate and a dormant internal module oblige nobody, and "new
blocking CI capability" has no meaning to an integrator or operator — the only
audiences §Versioning policy's catch-all names. Consequences, stated plainly so
the choice is informed:

- **Drop it** → `0.92.5`–`0.92.7` were correctly patches, `0.92.1` and `0.92.3`
  remain the only two misses, and **RFC 180 must be re-leveled to a patch before
  it ships**, making the next cut `0.92.8`.
- **Write it in** → `0.92.5`–`0.92.7` were misleveled too (five of seven), RFC
  180 stays a minor, and the next cut is `0.93.0`.

Either way the rubric must say which, because the architect has been deciding it
silently at dispatch and has now decided it both ways within four days.

### 6.2 This RFC's own §4.2 ruling was broken by the architect, four days after accepting it

§4.2 rules that **every dispatch handoff names the target level and which
trigger the work hits**, and that *"none, therefore a patch" is an argument to be
made, not a default.*

- **RFC 179's handoff** (2026-11-07) says only *"**Target release.** **Patch —
  the next cut.** Number assigned at the cut."* **No trigger named, no argument
  made** — the default this ruling exists to forbid.
- **RFC 180's handoff** (2026-11-07) does comply: *"**Minor.** It adds module
  surface, the same reason R2a was a minor in 0.82.0."* — and §6.1 is now
  challenging that reason, which is precisely the review the ruling was written
  to enable. **The ruling worked where it was followed.**

### 6.3 What is not proposed

**Not retagging.** `0.92.1` and `0.92.3` are shipped, signed, immutable
artifacts; §Versioning policy already settles this class as historical debt
(*"those releases are immutable artifacts"*), and this RFC is forward-looking at
the owner's own direction — *"You don't have to be too sensitive on the past
versions. I care about ruling, workflow and guidelines for the future."* The two
misses are recorded here and nothing else.

**What is proposed:** build this RFC's three checks, which are still unbuilt
seven releases later, **plus a fourth it does not currently specify** — a
URL-set diff against the previous tag. That one is two lines over
`route-contracts.md` and would have caught `0.92.3` mechanically, without
judgement: **194 → 192**.
