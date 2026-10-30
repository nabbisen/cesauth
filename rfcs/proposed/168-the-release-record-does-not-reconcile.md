# RFC 168 — The release record does not reconcile with the tags, and nothing checks either

**Status.** **Proposed** 2026-10-31. Awaiting nabbisen's acceptance.
**Tier.** **P1.** Nothing is exposed and nothing is broken at runtime. Four
versions the tree cites as shipped have **no tag**, two tags have **no release
notes**, and **seventeen HTTP routes shipped in five patch releases** against
the policy's own first minor trigger. The release record is the project's
account of itself, and it does not add up.
**Size.** Small for both checks. The disposition of the six mismatched versions
is the owner's and is §5.
**Touches.** `scripts/` (a section in an existing release-gating script),
`CHANGELOG.md` (annotations only, if §5 goes that way), `ROADMAP.md`'s
versioning policy.
**Found by.** The architect, 2026-10-31, answering *"Is there no other points to
be fixed on semver?"* — the two fixes made that day were the two I happened to
have touched, which is not an audit.
**Relates to.** RFC 028 (whose own enforcement gap was found the same day),
RFC 151 (`done/` cannot distinguish shipped from working), RFC 156, RFC 163,
RFC 164, RFC 165, RFC 166 — the sixth instance of a documented rule with no
gate.

**On 1.0:** not declared, not scoped, not dated. Nothing here is a 1.0
requirement — though §3 is the kind of thing that has to be true before a 1.0
can mean anything.

---

## 1. Summary

Three findings, each derived today and each reproducible from a command.

**(a) Four versions are documented and were never tagged.** `CHANGELOG.md` plus
the archive carry `## [X]` entries for **0.50.3, 0.64.0, 0.78.13 and 0.79.7**;
`git tag` has none of them. **0.64.0 is a minor.** They are not dead letters:
those four are cited in **55 files** across `.rs`, `.sh` and `.md` — including
`scripts/drift-scan.sh`'s own reason string (*"renamed to delivery_payload in
v0.50.3 (RFC 008)"*) and `crates/backend/src/lib.rs`'s RFC 011 test comment.
**A release gate's justification cites a version that was never cut.**

**0.79.7 is the one that matters most.** It is the release note RFC 161 §7
quotes as evidence — *"35 GET routes under `/admin/console/*` … migrated"* —
and the basis for dating the console's disconnection. That analysis stands on a
version with no artifact.

**(b) Two tags have no release notes.** **0.50.2** and **0.79.6** are tagged
and appear in the CHANGELOG only in passing — an *"Upgrade path 0.50.1 →
0.50.2"* fragment, and the heading *"Note — 0.79.6 through 0.81.3 could not
serve a request"*. Neither has a `## [X]` entry. (0.1.0, 0.2.0, 0.3.1 and 0.4.0
are also entryless and are **not** counted here: the policy states it begins at
0.18.0, and pre-policy artifacts are out of scope.)

**(c) Seventeen routes shipped in five patch releases.** The policy's first
minor trigger is *"a new HTTP route surface"*:

```
0.79.0 -> 0.79.1   ROUTES +1   (165 -> 166)
0.79.1 -> 0.79.2   ROUTES +1   (166 -> 167)
0.79.2 -> 0.79.3   ROUTES +1   (167 -> 168)
0.79.3 -> 0.79.4   ROUTES +3   (168 -> 171)
0.79.5 -> 0.79.6   ROUTES +11  (171 -> 182)
```

Across all **115** tags from 0.18.0 onward these five are the only violations —
no patch has ever added a migration or bumped the MSRV, which stayed `1.85`
throughout. So the rule has held everywhere except one six-release window, and
that window is RFC 115 Phase C's CSR migration, where JSON endpoints were being
added beside the HTML routes they served.

## 2. What is established

1. **Every figure above is from a command, and the first version of that command
   was vacuous.** The audit's first run reported *"0 violations"* because the
   loop never updated its `prev` variable, so the comparison never executed. It
   printed a clean bill of health having compared nothing. **That is this
   project's recurring defect reproduced inside the audit of it**, and it is why
   §3's check must print its own comparison count.
2. **Nothing checks any of this.** No workflow reads `CHANGELOG.md`; none
   compares tags to entries; none compares a release's level to what it changed.
   The thirteen release gates all pass over every finding above.
3. **The MSRV column is clean and worth saying so.** `rust-version = "1.85"` has
   never moved, so the question of whether an MSRV bump is a minor has not yet
   been answered by accident — it can be decided deliberately.

## 3. Direction

**Two checks, one home.** `drift-scan.yml` is already the gate for "the
repository contradicts itself" and is already taking RFC 164's link check and
RFC 028's byte budgets. The manifest stays at **13**.

1. **Reconciliation.** Every `git tag` matching `X.Y.Z` has a `## [X.Y.Z]`
   entry in `CHANGELOG.md` or the archive, and every such entry has a tag.
   Failures are named, with both directions distinguished — "documented, never
   tagged" and "tagged, never documented" are different defects with different
   remedies. Pre-0.18.0 is excluded by a named, dated entry, because the policy
   says so and an unexplained exclusion is how an exemption list starts rotting
   (RFC 165).
2. **Level.** At a cut, a **patch** must not add a registered route, a
   migration, or an MSRV bump versus the previous tag. This is the check that
   would have caught (c), and it is mechanical: the route extractor already
   exists in `route-contracts-check.sh`.
3. **Both print their population.** Tags compared, entries compared,
   comparisons actually performed. §2.1 is the reason this is a requirement and
   not a nicety: a check that silently compares nothing is worse than no check,
   because it reports success.

## 4. One open question, not a fork

**Is an MSRV bump a minor?** The policy does not say. The ecosystem is split and
Cargo does not enforce it. It has never arisen here, so the honest move is to
decide it before it does rather than discover the answer in a release note.
**My recommendation: yes, a minor** — raising the required toolchain is the
clearest possible case of an operator reading a release note and having to do
something, which is the test §Versioning policy now states. But it is a
judgement and it belongs to the owner.

## 5. The six mismatched versions — the owner's disposition

Tags are immutable and owner-authorised, so this RFC proposes nothing unilateral.

- **For the four documented-but-untagged (0.50.3, 0.64.0, 0.78.13, 0.79.7):**
  **do not retro-tag.** Choosing the commit would be a guess, and a signed tag
  asserting a date and a tree that nobody verified is worse than a gap. Instead
  **annotate the four CHANGELOG entries** to say they were documented and never
  cut, so the 55 citations resolve to something true. The reconciliation check
  then exempts exactly those four, named and dated.
- **For the two tagged-but-undocumented (0.50.2, 0.79.6):** write the missing
  entries from the commits between their neighbours, marked as reconstructed
  **after** the fact rather than presented as contemporaneous notes.
- **Either way, the citations get corrected**, starting with the two that are
  load-bearing: `drift-scan.sh`'s v0.50.3 reason string and RFC 161 §7's
  reliance on v0.79.7.

## 6. What this does not claim

- Not that (c) was careless. Five patch releases in one migration window, out of
  115 tags, with every other trigger clean — that is a rule that held and a
  window where it did not, and RFC 115 Phase C was adding JSON endpoints beside
  existing HTML routes rather than opening new surface area. **The finding is
  that nothing noticed, not that someone chose wrongly.**
- Not that the four untagged versions were never released in any sense. What is
  established is that no tag exists; what happened at the time is not something
  this RFC reconstructs.
- Not an audit of pre-0.18.0. The policy begins there and so does this.
- Not that SemVer requires any of it. At `0.y.z` the spec imposes no rule
  (§4; its PATCH/MINOR/MAJOR requirements are scoped `x > 0`). Everything here
  is the project's own rubric holding itself to account — which is the only kind
  of account that matters before a 1.0.
