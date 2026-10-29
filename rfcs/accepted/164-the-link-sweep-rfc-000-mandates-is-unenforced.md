# RFC 164 — The link sweep RFC 000 mandates is unenforced, and nine links rotted

**Status.** **Accepted** 2026-10-30. **Release 0.89.4 — patch**: a gate section
and a link repair, no capability added. **Queued behind RFC 159's cycle 3
(0.89.2) and RFC 162 (0.89.3)** — not dispatched, because its commits would
otherwise land on `main` under a tag not meant to carry them.
**§4's fork is decided at dispatch, not here**: the recommendation is to
de-link the two lifecycle documents' fourteen example links rather than exempt
the files.
**Tier.** **P2.** Nothing is exposed and nothing is broken at runtime. The
corpus the whole process runs on sends readers to the wrong folder, which
means to the wrong **status**.
**Size.** Small. The repair is done (see §1); the gate is a dozen lines inside
an existing workflow, and §4's fork is the only part needing a decision.
**Touches.** `scripts/drift-scan.sh` (or a new script inside
`.github/workflows/drift-scan.yml`), `rfcs/done/000-rfc-lifecycle-policy.md`
and `rfcs/archive/019-rfc-lifecycle-policy.md` if §4 goes that way.
**Found by.** The architect, 2026-10-30, running the inbound-link sweep RFC 000
requires while moving RFC 161 and RFC 162 into `accepted/` — the step itself,
done once with a script instead of by eye.
**Relates to.** RFC 000 §"Letting cross-references rot" and the lifecycle
section quoted in §2; RFC 151 (`done/` cannot distinguish shipped from working);
RFC 156 (*a gate that stops covering something must fail*); RFC 163 (three
unenforced extractors of the same fact).

**On 1.0:** not declared, not scoped, not dated.

---

## 1. Summary

A relative-link check over `rfcs/**/*.md` found **25 broken links**. **Eleven
were unambiguous and are repaired in the commit that proposes this RFC**:

| Kind | Count | Detail |
|---|---|---|
| Folder-move rot | **9** | RFC **142**, **153**, **154**, **155** all moved to `done/`; nine inbound links still point at `../proposed/` or `../accepted/` |
| Wrong relative depth | **2** | `done/001`'s ADR-008 link and `done/028`'s changelog-archive link are each one `../` short, so both resolve inside `rfcs/` |
| Illustrative example links | **14** | all inside `rfcs/done/000-rfc-lifecycle-policy.md` (7) and `rfcs/archive/019-rfc-lifecycle-policy.md` (7) — §4's fork |

**The nine did not merely break navigation; they misreported status.** A link
reading `../proposed/153-an-invitation-grants-nothing.md` after RFC 153 shipped
tells a reader RFC 153 is *proposed*. The folder is authoritative in this
project (RFC 000), so a stale inbound link is a status claim, and it was wrong
in nine places across four RFCs. That is RFC 151's subject — status that lies —
arriving through the links rather than through a Status field.

## 2. What is established

1. **RFC 000 mandates the sweep, in two places, and names this exact failure.**

   > *"when an RFC moves to `done/` or `archive/`, the maintainer also runs a
   > quick `grep -l "<NNN>-<slug>.md" rfcs/` to find inbound references and
   > updates them in the same commit … The cost is seconds per move; the
   > alternative — broken links accumulating silently — is worse."*

   and, under **Letting cross-references rot**:

   > *"The fix: a one-line `grep -l 'NNN-slug.md' rfcs/` before every move,
   > plus updating every match. Or CI enforcement. Either works; doing nothing
   > does not."*

2. **Nothing enforces it.** No workflow reads `rfcs/`. The 13 release gates are
   `audit`, `browser-tests`, `bundle-size`, `clippy`, `csr-bundle-check`,
   `deny`, `docs`, `drift-scan`, `release-gate-manifest`, `route-contracts`,
   `test`, `trunk-release-build`, `worker-build`; `mdbook build docs` passes
   because `rfcs/` is not in the book at all (`docs/src/SUMMARY.md` references
   none of it).

3. **The manual alternative was chosen and it did not hold.** Four moves, nine
   missed links. This is not a reproach of whoever moved them — it is the
   predicted outcome of the branch RFC 000 called "doing nothing does not
   [work]", and it is *why* the policy offered CI as the other branch.

4. **The remaining 14 are not rot.** Each points at an invented filename
   (`010-revoke-tokens.md`, `042-feature-flags.md`, `047-caching.md`,
   `015-deprecate-old-api.md`, `023-multi-region.md`, `035-old-caching.md`) and
   sits inside a worked example of what the index table should look like. The
   real RFCs 010, 015, 023, 035, 042 and 047 exist under different slugs, so
   retargeting them would be a fabrication, not a repair.

5. **Checked, not assumed:** the repair's correctness is the check's own output
   going from 25 to 14 in one run, with the 14 enumerated.

## 3. Direction

1. **A relative-link check over `rfcs/**/*.md`.** Every `](./…)` / `](../…)`
   target that is a path must resolve to a file that exists. Exit non-zero with
   the file, the link and the resolved path for each failure. Roughly a dozen
   lines; the prototype that produced §1's table is three.
2. **Inside an existing workflow.** `drift-scan.yml` is already a release gate
   and already the home for "the repository contradicts itself" checks, so this
   is a section in `scripts/drift-scan.sh`, **not a 14th workflow** — the
   manifest stays at 13 and needs no edit, the same reasoning that put RFC 159's
   E4 inside `route-contracts-check.sh`.
3. **A non-zero-link assertion.** If the scan finds zero *links* (not zero
   failures), that is a failure, not a pass — RFC 125 T5's rule, and the defect
   RFC 163 §2 found in RFC 011's test. A link checker whose matcher stops
   matching must say so.
4. **Extend to `docs/` targets, not to the web.** `rfcs/` links into
   `docs/src/…` and `docs/changelog-archive/…` (two of the eleven repairs were
   exactly that), so those resolve too. External `http(s)` links are **out of
   scope**: they fail for reasons that are not the repository's, and a gate that
   goes red because someone else's site is down is a gate people learn to
   ignore.

## 4. The fork: what to do about the two lifecycle documents' 14 example links

The check cannot pass while they exist as links, so one of:

1. **De-link the examples** — render them as code spans (`` `042-feature-flags.md` ``)
   or plain text in the two worked-example blocks. The documents read the same;
   nothing claims to be a destination that is not one.
2. **Exempt the two files**, named and reasoned, the way `E3_EXEMPT` /
   `E4_EXEMPT` are.

**Recommended: 1.** An exemption whose single entry is *the document that
defines the rule* is the worst possible first entry — it is the argument I made
against exempting RFC 159's tenth handler, pointed at the policy itself. And
`rfcs/archive/019` is an archived predecessor of `000`: carrying a permanent
exemption for a historical document, so that a worked example can keep
pretending to link somewhere, buys nothing.

One caveat for whoever does it: `000` is RFC 000. Editing it is editing the
policy document, so the diff should touch **only** the example blocks' link
syntax, change no sentence, and say so in the commit message.

## 5. What this does not claim

- Not that any RFC's **Status field** is wrong. This is about links; the
  folder/Status consistency question is RFC 151's and is not reopened here.
- Not that the eleven repairs needed this RFC. They were mechanical, they are
  already committed, and they are reported here as the check's first output, not
  as pending work.
- Not that `docs/` has no broken links of its own. The scan ran over `rfcs/`;
  `docs/` is `mdbook`'s and was not enumerated. If §3 step 4 lands, that
  population gets measured rather than assumed — and it is measured **before**
  anyone claims a number for it.
