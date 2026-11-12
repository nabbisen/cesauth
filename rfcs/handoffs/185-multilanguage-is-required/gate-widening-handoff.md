# Developer Handoff — RFC 185 §5.2, round 2: make the gate's zero mean something

**Governing RFC.** `rfcs/accepted/185-multilanguage-is-required-and-the-csr-app-has-no-locale-at-all.md` — §8 first.
**Prior reviews.** `.git-exclude/reviewed/185-gate-type-and-record-review.md` (**F-A**),
`.git-exclude/reviewed/185-slice3-screen1-review.md` (**F-1**, **F-B**).
**Target release.** **Minor.** A new CI gate condition changes what contributors
must satisfy, which `rfcs/handoffs/TEMPLATE.md` names as disqualifying for a patch.
**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing.

---

## 1. Purpose

The i18n ceiling gate currently **certifies files at `0` that still contain
hardcoded natural language**. After this lands, a ceiling of 0 means what it
reads as, and the four screens about to be converted inherit a gate that can
actually see their English.

**This cut converts nothing.** It widens the matcher, measures what that
exposes, and caps it. Conversion is later work.

## 2. Why this matters

Round 1's **F-A** said the matcher misses English inside `format!` HTML
templates and in non-standalone positions. Screen 1 then **demonstrated** it:
`pages/operator/audit.rs:321` was `<th scope="col">"Seq"</th>` — English, in a
`<th>`, on a screen the gate scored `cjk 0 + en 0` against a ceiling of 0. The
literal shared its line with its own tags, and clause (b) requires the literal
to be the entire trimmed content of its line.

So the gate's zero is currently a weaker claim than it reads, **and four more
screens are about to be converted against it.**

**The tension, stated so it is not rediscovered as an objection.** Widening
exposes a large amount of debt in directories whose conversion is not
scheduled, producing recorded debt and no user-visible improvement. That is
real, and the answer is that a ceiling *caps* what it exposes: today those
directories can accumulate English prose with **zero signal**. Capping is
protection even when conversion is distant. A gate that certifies falsely is
worse than a gate with big honest numbers.

## 3. Resolved decisions — do not re-open

**D1. Convert nothing.** No literal moves onto the catalog in this cut. Not in
`pages/`, not in the server directories, not the two the architect's probe
happened to surface. The deliverable is a matcher, a hit list, and ceilings.

**D2. The matcher is yours to design, and that is deliberate.** The architect
specified the first matcher without validating it and shipped the blind spot
this cut exists to close — **F-A is that mistake**. §4 F2 hands you a probe as
a *starting point with its defects already named*, not a specification. You
propose the final rule; G1 approves it before any ceiling is written.

**D3. Ceilings may only go down, slack is a hard failure, test paths stay
excluded.** Unchanged from the shipped gate: `scripts/drift-scan.sh`'s
`I18N_CEILINGS`, D4/D5/D7 of the original handoff. Widening changes *what is
counted*, not *how the ceiling behaves*.

**D4. Existing ceilings will move, and that is expected.** A widened matcher
re-scores the 18 listed files too. Where a file's count rises above its current
ceiling, **raise nothing** — recompute the whole table from the new matcher and
replace it, stating in the report that the table was rebaselined rather than
edited. That is the one circumstance in which a number in that table may be
larger than before, and it is allowed only because the *measurement* changed,
not the tree.

**D5. `templates/` scoring 0 under the probe is correct, not a bug.** Its text
nodes are `{placeholder}` interpolations fed by `lookup()`, so there is no
literal to count. If your matcher makes `templates/` non-zero, check whether it
is counting interpolations before concluding the directory got worse.

## 4. Facts already measured — do not re-derive

**If any of this fails to reproduce, that is a finding — report it.**

**F1 — volume.** The architect's probe, over non-test code in the six scanned
directories:

| scope | current gate | probe |
|---|---|---|
| `pages/` | 198 → 174 after screen 1 | **167** |
| `components/` | 12 | **10** |
| `admin/` | **0** | **179** |
| `templates/` | 0 | **0** (D5) |
| `tenancy_console/` | **0** | **279** |
| `tenant_admin/` | **0** | **164** |
| total | 210 | **799** |

**~622 of those are in the three server directories the gate currently reports
as 0.** That also puts a number on review finding **F-B**, which said their
size was unmeasured: 48 of 55 server-template files make zero `lookup()` calls,
and this is roughly how much text that is.

**F2 — the probe, with its known defects.** Starting point only.

```sh
awk '/^#\[cfg\(test\)\]/{exit} {print}' "$f" | grep -vP '^\s*//' \
  | grep -oP '>\s*"?[^<>"{}]*[A-Za-z]{3}[^<>"{}]*"?\s*<' \
  | grep -vP '^>\s*"?[a-z][a-z0-9-]*"?\s*<$'
```

It reads a text node as `>text<` on one line, which works for both a `view!`
child inline with its tags and a `format!` raw-string HTML template. **It
catches `>"Seq"<`** — verified against `git show 2ea2758:…/pages/operator/audit.rs`,
so the demonstrated miss is closed.

**Defects already found, in about a minute of looking — there will be more:**

- **It reads Rust generics as HTML.** `-> Result<` matches as a text node
  `> Result<`. Any `Vec<`, `Option<`, `HashMap<` after a `>` or `->` is the
  same class. **This is the one that most needs solving** and it is why the
  matcher is not specified here.
- `>RUNBOOK_URL<` matches — an identifier, but genuinely rendered inside a
  sentence, so whether it is debt is a judgement call you should state rather
  than assume.
- The `[A-Za-z]{3}` floor is arbitrary. It admits `Seq` (wanted) and would
  admit `col` were it not for the lowercase-exclusion.

**F3 — baseline gates at `0.100.0` (`cf34d37`).** Host **1,711 / 0 / 4** across
**12** `test result:` lines. `route-contracts-check.sh` exit 0, **197 routes**,
E3 47 · GATE_42 24 · NONCE 13 · E4 219 · E5 19 · E6 95 · E7 156.
`drift-scan.sh` clean, 10 sections, i18n ceiling **104 scanned, 15 hit, 18
entries**. `cargo check` warnings **8** frontend, **1** core. Bundle
**900,733 B**.

## 5. Report-and-stop gates

**G1 — the matcher and the hit list, before any ceiling is written.** Report:

1. **The rule you propose**, in words and as the command.
2. **The full hit list as a redirected file** under your evidence directory —
   file:line:literal for every hit. At this volume that is output redirection,
   not transcription.
3. **Every false-positive *class* enumerated** — not every instance. Name the
   class, say how the rule excludes it, and give one example. F2 names two
   classes to start from; find the rest.
4. **Per-directory classification with a stated sample size.** Do **not**
   hand-classify 799 literals: say "sampled N of M in this directory, found
   K classes", per the *cost the evidence bar before setting it* discipline.
   A full enumeration of classes plus a sample of instances is the bar.
5. **The proposed ceiling table**, rebaselined per D4.

**Stop there.** This is the same shape as screen 1's G1, for the same reason.

**G2 — the regression that proves the point.** Show the widened matcher firing
on the historical `"Seq"` literal (`git show 2ea2758:…`) and the shipped matcher
*not* firing on it. That is the fires/does-not-fire pair for the widening
itself, and it is free because the commit is in history.

## 6. Change scope

| # | Task | Files |
|---|---|---|
| **T1** | Design the matcher; produce G1 and stop | — (measurement only) |
| **T2** | Implement it in the existing `drift-scan.sh` section, replacing clause (b). Keep clause (a) as-is | `scripts/drift-scan.sh` |
| **T3** | Rebaseline `I18N_CEILINGS` from the new matcher (D4) | `scripts/drift-scan.sh` |
| **T4** | G2's pair, plus the three pairs the shipped gate already requires (over-ceiling, under-ceiling, unlisted file) re-driven against the new matcher | — |
| **T5** | Update the section's header comment: the F-A limitation text is now partly obsolete, and the honest new statement of what the gate does and does not see replaces it | `scripts/drift-scan.sh` |

## 7. Explicit non-change scope

- **Convert nothing** (D1).
- **Do not touch `pages/operator/audit.rs`** — screen 1 is done.
- **Do not change ceiling mechanics** (D3).
- **Do not start screens 2–5.** They follow, each on its own handoff.
- **Do not fix `admin/safety.rs`'s two sentences**, or `role_impact.rs`'s
  fragment sentence, or anything else the hit list surfaces. Report, do not fix.
- Standing rules: **no `cargo fmt`**; no route-string changes; no `#[allow]`.

## 8. Task detail worth stating explicitly

**The RFC 182 polarity applies and the dangerous direction is the pass.** In
this gate "no match" is the pass condition, so a match→miss error is a **false
pass** — a literal becomes invisible and the ceiling is satisfied by a count
that is too low. Every `grep` in a pipeline needs `|| true` under
`set -euo pipefail`; state per site whether a miss produces a false failure or a
false pass.

**A ceiling built on false positives is tolerable; one built on false negatives
is the bug.** If you must err while designing the rule, err toward catching too
much: a false positive inflates a number that can only go down, while a false
negative is exactly the defect this cut exists to remove. Say which way you
erred.

**Do not special-case `admin/safety.rs`.** Its two sentences were the original
blind-spot example and the temptation is to tune the rule until they are caught.
Tune for the class, then check they fall out of it.

## 9. Assert machine-checkable things mechanically

```sh
# 1. The widened matcher catches the historical miss (G2).
git show 2ea2758:crates/frontend/src/pages/operator/audit.rs | <your matcher> | grep -c 'Seq'

# 2. Nothing outside scripts/ changed -- this cut converts nothing (D1).
git diff --name-only | grep -v '^scripts/drift-scan.sh$' || echo "(clean)"

# 3. The ceiling table and the matcher agree on every file: drift-scan exit 0
#    with 0 violations and 0 stale is itself that assertion.
bash scripts/drift-scan.sh
```

## 10. Required tests and evidence

The full set from §10 of the screen-1 handoff, unchanged, plus the G1 hit-list
file and G2's pair. Expected against F3: **host tests, route-contracts and
warnings all unchanged** — this cut touches one shell script, so **any movement
in those is a finding, not a pass.** `drift-scan.sh` exit 0 with the new
figures.

**Evidence policy.** Every file under `evidence/` is redirected command output.
The hit list especially: at ~800 lines a transcription is not possible and not
acceptable.

## 11. What must NOT be claimed

- **Do not claim the gate now catches all hardcoded natural language.** It will
  catch more. State the residue: what shape of literal still escapes, with an
  example, the way F2 does for the current rule.
- **Do not claim the server directories are "now covered"** — they are
  *counted*. Nothing is converted and nothing is localised.
- **Do not claim a ceiling of 0 proves a file is converted**, for any file.
  That inference is what this cut exists to make *less* wrong, not to make safe.

## 12. Prohibited shortcuts

- No converting a literal to make a number move.
- **No raising a ceiling** — except the whole-table rebaseline of D4, which is
  a measurement change and must be stated as one.
- No `continue-on-error`; no weakening the gate until it passes.
- No tuning the rule to a single file (§8).
- No `cargo fmt`.

## 13. Acceptance criteria

RFC 185 §5.2, re-met against a matcher that sees what the first one missed.

**Checked hardest:** (1) G1's false-positive *class* enumeration, because a
rule validated against one example is how the first matcher shipped;
(2) G2's pair; (3) that nothing outside `scripts/` changed.

## 14. Known risks

- **The volume may make the rule look worse than it is.** 799 is not a
  regression; it is the first honest count. If your rule yields a very
  different total, report the difference and its cause rather than reconciling
  to mine — mine is a probe with known defects.
- **The Rust-generics false positive is the hard part.** If you cannot
  discriminate it cleanly, say so and propose the narrowest rule that does,
  even if it catches less. A smaller honest rule beats a larger guessed one.
- **If the work turns out materially larger than scoped, stop and report.**
  Re-scoping is the architect's call.

## 15. Review request

Write to `.git-exclude/review-request/`. Include: the matcher rule in words and
as a command · G1's four parts · G2's pair · the three re-driven ceiling pairs ·
every log from §10 · the §9 assertions · gates against F3 · the residue
statement (§11) · unresolved issues · requested review focus.

**Report the path only.**
