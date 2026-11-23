# Developer Handoff — a GitHub Release built from the CHANGELOG, and the 12 KB nobody has named

**Target**: `0.109.0`, slice B of two · **Level**: minor (ships with slice A)
**Origin**: the owner asked for CI to publish a GitHub Release with release
notes (2026-11-23). No RFC: the request is the acceptance, and the design
decisions are §3 below, in git, where the handoff is the record.
**Baseline**: `1876cc9` / tag `0.108.0`

---

## 1. Purpose

Every release this project cuts produces a signed tag, a CHANGELOG entry
and a long-form tag message — and **no GitHub Release**, so the project
has no page a reader outside the repository can land on. `gh release
list` is empty against 164 tags. This slice makes the tag push publish a
Release whose body is the CHANGELOG entry, and answers the bundle
question `0.108.0` left open while it is in CI anyway.

## 2. Why the notes come from the CHANGELOG and nowhere else

There are three candidate sources and only one of them is already the
record:

| candidate | why not |
|---|---|
| GitHub's auto-generated notes (`--generate-notes`) | a **fourth** account of what shipped, derived from commit subjects, with no security answer, no gate figures and no operator instructions. This project has spent six cuts removing records that disagree with each other; generating a new one in CI would be the largest such addition yet |
| the tag message | already written per release and narrative in tone, but it is **plain text**, it is not markdown, and it is not the document the release rubric governs |
| **the CHANGELOG entry** | **the record.** `drift-scan`'s release reconciliation already asserts that every tag has one and every entry has a tag, so the mapping the workflow needs is the mapping a gate already enforces |

So: extract `## [X.Y.Z] - YYYY-MM-DD` through the line before the next
`## [` (or the trailing `---`), and publish that. **If the entry is
missing or empty, fail the workflow** — do not fall back to generated
notes, and do not publish an empty Release. A release whose notes cannot
be found is a release whose record is broken, and the gate that would
have caught it (reconciliation) runs on the push, not the tag.

## 3. Resolved decisions — do not re-open

- **D1. Source: the root `CHANGELOG.md`, then the archive.** A current
  tag's entry is always in the root file; a backfilled one may be in
  `docs/changelog-archive/*.md`. Look in the root first, then the archive
  files — the same set `drift-scan.sh`'s `CHANGELOG_FILES` builds. Fail if
  neither has it.
- **D2. Trigger: `on: push: tags:` matching bare `X.Y.Z` only**, plus
  `workflow_dispatch` with a `tag` input (see D7). The tag pattern must
  not match anything else this repository might ever tag.
- **D3. Permissions: `contents: write`, and nothing else.** This is the
  **first workflow in this repository that writes to the repository** —
  every other one is read-only apart from `audit.yml`'s `issues: write`.
  Say so in the workflow's own header comment, scope the permission to
  the single job, and **do not** add `pull_request` as a trigger: a
  write-capable workflow that can be started from a fork's PR is a
  different security posture and this project does not want it
  (`contributing.md` §*How a change reaches `main`*).
- **D4. The Release is derived; the tag stays the authority.** The body
  ends with a line saying so: the signed tag object is what carries the
  provenance (`git verify-tag X.Y.Z`), and the Release is a rendering of
  the CHANGELOG entry for readers who are not in a terminal. Do not sign
  anything new; do not imply the Release itself is signed.
- **D5. No artifacts attached.** This project publishes no downloadable
  build: the Worker is deployed, not distributed, and attaching
  `index_bg.wasm` would imply a distribution channel that does not exist
  and that nobody has agreed to support. Rowed for whenever crates.io
  publication lands.
- **D6. Not a draft, not a prerelease, and no overwrite.** If a Release
  already exists for that tag, **fail** — a second publish for one
  version means something unexpected happened, and `--clobber` would
  hide it. `gh release create` fails on an existing tag already; do not
  work around it.
- **D7. The manifest gets a third list, not a lie in the second one.**
  `scripts/release-gate-manifest-check.sh` queries
  `actions/runs?head_sha=$SHA` **with no event filter** (`:59`), and a
  tag push carries the same head SHA as the release commit — so this
  workflow *will* appear in that query and, today, would be reported as
  `UNEXPECTED` and fail the check. Filing it under
  `not_on_release_path` would be false: it **does** run on a release.
  Add a third key, `on_tag_push`, each entry carrying a `reason`, teach
  the script to treat those as accounted-for, and keep the existing
  "exempt accounted for" count honest by counting the two lists
  separately in the summary line.
- **D8. The script must tolerate the race in both directions.** The
  manifest check runs as part of the branch push; the tag push lands
  seconds later. Whether the tag-triggered run has registered by then is
  not deterministic, so an `on_tag_push` entry must be accounted for
  **whether it appears in the query or not** — never required, never
  unexpected.

## 4. Facts already measured — do not re-derive

- `.github/workflows/` holds **15** files; 14 are the manifest's
  `release` list and `fuzz.yml` is its `not_on_release_path` entry.
- `release-gate-manifest-check.sh` is 99 lines; the comparison is
  `REQUIRED` (from `.release[]`) against `TRIGGERED` (basenames from the
  API, sorted unique), with `EXEMPT` from
  `.not_on_release_path[].workflow`; it already **fails if any
  `not_on_release_path` entry has an empty `reason`** (`:43`), so your
  new list should get the same treatment.
- **The check-run doctrine moves again.** A release tip has carried
  **14 push workflow runs → 16 check runs** for the last two releases
  (15 base, since `worker-build.yml` emits two jobs, plus the
  `Security audit` check run `rustsec/audit-check` creates through the
  Checks API). With this workflow the tip gains **one more workflow run
  and one more check run**: expect **17**, and `contributing.md`'s
  *CI gate parity* paragraph ("CI runs fourteen workflows on every push
  to `main`") needs the tag-triggered one named as a separate event
  rather than folded into that count.
- `gh` is available to workflows with `GH_TOKEN: ${{ github.token }}`;
  no new secret is needed and none may be added.
- The CHANGELOG's heading format is exactly `## [X.Y.Z] - YYYY-MM-DD`,
  and every entry is followed by a `---` separator (the 0.107.0 cut
  established that the last entry carries one too).

## 5. Report-and-stop gates

**None.** D1–D8 settle the design. **One stop condition**: if extracting
the entry for an existing tag produces something you would not want
published — truncated, missing the security answer, or picking up the
next entry's heading — stop and report the extraction's output rather
than adjusting the Release body by hand.

## 6. Change scope

| file | change |
|---|---|
| `.github/workflows/github-release.yml` (new) | T1 — the workflow |
| `scripts/changelog-release-notes.sh` (new) | T2 — the extractor, runnable locally with a version argument |
| `.github/release-gate-manifest.json` | T3 — the `on_tag_push` list |
| `scripts/release-gate-manifest-check.sh` | T3 — accept it, in both race directions |
| `docs/src/expert/contributing.md` | T4 — the parity paragraph, the check-run count, and the release rubric's new step |
| `.github/workflows/bundle-size.yml` | T5 — the attribution measurement (§8) |

## 7. Task detail worth stating explicitly

- **T2 is a script, not inline YAML.** The extractor must be runnable as
  `bash scripts/changelog-release-notes.sh 0.108.0` on a developer's
  machine and print exactly what the Release would contain — that is how
  this gets reviewed, and how the stop condition in §5 gets exercised
  without publishing anything.
- **T2's failure modes, each with its own exit:** version not found in
  any CHANGELOG file; found but the body is empty; found more than once
  (two files claiming the same version is a reconciliation defect the
  release must not paper over).
- **T1 must check out with enough history to read the archive** —
  `fetch-depth: 0` is what `drift-scan.yml` already uses and the reason
  is the same shape.
- **T1's body** is the extracted entry, then a blank line, then the D4
  provenance line naming `git verify-tag` and the tag as the authority.
  The Release **title is the bare version**, matching the tag format.
- **T5 answers `0.108.0`'s open question**, which the ROADMAP rows: the
  bundle grew **+12,841 B** for a cut whose visible surface was 11
  catalog keys and one console section — **8.5×** the per-key cost
  `0.106.0` measured (+1,516 B for 33 keys). The frontend links
  `cesauth-core` and never calls the verifier (its only mention in
  `crates/frontend/src` is a doc comment), while that cut added 742 lines
  across nine core files. **Measure, do not theorise**: add a
  symbol-level sizing step to `bundle-size.yml` (`twiggy top -n 40` on
  the release `.wasm`, or `wasm-objdump`/`llvm-nm` if `twiggy` is
  awkward to pin), print the top contributors, and report **which
  symbols account for the 12 KB**. If it is the verifier or
  `serde_json`'s derive code, say so with the numbers; if it is
  something else, that is the finding. **Do not change what is linked in
  this slice** — a fix (feature-gating the verifier out of the wasm
  target) is a separate decision that needs this measurement first.

## 8. Assert machine-checkable things mechanically

```bash
# the extractor against three real versions, one per CHANGELOG location
bash scripts/changelog-release-notes.sh 0.108.0 | head -5     # root file
bash scripts/changelog-release-notes.sh 0.95.0  | head -5     # archive file
bash scripts/changelog-release-notes.sh 9.9.9   ; echo "exit=$?"  # want non-zero

# the manifest check still passes on the last release commit, with the new list
bash scripts/release-gate-manifest-check.sh c76eafc

# and fails if an on_tag_push entry loses its reason (the :43 pattern, extended)
```

## 9. Required tests and evidence

No Rust changes, so the host suite is unchanged — **state the figure you
measured rather than assuming it**: baseline **1,769 / 0 / 4 across 12
lines**. Run the gate set as usual
(`scripts/route-contracts-check.sh`, `scripts/drift-scan.sh`, both
unaffected and both to be quoted).

**The Release itself, proved without an outward-facing surprise:**

1. Run the workflow by `workflow_dispatch` against the **already-tagged
   `0.108.0`**, with `--draft` so nothing is public yet.
2. Read the draft's body against
   `bash scripts/changelog-release-notes.sh 0.108.0` — they must be
   identical, and the body must contain the entry's security answer and
   its gate figures.
3. Publish it (`gh release edit 0.108.0 --draft=false`). `0.108.0`
   deserves a Release and this is the slice that gives it one. **State in
   the report that a public Release now exists**, and name the one-line
   reversal (`gh release delete 0.108.0`) so the owner can undo it
   without asking how.
4. Do **not** dispatch it for any other tag. The backfill question is
   rowed, not yours.

**Evidence** in `0.109.0b-evidence/`: the three extractor runs, the
manifest check against `c76eafc`, the draft body, the published
Release's URL, and `twiggy`'s output with the attribution conclusion
stated in prose.

## 10. What must NOT be claimed

- **Not that the Release is signed.** The tag is; the Release is a
  rendering (D4).
- **Not that every version has a Release.** One does, after this slice:
  `0.108.0`. The other 163 tags do not, and the backfill is rowed.
- **Not that the bundle question is closed by a theory.** It is closed by
  named symbols and their byte counts, or it stays open with the
  measurement attached.
- **Not that this workflow is a gate.** It publishes. It is not in the
  `release` list, it must never gate a release, and `contributing.md`'s
  "no check blocks anything" statement is unaffected.

## 11. Prohibited shortcuts

- No `--generate-notes`, no `--notes-from-tag`, no hand-written body (§2).
- No `--clobber`, no `--draft` left behind, no prerelease flag (D6).
- No new secret, no `id-token`, no `pull_request` trigger, no permission
  beyond `contents: write` (D3).
- Do not add this workflow to the manifest's `release` list (D7) — it
  would then be *required* on every push, which it is not.
- Do not change what the wasm links (T5).
- Do not run `cargo test --workspace --all-features`
  (`contributing.md:495-504`).

## 12. Acceptance criteria

1. A tag push publishes a Release whose body is byte-identical to the
   extractor's output for that version, titled with the bare version.
2. The extractor works for a root-file version and an archive version,
   and exits non-zero for an unknown one, an empty body, and a duplicate.
3. `release-gate-manifest-check.sh` passes on `c76eafc` with the new
   `on_tag_push` list, accounts for the entry whether or not the
   tag-triggered run has registered, and still fails on a reasonless
   entry.
4. `contributing.md` names the tag-triggered workflow as its own event,
   corrects the check-run expectation to **17** on a release tip, and
   adds the Release step to the release rubric.
5. `0.108.0`'s Release exists and is published, with its reversal named.
6. The bundle's 12 KB is attributed to named symbols, with no change to
   what is linked.
7. Gates: host **1,769 / 0 / 4 across 12 lines**, **197 routes**,
   `drift-scan` clean.

## 13. Known risks

- **The extractor is a parser over a document with a self-describing
  masthead.** The 0.102+ entries are uniform; the archive's older ones
  may not be. The `0.95.0` case in §8 exists to find that out before the
  workflow does.
- **A write-capable workflow is a new posture.** Keep the permission on
  the job, not the file-level default, and keep the trigger set to two
  events you can name.
- **`twiggy` needs a pinned version** like every other tool here
  (`DEPENDENCIES.md`), and it may need the pre-`wasm-opt` artifact to be
  meaningful — if the stripped release artifact has no usable symbol
  names, say so and measure the pre-opt one instead, stating which.

## 14. Review request

`.git-exclude/review-request/0.109.0b-release-machinery-report.md`,
evidence under `0.109.0b-evidence/`. Report the entry-point path only.
