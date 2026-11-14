# Private document manifest

**Every document outside git's control that this project relies on, classified.**

`.git-exclude/` is deliberately untracked — it holds the architect/dev-team
workflow, specs, roles and correspondence. That is a legitimate choice, and it
creates a specific hazard: **a private document can quietly become an authority
that no reader of this repository can reach.** It has happened — the Category
A–D taxonomy was a header field on 64 RFCs with its definition only in a private
strategy, and `Tier` `P0`–`P3` was defined nowhere at all.

This manifest is the answer, and it is **gated**: `scripts/drift-scan.sh` fails
when a file appears under the normative directories with no row here, when a row
names a file that is gone, or when a row's named in-repo document does not
exist. A new private document therefore cannot become an authority silently —
it has to be classified first.

**The rule this serves** is in
[contributing.md §Documentation self-containment](./contributing.md): normative
content that tracked files depend on must live in a tracked file; a citation to
a private document is provenance and is permitted only alongside the substance
being cited.

## Classifications

| | meaning |
|---|---|
| **`provenance`** | The repo cites it only as *where a rule came from*. Every citation carries the rule itself inline, so nothing is lost if the document is never seen. |
| **`extracted`** | Its governing content is carried by a named in-repo document. The private copy is the origin; the tracked one is the authority. |
| **`partial`** | Some governing content is in-repo at the named document, and **coverage has not been fully verified**. An honest in-between, not a resting place — each `partial` row is work remaining. |

## Manifest

Paths are relative to `.git-exclude/`. The gate parses this table.

| path | class | in-repo authority | notes |
|---|---|---|---|
| `specs/security-critical-assurance-strategy-v.0.80.2.md` | `extracted` | `docs/src/expert/adr/020-security-assurance-posture.md` | Category A–D, the adopt/pilot/defer/reject direction, §9 design guidance, and the two §5 invariants RFCs 118 and 120 cite as authority. The gap that prompted this manifest. |
| `specs/cesauth-external-design-v2-v0.78.13.md` | `provenance` | — | Baseline `0.78.13`, 24 minors behind `0.102.0`. RFC 132 quotes §4 verbatim before replacing it; the successor is `docs/src/expert/view-rendering-policy.md`. `pages/sessions.rs` cites §S-11 and enumerates its three UX requirements inline. |
| `specs/cesauth-requirements-v2-v0.78.13.md` | `provenance` | — | Same baseline and staleness. `rfcs/done/017` cites §5 and states the uniqueness check in full. Publication declined on staleness — see contributing.md §Direction. |
| `specs/mockup` | `provenance` | — | The UI mockup repository. RFC 180 imported from it at pinned revision `df3d9d0`; `scope_breadcrumb.rs` cites external design §8.2 and states the rule inline. |
| `specs/cesauth-handoff-files-260630-0.81.0.tar.gz` | `provenance` | — | A point-in-time archive of handoff files. Historical; nothing tracked depends on its contents. |
| `rules/000-rfc-lifecycle-policy.md` | `extracted` | `rfcs/done/000-rfc-lifecycle-policy.md` | **The tracked copy is the superset** — 700 lines against 617, carrying §22's evidence-term amendment (RFC 151) and a project adoption note the private copy lacks. The authority is already in the repo; this is the ancestor. |
| `rules/project-instructions-general-common.md` | `partial` | `docs/src/expert/contributing.md` | **Verified 2026-11-14, gaps enumerated.** In-repo: RFC management (RFC 000), plans in `rfcs/`/`ROADMAP.md`, changes in `CHANGELOG.md`, mdbook under `docs/src`, Apache-2.0 + author, README shape, and now the English-only rule. **Not in-repo**: the design-before-implementation workflow chain; *"less is more"* as a stated UI/UX principle; the documentation personas; and **the per-release security audit with its threat-model trigger** — see `ROADMAP.md`, which carries all four as rows. |
| `rules/project-instructions-rust.md` | `extracted` | `docs/src/expert/contributing.md` | **Verified and closed 2026-11-14.** All of it is now in-repo at §Test file organization: the `some_mod/tests.rs` separation, the no-`#[test]`-in-impl rule, the split-when-large rule, the `tests/` consistency rule, and the Rust 2024 / 2018+ module layout. It had been enforced by practice for **four releases** (v0.75.0–v0.78.0, test-file modularization) and written nowhere. |
| `roles/high-capability-model-operating-instructions.md` | `partial` | `docs/src/expert/contributing.md` | The architect role. `contributing.md` carries the review/authorization boundary and the gate-running split; the full operating instruction is not mirrored and does not need to be — but the split is asserted, not verified. |
| `roles/mid-capability-model-operating-instructions.md` | `partial` | `docs/src/expert/contributing.md` | The implementing role. Same status. The handoff template (`rfcs/handoffs/TEMPLATE.md`) carries most of what a reader needs. |
| `roles/ai-multi-agent-software-development-organization-and-workflow.md` | `partial` | `docs/src/expert/contributing.md` | The workflow itself. Visible in-repo through the handoff/review/authorization structure; the organizing document is not mirrored. |

## What this manifest is not

It does **not** publish or summarise the private documents, and it is not a
table of contents for them. It records **what the repository depends on and
where that dependency is satisfied** — nothing more. A `provenance` row is a
statement that the repo needs nothing from that file.

It also does not cover `review-request/`, `reviewed/`, `release/`, `tasks/` or
`upstream/`. Those are **evidence**, not authority: their conclusions are
summarised in the `ROADMAP.md` row, the `CHANGELOG.md` entry or the RFC's own
outcome section, and that summary is what makes a pointer to them acceptable.
The 2026-11-14 audit measured 154 such citations and spot-checked the summaries.
