# RFC 126 — Documentation rename sweep and drift-scan crate-name rule

**Status.** Proposed
**Tier.** P1 · Category A (one item is operationally misleading today)
**Size.** Small–Medium (documentation + one script rule; no domain logic)
**Tracks.** Architect review of RFC 125 — findings F1 and F2
(`.git-exclude/reviewed/125-release-gate-integrity-review.md` §5). Extends
RFC 012 (drift-scanner). Completes the RFC 114 workspace rename.
**Touches.** 19 files under `docs/src/` (excluding `adr/`),
`.github/CONTRIBUTING.md`, `scripts/drift-scan.sh`.
**Depends on.** RFC 125 (C1 touches `route-contracts.md`; avoid the collision).
**Target release.** v0.81.2 (patch; documentation and tooling only).

## 1. Summary

The RFC 114 workspace rename (`worker` → `backend`, `ui` → `frontend`) changed
the code but never reached the documentation. **56 stale references remain
across 19 files** under `docs/src/`. One of them documents a deployment
configuration that no longer works. Sweep them, exclude the ADRs as historical
records, and add the drift-scan rule whose absence is why this went unnoticed
for two release cycles.

## 2. Motivation

The second half is the important half. RFC 012 built `scripts/drift-scan.sh`
precisely to catch stale documentation phrases, its `SCAN_PATHS` already
include `docs/`, and it **passes clean** on a tree carrying 56 stale crate
references. The sweep is a one-time correction; the missing rule is the reason
the correction is needed at all. Fixing only the documents guarantees a third
occurrence at the next rename.

The first half is not cosmetic. `docs/src/deployment/wrangler.md:99,102`
documents:

```toml
main = "crates/worker/build/worker/shim.mjs"
command = "cargo install -q worker-build && worker-build --release crates/worker"
```

while `wrangler.toml:10` actually says `crates/backend/build/worker/shim.mjs`.
An operator following the deployment guide verbatim builds the wrong crate
path. This is in the `deployment/` section — the part of the book most likely
to be followed literally, by someone who cannot check it against the code.

## 3. Background

Distribution of the 56 occurrences:

| File | Count | Severity |
|---|---:|---|
| `docs/src/expert/csrf-audit.md` | 10 | Misleading path references |
| `docs/src/expert/tenancy.md` | 10 | Misleading path references |
| `docs/src/expert/rfc-110-baseline.md` | 5 | Misleading path references |
| `docs/src/deployment/cron-triggers.md` | 4 | **Operator-facing** |
| `docs/src/deployment/observability.md` | 4 | **Operator-facing** |
| `docs/src/expert/architecture.md` | 4 | **Documents wrong build path** |
| `docs/src/deployment/wrangler.md` | 3 | **Documents wrong build path** |
| `docs/src/expert/{admin-console,crate-layout,route-contracts}.md` | 2 each | `crate-layout.md` describes the wrong layout |
| `docs/src/deployment/{environments}.md` | 2 | Operator-facing |
| 8 further files | 1 each | Incidental |

`docs/src/expert/adr/` contains **7 further files** that match. These are
**deliberately out of scope** — an ADR records what was decided at the time it
was written, exactly like an RFC in `done/`. Rewriting them would falsify the
record. This distinction is the reason the drift rule needs a path exclusion
(§6).

## 4. Target areas

- 19 files under `docs/src/`, excluding `adr/`.
- `.github/CONTRIBUTING.md` — the `cargo test --workspace --lib` example, which
  cannot succeed on this workspace (`cesauth-adapter-cloudflare` and
  `cesauth-backend` are wasm32-only and fail host compilation by design).
- `docs/src/expert/contributing.md` — "Current highest RFC number: 029. Next
  RFC: 030", now off by ~96.
- `docs/src/beginner/prerequisites.md` — `cargo test -p cesauth-ui`, and the
  claim that `core`/`adapter-test`/`ui` are "the three crates" for host-only
  iteration.
- `scripts/drift-scan.sh` — new rule, path exclusion, and `SCAN_PATHS`.

## 5. Non-goals

- Any change to `docs/src/expert/adr/**`.
- Rewriting RFCs in `done/` or `proposed/` that reference old crate names.
- The mockup / `cesauth-ui` integration question (owner decision, still open).
- Reformatting, restructuring, or rewriting doc prose beyond the stale facts.
- The 106 residual clippy warnings.
- Anything in RFC 125's scope, including C1's edit to `route-contracts.md`.

## 6. Proposed design

**D1 — Sweep the 19 files.** Mechanical substitution: `crates/worker` →
`crates/backend`, `crates/ui` → `crates/frontend`, `cesauth-worker` →
`cesauth-backend`, `cesauth-ui` → `cesauth-frontend`. Read each hit in context
before substituting: a sentence explaining *why* something changed may
legitimately name the old crate, and those must be preserved with tense that
makes the history explicit.

**D2 — Verify the deployment docs against the source of truth**, don't just
substitute strings. `wrangler.md`, `architecture.md`, and `cron-triggers.md`
must match `wrangler.toml` and the `Makefile` as they actually are — the
rename may not be the only drift in those files.

**D3 — Add a path-exclusion field to the drift-scan pattern registry.**
Entries are currently `"pattern<TAB>reason"`. Extend to an optional third
field: `"pattern<TAB>reason<TAB>exclude_regex"`. Existing two-field entries
must continue to work unchanged.

This mechanism is required, not cosmetic: `crates/worker` in
`docs/src/expert/adr/015-magic-link-mailer.md` is textually identical to
`crates/worker` in `architecture.md`, so no pattern can distinguish the
historical record from the live error. Path exclusion is the only way to
express "stale here, correct there."

**D4 — Add the crate-name rules**, excluding `docs/src/expert/adr/`:

```
"crates/worker	RFC 114 renamed crates/worker → crates/backend	docs/src/expert/adr/"
"crates/ui	RFC 114 renamed crates/ui → crates/frontend	docs/src/expert/adr/"
"cesauth-worker	RFC 114 renamed cesauth-worker → cesauth-backend	docs/src/expert/adr/"
"cesauth-ui	RFC 114 renamed cesauth-ui → cesauth-frontend	docs/src/expert/adr/"
```

**D5 — Add `ROADMAP.md` to `SCAN_PATHS`.** Currently
`SCAN_PATHS=(crates docs README.md)` — `ROADMAP.md` is not scanned. This is
not hypothetical: the registry already carries the pattern
`"No management GUI	README claim corrected in v0.52.1 (RFC 012)"`, and
`ROADMAP.md` still asserts under "Explicitly out of scope" that a management
GUI is not planned — contradicted by the README, External Design v2 §4, the
shipped `crates/frontend`, and the entire mockup track. The rule to catch it
has existed since v0.52.1; it has simply never been pointed at the file.

**Sequencing caveat:** adding `ROADMAP.md` will surface that contradiction as a
CI failure. Its resolution is a **pending owner scope decision**, not a
drafting fix. Therefore: land D5 only after the owner rules on the
Management-GUI scope question, or land it in the same change as the ruling. Do
not land D5 with the contradiction unresolved — that ships a knowingly red
gate, which is precisely what RFC 125 was written to stop.

## 7. Data model / API impact

None. Documentation and one shell script.

## 8. Testing strategy

1. `bash scripts/drift-scan.sh --verbose` — exit 0.
2. **Regression guard for D3:** temporarily reintroduce a single stale
   reference into a non-ADR doc and confirm drift-scan fails on it; confirm the
   same string inside `docs/src/expert/adr/` does **not** fail. Capture both
   runs. A rule that cannot demonstrate it fires is not a rule — this is the
   whole lesson of RFC 125.
3. Confirm all pre-existing two-field patterns still fire (D3 must be
   backwards compatible).
4. `grep -rn 'crates/worker\|crates/ui\|cesauth-ui\|cesauth-worker' docs/src
   --include='*.md' | grep -v '/adr/'` — zero matches.
5. `mdbook build docs` — no broken intra-book links introduced.
6. Full gate set (RFC 125 §9) — no regression.

## 9. Migration / rollout

Single patch release **v0.81.2**, after v0.81.1 ships. Documentation-only;
nothing for consumers to do.

Order: D3 (mechanism) → D4 (rules, which will then fail) → D1/D2 (sweep until
green) → D5 (gated on the owner decision). Doing D4 before D1 is deliberate:
let the rule enumerate the work rather than trusting a hand-built list.

## 10. Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Blind substitution corrupts a sentence explaining the rename | Docs become wrong in a new way | D1 requires reading each hit in context; §8.5 link check |
| **`cesauth-ui` becomes a live name again** if the mockup is adopted — its production-safe crate is literally named `cesauth-ui` | D4's rule would fire on correct references | Flagged for the owner's UI-strategy decision; if the mockup lands, drop or re-scope that one pattern in the same change. Recorded here so it is not discovered as a mystery CI failure. |
| D5 lands before the scope ruling | Knowingly red gate | §6 D5 forbids it explicitly |
| Deployment docs have drift beyond the rename | A "fixed" doc still misleads | D2 requires verification against `wrangler.toml` / `Makefile`, not string substitution |

## 11. Acceptance criteria

1. Zero non-ADR stale crate references under `docs/src/` (§8.4).
2. `docs/src/expert/adr/**` unmodified — verify with `git diff --stat`.
3. `wrangler.md`, `architecture.md`, `cron-triggers.md` agree with
   `wrangler.toml` and the `Makefile` on build path, entrypoint, and commands.
4. `drift-scan.sh` exit 0, and the §8.2 fires/does-not-fire pair is captured as
   evidence.
5. Pre-existing patterns still fire (§8.3).
6. `.github/CONTRIBUTING.md` names a host-test command that actually succeeds.
7. `contributing.md` RFC bookkeeping current.
8. Full RFC 125 gate set green; `mdbook build` clean.
9. D5 either landed with the owner's scope ruling, or explicitly deferred with
   a note in this RFC.

## 12. Open questions

1. **D5 is gated** on the Management-GUI scope decision. If the owner rules
   that the ROADMAP entry is simply wrong, D5 lands here; if the entry is meant
   to say something narrower, the rewrite lands first and D5 follows.
2. Should the drift registry also gain a rule for the release-record mismatch
   found during the v0.81.0 review (`0.79.6` tagged with no CHANGELOG entry;
   `0.78.13` — the declared baseline of both governing specs — documented but
   never tagged)? That is a different class of check (tags vs. file content,
   not phrase matching) and may not belong in a phrase scanner. Raised because
   nothing currently guards it.
