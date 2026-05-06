# RFC 012: Documentation and repo hygiene — README drift, `migrate.rs` split, dev directive corrections

**Status**: Ready
**ROADMAP**: External codebase review v0.50.1 — Medium / Low findings on README drift, migrate.rs size, dev directive drift, comment staleness
**ADR**: N/A
**Severity**: **P2 — quality and reviewability; ship after v0.50.2 production-blocker sweep**
**Estimated scope**: Small per item, medium overall — ~150 LOC mechanical refactor + ~600 LOC of doc edits + new CI workflow ~80 LOC
**Source**: External Rust+Cloudflare codebase review attached to v0.50.1 conversation, plus internal cross-checks against the development directive.

## Background

Four documentation-and-cleanup items surfaced by
the external review. None affect production
behavior, but each erodes reviewability —
contributors get conflicting signals from README,
ADRs, comments, and code.

1. **README claims contradicted by reality**
   (`README.md:15-20`):
   - "No management GUI" — false; admin console
     has shipped since v0.3.0; tenant-scoped
     admin surface since v0.13.0.
   - "Audit … all land in R2" — false; R2 audit
     bucket was removed in v0.32.0; D1 is the
     single audit source.

2. **`crates/core/src/migrate.rs` is 2568 lines** —
   far above the 800-line soft cap from the
   development directive ("1 ファイルが 800 行を超え
   そうな場合や、複数の概念を抱えている場合はサブ
   ディレクトリに分割"). The file holds 9+ distinct
   concepts (types, errors, redaction, export,
   verify, invariants, import, table ordering,
   tests).

3. **Development directive itself drifted**:
   - Describes rate-limit storage as KV; actual
     implementation is a Durable Object
     (`RATE_LIMIT` DO).
   - Lists `crates/do` as a workspace member with
     DO implementations; in practice DO impls
     live in `adapter-cloudflare`, and `crates/do`
     is a small skeleton.

4. **Inline comments referencing removed
   subsystems**:
   - `worker/src/log.rs` mentions R2 as audit
     destination.
   - `core/src/types.rs` `audience` field
     commentary refers to pre-RFC-009 fail-open
     gate behavior (will be addressed during
     RFC 009 work; cross-reference here to avoid
     double-edit).

The fix is doc reconciliation, not new design.

## Requirements

1. README MUST accurately describe what cesauth
   ships today.
2. `crates/core/src/migrate.rs` MUST be split into
   submodules respecting the soft cap and
   single-concept-per-file principle.
3. Development directive MUST accurately describe
   storage backends and workspace structure.
4. Inline comments referencing removed subsystems
   MUST be updated or removed.
5. Project MUST have a routine for catching future
   doc drift (CI step or release-checklist
   addition).

## Design

### Item 1 — README rewrite

**Current** (`README.md:15-20`):

```markdown
- **Minimal surface.** No management GUI, no SAML, no LDAP, no password login.
- **Strong consistency first.** Anything that must not double-spend lives in Durable Objects.
- **Passkey first, username-less first.** Magic Link is a fallback, not the default.
- **Slim dependency graph.** Only what's known to build on the Workers WASM target.
- **Accessibility baked in.** Semantic HTML, `aria-live`, keyboard-navigable forms.
- **Audit everything sensitive.** Authentication, admin, failures, revocations — all land in R2.
```

**Replacement**:

```markdown
- **Minimal surface — minus the admin path.** No
  SAML, no LDAP, no password login. cesauth ships
  an admin console (`/admin/console/*`) and a
  tenant-scoped admin surface (`/admin/t/<slug>/*`)
  for operator and tenant administration — but no
  end-user signup gallery, no public registration UI.
- **Strong consistency first.** Anything that must
  not double-spend lives in Durable Objects.
- **Passkey first, username-less first.** Magic
  Link is a fallback, not the default.
- **Slim dependency graph.** Only what's known to
  build on the Workers WASM target.
- **Accessibility baked in.** Semantic HTML,
  `aria-live`, keyboard-navigable forms.
- **Audit everything sensitive.** Authentication,
  admin, failures, revocations — all land in D1's
  hash-chained `audit_events` table (ADR-010).
  Operators forward to external SIEM via Logpush.
```

**Other README sections to audit during this PR**:
- "Quick Start": confirm wrangler / D1 / DO setup
  steps reflect current bindings.
- "Features": confirm the enumeration is accurate
  (TOTP, anonymous trial, audit chain, multi-key
  introspection, audience scoping, repair tool,
  retention, etc. are all mentioned where present).
- "Documentation" link: confirm pointing to
  current `docs/src/SUMMARY.md` structure.

### Item 2 — `migrate.rs` split

`crates/core/src/migrate.rs` (2568 lines) splits
into:

```
crates/core/src/migrate.rs              ← shrinks to ~150 lines: facade + re-exports + SCHEMA_VERSION
crates/core/src/migrate/
├── types.rs                            ← Manifest, TableSummary, PayloadLine, FORMAT_VERSION
├── error.rs                            ← MigrateError, RedactionError
├── redaction.rs                        ← profile registry, two built-ins, apply_redaction
├── export.rs                           ← Exporter, ExportSigner, fingerprint
├── verify.rs                           ← verify function
├── invariants.rs                       ← Violation, ViolationReport, default_invariant_checks, SeenSnapshot
├── import.rs                           ← ImportSink trait
├── tables.rs                           ← MIGRATION_TABLE_ORDER, TenantScope
└── tests.rs                            ← existing tests, mostly unchanged
```

Each submodule under 500 lines. The facade
re-exports the public API so external callers see
no surface change:

```rust
// crates/core/src/migrate.rs after split
pub mod error;
pub mod export;
pub mod import;
pub mod invariants;
pub mod redaction;
pub mod tables;
pub mod types;
pub mod verify;

pub use error::*;
pub use export::*;
pub use import::*;
pub use invariants::*;
pub use redaction::*;
pub use tables::*;
pub use types::*;
pub use verify::*;

pub const SCHEMA_VERSION: u32 = 10;

#[cfg(test)]
mod tests;
```

**Mechanical refactor**. Zero behavior change. The
existing test suite (29 migrate integration tests)
is the regression gate. After the split, no test
should require modification beyond import-path
adjustments.

### Item 3 — Development directive corrections

Current directive
(`/mnt/user-data/outputs/cesauth-development-directives-v2.md`,
or after the move, `docs/src/expert/development.md`):

| Section | Current text | Correction |
|---|---|---|
| アーキテクチャ / ランタイム | "**KV** でキャッシュとレート制限のバケットを保持する" | Split: "**KV** でキャッシュ (audit chain checkpoint, OIDC discovery doc) を保持する。**Durable Objects** でレート制限のバケットを保持する (`RATE_LIMIT` DO)" |
| ワークスペース構成 | "`crates/do/` — `cesauth-do`: Durable Objects 実装" | "`crates/do/` — `cesauth-do`: Durable Object class registration skeleton (実体は `adapter-cloudflare/src/objects/*` に存在)" |

A small clarifying comment in `wrangler.toml` near
the `[[durable_objects]]` block confirms which DO
classes live where.

### Item 4 — Inline comment cleanup

Grep pass over the workspace:

```bash
git grep -nE 'R2 audit|land in R2|R2 bucket|R2_AUDIT' -- crates/
git grep -nE 'argon2id\\(secret\\)' -- migrations/  # cross-ref RFC 002
git grep -nE 'jsonwebtoken' -- crates/             # post-v0.44.0 should be empty
```

Each hit is a stale comment. The implementer reads
each and decides update vs delete. Specific known
sites:

- `worker/src/log.rs` — R2 reference in module
  doc.
- `core/src/types.rs` — pre-fail-closed audience
  gate comment (RFC 009 will rewrite the
  surrounding code; coordinate to single-pass
  edit).
- Various comments referencing
  `crate::jwt::jsonwebtoken_*` (should not exist
  post-v0.44.0).

### Item 5 — Drift-detection automation

**`scripts/drift-scan.sh`**:

```bash
#!/bin/bash
set -euo pipefail

declare -a PATTERNS=(
    "land in R2"
    "R2 audit"
    "argon2id(secret)"
    "no management GUI"
    "code_plaintext"        # RFC 008 — should be renamed to delivery_payload
    "expected_aud"          # RFC 009 — verifier no longer takes this
)

found=0
for pattern in "${PATTERNS[@]}"; do
    if git grep -l -F -- "$pattern" -- crates/ docs/ README.md 2>/dev/null; then
        echo "Stale-phrase pattern matched: $pattern"
        found=$((found + 1))
    fi
done

if [ $found -gt 0 ]; then
    echo "$found stale phrase(s) detected. Update or remove."
    exit 1
fi
```

**`.github/workflows/drift-scan.yml`** runs on
every PR, < 10s. The pattern list grows as new
"old phrases" emerge — treat as living checklist.

The pattern list deliberately includes
post-RFC-008/009 patterns (`code_plaintext`,
`expected_aud`) so the drift-scan reinforces RFC
008's static-grep test and RFC 009's parameter
removal.

**Release-checklist addition** in dev directive's
checklist section:

> - [ ] `scripts/drift-scan.sh` passes
> - [ ] README "Design principles" matches current
>   shipped feature set
> - [ ] Comments in any file edited this release
>   are factually current

### Item 6 — Move dev directive into the docs tree

The `cesauth-development-directives-v2.md` file
currently lives at `/mnt/user-data/outputs/`. It
should be versioned with the codebase. Move to
`docs/src/expert/development.md` and add to
`SUMMARY.md`. The `/mnt/user-data/outputs/` copy
becomes a dated artifact pointer — operators
reading it find a redirect note.

This makes the directive subject to the same
review and drift-detection as other docs, and
makes mdBook render it alongside expert
documentation.

## Test plan

No automated tests for documentation changes —
human-judgment items. The drift-scan script is the
ongoing gate.

For Item 2 (migrate.rs split), the existing test
suite is the regression gate. All 29 migrate
integration tests + ~50 migrate unit tests must
pass unchanged. No new tests needed.

For Item 1, a documentation reviewer (project
maintainer) approves the README edits.

## Security considerations

None. All changes are documentation or mechanical
refactor. The migrate.rs split is a pure refactor;
test suite confirms zero behavior change.

## Open questions

**Per-release drift-scan or PR-level drift-scan?**
Both. PR-level catches new drift; per-release pass
catches drift accumulated from out-of-band
documentation changes.

**Should the drift-scan pattern list be in the
test suite rather than a shell script?** The shell
script is fine — no need to load Rust toolchain
just for grep. Migration to a Rust-test-based
implementation if the patterns list grows complex
or `git grep` portability issues emerge.

## Implementation order

1. **PR 1 — Item 1**: README rewrite. ~50 LOC of
   prose. No code change.
2. **PR 2 — Item 4**: inline comment cleanup,
   driven by grep output. ~50 LOC, multi-file.
3. **PR 3 — Item 5**: drift-scan script + CI
   workflow + release-checklist update. ~80 LOC +
   new workflow.
4. **PR 4 — Items 3+6**: dev directive corrections
   + move into `docs/src/expert/development.md`.
   ~30 LOC of edits + mdBook integration.
5. **PR 5 — Item 2**: `migrate.rs` split.
   Mechanical refactor. ~150 LOC structural
   redistribution; tests gate.
6. **PR 6 — CHANGELOG + release.**

PRs 1–4 can ship in any order; PR 5 is mostly
independent.

## Notes for the implementer

- Item 2 (migrate.rs split): use `mv` + Rust's
  module system, not text-edit retyping. Run
  `cargo check` after each submodule carve-out to
  catch missing re-exports immediately.
- Item 1 (README): err on the side of fewer
  claims rather than more. Every claim is a
  future drift candidate. If a feature is
  documented in `docs/src/expert/`, the README
  can link rather than re-summarize.
- Item 5 (drift-scan): keep the pattern list
  short initially. `"R2 bucket"` is fine;
  `"audit"` would scan-fail every release. The
  patterns must be specific enough to be unique
  to stale narrative.
- Coordinate with RFC 009 on `core/src/types.rs`
  audience-gate comment — RFC 009 will rewrite
  the surrounding code, so the comment update
  rides in RFC 009's PR rather than this RFC's
  Item 4 grep pass. Track in the implementer
  handoff.
