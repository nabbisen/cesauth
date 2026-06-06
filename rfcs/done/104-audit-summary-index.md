# RFC 104 — Code audit summary index (v0.65.0)

**Status**: Index document | **Tier**: Documentation

## Overview

This document indexes the findings from the v0.65.0 codebase audit
(performed against 1,192 tests, 165 routes, 93 prior RFCs). Each finding
is detailed in an individual RFC.

## Audit scope

- **Files audited**: every `*.rs` under `crates/{core,ui,worker,adapter-cloudflare,adapter-test,migrate,migrate-test}/src/`
- **LOC counted**: 58,601 production lines (excluding tests)
- **Test count**: 1,192 (726 core / 125 adapter-test / 310 ui / 31 migrate)
- **Warning count**: 28 `cargo build` warnings

## Findings summary

### Category A — Duplicated logic (high priority)

| RFC | Subject | Severity |
|---|---|---|
| **096** | 5 `constant_time_eq` implementations, 3 ISO-8601 formatters, 3 `test_signer` builders | High |

Same pure functions independently re-implemented across crates. Risk:
incremental drift in subtle behavior.

### Category B — Bloated files (medium priority)

| RFC | File | Lines | Issue |
|---|---|---|---|
| **097** | `crates/core/src/i18n.rs` | 1,145 | Single `lookup()` fn with 145 match arms (684 lines) |
| **098** | `crates/ui/src/templates.rs` | 1,537 | 5 unrelated surfaces in one file |
| **099** | `crates/core/src/admin/service.rs` | 706 | 11 unrelated services co-located |

Each of these is technically working code; the problem is editing friction
and review fatigue as the codebase grows.

### Category C — Boilerplate (medium priority)

| RFC | Subject | Affected files |
|---|---|---|
| **100** | Worker route auth preamble (5 lines × 59 routes) | 59 |

Macros or combinators can eliminate the boilerplate and prevent drift.

### Category D — Dead code (low priority, easy)

| RFC | Subject | Count |
|---|---|---|
| **101** | Unused imports, missing `Debug` derives, dead `design_tokens.rs` | 28 warnings |

Mechanical cleanup. `design_tokens.rs` is the standout — it's a public
module that no one imports.

### Category E — Hardcoding (medium priority)

| RFC | Subject | Instances |
|---|---|---|
| **102** | UI route paths hardcoded as string literals | 202 |
| **103** | TTL constants scattered across 12+ files | 10+ |

Both are correctness risks (renames don't propagate, two TTLs of `3600`
exist for the same concept).

## Recommended sequencing

Given disk constraints and review bandwidth, recommend implementing across
two release cycles:

### v0.66.0 — Hygiene + utility extraction (small risk, immediate benefit)

1. **RFC 101** — Dead code cleanup (warnings to zero, ~30 min)
2. **RFC 096** — Shared utilities extraction (~2 hours)
3. **RFC 103** — TTL constants centralization (~1 hour)

These are safe: each change is localized, mechanical, and verifiable by the
existing test suite.

### v0.67.0 — Structural refactoring (more impactful, more careful)

4. **RFC 100** — Worker auth boilerplate macros (~2 hours)
5. **RFC 099** — `admin/service.rs` split (~1 hour)
6. **RFC 097** — `i18n.rs` split into sub-modules (~3 hours)
7. **RFC 098** — `templates.rs` split (~3 hours)
8. **RFC 102** — UI route path catalog (~4 hours)

These touch many files and warrant careful review per commit.

## Non-findings (audited, deemed acceptable)

For transparency, the following were audited and **deemed acceptable as-is**:

| Subject | Why acceptable |
|---|---|
| `security_headers.rs` 847 lines | Cohesive — one concept (HTTP security headers); split would fragment |
| `totp.rs` 632 lines | Cohesive — full RFC 6238 implementation in one place is correct |
| `worker/src/lib.rs` 597 lines, 160 route registrations | Necessarily the central table; splitting risks routes being silently unregistered |
| `migrate/src/main.rs` 1,024 lines | One-shot CLI tool, not on the hot path; rewriting carries no immediate benefit |
| Admin frame files at ~400 lines each | Mostly inline CSS; RFC 082's design_tokens.rs (if RFC 101 wires it in) would address this |
| Three independent `escape()` and `lookup()` calls per template | Inherent to the rendering pattern; macros would obscure flow |

## Statistics

- **Total RFCs to address audit**: 8 (RFC 096–103)
- **Estimated total effort**: ~16 hours of focused work
- **Expected line count reduction**: ~1,500 lines (4-5%)
- **Expected file count after splits**: ~25 new files, ~3 deleted
- **No public API changes** required by any of these RFCs.
