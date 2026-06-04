# ADR-016: Operational baseline — Cloudflare plan tier and resource budgets

**Status**: Accepted  
**RFC**: RFC 013, RFC 025  
**Date**: 2026-05-xx  

## Context

The v0.50.1 external codebase review surfaced four undocumented operational
assumptions: cron-pass subrequest budget, `/introspect` D1 query count, worker
bundle size, and `nodejs_compat` necessity.

This ADR establishes the official baseline for cesauth deployment.

## Decision

### Plan tier: Paid

cesauth targets the **Cloudflare Workers Paid plan** as its supported
deployment baseline.

**Rationale**: The daily cron passes consume more than the Free plan's
50-subrequest-per-invocation limit when configured at their defaults:

| Cron pass | Worst-case subrequests | Free limit | Paid limit |
|---|---|---|---|
| `session_index_audit` | ~2000 (1000 DO peeks + 1000 writes) | **50** | 1000 |
| `session_index_repair` | ~2000 | **50** | 1000 |
| `audit_chain_cron` | ~200 (page fetches) | 50 | 1000 |
| `audit_retention_cron` | ~100 (D1 batch) | 50 | 1000 |
| `sweep` (anonymous retention) | ~100 | 50 | 1000 |

Note: each cron trigger is a **separate Worker invocation**; subrequest limits
reset per invocation.  Hot-path routes (`/authorize`, `/token`, `/introspect`)
are comfortably within Free limits when invoked individually.

**Free-plan operators** can reduce batch sizes via env vars to fit within 50
subrequests.  This is documented in `docs/src/deployment/preflight.md` but
is not the primary supported configuration.

### Worker bundle size budget

CI gate: 2.5 MiB gzip (`BUNDLE_SIZE_BUDGET = 2621440` bytes).  See
`BUNDLE_SIZE_BUDGET.md` and `.github/workflows/bundle-size.yml`.

Free plan ceiling is 3 MiB; Paid is 10 MiB.  The 2.5 MiB soft cap leaves
500 KiB headroom for a feature release without immediately hitting the
Free-plan ceiling.

### `nodejs_compat` flag

RFC 029 measurement confirmed: removing `nodejs_compat` produces **zero diff**
against the codebase.  The flag was a wrangler scaffold default and carries no
active code path.

**Decision**: `rustfmt.toml` removed (RFC 029 finding).  `nodejs_compat` is
retained in `wrangler.toml` for the v0.53.x release and tagged for removal in
v0.54.x once the measurement is confirmed on a live deployment.  A comment in
`wrangler.toml` records this note.

### Cron batch size configuration

Each cron pass that walks rows exposes an env var:

| Cron | Env var | Default | Paid-safe | Free-safe |
|---|---|---|---|---|
| `session_index_audit` | `SESSION_INDEX_AUDIT_BATCH_LIMIT` | 1000 | yes | 30 |
| `session_index_repair` | `SESSION_INDEX_REPAIR_BATCH_LIMIT` | 1000 | yes | 30 |

The defaults are sized for Paid; Free-plan operators set them lower.

## Consequences

- `docs/src/deployment/preflight.md` carries the plan-tier table and
  the Free-plan tuning section.
- `BUNDLE_SIZE_BUDGET.md` documents the budget, rationale, and investigation
  guide.
- CI fails PRs that exceed the gzip budget.
- Future operators reading this ADR understand why certain operations
  require Paid plan without digging into subrequest accounting.

## Alternatives considered

**A. Target Free plan**: Require all cron passes to fit within 50 subrequests
by default.  Rejected: default batch of ~30 rows per session-index-audit pass
means a deployment with 1000 sessions takes ~33 days to converge a full audit
scan.  This degrades the operational visibility that ADR-012 was designed to
provide.

**B. Per-operation micro-crons**: Register 5 cron triggers (one per pass)
each with a smaller batch limit.  Rejected: `wrangler.toml` cron is a
deployment-level concern; fragmenting into 5 triggers adds operational
complexity without reducing the fundamental subrequest need.

**C. Free + Paid configuration presets**: Ship two `wrangler.toml` variants.
Rejected: increases maintenance surface; the env-var approach covers both
tiers with a single deployment artifact.
