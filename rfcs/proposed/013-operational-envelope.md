# RFC 013: Operational envelope — Cloudflare plan baseline, bundle budget, cron sizing, `nodejs_compat` review

**Status**: Proposed
**ROADMAP**: External codebase review v0.50.1 — P2 ops + plan-limit budgeting
**ADR**: This RFC produces ADR-016 establishing the operational baseline; the budget choices warrant ADR-level documentation
**Severity**: **P2 — quality and operational correctness; ship after v0.50.2 production-blocker sweep**
**Estimated scope**: Small per item, medium overall — ~50 LOC config + ~1500 LOC docs + CI workflow ~80 LOC
**Source**: External Rust+Cloudflare codebase review attached to v0.50.1 conversation; the reviewer cited Cloudflare's published plan limits.

## Background

The external review surfaced four implicit
operational assumptions that are not documented:

1. **Cron passes** (`session_index_audit`,
   `session_index_repair_cron`, etc.) walk up to
   1000 rows × one DO query per row. Free plan
   subrequest limit is 50; internal services 1000;
   Paid plan 1000 / 50000. Free-plan deployments
   silently fail past the subrequest cliff.

2. **`/introspect` hot path** issues multiple D1
   reads + DO calls per invocation. Free plan D1
   query limit per Worker invocation is 50; an
   `/introspect`-heavy deployment exhausts the
   budget.

3. **Worker bundle size** — cesauth ships a
   monolithic worker. Free plan gzip ceiling is
   3 MB; Paid is 10 MB. cesauth's bundle size has
   not been measured against either ceiling in CI.

4. **`nodejs_compat` flag** is enabled in
   `wrangler.toml` despite cesauth using no Node
   API at runtime. The flag enables
   `nodejs_compat_v2` polyfills/globals and bloats
   the bundle.

The fix is **not to refactor cesauth to fit Free
plan**. The fix is to **document the supported
plan floor**, **gate bundle size in CI**,
**configure cron batch sizes**, and **review
`nodejs_compat`**.

## Requirements

1. cesauth MUST document its plan floor — minimum
   Cloudflare plan that will reliably run a
   production deployment.
2. CI MUST measure worker bundle size on every PR
   and fail when the bundle exceeds a documented
   budget.
3. Cron pass batch sizes MUST be configurable via
   env, with documented defaults appropriate to
   the plan floor.
4. `nodejs_compat` MUST be re-evaluated and either
   removed or justified with an in-tree comment
   citing the specific Node API in use.
5. The deployment chapter MUST surface the budget
   contract: subrequests per request, D1 queries
   per invocation, cron batch sizes — what
   cesauth uses vs the plan limits.

## Design

### Item 1 — Plan floor: Paid plan

ADR-016 declares:

> cesauth's supported deployment floor is the
> Cloudflare Workers **Paid plan**.
>
> Free plan deployments are NOT supported. They
> may work for development but will hit
> subrequest, D1 query, and bundle size cliffs
> at any production scale.
>
> Free plan limits cited by Cloudflare as of
> 2026-Q2:
> - Subrequests per request: 50 (Paid: 50/1000
>   split internal/external)
> - D1 queries per Worker invocation: 50 (Paid:
>   1000)
> - Worker bundle gzip size: 3 MB (Paid: 10 MB)
>
> cesauth's hot paths reference D1 and DO
> sufficiently to require Paid tier at any
> production volume.

Documented in
`docs/src/deployment/production.md` under "Plan
floor: Paid plan required".

### Item 2 — Bundle budget CI gate

`.github/workflows/bundle-size.yml`:

```yaml
name: bundle-size
on: [pull_request, push]
jobs:
  measure:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rust-lang/setup-rust-toolchain@v1
        with:
          toolchain: 1.91
          target: wasm32-unknown-unknown
      - name: Build worker bundle
        run: |
          cd crates/worker
          cargo build --release --target wasm32-unknown-unknown
      - name: Measure
        run: |
          BYTES=$(stat -c%s target/wasm32-unknown-unknown/release/cesauth_worker.wasm)
          GZIPPED=$(gzip -c target/wasm32-unknown-unknown/release/cesauth_worker.wasm | wc -c)
          echo "raw=$BYTES gzipped=$GZIPPED"
          # Budget: 7 MB gzipped (70% of Paid 10 MB ceiling).
          BUDGET=$((7 * 1024 * 1024))
          if [ "$GZIPPED" -gt "$BUDGET" ]; then
            echo "Bundle exceeded budget ($GZIPPED > $BUDGET)"
            exit 1
          fi
```

Budget at 70% of Paid plan ceiling leaves headroom
for ongoing feature work. Reviewer's alternative
(`wrangler deploy --dry-run --outdir`) is also
viable — it runs the same bundling pipeline as
production. Choose whichever produces representative
output.

### Item 3 — Configurable cron batch sizes

Audit each cron pass. Some already have env knobs
(v0.49.0 added `SESSION_INDEX_REPAIR_BATCH_LIMIT`),
others don't:

| Cron pass | Current default | Env knob | Plan-floor recommended |
|---|---|---|---|
| `sweep::run` | unbounded (full table) | none | add `SWEEP_BATCH_LIMIT=1000` |
| `audit_chain_cron::run` | full chain | none | add `AUDIT_CHAIN_BATCH_LIMIT=1000` (resumes from checkpoint) |
| `session_index_audit::run` | 1000 rows | confirm exists | default 1000 |
| `audit_retention_cron::run` | per-pass, all eligible | none | add `AUDIT_RETENTION_BATCH_LIMIT=10000` |
| `session_index_repair_cron::run` | 1000 rows | exists v0.49.0 | unchanged |

A pass that hits its batch limit must persist its
cursor for resumption on the next cron tick. For
`session_index_audit`, KV-stored cursor on
`(created_at, id)`. For `audit_retention_cron`,
existing `floor_seq` logic is already cursor-shaped.

### Item 4 — `nodejs_compat` review

Action: remove `nodejs_compat` from `wrangler.toml`
and rebuild. If the build or runtime fails,
identify the specific Node API and document.

```toml
# wrangler.toml — current
compatibility_date = "2026-04-01"
compatibility_flags = [ "nodejs_compat" ]
```

Replacement (assuming no real Node API dependency):

```toml
compatibility_date = "2026-04-01"
# nodejs_compat NOT enabled — cesauth uses no Node
# runtime APIs. Removing reduces bundle size by
# ~50-200 KB (polyfills) and reduces cold-start
# time. (RFC 013, v0.50.x)
```

If a Node API IS in use, document in-place with
the specific symbol. The bundle-size CI gate
(Item 2) measures the impact.

### Item 5 — Operational envelope chapter

New chapter
`docs/src/deployment/operational-envelope.md`:

```markdown
# Operational envelope

cesauth runs on Cloudflare Workers. This chapter
documents what cesauth uses per request and per
cron tick against plan ceilings.

## Plan floor

**Paid plan required.** [...]

## Per-request budget

### `/introspect`

| Resource | v0.50.1 | post-RFC-009 (merged client lookup) |
|---|---|---|
| D1 reads | 2 | 1 |
| DO calls | 2 | 2 |
| KV reads | 0 | 0 |
| Subrequests | 4 | 3 |

### `/token` — authorization_code

| Resource | Count |
|---|---|
| D1 reads | 3 |
| D1 writes | 1 |
| DO calls | 2 |
| Subrequests | 5 |

### `/token` — refresh_token

| Resource | Count |
|---|---|
| D1 reads | 1 |
| DO calls | 2 |
| Subrequests | 3 |

[... etc for /authorize, /webauthn/*, /magic-link/* ...]

## Cron budget

cron triggers daily at 04:00 UTC. Five passes
sequentially. Total per cron tick: ~5000
subrequests, ~3000 D1 queries — well within Paid
plan envelope.

## Bundle budget

CI enforces 7 MB gzipped ceiling (70% of Paid plan
10 MB). Per-release bundle size recorded in
`docs/src/deployment/bundle-history.md` for trend
analysis.

## Scaling beyond a single worker

For deployments approaching plan ceilings:
1. Split worker (auth-hot-path vs admin) — see
   ROADMAP.
2. D1 sharding — future ADR.
3. Move to Cloudflare Enterprise.
```

### Item 6 — Bundle history trend doc

`docs/src/deployment/bundle-history.md`:

```markdown
# Bundle size history

| Version | Raw (bytes) | Gzipped (bytes) | Delta |
|---|---|---|---|
| v0.50.1 | 7,234,567 | 2,456,789 | +12,345 |
| v0.50.2 | 7,156,432 | 2,422,108 | -34,681 (RFC 013 nodejs_compat removal) |
```

Updated as part of release plumbing. Anomalous
jumps (>5% release-over-release) get a comment.

## Test plan

### CI

1. **bundle-size.yml gate** — fails CI if bundle
   exceeds 7 MB gzipped. Reports actual size +
   delta.
2. **No-Node-API regression** — small clippy lint
   or grep for `node:` imports in
   `crates/worker/`.

### Manual

3. Operator runs deployment chapter's "Operation:
   budget verification" — representative load
   (1000 requests across `/introspect`, `/token`,
   `/authorize`); export from Wrangler / Logpush;
   reconcile against per-request budget table.

### Documentation

4. **Per-release**: bundle-history.md update gates
   the release.
5. **Per-quarter**: re-validate per-request budget
   table against current code (table drifts as
   RFCs land).

## Security considerations

**Plan floor as security boundary**. cesauth has
not been pen-tested under Free plan resource
exhaustion. A determined attacker on a Free-plan
deployment could plausibly trigger budget-
exhaustion DoS. Documenting Paid plan as the
floor closes that surface.

**Cron budget exhaustion**. A pass that exhausts
its budget mid-run leaves work partially done.
For `audit_chain_cron`, checkpoint-based resume
handles this — next tick continues. For
`session_index_audit/repair`, cursor-based resume
must be implemented (Item 3) or the pass simply
re-walks each tick (less efficient but correct).

**Bundle size as fingerprinting**. Precise bundle
size could in theory let an attacker fingerprint
the cesauth version. Bundle size is already
public via Cloudflare's analytics if the attacker
has admin access to the deployment, so this is
marginal. Worth noting, not mitigating.

## Open questions

**Should we document an Enterprise plan floor for
high-traffic deployments?** Out of v0.50.x scope.
Reference Enterprise as "next tier if you need
more" without committing to a specific limit
table.

**Should the bundle budget auto-tighten over
time?** Once at 6.5 MB, ratchet to 7 MB and
fail the next release that crosses. Provocative
but likely too aggressive. Keep static for
v0.50.x.

**`compatibility_date` policy?** Bump only when a
runtime fix requires it, with explicit testing
against the new date in CI.

## Implementation order

1. **PR 1 — Item 4**: `nodejs_compat` removal (or
   justification). Single-file edit + build
   verification. Quickest win.
2. **PR 2 — Item 2**: bundle-size.yml CI workflow.
   ~80 LOC + initial baseline measurement.
3. **PR 3 — Item 3**: configurable cron batch
   sizes. ~30 LOC.
4. **PR 4 — Items 1+5**: ADR-016 + plan-floor
   doc + operational envelope chapter. Doc-heavy.
5. **PR 5 — Item 6**: bundle-history.md
   scaffolding + release-plumbing update.
6. **PR 6 — CHANGELOG + release.**

## Notes for the implementer

- Item 4 first — best signal-to-effort ratio.
  Measure bundle pre/post; record in
  bundle-history as v0.50.x baseline.
- Item 2's CI gate must ratchet: choose a budget
  that doesn't fail today's bundle but does fail
  at +50%. Re-tune after a few releases.
- The operational envelope chapter is the "what
  operators need to know" doc; tone is
  technical-matter-of-fact, not aspirational.
- Coordinate with RFC 014 (audit append
  performance) — that RFC's telemetry could
  shift the per-request budget table for
  audit-heavy paths.
