# RFC 025: Workers operational readiness — bundle size CI, `nodejs_compat` measurement, plan budgeting

**Status**: Implemented
**ROADMAP**: External codebase review v0.50.1 — P2 findings on Cloudflare-platform readiness (deployment assumptions, bundle size, `nodejs_compat`, cron batch sizing under Free vs Paid plan)
**ADR**: N/A — operational hygiene, not new design
**Severity**: **P2 — current build deploys, but plan-level limits are unverified; first surprise on a real Free-plan deployment is a sweep that exceeds subrequest budget mid-pass**
**Estimated scope**: Medium — CI workflow + measurement + 2-3 docs chapters; ~120 LOC of bash/yml + ~250 LOC of operator docs
**Source**: External codebase review attached to the v0.50.1 conversation, §"Cloudflare Workers 適合性とホスティング所見"

## Background

The codebase review's "Cloudflare Workers 適合性"
section identifies four operational-readiness gaps
that don't show up in `cargo test` but do affect
deploy quality:

1. **No bundle-size CI gate.** Cloudflare's Workers
   gzip-size limit is 3 MB on Free, 10 MB on Paid.
   The current build produces an output that fits
   today, but each new dependency or feature can
   push over budget. There is no CI-time check.

2. **`nodejs_compat` is enabled with no measured
   benefit.** `wrangler.toml` line 12 sets
   `compatibility_flags = ["nodejs_compat"]`. The
   codebase has no Node API call sites
   (verified via static review). `nodejs_compat`
   pulls in Node polyfills and globals; for a
   pure-Rust WASM Worker, this is dead-code-cost
   on bundle size and cold-start time. The flag
   may or may not be necessary; we don't know
   because no measurement was run.

3. **Plan-level limits are not documented.** The
   project's existing deployment docs do not
   declare which Cloudflare plan tier is the
   intended baseline. Cron-pass operations that
   walk 1000 rows × per-row DO peek would exhaust
   Free-plan subrequest budget (50 internal
   subrequests per Worker invocation); the
   `session_index_audit` and `session_index_repair`
   crons assume budgets that need Paid.

4. **No automated bundle / deploy validation.**
   `wrangler deploy --dry-run --outdir bundled/`
   produces a deployable bundle without actually
   uploading; this should be a CI gate so
   "wouldn't deploy" surfaces at PR time.

The codebase review proposes a single recommended
hosting profile at the end:

| Item | Recommendation |
|---|---|
| Plan baseline | **Paid** (declared in docs) |
| CI bundle check | `wrangler deploy --dry-run --outdir` with size budget |
| Cron batches | Tested against subrequest budget |
| `nodejs_compat` | Measured; remove if not needed |
| Worker split | `auth-hot-path` vs `admin-ui` if size grows further |

This RFC ships the first three and defers the fourth
(worker split) as a future option, since the current
bundle still fits and splitting is a substantial
refactor.

## Requirements

The fix must:

1. CI fails on any PR or merge whose bundled gzip
   size exceeds a declared budget.
2. The `nodejs_compat` flag's necessity is measured
   and the result documented; if removable, removed.
3. The deployment documentation declares the
   minimum Cloudflare plan tier and explains the
   rationale (cron budgets, D1 query limits).
4. Cron handlers that depend on per-invocation
   subrequest count are documented with the
   expected budget consumption.

## Decision / Plan

### Step 1 — Add `wrangler deploy --dry-run` CI gate

New file `.github/workflows/bundle-size.yml`:

```yaml
name: Worker bundle size budget

on:
  pull_request:
  push:
    branches: [main]

jobs:
  bundle:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: wasm32-unknown-unknown
      - uses: cloudflare/wrangler-action@v3
        with:
          command: deploy --dry-run --outdir bundled/
          # No API token needed — dry-run is local.
      - name: Check bundled gzip size
        run: |
          set -euo pipefail
          bundle="$(find bundled/ -name '*.js' -size +0 -print -quit)"
          gz_size=$(gzip -c "$bundle" | wc -c)
          # Budget pinned per BUNDLE_SIZE_BUDGET.md (RFC 025).
          # Free plan ceiling is 3 MiB; we set 2.5 MiB as the soft cap
          # to leave headroom for a feature release; a PR that takes
          # us within 100 KiB of the cap should prompt review.
          BUDGET=2621440  # 2.5 MiB
          if [ "$gz_size" -gt "$BUDGET" ]; then
            echo "Bundle gzip size $gz_size exceeds budget $BUDGET" >&2
            exit 1
          fi
          echo "Bundle gzip size: $gz_size / $BUDGET ($(( gz_size * 100 / BUDGET ))%)"
```

A companion file `BUNDLE_SIZE_BUDGET.md` at the
repo root (or under `docs/src/expert/`) records:

- Current measured size + date.
- The budget value and rationale.
- Top-five contributing crates by size (output
  of `cargo bloat --release --target
  wasm32-unknown-unknown -p cesauth-worker`).
- A "how to investigate a regression" section.

### Step 2 — `nodejs_compat` measurement

Run a one-shot experiment, recording results in
`docs/src/expert/nodejs-compat-investigation.md`:

1. Build with `nodejs_compat` enabled (current
   state). Record bundle size, cold-start time
   (via `wrangler dev` startup wallclock or
   `console.time` instrumentation).
2. Build with `nodejs_compat` removed. If the
   build fails, capture the failure mode (which
   shim is missing). If it succeeds, record
   bundle size + cold-start.
3. Run integration tests against both builds
   (the tests are wasm-target, not Node-target,
   so they should pass either way; this is the
   smoke test for "did we break anything?").

If removal is safe and yields material bundle-size
reduction (≥5%), remove it from `wrangler.toml`. If
it isn't safe, the document records *why* —
specifically which transitive dependency requires
the polyfill — so a future depend-graph improvement
can revisit.

The measurement is the deliverable of this RFC's
Step 2; the actual removal is conditional on the
measurement.

### Step 3 — Plan-tier declaration in deployment docs

`docs/src/deployment/preflight.md` adds a top
section:

```markdown
## Cloudflare plan tier

cesauth's deployment is designed for the **Paid plan**.

The hot path (`/authorize`, `/token`, `/introspect`,
`/revoke`, login flows) is comfortably within Free-plan
limits. The cron-driven maintenance work — daily
sweep, audit chain verification, session-index audit,
audit retention, session-index repair — relies on
budgets only Paid provides:

| Limit | Free | Paid | cesauth uses |
|---|---|---|---|
| Subrequests per invocation | 50 | 1000 | up to ~1100 (cron path) |
| D1 queries per invocation  | 50 | 1000 | up to ~1050 (cron path) |
| Worker gzip size           | 3 MiB | 10 MiB | ~XXX KiB (current; CI-budgeted to 2.5 MiB) |
| CPU per invocation         | 10 ms (HTTP) / 30 s (cron) | 30 s / 30 s | nominal |

Free-plan deployments will see truncated cron passes
during retention, audit verification, and session
index reconciliation. The functional effect: orphaned
DOs / drifted index entries / accumulated audit rows
take longer to resolve than the daily cycle suggests,
and may never converge if the daily new-row rate
exceeds the per-pass budget.

A Free-plan-friendly deployment profile may be
introduced as a future enhancement (smaller per-pass
batches; multiple smaller cron triggers per day)
but is out of v0.52.x scope.
```

### Step 4 — Per-cron subrequest budget annotation

Each cron entry point gets a doc-comment header
declaring its budget consumption:

```rust
//! # session_index_audit cron
//!
//! Daily 04:00 UTC pass after `sweep::run` and
//! `audit_chain_cron::run`.
//!
//! Subrequest budget under default config:
//!   - 1× D1 read (list active sessions, LIMIT
//!     `SESSION_INDEX_AUDIT_BATCH_LIMIT`, default 1000)
//!   - up to N× DO `status` peeks where N is the
//!     batch size
//!   - up to N× audit-event writes (D1) when drift
//!     is detected
//!
//! Worst case: ~3000 subrequests for a fully drifted
//! batch of 1000. Comfortably within Paid (1000 per
//! invocation; cron passes are independent
//! invocations and reset the counter).
//!
//! Free-plan operators MUST reduce batch limit via
//! env to ~30 to fit within 50 subrequests.
```

The `SESSION_INDEX_AUDIT_BATCH_LIMIT` env var is
introduced if not already present; default 1000;
Free-plan operators set it lower.

Equivalent annotations for `sweep`,
`audit_chain_cron`, `audit_retention_cron`,
`session_index_repair_cron`.

### Step 5 — Bundle composition tracking

Add `scripts/bundle-bloat.sh` that runs
`cargo bloat --release --target
wasm32-unknown-unknown -p cesauth-worker --crates`
and writes the top-30 contributors to
`docs/src/expert/bundle-composition-snapshot.md`.
The snapshot is human-readable and re-generated
during the bundle-size RFC review at major
milestones.

This is *not* a CI gate — bundle composition is
operator information, not a regression class.

## Test plan

- The new `bundle-size.yml` workflow self-tests by
  running on its own PR.
- The `nodejs_compat` experiment is a one-shot
  recorded in the investigation doc; no
  recurring test.
- Existing test suite (888 tests as of v0.52.1)
  continues to pass under both `nodejs_compat`
  on/off configurations as a safety check.

## Security considerations

This RFC has no direct security surface. Indirect
links:

- A truncated audit-retention cron leaves audit
  history longer than policy; not a security
  issue per se but a data-protection one.
- A truncated session-index repair leaves drift
  visible in operator dashboards but not
  exploited by an attacker (drift doesn't widen
  authorization).

The plan-tier declaration is an operator-honesty
matter: deployments running on Free plan with
the assumption "cesauth handles housekeeping
automatically" will discover otherwise during an
audit; better to declare upfront.

## Open questions

1. **Should we add a `wrangler deploy --dry-run`
   smoke test on the wasm32 target as a separate
   CI job?** RFC 025 includes it implicitly via
   the bundle-size workflow. A separate job is
   redundant.

2. **Worker split (`auth-hot-path` vs `admin-ui`)
   — when does it become worth doing?** When
   bundle gzip exceeds ~5 MiB OR cold-start
   exceeds ~50 ms p95. Today neither is hit;
   defer to a future RFC.

3. **Should bundle-size budget regression
   trigger a release-blocking failure or just a
   PR comment?** This RFC: hard CI failure. The
   budget can always be raised by a deliberate
   PR that updates `BUNDLE_SIZE_BUDGET.md`; the
   gate's job is to make the increase visible.

## Implementation order

1. Add `bundle-size.yml` and
   `BUNDLE_SIZE_BUDGET.md` (sets baseline).
2. Add per-cron subrequest annotations and the
   plan-tier doc. These are independent of the
   measurement work.
3. Run the `nodejs_compat` experiment, write the
   investigation doc, decide on removal.
4. If removal: drop the flag from `wrangler.toml`
   in the same PR as the investigation doc.
5. Add `scripts/bundle-bloat.sh` and the
   bundle-composition snapshot.
6. Single PR per step or one bundled PR; prefer
   one per step for reviewability.

## Notes for the implementer

- `wrangler deploy --dry-run --outdir` does not
  require a Cloudflare API token; it runs
  entirely locally.
- `cargo bloat` requires
  `cargo install cargo-bloat`; the script can
  install it if missing or rely on the CI image
  to provide it.
- Cold-start measurement on Cloudflare Workers
  is noisy; use `wrangler dev`'s startup time
  as a coarse signal, and accept that p95
  comparisons want at least 30 samples.
- The `nodejs_compat` flag also enables
  `nodejs_compat_v2` per Cloudflare's current
  semantics; the experiment must check both
  variants if Cloudflare splits them in the
  future.
- For Free-plan operators reading the
  documentation: include a worked example
  showing the env-var changes that fit cesauth
  inside Free budgets, with the caveat that
  some maintenance work runs slower.
