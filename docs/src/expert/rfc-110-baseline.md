# RFC 110 baseline — Safety controls dashboard alignment audit (v0.72.0)

This document captures the verification step RFC 110 required before any
gap-fill work. The audit was performed against the v0.71.0 codebase.

## PDF v0.50.1 page 9 — Safety controls panel

The deck enumerates four items plus a runbook link:

```
Safety controls
- Rate limit status
- Turnstile configured
- Refresh reuse alerts
- TOTP key status
[ Open runbook ]
```

### Findings against the current admin surface

| PDF item              | Current state                                                                                                  | Status |
|-----------------------|----------------------------------------------------------------------------------------------------------------|--------|
| Rate limit status     | `crates/worker/src/routes/admin/console/operations*.rs` surfaces cron pass status (RFC 081). **No rate-limit summary** anywhere in the admin console. | gap |
| Turnstile configured  | `crates/worker/src/turnstile.rs` has `TurnstileConfig::is_configured()`. **Indicator not surfaced** in any admin page. | gap |
| Refresh reuse alerts  | `EventKind::RefreshTokenReuseDetected` is written to `audit_events`. **No summary of recent occurrences** in admin UI; operator must query the audit log directly. | gap |
| TOTP key status       | `TOTP_SECRET_KEY` env-var presence not surfaced in admin UI. | gap |
| Open runbook link     | `docs/src/deployment/day-2-runbook.md` exists, but **no hyperlink** from `/admin/console/safety` to it. | gap |

Note: `/admin/console/safety` is the **Data Safety Dashboard** (R2 bucket
public/private safety, RFC 047) — a different surface from PDF page 9's
"Safety controls". The names collide; the contents do not.

## PDF v0.50.1 page 8 — Console shell nav

The deck specifies six tabs: `Overview / Safety / Audit / Config / Alerts / Tokens`.

### Findings against `crates/ui/src/admin/frame.rs::Tab`

| PDF tab   | Implementation                              | Status |
|-----------|---------------------------------------------|--------|
| Overview  | `Tab::Overview` → `routes::admin::OVERVIEW` | present |
| Safety    | `Tab::Safety`   → `routes::admin::SAFETY`   | present (Data Safety surface, not PDF Safety controls) |
| Audit     | `Tab::Audit`    → `routes::admin::AUDIT`    | present (RFC 109 viewer, v0.71.0) |
| Config    | `Tab::Config`   → `routes::admin::CONFIG`   | present |
| Alerts    | `Tab::Alerts`   → `routes::admin::ALERTS`   | present |
| Tokens    | `Tab::Tokens`   → `routes::admin::TOKENS`   | present (Super role only — RFC convention) |
| _(extra)_ | `Tab::Cost`     → `routes::admin::COST`     | superset — Cost view (RFC ~ cost dashboard) |
| _(extra)_ | `Tab::Operations` → `routes::admin::OPERATIONS` | superset — cron pass status (RFC 081) |

**Conclusion**: nav alignment is a **clean superset** of PDF page 8. All
six required tabs present; two implementation-driven additions (`Cost`,
`Operations`) exist beyond the PDF.

## Closure for RFC 110 in v0.72.0

Per RFC 110 §"Open questions" Q1, the suggested closure is:

> verification step を本 RFC の唯一 deliverable とし、gap が有る場合は
> follow-up RFC (e.g., 110a-rate-limit-summary 等) を別建てする。

v0.72.0 adopts this closure. RFC 110 itself ships:

1. **This baseline document** (audit findings recorded).
2. **Pin tests** in `crates/ui/src/admin/tests.rs` that assert the current
   shape of `safety_page`, `operations_page`, and the `Tab` enum / nav.
   Future gap-fill PRs (110a–110e) will need to update these tests, which
   forces the question "did this PR also update the baseline doc?" to
   surface in code review.

The five gaps become **deferred RFCs** for follow-up work:

- **RFC 110a** — Rate limit summary surface (data source: KV-backed
  rate-limit buckets per `auth_brute_force.rs` / `token_endpoint.rs`).
- **RFC 110b** — Turnstile configured indicator (data source:
  `TurnstileConfig::is_configured()`).
- **RFC 110c** — Refresh reuse alerts summary (data source: count of
  recent `RefreshTokenReuseDetected` audit events).
- **RFC 110d** — TOTP key status indicator (data source:
  env-var presence check).
- **RFC 110e** — Open-runbook hyperlink + safety controls landing
  section that gathers 110a–110d. This RFC also revisits whether the
  "Safety controls" panel should be a sub-section of the existing
  `/admin/console/safety` Data Safety Dashboard or a separate
  `/admin/console/safety-controls` surface.

The gap-fills are deliberately split: each touches a different worker
data source, and several need rustup/wasm32-blocked verification of the
worker handler.

## How to run the pin tests

```bash
cargo-1.91 test -p cesauth-ui --lib admin::tests::rfc_110
```

A failure of any `rfc_110_*` test signals one of two things:

- The Data Safety Dashboard rendering shape changed without a baseline
  update — the doc above should be revised before the test is loosened.
- A gap-fill PR (110a–110e) landed but did not update the pin to its
  new positive assertion — the PR must adjust the test in the same
  commit.
