//! Data Safety Dashboard page (§4.3) — plus the "Safety controls"
//! sub-section that surfaces PDF v0.50.1 page 9 indicators (RFC 110b/c/d/e,
//! v0.74.0). The two surfaces share the page because operators reach for
//! both from the same nav tab.

use crate::escape;
use cesauth_core::admin::scope::ScopeBadge;
use cesauth_core::admin::policy::role_allows;
use cesauth_core::admin::types::{
    AdminAction, AdminPrincipal, BucketSafetyState, DataSafetyReport,
    SafetyControlsReport,
};
use cesauth_core::routes::admin as routes;

use super::frame::{admin_frame, Tab};

/// Render the safety page.
///
/// `controls` is `Some(report)` when the worker has assembled the
/// Safety controls panel (RFC 110b/c/d/e). It's `None` while the worker
/// handler is still env-blocked or for tests that exercise only the
/// data-safety surface. When `None`, the controls section is omitted
/// entirely.
pub fn safety_page(
    principal: &AdminPrincipal,
    report:    &DataSafetyReport,
    controls:  Option<&SafetyControlsReport>,
) -> String {
    let body = format!(
        "{summary}\n{controls_section}\n{table}",
        summary  = render_summary(report),
        controls_section = match controls {
            Some(c) => render_safety_controls(c),
            None    => String::new(),
        },
        table    = render_table(principal, &report.buckets),
    );
    admin_frame(
        "Data safety",
        principal.role,
        principal.name.as_deref(),
        Tab::Safety,
        &ScopeBadge::System,
        &body,
    )
}

/// Render the PDF v0.50.1 page 9 "Safety controls" panel.
///
/// The four indicators (RFC 110b/c/d/e) are rendered as a compact
/// table; the runbook link surfaces below as a button-styled anchor
/// when the deployment has set `RUNBOOK_URL`. RFC 110a's
/// `rate_limit_status` is rendered as "—" when None.
///
/// **Secret-leakage invariant** (pin: `safety_page_never_exposes_secret_material`):
/// this surface only ever renders the *boolean* indicators
/// `turnstile_configured` / `totp_key_configured` — never the secret
/// bytes those env vars carry. A PR that surfaces the secret would
/// trip the negative pin in `tests.rs::rfc_110`.
fn render_safety_controls(c: &SafetyControlsReport) -> String {
    let badge = |configured: bool, label_ok: &str, label_missing: &str| {
        if configured {
            format!(r#"<span class="badge ok">{}</span>"#, escape(label_ok))
        } else {
            format!(r#"<span class="badge critical">{}</span>"#, escape(label_missing))
        }
    };
    let reuse_badge = if c.refresh_reuse_count_24h == 0 {
        r#"<span class="badge ok">0 (clean)</span>"#.to_owned()
    } else {
        // Any reuse event in 24h is an operator-attention-grabbing
        // signal. Refresh-token reuse means either a session got
        // stolen or replayed (RFC 9700 §4.14.2).
        format!(
            r#"<span class="badge critical">{} in 24h</span>"#,
            c.refresh_reuse_count_24h,
        )
    };
    let rate_limit_cell = match &c.rate_limit_status {
        Some(s) => format!(
            "{} throttled bucket(s), {} tripped client(s)",
            s.throttled_buckets, s.tripped_clients,
        ),
        None => r#"<span class="muted">— (RFC 110a deferred)</span>"#.to_owned(),
    };
    let runbook_link = match c.runbook_url.as_deref() {
        Some(url) => format!(
            // Open runbook in a new tab (operator is mid-incident — keep
            // the safety dashboard pinned).
            r##"<p><a class="action" href="{url}" target="_blank" rel="noopener noreferrer">Open runbook ↗</a></p>"##,
            url = escape(url),
        ),
        None => r#"<p class="muted">Runbook URL not configured. Set <code>RUNBOOK_URL</code> in the worker env to surface a quick link here.</p>"#.to_owned(),
    };
    format!(
        r##"<section aria-label="Safety controls">
  <h2>Safety controls</h2>
  <table>
    <tbody>
      <tr><th scope="row">Rate limit status</th>     <td>{rate_limit_cell}</td></tr>
      <tr><th scope="row">Turnstile configured</th>  <td>{turnstile}</td></tr>
      <tr><th scope="row">Refresh-token reuse (24h)</th><td>{reuse_badge}</td></tr>
      <tr><th scope="row">TOTP key configured</th>   <td>{totp_key}</td></tr>
    </tbody>
  </table>
  {runbook_link}
  <p class="note">Indicators reflect runtime state at the moment this
     page was loaded. Re-load to refresh. Secrets are never rendered —
     only their presence.</p>
</section>"##,
        rate_limit_cell = rate_limit_cell,
        turnstile       = badge(c.turnstile_configured, "configured", "MISSING"),
        reuse_badge     = reuse_badge,
        totp_key        = badge(c.totp_key_configured, "configured", "MISSING"),
        runbook_link    = runbook_link,
    )
}

fn render_summary(r: &DataSafetyReport) -> String {
    let freshness_cls = if r.all_fresh { "ok" } else { "warn" };
    let freshness = if r.all_fresh {
        "all buckets verified within staleness window"
    } else {
        "one or more buckets need re-verification"
    };
    let public_cls = if r.public_bucket_count == 0 { "ok" } else { "critical" };
    format!(
        r##"<section aria-label="Summary">
  <h2>Summary</h2>
  <p role="status">
    Staleness threshold: <strong>{days} days</strong>.
    &nbsp;<span class="badge {freshness_cls}">{freshness}</span>
    &nbsp;<span class="badge {public_cls}">{public_count} public</span>
  </p>
</section>"##,
        days            = r.staleness_threshold_days,
        freshness_cls   = freshness_cls,
        freshness       = freshness,
        public_cls      = public_cls,
        public_count    = r.public_bucket_count,
    )
}

fn render_table(principal: &AdminPrincipal, buckets: &[BucketSafetyState]) -> String {
    if buckets.is_empty() {
        return r#"<section aria-label="Buckets">
  <h2>Buckets</h2>
  <div class="empty">No buckets recorded. Re-run migration 0002.</div>
</section>"#.to_owned();
    }

    let may_verify = role_allows(principal.role, AdminAction::VerifyBucketSafety);

    let rows: String = buckets.iter().map(|b| render_row(b, may_verify)).collect();
    format!(
        r##"<section aria-label="Buckets">
  <h2>Buckets</h2>
  <table><thead>
    <tr>
      <th scope="col">Bucket</th>
      <th scope="col">Public</th>
      <th scope="col">CORS</th>
      <th scope="col">Lock</th>
      <th scope="col">Lifecycle</th>
      <th scope="col">Events</th>
      <th scope="col" class="num">Last verified</th>
      <th scope="col">By</th>
      <th scope="col">Action</th>
    </tr>
  </thead><tbody>
{rows}
  </tbody></table>
  <p class="note">A green check means the attestation records it present. cesauth cannot read Cloudflare's bucket configuration API from the Worker runtime, so these values are what the operator last confirmed; re-verify after any wrangler-side change.</p>
</section>"##,
    )
}

fn render_row(b: &BucketSafetyState, may_verify: bool) -> String {
    let public_cell = if b.public {
        r#"<td class="critical">PUBLIC</td>"#
    } else {
        r#"<td class="ok">private</td>"#
    };
    let verified_cell = match b.last_verified_at {
        Some(ts) => format!(r#"<td class="num">{ts}</td>"#),
        None     => r#"<td class="warn">never</td>"#.to_owned(),
    };
    let action_cell = if may_verify {
        format!(
            r##"<td>
  <form class="inline" method="post" action="{verify_url}">
    <button type="submit" aria-label="Stamp '{bucket}' as re-verified now">re-verify</button>
  </form>
</td>"##,
            bucket     = escape(&b.bucket),
            // RFC 108 escape contract: catalog builder returns raw URL.
            verify_url = escape(&routes::safety_verify(&b.bucket)),
        )
    } else {
        r#"<td class="muted">—</td>"#.to_owned()
    };
    format!(
        r##"<tr>
  <td><code>{bucket}</code></td>
  {public_cell}
  <td>{cors}</td>
  <td>{lock}</td>
  <td>{lifecycle}</td>
  <td>{events}</td>
  {verified_cell}
  <td class="muted">{by}</td>
  {action_cell}
</tr>"##,
        bucket        = escape(&b.bucket),
        public_cell   = public_cell,
        cors          = if b.cors_configured      { r#"<span class="ok">✓</span>"# } else { r#"<span class="muted">—</span>"# },
        lock          = if b.bucket_lock          { r#"<span class="ok">✓</span>"# } else { r#"<span class="muted">—</span>"# },
        lifecycle     = if b.lifecycle_configured { r#"<span class="ok">✓</span>"# } else { r#"<span class="muted">—</span>"# },
        events        = if b.event_notifications  { r#"<span class="ok">✓</span>"# } else { r#"<span class="muted">—</span>"# },
        verified_cell = verified_cell,
        by            = escape(b.last_verified_by.as_deref().unwrap_or("—")),
        action_cell   = action_cell,
    )
}
