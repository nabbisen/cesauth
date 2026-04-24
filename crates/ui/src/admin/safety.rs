//! Data Safety Dashboard page (§4.3).

use crate::escape;
use cesauth_core::admin::policy::role_allows;
use cesauth_core::admin::types::{AdminAction, AdminPrincipal, BucketSafetyState, DataSafetyReport};

use super::frame::{admin_frame, Tab};

pub fn safety_page(
    principal: &AdminPrincipal,
    report:    &DataSafetyReport,
) -> String {
    let body = format!(
        "{summary}\n{table}",
        summary = render_summary(report),
        table   = render_table(principal, &report.buckets),
    );
    admin_frame(
        "Data safety",
        principal.role,
        principal.name.as_deref(),
        Tab::Safety,
        &body,
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
  <form class="inline" method="post" action="/admin/console/safety/{bucket}/verify">
    <button type="submit" aria-label="Stamp '{bucket}' as re-verified now">re-verify</button>
  </form>
</td>"##,
            bucket = escape(&b.bucket),
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
