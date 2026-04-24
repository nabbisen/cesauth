//! Configuration Review page (§4.5).
//!
//! Shows two tables: the attested bucket-safety rows (same source as
//! the Safety Dashboard, but re-exposed here as a "these are the
//! settings you should eyeball" surface), and the operator-editable
//! thresholds.
//!
//! Editing thresholds and safety attestations via the UI is a 0.3.1
//! item; for now the JSON API at `/admin/console/thresholds/:name` and
//! `/admin/console/config/:bucket/preview` + `/apply` is the canonical
//! path.

use crate::escape;
use cesauth_core::admin::policy::role_allows;
use cesauth_core::admin::types::{AdminAction, AdminPrincipal, DataSafetyReport, Threshold};

use super::frame::{admin_frame, Tab};

pub fn config_page(
    principal:  &AdminPrincipal,
    report:     &DataSafetyReport,
    thresholds: &[Threshold],
) -> String {
    let may_edit = role_allows(principal.role, AdminAction::EditBucketSafety);
    let body = format!(
        "{safety}\n{thresholds}\n{how}",
        safety     = render_safety(report, may_edit),
        thresholds = render_thresholds(thresholds),
        how        = render_howto(),
    );
    admin_frame(
        "Configuration review",
        principal.role,
        principal.name.as_deref(),
        Tab::Config,
        &body,
    )
}

fn render_safety(r: &DataSafetyReport, may_edit: bool) -> String {
    let header_cells = if may_edit {
        r#"<th scope="col">Notes</th><th scope="col">Action</th>"#
    } else {
        r#"<th scope="col">Notes</th>"#
    };
    let rows: String = if r.buckets.is_empty() {
        let span = if may_edit { 8 } else { 7 };
        format!(r#"<tr><td colspan="{span}" class="empty">No attestation rows.</td></tr>"#)
    } else {
        r.buckets.iter().map(|b| {
            let action_cell = if may_edit {
                format!(
                    r#"<td><a href="/admin/console/config/{bucket}/edit">edit</a></td>"#,
                    bucket = escape(&b.bucket),
                )
            } else {
                String::new()
            };
            format!(
                r##"<tr>
  <td><code>{bucket}</code></td>
  <td>{public}</td>
  <td>{cors}</td>
  <td>{lock}</td>
  <td>{lifecycle}</td>
  <td>{events}</td>
  <td class="muted">{notes}</td>
  {action_cell}
</tr>"##,
                bucket    = escape(&b.bucket),
                public    = if b.public { r#"<span class="critical">public</span>"# } else { r#"<span class="ok">private</span>"# },
                cors      = if b.cors_configured      { "✓" } else { "—" },
                lock      = if b.bucket_lock          { "✓" } else { "—" },
                lifecycle = if b.lifecycle_configured { "✓" } else { "—" },
                events    = if b.event_notifications  { "✓" } else { "—" },
                notes     = escape(b.notes.as_deref().unwrap_or("")),
                action_cell = action_cell,
            )
        }).collect::<Vec<_>>().join("\n")
    };
    format!(
        r##"<section aria-label="Attested bucket settings">
  <h2>Bucket settings (attested)</h2>
  <table><thead>
    <tr>
      <th scope="col">Bucket</th>
      <th scope="col">Public</th>
      <th scope="col">CORS</th>
      <th scope="col">Lock</th>
      <th scope="col">Lifecycle</th>
      <th scope="col">Events</th>
      {header_cells}
    </tr>
  </thead><tbody>
{rows}
  </tbody></table>
</section>"##
    )
}

fn render_thresholds(thresholds: &[Threshold]) -> String {
    if thresholds.is_empty() {
        return r#"<section aria-label="Thresholds">
  <h2>Thresholds</h2>
  <div class="empty">No thresholds recorded. Re-run migration 0002.</div>
</section>"#.to_owned();
    }
    let rows: String = thresholds.iter().map(|t| {
        format!(
            r##"<tr>
  <td><code>{name}</code></td>
  <td class="num">{value}</td>
  <td class="muted">{unit}</td>
  <td class="muted">{desc}</td>
  <td class="num muted">{updated_at}</td>
</tr>"##,
            name       = escape(&t.name),
            value      = t.value,
            unit       = escape(&t.unit),
            desc       = escape(t.description.as_deref().unwrap_or("")),
            updated_at = t.updated_at,
        )
    }).collect::<Vec<_>>().join("\n");
    format!(
        r##"<section aria-label="Thresholds">
  <h2>Thresholds</h2>
  <table><thead>
    <tr>
      <th scope="col">Name</th>
      <th scope="col" class="num">Value</th>
      <th scope="col">Unit</th>
      <th scope="col">Description</th>
      <th scope="col" class="num">Updated (unix)</th>
    </tr>
  </thead><tbody>
{rows}
  </tbody></table>
</section>"##
    )
}

fn render_howto() -> String {
    r##"<section aria-label="How to edit">
  <h2>Editing</h2>
  <p class="muted">Operations+ principals can edit bucket-safety attestations directly in the UI via the <em>edit</em> link in each row above. Every edit goes through a two-step confirmation: the form submission shows a before/after diff, and the &quot;Apply&quot; button on the diff page performs the write.</p>
  <p class="muted">The same operations are available as a scripted JSON API:</p>
  <pre style="background:#f4f4f4; padding:12px; border-radius:4px; overflow-x:auto;"><code># Update a threshold (Operations+)
curl -X POST -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"value": 200000}' \
  https://cesauth.example/admin/console/thresholds/cost.d1.row_count.warn

# Preview a bucket-safety change (Operations+)
curl -X POST -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"public":false,"cors_configured":true,"bucket_lock":true,
       "lifecycle_configured":true,"event_notifications":false,
       "notes":"confirmed via wrangler r2"}' \
  https://cesauth.example/admin/console/config/AUDIT/preview

# Apply the same change (Operations+, confirm:true required)
curl -X POST ... (same body plus "confirm":true) \
  https://cesauth.example/admin/console/config/AUDIT/apply</code></pre>
</section>"##.to_owned()
}
