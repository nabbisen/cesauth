//! HTML form surface for bucket-safety edits (v0.4.0).
//!
//! Two screens:
//!
//!   * [`edit_form`] — an editable form pre-populated with the current
//!     attested state. Posts to the same URL; when no `confirm=yes`
//!     field is present the handler re-renders the confirmation page
//!     below instead of writing.
//!   * [`confirm_page`] — shows before / after side-by-side with the
//!     changed fields highlighted. Has a prominent "Apply the change"
//!     submit button (styled red; spec §9 asks for strong visual cues
//!     on dangerous operations). Submitting this form re-POSTs with
//!     `confirm=yes` and the same hidden fields, which the handler
//!     then applies.
//!
//! The hidden-field approach is deliberate. A nonce-in-DO scheme would
//! prevent a mid-flight payload swap, but the threat model here is
//! "operator typo in the edit form", not "operator attacks themselves
//! between confirm and apply". The operator is already authenticated
//! with a Super or Operations bearer; the only thing between the two
//! POSTs is the operator's own browser. Keeping it simple.

use crate::escape;
use cesauth_core::admin::types::{
    AdminPrincipal, BucketSafetyChange, BucketSafetyDiff, BucketSafetyState,
};

use super::frame::{admin_frame, Tab};

/// GET /admin/console/config/:bucket/edit
///
/// `error` carries a short human-facing message when this render is a
/// re-display after a bad submission (e.g. unknown bucket). `None` for
/// the first view.
pub fn edit_form(
    principal: &AdminPrincipal,
    state:     &BucketSafetyState,
    error:     Option<&str>,
) -> String {
    let body = format!(
        "{error}\n{form}\n{back}",
        error  = render_error(error),
        form   = render_form(&state.bucket, state, ""),
        back   = r#"<p><a href="/admin/console/config">← Back to configuration review</a></p>"#,
    );
    admin_frame(
        &format!("Edit bucket: {}", state.bucket),
        principal.role,
        principal.name.as_deref(),
        Tab::Config,
        &body,
    )
}

/// POST /admin/console/config/:bucket/edit (first step — no `confirm`).
///
/// Shows the diff and offers a prominent "Apply" button. If
/// `changed_fields` is empty we short-circuit with a friendly note and
/// do not render the apply form.
pub fn confirm_page(
    principal: &AdminPrincipal,
    diff:      &BucketSafetyDiff,
) -> String {
    let body = if diff.changed_fields.is_empty() {
        render_no_changes(&diff.current.bucket)
    } else {
        format!(
            "{diff_section}\n{apply_form}",
            diff_section = render_diff(diff),
            apply_form   = render_apply_form(diff),
        )
    };
    admin_frame(
        &format!("Confirm change: {}", diff.current.bucket),
        principal.role,
        principal.name.as_deref(),
        Tab::Config,
        &body,
    )
}

// -------------------------------------------------------------------------
// Fragments
// -------------------------------------------------------------------------

fn render_error(error: Option<&str>) -> String {
    match error {
        None => String::new(),
        Some(msg) => format!(
            r#"<section aria-label="Error"><p role="status" class="critical"><span class="badge critical">error</span> {msg}</p></section>"#,
            msg = escape(msg),
        ),
    }
}

fn checkbox(name: &str, label: &str, checked: bool) -> String {
    let checked_attr = if checked { r#" checked"# } else { "" };
    format!(
        r#"<tr>
  <th scope="row"><label for="{name}">{label}</label></th>
  <td><input id="{name}" name="{name}" type="checkbox" value="1"{checked_attr}></td>
</tr>"#
    )
}

fn render_form(bucket: &str, state: &BucketSafetyState, hidden: &str) -> String {
    let bucket_esc = escape(bucket);
    let notes_esc  = escape(state.notes.as_deref().unwrap_or(""));
    format!(
        r##"<section aria-label="Edit attested state">
  <h2>Attested state</h2>
  <form class="danger" method="post" action="/admin/console/config/{bucket_esc}/edit">
    {hidden}
    <table>
      {public}
      {cors}
      {lock}
      {lifecycle}
      {events}
      <tr>
        <th scope="row"><label for="notes">notes</label></th>
        <td><input id="notes" name="notes" type="text" value="{notes}" style="width:100%" placeholder="optional free-form comment"></td>
      </tr>
      <tr>
        <th scope="row"></th>
        <td>
          <p class="muted" style="margin-top:0;">This will update the operator-attested state of <code>{bucket_esc}</code>. Your submission will show a diff before actually writing.</p>
          <button type="submit">Preview change…</button>
        </td>
      </tr>
    </table>
  </form>
</section>"##,
        bucket_esc = bucket_esc,
        hidden     = hidden,
        notes      = notes_esc,
        public     = checkbox("public",               "Public bucket (DANGEROUS)",     state.public),
        cors       = checkbox("cors_configured",      "CORS configured",               state.cors_configured),
        lock       = checkbox("bucket_lock",          "Bucket lock configured",        state.bucket_lock),
        lifecycle  = checkbox("lifecycle_configured", "Lifecycle rule configured",     state.lifecycle_configured),
        events     = checkbox("event_notifications", "Event notifications configured", state.event_notifications),
    )
}

fn flag_cell(on: bool) -> &'static str {
    if on { r#"<span class="ok">✓ yes</span>"# } else { r#"<span class="muted">— no</span>"# }
}

fn changed_marker(field: &'static str, diff: &BucketSafetyDiff) -> &'static str {
    if diff.changed_fields.contains(&field) {
        r#" <span class="badge warn">changed</span>"#
    } else { "" }
}

fn render_diff(diff: &BucketSafetyDiff) -> String {
    let bucket = escape(&diff.current.bucket);
    let c = &diff.current;
    let p = &diff.proposed;

    let row = |label: &str, field: &'static str, cur_cell: &str, new_cell: &str| -> String {
        format!(
            r#"<tr>
  <th scope="row">{label}{marker}</th>
  <td>{cur_cell}</td>
  <td>{new_cell}</td>
</tr>"#,
            label    = label,
            marker   = changed_marker(field, diff),
            cur_cell = cur_cell,
            new_cell = new_cell,
        )
    };

    format!(
        r##"<section aria-label="Diff">
  <h2>You are about to change <code>{bucket}</code></h2>
  <p role="status"><span class="badge warn">{n} field{s} will change</span></p>
  <table>
    <thead>
      <tr>
        <th scope="col">Field</th>
        <th scope="col">Current</th>
        <th scope="col">Proposed</th>
      </tr>
    </thead>
    <tbody>
      {public_row}
      {cors_row}
      {lock_row}
      {lifecycle_row}
      {events_row}
      {notes_row}
    </tbody>
  </table>
</section>"##,
        bucket = bucket,
        n = diff.changed_fields.len(),
        s = if diff.changed_fields.len() == 1 { "" } else { "s" },
        public_row    = row("public",               "public",
            &if c.public { r#"<span class="critical">PUBLIC</span>"#.to_owned() } else { r#"<span class="ok">private</span>"#.to_owned() },
            &if p.public { r#"<span class="critical">PUBLIC</span>"#.to_owned() } else { r#"<span class="ok">private</span>"#.to_owned() }),
        cors_row      = row("cors_configured",      "cors_configured",      flag_cell(c.cors_configured),      flag_cell(p.cors_configured)),
        lock_row      = row("bucket_lock",          "bucket_lock",          flag_cell(c.bucket_lock),          flag_cell(p.bucket_lock)),
        lifecycle_row = row("lifecycle_configured", "lifecycle_configured", flag_cell(c.lifecycle_configured), flag_cell(p.lifecycle_configured)),
        events_row    = row("event_notifications",  "event_notifications",  flag_cell(c.event_notifications),  flag_cell(p.event_notifications)),
        notes_row     = row("notes",                "notes",
            &format!(r#"<span class="muted">{}</span>"#, escape(c.notes.as_deref().unwrap_or("—"))),
            &format!(r#"<span class="muted">{}</span>"#, escape(p.notes.as_deref().unwrap_or("—")))),
    )
}

fn render_apply_form(diff: &BucketSafetyDiff) -> String {
    let bucket_esc = escape(&diff.current.bucket);
    let p = &diff.proposed;
    let hidden = hidden_fields(p);

    format!(
        r##"<section aria-label="Apply the change">
  <form class="danger" method="post" action="/admin/console/config/{bucket_esc}/edit">
    {hidden}
    <input type="hidden" name="confirm" value="yes">
    <p><strong>This will write the new attestation to D1 and emit an audit event.</strong>
       If this doesn't look right, click &quot;Start over&quot; instead.</p>
    <button type="submit" aria-label="Apply this change to bucket {bucket_esc}">Apply the change</button>
    &nbsp;
    <a href="/admin/console/config/{bucket_esc}/edit">Start over</a>
  </form>
</section>"##,
        bucket_esc = bucket_esc,
        hidden     = hidden,
    )
}

fn render_no_changes(bucket: &str) -> String {
    format!(
        r##"<section aria-label="No changes">
  <p role="status"><span class="badge muted">no change</span> The values you submitted match the current attestation for <code>{bucket}</code>. Nothing to apply.</p>
  <p><a href="/admin/console/config/{bucket}/edit">← Back to edit form</a>
    &nbsp;&middot;&nbsp;
    <a href="/admin/console/config">← Back to configuration review</a>
  </p>
</section>"##,
        bucket = escape(bucket),
    )
}

fn hidden_bool(name: &str, v: bool) -> String {
    // Always emit the field so the server can distinguish "unchecked"
    // from "missing". Plain "1" / "0" is the wire format.
    format!(r#"<input type="hidden" name="{name}" value="{v}">"#, v = if v { "1" } else { "0" })
}

fn hidden_fields(change: &BucketSafetyChange) -> String {
    let notes = escape(change.notes.as_deref().unwrap_or(""));
    format!(
        "{p}{c}{l}{life}{ev}<input type=\"hidden\" name=\"notes\" value=\"{notes}\">",
        p    = hidden_bool("public",               change.public),
        c    = hidden_bool("cors_configured",      change.cors_configured),
        l    = hidden_bool("bucket_lock",          change.bucket_lock),
        life = hidden_bool("lifecycle_configured", change.lifecycle_configured),
        ev   = hidden_bool("event_notifications",  change.event_notifications),
        notes = notes,
    )
}
