//! OIDC client audience-scoping editor — RFC 017.
//!
//! Renders the audience editor form and a read-only client detail page.
//! The form enables tenant admins to set `oidc_clients.audience` without
//! running raw D1 SQL.

use crate::escape;
use cesauth_core::oidc::audience::AudienceTarget;

/// Render the audience editor form (GET).
///
/// `client_id`        — the OIDC client being edited.
/// `current_target`   — the current audience state from the database.
/// `csrf_token`       — CSRF form token.
/// `tenant_slug`      — for building action URLs and breadcrumbs.
/// `uniqueness_warning` — if `Some(other_client_id)`, show a warning that
///                        this audience is already used by another client.
pub fn audience_edit_page(
    client_id:          &str,
    current_target:     &AudienceTarget,
    csrf_token:         &str,
    tenant_slug:        &str,
    uniqueness_warning: Option<&str>,
) -> String {
    let client_id_esc  = escape(client_id);
    let csrf_esc       = escape(csrf_token);
    let slug_esc       = escape(tenant_slug);

    let (checked_unscoped, checked_scoped) = match current_target {
        AudienceTarget::Unscoped => (r#"checked"#, ""),
        _                        => ("", r#"checked"#),
    };
    let current_value_esc = match current_target {
        AudienceTarget::Scoped(v)  => escape(v),
        _                          => String::new(),
    };

    let uniqueness_html = if let Some(other_id) = uniqueness_warning {
        format!(
            r#"<div class="warning-box" role="alert">
  <strong>Warning:</strong> Audience <code>{aud}</code> is also configured on client
  <code>{other}</code>. Two clients sharing an audience is supported (multi-RS fronting
  one logical audience), but is unusual. Add <code>?force=1</code> to the form action
  to proceed, or choose a different audience.
</div>"#,
            aud   = current_value_esc,
            other = escape(other_id),
        )
    } else {
        String::new()
    };

    format!(
        r##"
<section>
  <h2>OIDC client: <code>{client_id_esc}</code></h2>

  {uniqueness_html}

  <form method="post" action="/admin/t/{slug_esc}/oidc-clients/{client_id_esc}/audience">
    <fieldset>
      <legend>Introspection audience scope</legend>
      <p class="field-explainer">
        When set, this client may only introspect tokens whose <code>aud</code> claim
        matches this audience verbatim. When unset (NULL), the client uses pre-v0.50.0
        unscoped behavior — it can introspect any token cesauth issues.
      </p>

      <div class="field radio-field">
        <label>
          <input type="radio" name="mode" value="unscoped" {checked_unscoped}>
          Unscoped (legacy default — any audience)
        </label>
      </div>

      <div class="field radio-field">
        <label>
          <input type="radio" name="mode" value="scoped" {checked_scoped}>
          Scoped to:
        </label>
        <input type="text" name="audience_value"
               value="{current_value_esc}"
               aria-label="Audience value"
               placeholder="https://api.example.com"
               class="audience-input">
      </div>

      <details>
        <summary>What goes in this field?</summary>
        <div class="field-help">
          <p>The audience is the identifier the resource server uses for its own tokens.
          For most deployments the audience equals the client's own <code>client_id</code>.
          For deployments where one cesauth instance fronts multiple resource servers,
          the audience is the operator-controlled identifier for the specific resource
          server this client represents.</p>
          <p>Change takes effect immediately for new requests. In-flight requests complete
          with the previous setting.</p>
        </div>
      </details>

      <input type="hidden" name="csrf_token" value="{csrf_esc}">
      <div class="form-actions">
        <a href="/admin/t/{slug_esc}/oidc-clients" class="button secondary">Cancel</a>
        <button type="submit" class="button primary">Save audience setting</button>
      </div>
    </fieldset>
  </form>
</section>
"##,
        client_id_esc   = client_id_esc,
        csrf_esc        = csrf_esc,
        slug_esc        = slug_esc,
        checked_unscoped = checked_unscoped,
        checked_scoped  = checked_scoped,
        current_value_esc = current_value_esc,
        uniqueness_html = uniqueness_html,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use cesauth_core::oidc::audience::AudienceTarget;

    #[test]
    fn unscoped_form_state_checks_unscoped_radio() {
        let html = audience_edit_page(
            "client-abc", &AudienceTarget::Unscoped, "csrf", "acme", None,
        );
        // The unscoped radio should be checked.
        assert!(html.contains(r#"name="mode" value="unscoped" checked"#),
            "unscoped state must pre-check the unscoped radio: {html}");
        // The scoped radio must NOT be checked.
        assert!(!html.contains(r#"value="scoped" checked"#),
            "scoped radio must not be checked in unscoped state");
    }

    #[test]
    fn scoped_form_state_checks_scoped_radio_and_shows_value() {
        let html = audience_edit_page(
            "client-abc",
            &AudienceTarget::Scoped("https://api.example.com".to_owned()),
            "csrf", "acme", None,
        );
        assert!(html.contains(r#"value="scoped" checked"#),
            "scoped state must pre-check the scoped radio");
        assert!(html.contains("https://api.example.com"),
            "scoped state must pre-fill the audience value");
    }

    #[test]
    fn explicit_empty_form_state_checks_scoped_radio_empty_value() {
        let html = audience_edit_page(
            "client-abc", &AudienceTarget::ExplicitEmpty, "csrf", "acme", None,
        );
        assert!(html.contains(r#"value="scoped" checked"#),
            "ExplicitEmpty must pre-check the scoped radio");
    }

    #[test]
    fn uniqueness_warning_shown_when_other_client_provided() {
        let html = audience_edit_page(
            "client-abc",
            &AudienceTarget::Scoped("https://api.example.com".to_owned()),
            "csrf", "acme", Some("client-xyz"),
        );
        assert!(html.contains("client-xyz"),
            "uniqueness warning must name the other client");
        assert!(html.contains("Warning"),
            "uniqueness warning must include warning label");
    }

    #[test]
    fn no_uniqueness_warning_when_none() {
        let html = audience_edit_page(
            "client-abc", &AudienceTarget::Unscoped, "csrf", "acme", None,
        );
        assert!(!html.contains("Warning"),
            "no warning when uniqueness_warning is None");
    }

    #[test]
    fn form_action_contains_tenant_slug_and_client_id() {
        let html = audience_edit_page(
            "my-client", &AudienceTarget::Unscoped, "csrf", "my-tenant", None,
        );
        assert!(html.contains(r#"action="/admin/t/my-tenant/oidc-clients/my-client/audience""#),
            "form action must embed tenant slug and client id: {html}");
    }

    #[test]
    fn csrf_token_embedded_in_hidden_field() {
        let html = audience_edit_page(
            "c", &AudienceTarget::Unscoped, "secret-csrf-value", "t", None,
        );
        assert!(html.contains("secret-csrf-value"),
            "CSRF token must appear in hidden field");
    }

    #[test]
    fn client_id_with_html_chars_is_escaped() {
        let html = audience_edit_page(
            "client<>&\"", &AudienceTarget::Unscoped, "csrf", "tenant", None,
        );
        assert!(!html.contains("client<>&\""),
            "HTML meta-chars in client_id must be escaped");
        assert!(html.contains("client&lt;&gt;&amp;"),
            "escaped client_id should appear in output");
    }
}
