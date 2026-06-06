//! Render smoke tests for admin-console templates.
//!
//! We do not parse the output HTML — that's overkill for "did
//! `format!` panic, is the role badge present, did escape happen".
//! A handful of `contains()` assertions against the rendered string
//! is enough to catch template drift without pinning byte-for-byte.

use super::*;
use cesauth_core::admin::types::{
    AdminPrincipal, AlertCounts, BucketSafetyChange, BucketSafetyDiff,
    BucketSafetyState, OverviewSummary, Role,
};

fn principal(role: Role) -> AdminPrincipal {
    AdminPrincipal {
        id:   "test-id".to_owned(),
        name: Some("pytest".to_owned()),
        role,
        user_id: None,
    }
}

fn empty_summary(role: Role) -> OverviewSummary {
    OverviewSummary {
        as_of: 0,
        principal: cesauth_core::admin::types::AdminPrincipalSummary {
            name: Some("pytest".to_owned()),
            role,
        },
        alert_counts: AlertCounts { critical: 0, warn: 0, info: 0 },
        recent_alerts: vec![],
        last_audit_events: vec![],
        last_verified_buckets: vec![],
    }
}

#[test]
fn overview_shows_role_badge_and_active_tab() {
    let out = overview_page(&empty_summary(Role::Super));
    assert!(out.contains("Super admin"),
        "Super role label should appear in header badge");
    assert!(out.contains(r#"aria-current="page""#),
        "active tab must carry aria-current");
    assert!(out.contains("/admin/console/tokens"),
        "Super sees the Tokens tab in the nav");
}

#[test]
fn non_super_roles_do_not_see_tokens_tab() {
    for role in [Role::ReadOnly, Role::Security, Role::Operations] {
        let out = overview_page(&empty_summary(role));
        assert!(!out.contains("/admin/console/tokens"),
            "role {role:?} must NOT see Tokens tab, got:\n{out}");
    }
}

#[test]
fn config_edit_form_escapes_untrusted_notes() {
    let state = BucketSafetyState {
        bucket:               "AUDIT".into(),
        public:               false,
        cors_configured:      true,
        bucket_lock:          false,
        lifecycle_configured: true,
        event_notifications:  false,
        notes:                Some(r#"<script>alert(1)</script>"#.to_owned()),
        last_verified_at:     Some(1_000_000),
        last_verified_by:     Some("alice".to_owned()),
        updated_at:           1_000_000,
    };
    let out = config_edit::edit_form(&principal(Role::Operations), &state, None);
    assert!(!out.contains("<script>alert(1)"),
        "notes field must be HTML-escaped");
    assert!(out.contains("&lt;script&gt;"), "expected escaped form of payload");
}

#[test]
fn config_confirm_page_marks_only_changed_fields() {
    let current = BucketSafetyState {
        bucket: "AUDIT".into(),
        public: false, cors_configured: false, bucket_lock: false,
        lifecycle_configured: false, event_notifications: false,
        notes: None, last_verified_at: None, last_verified_by: None,
        updated_at: 0,
    };
    let proposed = BucketSafetyChange {
        bucket: "AUDIT".into(),
        public: false,            // unchanged
        cors_configured: true,    // CHANGED
        bucket_lock: false,
        lifecycle_configured: true, // CHANGED
        event_notifications: false,
        notes: None,
    };
    let diff = BucketSafetyDiff {
        bucket: "AUDIT".into(),
        current,
        proposed,
        changed_fields: vec!["cors_configured", "lifecycle_configured"],
    };
    let out = config_edit::confirm_page(&principal(Role::Operations), &diff);
    assert!(out.contains("2 fields will change"));
    assert!(out.contains(r#"name="confirm" value="yes""#),
        "confirm hidden field must be present so submit applies");
}

#[test]
fn config_confirm_page_with_no_changes_omits_apply_button() {
    let s = BucketSafetyState {
        bucket: "AUDIT".into(),
        public: false, cors_configured: false, bucket_lock: false,
        lifecycle_configured: false, event_notifications: false,
        notes: None, last_verified_at: None, last_verified_by: None,
        updated_at: 0,
    };
    let same_as_current = BucketSafetyChange {
        bucket: "AUDIT".into(),
        public: s.public,
        cors_configured: s.cors_configured,
        bucket_lock: s.bucket_lock,
        lifecycle_configured: s.lifecycle_configured,
        event_notifications: s.event_notifications,
        notes: s.notes.clone(),
    };
    let diff = BucketSafetyDiff {
        bucket: "AUDIT".into(),
        current: s,
        proposed: same_as_current,
        changed_fields: vec![],
    };
    let out = config_edit::confirm_page(&principal(Role::Operations), &diff);
    assert!(out.contains("no change"));
    assert!(!out.contains(r#"name="confirm""#),
        "no-change page must not render the apply button");
}

#[test]
fn token_created_page_shows_plaintext_but_escapes_it() {
    let minted = principal(Role::Operations);
    // Contrived plaintext with an HTML meta-char.
    let plaintext = "abc<def";
    let out = tokens::created_page(&principal(Role::Super), &minted, plaintext);
    assert!(out.contains("abc&lt;def"), "plaintext must be HTML-escaped");
    assert!(!out.contains("abc<def\""), "raw plaintext must not survive escape");
    assert!(out.contains("displayed once"),
        "the one-shot warning must be visible");
}

#[test]
fn token_list_empty_explains_bootstrap_fallback() {
    let out = tokens::list_page(&principal(Role::Super), &[]);
    assert!(out.contains("ADMIN_API_KEY"),
        "empty-list state must explain the bootstrap bearer");
}

// =====================================================================
// RFC 016 — scope badge tests for admin (system) frame
// =====================================================================

#[test]
fn admin_frame_renders_scope_badge_with_correct_class() {
    let out = overview_page(&empty_summary(Role::Super));
    assert!(
        out.contains("scope-badge scope-system"),
        "admin frame must carry scope-badge scope-system class"
    );
}

#[test]
fn admin_frame_scope_badge_label_ja_default() {
    // Default locale is JA; badge renders "システム全体".
    let out = overview_page(&empty_summary(Role::Operations));
    assert!(
        out.contains("システム全体"),
        "admin frame scope badge must show 'システム全体' (JA default): missing in: {}",
        &out[..out.find("</head>").unwrap_or(200)]
    );
}

#[test]
fn admin_frame_scope_badge_aria_label_carries_full_prose() {
    let out = overview_page(&empty_summary(Role::Super));
    assert!(
        out.contains("Operating scope:"),
        "admin frame scope badge aria-label must contain 'Operating scope:'"
    );
}

// ── RFC 071 — footer version hygiene ─────────────────────────────────────

#[test]
fn admin_frame_footer_has_no_version_caption() {
    // overview_page wraps admin_frame internally
    let out = overview_page(&empty_summary(Role::ReadOnly));
    assert!(!out.contains("v0.4.0"),
        "admin frame footer must not contain v0.4.0");
    assert!(!out.contains("v0.50."),
        "admin frame footer must not contain v0.50.x");
}

// =====================================================================
// RFC 105 — design-token unification
// =====================================================================

/// Admin frame must embed the shared semantic tokens from
/// `design_tokens::DESIGN_TOKENS_FMT`. We assert by sampling the named
/// CSS variables that the constant defines; if the constant ever stops
/// being embedded, every state-aware component on the page loses its
/// color treatment and these assertions catch it.
#[test]
fn admin_frame_embeds_shared_semantic_tokens() {
    let out = overview_page(&empty_summary(Role::Super));
    for var in ["--success:", "--success-bg:", "--warning:", "--warning-bg:",
                "--danger:", "--danger-bg:", "--info:", "--info-bg:",
                "--ok:", "--warn:", "--critical:"] {
        assert!(out.contains(var),
            "admin frame must embed shared semantic token {var}");
    }
}

#[test]
fn admin_frame_embeds_shared_scope_tokens() {
    let out = overview_page(&empty_summary(Role::Super));
    for var in ["--scope-system:", "--scope-tenancy:", "--scope-tenant:"] {
        assert!(out.contains(var),
            "admin frame must embed shared scope token {var}");
    }
}

#[test]
fn admin_frame_carries_dark_mode_override() {
    let out = overview_page(&empty_summary(Role::Super));
    // Both the semantic-tokens dark override and the scope-tokens dark
    // override land in the same rendered CSS; we only need a single
    // assertion to confirm `prefers-color-scheme: dark` is present.
    assert!(out.contains("@media (prefers-color-scheme: dark)"),
        "admin frame must carry the dark-mode override block");
}
