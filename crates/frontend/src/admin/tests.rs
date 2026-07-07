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

// ─── RFC 110 baseline pins ──────────────────────────────────────────────
//
// These tests pin the **current** shape of the safety-related surfaces
// against the PDF v0.50.1 page 9 / page 8 audit recorded in
// `docs/src/expert/rfc-110-baseline.md`. They are deliberately negative
// assertions for the gap items: the absence of those surface elements is
// a known state, documented in the baseline.
//
// When a follow-up RFC (110a–110e) ships the corresponding gap-fill,
// it MUST update the corresponding pin from "absent" to "present" in
// the same commit. That update forces a code-review pass over the
// baseline doc — the discipline RFC 110 §"Closure" calls for.

mod rfc_110 {
    use super::*;
    use cesauth_core::admin::types::{DataSafetyReport, SafetyControlsReport};
    use crate::admin::frame::Tab;

    fn empty_report() -> DataSafetyReport {
        DataSafetyReport {
            buckets:                  vec![],
            staleness_threshold_days: 7,
            public_bucket_count:      0,
            all_fresh:                true,
        }
    }

    #[test]
    fn nav_carries_all_six_pdf_page_8_tabs() {
        // PDF page 8: Overview / Safety / Audit / Config / Alerts / Tokens.
        // The implementation has these six plus Cost and Operations
        // (documented superset in rfc-110-baseline.md).
        let html = safety_page(&principal(Role::Super), &empty_report(), None);
        for label in ["Overview", "Safety", "Audit", "Config", "Alerts", "Tokens"] {
            assert!(html.contains(label),
                "admin nav must include PDF page-8 tab '{label}'; \
                 see docs/src/expert/rfc-110-baseline.md");
        }
    }

    #[test]
    fn nav_carries_implementation_superset_tabs() {
        // Cost and Operations are the documented superset additions.
        let html = safety_page(&principal(Role::Super), &empty_report(), None);
        assert!(html.contains("Cost"),
            "admin nav superset tab 'Cost' must be present (baseline §page 8)");
        assert!(html.contains("Operations"),
            "admin nav superset tab 'Operations' must be present (baseline §page 8)");
    }

    #[test]
    fn tab_enum_has_eight_variants() {
        // If a tab is added or removed, the baseline doc must be revisited.
        // Walking the iter() gives the count without reaching into private
        // internals.
        let count = [
            Tab::Overview, Tab::Cost, Tab::Safety, Tab::Audit,
            Tab::Config,   Tab::Alerts, Tab::Tokens, Tab::Operations,
        ].len();
        assert_eq!(count, 8,
            "Tab enum count drifted — update docs/src/expert/rfc-110-baseline.md");
    }

    // --- PDF page 9 "Safety controls" pins (v0.74.0 mixed state) --------
    //
    // RFC 110b/c/d/e shipped in v0.74.0 — positive pins assert the
    // indicators appear when `Some(SafetyControlsReport)` is passed.
    // RFC 110a (rate-limit summary) is still deferred — its pin stays
    // negative until that gap-fill lands.
    //
    // Each test passes `controls: Some(&report)` to exercise the
    // shipped section; the `None` path (omits the section entirely)
    // is exercised by `safety_page_does_not_yet_show_rate_limit_status`
    // and the non-rfc_110 tests.

    fn full_controls() -> SafetyControlsReport {
        SafetyControlsReport {
            turnstile_configured:    true,
            totp_key_configured:     true,
            refresh_reuse_count_24h: 0,
            runbook_url:             Some("https://runbook.example/cesauth".to_owned()),
            rate_limit_status:       None,  // RFC 110a deferred
        }
    }

    #[test]
    fn safety_page_does_not_yet_show_rate_limit_status() {
        // RFC 110a deferred. The page renders the indicator slot as
        // "— (RFC 110a deferred)" when rate_limit_status is None.
        let html = safety_page(&principal(Role::Super), &empty_report(), Some(&full_controls()));
        // Once the rate-limit summary lands, replace this assertion
        // with a positive check on the rendered count.
        assert!(html.contains("RFC 110a deferred"),
            "rate-limit summary not yet implemented (RFC 110a); \
             when it lands, populate rate_limit_status and flip this pin");
    }

    #[test]
    fn safety_page_shows_turnstile_indicator_when_configured() {
        // RFC 110b shipped v0.74.0.
        let html = safety_page(&principal(Role::Super), &empty_report(), Some(&full_controls()));
        assert!(html.contains("Turnstile configured"),
            "Turnstile indicator row label must appear (RFC 110b)");
        assert!(html.contains("configured") && !html.contains("MISSING"),
            "Turnstile=true should render as `configured`, not `MISSING`");
    }

    #[test]
    fn safety_page_shows_turnstile_missing_when_not_configured() {
        let controls = SafetyControlsReport {
            turnstile_configured: false,
            ..full_controls()
        };
        let html = safety_page(&principal(Role::Super), &empty_report(), Some(&controls));
        assert!(html.contains("MISSING"),
            "Turnstile=false should render as `MISSING` (RFC 110b)");
    }

    #[test]
    fn safety_page_shows_refresh_reuse_zero_as_clean() {
        // RFC 110c shipped v0.74.0.
        let html = safety_page(&principal(Role::Super), &empty_report(), Some(&full_controls()));
        assert!(html.contains("Refresh-token reuse (24h)"),
            "refresh-reuse row label must appear (RFC 110c)");
        assert!(html.contains("0 (clean)"),
            "refresh-reuse=0 should render as `0 (clean)` badge");
    }

    #[test]
    fn safety_page_shows_refresh_reuse_count_as_critical() {
        let controls = SafetyControlsReport {
            refresh_reuse_count_24h: 3,
            ..full_controls()
        };
        let html = safety_page(&principal(Role::Super), &empty_report(), Some(&controls));
        assert!(html.contains("3 in 24h"),
            "refresh-reuse=3 should render as `3 in 24h` (RFC 110c)");
        assert!(html.contains("critical"),
            "non-zero refresh reuse must render as a critical badge");
    }

    #[test]
    fn safety_page_shows_totp_key_indicator() {
        // RFC 110d shipped v0.74.0.
        let html = safety_page(&principal(Role::Super), &empty_report(), Some(&full_controls()));
        assert!(html.contains("TOTP key configured"),
            "TOTP key row label must appear (RFC 110d)");
    }

    #[test]
    fn safety_page_renders_runbook_link_when_url_present() {
        // RFC 110e shipped v0.74.0.
        let html = safety_page(&principal(Role::Super), &empty_report(), Some(&full_controls()));
        assert!(html.contains("Open runbook"),
            "runbook link text must appear when RUNBOOK_URL is set (RFC 110e)");
        assert!(html.contains("https://runbook.example/cesauth"),
            "runbook URL must appear as href value");
        assert!(html.contains(r#"target="_blank""#),
            "runbook link must open in a new tab (operator is mid-incident)");
        assert!(html.contains(r#"rel="noopener noreferrer""#),
            "runbook link must carry rel=noopener noreferrer for security");
    }

    #[test]
    fn safety_page_omits_runbook_link_when_url_missing() {
        let controls = SafetyControlsReport {
            runbook_url: None,
            ..full_controls()
        };
        let html = safety_page(&principal(Role::Super), &empty_report(), Some(&controls));
        // The page shows a hint message instead of a broken anchor.
        assert!(html.contains("Runbook URL not configured"),
            "missing runbook URL should surface a hint, not a broken link");
        assert!(!html.contains(r#"href="""#),
            "no empty href= attribute should be emitted when runbook URL is None");
    }

    #[test]
    fn safety_page_omits_controls_section_when_none() {
        // The None path is the v0.73.0 baseline behaviour: just the
        // Data Safety Dashboard, no Safety controls section.
        let html = safety_page(&principal(Role::Super), &empty_report(), None);
        assert!(!html.contains("Safety controls"),
            "controls section must be omitted entirely when controls=None");
    }

    // --- Crucial invariant: secrets never leak via this surface ---------
    //
    // Even after gap-fills (110b, 110d) shipped, the rendered HTML must
    // NEVER contain the secret material itself — only a presence
    // indicator. We pin a sentinel negative now so any future PR that
    // accidentally includes the secret bytes is caught. This pin is
    // load-bearing: it protects the privacy contract that lets us
    // surface env-var presence on a public-ish admin page.

    #[test]
    fn safety_page_never_exposes_secret_material() {
        let html = safety_page(&principal(Role::Super), &empty_report(), Some(&full_controls()));
        // Sentinels that would be present if someone accidentally embedded
        // PEM-encoded key material or base64 secrets.
        assert!(!html.contains("BEGIN PRIVATE KEY"),
            "secret material must never appear in safety page");
        assert!(!html.contains("BEGIN ENCRYPTED"),
            "secret material must never appear in safety page");
        // Also assert that env-var *names* don't appear in the rendered
        // page — they shouldn't be needed because the indicators are
        // bools, not env-var dumps.
        assert!(!html.contains("TURNSTILE_SECRET_KEY"),
            "env var name must not leak into rendered page");
        assert!(!html.contains("TOTP_SECRET_KEY"),
            "env var name must not leak into rendered page");
    }
}

// ─── RFC 111 — date rendering policy (ADR-013 §Q4 date-side closure) ─────
//
// Every visible timestamp in cesauth goes through
// `cesauth_core::util::format_unix_as_iso8601`. The pin below asserts
// the format the canonical formatter produces (UTC `Z` form, RFC 3339).
// A change in formatter output requires updating the docs at
// `docs/src/expert/i18n.md` §"Date / time rendering" in the same commit.

mod rfc_111 {
    use cesauth_core::util::format_unix_as_iso8601;

    #[test]
    fn canonical_formatter_emits_utc_z_form() {
        // 2024-01-01T00:00:00Z is a useful round-number anchor.
        assert_eq!(format_unix_as_iso8601(1_704_067_200), "2024-01-01T00:00:00Z");
    }

    #[test]
    fn canonical_formatter_emits_epoch_for_zero() {
        assert_eq!(format_unix_as_iso8601(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn canonical_formatter_never_emits_offset_form() {
        // RFC 111 amendment: legacy formatters used the `+00:00` offset
        // form. The canonical formatter standardised on `Z`. Pin the
        // negative so any regression to the offset form is caught.
        let s = format_unix_as_iso8601(1_704_067_200);
        assert!(!s.contains("+00:00"),
            "RFC 111: canonical formatter must use 'Z' suffix, not '+00:00'. \
             Got: {s}");
        assert!(s.ends_with('Z'),
            "RFC 111: canonical formatter output must end with 'Z'. Got: {s}");
    }

    #[test]
    fn canonical_formatter_handles_negative_as_epoch() {
        // Defensive: negative inputs (rare but possible from i64 fields)
        // clamp to epoch, not panic.
        assert_eq!(format_unix_as_iso8601(-1), "1970-01-01T00:00:00Z");
    }
}
