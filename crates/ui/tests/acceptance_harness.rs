//! UI rendering acceptance harness — RFC 113 (v0.72.0).
//!
//! Universal invariants every browser-facing page in cesauth must
//! satisfy, asserted at the frame-fixture granularity. The deck (PDF
//! v0.50.1 page 14) enumerates six acceptance criteria; this harness
//! covers the five that are mechanically checkable in the rendered
//! HTML:
//!
//! 1. **`<html lang>` matches locale** (RFC 072). End-user frames cover
//!    both EN and JA; admin frames are JA-only per ADR-013.
//! 2. **Skip-link present** (RFC 077). Every frame emits
//!    `<a href="#main" class="skip-link">…</a>` as the first body element.
//! 3. **Flash region anchor present**. `<main id="main">` is the target
//!    the skip-link points at and the surface every page mounts its
//!    flash banner under.
//! 4. **Footer present, no version caption** (RFC 071). Operators
//!    identify build from wrangler/deploy logs; embedding version
//!    strings in the rendered HTML was explicitly removed.
//! 5. **Scope badge present on admin frames** (RFC 016). One of the
//!    three admin-scope variants (System / Tenancy / Tenant) shows up
//!    in every admin / tenant-admin / tenancy-console render.
//!
//! ## Scope-amendment note vs the original RFC 113 draft
//!
//! The draft listed `has_footer_ver: bool → assert!(html.contains("v0."))`.
//! RFC 071 (already shipped) **removed** footer version captions. The
//! correct invariant is the inverse — the footer must be present but
//! must NOT carry a version string. This harness implements the actual
//! contract; the RFC 113 doc carries an amendment note.
//!
//! ## Granularity choice (frame fixtures, not per-page)
//!
//! The original draft proposed enumerating every browser-facing route
//! (~30 entries) with per-route dispatch. The simpler model that ends
//! up giving the same coverage: walk the **frame functions** (4 of
//! them) with synthesised body content. The universal invariants are
//! properties of the frame layer, not of any specific page; per-page
//! tests still exist for content-level assertions (and live next to
//! the per-page render functions).
//!
//! New page added to the codebase? It must go through one of the four
//! frame functions — admin / tenant_admin / tenancy_console / chrome.
//! All five invariants apply automatically. The harness drift-detects
//! frame-level regressions, not new-page-coverage gaps; the latter
//! would warrant a separate per-route registry (deferred).

use cesauth_core::admin::scope::ScopeBadge;
use cesauth_core::admin::types::Role;
use cesauth_core::i18n::Locale;
use cesauth_ui::admin::frame::{admin_frame_for, Tab};
use cesauth_ui::tenancy_console::frame::{tenancy_console_frame_for, TenancyConsoleTab};
use cesauth_ui::tenant_admin::frame::{tenant_admin_frame_for, TenantAdminTab};
use cesauth_ui::templates::chrome::frame_for;

const BODY: &str = "<p>fixture body</p>";

/// One frame-fixture invocation: function pointer + locale + scope tag.
#[derive(Debug, Clone, Copy)]
struct FrameSpec {
    /// Human-readable label that appears in panic messages on failure.
    label:  &'static str,
    /// Whether the frame must carry a scope-badge marker (admin family).
    /// End-user (`chrome::frame_for`) renders no scope badge.
    admin:  bool,
    /// Expected `<html lang>` value (`locale.bcp47()`).
    locale: Locale,
}

/// All frame fixtures the harness walks. Each (label, locale) pair
/// produces one render and one full invariant check pass.
fn fixtures() -> Vec<FrameSpec> {
    vec![
        // End-user chrome: EN + JA both supported per RFC 072.
        FrameSpec { label: "chrome::frame_for / EN",  admin: false, locale: Locale::En },
        FrameSpec { label: "chrome::frame_for / JA",  admin: false, locale: Locale::Ja },
        // Admin family: JA only per ADR-013. (EN is reachable in code
        // — exhaustiveness pin — but production never reaches it.)
        FrameSpec { label: "admin_frame_for / JA",           admin: true,  locale: Locale::Ja },
        FrameSpec { label: "tenant_admin_frame_for / JA",    admin: true,  locale: Locale::Ja },
        FrameSpec { label: "tenancy_console_frame_for / JA", admin: true,  locale: Locale::Ja },
    ]
}

/// Render the frame identified by `spec`.
fn render(spec: &FrameSpec) -> String {
    match spec.label {
        s if s.starts_with("chrome::frame_for") => {
            frame_for("Acceptance harness", BODY, spec.locale)
        }
        s if s.starts_with("admin_frame_for") => {
            admin_frame_for(
                "Acceptance harness", Role::Super, Some("harness"),
                Tab::Overview, &ScopeBadge::System, spec.locale, BODY,
            )
        }
        s if s.starts_with("tenant_admin_frame_for") => {
            tenant_admin_frame_for(
                "Acceptance harness", "fixture-slug", "Fixture Tenant",
                Role::Super, Some("harness"),
                TenantAdminTab::Overview, spec.locale, BODY,
            )
        }
        s if s.starts_with("tenancy_console_frame_for") => {
            tenancy_console_frame_for(
                "Acceptance harness", Role::Super, Some("harness"),
                TenancyConsoleTab::Overview, spec.locale, BODY,
            )
        }
        other => panic!("acceptance harness: unknown frame label {other:?}"),
    }
}

/// Universal invariant 1: `<html lang="..">` matches the expected locale.
fn assert_html_lang_matches(html: &str, spec: &FrameSpec) {
    let needle = format!(r#"<html lang="{}">"#, spec.locale.bcp47());
    assert!(html.contains(&needle),
        "[{label}] missing or wrong <html lang>: expected {needle:?}",
        label = spec.label);
}

/// Universal invariant 2: skip-link present (RFC 077).
fn assert_skip_link_present(html: &str, spec: &FrameSpec) {
    assert!(html.contains(r#"class="skip-link""#),
        "[{label}] skip-link missing (RFC 077)", label = spec.label);
    assert!(html.contains(r##"href="#main""##),
        "[{label}] skip-link href=\"#main\" missing", label = spec.label);
}

/// Universal invariant 3: `<main id="main">` anchor for flash region.
fn assert_main_anchor_present(html: &str, spec: &FrameSpec) {
    assert!(html.contains(r#"<main id="main">"#),
        "[{label}] <main id=\"main\"> anchor missing — flash region has no mount",
        label = spec.label);
}

/// Universal invariant 4: footer present, no version caption (RFC 071).
fn assert_footer_present_no_version(html: &str, spec: &FrameSpec) {
    assert!(html.contains("<footer"),
        "[{label}] <footer> element missing", label = spec.label);
    // RFC 071 removed version captions. If a future RFC re-introduces
    // them, this assertion must be updated in the same commit (which
    // surfaces the RFC 071 reversal for review).
    let footer_start = html.find("<footer").expect("footer present");
    let footer_end   = html[footer_start..].find("</footer>").map(|i| footer_start + i + 9);
    let footer_html  = match footer_end {
        Some(end) => &html[footer_start..end],
        None      => &html[footer_start..],
    };
    // Heuristic: any `v0.NN` pattern in the footer block would be a
    // version caption. We don't try to spot v1+ since the project is
    // pre-1.0; if/when that changes, broaden this check.
    assert!(!footer_html.contains("v0."),
        "[{label}] footer contains a version caption — RFC 071 contract violated.\n\
         Footer was: {footer_html}",
        label = spec.label);
}

/// Universal invariant 5: admin frames carry a scope badge (RFC 016).
fn assert_scope_badge_present_when_admin(html: &str, spec: &FrameSpec) {
    if !spec.admin { return; }
    // ScopeBadge renders include the literal "scope" or the badge CSS
    // class — we look for either to stay robust against the
    // copy-rendering convention. The per-variant content (System /
    // Tenancy / Tenant) is asserted in the per-frame tests; here we
    // only assert *some* badge is present.
    let has_badge = html.contains("scope-badge")
                 || html.contains("scope_badge")
                 || html.contains("System scope")
                 || html.contains("Tenancy scope")
                 || html.contains("Tenant scope")
                 // JA labels (admin frames render JA per ADR-013):
                 || html.contains("システムスコープ")
                 || html.contains("テナンシースコープ")
                 || html.contains("テナントスコープ");
    assert!(has_badge,
        "[{label}] scope badge marker absent — RFC 016 invariant violated",
        label = spec.label);
}

// ─── Single walking test ────────────────────────────────────────────────
//
// One `#[test]` walks the full fixture × invariant matrix. A failure
// names the fixture label so the operator immediately sees which frame
// is broken. We deliberately do not split into per-fixture tests: the
// table is short, the failure mode is "fix the frame", and a single
// test integrates cleanly with CI gating.

#[test]
fn acceptance_harness_walks_all_frame_fixtures() {
    let specs = fixtures();
    assert!(!specs.is_empty(), "fixture table empty — harness misconfigured");
    for spec in &specs {
        let html = render(spec);
        assert_html_lang_matches(&html, spec);
        assert_skip_link_present(&html, spec);
        assert_main_anchor_present(&html, spec);
        assert_footer_present_no_version(&html, spec);
        assert_scope_badge_present_when_admin(&html, spec);
    }
}

// ─── Self-tests: detect harness coverage regressions ─────────────────────

#[test]
fn fixture_table_covers_both_end_user_locales() {
    let specs = fixtures();
    assert!(specs.iter().any(|s| !s.admin && s.locale == Locale::En),
        "end-user EN fixture missing — RFC 072 coverage regression");
    assert!(specs.iter().any(|s| !s.admin && s.locale == Locale::Ja),
        "end-user JA fixture missing — RFC 072 coverage regression");
}

#[test]
fn fixture_table_covers_all_three_admin_frames() {
    let labels: Vec<&str> = fixtures().iter().map(|s| s.label).collect();
    assert!(labels.iter().any(|l| l.contains("admin_frame_for /")),
        "admin frame fixture missing");
    assert!(labels.iter().any(|l| l.contains("tenant_admin_frame_for /")),
        "tenant_admin frame fixture missing");
    assert!(labels.iter().any(|l| l.contains("tenancy_console_frame_for /")),
        "tenancy_console frame fixture missing");
}

#[test]
fn admin_fixtures_render_in_ja_only_per_adr_013() {
    let admin_fixtures: Vec<_> = fixtures().into_iter().filter(|s| s.admin).collect();
    for s in &admin_fixtures {
        assert_eq!(s.locale, Locale::Ja,
            "admin fixture {label} must render in JA per ADR-013; got {locale:?}",
            label = s.label, locale = s.locale);
    }
}
