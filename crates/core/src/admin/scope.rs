//! Admin scope badge — RFC 016.
//!
//! Every admin frame carries a `ScopeBadge` next to the brand so the
//! operating scope is a first-class UI element rather than incidental
//! chrome styling.
//!
//! Three scopes:
//! - `System`  — deployment-wide infrastructure (`/admin/console/*`).
//! - `Tenancy` — cross-tenant operator console (`/admin/tenancy/*`).
//! - `Tenant`  — one specific tenant (`/admin/t/<slug>/*`).
//!
//! The badge renders a `<span class="scope-badge scope-{variant}">` with
//! a localized label and a full `aria-label` for screen readers.

use std::borrow::Cow;

use crate::i18n::{lookup, Locale, MessageKey};

/// The scope in which an admin operation is being performed.
#[derive(Debug, Clone)]
pub enum ScopeBadge<'a> {
    /// Deployment-wide system scope (`/admin/console/*`).
    System,
    /// Cross-tenant tenancy console (`/admin/tenancy/*`).
    Tenancy,
    /// Single-tenant scope (`/admin/t/<slug>/*`).  The slug is shown
    /// inline in the badge label so the tenant identity is unambiguous
    /// in screenshots and bug reports.
    Tenant(&'a str),
}

impl<'a> ScopeBadge<'a> {
    /// Localized label for this scope.  For `Tenant(slug)` the slug is
    /// substituted into the catalog string's `{slug}` placeholder.
    pub fn label_for(&self, locale: Locale) -> Cow<'static, str> {
        match self {
            Self::System  => Cow::Borrowed(lookup(MessageKey::AdminScopeSystem,  locale)),
            Self::Tenancy => Cow::Borrowed(lookup(MessageKey::AdminScopeTenancy, locale)),
            Self::Tenant(slug) => {
                let template = lookup(MessageKey::AdminScopeTenant, locale);
                Cow::Owned(template.replace("{slug}", slug))
            }
        }
    }

    /// CSS class string for the `<span>` element.
    pub fn css_class(&self) -> &'static str {
        match self {
            Self::System  => "scope-badge scope-system",
            Self::Tenancy => "scope-badge scope-tenancy",
            Self::Tenant(_) => "scope-badge scope-tenant",
        }
    }

    /// Full prose `aria-label` for screen readers.
    pub fn aria_label_for(&self, locale: Locale) -> Cow<'static, str> {
        let label = self.label_for(locale);
        // "Operating scope: " prefix; fine as EN-only since the
        // admin surfaces are EN-only for now.
        Cow::Owned(format!("Operating scope: {label}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_badge_css_class() {
        assert_eq!(ScopeBadge::System.css_class(), "scope-badge scope-system");
    }

    #[test]
    fn tenancy_badge_css_class() {
        assert_eq!(ScopeBadge::Tenancy.css_class(), "scope-badge scope-tenancy");
    }

    #[test]
    fn tenant_badge_css_class() {
        assert_eq!(ScopeBadge::Tenant("acme").css_class(), "scope-badge scope-tenant");
    }

    #[test]
    fn system_label_en() {
        assert_eq!(ScopeBadge::System.label_for(Locale::En), "System scope");
    }

    #[test]
    fn system_label_ja() {
        assert_eq!(ScopeBadge::System.label_for(Locale::Ja), "システム全体");
    }

    #[test]
    fn tenancy_label_en() {
        assert_eq!(ScopeBadge::Tenancy.label_for(Locale::En), "Tenancy scope");
    }

    #[test]
    fn tenancy_label_ja() {
        assert_eq!(ScopeBadge::Tenancy.label_for(Locale::Ja), "テナント運用");
    }

    #[test]
    fn tenant_label_en_substitutes_slug() {
        let badge = ScopeBadge::Tenant("acme");
        assert_eq!(badge.label_for(Locale::En), "Tenant: acme");
    }

    #[test]
    fn tenant_label_ja_substitutes_slug() {
        let badge = ScopeBadge::Tenant("acme");
        assert_eq!(badge.label_for(Locale::Ja), "テナント: acme");
    }

    #[test]
    fn aria_label_carries_full_prose() {
        let badge = ScopeBadge::Tenant("demo-org");
        let aria = badge.aria_label_for(Locale::En);
        assert!(aria.contains("Operating scope:"), "aria-label must contain prefix: {aria}");
        assert!(aria.contains("demo-org"), "aria-label must contain slug: {aria}");
    }

    #[test]
    fn tenant_badge_empty_slug_is_safe() {
        let badge = ScopeBadge::Tenant("");
        let label = badge.label_for(Locale::En);
        assert_eq!(label, "Tenant: ");
    }
}
