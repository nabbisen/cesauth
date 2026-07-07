//! Originally part of `crates/ui/src/tenant_admin/tests.rs`. Split
//! into a sibling file in v0.77.0 — test-file modularization track.

use super::common::*;            // shared fixtures (sample_tenant, sample_principal, etc.)
use super::super::*;             // reaches the tenant_admin module
use super::super::affordances::Affordances;
use super::super::frame::{tenant_admin_frame, TenantAdminTab};
#[allow(unused_imports)]
use cesauth_core::admin::types::{AdminPrincipal, Role};
#[allow(unused_imports)]
use cesauth_core::tenancy::AccountType;
#[allow(unused_imports)]
use cesauth_core::tenancy::types::{Tenant, TenantStatus};
#[allow(unused_imports)]
use cesauth_core::types::{User, UserStatus};

// RFC 105 — design-token unification
// =====================================================================

/// Helper: render the tenant-admin overview with a minimal fixture
/// (reuses the existing `tenant()` and `principal()` helpers).
fn tenant_admin_overview_html() -> String {
    let counts = TenantOverviewCounts {
        users:         0,
        organizations: 0,
        groups:        0,
        current_plan:  None,
    };
    overview_page(&principal(), &tenant(), &counts, &Affordances::all_allowed())
}

#[test]
fn tenant_admin_frame_embeds_shared_semantic_tokens() {
    let out = tenant_admin_overview_html();
    for var in ["--success:", "--success-bg:", "--warning:", "--warning-bg:",
                "--danger:", "--danger-bg:", "--info:", "--info-bg:",
                "--ok:", "--warn:", "--critical:"] {
        assert!(out.contains(var),
            "tenant_admin frame must embed shared semantic token {var}");
    }
}

#[test]
fn tenant_admin_frame_embeds_shared_scope_tokens() {
    let out = tenant_admin_overview_html();
    for var in ["--scope-system:", "--scope-tenancy:", "--scope-tenant:"] {
        assert!(out.contains(var),
            "tenant_admin frame must embed shared scope token {var}");
    }
}

#[test]
fn tenant_admin_frame_carries_dark_mode_override() {
    let out = tenant_admin_overview_html();
    assert!(out.contains("@media (prefers-color-scheme: dark)"),
        "tenant_admin frame must carry the dark-mode override block");
}
