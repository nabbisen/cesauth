//! RFC 185 §5.3 screen 3, T6.
//!
//! `operator_json_api::shell`'s eleven callers used to pass a hardcoded
//! title string; this slice replaces each with
//! `format!("{} — cesauth", lookup(key, locale))`. **Ten of the eleven
//! must render byte-identical to the literal they replace** — a key
//! rename that quietly changes an operator title eight screens didn't
//! ask to be touched has no other witness (handoff §6 T6). The literals
//! below are captured from `git show 1be6103:<file>`, the baseline this
//! slice's handoff names, and confirmed unchanged at the point this
//! slice started.
//!
//! The eleventh, `console/overview.rs`, is **deliberately** not
//! byte-identical: G1's Q2 decided to compose it like the other ten
//! rather than leave it the one irregular shape among eleven
//! (`cesauth コンソール` → `コンソール — cesauth`). Asserted against the
//! new value instead, so a future accidental revert back to the old
//! irregular string is still caught.

use super::super::*;

fn composed_title(key: MessageKey, locale: Locale) -> String {
    format!("{} — cesauth", lookup(key, locale))
}

#[test]
fn console_alerts_title_is_byte_identical_to_the_pre_cut_literal() {
    assert_eq!(composed_title(MessageKey::ConsoleAlertsPageTitle, Locale::Ja), "アラート — cesauth");
}

#[test]
fn console_operations_title_is_byte_identical_to_the_pre_cut_literal() {
    assert_eq!(composed_title(MessageKey::OperationsTitle, Locale::Ja), "オペレーション — cesauth");
}

#[test]
fn console_tokens_title_is_byte_identical_to_the_pre_cut_literal() {
    assert_eq!(composed_title(MessageKey::TokensTitle, Locale::Ja), "管理トークン — cesauth");
}

#[test]
fn console_config_title_is_byte_identical_to_the_pre_cut_literal() {
    assert_eq!(composed_title(MessageKey::ConfigTitle, Locale::Ja), "設定 — cesauth");
}

#[test]
fn console_cost_title_is_byte_identical_to_the_pre_cut_literal() {
    assert_eq!(composed_title(MessageKey::ConsoleCostPageTitle, Locale::Ja), "コスト — cesauth");
}

#[test]
fn console_clients_title_is_byte_identical_to_the_pre_cut_literal() {
    assert_eq!(composed_title(MessageKey::OidcClientsTitle, Locale::Ja), "OIDC クライアント — cesauth");
}

#[test]
fn console_safety_title_is_byte_identical_to_the_pre_cut_literal() {
    assert_eq!(composed_title(MessageKey::ConsoleSafetyPageTitle, Locale::Ja), "安全性 — cesauth");
}

#[test]
fn tenancy_overview_title_is_byte_identical_to_the_pre_cut_literal() {
    assert_eq!(composed_title(MessageKey::TenancyOverviewPageTitle, Locale::Ja), "テナント管理 — cesauth");
}

#[test]
fn tenancy_tenants_title_is_byte_identical_to_the_pre_cut_literal() {
    assert_eq!(composed_title(MessageKey::TenancyTenantsPageTitle, Locale::Ja), "テナント一覧 — cesauth");
}

#[test]
fn tenancy_tenant_detail_title_is_byte_identical_to_the_pre_cut_literal() {
    assert_eq!(composed_title(MessageKey::TenancyTenantDetailPageTitle, Locale::Ja), "テナント詳細 — cesauth");
}

/// The one deliberate exception — G1 decision §1 Q2. Pinned against the
/// NEW value, not the old `cesauth コンソール`, so a revert is caught too.
#[test]
fn console_overview_title_is_deliberately_not_byte_identical_to_the_pre_cut_literal() {
    let composed = composed_title(MessageKey::ConsoleOverviewPageTitle, Locale::Ja);
    assert_eq!(composed, "コンソール — cesauth");
    assert_ne!(composed, "cesauth コンソール", "the pre-cut literal — G1 Q2 renamed this deliberately");
}
