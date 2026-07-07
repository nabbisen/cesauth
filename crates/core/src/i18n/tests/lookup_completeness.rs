//! Originally part of `crates/core/src/i18n/tests.rs`.
//! Split into a sibling file in v0.78.0.

use super::super::*;

// lookup() completeness
// =====================================================================

/// Iterate every `MessageKey` variant. The match here is
/// **compiler-exhaustive**: adding a new variant without
/// adding it to this list is a build error, not a silently-
/// missed test. This replaces the v0.36.0 manually-listed
/// array which had become tedious + error-prone with the 47
/// new variants v0.39.0 added.
///
/// The function takes a closure rather than returning a
/// collection because returning would either box the
/// closure-friendly iterator (allocation in tests is fine
/// but ugly) or build a `Vec` (also allocation). The
/// closure shape is the cleanest of the three.
fn for_each_key(mut f: impl FnMut(MessageKey)) {
    use MessageKey::*;
    // The match below MUST stay exhaustive. If you add a
    // variant to MessageKey, you'll get a compile error here
    // — fix it by adding the variant to one of the arms
    // below. Variants are grouped by surface (matching the
    // enum definition's grouping) to make the list scannable.
    let pin: MessageKey = FlashTotpEnabled;
    match pin {
        FlashTotpEnabled | FlashTotpDisabled | FlashTotpRecovered |
        FlashLoggedOut   | FlashSessionRevoked |
        TotpEnrollWrongCode |
        SessionsPageTitle | SessionsPageIntro | SessionsPageEmpty |
        SessionsBackLink  |
        SessionsCurrentBadge | SessionsCurrentDisabled |
        SessionsCurrentDisabledTitle | SessionsRevokeButton |
        SessionsAuthMethodPasskey | SessionsAuthMethodMagicLink |
        SessionsAuthMethodAdmin   | SessionsAuthMethodUnknown |
        SessionsLabelSignIn   | SessionsLabelLastSeen |
        SessionsLabelClient   | SessionsLabelSessionId |
        // v0.39.0 — login
        LoginTitle  | LoginIntro |
        LoginPasskeyHeading  | LoginPasskeyButton  |
        LoginPasskeyJsRequired | LoginPasskeyFailed |
        LoginEmailHeading    | LoginEmailLabel     | LoginEmailButton |
        LoginPageTitleHtml   |
        // v0.39.0 — TOTP enroll
        TotpEnrollTitle | TotpEnrollIntro | TotpEnrollQrAriaLabel |
        TotpEnrollManualSummary | TotpEnrollManualMeta |
        TotpEnrollConfirmHeading | TotpEnrollConfirmIntro |
        TotpEnrollCodeLabel | TotpEnrollConfirmButton |
        TotpEnrollCancelLink | TotpEnrollPageTitleHtml |
        // v0.39.0 — TOTP verify
        TotpVerifyTitle | TotpVerifyIntro |
        TotpVerifyHeading | TotpVerifyCodeLabel |
        TotpVerifyContinueButton | TotpVerifyLostSummary |
        TotpVerifyRecoverIntro | TotpVerifyRecoverAriaLabel |
        TotpVerifyRecoverCodeLabel | TotpVerifyRecoverButton |
        TotpVerifyPageTitleHtml | TotpVerifyWrongCode |
        // v0.39.0 — Security Center index
        SecurityTitle | SecurityIntro | SecurityPrimaryHeading |
        SecurityTotpHeading | SecurityTotpAnonymousNotice |
        SecurityTotpDisabledBadge | SecurityTotpDisabledIntro |
        SecurityTotpEnableLink |
        SecuritySessionsHeading | SecuritySessionsIntro |
        SecuritySessionsLink | SecurityBackLink | SecurityPageTitleHtml |
        // RFC 106 — Security Center TOTP enabled + recovery banners
        SecurityTotpEnabledBadge | SecurityTotpDisableLink |
        SecurityRecoveryZeroTitle | SecurityRecoveryZeroDetail |
        SecurityRecoveryOneTitle  | SecurityRecoveryOneDetail  |
        SecurityRecoveryRemaining |
        // v0.45.0 — bulk revoke
        SessionsRevokeOthersButton | SessionsRevokeOthersConfirm |
        FlashOtherSessionsRevoked | FlashOtherSessionsRevokeFailed |
        FlashNoOtherSessions |
        // v0.47.0 — i18n-2 continuation
        PrimaryAuthMethodPasskey | PrimaryAuthMethodMagicLink | PrimaryAuthMethodAnonymous |
        MagicLinkSentPageTitle | MagicLinkSentHeading | MagicLinkSentIntro |
        MagicLinkSentOtpHeading | MagicLinkSentCodeLabel |
        TotpRecoveryCodesPageTitle | TotpRecoveryCodesHeading |
        TotpRecoveryCodesAlertStrong | TotpRecoveryCodesAlertBody |
        TotpRecoveryCodesBody | TotpRecoveryCodesContinue |
        TotpDisablePageTitle | TotpDisableHeading |
        TotpDisableAlertStrong | TotpDisableAlertBody | TotpDisableRecoveryHint |
        TotpDisableConfirmHeading | TotpDisableSubmit |
        ErrorPageBackLink |
        // RFC 016 — admin scope badge
        AdminScopeSystem | AdminScopeTenancy | AdminScopeTenant |
        // RFC 075 — Security Center summary card
        SecuritySummaryHeading | SecuritySummaryPasskeyOk | SecuritySummaryPasskeyAnonymous |
        SecuritySummaryPasskeyMagicLink | SecuritySummaryTotpEnabled | SecuritySummaryTotpDisabled |
        SecuritySummaryRecovery | SecuritySummarySessions |
        // RFC 076 — recovery code save gate
        TotpRecoverySavedConfirmLabel | TotpRecoveryProceedButton |
        // RFC 077 — skip-to-content
        SkipToMainContent |
        // RFC 079 — magic link unavailable notice
        LoginMagicLinkUnavailableNotice |
        // RFC 084 — sessions drift note
        SessionsDriftNote |
        // RFC 078 — tenant admin invitation/deletion i18n
        TenantInvitePageTitle | TenantInviteSectionTitle | TenantInviteEmailLabel |
        TenantInviteRoleLabel | TenantInviteRoleMember | TenantInviteRoleAdmin |
        TenantInviteSubmitButton | TenantInvitePendingHeading | TenantInviteEmpty |
        TenantInviteColEmail | TenantInviteColRole | TenantInviteColStatus |
        TenantInviteColExpires | TenantInviteStatusPending | TenantInviteStatusExpired |
        TenantInviteStatusRevoked | TenantInviteExpiresInHours |
        TenantInviteRevokeButton | TenantInviteRevokeConfirm |
        TenantDeletionPageTitle | TenantDeletionGracePeriodNotice | TenantDeletionTableHeading |
        TenantDeletionEmpty | TenantDeletionColUserId | TenantDeletionColStatus |
        TenantDeletionColScheduled | TenantDeletionColActions |
        TenantDeletionStatusPending | TenantDeletionStatusExecuted | TenantDeletionStatusCancelled |
        TenantDeletionScheduledInDays | TenantDeletionCancelButton |
        TenantDeletionExecuteButton | TenantDeletionExecuteConfirm |
        // RFC 109 — audit log viewer
        AuditViewerPageTitle | AuditViewerSectionTitle | AuditViewerActorLabel |
        AuditViewerEventLabel | AuditViewerEventAny | AuditViewerPeriodLabel |
        AuditViewerFromLabel | AuditViewerToLabel | AuditViewerSubmitButton |
        AuditViewerExportButton | AuditViewerNewerLink | AuditViewerOlderLink |
        AuditViewerEmptyState | AuditViewerColTime | AuditViewerColActor |
        AuditViewerColEvent | AuditViewerColReason | AuditViewerColSeq |
        AuditViewerNoteSchemaTenant
            => {}  // exhaustiveness pin — body is irrelevant
    }
    // Now actually iterate. The list below mirrors the match
    // above; the match is the build-time guard, this is the
    // runtime walker.
    let all = [
        FlashTotpEnabled, FlashTotpDisabled, FlashTotpRecovered,
        FlashLoggedOut,   FlashSessionRevoked,
        TotpEnrollWrongCode,
        SessionsPageTitle, SessionsPageIntro, SessionsPageEmpty,
        SessionsBackLink,
        SessionsCurrentBadge, SessionsCurrentDisabled,
        SessionsCurrentDisabledTitle, SessionsRevokeButton,
        SessionsAuthMethodPasskey, SessionsAuthMethodMagicLink,
        SessionsAuthMethodAdmin,   SessionsAuthMethodUnknown,
        SessionsLabelSignIn,   SessionsLabelLastSeen,
        SessionsLabelClient,   SessionsLabelSessionId,
        LoginTitle,  LoginIntro,
        LoginPasskeyHeading,  LoginPasskeyButton,
        LoginPasskeyJsRequired, LoginPasskeyFailed,
        LoginEmailHeading,    LoginEmailLabel,     LoginEmailButton,
        LoginPageTitleHtml,
        TotpEnrollTitle, TotpEnrollIntro, TotpEnrollQrAriaLabel,
        TotpEnrollManualSummary, TotpEnrollManualMeta,
        TotpEnrollConfirmHeading, TotpEnrollConfirmIntro,
        TotpEnrollCodeLabel, TotpEnrollConfirmButton,
        TotpEnrollCancelLink, TotpEnrollPageTitleHtml,
        TotpVerifyTitle, TotpVerifyIntro,
        TotpVerifyHeading, TotpVerifyCodeLabel,
        TotpVerifyContinueButton, TotpVerifyLostSummary,
        TotpVerifyRecoverIntro, TotpVerifyRecoverAriaLabel,
        TotpVerifyRecoverCodeLabel, TotpVerifyRecoverButton,
        TotpVerifyPageTitleHtml, TotpVerifyWrongCode,
        SecurityTitle, SecurityIntro, SecurityPrimaryHeading,
        SecurityTotpHeading, SecurityTotpAnonymousNotice,
        SecurityTotpDisabledBadge, SecurityTotpDisabledIntro,
        SecurityTotpEnableLink,
        SecuritySessionsHeading, SecuritySessionsIntro,
        SecuritySessionsLink, SecurityBackLink, SecurityPageTitleHtml,
        // RFC 106
        SecurityTotpEnabledBadge, SecurityTotpDisableLink,
        SecurityRecoveryZeroTitle, SecurityRecoveryZeroDetail,
        SecurityRecoveryOneTitle,  SecurityRecoveryOneDetail,
        SecurityRecoveryRemaining,
        SessionsRevokeOthersButton, SessionsRevokeOthersConfirm,
        FlashOtherSessionsRevoked, FlashOtherSessionsRevokeFailed,
        FlashNoOtherSessions,
        // v0.47.0
        PrimaryAuthMethodPasskey, PrimaryAuthMethodMagicLink, PrimaryAuthMethodAnonymous,
        MagicLinkSentPageTitle, MagicLinkSentHeading, MagicLinkSentIntro,
        MagicLinkSentOtpHeading, MagicLinkSentCodeLabel,
        TotpRecoveryCodesPageTitle, TotpRecoveryCodesHeading,
        TotpRecoveryCodesAlertStrong, TotpRecoveryCodesAlertBody,
        TotpRecoveryCodesBody, TotpRecoveryCodesContinue,
        TotpDisablePageTitle, TotpDisableHeading,
        TotpDisableAlertStrong, TotpDisableAlertBody, TotpDisableRecoveryHint,
        TotpDisableConfirmHeading, TotpDisableSubmit,
        ErrorPageBackLink,
        // RFC 016
        AdminScopeSystem, AdminScopeTenancy, AdminScopeTenant,
        // RFC 075-079, 084
        LoginMagicLinkUnavailableNotice,
        SessionsDriftNote,
        SecuritySummaryHeading, SecuritySummaryPasskeyOk, SecuritySummaryPasskeyAnonymous,
        SecuritySummaryPasskeyMagicLink, SecuritySummaryTotpEnabled, SecuritySummaryTotpDisabled,
        SecuritySummaryRecovery, SecuritySummarySessions,
        TotpRecoverySavedConfirmLabel, TotpRecoveryProceedButton,
        SkipToMainContent,
        TenantInvitePageTitle, TenantInviteSectionTitle, TenantInviteEmailLabel,
        TenantInviteRoleLabel, TenantInviteRoleMember, TenantInviteRoleAdmin,
        TenantInviteSubmitButton, TenantInvitePendingHeading, TenantInviteEmpty,
        TenantInviteColEmail, TenantInviteColRole, TenantInviteColStatus,
        TenantInviteColExpires, TenantInviteStatusPending, TenantInviteStatusExpired,
        TenantInviteStatusRevoked, TenantInviteExpiresInHours,
        TenantInviteRevokeButton, TenantInviteRevokeConfirm,
        TenantDeletionPageTitle, TenantDeletionGracePeriodNotice, TenantDeletionTableHeading,
        TenantDeletionEmpty, TenantDeletionColUserId, TenantDeletionColStatus,
        TenantDeletionColScheduled, TenantDeletionColActions,
        TenantDeletionStatusPending, TenantDeletionStatusExecuted, TenantDeletionStatusCancelled,
        TenantDeletionScheduledInDays, TenantDeletionCancelButton,
        TenantDeletionExecuteButton, TenantDeletionExecuteConfirm,
        // RFC 109 — audit log viewer
        AuditViewerPageTitle, AuditViewerSectionTitle, AuditViewerActorLabel,
        AuditViewerEventLabel, AuditViewerEventAny, AuditViewerPeriodLabel,
        AuditViewerFromLabel, AuditViewerToLabel, AuditViewerSubmitButton,
        AuditViewerExportButton, AuditViewerNewerLink, AuditViewerOlderLink,
        AuditViewerEmptyState, AuditViewerColTime, AuditViewerColActor,
        AuditViewerColEvent, AuditViewerColReason, AuditViewerColSeq,
        AuditViewerNoteSchemaTenant,
    ];
    for k in all { f(k); }
}

/// Every supported locale must resolve every MessageKey to a
/// non-empty string.
#[test]
fn every_message_key_resolves_in_every_locale_to_nonempty() {
    for_each_key(|key| {
        for locale in [Locale::Ja, Locale::En] {
            let text = lookup(key, locale);
            assert!(!text.is_empty(),
                "lookup({key:?}, {locale:?}) returned empty string — \
                 every key must have a real translation in every locale");
        }
    });
}

/// Within one locale, no two keys may resolve to the SAME
/// rendered text. If they do, either the keys are redundant
/// or the translations have drifted to be indistinguishable.
/// Some legitimate exceptions are listed in `is_legitimate_duplicate`.
#[test]
fn no_two_keys_share_text_within_a_locale() {
    /// Returns true for the rare cases where two keys
    /// SHOULD share text (brand strings, repeated labels
    /// across locale boundaries).
    fn is_legitimate_duplicate(text: &str) -> bool {
        // Brand and term-of-art strings: legitimately the
        // same in every locale or across multiple keys.
        const SHARED: &[&str] = &[
            "Magic Link",
            "パスキー",
            "Passkey",
            // The phrase "Active sessions" / "アクティブなセッション"
            // is used both as the dedicated `/me/security/sessions`
            // page title (`SessionsPageTitle`) and as the
            // section heading on the Security Center index
            // (`SecuritySessionsHeading`). Same concept, two
            // surfaces; reusing the canonical translation is
            // correct.
            "Active sessions",
            "アクティブなセッション",
            // RFC 078: "メールアドレス" is legitimately shared between
            // the login form (LoginEmailLabel) and the invitation form
            // (TenantInviteEmailLabel) — both refer to the same field.
            "メールアドレス",
            "Email address",
            // "状態" / "Status" used in both invitation and deletion tables
            "状態",
            "Status",
            // "保留中" / "Pending" shared across invitation and deletion status
            "保留中",
            "Pending",
            // "ロール" / "Role" — generic term used across multiple surfaces
            "ロール",
            // "取り消す" / "Revoke" — used for both session revoke and invitation revoke
            "取り消す",
            "Revoke",
        ];
        SHARED.contains(&text)
    }

    for locale in [Locale::Ja, Locale::En] {
        let mut seen: std::collections::HashMap<&str, MessageKey> =
            std::collections::HashMap::new();
        for_each_key(|key| {
            let text = lookup(key, locale);
            if is_legitimate_duplicate(text) { return; }
            if let Some(prev) = seen.insert(text, key) {
                panic!(
                    "duplicate text {text:?} in locale {locale:?}: \
                     {prev:?} and {key:?} resolve to the same string"
                );
            }
        });
    }
}

// =====================================================================
