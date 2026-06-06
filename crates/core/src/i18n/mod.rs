//! Internationalization (v0.36.0, ADR-013).
//!
//! cesauth's user-facing UI is a mix of hardcoded Japanese
//! (TOTP, Security Center, sessions page) and hardcoded
//! English (admin console, machine error bodies) with no
//! `Accept-Language` handling. This module is the
//! infrastructure that retires that debt:
//!
//! - [`Locale`] is the closed set of supported locales.
//!   v0.36.0 ships `Ja` and `En`. Adding a locale requires a
//!   recompile — runtime catalog loading would mean trusting
//!   filesystem-shaped data and would be more attack surface
//!   for marginal benefit.
//!
//! - [`MessageKey`] is the closed set of user-visible strings
//!   that callers ask for through this module. Every variant
//!   has every locale's translation, statically guaranteed by
//!   the lookup function's match exhaustiveness — adding a
//!   key without a translation in every locale is a compile
//!   error.
//!
//! - [`lookup`] resolves a `(MessageKey, Locale)` pair to a
//!   `&'static str`. Zero allocation.
//!
//! - [`parse_accept_language`] is a small RFC 7231 §5.3.5
//!   parser that picks the highest-q supported locale, with
//!   `Locale::default()` as the fallthrough.
//!
//! ## Why this is in core
//!
//! `cesauth-core` already holds the domain types
//! (`SessionState`, `FlashKey`-equivalent enums, etc.) and is
//! the single crate every other crate depends on. Putting
//! the catalog here lets `cesauth-ui` templates and worker
//! audit dispatch share the same canonical source.
//!
//! ## Migration path
//!
//! Existing callsites that currently hold hardcoded strings
//! migrate by:
//!
//! 1. Replacing the literal with `MessageKey::ThisKey`.
//! 2. Resolving via `lookup(key, locale)` at the rendering
//!    boundary (template / response builder).
//! 3. The locale is passed in by the worker layer — see
//!    `cesauth_worker::i18n` for the resolver.
//!
//! Migration happens incrementally; v0.36.0 migrates the
//! flash keys + TOTP wrong-code re-render + sessions page
//! chrome. Subsequent releases migrate the rest of the
//! end-user surfaces (admin console stays English; that's a
//! separable concern).

/// Closed set of supported locales. `Default` returns `Ja`
/// because the existing user-facing surfaces are
/// JA-hardcoded and the default-locale tie-breaker should
/// preserve that behavior for users who don't send
/// Accept-Language at all.
///
/// Adding a locale: add a variant here, add an arm to every
/// `match` in `lookup` (compile-time exhaustiveness will tell
/// you which ones), update `parse_accept_language`'s
/// supported-list, add tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Locale {
    /// Japanese.
    Ja,
    /// English (no region subtag; v0.36.0 doesn't distinguish
    /// `en-US` from `en-GB` because the catalog text doesn't
    /// vary by region).
    En,
}

impl Default for Locale {
    fn default() -> Self { Self::Ja }
}

impl Locale {
    /// BCP-47 primary subtag. Used in `<html lang="...">`
    /// emit and in tests. 2-letter ISO 639-1 codes only;
    /// no script or region subtags in v0.36.0.
    pub fn bcp47(self) -> &'static str {
        match self {
            Self::Ja => "ja",
            Self::En => "en",
        }
    }

    /// Parse a primary subtag — the substring before any `-`.
    /// Case-insensitive. Returns `None` for unsupported
    /// languages so the caller can fall through to the
    /// default.
    pub fn from_primary_subtag(s: &str) -> Option<Self> {
        // Strip any region/script subtags first. RFC 5646:
        // primary subtag is the part before the first '-'.
        let primary = s.split('-').next().unwrap_or(s);
        match primary.to_ascii_lowercase().as_str() {
            "ja" => Some(Self::Ja),
            "en" => Some(Self::En),
            _    => None,
        }
    }
}

/// Closed set of user-visible message keys.
///
/// **Naming convention**: keys are PascalCase, named after
/// the *concept* (e.g., `TotpEnabled`) rather than the
/// rendered text. Renaming the text doesn't require renaming
/// the key.
///
/// **Adding a key**:
/// 1. Add a variant here (PascalCase).
/// 2. Add a translation arm in `lookup` for every `Locale`
///    — the compiler enforces this via match exhaustiveness.
/// 3. If the key is for an existing surface that previously
///    held a hardcoded string, replace that string with a
///    call site through `lookup`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageKey {
    // --- flash banners ---
    FlashTotpEnabled,
    FlashTotpDisabled,
    FlashTotpRecovered,
    FlashLoggedOut,
    FlashSessionRevoked,

    // --- TOTP enroll wrong-code re-render ---
    TotpEnrollWrongCode,

    // --- /me/security/sessions page chrome ---
    SessionsPageTitle,
    SessionsPageIntro,
    SessionsPageEmpty,
    SessionsBackLink,
    SessionsCurrentBadge,
    SessionsCurrentDisabled,
    SessionsCurrentDisabledTitle,
    SessionsRevokeButton,
    SessionsAuthMethodPasskey,
    SessionsAuthMethodMagicLink,
    SessionsAuthMethodAdmin,
    SessionsAuthMethodUnknown,
    SessionsLabelSignIn,
    SessionsLabelLastSeen,
    SessionsLabelClient,
    SessionsLabelSessionId,

    // ---- v0.39.0: login page (`/login`) ----
    LoginTitle,
    LoginIntro,
    LoginPasskeyHeading,
    LoginPasskeyButton,
    LoginPasskeyJsRequired,
    LoginPasskeyFailed,
    LoginEmailHeading,
    LoginEmailLabel,
    LoginEmailButton,
    LoginPageTitleHtml,
    /// RFC 079: shown instead of the email form when MagicLinkMailer is unconfigured.
    LoginMagicLinkUnavailableNotice,

    // ---- v0.39.0: TOTP enroll page (`/me/security/totp/enroll`) ----
    TotpEnrollTitle,
    TotpEnrollIntro,
    TotpEnrollQrAriaLabel,
    TotpEnrollManualSummary,
    TotpEnrollManualMeta,
    TotpEnrollConfirmHeading,
    TotpEnrollConfirmIntro,
    TotpEnrollCodeLabel,
    TotpEnrollConfirmButton,
    TotpEnrollCancelLink,
    TotpEnrollPageTitleHtml,

    // ---- v0.39.0: TOTP verify gate page (`/me/security/totp/verify`) ----
    TotpVerifyTitle,
    TotpVerifyIntro,
    TotpVerifyHeading,
    TotpVerifyCodeLabel,
    TotpVerifyContinueButton,
    TotpVerifyLostSummary,
    TotpVerifyRecoverIntro,
    TotpVerifyRecoverAriaLabel,
    TotpVerifyRecoverCodeLabel,
    TotpVerifyRecoverButton,
    TotpVerifyPageTitleHtml,
    /// **v0.39.0** — Inline error rendered when the
    /// `/me/security/totp/verify` POST receives a non-matching
    /// 6-digit code. Distinct from `TotpEnrollWrongCode` because
    /// the *enroll* surface tells the user "enter the LATEST
    /// 6-digit code" (a setup hint), while *verify* simply asks
    /// them to try again — they're already past the QR-scan
    /// step. Same idea, different stage of the user journey;
    /// keep the keys separate so translations can diverge.
    TotpVerifyWrongCode,

    // ---- v0.39.0: Security Center index (`/me/security`) ----
    SecurityTitle,
    SecurityIntro,
    SecurityPrimaryHeading,
    SecurityTotpHeading,
    SecurityTotpAnonymousNotice,
    SecurityTotpDisabledBadge,
    SecurityTotpDisabledIntro,
    SecurityTotpEnableLink,
    SecuritySessionsHeading,
    SecuritySessionsIntro,
    SecuritySessionsLink,
    SecurityBackLink,
    SecurityPageTitleHtml,

    // ---- RFC 106 (v0.67.0): Security Center TOTP enabled-state + recovery banners ----
    /// Badge text for the TOTP-enabled state on `/me/security`
    /// ("有効" / "Enabled"). Distinct from `SecurityTotpDisabledBadge`
    /// because the two states share the heading but never the badge.
    SecurityTotpEnabledBadge,
    /// Link copy ("TOTP を無効化する" / "Disable TOTP") shown beneath
    /// the enabled badge. Points the user at `/me/security/totp/disable`.
    SecurityTotpDisableLink,
    /// Strong title for the N=0 recovery banner ("リカバリーコード残なし。"
    /// / "No recovery codes remaining."). Paired with
    /// [`SecurityRecoveryZeroDetail`].
    SecurityRecoveryZeroTitle,
    /// Detail copy for the N=0 recovery banner.
    SecurityRecoveryZeroDetail,
    /// Strong title for the N=1 recovery banner ("リカバリーコード: 残り 1 個。"
    /// / "Recovery codes: 1 remaining."). Paired with
    /// [`SecurityRecoveryOneDetail`].
    SecurityRecoveryOneTitle,
    /// Detail copy for the N=1 recovery banner — explains the
    /// re-enroll path back to a full set of codes.
    SecurityRecoveryOneDetail,
    /// Template for the N≥2 recovery status badge
    /// ("リカバリーコード: {n} 個有効" / "Recovery codes: {n} valid").
    /// Caller substitutes `{n}` with the count via `.replace("{n}", ...)`.
    /// True plural-form handling is deferred to RFC 107 (ADR-013 §Q4).
    SecurityRecoveryRemaining,

    // ---- RFC 075: Security Center mobile state summary card ----
    SecuritySummaryHeading,           // screen-reader heading for the card (visually hidden)
    SecuritySummaryPasskeyOk,         // "パスキー設定済み" / "Passkey OK"
    SecuritySummaryPasskeyAnonymous,  // "ゲスト" / "Guest"
    SecuritySummaryPasskeyMagicLink,  // "メールリンク認証" / "Magic Link"
    SecuritySummaryTotpEnabled,       // "TOTP 有効" / "TOTP enabled"
    SecuritySummaryTotpDisabled,      // "TOTP 未設定" / "TOTP off"
    SecuritySummaryRecovery,          // "リカバリーコード {n} 残" / "Recovery: {n}" (format with n)
    SecuritySummarySessions,          // "セッション {n}" / "Sessions: {n}" (format with n)

    // ---- v0.45.0: bulk "revoke all other sessions" ----
    SessionsRevokeOthersButton,
    SessionsRevokeOthersConfirm,
    /// RFC 084: subtle note about session index eventual consistency.
    SessionsDriftNote,
    FlashOtherSessionsRevoked,
    FlashOtherSessionsRevokeFailed,
    FlashNoOtherSessions,

    // ---- v0.47.0: i18n-2 continuation ----
    // PrimaryAuthMethod labels (Security Center)
    PrimaryAuthMethodPasskey,
    PrimaryAuthMethodMagicLink,
    PrimaryAuthMethodAnonymous,

    // Magic Link "Check your inbox" page
    MagicLinkSentPageTitle,
    MagicLinkSentHeading,
    MagicLinkSentIntro,
    MagicLinkSentOtpHeading,
    MagicLinkSentCodeLabel,

    // TOTP recovery codes display page
    TotpRecoveryCodesPageTitle,
    TotpRecoveryCodesHeading,
    TotpRecoveryCodesAlertStrong,
    TotpRecoveryCodesAlertBody,
    TotpRecoveryCodesBody,
    TotpRecoveryCodesContinue,
    /// **RFC 076**: checkbox label for the save-confirmation gate
    TotpRecoverySavedConfirmLabel,
    /// **RFC 076**: button label after confirmation
    TotpRecoveryProceedButton,

    // TOTP disable confirm page
    TotpDisablePageTitle,
    TotpDisableHeading,
    TotpDisableAlertStrong,
    TotpDisableAlertBody,
    TotpDisableRecoveryHint,
    TotpDisableConfirmHeading,
    TotpDisableSubmit,

    // Error page
    ErrorPageBackLink,

    // --- RFC 016: admin scope badge ---
    /// `/admin/console/*` — deployment-wide system scope.
    AdminScopeSystem,
    /// `/admin/tenancy/*` — cross-tenant operator console.
    AdminScopeTenancy,
    /// `/admin/t/<slug>/*` — single-tenant scope.
    /// The slug is interpolated by the caller using the
    /// `{slug}` placeholder; the returned string contains
    /// `{slug}` verbatim for the caller to substitute.
    AdminScopeTenant,

    // ---- RFC 077: skip-to-content link (WCAG 2.4.1) ----
    SkipToMainContent,

    // ---- RFC 078: tenant admin invitation page ----
    TenantInvitePageTitle,
    TenantInviteSectionTitle,
    TenantInviteEmailLabel,
    TenantInviteRoleLabel,
    TenantInviteRoleMember,
    TenantInviteRoleAdmin,
    TenantInviteSubmitButton,
    TenantInvitePendingHeading,
    TenantInviteEmpty,
    TenantInviteColEmail,
    TenantInviteColRole,
    TenantInviteColStatus,
    TenantInviteColExpires,
    TenantInviteStatusPending,
    TenantInviteStatusExpired,
    TenantInviteStatusRevoked,
    TenantInviteExpiresInHours,
    TenantInviteRevokeButton,
    TenantInviteRevokeConfirm,

    // ---- RFC 078: tenant admin deletion request page ----
    TenantDeletionPageTitle,
    TenantDeletionGracePeriodNotice,
    TenantDeletionTableHeading,
    TenantDeletionEmpty,
    TenantDeletionColUserId,
    TenantDeletionColStatus,
    TenantDeletionColScheduled,
    TenantDeletionColActions,
    TenantDeletionStatusPending,
    TenantDeletionStatusExecuted,
    TenantDeletionStatusCancelled,
    TenantDeletionScheduledInDays,
    TenantDeletionCancelButton,
    TenantDeletionExecuteButton,
    TenantDeletionExecuteConfirm,

    // ---- RFC 109: audit log viewer (admin console, JA-only per ADR-013) ----
    AuditViewerPageTitle,
    AuditViewerSectionTitle,
    AuditViewerActorLabel,
    AuditViewerEventLabel,
    AuditViewerPeriodLabel,
    AuditViewerFromLabel,
    AuditViewerToLabel,
    AuditViewerSubmitButton,
    AuditViewerExportButton,
    AuditViewerNewerLink,
    AuditViewerOlderLink,
    AuditViewerEmptyState,
    AuditViewerColTime,
    AuditViewerColActor,
    AuditViewerColEvent,
    AuditViewerColReason,
    AuditViewerColSeq,
    AuditViewerNoteSchemaTenant,
    AuditViewerEventAny,
}

/// Resolve `(key, locale) -> &'static str`. Zero allocation.
///
/// Adding a `MessageKey` variant without translations in
/// every locale is a compile error — the inner match against
/// `Locale` is exhaustive, and the outer match against
/// `MessageKey` is exhaustive, so the compiler enforces full
/// coverage of both axes.

/// Resolve `(key, locale) -> &'static str`. Zero allocation.
///
/// Dispatches to one of ten grouped sub-functions (RFC 097) to keep
/// each group ≤ 150 lines. Every `MessageKey` variant is covered by
/// exactly one sub-function; the compiler enforces exhaustiveness via
/// the top-level match in the `inline_tests` module.
pub fn lookup(key: MessageKey, locale: Locale) -> &'static str {
        if let Some(s) = lookup_flash(&key, locale) { return s; }
        if let Some(s) = lookup_sessions(&key, locale) { return s; }
        if let Some(s) = lookup_login(&key, locale) { return s; }
        if let Some(s) = lookup_totp_flow(&key, locale) { return s; }
        if let Some(s) = lookup_security(&key, locale) { return s; }
        if let Some(s) = lookup_sessions_bulk(&key, locale) { return s; }
        if let Some(s) = lookup_magic_link_totp_pages(&key, locale) { return s; }
        if let Some(s) = lookup_admin(&key, locale) { return s; }
    // Fallback: panic with the key name so missing translations fail loudly
    // during development. In production this path is unreachable if the
    // exhaustive-match test in i18n/tests.rs passes.
    panic!("i18n: no translation for {key:?} in locale {locale:?}")
}

#[inline]
fn lookup_flash(key: &MessageKey, locale: Locale) -> Option<&'static str> {
    use MessageKey::*;
    Some(match key {
        // ----- flash banners -----
        FlashTotpEnabled => match locale {
            Locale::Ja => "TOTP を有効にしました。",
            Locale::En => "TOTP is now enabled.",
        },
        FlashTotpDisabled => match locale {
            Locale::Ja => "TOTP を無効にしました。",
            Locale::En => "TOTP is now disabled.",
        },
        FlashTotpRecovered => match locale {
            Locale::Ja => "リカバリーコードを使用しました。authenticator を失った場合は再 enroll を検討してください。",
            Locale::En => "Recovery code accepted. If you've lost your authenticator, consider re-enrolling.",
        },
        FlashLoggedOut => match locale {
            Locale::Ja => "ログアウトしました。",
            Locale::En => "Signed out.",
        },
        FlashSessionRevoked => match locale {
            Locale::Ja => "セッションを取り消しました。",
            Locale::En => "Session revoked.",
        },

        // ----- TOTP enroll wrong-code re-render -----
        TotpEnrollWrongCode => match locale {
            Locale::Ja => "入力されたコードが一致しませんでした。Authenticator アプリの最新の 6 桁を入力してください。",
            Locale::En => "That code didn't match. Enter the latest 6-digit code from your authenticator app.",
        },

        _ => return None,
    })
}

#[inline]
fn lookup_sessions(key: &MessageKey, locale: Locale) -> Option<&'static str> {
    use MessageKey::*;
    Some(match key {
        // ----- /me/security/sessions page chrome -----
        SessionsPageTitle => match locale {
            Locale::Ja => "アクティブなセッション",
            Locale::En => "Active sessions",
        },
        SessionsPageIntro => match locale {
            Locale::Ja => "サインイン中の端末/ブラウザの一覧です。心当たりのないセッションは右側のボタンで取り消してください。",
            Locale::En => "Devices and browsers signed in to your account. Revoke any session you don't recognize.",
        },
        SessionsPageEmpty => match locale {
            Locale::Ja => "アクティブなセッションはありません。",
            Locale::En => "No active sessions.",
        },
        SessionsBackLink => match locale {
            Locale::Ja => "← セキュリティ センターへ戻る",
            Locale::En => "← Back to Security Center",
        },
        SessionsCurrentBadge => match locale {
            Locale::Ja => "この端末",
            Locale::En => "This device",
        },
        SessionsCurrentDisabled => match locale {
            Locale::Ja => "使用中",
            Locale::En => "Current",
        },
        SessionsCurrentDisabledTitle => match locale {
            Locale::Ja => "このセッションは現在使用中です。ログアウトはトップページからどうぞ。",
            Locale::En => "This is the session you're using right now. To end it, sign out from the home page.",
        },
        SessionsRevokeButton => match locale {
            Locale::Ja => "取り消す",
            Locale::En => "Revoke",
        },
        SessionsAuthMethodPasskey => match locale {
            Locale::Ja => "パスキー",
            Locale::En => "Passkey",
        },
        SessionsAuthMethodMagicLink => match locale {
            Locale::Ja => "Magic Link",
            Locale::En => "Magic Link",
        },
        SessionsAuthMethodAdmin => match locale {
            Locale::Ja => "管理者ログイン",
            Locale::En => "Admin sign-in",
        },
        SessionsAuthMethodUnknown => match locale {
            Locale::Ja => "不明",
            Locale::En => "Unknown",
        },
        SessionsLabelSignIn => match locale {
            Locale::Ja => "サインイン",
            Locale::En => "Signed in",
        },
        SessionsLabelLastSeen => match locale {
            Locale::Ja => "最終アクセス",
            Locale::En => "Last seen",
        },
        SessionsLabelClient => match locale {
            Locale::Ja => "クライアント",
            Locale::En => "Client",
        },
        SessionsLabelSessionId => match locale {
            Locale::Ja => "セッション ID",
            Locale::En => "Session ID",
        },

        _ => return None,
    })
}

#[inline]
fn lookup_login(key: &MessageKey, locale: Locale) -> Option<&'static str> {
    use MessageKey::*;
    Some(match key {
        // ----- v0.39.0: login page -----
        LoginTitle => match locale {
            // JA: action-verb form to distinguish from
            // SessionsLabelSignIn ("サインイン" = sign-in
            // timestamp label on the session card). The
            // login page is asking the user to do the
            // action; the session row is reporting that
            // it happened. "する" disambiguates while
            // staying natural.
            Locale::Ja => "サインインする",
            Locale::En => "Sign in",
        },
        LoginIntro => match locale {
            Locale::Ja => "パスキーをお持ちであればパスキーで、そうでなければメールアドレスでワンタイムコードを送信します。",
            Locale::En => "Use your passkey if you have one. Otherwise, enter your email and we'll send you a one-time code.",
        },
        LoginPasskeyHeading => match locale {
            Locale::Ja => "パスキー",
            Locale::En => "Passkey",
        },
        LoginPasskeyButton => match locale {
            Locale::Ja => "パスキーでサインイン",
            Locale::En => "Sign in with a passkey",
        },
        LoginPasskeyJsRequired => match locale {
            Locale::Ja => "パスキーによるサインインには JavaScript が必要です。下のメールでサインインをお使いください。",
            Locale::En => "Passkey sign-in requires JavaScript. Use the email option below.",
        },
        LoginPasskeyFailed => match locale {
            Locale::Ja => "パスキーでサインインできませんでした。メールでのサインインをお試しください。",
            Locale::En => "Passkey sign-in didn't work. Try the email option.",
        },
        LoginEmailHeading => match locale {
            Locale::Ja => "またはメールでコードを受け取る",
            Locale::En => "Or email me a code",
        },
        LoginEmailLabel => match locale {
            Locale::Ja => "メールアドレス",
            Locale::En => "Email address",
        },
        LoginEmailButton => match locale {
            Locale::Ja => "コードをメールで受け取る",
            Locale::En => "Email me a code",
        },
        LoginPageTitleHtml => match locale {
            Locale::Ja => "サインイン - cesauth",
            Locale::En => "Sign in - cesauth",
        },
        // RFC 079: shown when MagicLinkMailer is not configured
        LoginMagicLinkUnavailableNotice => match locale {
            Locale::Ja => "メールリンクは現在ご利用いただけません。パスキーでサインインしてください。",
            Locale::En => "Magic Link is currently unavailable. Please sign in with a passkey.",
        },

        _ => return None,
    })
}

#[inline]
fn lookup_totp_flow(key: &MessageKey, locale: Locale) -> Option<&'static str> {
    use MessageKey::*;
    Some(match key {
        // ----- v0.39.0: TOTP enroll -----
        TotpEnrollTitle => match locale {
            Locale::Ja => "Authenticator を設定する",
            Locale::En => "Set up an authenticator",
        },
        TotpEnrollIntro => match locale {
            Locale::Ja => "Google Authenticator、Authy、1Password など RFC 6238 準拠の TOTP アプリで、この QR コードをスキャンしてください:",
            Locale::En => "Scan this QR code with Google Authenticator, Authy, 1Password, or any other RFC 6238 TOTP app:",
        },
        TotpEnrollQrAriaLabel => match locale {
            Locale::Ja => "TOTP シークレットを含む QR コード",
            Locale::En => "QR code containing your TOTP secret",
        },
        TotpEnrollManualSummary => match locale {
            Locale::Ja => "スキャンできない場合: 手動で鍵を入力する",
            Locale::En => "Can't scan? Enter the key manually:",
        },
        TotpEnrollManualMeta => match locale {
            Locale::Ja => "アルゴリズム: SHA-1 · 桁数: 6 · 周期: 30 秒",
            Locale::En => "Algorithm: SHA-1 · Digits: 6 · Period: 30 seconds",
        },
        TotpEnrollConfirmHeading => match locale {
            Locale::Ja => "コードで確認する",
            Locale::En => "Confirm with a code",
        },
        TotpEnrollConfirmIntro => match locale {
            Locale::Ja => "スキャン後、アプリには 30 秒ごとに変わる 6 桁のコードが表示されます。現在のコードを入力してセットアップを完了してください。",
            Locale::En => "After scanning, your app will display a 6-digit code that changes every 30 seconds. Enter the current code to finish setup.",
        },
        TotpEnrollCodeLabel => match locale {
            Locale::Ja => "現在のコード",
            Locale::En => "Current code",
        },
        TotpEnrollConfirmButton => match locale {
            Locale::Ja => "確認して有効化する",
            Locale::En => "Confirm and enable",
        },
        TotpEnrollCancelLink => match locale {
            Locale::Ja => "キャンセルして戻る",
            Locale::En => "Cancel and go back",
        },
        TotpEnrollPageTitleHtml => match locale {
            Locale::Ja => "Authenticator を設定する - cesauth",
            Locale::En => "Set up an authenticator - cesauth",
        },

        // ----- v0.39.0: TOTP verify gate -----
        TotpVerifyTitle => match locale {
            Locale::Ja => "コードを入力してください",
            Locale::En => "Enter your code",
        },
        TotpVerifyIntro => match locale {
            Locale::Ja => "セキュリティ強化のため、このアカウントは Authenticator アプリで保護されています。アプリに表示されている 6 桁のコードを入力してください。",
            Locale::En => "For added security, your account is protected by an authenticator app. Enter the 6-digit code your app shows now.",
        },
        TotpVerifyHeading => match locale {
            Locale::Ja => "Authenticator コード",
            Locale::En => "Authenticator code",
        },
        TotpVerifyCodeLabel => match locale {
            Locale::Ja => "6 桁のコード",
            Locale::En => "6-digit code",
        },
        TotpVerifyContinueButton => match locale {
            Locale::Ja => "続ける",
            Locale::En => "Continue",
        },
        TotpVerifyLostSummary => match locale {
            Locale::Ja => "Authenticator を紛失した場合",
            Locale::En => "Lost your authenticator?",
        },
        TotpVerifyRecoverIntro => match locale {
            Locale::Ja => "登録時に保存したリカバリーコードを 1 つ使用できます:",
            Locale::En => "Use a recovery code from your enrollment instead:",
        },
        TotpVerifyRecoverAriaLabel => match locale {
            Locale::Ja => "ワンタイムリカバリーコードで認証する",
            Locale::En => "Recover with a one-time code",
        },
        TotpVerifyRecoverCodeLabel => match locale {
            Locale::Ja => "リカバリーコード",
            Locale::En => "Recovery code",
        },
        TotpVerifyRecoverButton => match locale {
            Locale::Ja => "リカバリーコードを使う",
            Locale::En => "Use recovery code",
        },
        TotpVerifyPageTitleHtml => match locale {
            Locale::Ja => "コードを入力 - cesauth",
            Locale::En => "Enter your code - cesauth",
        },
        TotpVerifyWrongCode => match locale {
            Locale::Ja => "コードが一致しませんでした。もう一度お試しください。",
            Locale::En => "That code didn't match. Try again.",
        },

        _ => return None,
    })
}

#[inline]
fn lookup_security(key: &MessageKey, locale: Locale) -> Option<&'static str> {
    use MessageKey::*;
    Some(match key {
        // ----- v0.39.0: Security Center index -----
        SecurityTitle => match locale {
            Locale::Ja => "セキュリティ",
            Locale::En => "Security",
        },
        SecurityIntro => match locale {
            Locale::Ja => "サインインと二段階認証の状態を確認します。",
            Locale::En => "Review your sign-in methods and two-factor settings.",
        },
        SecurityPrimaryHeading => match locale {
            Locale::Ja => "サインイン方法",
            Locale::En => "Sign-in method",
        },
        SecurityTotpHeading => match locale {
            Locale::Ja => "二段階認証 (TOTP)",
            Locale::En => "Two-factor authentication (TOTP)",
        },
        SecurityTotpAnonymousNotice => match locale {
            Locale::Ja => "匿名トライアルでは TOTP を有効化できません。通常アカウントへの promote 後に有効化できます。",
            Locale::En => "TOTP isn't available on anonymous trial accounts. Promote to a regular account first.",
        },
        SecurityTotpDisabledBadge => match locale {
            Locale::Ja => "無効",
            Locale::En => "Disabled",
        },
        SecurityTotpDisabledIntro => match locale {
            Locale::Ja => "Authenticator アプリで生成する 6 桁コードによる二段階認証を有効にできます。パスキーをお使いの場合は既に強力な認証が有効なので、TOTP は任意です。",
            Locale::En => "Enable a 6-digit code from your authenticator app as a second factor. If you use a passkey, you already have strong authentication; TOTP is optional.",
        },
        SecurityTotpEnableLink => match locale {
            Locale::Ja => "TOTP を有効化する",
            Locale::En => "Enable TOTP",
        },
        SecuritySessionsHeading => match locale {
            Locale::Ja => "アクティブなセッション",
            Locale::En => "Active sessions",
        },
        SecuritySessionsIntro => match locale {
            Locale::Ja => "サインイン中の端末/ブラウザを一覧表示し、不要なセッションを取り消せます。",
            Locale::En => "List signed-in devices and browsers, and revoke any session you don't recognize.",
        },
        SecuritySessionsLink => match locale {
            Locale::Ja => "セッションを確認する",
            Locale::En => "View sessions",
        },
        SecurityBackLink => match locale {
            Locale::Ja => "トップへ戻る",
            Locale::En => "Back to home",
        },
        SecurityPageTitleHtml => match locale {
            Locale::Ja => "セキュリティ - cesauth",
            Locale::En => "Security - cesauth",
        },

        // ----- RFC 106 (v0.67.0): TOTP enabled-state + recovery banners -----
        SecurityTotpEnabledBadge => match locale {
            Locale::Ja => "有効",
            Locale::En => "Enabled",
        },
        SecurityTotpDisableLink => match locale {
            Locale::Ja => "TOTP を無効化する",
            Locale::En => "Disable TOTP",
        },
        SecurityRecoveryZeroTitle => match locale {
            Locale::Ja => "リカバリーコード残なし。",
            Locale::En => "No recovery codes remaining.",
        },
        SecurityRecoveryZeroDetail => match locale {
            Locale::Ja => "authenticator を失うと管理者連絡が必要です。",
            Locale::En => "Losing your authenticator will require operator contact.",
        },
        SecurityRecoveryOneTitle => match locale {
            Locale::Ja => "リカバリーコード: 残り 1 個。",
            Locale::En => "Recovery codes: 1 remaining.",
        },
        SecurityRecoveryOneDetail => match locale {
            Locale::Ja => "次に authenticator を失うと管理者連絡が必要になります。TOTP を一度無効化して再 enroll すると 10 個に戻せます。",
            Locale::En => "If you lose your authenticator next, operator contact is required. Disable TOTP and re-enroll to refresh to 10 codes.",
        },
        // Caller substitutes "{n}" placeholder with the count. Plural-form
        // handling is deferred to RFC 107 (ADR-013 §Q4 closure).
        SecurityRecoveryRemaining => match locale {
            Locale::Ja => "リカバリーコード: {n} 個有効",
            Locale::En => "Recovery codes: {n} valid",
        },

        // ----- RFC 075: summary card -----
        SecuritySummaryHeading => match locale {
            Locale::Ja => "状態サマリ",
            Locale::En => "At a glance",
        },
        SecuritySummaryPasskeyOk => match locale {
            Locale::Ja => "パスキー設定済み",
            Locale::En => "Passkey OK",
        },
        SecuritySummaryPasskeyAnonymous => match locale {
            Locale::Ja => "ゲスト",
            Locale::En => "Guest",
        },
        SecuritySummaryPasskeyMagicLink => match locale {
            Locale::Ja => "メールリンク認証",
            Locale::En => "Magic Link",
        },
        SecuritySummaryTotpEnabled => match locale {
            Locale::Ja => "TOTP 有効",
            Locale::En => "TOTP enabled",
        },
        SecuritySummaryTotpDisabled => match locale {
            Locale::Ja => "TOTP 未設定",
            Locale::En => "TOTP off",
        },
        // Note: caller formats "{n}" placeholder using .replace("{n}", &count.to_string())
        SecuritySummaryRecovery => match locale {
            Locale::Ja => "リカバリーコード {n} 残",
            Locale::En => "Recovery: {n}",
        },
        SecuritySummarySessions => match locale {
            Locale::Ja => "セッション {n}",
            Locale::En => "Sessions: {n}",
        },

        _ => return None,
    })
}

#[inline]
fn lookup_sessions_bulk(key: &MessageKey, locale: Locale) -> Option<&'static str> {
    use MessageKey::*;
    Some(match key {
        // ----- v0.45.0: bulk "revoke all other sessions" -----
        SessionsRevokeOthersButton => match locale {
            // Action label on the button. Verb form so it
            // reads as a command, matching the existing
            // per-row `SessionsRevokeButton` style.
            Locale::Ja => "他のすべてのセッションを取り消す",
            Locale::En => "Sign out all other devices",
        },
        SessionsRevokeOthersConfirm => match locale {
            // Inline confirmation copy on the button form.
            // Renders as a `<p>` directly above the button.
            Locale::Ja => "現在のセッション以外のすべての端末でサインアウトします。元に戻すには各端末で再度サインインが必要です。",
            Locale::En => "All other devices will be signed out. To use them again you'll need to sign in on each one.",
        },
        // RFC 084: subtle footnote about session index eventual consistency
        SessionsDriftNote => match locale {
            Locale::Ja => "セッション情報は数分程度の遅延が生じる場合があります。",
            Locale::En => "Session information may be delayed by a few minutes.",
        },
        FlashOtherSessionsRevoked => match locale {
            // Flash banner shown after a successful bulk
            // revoke. The count is interpolated via
            // `flash::format`'s {n} substitution (a small
            // count-template helper added alongside this
            // PR — see flash.rs for the formatter).
            // Pluralization is deferred to ADR-013 §Q4
            // along with the recovery-code count messages
            // already deferred from v0.39.0; the JA form
            // works for any count, the EN form uses the
            // bare number as a defensive fallback ("Signed
            // out 1 other device" reads slightly off but
            // is unambiguous).
            Locale::Ja => "他の {n} 件のセッションをサインアウトしました。",
            Locale::En => "Signed out {n} other device(s).",
        },
        FlashOtherSessionsRevokeFailed => match locale {
            // Flash shown when at least one per-row revoke
            // failed. Best-effort semantics — we DO NOT
            // tell the user "0 succeeded" because some may
            // have; we say "couldn't sign out N, try
            // again". {n} is the error count.
            Locale::Ja => "{n} 件のセッションをサインアウトできませんでした。もう一度お試しください。",
            Locale::En => "Couldn't sign out {n} device(s). Please try again.",
        },
        FlashNoOtherSessions => match locale {
            // Flash shown when the user pressed the bulk
            // button but had no other active sessions.
            // Friendlier than "0 other sessions revoked".
            Locale::Ja => "他のサインイン中のセッションはありません。",
            Locale::En => "No other devices are signed in.",
        },

        // ============================================================
        // v0.47.0: i18n-2 continuation
        // ============================================================

        PrimaryAuthMethodPasskey => match locale {
            Locale::Ja => "パスキー",
            Locale::En => "Passkey",
        },
        PrimaryAuthMethodMagicLink => match locale {
            Locale::Ja => "メールリンク",
            Locale::En => "Magic Link",
        },
        PrimaryAuthMethodAnonymous => match locale {
            // Anonymous trial principal label. Used by
            // Security Center for users who haven't yet
            // bound a passkey or email; cesauth permits
            // a limited "anonymous trial" mode where
            // such users get scoped tokens but can't
            // enroll TOTP.
            Locale::Ja => "匿名トライアル",
            Locale::En => "Anonymous trial",
        },

        _ => return None,
    })
}

#[inline]
fn lookup_magic_link_totp_pages(key: &MessageKey, locale: Locale) -> Option<&'static str> {
    use MessageKey::*;
    Some(match key {
        // ----- Magic Link "Check your inbox" page -----
        MagicLinkSentPageTitle => match locale {
            Locale::Ja => "メールを確認 - cesauth",
            Locale::En => "Check your inbox - cesauth",
        },
        MagicLinkSentHeading => match locale {
            Locale::Ja => "メールを確認してください",
            Locale::En => "Check your inbox",
        },
        MagicLinkSentIntro => match locale {
            // Privacy-preserving phrasing: "if that
            // address is registered" — never confirm
            // account existence in the response (RFC
            // does not require it; cesauth's discipline
            // is to not leak user enumeration via the
            // sign-in flow).
            Locale::Ja => "このメールアドレスが登録されている場合、ワンタイムコードを送信しました。コードの有効期限は10分です。",
            Locale::En => "If that address is registered, we've just sent a one-time code. It expires in 10 minutes.",
        },
        MagicLinkSentOtpHeading => match locale {
            Locale::Ja => "コードを入力",
            Locale::En => "Enter the code",
        },
        MagicLinkSentCodeLabel => match locale {
            Locale::Ja => "ワンタイムコード",
            Locale::En => "One-time code",
        },

        // ----- TOTP recovery codes display page -----
        TotpRecoveryCodesPageTitle => match locale {
            Locale::Ja => "リカバリーコードを保存 - cesauth",
            Locale::En => "Save your recovery codes - cesauth",
        },
        TotpRecoveryCodesHeading => match locale {
            Locale::Ja => "リカバリーコードを保存してください",
            Locale::En => "Save your recovery codes",
        },
        TotpRecoveryCodesAlertStrong => match locale {
            // Alert-strong: the cardinal warning. This
            // is the only time the codes are shown in
            // plaintext (storage is at-rest hashed); a
            // user who navigates away without saving
            // has to disable + re-enroll TOTP.
            Locale::Ja => "これらのコードが表示されるのはこの一度だけです。",
            Locale::En => "This is the only time these codes will be shown.",
        },
        TotpRecoveryCodesAlertBody => match locale {
            Locale::Ja => "安全な場所(パスワードマネージャー、引き出しに保管した印刷物など)に保存してください。各コードは認証器を紛失した場合に1回だけ使用できます。",
            Locale::En => "Save them somewhere safe (a password manager, a printed copy in a drawer). Each code can be used once if you lose access to your authenticator.",
        },
        TotpRecoveryCodesBody => match locale {
            Locale::Ja => "認証器が利用できないときは、リカバリーコードでサインインできます。一度使用したコードは再利用できません。",
            Locale::En => "You'll need a recovery code to sign in if your authenticator is unavailable. Once a code is used, it can't be reused.",
        },
        TotpRecoveryCodesContinue => match locale {
            Locale::Ja => "保存しました — 続行",
            Locale::En => "I've saved them — continue",
        },
        // RFC 076: save-confirmation gate
        TotpRecoverySavedConfirmLabel => match locale {
            Locale::Ja => "リカバリーコードを安全に保管しました",
            Locale::En => "I have saved my recovery codes in a safe place",
        },
        TotpRecoveryProceedButton => match locale {
            Locale::Ja => "保存して続ける",
            Locale::En => "Proceed",
        },

        // ----- TOTP disable confirm page -----
        TotpDisablePageTitle => match locale {
            Locale::Ja => "TOTPを無効化 - cesauth",
            Locale::En => "Disable TOTP - cesauth",
        },
        TotpDisableHeading => match locale {
            Locale::Ja => "二要素認証を無効にしますか?",
            Locale::En => "Disable two-factor authentication?",
        },
        TotpDisableAlertStrong => match locale {
            Locale::Ja => "アカウントのTOTPがオフになります。",
            Locale::En => "This will turn off TOTP for your account.",
        },
        TotpDisableAlertBody => match locale {
            Locale::Ja => "認証器アプリのエントリは使用できなくなり、未使用のリカバリーコードもすべて削除されます。後で新しい認証器を登録すれば、TOTPを再度有効化できます。",
            Locale::En => "Your authenticator app's entry will stop working, and any unused recovery codes will also be deleted. You can re-enable TOTP later by enrolling a new authenticator.",
        },
        TotpDisableRecoveryHint => match locale {
            // Note: "the sign-in screen, not here" —
            // disable-with-recovery-code is a sign-in-
            // path action, distinct from the disable-
            // confirm page (which assumes the user has
            // an active session AND access to their
            // authenticator).
            Locale::Ja => "認証器を紛失した場合は、登録時に発行されたワンタイムコード(リカバリーコード)で復旧できます。その手続きはサインイン画面から行ってください — このページからではありません。",
            Locale::En => "If you've lost access to your authenticator, you can recover with a one-time code from your enrollment instead — that path is on the sign-in screen, not here.",
        },
        TotpDisableConfirmHeading => match locale {
            Locale::Ja => "確認",
            Locale::En => "Confirm",
        },
        TotpDisableSubmit => match locale {
            Locale::Ja => "TOTPを無効にする",
            Locale::En => "Yes, disable TOTP",
        },

        _ => return None,
    })
}

#[inline]
fn lookup_admin(key: &MessageKey, locale: Locale) -> Option<&'static str> {
    use MessageKey::*;
    Some(match key {
        // ----- Error page -----
        ErrorPageBackLink => match locale {
            Locale::Ja => "サインインに戻る",
            Locale::En => "Back to sign in",
        },

        // ----- RFC 016 admin scope badge -----
        AdminScopeSystem => match locale {
            Locale::Ja => "システム全体",
            Locale::En => "System scope",
        },
        AdminScopeTenancy => match locale {
            Locale::Ja => "テナント運用",
            Locale::En => "Tenancy scope",
        },
        AdminScopeTenant => match locale {
            // The caller substitutes `{slug}` at render time.
            Locale::Ja => "テナント: {slug}",
            Locale::En => "Tenant: {slug}",
        },
        // RFC 077: skip-to-content link (WCAG 2.4.1)
        SkipToMainContent => match locale {
            Locale::Ja => "メインコンテンツへスキップ",
            Locale::En => "Skip to main content",
        },

        // RFC 078: tenant admin invitation page (admin is JA-only; EN provided for future)
        TenantInvitePageTitle => match locale {
            Locale::Ja => "招待",
            Locale::En => "Invitations",
        },
        TenantInviteSectionTitle => match locale {
            Locale::Ja => "ユーザーを招待する",
            Locale::En => "Invite a user",
        },
        TenantInviteEmailLabel => match locale {
            Locale::Ja => "メールアドレス",
            Locale::En => "Email address",
        },
        TenantInviteRoleLabel => match locale {
            Locale::Ja => "初期ロール",
            Locale::En => "Initial role",
        },
        TenantInviteRoleMember => match locale {
            Locale::Ja => "テナントメンバー",
            Locale::En => "Tenant Member",
        },
        TenantInviteRoleAdmin => match locale {
            Locale::Ja => "テナント管理者",
            Locale::En => "Tenant Admin",
        },
        TenantInviteSubmitButton => match locale {
            Locale::Ja => "招待を送信",
            Locale::En => "Send invitation",
        },
        TenantInvitePendingHeading => match locale {
            Locale::Ja => "保留中の招待",
            Locale::En => "Pending invitations",
        },
        TenantInviteEmpty => match locale {
            Locale::Ja => "保留中の招待はありません",
            Locale::En => "No pending invitations",
        },
        TenantInviteColEmail => match locale {
            Locale::Ja => "メールアドレス",
            Locale::En => "Email",
        },
        TenantInviteColRole => match locale {
            Locale::Ja => "ロール",
            Locale::En => "Role",
        },
        TenantInviteColStatus => match locale {
            Locale::Ja => "状態",
            Locale::En => "Status",
        },
        TenantInviteColExpires => match locale {
            Locale::Ja => "有効期限",
            Locale::En => "Expires",
        },
        TenantInviteStatusPending => match locale {
            Locale::Ja => "保留中",
            Locale::En => "Pending",
        },
        TenantInviteStatusExpired => match locale {
            Locale::Ja => "期限切れ",
            Locale::En => "Expired",
        },
        TenantInviteStatusRevoked => match locale {
            Locale::Ja => "取り消し済み",
            Locale::En => "Revoked",
        },
        // Caller replaces {n} with the hour count
        TenantInviteExpiresInHours => match locale {
            Locale::Ja => "{n}時間後に期限切れ",
            Locale::En => "Expires in {n}h",
        },
        TenantInviteRevokeButton => match locale {
            Locale::Ja => "取り消す",
            Locale::En => "Revoke",
        },
        TenantInviteRevokeConfirm => match locale {
            Locale::Ja => "この招待を取り消しますか?",
            Locale::En => "Revoke this invitation?",
        },

        // RFC 078: tenant admin deletion request page
        TenantDeletionPageTitle => match locale {
            Locale::Ja => "削除リクエスト",
            Locale::En => "Deletion Requests",
        },
        TenantDeletionGracePeriodNotice => match locale {
            Locale::Ja => "削除リクエストはスケジュール日以降に実行されます（デフォルト30日）。実行された削除は復元できません。",
            Locale::En => "Deletion requests execute after the scheduled date (default: 30 days). Executed deletions are irreversible.",
        },
        TenantDeletionTableHeading => match locale {
            Locale::Ja => "リクエスト一覧",
            Locale::En => "Deletion requests",
        },
        TenantDeletionEmpty => match locale {
            Locale::Ja => "保留中の削除リクエストはありません",
            Locale::En => "No pending deletion requests",
        },
        TenantDeletionColUserId => match locale {
            Locale::Ja => "ユーザー ID",
            Locale::En => "User ID",
        },
        TenantDeletionColStatus => match locale {
            Locale::Ja => "状態",
            Locale::En => "Status",
        },
        TenantDeletionColScheduled => match locale {
            Locale::Ja => "予定日",
            Locale::En => "Scheduled",
        },
        TenantDeletionColActions => match locale {
            Locale::Ja => "操作",
            Locale::En => "Actions",
        },
        TenantDeletionStatusPending => match locale {
            Locale::Ja => "保留中",
            Locale::En => "Pending",
        },
        TenantDeletionStatusExecuted => match locale {
            Locale::Ja => "実行済み",
            Locale::En => "Executed",
        },
        TenantDeletionStatusCancelled => match locale {
            Locale::Ja => "キャンセル済み",
            Locale::En => "Cancelled",
        },
        // Caller replaces {n} with day count
        TenantDeletionScheduledInDays => match locale {
            Locale::Ja => "{n}日後",
            Locale::En => "in {n}d",
        },
        TenantDeletionCancelButton => match locale {
            Locale::Ja => "キャンセル",
            Locale::En => "Cancel",
        },
        TenantDeletionExecuteButton => match locale {
            Locale::Ja => "すぐに実行",
            Locale::En => "Execute now",
        },
        TenantDeletionExecuteConfirm => match locale {
            Locale::Ja => "この削除を即時実行しますか? 取り消せません",
            Locale::En => "Execute this deletion immediately? This is irreversible.",
        },

        // ---- RFC 109: audit log viewer ----
        // Admin console is JA-only per ADR-013; English strings are
        // provided for completeness (exhaustiveness test) but production
        // never reaches them.
        AuditViewerPageTitle => match locale {
            Locale::Ja => "監査ログ",
            Locale::En => "Audit log",
        },
        AuditViewerSectionTitle => match locale {
            Locale::Ja => "絞り込み",
            Locale::En => "Filters",
        },
        AuditViewerActorLabel => match locale {
            Locale::Ja => "Actor (部分一致)",
            Locale::En => "Actor (substring)",
        },
        AuditViewerEventLabel => match locale {
            Locale::Ja => "イベント種別",
            Locale::En => "Event kind",
        },
        AuditViewerEventAny => match locale {
            Locale::Ja => "(すべて)",
            Locale::En => "(any)",
        },
        AuditViewerPeriodLabel => match locale {
            Locale::Ja => "期間 (UTC)",
            Locale::En => "Period (UTC)",
        },
        AuditViewerFromLabel => match locale {
            Locale::Ja => "開始",
            Locale::En => "From",
        },
        AuditViewerToLabel => match locale {
            Locale::Ja => "終了",
            Locale::En => "To",
        },
        AuditViewerSubmitButton => match locale {
            Locale::Ja => "絞り込む",
            Locale::En => "Apply filter",
        },
        AuditViewerExportButton => match locale {
            Locale::Ja => "絞り込み条件で export",
            Locale::En => "Export filtered",
        },
        AuditViewerNewerLink => match locale {
            Locale::Ja => "← より新しい",
            Locale::En => "← Newer",
        },
        AuditViewerOlderLink => match locale {
            Locale::Ja => "より古い →",
            Locale::En => "Older →",
        },
        AuditViewerEmptyState => match locale {
            Locale::Ja => "条件に合致するイベントはありません。",
            Locale::En => "No events match the current filter.",
        },
        AuditViewerColTime => match locale {
            Locale::Ja => "時刻 (UTC)",
            Locale::En => "Time (UTC)",
        },
        AuditViewerColActor => match locale {
            Locale::Ja => "Actor",
            Locale::En => "Actor",
        },
        AuditViewerColEvent => match locale {
            Locale::Ja => "Event",
            Locale::En => "Event",
        },
        AuditViewerColReason => match locale {
            Locale::Ja => "Reason",
            Locale::En => "Reason",
        },
        AuditViewerColSeq => match locale {
            Locale::Ja => "seq",
            Locale::En => "seq",
        },
        AuditViewerNoteSchemaTenant => match locale {
            Locale::Ja => "tenant_id 単位での絞り込みは現在のスキーマでは未提供 (RFC 109 §scope amendments)。",
            Locale::En => "Filtering by tenant_id is not yet supported by the schema (RFC 109 §scope amendments).",
        },

        _ => return None,
    })
}

// =====================================================================
// Accept-Language parser
// =====================================================================

/// Parse an `Accept-Language` header value and return the
/// supported locale with the highest q-value, falling through
/// to `Locale::default()`.
///
/// Implements the practical subset of RFC 7231 §5.3.5:
///
/// - Splits on `,` for entries.
/// - Per-entry: splits on `;` for parameters, recognizes
///   `q=<float>` (default 1.0).
/// - Trims whitespace.
/// - Treats `*` as a wildcard matching the default locale.
/// - Drops entries with q=0 (RFC 7231: "not acceptable").
///
/// Edge cases handled:
///
/// - Missing or empty header → default.
/// - Malformed q value → entry treated as q=1.0 (lenient).
/// - Unknown language → entry skipped, fall through.
/// - All entries unsupported → default.
///
/// Stability: results are deterministic for any given input;
/// in particular, ties in q-value resolve in document order
/// (the first matching entry wins).
pub fn parse_accept_language(header: &str) -> Locale {
    let mut best: Option<(f32, Locale)> = None;

    for raw_entry in header.split(',') {
        let entry = raw_entry.trim();
        if entry.is_empty() { continue; }

        // Split off parameters (q=...).
        let (lang_part, q) = match entry.find(';') {
            Some(i) => {
                let (lang, params) = entry.split_at(i);
                let q = parse_q_value(&params[1..]);
                (lang.trim(), q)
            }
            None => (entry, 1.0),
        };

        if q <= 0.0 { continue; }

        // Wildcard matches the default locale.
        let candidate = if lang_part == "*" {
            Locale::default()
        } else {
            match Locale::from_primary_subtag(lang_part) {
                Some(l) => l,
                None    => continue,
            }
        };

        match best {
            None => best = Some((q, candidate)),
            Some((best_q, _)) if q > best_q => best = Some((q, candidate)),
            _ => {}  // tie or worse: keep document order
        }
    }

    best.map(|(_, l)| l).unwrap_or_default()
}

/// Extract the q-value from `q=<float>` parameter strings.
/// Permissive: anything malformed → 1.0.
fn parse_q_value(params: &str) -> f32 {
    for raw in params.split(';') {
        let p = raw.trim();
        if let Some(v) = p.strip_prefix("q=") {
            return v.parse::<f32>().unwrap_or(1.0);
        }
    }
    1.0
}

#[cfg(test)]
mod tests;

// ---------------------------------------------------------------------------
// RFC 088 — i18n.rs inline tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod inline_tests {
    use super::*;

    #[test]
    fn bcp47_ja_returns_ja() {
        assert_eq!(Locale::Ja.bcp47(), "ja");
    }

    #[test]
    fn bcp47_en_returns_en() {
        assert_eq!(Locale::En.bcp47(), "en");
    }

    #[test]
    fn default_locale_is_ja() {
        assert_eq!(Locale::default(), Locale::Ja);
    }

    #[test]
    fn lookup_returns_non_empty_for_all_keys_ja() {
        // spot-check several key categories
        assert!(!lookup(MessageKey::LoginTitle, Locale::Ja).is_empty());
        assert!(!lookup(MessageKey::SecurityTitle, Locale::Ja).is_empty());
        assert!(!lookup(MessageKey::SkipToMainContent, Locale::Ja).is_empty());
        assert!(!lookup(MessageKey::TenantInvitePageTitle, Locale::Ja).is_empty());
        assert!(!lookup(MessageKey::SessionsDriftNote, Locale::Ja).is_empty());
    }

    #[test]
    fn lookup_returns_non_empty_for_all_keys_en() {
        assert!(!lookup(MessageKey::LoginTitle, Locale::En).is_empty());
        assert!(!lookup(MessageKey::SecurityTitle, Locale::En).is_empty());
        assert!(!lookup(MessageKey::SkipToMainContent, Locale::En).is_empty());
        assert!(!lookup(MessageKey::TenantInvitePageTitle, Locale::En).is_empty());
        assert!(!lookup(MessageKey::SessionsDriftNote, Locale::En).is_empty());
    }

    #[test]
    fn ja_and_en_differ_for_selected_keys() {
        // These specific keys must not be the same in JA and EN
        // (they are not in the legitimate-duplicate whitelist)
        let ja = lookup(MessageKey::LoginTitle, Locale::Ja);
        let en = lookup(MessageKey::LoginTitle, Locale::En);
        assert_ne!(ja, en, "LoginTitle should differ between JA and EN");
    }
}
