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
}

/// Resolve `(key, locale) -> &'static str`. Zero allocation.
///
/// Adding a `MessageKey` variant without translations in
/// every locale is a compile error — the inner match against
/// `Locale` is exhaustive, and the outer match against
/// `MessageKey` is exhaustive, so the compiler enforces full
/// coverage of both axes.
pub fn lookup(key: MessageKey, locale: Locale) -> &'static str {
    use MessageKey::*;
    match key {
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
    }
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
