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
//! the catalog here lets `cesauth-frontend` templates and worker
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
//!    `cesauth_backend::i18n` for the resolver.
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

/// CLDR cardinal plural category for the currently-supported locales
/// (RFC 107, ADR-013 §Q4 closure).
///
/// cesauth ships the minimum useful subset of CLDR's plural categories.
/// Today's locales only need `One` and `Other`:
///
/// - **JA**: every count maps to `Other`. Japanese has no morphological
///   plural; CLDR calls this "no plural rule".
/// - **EN**: `n == 1` → `One`; everything else (including `0`) → `Other`.
///   This is the CLDR EN cardinal rule verbatim.
///
/// Adding a locale with richer plural categories (`Zero` / `Few` / `Many`
/// / `Two` — Slavic, Arabic, etc.) means:
///
/// 1. add the missing variant to this enum;
/// 2. extend [`plural_for`] with that locale's CLDR rule;
/// 3. extend every plural-aware catalog entry in `lookup_plural`.
///
/// All three steps surface as compile errors thanks to exhaustive
/// `match`. No runtime parsing of CLDR XML, no `icu` dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Plural {
    /// CLDR `one` — singular form. EN: `n == 1`. JA: never used.
    One,
    /// CLDR `other` — default / plural form. All locales reach this.
    Other,
}

/// Pick the CLDR plural category for an integer count.
///
/// Returns the [`Plural`] variant the catalog should look up for this
/// `(locale, n)` pair. Bridge between counts and the plural-aware
/// branch of [`lookup_plural`].
pub fn plural_for(locale: Locale, n: u64) -> Plural {
    match locale {
        // CLDR EN: one ↔ n == 1; everything else (including 0) is other.
        Locale::En => if n == 1 { Plural::One } else { Plural::Other },
        // CLDR JA: every count is "other" (Japanese is plural-invariant).
        Locale::Ja => Plural::Other,
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
    /// **RFC 185 round 1 T3.** The session card's own `aria-label`,
    /// carrying a `{sid}` placeholder the caller substitutes — was a
    /// hardcoded Japanese literal in `templates/security_center.rs`
    /// regardless of the negotiated `locale`, the one live mismatch
    /// RFC 185 §4 found on a server-rendered surface.
    SessionsCardAriaLabel,

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
    /// **RFC 185 round 1 T3.** The `<legend class="visually-hidden">`
    /// for the save-confirmation `<fieldset>` below — was a hardcoded
    /// Japanese literal in `templates/totp.rs`, excused by a comment
    /// claiming "end-user route is also fine with short literal". It
    /// is not: the route negotiates, and a screen reader on an `en`
    /// request announced this one element in Japanese regardless.
    TotpRecoverySaveGateLegend,
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
    /// **RFC 187 round 2 (T6 §3).** Renamed from `AuditViewerActorLabel`
    /// — the key name said "Actor" while decision 1 (`0.102.0`) had
    /// already repointed its *value* at "Subject", and the mismatch sat
    /// unnoticed until RFC 187 needed the freed name for the real actor
    /// filter. Value unchanged in substance here, corrected for wording
    /// in the same cut (see `AuditViewerActorLabel` below for why
    /// "exact match" replaces "substring").
    AuditViewerSubjectLabel,
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
    /// **RFC 187 round 2 (T6 §3).** Renamed from `AuditViewerColActor`,
    /// same reason as `AuditViewerSubjectLabel` above.
    AuditViewerColSubject,
    AuditViewerColEvent,
    AuditViewerColReason,
    /// **RFC 185 §5.3 screen 1, round 2 — the fourth D2 entry.** Wired
    /// into the CSR screen at review, which had previously left this
    /// column hardcoded as `"Seq"` on the theory that it names an
    /// identifier rather than a label. It is a label: the old template
    /// rendered it through this key, and the field it names is `seq`
    /// (lowercase) in the export CSV header
    /// (`crates/core/src/admin/service/audit_export.rs:95`) — the same
    /// kind of evidence as D2's other three reversions. The value
    /// itself is unchanged (`"seq"` in both locales); only the screen's
    /// own hardcoded `"Seq"` moved to it.
    AuditViewerColSeq,
    AuditViewerNoteSchemaTenant,
    AuditViewerEventAny,
    /// **RFC 185 §5.3 screen 1.** The nav link from the audit viewer to
    /// the chain-verification status screen. `Locale::En` reuses the
    /// old server template's own wording for this exact link rather
    /// than inventing new copy: `render_nav` in the 545-line
    /// `crates/frontend/src/admin/audit.rs`, **deleted in the same cut**
    /// — `git show 2ea2758:crates/frontend/src/admin/audit.rs`.
    AuditViewerChainLink,
    /// **RFC 187 round 2 (T6 §3).** The real actor filter's `<label>` —
    /// takes the name freed by `AuditViewerSubjectLabel`'s rename above.
    /// `AuditViewerColActor` is this family's new column header. "exact
    /// match" / "完全一致", not "substring" — `actor = ?N` in the
    /// adapter, the same already-exact query `AuditViewerSubjectLabel`
    /// was wrongly describing as "部分一致" before this round.
    AuditViewerActorLabel,
    AuditViewerColActor,

    // ---- RFC 188 Phase 2, T4 (G1 ruled:
    // `.git-exclude/reviewed/0.109.0-slice-b-review-and-phase2-g1-decision.md`
    // Part 2) — the divergence mark on this same screen's results
    // table. `AuditViewerDivergenceMarkLabel` is Change 2's short form
    // (three sentences rejected: a screen reader reads it per marked
    // row, and the long explanation already lives once in
    // `AuditViewerNoteFilterResidual`, read before the table).
    // `AuditViewerUnparseableMarker`'s value is Change 3's: it names the
    // artefact that failed (the payload), not the field it sits in.
    /// New last column's header, next to the existing `seq` one.
    AuditViewerColDivergence,
    /// The visible mark rendered in that column for a diverged row
    /// (`PayloadDivergence::Diverges` or `PayloadUnreadable`); empty
    /// cell for `Clean`, same convention `reason`'s `None` already uses.
    AuditViewerDivergenceMark,
    /// `title`/`aria-label` on the mark's `<span>` — Change 2: short,
    /// not an explanation. The explanation is
    /// `AuditViewerNoteFilterResidual`, read once, before the table.
    AuditViewerDivergenceMarkLabel,
    /// Rendered in place of `subject`/`actor`/`client`/`reason` for a
    /// row whose state is `PayloadDivergence::PayloadUnreadable` — never
    /// inferred from an absent field (G1 Change 1: the state is carried
    /// on the wire, not re-derived in the view).
    AuditViewerUnparseableMarker,
    /// The filter-residual sentence (D4), placed under the existing
    /// schema note — read before the results table, where an operator
    /// meets a marked row.
    AuditViewerNoteFilterResidual,
    /// **0.110.0-signals-get-readers, F-5, G1-ruled.** The export
    /// form's cap line. `{n}` substitutes the deployment's actual
    /// `export_max_rows` (served by `audit.json`, never a literal
    /// `10,000` baked into the string — 0.108.0's ruling against copy
    /// that restates a code constant).
    AuditViewerExportCapNote,

    // ---- RFC 185 §5.3 screen 2: the chain-status screen
    // (`/admin/console/audit/chain`). G1 reviewed and approved
    // (`.git-exclude/reviewed/185-slice3-screen2-g1-decision.md`); every
    // value below is exactly what that review signed off on, including
    // the one wording change it required
    // (`AuditChainStatusNoRuns`'s En). `chain_hash` and `seq` stay
    // lowercase and untranslated in both locales throughout this
    // family — identifiers from the data/API, not prose, the same
    // carve-out screen 1 made for `Export CSV`/`Export JSONL`. ----
    AuditChainPageTitle,
    AuditChainHeading,
    AuditChainNavBack,
    /// Status badge, five-arm match (`badge_html`/`render_summary`'s own
    /// five states) — "no runs yet". **En reviewed and changed from "No
    /// runs yet" to "Not yet verified"**: it renders as the value of a
    /// row whose own label already says "Status", where "No runs yet"
    /// invites "runs of what?" while the Ja (`検証未実行`) says plainly
    /// that verification has not run — the English should not need the
    /// surrounding table to disambiguate it when the Japanese doesn't.
    AuditChainStatusNoRuns,
    AuditChainStatusValid,
    /// Carries `{seq}`, substituted at the call site via
    /// `.replace("{seq}", &seq.to_string())` — `SessionsCardAriaLabel`'s
    /// own `{sid}` convention.
    AuditChainStatusTamperAtSeq,
    AuditChainStatusHistoryMismatch,
    AuditChainStatusVerificationFailed,
    AuditChainConsistencyMatch,
    /// **En says "(rewrite suspected)", not the old template's flat
    /// "(rewrite)" — reviewed and confirmed, reasoning generalised
    /// beyond this one string**: `疑い` means suspicion, and a
    /// `chain_hash` mismatch at the recorded `seq` proves the row
    /// changed, not why — corruption and a botched migration produce
    /// the identical signal. "(rewrite)" asserts a cause the check
    /// cannot establish; this reports the finding instead. On a
    /// security surface, overstating certainty is the worse error.
    AuditChainConsistencyMismatch,
    /// Genuine cold start — no checkpoint has ever existed
    /// (`checkpoint_seq.is_none()`). Split from `NotApplicable` below as
    /// the `0.97.0` bug fix this component's own module doc describes;
    /// the old template's single `None` arm conflated the two, and had
    /// only `"cold start — no cross-check"` for both, so there is no
    /// 1:1 old English to copy for either — both are translated fresh
    /// from the live Ja.
    AuditChainConsistencyColdStart,
    /// A checkpoint already exists, but the last run was a full
    /// re-walk, which always skips the cross-check — distinct from
    /// `ColdStart` above; see that variant's doc for why both are new.
    AuditChainConsistencyNotApplicable,
    AuditChainSummaryTitle,
    AuditChainColChainLength,
    /// Trailing text after `<code>{current_chain_length}</code>` —
    /// **keeps its leading space**, which is load-bearing for the
    /// rendered gap between the number and the unit; not a stray space
    /// to clean up.
    AuditChainChainLengthUnit,
    AuditChainColLastVerification,
    AuditChainColRowsWalked,
    AuditChainGrowthHint,
    /// RFC 184 §3.3 — postdates the old template entirely (it has no
    /// acknowledgement concept at all), so this and the next two keys
    /// are translated fresh from the live Ja, not copied from anywhere.
    AuditChainAckTitle,
    /// **The sentence that matters most on this screen** (reviewed): "do
    /// not erase the audit log record" is the exact misunderstanding
    /// `0.98.0` existed to prevent.
    AuditChainAckNote,
    AuditChainAckButton,
    /// **0.110.0-signals-get-readers, F-6, G1-ruled.** Rendered beside
    /// the standing alarm (the row this describes), not as a state of
    /// its own — only when `AuditChainStatus::clean_walk_refused_at`
    /// is `Some`. `{ts}` substitutes the canonical-formatted timestamp
    /// in place; must not read as "verification is broken" — a later
    /// run *did* find the chain clean, and was refused permission to
    /// clear this standing, unacknowledged alarm.
    AuditChainCleanWalkRefusedNote,
    /// Serves the section `aria-label` and the `<h2>` in **both**
    /// branches of the empty/populated checkpoint split — one key,
    /// three call sites.
    AuditChainCheckpointTitle,
    AuditChainCheckpointEmpty,
    AuditChainCheckpointNote,
    AuditChainColLastVerifiedSeq,
    AuditChainColRecordedChainHash,
    AuditChainColRecordedAt,
    AuditChainColConsistency,
    AuditChainVerifyTitle,
    /// The first four sentences are the old template's own
    /// `render_verify_form` wording, reused directly (same condition,
    /// same mechanism). **The fifth sentence has no old-template
    /// source** — RFC 184's `persist_result` refusal behaviour
    /// postdates it — and is written fresh from the live Ja's own added
    /// sentence.
    AuditChainVerifyNote,
    AuditChainVerifyButton,

    // ---- RFC 188 Phase 1 (`0.108.0`): the column cross-check section on
    // the chain-status screen. G1 reviewed and ruled
    // (`.git-exclude/reviewed/188-phase1-g1-g2-decisions.md`): all new
    // (S5's three states postdate everything on this screen), except
    // `Status` reused as the summary row's label and `AuditChainAckButton`
    // NOT reused here (see `AuditChainColumnsAckButton` below) — one
    // control clearing two different findings under one button label is
    // the F-7-at-the-UI-layer defect S3 made `class` required to avoid. ----
    AuditChainColumnsStatusNotChecked,
    AuditChainColumnsStatusClean,
    /// Carries `{n}`, substituted via `.replace("{n}", &n.to_string())` —
    /// `AuditChainStatusTamperAtSeq`'s own `{seq}` convention. An operator
    /// count in a status line, not a grammatical plural needing
    /// `lookup_plural`.
    AuditChainColumnsStatusDiverging,
    AuditChainColumnsSectionTitle,
    /// The single most important sentence in this section (G1 ruling):
    /// states plainly that this check does **not** reach the admin search
    /// or audit viewer, which still read the columns directly — Phase 2's
    /// residual, stated where an operator would otherwise assume the
    /// opposite.
    AuditChainColumnsNote,
    AuditChainColumnsColRow,
    AuditChainColumnsColColumn,
    AuditChainColumnsAckTitle,
    AuditChainColumnsAckNote,
    /// Carries `{n}`. **Does not restate S7's 50-row cap** (G1 ruling,
    /// change 2) — that number lives in `verifier.rs`'s own const, and
    /// copy that repeats a constant drifts from it silently the first
    /// time the constant moves.
    AuditChainColumnsMoreNote,
    /// **Not a reuse of `AuditChainAckButton`** (G1 ruling, change 1): the
    /// chain-class and columns-class acknowledgement forms sit on one
    /// screen and clear two independent findings (S3); two identical
    /// button labels is the same defect F-7 was, moved to the UI.
    AuditChainColumnsAckButton,

    // ---- RFC 185 §5.3 screen 3: the tenancy console
    // (`TenancyOverview`/`TenancyTenants`/`TenancyTenantDetail`,
    // `/admin/tenancy*`). G1 reviewed and ruled
    // (`.git-exclude/reviewed/185-slice3-screen3-g1-decision.md`): three
    // page-title keys double as their own `<h1>` (the `AuditViewerPageTitle`
    // precedent); the two create-tenant links collapse into one key (§4 of
    // that decision); the generic fetch-failure wording reuses `FetchFailed`
    // rather than keeping a third phrasing of one condition. ----
    TenancyOverviewPageTitle,
    TenancyTenantsPageTitle,
    TenancyTenantDetailPageTitle,
    /// Used at both `/admin/tenancy` (overview nav) and
    /// `/admin/tenancy/tenants` (tenants-list nav) — both point at
    /// `/admin/tenancy/tenants/new`, one destination, one name (G1
    /// decision §4).
    TenancyCreateTenantLink,
    TenancyOverviewTenantCountLabel,
    /// **Not `FetchFailed`** — this is an inline label beside a count,
    /// not a page-level failure state, and the G1 decision's §1 ruling
    /// gives it its own wording without `FetchFailed`'s "Please reload."
    /// instruction.
    TenancyOverviewTenantCountFetchFailed,
    TenancyTenantsBackLink,
    TenancyTenantsEmpty,
    /// **0.110.0-tenancy-console-slice-1, D5/G1.** The list's third
    /// state: the read itself failed, distinct from a legitimately
    /// empty deployment (`TenancyTenantsEmpty`). G1 ruling: two
    /// clauses, what happened and what to do — not a third clause
    /// pre-empting the "zero tenants" misreading, since the separate
    /// message already carries that distinction by existing.
    TenancyTenantsFetchFailed,
    TenancyTenantsColSlug,
    TenancyTenantsColDisplayName,
    /// **0.110.0-tenancy-console-slice-1, T4.** The list's `Created`
    /// column, dropped since the superseded template. The `Id` column
    /// reuses `ClientsColId` — the same generic concept (a row
    /// identifier column header), not a new key.
    TenancyTenantsColCreated,
    TenancyTenantsRowDetailLink,
    /// **0.110.0-tenancy-console-slice-1, D6/G1.** `TenantStatus`'s
    /// four variants, keyed so `format!("{:?}", status)` stops reaching
    /// the screen. `Suspended` reuses `StatusSuspended` (same concept
    /// as `SuspendedNotice`'s tenant-suspended fact, not a new key) —
    /// see the G1 submission for why that is a reuse and not a
    /// duplicate, unlike `TenantInviteStatusPending`/
    /// `TenantDeletionStatusPending`'s deliberate text-only overlap.
    TenantStatusPending,
    TenantStatusActive,
    TenantStatusDeleted,
    TenancyTenantDetailBackLink,
    TenancyTenantDetailStatusChangeLink,
    TenancyTenantDetailSubscriptionHistoryLink,
    TenancyTenantDetailPlanChangeLink,
    TenancyTenantDetailAddMemberLink,
    /// Composed title for `/admin/console` (`operator_json_api::shell`'s
    /// title argument, RFC 185 §5.3 screen 3 T2/T3). G1 Q2: the console's
    /// landing title moves from the one irregular shape among eleven
    /// (`cesauth コンソール`, prefix not suffix) to the same `X — cesauth`
    /// composition every other operator title uses. The page's own
    /// `<h1>` (`cesauth オペレーターコンソール`) is untouched — out of
    /// this slice's scope (§7) — so the title and the heading now
    /// disagree where they agreed by accident before; rowed for whichever
    /// cut converts `console.rs`.
    ConsoleOverviewPageTitle,
    ConsoleCostPageTitle,
    ConsoleAlertsPageTitle,
    ConsoleSafetyPageTitle,

    // ---- RFC 185 §5.3 screen 4: the operator console's seven
    // (`ConsoleOverview`/`ConsoleOperations`/`ConsoleTokens`/`ConsoleSafety`/
    // `ConsoleCost`/`ConsoleAlerts`/`ConsoleConfig`, `/admin/console/*`). G1
    // reviewed and ruled
    // (`.git-exclude/reviewed/185-slice3-screen4-g1-decision.md`): the
    // heading keys are supersets of their screen's own `*PageTitle` key
    // (R2 — a heading may be fuller than its title, and must contain the
    // title's words); the four RFC 161 placeholder sentences collapse into
    // one key (R1); the status-check failure joins the `読み込みに失敗
    // しました`/`取得に失敗しました` register rather than opening a fourth
    // verb for one condition (R-c, screen 3's own lesson applied again). ----
    /// Superset of `ConsoleOverviewPageTitle` (`コンソール`/`Console`) —
    /// must contain its words, per R2.
    ConsoleOverviewHeading,
    /// Superset of `ConsoleSafetyPageTitle` (`安全性`/`Safety`) — same
    /// rule, used both as `ConsoleOverview`'s nav link to `/admin/console/safety`
    /// and as `ConsoleSafety`'s own `<h1>`.
    ConsoleSafetyHeading,
    ConsoleStatusOk,
    ConsoleStatusCheckFailed,
    ConsoleOperationsCronNote,
    ConsoleTokensIssueLink,
    ConsoleTokensDisableNote,
    /// **Not `ActionFailed`** — G1 decision R-b: a key's name and its
    /// value say the same thing, and the Japanese says an error occurred,
    /// not that an action failed. Also the key `0.106.0`'s
    /// `pages/operator/clients.rs:126` reuses — minted once, here, before
    /// a second variant of this exact sentence exists (R3).
    GenericErrorOccurred,
    /// Shared by all four RFC 161 placeholder screens (R1) — each already
    /// names itself in its own `<h1>`, so this only has to say the status.
    ConsoleNotImplementedNote,

    // ---- RFC 185 §5.3 screen 5: the OIDC client manager
    // (`ConsoleClients`/`ClientRow`/`SecretReveal`/`CreateClientForm`,
    // `/admin/console/clients`). G1 reviewed and ruled
    // (`.git-exclude/reviewed/185-slice3-screen5-g1-decision.md`): the
    // created-at column names its unit (R1 — RFC 111's own UTC-disclosure
    // policy, applied here the same way screen 1 applied it); the two
    // secret-reveal headings name the secret in both locales, not just
    // English (R3); the delete/reissue sentences keep the client name bold
    // via `split_once("{name}")` (S1); the reissue/create headings have no
    // such split — the source `<h2>` never bolded the name (S2); each
    // three-fragment warning collapses to one key (S3). The two
    // one-time-secret warnings land exactly as proposed, word for word. ----
    ClientsManagementAriaLabel,
    ClientsDeleteConfirmAriaLabel,
    /// `{name}` substituted via `split_once` so the client name stays
    /// bold in the rendered confirm panel (S1) — see `T6` for the test
    /// asserting the placeholder appears exactly once in both locales.
    ClientsDeleteConfirmBody,
    ClientsRowRotateButton,
    ClientsRowDeleteButton,
    /// **Not `"Delete"` again** — G1 Q2: the dialog's button answers the
    /// dialog's own question rather than restating the table's label,
    /// which is what keeps the pair distinguishable once English loses
    /// Japanese's noun/verb-form distinction (`削除`/`削除する`).
    ClientsDeleteConfirmButton,
    ClientsRotateConfirmAriaLabel,
    ClientsRotateConfirmBody,
    ClientsRotateConfirmWarning,
    /// **Not `"Reissue secret"` again** — same reasoning as
    /// `ClientsDeleteConfirmButton`.
    ClientsRotateConfirmButton,
    ClientsShowCreateFormButton,
    ClientsEmptyState,
    ClientsColName,
    ClientsColType,
    ClientsColRedirectUri,
    /// **Round 2 (review).** Keyed although both locales say `ID`: a
    /// hardcoded literal cannot be translated by a locale this catalog
    /// has not met yet, and an equal value today is a translation, not a
    /// missing one. The sibling `ClientsCreateIdLabel` says `クライアント
    /// ID` because the create form has several fields to tell apart;
    /// this column sits beside Name in a table that is already the
    /// client list, so `ID` is the whole label.
    ClientsColId,
    /// **`(UTC)` is load-bearing, not decoration** — G1 R1:
    /// `format_created_at` builds the cell from
    /// `OffsetDateTime::from_unix_timestamp`, which is UTC, and keying
    /// this column without the unit would cement a header that hides it.
    /// Screen 1 reverted the identical omission (`時刻 (UTC)` → `時刻`) on
    /// RFC 111's own grounds; same policy, four screens apart.
    ClientsColCreatedAt,
    ClientsReloadButton,
    /// `{name}` via plain `.replace`, no bold-split — the source `<h2>`
    /// never wrapped the name in `<strong>` (S2), so there is no emphasis
    /// to preserve. **Names the secret in both locales** (R3): the
    /// Japanese said only "client X's reissue"; the panel is showing a
    /// secret, and the English already said so.
    ClientsSecretRevealHeadingRotate,
    ClientsSecretRevealHeadingCreate,
    ClientsSecretWarningHeading,
    /// **No leading space in the value** — R2: the separator between this
    /// and `ClientsSecretWarningHeading`'s `</strong>` is an explicit `" "`
    /// text node in the markup, not whitespace baked into the catalog
    /// value, which `no_two_keys_share_text_within_a_locale` cannot see
    /// and a translation tool trims on sight (the lesson screen 3's own
    /// `TenancyOverviewTenantCountLabel` cost a round over).
    ClientsSecretWarningBody,
    ClientsSecretFieldLabel,
    ClientsSecretDismissButton,
    ClientsCreateFormHeading,
    ClientsCreateIdLabel,
    ClientsCreateConfidentialWarning,
    ClientsCreateTokenAuthLabel,
    ClientsCreateRedirectUrisLabel,
    ClientsCreateScopesLabel,
    ClientsCreateSubmitBusy,
    ClientsCreateSubmitButton,
    /// A different condition from `FetchFailed`/`GenericErrorOccurred`/
    /// `ConsoleStatusCheckFailed` — the request succeeded and the body
    /// didn't parse — in the same `"Failed to …"` register as all three
    /// (G1 Q3).
    ClientsResponseParseFailed,

    // ---- RFC 180 (R2b): dormant CSR component chrome imported from the
    // mockup at df3d9d0 -- operator/tenant-admin shells, role-impact
    // preview, permission-denied/suspended notices, sign-in volume
    // chart. Six of the mockup's 47 keys mapped to existing variants
    // above (AuditTitle, DeletionRequestsTitle, ScopeSystem,
    // SecurityCentreTitle, SessionsTitle, TenantAdminInvitations); these
    // 41 are additive. ----
    ActionBack,
    ActionCopy,
    ActionCopied,
    ActionSignOut,
    AuditorRoleReadOnly,
    ConfigTitle,
    EnvironmentProduction,
    EnvironmentStaging,
    EnvironmentLocal,
    InvestigateTitle,
    LocaleSwitchLabel,
    OidcClientsTitle,
    OneTimeRevealNotice,
    OperationsTitle,
    OperatorDashboardTitle,
    /// **RFC 185 §5.3 screen 1.** Shared "back to console" nav link,
    /// hardcoded independently in 4 operator pages today (audit.rs is
    /// the first to use the key). `Locale::Ja` is unchanged from the
    /// screen's own current wording — reviewed and refused an
    /// expansion to match `SessionsBackLink`'s register, since
    /// `SecurityBackLink`/`ErrorPageBackLink` don't share that
    /// register either, so there is nothing consistent to conform to.
    OperatorConsoleBackLink,
    PermissionDeniedTitle,
    PermissionDeniedBody,
    PoweredBy,
    Privacy,
    Terms,
    Status,
    RoleAssignPreviewAllowed,
    RoleAssignPreviewNotAllowed,
    RoleAssignAuditNotice,
    RolesCatalogTitle,
    ScopeTenant,
    SidebarGroupMembers,
    SidebarGroupAccess,
    SidebarGroupApplications,
    SidebarGroupSettings,
    SignInVolumeLast24h,
    StatusSuspended,
    SuspendedTenantTitle,
    SuspendedTenantBody,
    TenantAdminUsers,
    TenantAdminOrganizations,
    TenantAdminGroups,
    TenantAdminSubscription,
    TenantAdminOverview,
    TenantAuditTitle,
    TokensTitle,

    // ---- RFC 185 §5.3 screen 1: a screen-neutral `Fetch*` family for a
    // CSR component's own async-fetch states. Not `Flash*` (those are
    // post-action, server-issued) and not `Action*` (those are verbs,
    // not states) -- reviewed and ruled a third family is honest rather
    // than a forced fit. Each of the three is already hardcoded
    // independently in multiple operator pages (measured at review:
    // FetchUnauthorized/FetchFailed in 3 files, FetchLoading in 5); this
    // cut wires only the audit viewer to them, the other pages keep
    // their own hardcoded copies until their own conversions. ----
    /// A fetch returned 401/403. **The Ja wording conflates "no
    /// permission" with "sign in again"**, which does not actually help
    /// a signed-in user with an insufficient role — reviewed, and kept
    /// faithful to what the Ja already says rather than fixed here
    /// (`ROADMAP.md` carries the defect as its own row).
    FetchUnauthorized,
    /// A fetch failed for any other reason (network error, non-2xx,
    /// parse failure).
    FetchFailed,
    /// A fetch is in flight.
    FetchLoading,
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
/// Dispatches to one of twelve grouped sub-functions (RFC 097, +1 for
/// RFC 185's `lookup_fetch`, +1 for `lookup_audit_chain`) to keep each
/// group ≤ 150 lines (two groups have grown past that since — `lookup_admin`
/// and `lookup_r2b` — rather than being split retroactively; a new feature
/// gets a new group, an existing one is not torn apart for this reason
/// alone). Every
/// `MessageKey` variant is covered by exactly one sub-function; the
/// compiler enforces exhaustiveness via the top-level match in the
/// `inline_tests` module.
pub fn lookup(key: MessageKey, locale: Locale) -> &'static str {
        if let Some(s) = lookup_flash(&key, locale) { return s; }
        if let Some(s) = lookup_sessions(&key, locale) { return s; }
        if let Some(s) = lookup_login(&key, locale) { return s; }
        if let Some(s) = lookup_totp_flow(&key, locale) { return s; }
        if let Some(s) = lookup_security(&key, locale) { return s; }
        if let Some(s) = lookup_sessions_bulk(&key, locale) { return s; }
        if let Some(s) = lookup_magic_link_totp_pages(&key, locale) { return s; }
        if let Some(s) = lookup_admin(&key, locale) { return s; }
        if let Some(s) = lookup_r2b(&key, locale) { return s; }
        if let Some(s) = lookup_fetch(&key, locale) { return s; }
        if let Some(s) = lookup_audit_chain(&key, locale) { return s; }
    // Fallback: panic with the key name so missing translations fail loudly
    // during development. In production this path is unreachable if the
    // exhaustive-match test in i18n/tests.rs passes.
    panic!("i18n: no translation for {key:?} in locale {locale:?}")
}

/// Resolve a plural-aware `(key, locale, n) -> &'static str`.
///
/// **RFC 107 (ADR-013 §Q4 closure).** Use this whenever a visible string
/// agrees grammatically with a count. The caller supplies the integer
/// `n`; this function picks the CLDR cardinal category via
/// [`plural_for`] and returns the catalog entry for that pair.
///
/// Plural-aware keys (today: `SecurityRecoveryRemaining`) carry distinct
/// variants for each plural category their locales need. Non-plural-aware
/// keys (the vast majority) are not registered here and would panic if
/// passed — the static helper `is_plural_aware` documents the closed set.
///
/// The catalog string returned may carry the `{n}` placeholder; the
/// caller substitutes it as usual. Decoupling plural-form selection from
/// `{n}` substitution keeps both steps narrow and testable.
pub fn lookup_plural(key: MessageKey, locale: Locale, n: u64) -> &'static str {
    use MessageKey::*;
    let category = plural_for(locale, n);
    match (key, locale, category) {
        // ── SecurityRecoveryRemaining — first plural-aware key (RFC 107) ──
        //
        // CLDR notes:
        //   - EN: `1 valid recovery code` vs `N valid recovery codes`
        //   - JA: every count uses the same form (plural-invariant)
        (SecurityRecoveryRemaining, Locale::En, Plural::One)   => "1 valid recovery code",
        (SecurityRecoveryRemaining, Locale::En, Plural::Other) => "{n} valid recovery codes",
        (SecurityRecoveryRemaining, Locale::Ja, _)             => "リカバリーコード: {n} 個有効",
        // Any other key is a programming error: this lookup is reserved
        // for keys explicitly registered as plural-aware. Mirror
        // `lookup`'s panic posture so the failure is loud during dev.
        (k, l, _) => panic!(
            "i18n::lookup_plural: key {k:?} is not plural-aware; use `lookup` \
             instead. (locale={l:?})"
        ),
    }
}

/// Whether a `MessageKey` is registered for plural-aware lookup.
///
/// Closed list maintained alongside `lookup_plural`'s match arms. Adding
/// a new plural-aware key requires updating both — the i18n test suite
/// pins this consistency.
pub const fn is_plural_aware(key: MessageKey) -> bool {
    matches!(key, MessageKey::SecurityRecoveryRemaining)
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
        SessionsCardAriaLabel => match locale {
            Locale::Ja => "セッション {sid}",
            Locale::En => "Session {sid}",
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
        // RFC 185 round 1 T3: the gate's own legend, visually-hidden.
        TotpRecoverySaveGateLegend => match locale {
            Locale::Ja => "保存確認",
            Locale::En => "Save confirmation",
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
        // RFC 185 decision 1 (`.git-exclude/reviewed/three-decisions-2026-11-12.md`):
        // "Actor" asserts agency that is false for cron-emitted
        // (AnonymousExpired) and admin-on-behalf (DeletionExecuted/
        // DeletionCancelled) event kinds, where this column holds the
        // AFFECTED user, not whoever acted. "Subject" is honest for all
        // three shapes. RFC 187 round 2 (T6 §3): the KEY itself is now
        // renamed too (decision 1's "a rename is churn with no reader"
        // held only until RFC 187 needed the freed name two cuts later —
        // a mislabelled identifier is not free, it taxes the next
        // change). The value also drops "部分一致"/"substring" for
        // "完全一致"/"exact match": the adapter has always run
        // `subject = ?N`, an exact match, not the substring the old
        // wording claimed.
        AuditViewerSubjectLabel => match locale {
            Locale::Ja => "Subject (完全一致)",
            Locale::En => "Subject (exact match)",
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
        AuditViewerColSubject => match locale {
            Locale::Ja => "Subject",
            Locale::En => "Subject",
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
        AuditViewerChainLink => match locale {
            Locale::Ja => "チェーン検証状況 →",
            Locale::En => "Chain verification status →",
        },
        // RFC 187 round 2 (T6 §3): "Actor" as the literal value in both
        // locales, on purpose — the backend's own vocabulary is "actor"
        // end to end (the D1 column, `write_owned_with_actor`), and a
        // third word (e.g. a Japanese-native 実行者) would make
        // operators learn a synonym for no reason. "完全一致"/"exact
        // match" for the same reason AuditViewerSubjectLabel's wording
        // just changed: `actor = ?N` is exact, never a substring.
        AuditViewerActorLabel => match locale {
            Locale::Ja => "Actor (完全一致)",
            Locale::En => "Actor (exact match)",
        },
        AuditViewerColActor => match locale {
            Locale::Ja => "Actor",
            Locale::En => "Actor",
        },

        // RFC 188 Phase 2, T4 — G1-ruled (Part 2 of
        // `.git-exclude/reviewed/0.109.0-slice-b-review-and-phase2-g1-decision.md`).
        AuditViewerColDivergence => match locale {
            Locale::Ja => "差異",
            Locale::En => "Divergence",
        },
        AuditViewerDivergenceMark => match locale {
            Locale::Ja => "⚠ 差異あり",
            Locale::En => "⚠ Diverges",
        },
        // Change 2: short — the explanation lives once, in
        // AuditViewerNoteFilterResidual, not per marked row.
        AuditViewerDivergenceMarkLabel => match locale {
            Locale::Ja => "差異あり（ペイロードと不一致）",
            Locale::En => "Diverges from payload",
        },
        // Change 3: names the artefact that failed (the payload), not
        // the field it's rendered in place of.
        AuditViewerUnparseableMarker => match locale {
            Locale::Ja => "（ペイロード読み取り不可）",
            Locale::En => "(payload unreadable)",
        },
        AuditViewerNoteFilterResidual => match locale {
            Locale::Ja => "表示されている値は封印された値です。絞り込みはインデックス用カラムに対して行われるため、カラムが変更された行は、検索した値では表示されないことがあります。",
            Locale::En => "The values shown here are the sealed ones. Filtering matches the indexed column, so a row whose column changed may not appear for the value you searched.",
        },
        AuditViewerExportCapNote => match locale {
            Locale::Ja => "エクスポートは最大 {n} 件までです。これを超える場合は切り捨てられます（ファイル名にその旨が記載されます）。",
            Locale::En => "Exports are capped at {n} rows; larger result sets are truncated (and the downloaded filename says so).",
        },

        _ => return None,
    })
}

/// RFC 180 (R2b): the dormant CSR component chrome imported from the
/// mockup at pin `df3d9d0` — operator/tenant-admin shell navigation,
/// role-impact preview, permission-denied/suspended notices, sign-in
/// volume chart. None of these components are wired to a route yet
/// (that is R3); the strings exist so the import can compile against
/// `cesauth_core::i18n` rather than carrying a second catalog.
fn lookup_r2b(key: &MessageKey, locale: Locale) -> Option<&'static str> {
    use MessageKey::*;
    Some(match key {
        // ----- generic actions -----
        ActionBack => match locale {
            Locale::Ja => "戻る",
            Locale::En => "Back",
        },
        ActionCopy => match locale {
            Locale::Ja => "コピー",
            Locale::En => "Copy",
        },
        ActionCopied => match locale {
            Locale::Ja => "コピーしました",
            Locale::En => "Copied",
        },
        ActionSignOut => match locale {
            Locale::Ja => "サインアウト",
            Locale::En => "Sign out",
        },

        // ----- auth shell footer (server-rendered; RFC 180 §4.3) -----
        PoweredBy => match locale {
            Locale::Ja => "Cloudflare 上でホスト",
            Locale::En => "Hosted on Cloudflare",
        },
        Privacy => match locale {
            Locale::Ja => "プライバシー",
            Locale::En => "Privacy",
        },
        Terms => match locale {
            Locale::Ja => "利用規約",
            Locale::En => "Terms",
        },
        Status => match locale {
            Locale::Ja => "ステータス",
            Locale::En => "Status",
        },

        // ----- operator shell chrome -----
        EnvironmentProduction => match locale {
            Locale::Ja => "本番",
            Locale::En => "Production",
        },
        EnvironmentStaging => match locale {
            Locale::Ja => "ステージング",
            Locale::En => "Staging",
        },
        EnvironmentLocal => match locale {
            Locale::Ja => "ローカル",
            Locale::En => "Local dev",
        },
        OperatorDashboardTitle => match locale {
            Locale::Ja => "オペレーターダッシュボード",
            Locale::En => "Operator dashboard",
        },
        OperatorConsoleBackLink => match locale {
            Locale::Ja => "← コンソール",
            Locale::En => "← Console",
        },
        InvestigateTitle => match locale {
            Locale::Ja => "調査",
            Locale::En => "Investigate",
        },
        // RFC 185 §5.3 screen 3, G1 decision §2: repointed from the
        // dormant mockup's own wording (`運用`) to the live operator
        // console's `/admin/console/operations` title/<h1> text, which
        // this key now also serves via `operator_json_api::shell`. Both
        // keys name the same screen; the live surface's wording wins.
        // The discarded mockup wording is rowed for RFC 131, which owns
        // adopting these dormant shells.
        OperationsTitle => match locale {
            Locale::Ja => "オペレーション",
            Locale::En => "Operations",
        },
        ConfigTitle => match locale {
            Locale::Ja => "設定",
            Locale::En => "Config",
        },
        // RFC 185 §5.3 screen 3, G1 decision §2: repointed from `管理者
        // トークン` to the live `/admin/console/tokens` title/<h1> text
        // (`管理トークン`) for the same reason as `OperationsTitle` above.
        TokensTitle => match locale {
            Locale::Ja => "管理トークン",
            Locale::En => "Admin tokens",
        },
        // RFC 185 §5.3 screen 3, G1 decision §2: repointed from `OIDC
        // クライアント` (no space) to the live `/admin/console/clients`
        // title/<h1> text (`OIDC クライアント`, with a space) for the
        // same reason. `OidcClientsTitle` also still names a different,
        // tenant-admin surface (`/admin/t/{slug}/oidc-clients`) — one key
        // for one concept across two surfaces, the same precedent
        // `is_legitimate_duplicate` already documents for "Active
        // sessions"; split it if a future cut needs to tell them apart.
        OidcClientsTitle => match locale {
            Locale::Ja => "OIDC クライアント",
            Locale::En => "OIDC clients",
        },

        // ----- locale toggle label. Dormant: the mockup's LocaleToggle
        // component itself is NOT imported (RFC 180 §5 bars a live
        // switcher and its reactive context); this is the string alone,
        // in case a future, non-reactive rendering wants it. -----
        LocaleSwitchLabel => match locale {
            Locale::Ja => "言語",
            Locale::En => "Language",
        },

        // ----- scope badge (the trap, RFC 180 §4.2: AdminScopeTenant
        // is parameterised with `{slug}`; this is the bare, unscoped
        // word the mockup's tenant-switcher button uses beside the
        // tenant's own display name, not a substitute for it) -----
        ScopeTenant => match locale {
            Locale::Ja => "テナント",
            Locale::En => "Tenant",
        },

        // ----- tenant-admin sidebar groups and nav items -----
        SidebarGroupMembers => match locale {
            Locale::Ja => "メンバー",
            Locale::En => "Members",
        },
        SidebarGroupAccess => match locale {
            Locale::Ja => "アクセス",
            Locale::En => "Access",
        },
        SidebarGroupApplications => match locale {
            Locale::Ja => "アプリケーション",
            Locale::En => "Applications",
        },
        SidebarGroupSettings => match locale {
            Locale::Ja => "テナント設定",
            Locale::En => "Tenant settings",
        },
        TenantAdminOverview => match locale {
            Locale::Ja => "概要",
            Locale::En => "Overview",
        },
        TenantAdminUsers => match locale {
            Locale::Ja => "ユーザー",
            Locale::En => "Users",
        },
        TenantAdminOrganizations => match locale {
            Locale::Ja => "組織",
            Locale::En => "Organizations",
        },
        TenantAdminGroups => match locale {
            Locale::Ja => "グループ",
            Locale::En => "Groups",
        },
        TenantAdminSubscription => match locale {
            Locale::Ja => "サブスクリプション",
            Locale::En => "Subscription",
        },
        RolesCatalogTitle => match locale {
            Locale::Ja => "ロール",
            Locale::En => "Roles",
        },
        // Tenant-scoped audit, distinct from AuditViewerPageTitle's
        // system-wide /admin/console/audit — a different page, not a
        // casing variant of the same one.
        TenantAuditTitle => match locale {
            Locale::Ja => "監査",
            Locale::En => "Audit",
        },

        // ----- role-assignment impact preview -----
        RoleAssignPreviewAllowed => match locale {
            Locale::Ja => "この変更後、ユーザーが行えること",
            Locale::En => "After this change, the user can",
        },
        RoleAssignPreviewNotAllowed => match locale {
            Locale::Ja => "ユーザーが行えないこと",
            Locale::En => "The user cannot",
        },
        RoleAssignAuditNotice => match locale {
            Locale::Ja => "この変更は監査ログに記録されます。",
            Locale::En => "This change will be recorded in the audit log.",
        },
        AuditorRoleReadOnly => match locale {
            Locale::Ja => "読み取り専用 — あなたのロールは監査ビューアーです。",
            Locale::En => "Read-only — your role is Audit viewer.",
        },

        // ----- permission-denied / suspended-tenant notices -----
        PermissionDeniedTitle => match locale {
            Locale::Ja => "アクセスが拒否されました",
            Locale::En => "Access denied",
        },
        PermissionDeniedBody => match locale {
            Locale::Ja => "このページを表示する権限がありません。正しいテナントにいることと、必要なロールを持っていることを確認してください。",
            Locale::En => "You do not have permission to view this page. Check that you are in the correct tenant and have the required role.",
        },
        StatusSuspended => match locale {
            Locale::Ja => "停止中",
            Locale::En => "Suspended",
        },
        SuspendedTenantTitle => match locale {
            Locale::Ja => "テナントが停止されています",
            Locale::En => "Tenant suspended",
        },
        SuspendedTenantBody => match locale {
            Locale::Ja => "このテナントは停止されています。サインインと管理操作はブロックされています。アクセスを復元するにはプラットフォームオペレーターにお問い合わせください。",
            Locale::En => "This tenant has been suspended. Sign-in and administrative actions are blocked. Contact a platform operator to restore access.",
        },

        // ----- sign-in volume sparkline -----
        SignInVolumeLast24h => match locale {
            Locale::Ja => "過去24時間",
            Locale::En => "Last 24 hours",
        },

        // ----- one-time secret reveal control -----
        OneTimeRevealNotice => match locale {
            Locale::Ja => "この値は一度しか表示されません。いまコピーして安全な場所に保管してください。",
            Locale::En => "This value is shown once. Copy it now and store it safely.",
        },

        _ => return None,
    })
}

/// RFC 185 §5.3 screen 1 — a screen-neutral `Fetch*` family for a CSR
/// component's own async-fetch states (401/403, any other failure, in
/// flight). See the `MessageKey::FetchUnauthorized` doc comment for why
/// this is a new family rather than `Flash*`/`Action*`.
#[inline]
fn lookup_fetch(key: &MessageKey, locale: Locale) -> Option<&'static str> {
    use MessageKey::*;
    Some(match key {
        FetchUnauthorized => match locale {
            Locale::Ja => "権限がありません。再度サインインしてください。",
            Locale::En => "You do not have permission. Please sign in again.",
        },
        FetchFailed => match locale {
            Locale::Ja => "読み込みに失敗しました。再読み込みしてください。",
            Locale::En => "Failed to load. Please reload.",
        },
        FetchLoading => match locale {
            Locale::Ja => "読み込み中…",
            Locale::En => "Loading…",
        },

        _ => return None,
    })
}

/// RFC 185 §5.3 screen 2 — the chain-status screen
/// (`/admin/console/audit/chain`). A dedicated function rather than
/// folding into `lookup_admin` (already well past this module's own
/// 150-line-per-group guideline) — 31 keys for one screen is exactly
/// the shape `lookup_fetch` set the precedent for: a cohesive feature
/// gets its own group. `AuditChainColStatus` does not exist here: the
/// row label reuses the screen-neutral `Status` key (`lookup_r2b`)
/// rather than duplicating it, and `error_message`'s unauthorized/
/// failed/loading states reuse `Fetch*` rather than appearing here —
/// both reuses found and verified at G1 review.
#[inline]
fn lookup_audit_chain(key: &MessageKey, locale: Locale) -> Option<&'static str> {
    use MessageKey::*;
    Some(match key {
        AuditChainPageTitle => match locale {
            Locale::Ja => "監査チェーン",
            Locale::En => "Audit chain",
        },
        AuditChainHeading => match locale {
            Locale::Ja => "監査チェーン検証",
            Locale::En => "Audit chain verification",
        },
        AuditChainNavBack => match locale {
            Locale::Ja => "← 監査ログ",
            Locale::En => "← Audit log",
        },
        AuditChainStatusNoRuns => match locale {
            Locale::Ja => "検証未実行",
            Locale::En => "Not yet verified",
        },
        AuditChainStatusValid => match locale {
            Locale::Ja => "✓ チェーン正常",
            Locale::En => "✓ Chain valid",
        },
        AuditChainStatusTamperAtSeq => match locale {
            Locale::Ja => "⛔ seq={seq} で改ざんを検出",
            Locale::En => "⛔ Tamper detected at seq={seq}",
        },
        AuditChainStatusHistoryMismatch => match locale {
            Locale::Ja => "⛔ チェーン履歴の不一致（チェックポイントが現在の先頭と一致しません）",
            Locale::En => "⛔ Chain history mismatch (checkpoint disagrees with current head)",
        },
        AuditChainStatusVerificationFailed => match locale {
            Locale::Ja => "⛔ 検証失敗",
            Locale::En => "⛔ Verification failed",
        },
        AuditChainConsistencyMatch => match locale {
            Locale::Ja => "✓ seq の現在行と一致",
            Locale::En => "✓ Matches current row at seq",
        },
        AuditChainConsistencyMismatch => match locale {
            Locale::Ja => "✗ seq の現在行と不一致（書き換えの疑い）",
            Locale::En => "✗ Does not match current row at seq (rewrite suspected)",
        },
        AuditChainConsistencyColdStart => match locale {
            Locale::Ja => "初回実行 — 照合なし",
            Locale::En => "First run — no cross-check",
        },
        AuditChainConsistencyNotApplicable => match locale {
            Locale::Ja => "対象外 — 直前の実行は全体再検証のため照合をスキップしています",
            Locale::En => "Not applicable — the last run was a full re-verify, which skips the cross-check",
        },
        AuditChainSummaryTitle => match locale {
            Locale::Ja => "検証状況",
            Locale::En => "Verification status",
        },
        AuditChainColChainLength => match locale {
            Locale::Ja => "現在のチェーン長",
            Locale::En => "Current chain length",
        },
        AuditChainChainLengthUnit => match locale {
            Locale::Ja => " 行（起点行を含む）",
            Locale::En => " rows (including the genesis row)",
        },
        AuditChainColLastVerification => match locale {
            Locale::Ja => "最終検証日時",
            Locale::En => "Last verification",
        },
        AuditChainColRowsWalked => match locale {
            Locale::Ja => "直前の検証で走査した行数",
            Locale::En => "Rows walked in last run",
        },
        AuditChainGrowthHint => match locale {
            Locale::Ja => "⏳ 前回の検証後に新しい監査イベントが追加されています。次回のcron（毎日04:00 UTC）がこれらを検証しますが、下の操作でいつでも全体を再検証できます。",
            Locale::En => "⏳ New audit events have been appended since the last verification. The next daily cron at 04:00 UTC will walk them; you can also trigger a full re-verify below.",
        },
        AuditChainAckTitle => match locale {
            Locale::Ja => "改ざん検出の確認",
            Locale::En => "Tamper detection acknowledgement",
        },
        AuditChainAckNote => match locale {
            Locale::Ja => "この検出はまだ確認されていません。確認するまで、チェックポイントは新しい先頭位置には進みません — 次回以降の検証が内部的には整合していても同じです。確認しても監査ログの記録は消えません。対応が完了してから確認してください。",
            Locale::En => "This detection has not yet been acknowledged. Until it is, the checkpoint will not advance to a new head — even if later verifications are internally consistent. Acknowledging does not erase the audit log record. Acknowledge only once you have dealt with it.",
        },
        AuditChainAckButton => match locale {
            Locale::Ja => "検出を確認済みにする",
            Locale::En => "Mark as acknowledged",
        },
        AuditChainCleanWalkRefusedNote => match locale {
            Locale::Ja => "{ts} に実行された後続の検証では、チェーンに問題はありませんでしたが、このアラームはまだ確認されていないため、解除が許可されませんでした。上記の検出結果は依然として有効です。対応が完了したら確認済みにしてください。次回の実行でチェックポイントを進められるようになります。",
            Locale::En => "A later verification run at {ts} found the chain clean and was not allowed to clear this alarm, because the alarm has not been acknowledged. The finding above still stands. Acknowledge it once you have dealt with it, and the next run will be able to advance the checkpoint again.",
        },
        AuditChainCheckpointTitle => match locale {
            Locale::Ja => "チェックポイント",
            Locale::En => "Checkpoint",
        },
        AuditChainCheckpointEmpty => match locale {
            Locale::Ja => "検証が一度も正常に完了していません。最初の日次cron実行でチェックポイントが作成されます。",
            Locale::En => "No successful verification has completed yet. The first daily cron run will produce a checkpoint.",
        },
        AuditChainCheckpointNote => match locale {
            Locale::Ja => "検証処理は、正常に完了するたびにチェーンの先頭位置を記録します。次回の実行では、記録された chain_hash を同じ seq の現在の行と照合します — 一致しない場合はチェーン全体の書き換えによる改ざんを示します。",
            Locale::En => "The verifier records the chain head after each successful run. The next run cross-checks the recorded chain_hash against the current row at the same seq — a mismatch indicates wholesale-rewrite tampering.",
        },
        AuditChainColLastVerifiedSeq => match locale {
            Locale::Ja => "最終検証済み seq",
            Locale::En => "Last verified seq",
        },
        AuditChainColRecordedChainHash => match locale {
            Locale::Ja => "記録された chain_hash",
            Locale::En => "Recorded chain_hash",
        },
        AuditChainColRecordedAt => match locale {
            Locale::Ja => "記録日時",
            Locale::En => "Recorded at",
        },
        AuditChainColConsistency => match locale {
            Locale::Ja => "整合性",
            Locale::En => "Consistency",
        },
        AuditChainVerifyTitle => match locale {
            Locale::Ja => "検証を実行",
            Locale::En => "Run verification",
        },
        AuditChainVerifyNote => match locale {
            Locale::Ja => "今すぐ全体を再検証します。既存のチェックポイントを無視して起点行からチェーン全体を走査します。成功すると、チェックポイントは新しい先頭位置に置き換わります。デプロイ後や、即時に状態を確認したいときに使用してください。未確認の改ざん検出がある間は、この操作を行ってもチェックポイントは進みません。",
            Locale::En => "Run a full re-verification right now. Walks the chain from the genesis row, ignoring the existing checkpoint. On success the checkpoint is replaced with the new head. Use after a deploy or whenever you want immediate confirmation. While there is an unacknowledged tamper detection, this action will not advance the checkpoint even so.",
        },
        AuditChainVerifyButton => match locale {
            Locale::Ja => "今すぐ検証する（全体再検証）",
            Locale::En => "Verify now (full re-walk)",
        },

        AuditChainColumnsStatusNotChecked => match locale {
            Locale::Ja => "未チェック — この実行はカラム照合に対応する前のものです",
            Locale::En => "Not yet checked — this run predates column cross-checking",
        },
        AuditChainColumnsStatusClean => match locale {
            Locale::Ja => "✓ カラムはペイロードと一致",
            Locale::En => "✓ Columns match payload",
        },
        AuditChainColumnsStatusDiverging => match locale {
            Locale::Ja => "⛔ {n} 件のカラムがペイロードと不一致",
            Locale::En => "⛔ {n} column(s) diverge from payload",
        },
        AuditChainColumnsSectionTitle => match locale {
            Locale::Ja => "カラム照合",
            Locale::En => "Column cross-check",
        },
        AuditChainColumnsNote => match locale {
            Locale::Ja => "重複している7つのカラム（subject、actor、client_id、ip、user_agent、reason、request_id）を、ペイロード内の対応するフィールドと比較します。不一致は、インデックス用カラムが直接書き換えられたことを意味します — ペイロード自体とチェーンは健全なままです。この照合は管理検索や監査ビューアには及びません。これらは今も直接カラムを読み取っているため、不一致のカラムは次のカットまでそれらの表示を誤らせる可能性があります。",
            Locale::En => "Compares the seven duplicated columns (subject, actor, client_id, ip, user_agent, reason, request_id) against the payload's own copy of each field. A divergence means an indexed column was edited directly — the payload itself, and the chain, remain intact. This does not reach the admin search or audit viewer, which still read the columns directly today; a diverged column can still mislead those views until a later cut.",
        },
        AuditChainColumnsColRow => match locale {
            Locale::Ja => "行（seq）",
            Locale::En => "Row (seq)",
        },
        AuditChainColumnsColColumn => match locale {
            Locale::Ja => "カラム",
            Locale::En => "Column",
        },
        AuditChainColumnsAckTitle => match locale {
            Locale::Ja => "カラム不一致の確認",
            Locale::En => "Column divergence acknowledgement",
        },
        AuditChainColumnsAckNote => match locale {
            Locale::Ja => "この不一致はまだ確認されていません。確認するまで、チェックポイントはその行を通過しますが、次回の実行でもこの画面に検出が残ります。確認しても監査ログの記録やカラムの値は復元されません — 確認する前に、カラムをペイロードと比較して行を直接調査してください。",
            Locale::En => "This divergence has not yet been acknowledged. Until it is, the checkpoint advances past the row, but the finding stays on this screen on the next run too. Acknowledging does not restore the column or erase the audit log record — investigate the row directly (compare the column against its payload) before acknowledging.",
        },
        AuditChainColumnsMoreNote => match locale {
            Locale::Ja => "他 {n} 件は表示していません",
            Locale::En => "+{n} more not shown",
        },
        AuditChainColumnsAckButton => match locale {
            Locale::Ja => "カラム不一致を確認済みにする",
            Locale::En => "Acknowledge column divergence",
        },

        TenancyOverviewPageTitle => match locale {
            Locale::Ja => "テナント管理",
            Locale::En => "Tenant management",
        },
        TenancyTenantsPageTitle => match locale {
            Locale::Ja => "テナント一覧",
            Locale::En => "Tenants",
        },
        TenancyTenantDetailPageTitle => match locale {
            Locale::Ja => "テナント詳細",
            Locale::En => "Tenant details",
        },
        TenancyCreateTenantLink => match locale {
            Locale::Ja => "テナント作成",
            Locale::En => "Create tenant",
        },
        // RFC 185 §5.3 screen 3 review: the literal this replaced carried a
        // TRAILING SPACE (`"登録テナント数: "`), which the conversion
        // faithfully reproduced. Whitespace inside a catalog value is
        // invisible to review, invisible to
        // `no_two_keys_share_text_within_a_locale` (which compares exact
        // strings, so `"X: "` and `"X:"` are simply different keys' text),
        // and the first thing a translation tool trims. The separator now
        // lives in the markup as its own text node
        // (`pages/operator/tenancy.rs`), where it is visible and cannot be
        // trimmed away; the value is clean. Do not reintroduce the space.
        TenancyOverviewTenantCountLabel => match locale {
            Locale::Ja => "登録テナント数:",
            Locale::En => "Registered tenants:",
        },
        TenancyOverviewTenantCountFetchFailed => match locale {
            Locale::Ja => "テナント数の読み込みに失敗しました。",
            Locale::En => "Failed to load the tenant count.",
        },
        TenancyTenantsBackLink => match locale {
            Locale::Ja => "← テナント管理",
            Locale::En => "← Tenant management",
        },
        TenancyTenantsEmpty => match locale {
            Locale::Ja => "テナントがまだ登録されていません。",
            Locale::En => "No tenants are registered yet.",
        },
        // 0.110.0-tenancy-console-slice-1, G1 ruling: two clauses, what
        // happened and what to do -- not a third clause pre-empting the
        // "zero tenants" misreading.
        TenancyTenantsFetchFailed => match locale {
            Locale::Ja => "テナント一覧を読み込めませんでした。再読み込みしてください。",
            Locale::En => "Could not load the tenant list. Please reload.",
        },
        TenancyTenantsColSlug => match locale {
            Locale::Ja => "スラッグ",
            Locale::En => "Slug",
        },
        TenancyTenantsColDisplayName => match locale {
            Locale::Ja => "表示名",
            Locale::En => "Display name",
        },
        TenancyTenantsColCreated => match locale {
            Locale::Ja => "作成日時",
            Locale::En => "Created",
        },
        TenancyTenantsRowDetailLink => match locale {
            Locale::Ja => "詳細",
            Locale::En => "Details",
        },
        TenantStatusPending => match locale {
            Locale::Ja => "保留中",
            Locale::En => "Pending",
        },
        TenantStatusActive => match locale {
            Locale::Ja => "アクティブ",
            Locale::En => "Active",
        },
        TenantStatusDeleted => match locale {
            Locale::Ja => "削除済み",
            Locale::En => "Deleted",
        },
        TenancyTenantDetailBackLink => match locale {
            Locale::Ja => "← テナント一覧",
            Locale::En => "← Tenants",
        },
        TenancyTenantDetailStatusChangeLink => match locale {
            Locale::Ja => "ステータス変更",
            Locale::En => "Change status",
        },
        TenancyTenantDetailSubscriptionHistoryLink => match locale {
            Locale::Ja => "サブスクリプション履歴",
            Locale::En => "Subscription history",
        },
        TenancyTenantDetailPlanChangeLink => match locale {
            Locale::Ja => "プラン変更",
            Locale::En => "Change plan",
        },
        TenancyTenantDetailAddMemberLink => match locale {
            Locale::Ja => "メンバー追加",
            Locale::En => "Add member",
        },
        ConsoleOverviewPageTitle => match locale {
            Locale::Ja => "コンソール",
            Locale::En => "Console",
        },
        ConsoleCostPageTitle => match locale {
            Locale::Ja => "コスト",
            Locale::En => "Cost",
        },
        ConsoleAlertsPageTitle => match locale {
            Locale::Ja => "アラート",
            Locale::En => "Alerts",
        },
        ConsoleSafetyPageTitle => match locale {
            Locale::Ja => "安全性",
            Locale::En => "Safety",
        },

        ConsoleOverviewHeading => match locale {
            Locale::Ja => "cesauth オペレーターコンソール",
            Locale::En => "cesauth operator console",
        },
        ConsoleSafetyHeading => match locale {
            Locale::Ja => "安全性チェック",
            Locale::En => "Safety check",
        },
        ConsoleStatusOk => match locale {
            Locale::Ja => "✓ システム正常",
            Locale::En => "✓ System normal",
        },
        ConsoleStatusCheckFailed => match locale {
            Locale::Ja => "⚠ 状態の確認に失敗しました",
            Locale::En => "⚠ Failed to check status",
        },
        ConsoleOperationsCronNote => match locale {
            Locale::Ja => "cronジョブの状態はKVストアに保存されています。",
            Locale::En => "Cron job status is stored in the KV store.",
        },
        ConsoleTokensIssueLink => match locale {
            Locale::Ja => "新しいトークンを発行",
            Locale::En => "Issue a new token",
        },
        ConsoleTokensDisableNote => match locale {
            Locale::Ja => "トークンの無効化はIDを指定して行います。",
            Locale::En => "Disable a token by specifying its ID.",
        },
        GenericErrorOccurred => match locale {
            Locale::Ja => "エラーが発生しました。",
            Locale::En => "An error occurred.",
        },
        ConsoleNotImplementedNote => match locale {
            Locale::Ja => "この画面はまだ実装されていません(RFC 161)。",
            Locale::En => "This screen is not yet implemented (RFC 161).",
        },

        ClientsManagementAriaLabel => match locale {
            Locale::Ja => "OIDC クライアント管理",
            Locale::En => "OIDC client management",
        },
        ClientsDeleteConfirmAriaLabel => match locale {
            Locale::Ja => "削除の確認",
            Locale::En => "Confirm delete",
        },
        ClientsDeleteConfirmBody => match locale {
            Locale::Ja => "クライアント {name} を削除します。この操作は元に戻せません。",
            Locale::En => "This deletes the client {name}. This action cannot be undone.",
        },
        ClientsRowRotateButton => match locale {
            Locale::Ja => "シークレット再発行",
            Locale::En => "Reissue secret",
        },
        ClientsRowDeleteButton => match locale {
            Locale::Ja => "削除",
            Locale::En => "Delete",
        },
        ClientsDeleteConfirmButton => match locale {
            Locale::Ja => "削除する",
            Locale::En => "Yes, delete",
        },
        ClientsRotateConfirmAriaLabel => match locale {
            Locale::Ja => "シークレット再発行の確認",
            Locale::En => "Confirm secret reissue",
        },
        ClientsRotateConfirmBody => match locale {
            Locale::Ja => "クライアント {name} のシークレットを再発行します。",
            Locale::En => "This reissues the secret for the client {name}.",
        },
        ClientsRotateConfirmWarning => match locale {
            Locale::Ja => "現在のシークレットは直ちに無効になり、このクライアントを使っているすべての連携先が認証できなくなります。新しいシークレットは次の画面で一度だけ表示されます — その場で必ずコピーしてください。後から再度表示することはできません。",
            Locale::En => "The current secret is invalidated immediately, and every integration using this client will be unable to authenticate. The new secret is shown only once, on the next screen — be sure to copy it then. It cannot be shown again afterward.",
        },
        ClientsRotateConfirmButton => match locale {
            Locale::Ja => "再発行する",
            Locale::En => "Yes, reissue",
        },
        ClientsShowCreateFormButton => match locale {
            Locale::Ja => "+ 新しいクライアントを登録",
            Locale::En => "+ Register a new client",
        },
        ClientsEmptyState => match locale {
            Locale::Ja => "登録されたクライアントはありません。",
            Locale::En => "No clients are registered.",
        },
        ClientsColName => match locale {
            Locale::Ja => "名前",
            Locale::En => "Name",
        },
        ClientsColType => match locale {
            Locale::Ja => "種別",
            Locale::En => "Type",
        },
        ClientsColRedirectUri => match locale {
            Locale::Ja => "リダイレクトURI",
            Locale::En => "Redirect URI",
        },
        ClientsColId => match locale {
            Locale::Ja => "ID",
            Locale::En => "ID",
        },
        ClientsColCreatedAt => match locale {
            Locale::Ja => "作成日時 (UTC)",
            Locale::En => "Created (UTC)",
        },
        ClientsReloadButton => match locale {
            Locale::Ja => "再読み込み",
            Locale::En => "Reload",
        },
        ClientsSecretRevealHeadingRotate => match locale {
            Locale::Ja => "クライアント「{name}」のシークレットを再発行しました",
            Locale::En => "Secret reissued for {name}",
        },
        ClientsSecretRevealHeadingCreate => match locale {
            Locale::Ja => "クライアント「{name}」のシークレットを発行しました",
            Locale::En => "New secret created for {name}",
        },
        ClientsSecretWarningHeading => match locale {
            Locale::Ja => "このシークレットは今だけ表示されます。",
            Locale::En => "This secret is shown only this once.",
        },
        ClientsSecretWarningBody => match locale {
            Locale::Ja => "このページを離れると二度と表示できません。今すぐ下の値をコピーしてください。",
            Locale::En => "Leave this page and it cannot be shown again. Copy the value below right now.",
        },
        ClientsSecretFieldLabel => match locale {
            Locale::Ja => "クライアントシークレット(クリックで選択)",
            Locale::En => "Client secret (click to select)",
        },
        ClientsSecretDismissButton => match locale {
            Locale::Ja => "コピーしました — 閉じる",
            Locale::En => "Copied — close",
        },
        ClientsCreateFormHeading => match locale {
            Locale::Ja => "新しいクライアントを登録",
            Locale::En => "Register a new client",
        },
        ClientsCreateIdLabel => match locale {
            Locale::Ja => "クライアントID",
            Locale::En => "Client ID",
        },
        ClientsCreateConfidentialWarning => match locale {
            Locale::Ja => "機密クライアント(confidential)を作成すると、シークレットが発行されます。シークレットは作成後に一度だけ表示されます — その場で必ずコピーしてください。後から再度表示することはできません(再発行は可能です)。",
            Locale::En => "Creating a confidential client issues a secret. The secret is shown only once, right after creation — be sure to copy it then. It cannot be shown again afterward (though it can be reissued).",
        },
        ClientsCreateTokenAuthLabel => match locale {
            Locale::Ja => "トークン認証方式",
            Locale::En => "Token auth method",
        },
        ClientsCreateRedirectUrisLabel => match locale {
            Locale::Ja => "リダイレクトURI(1行に1つ)",
            Locale::En => "Redirect URIs (one per line)",
        },
        ClientsCreateScopesLabel => match locale {
            Locale::Ja => "許可スコープ(空白区切り)",
            Locale::En => "Allowed scopes (space-separated)",
        },
        ClientsCreateSubmitBusy => match locale {
            Locale::Ja => "登録中…",
            Locale::En => "Registering…",
        },
        ClientsCreateSubmitButton => match locale {
            Locale::Ja => "登録する",
            Locale::En => "Register",
        },
        ClientsResponseParseFailed => match locale {
            Locale::Ja => "応答の解析に失敗しました。",
            Locale::En => "Failed to parse the response.",
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
