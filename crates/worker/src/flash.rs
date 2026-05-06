//! Flash-message infrastructure (v0.31.0).
//!
//! Cookie-based one-shot notifications. A handler sets a flash via
//! [`set_on_response`], the next page render reads it via
//! [`take_from_request`], and the cookie self-expires (the take
//! emits a `Set-Cookie: __Host-cesauth_flash=; Max-Age=0` header).
//!
//! ## Threat model
//!
//! Flash content is rendered into the HTML body. If the cookie were
//! treated as opaque user-controlled text, an attacker could craft a
//! cookie that displayed arbitrary content ("Your account is
//! compromised, call 555-1234") — a social-engineering vector.
//!
//! Two defenses combined:
//!
//! 1. **HMAC signature**. Cookie value is `v1:{b64(payload)}.{b64(mac)}`
//!    where `mac = HMAC-SHA256(flash_key, payload_bytes)` and the
//!    `flash_key` is derived from `SESSION_COOKIE_KEY` (operator
//!    secret). A tampered or absent MAC fails verification → flash
//!    is dropped, no display.
//! 2. **Token table**. The signed payload contains only a *key*
//!    (e.g., `totp_disabled`), not free text. The display string is
//!    looked up from a hard-coded table in this module. Even if an
//!    attacker somehow obtained the flash key, they could only emit
//!    one of the predefined messages. Token names are a closed set
//!    (defined in [`FlashKey`]).
//!
//! ## Why a Cookie at all
//!
//! v0.31.0 release plan §3.1 P0-B evaluated alternatives:
//! - URL query string (`?flash=...`) — refresh shows it twice, URL
//!   sharing leaks the message, attacker can craft URLs.
//! - Server-side render-then-redirect — breaks POST/Redirect/GET.
//! - DO ActiveSession field — requires session, doesn't work for
//!   anonymous flows like `POST /logout`.
//!
//! A cookie is the standard answer; the security work is in the
//! signing + token-table discipline, not the storage choice.
//!
//! ## SameSite policy
//!
//! `__Host-cesauth_flash` is `SameSite=Lax`, distinct from the
//! `Strict` cookies (`__Host-cesauth-csrf`, `__Host-cesauth_totp`).
//! Rationale: flash should survive an OAuth redirect chain (e.g.,
//! `/me/security` → `/authorize` → RP → cesauth callback), and Lax
//! is the standard cookie policy that allows top-level navigations.
//! The flash never authorizes anything by itself, so allowing
//! cross-site `<a href>` traversal to carry it does not weaken any
//! security boundary.
//!
//! ## TTL
//!
//! 60 seconds. Long enough to survive a typical redirect chain
//! (sub-second) plus user delay (back-button, slow link), short
//! enough that an abandoned flash doesn't display a stale message
//! the next time the user signs in. Server-side `take` actively
//! expires the cookie, so this TTL is only the worst-case bound
//! when the user closes the tab before the destination page loads.
//!
//! ## Privacy / GDPR posture
//!
//! See `docs/src/expert/cookies.md` (added in PR-10). Per EDPB
//! Guidelines 5/2020 §3.1.1 this cookie is "strictly necessary" /
//! "user interface customization" and does not require user consent
//! before being set: it carries no identity, no tracking, no
//! cross-user correlation, and the payload space is a closed
//! dictionary.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use worker::{Env, Headers, Result};

use crate::config::load_session_cookie_key;

/// Cookie name. The `__Host-` prefix gives us Path=/; Secure; no
/// Domain attribute, all guaranteed by the user agent.
pub const COOKIE_NAME: &str = "__Host-cesauth_flash";

/// Cookie lifetime in seconds. See module doc on TTL choice.
pub const TTL_SECONDS: i64 = 60;

/// Format version prefix on the cookie value. If a future release
/// changes the encoding (e.g., switches MAC algorithm), bump this
/// and treat the old prefix as "drop cookie silently". Avoids
/// silent breakage during a rolling upgrade.
const FORMAT_PREFIX: &str = "v1:";

/// HKDF-style domain separation tag for deriving the flash MAC key
/// from `SESSION_COOKIE_KEY`. Must remain stable across releases —
/// changing it invalidates every in-flight flash cookie.
const HKDF_INFO: &[u8] = b"cesauth flash v1 hmac";

type HmacSha256 = Hmac<Sha256>;

// =====================================================================
// Public API
// =====================================================================

/// Severity / styling level for a flash message. Each maps to a
/// `.flash--*` CSS modifier and a different ARIA live politeness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlashLevel {
    /// Informational. `aria-live="polite"`, blue accent.
    Info,
    /// Successful completion. `aria-live="polite"`, green accent.
    Success,
    /// Warning, recoverable but worth user attention.
    /// `aria-live="assertive"`, amber accent.
    Warning,
    /// Error, requires user action. `aria-live="assertive"`, red.
    Danger,
}

impl FlashLevel {
    /// CSS modifier class for the `.flash` container.
    pub fn css_modifier(self) -> &'static str {
        match self {
            Self::Info    => "flash--info",
            Self::Success => "flash--success",
            Self::Warning => "flash--warning",
            Self::Danger  => "flash--danger",
        }
    }

    /// ARIA live region politeness. Warning and danger announce
    /// immediately; info and success defer until the user pauses.
    pub fn aria_live(self) -> &'static str {
        match self {
            Self::Info | Self::Success => "polite",
            Self::Warning | Self::Danger => "assertive",
        }
    }

    /// Decorative icon character. Used together with the text
    /// label so state is legible without color perception
    /// (WCAG 1.4.1 Use of Color).
    pub fn icon(self) -> &'static str {
        match self {
            Self::Info    => "\u{2139}",   // ℹ
            Self::Success => "\u{2713}",   // ✓
            Self::Warning => "\u{26A0}",   // ⚠
            Self::Danger  => "\u{26D4}",   // ⛔
        }
    }

    /// Encode for the cookie payload. Single-letter shape keeps
    /// the cookie tiny (`__Host-cesauth_flash` budget is ~256 byte).
    fn as_code(self) -> &'static str {
        match self {
            Self::Info    => "i",
            Self::Success => "s",
            Self::Warning => "w",
            Self::Danger  => "d",
        }
    }

    fn from_code(code: &str) -> Option<Self> {
        match code {
            "i" => Some(Self::Info),
            "s" => Some(Self::Success),
            "w" => Some(Self::Warning),
            "d" => Some(Self::Danger),
            _   => None,
        }
    }
}

/// The closed set of flash keys the worker can emit. Each variant
/// has a fixed display string (see [`display_text`]). A cookie
/// carrying an unknown key is silently dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlashKey {
    /// Set after `POST /me/security/totp/enroll/confirm` succeeds.
    /// Pairs with `Success`.
    TotpEnabled,
    /// Set after `POST /me/security/totp/disable` succeeds.
    /// Pairs with `Success`.
    TotpDisabled,
    /// Set after `POST /me/security/totp/recover` succeeds.
    /// Pairs with `Warning` (recovery is recoverable but the user
    /// should re-enroll an authenticator soon).
    TotpRecovered,
    /// Set after `POST /logout`. Pairs with `Info`.
    LoggedOut,
    /// **v0.35.0** — Set after `POST /me/security/sessions/:id/revoke`
    /// succeeds. Pairs with `Success`.
    SessionRevoked,
}

impl FlashKey {
    /// Storage form for the cookie payload.
    fn as_str(self) -> &'static str {
        match self {
            Self::TotpEnabled     => "totp_enabled",
            Self::TotpDisabled    => "totp_disabled",
            Self::TotpRecovered   => "totp_recovered",
            Self::LoggedOut       => "logged_out",
            Self::SessionRevoked  => "session_revoked",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "totp_enabled"     => Some(Self::TotpEnabled),
            "totp_disabled"    => Some(Self::TotpDisabled),
            "totp_recovered"   => Some(Self::TotpRecovered),
            "logged_out"       => Some(Self::LoggedOut),
            "session_revoked"  => Some(Self::SessionRevoked),
            _                  => None,
        }
    }

    /// Map this `FlashKey` to its catalog `MessageKey`.
    /// **v0.36.0** — flash text now flows through
    /// `cesauth_core::i18n::lookup`, so adding a new flash
    /// requires a matching MessageKey + translations in
    /// every supported locale.
    pub fn message_key(self) -> cesauth_core::i18n::MessageKey {
        use cesauth_core::i18n::MessageKey;
        match self {
            Self::TotpEnabled    => MessageKey::FlashTotpEnabled,
            Self::TotpDisabled   => MessageKey::FlashTotpDisabled,
            Self::TotpRecovered  => MessageKey::FlashTotpRecovered,
            Self::LoggedOut      => MessageKey::FlashLoggedOut,
            Self::SessionRevoked => MessageKey::FlashSessionRevoked,
        }
    }

    /// Human-readable text for the rendered banner in the
    /// given locale. Resolves through the
    /// `cesauth_core::i18n` catalog. Adding a new
    /// `FlashKey` variant requires a matching `MessageKey`
    /// and a translation in every locale (compile-time
    /// enforced via the catalog's match exhaustiveness).
    pub fn display_text_for(self, locale: cesauth_core::i18n::Locale) -> &'static str {
        cesauth_core::i18n::lookup(self.message_key(), locale)
    }

    /// Backward-compat shim: returns the default-locale (Ja)
    /// rendering. Existing callers that haven't been
    /// migrated to `display_text_for(locale)` continue to
    /// work; the migration can happen at each call site
    /// independently as locale negotiation is wired up.
    /// New code should call `display_text_for` directly.
    pub fn display_text(self) -> &'static str {
        self.display_text_for(cesauth_core::i18n::Locale::default())
    }
}

/// A flash that has been verified out of the cookie. The display
/// text is a `&'static str` so the rendering layer never has to
/// allocate or escape it — the value comes from a compile-time
/// constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flash {
    pub level: FlashLevel,
    pub key:   FlashKey,
}

impl Flash {
    pub fn new(level: FlashLevel, key: FlashKey) -> Self {
        Self { level, key }
    }
}

// =====================================================================
// Cookie codec (pure functions, env-free, fully testable)
// =====================================================================

/// Encode a flash into a signed cookie value. Returns the value
/// without the `Name=` prefix or attribute string — see
/// [`set_cookie_header`] for the wrapped form.
pub(crate) fn encode(flash: &Flash, mac_key: &[u8]) -> String {
    // Payload is `"<level_code>.<key>"`. Compact, fixed shape,
    // single delimiter (`.` is not in any FlashKey string).
    let payload = format!("{}.{}", flash.level.as_code(), flash.key.as_str());

    let mut mac = HmacSha256::new_from_slice(mac_key)
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(payload.as_bytes());
    let tag = mac.finalize().into_bytes();

    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());
    let tag_b64     = URL_SAFE_NO_PAD.encode(tag);
    format!("{FORMAT_PREFIX}{payload_b64}.{tag_b64}")
}

/// Decode and verify a cookie value. Returns `None` for any kind
/// of structural or cryptographic failure — there is no error
/// mode that lets the cookie display garbage. Failure modes:
///
/// - missing/wrong format prefix
/// - missing or extra `.` separator
/// - non-base64url payload or tag
/// - HMAC mismatch (constant-time)
/// - unknown level code or unknown key
pub(crate) fn decode(cookie_value: &str, mac_key: &[u8]) -> Option<Flash> {
    let rest = cookie_value.strip_prefix(FORMAT_PREFIX)?;

    // Exactly one `.` separator between payload_b64 and tag_b64.
    // Multiple `.` or zero `.` is malformed.
    let (payload_b64, tag_b64) = rest.split_once('.')?;
    if payload_b64.is_empty() || tag_b64.is_empty() {
        return None;
    }
    if tag_b64.contains('.') {
        return None;
    }

    let payload = URL_SAFE_NO_PAD.decode(payload_b64.as_bytes()).ok()?;
    let tag     = URL_SAFE_NO_PAD.decode(tag_b64.as_bytes()).ok()?;

    // Verify the MAC in constant time. The hmac crate's `verify_slice`
    // does the constant-time compare for us.
    let mut mac = HmacSha256::new_from_slice(mac_key)
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(&payload);
    mac.verify_slice(&tag).ok()?;

    // Payload is "<level_code>.<key>".
    let payload_str = std::str::from_utf8(&payload).ok()?;
    let (level_code, key_str) = payload_str.split_once('.')?;
    let level = FlashLevel::from_code(level_code)?;
    let key   = FlashKey::from_str(key_str)?;
    Some(Flash::new(level, key))
}

/// Find the value of `__Host-cesauth_flash` in a raw `Cookie:`
/// header. Returns `None` if the cookie isn't present. Does NOT
/// verify — that's [`decode`]'s job.
fn extract_cookie<'a>(cookie_header: &'a str) -> Option<&'a str> {
    for piece in cookie_header.split(';') {
        let piece = piece.trim();
        if let Some(rest) = piece.strip_prefix(COOKIE_NAME) {
            if let Some(v) = rest.strip_prefix('=') {
                return Some(v);
            }
        }
    }
    None
}

/// Build the `Set-Cookie` header value (without the `Set-Cookie:`
/// name) for a freshly-set flash.
fn set_cookie_header(value: &str) -> String {
    format!(
        "{COOKIE_NAME}={value}; Max-Age={TTL_SECONDS}; Path=/; HttpOnly; Secure; SameSite=Lax"
    )
}

/// Build the `Set-Cookie` header value that clears the flash
/// cookie. Emitted by [`take_from_request`] so a flash is
/// displayed exactly once.
pub(crate) fn clear_cookie_header() -> String {
    format!(
        "{COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax"
    )
}

// =====================================================================
// Env-aware API (used by handlers)
// =====================================================================

/// Append a `Set-Cookie` header that delivers a signed flash to
/// the next request. The handler should call this on the response
/// it returns from a redirect handler (POST/Redirect/GET).
///
/// Returns `Err` only if the operator hasn't provisioned
/// `SESSION_COOKIE_KEY` (which is a release-gate item — see
/// `docs/src/expert/security.md`). In production deployments
/// this never errors.
pub fn set_on_response(env: &Env, headers: &mut Headers, flash: Flash) -> Result<()> {
    let key = derive_mac_key(env)?;
    let value = encode(&flash, &key);
    headers.append("set-cookie", &set_cookie_header(&value)).ok();
    Ok(())
}

/// Read and consume a flash from the incoming request. Returns
/// `(Some(flash), clear_header)` when a valid signed cookie is
/// present, `(None, clear_header)` otherwise. The clear header
/// expires the cookie regardless of validity, so a malformed
/// flash is dropped on the next round trip.
///
/// The caller is responsible for appending `clear_header` to
/// their response so the cookie self-expires.
pub fn take_from_request(env: &Env, cookie_header: &str) -> (Option<Flash>, String) {
    let clear = clear_cookie_header();

    let raw = match extract_cookie(cookie_header) {
        Some(v) if !v.is_empty() => v,
        _ => return (None, clear),
    };

    let key = match derive_mac_key(env) {
        Ok(k) => k,
        Err(_) => {
            // No SESSION_COOKIE_KEY → can't verify, treat as
            // absent. Clear the cookie so the user doesn't keep
            // sending us garbage.
            return (None, clear);
        }
    };

    (decode(raw, &key), clear)
}

/// Derive the flash MAC key from `SESSION_COOKIE_KEY`. Uses a
/// minimal HKDF-style construction (`HMAC(session_key, info)`) so
/// the flash cookie's compromise can't be replayed against a
/// different cesauth subsystem. We don't pull in the `hkdf` crate
/// for this single 32-byte derivation — the inline construction
/// is the standard "expand to one block" shortcut.
fn derive_mac_key(env: &Env) -> Result<Vec<u8>> {
    let session_key = load_session_cookie_key(env)?;
    let mut prk = HmacSha256::new_from_slice(&session_key)
        .expect("HMAC-SHA256 accepts any key length");
    prk.update(HKDF_INFO);
    Ok(prk.finalize().into_bytes().to_vec())
}

/// Project a `Flash` to the rendering-layer `FlashView` in
/// the given locale. The projection is mechanical (each
/// Flash field has a 1:1 mapping to FlashView) but tedious;
/// centralizing it here saves every handler from rebuilding
/// the same four-field map.
///
/// **v0.36.0** — added a `locale` parameter so the rendered
/// `text` is locale-aware. The `render_view(flash)`
/// shorthand below preserves the default-locale behavior
/// for callers that haven't yet been migrated to negotiated
/// locales.
pub fn render_view_for(
    flash:  Flash,
    locale: cesauth_core::i18n::Locale,
) -> cesauth_ui::templates::FlashView {
    cesauth_ui::templates::FlashView {
        aria_live:    flash.level.aria_live(),
        css_modifier: flash.level.css_modifier(),
        icon:         flash.level.icon(),
        text:         flash.key.display_text_for(locale),
    }
}

/// Default-locale shorthand for `render_view_for`. Kept for
/// backward compatibility with callers that haven't been
/// migrated to negotiate locale yet. New code should call
/// `render_view_for(flash, locale)`.
pub fn render_view(flash: Flash) -> cesauth_ui::templates::FlashView {
    render_view_for(flash, cesauth_core::i18n::Locale::default())
}

#[cfg(test)]
mod tests;
