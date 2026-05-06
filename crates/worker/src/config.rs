//! Runtime configuration, read from the Workers `Env`.
//!
//! We read config once per request into a `Config` struct so handlers
//! do not keep re-fetching the same variables. Secrets (`JWT_SIGNING_KEY`,
//! `SESSION_COOKIE_KEY`, `MAGIC_LINK_MAIL_API_KEY`, `TURNSTILE_SECRET`)
//! are read lazily when a handler actually needs them, so a
//! misconfigured dev environment still lets unrelated endpoints
//! respond.

use worker::{Env, Result};

use crate::log::LogConfig;

#[derive(Debug, Clone)]
pub struct Config {
    pub issuer:                 String,
    pub jwt_kid:                String,
    pub access_token_ttl_secs:  i64,
    pub refresh_token_ttl_secs: i64,
    pub magic_link_ttl_secs:    i64,
    /// Session cookie lifetime. Separate from access/refresh TTLs -
    /// we do not want the browser to surface a login prompt every
    /// hour just because the access token expired.
    pub session_ttl_secs:       i64,
    /// **v0.35.0** — Idle timeout. If `last_seen_at` is older than
    /// `now - session_idle_timeout_secs` at touch time, the session
    /// is considered idle-expired and forcibly revoked. Distinct
    /// from `session_ttl_secs` (the absolute lifetime): a session
    /// can survive the absolute window if it's been actively used,
    /// but goes away if the user walks away. Default 30 minutes.
    /// Setting this to 0 disables idle timeout (only the absolute
    /// `session_ttl_secs` applies).
    pub session_idle_timeout_secs: i64,
    /// How long a `PendingAuthorize` challenge lives in the DO
    /// before it's garbage-collected. The user has this long to
    /// complete authentication after clicking through from
    /// `/authorize`.
    pub pending_authorize_ttl_secs: i64,
    /// Code minting TTL for `AuthCode` - the window between
    /// `/authorize -> redirect` and the client's `/token` call.
    pub auth_code_ttl_secs:     i64,
    pub rp_id:                  String,
    pub rp_name:                String,
    pub rp_origin:              String,
    pub turnstile_sitekey:      String,
    /// **v0.37.0** — Per-family rate limit on `/token` refresh
    /// (ADR-011 §Q1 resolution). Bounds rapid retry attempts
    /// against a single refresh-token family. The check is
    /// keyed on `family_id` so unrelated families don't
    /// interfere — `user_id` would have unrelated apps pinging
    /// each other; per-jti would not catch the leaked-token
    /// rapid-replay case.
    ///
    /// Threshold defaults to 5 attempts per 60-second window.
    /// Legitimate clients rotate ~once per family (the family
    /// is single-current-jti by design), with retry margin for
    /// transient failures. A real attacker rotating in tight
    /// loop hits the threshold quickly; a real user just
    /// browsing doesn't.
    ///
    /// Set `refresh_rate_limit_threshold = 0` to disable the
    /// gate (the BCP atomic-revoke-on-reuse continues to
    /// apply regardless).
    pub refresh_rate_limit_threshold:   u32,
    pub refresh_rate_limit_window_secs: i64,
    /// **v0.43.0** — Per-client introspection rate
    /// limit threshold (ADR-014 §Q2). Bucket key is
    /// `introspect:<authenticated_client_id>`; counter
    /// resets every `introspection_rate_limit_window_secs`.
    /// Default 600 (= 10/sec sustained over a 60s window).
    /// Tunes for normal resource-server-typed traffic
    /// while bounding the damage from a runaway poll
    /// loop or buggy retry logic. Operators with tighter
    /// bundle-size or upstream-LB constraints can lower
    /// this; operators whose RSes legitimately need
    /// extreme rates can raise it. Set to 0 to disable.
    pub introspection_rate_limit_threshold:   u32,
    pub introspection_rate_limit_window_secs: i64,
    /// Operational logging. See `log::LogConfig`.
    pub log:                    LogConfig,
}

impl Config {
    pub fn from_env(env: &Env) -> Result<Self> {
        let var = |k: &str| -> Result<String> {
            env.var(k).map(|v| v.to_string())
        };
        let var_parsed = |k: &str| -> Result<i64> {
            var(k)?.parse::<i64>().map_err(|_| worker::Error::RustError(
                format!("var {k} is not an integer")
            ))
        };
        // Optional integer with a default - lets us add new knobs
        // without breaking old wrangler.toml files.
        let var_parsed_default = |k: &str, default: i64| -> Result<i64> {
            match env.var(k) {
                Ok(v) => v.to_string().parse::<i64>().map_err(|_| worker::Error::RustError(
                    format!("var {k} is not an integer")
                )),
                Err(_) => Ok(default),
            }
        };

        Ok(Self {
            issuer:                 var("ISSUER")?,
            jwt_kid:                var("JWT_KID")?,
            access_token_ttl_secs:  var_parsed("ACCESS_TOKEN_TTL_SECS")?,
            refresh_token_ttl_secs: var_parsed("REFRESH_TOKEN_TTL_SECS")?,
            magic_link_ttl_secs:    var_parsed("MAGIC_LINK_TTL_SECS")?,
            // Defaults chosen for passkey-first UX: 7-day session, 10-
            // minute pending-authorize window, 1-minute AuthCode.
            session_ttl_secs:           var_parsed_default("SESSION_TTL_SECS",           7 * 24 * 60 * 60)?,
            // v0.35.0: 30-minute idle timeout default. Operators can
            // tighten (e.g., 10 min for high-security tenants) or set
            // to 0 to disable.
            session_idle_timeout_secs:  var_parsed_default("SESSION_IDLE_TIMEOUT_SECS",  30 * 60)?,
            pending_authorize_ttl_secs: var_parsed_default("PENDING_AUTHORIZE_TTL_SECS", 10 * 60)?,
            auth_code_ttl_secs:         var_parsed_default("AUTH_CODE_TTL_SECS",         60)?,
            rp_id:                  var("WEBAUTHN_RP_ID")?,
            rp_name:                var("WEBAUTHN_RP_NAME")?,
            rp_origin:              var("WEBAUTHN_RP_ORIGIN")?,
            turnstile_sitekey:      var("TURNSTILE_SITEKEY").unwrap_or_default(),
            // v0.37.0: 5 attempts per 60-sec window default
            // (ADR-011 §Q1). Operators may tighten or set
            // threshold to 0 to disable.
            refresh_rate_limit_threshold:   var_parsed_default("REFRESH_RATE_LIMIT_THRESHOLD",   5)? as u32,
            refresh_rate_limit_window_secs: var_parsed_default("REFRESH_RATE_LIMIT_WINDOW_SECS", 60)?,
            // v0.43.0: 600/min default per authenticated
            // client_id (ADR-014 §Q2). Set
            // INTROSPECTION_RATE_LIMIT_THRESHOLD=0 to
            // disable; raise for high-traffic resource
            // servers that legitimately introspect every
            // request.
            introspection_rate_limit_threshold:   var_parsed_default("INTROSPECTION_RATE_LIMIT_THRESHOLD",   600)? as u32,
            introspection_rate_limit_window_secs: var_parsed_default("INTROSPECTION_RATE_LIMIT_WINDOW_SECS", 60)?,
            log:                    LogConfig::from_env(env),
        })
    }
}

/// Load the Ed25519 signing key. Separate from `Config::from_env` so
/// endpoints that don't sign anything (discovery, static UI) can
/// start up even if the secret hasn't been provisioned yet in a dev
/// environment.
/// Load the raw bytes of the JWT signing key (PKCS#8 PEM). The caller
/// hands the result to `JwtSigner::from_pem`.
///
/// ## Defensive `\n` unescaping
///
/// The secret typically arrives via `.dev.vars` (local) or
/// `wrangler secret put` (remote). `.dev.vars` uses dotenv syntax:
/// double-quoted values are supposed to have their `\n` escapes
/// expanded into real newlines by the parser. In practice this depends
/// on which dotenv flavor is loading the file - across wrangler
/// versions, miniflare versions, and the exact write-path a user used
/// to populate the file (shell `printf`, `echo -e`, quoted heredoc,
/// etc.) we have seen all three of:
///
///   * real `\n` bytes (0x0A) - best case; parser did its job
///   * literal two-char `\n` (backslash, `n`) - no expansion happened
///   * a mix, e.g. `-----BEGIN...\nBODY\n-----END-----\n` with the
///     final newline real and the interior ones literal
///
/// `jsonwebtoken::EncodingKey::from_ed_pem` (via its PKCS8 parser)
/// requires real newlines between the `-----BEGIN`/`-----END` markers
/// and the base64 body. So before handing the bytes along, we
/// normalize: replace every literal `\n` with a real newline. If the
/// string already had real newlines they're untouched.
///
/// If you get "JwtSigner::from_pem failed" in the log after this,
/// the cause is almost certainly NOT escaping - check for a stray
/// character count mismatch (e.g., a missing `-----END PRIVATE KEY-----`
/// trailer because awk skipped the last line).
pub fn load_signing_key(env: &Env) -> Result<Vec<u8>> {
    let secret = env.secret("JWT_SIGNING_KEY")
        .map_err(|_| worker::Error::RustError("JWT_SIGNING_KEY secret is not set".into()))?;
    let raw = secret.to_string();
    let normalized = raw.replace("\\n", "\n");
    Ok(normalized.into_bytes())
}

/// Load the HMAC secret used for signing session cookies. Must be at
/// least 16 bytes (see `core::session::SessionCookie::sign`); in
/// practice we recommend 32 or 64. Generated once per deployment with
/// `openssl rand -base64 48 | wrangler secret put SESSION_COOKIE_KEY`.
pub fn load_session_cookie_key(env: &Env) -> Result<Vec<u8>> {
    let secret = env.secret("SESSION_COOKIE_KEY")
        .map_err(|_| worker::Error::RustError("SESSION_COOKIE_KEY secret is not set".into()))?;
    Ok(secret.to_string().into_bytes())
}

/// Load the Turnstile server-side secret. Returns `None` (not an
/// error) when unset so Turnstile enforcement can be disabled just by
/// not configuring it. Production deployments MUST set it.
pub fn load_turnstile_secret(env: &Env) -> Option<String> {
    env.secret("TURNSTILE_SECRET").ok().map(|s| s.to_string())
}

/// Load the TOTP secret-encryption key. 32 bytes (AES-GCM-256).
/// The wrangler secret stores the key base64-encoded; we decode here
/// before returning the raw bytes for use with `aes_gcm`.
///
/// Operators provision with:
/// ```sh
/// openssl rand -base64 32 | wrangler secret put TOTP_ENCRYPTION_KEY
/// ```
///
/// Returns `Ok(None)` (not an error) when the secret is unset, so
/// deployments that haven't enabled TOTP yet still respond on
/// non-TOTP routes. Routes that need to encrypt or decrypt TOTP
/// secrets check the `Option` and return a clear "TOTP not
/// configured" error if `None`.
///
/// See ADR-009 §Q5 for the encryption-at-rest design and key
/// rotation procedure.
pub fn load_totp_encryption_key(env: &Env) -> Result<Option<Vec<u8>>> {
    let secret = match env.secret("TOTP_ENCRYPTION_KEY") {
        Ok(s)  => s.to_string(),
        Err(_) => return Ok(None),
    };
    parse_totp_encryption_key(&secret)
        .map(Some)
        .map_err(worker::Error::RustError)
}

/// Pure helper for parsing the TOTP encryption key string. Extracted
/// from `load_totp_encryption_key` so the parsing rules (whitespace
/// stripping, base64 decoding, length validation) are unit-testable
/// without a Worker `Env`.
fn parse_totp_encryption_key(raw: &str) -> std::result::Result<Vec<u8>, String> {
    use base64::Engine;
    // Strip whitespace (operators sometimes paste with newlines)
    // before base64-decoding. `openssl rand -base64 32` emits a
    // trailing newline that `wrangler secret put` may or may not
    // strip depending on shell.
    let cleaned: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(cleaned.as_bytes())
        .map_err(|e| format!("TOTP_ENCRYPTION_KEY is not valid base64: {e}"))?;
    if bytes.len() != cesauth_core::totp::ENCRYPTION_KEY_LEN {
        return Err(format!(
            "TOTP_ENCRYPTION_KEY must decode to {} bytes (got {})",
            cesauth_core::totp::ENCRYPTION_KEY_LEN,
            bytes.len()
        ));
    }
    Ok(bytes)
}

/// Load the TOTP encryption key id — a human-readable identifier for
/// which key encrypted a row. Stored in `secret_key_id` column on
/// `totp_authenticators`. Used by the rotation procedure: when a new
/// key is provisioned, operators bump `TOTP_ENCRYPTION_KEY_ID` and
/// new rows record the new id; old rows still decrypt because
/// adapters look up the historical key by `secret_key_id`.
///
/// Returns `None` when unset (analogous to `load_totp_encryption_key`).
/// Routes that need the id pair the two reads.
pub fn load_totp_encryption_key_id(env: &Env) -> Option<String> {
    env.var("TOTP_ENCRYPTION_KEY_ID").ok().map(|v| v.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- parse_totp_encryption_key (v0.27.0) -------------------------
    //
    // Pin the parsing rules: clean whitespace, decode base64, check
    // length. Each branch's error is operator-facing so messages
    // matter — test that unhelpful messages aren't emitted.

    #[test]
    fn parse_totp_key_accepts_well_formed() {
        // 32 random bytes → standard base64 → 44 chars including
        // one trailing `=`. Build deterministically with
        // [0u8;32] for reproducibility.
        let raw = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let bytes = parse_totp_encryption_key(raw).expect("well-formed key parses");
        assert_eq!(bytes.len(), 32);
        assert!(bytes.iter().all(|b| *b == 0));
    }

    #[test]
    fn parse_totp_key_strips_whitespace() {
        // `openssl rand -base64 32` emits a trailing newline.
        // `wrangler secret put` may or may not strip it.
        let raw = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n";
        assert!(parse_totp_encryption_key(raw).is_ok(),
            "trailing newline must not break parsing");

        let with_internal_ws = "AAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAA AAA=";
        assert!(parse_totp_encryption_key(with_internal_ws).is_ok(),
            "internal whitespace stripped before decoding");
    }

    #[test]
    fn parse_totp_key_rejects_invalid_base64() {
        let bad = "this is not!!! base64 data $$$";
        let err = parse_totp_encryption_key(bad).err().unwrap();
        assert!(err.contains("base64"),
            "error message must mention base64 (operator-facing): {err}");
    }

    #[test]
    fn parse_totp_key_rejects_wrong_length() {
        // 16 zero bytes — base64-encoded — is the wrong size for
        // AES-GCM-256. The error must clearly say so.
        let raw = "AAAAAAAAAAAAAAAAAAAAAA==";
        let err = parse_totp_encryption_key(raw).err().unwrap();
        assert!(err.contains("32") && err.contains("16"),
            "length error must mention expected vs actual: {err}");
    }

    #[test]
    fn parse_totp_key_rejects_empty() {
        // Empty string decodes to 0 bytes — wrong length, clear
        // error rather than silently accepting.
        let err = parse_totp_encryption_key("").err().unwrap();
        assert!(err.contains("0"), "empty input must report 0 bytes: {err}");
    }
}
