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
            pending_authorize_ttl_secs: var_parsed_default("PENDING_AUTHORIZE_TTL_SECS", 10 * 60)?,
            auth_code_ttl_secs:         var_parsed_default("AUTH_CODE_TTL_SECS",         60)?,
            rp_id:                  var("WEBAUTHN_RP_ID")?,
            rp_name:                var("WEBAUTHN_RP_NAME")?,
            rp_origin:              var("WEBAUTHN_RP_ORIGIN")?,
            turnstile_sitekey:      var("TURNSTILE_SITEKEY").unwrap_or_default(),
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
