//! Operational logging.
//!
//! Purpose: system monitoring. This is NOT a replacement for `audit` -
//! audit events are append-only security artifacts persisted to R2;
//! logs are short-lived structured diagnostics streamed to Cloudflare's
//! logging surface (`wrangler tail`, the Logs tab). They answer very
//! different questions:
//!
//! - **Audit:** "Was this refresh token revoked?", "Who authenticated
//!   at 14:03 UTC last Tuesday?" Must survive indefinitely and must
//!   never be lossy.
//! - **Logs:** "What is the p95 latency of `/token` today?", "Is the
//!   rate limiter escalating unusually often?" Short-lived, lossy-OK,
//!   usually read live via `wrangler tail`.
//!
//! ## Levels
//!
//! `Trace < Debug < Info < Warn < Error`. The server runs at `Info` by
//! default. Set `LOG_LEVEL` in `wrangler.toml` `[vars]` to override.
//!
//! ## Categories and sensitivity
//!
//! Every log line carries a `Category`. Categories flagged
//! `is_sensitive()` are **dropped** unless `LOG_EMIT_SENSITIVE=1` is
//! set. Sensitive categories are those that may carry user identifiers,
//! credential identifiers, or other fields that -- while not secret --
//! would be inappropriate to route to a general ops dashboard. The
//! default posture is "safe": operators who need the detail must opt in
//! explicitly, ideally only in a pre-production environment.
//!
//! Concrete categorization (see `Category::is_sensitive`):
//! - `Http`, `RateLimit`, `Storage`, `Config`, `Dev` -- safe.
//! - `Auth`, `Session`, `Crypto` -- sensitive.
//!
//! ## Output shape
//!
//! One JSON object per line via `worker::console_{log,warn,error}!`.
//! Fields: `ts` (Unix seconds), `level`, `category`, `msg`, optional
//! `subject`. Cloudflare's log viewer picks up these fields as columns.

use serde::Serialize;
use time::OffsetDateTime;
use worker::{Env, console_error, console_log, console_warn};

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl Level {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "trace" => Some(Self::Trace),
            "debug" => Some(Self::Debug),
            "info"  => Some(Self::Info),
            "warn" | "warning" => Some(Self::Warn),
            "error" | "err" => Some(Self::Error),
            _ => None,
        }
    }
}

/// Log categories. Dropping a whole category is the single largest
/// knob we expose; anything with finer granularity than "category of
/// call site" belongs in the message body.
#[derive(Copy, Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Request lifecycle: method, path, status, duration. Safe.
    Http,
    /// Authentication flows (magic link, passkey). May carry user_id
    /// or credential_id. **Sensitive.**
    Auth,
    /// Session cookie issue / verify / revoke. May carry user_id
    /// or session_id. **Sensitive.**
    Session,
    /// Rate-limit decisions and escalation signals. Keyed by bucket;
    /// the bucket includes an email hash or handle, which is not
    /// directly identifying in logs. Safe.
    RateLimit,
    /// Durable Object / D1 / KV / R2 unexpected failures. Safe -
    /// storage keys should never embed secrets.
    Storage,
    /// JWT signing and WebAuthn crypto paths. May carry key ids.
    /// **Sensitive.**
    Crypto,
    /// Config loading and secret resolution. We log variable names,
    /// never values. Safe.
    Config,
    /// Dev-only (`WRANGLER_LOCAL`) routes. Safe; guarded off in prod.
    Dev,
}

impl Category {
    /// Whether records in this category are dropped by default.
    pub fn is_sensitive(self) -> bool {
        matches!(self, Category::Auth | Category::Session | Category::Crypto)
    }

    fn as_str(self) -> &'static str {
        match self {
            Category::Http      => "http",
            Category::Auth      => "auth",
            Category::Session   => "session",
            Category::RateLimit => "rate_limit",
            Category::Storage   => "storage",
            Category::Crypto    => "crypto",
            Category::Config    => "config",
            Category::Dev       => "dev",
        }
    }
}

/// Per-request logger configuration. Cheap to construct.
#[derive(Debug, Clone)]
pub struct LogConfig {
    /// Records below this level are dropped.
    pub min_level:      Level,
    /// If false (default), records in sensitive categories are dropped.
    pub emit_sensitive: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            min_level:      Level::Info,
            emit_sensitive: false,
        }
    }
}

impl LogConfig {
    /// Read from the Workers env. Vars:
    ///
    /// - `LOG_LEVEL` = `trace|debug|info|warn|error`. Default: `info`.
    /// - `LOG_EMIT_SENSITIVE` = `0|1`. Default: `0`.
    ///
    /// Unknown or missing values fall back to defaults rather than
    /// error; a misconfigured logger should not break the worker.
    pub fn from_env(env: &Env) -> Self {
        let min_level = env.var("LOG_LEVEL").ok()
            .and_then(|v| Level::parse(&v.to_string()))
            .unwrap_or(Level::Info);
        let emit_sensitive = env.var("LOG_EMIT_SENSITIVE").ok()
            .map(|v| v.to_string() == "1")
            .unwrap_or(false);
        Self { min_level, emit_sensitive }
    }
}

/// The wire shape. Kept tiny because every field is paid for on every
/// log line. Add fields here only after confirming Cloudflare's log
/// pipeline will surface them usefully.
#[derive(Serialize)]
struct Record<'a> {
    ts:       i64,
    level:    Level,
    category: &'static str,
    msg:      &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject:  Option<&'a str>,
}

/// Emit a log record. No-op when level or sensitivity gates would
/// drop it. On serialization failure the record is dropped silently
/// (we cannot afford to log-that-the-log-failed -- that leads to a
/// loop or an observability gap and ops alerts pick up the missing
/// stream anyway).
pub fn emit(
    cfg:      &LogConfig,
    level:    Level,
    category: Category,
    msg:      &str,
    subject:  Option<&str>,
) {
    if level < cfg.min_level {
        return;
    }
    if category.is_sensitive() && !cfg.emit_sensitive {
        return;
    }

    let rec = Record {
        ts:       OffsetDateTime::now_utc().unix_timestamp(),
        level,
        category: category.as_str(),
        msg,
        subject,
    };

    let line = match serde_json::to_string(&rec) {
        Ok(s)  => s,
        Err(_) => return,
    };

    match level {
        Level::Error => console_error!("{}", line),
        Level::Warn  => console_warn!("{}", line),
        // console_log is used for trace/debug/info. The runtime does
        // not distinguish among these at the transport level; the
        // `level` field in the JSON is how consumers filter.
        _ => console_log!("{}", line),
    }
}

#[cfg(test)]
mod tests;
