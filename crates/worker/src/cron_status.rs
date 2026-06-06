//! KV record writing for cron pass status (RFC 090).
//!
//! Each of the 5 daily cron passes writes a JSON record to
//! `cron:last-run:{name}` with TTL 8 days. The admin `/operations`
//! page reads these records to surface the status.

use worker::Env;

/// Write a cron pass completion record to KV.
///
/// Key: `cron:last-run:{pass_name}`
/// TTL: 8 days (691200 seconds)
///
/// Failure is best-effort — we never panic or abort the cron pass
/// because of a KV write failure.
pub async fn record_cron_pass(env: &Env, record: &CronPassRecord) -> worker::Result<()> {
    let kv   = env.kv("CESAUTH_KV")?;
    let key  = format!("cron:last-run:{}", record.pass_name);
    let body = serde_json::to_string(record)
        .map_err(|e| worker::Error::RustError(format!("cron_status serialize: {e}")))?;
    kv.put(&key, body)?
        .expiration_ttl(8 * 24 * 3600) // 8 days
        .execute()
        .await
}

/// Status record stored in KV for one cron pass run.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct CronPassRecord {
    pub pass_name:       String,
    pub started_at:      String, // ISO-8601 UTC
    pub finished_at:     String, // ISO-8601 UTC
    pub success:         bool,
    pub processed_count: u64,
    /// Mode under which the pass ran.
    /// "apply" = mutations performed; "dryrun" = no mutations.
    pub mode:            String,
    /// Truncated error message on failure (max 200 chars, no secret material).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message:   Option<String>,
}

impl CronPassRecord {
    /// Build a record from wall-clock unix timestamps.
    pub fn new(
        pass_name:       impl Into<String>,
        started_unix:    i64,
        finished_unix:   i64,
        success:         bool,
        processed_count: u64,
        mode:            impl Into<String>,
        error:           Option<String>,
    ) -> Self {
        Self {
            pass_name:       pass_name.into(),
            started_at:      cesauth_core::util::format_unix_as_iso8601(started_unix),
            finished_at:     cesauth_core::util::format_unix_as_iso8601(finished_unix),
            success,
            processed_count,
            mode:            mode.into(),
            error_message:   error.map(|e| {
                let mut s = e;
                s.truncate(200);
                s
            }),
        }
    }
}

// RFC 096: fmt_unix and days_to_ymd replaced by cesauth_core::util
