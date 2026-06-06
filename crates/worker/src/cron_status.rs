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
            started_at:      fmt_unix(started_unix),
            finished_at:     fmt_unix(finished_unix),
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

fn fmt_unix(unix: i64) -> String {
    // Minimal ISO-8601 UTC (no external dep) — same logic as admin/service.rs
    let secs = unix.max(0) as u64;
    let (h, m, s) = {
        let t = secs % 86400;
        (t / 3600, (t % 3600) / 60, t % 60)
    };
    let days = secs / 86400;
    let (y, mo, d) = days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let y400 = days / 146097; days %= 146097;
    let y100 = (days / 36524).min(3); days -= y100 * 36524;
    let y4   = days / 1461;           days %= 1461;
    let y1   = (days / 365).min(3);   days -= y1 * 365;
    let year = y400 * 400 + y100 * 100 + y4 * 4 + y1 + 1970;
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let md: [u64; 12] = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut mo = 0u64;
    for &m in &md { if days < m { break; } days -= m; mo += 1; }
    (year, mo + 1, days + 1)
}
