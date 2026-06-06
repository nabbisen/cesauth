//! `GET /admin/console/operations` — cron pass status (RFC 081).

use worker::{Request, Response, RouteContext};

use cesauth_core::admin::types::AdminAction;
use cesauth_ui::admin::operations::{operations_page, CronPassDisplay};

use crate::require_system_admin;

pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> worker::Result<Response> {
    require_system_admin!(req, ctx, principal, AdminAction::ViewConsole);

    // Load cron pass records from KV (best-effort — None if KV unavailable).
    let kv = ctx.env.kv("CESAUTH_KV").ok();

    let mut passes = vec![
        CronPassDisplay::placeholder("sweep",                "Sweep",                "Apply"),
        CronPassDisplay::placeholder("audit_chain",          "Audit chain verify",   "Apply"),
        CronPassDisplay::placeholder("session_index_audit",  "Session index audit",  "Apply"),
        CronPassDisplay::placeholder("audit_retention",      "Audit retention prune","Dry-run"),
        CronPassDisplay::placeholder("session_index_repair", "Session index repair", "Dry-run"),
    ];

    if let Some(kv) = &kv {
        for pass in &mut passes {
            let key = format!("cron:last-run:{}", pass.name);
            if let Ok(Some(text)) = kv.get(&key).text().await {
                if let Ok(rec) = serde_json::from_str::<CronRecord>(&text) {
                    pass.last_run  = Some(rec.finished_at);
                    pass.success   = Some(rec.success);
                    pass.processed = Some(rec.processed_count);
                    if !rec.success {
                        pass.error = rec.error_message;
                    }
                    // Dry-run detection
                    if rec.mode.as_deref() == Some("dryrun") {
                        pass.mode = "Dry-run";
                    } else if rec.mode.as_deref() == Some("apply") {
                        pass.mode = "Apply";
                    }
                }
            }
        }
    }

    let html = operations_page(&principal, &passes);
    Response::from_html(html)
}

/// Shape of the JSON stored in KV by each cron pass (RFC 081).
#[derive(serde::Deserialize)]
struct CronRecord {
    finished_at:     String,
    success:         bool,
    processed_count: u64,
    mode:            Option<String>,
    error_message:   Option<String>,
}
