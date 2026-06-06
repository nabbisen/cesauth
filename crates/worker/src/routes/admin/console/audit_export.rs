//! `POST /admin/console/audit/export` — export filtered audit rows (RFC 080).

use worker::{Request, Response, RouteContext};

use cesauth_core::admin::{
    service::{export_audit, ExportFormat},
    types::{AdminAction, AuditQuery},
};

use crate::{audit as waudit, audit::EventKind, require_system_admin};

pub async fn export<D>(mut req: Request, ctx: RouteContext<D>) -> worker::Result<Response> {
    require_system_admin!(req, ctx, principal, AdminAction::ViewConsole);

    let form = req.form_data().await?;
    let get  = |key: &str| -> Option<String> {
        form.get(key).and_then(|e| {
            if let worker::FormEntry::Field(v) = e { Some(v) } else { None }
        })
    };

    let format = match get("format").as_deref() {
        Some("jsonl") => ExportFormat::Jsonl,
        _             => ExportFormat::Csv,
    };

    let query = AuditQuery {
        kind_contains:    get("kind").filter(|s| !s.is_empty()),
        subject_contains: get("subject").filter(|s| !s.is_empty()),
        limit: get("limit")
            .and_then(|s| s.parse::<u32>().ok())
            .map(|n| n.min(10_000)),
        ..Default::default()
    };

    let max_rows: usize = ctx.env
        .var("AUDIT_EXPORT_MAX_ROWS")
        .ok()
        .and_then(|v| v.to_string().parse().ok())
        .unwrap_or(10_000);

    let audit_repo = crate::adapter_cf::audit_repo(&ctx.env)?;
    let result = export_audit(&audit_repo, &query, format, max_rows).await
        .map_err(|e| worker::Error::RustError(format!("audit export failed: {e:?}")))?;

    // Emit audit event for the export operation itself
    let filter_desc = query.kind_contains.as_deref().unwrap_or("*");
    waudit::write_owned(
        &ctx.env,
        EventKind::AuditExported,
        Some(principal.id.clone()),
        None,
        Some(format!(
            "format={} rows={} truncated={} filter={}",
            format.extension(),
            result.row_count,
            result.truncated,
            filter_desc,
        )),
    ).await.ok(); // best-effort — don't fail the export if audit write fails

    let disp = format!(r#"attachment; filename="{}""#, result.filename);
    let mut resp = Response::ok(result.body)?;
    let h = resp.headers_mut();
    h.set("content-type", result.content_type)?;
    h.set("content-disposition", &disp)?;
    h.set("cache-control", "no-store")?;
    if result.truncated {
        h.set("x-cesauth-export-truncated", "true")?;
    }
    Ok(resp)
}
