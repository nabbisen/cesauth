//! Dev-only routes.
//!
//! These handlers exist **only** to make the local-development
//! tutorial in `docs/local-development.md` runnable from `curl`
//! without first building a full session-cookie flow.  Every handler
//! here is guarded by the `WRANGLER_LOCAL` var (see `wrangler.toml`
//! dev config): if that var is not set to `"1"`, the handler returns
//! 404 as if it didn't exist.
//!
//! Production deploys MUST NOT set `WRANGLER_LOCAL`.  The guard is
//! redundant with *not* wiring these routes into the main router, but
//! redundancy is cheap here and the cost of an accidental surface
//! enables bypassing the entire authentication ceremony.

use cesauth_cf::ports::store::CloudflareAuthChallengeStore;
use cesauth_core::ports::audit::AuditEventRepository;
use cesauth_core::ports::store::{AuthChallengeStore, Challenge};
use worker::{Request, Response, Result, RouteContext};

/// Returns `Ok(())` iff the request is in the dev surface.  The
/// handlers below short-circuit with 404 otherwise - the same as any
/// other unknown path.
fn dev_mode_enabled<D>(ctx: &RouteContext<D>) -> bool {
    ctx.env
        .var("WRANGLER_LOCAL")
        .map(|v| v.to_string() == "1")
        .unwrap_or(false)
}

/// `POST /__dev/stage-auth-code/:handle`
///
/// Body: a raw `Challenge::AuthCode` JSON blob (see
/// `cesauth_core::ports::store::Challenge`).  The handler `put`s it
/// into the `AuthChallenge` DO under the url-supplied handle, which
/// can then be redeemed at `/token` as if `/authorize` had minted it.
///
/// The body is deserialized through `core`'s tagged-enum representation
/// so a malformed challenge is rejected with the same 400 as any
/// other handler would give it.  No reshaping or validation happens
/// here on purpose - this is the "raw" entry point, used only when the
/// caller wants to bypass the interactive flow.
pub async fn stage_auth_code<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    if !dev_mode_enabled(&ctx) {
        return Response::error("not found", 404);
    }

    let Some(handle) = ctx.param("handle") else {
        return Response::error("missing handle", 400);
    };

    let challenge: Challenge = match req.json().await {
        Ok(c)  => c,
        Err(_) => return Response::error("bad challenge body", 400),
    };

    // Only AuthCode variants make sense here; the WebAuthn / MagicLink
    // variants have their own start endpoints.  Reject otherwise - the
    // dev user almost certainly mistyped the `kind` tag.
    if !matches!(challenge, Challenge::AuthCode { .. }) {
        return Response::error("challenge.kind must be 'auth_code'", 400);
    }

    let store = CloudflareAuthChallengeStore::new(&ctx.env);
    match store.put(handle, &challenge).await {
        Ok(())  => Response::ok("staged"),
        Err(cesauth_core::ports::PortError::Conflict) =>
            Response::error("handle already in use", 409),
        Err(_)  => Response::error("storage error", 500),
    }
}

/// `GET /__dev/audit`
///
/// Lists audit-log objects in the `AUDIT` R2 bucket. Exists because
/// `wrangler r2 object list` does not exist as of wrangler v3/v4 -
/// the only `wrangler r2 object` subcommands are `get`, `put`, and
/// `delete`. Writing a manual `find` inside the miniflare state
/// directory works but depends on miniflare's on-disk format, which
/// is not a documented API contract.
///
/// This handler reads from the v0.32.0 `audit_events` D1 table. It
/// is still guarded by `WRANGLER_LOCAL=1` because shipping an
/// un-authenticated audit reader to production would be a
/// data-exfiltration gift.
///
/// Query parameters (all optional):
/// - `kind`    - exact match on the event `kind` column.
/// - `subject` - exact match on the event `subject` column.
/// - `since`   - lower bound on `ts` (Unix seconds, inclusive).
/// - `until`   - upper bound on `ts` (Unix seconds, inclusive).
/// - `limit`   - max results, clamped to 100. Default 20.
/// - `body`    - if `1`, includes each row's full payload + chain
///               metadata. Default: indexed-fields-only summary.
///
/// Response: JSON object `{ "rows": [...], "count": N }`.
pub async fn list_audit<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    if !dev_mode_enabled(&ctx) {
        return Response::error("not found", 404);
    }

    let url = req.url()?;
    let mut kind:    Option<String> = None;
    let mut subject: Option<String> = None;
    let mut since:   Option<i64> = None;
    let mut until:   Option<i64> = None;
    let mut limit: u32 = 20;
    let mut include_body: bool = false;
    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "kind"    => kind    = Some(v.into_owned()),
            "subject" => subject = Some(v.into_owned()),
            "since"   => since   = v.parse::<i64>().ok(),
            "until"   => until   = v.parse::<i64>().ok(),
            "limit"   => limit   = v.parse::<u32>().unwrap_or(20).min(100),
            "body"    => include_body = v == "1",
            _ => {}
        }
    }

    let repo = cesauth_cf::ports::audit::CloudflareAuditEventRepository::new(&ctx.env);
    let search = cesauth_core::ports::audit::AuditSearch {
        kind, subject, since, until,
        limit: Some(limit),
    };
    let rows = match repo.search(&search).await {
        Ok(r)  => r,
        Err(e) => return Response::error(format!("audit_events search failed: {e:?}"), 500),
    };

    let json_rows: Vec<serde_json::Value> = rows.iter().map(|r| {
        if include_body {
            serde_json::json!({
                "seq":           r.seq,
                "id":            r.id,
                "ts":            r.ts,
                "kind":          r.kind,
                "subject":       r.subject,
                "client_id":     r.client_id,
                "ip":            r.ip,
                "user_agent":    r.user_agent,
                "reason":        r.reason,
                "payload":       serde_json::from_str::<serde_json::Value>(&r.payload)
                                   .unwrap_or_else(|_| serde_json::Value::String(r.payload.clone())),
                "payload_hash":  r.payload_hash,
                "previous_hash": r.previous_hash,
                "chain_hash":    r.chain_hash,
                "created_at":    r.created_at,
            })
        } else {
            serde_json::json!({
                "seq":     r.seq,
                "id":      r.id,
                "ts":      r.ts,
                "kind":    r.kind,
                "subject": r.subject,
            })
        }
    }).collect();

    let body = serde_json::json!({
        "rows":  json_rows,
        "count": rows.len(),
    });
    let mut resp = Response::from_json(&body)?;
    let _ = resp.headers_mut().set("cache-control", "no-store");
    Ok(resp)
}
