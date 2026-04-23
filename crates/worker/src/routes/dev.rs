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
/// This handler uses the R2 binding itself, so it works identically
/// against local miniflare and a remote bucket. It is still guarded
/// by `WRANGLER_LOCAL=1` because shipping an un-authenticated audit
/// reader to production would be a data-exfiltration gift.
///
/// Query parameters (all optional):
/// - `prefix` - narrows to keys with the given prefix. Defaults to
///              today's date folder `audit/YYYY/MM/DD/`.
/// - `limit`  - max results, clamped to 100. Default 20.
/// - `body`   - if `1`, includes each object's body (parsed as JSON)
///              in the response. Default: keys only.
///
/// Response: JSON object `{ "keys": [...], "truncated": bool, ... }`.
pub async fn list_audit<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    if !dev_mode_enabled(&ctx) {
        return Response::error("not found", 404);
    }

    let url = req.url()?;
    let mut prefix: Option<String> = None;
    let mut limit: u32 = 20;
    let mut include_body: bool = false;
    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "prefix" => prefix = Some(v.into_owned()),
            "limit"  => limit = v.parse::<u32>().unwrap_or(20).min(100),
            "body"   => include_body = v == "1",
            _ => {}
        }
    }

    // Default prefix: today's UTC day. Matches the key layout in
    // `audit::write` -> `audit/YYYY/MM/DD/<uuid>.ndjson`.
    let prefix = prefix.unwrap_or_else(|| {
        let now = time::OffsetDateTime::now_utc();
        format!(
            "audit/{:04}/{:02}/{:02}/",
            now.year(),
            u8::from(now.month()),
            now.day(),
        )
    });

    let bucket = match ctx.env.bucket("AUDIT") {
        Ok(b)  => b,
        Err(_) => return Response::error("AUDIT bucket unavailable", 500),
    };

    let listing = match bucket.list().prefix(prefix.clone()).limit(limit).execute().await {
        Ok(l)  => l,
        Err(e) => return Response::error(format!("list failed: {e}"), 500),
    };

    let mut keys: Vec<serde_json::Value> = Vec::new();
    for obj in listing.objects() {
        let key = obj.key();
        if !include_body {
            keys.push(serde_json::json!({
                "key":      key,
                "size":     obj.size(),
                "uploaded": obj.uploaded().as_millis(),
            }));
            continue;
        }
        // Fetch the body for each key. At `limit <= 100` this is
        // bounded work, but N network hops for N audit records -
        // only do this when `body=1` is explicitly asked for.
        let body = match bucket.get(&key).execute().await {
            Ok(Some(o)) => match o.body() {
                Some(b)  => b.text().await.ok(),
                None     => None,
            },
            _ => None,
        };
        let parsed = body.as_deref().and_then(|s| {
            // ndjson: single-object files. Try to parse; if it looks
            // like multi-line, fall back to the raw string.
            serde_json::from_str::<serde_json::Value>(s.trim()).ok()
        });
        keys.push(serde_json::json!({
            "key":      key,
            "size":     obj.size(),
            "uploaded": obj.uploaded().as_millis(),
            "body":     parsed.or(body.map(serde_json::Value::String)),
        }));
    }

    let body = serde_json::json!({
        "prefix":    prefix,
        "truncated": listing.truncated(),
        "cursor":    listing.cursor(),
        "keys":      keys,
    });
    let mut resp = Response::from_json(&body)?;
    let _ = resp.headers_mut().set("cache-control", "no-store");
    Ok(resp)
}
