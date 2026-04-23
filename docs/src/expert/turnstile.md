# Turnstile integration

cesauth integrates Cloudflare Turnstile as a **risk-escalation**
control, not a blanket CAPTCHA. Honest users see zero challenges.

## Design

`RateLimitDecision` returned by `RateLimitStore::hit(...)` carries
two fields:

```rust
pub struct RateLimitDecision {
    pub allowed:   bool,
    pub escalate:  bool,   // ← this
    pub resets_in: i64,
}
```

`escalate=true` is set when the bucket is approaching its limit —
the signal that cesauth should make the *next* request by this
client cheaper to verify. The handler's response is:

1. Set a short-lived KV flag `turnstile:required:<bucket>` with TTL
   matching the rate-limit window.
2. While the flag is set, endpoints on that bucket read the
   `cf-turnstile-response` form field, call the siteverify endpoint
   via `HttpTurnstileVerifier`, and reject tokenless or failing
   requests.
3. After the window expires, the flag falls out and challenges
   stop.

## Why flag-based, not always-on

A Turnstile widget on every form hit is:

- **Accessibility-hostile.** Screen readers and slower connections
  suffer for a rare attack surface.
- **UX-hostile.** Users trained on "click this checkbox for no
  reason" stop reading warnings.
- **Not much more secure** for well-behaved traffic. The rate limit
  is already the first line of defense.

Gating on `escalate` means the challenge only appears during actual
probing. A legitimate user who triggers the escalation once sees
the challenge the *next* time, solves it, and the flag expires
normally.

## Secrets

| Secret               | Role                                              |
|----------------------|---------------------------------------------------|
| `TURNSTILE_SECRET`   | Server-side secret for the siteverify call        |
| `TURNSTILE_SITEKEY`  | Public key embedded in the login page's Turnstile widget |

`TURNSTILE_SITEKEY` is a non-secret `[vars]` entry in
`wrangler.toml`; `TURNSTILE_SECRET` is a `wrangler secret put`.

`load_turnstile_secret` returns `Option<String>` — missing secret
disables Turnstile entirely. This is intentional: you can run
cesauth without Turnstile for local dev or a very small deployment
by simply not setting the secret.

## Siteverify

```rust
let req = SiteverifyRequest {
    secret:   turnstile_secret,
    response: form_field_token,
    remoteip: client_ip,      // cf-connecting-ip header
    idempotency_key: Some(handle),   // optional, for retries
};
let resp = HttpTurnstileVerifier.verify(&req).await?;
if !resp.success { return Response::error("challenge failed", 403); }
```

`SiteverifyResponse::success` is the only bit that matters for the
control flow. The returned `error-codes` array is logged but not
surfaced to the user — the error body is deliberately terse to
avoid telling an attacker whether the failure was "bad token",
"expired token", or "duplicate token".

## Buckets

The bucket name in `turnstile:required:<bucket>` matches the
rate-limit bucket. Current buckets:

| Bucket                   | Protects                                    |
|--------------------------|---------------------------------------------|
| `magic_link_request`     | `POST /magic-link/request`                  |
| `magic_link_verify`      | `POST /magic-link/verify`                   |
| `webauthn_authn_start`   | `POST /webauthn/authenticate/start`         |
| `admin_user_create`      | `POST /admin/users`                         |

New endpoints should choose a bucket name that narrowly identifies
the thing being abused (not "global"), so escalation on one flow
does not impose Turnstile on unrelated flows.

## Status of the wiring

The `escalate` signal is **produced** by `RateLimitStore::hit`. The
Turnstile enforcement around form routes is **implemented** in
`crates/worker/src/routes/magic_link.rs` and the login page
template, and gated by the flag-setting logic.

What is still manual: tuning the `window_secs` / `threshold` per
bucket for the production workload. See the rate-limit section of
`wrangler.toml` for the current defaults.
