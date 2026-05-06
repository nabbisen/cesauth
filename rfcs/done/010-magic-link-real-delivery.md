# RFC 010: Magic Link real delivery — mailer port + provider adapters

**Status**: Implemented (v0.51.0)
**ROADMAP**: External codebase review v0.50.1 — High finding (Magic Link production-incomplete)
**ADR**: This RFC produces ADR-015 alongside the implementation; the architectural decision (port shape, audit boundary, provider adapter pattern) is non-trivial enough to warrant ADR-level documentation
**Severity**: **P0 — structural fix that allows RFC 008 to stay fixed**
**Estimated scope**: Medium — new core port, three reference adapters, worker wiring, ~400 LOC + tests + new operator chapter
**Source**: External Rust+Cloudflare codebase review attached to v0.50.1 conversation, plus internal grep confirming no `MagicLinkMailer` trait exists despite developer-directive's claim of an operator-implemented mailer interface.

## Background

### What the dev directive claims

The development directive's "Authentication" section
states:

> Magic Link sends via a generic `MagicLinkMailer`
> trait that operators implement.

### What the codebase actually has

Workspace-wide grep for `MagicLinkMailer`,
`Mailer`, `EmailDeliveryProvider`, or any analogous
trait returns **zero hits**. The Magic Link issue
path writes the OTP plaintext into the audit log
(see RFC 008) with the comment:

> When production mail is wired in, this line MUST
> change to log only the handle.

The audit log IS the OTP delivery mechanism in
cesauth today. Operators are presumed to ship the
audit log to a script that parses out
`code=<OTP>` lines and SMTPs them. This is:

- A **security violation** (RFC 008): plaintext
  OTPs in audit, observable to anyone with
  audit-read.
- A **correctness gap**: there is no defined
  contract between cesauth and a real mailer. The
  dev directive's promised trait is fiction.
- A **production-readiness gap**: cesauth
  advertises Magic Link as a "fallback" auth method
  but no operator can run it without bespoke
  delivery glue.

### Why this is structurally a P0

RFC 008 removes the audit-leak. **Without a
delivery contract, operators under deadline
pressure will revert to the audit-as-delivery hack**
because that's the only delivery path that exists.
This RFC builds the trait the directive claims
exists, plus reference adapters, plus an
unconfigured-fallback for environments that
genuinely don't run Magic Link.

The dev directive's promise becomes truth.

## Requirements

1. cesauth MUST expose a `MagicLinkMailer` trait in
   `cesauth-core` with an async send method
   carrying handle, recipient, OTP plaintext,
   locale, tenant context, and reason.
2. The Magic Link issuance path MUST call the
   mailer trait, not the audit log, for delivery.
3. The audit log receives only operational
   metadata (handle, recipient ID, delivery
   outcome summary), never the plaintext (RFC 008
   invariant pin enforces this).
4. cesauth MUST ship reference adapters for at
   least: a Cloudflare service binding, an HTTPS
   provider (SendGrid/SES/Postmark/Resend
   shape), a dev-only console adapter, and an
   `UnconfiguredMailer` fallback.
5. Mailer adapter code MUST be structurally
   prevented from depending on the audit module —
   `cesauth-core` mailer port and
   `cesauth-worker::audit` are crate-disjoint.
6. Delivery failures MUST be observable via audit
   (`MagicLinkDeliveryFailed`) and operational
   logs (severity Error). The user-facing
   response on failure MUST be the same as
   success (no enumeration leak via differential
   error response).
7. The trait MUST be operator-extensible without
   forking cesauth — third-party provider adapters
   are small operator-side crates.

## Design

### `MagicLinkMailer` trait (in `cesauth-core`)

```rust
// crates/core/src/magic_link/mailer.rs

/// Port for delivering a Magic Link OTP to a user.
///
/// **Trust boundary**: the implementor receives the
/// OTP plaintext via `payload.code`. Implementors
/// MUST NOT log, audit, persist, or otherwise
/// transmit the plaintext outside the immediate
/// delivery channel (SMTP / API hand-off to the
/// mail provider).
///
/// **Audit boundary**: this trait MUST NOT depend
/// on `cesauth-worker::audit`. Audit writes happen
/// in the calling worker handler — before the
/// mailer is invoked (`MagicLinkIssued`) and after
/// the mailer returns (`MagicLinkDelivered` or
/// `MagicLinkDeliveryFailed`). The mailer itself
/// is a pure I/O sink; it cannot import the audit
/// module because `cesauth-core` doesn't depend on
/// `cesauth-worker`.
pub trait MagicLinkMailer: Send + Sync {
    /// Deliver the OTP. Returns `Ok(DeliveryReceipt)`
    /// on successful enqueue (NOT successful inbox
    /// receipt — for SMTP / API providers, the
    /// receipt is the provider's accept). Returns
    /// `Err` on delivery failure.
    async fn send(
        &self,
        payload: &MagicLinkPayload<'_>,
    ) -> Result<DeliveryReceipt, MailerError>;
}

pub struct MagicLinkPayload<'a> {
    /// Recipient. Matches `users.email` for
    /// returning users; raw input for first-time.
    pub recipient: &'a str,
    /// Cesauth's server-side handle for the
    /// challenge. NOT secret. Useful for operator
    /// audit correlation.
    pub handle: &'a str,
    /// **Secret.** OTP plaintext. Only this
    /// mailer instance sees it.
    pub code: &'a str,
    /// Locale for body rendering.
    pub locale: &'a str,
    /// Originating tenant if known. Used for
    /// per-tenant SMTP config in multi-tenant
    /// deployments.
    pub tenant_id: Option<&'a str>,
    /// Why the link was issued.
    pub reason: MagicLinkReason,
}

#[derive(Debug, Clone, Copy)]
pub enum MagicLinkReason {
    InitialAuth,
    ReturningUserAuth,
    AnonymousPromote,
}

pub struct DeliveryReceipt {
    /// Provider-side identifier (provider message
    /// id, etc.) — opaque from cesauth's view.
    pub provider_message_id: Option<String>,
    pub queued_at_unix:      i64,
}

#[derive(Debug, thiserror::Error)]
pub enum MailerError {
    #[error("mailer transient failure: {0}")]
    Transient(String),
    #[error("mailer permanent failure: {0}")]
    Permanent(String),
    #[error("mailer not configured (no env)")]
    NotConfigured,
}

impl MailerError {
    /// Snake-case category for audit payloads.
    /// Distinct values let operators alarm on
    /// permanent vs transient differently.
    pub fn audit_kind(&self) -> &'static str {
        match self {
            MailerError::Transient(_)     => "transient",
            MailerError::Permanent(_)     => "permanent",
            MailerError::NotConfigured    => "not_configured",
        }
    }
}
```

### Audit-boundary enforcement (compile-time)

`cesauth-core` does NOT depend on
`cesauth-worker::audit`. Mailer adapter crates
likewise. A mailer adapter cannot call
`audit::write_*` because the symbol isn't in
scope. Cargo's crate dependency graph enforces the
boundary structurally — no test discipline
required.

This complements RFC 008's static-grep test: RFC
008 catches accidental audit-write sites in
`cesauth-worker`; the crate boundary catches
attempts to violate from `cesauth-core` /
`cesauth-adapter-cloudflare` / mailer adapters.

### Worker handler integration

`crates/worker/src/routes/magic_link/request.rs`:

```rust
// 1. Audit the issuance — handle only, NO
//    plaintext (per RFC 008).
audit::write_owned(
    &ctx.env, EventKind::MagicLinkIssued,
    Some(body.email.clone()), None,
    Some(format!("handle={handle}")),
).await.ok();

// 2. Construct mailer adapter from env.
let mailer = adapter::mailer::from_env(&ctx.env)?;

// 3. Build payload — this is the only place
//    plaintext flows.
let payload = MagicLinkPayload {
    recipient: &body.email,
    handle:    &handle,
    code:      &issued.delivery_payload,  // ← renamed from code_plaintext per RFC 008
    locale:    request_locale.as_str(),
    tenant_id: tenant.as_deref(),
    reason:    MagicLinkReason::InitialAuth,
};

// 4. Dispatch.
match mailer.send(&payload).await {
    Ok(receipt) => {
        audit::write_owned(
            &ctx.env, EventKind::MagicLinkDelivered,
            Some(body.email.clone()), None,
            Some(format!("handle={handle} provider_msg_id={}",
                receipt.provider_message_id.as_deref().unwrap_or("-"))),
        ).await.ok();
    }
    Err(e) => {
        audit::write_owned(
            &ctx.env, EventKind::MagicLinkDeliveryFailed,
            Some(body.email.clone()), None,
            Some(format!("handle={handle} kind={}", e.audit_kind())),
        ).await.ok();
        log::emit(&cfg.log, Level::Error, Category::Magic,
            &format!("magic_link mailer failed: {e}"),
            Some(&body.email));
        // Continue to the success-shaped response.
        // **Do NOT surface failure to the user** —
        // differential responses would let an
        // attacker enumerate valid email addresses.
        // Operators detect via the audit dashboard.
    }
}

// 5. Render the same "check your inbox" response
//    regardless of delivery outcome.
```

### Reference adapter 1: Cloudflare service binding

`crates/adapter-cloudflare/src/mailer/service_binding.rs`
sends a POST through a Cloudflare service binding
to an operator-deployed mail worker. cesauth ships
the contract (JSON envelope), not the mail worker
itself.

`wrangler.toml`:

```toml
[[services]]
binding     = "MAGIC_LINK_MAILER"
service     = "operator-mail-worker"
environment = "production"
```

```rust
pub struct ServiceBindingMailer<'a> {
    env: &'a Env,
}

impl<'a> ServiceBindingMailer<'a> {
    pub fn new(env: &'a Env) -> Self { Self { env } }
}

impl MagicLinkMailer for ServiceBindingMailer<'_> {
    async fn send(&self, payload: &MagicLinkPayload<'_>)
        -> Result<DeliveryReceipt, MailerError>
    {
        let svc = self.env.service("MAGIC_LINK_MAILER")
            .map_err(|_| MailerError::NotConfigured)?;
        let body = serde_json::json!({
            "recipient": payload.recipient,
            "handle":    payload.handle,
            "code":      payload.code,
            "locale":    payload.locale,
            "tenant_id": payload.tenant_id,
            "reason":    payload.reason.as_str(),
        }).to_string();
        // ... fetch via service binding, map response ...
    }
}
```

The body shape is the cesauth ↔ mail-worker
contract. An operator-supplied mail worker receives
this envelope and chooses how to render and send.

`examples/mail-worker-service-binding/` ships a
small reference mail worker (separate Cargo, separate
`wrangler.toml`) showing the receive side. Not used
in production; illustrative only.

### Reference adapter 2: HTTPS provider

`crates/adapter-cloudflare/src/mailer/https_provider.rs`:

```
MAILER_PROVIDER_URL=https://api.sendgrid.com/v3/mail/send
MAILER_PROVIDER_AUTH_HEADER="Authorization: Bearer <key>"
MAILER_PROVIDER_FROM_ADDRESS=noreply@example.com
```

Sends a POST with the bearer auth header. Body
shape is a simple multipart envelope; per-provider
quirks (SendGrid v3 vs SES vs Postmark vs Resend
vs Mailgun) live in operator-supplied templates.
v0.50.2 ships a single hardcoded body shape (see
"Body templates" below); operator customization is
a follow-up.

### Reference adapter 3: dev-only console

`crates/adapter-cloudflare/src/mailer/dev_console.rs`:

```rust
pub struct DevConsoleMailer;

impl MagicLinkMailer for DevConsoleMailer {
    async fn send(&self, payload: &MagicLinkPayload<'_>)
        -> Result<DeliveryReceipt, MailerError>
    {
        // **Never** log code plaintext. Handle is
        // sufficient for the developer to fetch the
        // OTP from local D1 via wrangler.
        worker::console_log!(
            "magic_link dev-console: handle={} recipient={} (code in local D1)",
            payload.handle, payload.recipient,
        );
        Ok(DeliveryReceipt {
            provider_message_id: None,
            queued_at_unix: time::OffsetDateTime::now_utc().unix_timestamp(),
        })
    }
}
```

The factory rejects `DevConsoleMailer` outside of
`WRANGLER_LOCAL=1` so the dev mailer cannot
accidentally ship to production.

### Reference adapter 4: `UnconfiguredMailer`

The default fallback when no env knob is set:

```rust
pub struct UnconfiguredMailer;

impl MagicLinkMailer for UnconfiguredMailer {
    async fn send(&self, _payload: &MagicLinkPayload<'_>)
        -> Result<DeliveryReceipt, MailerError>
    {
        Err(MailerError::NotConfigured)
    }
}
```

The handler audits this as
`MagicLinkDeliveryFailed { kind: "not_configured" }`
on every Magic Link issuance. Operator's first
real Magic Link request surfaces the misconfig
loud and clear in audit + ops logs without
crashing cesauth and without leaking that
delivery is broken to end users.

### Adapter selection

```rust
// crates/worker/src/adapter/mailer.rs
pub fn from_env(env: &Env) -> Box<dyn MagicLinkMailer> {
    if env.var("WRANGLER_LOCAL").map(|v| v.to_string()) == Ok("1".to_string()) {
        return Box::new(DevConsoleMailer);
    }
    if env.service("MAGIC_LINK_MAILER").is_ok() {
        return Box::new(ServiceBindingMailer::new(env));
    }
    if env.var("MAILER_PROVIDER_URL").is_ok() {
        if let Ok(m) = HttpsProviderMailer::from_env(env) {
            return Box::new(m);
        }
    }
    Box::new(UnconfiguredMailer)
}
```

Selection priority: dev → service binding →
HTTPS → unconfigured. Documented in the new
deployment chapter.

### New audit event kinds

```rust
EventKind::MagicLinkDelivered,
EventKind::MagicLinkDeliveryFailed,
```

Snake-case: `magic_link_delivered`,
`magic_link_delivery_failed`.

`MagicLinkIssued` (existing) is written **before**
the mailer call. The two new kinds bracket the
mailer hand-off. Together they let operators
compute issue-to-delivery success rate without
needing provider-side telemetry.

### Body templates (v0.50.2 minimum)

Single hardcoded multilingual template via
existing `MessageKey` catalog:

```
Subject: <MessageKey::MagicLinkSubject>

<MessageKey::MagicLinkBodyIntro>

  <CODE>

<MessageKey::MagicLinkBodyExpiry5min>

— cesauth
```

Operators customizing copy: out of v0.50.2 scope.
Future RFC handles per-tenant / per-locale
templates (likely KV-stored).

## Test plan

### Unit (mailer trait + adapters)

1. **`MailerError::audit_kind` returns expected snake_case** — pin.
2. **`DevConsoleMailer::send` does not log plaintext code** — pin: stdout capture in test asserts the code never appears.
3. **`ServiceBindingMailer::send` builds correct JSON envelope** — pin body shape; mock `Service` binding.
4. **`HttpsProviderMailer::send` builds correct Authorization header** — pin.
5. **`UnconfiguredMailer::send` returns NotConfigured** — trivial.
6. **`from_env` selects DevConsoleMailer when `WRANGLER_LOCAL=1`** — env-priority pin.
7. **`from_env` rejects DevConsoleMailer when `WRANGLER_LOCAL!=1`** — pin: dev mailer cannot leak into prod.
8. **`from_env` falls back to UnconfiguredMailer when no env set** — pin.

### Worker handler integration

9. **`/magic-link/request` calls mailer with correct payload** — fixture mailer that records calls, asserts every payload field.
10. **`/magic-link/request` audits `MagicLinkDelivered` on success** — pin payload shape (handle present, code absent).
11. **`/magic-link/request` audits `MagicLinkDeliveryFailed` on error** — pin payload shape (kind present, code absent).
12. **`/magic-link/request` returns 200 on delivery failure** — enumeration-defense pin.
13. **`/magic-link/request` does NOT log plaintext code anywhere on the failure path** — RFC 008 invariant pin must hold post-RFC-010.

### End-to-end

14. **Magic Link issue → mailer dispatch → recorded payload contains plaintext** — the happy path: confirm the plaintext IS reaching the mailer.
15. **Magic Link issue with no mailer config → audit surfaces failure, user sees normal page** — misconfig path.

## Security considerations

**Plaintext flow boundary**. The plaintext flows
exactly: `magic_link::issue` → `MagicLinkPayload.code`
→ `MagicLinkMailer::send` → operator's mail
provider. This is the **only** path. Any adapter
copying `payload.code` to a non-delivery
destination is a violation; the audit-boundary
discipline (mailer adapters cannot import audit)
prevents the most likely accident.

**Provider-side leak**. Once plaintext leaves
cesauth, the provider's storage and pipeline
become the trust boundary. cesauth's
responsibility ends at the `send()` call. The new
`docs/src/deployment/email-delivery.md` chapter
documents operator due-diligence on provider
security (TLS, at-rest encryption, retention).

**Enumeration via timing**. Different mailer
providers have different latency profiles. A
provider that responds quickly for "address
rejected" vs slowly for "address accepted, queued"
leaks valid-recipient information. Adapters MUST
respond uniformly. Pragmatically: respond to the
user with a fixed-time placeholder before the
mailer call completes. Investigate within
Workers' execution model — `ctx.waitUntil` allows
fire-and-forget after response. Document the
threat in the chapter.

**Bounce handling out of scope**. cesauth doesn't
process incoming bounces. A user with an invalid
email will fail repeatedly. Future RFC: bounce
adapter that flips `users.email_verified=false`
or suppresses further sends.

**Provider failure cascade**. A degraded provider
turns Magic Link into an outage for users without
WebAuthn. Mitigations are operator-side (provider
monitoring) until a future multi-provider failover
adapter ships.

**Reverting to audit-as-delivery**. The compile-
time crate boundary plus RFC 008's runtime grep
test together prevent silent reversion. An
operator under pressure cannot simply re-add the
`code=` line to audit without failing CI.

## Migration / upgrade path

Operators upgrading v0.50.1 → v0.50.2:

1. **Choose mailer strategy**:
   - Service binding (recommended; stays inside
     CF, lower latency)
   - HTTPS provider
   - Defer (unconfigured; Magic Link unusable
     until configured)

2. **Configure**:
   - Service binding: add `[[services]]` block.
   - HTTPS: `wrangler secret put`.
   - Defer: do nothing; audit will surface
     misconfig on first user attempt.

3. **Run RFC 008's audit purge** to clear
   pre-v0.50.2 leaked OTP audit rows. Re-baseline
   the chain.

4. **Test in staging**: Magic Link to a known
   address. Confirm receipt. Confirm no plaintext
   in audit (RFC 008's pin enforces this).

5. **Deploy production**.

## Open questions

**Operator-customizable templates in v0.50.2?**
Out of scope. v0.50.2 ships trait + 4 adapters +
single hardcoded body shape via existing i18n
catalog. Per-tenant / per-locale customization is
a follow-up RFC.

**ADR-015 graduation timing?** Draft alongside the
implementation; graduates to Accepted on v0.50.2
ship.

**Should the JSON envelope include a signature
proving the request came from cesauth?** Out of
v0.50.2 scope — the service binding's CF-internal
auth is sufficient; HTTPS provider's bearer token
is operator-provisioned. A request-signing layer
would matter only if the mail worker is exposed
to public internet, which neither adapter shape
implies.

## Implementation order

1. **PR 1 — Trait + value types in `cesauth-core`.**
   `MagicLinkMailer`, `MagicLinkPayload`,
   `DeliveryReceipt`, `MailerError`,
   `MagicLinkReason`. ~100 LOC. Compiles
   stand-alone.
2. **PR 2 — `DevConsoleMailer` + `UnconfiguredMailer`
   + `from_env` factory + worker wiring.**
   Magic Link issuance now calls the mailer; on
   defaults, every issue audits as
   `MagicLinkDeliveryFailed { not_configured }`.
   The audit-as-delivery hack is structurally
   gone. Coordinate with RFC 008 PR 1 (the
   plaintext-removal PR).
3. **PR 3 — `ServiceBindingMailer` + reference
   mail worker under `examples/`.**
4. **PR 4 — `HttpsProviderMailer` (SendGrid +
   Postmark body shapes).**
5. **PR 5 — Documentation:**
   `docs/src/deployment/email-delivery.md` chapter
   covering choice, configuration, monitoring,
   threats.
6. **PR 6 — ADR-015 graduates to Accepted.
   CHANGELOG ships v0.50.2.**

## Notes for the implementer

- Coordinate with RFC 008 (audit OTP elimination)
  and RFC 009 (introspection fixes). All three
  comprise the v0.50.2 production-blocker sweep.
- The example mail worker is illustrative, not
  authoritative. Operators write their own;
  cesauth's contract is the JSON envelope.
- Bundle size: trait + factory + four adapters
  add ~30 KB to worker WASM. Acceptable. The
  bundle-size CI gate from RFC 013 will measure.
- Local dev workflow with `WRANGLER_LOCAL=1`:
  developers see the handle in console_log, fetch
  the OTP from local D1 via `wrangler d1 execute
  "SELECT code_hash FROM auth_challenges WHERE
  handle = '<handle>'"` plus a small developer
  script that grinds the hash back to plaintext
  using known short-prefix dev OTPs. Document this
  workflow in the deployment chapter's "Local
  development" section.
- The `delivery_payload` rename from RFC 008 is
  the field name read by `MagicLinkPayload.code`.
  Coordinate the rename to land in PR 1 or
  immediately after.
