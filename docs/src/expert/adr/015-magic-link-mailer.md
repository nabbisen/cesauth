# ADR-015: Magic Link mail delivery port

**Status**: Accepted (v0.51.0)

**Context**: Prior to v0.51.0 cesauth had no mailer abstraction. The Magic
Link OTP plaintext was written into the audit log on every issuance (see
RFC 008 / v0.50.3 for the security disclosure). Operators were expected to
ship the audit stream to a script that parsed `code=<OTP>` lines and SMTPd
them. This created a structural gap: no contract existed between cesauth
and a real mail provider, making RFC 008's audit-leak fix fragile — operators
under deadline pressure could reintroduce the hack.

---

## Decision

**Ship a `MagicLinkMailer` port** (`cesauth_core::magic_link::mailer`) —
a `Send + Sync` async trait that receives the OTP plaintext and is
responsible for delivery. Four reference adapters ship in
`cesauth-adapter-cloudflare`.

---

## Design questions

### Q1 — Where does the trait live?

**Decision**: `cesauth-core::magic_link::mailer`. Keeps the port adjacent
to the domain type (`IssuedOtp`, `MagicLinkPayload`) and enforces the audit
boundary compile-time: `cesauth-core` doesn't depend on `cesauth-worker::audit`,
so no mailer adapter can accidentally call `audit::write_*`.

Alternatives rejected:
- `cesauth-worker`: would allow adapters to call audit by accident; mixes
  domain contract with runtime glue.
- Separate crate: overkill for the current surface.

### Q2 — Trait signature: `async fn send` or `fn send → impl Future`?

**Decision**: `fn send(...) → impl Future<Output = ...> + Send` (RPITIT
pattern). Reason: Rust 2024 edition allows `async fn` in traits with
`Send` + `Sync` bounds via the `async-trait`-free path, but `impl Future`
is more explicit about `Send` requirement (needed for `Box<dyn MagicLinkMailer>`
on the Cloudflare Workers runtime which requires `Send`).

### Q3 — How many adapters ship at v0.51.0?

**Decision**: Four.
1. `DevConsoleMailer` — dev (`WRANGLER_LOCAL=1`) only; logs handle, never code.
2. `UnconfiguredMailer` — fallback; returns `NotConfigured` and surfaces via audit.
3. `ServiceBindingMailer` — CF service binding to operator mail worker.
4. `HttpsProviderMailer` — generic HTTPS provider POST (SendGrid v3 shape).

Custom adapters: operators implement `MagicLinkMailer` in their own crate
and pass the `Box<dyn MagicLinkMailer>` into cesauth's worker at startup.
ADR does not prescribe how — that's operator choice.

### Q4 — Does the handler fail-closed on delivery failure?

**Decision**: **No.** Differential responses (200 on success, error on
failure) leak whether the email address is registered / deliverable.
On delivery failure: audit `MagicLinkDeliveryFailed`, log at Error, return
the same "check your inbox" 200. Operators detect failures via the audit
dashboard.

### Q5 — Where does the adapter selection live?

**Decision**: `cesauth_worker::adapter::mailer::from_env`. Priority:
`WRANGLER_LOCAL=1` → DevConsole; `MAGIC_LINK_MAILER` service binding
present → ServiceBinding; `MAILER_PROVIDER_URL` set → HttpsProvider;
else → Unconfigured. Documented in `docs/src/deployment/email-delivery.md`.

### Q6 — Email body rendering: hardcoded or configurable?

**Decision**: Single hardcoded body via `HttpsProviderMailer`'s inline
strings (with JA/EN switch). Per-tenant/per-locale template customization
is a future RFC. The service binding adapter delegates rendering to the
operator's mail worker entirely.

### Q7 — Timing-attack mitigation for HTTPS provider?

**Decision**: Documented concern in `docs/src/deployment/email-delivery.md`;
not structurally enforced at v0.51.0. Cloudflare Workers' `waitUntil` allows
fire-and-forget after the response is sent; operators running HTTPS provider
should use `ctx.waitUntil(mailer.send(...))`. Implementation deferred until
a concrete timing-leak threat is measured.

---

## Consequences

- Magic Link is now usable in production without a bespoke audit-script
  delivery hack.
- RFC 008's audit-leak fix is structurally reinforced: the compile-time
  crate boundary prevents mailer adapters from reaching `audit::write_*`.
- Operators choosing Unconfigured (the default) see audit noise
  (`magic_link_delivery_failed kind=not_configured`) on the first Magic
  Link attempt — the intended misconfig signal.
- Env vars added (minor bump): `MAGIC_LINK_MAILER` (service binding name),
  `MAILER_PROVIDER_URL`, `MAILER_PROVIDER_AUTH_HEADER`,
  `MAILER_PROVIDER_FROM_ADDRESS`, `MAILER_PROVIDER_FROM_NAME`.
  `WRANGLER_LOCAL` is pre-existing.

---

## Open questions

**Q8** — Should `HttpsProviderMailer` support per-provider body templates
(Postmark vs Resend vs SendGrid have different JSON shapes)?
Deferred — current single shape (SendGrid v3 compatible) works for most.
A future RFC adds a template/adapter registry when the demand is concrete.

**Q9** — Should the delivery audit event carry `provider_msg_id`?
Yes (already implemented). The operator can correlate `magic_link_delivered`
events with provider-side delivery logs by message ID.
