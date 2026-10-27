# RFC 030 — Category::Magic + mailer log sanitization

> **2026-10-27 — §Decision(2) was unenforced; fixed in 0.86.3.** Determined
> while assigning this RFC's evidence term under RFC 000 §22.
> `MagicLinkPayload` carried a plain `#[derive(Debug)]`
> (`core/src/magic_link/mailer.rs:81`), so nothing prevented `code` —
> documented in that struct as **"Secret. OTP plaintext"** — from reaching
> `Debug` output. **It was never actually violated:** nothing in the
> workspace formatted a payload with `{:?}`. But the guarantee was carried
> by a doc comment, and for invitations `code` is a full accept URL, not
> an expiring OTP.
>
> **[RFC 155](../accepted/155-two-p0-guarantees-rest-on-nothing-that-fails.md)**
> replaced the `derive(Debug)` with a hand-written impl that redacts `code`
> as `REDACTION_MARKER`, asserted against both an OTP-shaped and a
> URL-shaped fixture. §Decision(1) — `Category::Magic` as sensitive — is
> present (`backend/src/log.rs:106`) and remains unasserted; out of
> RFC 155's scope.

**Status**: Done. **`exercised`** (RFC 000 §22) —
`cesauth_core::magic_link::mailer::tests::debug_redacts_code_for_both_otp_and_url_shaped_values`,
which fails if `Debug` for `MagicLinkPayload` ever prints `code` again
(demonstrated: reverting to the field-literal shape fails this test).  
**Priority**: P0 (compile error + secret leak)  
**Size**: Small (~30 LOC)  
**Depends on**: nothing

## Problem

Two related issues in the Magic Link logging path:

1. `Category::Magic` is referenced in `worker/src/routes/magic_link/request.rs`
   but does not exist in `worker/src/log.rs` → compile error on any build that
   includes the worker crate.

2. `HttpsProviderMailer` / service binding mailer includes the provider
   response body in `MailerError`, and the handler logs `format!("magic_link mailer
   failed: {e}")`. If the external mail provider echoes the request body on error
   (common debug behavior), the OTP code flows into the Cloudflare log drain.

## Decision

1. Add `Category::Magic` to `log::Category` as a **sensitive** category
   (`is_sensitive() == true`). Magic Link paths handle email addresses and
   delivery state; they belong alongside `Category::Auth`.

2. Sanitize mailer error logging: log only `status`, `provider_kind`, and
   `provider_message_id`. Never include provider response body. Never allow
   `MagicLinkPayload.code` to reach `Debug` / `Display` / log output.

## Implementation

- `worker/src/log.rs`: add `Magic` variant, mark sensitive
- `adapter-cloudflare/src/mailer.rs` (and any provider impl): strip body from
  `MailerError`, expose only `status: u16` + `provider_message_id: Option<String>`
- Handler log site: replace `format!("{e}")` with structured `{status} {kind}`
