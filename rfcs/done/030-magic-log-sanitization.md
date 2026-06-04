# RFC 030 — Category::Magic + mailer log sanitization

**Status**: Implemented  
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
