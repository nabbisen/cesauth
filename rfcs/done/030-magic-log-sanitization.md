# RFC 030 — Category::Magic + mailer log sanitization

> **2026-10-27 — §Decision(2) is unenforced.** Determined while assigning this
> RFC's evidence term under RFC 000 §22. `MagicLinkPayload` carries a plain
> `#[derive(Debug)]` (`core/src/magic_link/mailer.rs:81`), so nothing prevents
> `code` — documented in that struct as **"Secret. OTP plaintext"** — from
> reaching `Debug` output. **Not currently violated:** nothing in the workspace
> formats a payload with `{:?}`. But the guarantee is carried by a doc comment,
> and for invitations `code` is a full accept URL, not an expiring OTP.
>
> **Evidence term: `reviewed`** — which RFC 000 §22 does not permit for a P0.
> Remedy scheduled 0.86.3 as
> **[RFC 155](../accepted/155-two-p0-guarantees-rest-on-nothing-that-fails.md)**,
> after which this becomes `exercised`. §Decision(1) — `Category::Magic` as
> sensitive — is present (`backend/src/log.rs:106`) and also unasserted.

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
