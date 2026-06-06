# Generic Error Policy

This document records the authentication error message policy for cesauth,
implementing the PDF design requirement: "security-sensitive failures must
not leak details; only the next actionable step should be explicit."

## Policy principle

For any authentication or 2FA failure, the user-visible error message must
not distinguish between:
- "wrong credential" vs "credential not found"
- "code expired" vs "code wrong"
- "user has no TOTP" vs "TOTP code wrong"

This prevents probing attacks that enumerate users or guess code structures.

## Audit table (v0.61.0)

| Route | Error path | Message key | Leaks info? |
|---|---|---|---|
| `POST /login` (Passkey) | WebAuthn finish failure | `LoginPasskeyFailed` | ✅ No — generic |
| `POST /magic-link/request` | Any email (existing or not) | `MagicLinkSentIntro` | ✅ No — always "sent" |
| `POST /magic-link/verify` | Wrong/expired code | `MagicLinkMismatch` → `server_error` 500 | ⚠️ 500 leaks impl error vs auth failure |
| `POST /me/security/totp/verify` | `BadCode` | `TotpVerifyWrongCode` | ✅ No — generic |
| `POST /me/security/totp/verify` | `NoUserAuthenticator` | treated same as `Success` | ✅ No — state hidden |
| `POST /me/security/totp/enroll/confirm` | `WrongCode` | `TotpEnrollWrongCode` | ✅ No — generic |
| `POST /me/security/totp/recover` | recovery code mismatch | `TotpRecoveryInvalidCode` | ✅ No — generic |

## Known gap (v0.61.0)

**`POST /magic-link/verify` → `MagicLinkMismatch`** maps to HTTP 500 via
`oauth_error_code_status()`. This is incorrect per RFC 6749 — an invalid
code is a client error (400/401), not a server error (500). The correct
mapping is `invalid_grant` + 400.

**Fix in v0.62.0 (RFC 074)**: Change `MagicLinkMismatch` and `MagicLinkExpired`
to map to `("invalid_grant", 400)` in `oauth_error_code_status()`.

## Constant-time note

`magic-link/verify` calls the `MagicLinkMailer` internal store lookup, which
may return faster for non-existent codes. The current implementation does not
apply a constant-time delay. Future hardening: pad response time to fixed
floor (tracked in ROADMAP).

## Invariant test

`crates/worker/src/routes/me/totp/verify.rs` contains inline commentary that
`NoUserAuthenticator` and `Success` use the same code path, ensuring that
successful completion and "user enrolled nothing" produce identical HTTP responses.

## Actionable next-steps rule

Per PDF design: "only the actionable next step must be clear." Apply to all
error messages:
- ✅ TOTP wrong code: "That code didn't match. Try again." (next step: try again)
- ✅ Passkey failure: "Authentication failed. Try again." (next step: try again)
- ✅ Magic Link: "If that address is registered, a link has been sent." (next step: check email)
- 🔜 Magic Link verify failure (RFC 074): return `invalid_grant` 400 with no detail body
