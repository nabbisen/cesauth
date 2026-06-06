# RFC 103 — TTL and timing constants catalog

**Status**: Implemented | **Tier**: Refactoring | **Size**: Small | **Target**: v0.66.0

## Problem

Time-to-live and timeout constants are defined inline in 12+ different files:

| Location | Constant | Value |
|---|---|---|
| `core/src/oidc/id_token.rs:160` | `TTL` | 3600 |
| `core/src/service/token.rs:28` | `ID_TOKEN_TTL_SECS` | 3600 |
| `core/src/invitation.rs:40` | `DEFAULT_INVITE_TTL_SECS` | 72 * 3600 |
| `core/src/anonymous.rs:188` | `ANONYMOUS_TOKEN_TTL_SECONDS` | 86_400 |
| `core/src/admin/preview.rs` | `PREVIEW_TOKEN_TTL_SECS` | (in tests) |
| `worker/src/post_auth.rs:117` | `TOTP_GATE_TTL_SECS` | 300 |
| `worker/src/post_auth.rs:163` | `TOTP_ENROLL_TTL_SECS` | 900 |
| `worker/src/routes/me/auth.rs:51` | `LOGIN_NEXT_TTL_SECS` | 300 |
| `worker/src/routes/magic_link.rs:54` | `MAIL_VERIFY_WINDOW_SECS` | 600 |
| `worker/src/cron_status.rs` | (inline) | 8 * 24 * 3600 |

Multiple problems:

1. **Two TTLs of value `3600`** in different files for the same concept
   (`id_token.rs::TTL` and `service/token.rs::ID_TOKEN_TTL_SECS`) — neither
   references the other.
2. **No single place to audit timing policy.** An operator wanting to answer
   "what's the magic-link expiry window?" has to grep across crates.
3. **No discovery from operations docs.** The values aren't documented in
   `docs/src/expert/` — they're spread across source code.

## Proposed solution

Create `crates/core/src/policy/timing.rs`:

```rust
//! Centralized TTL and timing constants for cesauth.
//!
//! Each constant lists:
//!   - **Surface**: which user-visible behavior it controls
//!   - **Rationale**: why this value (link to ADR or RFC)
//!   - **Sensitivity**: whether changing this is a security decision

// ─── Authentication windows ─────────────────────────────────────

/// How long an issued ID token (OIDC) is valid.
/// Surface: relying parties; Rationale: ID tokens are short-lived per
/// OIDC §2; 1 hour is the standard window. Sensitivity: low (clients
/// must already handle expired ID tokens).
pub const ID_TOKEN_TTL_SECS: i64 = 3600;

/// How long a magic-link verification challenge is accepted.
/// Surface: end-user receiving the email; Rationale: short enough to
/// limit replay window if email is exposed, long enough for slow
/// email delivery. Sensitivity: medium.
pub const MAGIC_LINK_VERIFY_WINDOW_SECS: i64 = 600;

/// How long an invitation token is valid before expiring.
/// Surface: tenant admin issuing invites; Rationale: 72 hours is a
/// reasonable balance for invitations sent over weekends.
pub const INVITATION_TTL_SECS: i64 = 72 * 3600;

/// How long the post-auth TOTP gate cookie is valid.
/// Surface: TOTP verification flow; Rationale: 5 min is enough for
/// the user to find their authenticator app. Sensitivity: high
/// (longer windows expand the social-engineering blast radius).
pub const TOTP_GATE_TTL_SECS: i64 = 300;

/// How long the TOTP enrollment context survives.
/// Surface: TOTP enrollment flow; Rationale: 15 min covers the
/// initial scan + first code entry. Sensitivity: medium.
pub const TOTP_ENROLL_TTL_SECS: i64 = 900;

// ─── Anonymous and trial ────────────────────────────────────────

/// Anonymous trial account access token validity.
/// Surface: anonymous-trial UX; Rationale: 24 hours = one day of
/// continuous trial. Sensitivity: low (anonymous accounts cannot
/// access protected data).
pub const ANONYMOUS_TOKEN_TTL_SECS: i64 = 86_400;

// ─── Operational windows ────────────────────────────────────────

/// How long the cron pass status record lives in KV before
/// expiring. Surface: /admin/console/operations page; Rationale:
/// 8 days = one operational cycle + buffer.
pub const CRON_STATUS_KV_TTL_SECS: i64 = 8 * 24 * 3600;

// ─── Login flow ─────────────────────────────────────────────────

/// How long the "next URL" cookie survives between login attempt
/// and successful authentication.
pub const LOGIN_NEXT_TTL_SECS: i64 = 300;

/// How long a config-preview token is valid before expiring.
/// Surface: admin config preview; Rationale: 10 minutes is enough
/// to review a change without leaving forever-valid tokens.
pub const PREVIEW_TOKEN_TTL_SECS: i64 = 600;
```

## Migration

Replace each inline constant with `use cesauth_core::policy::timing::*;`
import. Code review checks that the new import is correct.

For each migrated module, verify the test that asserts the constant value
(e.g. `anonymous.rs:188`) is updated to import from the policy module.

## Documentation

Add `docs/src/expert/timing-policy.md` cross-referencing each constant with
its rationale. The rustdoc on `timing.rs` is the source of truth; the markdown
doc is a digest.

## Acceptance

- All TTL constants live in `policy::timing`.
- No raw `3600`, `86_400`, or `* 3600` magic numbers in production code paths.
- `docs/src/expert/timing-policy.md` exists.
- All 1,192 tests still pass.

## Out of scope

- Making TTLs configurable via env vars. That's a separate decision per RFC
  (some TTLs are policy, not knobs). Document any per-deployment overrides
  here when they're added.
