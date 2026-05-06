# ADR-002: User-as-bearer mechanism

**Status**: Accepted (v0.11.0)
**Decision**: Extend `admin_tokens` with an optional `user_id`
column. Continue using `Authorization: Bearer <token>` as the
wire format.
**Rejected**: Session cookies; short-lived JWTs.

## Context

The v0.13.0+ tenant-scoped admin surface needs to know not only
"is this caller authorized" but "*which user* is this caller, so
we can run `check_permission(user_id, ...)` against the spec §9.2
authorization engine."

The existing v0.3.x admin surface uses
`Authorization: Bearer <token>` against rows in `admin_tokens`.
That mechanism resolves a token to an `AdminPrincipal`
(`{ id, name, role }`) — there is no concept of "which user is
this." We need to add one.

Three options:

1. **Extend `admin_tokens` with `user_id`**. A token row can
   optionally point at a row in `users`. A token with
   `user_id IS NULL` is a system-admin token (the kind we have
   today); a token with `user_id IS NOT NULL` is a user-as-bearer
   token. `Authorization: Bearer <token>` continues to be the
   wire format.
2. **Session cookies**. Operator logs in (with WebAuthn or
   password), Worker sets a `Set-Cookie`, subsequent requests
   carry the cookie automatically.
3. **Short-lived JWTs**. Operator logs in, server issues a JWT
   with `sub = user_id` and a short TTL; client refreshes via
   the existing OIDC refresh-token machinery.

## Decision

Option 1: extend `admin_tokens` with `user_id`.

## Consequences

### What this gives us

- **One auth path, not three.** v0.3.x bearer tokens, v0.13.0
  user-as-bearer tokens, and any future automation tokens all
  flow through one `resolve_from_request` lookup. The lookup
  loads an `AdminToken` row which already carries `role`, and
  *now also* carries `user_id`. Calling code that doesn't care
  about `user_id` (the v0.3.x and v0.4.x admin console handlers)
  continues to ignore it.

- **No new CSRF surface.** `Authorization` headers are not auto-
  set by browsers across origins; that's the existing CSRF
  defense. Cookie-based auth would mean every form post needs a
  CSRF token, doubling the form complexity. (The v0.9.0 forms
  documentation already calls this out as a design constraint.)

- **No new cryptographic key to rotate.** A JWT path would mean
  key rotation, a refresh-token path, and `aud`/`iss` validation
  — all reasonable but each is an opportunity for misconfig.
  Token-row lookup is the same shape we've been doing.

- **Migration is additive.** v0.11.0's `0005` migration adds the
  column with no `NOT NULL` constraint, so every existing token
  remains valid as a system-admin token. We don't have to
  migrate any data.

### What this costs us

- **No browser-native login UX (yet).** A tenant admin doesn't
  log in by entering a password and clicking "Sign in"; they
  log in by being given a token (out of band) and configuring
  their browser/extension to send it. This is the same operator
  workflow as the existing v0.3.x admin console, so it's
  consistent — but it is a barrier compared to a full login UI.
  A future ADR can revisit this once the user-as-bearer mechanism
  is in place.

- **Tokens don't expire automatically.** Cookie sessions can
  carry an idle timeout; bearer tokens are valid until disabled.
  Operator-side discipline (rotating tokens, disabling on
  off-boarding) becomes more important. The existing v0.3.x
  console already requires this discipline; we're not adding new
  burden, just not subtracting any.

- **Tokens can leak.** A bearer token in a config file or
  environment variable can leak more easily than a session
  cookie that's HttpOnly and Secure. The v0.3.x model has this
  exposure already; we're not making it worse.

### What we explicitly didn't decide

- **Whether to add a session-cookie path later** as an *additional*
  mechanism. The decision rejects cookies *as the primary*
  user-as-bearer path; it doesn't preclude introducing them
  later for the specific case of "operator logs in via
  WebAuthn." We expect this to come up in a future ADR once
  there's a concrete need.
- **How user-as-bearer tokens are minted.** The token-creation
  flow (and whether it's accessible to tenant admins or only
  to system admins) is a 0.13.0 concern.

## Schema impact

```sql
ALTER TABLE admin_tokens ADD COLUMN user_id TEXT;
CREATE INDEX idx_admin_tokens_user_id
  ON admin_tokens(user_id) WHERE user_id IS NOT NULL;
```

The application layer enforces the FK: when `user_id` is set on
write, the writer verifies a row in `users` with that id exists
and shares the right tenant. SQLite/D1 don't allow adding inline
FKs via `ALTER TABLE`, and we follow the same enforcement
approach the rest of the schema already uses.

## Type impact

```rust
// AdminPrincipal — produced by the resolution layer.
pub struct AdminPrincipal {
    pub id:      String,
    pub name:    Option<String>,
    pub role:    Role,
    pub user_id: Option<String>,  // NEW in 0.11.0
}
```

Every existing call site that constructs an `AdminPrincipal`
defaults `user_id` to `None` — no behavior change. v0.13.0
introduces the `Some(user_id)` path through the
`AdminTokenRepository::create_user_bound` (or similar) method
and the resolution layer that propagates it.

## Alternatives considered

### Session cookies (rejected)

The strongest argument for cookies is browser ergonomics — no
extension needed, just visit and log in. This matters for
tenant admins (the people who'd use the new surface) more than
it matters for system admins (operators who already use curl).

We rejected this because:

1. CSRF defense becomes mandatory. Every form needs a CSRF token
   round-trip; the v0.9.0 forms code would need updating.
2. Adding cookies *and* keeping bearer auth means two parallel
   resolution paths to keep in sync.
3. The cookie work isn't blocked by this ADR — it can be added
   later as an alternate mechanism.

### Short-lived JWTs with refresh tokens (rejected)

Strongest argument: refresh-token rotation is the existing
spec's pattern for end-user OIDC, and reusing that pattern for
admin auth would compose nicely. Plus JWT carries the `sub` and
the role inline, so no DB lookup per request.

We rejected this because:

1. cesauth's JWT machinery (`jsonwebtoken@10`) is presently
   issuing user-facing OIDC tokens. Adding a second issuer
   purpose would mean signing-key rotation discipline, `aud`
   discrimination, and a refresh-flow on the admin path.
2. The "no DB lookup per request" win is real for end-user
   tokens at OIDC scale, but admin requests are *not* at that
   scale. The lookup overhead is not a problem.
3. Token revocation becomes harder. A JWT is valid until its
   exp; a row-backed token can be disabled instantly.

## See also

- ADR-001: URL shape (decided first; this ADR's choice depends
  on a single-origin URL)
- ADR-003: System-admin from inside the tenant view (depends on
  this auth model)
- Migration `0005_admin_token_user_link.sql` — schema change
- v0.9.0 forms documentation — auth caveat (existing
  Authorization-header limitation)
