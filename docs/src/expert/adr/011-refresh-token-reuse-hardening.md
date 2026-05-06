# ADR-011: Refresh token reuse hardening

**Status**: **Accepted (v0.34.0)**.

**Context**: cesauth has implemented family-based refresh token
rotation since v0.4 — the `RefreshTokenFamilyStore` trait
(`crates/core/src/ports/store.rs`) plus a Durable Object
adapter (`crates/adapter-cloudflare/src/refresh_token_family.rs`).
The mechanism: each family tracks one `current_jti` plus a
ring of `retired_jtis` (size 16); rotating successfully bumps
the current and pushes the old to retired; presenting any
non-current jti revokes the family atomically. The DO is a
single-writer state machine, so the rotate vs revoke decision
is naturally serializable.

That covers the structural invariant from RFC 9700 §4.14.2
(formerly OAuth 2.0 Security BCP §4.13.2): "If a refresh
token is reused, the AS SHOULD invalidate all refresh tokens
for that authorization grant." But an audit of the v0.33.0
implementation against the BCP surfaced gaps in the
**observability** of reuse events. The BCP §4.13 explicitly
recommends operators be able to detect compromise via reuse
detection; cesauth's reuse signal was being collapsed into
the same audit event as routine refresh failures
(`token_refresh_rejected`), making it invisible to the
operator monitoring pattern the BCP intends.

This ADR documents the v0.34.0 changes that close those
gaps without changing the structural rotation invariant.

## Audit findings (v0.33.0 baseline)

What v0.33.0 already does correctly:

1. **Family is the rotation unit.** Every refresh issued at
   `/token` carries a family_id that addresses a DO; rotation
   updates a single state record per family.
2. **Reuse detection is atomic.** Inside the DO,
   `fam.revoked_at = Some(now_unix)` is set in the same
   `storage.put` as the rest of the rejection path — no
   window where a reused token could rotate.
3. **Subsequent rotates against a revoked family return
   `AlreadyRevoked`.** The poisoned-family invariant holds
   beyond the initial reuse detection.
4. **Reuse outcome propagates to the worker as an error.**
   The `/token` route writes `token_refresh_rejected` and
   returns `invalid_grant`, refusing the request.

What v0.33.0 does NOT do, and the gaps that drove this ADR:

1. **The audit event collapses reuse with routine rejection.**
   Both legitimate revocation (admin revoked, expired) AND
   reuse-detected revocation surface as `token_refresh_rejected`.
   The BCP-prescribed monitoring pattern — "alert when reuse
   is detected" — has no signal to attach to.
2. **The service-layer error collapses the same way.**
   `rotate_refresh` returns `CoreError::InvalidGrant("refresh
   token revoked")` for both `AlreadyRevoked` and
   `ReusedAndRevoked`. The worker can't dispatch to a
   distinct audit event because it can't tell the variants
   apart.
3. **Reuse cause isn't recorded.** When `ReusedAndRevoked`
   fires, the DO sets `revoked_at` and returns the unit
   variant. The cause (was the presented jti a recognized
   retired one? wholly unknown?) is lost. The `peek` API
   returns nothing reuse-specific. Forensic triage is
   blind to the data the rotate path actually had at hand.
4. **No `reused_jti` / `reused_at` on family state.** The
   first jti to be reused is the investigation anchor —
   what client_id was using it, when did it stop being
   the current jti, were there subsequent attempts. None
   of that is observable post-revoke.

The remaining items from the audit are out of v0.34.0 scope:

- **Rate-limiting `/token` refresh attempts.** A leaked
  refresh token + an attacker rotating rapidly can exhaust
  the family's retired_jtis ring (size 16) before the
  legitimate party notices. The fix is a rate limiter
  keyed on family_id. Lower priority — atomic family revoke
  still happens on the first reuse detection — but worth
  scheduling. Defer to a future security-track release.
- **User-facing self-service refresh family list at
  `/me/security/sessions`.** v0.35.0 territory per ROADMAP.
- **Tenant admin "show me all reuse-detected revocations
  in last N days" view.** Useful for operators but separable
  from the BCP-direct fixes; defer to the UI/UX iteration.

## Decision

Close the four observability gaps (1-4 above) with minimal,
backward-compatible changes:

### `FamilyState` gains three optional forensic fields

```rust
pub struct FamilyState {
    // ... existing fields ...
    pub reused_jti:        Option<String>,
    pub reused_at:         Option<i64>,
    pub reuse_was_retired: Option<bool>,
}
```

Each new field uses `#[serde(default)]` so the DO storage
deserializer accepts pre-v0.34.0 records unchanged (they
just see `None`). No DO migration needed — the fields
populate lazily on the next reuse event.

`reuse_was_retired` distinguishes the two reuse subcases:

- `Some(true)` — the presented jti was found in the family's
  `retired_jtis` ring. This is the classic reuse pattern: a
  real, previously-rotated-out token has been replayed. Most
  often indicates a leak of a real session.
- `Some(false)` — the presented jti was wholly unknown
  (neither current nor retired). More likely a forged or
  shotgun-style attempt where the attacker doesn't have any
  legitimate jti to replay.

The `was_retired` distinction is the v0.34.0 forensic
gain. Operators reading the audit log can prioritize
investigation: a `was_retired=true` event is a stronger
"someone stole a real token" signal than `was_retired=false`.

Admin-initiated `revoke()` does NOT populate any reuse
field — those are reserved for actual reuse detection.
Test `admin_revoke_does_not_populate_reuse_forensics` pins
this contract.

Once a family is revoked, subsequent rotation attempts
do NOT overwrite the recorded `reused_jti` / `reused_at` /
`reuse_was_retired`. The first reuse is the investigation
anchor; later pokes from an attacker still holding the
stale token are recorded only as `AlreadyRevoked` outcomes
(they don't even reach the forensic-field-write branch).
Test `refresh_reuse_then_more_attempts_preserve_first_forensics`
pins this.

### `RotateOutcome::ReusedAndRevoked` gains forensic payload

```rust
pub enum RotateOutcome {
    Rotated { new_current_jti: String },
    AlreadyRevoked,
    ReusedAndRevoked {
        reused_jti:  String,
        was_retired: bool,
    },
}
```

The caller (the service layer) doesn't have to peek the
family again to learn what was reused — the rotate operation
already had that information at the decision point and now
returns it.

### `CoreError::RefreshTokenReuse` distinct from `InvalidGrant`

```rust
CoreError::RefreshTokenReuse {
    reused_jti:  String,
    was_retired: bool,
}
```

The service layer's `rotate_refresh` now distinguishes:

- `RotateOutcome::AlreadyRevoked` →
  `CoreError::InvalidGrant("refresh token revoked")` (as
  before).
- `RotateOutcome::ReusedAndRevoked { .. }` →
  `CoreError::RefreshTokenReuse { reused_jti, was_retired }`.

The worker dispatches on the variant.

### Same wire-level response for both error variants

Both errors map to `error: "invalid_grant"` with HTTP 400 in
`oauth_error_response`. **This is intentional**: the
internal/external separation in spec §10.3 means observers
on the wire can NOT distinguish reuse from revoked.
Distinguishing them externally would let an attacker probe
whether a presented jti is currently in the retired ring —
they could submit a guess, observe the error code, and learn
information about the family's history. Internally (audit +
Workers logs) the variants ARE distinct.

### New audit event `RefreshTokenReuseDetected`

```rust
EventKind::RefreshTokenReuseDetected => "refresh_token_reuse_detected"
```

Emitted by the worker only on `CoreError::RefreshTokenReuse`.
Other rotation failures continue to emit
`token_refresh_rejected`. Payload:

```json
{
  "family_id":     "fam_...",
  "client_id":     "...",
  "presented_jti": "...",
  "was_retired":   true
}
```

`family_id` is decoded lossily on the worker side via
`decode_family_id_lossy` — the audit-write path must not
fail-closed on a malformed token, since losing the audit
signal is worse than recording an empty family_id. The
authoritative decode used by the rotation path stays in
core where its errors propagate normally.

## Wire compatibility

No client-visible changes. The `error` field on `/token`
failure is the same `invalid_grant` for all rotation
failures including reuse. Existing OAuth clients work
unchanged.

## Operator-visible changes

Audit events split into two streams. Operators monitoring
for compromise should now alert on
`refresh_token_reuse_detected` specifically rather than on
the generic `token_refresh_rejected` (which fires for any
expired/revoked rotation, not just reuse).

The audit event payload includes `was_retired`. A
high-confidence "stolen token" alert pattern is:

```sql
SELECT * FROM audit_events
WHERE kind = 'refresh_token_reuse_detected'
  AND json_extract(payload, '$.was_retired') = 1
ORDER BY ts DESC LIMIT 50
```

`was_retired = 0` events are also worth reviewing but at
lower urgency.

## Open questions

- **Q1**: Rate-limit `/token` refresh attempts at the
  family_id level. The current implementation has no
  per-family rate limit; an attacker with a leaked refresh
  token can drive rapid attempts in a tight loop. The
  family revoke is still atomic on first reuse, so the
  damage is bounded — but until-the-first-reuse the
  attacker can also blast through the legitimate party's
  rotation window. Schedule for a future hardening.
- **Q2**: Eventually surface a tenant admin view at
  something like `/admin/console/sessions/refresh-reuse`
  that aggregates `refresh_token_reuse_detected` events.
  Cross-references against the v0.33.0 audit chain
  surface. Defer to the UI/UX iteration alongside
  v0.35.0's session hardening.
- **Q3**: User-facing notification on reuse detection.
  Email the user when their refresh token family is
  burned by reuse — they likely lost the device or had
  it compromised. Belongs with v0.35.0's "new device"
  notification path.

## Considered alternatives (rejected)

- **Distinct OAuth wire error code for reuse.**  Rejected
  per spec §10.3. The wire is observable to anyone (legitimate
  client OR attacker); leaking the variant lets the attacker
  probe the family's state. The internal audit event is the
  right place to surface the distinction.
- **Auto-trigger user notification from the DO.** Rejected
  for v0.34.0 — the DO doesn't have email plumbing and
  shouldn't grow it. v0.35.0's notification path already
  has this on its scope; the audit event is the trigger
  point for that path.
- **Make `was_retired` the SAME signal as a stricter
  "high-confidence" alarm and skip recording
  was_retired=false events.** Rejected — even an unknown jti
  reuse is interesting (forging attempts), and discarding
  the lower-signal events would lose the volume metric
  operators need to detect attack campaigns. Both kinds
  emit; operators decide which to alert on.

## See also

- [Audit log hash chain](../audit-log-hash-chain.md) — the
  v0.32.0/v0.33.0 audit infrastructure that
  `refresh_token_reuse_detected` events flow through.
- [ADR-008: ID token issuance](008-id-token-issuance.md)
  — the sibling token-issuance decision; refresh tokens
  are minted at the same `/token` endpoint.
- RFC 9700 §4.14.2 (formerly draft-ietf-oauth-security-
  topics §4.13.2) — the BCP this hardening tracks against.
- [Storage](../storage.md) — the
  `RefreshTokenFamilyStore` port and DO adapter overview.
