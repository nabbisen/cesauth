# RFC 139 — Refresh tokens never expire

**Status.** Accepted — approved by the owner 2026-09-16, as ruled in §9 and §10. Handoff dispatched.
**Author.** Architect · **Date.** 2026-09-15
**Priority.** **P1, security.** A leaked refresh token is a permanent bearer
credential.
**Target release.** After RFC 137, which touches the same refresh path.
**Found by.** Measuring the refresh grant while preparing RFC 137's handoff.

---

## 1. Summary

`REFRESH_TOKEN_TTL_SECS = "2592000"` (30 days) is configured
(`wrangler.toml:128`) and **enforced nowhere**. The value is written into the
refresh token itself, the code that decodes the token deliberately ignores it,
and the store that is named as the authority stores no expiry and checks none.
A refresh family rotates indefinitely.

Introspection compounds it: it reads the expiry back **out of the unsigned
token** and reports it as `exp` beside `active: true`, so the lifetime a
resource server sees is whatever the presenter wrote.

## 2. What is established

**The token format** — unsigned:

```
base64url("{family_id}.{jti}.{expiry}")        service/token.rs:418-423
```

**The TTL is used only to write that third field** — `refresh_ttl_secs`
appears at `service/token.rs:65` (field), `:195` and `:353`
(`encode_refresh`), and nowhere else in non-test code.

**Rotation ignores it, and says why:**

```rust
// We don't consult the third part (expiry) here; the DO is the
// authority. It only exists for debugging / future eager rejection.
let _expiry = parts.next();                     service/token.rs:425-439
```

**The authority has nothing to enforce:**

| Where | What it checks |
|---|---|
| `FamilyState` (`ports/store.rs:163-203`) | stores `created_at`, `last_rotated_at`, `revoked_at` — **no `expires_at`** |
| The production DO, `Command::Rotate` (`adapter-cloudflare/src/refresh_token_family.rs:98-127`) | revoked → reject; current jti → rotate; else revoke on reuse. **No TTL, no alarm, no storage deletion** |
| The conformance oracle (`adapter-test/src/store/refresh_token_family.rs:46`) | identical — **no expiry in the port contract at all** |
| The daily cron (`lib.rs`, `event(scheduled)`) | anonymous-trial sweep, audit chain, retention — **nothing purges families** |

**Introspection trusts the client's number.** `introspect_refresh`
(`service/introspect.rs:285`) decodes the token's third field
(`decode_refresh_token`, `:412`) and passes it straight through as `exp`
(`:398-405`). It receives `now_unix` and never compares it to anything. Its own
documentation says otherwise: *"lifetime is the family's `created_at +
refresh_ttl`"* (`oidc/introspect.rs:352-355`).

## 3. Impact

- **A leaked refresh token never stops working.** RFC 137 binds it to its
  client, which narrows who can use it — not for how long.
- **Introspection reports an attacker-controlled `exp`.** Edit the base64 and
  `/introspect` echoes the new expiry as authoritative.
- **An operator who sets `REFRESH_TOKEN_TTL_SECS` believes they have set a
  lifetime.** They have set a field nothing reads.

**Mitigation that exists:** rotation with reuse detection. A token that is
stolen *and used* collides with the legitimate client's next use and burns the
family. A token stolen from a client that has stopped refreshing is live
forever.

## 4. Non-goals

- Not RFC 137's client binding.
- Not a signed refresh-token format. The DO is the right authority; the fix is to
  give it the data, not to make the token self-describing.
- Not access-token lifetimes, which are signed JWTs with a checked `exp`.

## 5. The change

**L1 — Store the expiry at family creation.** `FamilyInit`/`FamilyState` gain
`expires_at = now + ttl`, set once. Changing the configured TTL later then does
not retroactively extend or shorten families that already exist — the correct
semantics for a credential.

**L2 — Enforce it in the DO.** `Command::Rotate` past `expires_at` → reject as an
invalid grant. Mirror it in the adapter-test oracle, and add it to the port
contract's documentation, so the conformance suite pins it.

**L3 — Introspection reads the family, never the token.** `exp` comes from
`FamilyState.expires_at`; past it → `inactive`. The token's third field stops
being read on either path.

**L4 — Existing families.** `#[serde(default)]` on `expires_at`. There is no
production use, so the owner decides between computing from `created_at + ttl`
for families that lack it, or treating them as expired (§8).

## 6. Testing strategy

1. A family past `expires_at` fails to rotate — on the oracle and against the DO.
2. Introspection of such a token returns `inactive`.
3. **A token with an edited expiry field** changes nothing: rotation and
   introspection both use the stored value.
4. A family within its lifetime rotates exactly as today.

## 7. Release level

**Patch** — a configured control that was never enforced is a defect.

## 8. Open questions — for the owner

1. **Absolute or sliding?** Absolute (`created_at + ttl`) is what the codebase's
   own documentation already says the lifetime is, and it is the recommendation.
   Sliding (`last_rotated_at + ttl`) keeps active sessions alive indefinitely,
   which is precisely the property this RFC removes. A combination — an idle
   window plus an absolute cap — is common practice and a larger decision.
2. **Families created before this lands:** compute `expires_at` from
   `created_at`, or treat as expired? No production use either way;
   recommendation is to compute, so a developer's local session does not die on
   upgrade.

## 9. Rulings (2026-09-15)

The owner answered §8 with the design standard rather than an option: *"finally
clean, safe and secure, robust and sophisticated design."* There is no
production use. Under that standard, and after measuring the precedent the
codebase already has:

### 9.1 Both: an idle window and an absolute cap

A refresh family is live only while **both** hold:

```
now_unix <  created_at      + REFRESH_TOKEN_TTL_SECS            (absolute)
now_unix <  last_rotated_at + REFRESH_TOKEN_IDLE_TIMEOUT_SECS   (idle)
```

- **This is the codebase's own model, not a new one.** `ActiveSessionStore`
  already enforces exactly this pair (`ports/store.rs:311-352`: `IdleExpired`,
  `AbsoluteExpired`, `idle_timeout_secs`, `absolute_ttl_secs`), configured by
  `SESSION_TTL_SECS` and `SESSION_IDLE_TIMEOUT_SECS` (`backend/src/config.rs:138,
  :142`). Refresh families following a different model from sessions would be
  the unclean choice.
- **Absolute alone** lets a stolen token from an idle client live out the full
  30 days. **Sliding alone** keeps an active thief alive forever. Only the pair
  bounds both cases.
- **Boundary:** expired when `now_unix >= deadline`, the same rule as RFC 140
  and `AnonymousSession::is_expired`.
- **Defaults:** absolute stays 30 days; idle **14 days**. Configuration is
  refused at startup if absolute ≤ 0, idle < 0, or idle > absolute. Idle `0`
  disables the idle check, as it does for sessions; the absolute cap cannot be
  disabled.

### 9.2 Policy is applied at check time; no expiry is stored (supersedes §5 L1 and L4)

§5 L1 proposed storing `expires_at` at creation. **Overruled, by the author, on
measurement:** `FamilyState` already stores `created_at` and `last_rotated_at`
(the DO's `Init`, `adapter-cloudflare/src/refresh_token_family.rs`), which is
everything §9.1 needs. The policy is passed in at rotation, exactly as sessions
receive `idle_timeout_secs`/`absolute_ttl_secs`. Consequences:

- **No schema change and no legacy branch.** §8 q2 dissolves: a family created
  before this lands has `created_at`, so it is governed from the first request
  after deploy. No `#[serde(default)]`, no "treat as expired" path.
- **Lowering the configured lifetime shortens every live family immediately.**
  That is what an operator responding to an incident needs. Raising it extends
  families, which is the operator's explicit choice. Storing the value at
  creation would have made the first case impossible.
- **One pure function decides.** `FamilyState::lifetime(now_unix, policy) ->
  Live | IdleExpired | AbsoluteExpired` in core, called by the DO, the adapter-test
  oracle and introspection. Three copies of the arithmetic would drift.

### 9.3 Expiry revokes, atomically, in the store

`rotate` on an expired family sets `revoked_at` in the same write and returns
`IdleExpired` / `AbsoluteExpired`, as `ActiveSessionStore::touch` does. It is
never rotated. On the wire this is `invalid_grant`, the same as a revoked
family. **Enforcement is in the DO**; a check in the service's peek alone would
race the rotation.

### 9.4 The token stops carrying an expiry (strengthens §5 L3)

The third field of `base64url("{family_id}.{jti}.{expiry}")` is unsigned,
unread by rotation, and the source of introspection's attacker-controlled `exp`.
**Remove it.** The format becomes `base64url("{family_id}.{jti}")`, and all three
decoders accept exactly two parts: `service/token.rs` `decode_refresh`,
`service/introspect.rs:412` `decode_refresh_token`, and `service/revoke.rs:333`
`decode_refresh_best_effort`. A three-part token is malformed. There is no
production use, so outstanding local tokens simply fail.

Introspection's `exp` becomes
`min(created_at + absolute, last_rotated_at + idle)` (only the absolute term when
idle is `0`), computed from the peeked family by §9.2's function. Past it is
`active: false`.

### 9.5 Level

**Minor.** Enforcing the configured absolute lifetime is a fix, but the idle
window and `REFRESH_TOKEN_IDLE_TIMEOUT_SECS` are a new control, and a release
mixing levels takes the higher one. §7's "Patch" is superseded. The natural
home is 0.84.0.

### 9.6 Sequencing

After RFC 140, which is authorized and dispatched. Both change
`service/token.rs` and its tests, so they run one after the other, not in
parallel.

**Authorized by the owner on 2026-09-16**, with these rulings and a 0.84.0
target.

## 10. Rulings made while writing the handoff (2026-09-16)

Measuring the refresh path for the handoff settled four things §9 left
implicit.

### 10.1 The store records *why* a family died, not *when* it would

§9.2's rule stands: no deadline is stored. But an expired family is revoked
(§9.3), and introspection classifies a revoked family by its forensic fields:
`reused_jti` present means `ReuseDetected`, otherwise `Explicit`
(`service/introspect.rs`). An expiry would therefore be reported as an
**explicit revocation**, which is false. So `FamilyState` gains
`expired: Option<LifetimeExpiry>` (`Idle` | `Absolute`), `#[serde(default)]`,
set in the same write as `revoked_at`. That is an `Option` defaulting to
`None`, exactly like the v0.34.0 reuse fields beside it. It is not a legacy
branch, because a family without it simply has not expired.

### 10.2 Check order: revoked, absolute, idle, then the jti

This is the session DO's order (`adapter-cloudflare/src/active_session.rs`,
`Command::Touch`). An expired family presented with a retired jti is
**expired, not reuse-detected**. It is dead by policy either way, and the reuse
forensics describe an attack inside a live family. The reuse fields stay `None`.

### 10.3 Introspection classifies expiry as its own state, without writing

`FamilyClassification` gains `Expired`, reported when either:

- `expired` is set (the DO already revoked it); or
- the family is not revoked but `lifetime(now, policy)` is expired (nobody has
  rotated since the deadline passed).

Introspection stays read-only in both cases. `revoked_at` is surfaced only when
stored. This adds one value to the `x_cesauth` extension and changes no
standard field. The introspection input therefore carries the lifetime policy,
and `introspect_refresh`'s ignored `_now` becomes used.

### 10.4 No new audit event kind

An expired rotation surfaces as the existing generic refresh rejection. The
token route's comment already lists "expired" among those causes. Dedicated
`RefreshIdleTimeout` / `RefreshAbsoluteTimeout` events, mirroring
`SessionIdleTimeout` / `SessionAbsoluteTimeout`, belong to RFC 123 (audit event
completeness).
