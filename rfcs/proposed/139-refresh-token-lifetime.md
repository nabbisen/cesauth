# RFC 139 — Refresh tokens never expire

**Status.** Proposed — needs owner authorization.
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
