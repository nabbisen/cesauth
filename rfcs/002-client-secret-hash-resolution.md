# RFC 002: `oidc_clients.client_secret_hash` documentation drift resolution

**Status**: Ready
**ROADMAP**: `## Planned (0.x) / Later` — "`oidc_clients.client_secret_hash` documentation drift"
**ADR**: N/A (decision is small enough to settle inline)
**Estimated scope**: Small — schema comment edit + ~50 LOC verification helper + 4 tests, OR ~150 LOC Argon2 implementation + 8 tests, depending on path chosen

## Background

`migrations/0001_initial.sql` describes
`oidc_clients.client_secret_hash` as `argon2id(secret) or
NULL`, but cesauth has no Argon2 implementation. The
`client_secret_basic` / `client_secret_post` verification
path in `client_auth::verify_client_credentials` currently
uses a SHA-256 comparison (matching the path
`admin_tokens` uses for similar bearer-style secrets), or
in some legacy paths plaintext comparison. The schema
comment is a lie; the implementation works but inconsistently.

This was discovered during the v0.26.0 TOTP work and parked
on the ROADMAP. v0.50.1 ships the RFC; the implementation
release closes the drift in one of two ways, described
below.

## Decision

**Choose Path B — relax the schema comment to SHA-256 and
unify on cesauth's existing bearer-secret hashing path.**

Reasoning honestly compared:

- **Path A — implement Argon2id.** The schema comment
  becomes accurate. Argon2id is the password-hashing
  best-practice; if `client_secret` were a low-entropy
  user-chosen password, this would be the right answer.
- **Path B — relax to SHA-256.** The schema comment
  becomes accurate. cesauth's existing bearer-secret
  hashing (admin_tokens, magic-link OTP) uses SHA-256.
  Unifying is one less code path and one less crypto
  dependency.

The deciding consideration is **`client_secret`'s entropy
profile**. cesauth mints `client_secret` server-side as
a 256-bit CSPRNG value (see `oidc::client::generate_secret`)
and never accepts a user-chosen string. Argon2's value
proposition (slow brute-force of low-entropy
human-memorable inputs) doesn't apply when every input is
a 256-bit random already. SHA-256 is correct for
high-entropy bearer secrets; the offline brute-force
attacker against a SHA-256 hash of 256 random bits has a
search space of 2^256 — Argon2's slowdown is irrelevant
when the brute-force is already infeasible.

Path B is **the honest path**: it makes the schema match
what the implementation correctly does, instead of adding
a dependency to satisfy a comment.

If a future cesauth ever accepts user-chosen
`client_secret` values (it doesn't today and we don't plan
to), revisit. Track via a Q in the eventual ADR; until
then, do not pre-build for the case.

## Plan

1. **Schema comment edit**. In `migrations/0001_initial.sql`,
   the `client_secret_hash` column comment changes from:
   ```
   -- argon2id(secret) or NULL for public clients
   ```
   to:
   ```
   -- SHA-256(secret) or NULL for public clients (high-entropy
   -- server-minted secret; SHA-256 sufficient at 256-bit
   -- entropy — see RFC 002 in the rfcs/ directory)
   ```
   This is a comment-only edit; no schema change, no
   migration bump.

2. **Verify the actual hashing path is SHA-256
   everywhere**. Audit:
   - `cesauth_core::oidc::client::hash_secret` — should
     be SHA-256 already for new clients. Confirm.
   - `cesauth_core::client_auth::verify_client_credentials`
     — the comparison path. Confirm SHA-256 hash-and-
     compare with constant-time equality.
   - `cesauth_adapter_cloudflare::ports::repo::clients`
     — the storage path. Confirm what's written matches
     what's verified.
   - Any plaintext-fallback path: REMOVE.

3. **Unify with `admin_tokens` hashing helper**. If the
   two have separate helpers, factor a single
   `cesauth_core::secret_hash::sha256_hex(secret) -> String`
   and have both call sites use it. Test the helper.

4. **Pin the contract via tests**:
   - `client_secret_hash_is_sha256_hex_lowercase` —
     pin format.
   - `client_secret_hash_uses_constant_time_eq` —
     pin via inspection (this is hard to test directly;
     the assertion is "the verify path calls
     `subtle::ConstantTimeEq` or equivalent" — done via
     code review + a dedicated module that exposes only
     the constant-time wrapper).
   - `verify_client_credentials_rejects_wrong_secret`
     (existing — keep).
   - `verify_client_credentials_accepts_correct_secret`
     (existing — keep).

5. **Document in `docs/src/expert/security.md`**. New
   subsection: "Client secret hashing". One paragraph
   stating the decision, the entropy reasoning, and a
   note on the future path (Argon2id if user-chosen
   `client_secret` is ever introduced).

6. **CHANGELOG**: this is a documentation-and-cleanup
   release. Patch bump (e.g. 0.51.x → 0.51.y), no
   schema change, no wire change.

## Open questions

None.

## Notes for the implementer

- `subtle::ConstantTimeEq` is already a transitive dep
  (via `aes-gcm` / `webauthn-rs-core`). No new deps.
- Audit the two existing call sites carefully before
  refactoring — there's been one historical bug where
  a legacy plaintext comparison was missed. The
  refactor's value is closing that variance.
- If the audit surfaces a path that was actually
  plaintext-comparing, that's a security finding —
  flag it in the CHANGELOG entry separately under
  "Discovered during this work" and credit the audit.
