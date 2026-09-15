# RFC 140 — Challenge stores do not enforce expiry at read

**Status.** Accepted — approved by the owner 2026-09-15. Handoff dispatched.
**Author.** Architect · **Date.** 2026-09-15
**Priority.** **P1, security.** Authorization codes, WebAuthn ceremony nonces, the
TOTP gate and parked authorization requests stay usable after `expires_at`
until a Durable Object alarm deletes them, and nothing checks the alarm
succeeded.
**Target release.** The next patch. **Ahead of RFC 117**, which assumes this
contract clause holds and would encode it.
**Found by.** Measuring the store contract before writing RFC 117's handoff.

---

## 1. Summary

The `AuthChallengeStore` contract says implementations **MUST** *"treat entries
past `expires_at` as absent (`None`)"* (`crates/core/src/ports/store.rs`, the
doc comment on the trait). Neither implementation does, and no caller makes up
for it on four of the six challenge kinds. This RFC makes `peek` and `take`
enforce expiry at read time, against a clock the caller passes in.

## 2. Evidence

### 2.1 Neither store checks

- **Durable Object** (`adapter-cloudflare/src/auth_challenge.rs`). `Command::Peek`
  and `Command::Take` return whatever is stored, and never read
  `expires_at`. Expiry is only the alarm set at `Put`:
  `storage.set_alarm(expires_at * 1000)`. The module doc says so: *"Expiry is
  handled via DO alarms."*
- **The alarm cannot report failure.**
  `async fn alarm(&self)` runs `let _ = self.state.storage().delete(KEY).await;`
  and then returns `Response::ok("expired")`. A failed delete is discarded and
  the handler reports success. So whatever retry the runtime offers for a
  failing alarm can never apply, and the challenge survives indefinitely.
- **In-memory store** (`adapter-test/src/store/auth_challenge.rs`). `peek` is
  `m.get(handle).cloned()` and `take` is `m.remove(handle)`. There is no clock
  at all, so **no host test can observe expiry**. `grep -rn -i 'expir'` over
  `core/src/service/token/tests.rs` and `adapter-test/src/store/` finds no
  challenge-expiry test.

### 2.2 Who is exposed

The non-test call sites
(`grep -rnE '\.(take|peek)\(' crates --include='*.rs'`, filtered to
`AuthChallengeStore` uses, plus core's multi-line call at
`service/token.rs:129-130`). For each, whether the caller checks expiry itself:

| Consumer | Kind | TTL | Checks expiry itself? |
|---|---|---|---|
| `core/service/token.rs:129` (`/token`) | `AuthCode` | `AUTH_CODE_TTL_SECS`, default 60 (`backend/src/config.rs:144`) | **no** |
| `backend/routes/webauthn/authenticate.rs:91` | `WebauthnAuthenticate` | 60 (`:47`) | **no** |
| `backend/routes/webauthn/register.rs:90` | `WebauthnRegister` | 60 (`:47`) | **no** |
| `backend/routes/me/totp/verify.rs:116, :289` | `PendingTotp` | `TOTP_GATE_TTL_SECS` 300 | **no, and it extends an expired gate** (§2.3) |
| `backend/routes/me/totp/recover.rs:146` | `PendingTotp` | 300 | **no** |
| `backend/post_auth.rs:196` | `PendingAuthorize` | — | **no** |
| `backend/routes/magic_link/verify.rs:166, :211` | `MagicLink` | — | yes: `magic_link::verify(…, now, expires_at)` at `:193` |
| `backend/routes/api_v1/anonymous.rs:321, :342` | `MagicLink` | — | yes: `magic_link::verify` at `:337` |

The expiry checks outside the adapters
(`grep -rn 'expires_at' crates/core/src crates/backend/src | grep -E '[<>]=?|now'`)
are in `magic_link.rs`, `anonymous.rs` (the session, not the challenge) and
`invitation.rs`. **None is in the token, WebAuthn, TOTP-gate or post-auth
paths.**

### 2.3 The TOTP gate turns an expired challenge into a fresh one

`totp/verify.rs:367` re-parks the gate after a failed attempt with
`expires_at: now_unix + TOTP_GATE_TTL_SECS.min(expires_at - now_unix).max(60)`.
If the challenge is already expired, `expires_at - now_unix` is negative, so
`.min` picks it and `.max(60)` lifts it to 60. **An expired gate comes back with
60 more seconds.** The arithmetic assumes the store never returns an expired
entry, which is exactly the clause neither store implements.

### 2.4 What is not measured

- **How late an alarm fires in production.** Nobody has deployed this tree. I
  make no claim about the typical window, only that the design has no read-time
  bound and that a failed alarm delete leaves it unbounded.
- **A live demonstration.** Under `wrangler dev`, a code staged with a past
  `expires_at` sets an alarm in the past, which fires at once and hides the
  defect. The read-time check therefore cannot be shown live without clock
  control; §6 says how it is verified instead.

## 3. Why it matters

RFC 6749 §4.1.2 requires authorization codes to expire shortly after issue.
cesauth sets 60 seconds and then enforces it only through a cleanup mechanism.
The WebAuthn nonce is the freshness bound of a ceremony, and the TOTP gate
bounds how long a password-less first factor may wait for its second. Each of
those bounds is currently a best-effort cleanup, not a check.

It is the same class as RFC 139 (a lifetime written down and enforced nowhere),
in a different store.

## 4. Design

### 4.1 The clock is an argument

`peek` and `take` gain `now_unix: i64`:

```rust
async fn peek(&self, handle: &ChallengeHandle, now_unix: i64) -> PortResult<Option<Challenge>>;
async fn take(&self, handle: &ChallengeHandle, now_unix: i64) -> PortResult<Option<Challenge>>;
```

The precedent is in the same file: `RefreshTokenFamilyStore::revoke(…, now_unix)`
and `ActiveSessionStore::revoke(…, now_unix)`. With an argument instead of a
clock inside the store, the in-memory store stays deterministic, and every
expiry boundary becomes a host test.

### 4.2 The rule

- **Expired iff `now_unix >= expires_at`**, matching `AnonymousSession::is_expired`
  (`core/src/anonymous.rs:104`, "expires_at == now counts as expired").
- **`take` of an expired entry deletes it and returns `None`.** Taking stays
  single-use whether or not the entry has expired, and no expired value ever
  leaves the store.
- **`peek` of an expired entry returns `None`** and does not delete. `peek`
  stays read-only.
- **`bump_magic_link_attempts` on an expired entry returns `NotFound`**, as its
  doc already says ("absent / expired").
- The Durable Object receives `now_unix` inside the command (`Peek { now_unix }`,
  `Take { now_unix }`, `Bump { now_unix }`), from the adapter wrapper. It does not
  read its own clock, so both stores apply one rule to one input.
- **The alarm handler propagates the delete error** (`?`) instead of discarding
  it. It becomes cleanup, and correctness no longer depends on it.

### 4.3 Callers

Every call site passes the `now` it already has (`input.now_unix` in core; the
`now` / `now_unix` each route already computes). **No caller adds its own expiry
check.** The rule lives in the store. `magic_link::verify`'s own check stays; it
is part of that function's tested contract and costs nothing.

`totp/verify.rs:367`'s arithmetic becomes correct once no expired entry
reaches it. **No change to it here**, beyond a test that an expired gate is
rejected.

## 5. Non-goals

- No change to TTL values, the storage layout, alarm scheduling or wire error
  shapes. An expired code at `/token` is the same `invalid_grant` as an unknown
  one.
- Not RFC 117's typestate pipeline, which encodes this rule afterwards.
- Not RFC 139 (refresh-token lifetime). Same class, different store.
- Not a clock-skew policy. One `now` per request, as today.

## 6. Testing

1. **Store contract, in-memory:** for `peek`, `take` and `bump`, at
   `now = expires_at - 1` the entry is present; at `now = expires_at` it is
   absent. A `take` at expiry removes the entry, so a later `take` at an earlier
   `now` still returns `None`.
2. **`/token`:** an expired code is `InvalidGrant` with **the same message** as an
   unknown code (RFC 117 invariant 4: indistinguishable from absent).
3. **TOTP gate:** an expired `PendingTotp` is rejected by verify and by recover,
   and is not re-parked.
4. **WebAuthn:** an expired ceremony challenge is rejected.
5. **Fires / does-not-fire:** remove the in-memory store's expiry comparison and
   show tests 1–2 fail; restore and show them pass.
6. **Durable Object:** not host-testable. Verified by a mechanical assertion:
   `Command::Peek` and `Command::Take` both compare `now_unix` with
   `expires_at()`, and the alarm handler contains no `let _ =`. It must not be
   claimed as live-verified (§2.4).

## 7. Acceptance criteria

1. Both stores implement §4.2, and the port's doc comment states the boundary.
2. §6 tests 1–5 are green, and the fires pair is shown.
3. Every existing test passes. Tests change only by passing a `now`, never by
   changing an assertion.
4. No caller of `peek`/`take` contains its own challenge-expiry comparison added
   by this RFC.

## 8. Risks

- **Every call site changes signature**: 31 matches by the §2.2 command, 21 of
  them in tests, plus core's multi-line call. This is mechanical, and the
  compiler finds every one it misses.
- **A caller passing the wrong `now`** (0, or a stale value) would make every
  challenge look live. Mitigation: each caller already computes `now` for other
  purposes, and review checks that it passes that value.

## 9. Level

**Patch.** A contract clause the code already claims is not implemented. Nothing
new becomes possible.

## 10. Implementation review (2026-09-15)

Landed in `4b22cb5` and accepted without a correction cycle.

- **Verified:**
  - 1,436 host tests (1,429 + 7), with all seven new tests by name.
  - The runtime smoke check.
  - Both sides of the DO wire carry `now_unix` under the same name and tag.
  - Every production `now` comes from `OffsetDateTime::now_utc()` or
    `input.now_unix`.
  - **Live:** an unknown code at `/token` returns `400 invalid_grant`, not the
    `500` a command mismatch would produce.
- **The TOTP GET path now reads a clock.** It read none before. Rendering the
  page for an expired gate was the defect, so reading the real clock is the
  intent of §4.3, not a departure from it.
- **Test 5 runs against core's `StubCodes`, not the in-memory store.** `cesauth-core`
  cannot dev-depend on `cesauth-adapter-test`. Each store has its own fires pair.
- **WebAuthn expiry has no host test.** The finish handlers take
  `worker::Request`. They are covered by the shared store rule.
- **Recorded, no change:** the DO's `Peek`/`Take` turn a storage *read* error into
  "absent" (`.ok().flatten()`). This predates the RFC and fails closed.
