# Developer Handoff — RFC 140, challenge stores enforce expiry at read (P1)

**Governing RFC.** [`rfcs/accepted/140-challenge-expiry-at-read.md`](../../accepted/140-challenge-expiry-at-read.md). Read §2 for the evidence and §4 for the design.
**Target release.** 0.83.2. **Level: patch.** The store contract already
requires this, and neither implementation does it. That is a fix, and nothing
new becomes possible.
**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **RFC 117 and RFC 139 wait on this.** Do not start
either.

---

## 1. Purpose

After this, an authorization code, a WebAuthn ceremony nonce, a TOTP gate and a
parked authorization request are **absent at or after their `expires_at`**, in
both stores, whether or not the Durable Object's alarm has run.

## 2. Why this matters

Expiry is currently cleanup, not a check. The DO returns whatever it holds, and
the alarm that deletes it discards its own failure. Four of six challenge kinds
have no other expiry check (RFC §2.2). One of them, the TOTP gate, re-parks an
expired challenge with 60 more seconds (RFC §2.3).

## 3. Resolved decisions — do not re-open

| Decision | Ruling |
|---|---|
| Where the clock comes from | **An argument.** `peek(handle, now_unix)`, `take(handle, now_unix)`, `bump_magic_link_attempts(handle, now_unix)`. No store reads a clock |
| The boundary | **Expired iff `now_unix >= expires_at`** |
| `take` on an expired entry | **Deletes it, returns `None`** |
| `peek` on an expired entry | **Returns `None`, does not delete** |
| `bump` on an expired entry | **`NotFound`**, the variant it already returns for absent |
| The DO | `now_unix` travels **inside** the command: `Peek { now_unix }`, `Take { now_unix }`, `Bump { now_unix }` |
| The alarm | Propagates the delete error with `?`. No `let _ =` |
| Callers | Pass the `now` they already compute. **No caller adds its own expiry check** |
| Wire | Unchanged. An expired code is `invalid_grant` with **the same message** as an unknown code |
| `totp/verify.rs:367` arithmetic | **Not changed.** It is correct once expired entries stop reaching it |
| `magic_link::verify`'s own check | **Stays** |

## 4. Facts already measured — do not re-derive

| Fact | Where |
|---|---|
| Contract clause | `ports/store.rs`, doc comment on `trait AuthChallengeStore`: "Treat entries past `expires_at` as absent (`None`)" |
| `Challenge::expires_at()` exists for every variant | `ports/store.rs:117-127` |
| DO returns without checking | `adapter-cloudflare/src/auth_challenge.rs`, `Command::Peek` / `Command::Take` |
| Alarm discards failure | same file, `async fn alarm`: `let _ = …delete(KEY)` |
| DO wire enums | DO side: `enum Command` / `enum Outcome` in `auth_challenge.rs`. Adapter side: `enum ChallengeCmd` / `enum ChallengeReply` in `adapter-cloudflare/src/ports/store/auth_challenge.rs`. **Both sides must change together** |
| In-memory store has no clock | `adapter-test/src/store/auth_challenge.rs:25-33` |
| Implementations of the trait | 3: `InMemoryAuthChallengeStore`, `CloudflareAuthChallengeStore`, and **`StubCodes` in `core/src/service/token/tests.rs:135`** (`grep -rn 'impl AuthChallengeStore for' crates`) |
| Call sites | 31 by `grep -rnE '\.(take|peek)\(' crates --include='*.rs' \| grep -E 'ChallengeHandle\|deps\.codes\|challenges\.\|store\.(take\|peek)\('` (21 in tests), **plus** core's multi-line `deps.codes.take(input.code)` at `service/token.rs:129-130`, which that command does not match |
| Existing precedent for `now_unix` on a port | `RefreshTokenFamilyStore::revoke(…, now_unix)`, `ActiveSessionStore::revoke(…, now_unix)` |
| The walkthrough stages codes for 5 minutes | `docs/src/beginner/first-oidc-flow.md:172-173`, `EXP=$((NOW + 300))` |

*If any of this fails to reproduce, that is a finding. Report it.*

## 5. Change scope

| # | Task | Files |
|---|---|---|
| T1 | **Port.** Add `now_unix: i64` to `peek`, `take` and `bump_magic_link_attempts`. Rewrite the contract comment to state §3's boundary and the `take`/`peek`/`bump` behaviour exactly | `core/src/ports/store.rs` |
| T2 | **In-memory store** implements §3. **Contract tests** (§9 tests 1–4) | `adapter-test/src/store/auth_challenge.rs`, `adapter-test/src/store/tests.rs` |
| T3 | **`StubCodes`** implements §3 too. It is a store; a stub that ignores expiry would make test 5 unpassable, and "fixing" the test would encode the defect (RFC 137 §4.1, same lesson) | `core/src/service/token/tests.rs` |
| T4 | **DO and adapter**: the three commands carry `now_unix`; `Peek`/`Take`/`Bump` compare with `challenge.expires_at()`; an expired `Take` deletes before returning `None`; alarm uses `?` | `adapter-cloudflare/src/auth_challenge.rs`, `adapter-cloudflare/src/ports/store/auth_challenge.rs` |
| T5 | **Callers** pass their existing `now`. `core` passes `input.now_unix` | `core/src/service/token.rs`; the 10 non-test backend sites in RFC §2.2 |
| T6 | **Consumer tests** (§9 tests 5–7) | as each consumer's existing tests |
| T7 | **Walkthrough**: one sentence after step 4b, saying the staged code expires at `EXP` (five minutes) and that `/token` returns `invalid_grant` after that, so stage again if step 4c comes later | `docs/src/beginner/first-oidc-flow.md` |

**Order: T1 → T2 (with the fires pair) → T3 → T4 → T5 → T6 → T7.** T1 breaks
every call site at once. That is intended: the compiler lists them. **Do not
batch-edit call sites from the error list before T2 is green.** The contract
tests are what prove the rule; the call sites only pass a value.

## 6. Explicit non-change scope

- **Not RFC 117** (typestate pipeline) and **not RFC 139** (refresh lifetime).
- No change to any TTL value, to `set_alarm` scheduling, to the stored
  `Challenge` shape, or to any wire error.
- No expiry check added in any route or service. The rule is the store's.
- No change to `totp/verify.rs:367`'s arithmetic, or to `magic_link::verify`.
- Not `RefreshTokenFamilyStore` or `ActiveSessionStore`.
- No route strings. No `cargo fmt`. **Do not open `.dev.vars`.**

## 7. The traps — each compiles and ships the defect

**7.1 Passing a `now` that is not now.** `0`, a constant, or `issued_at` makes
every challenge live. In **production code**, every `now_unix` argument must be
the value that caller already computes from the real clock. Tests pass explicit
values chosen for the boundary.

**7.2 Returning the expired value from `take`.** "Delete, then return `None`" and
"delete, then return the value" differ by one token, and only the first is
right. Test 3 pins it.

**7.3 One side of the DO wire.** Adding `now_unix` to `ChallengeCmd` but not to
`Command` (or the reverse) compiles, because they are separate types in
separate crates, and fails only at runtime with `bad command` 400. The runtime
smoke check and the walkthrough are what catch it. Both are required (§9).

**7.4 A peek-then-take consumer with two different `now`s.** `totp/verify.rs`
peeks at `:116` and takes at `:289`, and `magic_link/verify.rs` and
`api_v1/anonymous.rs` also peek then take. Each request uses **one** `now` for
both calls.

**7.5 The alarm "fix" that swallows differently.** `.ok()`, `unwrap_or`, or
`if let Err(_)` are the same defect as `let _ =`. Propagate with `?`.

**7.6 The `>` / `>=` boundary.** `magic_link::verify` uses `now > expires_at`,
and this store rule is `>=`. That is deliberate (§3). Do not "harmonise"
`magic_link.rs`.

## 8. Mechanical assertions

```sh
# every DO read command compares with expiry
grep -n 'now_unix' crates/adapter-cloudflare/src/auth_challenge.rs
grep -n 'expires_at()' crates/adapter-cloudflare/src/auth_challenge.rs      # in Peek, Take and Bump, as well as Put

# both sides of the wire carry now_unix
grep -n 'now_unix' crates/adapter-cloudflare/src/ports/store/auth_challenge.rs

# the alarm no longer discards
grep -n -A4 'async fn alarm' crates/adapter-cloudflare/src/auth_challenge.rs | grep -c 'let _' # must be 0

# no caller grew its own expiry check
git diff -U0 -- crates/backend/src/routes crates/backend/src/post_auth.rs crates/core/src/service \
  | grep -E '^\+.*expires_at' || echo "clean"

# no production call passes a literal now
git diff -U0 -- crates/backend/src crates/core/src/service/token.rs \
  | grep -E '^\+.*\.(take|peek|bump_magic_link_attempts)\(.*,\s*(0|[0-9]+)\s*\)' || echo "clean"
```

## 9. Required tests and evidence

**New tests:**

*Store contract, in-memory (`adapter-test`)*
1. `peek` at `expires_at - 1` → `Some`; at `expires_at` → `None`; the entry is still
   present afterwards (a `peek` at `expires_at - 1` again → `Some`).
2. `take` at `expires_at - 1` → `Some`, then `take` → `None` (existing
   single-use, now with `now`).
3. `take` at `expires_at` → `None`, and **the entry is gone**: a later `take` at
   `expires_at - 1` also returns `None`.
4. `bump_magic_link_attempts` at `expires_at` → `NotFound`.

*Consumers*
5. `/token` (`service::token`): an expired code → `InvalidGrant` whose message
   **equals** the unknown-code message. Assert the equality, not two literals.
6. TOTP gate: an expired `PendingTotp` is rejected by verify and by recover, and
   verify **does not re-park it** (the store holds nothing at that handle
   afterwards).
7. WebAuthn: an expired ceremony challenge is rejected, if the existing test
   harness reaches those routes on the host. If it does not, **say so** and cover
   it only with the §8 assertions. Do not build a harness for it here.

**Fires / does-not-fire:** remove the in-memory store's expiry comparison →
tests 1, 3, 4 and 5 red; restore byte-identical → green. Use `--verbose` for any
drift-scan output.

**The documented walkthrough still works**: `first-oidc-flow.md` 4b → 4c → 5
against `wrangler dev`, run within the five minutes, with the output attached.
**Also stage a code whose `expires_at` is 5 seconds ahead, wait 10 seconds, and
redeem it** → `invalid_grant`. The alarm may already have deleted it, so this
proves nothing about the read-time check, and the package must not claim it
does. It **does** prove the DO wire works end to end (7.3), and it is the only
live evidence of that.

**Evidence.** You run the full gate set and send it:
- host tests (baseline **1,429**, plus the new ones), stated as the command and
  its summed `test result` lines;
- `migration_chain`, the wasm32 and csr checks;
- clippy over **six** crates;
- deny, audit, route-contracts, drift-scan `--verbose`, mdbook;
- `make build-frontend`, `make build-backend`;
- runtime smoke and the browser suite, each showing wrangler 4.131.2.

I re-run the store and token tests, the runtime smoke check and the live
walkthrough myself.

## 10. What must NOT be claimed

- **Not that the DO's read-time check is live-verified.** An alarm in the past
  fires at once and hides the difference (RFC §2.4). It is verified by code, the
  §8 assertions and the shared rule, not by a live run.
- **Not how late alarms fire in production.** Nobody has deployed this tree.
- **Not that refresh tokens expire.** RFC 139.
- Not that CI has run it.

## 11. Prohibited shortcuts

- No assertion changed in an existing test. Existing tests change only by
  passing a `now`, and that `now` must keep them inside the lifetime they
  already assume.
- No `#[ignore]`, no `continue-on-error`, no `cargo fmt`.
- No expiry check in a caller "for safety".
- No `let _ =`, `.ok()` or `unwrap_or` on the alarm's delete.

## 12. Acceptance criteria

RFC 140 §7. Checked hardest: **test 3** (an expired `take` removes the entry),
**test 5** (an expired code is indistinguishable from an unknown one), and
**7.3** (both sides of the DO wire, proven by the live expired-code run).

## 13. Known risks

| Risk | Mitigation |
|---|---|
| A caller passes a wrong `now` | 7.1; §8's literal-`now` assertion; review of every call site in the diff |
| DO wire mismatch | 7.3; runtime smoke; the live run |
| An existing test used a fixture `expires_at` in the past and passed only because nothing checked | **Report which, before changing it.** That test was relying on the defect, and its fixture is corrected, not its assertion |
| The walkthrough reader is slower than five minutes | T7 |

**If the work turns out materially larger than scoped, stop and report.**

## 14. Review request

To `.git-exclude/review-request/`:
- implementation summary and changed files;
- any existing test whose fixture expiry was in the past (§13);
- every log from §9, and the §8 assertion output;
- the fires pair;
- the walkthrough and live expired-code output;
- what remains unverified (§10), and requested review focus.

**Do not cut a release, bump a version, or create a tag.**

Report the path only.
