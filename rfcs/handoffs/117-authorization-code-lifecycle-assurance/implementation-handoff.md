# Developer Handoff — RFC 117, authorization-code lifecycle assurance (P0)

**Governing RFC.** [`rfcs/accepted/117-authorization-code-lifecycle-assurance.md`](../../accepted/117-authorization-code-lifecycle-assurance.md) — read **§2a, §2b and §2c** first. They correct five premises of the original text, and §2c carries the rulings below.
**Target release.** The first release after 0.84.0. **Level: patch** — the wire
does not change, no capability is added, and nothing that was broken is fixed.
It is internal hardening plus tests. Re-check at the cut if anything else rides
along.
**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** **The 0.84.0 tag. Do not start before it exists.** 0.84.0 is
ready but untagged, and code landing on `main` ahead of a pending cut is what
cancelled 0.83.2.

---

## 1. Purpose

After this, minting tokens from an authorization code is **unreachable** except
from a value that proves, in the type system, that the code was consumed, that
it belonged to the authenticated client, that the redirect URI matched, and that
PKCE verified — in that order. A future refactor that mints before verifying
will not compile.

## 2. Why this matters

`exchange_code` performs the right sequence today, procedurally. Every control
in it is one edit away from being reordered or dropped, and only example-based
tests would notice. This is the highest-value flow in an IdP, and its history in
this repository is the argument: RFC 137 found that the client binding and
client authentication were **missing outright**, and RFC 140 found that expiry
was enforced nowhere. Both were single missing lines in a procedural chain.

## 3. Resolved decisions — do not re-open

| Decision | Ruling |
|---|---|
| Error type | **`CoreError`, not a new `ExchangeError`.** §7.1's sketch had one; a second error type would need a mapping layer, and the wire shapes are pinned by existing tests. Each transition returns exactly the `CoreError` that line returns today |
| What `bind_client` takes | **An `AuthenticatedClient`**, not a `&ClientId` (§2a). Its only constructor runs `authenticate_token_client`, so "bound to the client" cannot be satisfied by passing the code's own id back to itself |
| Order | authenticate → `take` → `bind_client` → `bind_redirect` → `verify_pkce` → mint. Authentication precedes consumption (RFC 137 §13.1); the client comparison follows `take` (RFC 137 T1), so a wrong-client attempt still consumes the code |
| Expiry | **The store's**, via RFC 140. `ConsumedCode::take` passes `now_unix` and treats `None` as today's `InvalidGrant("code is unknown or already used")`. Add **no** expiry comparison in the pipeline |
| `MintInput` | Private fields plus accessors, constructed only by `VerifiedExchange::into_mint_input`. A pub-field struct would satisfy §14's grep and still be constructible elsewhere |
| Scope of "cannot mint" | The **code-exchange** path only. `rotate_refresh` also signs access tokens (§2b.4); it is RFC 118's, and it is not touched |
| `rotate_refresh` | **Not in scope** (RFC §15, RFC 118) |
| Proptest home | `cesauth-adapter-test` gains `proptest` as a **dev-dependency** (`{ workspace = true }`, as `cesauth-core` has it). The store state-machine test lives beside the store it exercises |
| RFC 121 | Proposed, not accepted (§2b.3). Build the harness for `AuthChallengeStore` alone; RFC 121 may generalise later |

## 4. Facts already measured — do not re-derive

| Fact | Where |
|---|---|
| Today's sequence, post-RFC-137/140 | `core/src/service/token.rs:108-170`: `find_auth_view` → `authenticate_token_client` → `take(code, now_unix)` → destructure `Challenge::AuthCode` → client compare → redirect compare → `ChallengeMethod::parse` + `pkce::verify` → mint |
| `ExchangeCodeInput` | `service/token.rs:75-87`: `code: &ChallengeHandle`, `redirect_uri`, `client_id`, `client_secret: Option<&str>`, `code_verifier`, `now_unix` |
| `Challenge::AuthCode` fields | `ports/store.rs:29-46`, including `client_id`, `redirect_uri`, `user_id`, `scopes`, `nonce`, `code_challenge`, `code_challenge_method`, `issued_at`, `expires_at`, `auth_time` |
| PKCE API | `oidc/pkce.rs`: `ChallengeMethod::parse(&str)`, `verify(verifier, challenge, method)`. S256 only |
| Id-token builder | `oidc/id_token.rs:88-97` — `build_id_token_claims(iss, user, client_id, scopes, nonce, auth_time, issued_at, ttl)` |
| Client authentication | `service/client_auth.rs::authenticate_token_client(&ClientAuthView, Option<&str>)`, RFC 137 §13 |
| Newtypes exist | `ChallengeHandle`, `ClientId`, `UnixSeconds` in `core/src/types` |
| `proptest` is a dev-dep of `cesauth-core` only | `crates/core/Cargo.toml:74-80`; `crates/adapter-test/Cargo.toml:27-28` has `tokio` alone |
| **No PKCE property test exists** (§2b.2) | `grep -rln 'proptest!' crates` → `jwt/proptests.rs`, `oidc/authorization/redirect_uri_proptests.rs`, `types/ids/tests.rs`, `types/secret/tests.rs`. PKCE has example tests only |
| Core's doctests run | `crates/core/Cargo.toml` `[lib]` sets no `doctest = false`, so `compile_fail` works |
| Baseline | 1,453 host tests (RFC 139), unchanged by R5f |

*If any of this fails to reproduce, that is a finding. Report it.*

## 5. Change scope

| # | Task | Files |
|---|---|---|
| T1 | **The pipeline module.** `AuthenticatedClient`, `ConsumedCode`, `ClientBoundCode`, `RedirectBoundCode`, `VerifiedExchange`, `MintInput`. All fields private; every transition takes `self` by value; no `Clone`, no `Copy`, no public constructors. Transition tests per state | new `core/src/service/token/exchange_pipeline.rs` (+ `exchange_pipeline/tests.rs`) |
| T2 | **`exchange_code` becomes the driver** — a linear chain over T1. Behaviour identical; every error is the one that line returns today | `service/token.rs` |
| T3 | **`compile_fail` doctest**: constructing `MintInput`, or a `VerifiedExchange`, outside the module does not compile | `exchange_pipeline.rs` |
| T4 | **Store state-machine property test** (RFC §7.3), against `InMemoryAuthChallengeStore`: generated sequences of `Put`, `Peek`, `Take`, `Bump`, `AdvanceClock`, asserting the contract's clauses (§6) | `adapter-test/Cargo.toml`, new `adapter-test/src/store/auth_challenge_proptests.rs` |
| T5 | **PKCE property test**: `verify(v, c, S256)` succeeds **iff** `c` is the base64url-unpadded SHA-256 of `v` | `core/src/oidc/pkce/proptests.rs` |

**Order: T1 → T2 → T3 → T4 → T5.** T1 lands with its own tests before
`exchange_code` moves onto it, so a failure in T2 is attributable to the driver
rather than the types.

## 6. T4 — the clauses to assert

The contract, as `ports/store.rs` now states it after RFC 140:

1. **No overwrite.** `put` on an occupied handle is `Conflict`, and the stored
   value is unchanged.
2. **At most one successful `take` per handle**, across any interleaving.
3. **Expiry is absence.** At `now >= expires_at`: `peek` is `None` and does not
   delete, `take` is `None` **and removes the entry**, `bump` is `NotFound`.
4. **A successful `take` implies a prior `put`** of that value: nothing is
   invented.

`AdvanceClock` is a generated monotonic `now` passed to the operations — the
store holds no clock (RFC 140 §4.1). Generate expiry times both ahead of and
behind the clock, so expired handles occur by construction and not by luck.

## 7. The traps — each compiles and ships the defect

**7.1 A transition that accepts what it should compare.** `bind_client(self,
presented: &ClientId)` type-checks when handed the code's own `client_id`. §3's
`AuthenticatedClient` is the fix: it can only come from a successful
authentication.

**7.2 A getter that leaks the whole state.** `ConsumedCode::fields()` returning a
struct, or `pub(crate)` fields, makes the states decorative — anything can then
assemble a `MintInput`. Only `VerifiedExchange::into_mint_input` produces one.

**7.3 A `Clone` derive.** With `Clone`, a `VerifiedExchange` can be minted twice
from one code. The states are move-only by design.

**7.4 Reordering while "preserving behaviour".** The chain's order is RFC 137's
ruling, not style: authenticate before `take`, compare the client after it.

**7.5 Changing an error on the way through.** Existing tests pin the wire. If a
transition's natural error differs from today's, **report it** rather than
changing either side.

**7.6 A property test that proves nothing.** A generator that never produces an
expired entry, or a PKCE strategy that only produces matching pairs, passes
vacuously. Both halves of "iff" need coverage: state the proportion of generated
cases that were expired, and that were mismatched, and show it is not ~0.

## 8. Mechanical assertions

```sh
# MintInput is constructed in exactly one file
grep -rn 'MintInput' crates/core --include='*.rs' | grep -v 'exchange_pipeline'
#   → uses only (type annotations, accessor calls), never a literal

# the states are move-only
grep -n 'derive' crates/core/src/service/token/exchange_pipeline.rs
#   → no Clone, no Copy on the five state types

# no field of a state type is public
grep -nE 'pub (\w+):' crates/core/src/service/token/exchange_pipeline.rs || echo "clean"

# the driver is a chain, not a re-implementation
grep -nE 'pkce::verify|ChallengeMethod::parse|\.take\(' crates/core/src/service/token.rs
#   → none: they live in the pipeline now

# proptest is a dev-dependency only
grep -n -A3 'dev-dependencies' crates/adapter-test/Cargo.toml
```

## 9. Required tests and evidence

**Transitions (T1):** wrong client, wrong redirect URI, wrong verifier, a
handle that is absent, a handle whose challenge is not an `AuthCode`, and the
happy path. Each asserts the **exact** `CoreError` today's code returns.

**Driver (T2):** every existing token test passes **unchanged**. This is the
gate on the refactor: an assertion that needs editing means behaviour moved.
**Report it instead of editing it.**

**T3:** the `compile_fail` doctest, shown in the `cargo test` output.

**T4/T5:** the property tests, with §7.6's coverage figures.

**Fires / does-not-fire:**
- Reorder the driver to verify PKCE **after** minting — it must **not compile**.
  Capture the compiler error. That is this RFC's whole point, and a
  demonstration that it merely fails a test would miss it.
- Remove the comparison inside `bind_client` (keeping the signature) → the
  wrong-client transition test and the existing RFC 137 tests go red; restore →
  green.

**Gate set.** The full set, with host tests stated as the command and its summed
`test result` lines (baseline **1,453** plus the new ones), and the bundle with
`du -b`, gzip and `sha256sum`.

I re-run the token tests, the property tests and the compile-fail demonstration
myself.

## 10. What must NOT be claimed

- **Not that the refresh path is protected.** `rotate_refresh` still mints
  procedurally (RFC 118).
- **Not that one-time use is newly guaranteed.** The store already guaranteed
  it; T4 pins it against arbitrary interleavings **in the in-memory store**. The
  Durable Object is not host-testable.
- Not that expiry is enforced here. It is the store's (RFC 140).
- Not that it works on Cloudflare. Not that CI has run it.

## 11. Prohibited shortcuts

- No `#[allow(dead_code)]` to keep an unused state alive — if a state has no
  transition, the design is wrong; report it.
- No `pub` fields, no `Clone`/`Copy` on the states, no public constructor.
- No assertion edited in an existing test (§9).
- No `#[ignore]`, no `continue-on-error`, no `cargo fmt`.

## 12. Acceptance criteria

RFC 117 §14, as corrected by §2a–§2c. Checked hardest: **criterion 1**
(`MintInput` constructed only inside the module), **criterion 3** (invariant 2 is
verifiable by reading the pipeline module alone), and the **non-compiling**
reorder in §9.

## 13. Known risks

| Risk | Mitigation |
|---|---|
| Typestate ergonomics creep | Five states, one module, RFC §13. If it exceeds ~250 lines, stop and report |
| A behaviour change hidden as a refactor | §9's rule: existing assertions are untouchable |
| A vacuous property test | §7.6's coverage figures |
| The pipeline duplicating the store's expiry rule | §3; §8's driver assertion |

**If the work turns out materially larger than scoped, stop and report.**

## 14. Review request

To `.git-exclude/review-request/`: implementation summary, changed files, the
§8 assertion output, the transition and property tests with §7.6's figures, the
compile-fail output, both fires demonstrations, the gate set, and anything you
had to report rather than change (§7.5, §9).

**Do not cut a release, bump a version, or create a tag.**

Report the path only.
