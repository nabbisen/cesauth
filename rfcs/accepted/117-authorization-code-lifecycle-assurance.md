# RFC 117 — Authorization code lifecycle assurance

**Status.** Accepted — approved by the owner 2026-09-12.
**Tier.** P0 · Category A
**Size.** Medium
**Tracks.** Strategy §5.1, §8 (RFC theme 2); audit G4.
**Touches.** `crates/core/src/service/token.rs` (exchange path),
`crates/core/src/oidc/{authorization, pkce}.rs`,
`crates/core/src/ports/store.rs` (docs only), new
`core/src/service/token/exchange_pipeline.rs`.
**Depends on.** RFC 116 (uses `ClientId`, `ChallengeHandle`, newtypes).

## 1. Summary

Encode the authorization-code exchange as a typestate pipeline so token
minting is only reachable from a value proving that consumption, client
binding, redirect-URI binding, and PKCE verification have all happened —
in that order. Add state-machine property tests over the
`AuthChallengeStore` one-time-consumption contract.

## 2. Motivation

`exchange_code` currently performs the correct sequence
(`take` → client/redirect binding checks → `pkce::verify` → mint), but
the ordering is procedural. A refactor could mint before verifying PKCE
and only example-based tests would notice. RFC 9700 §2.1.1 (one-time
codes) and §4.8 (PKCE downgrade) invariants deserve structural
enforcement: this is the single highest-value flow in an IdP.

## 2a. Premise correction — one of the four checks does not exist

**Added 2026-09-12, on acceptance**, from measuring `exchange_code` before
writing this RFC's handoff.

§2 above states that `exchange_code` *"currently performs the correct sequence
(`take` → client/redirect binding checks → `pkce::verify` → mint)"*. **It does
not.** There is no client binding check, and `/token` does not authenticate the
client either:

- `Challenge::AuthCode` carries `client_id` (`ports/store.rs:30`); the
  destructure at `service/token.rs:128-138` discards it via `..` and nothing
  compares it to the presented `client_id`.
- `client_secret` is parsed at `routes/oidc/token.rs:33` and never read again —
  `ExchangeCodeInput` has no field for it.

So **§5 invariant 3 describes behaviour cesauth does not have**, and PKCE is
the only thing binding a code to its redeemer. **RFC 137** fixes both and is
sequenced ahead of this RFC.

This sharpens rather than weakens the design. `bind_client` was going to be a
no-op rename of an existing check; it now encodes a control RFC 137 introduces,
and the typestate makes deleting it again unwritable. **Fix first, then encode.**

Two consequences for the work here:

- The pipeline's `bind_client` transition must compare against the code's own
  stored `client_id` — not merely accept a `ClientId` argument. A transition
  that takes the presented value and returns `ClientBoundCode` without
  comparing would reproduce today's defect in types that claim otherwise.
- `ConsumedCode` must carry `client_id` out of the challenge. §7.1's comment
  says its fields come "from `Challenge::AuthCode`"; that must include the one
  the current code drops.

## 2b. Premise corrections — measured before the handoff (2026-09-15)

RFC 137 has shipped (v0.83.1), so §2a's missing checks now exist. Measuring
the code again before writing the handoff found four more premises that do not
hold. **The handoff waits on the first.**

1. **§3's "expiry = absence" is not implemented by either store.** The
   `AuthChallengeStore` contract requires it; the Durable Object and the
   in-memory store both return expired entries, and only a DO alarm, whose
   failures are discarded, removes them. No service code checks `expires_at` on
   an authorization code. **RFC 140** fixes this and is sequenced ahead of this
   RFC, on the same "fix first, then encode" rule as RFC 137. §5 invariant 4 and
   §7.3's third clause describe behaviour RFC 140 introduces.
2. **There are no PKCE property tests to extend** (§10). The `proptest!` files
   are `jwt/proptests.rs`, `oidc/authorization/redirect_uri_proptests.rs`,
   `types/ids/tests.rs` and `types/secret/tests.rs`
   (`grep -rln 'proptest!' crates`). PKCE has example tests only
   (`oidc/pkce/tests.rs`). The PKCE property test is new work, not an extension.
3. **RFC 121 is Proposed, not accepted.** §4 and §7.3 share a harness with it.
   This RFC builds its store state-machine test for `AuthChallengeStore` alone.
   RFC 121 may generalise it later, and nothing here waits on RFC 121.
4. **`MintInput` cannot be the sole input of "the token builders."**
   `rotate_refresh` signs access tokens too (`service/token.rs:404`). The
   typestate governs the **code-exchange** mint only. §14 criterion 1 is about
   constructing `MintInput`, which still holds; the §7.1 sentence "cannot be
   written" is scoped to the exchange path.

**One design ruling carried into the handoff.** After RFC 137, authentication
precedes `take`. `bind_client` must therefore take proof that the client
authenticated, not a bare `&ClientId`. A bare `ClientId` could be the code's own
stored id, and the transition would then compare a value with itself.

## 2c. Design rulings for the handoff (2026-09-16)

RFC 140 has landed, so §2b.1's blocker is cleared. Writing the handoff settled
the remaining open shapes.

- **Errors stay `CoreError`.** §7.1's `ExchangeError` would need a mapping layer
  back to the wire, and the wire shapes are pinned by existing tests. Each
  transition returns the error that line returns today.
- **`bind_client` takes an `AuthenticatedClient`**, whose only constructor runs
  `authenticate_token_client` (§2a). A transition taking a bare `ClientId` would
  accept the code's own id and compare a value with itself.
- **`MintInput` has private fields and accessors.** §14's criterion is that it
  is constructed only inside the module; a pub-field struct would pass the grep
  and still be constructible anywhere.
- **Expiry is not re-checked in the pipeline.** RFC 140 made it the store's, and
  `ConsumedCode::take` passes `now_unix`.
- **The store state-machine test lives in `cesauth-adapter-test`**, which gains
  `proptest` as a dev-dependency. Its clauses now include RFC 140's
  expiry-is-absence.
- **Level: patch.** No wire change, no added capability, nothing fixed — internal
  hardening and tests.
- **Sequenced after the 0.84.0 tag.** The handoff is written; it is not
  dispatched while a cut is pending, which is what cancelled 0.83.2.

## 3. Background

Codes live as `Challenge::AuthCode` in the AuthChallenge DO. The store
contract already guarantees atomic `take` (no double-consumption at the
storage layer — this RFC does **not** re-solve that). What is missing is
(a) a compile-time proof that validation precedes minting, and
(b) generated-sequence tests that the contract holds under arbitrary
interleavings against any store implementation.

## 4. Target code areas

- New `core/src/service/token/exchange_pipeline.rs` — typestate types.
- `core/src/service/token.rs::exchange_code` — rewritten as pipeline
  driver; wire behaviour unchanged.
- `core/src/service/token/tests.rs` + new
  `exchange_pipeline/proptests.rs`.
- `crates/adapter-test` conformance suite — store-contract
  state-machine test (shared with RFC 121 harness).

## 5. Security properties / invariants

1. **One-time use.** A code yields tokens at most once (already
   storage-enforced; now also pinned by generated tests).
2. **No mint before validation.** Token issuance is unreachable
   without prior client-binding, redirect-binding, and PKCE proofs.
3. **No cross-request mixing.** `client_id`, `redirect_uri`,
   `code_challenge`, and the subject are those captured at code-mint
   time; the exchange compares, never substitutes.
4. **Expiry.** An expired code is indistinguishable from an absent one.
5. **Failure consumes.** A code that fails validation after `take` is
   gone — failure must not return it to the store.

## 6. Non-goals

- No change to the DO storage layout, code TTLs, or error wire shapes.
- No typestate for `PendingAuthorize`, WebAuthn, Magic Link, or TOTP
  challenges (RFC 121 covers their testing; their flows are simpler).
- No support for non-PKCE exchanges (S256 remains mandatory).

## 7. Proposed design

### 7.1 Typestate pipeline

```rust
// exchange_pipeline.rs — all fields private; module is the capability boundary
pub struct ConsumedCode      { /* fields from Challenge::AuthCode */ }
pub struct ClientBoundCode   { inner: ConsumedCode }
pub struct RedirectBoundCode { inner: ClientBoundCode }
pub struct VerifiedExchange  { inner: RedirectBoundCode }   // the mint license

impl ConsumedCode {
    /// Only constructor: takes the challenge from the store, atomically.
    pub async fn take<S: AuthChallengeStore>(
        store: &S, handle: &ChallengeHandle, now: UnixSeconds,
    ) -> Result<Self, ExchangeError>;          // absent/expired → InvalidGrant

    pub fn bind_client(self, presented: &ClientId)
        -> Result<ClientBoundCode, ExchangeError>;
}
impl ClientBoundCode {
    pub fn bind_redirect(self, presented: &str)
        -> Result<RedirectBoundCode, ExchangeError>;
}
impl RedirectBoundCode {
    pub fn verify_pkce(self, verifier: &str)
        -> Result<VerifiedExchange, ExchangeError>;  // delegates to oidc::pkce
}
impl VerifiedExchange {
    // The ONLY way the rest of token.rs obtains claims input.
    pub fn into_mint_input(self) -> MintInput;
}
```

Each transition consumes `self`; states are not `Clone`; constructors
outside the module do not exist. `MintInput` is the sole argument type
of the id/access/refresh-token builders, so "mint without
`VerifiedExchange`" cannot be written. Failure at any stage drops the
value — combined with the store's `take`, this realises invariant 5.

### 7.2 Driver

`exchange_code` becomes a linear `?`-chain over the pipeline. Error
mapping to OAuth error codes (`invalid_grant`, `invalid_client`) is
preserved exactly; existing tests pin the wire shapes.

### 7.3 State-machine property test (store contract)

A `proptest` strategy generates operation sequences
`{Put, Peek, Take, AdvanceClock}` against any `AuthChallengeStore` and
asserts the contract's three clauses (no overwrite; at-most-one
successful `take` per handle; expiry = absence). Runs against the
in-memory adapter in CI; the harness is shared with RFC 121.

## 8. Data model impact

None.

## 9. API impact

None on the wire. `core::service::token` public functions keep their
signatures (modulo RFC 116 newtypes).

## 10. Testing strategy

- All existing token-exchange tests pass unchanged (wire compatibility).
- New unit tests per transition: wrong client, wrong redirect, wrong
  verifier, expired, replayed handle.
- Property test: for arbitrary generated `(challenge, presented)` pairs,
  `verify_pkce` succeeds iff `S256(verifier) == challenge` (extends the
  existing PKCE proptests).
- Store-contract state-machine test as §7.3.
- Doc-test with `compile_fail` showing `MintInput` is unconstructible
  without the pipeline.

## 11. Migration strategy

Additive module + rewrite of one driver function. Single phase.

## 12. Rollout plan

One minor release, after RFC 116. CHANGELOG: internal hardening; no
operator action.

## 13. Risks and mitigations

- **Typestate ergonomics creep** → the pipeline has exactly four states
  and lives in one ~200-line module; strategy §9 anti-explosion
  guidance honoured.
- **Wire regressions in error mapping** → existing error-shape tests
  are the gate; no test may be edited to pass.

## 14. Acceptance criteria

1. `rg "MintInput" crates/core` shows construction only inside
   `exchange_pipeline.rs`.
2. New transition tests + state-machine test green; full suite green.
3. A reviewer can verify invariant 2 by reading only
   `exchange_pipeline.rs` (no whole-crate reasoning required).

## 15. Open questions

- Should `rotate_refresh` adopt the same pipeline shape? Covered
  separately in RFC 118 (its lifecycle authority is the DO, where
  typestate adds less; tests add more).

## 16. Implementation review (2026-09-22)

T1–T5 landed in `99feadb` and are accepted. **Level: patch**, confirmed at
review.

**Verified:** 1,482 host tests (1,453 + 29); the five doctests, proved
non-vacuous from outside the repo against a compiling control; `MintInput`
constructed nowhere in `crates/core` but the pipeline module; states move-only
with no `derive`; and, re-run by the reviewer, deleting the PKCE step from the
driver so the mint reads a `RedirectBoundCode` **fails to compile**
(`E0599: no method named 'into_mint_input'`).

**C1-117, both raised by the implementer:**

1. **`ConsumedCode::take` will take `&AuthenticatedClient`.** The types proved
   the order of the four checks but not that authentication preceded
   consumption: swapping the driver's first two steps still compiled, leaving
   RFC 137 §13.1 held by line order and tests alone. The proof is carried, not
   compared — `bind_client` still compares, after `take`, so a wrong-client
   attempt continues to consume the code.
2. **The `put` clause goes into the port contract.** `put` refuses an occupied
   handle with `Conflict` whether or not the stored entry has expired; RFC 140's
   "past `expires_at` is absent" governs `peek`, `take` and `bump`. Both stores
   already behave this way and neither changes; the contract was silent, which
   is the defect.

**Recorded, no change:** `MintInput` shares its name with an unrelated
admin-console type in `crates/frontend`. Criterion 1 is scoped to `crates/core`,
where the grep is clean; a workspace-wide search shows both.

**A measurement worth keeping.** Two of the four `pkce::verify` mutations
survive a property whose inputs are arbitrary strings — random inputs never come
near a match — and are caught only by the structured-case property. The weak
property was kept with its blind spot stated, rather than deleted.
