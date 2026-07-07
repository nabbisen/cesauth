# RFC 117 — Authorization code lifecycle assurance

**Status.** Proposed
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
