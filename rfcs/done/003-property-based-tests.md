# RFC 003: Property-based tests for crypto round-trips and `redirect_uri` matcher

**Status**: Implemented (v0.51.1)
**ROADMAP**: `## Planned (0.x) / Next minor releases` — "Property-based tests (`proptest`)"
**ADR**: N/A
**Estimated scope**: Small — 2 dev-dep additions, ~250 LOC test code, no production-code change

## Background

Two surfaces in cesauth have well-defined invariants and
adversarial input shapes that example-based tests can't
realistically cover:

1. **Crypto round-trips** — Ed25519 key-encoding parsing
   (PEM → DER → JWS → DER → PEM), JWT sign/verify,
   magic-link token mint/verify. The invariant is
   trivial to state ("decode-encode = identity, sign
   then verify = OK") but the input space is vast.
2. **`redirect_uri` matcher** — historically the most
   bug-prone OAuth provider component. cesauth's matcher
   in `oidc::redirect_uri::is_allowed` is straightforward
   today but has the open-redirect risk profile that
   makes property-based exploration valuable.

`proptest` is dev-dep only and adds no production
dependency cost.

## Decision / Plan

Add two property-based test modules to the existing test
suites; do not introduce a new test crate.

### Setup

`Cargo.toml` workspace dev-dependencies:

```toml
proptest = { version = "1", default-features = false, features = ["std"] }
```

`crates/core/Cargo.toml` `[dev-dependencies]`:

```toml
proptest.workspace = true
```

### Module A: Crypto round-trips

File: `crates/core/src/jwt/proptests.rs`. Gated
`#[cfg(test)]`, registered from `jwt.rs` as
`#[cfg(test)] mod proptests;`.

Properties:

1. **PEM → DER → PEM round-trip**:
   ```rust
   proptest! {
       #[test]
       fn ed25519_pem_round_trip(seed: [u8; 32]) {
           let key = Ed25519SigningKey::from_seed(&seed);
           let pem = key.to_pkcs8_pem();
           let parsed = Ed25519SigningKey::from_pkcs8_pem(&pem)?;
           prop_assert_eq!(key.public_key_raw(), parsed.public_key_raw());
       }
   }
   ```

2. **JWT sign-verify round-trip**:
   ```rust
   #[test]
   fn jwt_round_trip(
       seed: [u8; 32],
       sub: String,
       iss: String,
       aud: String,
       exp_offset in 1i64..86_400,
   ) {
       let key = Ed25519SigningKey::from_seed(&seed);
       let claims = AccessTokenClaims { sub, iss: iss.clone(), aud: aud.clone(), ... };
       let token = sign(&claims, &key, "test-kid")?;
       let decoded: AccessTokenClaims = verify(&token, key.public_key_raw(), &iss, &aud, 0)?;
       prop_assert_eq!(decoded, claims);
   }
   ```

3. **Magic-link token mint/verify round-trip**:
   Use the existing `magic_link::token::generate` /
   `verify`. The invariant: any subject string round-trips
   through generation + verification with equal subject.

4. **Tampered-byte rejection**: generate a valid JWT,
   flip a random byte, assert verify returns `Err`.
   ```rust
   #[test]
   fn jwt_tamper_detection(seed: [u8; 32], tamper_at in 0usize..200) {
       let token = sign_test_jwt(&seed)?;
       let mut bytes = token.into_bytes();
       if let Some(b) = bytes.get_mut(tamper_at % bytes.len()) {
           *b = b.wrapping_add(1);
       }
       let result = verify_jwt(std::str::from_utf8(&bytes)?);
       prop_assert!(result.is_err());
   }
   ```

### Module B: `redirect_uri` matcher

File: `crates/core/src/oidc/redirect_uri/proptests.rs`.

The matcher's intended behavior (already pinned by
example-based tests): exact byte-equal string match. No
prefix matching, no port stripping, no scheme inference.

Properties:

5. **Exact match always accepted**:
   ```rust
   #[test]
   fn matcher_accepts_byte_equal_uri(uri in valid_https_uri()) {
       let allowed = vec![uri.clone()];
       prop_assert!(is_allowed(&allowed, &uri));
   }
   ```

6. **Single-byte difference always rejected**:
   ```rust
   #[test]
   fn matcher_rejects_single_byte_diff(
       uri in valid_https_uri(),
       diff_at in 0usize..200,
   ) {
       let allowed = vec![uri.clone()];
       let mut tampered = uri.into_bytes();
       if let Some(b) = tampered.get_mut(diff_at % tampered.len()) {
           *b = b.wrapping_add(1);
       }
       let tampered_str = String::from_utf8_lossy(&tampered).to_string();
       prop_assert!(!is_allowed(&allowed, &tampered_str));
   }
   ```

7. **Trailing-slash difference rejected** (the classic
   open-redirect class):
   ```rust
   #[test]
   fn matcher_rejects_trailing_slash_difference(uri in valid_https_uri_no_trailing_slash()) {
       let allowed = vec![uri.clone()];
       prop_assert!(!is_allowed(&allowed, &format!("{uri}/")));
       prop_assert!(!is_allowed(&allowed, &format!("{uri}/path")));
   }
   ```

8. **Path-traversal in suffix never satisfies match**:
   ```rust
   #[test]
   fn matcher_rejects_appended_path(
       allowed_uri in valid_https_uri(),
       suffix in "[a-zA-Z0-9/_-]{1,30}",
   ) {
       let allowed = vec![allowed_uri.clone()];
       prop_assert!(!is_allowed(&allowed, &format!("{allowed_uri}/{suffix}")));
       prop_assert!(!is_allowed(&allowed, &format!("{allowed_uri}{suffix}")));
   }
   ```

9. **Port-stripping doesn't fool matcher**:
   ```rust
   #[test]
   fn matcher_distinguishes_port_explicit_vs_default(host in valid_host()) {
       let with_default = format!("https://{host}/cb");
       let with_443     = format!("https://{host}:443/cb");
       let allowed = vec![with_default.clone()];
       prop_assert!( is_allowed(&allowed, &with_default));
       prop_assert!(!is_allowed(&allowed, &with_443));
   }
   ```

The point of this property isn't that explicit-port URIs
are wrong (they're valid URIs); it's that the matcher
treats them as **distinct strings** and won't fold them
together — clients must register the exact URI they'll
present, including port, and that's by design.

10. **IDN doesn't bypass match**:
    ```rust
    #[test]
    fn matcher_does_not_normalize_idn(host in idn_compatible_host()) {
        let punycode = idna::domain_to_ascii(&host)?;
        let unicode  = host.clone();
        if punycode != unicode {
            let allowed = vec![format!("https://{punycode}/cb")];
            prop_assert!(!is_allowed(&allowed, &format!("https://{unicode}/cb")));
        }
    }
    ```

### Strategies

Helper strategy generators in
`crates/core/src/oidc/redirect_uri/proptests.rs`:

```rust
fn valid_https_uri() -> impl Strategy<Value = String> { ... }
fn valid_https_uri_no_trailing_slash() -> impl Strategy<Value = String> { ... }
fn valid_host() -> impl Strategy<Value = String> { ... }
fn idn_compatible_host() -> impl Strategy<Value = String> { ... }
```

Use `proptest::prelude::*` `prop_compose!` for these.
Cap host components to ASCII alphanumerics + `-` + `.`
(plus the IDN strategy uses a fixed set of unicode-host
samples — full IDN-fuzzing is out of scope; the goal is
to confirm the matcher doesn't normalize).

### Configuration

Default proptest config (256 cases per property) is
fine. CI run time impact is bounded: the workspace test
suite is fast; adding ~10 properties × 256 cases each is
negligible.

## Open questions

**Should `proptest` be a workspace-wide standard, or
limited to these two surfaces?** Decision: limit to these
two surfaces for now. proptest works best for code with
algebraic invariants; introducing it elsewhere (e.g.
storage adapters, audit log) adds noise without
proportional value. Revisit if a future surface develops
similar invariants worth fuzzing.

## Notes for the implementer

- The properties above are sketches; final test names and
  signatures will adjust to fit existing module
  conventions. Keep names declarative-style
  (`matcher_rejects_trailing_slash_difference`) to match
  the rest of the test suite.
- proptest's default failure-shrinking is excellent;
  on the rare regression, the failing minimal input
  appears in the test output. Don't add custom
  `Arbitrary` impls unless shrinking gets in the way.
- `proptest-regressions/` files are auto-generated when a
  property finds a counterexample. Commit those to the
  tree — they're the "remember the past failure" record.
- Run order: write the round-trip properties (Module A)
  first; they'll likely all pass on first run, confirming
  the proptest setup is healthy. Then write Module B; if
  the matcher has any latent bug, this is where it
  surfaces.
