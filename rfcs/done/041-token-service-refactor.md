# RFC 041 — Token service type parameter refactor

**Status**: Implemented  
**Priority**: P1 (technical debt: 5+ generic type parameters per function)  
**Size**: Medium refactor (~0 LOC net change, significant internal restructure)  
**Depends on**: nothing

## Problem

`exchange_code<CR, AS, FS, GR, UR>` and `rotate_refresh<CR, FS, RL, UR>` each
carry 4-5 generic type parameters. This grows with every new repository added
(RFC 026 added `UR`, making it 5). The pattern makes call sites verbose and
error messages cryptic.

Since backward compatibility is not required, we can eliminate this debt now.

## Decision

Replace per-function generic parameters with a **dependency struct**:

```rust
pub struct TokenDeps<'r, CR, AS, FS, GR, UR, RL>
where CR: ClientRepository, AS: AuthChallengeStore, ...
{
    pub clients:  &'r CR,
    pub codes:    &'r AS,
    pub families: &'r FS,
    pub grants:   &'r GR,
    pub users:    &'r UR,
    pub rates:    &'r RL,
}
```

Functions become:

```rust
pub async fn exchange_code(
    deps:  &TokenDeps<'_, impl ..., ...>,
    signer: &JwtSigner,
    cfg:   &TokenConfig,
    input: &ExchangeCodeInput<'_>,
) -> CoreResult<TokenResponse>
```

`TokenConfig` bundles `access_ttl_secs`, `refresh_ttl_secs`, `iss`.
Wire change: none. The worker call site constructs `TokenDeps` inline.

## Secondary cleanup

- `ExchangeCodeInput` and `RotateRefreshInput` lose the redundant fields
  that duplicated config (ttl values were already in `input` AND in args).
- `challenge_nonce` variable rename to `code_nonce` for clarity.
