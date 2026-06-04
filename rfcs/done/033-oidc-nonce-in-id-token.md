# RFC 033 — OIDC nonce reflected in id_token

**Status**: Implemented  
**Priority**: P1 (OIDC spec compliance, replay attack vector)  
**Size**: Trivial (~5 LOC + tests)  
**Depends on**: RFC 001

## Problem

`service::token::exchange_code` extracts `nonce` from `Challenge::AuthCode`
but passes `None` to `build_id_token_claims`. Comment claims "nonce is already
consumed; not needed on id_token at exchange time" — this is incorrect.

OIDC Core §3.1.3.6 requires that when `nonce` was present in the authorization
request, it MUST be included in the `id_token`. Strict RPs will reject the
token if `nonce` is absent.

## Decision

Pass `nonce.as_deref()` to `build_id_token_claims` in `exchange_code`.
The nonce is NOT stored in `FamilyState` — it applies only to the initial
`id_token` at code exchange time (per OIDC Core §12). Refresh-path `id_token`
correctly omits `nonce`.

## Tests

- `exchange_code_id_token_carries_nonce_when_authorize_had_one`
- `exchange_code_id_token_omits_nonce_when_authorize_did_not`
- `rotate_refresh_id_token_never_carries_nonce` (already implicitly tested)
