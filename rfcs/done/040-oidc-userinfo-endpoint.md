# RFC 040 — OIDC /userinfo endpoint

**Status**: Implemented  
**Priority**: P0 (OIDC Core §5.3 compliance — required now that id_tokens ship)  
**Size**: Medium (~120 LOC core + 80 LOC worker)  
**Depends on**: RFC 001 (id_token)

## Problem

OIDC Core §5.3 mandates a `/userinfo` endpoint when the server issues id_tokens.
cesauth now issues id_tokens (RFC 001) but the endpoint is absent. Strict RPs
that call `/userinfo` after token exchange receive 404 instead of claims.

The discovery document already advertises `claims_supported`; adding
`userinfo_endpoint` completes the OIDC posture.

## Decision

Add `GET /userinfo` (plus `POST /userinfo` per §5.3.1):

1. Bearer access token validation (existing `verify` + `verify_for_introspect`)
2. Read user row from `UserRepository` by `sub` claim
3. Build response claims gated on scopes in the access token
4. Return JSON; 401 on missing/invalid token; 403 on insufficient scope

Claim population reuses `build_id_token_claims` logic (DRY via shared helper).

## New core items

- `cesauth_core::oidc::userinfo::build_userinfo_claims(user, scopes, sub)` — pure
- `UserInfoClaims` struct (subset of id_token claims, no `exp`/`iat`/`auth_time`)
- Route: `GET /userinfo` + `POST /userinfo` in lib.rs
- Discovery doc: `userinfo_endpoint` field added

## Tests

10 tests: bearer absent → 401, invalid token → 401, openid-only → {sub},
email scope → email claims, profile scope → name claim, combined scopes,
access token with no openid in scopes → 403, token for deleted user → 401.
