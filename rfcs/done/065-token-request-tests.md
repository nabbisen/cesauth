# RFC 065 — oidc/token.rs classify() + TokenResponse tests

**Status**: Implemented  
**Size**: Small

`TokenRequest::classify()` parses grant_type from a form body and dispatches
to `AuthorizationCodeGrant` / `RefreshTokenGrant`. This is the boundary between
the HTTP layer and the token service. Tests cover: authorization_code grant,
refresh_token grant, missing grant_type, unknown grant_type, missing code,
missing refresh_token.
