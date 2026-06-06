# RFC 085 — JWT signer coverage

**Status**: Implemented | **Tier**: Quality | **Size**: Medium

`jwt/signer.rs` (368 LOC) holds `JwtSigner::sign`, `verify`, `verify_for_introspect`,
`extract_kid`. Zero tests. These are the most security-critical code paths — sign and
verify are called on every token issuance / introspection. Full unit test coverage with
known-answer vectors and error injection.
