# RFC 089 — jwt/proptests.rs property-based test expansion

**Status**: Implemented | **Tier**: Quality | **Size**: Small

`jwt/proptests.rs` exists but is currently unreached by the standard test runner
(no `#[test]` — uses proptest framework). Verify it runs, add edge-case claims tests:
expired tokens rejected, tampered signatures rejected, wrong-issuer rejected.
