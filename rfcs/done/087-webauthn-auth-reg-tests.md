# RFC 087 — WebAuthn authentication.rs + registration.rs coverage

**Status**: Implemented | **Tier**: Quality | **Size**: Medium

`webauthn/authentication.rs::start/finish` (230 LOC) and
`webauthn/registration.rs::start/finish` (271 LOC) have zero inline tests.
These exercise CBOR/COSE parsing, signature verification, and flag checking.
Tests will use hard-coded credential fixtures to avoid test-time crypto.
