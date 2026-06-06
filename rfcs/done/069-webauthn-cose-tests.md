# RFC 069 — webauthn/cose.rs tests

**Status**: Implemented  
**Size**: Small

`cose.rs` has `CoseKeyType` and `parse_cose_key` (140 LOC). Tests cover
known COSE key parsing (EdDSA/P256), rejection of malformed input,
and round-trip consistency.
