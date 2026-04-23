# WebAuthn implementation

cesauth implements WebAuthn registration and assertion from scratch
in pure Rust. The scope is intentionally narrow.

## What is supported

- **Algorithms**: EdDSA (COSE alg `-8`) and ES256 (COSE alg `-7`).
  `pubKeyCredParams` advertised by `/webauthn/register/start`
  lists only these two. RSA (`-257`) is deliberately unsupported.
  This covers iCloud Keychain, Google Password Manager, 1Password,
  and YubiKey — the bulk of the passkey-capable surface.
- **Attestation formats**: **`none` only.** All of `packed`, `tpm`,
  `android-key`, `android-safetynet`, `fido-u2f`, and `apple` are
  rejected.
- **Transports**: the client advertises them; cesauth stores
  whatever the browser sent without filtering.
- **Backup flags**: `backup_eligible` and `backup_state` bits are
  parsed from authenticator data and persisted for audit, but are
  not used in authorization decisions.

## Why not `webauthn-rs`

`webauthn-rs-core`'s 2025 releases chain through `openssl-sys`,
which does not build for `wasm32-unknown-unknown`. cesauth instead
implements the subset above in `core::webauthn::cose`, which uses
pure-Rust crypto (`ed25519-dalek`, `p256`) and has no C
dependencies.

This is the same reason `jsonwebtoken` is configured with the
`rust_crypto` feature rather than `aws_lc_rs` — the wasm32 target
is the constraint, and the project will not compromise on pure-Rust
crypto for domain-critical paths.

The trade-off is that cesauth's WebAuthn does not carry FIDO
Alliance conformance certification. The implementation aims at
spec compliance for the supported subset and is covered by host
tests, but the FIDO cert paperwork is out of scope.

## Registration ceremony

```
POST /webauthn/register/start
    │
    ├── mint challenge (32 random bytes, base64url)
    ├── store Challenge::Registration in AuthChallenge DO
    │     {challenge, user_id, rp_id, origin, issued_at, expires_at}
    ├── return JSON with pubKeyCredParams, user, rp, challenge, etc.
    │
    (browser calls navigator.credentials.create(), user touches key)
    │
POST /webauthn/register/finish
    │
    ├── take(handle) → Challenge::Registration
    ├── parse clientDataJSON:
    │     verify type=="webauthn.create", challenge matches, origin in rp_origins
    ├── parse attestationObject:
    │     require fmt == "none"
    │     parse authData: flags UP=1, UV=?, AT=1 required
    │     parse AttestedCredentialData → credentialId, COSE publicKey
    │     require alg in {-7, -8}
    ├── persist StoredAuthenticator row in D1
    └── 302 to /post-auth (complete_auth)
```

## Authentication ceremony

```
POST /webauthn/authenticate/start
    │
    ├── mint challenge
    ├── store Challenge::Authentication
    ├── return JSON with challenge, allowCredentials from D1
    │
    (browser calls navigator.credentials.get())
    │
POST /webauthn/authenticate/finish
    │
    ├── take(handle) → Challenge::Authentication
    ├── look up StoredAuthenticator by credential_id
    ├── parse clientDataJSON (type=="webauthn.get", challenge, origin)
    ├── parse authenticatorData (flags, sign_count)
    ├── verify signature(authData || sha256(clientDataJSON)) with stored publicKey
    ├── enforce sign_count monotonicity:
    │     new_sign_count must be 0 (counterless authenticator)
    │     OR strictly greater than stored sign_count
    │     A non-monotonic value is a spec-defined cloning indicator;
    │     the SQL UPDATE returns 0 rows and we surface PreconditionFailed.
    ├── update last_used_at + sign_count in D1
    └── 302 to /post-auth (complete_auth)
```

## Things deliberately out of scope

- **Full FIDO attestation verification.** Adding `packed` / `tpm` /
  `android-key` would require a FIDO MDS implementation (periodic
  fetch, caching, AAGUID lookup) and a CA trust store. If a future
  deployment needs AAGUID-gated access control, it becomes a
  well-defined extension point: `cose::parse_att_obj` grows new
  fmt branches and a new `AttestationPolicy` port gets added.

- **Resident-key ("discoverable credential") flows.** cesauth
  currently lists credentials via `allowCredentials`; username-less
  authentication where the user does not type any identifier first
  is a planned extension.

- **Conditional UI (autofill-assisted sign-in).** Requires
  `mediation: "conditional"` on the client side and a resident-key
  flow on the server side; both out of scope in this milestone.

## Where the code lives

- `core/src/webauthn/cose.rs` — COSE parser, signature verification
- `core/src/webauthn/registration.rs` — `start()` / `finish()` for
  register
- `core/src/webauthn/authentication.rs` — `start()` / `finish()` for
  auth
- `worker/src/routes/webauthn.rs` — HTTP glue; post-auth handoff to
  `post_auth::complete_auth`
- `adapter-test/src/webauthn.rs` — in-memory authenticator repo for
  host tests
