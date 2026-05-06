# RFC 005: `cargo fuzz` for the JWT parser surface

**Status**: Ready
**ROADMAP**: `## Planned (0.x) / Next minor releases` — "`cargo fuzz` for the JWT parser surface"
**ADR**: N/A
**Estimated scope**: Small — one fuzz target, one GH Actions one-shot job, ~80 LOC

## Background

cesauth receives potentially adversarial JWTs on every
`Authorization: Bearer ...` request. v0.44.0 dropped the
`jsonwebtoken` crate and replaced its parser with
cesauth's own JWS Compact deserializer (`jwt::signer.rs` +
`jwt::verifier.rs`). That code is independently
correct-by-tests, but the parser surface is exactly the
class of code where fuzzing finds the hard cases that
example-based tests miss: malformed UTF-8 in headers,
truncated base64, oversized claims, etc.

This RFC adds **layer-1** fuzzing: a single target run
in CI as a one-shot per push, with timeouts. **Continuous
fuzzing** (OSS-Fuzz, ClusterFuzzLite) is parked in
`Later` — not blocking and the threat model doesn't
require it yet.

## Decision / Plan

### Repository layout

Add a `fuzz/` directory (gitignored from `cargo
package` via the workspace `[package].exclude`). Use the
standard `cargo-fuzz` skeleton:

```
fuzz/
├── Cargo.toml
├── fuzz_targets/
│   └── jwt_parse.rs
└── corpus/
    └── jwt_parse/
        ├── valid-1.bin       # known-good JWT
        ├── valid-2.bin       # rotation-key JWT
        ├── empty.bin         # 0 bytes
        ├── single-dot.bin    # 1-byte boundary
        └── ...
```

`fuzz/Cargo.toml`:

```toml
[package]
name    = "cesauth-fuzz"
version = "0.0.0"
publish = false
edition = "2024"

[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4"
cesauth-core  = { path = "../crates/core" }

[[bin]]
name = "jwt_parse"
path = "fuzz_targets/jwt_parse.rs"
test = false
doc  = false
```

`fuzz_targets/jwt_parse.rs`:

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use cesauth_core::jwt::verifier;

// Static valid public key for verification calls. The
// fuzz target's job is to confirm the *parser* doesn't
// panic / OOM / loop, not that any random input
// verifies — verification will fail almost always; we
// only assert "no crash".
const PUB_KEY: &[u8; 32] = &[/* hardcoded test public key */];

fuzz_target!(|data: &[u8]| {
    let s = match std::str::from_utf8(data) {
        Ok(s)  => s,
        Err(_) => return,
    };
    let _ = verifier::verify::<cesauth_core::jwt::AccessTokenClaims>(
        s,
        PUB_KEY,
        "test-iss",
        "test-aud",
        0,
    );
});
```

### Goals

1. **Catch panics in parsing**. The verifier should
   return `Err`, never panic, on any input. cesauth's
   fail-closed posture depends on this.
2. **Catch OOM / unbounded allocation**. A malicious JWT
   with a header claiming a 4 GB payload should not be
   honored.
3. **Catch DoS via super-linear parsing**. A pathological
   nested base64 string should not cause super-linear
   work.

### CI integration

`.github/workflows/fuzz.yml`:

```yaml
name: fuzz
on:
  pull_request:
    paths: ['crates/core/src/jwt/**', 'fuzz/**']
  workflow_dispatch:

jobs:
  jwt-parser:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly  # cargo-fuzz needs nightly
      - run: cargo install cargo-fuzz
      - name: One-shot fuzz (60 seconds)
        run: cargo +nightly fuzz run jwt_parse -- -max_total_time=60
        working-directory: fuzz
```

60-second one-shot is enough to catch trivial panic-on-
parse bugs; for deeper coverage operators run
`cargo +nightly fuzz run jwt_parse` locally for hours.

The job runs on PR-touching-jwt-or-fuzz only, not on
every PR. Reduces CI noise; the path filter is
maintainable.

### Initial corpus

Seed the corpus with:

- One legitimate JWT minted by cesauth's test fixtures.
- One JWT with a rotated `kid` (multi-key path).
- Empty input.
- Single-byte input.
- Single-dot input (`.`) — 0/0/0 segment shape.
- Two-dot input (`..`) — empty all-segments shape.
- A JWT with claims size 1 byte and 64 KB.
- A JWT with `alg: none` (must reject; pin via test, not
  fuzz, but include in corpus for noise tolerance).

The corpus is committed; `cargo-fuzz` will minimize and
extend automatically.

## Open questions

**`jsonwebtoken` was already upstream-fuzzed; should we
fuzz our own wrapper?** Yes — cesauth's parser since
v0.44.0 is independent code. Upstream fuzzing of the
crate we no longer use is irrelevant.

**Should we add fuzz targets for other parsers (CBOR
WebAuthn payloads, OIDC discovery JSON, PKCS#8 PEM)?**
Out of scope for this RFC. Add when a theme touches
those parsers; this RFC scopes JWT only.

## Security considerations

**Hardcoded public key**. The fuzz target's static
`PUB_KEY` is deliberately a fixed test value, not a
production key. If a fuzz finding ever reaches a
verification success path with adversarial input, that's
a critical bug regardless of which key was used; the
particular key value isn't sensitive.

**False positives from libfuzzer leaks**. Workers'
ed25519-dalek allocates internally during signature
verification. Use `--detect_leaks=0` in the local
invocation if libfuzzer reports leaks that aren't
actual leaks (they're usually leak-on-exit which is
benign for the fuzz binary).

## Notes for the implementer

- Nightly Rust is required for `cargo-fuzz`. The CI job
  uses nightly only for that step; the workspace
  build still pins stable 1.91 elsewhere.
- `fuzz/` is its own crate, NOT a workspace member.
  Keep it standalone so fuzz dependencies don't leak
  into the workspace lockfile.
- When a finding occurs, file as a security issue
  per `.github/SECURITY.md` — don't open public PRs
  with the fuzz seed.
