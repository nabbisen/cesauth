# `verification/` — RFC 183 Verus narrow pilot

Out-of-workspace, the way `fuzz/` already is — no `Cargo.toml`, since
Verus invokes `rustc` directly and never goes through `cargo`. Not a
workspace member (confirmed: `cargo check --workspace` does not see
this directory at all), so it needed no `exclude` entry the way
`fuzz/Cargo.toml` did.

**Scope.** One function, one obligation set, by RFC 183's own mandate.
No second target.

## What's here

- `totp_truncation.rs` — a Verus-annotated **copy** of
  `crates/core/src/totp.rs`'s dynamic-truncation block (RFC 4226
  §5.3). Verus cannot verify the real `compute_code` directly: it
  goes through `hmac`/`sha1`, external crates Verus does not
  understand, and returns a `GenericArray<u8, U20>`, not a primitive
  array. The HMAC computation itself is irrelevant to what is being
  proved — only the truncation step is — so the copy takes the
  20-byte HMAC output as an opaque `[u8; 20]` function argument, which
  Verus's own semantics treat as universally quantified: proving a
  property of this function proves it for all 2^160 possible HMAC-SHA1
  outputs, not just the ones a test happens to construct.

## Running it

```bash
verus verification/totp_truncation.rs
```

Expected output: `verification results:: 3 verified, 0 errors`. Needs
the Verus toolchain installed locally (owner-installed, unpinned —
**not** in CI, by RFC 183 §6/non-goals). Version used for this pilot:
`0.2026.07.27.31579f0`.

## The drift check (RFC 183 §4, not optional)

A copy that drifts from production verifies fiction — the project has
already paid for exactly this class of mistake once (RFC 171 Q1: a
caller matched a `PortError` the real adapter could never produce,
with a green suite). `scripts/drift-scan.sh`'s "RFC 183 pilot" section
byte-compares this file's marked region (between the `BEGIN`/`END`
comments inside `compute_code_truncation`) against
`crates/core/src/totp.rs`'s own five-line truncation block, found by
its own existing, unmodified text — no marker was added to production
to make this check possible.

If you change `totp.rs`'s truncation block, `drift-scan.sh` will fail
until you update this file's marked region to match and **re-run
Verus by hand** — a passing proof about old text is not evidence about
new text, and nothing re-runs Verus automatically (it is not in CI).
