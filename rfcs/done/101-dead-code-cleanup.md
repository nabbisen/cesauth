# RFC 101 — Dead code and unused imports cleanup

**Status**: Implemented | **Tier**: Hygiene | **Size**: Small | **Target**: v0.66.0

## Problem

The workspace emits **28 warnings** on `cargo build --workspace`, including:

| Category | Count | Example |
|---|---|---|
| Unused imports `Deserialize`/`Serialize` | 6 | Across `crates/core/src/migrate/*.rs` |
| Deprecated `generic-array::from_slice` | 4 | `hmac`-related call sites |
| Missing `Debug` derives | 4 | Various types |
| Unused `sha2::Digest` import | 3 | Multiple modules |
| Other unused imports | 5 | `super::types::PayloadLine`, etc. |
| Unused variables | 1 | `total_seq` |

Additionally, **`crates/ui/src/design_tokens.rs`** was created by RFC 082 but
**nothing imports it**. It's pure dead code as of v0.65.0:

```bash
$ grep -rn "DESIGN_TOKENS\|design_tokens" crates/ --include="*.rs"
crates/ui/src/design_tokens.rs:11:pub const DESIGN_TOKENS: &str = r#"...
crates/ui/src/lib.rs:34:pub mod design_tokens;
```

The actual token values were inlined directly into each frame's `:root` block.
The `DESIGN_TOKENS` constant in `design_tokens.rs` serves no consumer.

## Proposed actions

### 1. Wire `design_tokens.rs` into use

Either:
- **Option A**: Use `DESIGN_TOKENS` in admin/end-user/tenant-admin/tenancy-console
  frames by string-interpolating the constant into each `<style>` block.
  Eliminates ~30 lines of duplicated token definitions across 4 frame files.
- **Option B**: Delete `crates/ui/src/design_tokens.rs` entirely; tokens are
  already inline in each frame.

Option A is preferred — it actually fulfills RFC 082's intent
(centralized tokens). The four frame files would each shrink by ~10 lines.

### 2. Clean unused imports

Run `cargo fix --workspace --allow-dirty --tests` and review the diff.
Most are benign auto-removable cases (`Serialize`/`Deserialize` imports that
were copy-pasted from a sibling file).

### 3. Address deprecated `generic-array` calls

```
warning: use of deprecated associated function
  `hmac::digest::generic_array::GenericArray::<T, N>::from_slice`:
  please upgrade to generic-array 1.x
```

This requires a `Cargo.toml` bump and minor call-site changes. Investigate
whether `hmac` itself has a fix, or whether we need to migrate.

### 4. Add missing `Debug` derives

The 4 warnings about missing `Debug` are likely on test-only stubs or
intermediate types. Add `#[derive(Debug)]` where it doesn't risk leaking
secret material; document the exception with `// SECURITY:` comment otherwise.

### 5. Remove the unused variable

`total_seq` is presumably a leftover from refactoring. Either use it or
remove the binding.

## Acceptance

- `cargo build --workspace` emits **zero warnings**.
- `crates/ui/src/design_tokens.rs` is either deleted or actually consumed by
  the 4 frame files (frame files don't duplicate the values).
- Test suite still passes.

## Risk

Suppressing warnings is tempting but bad practice; the warnings exist for
reasons. The `generic-array` deprecation in particular hints at a coming
breaking change in upstream `hmac` — addressing it now is cheap.
