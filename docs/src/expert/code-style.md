# Code style: hand-aligned columns are house style

**Status.** Amends [RFC 029](../../../rfcs/done/029-rustfmt-toml-review.md)
(`rustfmt.toml` necessity review). See
[RFC 125 §5](../../../rfcs/done/125-release-gate-integrity-restoration.md#5-the-formatting-decision-with-evidence)
for the measurement behind this decision.

## The decision

cesauth does not run `cargo fmt --check` as a CI gate, and does not
require `cargo fmt` before a PR. Hand-aligned columns in
security-sensitive signatures — struct fields, match arms, adjacent
parameter lists — are **house style**, not a formatting lapse.

## Why

[RFC 029](../../../rfcs/done/029-rustfmt-toml-review.md) removed
`rustfmt.toml` on the basis that the codebase formatted identically to
stable `rustfmt` defaults. That was true at the time. It no longer is:
as of this decision, `cargo fmt --check` on `main` reports 4,568 diff
hunks across 447 of 498 `.rs` files.

Restoring `rustfmt.toml` does not recover the old measurement.
Re-adding `use_small_heuristics = "Max"` closes only 4.8% of the gap
(4,568 → 4,347 hunks). The residual is column alignment —
`_env:  Env`, `family_id:     &crate::types::FamilyId` — and the only
`rustfmt` option that emits column alignment,
`struct_field_align_threshold`, is **nightly-only**; stable `rustfmt`
refuses it (`unstable features are only available in nightly channel`).
No stable `rustfmt`, at any version, can produce or accept this tree.
This is not toolchain drift and is not configurable away.

The choice was binary: reformat 447 of 498 files, or stop enforcing a
rule the project has never actually followed. The owner chose not to
reformat, because the alignment is load-bearing exactly where it
matters most: aligned parameter lists in `core::ports` and RFC 116's
identifier/secret newtypes are what make an argument transposition
*visible to a reviewer* — the same bug class those newtypes exist to
make uncompilable. A `cargo fmt --check` gate that has never once
passed on this tree provided no signal either way.

## What this means in practice

- `.github/workflows/fmt.yml` has been removed. There is no CI
  formatting gate.
- Do **not** run `cargo fmt` (with or without `--check`) across the
  whole tree. It will collapse hand-aligned blocks.
- When you touch a struct, match arm, or parameter list that already
  uses column alignment, preserve it by eye. Match the existing
  column position; do not let your editor's format-on-save undo it.
- New code that is not in an alignment-sensitive block may still use
  an editor's default `rustfmt` formatting for that block in
  isolation — this note does not forbid `rustfmt`, it forbids treating
  its output as authoritative over hand-alignment.

## Reversal path

This decision is reversible. If the project later prefers uniform
`rustfmt` formatting over hand-alignment, a single mechanical reformat
commit (`cargo fmt --all`) plus restoring `.github/workflows/fmt.yml`
replaces this note. That tradeoff — losing the alignment that makes
transposition-class bugs visible at a glance, in exchange for uniform
formatting — is an owner decision, not a default to drift into.
