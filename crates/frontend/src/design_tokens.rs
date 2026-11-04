//! Shared CSS design tokens for all cesauth UI frames.
//!
//! Each admin frame embeds these constants in its `<style>` block to ensure
//! consistent color semantics across admin, tenant-admin, and
//! tenancy-console surfaces. End-user surfaces (`templates/chrome.rs`)
//! define their own tokens inline because their canvas (`Canvas`/`CanvasText`
//! system tokens) differs from the admin chrome.
//!
//! ## Two constants
//!
//! - [`DESIGN_TOKENS_FMT`] — semantic state tokens shared with the
//!   end-user UI: `--success`, `--warning`, `--danger`, `--info`,
//!   their `-bg` variants, the `--ok` / `--warn` / `--critical` legacy
//!   aliases, plus a `prefers-color-scheme: dark` override.
//! - [`SCOPE_TOKENS_FMT`] — admin-only scope badge colors
//!   (`--scope-system`, `--scope-tenancy`, `--scope-tenant`) introduced
//!   by RFC 016 and refined by RFC 073, plus a dark-mode override.
//!   End-user UI has no scope badge so this constant is admin-only.
//!
//! ## RFC 176 §6.1 — the scope dark-mode override is not gate-checked
//!
//! `SCOPE_TOKENS_FMT`'s `prefers-color-scheme: dark` block is left as-is
//! by RFC 176's AAA pass, and `scripts/drift-scan.sh`'s contrast gate
//! does not check it. Every frame that consumes a scope token as
//! foreground text (`admin/frame.rs`'s `.scope-badge` rule) pairs it
//! with a **hardcoded** badge background (`#f5f0fb` / `#e7f5ff` /
//! `#e8f5e9`) that has no dark-mode override of its own — so on a
//! dark-mode OS, the dark-mode scope *foreground* (a vivid pastel meant
//! for a dark surface) would render against that same light badge
//! background, not against anything resembling white or black. There
//! is no textually-determinable background this override actually
//! renders on that a "reach 7:1 against white" rule would be honest
//! about, and forcing one to pass against white would require a
//! near-black value that defeats the point of having a separate
//! dark-mode value at all. Flagged as a pre-existing mismatch between
//! this constant's dark override and the admin frames' own
//! light-only chrome — RFC 176 never measured it and this cycle does
//! not fix it; it is its own sizing decision.
//!
//! ## Why `_FMT`
//!
//! Admin frame CSS blocks are built via the `format!()` macro and therefore
//! require that literal `{` characters appear as `{{`. Both constants below
//! are pre-escaped for that purpose and must be embedded as positional
//! `{}` arguments of the surrounding `format!()` call (see each frame's
//! `format!()` site for the pattern).
//!
//! ## RFC 105
//!
//! Before v0.67.0 these tokens were duplicated inline in each admin frame
//! and an unused `DESIGN_TOKENS` raw constant lived alongside the escaped
//! variant. RFC 105 consolidates the token source here and removes the raw
//! duplicate. Each frame embeds both constants via `format!()` so the
//! visible color semantics are guaranteed to match.

/// Semantic state tokens (`--success` / `--warning` / `--danger` / `--info`)
/// plus their soft `-bg` variants, the `--ok` / `--warn` / `--critical`
/// legacy aliases, and a `prefers-color-scheme: dark` override.
///
/// Used by every cesauth frame that renders state (flash banners, badges,
/// alert callouts). Pre-escaped for embedding in `format!()` argument
/// position.
///
/// RFC 176 §6.1: every pair here reaches AAA (7:1) against its own `-bg`
/// partner, not just AA — contrast sensitivity declines with age, and
/// `--success`/`--warning` carry the reassurances ("saved", "active")
/// a user reads most often and scrutinises least. Hue and saturation
/// preserved, only lightness moved; in dark mode the *background*
/// moved instead of the foreground, since lightening `--danger` to
/// 7:1 would turn it into a pale pink, trading contrast for salience.
/// `scripts/drift-scan.sh`'s contrast gate recomputes all eight pairs
/// from this constant on every push.
pub const DESIGN_TOKENS_FMT: &str = r##":root {{
  /* Semantic status tokens — shared across all cesauth frames (RFC 105) */
  --success:    #125d32;
  --success-bg: #e8f5e9;
  --warning:    #7a4a00;
  --warning-bg: #fff7e6;
  --danger:     #9b2020;
  --danger-bg:  #fdecea;
  --info:       #14548f;
  --info-bg:    #e7f5ff;

  /* Admin console legacy aliases (RFC 082 compat) */
  --ok:       var(--success);
  --warn:     var(--warning);
  --critical: var(--danger);
}}
@media (prefers-color-scheme: dark) {{
  :root {{
    --success:    #4ade80;
    --success-bg: #0f3d21;
    --warning:    #fbbf24;
    --warning-bg: #5d290c;
    --danger:     #f87171;
    --danger-bg:  #1c0606;
    --info:       #60a5fa;
    --info-bg:    #0b1634;
  }}
}}
"##;

/// Admin-only scope badge tokens (`--scope-system` / `--scope-tenancy` /
/// `--scope-tenant`) plus a `prefers-color-scheme: dark` override.
///
/// Introduced by RFC 016 (system / tenancy scopes) and extended by
/// RFC 073 (tenant scope). Consumed only by the three admin-side
/// frames; end-user surfaces do not render scope badges.
///
/// Pre-escaped for embedding in `format!()` argument position.
///
/// RFC 176 §6.1: each `:root` value reaches AAA (7:1) against white —
/// the badge's own background in every admin frame that uses it as
/// foreground text (`admin/frame.rs`'s `.scope-badge` rule).
/// `--scope-system` already did (7.67); the other two moved. The
/// dark-mode override below is unchanged; see this module's own doc
/// comment above for why it is not part of the contrast gate.
pub const SCOPE_TOKENS_FMT: &str = r##":root {{
  /* RFC 016 / 073 scope tokens — admin / tenant / tenancy badges */
  --scope-system:  #6b3aa0;
  --scope-tenancy: #165a9b;
  --scope-tenant:  #146637;
}}
@media (prefers-color-scheme: dark) {{
  :root {{
    --scope-system:  #c084fc;
    --scope-tenancy: #60a5fa;
    --scope-tenant:  #4ade80;
  }}
}}
"##;
