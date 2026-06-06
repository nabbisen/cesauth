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
pub const DESIGN_TOKENS_FMT: &str = r##":root {{
  /* Semantic status tokens — shared across all cesauth frames (RFC 105) */
  --success:    #1f9d55;
  --success-bg: #e8f5e9;
  --warning:    #b76e00;
  --warning-bg: #fff7e6;
  --danger:     #c92a2a;
  --danger-bg:  #fdecea;
  --info:       #1864ab;
  --info-bg:    #e7f5ff;

  /* Admin console legacy aliases (RFC 082 compat) */
  --ok:       var(--success);
  --warn:     var(--warning);
  --critical: var(--danger);
}}
@media (prefers-color-scheme: dark) {{
  :root {{
    --success:    #4ade80;
    --success-bg: #14532d;
    --warning:    #fbbf24;
    --warning-bg: #78350f;
    --danger:     #f87171;
    --danger-bg:  #7f1d1d;
    --info:       #60a5fa;
    --info-bg:    #1e3a8a;
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
pub const SCOPE_TOKENS_FMT: &str = r##":root {{
  /* RFC 016 / 073 scope tokens — admin / tenant / tenancy badges */
  --scope-system:  #6b3aa0;
  --scope-tenancy: #1864ab;
  --scope-tenant:  #1f9d55;
}}
@media (prefers-color-scheme: dark) {{
  :root {{
    --scope-system:  #c084fc;
    --scope-tenancy: #60a5fa;
    --scope-tenant:  #4ade80;
  }}
}}
"##;
