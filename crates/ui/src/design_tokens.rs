//! Shared CSS design tokens for all cesauth UI frames (RFC 082).
//!
//! Each frame embeds this constant in its `<style>` block to ensure
//! consistent color semantics across admin, tenant-admin, tenancy-console,
//! and end-user surfaces.
//!
//! **Token naming** follows the end-user convention (`--success`, `--warning`,
//! `--danger`, `--info`) with the admin `--ok`/`--warn`/`--critical` aliases
//! mapped to the same values for backward compatibility.

pub const DESIGN_TOKENS: &str = r#"
:root {
  /* Semantic status tokens — used by .flash, .badge, and button.danger */
  --success:    #1f9d55;
  --success-bg: #e8f5e9;
  --warning:    #b76e00;
  --warning-bg: #fff7e6;
  --danger:     #c92a2a;
  --danger-bg:  #fdecea;
  --info:       #1864ab;
  --info-bg:    #e7f5ff;

  /* Admin console aliases (backward compat with existing --ok/--warn/--critical) */
  --ok:       var(--success);
  --warn:     var(--warning);
  --critical: var(--danger);
}
@media (prefers-color-scheme: dark) {
  :root {
    --success:    #4ade80;
    --success-bg: #14532d;
    --warning:    #fbbf24;
    --warning-bg: #78350f;
    --danger:     #f87171;
    --danger-bg:  #7f1d1d;
    --info:       #60a5fa;
    --info-bg:    #1e3a8a;
  }
}
"#;

/// Same token definitions as [`DESIGN_TOKENS`] but with `{` / `}` doubled
/// for use as a literal fragment inside a Rust `format!()` macro argument.
///
/// Admin frame CSS blocks are built via `format!()` and therefore require
/// that literal `{` characters appear as `{{`. Reference this constant in
/// your `<style>` block instead of duplicating the token definitions.
pub const DESIGN_TOKENS_FMT: &str = ":root {{
  /* Semantic status tokens — shared across all cesauth frames (RFC 101) */
  --success:    #1f9d55;
  --success-bg: #e8f5e9;
  --warning:    #b76e00;
  --warning-bg: #fff7e6;
  --danger:     #c92a2a;
  --danger-bg:  #fdecea;
  --info:       #1864ab;
  --info-bg:    #e7f5ff;

  /* Admin console aliases (backward compat) */
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
";
