//! `cesauth-migrate` — server-to-server data migration tool.
//!
//! v0.20.0 ships **real export and verify**. The CLI now produces
//! actual `.cdump` files from a live D1 source (via wrangler) and
//! verifies them on a different host without D1 contact. Import
//! still ships skeleton-only — it lands in v0.21.0 with the
//! operator handshake + invariant accumulation.
//!
//! The skeleton continues to ship explanatory errors for the
//! unimplemented subcommands so operators can install once and
//! get a useful response in any state.

use anyhow::{bail, Context, Result};
use cesauth_core::migrate::{
    built_in_profiles, default_invariant_checks, import, lookup_profile, verify,
    ExportSpec, Exporter, ImportSink as _, FORMAT_VERSION, SCHEMA_VERSION,
};
use clap::{Parser, Subcommand};

mod d1_sink;
mod d1_source;
mod schema;

use d1_sink::WranglerD1Sink;
use d1_source::{D1Source, TenantFilter, WranglerD1Source};
use schema::{tenant_scope_for, MIGRATION_TABLE_ORDER, TenantScope};

/// Top-level CLI.
///
/// The four subcommands map to the four phases ADR-005 settles:
/// export, import, list-profiles (operator visibility into what
/// redaction is available), and verify (read a `.cdump`'s
/// manifest, confirm the signature, print the table summary
/// without touching D1 — useful for "did the file survive
/// transit").
#[derive(Debug, Parser)]
#[command(
    name    = "cesauth-migrate",
    version,
    about   = "Server-to-server data migration tool for cesauth.",
    long_about = "\
Reads a cesauth deployment's data out of D1 (export) and writes \
it back into a different deployment's D1 (import). The on-disk \
format is described in ADR-005 and in the cesauth_core::migrate \
module documentation.

Secrets are not transported. The destination operator mints fresh \
JWT signing keys, session cookie keys, and admin tokens at the \
destination; this tool prints a checklist of which secrets are \
needed.

As of v0.22.0: the data-migration tooling is feature-complete for \
ADR-005's scope. `export`, `verify`, `import`, and \
`refresh-staging` are all implemented. `--tenant <id>` filtering \
on `export` and `refresh-staging` scopes the dump to specific \
tenants. Resume support, native HTTP API client, and operator-\
supplied custom invariants are tracked as future polish items.\
",
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Export the source D1 to a `.cdump` file.
    ///
    /// Reads the source via `wrangler d1 execute --remote` (so
    /// wrangler must be installed and authenticated). Generates
    /// a fresh per-export Ed25519 keypair, signs the payload,
    /// embeds the signature in the manifest. The private key is
    /// discarded after signing — single-use.
    ///
    /// Optional redaction: pass `--profile <name>` to apply one of
    /// the built-in PII redaction profiles (see `list-profiles`)
    /// before writing the dump. The dump's manifest records which
    /// profile was applied so the importer can refuse a redacted
    /// dump where production-fidelity was required.
    ///
    /// Implemented in v0.20.0.
    Export {
        /// Output `.cdump` path.
        #[arg(short, long, value_name = "PATH")]
        output: std::path::PathBuf,

        /// Cloudflare account ID for the source. Surfaced in
        /// the manifest's `source_account_id` field for diagnostic
        /// audit. Required because the manifest must record where
        /// the dump came from.
        #[arg(long, value_name = "ID")]
        account_id: String,

        /// Source D1 database name (matches the
        /// `database_name` field in the source's `wrangler.toml`).
        #[arg(long, value_name = "NAME")]
        database: String,

        /// Apply a redaction profile. Pass `prod-to-staging` for
        /// the standard staging-refresh shape. List built-ins
        /// with `cesauth-migrate list-profiles`.
        #[arg(long, value_name = "PROFILE")]
        profile: Option<String>,

        /// Restrict the dump to specific tenants by id. Repeat
        /// the flag for multiple. Without this, the entire D1 is
        /// dumped.
        ///
        /// Tables with `TenantScope::Global` (`plans`,
        /// `permissions`, `oidc_clients`, `jwt_signing_keys`,
        /// etc.) export in full regardless of the filter.
        /// Tenant-scoped tables filter on their `tenant_id`
        /// column. Implemented in v0.22.0.
        #[arg(long, value_name = "ID")]
        tenant: Vec<String>,
    },

    /// Import a `.cdump` into the destination D1.
    ///
    /// Two-stage:
    ///
    /// 1. Verify the dump's manifest signature and the per-table
    ///    SHA-256s. Surface the public-key fingerprint to the
    ///    operator for out-of-band confirmation. Refuse to proceed
    ///    if the operator declines.
    /// 2. Stream the payload into the destination D1, running
    ///    schema invariants over each row. Accumulate violations.
    ///    Either commit (no violations or `--accept-violations`)
    ///    or roll back.
    ///
    /// The destination must have its `JWT_SIGNING_KEY` already set
    /// before `--commit` — the tool checks via the wrangler
    /// binding API and refuses otherwise. ADR-005 §Q6 walks why.
    ///
    /// Implemented in v0.21.0.
    Import {
        /// Input `.cdump` path.
        #[arg(short, long, value_name = "PATH")]
        input: std::path::PathBuf,

        /// Destination Cloudflare account ID.
        #[arg(long, value_name = "ID")]
        account_id: String,

        /// Destination D1 database name.
        #[arg(long, value_name = "NAME")]
        database: String,

        /// Without `--commit`, the importer only verifies + dry-
        /// runs. Pass this flag to actually write rows.
        #[arg(long)]
        commit: bool,

        /// Refuse to commit a redacted dump. Use when the import
        /// is a production-restore rather than a staging-refresh.
        #[arg(long)]
        require_unredacted: bool,

        /// Force-commit despite invariant violations. For
        /// recovery scenarios where partial integrity is
        /// acceptable. Refused by default.
        #[arg(long)]
        accept_violations: bool,
    },

    /// List the built-in redaction profiles.
    ///
    /// Each profile is a named set of column-level
    /// transformations. Profiles are documented in the cesauth
    /// repo at `crates/core/src/migrate.rs`.
    ListProfiles,

    /// Verify a `.cdump` without touching any D1.
    ///
    /// Parses the manifest, checks format version, verifies the
    /// signature against the payload SHA-256, prints the
    /// per-table summary. Useful for "did the file arrive
    /// intact" checks before scheduling an import window.
    ///
    /// Implemented in v0.20.0.
    Verify {
        /// Path to the `.cdump`.
        #[arg(short, long, value_name = "PATH")]
        input: std::path::PathBuf,
    },

    /// Refresh a staging deployment from a production source in
    /// one command.
    ///
    /// Equivalent to running `export --profile prod-to-staging`
    /// followed by `import --commit`, with operator-attended
    /// prompts collapsed to a single up-front confirmation. The
    /// dump is written to a temp file that is deleted on
    /// success.
    ///
    /// **Convenience, not security-critical.** This subcommand
    /// trusts the caller to be in control of both endpoints
    /// (same operator, same keychain). For cross-organization
    /// moves where source and destination operators are
    /// different people, use `export` + `verify` + `import`
    /// separately so the fingerprint handshake protects against
    /// in-transit substitution.
    ///
    /// Implemented in v0.22.0.
    RefreshStaging {
        /// Source Cloudflare account ID.
        #[arg(long, value_name = "ID")]
        source_account_id: String,

        /// Source D1 database name.
        #[arg(long, value_name = "NAME")]
        source_database: String,

        /// Destination Cloudflare account ID.
        #[arg(long, value_name = "ID")]
        dest_account_id: String,

        /// Destination D1 database name.
        #[arg(long, value_name = "NAME")]
        dest_database: String,

        /// Skip the up-front confirmation prompt. For unattended
        /// runs (CI staging refresh, scheduled jobs). Default is
        /// to prompt.
        #[arg(long)]
        yes: bool,

        /// Restrict the refresh to specific tenants by id.
        /// Repeat the flag for multiple. Without this, the
        /// entire D1 is refreshed.
        #[arg(long, value_name = "ID")]
        tenant: Vec<String>,

        /// Redaction profile. Default is `prod-to-staging`. Use
        /// a different profile (e.g., `prod-to-dev`) for stricter
        /// scrubbing.
        #[arg(long, value_name = "PROFILE", default_value = "prod-to-staging")]
        profile: String,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Export { output, account_id, database, profile, tenant } => {
            do_export(output, account_id, database, profile, tenant).await
        }

        Command::Import { input, account_id, database, commit, require_unredacted, accept_violations } => {
            do_import(input, account_id, database, commit, require_unredacted, accept_violations).await
        }

        Command::Verify { input } => do_verify(input),

        Command::RefreshStaging {
            source_account_id, source_database,
            dest_account_id, dest_database,
            yes, tenant, profile,
        } => {
            do_refresh_staging(
                source_account_id, source_database,
                dest_account_id, dest_database,
                yes, tenant, profile,
            ).await
        }

        Command::ListProfiles => list_profiles(),
    }
}

// ---------------------------------------------------------------------
// Export handler
// ---------------------------------------------------------------------

async fn do_export(
    output:     std::path::PathBuf,
    account_id: String,
    database:   String,
    profile:    Option<String>,
    tenant:     Vec<String>,
) -> Result<()> {
    // Resolve redaction profile, if any.
    let prof = match profile.as_deref() {
        None       => None,
        Some(name) => Some(lookup_profile(name)
            .ok_or_else(|| anyhow::anyhow!(
                "unknown redaction profile `{name}` (run `cesauth-migrate \
                 list-profiles` for available profiles)"
            ))?),
    };

    // Tenant filter: empty Vec → whole-database; non-empty → scope.
    // Empty values like `--tenant ""` are operator typos; reject.
    for slug in &tenant {
        if slug.trim().is_empty() {
            bail!("--tenant value must be non-empty");
        }
    }
    let tenant_filter: Option<&[String]> = if tenant.is_empty() {
        None
    } else {
        Some(&tenant[..])
    };

    // Build the source. Hard-coded to WranglerD1Source for now —
    // future native HTTP API client lands behind the same trait.
    let src = WranglerD1Source {
        database:    database.clone(),
        config_path: None,
    };

    // Open the output file. Refuse to clobber: the file must not
    // already exist. A previous run that the operator forgot
    // about is the most common cause of "two dumps with the same
    // name in the move folder", and silent overwrite is bad.
    if output.exists() {
        bail!(
            "output file `{}` already exists; refusing to overwrite. \
             Move it aside or use a different --output path.",
            output.display(),
        );
    }
    let mut out_file = std::fs::File::create(&output)
        .with_context(|| format!("creating {}", output.display()))?;

    // exported_at is set once at start; the manifest carries this
    // as the export's logical timestamp even though the actual
    // export runs for some seconds afterward.
    let exported_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let cesauth_version = env!("CARGO_PKG_VERSION");

    let spec = ExportSpec {
        cesauth_version,
        schema_version: SCHEMA_VERSION,
        exported_at,
        source_account_id:     &account_id,
        source_d1_database_id: Some(&database),
        tables: MIGRATION_TABLE_ORDER,
        profile: prof,
        tenants: tenant_filter,
    };
    let mut exporter = Exporter::new(spec, &mut out_file)
        .context("initializing exporter (RNG failure?)")?;

    // Print fingerprint EARLY so the operator can read it
    // out-of-band before transmitting the dump. This is the
    // "verification handshake" half on the source side; the
    // importer prints the same fingerprint and asks the
    // operator to confirm.
    eprintln!("Per-export public-key fingerprint (read this out-of-band to the importing operator):");
    eprintln!("  {}", exporter.fingerprint());
    eprintln!();
    if let Some(ids) = tenant_filter {
        eprintln!("Tenant scope: filtering to {} tenant(s):", ids.len());
        for id in ids {
            eprintln!("  - {id}");
        }
        eprintln!();
    }

    // Walk tables in topological order. Per table, decide whether
    // to apply the tenant filter based on TENANT_SCOPES.
    let mut totals: Vec<(&str, u64)> = Vec::with_capacity(MIGRATION_TABLE_ORDER.len());
    let mut total_rows = 0_u64;
    for table in MIGRATION_TABLE_ORDER {
        eprint!("Exporting {table}...");
        let table_filter = build_table_filter(table, tenant_filter)?;
        let rows = src.fetch_table(table, table_filter).await
            .with_context(|| format!("fetching table `{table}`"))?;
        let n = rows.len() as u64;
        for (i, row) in rows.into_iter().enumerate() {
            exporter.push(table, row)
                .with_context(|| format!("pushing row to `{table}`"))?;
            total_rows += 1;
            // Per-row progress for big tables (v0.22.0): emit a
            // dot every 1000 rows. Spares the operator the "is it
            // hung?" anxiety on long fetches without flooding
            // narrow terminals.
            if (i + 1) % 1000 == 0 {
                eprint!(".");
            }
        }
        totals.push((table, n));
        eprintln!(" {n} rows");
    }

    exporter.finish().context("finalizing dump (signing)")?;
    drop(out_file);

    // Operator-facing summary: what landed in the dump.
    eprintln!();
    eprintln!("Export complete. Wrote {} ({total_rows} total rows).", output.display());
    eprintln!("Tables:");
    for (table, n) in &totals {
        eprintln!("  {table:30} {n} rows");
    }

    // Print the secrets-coordination checklist. ADR-005 §Q6 —
    // tool prints, operator does. Keep it concise; the operator
    // runbook has the long form.
    eprintln!();
    eprintln!("Before importing this dump at the destination, mint the following secrets:");
    eprintln!("  - JWT_SIGNING_KEY      (Ed25519 PKCS#8 PEM; new kid recommended)");
    eprintln!("  - SESSION_COOKIE_KEY   (48 random bytes, base64)");
    eprintln!("  - ADMIN_API_KEY        (opaque bearer)");
    eprintln!("  - MAGIC_LINK_MAIL_API_KEY (if Magic Link is enabled)");
    eprintln!("  - TURNSTILE_SECRET     (if Turnstile is enabled)");
    eprintln!();
    eprintln!("See docs/src/deployment/data-migration.md for the full runbook (lands with v0.21.0).");
    Ok(())
}

// ---------------------------------------------------------------------
// Verify handler
// ---------------------------------------------------------------------

fn do_verify(input: std::path::PathBuf) -> Result<()> {
    let file = std::fs::File::open(&input)
        .with_context(|| format!("opening {}", input.display()))?;
    let reader = std::io::BufReader::new(file);

    let report = verify(reader)
        .map_err(|e| anyhow::anyhow!("verification failed: {e}"))?;

    println!("Dump format:       v{}", report.manifest.format_version);
    println!("cesauth version:   {}", report.manifest.cesauth_version);
    println!("Schema version:    {} (this build supports {SCHEMA_VERSION})",
        report.manifest.schema_version);
    if report.manifest.schema_version != SCHEMA_VERSION {
        println!("                   ⚠ schema mismatch — see operator runbook");
    }
    println!("Source account:    {}", report.manifest.source_account_id);
    if let Some(db) = &report.manifest.source_d1_database_id {
        println!("Source database:   {db}");
    }
    println!("Exported at:       {} (Unix)",  report.manifest.exported_at);
    println!("Redaction profile: {}",
        report.manifest.redaction_profile.as_deref().unwrap_or("(none — full unredacted dump)"));
    println!();
    println!("Public-key fingerprint: {}", report.manifest.fingerprint());
    println!("  ↑ confirm this matches the value the EXPORTING operator printed at export time.");
    println!("    If it does not match, refuse to import.");
    println!();
    println!("Tables:");
    let mut total = 0_u64;
    for (table, count) in &report.table_counts {
        println!("  {table:30} {count} rows");
        total += count;
    }
    println!();
    println!("Total: {total} rows across {} tables", report.table_counts.len());
    println!("Signature verified ✓");
    Ok(())
}

// ---------------------------------------------------------------------
// Refresh-staging combinator (v0.22.0)
// ---------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn do_refresh_staging(
    source_account_id: String,
    source_database:   String,
    dest_account_id:   String,
    dest_database:     String,
    yes:               bool,
    tenant:            Vec<String>,
    profile_name:      String,
) -> Result<()> {
    // Resolve redaction profile early — fail fast on typos.
    let prof = lookup_profile(&profile_name)
        .ok_or_else(|| anyhow::anyhow!(
            "unknown redaction profile `{profile_name}` (run `cesauth-migrate \
             list-profiles` for available profiles)"
        ))?;

    // Validate operator-supplied tenant slugs (same boundary
    // check as do_export).
    for slug in &tenant {
        if slug.trim().is_empty() {
            bail!("--tenant value must be non-empty");
        }
    }
    let tenant_filter: Option<&[String]> = if tenant.is_empty() {
        None
    } else {
        Some(&tenant[..])
    };

    println!("Refresh staging from production:");
    println!("  Source:        account {source_account_id}, D1 `{source_database}`");
    println!("  Destination:   account {dest_account_id}, D1 `{dest_database}`");
    println!("  Profile:       {}", prof.name);
    if let Some(ids) = tenant_filter {
        println!("  Tenant scope:  {} tenant(s) — {}", ids.len(), ids.join(", "));
    } else {
        println!("  Tenant scope:  whole database");
    }
    println!();
    println!("This will OVERWRITE the destination's existing data.");
    println!();

    if !yes {
        // Default-no — require affirmative consent.
        let confirmed = prompt_yn(
            "Proceed with refresh?",
            false,
        )?;
        if !confirmed {
            bail!("refresh aborted by operator");
        }
    }

    // ---- Phase 1: export to a temp file --------------------------
    // The dump is written to a per-process temp file. On success
    // we delete it; on failure we leave it for the operator to
    // inspect.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos()).unwrap_or(0);
    let temp_path = std::env::temp_dir()
        .join(format!("cesauth-refresh-{nanos}.cdump"));

    // Run the export half by reusing do_export's logic. Rather
    // than calling do_export directly (which prints a
    // secrets-coordination checklist that's irrelevant for a
    // staging refresh), inline a smaller version.
    eprintln!();
    eprintln!("→ Phase 1: export from source");
    export_to_path(
        &temp_path,
        &source_account_id, &source_database,
        Some(prof), tenant_filter,
    ).await?;

    // ---- Phase 2: import to destination ---------------------------
    eprintln!();
    eprintln!("→ Phase 2: import to destination");
    let result = import_from_path(
        &temp_path,
        &dest_account_id, &dest_database,
    ).await;

    // Clean up the temp file on success; preserve on failure for
    // forensics.
    match &result {
        Ok(_) => {
            if let Err(e) = std::fs::remove_file(&temp_path) {
                eprintln!("(note: could not delete temp dump {}: {e})",
                    temp_path.display());
            }
        }
        Err(_) => {
            eprintln!();
            eprintln!("Refresh failed mid-flight. Temp dump preserved at:");
            eprintln!("  {}", temp_path.display());
            eprintln!("Inspect with `cesauth-migrate verify --input <path>`.");
        }
    }
    result?;

    println!();
    println!("✓ Refresh complete. Destination D1 `{dest_database}` now mirrors source.");
    Ok(())
}

/// Export half of refresh-staging. Same logic as `do_export`
/// minus the operator-facing fingerprint print and the
/// secrets-coordination checklist (those don't apply when one
/// operator drives both ends).
async fn export_to_path(
    output:     &std::path::Path,
    account_id: &str,
    database:   &str,
    profile:    Option<&'static cesauth_core::migrate::RedactionProfile>,
    tenants:    Option<&[String]>,
) -> Result<()> {
    let src = WranglerD1Source {
        database:    database.to_owned(),
        config_path: None,
    };
    let mut out_file = std::fs::File::create(output)
        .with_context(|| format!("creating {}", output.display()))?;

    let exported_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let cesauth_version = env!("CARGO_PKG_VERSION");

    let spec = ExportSpec {
        cesauth_version,
        schema_version:        SCHEMA_VERSION,
        exported_at,
        source_account_id:     account_id,
        source_d1_database_id: Some(database),
        tables:                MIGRATION_TABLE_ORDER,
        profile,
        tenants,
    };
    let mut exporter = Exporter::new(spec, &mut out_file)
        .context("initializing exporter")?;

    let mut total_rows = 0_u64;
    for table in MIGRATION_TABLE_ORDER {
        eprint!("  {table}...");
        let table_filter = build_table_filter(table, tenants)?;
        let rows = src.fetch_table(table, table_filter).await
            .with_context(|| format!("fetching `{table}`"))?;
        let n = rows.len() as u64;
        for row in rows {
            exporter.push(table, row)
                .with_context(|| format!("pushing row to `{table}`"))?;
            total_rows += 1;
        }
        eprintln!(" {n}");
    }
    exporter.finish().context("finalizing dump (signing)")?;
    drop(out_file);

    eprintln!("  → {} rows total", total_rows);
    Ok(())
}

/// Import half of refresh-staging. Skips the fingerprint
/// handshake (single-operator workflow) and the
/// secret-pre-flight check (operators using refresh-staging
/// have already configured the destination's secrets out of
/// band, this is a routine refresh not a migration). Goes
/// straight to staging + commit, with `--accept-violations`
/// implicit because staging is allowed to be a little messy.
async fn import_from_path(
    input:      &std::path::Path,
    _account_id: &str,
    database:   &str,
) -> Result<()> {
    let mut file = std::fs::File::open(input)
        .with_context(|| format!("opening {}", input.display()))?;

    // Quick verify pass — surface format/signature errors before
    // staging.
    let initial_report = verify(std::io::BufReader::new(&file))
        .map_err(|e| anyhow::anyhow!("dump failed verification: {e}"))?;
    eprintln!("  Dump verified ✓ ({} tables, fingerprint {})",
        initial_report.manifest.tables.len(),
        initial_report.manifest.fingerprint());

    let mut sink = WranglerD1Sink::new(database.to_owned(), None);
    let import_report = import(
        &mut file,
        &mut sink,
        default_invariant_checks(),
        false,  // require_unredacted = false, redacted dumps are fine here
    )
    .await
    .map_err(|e| anyhow::anyhow!("import staging failed: {e}"))?;

    eprintln!("  Staged {} rows ({} violations)",
        import_report.rows_staged, import_report.violations.len());
    if !import_report.is_clean() {
        eprintln!("  Note: {} schema invariant violation(s) — staging tolerates them",
            import_report.violations.len());
        // Print first 3 violations so the operator has a signal,
        // even if we proceed.
        for v in import_report.violations.iter().take(3) {
            eprintln!("    {v}");
        }
        if import_report.violations.len() > 3 {
            eprintln!("    ... and {} more", import_report.violations.len() - 3);
        }
    }

    let written = sink.commit().await
        .map_err(|e| anyhow::anyhow!("commit failed: {e}"))?;
    eprintln!("  Committed {written} rows to D1 `{database}`");
    Ok(())
}


///
/// Implemented in v0.19.0 because it has no D1 dependency — the
/// profile registry is purely in-process. Surfaces operator
/// visibility into "what redaction is available" without waiting
/// for the export/import code to land.
fn list_profiles() -> Result<()> {
    println!("Built-in redaction profiles:\n");
    for p in built_in_profiles() {
        println!("  {}", p.name);
        // Indent the description by 4 spaces; collapse whitespace
        // runs from the multi-line `&'static str` source.
        let collapsed = p.description.split_whitespace()
            .collect::<Vec<_>>().join(" ");
        // Soft-wrap at ~70 chars for terminal readability.
        for line in wrap(&collapsed, 70) {
            println!("    {line}");
        }
        println!("    rules:");
        for r in p.rules {
            println!("      - {}.{} → {:?}", r.table, r.column, r.kind);
        }
        println!();
    }
    println!(
        "format_version = {FORMAT_VERSION}, schema_version = {SCHEMA_VERSION}"
    );
    Ok(())
}

/// Compute the tenant filter to apply to one table for an
/// export. Returns `None` (no filter) when:
/// - operator did not pass `--tenant`, OR
/// - the table is `TenantScope::Global` (deployment-wide rows).
///
/// Returns `Some(TenantFilter)` for tenant-scoped tables when an
/// operator filter is in effect.
///
/// Errors if the table is unknown to the schema map — defensive
/// against typos in `MIGRATION_TABLE_ORDER` getting out of sync
/// with `TENANT_SCOPES`.
fn build_table_filter<'a>(
    table:   &str,
    tenants: Option<&'a [String]>,
) -> Result<Option<TenantFilter<'a>>> {
    let Some(ids) = tenants else { return Ok(None); };
    let scope = tenant_scope_for(table)
        .ok_or_else(|| anyhow::anyhow!(
            "table `{table}` has no scope metadata in TENANT_SCOPES \
             (schema.rs out of sync with MIGRATION_TABLE_ORDER?)"
        ))?;
    Ok(match scope {
        TenantScope::Global         => None,
        TenantScope::OwnColumn(col) => Some(TenantFilter { column: col, ids }),
    })
}


/// Greedy word-fill; never breaks within a word. Used by
/// `list-profiles` for terminal output. Kept inline rather than
/// pulling in `textwrap` — the wrap behaviour is undemanding and
/// the marginal dep adds nothing.
fn wrap(s: &str, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for word in s.split_whitespace() {
        if !cur.is_empty() && cur.len() + 1 + word.len() > width {
            out.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push(' ');
        }
        cur.push_str(word);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

// ---------------------------------------------------------------------
// Import handler
// ---------------------------------------------------------------------

async fn do_import(
    input:              std::path::PathBuf,
    account_id:         String,
    database:           String,
    commit:             bool,
    require_unredacted: bool,
    accept_violations:  bool,
) -> Result<()> {
    // ---- 1. Open the dump and run verify (pass 1 of import) -------
    eprintln!("Reading {}...", input.display());
    let mut file = std::fs::File::open(&input)
        .with_context(|| format!("opening {}", input.display()))?;

    // Synchronous file I/O for the verify-only print phase. The
    // import library's two-pass design means we'll re-read; that
    // requires Seek, which std::fs::File supports.
    let initial_report = verify(std::io::BufReader::new(&file))
        .map_err(|e| anyhow::anyhow!("dump failed verification: {e}"))?;

    println!();
    println!("Dump verified ✓");
    println!("  cesauth version:   {}", initial_report.manifest.cesauth_version);
    println!("  Source account:    {}", initial_report.manifest.source_account_id);
    println!("  Schema version:    {} (this build supports {SCHEMA_VERSION})",
        initial_report.manifest.schema_version);
    if initial_report.manifest.schema_version != SCHEMA_VERSION {
        println!("    ⚠ schema mismatch — proceed with care");
    }
    println!("  Redaction profile: {}",
        initial_report.manifest.redaction_profile.as_deref()
            .unwrap_or("(none — full unredacted dump)"));
    println!();

    // ---- 2. Operator handshake — fingerprint confirmation ---------
    println!("Public-key fingerprint of this dump:");
    println!("    {}", initial_report.manifest.fingerprint());
    println!();
    println!("Confirm with the EXPORTING operator (over a separate channel)");
    println!("that this fingerprint matches what they printed at export time.");
    println!();

    let confirmed = prompt_yn(
        "Does the fingerprint match? Proceed with import?",
        false,
    )?;
    if !confirmed {
        bail!("import aborted: operator declined fingerprint confirmation");
    }

    // ---- 3. Pre-flight: destination must have JWT_SIGNING_KEY -----
    if commit {
        check_destination_secrets(&database).await
            .context("destination secrets pre-flight")?;
    }

    // ---- 4. Run the import library against the destination sink ---
    eprintln!();
    eprintln!("Staging rows to destination D1 `{database}`...");
    let raw_sink = WranglerD1Sink::new(database.clone(), None);
    let mut sink = d1_sink::ProgressSink::new(raw_sink, 1000);

    // The library needs Read + Seek; std::fs::File satisfies both.
    let import_report = import(
        &mut file,
        &mut sink,
        default_invariant_checks(),
        require_unredacted,
    )
    .await
    .map_err(|e| anyhow::anyhow!("import staging failed: {e}"))?;

    // ---- 5. Display the violation report ---------------------------
    println!();
    println!("Import staging complete.");
    println!("  Rows seen:    {}", import_report.rows_seen);
    println!("  Rows staged:  {}", import_report.rows_staged);
    println!("  Violations:   {}", import_report.violations.len());

    if !import_report.is_clean() {
        println!();
        println!("⚠ Schema invariant violations detected:");
        for (table, count) in import_report.by_table() {
            println!("  {table:30} {count} violation(s)");
        }
        println!();
        // Detail dump: first 10 violations. More than that and
        // the operator should re-export from a clean source.
        println!("First {} violations:",
            import_report.violations.len().min(10));
        for v in import_report.violations.iter().take(10) {
            println!("  {v}");
        }
        if import_report.violations.len() > 10 {
            println!("  ... and {} more", import_report.violations.len() - 10);
        }
        println!();
    }

    // ---- 6. Decide whether to commit -------------------------------
    if !commit {
        println!();
        println!("--commit was not passed; rolling back staged rows.");
        println!("The destination D1 was not modified.");
        sink.rollback().await
            .map_err(|e| anyhow::anyhow!("rollback failed: {e}"))?;
        return Ok(());
    }

    if !import_report.is_clean() && !accept_violations {
        println!("Refusing to commit: violations present and --accept-violations was not passed.");
        sink.rollback().await
            .map_err(|e| anyhow::anyhow!("rollback failed: {e}"))?;
        bail!(
            "{} violations present; re-run with --accept-violations to commit anyway",
            import_report.violations.len(),
        );
    }

    // ---- 7. Final commit confirmation ------------------------------
    let prompt = if import_report.is_clean() {
        format!(
            "Commit {} rows to destination `{database}` (account {account_id})?",
            import_report.rows_staged,
        )
    } else {
        format!(
            "Commit {} rows DESPITE {} violations?",
            import_report.rows_staged,
            import_report.violations.len(),
        )
    };
    let confirmed = prompt_yn(&prompt, false)?;
    if !confirmed {
        println!("Operator declined final commit; rolling back.");
        sink.rollback().await
            .map_err(|e| anyhow::anyhow!("rollback failed: {e}"))?;
        return Ok(());
    }

    // ---- 8. Commit -------------------------------------------------
    eprintln!();
    eprintln!("Committing to destination...");
    let written = sink.commit().await
        .map_err(|e| anyhow::anyhow!("commit failed: {e}"))?;

    println!();
    println!("✓ Import complete. {written} rows written to D1 `{database}`.");
    println!();
    println!("Post-commit checklist:");
    println!("  1. Update destination wrangler.toml's JWT_KID to match the new signing key.");
    println!("  2. Deploy: wrangler deploy --env production");
    println!("  3. Smoke-test: curl -s https://<destination>/.well-known/openid-configuration");
    println!("  4. Update DNS to direct user traffic to the destination.");
    println!("  5. Source-side: revoke old admin tokens, retire old signing keys per ADR-005 §Q6.");
    Ok(())
}

/// Prompt the operator with a yes/no question. Reads a single
/// line from stdin. `default_yes` selects the default-on-Enter
/// behavior. Refuses ambiguous responses (treats anything other
/// than y/Y/n/N + Enter as a re-prompt).
fn prompt_yn(question: &str, default_yes: bool) -> Result<bool> {
    use std::io::{BufRead as _, Write as _};
    let prompt_suffix = if default_yes { " [Y/n] " } else { " [y/N] " };
    let stdin = std::io::stdin();
    let mut handle = stdin.lock();
    let mut line = String::new();
    loop {
        print!("{question}{prompt_suffix}");
        std::io::stdout().flush().ok();
        line.clear();
        let n = handle.read_line(&mut line)
            .context("reading stdin")?;
        if n == 0 {
            // EOF — treat as decline. Common in scripted invocations
            // where stdin is closed; refusing here makes the failure
            // mode explicit rather than silently committing.
            return Ok(false);
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Ok(default_yes);
        }
        match trimmed.chars().next().unwrap().to_ascii_lowercase() {
            'y' => return Ok(true),
            'n' => return Ok(false),
            _ => {
                println!("Please answer y or n.");
                continue;
            }
        }
    }
}

/// Pre-flight check for `--commit`: the destination's
/// `JWT_SIGNING_KEY` secret must already be set. ADR-005 §Q6.
///
/// We can't read the secret value through the wrangler CLI (it's
/// write-only by design), but `wrangler secret list` tells us
/// whether it exists. The check parses that output.
async fn check_destination_secrets(database: &str) -> Result<()> {
    eprintln!("Checking destination has required secrets set...");
    let output = tokio::process::Command::new("wrangler")
        .arg("secret")
        .arg("list")
        .output()
        .await
        .context("running wrangler secret list")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "wrangler secret list failed: {stderr}\n\
             Cannot verify destination is ready. Pass --skip-preflight\n\
             (NOT yet implemented) or set up wrangler auth first."
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.contains("JWT_SIGNING_KEY") {
        anyhow::bail!(
            "destination D1 `{database}` does not have JWT_SIGNING_KEY set.\n\
             Run `wrangler secret put JWT_SIGNING_KEY` (paste an Ed25519 PKCS#8 PEM)\n\
             before committing the import. ADR-005 §Q6."
        );
    }
    eprintln!("  JWT_SIGNING_KEY: set ✓");
    Ok(())
}
