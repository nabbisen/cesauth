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
    built_in_profiles, lookup_profile, verify, ExportSpec, Exporter,
    FORMAT_VERSION, SCHEMA_VERSION,
};
use clap::{Parser, Subcommand};

mod d1_source;
mod schema;

use d1_source::{D1Source, WranglerD1Source};
use schema::MIGRATION_TABLE_ORDER;

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

As of v0.20.0: `export` and `verify` are real. `import` is \
skeleton-only and lands in v0.21.0 with the operator handshake \
and invariant accumulation. `--tenant` filtering and resume \
support land in v0.22.0.\
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

        /// Restrict the dump to specific tenants by slug. Repeat
        /// the flag for multiple. Without this, the entire D1 is
        /// dumped.
        ///
        /// Lands in v0.22.0 alongside the polish phase. v0.20.0's
        /// export is whole-database only.
        #[arg(long, value_name = "SLUG")]
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
    /// **Not yet implemented.** Lands in v0.21.0.
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
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Export { output, account_id, database, profile, tenant } => {
            do_export(output, account_id, database, profile, tenant).await
        }

        Command::Import { .. } => {
            bail!(
                "import not implemented yet (lands in v0.21.0; \
                 see ADR-005 phasing)."
            );
        }

        Command::Verify { input } => do_verify(input),

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
    if !tenant.is_empty() {
        bail!(
            "--tenant filter is not implemented yet (lands in v0.22.0). \
             Run without --tenant to export the whole database."
        );
    }

    // Resolve redaction profile, if any.
    let prof = match profile.as_deref() {
        None       => None,
        Some(name) => Some(lookup_profile(name)
            .ok_or_else(|| anyhow::anyhow!(
                "unknown redaction profile `{name}` (run `cesauth-migrate \
                 list-profiles` for available profiles)"
            ))?),
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

    // Walk tables in topological order. Each table's rows are
    // pushed in primary-key order; the source's `fetch_table`
    // is responsible for that ordering.
    let mut totals: Vec<(&str, u64)> = Vec::with_capacity(MIGRATION_TABLE_ORDER.len());
    for table in MIGRATION_TABLE_ORDER {
        eprint!("Exporting {table}...");
        let rows = src.fetch_table(table).await
            .with_context(|| format!("fetching table `{table}`"))?;
        let n = rows.len() as u64;
        for row in rows {
            exporter.push(table, row)
                .with_context(|| format!("pushing row to `{table}`"))?;
        }
        totals.push((table, n));
        eprintln!(" {n} rows");
    }

    exporter.finish().context("finalizing dump (signing)")?;
    drop(out_file);

    // Operator-facing summary: what landed in the dump.
    eprintln!();
    eprintln!("Export complete. Wrote {}.", output.display());
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

/// `cesauth-migrate list-profiles`.
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

/// Soft-wrap a string at approximately `width` characters.
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
