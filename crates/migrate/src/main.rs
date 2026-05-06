//! `cesauth-migrate` — server-to-server data migration tool.
//!
//! v0.19.0 ships the **CLI skeleton only**: subcommands are defined,
//! help text is in place, but the export and import paths return
//! "not implemented yet" error messages. The library types and
//! invariants live in `cesauth_core::migrate` and are
//! tested at the foundation level. Real export and import logic
//! lands in v0.20.0 and v0.21.0 respectively, per ADR-005's
//! implementation phasing.
//!
//! The skeleton is shipped early so:
//!
//! - Operators can `cargo install --path crates/migrate` and have
//!   the binary on their `$PATH` waiting for the v0.20.0 export
//!   path; no last-minute install at the moment of the move.
//! - The `--help` text is the authoritative spec for what the
//!   final tool will look like, and reviewers can comment on UX
//!   before implementation locks it in.
//! - Documentation can link to a real CLI invocation rather than
//!   a placeholder.

use anyhow::{bail, Result};
use cesauth_core::migrate::{built_in_profiles, FORMAT_VERSION, SCHEMA_VERSION};
use clap::{Parser, Subcommand};

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

This release (v0.19.0) is the CLI skeleton only — the export and \
import paths are not yet wired. See `cesauth-migrate <subcommand> \
--help` for what each subcommand will do once implemented.\
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
    /// Reads the source via the Cloudflare D1 HTTP API. Generates
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
    /// **Not yet implemented.** Lands in v0.20.0.
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
    /// **Not yet implemented.** Lands in v0.20.0 (alongside
    /// export, since they share the format-parsing path).
    Verify {
        /// Path to the `.cdump`.
        #[arg(short, long, value_name = "PATH")]
        input: std::path::PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Export { .. } => {
            bail!(
                "export not implemented yet (lands in v0.20.0; \
                 see ADR-005 phasing). The CLI skeleton in v0.19.0 \
                 ships so operators can install the binary in \
                 advance and review the UX."
            );
        }

        Command::Import { .. } => {
            bail!(
                "import not implemented yet (lands in v0.21.0; \
                 see ADR-005 phasing)."
            );
        }

        Command::Verify { .. } => {
            bail!(
                "verify not implemented yet (lands in v0.20.0)."
            );
        }

        Command::ListProfiles => list_profiles(),
    }
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
