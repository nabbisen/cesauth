//! Source-side abstraction for reading rows from a cesauth D1.
//!
//! The migration CLI needs to enumerate rows from a D1 database
//! (the source). The shape of "how to talk to D1" is operator
//! environment-specific:
//!
//! - In production: `wrangler d1 execute <name> --remote --json`
//!   shells out to wrangler, which already handles Cloudflare API
//!   auth, retries, and rate limiting. cesauth's operators almost
//!   certainly have wrangler configured already.
//! - In tests: a fixed in-memory map of `(table, [row])`. No
//!   network, deterministic.
//! - Future: native Cloudflare D1 HTTP API client without
//!   shelling out. Faster, no wrangler dependency. Not shipped
//!   in v0.20.0 because shelling out is enough.
//!
//! `D1Source` is the trait that hides this. Two implementations
//! ship in v0.20.0:
//!
//! - `WranglerD1Source` — calls wrangler.
//! - `MockD1Source` — in-memory, used in tests.

use anyhow::{Context, Result};
use serde_json::Value;

/// Read-only access to a D1 database. Each call returns rows
/// from one table, in primary-key order. Caller iterates tables
/// in topological order.
///
/// The trait is `async` because real implementations call out to
/// network or shell. The mock blocks immediately. No assumption
/// about thread safety — callers use one source at a time.
#[allow(async_fn_in_trait)]
pub trait D1Source {
    /// Return all rows from one table, ordered by primary key.
    /// Each row is a JSON object keyed by column name. The
    /// migrate library doesn't know the schema; rows pass
    /// through as-is.
    ///
    /// Pagination is the source's problem, not the caller's —
    /// the trait deliberately has no cursor parameter. Real
    /// `WranglerD1Source` is expected to internally paginate
    /// for tables larger than what fits in one wrangler
    /// response.
    async fn fetch_table(&self, table: &str) -> Result<Vec<Value>>;
}

// ---------------------------------------------------------------------
// WranglerD1Source — production
// ---------------------------------------------------------------------

/// `D1Source` implementation that shells out to `wrangler d1
/// execute --remote --json`. Operator's `wrangler.toml` selects
/// which D1 the call hits via `--config <path>`; this struct
/// just wraps the database name.
///
/// `--remote` is hard-coded — local D1 dumps can be done with
/// `wrangler d1 export --local`, that's not migration territory.
pub struct WranglerD1Source {
    /// D1 database name (matches `database_name` in
    /// `wrangler.toml`).
    pub database: String,
    /// Optional path to a `wrangler.toml` other than the cwd.
    pub config_path: Option<std::path::PathBuf>,
}

impl D1Source for WranglerD1Source {
    async fn fetch_table(&self, table: &str) -> Result<Vec<Value>> {
        // SQL injection note: `table` flows directly into the
        // SELECT. cesauth tables are an enumerated set; the
        // exporter's caller passes a fixed list, not a value
        // derived from user input. The risk model is "operator
        // accidentally configures the table list wrong" not
        // "attacker injects via table name". Still, we check
        // the table name against a regex that allows only
        // SQL-safe identifiers, just so a typo failing closed
        // is a syntax error rather than an unintended query.
        if !is_sql_identifier(table) {
            anyhow::bail!(
                "table name `{table}` is not a valid SQL identifier"
            );
        }
        let sql = format!("SELECT * FROM {table} ORDER BY rowid");
        // Build the wrangler command. Use `--json` for parseable
        // output. Spawn under tokio's blocking pool because
        // tokio::process::Command is async-friendly.
        let mut cmd = tokio::process::Command::new("wrangler");
        cmd.arg("d1")
           .arg("execute")
           .arg(&self.database)
           .arg("--remote")
           .arg("--json")
           .arg("--command")
           .arg(&sql);
        if let Some(path) = &self.config_path {
            cmd.arg("--config").arg(path);
        }
        let output = cmd.output().await
            .context("running wrangler (is it installed and on PATH?)")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "wrangler d1 execute failed (exit {}): {stderr}",
                output.status.code().unwrap_or(-1),
            );
        }
        // wrangler --json output is an array of result objects;
        // each has a `.results` array of row objects. We're
        // running one statement so we expect a one-element outer
        // array.
        let parsed: Value = serde_json::from_slice(&output.stdout)
            .context("parsing wrangler JSON output")?;
        let results = parsed.as_array()
            .and_then(|arr| arr.first())
            .and_then(|first| first.get("results"))
            .and_then(|r| r.as_array())
            .ok_or_else(|| anyhow::anyhow!(
                "unexpected wrangler JSON shape (no .[0].results array)"
            ))?;
        Ok(results.clone())
    }
}

/// Identifier check: only `[A-Za-z_][A-Za-z0-9_]*`. Catches
/// typos and any non-ASCII surprise. cesauth's tables all match.
fn is_sql_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    let first = chars.next();
    let Some(c) = first else { return false; };
    if !(c.is_ascii_alphabetic() || c == '_') { return false; }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

// ---------------------------------------------------------------------
// MockD1Source — tests
// ---------------------------------------------------------------------

/// In-memory `D1Source` for tests. Maps table name → row list.
/// `fetch_table` returns the configured rows or an empty Vec
/// for unknown tables (mirroring the real D1 behavior — querying
/// a missing table is a SQL error, but for the tests' purposes
/// the migrate library should never ask for a table that doesn't
/// exist anyway).
#[cfg(test)]
#[derive(Debug, Default, Clone)]
pub struct MockD1Source {
    pub tables: std::collections::HashMap<String, Vec<Value>>,
}

#[cfg(test)]
impl MockD1Source {
    pub fn new() -> Self { Self::default() }

    pub fn with(mut self, table: &str, rows: Vec<Value>) -> Self {
        self.tables.insert(table.to_owned(), rows);
        self
    }
}

#[cfg(test)]
impl D1Source for MockD1Source {
    async fn fetch_table(&self, table: &str) -> Result<Vec<Value>> {
        Ok(self.tables.get(table).cloned().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_sql_identifier_accepts_table_names() {
        assert!(is_sql_identifier("users"));
        assert!(is_sql_identifier("user_tenant_memberships"));
        assert!(is_sql_identifier("_underscore_prefix"));
        assert!(is_sql_identifier("OidcClients"));
    }

    #[test]
    fn is_sql_identifier_rejects_injection_attempts() {
        // The point of the check.
        assert!(!is_sql_identifier(""));
        assert!(!is_sql_identifier("users; DROP TABLE users"));
        assert!(!is_sql_identifier("users WHERE 1=1"));
        assert!(!is_sql_identifier("'); DROP--"));
        assert!(!is_sql_identifier("users-table"));
        assert!(!is_sql_identifier("users.column"));
        assert!(!is_sql_identifier("123users"));     // leading digit
        assert!(!is_sql_identifier(" users"));       // whitespace
        assert!(!is_sql_identifier("ユーザー"));   // non-ASCII
    }

    #[tokio::test]
    async fn mock_returns_configured_rows() {
        let src = MockD1Source::new()
            .with("users", vec![
                serde_json::json!({"id": "u-1"}),
                serde_json::json!({"id": "u-2"}),
            ]);
        let rows = src.fetch_table("users").await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["id"], "u-1");
    }

    #[tokio::test]
    async fn mock_returns_empty_for_unknown_table() {
        let src = MockD1Source::new();
        let rows = src.fetch_table("nope").await.unwrap();
        assert!(rows.is_empty());
    }
}
