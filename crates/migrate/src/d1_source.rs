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

/// Fully-resolved tenant filter for a single table. The caller
/// (the export driver) computes this from the table's
/// `TenantScope` and the operator's `--tenant` list, then hands
/// it to the source implementation. `column` is the SQL column
/// name; `ids` is the operator-supplied tenant list.
///
/// Tables with `TenantScope::Global` or no operator filter pass
/// `None` instead of constructing this struct.
#[derive(Debug, Clone)]
pub struct TenantFilter<'a> {
    pub column: &'a str,
    pub ids:    &'a [String],
}

/// Read-only access to a D1 database. Each call returns rows
/// from one table, in primary-key order. Caller iterates tables
/// in topological order.
///
/// The trait is `async` because real implementations call out to
/// network or shell. The mock blocks immediately. No assumption
/// about thread safety — callers use one source at a time.
///
/// `filter` (added in v0.22.0): optional per-table tenant scope.
/// `None` returns every row; `Some(TenantFilter)` returns rows
/// whose `column` is in `ids`.
#[allow(async_fn_in_trait)]
pub trait D1Source {
    /// Return rows from one table, ordered by primary key,
    /// optionally filtered.
    async fn fetch_table(&self, table: &str, filter: Option<TenantFilter<'_>>)
        -> Result<Vec<Value>>;
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
    async fn fetch_table(&self, table: &str, filter: Option<TenantFilter<'_>>)
        -> Result<Vec<Value>>
    {
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

        // Build SQL. With a filter, add a WHERE column IN ('id1','id2',...).
        // Without a filter, plain SELECT.
        let sql = match &filter {
            None => format!("SELECT * FROM {table} ORDER BY rowid"),
            Some(f) => {
                if !is_sql_identifier(f.column) {
                    anyhow::bail!(
                        "filter column `{}` for table `{table}` is not a valid SQL identifier",
                        f.column,
                    );
                }
                if f.ids.is_empty() {
                    // Empty filter list — no rows match anything.
                    // Return early without spawning wrangler.
                    return Ok(Vec::new());
                }
                // Quote each id with single quotes; SQLite-style escape.
                let in_list = f.ids.iter()
                    .map(|id| format!("'{}'", id.replace('\'', "''")))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!(
                    "SELECT * FROM {table} WHERE {column} IN ({in_list}) ORDER BY rowid",
                    column = f.column,
                )
            }
        };

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
    async fn fetch_table(&self, table: &str, filter: Option<TenantFilter<'_>>)
        -> Result<Vec<Value>>
    {
        let rows = self.tables.get(table).cloned().unwrap_or_default();
        let Some(f) = filter else { return Ok(rows); };
        if f.ids.is_empty() { return Ok(Vec::new()); }
        // Naive filter: keep rows whose `column` value is a string
        // present in `ids`. Sufficient for tests; real wrangler
        // path uses SQL.
        let kept = rows.into_iter()
            .filter(|row| {
                row.get(f.column)
                    .and_then(|v| v.as_str())
                    .map(|v| f.ids.iter().any(|id| id == v))
                    .unwrap_or(false)
            })
            .collect();
        Ok(kept)
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
        let rows = src.fetch_table("users", None).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["id"], "u-1");
    }

    #[tokio::test]
    async fn mock_returns_empty_for_unknown_table() {
        let src = MockD1Source::new();
        let rows = src.fetch_table("nope", None).await.unwrap();
        assert!(rows.is_empty());
    }

    #[tokio::test]
    async fn mock_filter_keeps_matching_tenant_rows() {
        // The filter is the load-bearing part of --tenant: only
        // rows whose `tenant_id` is in the operator-supplied list
        // come through.
        let src = MockD1Source::new()
            .with("users", vec![
                serde_json::json!({"id": "u-1", "tenant_id": "t-acme"}),
                serde_json::json!({"id": "u-2", "tenant_id": "t-other"}),
                serde_json::json!({"id": "u-3", "tenant_id": "t-acme"}),
            ]);
        let ids = vec!["t-acme".to_string()];
        let f = TenantFilter { column: "tenant_id", ids: &ids };
        let rows = src.fetch_table("users", Some(f)).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r["tenant_id"] == "t-acme"));
    }

    #[tokio::test]
    async fn mock_filter_empty_ids_returns_no_rows() {
        // Empty filter list = no tenants requested = no rows.
        // (The CLI rejects empty filter at the operator boundary,
        // but the source must handle it cleanly anyway.)
        let src = MockD1Source::new()
            .with("users", vec![serde_json::json!({"id":"u-1","tenant_id":"t-1"})]);
        let ids: Vec<String> = vec![];
        let f = TenantFilter { column: "tenant_id", ids: &ids };
        let rows = src.fetch_table("users", Some(f)).await.unwrap();
        assert!(rows.is_empty());
    }
}
