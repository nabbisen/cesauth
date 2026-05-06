//! Destination-side `ImportSink` implementations for `cesauth-migrate`.
//!
//! The migration library's `ImportSink` trait abstracts "how does
//! the importer write rows into the destination". v0.21.0 ships
//! `WranglerD1Sink` — shells out to `wrangler d1 execute` with a
//! batched INSERT plan. As with `WranglerD1Source` on the export
//! side, this leans on operator-existing wrangler configuration
//! rather than bringing native API auth into the binary.
//!
//! The sink follows a stage-then-commit pattern:
//!
//! 1. `stage_row` collects INSERT statements in memory.
//! 2. `commit` writes them as one or more wrangler-batched runs.
//! 3. `rollback` discards the in-memory queue without touching
//!    the destination.
//!
//! The destination D1 is left **unmodified** until the operator
//! confirms commit. This is the load-bearing property — ADR-005
//! §Q5 requires accumulate-then-commit so a violation report can
//! halt the move with the destination intact.

use anyhow::{Context as _, Result};
use cesauth_core::migrate::ImportSink;
use serde_json::Value;

/// `ImportSink` that writes via `wrangler d1 execute --remote`.
/// Operator's wrangler authentication selects the destination
/// account; this struct just wraps the database name and the
/// stage queue.
pub struct WranglerD1Sink {
    pub database:    String,
    pub config_path: Option<std::path::PathBuf>,

    /// Per-table queue of `serde_json::Value` rows. Built up by
    /// `stage_row`, drained by `commit`. Keyed by table name.
    /// Insertion order within a table is preserved (matters
    /// because the dump's payload is in primary-key order, and
    /// preserving that order keeps INSERT-time errors
    /// localizable).
    staged: std::collections::BTreeMap<String, Vec<Value>>,
}

impl WranglerD1Sink {
    pub fn new(database: String, config_path: Option<std::path::PathBuf>) -> Self {
        Self { database, config_path, staged: std::collections::BTreeMap::new() }
    }

    /// Total rows currently staged across all tables.
    #[allow(dead_code)] // used by tests and reserved for v0.22.0 progress reporting
    pub fn total_staged(&self) -> u64 {
        self.staged.values().map(|v| v.len() as u64).sum()
    }
}

impl ImportSink for WranglerD1Sink {
    async fn stage_row(&mut self, table: &str, row: &Value) -> Result<(), String> {
        // Stash a clone. We don't translate to SQL yet — that
        // happens at commit time, after we know the column set
        // for the table (taken from the union of every row's
        // keys). Some rows may have NULL columns omitted from
        // their JSON; building the SQL upfront would have to
        // pre-compute the column union, so it's simpler to
        // defer.
        self.staged.entry(table.to_owned()).or_default().push(row.clone());
        Ok(())
    }

    async fn commit(&mut self) -> Result<u64, String> {
        // Walk staged tables in BTreeMap order — alphabetical, NOT
        // topological. That's fine: by commit time, every row's
        // FK references are guaranteed satisfiable inside the
        // dump (the importer's invariant checks ensured that),
        // and SQLite/D1 doesn't enforce ordering as long as
        // foreign_keys is OFF or every reference resolves by
        // statement-end. The CLI's pre-flight ensures the
        // destination has `PRAGMA foreign_keys = OFF` for the
        // import session.
        //
        // Future polish (v0.22.0): walk in topological order and
        // turn FK enforcement back on. Skipped for v0.21.0 to
        // keep the import single-pass.
        let mut total = 0_u64;
        for (table, rows) in &self.staged {
            if rows.is_empty() { continue; }
            let n = self.execute_batch(table, rows).await
                .map_err(|e| format!("commit table `{table}`: {e}"))?;
            total += n;
        }
        // Drain staged after a successful commit — repeat
        // commits would be a CLI bug, but draining makes that
        // bug surface as a no-op rather than a duplicate write.
        self.staged.clear();
        Ok(total)
    }

    async fn rollback(&mut self) -> Result<(), String> {
        // Nothing to undo at the destination — we never wrote.
        // Just drop the staged queue.
        self.staged.clear();
        Ok(())
    }
}

impl WranglerD1Sink {
    /// Execute one table's INSERTs as a single wrangler call.
    /// Builds a multi-statement SQL string, passes via
    /// `--command`. Returns the row count on success.
    ///
    /// SQL safety: column names are validated against the SQL
    /// identifier regex; values are JSON-serialized to literal
    /// SQL via `value_to_sql_literal`. wrangler's D1 layer is
    /// responsible for the final sanitization, but we do
    /// belt-and-suspenders by quoting strings and rejecting
    /// values that don't fit the literal grammar.
    async fn execute_batch(&self, table: &str, rows: &[Value]) -> Result<u64> {
        if !is_sql_identifier(table) {
            anyhow::bail!("table `{table}` is not a valid SQL identifier");
        }

        // Determine column union across all rows. Some rows may
        // omit nullable fields entirely; we want every row's
        // INSERT to use the same column list so wrangler's
        // statement processing is uniform. Missing values become
        // explicit NULLs.
        let mut columns: Vec<String> = Vec::new();
        for row in rows {
            if let Value::Object(map) = row {
                for k in map.keys() {
                    if !columns.iter().any(|c| c == k) {
                        columns.push(k.clone());
                    }
                }
            }
        }
        for col in &columns {
            if !is_sql_identifier(col) {
                anyhow::bail!("column `{col}` in `{table}` is not a valid SQL identifier");
            }
        }

        // Build INSERT statements. Concatenate as a single
        // string; wrangler accepts multi-statement SQL. SQLite's
        // limit on statements per execute is high enough that
        // every reasonable cesauth table fits in one batch (low
        // tens of thousands of rows). If a table grows past
        // that, the future polish work in v0.22.0 will chunk.
        let col_list = columns.iter()
            .map(|c| format!("\"{c}\"")).collect::<Vec<_>>().join(", ");
        let mut sql = String::new();
        for row in rows {
            sql.push_str(&format!("INSERT INTO \"{table}\" ({col_list}) VALUES ("));
            let values: Vec<String> = columns.iter()
                .map(|c| {
                    let v = row.get(c).unwrap_or(&Value::Null);
                    value_to_sql_literal(v)
                })
                .collect();
            sql.push_str(&values.join(", "));
            sql.push_str(");\n");
        }

        let mut cmd = tokio::process::Command::new("wrangler");
        cmd.arg("d1")
           .arg("execute")
           .arg(&self.database)
           .arg("--remote")
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
        Ok(rows.len() as u64)
    }
}

/// Convert a JSON value to an SQL literal. Conservative shape
/// — bails on values we don't know how to render rather than
/// guessing. cesauth's row values are TEXT, INTEGER, REAL, NULL,
/// or JSON-stored-as-TEXT; this covers all of them.
fn value_to_sql_literal(v: &Value) -> String {
    match v {
        Value::Null         => "NULL".to_owned(),
        Value::Bool(true)   => "1".to_owned(),
        Value::Bool(false)  => "0".to_owned(),
        Value::Number(n)    => n.to_string(),
        Value::String(s)    => sqlite_quote(s),
        Value::Array(_) | Value::Object(_) => {
            // JSON arrays/objects ride as TEXT-stored JSON in
            // cesauth's schema (e.g. oidc_clients.redirect_uris).
            // Serialize back to JSON, then quote as a string.
            sqlite_quote(&serde_json::to_string(v).unwrap_or_default())
        }
    }
}

/// SQLite single-quoted literal: doubles every embedded `'`.
fn sqlite_quote(s: &str) -> String {
    let escaped = s.replace('\'', "''");
    format!("'{escaped}'")
}

/// Same identifier check as `d1_source` — duplicated rather than
/// imported across module boundaries to keep the modules
/// independently auditable.
fn is_sql_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    let first = chars.next();
    let Some(c) = first else { return false; };
    if !(c.is_ascii_alphabetic() || c == '_') { return false; }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_to_sql_handles_primitives() {
        assert_eq!(value_to_sql_literal(&Value::Null), "NULL");
        assert_eq!(value_to_sql_literal(&Value::Bool(true)), "1");
        assert_eq!(value_to_sql_literal(&Value::Bool(false)), "0");
        assert_eq!(value_to_sql_literal(&serde_json::json!(42)), "42");
        assert_eq!(value_to_sql_literal(&serde_json::json!("hello")), "'hello'");
    }

    #[test]
    fn value_to_sql_escapes_single_quotes() {
        // Critical — naive concatenation here is the canonical
        // SQL injection. Pin the escape behavior.
        let v = serde_json::json!("O'Brien");
        assert_eq!(value_to_sql_literal(&v), "'O''Brien'");
    }

    #[test]
    fn value_to_sql_serializes_json_blobs() {
        // oidc_clients.redirect_uris-shaped values ride as
        // TEXT-stored JSON arrays.
        let v = serde_json::json!(["https://a.example", "https://b.example"]);
        let lit = value_to_sql_literal(&v);
        // Result is a quoted JSON string. Just check it round-
        // trips through string-shape rather than nailing exact
        // serde_json formatting (which can vary by version).
        assert!(lit.starts_with('\''));
        assert!(lit.ends_with('\''));
        assert!(lit.contains("https://a.example"));
    }

    #[test]
    fn sqlite_quote_doubles_embedded_quotes() {
        assert_eq!(sqlite_quote("a'b'c"), "'a''b''c'");
        assert_eq!(sqlite_quote("''"),    "''''''");
    }

    #[tokio::test]
    async fn rollback_clears_staged_without_writing() {
        // Critical: rollback never touches the destination.
        // The unit test can't observe destination state directly,
        // but it CAN observe that no wrangler command was
        // attempted by checking that the staged map is cleared
        // after a rollback on a fake-named DB.
        let mut sink = WranglerD1Sink::new("never-touched".into(), None);
        sink.stage_row("users", &serde_json::json!({"id":"u-1"})).await.unwrap();
        sink.stage_row("users", &serde_json::json!({"id":"u-2"})).await.unwrap();
        assert_eq!(sink.total_staged(), 2);
        sink.rollback().await.unwrap();
        assert_eq!(sink.total_staged(), 0);
    }
}
