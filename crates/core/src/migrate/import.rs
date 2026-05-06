use serde::{Deserialize, Serialize};
use sha2::Digest as _;

pub trait ImportSink {
    /// Buffer one row for the named table. Caller invokes once
    /// per row, in the same order as the dump's payload.
    async fn stage_row(&mut self, table: &str, row: &serde_json::Value)
        -> Result<(), String>;

    /// Apply every staged row. Returns the number of rows actually
    /// written (typically equal to total staged unless the sink
    /// short-circuits some).
    async fn commit(&mut self) -> Result<u64, String>;

    /// Discard every staged row. The destination is left
    /// unmodified. Called when the operator declines commit, or
    /// when the import fails before commit.
    async fn rollback(&mut self) -> Result<(), String>;
}
