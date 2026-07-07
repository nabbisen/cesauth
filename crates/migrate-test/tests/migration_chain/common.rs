//! Shared helpers for migration_chain integration tests.
//!
//! Split out from `tests/migration_chain.rs` in v0.77.0.

use rusqlite::{Connection, Result as RusqliteResult};
use std::{fs, path::PathBuf};


/// Path to the workspace-root `migrations/` directory.
pub fn migrations_dir() -> PathBuf {
    // The integration test binary runs from the workspace root or a
    // crate-local CWD.  We walk upward until we find `migrations/`.
    let mut dir = std::env::current_dir().expect("current_dir");
    loop {
        let candidate = dir.join("migrations");
        if candidate.is_dir() {
            return candidate;
        }
        if !dir.pop() {
            panic!(
                "Could not find migrations/ directory from {:?}",
                std::env::current_dir().unwrap()
            );
        }
    }
}

/// Open an in-memory SQLite database and apply every migration in
/// lexical order.  Returns the open connection.
pub fn apply_all_migrations() -> RusqliteResult<Connection> {
    let conn = Connection::open_in_memory()?;

    // Enable foreign keys for the session so that FK violations
    // surface during the apply loop.
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;

    let mdir = migrations_dir();
    let mut files: Vec<_> = fs::read_dir(&mdir)
        .unwrap_or_else(|e| panic!("read migrations dir {:?}: {e}", mdir))
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|x| x == "sql")
                .unwrap_or(false)
        })
        .map(|e| e.path())
        .collect();
    files.sort(); // lexical order == numeric order for 0001..NNN

    for path in &files {
        let sql = fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {:?}: {e}", path));
        // SQLite's PRAGMA foreign_key_check inside a migration returns
        // rows on violation; we ignore the result here (the FK-check
        // test below catches violations post-apply).
        conn.execute_batch(&sql)
            .unwrap_or_else(|e| panic!("apply {:?}: {e}", path));
    }

    Ok(conn)
}

/// Return the expected SCHEMA_VERSION: the count of *.sql files in
/// migrations/.
pub fn expected_schema_version() -> u32 {
    let mdir = migrations_dir();
    fs::read_dir(&mdir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|x| x == "sql")
                .unwrap_or(false)
        })
        .count() as u32
}

// ---------------------------------------------------------------------------
