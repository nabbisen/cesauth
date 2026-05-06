use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use super::error::{MigrateError, MigrateResult};
use super::types::{FORMAT_VERSION, Manifest, PayloadLine, SCHEMA_VERSION};
use super::import::ImportSink;
use super::verify::verify as verify_dump;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// Source table — which payload table the offending row was in.
    pub table:    String,
    /// Source row primary key, if extractable. Best-effort: rows
    /// without a recognizable `id` field surface here as
    /// `<unknown>`. The CLI uses this for operator diagnostics.
    pub row_id:   String,
    /// One-line description of what went wrong. Examples: "tenant_id
    /// references missing tenant", "duplicate email within tenant",
    /// "role_id references missing role".
    pub reason:   String,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}: {}", self.table, self.row_id, self.reason)
    }
}

/// Outcome of `Importer::run`. Lists the violations collected per
/// table along with the count of rows the importer attempted to
/// write. The CLI uses this to decide whether to commit or roll
/// back, and to print a structured operator summary.
#[derive(Debug, Clone, Default)]
pub struct ViolationReport {
    pub rows_seen:   u64,
    pub rows_staged: u64,
    pub violations:  Vec<Violation>,
}

impl ViolationReport {
    /// True when no violations were detected. The CLI uses this as
    /// the gate for commit-without-`--accept-violations`.
    pub fn is_clean(&self) -> bool { self.violations.is_empty() }

    /// Count violations by table — useful for the CLI's tabular
    /// summary. Returns a Vec rather than HashMap so output
    /// ordering matches the table declaration order in the
    /// manifest.
    pub fn by_table(&self) -> Vec<(String, u64)> {
        let mut out: Vec<(String, u64)> = Vec::new();
        for v in &self.violations {
            if let Some(entry) = out.iter_mut().find(|(t, _)| t == &v.table) {
                entry.1 += 1;
            } else {
                out.push((v.table.clone(), 1));
            }
        }
        out
    }
}

/// Per-row schema-invariant check function. Called once per row
/// during import; returns `None` if the row is OK, `Some(reason)`
/// if it violates an invariant. The library ships a default set
/// in `default_invariant_checks()`; the CLI can extend or replace.
///
/// The check has read access to "what's been imported so far" via
/// the `seen` parameter — a snapshot of `(table, row_id)` pairs
/// the importer has staged. This lets a check ask "does
/// `users.tenant_id` reference a tenant we've already imported"
/// without a destination-side query.
///
/// As of v0.22.0 the parameter is `&mut SeenSnapshot` so checks
/// that maintain secondary indexes (e.g., per-tenant email
/// uniqueness) can populate them. Checks that only read still
/// pass the parameter through; the borrow-check is unchanged
/// for them.
pub type InvariantCheckFn = fn(
    table: &str,
    row:   &serde_json::Value,
    seen:  &mut SeenSnapshot,
) -> Option<String>;

/// Snapshot of staged rows. Keyed by table; each entry is a
/// `HashSet<String>` of primary-key values seen so far. Maintained
/// by the `Importer` as rows arrive.
///
/// "Seen" means "the exporter wrote it earlier in the dump", not
/// "it's in the destination D1". The destination's pre-existing
/// rows are NOT in `SeenSnapshot` — the importer's contract is
/// "destination starts empty for the migrated tables", which the
/// CLI enforces via a pre-flight check.
///
/// As of v0.22.0 the snapshot also tracks **scoped secondary
/// indexes**: `(table, scope_key, scope_value, secondary_value)`
/// → presence. Used by uniqueness checks that need to know
/// whether a tuple like `(tenant_id, email)` has been seen
/// within a tenant. Populated by the importer alongside primary
/// keys; consulted by check functions.
#[derive(Debug, Default, Clone)]
pub struct SeenSnapshot {
    inner: std::collections::HashMap<String, std::collections::HashSet<String>>,
    /// `(table, scope_key, scope_value)` → set of secondary values.
    /// E.g., `("users", "tenant_id", "t-1")` → `{"alice@x", "bob@y"}`.
    /// Populated only when a check function asks the snapshot to
    /// remember secondary uniqueness, via
    /// `record_scoped_secondary` (called from check fn).
    scoped_secondary: std::collections::HashMap<
        (String, String, String),
        std::collections::HashSet<String>,
    >,
}

impl SeenSnapshot {
    /// Returns true if `(table, id)` was previously staged.
    pub fn contains(&self, table: &str, id: &str) -> bool {
        self.inner.get(table).map(|s| s.contains(id)).unwrap_or(false)
    }
    pub fn insert(&mut self, table: &str, id: String) {
        self.inner.entry(table.to_owned()).or_default().insert(id);
    }

    /// Returns true if `(table, scope_key=scope_value, secondary)`
    /// has been seen. Used by per-tenant uniqueness checks.
    /// Always false until `record_scoped_secondary` is called for
    /// the same key — checks that don't populate the index won't
    /// observe anything.
    pub fn contains_scoped_secondary(
        &self,
        table:        &str,
        scope_key:    &str,
        scope_value:  &str,
        secondary:    &str,
    ) -> bool {
        self.scoped_secondary
            .get(&(table.to_owned(), scope_key.to_owned(), scope_value.to_owned()))
            .map(|s| s.contains(secondary))
            .unwrap_or(false)
    }

    /// Insert into the scoped secondary index. Returns true if
    /// the value was already present (which is the duplicate-
    /// detection signal a uniqueness check uses).
    pub fn record_scoped_secondary(
        &mut self,
        table:       &str,
        scope_key:   &str,
        scope_value: &str,
        secondary:   String,
    ) -> bool {
        let already = self.scoped_secondary
            .entry((table.to_owned(), scope_key.to_owned(), scope_value.to_owned()))
            .or_default()
            .insert(secondary);
        // `insert` returns true if newly inserted, false if already present.
        // Flip — caller wants "was already present".
        !already
    }
}

/// The destination-side row writer. The library doesn't know how
/// to talk to D1; the CLI provides the implementation (wrangler
/// shell-out or future native API). Trait shape kept narrow:
/// `stage_row` is "queue this row for eventual write",
/// `commit`/`rollback` finalize.
///
/// Why staging-then-commit instead of write-as-we-go: ADR-005 §Q5
/// requires the importer to refuse commit on violations. Writing
/// each row immediately makes rollback impossible (or expensive —
/// would need a destination-side undo). Staging keeps the
/// destination unmodified until the operator-confirmed commit
/// moment.
#[allow(async_fn_in_trait)]

/// Default invariant checks. The CLI uses this set unless the
/// operator-supplied `--no-invariant-checks` flag disables them.
/// New invariants land here as cesauth's schema evolves.
///
/// Invariants in v0.22.0:
///
/// 1. **Memberships' user_id references seen user.** Any row in
///    `user_tenant_memberships`, `user_organization_memberships`,
///    or `user_group_memberships` that names a `user_id` not
///    previously staged in `users` is flagged.
/// 2. **Memberships' container references seen container.** A
///    `tenant_id`/`organization_id`/`group_id` not previously
///    staged is flagged.
/// 3. **users.tenant_id references seen tenant.** A user with a
///    tenant_id not in `tenants` is flagged.
/// 4. **role_assignments references seen role + user.**
/// 5. **users.email unique per tenant.** Catches duplicate
///    `(tenant_id, email)` tuples within the dump. Added in
///    v0.22.0; redaction-aware (see check function docs).
///
/// Not yet checked (deferred to follow-ups):
/// - OIDC client `redirect_uris` JSON validity — out of scope for
///   the migration tool; the destination's `oidc_clients` repo
///   re-validates on first use.
pub fn default_invariant_checks() -> &'static [InvariantCheckFn] {
    &[
        check_user_tenant_ref,
        check_membership_user_ref,
        check_membership_container_ref,
        check_role_assignment_refs,
        check_user_email_unique_per_tenant,
    ]
}

pub(super) fn extract_id(row: &serde_json::Value) -> String {
    row.get("id").and_then(|v| v.as_str()).unwrap_or("<unknown>").to_owned()
}

fn extract_str<'a>(row: &'a serde_json::Value, field: &str) -> Option<&'a str> {
    row.get(field).and_then(|v| v.as_str())
}

pub(super) fn check_user_tenant_ref(
    table: &str,
    row:   &serde_json::Value,
    seen:  &mut SeenSnapshot,
) -> Option<String> {
    if table != "users" { return None; }
    let tenant_id = extract_str(row, "tenant_id")?;
    if !seen.contains("tenants", tenant_id) {
        return Some(format!("tenant_id `{tenant_id}` references missing tenant"));
    }
    None
}

pub(super) fn check_membership_user_ref(
    table: &str,
    row:   &serde_json::Value,
    seen:  &mut SeenSnapshot,
) -> Option<String> {
    let is_membership = matches!(table,
        "user_tenant_memberships"
        | "user_organization_memberships"
        | "user_group_memberships"
    );
    if !is_membership { return None; }
    let user_id = extract_str(row, "user_id")?;
    if !seen.contains("users", user_id) {
        return Some(format!("user_id `{user_id}` references missing user"));
    }
    None
}

pub(super) fn check_membership_container_ref(
    table: &str,
    row:   &serde_json::Value,
    seen:  &mut SeenSnapshot,
) -> Option<String> {
    let (container_table, field) = match table {
        "user_tenant_memberships"       => ("tenants",       "tenant_id"),
        "user_organization_memberships" => ("organizations", "organization_id"),
        "user_group_memberships"        => ("groups",        "group_id"),
        _ => return None,
    };
    let id = extract_str(row, field)?;
    if !seen.contains(container_table, id) {
        return Some(format!("{field} `{id}` references missing {container_table} row"));
    }
    None
}

pub(super) fn check_role_assignment_refs(
    table: &str,
    row:   &serde_json::Value,
    seen:  &mut SeenSnapshot,
) -> Option<String> {
    if table != "role_assignments" { return None; }
    if let Some(role_id) = extract_str(row, "role_id") {
        if !seen.contains("roles", role_id) {
            return Some(format!("role_id `{role_id}` references missing role"));
        }
    }
    if let Some(user_id) = extract_str(row, "user_id") {
        if !seen.contains("users", user_id) {
            return Some(format!("user_id `{user_id}` references missing user"));
        }
    }
    None
}

/// Email-uniqueness within a tenant. Pinned to `users` table.
/// Each `(tenant_id, email)` tuple must be seen at most once.
///
/// **Redaction-aware**: when emails come from a redacted dump
/// (HashedEmail kind), the values are deterministic distinct
/// hashes. The check still runs and still catches duplicates
/// — same source emails produce same redacted values, so a
/// duplicate at source remains a duplicate after redaction.
/// What the check WON'T flag is "different source emails
/// happen to hash to the same redacted value" — vanishingly
/// improbable given SHA-256.
///
/// What about NULL emails? The cesauth schema declares
/// `users.email TEXT UNIQUE COLLATE NOCASE` — NULL is
/// permitted (anonymous users). The check skips rows with
/// missing/NULL email.
///
/// Implemented in v0.22.0; deferred from v0.21.0 because of
/// concerns about redaction semantics that turned out (after
/// implementation) to not be problematic.
pub(super) fn check_user_email_unique_per_tenant(
    table: &str,
    row:   &serde_json::Value,
    seen:  &mut SeenSnapshot,
) -> Option<String> {
    if table != "users" { return None; }
    let Some(email)     = extract_str(row, "email")     else { return None; };
    let Some(tenant_id) = extract_str(row, "tenant_id") else { return None; };
    // Lower-case the email for comparison. cesauth's schema
    // uses COLLATE NOCASE; emulating that here keeps the
    // semantic match.
    let email_norm = email.to_ascii_lowercase();
    let already = seen.record_scoped_secondary(
        "users", "tenant_id", tenant_id, email_norm.clone(),
    );
    if already {
        return Some(format!(
            "email `{email}` duplicates an earlier user in tenant `{tenant_id}`"
        ));
    }
    None
}

/// Streaming importer. Reads a dump from `input`, verifies its
/// signature + hashes (via `verify`), then re-streams the payload
/// while:
///
/// - staging each row to `sink`,
/// - running invariant checks against the in-memory `SeenSnapshot`,
/// - accumulating violations.
///
/// Returns the report; the caller (CLI) decides whether to call
/// `sink.commit()` or `sink.rollback()` based on
/// `report.is_clean()` plus operator confirmation.
///
/// **Two-pass.** The first pass is `verify` (full payload SHA-256
/// + signature). The second pass is the actual import. Both
/// passes are necessary: a signature check on the bytes the
/// importer is about to act on must precede acting on them. The
/// caller passes a `Read` that supports re-reading; in practice
/// this is `BufReader<File>` and the importer seeks to start
/// between passes.
pub async fn import<S: ImportSink>(
    input:        &mut (impl std::io::Read + std::io::Seek),
    sink:         &mut S,
    invariants:   &[InvariantCheckFn],
    require_unredacted: bool,
) -> MigrateResult<ViolationReport> {
    use std::io::{BufReader, SeekFrom};

    // ---- Pass 1: verify ---------------------------------------------
    input.seek(SeekFrom::Start(0))?;
    let report = verify_dump(BufReader::new(&mut *input))?;
    if require_unredacted && report.manifest.redaction_profile.is_some() {
        return Err(MigrateError::Parse(format!(
            "dump was exported with redaction profile `{}`; \
             --require-unredacted refuses to import",
            report.manifest.redaction_profile.as_deref().unwrap_or("?"),
        )));
    }

    // ---- Pass 2: stream rows + run invariants + stage --------------
    input.seek(SeekFrom::Start(0))?;
    let mut reader = BufReader::new(&mut *input);

    // Skip the manifest line.
    let mut manifest_line = String::new();
    std::io::BufRead::read_line(&mut reader, &mut manifest_line)?;

    let mut seen = SeenSnapshot::default();
    let mut violations = Vec::new();
    let mut rows_seen   = 0_u64;
    let mut rows_staged = 0_u64;

    let mut line = String::new();
    loop {
        line.clear();
        let n = std::io::BufRead::read_line(&mut reader, &mut line)?;
        if n == 0 { break; }
        rows_seen += 1;

        let pl: PayloadLine = serde_json::from_str(line.trim_end_matches('\n'))
            .map_err(|e| MigrateError::Parse(format!("payload line: {e}")))?;

        // Run invariants. Multiple checks may fire on the same row;
        // collect all of them.
        let row_id = extract_id(&pl.row);
        let mut row_violated = false;
        for chk in invariants {
            if let Some(reason) = chk(&pl.table, &pl.row, &mut seen) {
                violations.push(Violation {
                    table:  pl.table.clone(),
                    row_id: row_id.clone(),
                    reason,
                });
                row_violated = true;
            }
        }

        // Stage the row regardless. Violations don't prevent
        // staging — they prevent commit. This means the caller's
        // sink may see rows that violate, and the sink must NOT
        // perform its own validation (the library is the
        // authority).
        sink.stage_row(&pl.table, &pl.row).await
            .map_err(MigrateError::Parse)?;
        rows_staged += 1;

        // Update the seen snapshot. We add the row's id even if
        // the row violated something — downstream checks that
        // depend on this row's existence stay coherent. If the
        // operator later rolls back, the seen snapshot is
        // discarded with the import process.
        seen.insert(&pl.table, row_id.clone());

        // `row_violated` is intentionally unused beyond
        // accumulation; future versions may use it to short-circuit
        // staging when a configurable max-violations threshold is
        // hit.
        let _ = row_violated;
    }

    Ok(ViolationReport { rows_seen, rows_staged, violations })
}



