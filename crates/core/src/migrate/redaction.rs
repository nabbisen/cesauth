use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use super::error::{MigrateError, MigrateResult};
use super::types::PayloadLine;

pub struct RedactionProfile {
    /// Operator-facing name, used at the CLI as
    /// `--profile <name>`. Recorded in the manifest so the
    /// importer knows what was scrubbed.
    pub name: &'static str,

    /// What this profile does, one paragraph. Surfaced by
    /// `cesauth-migrate export --list-profiles`.
    pub description: &'static str,

    /// Per-table column transformations. `(table, column,
    /// transform)`. A column not listed is preserved as-is.
    pub rules: &'static [RedactionRule],

    /// Tables to drop entirely from the export. Used when
    /// per-column scrubbing isn't safe enough — TOTP secrets
    /// must not survive redaction (ADR-009 §Q5/§Q11) even
    /// hashed, because a staging deployment with real users'
    /// hashed TOTP secrets would let any staging operator
    /// brute-force the secret offline (the search space is
    /// 2^160 in theory but in practice an attacker only needs
    /// to enumerate plausible 160-bit secrets generated from
    /// the staging worker's CSPRNG, which they can re-run with
    /// staging entropy).
    ///
    /// Added in v0.30.0 alongside the TOTP track conclusion.
    /// The CLI export loop checks this list and skips the
    /// matching tables; the manifest records them as
    /// `dropped_tables` so the importer can verify the
    /// redacted dump matches the profile description.
    pub drop_tables: &'static [&'static str],
}

/// Single column-level transformation in a redaction profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedactionRule {
    pub table:  &'static str,
    pub column: &'static str,
    pub kind:   RedactionKind,
}

/// Kind of transformation a redaction rule applies. Each kind
/// preserves whatever cesauth-side invariants the column is
/// involved in (uniqueness, referential integrity), while
/// removing identifying value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionKind {
    /// Replace with a deterministic synthetic value derived
    /// from a hash of the original. Used for emails: the
    /// hash makes redacted values stable across runs (so a
    /// re-export of the same source produces the same redacted
    /// output), and the synthetic format
    /// (`anon-<hex>@example.invalid`) preserves the
    /// `users.email` UNIQUE invariant.
    HashedEmail,
    /// Replace with the literal string `"[redacted]"`. Used
    /// for free-form display names where collision doesn't
    /// matter for invariants.
    StaticString,
    /// Drop the value (set to JSON `null`). Used for columns
    /// that are optional in the schema and not load-bearing
    /// for invariants.
    Null,
}

/// Built-in redaction profiles. The CLI's
/// `--list-profiles` flag enumerates these. Custom profiles
/// land in v0.20.0 alongside the export path.
pub fn built_in_profiles() -> &'static [RedactionProfile] {
    &BUILT_IN_PROFILES
}

/// Look up a built-in profile by name. Returns `None` for
/// unknown profiles. CLI maps `None` to a recoverable error
/// with the list of known profile names.
pub fn lookup_profile(name: &str) -> Option<&'static RedactionProfile> {
    BUILT_IN_PROFILES.iter().find(|p| p.name == name)
}

const BUILT_IN_PROFILES: [RedactionProfile; 2] = [
    RedactionProfile {
        name: "prod-to-staging",
        description: "\
Replace user emails with hashed synthetic values that preserve \
the UNIQUE invariant; drop display names. Authenticator \
public-key material is preserved (it's not PII; passkey \
challenges live in DO state and aren't dumped). Audit-event \
subject IDs are preserved (they're already pseudonyms — user \
ids, not raw identifiers). \
\n\nTOTP authenticators and recovery codes are dropped entirely \
(see ADR-009 §Q5/§Q11) — TOTP secrets must NOT survive \
redaction, even encrypted, because a staging deployment with \
real users' encrypted TOTP secrets would let any staging \
operator authenticate as those users.",
        rules: &[
            RedactionRule { table: "users",       column: "email",        kind: RedactionKind::HashedEmail   },
            RedactionRule { table: "users",       column: "display_name", kind: RedactionKind::StaticString  },
        ],
        drop_tables: &[
            "totp_authenticators",
            "totp_recovery_codes",
        ],
    },
    RedactionProfile {
        name: "prod-to-dev",
        description: "\
Stricter than `prod-to-staging`: also nulls out OIDC clients' \
display names and admin tokens' display names, on the theory \
that a developer machine has weaker isolation than a staging \
environment. Use for `wrangler dev`-bound dumps. \
\n\nLike `prod-to-staging`, drops TOTP authenticators and \
recovery codes entirely — the threat surface is even worse on \
a developer's laptop than on staging.",
        rules: &[
            RedactionRule { table: "users",        column: "email",         kind: RedactionKind::HashedEmail  },
            RedactionRule { table: "users",        column: "display_name",  kind: RedactionKind::StaticString },
            RedactionRule { table: "oidc_clients", column: "name",          kind: RedactionKind::StaticString },
            RedactionRule { table: "admin_tokens", column: "name",          kind: RedactionKind::Null         },
        ],
        drop_tables: &[
            "totp_authenticators",
            "totp_recovery_codes",
        ],
    },
];

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

/// Decode a base64-url-no-pad string into bytes. Returns `None`
/// for any decode error — callers map to their own error type.
pub(super) fn base64_url_decode(s: &str) -> Option<Vec<u8>> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.decode(s.as_bytes()).ok()
}

// ---------------------------------------------------------------------
// Redaction application
// ---------------------------------------------------------------------

/// Apply a redaction profile to one row. Caller passes the table
/// name and the row as a JSON object; returns the transformed row.
/// Rows whose table is not mentioned in the profile pass through
/// unchanged. Columns not mentioned in the profile pass through
/// unchanged.
///
/// This is the only place redaction is applied; the export function
/// calls into it once per row. Centralizing here means there is
/// exactly one definition of "what does `prod-to-staging` do",
/// matching the manifest's `redaction_profile` field.
pub fn apply_redaction(
    profile: &RedactionProfile,
    table:   &str,
    row:     &mut serde_json::Value,
) {
    let serde_json::Value::Object(map) = row else { return };
    for rule in profile.rules {
        if rule.table != table { continue; }
        let Some(v) = map.get_mut(rule.column) else { continue };
        match rule.kind {
            RedactionKind::HashedEmail => {
                // For string values, derive a synthetic email from
                // SHA-256 of the original. Preserves users.email
                // UNIQUE constraint after redaction. Format:
                // "anon-<8 hex chars>@example.invalid". Stable
                // across runs (same input → same output) so a
                // re-export of the same source produces a
                // diff-friendly dump.
                if let Some(s) = v.as_str() {
                    use sha2::{Digest, Sha256};
                    let mut h = Sha256::new();
                    h.update(s.as_bytes());
                    let digest = h.finalize();
                    let hex8: String = digest[..4].iter()
                        .map(|b| format!("{b:02x}"))
                        .collect();
                    *v = serde_json::Value::String(
                        format!("anon-{hex8}@example.invalid"),
                    );
                }
                // Non-string values (NULL etc.) pass through —
                // the schema invariants on the receiving side will
                // re-validate.
            }
            RedactionKind::StaticString => {
                *v = serde_json::Value::String("[redacted]".to_owned());
            }
            RedactionKind::Null => {
                *v = serde_json::Value::Null;
            }
        }
    }
}

// ---------------------------------------------------------------------
// Export
