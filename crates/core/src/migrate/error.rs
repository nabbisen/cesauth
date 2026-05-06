use serde::{Deserialize, Serialize};

pub type MigrateResult<T> = Result<T, MigrateError>;

#[derive(Debug)]
pub enum MigrateError {
    /// A `Read`/`Write` on the underlying stream failed. Mostly disk
    /// or pipe issues; not cesauth's problem to diagnose further.
    Io(std::io::Error),

    /// The manifest line could not be parsed as JSON, or a payload
    /// line was malformed. The dump is corrupt or not a `.cdump`.
    Parse(String),

    /// A `format_version` in the dump is unknown to this build.
    /// Old dumps from newer cesauth releases land here. Cesauth does
    /// not silently downgrade — the importer must explicitly know
    /// the format.
    UnsupportedFormatVersion { found: u32, supported: u32 },

    /// The signature did not verify. Either the dump was tampered
    /// with in transit, or the signature was produced for a
    /// different payload than what arrived. Treat as security
    /// event.
    SignatureMismatch,

    /// A per-table SHA-256 in the manifest disagrees with what was
    /// computed while streaming the payload. Localizes corruption to
    /// a specific table.
    TableHashMismatch { table: String },

    /// The whole-payload SHA-256 in the manifest disagrees with
    /// what was computed while streaming. The signature might be
    /// valid (signing a different payload-hash) but the payload
    /// itself was substituted.
    PayloadHashMismatch,

    /// Random number generation failed. Astronomically unlikely on
    /// a real machine; surfaced as a distinct kind so a CI hosted
    /// without `/dev/urandom` is diagnosable.
    Random(String),

    /// Internal cryptographic error from `ed25519-dalek`. Surfaced
    /// here rather than swallowed so a debugging operator gets a
    /// useful trail.
    Crypto(String),
}

impl std::fmt::Display for MigrateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e)                                  => write!(f, "I/O error: {e}"),
            Self::Parse(s)                               => write!(f, "parse error: {s}"),
            Self::UnsupportedFormatVersion { found, supported } => {
                write!(f, "unsupported .cdump format version {found} (this build supports {supported})")
            }
            Self::SignatureMismatch                      => write!(f, "signature did not verify (dump tampered or substituted)"),
            Self::TableHashMismatch { table }            => write!(f, "table hash mismatch on `{table}` (table-localized corruption)"),
            Self::PayloadHashMismatch                    => write!(f, "payload hash mismatch (whole-payload corruption)"),
            Self::Random(s)                              => write!(f, "RNG failure: {s}"),
            Self::Crypto(s)                              => write!(f, "crypto error: {s}"),
        }
    }
}

impl std::error::Error for MigrateError {}

impl From<std::io::Error> for MigrateError {
    fn from(e: std::io::Error) -> Self { Self::Io(e) }
}


// ---------------------------------------------------------------------
// Format version constants
