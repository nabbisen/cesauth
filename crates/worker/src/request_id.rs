//! Per-request correlation identifier — RFC 015.
//!
//! Sourced from the `cf-ray` header in production (a globally-unique
//! Cloudflare edge identifier already present in Logpush and the dashboard),
//! with a `local-<uuid>` fallback for `WRANGLER_LOCAL=1` development and
//! testing environments where no real cf-ray is generated.
//!
//! The identifier is threaded through [`LogConfig`](crate::log::LogConfig)
//! so every log line emitted during a request carries it, enabling
//! post-hoc grouping of related lines during incident review.
//!
//! The identifier is also written to `audit_events.request_id`
//! (added by migration 0015) so audit rows can be cross-linked to
//! the surrounding log lines.
//!
//! ## Why cf-ray?
//!
//! * **Free**: no allocation, no CSPRNG, no schema work for the id itself.
//! * **Already in operator's pipeline**: Logpush records it; the Cloudflare
//!   dashboard shows it.  Operators already know how to grep for a cf-ray.
//! * **Client-observable**: the header appears in responses, so a client
//!   that captures it on failure can hand it to the operator for correlation.
//! * **Not secret**: cf-ray is already in the response headers cesauth
//!   returns; including it in logs reveals nothing new.
//!
//! ## Length guard
//!
//! `cf-ray` in observed practice is ~20 characters.  The guard at ≤ 64
//! characters is defensive: the Workers runtime overwrites the inbound
//! header, so a malicious client cannot supply an arbitrary value, but a
//! future platform change could make headers longer.

use uuid::Uuid;

/// Maximum accepted length for a cf-ray value before falling back to local.
const CF_RAY_MAX_LEN: usize = 64;

/// Per-request correlation key.  Cheap to clone (small heap string).
#[derive(Debug, Clone)]
pub struct RequestId(String);

impl RequestId {
    /// Attempt to read `cf-ray`; fall back to `local-<uuid>` if absent,
    /// empty, or suspiciously long.
    ///
    /// The `headers_get` closure allows callers to inject a header lookup
    /// without depending on a specific `Request` type, keeping this module
    /// testable without a Workers runtime.
    pub fn from_header_lookup<F>(get_header: F) -> Self
    where
        F: FnOnce(&'static str) -> Option<String>,
    {
        let from_cf = get_header("cf-ray")
            .filter(|v| !v.is_empty() && v.len() <= CF_RAY_MAX_LEN);

        match from_cf {
            Some(ray) => Self(ray),
            None      => Self(format!("local-{}", Uuid::new_v4())),
        }
    }

    /// Convenience constructor for contexts where the cf-ray value is
    /// known up-front (e.g. forwarded from a parent handler).
    pub fn from_known(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Produce a `local-<uuid>` request id (used in cron paths and tests).
    pub fn local() -> Self {
        Self(format!("local-{}", Uuid::new_v4()))
    }

    pub fn as_str(&self) -> &str { &self.0 }

    /// Whether this id was generated locally (no cf-ray available).
    pub fn is_local(&self) -> bool { self.0.starts_with("local-") }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cf_ray_header_used_when_present() {
        let id = RequestId::from_header_lookup(|_| Some("8b3c4d5e6f7a8b9c-NRT".to_owned()));
        assert_eq!(id.as_str(), "8b3c4d5e6f7a8b9c-NRT");
        assert!(!id.is_local());
    }

    #[test]
    fn empty_cf_ray_falls_back_to_local() {
        let id = RequestId::from_header_lookup(|_| Some(String::new()));
        assert!(id.is_local());
        assert!(id.as_str().starts_with("local-"));
    }

    #[test]
    fn missing_cf_ray_falls_back_to_local() {
        let id = RequestId::from_header_lookup(|_| None);
        assert!(id.is_local());
    }

    #[test]
    fn oversized_cf_ray_falls_back_to_local() {
        let big = "a".repeat(CF_RAY_MAX_LEN + 1);
        let id = RequestId::from_header_lookup(|_| Some(big));
        assert!(id.is_local(), "oversized cf-ray must fall back to local");
    }

    #[test]
    fn exactly_max_len_cf_ray_is_accepted() {
        let max = "a".repeat(CF_RAY_MAX_LEN);
        let id = RequestId::from_header_lookup(|_| Some(max.clone()));
        assert_eq!(id.as_str(), max);
        assert!(!id.is_local());
    }

    #[test]
    fn local_constructor_produces_local_prefix() {
        let id = RequestId::local();
        assert!(id.is_local());
        assert!(id.as_str().starts_with("local-"));
    }

    #[test]
    fn distinct_local_ids_are_unique() {
        let a = RequestId::local();
        let b = RequestId::local();
        assert_ne!(a.as_str(), b.as_str(),
            "each RequestId::local() must be unique");
    }

    #[test]
    fn display_produces_the_id_string() {
        let id = RequestId::from_known("test-ray-123");
        assert_eq!(format!("{id}"), "test-ray-123");
    }
}
