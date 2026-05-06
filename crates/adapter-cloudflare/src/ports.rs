//! Cloudflare implementations of the `cesauth_core::ports` traits.
//!
//! The crate split:
//!
//! * **DO-shaped stores** (`store.rs`) call into the four DO classes
//!   via the `Env::durable_object(...)` binding. Their RPC shape is
//!   the tagged enum defined alongside each DO class.
//! * **D1 repositories** (`repo.rs`) translate between `cesauth_core`
//!   domain types and the SQL rows defined in `migrations/`.
//! * **D1 audit chain** (`audit.rs`) writes chain-extended rows to
//!   the `audit_events` D1 table (v0.32.0+, ADR-010). Pre-v0.32.0
//!   this slot held an R2-backed sink; the R2 path was retired.
//! * **KV cache** (`cache.rs`) wraps the `CACHE` namespace.
//!
//! Adapters take a `&Env` at construction and do *not* clone it - the
//! binding handles are cheap references, and we want every request's
//! adapter to use the freshest bindings rather than stashed copies.

pub mod audit;
pub mod cache;
pub mod repo;
pub mod store;
