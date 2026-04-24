//! In-memory implementations of the DO-shaped store ports.
//!
//! Each impl uses a single `Mutex<HashMap>` keyed by the handle. Since
//! all of `async fn` here is synchronous under the hood, the mutex is a
//! faithful stand-in for per-key DO serialization: two concurrent
//! callers will be ordered, the first wins state transitions, the
//! second sees the post-first state.
//!
//! One submodule per store trait.

mod active_session;
mod auth_challenge;
mod rate_limit;
mod refresh_token_family;

pub use active_session::InMemoryActiveSessionStore;
pub use auth_challenge::InMemoryAuthChallengeStore;
pub use rate_limit::InMemoryRateLimitStore;
pub use refresh_token_family::InMemoryRefreshTokenFamilyStore;

#[cfg(test)]
mod tests;
