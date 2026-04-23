# Changelog

All notable changes to cesauth will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

cesauth is pre-1.0. The public surface — endpoints, `wrangler.toml`
variable names, secret names, D1 schema, and `core::ports` traits —
may change between minor versions until 1.0. Breaking changes will
always be called out here.

---

## [Unreleased]

### Added

- **Documentation restructure.** The previous monolithic
  `docs/architecture.md` and `docs/local-development.md` have been
  migrated into an [mdBook](https://rust-lang.github.io/mdBook/) site
  under `docs/`, split into a beginner-facing *Getting Started* track
  and an expert-facing *Concepts & Reference* track plus a
  *Deployment* section and an *Appendix* (endpoints, error codes,
  glossary).
- **Project governance files at the repository root.** `ROADMAP.md`,
  `CHANGELOG.md`, `.github/SECURITY.md`, `TERMS_OF_USE.md`.
- **`/token` observability.** Every 500 path in the token handler now
  emits a structured `log::emit` line with the appropriate category
  (`Config`, `Crypto`, or `Auth`), so `wrangler tail` shows the
  immediate cause of a token-endpoint failure instead of a bare 500.
- **Dev-only helper routes** (`GET /__dev/audit`,
  `POST /__dev/stage-auth-code/:handle`), gated on
  `WRANGLER_LOCAL="1"`. They exist to make the end-to-end curl
  tutorial runnable without a browser cookie jar. Production deploys
  MUST NOT set `WRANGLER_LOCAL`.

### Changed

- **README is now slim.** Storage responsibilities, crate layout, and
  implementation status have moved out of the README into the book
  (storage / crate layout) and `ROADMAP.md` (implementation status).
  The README keeps a Quick Start and an Endpoints table and points
  into the book for detail.
- **`jsonwebtoken` now built with the `rust_crypto` feature.**
  Version 10.x requires a crypto provider; we pick the pure-Rust one
  (ed25519-dalek / p256 / rsa / sha2 / hmac / rand) and explicitly
  NOT `aws_lc_rs`, which vendors a C library and does not build for
  `wasm32-unknown-unknown`. With `default-features = false` and
  neither feature set, jsonwebtoken 10 panics at first use.
- **`config::load_signing_key` normalizes escape sequences.** The
  function accepts either real newlines or literal `\n` escapes in
  the PEM body; the latter is useful for single-line dotenv setups.

### Fixed

- **D1 `bind()` now uses a `d1_int(i64) -> JsValue` helper.**
  `wasm_bindgen` converts a Rust `i64` into a JavaScript `BigInt` on
  the wire, but D1's `bind()` rejects BigInt with
  `cannot be bound`. The helper coerces via `JsValue::from_f64` the
  same way worker-rs's `D1Type::Integer` does internally. Every
  INSERT / UPDATE site now uses it.
- **`run_err(context, worker::Error) -> PortError::Unavailable`
  helper** logs the underlying D1 error via `console_error!` before
  collapsing it into the payload-less `PortError::Unavailable`
  variant. Previously, the HTTP layer just said "storage error" with
  no breadcrumb.
- **`.tables` in the beginner tutorial** (`sqlite3` dot-command) has
  been replaced with a real `SELECT … FROM sqlite_master` query.
  `wrangler d1 execute` runs its `--command` argument through D1's
  SQL path, which does not interpret dot-commands.

### Security

- **Session cookies now use HMAC-SHA256, not JWT.** The session
  cookie is an internal server-to-browser token with no need for
  algorithm negotiation or third-party verification, and the
  simpler `<b64url(payload)>.<b64url(hmac)>` format sidesteps a
  class of JWT-library pitfalls.
- **`__Host-cesauth_pending` is unsigned by design; `__Host-cesauth_session` is signed.**
  The pending cookie carries only a server-side handle; forging it
  points to a non-existent or mis-bound challenge and is rejected
  on `take`. The session cookie carries identity and MUST be signed.
- **Sensitive log categories default to off.** `Auth`, `Session`, and
  `Crypto` lines are dropped unless `LOG_EMIT_SENSITIVE=1` is set.
  Enabling this in production should be an explicit, time-boxed ops
  action.

---

## Release-gate reminders

Before cesauth's first production deploy:

1. Replace the `dev-delivery` audit line in
   `routes::magic_link::request` with a real transactional-mail
   HTTP call keyed by `MAGIC_LINK_MAIL_API_KEY`.
2. `WRANGLER_LOCAL` MUST be `"0"` (or unset) in the deployed
   environment. Verify with an explicit `[env.production.vars]`
   entry rather than relying on inheritance.
3. Freshly generate `JWT_SIGNING_KEY`, `SESSION_COOKIE_KEY`, and
   `ADMIN_API_KEY` per environment; do not reuse local-dev values.

See
[Deployment → Migrating from local to production](docs/src/deployment/production.md)
for the full release-gate walkthrough.

---

## Format

Each future release will have sections in this order:

- **Added** — new user-facing capability.
- **Changed** — behavior that existed previously and now works
  differently.
- **Deprecated** — slated for removal in a later release.
- **Removed** — gone this release.
- **Fixed** — bugs fixed.
- **Security** — vulnerability fixes or security-relevant posture
  changes. See also [.github/SECURITY.md](.github/SECURITY.md).

[Unreleased]: https://github.com/nabbisen/cesauth/commits/main
