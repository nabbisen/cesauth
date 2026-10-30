# cesauth

> Headless-first IDaaS on Cloudflare Workers, written in Rust.
>
> The name comes from **caesium (Cs)** — the element whose atomic
> oscillation defines the SI second. cesauth aspires to the same
> precision in authentication and authorization.

![Status](https://img.shields.io/badge/status-unstable-red)
[![crates.io](https://img.shields.io/crates/v/cesauth?label=rust)](https://crates.io/crates/cesauth)
[![Documentation](https://docs.rs/cesauth/badge.svg?version=latest)](https://docs.rs/cesauth)
[![Dependency Status](https://deps.rs/crate/cesauth/latest/status.svg)](https://deps.rs/crate/cesauth)
[![License](https://img.shields.io/github/license/nabbisen/cesauth)](https://github.com/nabbisen/cesauth/blob/main/LICENSE)

> The three badges above point at a **`0.0.0` name reservation**, not a
> published library — none of this workspace's seven crates are published
> (`publish = false`). See [Publishing to
> crates.io](docs/src/expert/contributing.md#publishing-to-cratesio).

---

## Design principles

- **Minimal surface — minus the admin path.** No SAML, no LDAP, no password
  login. cesauth ships an admin console (`/admin/console/*`) and a tenant-scoped
  admin surface (`/admin/t/<slug>/*`) for operator and tenant administration —
  but no end-user signup gallery and no public registration UI.
- **Strong consistency first.** Anything that must not double-spend lives in
  Durable Objects.
- **Passkey first, username-less first.** Magic Link is a fallback, not the
  default.
- **Slim dependency graph.** Only what's known to build on the Workers WASM
  target.
- **Accessibility baked in.** Semantic HTML, `aria-live`, keyboard-navigable
  forms.
- **Audit everything sensitive.** Authentication, admin, failures, revocations —
  all land in D1's hash-chained `audit_events` table (ADR-010). cesauth does not
  push these rows to an external SIEM today — see
  [Observability](docs/src/deployment/observability.md).

---

## Quick start

### Run it locally

This is the contributor / evaluation loop — a local Cloudflare
simulation (Miniflare), no network-side setup:

```sh
# Host-only domain tests — no Cloudflare needed:
cargo test

# Full flow with Miniflare. Local D1/KV/DOs are auto-provisioned
# from the bindings in wrangler.toml — you do NOT call
# `wrangler d1 create` etc. for local dev.
wrangler d1 migrations apply cesauth --local
wrangler dev
```

A full curl-based walkthrough — admin user creation → Magic Link →
OIDC Authorization Code + PKCE → refresh rotation → revocation —
lives in the book:

**→ [docs/src/beginner/first-oidc-flow.md](docs/src/beginner/first-oidc-flow.md)**

### Deploy it

Each step owns its own chapter — read this list for the order, then
follow the link for the procedure:

1. **Pre-flight** — [Pre-flight checklist](docs/src/deployment/preflight.md)
2. **`wrangler deploy`** — [Migrating from local to production, Step 9](docs/src/deployment/production.md#step-9--deploy)
3. **Secrets** — [Secrets & environment variables](docs/src/deployment/secrets.md)
4. **Migrations `--remote`** — [Migrating from local to production, Step 2](docs/src/deployment/production.md#step-2--apply-migrations-remotely)
5. **First admin** — [Migrating from local to production, Step 4](docs/src/deployment/production.md#step-4--set-production-secrets) (`ADMIN_API_KEY`)
6. **First OIDC client** — [Migrating from local to production, Step 5](docs/src/deployment/production.md#step-5--register-your-oidc-clients)
7. **Observability** — [Observability](docs/src/deployment/observability.md)
8. **Day-2** — [Day-2 operations runbook](docs/src/deployment/runbook.md)

---

## Endpoints

| Method | Path                                   | Purpose                             |
|--------|----------------------------------------|-------------------------------------|
| GET    | `/.well-known/openid-configuration`    | OIDC discovery                      |
| GET    | `/jwks.json`                           | Public keys                         |
| GET    | `/authorize`                           | Authorization Code + PKCE start     |
| POST   | `/token`                               | Token exchange + refresh            |
| POST   | `/revoke`                              | Token revocation                    |
| POST   | `/webauthn/register/start` / `/finish` | Passkey registration ceremony       |
| POST   | `/webauthn/authenticate/start` / `/finish` | Passkey authentication ceremony |
| POST   | `/magic-link/request` / `/verify`      | Email OTP fallback                  |
| POST   | `/admin/users` · DELETE `/admin/sessions/:id` | Admin (bearer auth)          |

Request/response shapes, error codes, and dev-only routes are
documented in the book's
[endpoint reference](docs/src/appendix/endpoints.md).

---

## For more detail, see our full documentation

cesauth's full documentation is an mdBook under [`docs/`](docs/),
split by audience:

- **[Getting Started](docs/src/beginner/prerequisites.md)** —
  prerequisites, first local run, your first OIDC flow with curl,
  inspecting state, troubleshooting. Start here if you have never
  run cesauth before.
- **[Concepts & Reference](docs/src/expert/architecture.md)** —
  architecture, storage model, crate layout, ports-and-adapters
  pattern, OIDC internals, WebAuthn subset, session cookie format,
  CSRF model, operational logging, Turnstile integration, security
  considerations.
- **[Deployment](docs/src/deployment/wrangler.md)** — Wrangler
  configuration, secrets handling, and
  [migrating from local to production](docs/src/deployment/production.md)
  (with its own [pre-flight checklist](docs/src/deployment/preflight.md)).
- **[Appendix](docs/src/appendix/endpoints.md)** — endpoint
  reference, error codes, glossary.

To build and serve the book locally:

```sh
cargo install mdbook          # one-time
mdbook serve docs             # http://localhost:3000
```

---

## Project status & governance

- **[ROADMAP.md](ROADMAP.md)** — what's shipped, what's planned,
  what's deliberately out of scope.
- **[CHANGELOG.md](CHANGELOG.md)** — notable changes per release.
- **[.github/SECURITY.md](.github/SECURITY.md)** — how to report
  security vulnerabilities. Please do not open public issues for
  security reports.
- **[TERMS_OF_USE.md](TERMS_OF_USE.md)** — cesauth is built
  exclusively on the Cloudflare Workers platform. Read this before
  deploying.

cesauth is in **active development**. The public surface (endpoints,
`wrangler.toml` variable names, secret names, D1 schema,
`core::ports` traits) may change between minor versions. Breaking
changes are called out in [CHANGELOG.md](CHANGELOG.md).
