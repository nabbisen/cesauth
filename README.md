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

This is the spine, in the order you actually do it — not every step
in [Migrating from local to production](docs/src/deployment/production.md),
just what you cannot safely skip. Follow each link for the procedure:

1. **Pre-flight, then provision resources** — [Pre-flight checklist](docs/src/deployment/preflight.md),
   then [provision D1 / KV / R2 / Durable Objects](docs/src/deployment/production.md#step-1--provision-real-resources)
2. **Migrations `--remote`** — [production.md, Step 2](docs/src/deployment/production.md#step-2--apply-migrations-remotely)
3. **Seed the signing key** — [production.md, Step 3](docs/src/deployment/production.md#step-3--seed-production-rows) — not optional: without the public half registered in `jwt_signing_keys`, `/jwks.json` serves no keys and every token cesauth issues fails verification
4. **Secrets**, including the first admin's `ADMIN_API_KEY` — [Secrets & environment variables](docs/src/deployment/secrets.md) ([production.md, Step 4](docs/src/deployment/production.md#step-4--set-production-secrets))
5. **Confirm `WRANGLER_LOCAL` is off** — [production.md, Step 6](docs/src/deployment/production.md#step-6--confirm-wrangler_local-is-off) — a classic footgun if skipped, not optional
6. **Configure Cron Triggers** — [Cron Triggers](docs/src/deployment/cron-triggers.md)
7. **`wrangler deploy`** — [production.md, Step 9](docs/src/deployment/production.md#step-9--deploy)
8. **Register your first OIDC client** — [production.md, Step 5](docs/src/deployment/production.md#step-5--register-your-oidc-clients) — comes *after* deploy here, even though the chapter numbers it Step 5; the chapter's own Step 5 curls a URL that isn't live until Step 9, a pre-existing inconsistency this list does not repeat (tracked for a future documentation-sequencing pass)
9. **Observability** — [Observability](docs/src/deployment/observability.md)
10. **Day-2** — [Day-2 operations runbook](docs/src/deployment/runbook.md)

Not on this list but in the chapter: configuring Magic Link mail
delivery (the chapter's Step 7 — only matters if you rely on the Magic
Link fallback rather than passkeys) and a local `cargo audit` dependency
check (the chapter's Step 8 — already run on every push by CI). Real
steps, just not ones a first deploy breaks without. Every "Step N" above
is `production.md`'s numbering, not this list's.

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
