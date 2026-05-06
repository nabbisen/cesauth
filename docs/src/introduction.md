# cesauth

> Headless-first IDaaS on Cloudflare Workers, written in Rust.

cesauth takes its name from **caesium** (Cs) — the element whose atomic
oscillation defines the SI second. The project aims for the same kind
of precision in authentication and authorization: small surface area,
strong consistency where it matters, every credential transition
audited.

## Who is this book for?

The book is split into two halves by audience. Both halves are
complete on their own — you do not need to read the expert chapters to
finish the beginner chapters, and vice versa.

### Getting Started (Beginner)

Start here if you have never run cesauth before. You will:

- Install the Rust toolchain and Wrangler.
- Provision D1, KV, R2, and Durable Objects locally.
- Create a user, issue a Magic Link, verify it, and run the full OIDC
  Authorization Code + PKCE flow — all from `curl`.
- Learn how to inspect state (D1 tables, audit log) and reset between
  runs.

No prior Cloudflare Workers experience required.

### Concepts & Reference (Expert)

Start here if you are integrating cesauth, auditing its security
posture, or extending it. You will find:

- The architectural decisions behind the five-crate workspace and the
  ports-and-adapters boundary.
- Which storage backend is canonical for which kind of state, and why
  KV is deliberately excluded from anything forgeable.
- The WebAuthn subset cesauth supports, how it is verified, and what
  was deliberately left out.
- Session cookie format, CSRF model, operational logging categories,
  Turnstile escalation rules.
- End-to-end flow traces for OIDC, refresh rotation, and revocation.

## Design principles

1. **Minimal surface — minus the admin path.** No SAML, no LDAP, no
   password login. An admin console (`/admin/console/*`) and tenant-scoped
   admin surface (`/admin/t/<slug>/*`) ship for operator use.
2. **Strong consistency first.** Anything that must not double-spend
   lives in Durable Objects.
3. **Passkey first, username-less first.** Magic Link is a fallback,
   not the default.
4. **Slim dependency graph.** Only what is known to build on the
   Workers WASM target.
5. **Accessibility baked in.** Semantic HTML, `aria-live`,
   keyboard-navigable forms.
6. **Audit everything sensitive.** Authentication, admin, failures,
   revocations — all land in D1's hash-chained `audit_events` table (ADR-010).

## Status

cesauth is **under active development**. The
[`ROADMAP.md`](https://github.com/…/cesauth/blob/main/ROADMAP.md) at
the project root tracks what is shipped, in progress, or planned.
Breaking changes land in the [`CHANGELOG.md`](https://github.com/…/cesauth/blob/main/CHANGELOG.md)
at the same level.

## A note on Cloudflare

cesauth is designed **exclusively for the Cloudflare Workers
platform**. It relies on Workers-native primitives (Durable Objects,
D1, KV, R2) that have no straightforward substitute elsewhere. The
project is also bound by Cloudflare's Terms of Service and Acceptable
Use Policy — please read [`TERMS_OF_USE.md`](https://github.com/…/cesauth/blob/main/TERMS_OF_USE.md)
before deploying.
