# Security policy

Thank you for taking the time to help keep cesauth safe. This document
explains how to report security issues, what is in scope, and what to
expect from us when you do.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security reports.**

Instead, send a private report via one of these channels, in order of
preference:

1. **GitHub Security Advisories** — use the "Report a vulnerability"
   button on the repository's Security tab. This creates a private
   advisory visible only to the repository maintainers and you.
2. **Email** — `nabbisen@scqr.net` . PGP key available on
   request.

In your report, please include:

- A description of the issue and its impact.
- Steps to reproduce, with a minimal proof-of-concept if possible.
- The affected component (crate, endpoint, configuration).
- The cesauth version or commit SHA you tested against.
- Your name and contact details for attribution if you want credit.

We will acknowledge your report within **5 business days** and aim
to provide a substantive response within **15 business days**.

## Disclosure timeline

We follow a coordinated-disclosure model with a **90-day default
window** from the date we acknowledge your report. During this
window:

- We will work with you on reproduction, impact assessment, and a
  fix.
- We will agree with you on a disclosure date, normally aligned with
  the fix being released.
- If the issue is actively exploited, we may shorten the window.
- If the fix requires coordination with upstream projects (Cloudflare
  platform, `worker-rs`, `jsonwebtoken`, `ed25519-dalek`, etc.), we
  may extend the window; we will communicate the reason.

After the disclosure date, the advisory becomes public with credit
to you unless you request otherwise.

## Scope

### In scope

Issues in the **cesauth codebase itself**:

- **Authentication bypass.** Any path where a non-authenticated
  request obtains a session, an access token, or an ID token.
- **Token forgery.** Signature verification bypass, algorithm
  confusion, key substitution, or any path that mints a valid-looking
  token for a user who did not authenticate.
- **Authorization-code issues.** Replay after redeem, TTL bypass,
  PKCE verifier bypass, code substitution across clients.
- **Refresh-token issues.** Family-reuse detection bypass, rotation
  inconsistency, or any path that lets a retired refresh token
  mint a fresh access token.
- **Session handling.** Cookie signature bypass, session fixation,
  race conditions in revocation.
- **CSRF escape.** A cross-origin POST that cesauth accepts despite
  the CSRF controls described in
  [`docs/src/expert/csrf.md`](../docs/src/expert/csrf.md).
- **Privilege escalation.** Any path where a non-admin obtains
  admin-level capabilities.
- **WebAuthn verification flaws.** Signature verification, challenge
  reuse, origin-check bypass.
- **Injection.** SQL injection in D1 queries, HTML / script injection
  in rendered templates.
- **Information disclosure.** Any endpoint that leaks a secret, a
  credential ID, or another user's data to an unauthenticated or
  under-authenticated caller.
- **Dev-route leakage.** `/__dev/*` behavior that lets a production
  deployment reveal audit contents or stage auth codes despite
  `WRANGLER_LOCAL != "1"`.

### Out of scope

- **Cloudflare platform issues.** Vulnerabilities in Workers, D1,
  Durable Objects, KV, R2, Turnstile, or the Cloudflare control
  plane should be reported directly to Cloudflare via
  <https://hackerone.com/cloudflare> or
  <https://www.cloudflare.com/disclosure/>. We will help triage
  whether an issue is a cesauth issue or a Cloudflare-platform
  issue if you are unsure.
- **Downstream deployments' misconfiguration.** A user who sets
  `WRANGLER_LOCAL="1"` in production, reuses `JWT_SIGNING_KEY` across
  environments, or fails to rotate credentials is not a cesauth
  vulnerability — but guidance on avoiding the footgun is welcome.
- **Denial of service via unreasonable request volume.** Rate
  limiting in cesauth is tunable via `wrangler.toml` `[vars]`; a
  report that cesauth falls over at a rate the operator has not
  budgeted for is a capacity-planning matter, not a security issue.
- **Abuse of a deployed instance** (phishing, spam via Magic Link,
  content abuse). Report these under
  [`TERMS_OF_USE.md`](../TERMS_OF_USE.md) — that file has the abuse
  contact and the Cloudflare reporting path.

### Unsure?

If you are not sure whether something is in scope, send the report
and we will triage it. Unclear-scope issues are always better
reported than withheld.

## Safe harbor

We support responsible security research. If you act in good faith
and follow this policy — specifically, you do not access data that
is not yours, you do not degrade service for other users, and you
give us reasonable time to respond — we will not pursue or support
legal action against you.

## Fix delivery

Security fixes are released as patch versions and documented in
[`CHANGELOG.md`](../CHANGELOG.md) under the **Security** section of
the release. A concurrent GitHub Security Advisory documents the
CVE (if assigned), affected versions, and remediation.

For deployed instances, the upgrade path is normally a
`git pull && wrangler deploy`. If a fix requires a schema migration
or a secret rotation, the advisory will spell it out.

---

For abuse reports on **deployed cesauth instances** (not source-code
vulnerabilities), see [`TERMS_OF_USE.md`](../TERMS_OF_USE.md).
