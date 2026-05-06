# Security policy

Thank you for taking the time to help keep cesauth safe. This document
explains how to report security issues, what is in scope, and what to
expect from us when you do.

## Reporting a vulnerability

If you believe you have found a security issue in cesauth:

1. **Do not file a public GitHub issue.** Public issues become indexable
   immediately and put other operators at risk.
2. **Open a [private security advisory](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)**
   on the repository: https://github.com/nabbisen/cesauth/security/advisories/new

In your report, please include:

- A description of the issue and its impact.
- Steps to reproduce, with a minimal proof-of-concept if possible.
- The affected component (crate, endpoint, configuration).
- The cesauth version or commit SHA you tested against.
- Your name and contact details are optional and will only be used for attribution if you explicitly consent. You may request full anonymity, in which case we will not disclose your identity publicly or internally beyond the core maintainers.

## What you can expect

- An acknowledgement within a small number of days.
- A discussion of severity and timeline before any public disclosure.
- Credit in the changelog and security advisory unless you ask for
  anonymity.

### Response targets by severity

These are best-effort SLAs, not contractual commitments; major incidents may temporarily push them out. Response times depend on the availability of maintainers and the complexity of the issue. These targets are aspirational goals and do not create any binding obligation. We may miss these targets during holidays, weekends, or periods of high maintainer workload.

| Severity | Acknowledgment | Initial assessment | Fix target |
|---|---|---|---|
| **Critical** (RCE, auth bypass, secret exfiltration, token forgery) | 48 hours | 120 hours | 10 days |
| **High** (privilege escalation, XSS in admin UI, CSRF on state-changing routes, refresh-token reuse not detected) | 96 hours | 10 days | 45 days |
| **Medium** (information disclosure, DoS, audit log integrity loss) | 10 business days | 21 days | 120 days |
| **Low** (header misconfigurations, low-impact info leak, missing telemetry) | 20 business days | 90 days | next minor release |

## Disclosure timeline

We follow a coordinated-disclosure model with a **120-day default
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

### Cloudflare Platform Dependency and Liability Boundaries

cesauth is built on top of Cloudflare Workers, D1, and related services. While we rigorously test our application logic, we do not control the underlying Cloudflare infrastructure.

- **Platform-Level Incidents:** Issues stemming from Cloudflare Workers runtime bugs, D1 database inconsistencies, KV storage failures, or global network outages are considered platform incidents, not cesauth vulnerabilities. In such cases, we will monitor Cloudflare's status page and advisories, and coordinate with the community to mitigate impact until Cloudflare resolves the issue.
- **Configuration Responsibility:** The security of a deployed cesauth instance relies heavily on correct configuration (e.g., `wrangler.toml` settings, environment variables, and DNS records). Misconfigurations introduced by the operator (such as exposing dev routes in production or using weak secrets) are not vulnerabilities in the cesauth codebase. We provide documentation and pre-flight checks to assist, but the final responsibility for secure deployment lies with the operator.
- **Third-Party Dependencies:** Vulnerabilities in upstream dependencies (e.g., `worker-rs`, `jsonwebtoken`) that are outside the scope of our control will be addressed by coordinating with the respective maintainers. We will track these issues and apply patches as soon as they are released upstream.

If you are unsure whether an issue is caused by cesauth logic or the Cloudflare platform, please report it. We will help triage the root cause.

### Unsure?

If you are not sure whether something is in scope, send the report
and we will triage it. Unclear-scope issues are always better
reported than withheld.

## Known Limitations and Design Trade-offs

The following items are documented architectural decisions or known constraints in the current version of cesauth. They are **not** considered vulnerabilities for the purpose of this policy, provided they are used within their intended context. However, they represent potential attack surfaces that operators and users should be aware of.

### Content Security Policy (CSP) Configuration
- **Current State:** The login, OAuth authorization, and admin console pages currently utilize `Content-Security-Policy` with `'unsafe-inline'` for styles and scripts.
- **Rationale:** This is a temporary measure to ensure compatibility with certain browser extensions and legacy template rendering engines.
- **Mitigation:** The policy strictly enforces `frame-ancestors 'none'`, `base-uri 'none'`, and `default-src 'none'`, and disallows `'unsafe-eval'`. These controls are the primary defense against clickjacking and code injection.
- **Roadmap:** Migration to nonce-based or hash-based CSP (removing `'unsafe-inline'`) is tracked in our ROADMAP. Reports regarding bypasses of the *existing* strict headers (e.g., `frame-ancestors`) remain in scope.

### Authentication Mechanisms
- **No Per-Account Brute-Force Lockout:** cesauth does not implement account lockouts for failed login attempts because it does not support password authentication.
- **Rationale:** Authentication is handled exclusively via Magic Links (high-entropy tokens) and WebAuthn (cryptography-based). These mechanisms inherently resist brute-force attacks due to token entropy and cryptographic signature verification.
- **Future Considerations:** A per-client lockout mechanism for OIDC `client_secret` brute-forcing is planned for a future release. Until then, operators are advised to rely on Cloudflare's rate-limiting capabilities at the edge.
- **Note:** If a report demonstrates that the token generation or signature verification logic itself is flawed (allowing prediction or forgery), this is a critical vulnerability and remains in scope.

### Development Mode Behavior
- **OTP Logging in `dev-delivery`:** In `dev-delivery` mode, One-Time Passwords (OTPs) are printed to the audit log for debugging purposes.
- **Constraint:** This mode is strictly intended for local development (`WRANGLER_LOCAL="1"`).
- **Operator Responsibility:** Production deployments **must** configure `MAGIC_LINK_MAIL_API_KEY` and ensure `dev-delivery` is disabled. Failure to do so is a deployment misconfiguration, not a software vulnerability. Guidance on securing production deployments is available in [`docs/src/deployment/preflight.md`](../docs/src/deployment/preflight.md).

### Admin Route Protection
- **Header-Based Authorization:** The `/admin/*` routes require an `Authorization: Bearer` header.
- **Implication:** Standard browser-based CSRF attacks are mitigated because browsers cannot automatically attach custom headers to cross-origin requests.
- **Caveat:** This protection relies on the absence of a cookie-fallback path. If a future update introduces cookie-based authentication for admin routes, the CSRF audit (documented in [`docs/src/expert/csrf-audit.md`](../docs/src/expert/csrf-audit.md)) must be re-evaluated before release.

**Important Note:** While these limitations are documented, they do not absolve operators of the responsibility to secure their deployments. Any exploit that goes *beyond* these documented limitations (e.g., a CSP bypass that defeats `frame-ancestors`, or a brute-force attack on a correctly implemented Magic Link) is considered a valid security report.

## Safe harbor

We support responsible security research. If you act in good faith and follow this policy — specifically, you do not access data that is not yours, you do not degrade service for other users, and you give us reasonable time to respond — We intend not to pursue legal action against researchers who act in good faith and comply with this policy. However, this safe harbor does not override Cloudflare's Terms of Service, applicable laws, or the rights of third parties. If your actions cause significant damage or violate these terms, we reserve the right to take necessary measures.

## Fix delivery

Security fixes are released as patch versions and documented in
[`CHANGELOG.md`](../CHANGELOG.md) under the **Security** section of
the release. A concurrent GitHub Security Advisory documents the
CVE (if assigned), affected versions, and remediation.

For deployed instances, the upgrade path is normally a
`git pull && wrangler deploy`. If a fix requires a schema migration
or a secret rotation, the advisory will spell it out.

## See also

- [`docs/src/expert/csrf.md`](../docs/src/expert/csrf.md) — CSRF model.
- [`docs/src/expert/csrf-audit.md`](../docs/src/expert/csrf-audit.md) — v0.24.0 CSRF audit (re-runs documented).
- [`docs/src/expert/security.md`](../docs/src/expert/security.md) — broader security model and pre-production release gates.
- [`docs/src/expert/adr/007-security-response-headers.md`](../docs/src/expert/adr/007-security-response-headers.md) — ADR-007: HTTP security response headers.
- [`docs/src/deployment/security-headers.md`](../docs/src/deployment/security-headers.md) — operator guide for HTTP security response headers.

---

For abuse reports on **deployed cesauth instances** (not source-code
vulnerabilities), see [`TERMS_OF_USE.md`](../TERMS_OF_USE.md).
