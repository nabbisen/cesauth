# Security considerations

This chapter consolidates security-relevant decisions that are
documented elsewhere, plus the trust boundaries you should know
before deploying cesauth.

## Trust boundaries

- **JWT signing key.** Ed25519 PKCS#8 PEM, stored as
  `JWT_SIGNING_KEY` secret. Accessible only in `worker` and only
  through `config::load_signing_key`. The `core::jwt::JwtSigner`
  wrapping it has a redacting `Debug` impl so the key cannot
  accidentally land in a log line.

- **Session cookie key.** `SESSION_COOKIE_KEY` secret, HMAC-SHA256.
  Distinct from `JWT_SIGNING_KEY` by design — the blast radius of
  leaking one does not compromise the other.

- **Admin API key.** `ADMIN_API_KEY` secret. Missing means the admin
  surface is closed; there is no "insecure dev mode" fallback.

- **Turnstile secret.** `TURNSTILE_SECRET`. Fires risk-based per
  `RateLimitStore::hit().escalate`. See
  [Turnstile](./turnstile.md).

- **Mail provider key.** `MAGIC_LINK_MAIL_API_KEY`. Currently unused
  — `routes::magic_link::request` logs the plaintext OTP to the
  audit sink for local development only, and that line is clearly
  marked `dev-delivery`. **Removing that line is a release gate
  before any production deploy.**

## The single-use / reuse-burn properties

Two invariants that are enforced by Durable Objects and verified by
`adapter-test`:

1. **Auth codes are single-use.** `AuthChallengeStore::take` returns
   `None` the second time. A race between a legitimate redeem and
   an attacker replay is impossible because the DO serializes all
   requests for a given handle.

2. **Refresh-token reuse burns the entire family.**
   `RefreshTokenFamilyStore::rotate` with a retired jti returns
   `ReusedAndRevoked`; the family is revoked as a side effect.
   Every subsequent operation on the family sees `AlreadyRevoked`.

These are the reasons those stores are DOs rather than D1 rows.

## Error disclosure

Error responses to clients follow **RFC 6749 / 6750 / 7009**.
Internal detail is never leaked past the `worker/` error layer.

- `/token` errors on invalid / expired / replayed codes all return
  `{"error":"invalid_grant"}`. The distinction is in the operational
  log, not the response.
- `/revoke` returns 200 regardless of whether the token existed (to
  prevent existence probing, per RFC 7009).
- `/authorize` errors before `redirect_uri` validation render an
  HTML error page (per RFC 6749 §3.1.2.6); errors after render a
  redirect to `redirect_uri?error=<code>&state=<state>`.

## Rate limits

Every endpoint that accepts user-supplied input has a rate-limit
bucket. The `RateLimit` Durable Object enforces serialized
decrement under a sliding window. Bucket thresholds live in
`wrangler.toml` `[vars]`; tuning them is an operational concern,
not an architectural one.

Hitting the limit returns 429 with `Retry-After`. Approaching the
limit escalates Turnstile (see [Turnstile](./turnstile.md)).

## Logging hygiene

Logs and audit are separate (see [Operational logging](./logging.md)).
Three categories — `Auth`, `Session`, `Crypto` — are flagged
sensitive and dropped unless `LOG_EMIT_SENSITIVE=1`. Enabling
sensitive logs in production should be an explicit, time-boxed ops
action. The default-off posture is there specifically to prevent
credential IDs or JWT internals from ending up in a log aggregator.

## Threat model

cesauth is designed against these:

- **Network attackers** — mitigated by end-to-end TLS (Workers
  requirement), signed session cookies, and HMAC-verified CSRF
  tokens.
- **Credential stuffing / brute force** — mitigated by rate limits
  on `/magic-link/verify` and `/webauthn/authenticate/finish`;
  escalates to Turnstile near the threshold.
- **Authorization code interception** — mitigated by PKCE (S256
  only), `redirect_uri` pre-registration, and auth-code
  single-consumption.
- **Refresh-token theft** — mitigated by the reuse-burns-family
  rule (RFC 9700 §4.14.2).
- **Session hijacking** — mitigated by HMAC-signed session cookies
  with `__Host-` prefix, plus authoritative revocation via
  `ActiveSessionStore`.
- **CSRF on form POSTs** — mitigated by double-submit cookie (see
  [CSRF](./csrf.md)).

cesauth is **not** designed against:

- **Attackers with access to the Cloudflare account.** If they
  can invoke the Worker as admin or read the KV store, they win.
  That is a platform trust decision, not a cesauth one.
- **Targeted attacks on specific users via social engineering of
  magic-link email delivery.** Adding a real mail provider is on
  the roadmap but mail security is the mail provider's problem.
- **Long-lived credential theft from the end user's device.** If a
  passkey is exfiltrated by malware, cesauth cannot distinguish
  the legitimate device from the attacker. Authenticator selection
  (FIDO2 level) would help; it is not wired today.

## Pre-production release gates

Before the first `wrangler deploy`:

1. Remove the `dev-delivery` audit line from
   `routes::magic_link::request` and wire a real mail provider via
   `MAGIC_LINK_MAIL_API_KEY`.
2. Regenerate `JWT_SIGNING_KEY` and `SESSION_COOKIE_KEY` fresh;
   don't reuse local-dev values.
3. Set `WRANGLER_LOCAL` to `"0"` (or omit entirely) in
   `wrangler.toml` `[vars]`. Make sure `[env.production.vars]`
   overrides any inherited `"1"`.
4. Rotate `ADMIN_API_KEY` to a production value of at least 32
   bytes of entropy.
5. Set `TURNSTILE_SECRET` if the deployment needs anti-abuse
   protection beyond pure rate limits.

## Dependency vulnerability scanning

cesauth's dependency tree is scanned against the RustSec Advisory
Database on every push to `main`, every pull request, and on a
weekly cron. The workflow lives at
`.github/workflows/audit.yml` and uses the
`rustsec/audit-check@v2.0.0` action.

### Triggers

- **`push` to `main`** — catches direct merges that bypassed PR
  review.
- **`pull_request`** — blocks PRs that introduce a new
  vulnerable dependency before they merge. The cheapest place to
  catch one.
- **Weekly cron, Mondays 06:00 UTC** — catches advisories that
  appeared *after* a dependency was already in the tree. The
  dependency didn't change; the world's understanding of it did.
  Result lands at the start of the work week so it's visible
  before merges.
- **Manual dispatch** — maintainer can kick off an on-demand
  audit.

### Failure path

The workflow fails on any new advisory matching a Cargo.lock
dependency. On `push` events, the action additionally opens a
GitHub issue describing the advisory (the workflow has
`issues: write` permission for this purpose). On `pull_request`,
the failure blocks the PR's status check.

A passing `main` branch means **no known CVEs in our dep tree**
at the time of the last audit run.

### Handling a finding

When `cargo audit` fails:

1. **Read the advisory**: <https://rustsec.org/advisories/> +
   the action's logs identify the affected crate and version.
2. **Determine applicability**: not every advisory in a
   dependency affects cesauth. Check whether the vulnerable
   code path is actually exercised. If not, document the
   reasoning before ignoring.
3. **Update**: prefer `cargo update -p <crate>` to pick up a
   patched version. If the patched version is across a major
   bump, plan a small migration.
4. **Ignore (if applicable)**: add the advisory ID to
   `.cargo/audit.toml` under `[advisories] ignore = [...]`
   with a one-line justification. The file does not yet exist
   (we don't have any ignored advisories); create it only
   when the first ignore is actually needed.
5. **Audit history**: when an advisory is fixed by an upgrade,
   reference the advisory ID in the CHANGELOG entry for the
   release that contains the upgrade. Search-friendly.

### Re-audit cadence for the workflow itself

The workflow uses pinned action versions
(`rustsec/audit-check@v2.0.0`, `actions/checkout@v4`). Renovate
or Dependabot should be configured to bump these when new majors
appear. As of v0.24.0 this is **not yet wired** — manual
review at major release cadence is the current process.
