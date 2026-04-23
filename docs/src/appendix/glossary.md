# Glossary

Terms that appear often in the code and the rest of the book.

**Adapter**  
An implementation of one or more port traits. cesauth has two:
`adapter-cloudflare` (real D1 / DOs / KV / R2) and `adapter-test`
(in-memory). See [Ports & adapters](../expert/ports-adapters.md).

**AR (Authorization Request)**  
The parameter bundle a client sends to `/authorize`: `client_id`,
`redirect_uri`, `scope`, `state`, `nonce`, `code_challenge`,
`code_challenge_method`, `prompt`, `max_age`.

**Audit log**  
R2-backed, append-only, date-partitioned event log. Authoritative
record of authentication and admin activity. Distinct from the
operational log — see [Operational logging](../expert/logging.md).

**Auth challenge**  
A server-side record tying a `handle` (UUID) to a one-shot
cryptographic or OTP-based proof. Lives in the `AuthChallenge`
Durable Object. Variants: `AuthCode`, `PendingAuthorize`,
`MagicLink`, `Registration`, `Authentication`.

**Binding**  
In Wrangler / Cloudflare terms, the name the Worker code uses to
refer to an attached resource (e.g. `env.d1("DB")`). Binding names
are the contract between `wrangler.toml` and Rust; binding IDs are
the contract between Wrangler and the Cloudflare control plane.

**Core**  
The `cesauth-core` crate. The pure-Rust domain layer. Has no
`use worker::*`. All services are defined here; all ports are
declared here.

**CSRF (Cross-Site Request Forgery)**  
See [CSRF model](../expert/csrf.md). cesauth protects form POSTs
via the double-submit cookie pattern; JSON POSTs bypass because
CORS preflight already prevents the cross-origin case.

**DO (Durable Object)**  
Cloudflare's per-key serialized state primitive. cesauth's four DO
classes: `AuthChallenge`, `RefreshTokenFamily`, `ActiveSession`,
`RateLimit`.

**Family (refresh-token family)**  
The set of refresh tokens descended from a single successful
authentication. Reuse of any retired token in the family burns
the whole family.

**Handle**  
A UUIDv4 used as a lookup key into the `AuthChallenge` DO. Handles
are not secrets per se — the validation happens inside the DO via
the stored IP + UA hash — but reusing handles across flows is not
allowed.

**jti (JWT ID)**  
The `jti` claim of an access token. Unique per token. cesauth
doesn't track jtis against a revocation list because access tokens
are short-lived.

**Kid (JWT key id)**  
The `kid` JOSE header field. cesauth rotates keys by adding a new
row to `jwt_signing_keys` and bumping `JWT_KID` in
`wrangler.toml`. Old kids remain in JWKS until `retired_at` is
set.

**Miniflare**  
The local simulator bundled with Wrangler 3+/4. Simulates D1, KV,
R2, and Durable Objects on disk under `.wrangler/state/`. This is
what makes `wrangler dev` a local development loop.

**Operational log**  
Structured JSON-Lines diagnostic output visible via `wrangler
tail`. Categorized (`Http`, `Auth`, `Session`, `RateLimit`,
`Storage`, `Crypto`, `Config`, `Dev`) and level-gated. Three
categories are sensitive by default and dropped unless
`LOG_EMIT_SENSITIVE=1`.

**Passkey**  
A WebAuthn credential backed by platform or roaming authenticator
state. Phishing-resistant, user-verification-capable. cesauth's
passkey support covers EdDSA + ES256 with `none` attestation.

**PKCE (Proof Key for Code Exchange)**  
RFC 7636. Client-side secret protecting the authorization-code
flow against code-interception attacks. cesauth requires `S256`;
`plain` is rejected.

**Port**  
A trait in `core::ports::*` that names a domain operation. See
[Ports & adapters](../expert/ports-adapters.md).

**RP (Relying Party)**  
The WebAuthn term for the service that authenticates users.
cesauth IS the RP. `RP_ID`, `RP_NAME`, and `RP_ORIGIN` vars
configure it.

**SiteVerify**  
Cloudflare Turnstile's server-side API for validating a
client-submitted token. cesauth's `HttpTurnstileVerifier` wraps it.

**Turnstile**  
Cloudflare's CAPTCHA replacement. cesauth uses it as a risk
escalation, triggered by `RateLimitDecision.escalate`.

**Wrangler**  
Cloudflare's CLI for Workers. cesauth targets v3.76+ and v4.x.
