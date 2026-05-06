# Cookie inventory

> Added in v0.31.0 alongside the flash-message infrastructure.
> Documents every cookie cesauth emits, why each is set, and the
> legal posture (no consent banner is required because all cookies
> are strictly necessary; see §"Legal posture" below).

## Inventory

cesauth emits exactly seven cookies. All use the `__Host-` prefix
(forces `Secure`, `Path=/`, no `Domain`), all are `HttpOnly`, all
are `Secure`. The only attribute that varies between cookies is
`SameSite`.

| Cookie | Purpose | Lifetime | SameSite | Set by |
|---|---|---|---|---|
| `__Host-cesauth_session` | Authenticated session. HMAC-signed value carries `session_id` + `user_id` + `auth_method` + `expires_at`. The worker also queries the `ActiveSession` Durable Object to confirm the session is still live (revocation, logout, admin-kicked). | `SESSION_TTL_SECS` (default 3600) | `Lax` | `complete_auth_post_gate` (after WebAuthn / Magic Link / TOTP verify success) |
| `__Host-cesauth_pending` | OAuth Authorization Request continuation. Stores the handle to a parked `Challenge::PendingAuthorize`. The worker pops it when `complete_auth` resumes the flow. | `PENDING_AUTHORIZE_TTL_SECS` (default 600) | `Lax` | `GET /authorize` when an unauthenticated user must sign in first |
| `__Host-cesauth-csrf` | Per-form CSRF token (random 24-byte URL-safe-base64). Stored as a cookie; submitted as a hidden form field; the worker compares constant-time. JSON callers are exempt (CORS preflight gates them). | unbounded (replaced on mint) | `Strict` | Login, magic-link, TOTP enroll/verify/disable, logout pages |
| `__Host-cesauth_totp` | TOTP gate continuation. Stores the handle to a parked `Challenge::PendingTotp` containing the AR fields inline (no chained handle, avoids race). Cleared on success or failure. | 300 (5 min) | `Strict` | `complete_auth` when a Magic-Link verify succeeds and the user has a confirmed TOTP authenticator |
| `__Host-cesauth_totp_enroll` | TOTP enrollment continuation. Stores the unconfirmed `totp_authenticators` row id during the QR-scan-then-confirm window. Cleared on confirm (success or abandonment). | 900 (15 min) | `Strict` | `GET /me/security/totp/enroll` |
| `__Host-cesauth_flash` | One-shot flash message. Carries a level (info / success / warning / danger) and a key from a closed dictionary; the rendering layer looks up display text from a server-side table. HMAC-signed. Cleared by the next page render. | 60 | `Lax` | TOTP disable / enroll-confirm / recover, logout |
| `__Host-cesauth_login_next` | Post-login landing target. base64url-encoded path validated against the `/me/*` + `/` allowlist. Cleared on first successful sign-in. | 300 (5 min) | `Lax` | `GET /login?next=...` when the encoded value passes `validate_next_path` |

## Why `SameSite=Lax` for some, `=Strict` for others

The `Lax` cookies are ones that must survive a top-level
navigation across origins:

- `_session` and `_pending` ride the OAuth redirect chain
  (RP → cesauth `/authorize` → cesauth `/login` → RP callback).
  `Strict` would drop them at the first cross-site step.
- `_flash` must survive the same OAuth chain (a user who logged
  in to confirm a TOTP disable, then was redirected through an
  RP, must still see the flash on the destination).
- `_login_next` must survive a Magic Link click (the email link
  is cross-origin from the user's perspective).

The `Strict` cookies are internal breadcrumbs whose flows never
involve a legitimate cross-origin step:

- `-csrf` is a per-page form binding; both endpoints are on the
  cesauth origin.
- `_totp` and `_totp_enroll` are mid-flow handles — the user
  enters cesauth on one cesauth page and exits on another. Any
  cross-site initiation would be a CSRF attempt.

## Legal posture (GDPR / ePrivacy)

cesauth does not display a cookie consent banner. The decision
rests on the following analysis of EU regulations, which is the
strictest of the regulatory regimes the project targets:

- **ePrivacy Directive 2002/58/EC + 2009 amendment** ("Cookie Law")
  Article 5(3) requires user consent for "the storing of
  information, or the gaining of access to information already
  stored, in the terminal equipment of a subscriber or user".
- The same Article exempts cookies that are
  "**strictly necessary** for the provision of [an information
  society service] explicitly requested by the subscriber or user."
- **EDPB Guidelines 5/2020** §3.1.1 enumerates the recognized
  strictly-necessary categories. Among them: **authentication
  cookies**, **CSRF protection cookies**, and "**user interface
  customization**" cookies that are session-scoped and triggered
  by user action.

Mapping cesauth's cookies onto those categories:

- `_session` — authentication cookie. Exempt.
- `_pending`, `_totp`, `_totp_enroll`, `_login_next` — multi-step
  authentication continuation. Same exemption (the flow is the
  user-requested service, the cookie is the only practical way
  to maintain its state across HTTP requests).
- `-csrf` — CSRF protection cookie. Exempt by EDPB §3.1.1's
  named list.
- `_flash` — falls under "user interface customization": user
  triggers a POST (e.g., disable TOTP), the next page must
  reflect the result, the cookie is the standard mechanism. The
  payload is a closed dictionary with no identity / tracking /
  analytics surface; it is short-lived (60 s); it cannot be
  used for cross-user correlation.

Independent supporting evidence: Rails (`flash`), Django
(`messages`), Flask (`flash()`), and similar mainstream
frameworks all treat their flash-message cookies as essential
without consent banners. cesauth's posture is consistent with
that established practice.

**Article 13 transparency** (the obligation to inform users about
data processing) is independent of the consent rule. This document
satisfies the transparency obligation by enumerating every
cookie, its purpose, and its lifetime.

## Operator-deployed cookies

This document covers cookies cesauth library itself emits.
Operators who deploy cesauth and add their own cookies (analytics
like Google Analytics or Hotjar, advertising cookies, third-party
embeds, etc.) take on independent obligations:

- Those cookies are typically **not** strictly necessary and
  therefore require user consent under ePrivacy Article 5(3).
- The operator must implement a consent management mechanism
  (banner, preference center, etc.).

cesauth's response Content-Security-Policy is `default-src 'self'`
which actively limits the operator's ability to inject third-party
scripts via cesauth-rendered pages. An operator that hosts other
pages on the same origin can still set additional cookies on
those pages; cesauth makes no claim about that surface.

cesauth itself **does not** provide a consent-management hook or
a `consent` extension point. If a future feature track requires
this (e.g., when cesauth itself integrates an analytics path),
ROADMAP will track it as a fresh ADR.

## Inventory maintenance rule

Any new cookie cesauth introduces MUST be added to this document
in the same release that introduces the cookie, with name +
purpose + lifetime + scope + SameSite + HttpOnly + Secure
attributes + a strictly-necessary justification. Releases that
modify a cookie's attributes (TTL change, SameSite change) MUST
update this document accordingly. The audit deliverable lives in
this file; the precommit checklist lives in
`docs/src/expert/security.md`'s "Pre-production release gate"
section.

## See also

- [Security](security.md) — sibling document on HTTP-level
  defenses (headers, CSP, pre-production checklist).
- [CSRF](csrf.md) — detailed treatment of the CSRF cookie's
  contract.
- [Sessions](sessions.md) — detailed treatment of the session
  cookie's contract.
- ADR-007 (security headers) and ADR-009 (TOTP) — architectural
  decisions that drove some of the cookie choices.
