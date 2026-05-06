# RFC 007: Cesauth-specific attack-surface review cadence

**Status**: Ready
**ROADMAP**: `## Planned (0.x) / Later` — "Cesauth-specific attack surface review"
**ADR**: N/A
**Estimated scope**: Small per review; sustained low-grade workload across releases

## Background

The ROADMAP "Later" entry frames this as a **periodic**
audit of cesauth-specific attack surfaces. The 2026
initial review identified eight starting categories
(open-redirect via `redirect_uri`, JWT alg confusion,
confused deputy in tenant scoping, subdomain takeover,
PKCE enforcement, cookie security attributes, timing
side-channels, open-registration paths). The list is
explicitly **not exhaustive** — the value of the
exercise is having a regular fresh-eyes pass over the
codebase.

cesauth has shipped substantial security-track work
since then (v0.32 audit hash chain, v0.41 multi-key,
v0.45 bulk revoke, v0.46 introspection extensions,
v0.48 retention, v0.49 repair, v0.50 audience scoping).
Each release has tightened individual surfaces, but
no review has re-walked the whole codebase since the
2026 initial pass.

This RFC defines the cadence and the per-review
deliverable shape — not the next review's findings
(those go in the review-specific output document).

## Decision / Plan

### Cadence

- **At minimum once per major milestone** (1.0 cuts,
  any subsequent major).
- **Additionally, before any major refactor** that
  touches cross-cutting code (e.g. removing a
  dependency, changing the auth model).
- **Additionally, when new threat classes surface**
  (a CVE in an upstream dep cesauth uses, a published
  attack against an OIDC OP, etc.).

The 2026 review's "by 2026-Q4 or before v0.30.0,
whichever is sooner" target was met (v0.30.0 shipped
with TOTP work that incidentally tightened
authenticator-session bindings). The next review is
due **before v1.0** OR by 2027-Q4, whichever is
sooner.

### Per-review deliverable

A single Markdown document at
`docs/src/expert/security-review-<year>-<quarter>.md`
(e.g. `security-review-2027-q3.md`). Structure:

```markdown
# Cesauth security review: <year>-<quarter>

**Reviewer**: <name>
**Date**: <YYYY-MM-DD>
**Scope**: <list of crates / modules examined>
**Methodology**: <brief — code reading, static analysis,
manual probing, etc.>

## Findings

### F-1: <short title>

**Severity**: Critical / High / Medium / Low / Informational
**Surface**: <route / module / data path>
**Description**: ...
**Disposition**: Fixed in vX.Y.Z / Tracked as <ROADMAP item> /
                 Accepted with mitigation <description> / N/A

### F-2: ...

## Surfaces examined (no findings)

- <surface 1>: walked, no findings.
- <surface 2>: walked, no findings.

## Surfaces NOT examined

- <surface>: out of scope because <reason>.

## Recommended next-review-date

<YYYY-MM-DD or "before vX.Y.Z release", whichever is sooner>
```

This shape is deliberately lightweight — the review's
output isn't a single audit report it's a tracked,
re-readable record of what was looked at.

### Review checklist

The starter checklist for any review (extending the
2026 review's eight items, refined by what subsequent
work surfaced):

#### OAuth / OIDC surfaces

- **Open redirect via `redirect_uri`**. Manually probe
  the matcher with adversarial pairs (trailing slash,
  port stripping, IDN, percent-encoding). RFC 003
  (proptest) provides automated coverage; the manual
  pass adds creative inputs proptest doesn't generate.
- **PKCE enforcement**. Confirm public clients are
  rejected without PKCE; confirm S256 verifier accepts
  only S256 challenges; confirm `plain` is not
  silently accepted.
- **`client_secret` brute-force resistance**. Per-client
  rate limit on `/token`. (Already in ROADMAP "Later"
  with explicit trigger condition.)
- **Token reuse and rotation**. Refresh-token-family
  reuse detection should burn the family; manually
  attempt the reuse against a live test deployment.
- **JWKS rotation behavior**. Multi-key invariant
  (v0.41.0) — confirm a token signed by an old key
  still verifies during the overlap window, and
  doesn't verify after the old key is removed from
  the JWKS.
- **JWT alg confusion**. Confirm verifier rejects
  `alg: none`; confirm verifier never verifies
  `alg: HS256` against a public key. (Trivially
  rejected by cesauth's typed verifier; worth
  re-confirming.)

#### Tenancy / authz surfaces

- **Confused deputy in tenant scoping**. Tenant A's
  admin operating tenant B's resources via global
  `/api/v1/...` routes. The `check_permission` call
  must be tenant-bounded.
- **Subdomain takeover**. If a deployment surfaces
  tenants on `<slug>.example.com`, retired tenants
  must have DNS reclaimed. (Operator-side concern;
  cesauth's responsibility is to **document the
  invariant** in `docs/src/deployment/`.)
- **Account-type promotion**. Anonymous → registered
  promotion flow must not allow promotion to admin
  via any path.

#### Session / cookie surfaces

- **Cookie attributes**. `SameSite`, `Secure`,
  `HttpOnly` on every cookie cesauth sets. Path scope
  on each.
- **Session-id rotation on auth state change**.
  After a password reset (when added) or a TOTP
  enrollment, the session id should rotate to defeat
  pre-auth fixation.
- **Cookie name binding**. The `__Host-` prefix is
  Browser-enforced; double-check every cookie cesauth
  sets uses it.

#### Cryptographic surfaces

- **Timing side-channels** in token comparison and
  secret verification. Constant-time comparison
  everywhere. (RFC 002 unifies the bearer-secret
  comparison path; the audit confirms it.)
- **AES-GCM AAD binding** for TOTP secret encryption
  (ADR-009 §Q5). Confirm the AAD is bound to the row
  id; confirm decrypt-with-wrong-aad fails closed.
- **Audit hash-chain integrity**. Confirm prune /
  repair paths preserve the chain (v0.48.0 / v0.49.0
  invariants tested; confirm the tests still pass on
  HEAD).

#### Open-registration / abuse surfaces

- **Anonymous trial creation rate limit**. Operator-
  configurable knob; confirm the default is
  reasonable.
- **Magic Link send rate limit**. Operator-configurable
  knob; confirm spam-defense bounds.
- **TOTP enrollment-then-abandon**. The cron sweep
  prunes unconfirmed authenticator rows; confirm
  the unbounded-growth class is contained.

#### Operational surfaces

- **Cron pass independence**. The five daily passes
  must not share state in a way that lets one pass's
  failure corrupt another. (Tested at unit level;
  confirm no recent changes coupled them.)
- **Deployment-time secrets**. `JWT_SIGNING_KEY`,
  `TOTP_ENCRYPTION_KEY`, etc. — confirm cesauth
  refuses to start if any required secret is
  missing or malformed.
- **Migration tool gates**. Five gates for
  `cesauth-migrate import` (verify → fingerprint →
  key pre-flight → invariant checks → final commit).
  Confirm each gate is hit on a fresh dry-run.

### Process notes

- **Fresh eyes**. Where possible, the reviewer is
  someone who didn't write the code being reviewed.
  Operator's choice; the deliverable shape doesn't
  change.
- **Time-boxing**. Each review is 1-3 days of focused
  work. If the checklist grows unworkable, split into
  multiple reviews and cite the previous deliverables.
- **Findings vs paranoia**. Severity calibration
  matters: don't inflate "this surface deserves
  more thought" into "Critical". The 5-tier scale
  (Critical / High / Medium / Low / Informational)
  is the standard; default to Informational unless
  there's a concrete attack scenario.

## Open questions

**Should the review be public or private?** The
deliverable lives in `docs/src/expert/`, which is
public via mdBook. The review itself reveals attack
surfaces but does not reveal **active vulnerabilities
or PoCs** — those go through `.github/SECURITY.md`'s
private channel. The line: a review documenting "we
checked X and found nothing" is fine public; a review
documenting "we found Y unfixed bug" is private until
fixed.

## Notes for the implementer (next reviewer)

- Read every prior review document before starting.
  Findings that previously closed should be sanity-
  checked still-closed.
- Commit findings as you go, not at the end. A
  half-finished review is more valuable than a
  perfectly-finished one shipped six months late.
- Cross-reference ADRs and RFCs. If a finding is
  covered by an existing tracked item, that's the
  disposition; don't write a new one.
