# Attack surface review cadence

**v0.52.1 (RFC 007)** — This page defines the periodic review cadence
and the per-review deliverable shape. It is a process document, not a
finding document. Findings go in the per-quarter review files
(`security-review-<year>-<quarter>.md`) alongside this page.

---

## Cadence

At a minimum, a review runs:

- **Before any major release** (1.0, 2.0, …).
- **Before any cross-cutting refactor** that touches authentication,
  token signing, session management, or the audit pipeline.
- **When a new threat class surfaces** — a CVE in an upstream
  dependency cesauth uses, a published attack against an OIDC OP,
  a new bypass technique against WebAuthn.

**Next scheduled review**: before v1.0, or by 2027-Q4, whichever
is sooner.

The 2026 initial review's findings were incorporated into the v0.50
series (introspection hardening, OTP audit leak, CSRF RNG fix,
CSP nonces, and other improvements). This page supersedes the
informal "by 2026-Q4 or v0.30.0" target stated in that review.

---

## Starting categories (2026 initial review)

These eight categories were the starting checklist. Each review
must re-walk them; add new categories as the codebase evolves.

1. **Open-redirect via `redirect_uri`** — exact-match enforcement;
   checked by RFC 003 proptest (v0.51.1).
2. **JWT alg confusion** — `alg: none` rejection, EdDSA-only;
   covered by cargo fuzz (RFC 005, v0.51.2) and `verify`'s
   signature-before-claims order.
3. **Confused deputy in tenant scoping** — operator/tenant boundary
   in admin routes; audience scoping in introspection (ADR-014,
   v0.50.0 + RFC 009 tightening v0.50.3).
4. **Subdomain takeover** — `WEBAUTHN_RP_ORIGIN` and
   `WEBAUTHN_RP_ID` validation; operator-configured, documented in
   `docs/src/deployment/`.
5. **PKCE enforcement** — `code_challenge` required; `code_verifier`
   constant-time check.
6. **Cookie security attributes** — `__Host-` prefix on session and
   CSRF cookies; `SameSite=Lax`; `Secure`; `HttpOnly`.
7. **Timing side-channels** — CSRF double-submit is constant-time;
   WebAuthn signature uses `Verifier::verify` (constant-time);
   Magic Link hash comparison is constant-time.
8. **Open-registration paths** — anonymous trial sessions are
   rate-limited; promote-to-registered requires email confirmation
   via Magic Link OTP.

---

## Per-review deliverable

Create a file `docs/src/expert/security-review-<year>-<quarter>.md`
(e.g. `security-review-2027-q3.md`) with the following structure:

```markdown
# cesauth security review: <year>-<quarter>

**Reviewer**: <name or "internal">
**Date**: <YYYY-MM-DD>
**Scope**: <list of crates / modules examined>
**Methodology**: code reading, static analysis, manual probing, etc.

## Findings

### F-1: <short title>

**Severity**: Critical / High / Medium / Low / Informational
**Surface**: <route / module / data path>
**Description**: ...
**Disposition**:
  Fixed in vX.Y.Z / Tracked in ROADMAP as <item> /
  Accepted with mitigation: <description> / N/A (informational)

### F-2: ...

## Surfaces walked — no findings

- <surface>: walked, no findings.

## Surfaces deferred to next review

- <surface>: out of scope this quarter because <reason>.
```

Add the new file to `docs/src/SUMMARY.md` under "Security" in the
Expert section.

---

## Automation

`scripts/drift-scan.sh` (RFC 012, v0.52.1) runs on every PR.
The drift-scan pattern list acts as a lightweight continuous
surface-integrity check between full reviews. Findings from past
reviews that were converted to code invariants should also be
represented in the drift-scan pattern list or the test suite so
they can't silently regress.

---

## References

- ADR-007: Security headers (`docs/src/expert/adr/007-security-headers.md`)
- `docs/src/expert/security.md`: threat model and security considerations
- `.github/SECURITY.md`: vulnerability reporting procedure
- RFC 003 (v0.51.1): redirect_uri property tests
- RFC 005 (v0.51.2): JWT parser cargo fuzz
- RFC 008 (v0.50.3): OTP audit leak closure
- RFC 009 (v0.50.3): introspection audience gate tightening
- RFC 011 (v0.50.3): CSRF RNG fail-closed
- RFC 006 (v0.52.0): CSP nonces, `'unsafe-inline'` removal
