# cesauth RFCs

Implementation-handover specifications for ROADMAP themes that
are ready to be picked up by an engineer.

## What an RFC is here, and isn't

An RFC in this directory is the **engineering spec** for an
upcoming theme — the thing an implementer reads after the
ROADMAP to know what to build, how to test it, and which
invariants must not break. It is **not** the design forum;
that's the ADR system in `docs/src/expert/adr/`. Where an ADR
exists for a theme (e.g. ADR-008 for id_token issuance), the
RFC builds on it — references the design decisions, fills in
the implementation-level detail the ADR deliberately omitted.

The split is:

| Document | Audience | Question it answers |
|---|---|---|
| **ROADMAP** entry | Reader scanning what's next | "Is this on the list?" |
| **ADR** | Reviewer evaluating design choices | "Why this design?" |
| **RFC** (this dir) | Implementer picking up the theme | "What do I need to build?" |
| **CHANGELOG** + **ROADMAP ✅** | Operator after release | "What changed?" |

When a theme has no real design ambiguity (small, isolated bug,
clear refactor), no ADR is needed and the RFC stands alone.
When a theme has clear external observable surface (HTTP route,
JSON schema, env var), the RFC has both an external spec
section and an internal design section. When the theme is
internal-only (test infrastructure, hashing-internals decision,
fuzzing harness), the RFC is internal-design-only.

## Template

The standard RFC structure is the **lightweight template**:

```
# RFC: <theme name>

**Status**: Draft / Ready / In progress / Shipped (vX.Y.Z) / Superseded
**ROADMAP**: <link or section reference>
**ADR**: <link if one exists, else N/A>
**Estimated scope**: <small / medium / large>

## Background  (optional — omit when context is obvious)

## Decision / Plan

## Open questions (if any)
```

For **medium or larger** themes, expand the standard sections:

```
## Requirements
## Design  (replaces "Decision / Plan")
## Test plan
## Security considerations
```

Background is optional in both shapes — omit when the ROADMAP
and any linked ADR already establish context.

## Index

### Tier 0 — Production blockers (P0/P1, ship in v0.50.2)

These are issues surfaced by the v0.50.1 external Rust+Cloudflare codebase review. Each represents a security violation, correctness regression, or production-readiness gap that blocks safe production deployment. **All four ship in the same release** (planned v0.50.2) because they're mutually entangled — RFC 008 (audit secret leak) cannot stay fixed without RFC 010 (real mailer); RFC 009 (introspection correctness) and RFC 010 share the audit-boundary discipline; RFC 011 (worker hardening) bundles the P1+P2 worker-layer items the same review surfaced.

| File | Theme | Severity | Source |
|---|---|---|---|
| [008-eliminate-otp-in-audit.md](008-eliminate-otp-in-audit.md) | Eliminate plaintext OTP in audit log | **P0** | External review (Critical) |
| [009-introspection-aud-correctness-and-fail-closed.md](009-introspection-aud-correctness-and-fail-closed.md) | Introspection access-token `aud` correctness + audience-gate fail-closed | **P0 + P1** | External review (High + High) |
| [010-magic-link-real-delivery.md](010-magic-link-real-delivery.md) | Magic Link real delivery — mailer port + provider adapters | **P0** | External review (High) + dev-directive audit |
| [011-worker-layer-hardening.md](011-worker-layer-hardening.md) | CSRF RNG, env validation, duplicate routes, duplicate ADR file | **P1 + P2** | External review |

### Tier 1 — Ready to implement, design settled

These are priority themes from the original v0.50.1 RFC batch. Each has a clear design (settled ADR or small enough to resolve inline). An engineer can pick one up after the Tier 0 sweep clears.

| File | Theme | ROADMAP source | Estimated scope |
|---|---|---|---|
| [001-id-token-issuance.md](001-id-token-issuance.md) | OIDC `id_token` issuance | "Later" / ADR-008 | Medium |
| [002-client-secret-hash-resolution.md](002-client-secret-hash-resolution.md) | `oidc_clients.client_secret_hash` documentation-vs-implementation drift | "Later" | Small |
| [003-property-based-tests.md](003-property-based-tests.md) | Property-based tests (`proptest`) for crypto round-trips and `redirect_uri` matcher | Next minor releases | Small |
| [004-webauthn-typed-error-responses.md](004-webauthn-typed-error-responses.md) | WebAuthn error → typed client responses (`WebAuthnErrorKind` enum) | Next minor releases | Small |

### Tier 2 — Internal design only, ready to implement

Lighter RFCs (internal-design-only or no external surface). Defer until Tier 0 and Tier 1 clear, or until operator demand surfaces.

| File | Theme | ROADMAP source | Estimated scope |
|---|---|---|---|
| [005-cargo-fuzz-jwt-parser.md](005-cargo-fuzz-jwt-parser.md) | `cargo fuzz` for the JWT parser surface | Next minor releases | Small |
| [006-csp-without-unsafe-inline.md](006-csp-without-unsafe-inline.md) | CSP without `'unsafe-inline'` (per-request nonces) | "Later" | Medium |
| [007-attack-surface-review-cadence.md](007-attack-surface-review-cadence.md) | Cesauth-specific attack-surface review cadence | "Later" | Small (one review pass) |

### Tier 3 — Quality / scaling work, defer behind P0 sweep

Quality-and-operations themes from the v0.50.1 external code review. None block production but each materially improves maintainability and operational reliability. Order is approximate.

| File | Theme | Source | Estimated scope |
|---|---|---|---|
| [012-doc-and-repo-hygiene.md](012-doc-and-repo-hygiene.md) | README drift, `migrate.rs` 2568→split, dev-directive corrections, drift-scan CI | External review (Medium / Low) | Small/medium (mechanical) |
| [013-operational-envelope.md](013-operational-envelope.md) | Cloudflare Paid plan baseline, bundle budget CI gate, configurable cron sizes, `nodejs_compat` review | External review (P2 ops) | Medium (docs-heavy) |
| [014-audit-append-performance.md](014-audit-append-performance.md) | Audit append D1 contention — Path A measure-then-decide | External review (P2 perf) | Small (Path A); medium-large if Path B triggers |
| [015-request-traceability.md](015-request-traceability.md) | Request-correlation ID (`cf-ray`) + lifecycle log + audit cross-link; ADR-018 documents file-logger non-feature | Operator follow-up question on logging | Small/medium (additive) |

### Tier 4 — Admin UX hardening, derived from external UI/UX update

Themes from the v0.50.1 external UI/UX design update (deck + one-page overview). Each closes a real operator-facing gap that the existing implementation doesn't address. Defer behind Tiers 0-3 but ship before next major feature work.

| File | Theme | Source | Estimated scope |
|---|---|---|---|
| [016-admin-scope-badge.md](016-admin-scope-badge.md) | Standardize system-vs-tenant scope badge across all three admin frames | UI/UX deck p.8 | Small (chrome change) |
| [017-oidc-audience-admin-editor.md](017-oidc-audience-admin-editor.md) | Admin UI for `oidc_clients.audience` (closes v0.50.0's "out of scope: admin UI for this" deferral) | UI/UX deck p.8 + ADR-014 §Q1 | Small/medium |
| [018-preview-and-apply-pattern.md](018-preview-and-apply-pattern.md) | Preview-and-apply pattern for destructive admin operations; ADR-019 establishes the convention | UI/UX deck p.9 | Medium (pattern + first 3 adopters) |

### Recommended implementation order

1. **v0.50.2 — production-blocker sweep**: RFCs 008, 009, 010 ship together. RFC 011 may ride along or land in v0.50.3.
2. **v0.51.0 — first feature release post-blocker**: RFC 001 (`id_token` issuance) — the largest queued feature work, ADR-008 design already Resolved.
3. **v0.51.x or 0.52.0 — quality**: RFCs 002, 011 (if not in v0.50.x), 012.
4. **v0.52.x — operations + traceability**: RFCs 013, 014 (Path A only; Path B deferred until telemetry triggers), 015 (alongside 013 since both touch the operational envelope and observability surface).
5. **v0.52.x or 0.53.0 — admin UX hardening**: RFCs 016 (scope badge — small, can ship anywhere), 018 (preview-and-apply pattern — ADR-019 lands first), 017 (audience editor — ideally rides on RFC 018's pattern, otherwise stand-alone with later refactor).
6. **Later, infrequent**: RFCs 003, 004, 005, 006, 007.

### Not covered here

Themes deliberately excluded from this RFC batch:

- **ADR-012 §Q2** (idle-timeout user notification) — needs an
  email pipeline cesauth doesn't yet have. Write the RFC when
  the email pipeline lands.
- **ADR-012 §Q3** (geo / device-fingerprint columns) — needs
  GeoIP infrastructure cesauth doesn't yet have.
- **ADR-012 §Q5** (orphan DOs) — structurally blocked by
  Cloudflare not supporting DO namespace iteration.
- **OIDC `client_secret` brute-force lockout** — has an explicit
  trigger condition ("production telemetry shows non-trivial
  volume of failed `client_secret` attempts") that hasn't
  fired. Write the RFC when the trigger fires.
- **Domain-metric observability** — design choice (Logpush
  vs `cloudflare:analytics-engine`) needs operator-side
  dashboarding requirements to be concrete first.
- **Rate-limit bucket tuning** — needs production telemetry.
- **Login → tenant resolution / external IdP federation** —
  these reach into multi-tenant UX territory big enough to
  deserve their own ADRs first; an RFC without that
  prerequisite would be premature.
- **Protocol extensions** (Device Authorization Grant,
  Dynamic Client Registration, Request Objects, PAR, full
  FIDO attestation, FIDO conformance) — speculative. Write
  the RFC when a concrete deployment requires one.
- **`prompt=select_account`** — explicitly rejected today.

## Workflow

When picking up an RFC:

1. Read the ADR linked from the RFC if any exists.
2. Read the RFC end-to-end before starting code.
3. Open a new release branch (e.g. `0.51.0-id-token-issuance`).
4. Implement to the test plan; treat the test list as
   acceptance criteria.
5. Update the RFC's status header to `In progress` while
   working, `Shipped (vX.Y.Z)` on release.
6. On release, update the ROADMAP and CHANGELOG per the
   project conventions (see development directives).

When proposing a new RFC:

- Confirm the theme is on the ROADMAP. RFCs should mirror
  what the ROADMAP already commits to, not introduce new
  scope.
- For themes that need design discussion, write the ADR
  first, then the RFC.
- File numbering is sequential; the next free number is
  `008-...`.

## Versioning

This directory is internal documentation. Adding or revising
an RFC qualifies as a patch release per the project
versioning policy (no surface change). The RFC's eventual
implementation gets a minor release on its own.
