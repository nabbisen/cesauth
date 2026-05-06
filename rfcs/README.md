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

### Tier 1 — Ready to implement, design settled

These are the priority themes. Each one has a clear design
(either a settled ADR, or design ambiguity small enough to
resolve inline). An engineer can pick one up next without
upstream blocking.

| File | Theme | ROADMAP source | Estimated scope |
|---|---|---|---|
| [001-id-token-issuance.md](001-id-token-issuance.md) | OIDC `id_token` issuance | "Later" / ADR-008 | Medium |
| [002-client-secret-hash-resolution.md](002-client-secret-hash-resolution.md) | `oidc_clients.client_secret_hash` documentation-vs-implementation drift | "Later" | Small |
| [003-property-based-tests.md](003-property-based-tests.md) | Property-based tests (`proptest`) for crypto round-trips and `redirect_uri` matcher | Next minor releases | Small |
| [004-webauthn-typed-error-responses.md](004-webauthn-typed-error-responses.md) | WebAuthn error → typed client responses (`WebAuthnErrorKind` enum) | Next minor releases | Small |

### Tier 2 — Internal design only, ready to implement

Lighter RFCs (internal-design-only or no external surface).
Defer until Tier 1 clears or until operator demand surfaces.

| File | Theme | ROADMAP source | Estimated scope |
|---|---|---|---|
| [005-cargo-fuzz-jwt-parser.md](005-cargo-fuzz-jwt-parser.md) | `cargo fuzz` for the JWT parser surface | Next minor releases | Small |
| [006-csp-without-unsafe-inline.md](006-csp-without-unsafe-inline.md) | CSP without `'unsafe-inline'` (per-request nonces) | "Later" | Medium |
| [007-attack-surface-review-cadence.md](007-attack-surface-review-cadence.md) | Cesauth-specific attack-surface review cadence | "Later" | Small (one review pass) |

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
