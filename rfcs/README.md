# cesauth RFCs

Implementation-handover specifications for ROADMAP themes.
Governed by **RFC 019 — RFC lifecycle policy** (`done/019-rfc-lifecycle-policy.md`).

## What an RFC is here

An RFC is the **engineering spec** for an upcoming theme — the thing an
implementer reads after the ROADMAP to know what to build, how to test it,
and which invariants must not break. It is **not** the design forum (that's
the ADR system in `docs/src/expert/adr/`).

| Document | Audience | Question it answers |
|---|---|---|
| ADR | Architect / reviewer | *Why* this design; trade-offs; alternatives rejected |
| RFC | Implementer | *What* to build; acceptance criteria; test strategy |
| CHANGELOG | Operator | *What shipped* and upgrade notes |

## Lifecycle

Folder = source of truth for state. `Status` field inside each file mirrors folder.

```
rfcs/
  proposed/    ← open for implementation
  done/        ← shipped; historical record — never delete
  archive/     ← withdrawn or superseded
  README.md    ← this index (update in same commit as any move)
```

Full policy: `done/019-rfc-lifecycle-policy.md`.

---

## Proposed

| ID | Title | Notes |
|----|-------|-------|
| [001](./proposed/001-id-token-issuance.md) | OIDC `id_token` issuance | ADR-008; ~30 tests; 5-PR scope |
| [013](./proposed/013-operational-envelope.md) | Operational envelope | Graceful shutdown, memory limits |
| [014](./proposed/014-audit-append-performance.md) | Audit append performance | Batch writes, back-pressure |
| [015](./proposed/015-request-traceability.md) | Request traceability | `X-Request-Id` propagation |
| [016](./proposed/016-admin-scope-badge.md) | Admin scope badge | UI elevated-scope indicator |
| [017](./proposed/017-oidc-audience-admin-editor.md) | OIDC audience admin editor | Tenant console `oidc_clients.audience` UI |
| [018](./proposed/018-preview-and-apply-pattern.md) | Preview-and-apply pattern | Dry-run / commit two-step |
| [020](./proposed/020-migration-chain-hygiene.md) | Migration chain hygiene | **P0** — `schema_meta`, FK rebuild, `COLLATE NOCASE` (data review) |
| [021](./proposed/021-user-fk-cascade-alignment.md) | User-scoped FK and cascade alignment | P1 — orphan-row cleanup (data review) |
| [022](./proposed/022-permission-catalog-seed-sync.md) | Permission catalog and role seed sync | P1 — `tenant:member:*` slugs (data review) |
| [023](./proposed/023-tenant-boundary-integrity.md) | Tenant boundary integrity | P1 — composite FKs + service-layer guard (data review) |
| [024](./proposed/024-d1-index-restoration.md) | D1 index restoration and tuning | P2 — restore `0001` indexes + partial indexes (data review) |
| [025](./proposed/025-workers-operational-readiness.md) | Workers operational readiness | P2 — bundle-size CI, `nodejs_compat`, plan budgeting (codebase review) |
| [026](./proposed/026-introspect-hot-path-consolidation.md) | `/introspect` hot path consolidation | P2 — single `ClientAuthView` query (codebase review) |
| [027](./proposed/027-accessibility-and-route-contracts.md) | Accessibility verification and route-addition checklist | P2 — color-only-status audit + per-route metadata table (UI/UX review) |
| [028](./proposed/028-changelog-roadmap-volume-policy.md) | CHANGELOG / ROADMAP volume policy | P2 — historical archive split |
| [029](./proposed/029-rustfmt-toml-review.md) | `rustfmt.toml` necessity review | P3 — measurement-driven keep / minimize / delete |

---

## Done

| ID | Title | Shipped |
|----|-------|---------|
| [002](./done/002-client-secret-hash-resolution.md) | `client_secret_hash` drift fix | v0.51.0 |
| [003](./done/003-property-based-tests.md) | proptest round-trips | v0.51.1 |
| [004](./done/004-webauthn-typed-error-responses.md) | WebAuthn typed errors | v0.51.1 |
| [005](./done/005-cargo-fuzz-jwt-parser.md) | `cargo fuzz` JWT parser | v0.51.2 |
| [008](./done/008-eliminate-otp-in-audit.md) | Eliminate OTP in audit | v0.50.3 |
| [009](./done/009-introspection-aud-correctness-and-fail-closed.md) | Introspection `aud` + fail-closed | v0.50.3 |
| [010](./done/010-magic-link-real-delivery.md) | Magic Link mailer port | v0.51.0 |
| [011](./done/011-worker-layer-hardening.md) | Worker-layer hardening | v0.50.3 |
| [006](./done/006-csp-without-unsafe-inline.md) | CSP without `unsafe-inline` | v0.52.0 |
| [007](./done/007-attack-surface-review-cadence.md) | Attack surface review cadence | v0.52.1 |
| [012](./done/012-doc-and-repo-hygiene.md) | Doc & repo hygiene | v0.52.1 |
| [019](./done/019-rfc-lifecycle-policy.md) | RFC lifecycle policy | v0.51.2 |

---

## Archive

*(none)*

---

## Adding a new RFC

Next number: **030**. Create `rfcs/proposed/030-slug.md`, set `**Status**: Proposed`,
add a row above, and update in the same commit. When shipped: move to `done/`,
update Status to `Implemented (vX.Y.Z)`, update README row. Numbers are permanent.

---

## RFCs 020–029 — context for the v0.52.1 → v0.53.x batch

The ten RFCs numbered 020–029 are the v0.52.1
review-driven batch. Their sources:

- **Data-structure review v0.52.1** → RFCs **020–024** (one P0,
  three P1, one P2). RFC 020 must land before any of 021–024
  because it cleans the migration chain those RFCs build on.
- **Codebase deep-research review v0.50.1** → RFCs **025**
  (operational readiness) and **026** (introspect hot path).
  The earlier P0/P1 findings of that review are already
  shipped via RFCs 008–012.
- **UI/UX design update v0.50.1** → RFC **027**
  (accessibility + route contracts). The deck's other
  themes are already covered by RFCs 016–018 or shipped
  in v0.31.0–v0.47.0 (i18n, flash, sessions self-service).
- **Internal repository hygiene** → RFCs **028**
  (CHANGELOG/ROADMAP volume policy) and **029**
  (rustfmt.toml necessity).

Recommended implementation order:

1. RFC 020 (P0; unblocks 021–024).
2. RFC 022 (small, self-contained; can land alongside 020).
3. RFC 021, 023 (build on 020; can land in either order).
4. RFC 024 (depends on a clean migration chain; lands after 023).
5. RFC 028 (no code dependency; ship at any release boundary;
   recommended early to make subsequent CHANGELOG entries
   smaller).
6. RFC 026 (small, isolated, latency-positive).
7. RFC 025 (CI infrastructure; benefits every later RFC).
8. RFC 027 (depends on no other RFC; ship when convenient).
9. RFC 029 (measurement-driven; effectively a one-PR side
   task).
