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

Next number: **020** (006 is now in done/). Create `rfcs/proposed/020-slug.md`, set `**Status**: Proposed`,
add a row above, and update in the same commit. When shipped: move to `done/`,
update Status to `Implemented (vX.Y.Z)`, update README row. Numbers are permanent.
