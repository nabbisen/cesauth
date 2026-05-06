# Summary

[Introduction](./introduction.md)

---

# Getting Started (Beginner)

- [Prerequisites](./beginner/prerequisites.md)
- [First local run](./beginner/first-local-run.md)
- [Your first OIDC flow with curl](./beginner/first-oidc-flow.md)
- [Inspecting state](./beginner/inspecting-state.md)
- [Resetting between runs](./beginner/resetting.md)
- [Troubleshooting](./beginner/troubleshooting.md)

---

# Concepts & Reference (Expert)

- [Architecture overview](./expert/architecture.md)
- [Crate layout](./expert/crate-layout.md)
- [Storage responsibilities](./expert/storage.md)
- [Ports & adapters pattern](./expert/ports-adapters.md)
- [OIDC internals](./expert/oidc-internals.md)
    - [Authorization Code + PKCE](./expert/oidc-authorization.md)
    - [Token issuance & refresh rotation](./expert/oidc-tokens.md)
    - [`prompt` & `max_age` handling](./expert/oidc-prompt-max-age.md)
- [WebAuthn implementation](./expert/webauthn.md)
- [Session cookies](./expert/sessions.md)
- [Cookie inventory (v0.31.0)](./expert/cookies.md)
- [CSRF model](./expert/csrf.md)
- [CSRF audit (v0.24.0)](./expert/csrf-audit.md)
- [Email verification audit (v0.25.0)](./expert/email-verification-audit.md)
- [Operational logging](./expert/logging.md)
- [Turnstile integration](./expert/turnstile.md)
- [Admin console](./expert/admin-console.md)
- [Tenancy service](./expert/tenancy.md)
- [Architecture decision records](./expert/adr/README.md)
    - [ADR-001: Tenant-scoped URL shape](./expert/adr/001-tenant-scoped-url-shape.md)
    - [ADR-002: User-as-bearer mechanism](./expert/adr/002-user-as-bearer-mechanism.md)
    - [ADR-003: System-admin from tenant view](./expert/adr/003-system-admin-from-tenant-view.md)
    - [ADR-004: Anonymous trial promotion](./expert/adr/004-anonymous-trial-promotion.md)
    - [ADR-005: Data migration tooling](./expert/adr/005-data-migration-tooling.md)
    - [ADR-007: HTTP security response headers](./expert/adr/007-security-response-headers.md)
    - [ADR-008: OIDC id_token issuance (Draft)](./expert/adr/008-id-token-issuance.md)
    - [ADR-009: TOTP as a second factor](./expert/adr/009-totp.md)
- [Security considerations](./expert/security.md)

---

# Deployment

- [Pre-flight checklist](./deployment/preflight.md)
- [Wrangler configuration](./deployment/wrangler.md)
- [Secrets & environment variables](./deployment/secrets.md)
- [Cron Triggers](./deployment/cron-triggers.md)
- [Custom domains & DNS](./deployment/custom-domains.md)
- [Multi-environment workflow](./deployment/environments.md)
- [Migrating from local to production](./deployment/production.md)
- [Backup & restore](./deployment/backup-restore.md)
- [Data migration](./deployment/data-migration.md)
- [Observability](./deployment/observability.md)
- [Security response headers](./deployment/security-headers.md)
- [TOTP configuration](./deployment/totp.md)
- [Day-2 operations runbook](./deployment/runbook.md)
- [Disaster recovery](./deployment/disaster-recovery.md)

---

# Appendix

- [Endpoint reference](./appendix/endpoints.md)
- [Error codes](./appendix/error-codes.md)
- [Glossary](./appendix/glossary.md)
