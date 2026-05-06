# Architecture Decision Records

cesauth's ADRs capture decisions that shaped the codebase in places
where the alternative was not obvious. They are written for a future
maintainer asking "why did this look so weird?" — not for advocacy
or for capturing every choice ever made.

We write an ADR when:

- The decision constrains future work (a new release can't undo it
  cheaply).
- A reasonable reviewer would have picked the other option.
- The non-obvious answer is the right one and we'll forget why
  in three months.

We do **not** write ADRs for choices that are obvious in retrospect,
choices forced by the platform (e.g. "use D1"), or refactors that
don't change observable behavior.

## Index

| ADR | Title                                              | Status   |
|-----|----------------------------------------------------|----------|
| 001 | URL shape for the tenant-scoped admin surface      | Accepted |
| 002 | User-as-bearer mechanism                            | Accepted |
| 003 | System-admin operations from inside the tenant view | Accepted |
| 004 | Anonymous trial → human user promotion              | Accepted |
| 005 | Data migration tooling for server-to-server moves   | Accepted |
| 006 | (withdrawn — see CHANGELOG)                         | Withdrawn |
| 007 | HTTP security response headers                      | Accepted |
| 008 | OIDC `id_token` issuance                            | Draft    |
| 009 | TOTP (RFC 6238) as a second factor                  | Accepted |
| 010 | Audit log hash chain                                | Accepted |
| 011 | Refresh token reuse hardening                       | Accepted |

ADRs 001-003 were authored together in v0.11.0 to settle the design
questions deferred from v0.10.0. Their decisions ship as the
foundation work in v0.11.0 (schema + types) and the full
implementation in v0.13.0+.

**ADR-006 was withdrawn before its v0.23.0 release graduated to
canonical status.** It proposed per-account lockout for password
brute-force defense, which was based on a faulty premise — cesauth
has no password authentication path (Magic Link + WebAuthn cover
the equivalent UX, see ROADMAP "Explicitly out of scope"). The
withdrawn artifact is preserved at
`cesauth-0.23.0-account-lockout-withdrawn.tar.gz` for historical
reference. The ADR-006 number is not reused. A future ADR may
revisit lockout for the OIDC `client_secret` brute-force surface
(per-client lockout); see ROADMAP "Later" for the trigger
condition.
