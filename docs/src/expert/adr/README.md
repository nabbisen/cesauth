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

ADRs 001-003 were authored together in v0.11.0 to settle the design
questions deferred from v0.10.0. Their decisions ship as the
foundation work in v0.11.0 (schema + types) and the full
implementation in v0.13.0+.
