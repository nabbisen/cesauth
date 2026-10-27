# RFC 148 — Account deletion leaves the user's email address behind

**Status.** **Accepted** 2026-10-27. **Scheduled 0.87.0** (minor — the scrub
write is a fix, but it rides with RFC 149's new surface; see §6).
**Tier.** P1 — in an identity product, a personal datum that outlives the
account it identifies is a substantive gap, not a tidiness one.
**Size.** Small in code; the design question is the work.
**Touches.** `migrations/` (one new migration), `crates/core/src/deletion.rs`,
the invitation repository, `docs/src/expert/admin-operations.md`.
**Depends on.** RFC 147 (done) — this is its §14, promoted to its own record.
**Found by.** The architect, 2026-10-25, while scoping RFC 147 cycle 2;
re-verified against `main` at `0a783c3`, 2026-10-27.

## 1. Summary

`execute_deletion` hard-deletes the `users` row, and `ON DELETE CASCADE`
removes every table holding a foreign key to `users(id)`. **`invitation_tokens`
holds no such key.** A deleted user's rows in that table survive, carrying
their **email address in plain text**, plus their user id in up to three
columns.

This RFC does not report a surprise. **RFC 147 cycle 2 documented the exception
accurately** and deferred the decision. The RFC exists to make the deferral a
record with a number rather than a sentence inside a closed RFC, and to settle
the policy.

## 2. What is established

**The schema has no key to `users`.** `migrations/0018_invitation_tokens.sql:21-33`
— `tenant_id` references `tenants(id) ON DELETE CASCADE`; `email`, `issued_by`,
`accepted_by` and `revoked_by` are plain `TEXT`.

**It is the only such table holding a personal datum.** Taking each table's
*last* definition across all migrations (a table rebuilt by a later migration
must be read there, not at its first appearance — the method matters, and two
earlier methods gave wrong answers):

| Table | Survives a user delete | Datum retained | Declared? |
|---|---|---|---|
| `audit_events` | yes | `subject` = user id | yes — the chain must not be broken |
| `deletion_requests` | yes | `user_id`, `requested_by`, `executed_by`, `cancelled_by` | yes — `0019:24` says so in a comment, and `execute_deletion`'s doc comment says the row is retained for audit |
| `invitation_tokens` | yes | **`email`**, `issued_by`, `accepted_by`, `revoked_by` | **no** |
| 11 others (`user_sessions`, `authenticators`, `totp_authenticators`, `totp_recovery_codes`, `grants`, `consent`, `anonymous_sessions`, `role_assignments`, and the three membership tables) | no | — | cascade |

Fifteen tables carry a user-identifying column; `users` is the deleted row itself,
**11 cascade, and 3 survive.** (`admin-operations.md` says 28 tables cascade — that
is every table with a key to `users(id)`, most of which carry no identifying
column of their own. The two figures measure different sets and both are right.)

The first two surviving tables retain an **opaque identifier whose subject no
longer exists**,
which is defensible for an audit trail and is declared as such. The third
retains **the personal datum itself**.

**The documentation is already correct.**
`docs/src/expert/admin-operations.md:110-120` states the exception, names the
columns, and says the purge-or-scrub decision is out of RFC 147's scope. No
documentation correction is needed — unusually for this project, the record and
the code agree.

**There is no functional lockout.** The unique index is partial —
`idx_invitation_tokens_email_tenant_active … WHERE accepted_at IS NULL AND
revoked_at IS NULL` (`0018:42-44`) — so a retained *accepted* row does not
block a later invitation to the same address. A retained *pending* row does,
until it expires. This is a minor consequence, not the reason for the RFC.

## 3. What is not established

Whether the retention is harmful enough to justify destroying the invitation
audit trail. Three columns here (`issued_by`, `revoked_by`) record *an admin's*
action, not the deleted user's; purging a row because its `email` names a
deleted user also erases a record of what an administrator did. **The two
interests are in tension and this RFC must resolve the tension, not pick a side
by default.**

## 4. Direction

Three candidates, to be decided in the design cycle rather than here:

1. **Scrub, not purge.** Replace `email` with a tombstone
   (`deleted-<hash>@invalid` or `NULL` after relaxing `NOT NULL`), keep
   `issued_by` / `accepted_at` / `role`. Preserves the administrative record,
   removes the personal datum. **This is the current preference.**
2. **Purge** rows whose `accepted_by` equals the deleted user, retain rows the
   user merely `issued_by`. Loses the acceptance record.
3. **Declare the retention.** Add the comment `0019` has, document it as
   intended, and stop there. Honest, but leaves an email address in the
   database after an account deletion the product calls irreversible.

Whichever is chosen, the deliverable includes:

- a migration or a deletion-path write, with the chain test extended;
- a host test in `crates/core` asserting the post-deletion state of the table,
  of the kind RFC 147 cycle 2 established for the deletion path;
- the `admin-operations.md` paragraph rewritten from "a separate design
  question" to what was in fact decided.

## 5. The open question, answered (architect, 2026-10-27)

The question was whether cesauth intends a **completeness claim** about
deletion — "no personal data remains" — or only a **functional** one — "the
account and its credentials are gone". I raised it as the owner's to make.
Tested against the owner's standard — *finally clean, safe and secure, and
robust and sophisticated design; APIs and UI/UX for users not to be confused or
misunderstand* — it does not need to go back to them, because the standard
answers it.

A user who deletes their account and is told the action is **irreversible**
understands that to mean cesauth no longer holds them. It does not mean "your
credentials are gone but we kept your email address in a table you were never
told about". **Whatever the law requires, that is a user misunderstanding the
product's own promise**, which is the second half of the standard, and it is
caused by us.

**Decision: option 1 — scrub, not purge.** The `email` column is replaced with
a tombstone on the deletion path; `issued_by`, `issued_at`, `role`,
`accepted_at` and `revoked_*` are kept. This is the only option that satisfies
both interests rather than trading one away: the personal datum goes, and the
record of *what an administrator did* — which is not the deleted user's data to
erase — stays.

Two consequences, to be handled in the cycle rather than discovered in it:

- **`email` is `NOT NULL COLLATE NOCASE`** (`0018:23`), so the tombstone is a
  value, not a `NULL` — `deleted-<opaque>@invalid` keyed off the request id, not
  a hash of the address, since a hash of an email address is still a pointer to
  the person and `.invalid` is reserved by RFC 2606 for exactly this.
- **The partial unique index** (`0018:42-44`) covers only rows with
  `accepted_at IS NULL AND revoked_at IS NULL`. Distinct tombstones per row keep
  pending rows from colliding; identical tombstones would not.

Scrubbing is a **fix**, so on its own it is patch-level. It is scheduled with
0.87.0 only because it touches the same deletion path RFC 149 rewrites, and
RFC 133's standing lesson is that two changes to one path in one cycle cost less
than two cycles.

## 6. The claim cesauth should make

`admin-operations.md:128-131` currently declines to claim GDPR compliance and
says only "the three routes above now do what they say". **That sentence should
survive this RFC unchanged.** Deleting the email address makes the product
cleaner; it does not make the project a compliance authority, and replacing a
careful disclaimer with a confident one would be the same defect class in a new
place. The paragraph gains the scrub and keeps the modesty.
