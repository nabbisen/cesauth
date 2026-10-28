# RFC 148 — Account deletion leaves the user's email address behind

**Status.** **Done** — **shipped v0.87.0** (the scrub) and **v0.87.1**
(§7, its outcome made observable).
**Evidence**: **`exercised`** (RFC 000 §22) — four real-schema SQL witnesses in
`migrate-test/tests/migration_chain/rfc_148_scrub.rs`, including a genuine
collision demonstration showing a naive tombstone violates the partial unique
index while the per-request+per-row one does not on identical data; plus five
`core::deletion` tests covering the whole `ScrubOutcome` space, of which
`execute_deletion_reports_failed_when_scrub_email_errors` is the one §7 said
was missing — it asserts `Failed` **and** that the deletion still completed.
**Precisely: the outcome is exercised; the callers' reporting of it is not** —
removing `scrub:{}` from both call sites fails nothing. §8.1, owned by
RFC 123 §1.2.

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
| `invitation_tokens` | yes | **`email`**, `issued_by` — and see §2.1 for `accepted_by` / `revoked_by` | **no** |
| 11 others (`user_sessions`, `authenticators`, `totp_authenticators`, `totp_recovery_codes`, `grants`, `consent`, `anonymous_sessions`, `role_assignments`, and the three membership tables) | no | — | cascade |

Fifteen tables carry a user-identifying column; `users` is the deleted row itself,
**11 cascade, and 3 survive.** (`admin-operations.md` says 28 tables cascade — that
is every table with a key to `users(id)`, most of which carry no identifying
column of their own. The two figures measure different sets and both are right.)

The first two surviving tables retain an **opaque identifier whose subject no
longer exists**,
which is defensible for an audit trail and is declared as such. The third
retains **the personal datum itself**.

### 2.1 Correction — two of those four columns never hold a user id

Established 2026-10-27 while RFC 000 §22's back-fill examined the invitation
flow (**RFC 153**). Of the four columns I listed:

- **`email`** — the invitee's address. Real, and the reason for this RFC.
- **`issued_by`** — a real admin principal id (`routes/invitations.rs:76`,
  `ctx_ta.principal.id`).
- **`accepted_by`** — **never a user id.** `accept_submit` writes the literal
  string `"pending-registration"` (`routes/invitations.rs:239`), in every row,
  always.
- **`revoked_by`** — **always `NULL`.** `core::invitation::revoke_invitation`
  has no caller outside its own tests, so no invitation has ever been revoked.

**This narrows the RFC, and the narrowing is worth stating rather than quietly
absorbing.** The retained personal data is the **email address and the issuing
admin's id** — not four identifiers. §5's decision is unchanged: scrub the
address, keep the administrative record. But the tombstone work is smaller than
§5 implied, and `accepted_by` needs no scrubbing because it has never contained
anything to scrub.

**It also removes an argument I made.** §3 said purging would "erase a record
of what an administrator did" partly on the strength of acceptance data. The
acceptance record does not exist. The `issued_by` / `issued_at` / `role`
argument stands on its own and is enough.

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

## 7. The scrub works and its failure is invisible — why this RFC has not closed (2026-10-28)

0.87.0 implemented §5's decision and the implementation is correct. **The
guarantee is still not observable**, so the RFC stays `accepted`.

### 7.1 What is established

`core/src/deletion.rs`, inside `execute_deletion`:

```rust
let email = user_repo.find_by_id(&req.user_id).await
    .ok()                       // ← a failed read yields None
    .and_then(|u| u.email);
user_repo.delete_by_id(&req.user_id).await.map_err(|_| CoreError::Internal)?;
if let Some(email) = email {
    invitation_repo.scrub_email(&email, request_id).await.ok();   // ← error discarded
}
```

and the signature is `-> CoreResult<()>`. So **both callers —
`routes/deletions.rs:445` and `sweep.rs:269` — receive `Ok(())` whether the
scrub succeeded, failed, or was never attempted.** No log, no audit detail, no
return value. In the failure case the address remains and **nothing anywhere
records that it did.**

### 7.2 Why the implementation is nonetheless right

The scrub runs **after** the user row is deleted, and it must. Reporting a
scrub failure as a failure of `execute_deletion` would tell the caller the
deletion failed when the user is already gone — and the caller's retry would
then get `deletion request is not pending`. The cycle's reasoning
(*"a scrub failure must not be reported as a failure to delete the user, who is
already gone by then"*) is correct.

**Discarding the error is not the only way to honour that**, and it is the one
that leaves no trace.

### 7.3 Why this did not block the release

**0.87.0 is strictly better than its absence.** Before it, the address *always*
remained. After it, the address remains only when a read or a write fails.
Holding the tag to perfect the failure path would have kept the worse state in
production longer, for a benefit available in the next patch.

**What did have to change immediately** is the documentation.
`admin-operations.md` was rewritten by the cycle to say `execute_deletion`
*"replaces `email` in every matching row"* — unconditionally, with no mention
of best-effort. **That sentence asserted something the code does not reliably
do**, on a privacy guarantee, which is this project's signature defect created
fresh in the release that fixed three other instances of it. Corrected in the
same release: the paragraph now states the best-effort behaviour and points
here.

### 7.4 What closes this RFC — 0.87.1

Make the outcome observable, without making it a deletion failure:

1. `execute_deletion` returns the scrub outcome — `CoreResult<ExecuteOutcome>`
   with a `scrub: ScrubOutcome` field (`Scrubbed` / `NoEmailOnFile` /
   `Failed`), or the smallest equivalent.
2. Both callers act on it: the admin route and the sweep **log** a `Failed`,
   and it goes into the `deletion_executed` audit event's detail — that event
   already carries free text and already distinguishes the sweep from an admin.
3. `NoEmailOnFile` is **not** a failure — an anonymous-promoted account may
   genuinely have no address — but it must be distinguishable from `Scrubbed`,
   because "nothing to scrub" and "scrub did not happen" look identical today.
4. A test per outcome, and the documentation's best-effort paragraph replaced
   by what is then true.

**Evidence term when it closes:** `exercised` — the cycle's SQL witnesses in
`migrate-test/.../rfc_148_scrub.rs` already cover the happy path; what is
missing is a witness for the failure path, which is exactly the shape RFC 155
was about.

## 8. §7 closed, and one residual it did not ask for (2026-10-28)

0.87.1 delivered §7.4's four items. `execute_deletion` returns
`ExecuteOutcome { scrub: ScrubOutcome }`, both types `#[must_use]`; five tests
cover `Scrubbed` / `NoEmailOnFile` / read-failure / scrub-failure, the last
also asserting the deletion **still completed** — constraint (2) proven under
the exact failure this RFC is about. Both callers carry `scrub:<outcome>` in
the `deletion_executed` detail and log a `Failed` at `Level::Error`.

**One reading improved on the specification.** §7.4 did not say what to do with
`Ok(None)` — a user that should have been found and was not. The cycle mapped
it to `Failed` rather than `NoEmailOnFile`, because it tells us nothing about
whether an email existed and so is not evidence that nothing needed scrubbing.
That is the distinction this whole section exists to preserve, and it is a
better answer than the one I specified.

### 8.1 The residual: the reporting has no witness

§7.4 item 2 required both callers to report the outcome. They do. **Nothing
asserts that they do.** Verified in review by removing `scrub:{}` from the
audit detail in both `routes/deletions.rs` and `sweep.rs` and running the full
host suite: **911 + 221 passed, nothing failed.** Deleting the reporting
regresses silently.

**That is this section's own defect one level up**, in the cycle that fixed it
one level down — and it is an observation, not a missed requirement: §7.4 asked
for "a test per outcome" and got five.

**It is not reopened here**, because the caller path is not host-testable —
`log::emit` and `audit::write_owned` take `worker::Env`, the impossibility
class RFC 146 §2 established. **The detail string is testable**: extract the
`format!` into a pure function and assert it, as RFC 143 did for
`decide_verify_*` and RFC 155 for its message functions. **Owned by
[RFC 123](../proposed/123-audit-event-completeness.md) §1.2**, which already
holds audit-event content.
