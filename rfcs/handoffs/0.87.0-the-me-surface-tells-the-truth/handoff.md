# Developer Handoff — 0.87.0, the `/me` surface tells the truth about itself

**Governing RFCs.** `rfcs/accepted/149-no-user-can-request-their-own-deletion.md`
· `rfcs/accepted/148-deletion-leaves-the-email-address-behind.md`
· `rfcs/accepted/154-the-second-factor-is-never-audited.md`

**Target release.** 0.87.0 — **minor.** RFC 149 adds a capability users do not
have; RFC 154 adds five audit event kinds, which is additive surface for anyone
parsing the stream. RFC 148's scrub is a fix on its own and rides because it
touches the same deletion path.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **RFC 150 shipped in 0.86.3**, which was RFC 149 §6's
only dependency — the `/me` surface's nonce is now per-request, so the new
form is not built on a defect that is invisible by construction.
**Dispatched 2026-10-28.**

**Order.** RFC 148 first (smallest, same path), then RFC 149, then RFC 154.

---

## 1. RFC 148 — scrub the email on deletion

**Read §5 and §2.1.** §5 is the decision (**scrub, not purge**); §2.1 corrects
§2's table and makes the work smaller than it first looked.

- Replace `email` with a tombstone on the deletion path. **It is
  `NOT NULL COLLATE NOCASE`** (`0018:23`), so the tombstone is a value, not a
  `NULL`: `deleted-<opaque>@invalid`, keyed off the **request id**, not a hash
  of the address — a hash of an email is still a pointer to the person, and
  `.invalid` is reserved by RFC 2606 for exactly this.
- **Distinct per row.** The partial unique index
  (`0018:42-44`, `WHERE accepted_at IS NULL AND revoked_at IS NULL`) will
  collide on identical tombstones across pending rows.
- **Do not scrub `accepted_by` or `revoked_by`.** §2.1: `accepted_by` is always
  the literal `"pending-registration"` and `revoked_by` is always `NULL`.
  Nothing to scrub, and RFC 153 owns why.
- Keep `issued_by`, `issued_at`, `role`, `accepted_at`.
- **`admin-operations.md:110-120` must stop saying the purge-or-scrub question
  is open**, and **§6's GDPR disclaimer must survive unchanged** — that
  paragraph's modesty is deliberate.

## 2. RFC 149 — a user can request, and cancel, their own deletion

**Read §5 and §6.** §5 decides **self-service cancellation: yes**, and the
alert carries the control.

**The surface.** A `/me/security` section with a form. **Form-encoded with a
real CSRF token in RFC 143's style**, not a JSON fetch — §4 explains why: this
product's security surfaces work without JavaScript and account deletion is
not the exception. So the human path is form-encoded; the existing JSON route
stays the programmatic one.

**Cancellation.** `POST /me/security/delete-account/cancel`, form-encoded,
CSRF-tokened, calling `deletion::cancel_deletion` — which exists
(`core/src/deletion.rs:185`) and has a production caller at
`routes/deletions.rs:196`. **Verify that for yourself**: §5 says so because
"the machinery is already there" is the claim shape that was false in
RFC 147 §2.

**The alert.** `pages/security_center.rs:79-88` currently renders an
irreversible-sounding `role="alert"` with no action. It must state the
deadline, that it can be stopped, and the control that stops it. **It must not
imply anything is reversible after execution** — nothing in cesauth makes an
executed deletion recoverable.

**The JSON contract — this is a surface-contract change and is the point.**
Today `302` is both "scheduled" and "not authenticated", so a redirect-following
client cannot tell whether it just scheduled the destruction of an account:

| Case | Today | Required |
|---|---|---|
| scheduled | `302` → `/me/security` | `200` + `{"scheduled_at": …}` |
| not authenticated | `302` → `/login?next=…` | `401` + JSON |
| already pending | `409` text | `409` + JSON |
| wrong content type | `400` text | `400` + JSON naming the CSRF reason |

**Do not remove the `Content-Type: application/json` requirement.** It is the
route's CSRF control — `route-contracts.md:107` records the column as
`N/A (JSON)` for exactly that reason. What is missing is a comment at the call
site saying so; add one.

**Audit.** A self-cancellation emits `deletion_cancelled` with
`cancelled_by` = the user, distinguishable from an admin's, the way RFC 147
cycle 2 made `executed_by` distinguish the sweep.

## 3. RFC 154 — emit the second factor's events

No TOTP operation emits anything today. Add emitters, and the kinds that do not
exist yet:

| Event | Kind | Notes |
|---|---|---|
| enrolment completed | `MfaEnrolled` | new |
| verification succeeded | **`MfaVerified`** | **already declared, emitted nowhere** |
| verification failed | `MfaFailed` | new |
| attempt limit reached | `MfaLockedOut` | new — RFC 143's lockout trips silently today |
| TOTP disabled | `MfaDisabled` | new; record the actor |
| recovery code used | `MfaRecoveryCodeUsed` | new |

**Fix the three comments in `recover.rs`** (`:15`, `:66`, `:91`) so none
describes a record that is not written. `:66` currently states a property of a
log that does not exist.

**Delete or justify the other unemitted variants.** `AuthSucceeded`,
`SessionCreated`, `SessionStarted`, `SessionExpired`, `SessionRevokedByAdmin`,
`WebauthnFailed`, `AdminConsoleViewed` are duplicates of kinds that *are*
emitted, or decisions not to audit. **Either is fine; being unable to tell
which is not** — remove each or give it a one-line "intentionally unemitted,
because …". `InvitationRevoked` is RFC 153's and
`IntrospectionRowMissing` is RFC 144's: **leave both alone.**

## 4. Resolved decisions — do not re-open

- **Minor**, for the reasons in the header.
- RFC 148: **scrub, not purge** (§5). RFC 149: **self-service cancel, yes**
  (§5). Both were decided against the owner's standard; they are not open.
- **Out of scope:** RFC 153 (the invitation flow — a 1.0 requirement, its own
  cycle), RFC 152 half B, RFC 156, RFC 123's coverage gate.
- **Do not run `cargo fix`** on the admin route modules (RFC 145 §13.2).
  `-D warnings` stays off; that decision is mine and still waits on a scoping
  pass.

## 5. Report-and-stop gates

- `cancel_deletion` turns out not to be reachable as §5 claims;
- the tombstone collides with a constraint not named in §1;
- a `recover.rs` comment turns out to describe a record that *is* written
  somewhere I did not find;
- **any evidence requirement in §6 you cannot construct.** One line saying so
  beats a silent substitution — my own handoff asked for an impossible test in
  RFC 145 cycle 2 and the substitution went unmentioned.

## 6. Required evidence

**RFC 000 §22 applies.** All three RFCs will carry a term when they close, and
the back-fill is now complete, so these are the first RFCs to be filed under
the rule from the start rather than back-filled into it.

1. **Assert the database rows, not the handler's status code.** RFC 147
   cycle 2's standard, and the reason RFC 047 survived 61 releases: for
   RFC 148, the post-deletion state of `invitation_tokens`; for RFC 154, rows
   in the audit table; for RFC 149, a real `deletion_requests` row and its
   cancellation.
2. **Fires/does-not-fire for each new witness.** Remove the behaviour, show the
   test fail, restore byte-identically, show it pass. Paste both.
3. **The JSON contract change asserted per row** of §2's table.
4. **Full gate set with counts.** CI's exact host-test command
   (`.github/workflows/test.yml:51-55`, five crates, **no `--lib`**), summed
   programmatically; baseline **1,594**. A release commit runs **12** CI
   workflows, not 13.
5. **A proposed `**Status**` + `**Evidence**` line** for each of the three, in
   the format the back-fill normalised:
   `**Evidence**: **\`term\`** (RFC 000 §22) — <the witness>`.

## 7. What must not be claimed

- Not that deletion is reversible after execution.
- Not that invitations work — RFC 153 is a separate, larger cycle.
- Not that the audit log is now complete; RFC 123 owns completeness and its
  coverage gate is not in this release.
- No count in prose without the command that produced it, and no derived total
  without checking it against its own parts.

## 8. Review request

Write the package to `.git-exclude/review-request/0.87.0-report.md` and give me
the commit. I verify independently before anything is tagged.
