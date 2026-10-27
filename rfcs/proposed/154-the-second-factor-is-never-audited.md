# RFC 154 — The second factor is never audited

**Status.** **Proposed** — awaiting owner authorization.
**Tier.** P1. The control that exists to survive a compromised first factor
leaves no record of being satisfied, failed, enrolled or removed.
**Size.** Small. Event kinds mostly exist; the emitters do not.
**Touches.** `crates/backend/src/routes/me/totp/{verify,enroll,disable,recover}.rs`,
`crates/backend/src/audit.rs` (kinds), `docs/src/expert/` audit chapter.
**Depends on.** Nothing. **RFC 123 owns the general gate** — see §5.
**Found by.** The architect, 2026-10-27, during RFC 000 §22's back-fill, while
determining RFC 045's evidence term.

## 1. Summary

**No TOTP operation emits an audit event.** Not enrolment, not a successful
verification, not a failed one, not disablement, not recovery-code use.

```
$ grep -rhoE "EventKind::[A-Za-z]+" crates/backend/src/routes/me/totp/ | sort -u
(no output)
```

`MfaVerified` is declared in the `EventKind` enum and **emitted nowhere in the
codebase.**

## 2. What is established

**The enum declares it and nothing sends it.** Of 71 `EventKind` variants, 10
have no reference anywhere outside the enum definition:

```
AuthSucceeded · SessionCreated · SessionStarted · SessionExpired
SessionRevokedByAdmin · MfaVerified · WebauthnFailed
AdminConsoleViewed · IntrospectionRowMissing · InvitationRevoked
```

**Most of those ten are not holes** — and this is worth stating, because my
first reading of the list was that successful logins are unaudited, which would
have been badly wrong. Authentication **is** audited, as `MagicLinkVerified`
and `WebauthnVerified`; admin session revocation as `AdminSessionRevoked`;
session expiry as `SessionIdleTimeout` / `SessionAbsoluteTimeout`. Those
variants are redundant names, not missing records. `InvitationRevoked` is
RFC 153's. `IntrospectionRowMissing` is RFC 144's.

**`MfaVerified` is the one with nothing behind it**, and the gap is wider than
the single variant: the whole `me/totp/` tree emits nothing.

**The doc comments describe the records as if they exist.**
`routes/me/totp/recover.rs` mentions audit three times, all in prose, none in
code:

- `:15` — *"audit record."*
- `:66` — *"audit log distinguishes the two failure modes."*
- `:91` — *"Phase 2's audit chain will…"*

`:66` states a property of a log that is never written. `:91` is honest about
being deferred, but it is the only one of the three that is, and nothing marks
the other two as aspirational. **Documentation asserting what the code does not
do, on a security control** — this project's named recurring defect class.

## 3. Why it matters concretely

An operator investigating a suspected account compromise cannot answer:

- **was the second factor satisfied?** No success record.
- **was it attacked?** No failure record — and RFC 143 established an
  attempt counter with a lockout, so **the lockout trips silently too.**
  A brute-force attempt against a TOTP gate is invisible after the fact.
- **was it removed, and by whom?** No disablement record. An attacker who
  reaches an authenticated session and disables TOTP leaves no audit trace of
  having done so.
- **were recovery codes used?** No record, despite `:15`'s comment.

For a product whose audit chain is hash-linked and tamper-evident
(RFC 128), the gap is not that the log is weak — it is that these events never
enter it.

## 4. Direction

Emit on every TOTP state transition and on both verification outcomes:

| Event | Kind | Subject |
|---|---|---|
| enrolment completed | `MfaEnrolled` (new) | the user |
| verification succeeded | **`MfaVerified`** (exists, unused) | the user |
| verification failed | `MfaFailed` (new) | the user |
| attempt limit reached | `MfaLockedOut` (new) | the user |
| TOTP disabled | `MfaDisabled` (new) | the user, with the actor |
| recovery code used | `MfaRecoveryCodeUsed` (new) | the user |

**Assert the rows, not the handler.** RFC 147 cycle 2's standard: drive the
path and read the audit table. A test that checks a handler returned 200 is
what let RFC 047 live for 61 releases.

**Delete or justify the other redundant variants.** `AuthSucceeded`,
`SessionCreated`, `SessionStarted`, `SessionExpired`,
`SessionRevokedByAdmin`, `WebauthnFailed`, `AdminConsoleViewed` are either
duplicates of emitted kinds or decisions not to audit. **Either is fine; being
unable to tell which is not.** Each should be removed or given a one-line
comment saying why it is intentionally unemitted — otherwise the next reader
repeats my wrong first inference.

**Fix the three comments** in `recover.rs` so none of them describes a record
that is not written.

## 5. Relationship to RFC 123, and why this is a separate record

**RFC 123 owns the mechanism** — its §1(2) is *"a route↔EventKind coverage test
that fails when a mutating route exists without a mapped event"*. That is the
**opposite direction** to this finding, and RFC 123 does not mention unemitted
kinds; the two are two directions of one property, as RFC 141 §13 and RFC 145
§4.2 were.

**RFC 123 should gain the missing direction**: a declared `EventKind` with no
emitter fails the same coverage test, unless named as intentionally unemitted.
Recorded there.

**This is a separate record because it is shippable now and RFC 123 is not.**
RFC 123 is a Category B programme with `Audited<T>` wrappers and property
tests, depending on RFC 116. The second factor being unauditable should not
wait behind it. Keeping this finding inside RFC 123 would be RFC 144's lesson
repeating: *recorded as an RFC because it was lost once* as a note in someone
else's.
