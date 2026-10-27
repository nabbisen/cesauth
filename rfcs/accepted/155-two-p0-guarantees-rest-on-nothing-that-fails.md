# RFC 155 — Two P0 security guarantees rest on nothing that fails

**Status.** **Accepted** 2026-10-27 — scheduled **0.86.3, patch**. Both
deliverables make code or tests match a claim the record already makes; no
capability is added. *(Architect-decided scope: these are two small
enforcement gaps of one shape, found together. Numbered rather than folded
into a handoff because RFC 144's standing lesson is what happens to a finding
that lives only in one.)*
**Tier.** P1 as a record. The two underlying RFCs are **P0**, and under
RFC 000 §22 neither may sit in `done/` on `reviewed`.
**Size.** Small: one manual `Debug`, one test, one assertion set.
**Touches.** `crates/core/src/magic_link/mailer.rs`,
`crates/backend/src/routes/magic_link/verify.rs` (tests only),
`rfcs/done/030-*.md` and `rfcs/done/074-*.md` (Status terms).
**Depends on.** RFC 116 for `RedactedSecret`, which already exists.
**Found by.** The architect, 2026-10-27, during RFC 000 §22's back-fill.

## 1. Summary

Two P0 RFCs state a security guarantee. Both guarantees hold today. **Neither
is enforced by anything that would fail if it stopped holding.**

## 2. RFC 030 — "never allow `MagicLinkPayload.code` to reach `Debug`"

**The guarantee.** RFC 030 §Decision(2): *"Never include provider response
body. **Never allow `MagicLinkPayload.code` to reach `Debug` / `Display` / log
output.**"*

**What enforces it.** Nothing. `core/src/magic_link/mailer.rs:81`:

```rust
#[derive(Debug)]
pub struct MagicLinkPayload<'a> {
    …
    /// **Secret.** OTP plaintext. Only this mailer instance receives it.
    /// Do not log, persist, or forward outside the delivery channel.
    pub code: &'a str,
```

A plain `derive(Debug)` prints `code`. **The guarantee is carried entirely by
the doc comment asking politely.**

**It is not currently violated** — nothing in the workspace formats a payload
with `{:?}`, verified. So this is a latent hazard, not a live leak, and the
RFC must not be written up as one.

**Two things make it worth fixing now rather than noting.** First, the
redaction tool already exists and is unused here: `RedactedSecret`
(`core/src/types/secret.rs:134`, RFC 116) with its own tests, and
`REDACTION_MARKER`. Second, **for invitations `code` is not an OTP but a full
accept URL** — `routes/invitations.rs:99`, *"the `code` IS the full accept URL
for invitations"* — so one `{:?}` in a future error path logs a working bearer
link, not a six-digit number that has probably expired.

**Deliverable.** A hand-written `Debug` for `MagicLinkPayload` that prints
`recipient`, `handle`, `locale`, `reason`, `tenant_id` and renders `code` as
`REDACTION_MARKER`; plus a test asserting `format!("{payload:?}")` does not
contain the code. `Display` is not implemented and should stay that way.

## 3. RFC 074 — the generic auth-failure messages

**The guarantee.** RFC 074 requires that a failure not reveal which stage
failed, with `/magic-link/verify` specifically not distinguishing *"Code
expired"* from *"Code wrong"*.

**It is implemented.** `routes/magic_link/verify.rs:202` —
*"Incorrect or expired code. Please check your email and try again."* — and
`:171`/`:185` conflate expiry with reuse: *"This magic link has expired or was
already used."* Correct, and deliberately so.

**Nothing asserts it:**

```
$ grep -rn "Incorrect or expired\|expired or was already used" crates/ --include='*.rs' \
    | grep -iE "assert|test"
(no output)
```

So a future edit that split the two cases for a better error message — the
most natural refactor in the world, and one a reviewer would likely wave
through — would reintroduce the oracle with no test failing.

**Deliverable.** Assertions on the conflated messages for the paths RFC 074's
table names, written against the **decision function** rather than the
response where the split would occur, so the test survives a rendering change.
RFC 143's `decide_verify_*` split is the precedent for where that boundary
goes.

## 4. Why one record for two RFCs

They are one shape: **a P0 guarantee with no failing witness.** Fixing them
means one manual `Debug` and one set of assertions, in one patch, verified by
the same question — *what fails if this stops holding?* Two numbers for thirty
lines would cost more to track than it buys.

They are **not** merged into the 0.86.3 handoff unnumbered, because a finding
recorded only in a handoff is RFC 144's lesson: *recorded as an RFC because it
was lost once.*

## 5. On both RFCs' Status terms

On landing, RFC 030 and RFC 074 become **`exercised`**, each naming the test
added here. Until then both are **`reviewed`**, which is recorded on them now
rather than after the fix — **a P0 carrying `reviewed` is exactly the signal
§22 exists to surface, and hiding it until the remedy ships would defeat the
rule in its first week.**
