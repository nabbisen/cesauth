# Developer Handoff — RFC 172: passkey registration must authenticate its subject

**Governing RFC.** [`rfcs/accepted/172-passkey-registration-authenticates-nobody.md`](../../accepted/172-passkey-registration-authenticates-nobody.md)
— **read §4.1 and not §4.** §4 was wrong and §4.1 says how; following §4 would
ship a fix that writes orphaned authenticator rows.
**Review that found it.** `.git-exclude/reviewed/152-half-d-stage-1-review.md` §4
**Builds on.** RFC 152 half D **stage 1b**, which runs first. Rebase on whatever
commit it lands as; do not start from `79e9090`.

**Target release.** **Patch — the same held cut as RFC 152 half D.** A P0 goes
out in the cut that is already held, not in a release of its own. Number
assigned at the cut.
**Tier.** **P0.** **Exposure today: none — nobody has deployed this tree.** That
is the only thing between urgent and incident, and it is not a reason to relax.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Stage 1b landing. **Dispatched 2026-11-03.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. The defect, in one paragraph

`POST /webauthn/register/start` reads the account it is about to register a
passkey for out of **the request body** — `RegisterStartBody::user_id` — and
reads no cookie, no `Authorization` header and no token.
`POST /webauthn/register/finish` takes that `user_id` back out of the stored
challenge, writes an authenticator row bound to it, and ends on
`post_auth::complete_auth(…, &authn.user_id, …)` under its own comment
*"Registration doubles as a first-login: issue a session."* **Given a user id,
that is account takeover in two unauthenticated requests.**

Observed by the architect against `wrangler dev`, and this is the check that is
not there:

```
POST /webauthn/register/start  {"user_id":"<an existing active user's id>"}
   no cookie, no Authorization, no CSRF token
-> 200 OK  {"handle":"…","public_key":{"attestation":"none", … }}
```

**Do not build an exploit.** The missing check is the defect; demonstrating the
consequence adds nothing and the repository should not contain it. No
authenticator row was created by that probe.

## 2. The fix

**The subject comes from the session. Never from the caller.**

1. **`register_start` resolves a session first**, before anything else, and uses
   that user's id. Use `me_auth::resolve_or_redirect`, and copy
   `routes/deletions.rs:101-107`'s shape exactly: `Err(_)` answers **401 JSON**
   (`{"error":"not authenticated"}`), **not** a 302 — RFC 149 §2's own ruling,
   because a redirect-following client cannot tell a 302-to-success from a
   302-to-failure.
2. **Delete `RegisterStartBody::user_id`.** `preferred_name` stays.
3. **Keep `registration::start`'s `user_id: Option<String>` parameter**, now
   filled with `Some(session_user_id)`. **Do not remove it** — that would leave
   the `None` branch as the only behaviour, and that is the branch that mints a
   UUID with no `users` row behind it and writes an orphan. §4.1 explains why
   the RFC's first draft had this backwards.
4. **`register_finish` needs no subject change** — it reads the challenge, and
   after (1) the challenge can only carry a session-derived id. **Check whether
   it should *also* require a session**: it issues a session for the challenge's
   user, and the challenge is already single-consumption and 60-second bound.
   **Report your reading either way**; if you add one, the same 401 JSON shape.

## 3. What the fix must carry

- **A witness, not a reading.** RFC 000 §22.2 bars a P0 closing on `reviewed`.
  The sufficient witness is the probe above, inverted — capture the status lines:
  - `register/start` with `{"user_id":"<some other id>"}` and no session →
    **401**;
  - the same with a **valid session** → **200**, and the returned
    `public_key.user.id` is **the session's user**, base64url-encoded, *not* the
    body's. That second half is the one that matters: a 401 alone would also be
    produced by a fix that ignored the session and rejected everything.
- **A route-layer regression test**, not only in `core`. The property is *the
  subject a request can choose*, and that lives in `register.rs`. A `core` test
  of `registration::start` cannot see it — testing the outcome type is not
  testing the caller that reports it.
- **The route-contracts rows updated**, and the **`Actor` column** with them: it
  reads `End user` today for a route that has no user. After the fix it has one.
- **`register/finish`'s CSRF cell, which stage 1b deliberately left to you.** It
  reads `N/A (no ambient credential)` and that is false: it captures the
  `cookie` header for `post_auth::extract_pending_handle` and passes it to
  `complete_auth`, which reads `login_next` — the identical shape to
  `authenticate/finish`, which carries a real control. Give it one, and make
  E6 resolve it. The review's §3 has the four-row table.
- **E6's two arithmetics must still close**, with `0 unclassified`.

## 4. Stop conditions

- **`me_auth::resolve_or_redirect` turns out to be the wrong resolver** for this
  route — report what you would use and why, and stop. Session resolution on a
  credential-writing route is not a detail to improvise.
- **Requiring a session breaks a caller you find** — RFC 152 half D stage 1
  found none under `crates/`, but you are closer to the code than that grep.
  Report the caller; do not weaken the fix to accommodate it.
- **The `None` branch turns out to have a production caller** after all — then
  §4.1's premise is wrong and the fix changes shape. Report it.
- **You conclude `register/finish` must change its subject handling** — that is
  a design question, not an implementation one.
- Any new test passes before the fix is applied.

## 5. Not in this cycle, named so it is not quietly assumed

- **Flow 1 has no screen.** RFC 131's passkey surface is unbuilt, so after this
  fix the route is still uncalled — RFC 166's own class. That is accepted
  deliberately: the alternative is leaving a takeover path open. **Do not build
  a screen.**
- **Unlimited anonymous account creation is not settled by this fix** and was
  never this RFC's to settle. After the fix, nothing creates an account through
  the passkey ceremony at all.
- **The gate question — *does every handler that writes security state
  authenticate the subject it writes it for?*** — is real, is not small, and is
  not yours. Nothing in the thirteen gates asks it. It belongs to RFC 171's
  family or to its own RFC.

## 6. Baselines

**Take them from stage 1b's report, not from here** — stage 1b lands first and
moves the host-test count and E6's arithmetic. The figures in
`half-d-stage-1b-handoff.md` §6 are `79e9090`'s and will be stale by the time
you start. **Name the command and the commit for every figure you report**, and
**name the gzip level with any bundle figure** — the project's progression is on
gzip 1.15's **default** level, and `-9` reads ~4.2 KB lower.
