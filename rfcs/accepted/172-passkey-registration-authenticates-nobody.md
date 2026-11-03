# RFC 172 — Passkey registration authenticates nobody, and names its own subject

**Status.** **Accepted** 2026-11-03 by the owner (*"RFC 172 is accepted."*).
Proposed the same day by the architect, found reviewing RFC 152 half D stage 1.

**Scheduled: the same held cut as RFC 152 half D** — patch, number assigned at
the cut. The cut was already held for half D stage 1b; a P0 goes out in it
rather than waiting for a release of its own. **Dispatched 2026-11-03, to run
after stage 1b** — both touch files near each other and the work is serialised.
**Ahead of RFC 170 and RFC 171 §3 Q1.**

**§4 is corrected below (§4.1, 2026-11-03), and the correction changes the
fix.** The original §4 recommended deleting the body field and leaving the
`user_id: None` branch as an anonymous signup path. That branch does not work:
it mints a UUID with no `users` row behind it. The fix takes the subject from
the **session** instead.
**Tier.** **P0.** `POST /webauthn/register/start` accepts the account it is
registering a passkey for **as a field in the request body**, with no credential
of any kind, and `POST /webauthn/register/finish` writes that authenticator and
then **issues a session for that account** — its own comment says *"Registration
doubles as a first-login"*. Given a user id, that is account takeover in two
unauthenticated requests.
**Exposure today: none.** **Nobody has deployed this tree** (`ROADMAP.md`
records it in three places), so there is no production instance to attack. That
is why this is urgent rather than an incident, and it is the only thing standing
between the two.
**Size.** **Small to write, and the decision is the work.** The identity input
has to stop coming from the caller; §4 says what it should come from instead,
and the answer differs for the two flows the one route serves.
**Touches.** `crates/backend/src/routes/webauthn/register.rs`,
`crates/core/src/webauthn/registration.rs` (signature),
`docs/src/expert/route-contracts.md`, tests. **No migration, no schema change.**
**Found by.** The architect, 2026-11-03, reviewing RFC 152 half D stage 1 — the
cycle recorded *"no ambient credential is ever consulted (reads `user_id` from
the challenge state `start` wrote, not a session cookie)"* as the justification
for a CSRF cell, which is correct, and is also the whole defect stated in one
line.
**Relates to.** [RFC 152](152-the-admin-surfaces-documented-csrf-control-is-not-the-real-one.md)
(the cycle that surfaced it), [RFC 166](166-reachability-stops-at-the-crate-boundary.md)
(these routes have no caller, and that is why nobody looked),
[RFC 171](171-the-arm-is-written-and-the-error-is-never-produced.md)
(the same shape one layer up: a control nothing produces).

**On 1.0:** not declared, not scoped, not dated.

---

## 0. Fixed in `ad0a648`, verified 2026-11-03 (not yet released)

`register_start` resolves a session first and takes the subject from it;
`RegisterStartBody::user_id` is **deleted**, so no field exists for a caller to
set; `registration::start`'s `Option` parameter is kept and always filled from
the session, per §4.1. `register_finish` needed no subject change — after the
fix the challenge can only carry a session-derived id. Both register rows gained
`require_json_content_type` and now read `required (Content-Type)`; the `Actor`
column reads `authenticated user`.

**Witness, `observed` by the dev team and independently by the architect** —
both halves, because a 401 alone would also be produced by a fix that rejected
everything:

```
register/start  {"user_id":"<another account>"}  no session     -> 401 {"error":"not authenticated"}
register/start  {"user_id":"<another account>"}  valid session  -> 200
   public_key.user.id == base64url(the SESSION's user id), byte-for-byte
   the body's id appears nowhere in the response
```

The session was a real magic-link sign-in. **No ceremony was driven to
completion and no exploit was written** — the missing check was the defect.
`authenticators` remained 0 rows throughout; probe sessions deleted.

**`register_finish` was deliberately left requiring no session**, and the
reasoning is the cycle's, not the architect's: a bare *does-a-session-exist*
check would be **worse than none**, because `complete_auth` signs the caller in
as the *challenge's* subject, so a second independently-valid session could
complete someone else's pending registration and be signed in as them. Doing it
correctly means comparing the finishing session against the challenge's bound
subject, which is a design decision and not a P0 fix's to improvise.
**The `Content-Type` control added to that route closes the matching hole**: an
attacker who gets a victim's browser to POST `finish` with the attacker's
pending handle would have the victim signed in as the attacker — session
fixation — and a cross-site form cannot send `application/json` while a
cross-site `fetch` with it preflights.

**After this fix `registration::start`'s `None` branch has no production
caller** (its only remaining callers are two `core` tests). An RFC 166 fact,
recorded, not acted on.

**§5's gate question stays open and unbuilt**: *does every handler that writes
security state authenticate the subject it writes it for?* Nothing in the
thirteen gates asks it.

## 1. Summary

`registration::start(rp, user_id: Option<String>, …)` uses the `user_id` it is
given, unvalidated:

```rust
let user_handle = user_id.unwrap_or_else(|| Uuid::new_v4().to_string());
```

`register_start` fills that argument from `req.json()` — `body.user_id` — and
reads no cookie, no header and no session. `register_finish` takes the
`user_id` back out of the stored challenge, writes an authenticator row bound to
it, and ends:

```rust
// Registration doubles as a first-login: issue a session. …
post_auth::complete_auth(&ctx.env, &cfg, &authn.user_id, AuthMethod::Passkey, …)
```

`complete_auth` is the same path magic-link sign-in ends on. **So the account a
passkey is registered against, and then signed in as, is chosen by whoever sends
the first request.**

## 2. What is established

**Observed, by the architect, against `wrangler dev` on 2026-11-03** — the
identity check that does not exist:

```
POST /webauthn/register/start   {"user_id":"<an existing active user's id>"}
   no cookie, no Authorization header, no CSRF token
-> 200 OK
   {"handle":"…","public_key":{"attestation":"none", … ,"challenge":"…","rp":{…}}}
```

A registration challenge for someone else's account, to an anonymous caller.
`"attestation":"none"` is in that response: the ceremony does not and cannot
attest which authenticator answers it, so the answering device is the caller's
choice. **No authenticator row was created by this probe** and none exists in
the local store; the challenge expires in 60 seconds.

**Reviewed** (read, with callers, not driven): the remaining two steps —
completing the ceremony against that challenge, and `register_finish`'s write
plus `complete_auth`. **No exploit was built and none should be**; the defect is
established by the missing check, not by demonstrating the consequence. RFC 000
§22.2 forbids a P0 entering `done/` on `reviewed` alone, so **the fix will need
a witness** — see §5.

**Both routes are registered unconditionally** (`lib.rs:199` and `:202`) and the
RP configuration they need ships with a default in `wrangler.toml` and sits on
the production preflight checklist, so there is no deployment in which they are
inert.

**No test asserts any of this.** `grep -rn "register_start\|register/start"
crates/ e2e/` finds no test or spec — the routes have no caller, no test, and no
gate that asks whether a route that writes a credential authenticates anyone.

## 3. Why it went unseen, and it is not a new reason

Three of this project's own established blind spots meet here:

1. **No caller.** The team confirmed nothing under `crates/` calls either
   register path. RFC 166's class exactly: the route is reachable over HTTP and
   unreachable from the product, so no screen exercises it and no reviewer
   walks it.
2. **Every gate the route does have, it passes.** It is registered (E4), it is
   documented (route contracts), its CSRF cell is now *true* (E6, as of half D
   stage 1). **Nothing in the gate set asks "does this handler authenticate the
   subject it acts on?"**
3. **The honest cell is what exposed it.** `N/A (no ambient credential)` is
   accurate and was the right answer to the question asked. A route that
   changes another account's security state and consults no ambient credential
   is not a CSRF exemption — it is a missing authentication. **The cell is
   correct and the sentence it states is the bug**, which is why half D stage 1
   is accepted as it stands and this is a separate RFC.

## 4. Direction — the identity must not come from the caller

**The rule: `register_start` never takes a subject from the request body.** The
one route serves two flows and they need different bindings, which is the actual
decision this RFC asks the owner to take.

**Flow 1 — a signed-in user adds a passkey to their own account.** The subject
is the session's user, read server-side. `routes::me`'s existing
`me_auth::resolve_or_redirect` is the resolver already used by
`/me/security/*`; `/me/security/delete-account` is the working precedent in the
same tree. A body field is never consulted.

**Flow 2 — a new user registers with a passkey and no account yet.** This is
not a mistake to remove: `docs/src/introduction.md` states the product's design
as *"Passkey first, username-less first. Magic Link is a fallback"*, so
self-service passkey signup is the declared primary flow, and
`user_id: None`'s mint-a-fresh-UUID branch is how it works. **That branch is
already safe** — the server chooses the identifier, so no existing account can
be named. It is the `Some(_)` branch, and only that branch, which is the defect.

**So the minimal correct fix is to delete the body field**, keep the `None`
behaviour as the anonymous signup path, and add flow 1 as a session-bound entry
point. Deleting the routes outright is **not** available: passkeys are the
product's headline capability, and removing them to close this would make
`introduction.md` false — this project's own recurring failure, one layer out.

**Two things this RFC deliberately does not decide**, because they are the
owner's and not consequences of the bug:

- **Unlimited anonymous account creation.** Flow 2 lets any caller create an
  account with no email verification and be signed in as it. That is a
  product/abuse question about self-service signup, not a takeover, and it is
  true of the design as declared. Named here so the fix is not quietly read as
  having settled it.
- **Whether flow 1 should exist yet.** There is no screen for it (RFC 131's
  passkey surface is unbuilt). Adding a session-bound entry point with no caller
  would create a new instance of §3's own class 1. **Shipping only the fix —
  drop the body field — and leaving flow 1 until a screen needs it is the
  smaller, more honest change**, and is this RFC's recommendation.

## 4.1 Correction, 2026-11-03, before dispatch: the subject comes from the session

**§4 above was wrong about flow 2, and the error would have shipped a broken
fix.** It called `user_id: None`'s mint-a-fresh-UUID branch *"already safe"* and
*"how [username-less signup] works"*. It is safe in the only sense that matters
to this RFC — it cannot name a victim — and it is **not a working flow**:

`register_finish`'s own comment states the premise the code is built on —
*"The user was created before this registration challenge was issued; fall back
to `'tenant-default'` if the lookup fails (defence-in-depth)."* **The design
expects an existing `users` row.** A server-minted UUID has none, so that branch
writes an authenticator for a user that does not exist and then issues a session
for it. The `tenant-default` fallback is what hides it.

**And "username-less first" in `introduction.md` does not mean what §4 read into
it.** The ceremony requests `"residentKey":"required"` — that is username-less
**authentication**, a discoverable credential the user signs in with *without
typing an identifier*. It is not account creation without a prior record.

**So there is one flow, not two**, and the fix is:

- **`register_start` requires an authenticated session** and takes the subject
  from it. `me_auth::resolve_or_redirect` is the resolver, and
  `routes/deletions.rs:101-107` is the precedent in this same tree for using it
  on a JSON route: `Err(_)` answers **401 JSON**, not a 302, so a
  redirect-following client cannot mistake a failure for success (RFC 149 §2).
- **`RegisterStartBody::user_id` is deleted.** `preferred_name` stays.
- **`registration::start`'s `user_id: Option<String>` parameter stays**, now
  filled with `Some(session.user_id)`. Removing it was the other candidate and
  is **rejected**: it would force the `None` branch to be the only behaviour,
  which is the branch that writes orphans. Its two remaining callers are tests
  in `crates/core/src/webauthn/registration/tests.rs`, both passing `None` —
  **so after this fix the `None` branch has no production caller at all**, which
  is an RFC 166 item to record, not to act on here.

**This is a surface-contract change and it is stated as one**: a caller may no
longer choose the account, and must now present a session. **No caller exists to
break** — RFC 152 half D stage 1 confirmed nothing under `crates/` calls either
register path — so the level stays **patch**. If a caller had existed, this
would still ship, and it would ship as a minor with notice.

**What this does not add.** No screen, and no new capability. A session-bound
registration entry point with no caller is RFC 166's own class, and it is
accepted here only because the alternative is leaving a takeover path open. The
route stays uncalled until RFC 131's passkey surface needs it.

## 5. What the fix must carry

- **A witness, not a reading.** §22.2 bars a P0 closing on `reviewed`. The
  cheap, sufficient witness is the probe in §2 inverted: `register/start` with
  a `user_id` body field must no longer bind to it — captured status and body.
  Driving a full ceremony is not required and an exploit must not be written.
- **A regression test at the route layer**, not only in `core`: §22.2's sibling
  lesson is that testing the outcome type is not testing the caller that reports
  it. The assertion that matters is *the subject a request can choose*, which
  lives in `register.rs`.
- **The route-contracts rows updated**, including the `Actor` column — it reads
  `End user` today for a route that has no user.
- **The gate question named, and left to RFC 171 or its own RFC**: *does every
  handler that writes security state authenticate the subject it writes it for?*
  Nothing asks it. That is the generalisation, it is not small, and folding it
  into a P0 fix would delay the fix.
