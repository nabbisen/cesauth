# RFC 152 — The admin surfaces' documented CSRF control is not the real one

**Status.** **Accepted** 2026-10-27. **Split: half A scheduled 0.86.3** (patch
— make the document true and pin the real control), **half B after 0.87.0**
(the 33 handlers and their forms). See §5.
**Tier.** P1 — not a live vulnerability, and that is established below rather
than assumed. It is P1 because **fifteen** destructive or disabling
operations rest on one undocumented layer while the document claims a different
one — a figure that is 15 of the 33, not of the 35.
**Size.** Small if the answer is "document it"; medium if the answer is "add the
check".
**Touches.** `docs/src/expert/route-contracts.md` (35 rows),
`crates/backend/src/routes/admin/tenant_admin/`,
`crates/backend/src/routes/admin/tenancy_console/`,
`crates/backend/src/routes/admin/admin_login.rs` (the cookie), and whatever
gate ends up asserting the claim.
**Depends on.** Nothing.
**Found by.** The **dev team**, 2026-10-27, while implementing RFC 145 cycle 2 —
outside that cycle's scope, reported rather than absorbed. Severity corrected by
the architect during review the same day.

## 1. Summary

All 35 `POST` routes on the tenant-admin and tenancy-console surfaces document
their CSRF column as **`required`**, which in this codebase means a
double-submit token check via `csrf::verify`. **Thirty-three of the 35 do not
call it.**

The two that do are `/admin/t/:slug/deletion-requests/:id/cancel` and
`…/execute` — **the newest routes on either surface**, written under RFC 147
cycle 2 three days ago. So the pattern is applied to new work and was never
retrofitted to the rest, which is a more useful thing to know than "it was
never applied here".

The surfaces are nonetheless protected — by the admin cookie's
`SameSite=Strict` attribute, which no row mentions and no test asserts. So the
defect is not an absent control. **It is a document that names the wrong one**,
across 35 rows, 14 of which destroy data.

## 2. What is established

**The documentation's claim.**

```
$ awk -F'|' '/^\| POST/ && ($3 ~ /admin\/t\/|admin\/tenancy/) {gsub(/ /,"",$9); print $9}' \
    docs/src/expert/route-contracts.md | sort | uniq -c
     35 required
```

Thirty-five rows, every one of them `required` — including the 33 where
nothing checks a token.

**The code's behaviour.** Measured by resolving each of the 35 `post_async`
registrations in `lib.rs` to its handler's module and checking that module for
`csrf::verify` — **not** by grepping the two surface directories, which is how I
first measured it and which was wrong: `/admin/t/:slug/deletion-requests/*` is
served from `routes/deletions.rs`, outside both directories. A directory-scoped
grep answering a route-scoped question is the same error that once made a
`grep -c 'operator_json_api::shell'` expectation wrong in an RFC 145 handoff.

```
POST routes on the two admin surfaces: 35
csrf::verify present:                   2   (deletion-requests cancel, execute)
NO csrf::verify:                       33
```

The function exists and is used widely in the same crate —
`console/audit_chain.rs:60`, `console/audit_export.rs:34`, `me/sessions.rs:101`
and `:216`, `me/totp/*`, `magic_link/*`, `deletions.rs:179` and `:243` — so this
is not a missing capability.

**The destructive subset of the 33** spans `groups/:gid/delete`,
`role_assignments/:id/delete` (and `role_assignment_delete`), four flavours of
`memberships/:uid/delete`, `…/status` on tenants and organizations (which
includes transitions to deleted), `tenants/:id/suspend`, and
`subscription/status`, on both surfaces. The non-destructive remainder still
creates tenants, mints tokens (`users/:uid/tokens/new`) and grants role
assignments, which is not a lesser concern.

**The surface is cookie-authenticated**, so CSRF is applicable in principle.
`routes/admin/auth.rs`'s `bearer()` tries the `Authorization` header first and
then **falls back to the admin cookie** "(browser Leptos clients)".

**And the cookie is `SameSite=Strict`.** `routes/admin/admin_login.rs:77`:

```rust
"{}={}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={}"
```

`__Host-cesauth_admin` is therefore not sent on **any** cross-site request. A
cross-site POST to any of the 35 arrives with no credential and is rejected by
the auth gate. **There is no exploitable CSRF path today**, and any report of
this finding that omits the cookie overstates it.

**The project already reasons this way.** `routes/session.rs:36`: *"SameSite=Lax
on the session cookie is the primary defense (cross-origin POST does not carry
the cookie, so logout is a no-op anyway). The Origin check is defense-in-depth."*

## 3. Why it is still P1

**The asymmetry is the tell.** The `/me` surface uses `SameSite=Lax` — it must,
so that following a magic link from an email works — **and** calls
`csrf::verify`. The admin surfaces use `Strict` and call nothing. As
engineering that is coherent: each surface has exactly the protection its cookie
policy requires.

As a **record** it is false, and the falseness is load-bearing:

1. **A reader checking whether these routes are CSRF-protected reads
   `required` and stops.** They conclude a token check runs. It does not. This
   is the project's named recurring defect class — documentation asserting what
   the code does not do — on a security control, 33 times out of 35.
2. **One attribute is the entire defence, and nothing guards the attribute.** No
   test asserts `SameSite=Strict` on `__Host-cesauth_admin`. If it is ever
   relaxed to `Lax` for a navigation reason — exactly the reason `/me`'s cookie
   is `Lax` — then fifteen destructive operations become cross-site reachable,
   **no test fails, and no document changes**, because the document already
   claims a protection that was never there.
3. **It cannot be fixed by changing the column alone.** Writing `N/A
   (SameSite=Strict)` into 35 rows makes the document true and leaves the single
   point of failure unguarded and unstated.

## 4. Direction, and the decision this RFC must make

**Three options. The choice is the work; do not treat it as obvious.**

1. **Document the real control and pin it.** Rewrite the 35 CSRF cells to name
   `SameSite=Strict`, add a host test asserting the cookie string, and add a
   gate assertion that the admin cookie carries `Strict`. Cheapest, honest, and
   leaves one layer.
2. **Add `csrf::verify` to the 33 and keep the column as written.** Makes the
   document true by making the code match it, gives the surfaces two layers like
   `/me`, and costs 35 handler edits plus a token in every admin form — several
   of which are rendered by templates this RFC does not own. **Preferred on the
   owner's standard** (*finally clean, safe and secure*): defence in depth is
   what the document already promises, and the promise was made for a reason.
3. **Both**, with (1) first as a patch and (2) as a follow-up cycle.

**Whichever is chosen, the gate is not optional.** The failure mode here is a
silent one — a cookie attribute edited for an unrelated reason — and the only
thing that catches it is an assertion that fails. RFC 145 §13 is the standing
example of a defect that was visible on every build and reported to nobody.

## 5. The open question, answered (architect, 2026-10-27)

The question was whether option 2's cost — a `verify` call in 33 handlers and a
token in roughly 32 forms — is worth a second layer behind a first layer that
currently holds. Tested against the owner's standard rather than returned to
them.

**Correcting my own measurement answered it.** I first reported that *no*
handler on either surface verifies. It is 33 of 35: the two deletion-request
routes **do**, and they are the newest routes on either surface, written three
days ago under RFC 147 cycle 2 — applied by the dev team without being asked,
because it is what this codebase does for a destructive POST.

So option 2 is not a new direction needing justification against its cost.
**It is the direction the codebase is already taking, and option 1 would mean
deliberately reversing it** for the 33 routes that predate the habit. On
*finally clean, safe and secure*, that settles it.

**Decision: option 3 — both, in this order.**

- **Half A (patch, 0.86.3).** Make the document true and pin the control that
  actually works: the 33 CSRF cells say what defends them today, a host test
  asserts the `__Host-cesauth_admin` cookie string including `SameSite=Strict`,
  and a gate fails if that attribute changes. **Half A lands first because the
  dangerous failure mode is silent** — a cookie attribute edited for a
  navigation reason, with nothing failing — and half A is what makes it loud.
  It is also small enough that it should not wait behind half B.
- **Half B (its own cycle, after 0.87.0).** The 33 `csrf::verify` calls and the
  ~32 form tokens, after which the cells revert to `required` and mean it.

**Half B is sized, not hand-waved**: 33 handlers and ~32 templates across
`tenant_admin/forms/*` and the whole `tenancy_console` tree, none of which
currently takes a token parameter. That is a cycle of its own and must not be
bolted onto another.

The owner may overturn this; it is a cost judgement, and I have made it rather
than handed it back.
