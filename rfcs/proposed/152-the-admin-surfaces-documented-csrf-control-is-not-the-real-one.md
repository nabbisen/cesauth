# RFC 152 — The admin surfaces' documented CSRF control is not the real one

**Status.** **Proposed** — awaiting owner authorization.
**Tier.** P1 — not a live vulnerability, and that is established below rather
than assumed. It is P1 because fourteen destructive operations rest on one
undocumented layer while the document claims a different one.
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

Every `POST` on the tenant-admin and tenancy-console surfaces documents its
CSRF column as **`required`**, which in this codebase means a double-submit
token check via `csrf::verify`. **No handler on either surface calls it.**

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

Thirty-five rows, every one of them `required`.

**The code's behaviour.**

```
$ grep -rn "csrf::verify" crates/backend/src/routes/admin/tenant_admin/ \
                          crates/backend/src/routes/admin/tenancy_console/
(no output)
```

Zero. The function exists and is used elsewhere in the same crate —
`console/audit_chain.rs:60`, `console/audit_export.rs:34`, `me/sessions.rs:101`
and `:216`, `me/totp/*`, `magic_link/*`, `deletions.rs:179` and `:243` — so this
is not a missing capability. It was never applied here.

**Fourteen of the 35 are destructive**: `groups/:gid/delete`,
`role_assignments/:id/delete`, three flavours of
`memberships/:uid/delete`, and `…/status` (which includes a transition to
deleted), on both the `/admin/t/:slug/*` and `/admin/tenancy/*` surfaces.

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
   the code does not do — on a security control, 35 times.
2. **One attribute is the entire defence, and nothing guards the attribute.** No
   test asserts `SameSite=Strict` on `__Host-cesauth_admin`. If it is ever
   relaxed to `Lax` for a navigation reason — exactly the reason `/me`'s cookie
   is `Lax` — then fourteen destructive operations become cross-site reachable,
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
2. **Add `csrf::verify` to all 35 and keep the column as written.** Makes the
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

## 5. Open question for the owner

Option 2 adds a CSRF token to 35 admin forms. That is real work and it buys a
second layer behind a first layer that currently holds. **I recommend option 2**
anyway, because the document has promised it for the life of these surfaces and
because `SameSite` is one edit away from not holding — but the cost is the
owner's to weigh, and option 1 is defensible if the gate in §4 lands with it.
