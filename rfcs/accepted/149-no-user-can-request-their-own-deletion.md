# RFC 149 — No user can request their own deletion, and the endpoint that would do it answers unreadably

**Status.** **Accepted** 2026-10-27. **Scheduled 0.87.0** (minor — it adds a
capability users do not have today). **Sequenced after RFC 150**; see §6.
**Tier.** P1 — a capability the product documents and routes, that no user can
reach, and whose one response code means two opposite things.
**Size.** Small-to-medium: one template section, one form, one handler's
response contract, one e2e test.
**Touches.** `crates/backend/src/routes/deletions.rs`,
`crates/frontend/src/pages/security_center.rs`,
`crates/backend/src/routes/me/security.rs`,
`docs/src/expert/route-contracts.md` row 107, `e2e/`.
**Depends on.** RFC 147 (done) — the pipeline this surface would drive now
works. **Related to RFC 145** — same defect class: declared, routed, unreachable.
**Found by.** The architect, 2026-10-27, while scoping RFC 147's follow-ups.

## 1. Summary

`POST /me/security/delete-account` exists, is routed, is documented, and
**has no caller.** No template renders a form to it; no page links to it; no
e2e test drives it. A user has no way to request deletion of their own account
through cesauth.

The page the endpoint redirects to on success, `/me/security`, *does* render an
alert reading **"Account deletion scheduled — Your account is scheduled for
deletion on <date>."** — a state the user cannot enter, cannot cancel, and is
given no instruction about.

Separately, the handler's response contract cannot be read by the JSON client
it demands to be: **`302` is both its success answer and its
not-authenticated answer.**

## 2. What is established

**No caller.**

```
$ grep -rn "delete-account" --include="*.rs" --include="*.html" --include="*.js" --include="*.ts" crates/ e2e/ docs/ | grep -v route-contracts.md
crates/backend/src/routes/deletions.rs:5://!   POST /me/security/delete-account
crates/backend/src/routes/deletions.rs:38:// POST /me/security/delete-account
crates/backend/src/lib.rs:233:        .post_async("/me/security/delete-account", |req, ctx| async move {
```

Three hits: two comments and the route registration. Nothing calls it.

**The notice with no exit.** `crates/frontend/src/pages/security_center.rs:79-88`
renders `<section role="alert">` with the heading and date above. It contains no
link, no form, and no cancellation control. The only cancel route in the system
is `POST /admin/t/:slug/deletion-requests/:id/cancel`
(`docs/src/expert/route-contracts.md:109`) — **tenant admin only.** A user who
somehow reaches the scheduled state is shown an irreversible-sounding alert and
offered nothing.

**`302` means two different things.** On success
(`routes/deletions.rs`, end of `request_self`):

```rust
let mut resp = Response::empty()?.with_status(302);
let _ = resp.headers_mut().set("location", "/me/security");
```

On an unauthenticated request, `me_auth::resolve_or_redirect` returns
`Ok(Err(redirect_to_login_with_next(req)?))`, and that helper
(`routes/me/auth.rs`) ends:

```rust
Ok(resp.with_status(302))     // location: /login?next=…
```

A JSON client therefore receives `302` whether the deletion was scheduled or
refused for want of a session, and must inspect `Location` to tell which. If
its HTTP library follows redirects by default — `curl -L`, `fetch` with its
default `redirect: "follow"`, most SDKs — it receives **`200` and an HTML
page in both cases** and cannot distinguish them at all. **For an endpoint whose
effect is scheduling the destruction of an account, "the client cannot tell
whether it happened" is the defect, not the status code.**

**Errors are plain text from an endpoint that demands JSON.** Every failure path
uses `Response::error(msg, status)` — `400`, `404`, `409`, `500` — which emits a
text body, not JSON.

**The body is never read.**

```
$ awk '/pub async fn request_self/,/^}/' crates/backend/src/routes/deletions.rs | grep -E "req\.(json|text|bytes|form_data)"
(no output)
```

The handler requires `Content-Type: application/json` and then never parses a
body. **This is not an oversight and must not be "fixed" by removing it:** the
requirement is the route's CSRF control — a cross-site HTML form cannot set that
header — and `route-contracts.md:107` already records the CSRF column for this
row as `N/A (JSON)`. The gate is load-bearing. What is missing is any statement
*at the call site* that this is why it is there.

## 3. The two halves, and why they are one RFC

The missing form and the unreadable contract look separable, and the reason to
keep them together is that **fixing either alone produces something worse than
today.** Add the form without fixing the contract and the browser follows the
`302` into `/login` on an expired session, silently, having not scheduled
anything — the user believes their account is being deleted. Fix the contract
without adding the form and the capability is still unreachable, now with a
tidier 401.

## 4. Direction

**The surface.** A `/me/security` section — heading, one sentence of
consequence, the grace period in days, a form. Given the CSRF control is the
JSON content type, a plain HTML form cannot post to this route; either the
section posts via a small inline script with a nonce (RFC 006, and see
**RFC 150**), or the route grows a second, form-encoded entry point with a real
CSRF token in the RFC 143 style. **The second is preferred** — RFC 143
established that this product's security surfaces work without JavaScript, and
account deletion should not be the exception. That makes the JSON route the
programmatic one and the form route the human one, each coherent.

**The contract**, if the JSON route is kept:

| Case | Today | Proposed |
|---|---|---|
| scheduled | `302` → `/me/security` | `200` + `{"scheduled_at": …}` |
| not authenticated | `302` → `/login?next=…` | `401` + JSON |
| already pending | `409` text | `409` + JSON |
| wrong content type | `400` text | `400` + JSON, body naming the CSRF reason |

**Cancellation.** A user shown the alert needs a way out, or the alert must say
plainly who can cancel it and how. Whether self-service cancellation is in scope
is the open question below; **the alert must not ship as it stands either way.**

**The gate.** RFC 145 §4.2 asks for a check that a declared route has a route in
`app.rs`. The defect here is the mirror image: a **route with no caller**. A
POST route that no template, script or test posts to is reachable only by hand.
Whether `scripts/route-contracts-check.sh` can assert that — and what the
legitimate exemptions are (a programmatic API is *meant* to have no in-repo
caller) — belongs in this RFC's cycle, because this route is the example.

## 5. The open question, answered (architect, 2026-10-27)

The question was whether a user should be able to cancel their own pending
deletion. Tested against the owner's standard rather than returned to them:

**The grace period already answers it.** `DEFAULT_GRACE_SECS` exists for one
reason — so that a request made in error, or in anger, can be withdrawn before
anything is destroyed. Today the only cancel route is tenant-admin only
(`route-contracts.md:109`), so the mechanism that exists to protect the user
can be operated only by someone else. For a **headless-first** product, where a
tenant may have no attentive admin and no support desk at all, that is a grace
period in name.

And the alert is the other half. A `role="alert"` reading *"Your account is
scheduled for deletion on <date>"* with nothing beside it is the exact shape
the owner's second clause forbids: the user cannot tell whether the state is
reversible, who can reverse it, or what to do next.

**Decision: yes — self-service cancellation, and the alert carries the
control.** This RFC gains:

- `POST /me/security/delete-account/cancel`, form-encoded, CSRF-tokened in the
  RFC 143 style, calling `deletion::cancel_deletion` — which **already exists**
  (`crates/core/src/deletion.rs:185`) and is already used by the admin route,
  so this is wiring, not new core logic. **Verify the callers, not just the
  body** — that is RFC 147 §2's lesson and it applies to every claim of the form
  "the machinery is already there", including this one.
- the alert rewritten to state the deadline, that it can be stopped, and the
  button that stops it;
- a `deletion_cancelled` audit event with `cancelled_by` = the user themself,
  which distinguishes a self-cancellation from an admin's in the same way
  RFC 147 cycle 2 made `executed_by` distinguish the sweep from an admin.

**What this does not become.** Self-service cancellation is not an undo for an
*executed* deletion. Nothing in cesauth makes execution reversible and this RFC
must not imply otherwise — the alert says what can still be stopped and by when,
and says nothing that reads as a promise after that moment.

## 6. Sequencing: after RFC 150

This RFC adds a rendered HTML surface with a CSRF-tokened form. **RFC 150
establishes that seven HTML responders outside the admin console serve documents
whose CSP nonce came from a previous request**, and the `/me` surface renders
through `templates/chrome.rs`, one of the five nonce-bearing templates. Building
a new security-critical form on that path before it is fixed means the new
surface inherits a defect that is invisible by construction — header and
document agree, so nothing looks wrong.

RFC 150 is therefore scheduled first, as a patch, and this RFC follows. The
dependency is one-directional: RFC 150 does not need anything here.
