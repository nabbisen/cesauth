# Developer Handoff — 0.86.3, three claimed security controls, enforced

**Governing RFCs.** `rfcs/accepted/150-the-csp-nonce-is-per-isolate-not-per-request.md`
· `rfcs/accepted/152-the-admin-surfaces-documented-csrf-control-is-not-the-real-one.md`
(**half A only**) · `rfcs/accepted/155-two-p0-guarantees-rest-on-nothing-that-fails.md`

**Target release.** 0.86.3 — **patch.** All three make code or tests match a
claim the record already makes. No capability is added, no surface changes
shape. **Three RFCs in one release because they are one shape**, not a bundle:
*a security control the project documents, with nothing that fails if it stops
holding.*

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-10-28.**

**Order matters.** RFC 150 first (§1), because it changes how every HTML
responder reaches its nonce and the other two are independent of it.

---

## 1. RFC 150 — the CSP nonce is per-isolate, not per-request

Read **RFC 150 §4** and follow its three measurements **before changing
anything**. The RFC is explicit that this needs measuring, not asserting, and
§3's prediction about `/admin/login` is falsifiable — settle it with one
request.

**Then** apply RFC 146's `render_with_nonce` to the seven responders in §2's
table. **Do not give each site its own `set_render_nonce` call** — per-site
fixes are what produced the spread.

**Then** the gate: `Response::from_html` must not be reached except through the
nonce-setting helper, in E3's shape — a named, dated exemption list that must
shrink, and **a hard failure when the resolver cannot decide**. RFC 150 §4's
last paragraph is the warning: E3 itself silently passed on a wrapper-shaped
call for all 35 routes it was believed to cover (RFC 145 §11.2).

**Report-and-stop** if §3's cold-isolate prediction is wrong — that changes
what the fix is for, and I would rather hear it than have the fix applied to a
problem that is not there.

## 2. RFC 152 half A — document the real CSRF control, and pin it

**Half A only. Half B — the 33 `csrf::verify` calls and ~32 form tokens — is
not in this release and must not be started.**

1. **Rewrite the 33 CSRF cells** in `route-contracts.md` to name the control
   that actually defends those routes. The column currently says `required`,
   which in this codebase means a double-submit token check, and no handler on
   either surface performs one. The real control is the admin cookie's
   `SameSite=Strict`.
2. **A host test asserting the cookie string** built by
   `routes/admin/admin_login.rs:77`, including `SameSite=Strict`, `Secure`,
   `HttpOnly`, `Path=/` and the `__Host-` prefix. Assert on the constructed
   value, not on a live response — RFC 146 §2 established that
   `worker::Response` cannot be built on the host.
3. **A gate assertion** that the attribute cannot be dropped silently. The
   failure mode is a cookie attribute edited for an unrelated navigation
   reason, with nothing failing; the test in (2) is what makes it loud.

**The two rows that already verify stay as they are** —
`/admin/t/:slug/deletion-requests/:id/{cancel,execute}`, from RFC 147 cycle 2.
It is **33 of 35**, not 35; if you find a different number, say so with the
command.

**Do not remove the `Content-Type: application/json` requirement anywhere.** On
`/me/security/delete-account` it *is* the CSRF control (RFC 149 §2), and
RFC 149 is a later release.

## 3. RFC 155 — two P0 guarantees with no witness

**3a. `MagicLinkPayload`'s `Debug`.** Replace the `derive(Debug)` at
`core/src/magic_link/mailer.rs:81` with a hand-written impl printing
`recipient`, `handle`, `locale`, `reason`, `tenant_id`, and `code` as
`REDACTION_MARKER` (`core/src/types/secret.rs`, RFC 116). Add a test asserting
`format!("{payload:?}")` does **not** contain the code's value.

**Do not implement `Display`.** It does not exist today and should not start.

Note while doing it: for invitations `code` is a **full accept URL**
(`routes/invitations.rs:99`), so the test's fixture should use a URL-shaped
value as well as an OTP-shaped one. A test that only checks six digits are
absent would pass on a leaked link.

**3b. RFC 074's generic messages.** Add assertions that the failure messages
RFC 074's table requires stay conflated —
`magic_link/verify.rs:202` *"Incorrect or expired code…"* and `:171`/`:185`
*"expired or was already used"*. **Assert against the decision function, not
the rendered response**, so the test survives a rendering change and fails on a
behaviour change. RFC 143's `decide_verify_*` split is the precedent for where
that boundary belongs.

## 4. Resolved decisions — do not re-open

- **Patch level** for all three. If any turns out to add surface, stop and say
  so rather than promoting the release.
- **RFC 152 half B is out of scope.** So is RFC 154 (0.87.0) and RFC 153.
- **Do not run `cargo fix`** on the admin route modules — it would delete the
  unused imports that are the compiler's report of a P1 defect (RFC 145 §13.2).
  `-D warnings` stays off; I own that decision and it waits on a scoping pass.

## 5. Report-and-stop gates

- RFC 150 §3's prediction is wrong, or the cold-isolate case cannot be reached;
- any of the 33 CSRF rows turns out to verify after all, or the count differs;
- a measurement contradicts a figure in any of the three RFCs. **Three of my
  counts have been corrected by you across the last four cycles and each
  correction was worth more than the agreement would have been.**

## 6. Required evidence

**RFC 000 §22 applies to all three.** RFC 150 and RFC 155 are the remedies that
move RFC 030 and RFC 074 from `reviewed` to `exercised`, so each needs a
**named** test or gate and a demonstration that it **fails** when the control
is removed:

1. **Fires/does-not-fire for each new gate or assertion.** Remove the control,
   show the test fail, restore byte-identically, show it pass. Paste both.
   A test never seen to fail is not evidence it can.
2. **RFC 150's three measurements**, recorded with the commit they were taken
   at — they are `observed`, not `exercised`, and should be labelled so.
3. **The full gate set**, with counts. Take the host-test count with CI's exact
   command (`.github/workflows/test.yml:51-55`, five crates, **no `--lib`**)
   and **sum it programmatically**; the baseline is **1,589**.
4. **A proposed `**Status**` line** for RFC 030, RFC 074, RFC 150, RFC 152 and
   RFC 155, each naming the specific witness. RFC 152 stays `accepted` (half B
   remains), so say what term half A earns on its own.

**One count correction to carry:** a release commit runs **12** CI workflows,
not 13. `fuzz.yml` triggers only on PRs touching the JWT parser, so it never
runs on a push to `main`. I wrote "thirteen" in several records before checking.

## 7. Acceptance criteria

- RFC 150's seven responders reach HTML through the nonce helper; the new gate
  lands **last**, with its exemption list named and dated.
- 33 CSRF cells name the real control; the cookie string is asserted; the gate
  fails if `SameSite` changes.
- `MagicLinkPayload`'s `Debug` redacts `code`, asserted with both an OTP-shaped
  and a URL-shaped fixture.
- RFC 074's conflated messages asserted at the decision boundary.
- Fires/does-not-fire evidence for every new witness.
- All 12 gates green, with counts.

## 8. Review request

Write the package to `.git-exclude/review-request/0.86.3-report.md` and give me
the commit. I verify independently before anything is tagged.
