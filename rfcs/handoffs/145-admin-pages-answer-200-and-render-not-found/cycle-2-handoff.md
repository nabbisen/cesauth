# Developer Handoff — RFC 145 cycle 2, the tenant-admin dead pages

**Governing RFC.** `rfcs/accepted/145-admin-pages-answer-200-and-render-not-found.md`
— read **§11** (the triage), **§12** (what cycle 1 refuted), and **§13**, added
2026-10-27, which is a compiler-verified worklist for this cycle.

**Target release.** 0.86.1 — **and why that level: patch.** Every route in §4
gets pointed at a template that **already exists** in `crates/frontend/src/tenant_admin/`.
No screen is designed, no surface is added or removed. This is cycle 1's shape
repeated on a second surface. **If the triage finds a route with no suitable
template, that route is reported, not invented** — see §6.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-10-27.**

**New since cycle 1 — read this.** RFC 151 was accepted today and amends
RFC 000 with **§22, the evidence term**. RFC 145 is the first RFC to close
under it, and it is **P1**, so it **may not enter `done/` on `reviewed`
alone**. Practically: this cycle must leave behind something that *fails* when
these routes regress. §9 says what that is.

---

## 1. Purpose

Thirty-three admin `GET` routes are documented as client-rendered, serve the
Leptos shell, and have **no matching route in `app.rs`**, so the router's
`<NotFound/>` fallback renders — **HTTP 200 with a Not Found page**, after an
admin auth check passes.

This cycle takes the **twelve** on the `/admin/t/:slug/…` tenant-admin surface.
Cycle 3 takes the twenty on `/admin/tenancy/…` plus the §4.2 gate.

## 2. Why this matters

A tenant administrator who reaches any of these twelve is told the page does
not exist, by a server that just authenticated them and authorised the read.
The status line says 200. Nothing in any log says otherwise.

## 3. Facts already measured — do not re-derive

**Thirty-three routes are dead at `f60aa2b`.** Measured by matching every
`client`-declared `GET` row in `route-contracts.md` against `path!()` in
`crates/frontend/src/app.rs`, with `:param` segments matching any one segment:

```
client-declared GET rows: 57   live: 24   DEAD: 33
dead by surface: {'admin/tenancy': 20, 'admin/t': 12, 'admin/console': 1}
```

The one `admin/console` row is `/admin/console/clients`, **excluded from
RFC 145 by §11.3** — RFC 141 cycle 2 owns it. So RFC 145's remaining list is
**32**: this cycle's 12, and cycle 3's 20.

**This does not reconcile with §12, and §12 is the one that is wrong.**
§12 predicted **10** tenant-admin routes for this cycle; the measurement at
HEAD finds **12**. The figure was hand-counted on 2026-10-25 and the
measurement is mechanical, so the measurement governs. **Reconciling the two —
naming which two routes §12 missed, or what added them — is deliverable (0)
below**, because three times in the last two cycles a count of mine was wrong
and you found it by running the assertion rather than trusting the prose.

**The compiler has been reporting this defect all along** (RFC 145 §13). In
each affected module the handler imports the server template and the renderer
and uses neither, because it returns the shell instead:

```
$ cargo build -p cesauth-backend --tests 2>&1 | tail -3
warning: `cesauth-backend` (lib test) generated 191 warnings
```

19 × `unused variable: req`, 19 × `ctx`, 16 × `ctx_ta`, 15 × `unused import:
…console::render`, 15 × `…admin::auth`. **Most of these should disappear as a
consequence of this cycle's fix**, and that is a second, independent check on
whether the work is complete — see §9.

**Do not run `cargo fix`.** It offers 178 suggestions and would *delete* those
imports, which destroys the evidence instead of acting on it. The imports must
become **used**. `-D warnings` stays off until cycles 2 and 3 land; that
decision is recorded in RFC 145 §13.2 and is not yours to revisit here.

## 4. Scope — the twelve routes, with the template each should reach

My mapping, from `crates/frontend/src/tenant_admin/` and its `forms/`
submodule. **It is a proposal, not a measurement** — verify each before using
it:

| Route (GET) | Template it should render |
|---|---|
| `/admin/t/:slug/organizations/:oid` | `organization_detail_page` |
| `/admin/t/:slug/organizations/:oid/status` | `forms::organization_set_status` |
| `/admin/t/:slug/organizations/:oid/groups/new` | `forms::group_create` |
| `/admin/t/:slug/organizations/:oid/memberships/new` | `forms::membership_add` |
| `/admin/t/:slug/organizations/:oid/memberships/:uid/delete` | `forms::membership_remove` |
| `/admin/t/:slug/groups/:gid/delete` | `forms::group_delete` |
| `/admin/t/:slug/groups/:gid/memberships/new` | `forms::membership_add` |
| `/admin/t/:slug/groups/:gid/memberships/:uid/delete` | `forms::membership_remove` |
| `/admin/t/:slug/memberships/:uid/delete` | `forms::membership_remove` |
| `/admin/t/:slug/users/:uid/role_assignments` | `role_assignments_page` |
| `/admin/t/:slug/users/:uid/role_assignments/new` | `forms::role_assignment_grant` |
| `/admin/t/:slug/role_assignments/:id/delete` | `forms::role_assignment_revoke` |

Each route is triaged into exactly one of RFC 145 §4's three outcomes —
**implement / delete / re-declare**. "Leave it" is not available; that is what
produced thirty-five.

## 5. Resolved decisions — do not re-open

- **Patch level**, for the reason in the header. If the triage forces a genuine
  screen build, **stop and report** rather than promoting the release yourself.
- **Your handler must not call `set_render_nonce`.** `render::html_response`
  owns it via RFC 146's `render_with_nonce`. (RFC 150, accepted today, covers
  the seven responders *outside* this helper; none of them is in this cycle.)
- **Rows become `server`-declared as you convert them**, so E3 begins guarding
  each one as it lands.
- **The §4.2 gate is cycle 3's**, and must land last, or it fails the tree
  while the triage is in progress.

## 6. Report-and-stop gates

Stop and write it up rather than deciding, if:

- a route has **no template that fits** — RFC 145 §11.3 set the precedent with
  `/admin/t/:slug/deletion-requests`: report what it needs, do not invent a
  screen;
- a route turns out to need **deletion** rather than wiring, and its `.json`
  companion has another consumer;
- the triage reveals a route whose handler does something **other** than return
  the shell — cycle 1 found exactly that, and it became RFC 147;
- my §4 mapping is wrong for any row. Say which and why.

## 7. Explicit non-scope

`/admin/tenancy/…` (cycle 3) · the §4.2 gate (cycle 3) ·
`/admin/console/clients` (RFC 141 cycle 2) · the seven nonce-less responders
(RFC 150, 0.86.2) · `-D warnings` (RFC 145 §13.2) · how the screens *look*
(RFC 131 R3).

## 8. Deliverable (0) — the count

Before any code: reproduce the 33/24/57 measurement, reconcile it against
§12's 10, and state in your report which two routes §12 missed and why. If my
33 is wrong, **say so and give the command** — that outcome is as useful as
agreement.

## 9. Required evidence — this is the part that is new

RFC 145 is **P1** and closes under RFC 000 §22, so `reviewed` is not
sufficient. Deliver **`exercised`**:

1. **A test per converted route** asserting the response is the real page, not
   the shell — the discriminator is a string only the server template emits,
   **not** the absence of `<NotFound/>`. Assert on presence, because an empty
   body also lacks `<NotFound/>`.
2. **A fires/does-not-fire demonstration for at least one route**: revert the
   handler to the shell locally, show the new test fails, restore it, show it
   passes. Paste both outputs. A test that has never been seen to fail is not
   evidence that it can.
3. **The warning count re-measured** after the cycle, with the command. State
   the before (191) and after. A count that barely moves means routes were
   re-declared rather than wired, which may be correct — but say which.
4. The full gate set, as usual. I re-run the release-critical and
   claim-bearing ones independently.

## 10. What must not be claimed

- Not "all tenant-admin pages now render" unless every one of the twelve is
  converted **and tested**; say twelve-of-twelve or say the number.
- Not "the warnings are fixed" — they are a side effect, and §13.2's gate is
  deliberately still off.
- No count in prose without the command that produced it.

## 11. Acceptance criteria

- Twelve routes triaged, each into one of §4's three outcomes, each with a test.
- `route-contracts.md` rows updated to match what the code now does.
- Host tests, migration_chain, clippy `-D clippy::correctness`, wasm32/csr,
  deny, audit, route-contracts, drift-scan `--verbose`, mdbook, build-frontend,
  build-backend, runtime-smoke, and the Playwright suite all green, with counts.
- Deliverable (0) answered.
- A one-line proposal for RFC 145's eventual `**Status**` evidence term, with
  the test or gate that justifies it.

## 12. Review request

Write the package to `.git-exclude/review-request/145-cycle2-report.md` and
give me the commit. I verify independently before anything is tagged.
