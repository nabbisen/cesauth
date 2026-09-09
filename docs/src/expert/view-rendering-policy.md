# View rendering policy

**Status.** Established by [RFC 132](../../../rfcs/accepted/132-view-rendering-policy.md)
(2026-09-05, amended 2026-09-09). Supersedes [RFC 131](../../../rfcs/accepted/131-mockup-adoption-strategy.md)'s
R0 as originally framed.
**Enforced by.** [`route-contracts.md`](./route-contracts.md)'s `Rendering`
column, checked by `scripts/route-contracts-check.sh` (E2, E3).

## Why this exists

cesauth had a stated rendering policy — External Design v2 §4: "The screens
use server-side rendering only (no client framework)" — that RFC 115's
migration to Leptos CSR silently abandoned. Nobody decided to move any
particular screen behind a JavaScript requirement; it accumulated one screen
at a time, with no rule governing it and no amendment to the document that
said otherwise.

The concrete harm: `/` and `/login` render the Leptos CSR shell
(`crates/backend/src/routes/ui.rs`), while `/magic-link/request` and
`/magic-link/verify` next door render real server HTML and work without
JavaScript. A user without JavaScript cannot reach the login page at all,
though the very next step in the same flow would render fine for them. That
inconsistency — not a chosen tradeoff — is what this policy exists to make
impossible to reintroduce silently.

## The rule

Rendering mode is **derived per surface, not chosen globally**. A single
project-wide "CSR or SSR" decision is the wrong question — it is what
produced the inconsistency above. For each browser-facing surface, ask in
order:

**Q1 — Can the user route around a failure of this surface?**
If no — the surface is on the only path to authenticating, or to recovering
access — it **must render server-side HTML** and be fully usable without
JavaScript. Enhancement may be layered on top; function may not depend on it.

**Q2 — Is it pre-authentication?**
Everything before a session exists inherits Q1's answer regardless of how
interactive it looks. A login page that cannot render is not a degraded
experience, it is an outage.

**Q3 — Does it require client-side interactivity that server HTML cannot
express?**
WebAuthn ceremonies, live filtering, progressive disclosure of large tables.
If yes *and* Q1/Q2 permit, client rendering is appropriate.

**Q4 — Is it machine-facing?**
JSON endpoints render nothing and are out of scope.

Anything not selected by Q1–Q3 defaults to **server-rendered**, because that
is the mode with fewer failure modes.

## Classification

| Surface | Q-path | Mode |
|---|---|---|
| `/`, `/login`, `/magic-link/*`, `/accept-invite`, TOTP verify + recovery, terminal errors | Q1 no / Q2 yes | **Server HTML.** Non-negotiable |
| `/webauthn/*` ceremonies | Q4 | **N/A — these render nothing.** All four are `POST` JSON. *Corrected 2026-09-09: an earlier draft of this table classified a "Server HTML page + scripted ceremony." No such page exists — WebAuthn's affordance is a property of `/login` and `/me/security`, both classified above.* |
| `/me/security*` (authenticated self-service) | Q1 yes — a session exists, support paths exist | Client, permitted |
| `/admin/t/*`, `/admin/tenancy/*`, `/admin/console/*` | Q1 yes, Q3 yes | Client, permitted |
| `*.json`, OIDC endpoints, `/api/v1/*` | Q4 | N/A |

This assigns mode by **surface class**, not route by route. Every route's
concrete value is recorded in
[`route-contracts.md`](./route-contracts.md)'s `Rendering` column.

## Enforcement

A policy nobody checks is what produced the situation this document exists
to correct. Enforcement lives in `route-contracts.md` and
`scripts/route-contracts-check.sh`, not in this prose:

- **Every route declares a mode.** `route-contracts.md`'s `Rendering` column
  (`server` | `client` | `n/a`) is required on every row; a missing value
  fails the check the same way an undocumented route does.
- **A `server` route's handler must not call the Leptos shell.** For every
  route declared `server`, its handler must not call
  `leptos_html_shell`. This is the invariant that actually matters: it makes
  it impossible to quietly move an authentication surface behind a
  JavaScript requirement, which is precisely what happened to `/login`.

The check is narrow on purpose — it verifies one direction (a `server`
route does not silently become client-rendered), not that every `client`
route is genuinely appropriate for client rendering. A general "does this
handler render what it claims" check would be fragile; this one covers the
failure mode that has already occurred.

**The `Rendering` column means two different things depending on its
value, and that asymmetry is deliberate — but it must be read correctly.**
For a `server` row, the value is an *enforced obligation*: E3 checks it, and
a violation fails the build. For a `client` row, the value is a
*permission*, not a description: nothing checks it, and at least one
`client`-classified route does not currently match it —
`POST /admin/console/config/log_level/preview` renders real server HTML
today (`ui::admin::frame::admin_frame`, no Leptos shell involved), which is
still policy-compliant (`/admin/console/*` permits either mode), just not
what the column's plain-English reading would suggest. Do not read a
`client` value as "this route is client-rendered" — read it as "this route
is *permitted* to be client-rendered, and may or may not currently be."
Auditing which `client` rows describe current behavior has no gate
consequence and was judged disproportionate to do wholesale (RFC 132
C1-132 review, 2026-09-09); fix it opportunistically if you're already in a
file, not as a dedicated sweep.

## Known conformance gaps

Declaring a route `server` under this policy is a statement of what it
**must** do, not a claim that it already does. Where a route's current
implementation does not yet conform, that is recorded as a named,
dated exemption in `scripts/route-contracts-check.sh`, each one naming the
work that removes it — not silently reclassified to `client` to make the
check pass, which would record the defect as the policy instead of fixing
it.

See `scripts/route-contracts-check.sh`'s exemption list for the current,
authoritative set — it changes as conformance work lands, and duplicating
the list here would create the exact two-document drift this policy exists
to avoid.

## What this does not decide

- **Whether SSR+hydrate is technically possible on Cloudflare Workers.**
  Not needed for any surface currently classified here; becomes worth
  investigating only if a `server`-classified surface later needs Q3
  interactivity, where SSR+hydrate would be the way to have both.
- **The shape of a `<noscript>` fallback for `client` surfaces.** A `client`
  classification must not permit a blank page — every such surface owes a
  `<noscript>` block naming the requirement and the fallback — but that is
  an implementation obligation for the surfaces that adopt it, not part of
  this policy document.
- **Rewriting any screen.** This document classifies and the script
  enforces; bringing a non-conforming route into conformance is separate,
  scoped work.
