# RFC 132 — View rendering policy

**Status.** Proposed
**Tier.** P1 · Category A — a policy RFC. It establishes the rule; conformance
work is scoped by it.
**Size.** Small to write, Medium to enforce, and it re-scopes part of RFC 131.
**Tracks.** Owner observation, 2026-09-05: the prior question ("CSR or
SSR+hydrate?") was posed at the wrong level. Supersedes RFC 131's R0 as
originally framed.
**Touches.** `docs/src/expert/route-contracts.md` (new column),
`scripts/route-contracts-check.sh`, External Design v2 §4, and RFC 131's R0/R3/R4.
**Depends on.** Nothing. **Blocks.** RFC 131 R3.
**Target release.** 0.81.4, alongside RFC 131 R2 + R5.

## 1. Summary

cesauth has no working rendering policy. It has a *stated* one that the code
abandoned without amendment, and the resulting behaviour is internally
contradictory on the most important flow in an identity provider. This RFC
replaces "pick a global mode" with a rule that derives rendering mode from
per-surface properties, and makes that rule machine-checkable so it cannot
drift the way its predecessor did.

## 2. The policy that already exists, and is false

**External Design v2 §4** (line 273), the governing external design document:

> The screens use server-side rendering only (no client framework).

RFC 115 migrated screens to Leptos CSR. **The document was never amended.** The
policy was not weighed against a successor and replaced — it was silently
abandoned, one screen at a time, and no replacement was written.

Two further statements in the governing specs constrain rendering and were not
consulted either:

- **Requirements §15**, forbidden patterns: *"Returning JSON from a
  browser-form route on error (must be HTML)."* This presumes a server-rendered
  error page. Under CSR-everywhere it is unsatisfiable for those routes.
- **Requirements, ABDD** — every UI surface operable by keyboard and screen
  reader *by default*, not by later patching.

## 3. What the absence produced

The pre-authentication flow, measured on this tree:

| Route | Renders | Usable without JS |
|---|---|---|
| `/`, `/login` — the entry point | `leptos_html_shell` (`routes/ui.rs:29`) | **no** |
| `/magic-link/request`, `/verify` | `magic_link_sent_page_for`, `error_page_for` | yes |
| `/me/security/totp/verify` | `totp_verify_page_for` | yes |
| `/me/security/totp/enroll` | `totp_enroll_page_for`, recovery codes | yes |
| `/me/security`, sessions, TOTP disable | `leptos_html_shell` | no |

**A user without JavaScript cannot reach the login page — but the magic-link
step after it would render fine.** The flow is inconsistent with itself. This
is not a design; it is the residue of incremental migration with no rule
governing it.

It also means the 750 KB wasm bundle is a hard prerequisite for authenticating
at all, on the one surface a user cannot route around.

## 4. Non-goals

- Choosing a single global rendering mode. That framing produced §3.
- Deciding whether SSR+hydrate is technically possible on Workers. §7 says when
  that question becomes worth asking, and it may never.
- Rewriting screens. This RFC classifies and enforces; RFC 131 R3 does the work.
- Changing any route, wire format, schema, or the `.json` contract.
- Retrofitting the four 0.82.0 feature screen groups. They inherit the policy
  when their RFCs are written.

## 5. The rule

Rendering mode is **derived, not chosen**. For each browser-facing surface, ask
in order:

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
WebAuthn ceremonies, live filtering, progressive disclosure of large tables. If
yes *and* Q1/Q2 permit, client rendering is appropriate.

**Q4 — Is it machine-facing?**
JSON endpoints render nothing and are out of scope.

Anything not selected by Q1–Q3 defaults to **server-rendered**, because that is
the mode with fewer failure modes and it is what ABDD implies.

### 5.1 Classification

| Surface | Q-path | Mode |
|---|---|---|
| `/`, `/login`, `/magic-link/*`, `/accept-invite`, TOTP verify + recovery, terminal errors | Q1 no / Q2 yes | **Server HTML.** Non-negotiable |
| `/webauthn/*` ceremonies | Q3 yes, but pre-auth | Server HTML page + scripted ceremony; the page must render and offer the Magic Link fallback without JS |
| `/me/security*` (authenticated self-service) | Q1 yes — a session exists, support paths exist | Client, permitted |
| `/admin/t/*`, `/admin/tenancy/*`, `/admin/console/*` | Q1 yes, Q3 yes | Client, permitted |
| `*.json`, OIDC, `/api/v1/*` | Q4 | N/A |

**The existing split becomes principled**, and one live defect falls out of it
immediately: `/` and `/login` are on the wrong side of the line.

## 6. Enforcement — the part that stops this recurring

A policy nobody checks is what §2 documents. `route-contracts.md` already
carries a row per route, gated by `scripts/route-contracts-check.sh`, so the
policy attaches there rather than living in prose:

**E1 — Add a `Rendering` column** to `route-contracts.md`: `server` | `client`
| `n/a`. Every one of the 188 rows declares one.

**E2 — Extend the check** so a missing value fails, exactly as an undocumented
route already does.

**E3 — Assert the declaration against reality.** For every route declared
`server`, its handler must not call `leptos_html_shell`. That is greppable
per-handler and it is the invariant that actually matters: it makes it
impossible to quietly move an authentication surface behind a JavaScript
requirement, which is precisely what happened to `/login`.

E3 is narrow on purpose. A general "does this handler render what it claims"
check would be fragile; this one covers the failure mode that has already
occurred once.

## 7. What this does to RFC 131

**R0 is superseded.** It asked which global mode to adopt. The answer is that
there isn't one — §5.1 assigns mode per surface, and RFC 131 R3 inherits the
assignment rather than a preference.

**R4 is amended.** "Collapse to one rendering path" becomes *"collapse to one
path per surface class, per §5.1, and delete every duplicate."* The goal was
always to remove *accidental* duplication; a deliberate, documented split by
trust boundary is not the thing §3 condemns.

**The SSR+hydrate spike is not needed for RFC 131 to proceed**, and may never
be. It becomes worth running only if a surface classified `server` also needs
Q3 interactivity — where SSR+hydrate would be the way to have both. No surface
in §5.1 currently does. If one arises, the spike gets scoped then, with a time
bound and a "renders correct HTML under `wrangler dev`" bar.

## 8. Conformance gap

One, and it is the significant one: **`/` and `/login` render client-side and
must not.** Fixing it is RFC 131 R3 work under the new classification, not this
RFC.

The other server-rendered pre-auth routes already conform, which is why R4 must
not delete their templates — RFC 131 already carries that constraint.

## 9. Testing strategy

1. Every route in `route-contracts.md` has a `Rendering` value; the check fails
   if any is missing (E1/E2).
2. No handler for a `server` route calls `leptos_html_shell` (E3).
3. **E2 and E3 each demonstrated to fire** — remove a value, observe red;
   restore. Point a `server` route at the shell, observe red; restore. Sixth
   time this project has required a fires/does-not-fire pair.
4. Full gate set green.

## 10. Migration

Documentation and one script. No code, no routes, no contracts.

**External Design v2 §4 must be amended** in the same change — leaving a
governing document asserting something false is how this started. The amendment
records both the new rule and that the old statement was abandoned rather than
superseded.

## 11. Risks

| Risk | Mitigation |
|---|---|
| The policy is written for cases that don't exist | §5.1 classifies the *actual* inventory — 188 routes — not hypotheticals |
| E3 gives false confidence — it checks one direction only | Stated plainly: it catches a `server` route moving to the shell, not a `client` route mis-declared. That is the failure that has occurred |
| Classification is contested later | Q1–Q4 are recorded, so a reclassification argues against the question, not against a table entry |
| A `server` surface later needs Q3 interactivity | That is exactly when the SSR spike becomes worth running (§7) |

## 12. Acceptance criteria

1. §5's questions and §5.1's classification recorded in `docs/src/expert/`.
2. `Rendering` column present on all 188 rows.
3. E2 and E3 implemented, blocking, each with a captured fires/does-not-fire pair.
4. External Design v2 §4 amended.
5. RFC 131's R0 marked superseded and R4 amended to reference §5.1.
6. Full gate set green.

## 13. Open questions

1. **`/webauthn/*` classification.** §5.1 says the page renders server-side and
   the ceremony is scripted, with Magic Link reachable without JS. That
   preserves passkey-first while keeping a no-JS path to authenticate. Worth
   confirming this is the intended product behaviour and not just the
   technically convenient reading.
2. **Does the operator console warrant an exception?** It is JA-only by
   ADR-013 and used by a known internal population, so a JS requirement is
   defensible there in a way it is not for end users. Currently classified
   `client` on that basis; flagging it as an assumption rather than a finding.
