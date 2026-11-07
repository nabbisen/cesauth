# RFC 179 — R2a imported the components and left the stylesheet behind

**Status.** **Accepted 2026-11-07** — the owner's reply was *"RFC 179 and 180
are accepted."* **Dispatched the same day as a patch**, §4 and §5/§6 in one
cycle because §4 alone makes the gate vacuous (§5). Proposed 2026-11-07 by the
architect, after the owner asked
whether RFC 131 R3's queue position still holds. It does not hold, but not for
the reason anyone recorded: the missing CSS is **not R3's unstarted design
work**. It is the half of **R2a** that was never imported, and the file it
should have come from still exists at the exact pin R2a used.
**Tier.** **P2.** Six elements authored to be invisible render visible, one of
them an operator's CSRF token labelled `"csrf: "`. Nothing is exploitable
(§2.3) and no API behaviour is wrong; this is a user-facing correctness and
confusion defect, which is what the owner's standing philosophy puts first.
**Size.** **Small**, and that is now a measured claim rather than an estimate
— §4 names the nine lines, the file they come from, and the four facts that
make the serving path a no-op. The **gate** in §5 is the larger half.
**Touches.** `crates/frontend/static/` (one new file),
`crates/backend/src/routes/leptos_shell.rs` (one `<link>` line),
`e2e/specs/stylesheet-presence.spec.ts` (assertion redesigned),
`.github/workflows/trunk-release-build.yml`, `scripts/` (the census gate).
**Depends on.** Nothing. Explicitly **not** RFC 131 R2b or R3 — §3.
**Supersedes.** The framing in `rfcs/done/135-wasm-under-csp.md` §4
(*"presentation wiring is RFC 131 R3's"*) and its two repetitions in RFC 178.
**Target release.** **Patch** for §4. §5's gate is a patch if it ships with
§6's exemption; see §6 for why it cannot ship bare.

---

## 1. Summary

RFC 178 found that the end-user app loads zero author CSS and concluded the gap
belonged to RFC 131 R3, an unbuilt slice of an accepted programme. **That
conclusion was wrong, and checking it took four greps.** R2a — which shipped in
**0.82.0** — imported 17 primitives, `view_models` and `icons` from the mockup
at pin `df3d9d0`, about 1,489 LOC. It did not import the four stylesheets
sitting beside them. Its changelog entry names exactly one thing as
outstanding: *"a future RFC wires them to real data."* The **data** half. The
presentation half is not mentioned anywhere, and so for fourteen releases the
project has described a missing file copy as unstarted design work.

The immediate fix is **nine lines that already exist**, at the same commit R2a
took the components from.

## 2. The finding, measured

### 2.1 Six elements authored invisible, rendering visible

`grep -rn "sr-only" crates/frontend/src/` — six sites, five files, and
**`grep -rn "\.sr-only" .` over the whole repository returns nothing**:

| # | site | what renders |
|---|---|---|
| 1 | `pages/operator/tenancy.rs:175` | `<p class="sr-only">"csrf: "{d.csrf_token}</p>` — **the operator's CSRF token, labelled** |
| 2 | `pages/operator/clients.rs:281` | `<p class="sr-only">{id2}</p>` — a raw OIDC client id |
| 3 | `pages/operator/clients.rs:350` | a `<th>` reading `"操作"` that should be an empty column head |
| 4 | `pages/sessions.rs:96` | same, `"Actions"` |
| 5 | `pages/tenant_admin/invitations.rs:83` | same, `"Actions"` |
| 6 | `pages/login.rs:114` | `<h2 class="sr-only">"Passkey sign-in"</h2>` — a visible heading on the sign-in page |

### 2.2 The reachability chain, verified end to end

Site 1 is the one worth tracing, because "the view has no caller" was the
likeliest reason it would not matter — RFC 161 found 9 of 12 admin views
callerless. It has one:

```
GET /admin/tenancy/tenants/:tid            lib.rs:327
  -> tenant_detail::page
  -> operator_json_api::shell
  -> leptos_shell::leptos_html_shell        serves the CSR shell
  -> SPA mounts, app.rs:91 routes :tid
  -> TenancyTenantDetail                    tenancy.rs:121
  -> tenancy.rs:175                         <p class="sr-only">"csrf: "{token}
```

### 2.3 What this is and is not — exploitability checked, not assumed

A CSRF token is **not a credential**. Without the operator's session cookie it
authorises nothing, so this is **not** a privilege path and should not be
written up as one. What it is: a token leaked to anything that captures the
screen — a screenshot in a ticket, a shared screen, a recording — which costs
one layer of defence in depth, and a string of visible gibberish on the
highest-privilege surface in the product. The other five are pure confusion:
three stray table headers, a raw client id, and a heading that was meant for
screen readers alone.

### 2.4 There is no CSS in this repository at all

`find . -name "*.css"` outside `target/`, `docs/book` and `node_modules`
returns **zero files**. Every rule the product has is the **209-line
`BASE_CSS` string constant** at `templates/chrome.rs:9-217`, which the
server-rendered templates interpolate and which the CSR app never loads.

## 3. Why this is not R3, and not R2b either

**R2a landed.** `crates/frontend/src/view_models`, `icons` and
`components/primitives` (17 files) are in the tree and have been since 0.82.0.

**R3 is "pair screens with data, one at a time"** (RFC 131 §5). It owns wiring
views to fetch logic and deleting the duplicate `format!` template per screen.
Nothing in R3's text owns *copying a stylesheet*, and nothing in it has to
happen before one is copied.

**R2b is not a blocker.** Its RFC 131 paragraph said it could not be settled
without RFC 132 §13 q1 — but **q1 was answered 2026-09-24** and RFC 132 states
*"R3 is no longer blocked."* RFC 131 was never updated; corrected 2026-11-07,
and scoped in **RFC 180**. Either way R2b is the **locale** mechanism, not CSS.

**And the serving path is already built.** Four facts, each checked:

| | |
|---|---|
| Static assets | `Makefile:204` copies `crates/frontend/static/*` → `crates/frontend/dist/assets/`, which Workers Static Assets serves at `/assets/`. `webauthn.js` reaches the browser this way today. |
| Production `<head>` | A `format!` in `leptos_shell.rs:113+`. One `<link rel="stylesheet">` line. |
| CSP | Already `style-src 'self'` with **no** `'unsafe-inline'` (`core/src/security_headers.rs:158`). A same-origin stylesheet is **already permitted**. No header change. |
| Trunk | Not involved. A `.css` in `static/` is copied, not compiled. |

## 4. Direction — import, do not author

**Do not write a stylesheet.** `crates/ui/assets/base.css` in the mockup
repository, at pin **`df3d9d0`** — the same commit R2a imported from — already
contains the rule, at lines 86-94, in its standard form:

```css
.sr-only {
  position: absolute !important;
  width: 1px; height: 1px;
  padding: 0; margin: -1px;
  overflow: hidden;
  clip: rect(0,0,0,0);
  white-space: nowrap;
  border: 0;
}
```

**Importing rather than authoring is the point**, not a convenience: a
hand-written rule would be a second presentation source for the project to
reconcile later, which is the condition RFC 131 §8 exists to prevent. Taking it
from the pin R2a used makes this a completed import, not a new decision.

**Scope: this rule, and nothing else.** No typography, no colour, no layout, no
tokens. Those are §7's non-goals and belong to the cycle §8 names.

## 5. The gate as it stands would pass vacuously, and that is worse than today

RFC 178 §4's spec asserts `ruleCount > 0`. **A stylesheet containing only
`.sr-only` satisfies it.** So landing §4 alone would:

1. make `KNOWN_NO_STYLESHEET`'s entries stale, so they must be deleted;
2. flip the gate from loudly exempt to **quietly passing**;
3. leave **84 distinct class names** across `pages/` and `components/` with no
   rule, and nothing reporting it.

That trades a gate that prints its own gap on every run for a green check that
proves one rule exists. **It must not ship that way.** The assertion has to
become a **census with a visible numerator** — the house pattern from RFC 159
§4.5 and the colour-contrast gate: every scanned item checked or named with a
reason, `unclassified` **0**.

Measured denominator — **and §10.1 corrects this figure once already**:

| source | sites | distinct names |
|---|---|---|
| literal `class="…"` in `pages/` | 48 | 29 |
| literal `class="…"` in `components/` | 59 | 56 |
| literal, union | 107 | **84** |
| **+ names only reachable by resolving §6's computed sites** | 9 | **+12** |
| **true denominator** | | **96** |

(`view_models` and `icons` carry none.) After §4 the census reads **1 of 96
styled**, and it prints that every run.

## 6. What the census cannot hold, and why it must ship exempted

**Nine `class=` sites compute their value in Rust and a literal grep misses all
nine** — found by grepping for `class=` *without* a quote, which is the check
the first pass would have skipped:

| shape | sites | enumerable? |
|---|---|---|
| `match` over `&'static str` — e.g. `alert.rs:17` `fn class()`, 4 arms | some | **yes**, resolve the arms |
| inline `if cond { "a" } else { "b" }` — `entity_list.rs:70`, `scope_breadcrumb.rs:36`, `density_toggle.rs:17` | 3 | **yes**, both branches are literals |
| `format!` over a caller-supplied prop — `badge.rs:13` `format!("badge {}", class)`, `metric_strip.rs:40` | 2 | **no.** The suffix comes from callers; `badge.rs`'s doc comment lists an intended set, but a doc comment is not a constraint |

So a complete markup→selector census **is not achievable by static analysis**,
and a gate claiming otherwise would be the "more precise matcher mistaken for a
more correct one" failure. The honest shape:

- literal and resolvable-computed sites → **checked**;
- the `format!`-with-prop sites → **declared out by name, dated, with a
  reason**, the `E6_BEARER_LEGACY_EXEMPT` / `KNOWN_NO_STYLESHEET` shape;
- the still-unstyled names → **exempted**, dated, citing this RFC, reporting
  every run, **failing as stale** the moment one gains a rule it is not declared
  for;
- `unclassified` must be **0**.

### 6.1 Refinement, 2026-11-07, while writing the handoff: declare the *styled* set, not the exempt one

§6 as accepted said the unstyled names are "exempted **by name**". Writing it out
showed that is the wrong polarity: **83 hand-maintained entries that must all be
deleted one at a time** is a list nobody will keep honest, and it inverts on
every import. Declare the **complement** instead:

- a dated declaration names the selectors the stylesheet is **expected to
  cover** — after §4 that is `sr-only`, one entry;
- *not-yet-styled* is **computed** as the remainder, never written down;
- **one** dated exemption block covers the remainder with its reason (§8's
  import), so the gap still reports every run with a live numerator;
- staleness keeps the same teeth, pointing the other way: **a class that has a
  matching rule but is not in the declared set fails**, naming itself, so a
  stylesheet cannot grow silently past what has been reviewed.

Same guarantees, one line of maintenance per import instead of 83 deletions.
**Recorded here rather than only in the handoff** because it changes what §9.4's
arithmetic means.

**It cannot ship bare.** Landing a census that fails on 83 unstyled names would
redden every cut, which is the mistake E7 made in 0.92.5 and RFC 178 §4 made
again three days later. Twice is a pattern; this RFC states the exemption as a
deliverable rather than discovering the need after a red `main`.

## 7. Non-goals

- **No visual design.** Not colour, typography, spacing or layout.
- **No token work.** RFC 176 §6.2/§6.3 (rem typography tokens, the 44 px
  control-height floor) stay where they are. Pulling them in here would make
  this a minor and couple it to §8's unresolved question.
- **No consolidation of `chrome.rs`'s `BASE_CSS`.** §8.
- **No new route, no wire-format, no schema, no permission change.**

## 8. The question this RFC deliberately does not answer

`crates/ui/assets/` holds four stylesheets at `df3d9d0` — `base.css` 2,221 B
(16 rule blocks), `tokens.css` 5,176 B (5), `components.css` 31,802 B (230),
`screens.css` 11,268 B (75); **50,467 B in all**. Importing them is the real
fix for the other 83 names, and it is **bounded and sizable** — a file copy at
a known pin, not a design exercise, which is the opposite of what RFC 178 §3
assumed when it called the size "unknown".

**But it cannot be a straight copy, and the reason is already on the record as
a defect we paid for.** RFC 131 R4 keeps the pre-authentication `format!`
templates deliberately, so two presentation paths are the intended end state.
That is precisely how RFC 176 bit this project three days ago: `chrome.rs`
carried **its own copy** of the four semantic colour tokens, so §6.1 fixed the
operator console while `/`, `/login` and `/me/security` kept values failing
WCAG AA, and §6.1b had to correct the same four values a second time. **A third
copy of the tokens reproduces that defect on schedule.**

So the import's hard requirement is **one source of truth for tokens, consumed
by both paths** — which also gives RFC 176 §6.2/§6.3 somewhere to live instead
of colliding later. That design is a separate RFC, sequenced after this one,
and it is the one of the three that governs the other two.

## 8.1 Found while writing the handoff: the server-rendered half is mostly unstyled too, and nobody has measured it

RFC 178 said the **end-user app** ships no stylesheet. True, and incomplete.
The **server-rendered** surfaces do have one — `BASE_CSS` — and it covers a
minority of what they use:

| | measured |
|---|---|
| distinct class names used by `admin/`, `tenancy_console/`, `tenant_admin/`, `templates/` | **75** |
| class selectors `BASE_CSS` actually defines | **22** |
| of the 75, **styled** | **17** |
| of the 75, **no rule anywhere** | **58** |

So `btn-primary`, `card`, `data-table`, `badge-ok`, `alert-info` and 53 more
render unstyled on the operator console today. **This is not RFC 179's scope and
must not be pulled into it** — it is a third surface with its own measurement,
its own naming convention and its own stylesheet, and it is dispatched as its
own ROADMAP row. It is recorded here because §8's token-ownership question
cannot be answered without it: the consolidation is **three** stylesheets, not
two.

## 8.2 The root cause of §2.1, stated properly: two names for one behaviour

`BASE_CSS` defines **`.visually-hidden`** at `templates/chrome.rs:184-192` —
the **same clip-rect rule** this RFC imports under a different name — and the
server-rendered templates use it and it works (`templates/totp.rs`,
`admin/audit.rs`). The CSR pages use **`sr-only`**, the mockup's name, whose
stylesheet was never imported.

So §2.1's six visible elements are not "a missing rule". They are **a surface
that adopted the mockup's vocabulary without the mockup's stylesheet, beside a
surface that kept its own vocabulary and its own working rule.** §4's import is
still the right immediate fix — it closes the defect without renaming markup on
five pages — but it leaves the project with **two names for one behaviour, in
two stylesheets**, which is precisely the duplication that made RFC 176 §6.1b
necessary. **Converging on one name is a §8 deliverable, named here so it cannot
be rediscovered**, and until it happens neither rule may be changed without the
other.

## 9. Acceptance criteria

1. `/assets/`-served stylesheet exists, carrying `.sr-only` **byte-identical**
   to `crates/ui/assets/base.css:86-94` at `df3d9d0`, with the pin recorded.
2. All six §2.1 elements are absent from the accessibility-visible rendering,
   **verified in a browser**, not inferred from the rule's presence.
3. `KNOWN_NO_STYLESHEET` is **deleted**, and the spec's assertion is §5's
   census.
4. The census prints `96 = 1 declared-and-matching + 95 not-yet-styled
   (one dated exemption, §6.1) + 0 unclassified`
   (or its then-current arithmetic, recomputed from source, **no committed data
   file**), and reconciles.
5. Forcing a listed name to gain a rule **fails as stale**, named directly —
   evidence required in both directions, as RFC 178 §4b's did.
6. `.github/workflows/trunk-release-build.yml`'s `exit 1` is **restored**: with
   a stylesheet present the `MISSING` branch is a real failure again.
7. Host tests, `migration_chain`, `route-contracts-check.sh`, `drift-scan.sh`
   and `mdbook` unchanged. Bundle deltas recorded with sha256 **and the gzip
   level**.

## 10. Baselines, each with its command

| | value | command |
|---|---|---|
| `sr-only` sites | 6, 5 files | `grep -rn "sr-only" crates/frontend/src/` |
| `.sr-only` rules in repo | **0** | `grep -rn "\.sr-only" .` (excl. `target/`) |
| `.css` files in repo | **0** | `find . -name "*.css"` (excl. `target/`, `docs/book`, `node_modules`, `dist/`) |
| distinct class names, literal only | **84** | `grep -rho 'class="[^"]*"' pages components \| sed/tr/sort -u` |
| distinct class names, **true** | **96** | the above ∪ the resolved values of §6's computed sites (§10.1) |
| server-rendered names vs `BASE_CSS` | **75 used, 17 styled, 58 not** | §8.1; `LC_ALL=C` required, see §10.1 |
| computed `class=` sites | **9** | `grep -rn 'class=[^"]' pages components` |
| `BASE_CSS` | 209 lines | `templates/chrome.rs:9-217` |
| CSP | `style-src 'self'`, no `'unsafe-inline'` | `security_headers.rs:158` |
| mockup CSS at `df3d9d0` | 50,467 B / 4 files / 326 rule blocks | `crates/ui/assets/*.css` |
| Worker bundle at `0.92.6` | 888,972 B gzip-default | `wrangler deploy --dry-run`, wasm + `shim.js` |

## 10.1 Corrections to this RFC, 2026-11-07, found while writing its own handoff

Three, all mine, all the same class — a census whose matcher bounded its answer:

1. **"84 distinct class names" was the literal-grep figure, not the
   denominator.** Resolving §6's computed sites adds **12** names the literal
   grep cannot see (`alert-info`, `alert-success`, `alert-danger`, `step`,
   `step-done`, `step-current`, `col-secondary`, `crumb-current`,
   `density-btn`, `active`, `metric-chip`, `metric-chip-link`). **True: 96.**
   §5 and §9.4 are corrected. **This is the exact error §6 and the handoff warn
   the implementer about**, written into the RFC that warns about it.
2. **There is a third attribute form I had not looked for.** The server-rendered
   directories write `class=\"…\"` **escaped inside `format!` strings** — 31
   sites — which `class="[^"]*"` cannot match at all. It does **not** affect
   this RFC's scope (`pages/` and `components/` have zero escaped sites,
   verified), but a census reused on those directories without it would silently
   under-report, and §8.1's figures depend on handling it.
3. **`comm` on `sort`ed-but-not-`LC_ALL=C`-sorted input returned a wrong
   partition that still summed correctly** — 15/60 instead of the real 17/58 in
   §8.1. The sum reconciling is **not** validation of a partition. `LC_ALL=C` is
   required, and the handoff says so.
