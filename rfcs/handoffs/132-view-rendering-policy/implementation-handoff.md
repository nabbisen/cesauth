# Developer Handoff — RFC 132, View rendering policy

**Governing RFC.** [`rfcs/done/132-view-rendering-policy.md`](../../done/132-view-rendering-policy.md)
**Target release.** 0.82.0 — **and why that level:** RFC 132 on its own is a
**patch**. It corrects a governing document that asserts something false and
adds a gate that stops the correction eroding; nothing here is new capability.
It ships inside 0.82.0 only because it travels with RFC 131 R2a + R5, which
*are* additive, and a release mixing levels takes the higher one. **If R2a/R5
slip and this lands alone, the release is 0.81.4, a patch.** Say so at the cut
rather than inheriting `0.82.0` from this line.
**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing.

---

## 1. Purpose

cesauth has no stated rule for which surfaces render server-side and which
render in the browser. It had one — External Design v2 §4 line 273, "server-side
rendering only (no client framework)" — and RFC 115 abandoned it without
amending it. After this, the rule is derived per surface, written down, and
enforced by a gate. The specific thing it makes impossible: quietly moving an
authentication surface behind a JavaScript requirement.

## 2. Why this matters

`/` and `/login` render `leptos_html_shell` (`crates/backend/src/routes/ui.rs:28-31`).
With JavaScript disabled a user sees an empty root div and **cannot sign in at
all** — while `magic_link/request.rs` and `magic_link/verify.rs` next door
render server HTML and work fine. Nobody decided that split; it accumulated.

**This RFC does not fix it.** Fixing it is RFC 131 R3 (RFC 132 §8). This RFC
makes the split *visible and checked*, so the next one cannot happen silently.

## 3. Resolved decisions — do not re-open

**`/webauthn/*` is `n/a`, not `server`.** All four routes are `POST` JSON —
`route-contracts.md:34-37` already records them as "JSON (challenge)" / "JSON",
rendering test "N/A (JSON)". RFC 132 §5.1 originally classified a "Server HTML
page + scripted ceremony"; **no such page exists** and the row is corrected.
Do not create one, and do not read the correction as licence to touch the
passkey flow.

**The operator console needs no exception.** `client` on Q1 + Q3 (a session
exists and operator fallbacks exist; live filtering and large tables). RFC 132
§13 q2 is withdrawn — it rested on an inverted reading of ADR-013 and on
"known internal population," which is not a reason. Classify it like
`/me/security` and move on.

**ADR-013's console language: Japanese.** Owner ruling 2026-09-09, ADR amended.
Not your concern here; noted so a JA page title does not read as drift.

**Open, and owned by the owner — RFC 132 §13 q1:** where the passkey affordance
lives on `/login`, and what a no-JS user meets. **Deferred, and it blocks
nothing in this handoff.** It is a prerequisite for R3. If you find yourself
needing its answer, you have left this scope — stop and report.

## 4. Facts already measured — do not re-derive

Treat RFC 132 §2, §3 and §5.1 as measured ground. Specifically:

- 188 routes in `route-contracts.md`, gated by
  `scripts/route-contracts-check.sh`. The count is current as of 0.81.3
  (`bash scripts/route-contracts-check.sh` → `✅ All 188 routes are documented`).
- The four pre-auth surfaces that already render server HTML and work without
  JS: `magic_link/request.rs`, `magic_link/verify.rs`,
  `me/totp/verify.rs`, `me/totp/enroll.rs`.
- `/` and `/login` both route to `routes::ui::login`, which calls
  `leptos_html_shell` — one handler, two routes.

*If any of this fails to reproduce on your run, that is a finding — report it
rather than working around it.*

## 5. Change scope

| # | Task | Files |
|---|---|---|
| P1 | Record §5's Q1–Q4 and §5.1's classification as a documentation chapter | new `docs/src/expert/view-rendering-policy.md` + `docs/src/SUMMARY.md` |
| E1 | Add a `Rendering` column — `server` \| `client` \| `n/a` — and a value on **all 188 rows** | `docs/src/expert/route-contracts.md` |
| E2 | Extend the check so a **missing** value fails, exactly as an undocumented route already does | `scripts/route-contracts-check.sh` |
| E3 | Assert declaration against reality: no handler for a `server` route may call `leptos_html_shell` | `scripts/route-contracts-check.sh` |
| D1 | Amend External Design v2 §4 line 273 — record the new rule **and** that the old statement was abandoned rather than superseded | the external-design spec |
| D2 | Mark RFC 131 R0 superseded and R4 amended to reference §5.1 | already done in `rfcs/accepted/131-…md`; **verify, do not redo** |

Order: **P1 → E1 → D1 → E2 → E3.** Both gates last, so they land green.

## 6. The classification is given. Do not re-derive it per route

§5.1 assigns mode by **surface class**, not route by route. Applying it to 188
rows is mechanical:

| Route shape | `Rendering` |
|---|---|
| `*.json`, `/api/v1/*`, OIDC endpoints, `/webauthn/*`, every `POST`-only endpoint that returns JSON | `n/a` |
| `/`, `/login`, `/magic-link/*`, `/accept-invite`, TOTP verify + recovery, terminal error pages | `server` |
| `/me/security*`, `/admin/t/*`, `/admin/tenancy/*`, `/admin/console/*` | `client` |

**`/` and `/login` are declared `server` even though they are not yet** — that
is the point. E3 will then fail on them, because `routes::ui::login` calls
`leptos_html_shell`.

**This is expected and it is the one thing you must not "fix."** See §8.

## 7. Explicit non-change scope

- **No code changes at all.** RFC 132 §10: "Documentation and one script. No
  code, no routes, no contracts." `crates/` is untouched — if your diff shows
  a `.rs` file, something has gone wrong.
- Do not convert `/` or `/login` to server rendering. That is R3, it needs
  §13 q1 answered, and it is a different release.
- Do not implement the `<noscript>` obligation (RFC 132 §13 q3). Policy only
  here; it lands with the console programme.
- Do not touch the passkey flow, `/webauthn/*`, or the Leptos pins.
- Nothing from RFC 129, 131, or 133.
- Do not change a route string. 188 rows, byte-identical.
- No `cargo fmt`.

## 8. The one decision that needs a report, not a workaround

E3 asserts that no `server` route calls `leptos_html_shell`. `/` and `/login`
are `server` by §5.1 and **do** call it. So a correctly-implemented E3 is
**red on the day it is written.**

You have exactly one permitted move, and three forbidden ones.

**Permitted:** land E3 with `/` and `/login` recorded as a **named, dated,
single-entry exemption list** inside the script, each entry carrying the RFC
that removes it (RFC 131 R3) — so the gate is green, the exemption is visible
in the diff, and removing the exemption is what R3's review will check.

**Forbidden:**
- Declaring `/` and `/login` `client` to make the gate pass. That is recording
  the defect as the policy, and it is precisely the erosion this RFC exists to
  prevent.
- `continue-on-error`, or merging E3 red "to be fixed in R3."
- Converting the routes yourself.

If the exemption mechanism turns out to need more than a literal list of two
paths, **stop and report** — a general exemption facility is a design decision
and it is mine.

## 9. Assert the machine-checkable parts mechanically

```sh
# every row has a Rendering value: table row count == rows with a value
bash scripts/route-contracts-check.sh          # must report 188

# E3's real subject: which handlers call the shell
grep -rn 'leptos_html_shell' crates/backend/src --include='*.rs'
```

Attach both. The second is the evidence that E3's exemption list is exactly as
long as reality requires — **two routes, one handler** — and not longer.

## 10. Required tests and evidence

```sh
mdbook build docs                     > evidence/mdbook.log 2>&1
bash scripts/route-contracts-check.sh > evidence/route-contracts.log 2>&1
bash scripts/drift-scan.sh            > evidence/drift-scan.log 2>&1
cargo test -p cesauth-core -p cesauth-adapter-test \
           -p cesauth-migrate-test -p cesauth-frontend > evidence/cargo-test.log 2>&1
cargo check -p cesauth-backend --target wasm32-unknown-unknown > evidence/wasm32-check.log 2>&1
cargo check -p cesauth-frontend --features csr --target wasm32-unknown-unknown > evidence/csr-check.log 2>&1
cargo clippy -p cesauth-core -p cesauth-adapter-test -p cesauth-migrate-test \
             -p cesauth-frontend --all-targets -- -D clippy::correctness > evidence/cargo-clippy.log 2>&1
cargo deny check   > evidence/cargo-deny.log 2>&1
cargo audit        > evidence/cargo-audit.log 2>&1
make build-frontend > evidence/make-build-frontend.log 2>&1
```

Expected: `mdbook` clean; **1,233 passed, 0 failed**; route contracts **188**;
everything else exit 0. On `make build-frontend`, record what the bundle
actually measures and **do not assert a prior figure** — 0.81.3 measured
751,711 B / `6f65f4f6…` where nine earlier builds agreed on 751,714 /
`06009a6f…`, same host, same day. RFC 133 §2.1 owns that; a differing figure is
data, not a failure.

Plus, per RFC 132 §9.3:

- **E2 fires:** delete one row's `Rendering` value → red; restore → green.
- **E3 fires:** point a `server` route's handler at `leptos_html_shell` → red;
  restore → green. Use a route that is **not** on the exemption list, or the
  test proves nothing.

Both pairs, both halves. Seventh time this project has asked; it has caught
something real every time.

**Counts in prose are measurements.** If you write "188 rows" or "two
exemptions," attach the command that says so —
`docs/src/expert/contributing.md` §Choosing the version level's neighbour rule,
added after RFC 128's C1 claimed five `admin_` kinds where there were ten.

## 11. What must NOT be claimed

That the rendering policy is *satisfied*. After this lands, the policy is
**stated and enforced with two known exemptions**, and the most important
surface in the product — the sign-in page — is one of them. A user without
JavaScript still cannot sign in. The honest sentence is: "the policy is
recorded, all 188 routes declare a mode, and the two routes that violate it are
now visible and gated rather than silent."

## 12. Prohibited shortcuts

- No `#[allow(...)]`, `continue-on-error: true`, or weakened gate commands.
- No merging E2 or E3 red.
- No declaring a `server` surface `client` to pass a gate.
- No touching `crates/`.
- No `cargo fmt`.

## 13. Acceptance criteria

RFC 132 §12, items 1–6. Checked hardest: **item 3** (E2 and E3 both blocking,
each with a captured fires/does-not-fire pair) and **item 2** (a value on all
188 rows — a partially-filled column that the check does not notice is the
failure mode, and it is the same shape as the script that once reported
`✅ All 0 routes are documented` on empty input).

Item 5 is already done in the RFC; verify rather than redo it.

## 14. Known risks

RFC 132 §11, plus:

| Risk | Mitigation |
|---|---|
| E3's exemption list becomes a habit | Two literal paths, dated, each naming RFC 131 R3 as its exit. Anything more general → stop and report |
| The `Rendering` column is filled by pattern-matching route strings, not by §5.1 | §6 gives the surface classes; spot-check that `.json` siblings of `server` pages are `n/a`, not inherited |
| E3 gives false confidence | It checks one direction only. RFC 132 §11 states this; repeat it in the review rather than implying coverage |

**If the work turns out materially larger than scoped, stop and report.**
Re-scoping is mine.

## 15. Review request

Write the package to `.git-exclude/review-request/`. It must include:

Implementation summary · changed files (**no `.rs` files**) · any deviation
from §5 · every log from §10 · both §9 assertion outputs · E2's and E3's
fires/does-not-fire pairs, all four halves · the exemption list verbatim and
the grep proving it is not longer than reality · the measured bundle figure
with its command · what remains unverified (§11) · requested review focus.

Report the path only.
