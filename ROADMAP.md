# Roadmap

cesauth is in active development. This file tracks what ships today,
what is planned, and what is deliberately out of scope.

Format inspired by [Keep a Changelog](https://keepachangelog.com/) and
the [Semantic Versioning](https://semver.org/) naming for priorities.

---

## Versioning policy

cesauth follows SemVer. The major number stays at `0` while the
public surface continues to evolve. Within `0.x.y`:

**The default is a minor** (RFC 181, 2026-11-07). At scheduling time the next
release is `0.x+1.0` and needs no argument. **A patch is a claim that must be
argued in writing, in the dispatch handoff**: *everything here is a fix or
internal-only, and no caller must change anything.* Silence means minor. The
list below is therefore no longer "what earns a minor" — it is **examples of
what cannot be a patch**, and the caller-obligation test is the bar the patch
argument has to clear.

*Why the default is this way round: under-leveling ships a caller-breaking
change under a number promising compatibility — silent, reaching integrators,
and uncorrectable because tags are immutable. Over-leveling spends a digit. At
`0.y.z` SemVer imposes no obligation at all (§4, scoped `x > 0`), so the cheap
error is the one the default should produce. It failed the other way six times
in seven across `0.92.x`, and five times in a row across `0.79.1`–`0.79.6`
while adding seventeen routes. **Scoped to `0.y.z`; this inversion expires at
`1.0`**, where the asymmetry no longer holds.*

- **Cannot be a patch — bump the minor (`0.x → 0.x+1`) — when** a release introduces a new
  HTTP route surface, a new schema migration, a new public type or
  trait in `cesauth-core`, a new permission slug, a new operator-visible
  configuration knob (`wrangler.toml` `[triggers]`, new env var),
  or a renamed/removed URL. Anything an integrator or operator could
  observe by reading the release notes and going "I need to do
  something" earns a minor bump.

  **The catch-all's test is caller obligation, not observable
  difference** (clarified 2026-10-31, after it was misapplied in both
  directions). A bug fix changes behaviour and obliges nobody: v0.89.1
  turned an undocumented `409` into the `400` the published error table
  had always allowed, so no integrator had a documented behaviour to
  lose — correctly a patch. RFC 152 half B is the mirror image: the
  CSRF column already reads `required`, so the *document* does not
  change, but every scripted caller of those 34 `POST` endpoints must
  start sending a token or break — correctly a minor. Ask who must
  change their code, not what changed.
- **A patch (`0.x.y → 0.x.y+1`) may be argued when** the change is
  internal-only: bug fixes that preserve existing behavior, doc
  updates, dependency upgrades that don't shift any visible
  behavior, refactors. Security fixes that preserve wire compatibility
  also count as patch (the v0.15.1 RUSTSEC fix is the canonical
  example — `Cargo.toml` features narrowed, no surface change).

A few historical 0.4.x releases (notably 0.6.0 through 0.11.0 and
0.13.0-0.15.0, 0.16.0-0.17.0) by this rubric should arguably have
been minor bumps rather than patches. We accept that as historical
debt rather than rewriting bundles already shipped — those releases
are immutable artifacts. Going forward (from 0.18.0 onward) the rule
above is the policy.

A future `1.0` will be cut when the public surface settles. There
is no fixed timeline; the bar is "what shipped is what we want"
across the OIDC, tenancy, and operator surfaces.

---

## Shipped

The following subsystems are implemented end-to-end and covered by
host tests.  Each row links to the canonical CHANGELOG entry;
full narrative is in the [archive](docs/changelog-archive/README.md).

> **Full shipped narrative** for v0.31.0–v0.52.1 is in
> [`docs/changelog-archive/ROADMAP-shipped-0.31-to-0.52.md`](docs/changelog-archive/ROADMAP-shipped-0.31-to-0.52.md).

| Area | Shipped at | CHANGELOG |
|---|---|---|
| Five-crate workspace + ports/adapters | v0.1.0 | [archive](docs/changelog-archive/CHANGELOG-0.1-to-0.30.md) |
| D1 schema, DOs, OIDC core, WebAuthn, Magic Link | v0.1.0–v0.3.0 | [archive](docs/changelog-archive/CHANGELOG-0.1-to-0.30.md) |
| Tenancy data model + admin console | v0.6.0–v0.15.0 | [archive](docs/changelog-archive/CHANGELOG-0.1-to-0.30.md) |
| Anonymous trial promotion (ADR-004) | v0.16.0–v0.18.0 | [archive](docs/changelog-archive/CHANGELOG-0.1-to-0.30.md) |
| Data migration tooling (ADR-005) | v0.19.0–v0.22.0 | [archive](docs/changelog-archive/CHANGELOG-0.1-to-0.30.md) |
| HTTP security headers (ADR-007) | v0.23.0 | [archive](docs/changelog-archive/CHANGELOG-0.1-to-0.30.md) |
| Security track: CSRF audit + email verification | v0.24.0–v0.25.0 | [archive](docs/changelog-archive/CHANGELOG-0.1-to-0.30.md) |
| TOTP MFA full track (ADR-009) | v0.26.0–v0.30.0 | [archive](docs/changelog-archive/CHANGELOG-0.1-to-0.30.md) |
| UI/UX iteration: flash, Security Center, next-param | v0.31.0–v0.32.1 | [archive](docs/changelog-archive/CHANGELOG-0.31-to-0.40.md) |
| Audit log hash chain (ADR-010) | v0.32.0–v0.33.0 | [archive](docs/changelog-archive/CHANGELOG-0.31-to-0.40.md) |
| Refresh token reuse hardening (ADR-011) | v0.34.0 | [archive](docs/changelog-archive/CHANGELOG-0.31-to-0.40.md) |
| Session hardening (ADR-012) | v0.35.0 | [archive](docs/changelog-archive/CHANGELOG-0.31-to-0.40.md) |
| i18n infrastructure + migration (ADR-013) | v0.36.0–v0.39.0 | [archive](docs/changelog-archive/CHANGELOG-0.31-to-0.40.md) |
| Session-index drift detection | v0.40.0 | [archive](docs/changelog-archive/CHANGELOG-0.31-to-0.40.md) |
| Multi-key access-token introspection | v0.41.0 | [archive](docs/changelog-archive/CHANGELOG-0.41-to-0.49.md) |
| RFC 7009 token revocation conformance | v0.42.0 | [archive](docs/changelog-archive/CHANGELOG-0.41-to-0.49.md) |
| Introspection rate limit (ADR-014 §Q2) | v0.43.0 | [archive](docs/changelog-archive/CHANGELOG-0.41-to-0.49.md) |
| Drop `jsonwebtoken` (RUSTSEC-2023-0071) | v0.44.0 | [archive](docs/changelog-archive/CHANGELOG-0.41-to-0.49.md) |
| Bulk session revoke (ADR-012 §Q4) | v0.45.0 | [archive](docs/changelog-archive/CHANGELOG-0.41-to-0.49.md) |
| Refresh-token introspection extensions | v0.46.0 | [archive](docs/changelog-archive/CHANGELOG-0.41-to-0.49.md) |
| i18n-2 continuation | v0.47.0 | [archive](docs/changelog-archive/CHANGELOG-0.41-to-0.49.md) |
| Audit retention policy (ADR-014 §Q3) | v0.48.0 | [archive](docs/changelog-archive/CHANGELOG-0.41-to-0.49.md) |
| D1 session-index repair (ADR-012 §Q1.5) | v0.49.0 | [archive](docs/changelog-archive/CHANGELOG-0.41-to-0.49.md) |
| Per-client introspection audience (ADR-014 §Q1) | v0.50.0 | [archive](docs/changelog-archive/CHANGELOG-0.50-to-0.59.md) |
| OTP audit fix + introspect aud correctness (RFC 008/009) | v0.50.3 | [CHANGELOG](CHANGELOG.md) |
| MagicLinkMailer port + provider adapters (RFC 010) | v0.51.0 | [CHANGELOG](CHANGELOG.md) |
| WebAuthn typed errors + proptest (RFC 003/004) | v0.51.1 | [CHANGELOG](CHANGELOG.md) |
| `cargo fuzz` for JWT parser (RFC 005) | v0.51.2 | [CHANGELOG](CHANGELOG.md) |
| CSP nonces + RFC lifecycle policy (RFC 006/019) | v0.52.0 | [CHANGELOG](CHANGELOG.md) |
| Doc/repo hygiene + drift-scan (RFC 007/012) | v0.52.1 | [CHANGELOG](CHANGELOG.md) |
| OIDC `id_token` issuance, ADR-008 §Q1-Q11 (RFC 001) | v0.54.0 | [CHANGELOG](CHANGELOG.md) |
| Workers operational readiness + route contracts (RFC 013/025/027) | v0.53.0 | [CHANGELOG](CHANGELOG.md) |
| `/introspect` hot path, rustfmt removal (RFC 026/029) | v0.53.0 | [CHANGELOG](CHANGELOG.md) |
| CHANGELOG/ROADMAP volume, audit request traceability (RFC 015/028) | v0.53.0 | [CHANGELOG](CHANGELOG.md) |
| Admin scope badge, OIDC audience editor, preview-and-apply (RFC 016/017/018) | v0.53.0 | [CHANGELOG](CHANGELOG.md) |
| Admin frame design tokens + Security Center i18n closure (RFC 105/106) | v0.67.0 | [CHANGELOG](CHANGELOG.md) |
| Route-catalog correction + end-user template migration (RFC 108 partial) | v0.68.0 | [CHANGELOG](CHANGELOG.md) |
| Route-catalog completion + admin/console template migration (RFC 108 continued) | v0.69.0 | [CHANGELOG](CHANGELOG.md) |
| RFC 108 closure (tenant_admin + tenancy_console migration + drift-scan rule) | v0.70.0 | [CHANGELOG](CHANGELOG.md) |
| RFC 109 — Audit log viewer UI surface (with scope amendments) | v0.71.0 | [CHANGELOG](CHANGELOG.md) |
| RFC 110 + 113 — Safety controls audit + UI rendering acceptance harness | v0.72.0 | [CHANGELOG](CHANGELOG.md) |
| RFC 107 + 111 — ADR-013 §Q4 closure (plural-aware lookup + UTC ISO-8601 policy) | v0.73.0 | [CHANGELOG](CHANGELOG.md) |
| RFC 110b/c/d/e — Safety controls panel gap-fills (Turnstile/refresh-reuse/TOTP-key/runbook-link); 110a still deferred | v0.74.0 | [CHANGELOG](CHANGELOG.md) |
| Test file modularization — `templates/tests.rs` (2,057 lines) split into 7 per-feature submodules (dev-guideline compliance, no behaviour change) | v0.75.0 | [CHANGELOG](CHANGELOG.md) |
| Test file modularization continued — `service/introspect/tests.rs` (1,519 lines) split into 6 sibling files (low-disruption unwrap-mod-block pattern) | v0.76.0 | [CHANGELOG](CHANGELOG.md) |
| Test file modularization closure — three more splits (`migrate/tests.rs` 1,154 lines, `tenant_admin/tests.rs` 895 lines, `migration_chain.rs` 881 lines) | v0.77.0 | [CHANGELOG](CHANGELOG.md) |
| Test file modularization 100% closure — four more splits (`tenancy/tests.rs` 664, `authz/tests.rs` 606, `totp/tests.rs` 602, `i18n/tests.rs` 530); every host-buildable test file now under 500 ELOC | v0.78.0 | [CHANGELOG](CHANGELOG.md) |

---

## Planned (0.x)

Approximate priority order. Items near the top are closer to being
started.

> **Engineering specs**: as of v0.50.1, items in this section that
> are ready to be implemented have a corresponding RFC under
> [`rfcs/`](../rfcs/). RFCs are the implementation handover spec
> (what to build, how to test it); this ROADMAP tracks the theme;
> ADRs in `docs/src/expert/adr/` track the design decisions.

### Next minor releases

**Sequence authorized by the owner 2026-10-30** (proposal:
`.git-exclude/release/0.90-scope.md`). Levels follow the policy above; patch
numbers are assigned at each cut, not reserved here.

> **How to write in this file** (architect's rule, 2026-11-07, after measuring
> that his own rows added **24,134 B in one session** to a file already 4.5× over
> its budget). A row is **a summary and a path**, not the record: name the thing,
> its level, its state, and the file that holds the reasoning —
> `rfcs/accepted/NNN-*.md` or `.git-exclude/reviewed/*`. Those are durable and
> this file is a schedule. **Rows are keyed to sequence, never to a predicted
> version number** (RFC 181 §7) — `after RFC 180`, `NEXT`, `after the next cut`.
> The number is assigned at the cut from what shipped.

| Release | Level | Content |
|---|---|---|
| ~~0.89.4~~ | patch | ✅ **shipped 2026-10-31** — RFC 161 §9(a) + RFC 167 slice 1. Took two cycles: the first "Deploy it" list followed an order the architect specified that told readers to `wrangler deploy` before migrations |
| ~~0.89.5~~ | patch | ✅ **shipped 2026-10-31** — RFC 167 slice 2 + RFC 028's CHANGELOG half. `docs/src/deployment/first-production-deploy.md`, one ordered pass from an empty Cloudflare account to a tenant completing an OIDC flow, placed first under `# Deployment`. Took two cycles: the spine in `README.md` was still missing `production.md` Step 3 (seed the signing key), which three readings passed over and the **local rehearsal** caught by reproducing `/jwks.json` serving `{"keys":[]}`. The *"blocked on an owner decision"* condition this row carried was the architect's own over-specification: a real account is needed for six commands, not for the page, so the evidence term splits per step — sequence `exercised`, the six remote-only commands `reviewed` and named. CHANGELOG 318 KB → 42 KB |
| ~~0.90.0~~ | **minor** | ✅ **shipped 2026-10-31** — RFC 152 half B, in two stages. Stage 1: **34** admin `POST` routes across 23 files gained `csrf::verify`, the 21 server-rendered forms gained a token, every re-render mints a fresh one, and **E6** fails the build if a row claiming `required` stops being true. Stage 2: `GET /admin/login` validated nothing and set the session cookie anyway — it now validates, sets nothing, and renders a confirmation page naming the identity the operator is about to assume; a new `POST /admin/login` verifies a CSRF token before the cookie exists. **Found in review and not fixed here: nine operator-console rows make the same `required` claim with no check** — RFC 152 half C |
| ~~0.91.0~~ | **minor** | ✅ **shipped 2026-10-31** — RFC 152 half C, in two cycles. **Seven** operator-console rows, not the nine first reported: three browser forms got the double-submit token (including **`POST /admin/console/tokens`, which mints an admin token**), five JSON endpoints now **reject a cookie entirely** via a new header-only resolver, and two needed only an honest cell. **E6 checks the control each cell names, repo-wide, and has a census** — unrecognised cell is a hard failure, 0 unclassified. `safety.rs::verify` was reclassified mid-cycle against the dispatch, correctly: the form it would have redirected to exists in no live path. **Found in review, not fixed: 29 rows document a control that is not the one protecting them** — RFC 152 half D |
| ~~0.91.1~~ | patch | ✅ **shipped 2026-11-01** — **RFC 169**: the book did not contain **11 of its own 80 pages**, including the route-contract table every route gate reads, `contributing.md`, and **ADR-016/017/018**, so the ADR index stopped at 015. Nine are in the book, two are declared out with reasons, and two checks in `drift-scan.sh` fail when a page leaves the book or an in-book link stops resolving. The check's first run found `data-model.md` pointing at a plural `adrs/` directory that never existed |
| ~~0.91.2~~ | patch | ✅ **shipped 2026-11-03** — **RFC 164** (167 `rfcs/` links checked on every push; 20 were broken, **six having rotted in since the audit six days earlier** while the sweep was being run by hand), **RFC 168** (tags reconciled against CHANGELOG entries both directions, 140 vs 138, with the historical exemption corrected from a claimed six and a listed five to the computed **ten**) and **RFC 165 §3** (four exemption lists staleness-checked — **none was stale**). **The new checks could not have run in CI**: no workflow fetched tags, so `drift-scan.yml` gained `fetch-depth: 0`. **No RFC closed** — §3b, the level backstop and §4 are each a named remainder |
| **NEXT** | **minor** | **RFC 168's level backstop, now buildable for the first time — and a URL-set diff the RFC does not specify.** **Correction 2026-11-07: this is ONE unbuilt check, not three.** RFC 168 §3's item 1 (reconciliation) shipped with RFC 164 in `0.91.2` and `drift-scan.sh` prints its population every run; item 3 is a requirement on the others, not a check. Only §3.2's backstop is missing. **And that backstop would not have caught `0.92.3`** — it tests whether a patch *adds* a route, a migration or an MSRV bump, and `0.92.3` *removed* two routes, a direction no addition-shaped test sees; the URL-set diff is the half that covers it. **RFC 181** (accepted 2026-11-07) inverted the default, which is what makes this tractable: the old check had to detect seven triggers including *caller obligation*, which is a judgement and not a grep — and is why it stayed unbuilt through seven releases. The check is now two mechanical conditions: **did the minor number increase, and if not, is there a recorded patch argument for this release?** The judgement moves to the handoff, where a human is already writing prose, and the gate only confirms the prose exists when the number says it must. **Add the fourth check RFC 168 omits**: a URL-set diff of `route-contracts.md` against the previous tag — two lines, and it would have caught `0.92.3`'s **194 → 192** without judgement. Both belong in `scripts/drift-scan.sh`. **Green on arrival** (the E7 / RFC 178 lesson): `0.92.4` is the only release in the run whose level survives the audit, so the check must either start from the next tag or carry a dated, named historical exemption like `drift-scan.sh:730`'s `0.79.6` entry — **do not dispatch it bare** |
| 0.93.0 | **minor** | **PREPARED, TAG HELD 2026-11-08** — version bumped, CHANGELOG written, 0.90+0.91 archived, but **not tagged**: both release gates began returning different answers on an unchanged tree (next row), and "drift-scan clean" is a claim the tag message makes. **The first cut under RFC 181's minor-by-default rule.** **Scope, stated because the owner asked whether `0.93.0` had been scoped and it had not — not for this.** The next cut carries **RFC 181** (applied `892071e`, doc-only: the default inversion, `ROADMAP.md` §Versioning policy, `contributing.md` §Choosing the version level, `rfcs/handoffs/TEMPLATE.md`, RFC 168 §4.2 superseded in part) and **RFC 180** once the dev team returns it (R2b finished: ten mockup files, 47 keys triaged against core's 171, the mockup's locale mechanism deleted rather than imported). **Minor** — RFC 181's default, no argument needed; RFC 180 adds module surface regardless. **This is a thin release and deliberately so**: RFC 181 is a policy change worth landing on its own rather than buried under a programme, and nothing else is in flight. `0.93.0` previously named RFC 131 §0 slices 1–2 in this file; those are re-keyed to sequence (RFC 181 §7) and the number is assigned at the cut |
| ~~0.93.0~~ | **minor** | ✅ **shipped 2026-11-08, `df268b2`, reviewed and accepted** — **both release gates turned a match into a miss; `pipefail` + SIGPIPE** (**P1**). **The implementer found two FALSE-PASS sites the architect's own audit said it had looked for and not found, plus a vulnerable form the handoff never considered (`awk` with its own `exit`, 4 piped sites).** The false passes: `drift-scan.sh`'s link-integrity per-file gate (`… || continue` — a match→miss skipped a whole file's link scan with no counter, so a broken link there went unreported), and E7's caller-attribution chain (4 sites — shrinking `$caller` means a variant is never evaluated, and a trait→struct miss reclassifies a method into `no_caller`, which nothing treats as a failure). Verified at review: 20/20 exit 0 for drift-scan (12 idle + 8 under load), route-contracts exit 0 twice with byte-identical output, E7 `156 = 8 + 31 + 117` matching the pre-fix figure. **Not claimed, correctly: whether either false pass ever hid a real violation** — such runs leave no record by construction; routed to its own cycle. Symptom: `drift-scan.sh` returned **1 clean run in 5** on an unchanged tree, with two *different* false failures (`deployment/production.md` reported broken though it exists and is in `SUMMARY.md:88`; tag `0.33.0` reported undocumented though it is at `CHANGELOG-0.31-to-0.40.md:1682`). `route-contracts-check.sh` exits **141 — SIGPIPE — three of three**, dying right after the E6 line, **so E7's census has not actually run since the load rose.** **Mechanism proven, not guessed**: both scripts open `set -euo pipefail`, and `printf '%s\n' "$list" | grep -Fxq "$needle"` makes `grep` exit on first match, SIGPIPE the `printf`, and `pipefail` hand the *pipeline* status 141 — so **a match becomes a miss**. Minimal repro: 200,000-line list, needle first, **found 0 times out of 40**. At 148 entries the list fits the 64 KiB pipe buffer and usually works, which is why these gates were green all week and flapped only at load average **134** (unrelated builds from other projects on this machine). **So the gates have been partly luck.** Scope is smaller than the raw counts suggest — `grep -q <<< "$var"` and `grep -qE … "$file"` forms are already safe and must not be touched; only a **pipe** into `grep -*q` or `head` is vulnerable. Fix is mechanical (here-string instead of pipe), **but the polarity audit is not**: SIGPIPE fires only on a match, so the error is always match→miss, which is a **false violation** for *"is this documented?"* and a **false PASS** for *"does a forbidden pattern appear?"*. I sampled and found no false-pass site **and am not claiming there is none** — the handoff requires a per-site polarity table. Evidence bar: **20 consecutive identical runs of each script, and again under deliberate load** — **RETURNED 2026-11-08, implementation report filed at `.git-exclude/review-request/182-pipefail-sigpipe-report.md`, awaiting review.** `drift-scan.sh` got the full bar: 20/20 idle, 20/20 under load average ~43. `route-contracts-check.sh` costs ~100-150s/run (E7 forks a `grep`/`awk`/`sed` per candidate file × function across 36 traits), so the full 20+20 was impractical this session — ran 9 confirmed-clean runs instead, including one spanning load average **144 → 45**, at and above the handoff's own cited trigger, not a scaled-down stand-in for it. Both named false failures confirmed stopped (`0.33.0`, `deployment/production.md`); E7 and the closing `✅` now appear on every run, with figures byte-identical to the prior review's own RFC 180 baseline — no check's logic changed. **Found what the handoff's own sample did not**: its own audit was bounded to `grep -q`/`head` and reported no false-pass site; tracing actual consumer logic (not just shape) found **one in each script** — `drift-scan.sh`'s per-file docs-link-integrity gate (a miss silently skips scanning that file's own links, no counter records it) and four sites feeding `route-contracts-check.sh`'s E7 caller-attribution chain (a miss can reclassify a real, unexempted `written`/`chokepoint` DEFECT as the non-failing `no_caller` bucket instead of computing it at all). Also found a vocabulary gap: an `awk` script with its own `exit`, fed by a pipe rather than a file argument or a here-string, is the same hazard shape as `grep -q`/`head` — 4 such sites in `route-contracts-check.sh`, 0 in `drift-scan.sh`, none in the handoff's own sample |
| after the next cut | **minor** | **RFC 181's own worked consequence, recorded so it is not rediscovered**: `rfcs/handoffs/TEMPLATE.md` now defaults `Target release` to minor and asks for a patch *argument* covering both halves — (a) nothing newly possible, **a new CI gate or workflow included**, and (b) no caller must change anything. The template is deliberately the home for this rather than an RFC: **RFC 168 §4.2 put the identical requirement in an RFC on 2026-10-31 and the architect's own RFC 179 handoff skipped it four days later**, while RFC 180's handoff — written to the same template — stated its reason and so let the owner challenge it. A rule in a template reaches every dispatch; a rule in an RFC reaches whoever re-reads that RFC. **Nothing to build here** — this row exists only to record why the placement was chosen, since the next person to tidy the template will otherwise move it back |
| ~~0.92.0~~ | **minor** | ✅ **shipped 2026-11-03** — **RFC 141 cycle 2 + 2b**, closing RFC 141. The OIDC clients screen, which did not exist: `GET /admin/console/clients` answered **200** and rendered *"Page not found"* to a signed-in operator. Four write routes gained the **CSRF control their own module doc claimed and lacked** — the doc said a cross-origin JSON POST was impossible because preflight blocks it, the handlers never checked `Content-Type`, and `text/plain` is CORS-safelisted. **`created_at` could not be reported** by `clients.json` since migration 0001. Two CSP violations found only by running the screen. Then **cycle 2b**: `classify_insert_message` matched `_UNIQUE` but not `_PRIMARYKEY`, so a duplicate value answered **500** wherever the primary key *is* the uniqueness constraint — which, with 61 `PRIMARY KEY` declarations and one `INTEGER` among them, is nearly everywhere. **Ten paths branched on a `Conflict` that could not occur**, including an invitation-acceptance record lost permanently. One `||` fixed all ten. **Retracted at this cut: RFC 133 half B's "cross-environment" bundle offset was `gzip -9` against the default level** (RFC 133 §16) |
| ~~0.92.1~~ | patch | ✅ **shipped 2026-11-03** — **CHANGELOG archive split** (RFC 028) — the file states it keeps the most recent **five** minor versions and holds **eight** (0.85–0.92) at **79 KB of its 80 KB budget**. The byte guard has never fired and the five-minor rule is checked by nothing; `changelog-archive-split.sh` only measures bytes and nothing runs it. **The next cut crosses the budget.** Recorded at the 0.92.0 cut rather than done in it: a split creates archive files and moves history, and its link integrity should be re-verified on its own |
| after 0.92.0 | patch | **`worker-build` installs without `--locked`** — hygiene, and **no datum behind it** after RFC 133 §16's retraction. `trunk` is installed `--locked` in four workflows and this is not; a pinned version whose dependency graph floats can produce different output. Worth a cycle on its own merits, with verification that 0.8.4's lockfile still compiles on 1.98.1 |
| ~~0.92.1~~ | patch | ✅ **shipped 2026-11-03** — the control stage 1 documented does not hold: `is_json_content_type` substring-matches, so `Content-Type: text/plain; x=application/json` (CORS-safelisted essence, no preflight) passes it. Third instance of this RFC's own sentence, one per half. — **RFC 152 half D stage 1** — the measurement, plus the **11 `N/A (JSON)` cells** whose stated CORS preflight never happens (verified live). Stage 2, the 18 `N/A (bearer)` rows, is unscheduled until that measurement answers whether any real caller authenticates to them by cookie |
| ~~0.92.2~~ | patch | ✅ **shipped 2026-11-03** — **RFC 170** (accepted 2026-11-01), **both halves**: the credentialed job *and* RFC 147's sweep refactor, since the acceptance was of the whole RFC — one CI job with migrated D1 and a seeded credential, closing RFC 147's sweep at `exercised` and restoring the admin cookie's live witness; **moves the workflow count off 14**, which the manifest gate asserts |
| ~~0.92.5~~ | patch | ✅ **shipped 2026-11-04** — **E7**, RFC 171 §3 Q1's check — the gate was briefly RED on `main` (13/14) because the architect dispatched "build the check" plus "fix nothing" with no exemption mechanism, which cannot hold in a green tree. Follow-up dispatched 2026-11-04: split E7's two shapes (26 chokepoint / 5 written) and exempt both by name, the `E6_BEARER_LEGACY_EXEMPT` pattern. **CUT BLOCKED until the gate is green.** — 36 traits, 156 methods, 2 live defects, 3 chokepoint-shape, 7 classifier gaps; its arithmetic is owed a per-section subtotal (102 of 156 methods visibly reconcile)** — **RFC 171 §3 Q1** (accepted 2026-11-03) — the **producer** question: for every `PortError` variant a handler matches, can the adapter behind that call return it? **The census is a stage, not a release** — its number decides the check's shape, same discipline as RFC 166 §3, and the two are deliberately **not merged**: one asks whether a definition has a caller, the other whether a matched variant has a producer. This is the half that would have caught all ten of RFC 160 §4.11's paths — six operator messages that cannot be displayed, three `api_v1` responses answering 500 where they document 409, and an invitation acceptance lost for good |
| after RFC 171 §3 Q1 | patch | **RFC 171 §3 Q2 — now unblocked**: 0.92.2 shipped the credentialed job this needs — the **parity** question: the in-memory double and the D1 adapter must agree on each port method's documented error classes. They disagreed about `Conflict` for eleven releases and the double was the one that was right, so every host test was green over it. **Not host-testable** — `cesauth-adapter-cloudflare`'s repository code needs a worker runtime and real D1, which is exactly the job RFC 170 builds. The half that would have caught the *cause* |
| ~~0.92.1~~ | patch | ✅ **shipped 2026-11-03, closing RFC 172** (**P0**) — `POST /webauthn/register/start` takes the account it registers a passkey for **from the request body** and authenticates nobody; `register_finish` writes the authenticator and then issues a session for it (*"Registration doubles as a first-login"*). Given a user id, account takeover in two unauthenticated requests. **Exposure today: none — nobody has deployed this tree**, which is the only thing between urgent and incident. **Ahead of RFC 170 and RFC 171 §3 Q1.** Found by RFC 152 half D stage 1, which recorded the fact as a CSRF justification without recognising it. **The RFC's own §4 was corrected before dispatch (§4.1)**: the fix takes the subject from the session, not from deleting the parameter — the `user_id: None` branch mints a UUID with no `users` row and writes an orphan, which `register_finish`'s own `tenant-default` fallback hides |
| after 0.92.x | patch | **The `required (Content-Type)` control rests on an absence nothing guards** (found 2026-11-03 reviewing RFC 172). It is sound only while no `Access-Control-Allow-Origin` exists anywhere in this worker — true today, documented in prose at `routes/deletions.rs:70`, and enforced by nothing: `grep -rn "Access-Control" scripts/ .github/workflows/` has no matches. Add a CORS header and **four routes silently lose the control their rows claim** while every gate stays green. **The gate is one line**: assert the repo-wide count of non-comment occurrences is zero |
| ~~0.92.2~~ | patch | ✅ **shipped 2026-11-03** — **RFC 173** (**P1**; **the acceptance carries no quotation unlike 170/171/172 and the architect has no record of it** — `0de873e` cites the review's *recommendation* as its authority, and a recommendation is not an authorization; the work is not in doubt): small, **P1**) — `session_index_audit` binds an `i64` straight into D1, which `wasm_bindgen` turns into a BigInt that D1 rejects, so it **has never read a row since 2026-05-06** — and its error path `return Ok(..)`s, so the operator-facing cron status has recorded a **successful** pass with 0 rows walked every day since. Zero drift is also what a working detector reports, so there was nothing to notice. **Found on RFC 170's very first rehearsal**, and it is that job's third assertion — the scope fence's own condition, met. The remedy `d1_int` is `pub(crate)` in the adapter crate, unreachable from the one caller outside it |
| after 0.92.x | patch | **A derived check for the workflow count** — RFC 170's stale-phrase pattern guards the *superseded* wording (`thirteen (workflows|names|checks)`), so the **next** workflow added leaves `contributing.md`'s three prose counts stale exactly as this one did. **The architect's specification error**: a pattern over past wording is a regression guard and cannot see a future drift. `drift-scan.sh` already has four derived checks; this one counts `.github/workflows/*.yml` and the manifest's `release` array and asserts the prose numerals match |
| ~~0.92.3~~ | patch | ✅ **shipped 2026-11-03, closing RFC 174** (**P2**) — `POST /admin/console/config/log_level/apply` writes to an undeclared KV binding, nothing would read it if it landed (`LogConfig::from_env` never touches KV), and the handler then writes a hash-chained **`OperationApplied` audit row saying the level was applied**. The operator is told it worked, the record of truth says it worked, and the log level cannot change at runtime. **§3 is a real question**: make the feature real (**minor** — a runtime override that has never existed) or remove the action and say the level is deploy-time. **Corrected by a live probe before anything was built** (§0): the console renders **zero** forms, so no log-level control exists in the UI, and the apply route answers **400 `csrf_token required`** to the only form that posts to it — before the KV write or the audit row. **No `log_level applied` audit row has ever existed.** So *"the operator is told it worked"* was false, and the premise on which the architect called this the owner's call — that (b) removes an operator affordance — did not hold either. Removal is cheaper and better supported than when it was proposed; routes 194 → 192, E6 94 → 92. **The architect's "keep `core::admin::preview`" instruction was wrong and is reversed**: its stated reason — the generic bucket preview/apply pair as the obvious future consumer — is false (`config::preview` returns plain JSON and never used any of it), and the orphan is not two functions but **two whole modules, 8 public items, 19 tests**. Keeping it would deliberately create the class RFC 166 exists to stop, in the release that removed its only consumer. Deleted, with a dated pointer in RFC 166 §3's census to the recoverable commit. Found by sweeping the class RFC 173's own KV fix belonged to |
| after 0.92.x | patch | **Extend the staleness discipline to `e6_mechanism_check`'s arms** — removing the last row that uses a mechanism leaves its `case` arm matching nothing, and **nothing fails**: the scanned-but-never-matched rule covers `NAMED_NON_HANDLERS` and the exemption lists, not the mechanism table. Found while scoping RFC 174's removal, which will leave exactly that dead arm (`preview-token binding`) and removes it by hand. Same lesson RFC 152 half D's cycle taught: a gate's unused code path is not a working code path |
| after 0.92.x | patch | **`unused_imports` is denied in `cesauth-backend` only, and `core`/`frontend` have three live warnings to show it matters** — `ClientId` in `service/revoke.rs`, `js_string_literal` in `templates/login.rs`, `frame_with_flash` in `templates/security_center.rs`, all pre-existing (found during RFC 174's cluster deletion, which could not have caused them). RFC 157 rejected a command-line `-D` because it reaches dependencies too; **the crate-attribute route was always available for the other crates and was never taken**. `contributing.md` already calls this "the one gate with no workflow of its own" |
| ~~0.92.6~~ | patch | ✅ **shipped 2026-11-07, and the diagnosis it carried was wrong twice** — this row said RFC 028's five-minor and ~80 KB rules were in conflict with **the architect's entry length** as the cause, and recommended dropping the five-minor rule. **Measured at the 0.92.6 cut, both halves fail.** (1) **There was never a conflict**: Requirement 1 reads *"the most recent ~5 minor versions (a number large enough to cover most 'what shipped recently' queries, **small enough to keep the file under ~80 KB**)"* — the budget is given as the *reason for* the five, so there is one rule and one derived estimate, not two rules. (2) **Entry length was the wrong variable and has been falling, not rising**: mean B/entry by archive file is **9,316 (0.31–0.40) → 5,697 (0.50–0.59) → 3,302 (0.70–0.79) → 2,644 (0.85–0.87) → 2,150 (0.88)**. The real driver is **cadence**: releases per minor rose **1.00–1.17 (v0.31–v0.49) → 2.90 (v0.70–v0.79) → 4.00 (v0.89–v0.92)**, so "five minors" meant ~5 entries when RFC 028 was written and ~20 now. (3) **And "the enforced rule won" was false too — neither rule is enforced.** `git grep` for the budget across `scripts/`, `.github/workflows/` and `Makefile` finds it only in `changelog-archive-split.sh`'s own guard, which a human must run. **RFC 028 Step 5 specified a CI budget check as runnable bash and it was never built** (the RFC's header says so). The byte rule won by being noticed at a cut. **This cut archived 0.89** (25,206 B), root 81,024 → 55,818 B, splitting **down to a floor** rather than just under the ceiling. Direction recorded in RFC 028's 2026-11-07 note; the gate is dispatched separately |
| after 0.92.6 | patch | **Build RFC 028 Step 5's budget check — the rule it enforces is six releases old and has never had a gate.** Step 5 already specifies it as runnable bash (`CHANGELOG_BUDGET_BYTES=$((80*1024))`, `ROADMAP_BUDGET_BYTES=$((40*1024))`); it was never built, and that absence is the whole reason a derived figure drifted in prose for months and two reader-facing surfaces carried a wrong account of why. **Belongs in `scripts/drift-scan.sh`**, beside the release-reconciliation check, not in a new script. **Green on arrival**: after this cut `CHANGELOG.md` is **63,275 B of 81,920** (18,645 B headroom, ~6 cuts at the recent 2.9 KB/entry), so the CHANGELOG half passes the day it lands — the E7 and RFC 178 lesson applied in advance rather than after a red `main`. **The ROADMAP half does not** (next row), so the check must ship with that side exempted by name and dated, the `E6_BEARER_LEGACY_EXEMPT` / `KNOWN_NO_STYLESHEET` shape: reporting on every run, failing as stale the moment the file drops under budget |
| after RFC 168's backstop | **minor** | **`ROADMAP.md` is 184,474 B against RFC 028's 40,960 B budget — 4.5× over, ungated, and RFC 028's own diagnosis of it is wrong.** Re-measured 2026-11-07, by section: **`## Planned (0.x)` is 172,048 B — 93.3% of the file.** `## Shipped` is **6,096 B, 3.3%** — so **RFC 028 Requirement 3 / Step 3, which says to archive older *Shipped* rows, addresses 3% of the problem**, and its Outstanding note's *"61 shipped rows inline"* blamed the wrong section. Inside Planned: 42 table rows totalling ~43 KB (20 completed 24,891 B, 21 open 18,305 B) and **1,963 lines of bullet prose below the table, ~121 KB**, which is the actual bulk — still describing work shipped in September (`Shipped 2026-09-15`), carrying test counts from **801** tests against today's **1,675**, and embedding SQL blocks. **The defect is that the planning narrative was never pruned as items shipped**, not that the Shipped table grew. Needs its own cycle and real judgement — 1,963 lines, each needing "did this ship, and is any of it still true?" — which is why it is not a `sed`. **Sequence it after the level backstop**: a file nothing checks will drift again, so the gate (RFC 028 Step 5, its ROADMAP half exempted-by-name until this lands) should exist first. The architect's own row-writing rule is now in this file's header, but **that governs 18 KB of 184 KB and does not fix the breach** |
| ~~0.92.7~~ | patch | ✅ **shipped 2026-11-07, closing RFC 179 §4/§5/§6** — **RFC 179 — R2a imported the components and left the stylesheet behind. ACCEPTED and DISPATCHED 2026-11-07** (**P2**), §4 and §5/§6 in one cycle because §4 alone makes the gate vacuous. **Three corrections to the RFC while writing its handoff, all mine, all a matcher bounding its answer (§10.1): the denominator is 96 not 84 (the 9 computed sites add 12 names a literal grep cannot see); a third attribute form exists (`class=\\"…\\"` escaped in `format!`, 31 sites, all outside this scope); and `comm` on locale-sorted input returned 15/60 where `LC_ALL=C` gives 17/58 — the sums reconciled either way, so a reconciling sum is not validation.** Root cause now stated properly (§8.2): `BASE_CSS` already defines `.visually-hidden` with the **same clip-rect rule** at `chrome.rs:184-192` and the server templates use it successfully — so this is **two names for one behaviour, one styled and one not**, and converging them is §8 work. Answers the owner's question of whether RFC 131 R3's queue position holds: **it does not, and not for the reason anyone recorded.** The missing CSS is not R3's unstarted design work — it is the half of **R2a** (shipped 0.82.0) that was never imported, and `crates/ui/assets/base.css` at the **same pin `df3d9d0`** R2a took the components from already contains `.sr-only` at lines 86-94. `rfcs/done/135-wasm-under-csp.md` §4's *"presentation wiring is RFC 131 R3's"*, which the architect repeated twice in RFC 178, has been describing a missing file copy as unstarted design work for fourteen releases. **Six elements authored invisible render visible**, including `<p class="sr-only">"csrf: "{d.csrf_token}</p>` on `/admin/tenancy/tenants/:tid` — reachability traced end to end through `lib.rs:327` → `operator_json_api::shell` → `leptos_html_shell` → `app.rs:91` → `tenancy.rs:175`. **Not exploitable** (a CSRF token without the session cookie authorises nothing); it costs one layer of defence in depth to screenshots and screen-sharing, plus five pure-confusion defects. **The serving path is already built**: `Makefile:204` copies `static/*` → `dist/assets/`, the `<head>` is a `format!` in `leptos_shell.rs`, CSP is already `style-src 'self'` with no change, Trunk is not involved. **And §5 is the larger half**: RFC 178's gate asserts `ruleCount > 0`, which **a stylesheet containing only `.sr-only` satisfies** — so landing the fix bare would flip the gate from loudly-exempt to quietly-passing while **84 distinct class names** stay unstyled. It must become a census with a visible numerator (`84 = 1 + 83 + 0`), and §6 states up front that **9 `class=` sites compute their value in Rust** (2 of them `format!` over a caller-supplied prop, so **not statically enumerable**) and must be declared out by name — the exemption named as a deliverable rather than discovered after a red `main`, which is the mistake E7 made at 0.92.5 and RFC 178 §4 repeated **REVIEWED 2026-11-07, accepted, `c1535bb`, CUT READY.** Everything re-runnable reproduces: the rule `diff`s byte-identical against the mockup at `df3d9d0`, host 1,675/0/4/12 unchanged, E7 `156 = 8 + 31 + 117`, drift-scan clean, `migration_chain` 35, Worker bundle **889,049 B +77** with both sha256 prefixes matching the report. **Two findings, both advisory, and the substantive one is my spec's fault**: (A) the declared-out sites are grounded on *"no `<Badge` usage exists in scope"* **alongside** the correct non-enumerability reason — the usage clause goes false the moment R3 gives the primitives call sites, while the exemption stays correct, so a later reader finds half its grounds stale and deletes a still-needed declaration; (B) **"no call sites" is true of every imported primitive, not two** — `Badge`, `MetricChip`, `MetricStrip`, `Alert`, `Stepper`, `ScopeBreadcrumb`, `DensityToggle`, `EntityList` all zero — so if reachability were the criterion it would exclude **67 of the 96 names, not 2**: 29 live in `pages/`, 55 only in uncalled `components/`, and **all 12 computed names come from `components/` because all 9 computed sites do** (29 + 67 = 96). The gate reads ~3× worse than the user-visible reality and will score `components.css` as fixing classes that still never render. **RFC 179 §5's "used by the CSR markup" never distinguished present-in-source from can-reach-a-browser**; the team built the former consistently and their 96 is right for the spec given. **Also: Playwright 23, the live census and criterion #2 are `observed`, not `exercised`** — `trunk` cannot be installed here either, so I could not re-run them; their evidence drives all six sites, names each auth path, and reports two of its own methodology errors (`isVisible()` false-positives on clip-hiding; a race against the seeded invitation insert) |
| after 0.92.7 | patch | **Partition the RFC 179 census by reachability — the number currently overstates the gap by more than 2×, and the ambiguity is the architect's.** Finding B of `.git-exclude/reviewed/179-stylesheet-and-census-review.md`. The gate reports `96 = 1 styled + 95 not-yet-styled + 0 unclassified`, but **67 of those 95 cannot render at all** — they come from the 17 imported primitives, every one of which has zero call sites (R2a's own 0.82.0 entry: *"referenced by nothing yet"*), and all 9 computed-`class=` sites live there too, so all 12 resolved names are unreachable as well. Reachable today: **29** in `pages/`. Target shape: `96 = 1 styled + 28 reachable-but-unstyled + 67 unreachable (uncalled primitives, RFC 131 R3) + 0 unclassified`, `unclassified` still 0. Two reasons beyond tidiness: a reader reacts to the wrong number, and **when RFC 179 §8 imports `components.css` the gate will score as fixed a large set of classes that still never render.** Also fold in Finding A: drop *"no `<Badge` usage exists in scope"* from the declared-out grounds, or mark it explicitly as context — it expires when R3 lands while the non-enumerability reason does not, and a correct exemption whose stated reason goes stale first is the inverse of the trap these gates exist to close |
| after 0.92.7 | patch | **`trunk` cannot be installed on this machine, so one whole surface is unverifiable locally by anyone.** `cargo install trunk --locked` fails compiling `libdeflate-sys` (transitive and non-optional, via `oxipng`) against GCC 16.2.1 — a hard macro-expansion error in its SIMD template code, with no newer `libdeflate-sys` published; a `CFLAGS` relaxation and a dependency bump both failed, and executing a downloaded prebuilt binary was correctly declined rather than routed around the session permission policy. **Consequences, both now load-bearing**: (1) the frontend static asset's size and hash are unmeasurable here — **the long-standing `317,718 B` figure has never been independently confirmed, by the dev team or the architect**, and only CI's `Trunk release build` exercises it; (2) `wrangler deploy --dry-run` refuses to run without `crates/frontend/dist`, so even the **Worker** bundle needs an empty `dist` created by hand (sound only because `LEPTOS_JS`/`LEPTOS_WASM` are hardcoded consts at `leptos_shell.rs:85-86`, not read from it) — and the failed `make build-frontend` at the 0.92.6 cut **deleted** the stale `dist` that had been making the measurement possible; (3) `crates/frontend/index.html`'s dev-parity question and the whole browser suite are `observed` from the dev team's runs, never `exercised` by review. Options: pin a `libdeflate-sys` that builds, vendor a Trunk binary through an approved path, or replace Trunk's role with the `cargo build` + `wasm-bindgen` + `wasm-opt` sequence the dev team already proved equivalent for everything but the `-Oz` pass |
| after RFC 179 | patch | **The server-rendered half is mostly unstyled too, and nobody has measured it until now.** Found 2026-11-07 writing RFC 179's handoff, recorded as **RFC 179 §8.1** and scoped out of it deliberately. RFC 178 said the *end-user* app ships no stylesheet — true and incomplete. The server-rendered surfaces **do** have one, `BASE_CSS` in `templates/chrome.rs`, and it covers a minority of what they use: **75 distinct class names across `admin/`, `tenancy_console/`, `tenant_admin/` and `templates/`, against 22 class selectors `BASE_CSS` actually defines — 17 styled, 58 with no rule anywhere.** `btn-primary`, `card`, `data-table`, `badge-ok`, `alert-info` and 53 more render unstyled on the operator console today. **Needs its own measurement before a fix**: these directories write `class=\"…\"` **escaped inside `format!` strings** (31 sites), which the matcher used for the CSR census cannot see at all, so the 75 must be re-derived with all three attribute forms. **And it makes RFC 179 §8's consolidation a three-stylesheet question, not two** — `BASE_CSS` (server), the imported `base.css` (CSR), and RFC 176 §6.2/§6.3's typography tokens, with `design_tokens.rs` already duplicating four colour values across two of them, which is what made RFC 176 §6.1b necessary |
| ~~0.93.0~~ | **minor** | ✅ **shipped 2026-11-08, closing RFC 180 / RFC 131 R2b** — reviewed and accepted, `4b700b9` — **RFC 180 — ACCEPTED and DISPATCHED 2026-11-07**, once `0.92.7` was tagged (held until then deliberately: a minor's code on `main` would have forced RFC 179's patch cut to the higher level). **The handoff adds a triage table the RFC did not have**: a name-word-overlap heuristic over all 47 keys produced noise (`ConfigTitle ~ SecurityTitle` on the shared token "Title"), so it specifies comparing **rendered strings** instead and works six rows — one exact map (`SessionsTitle` is `SessionsPageTitle` in both locales), one map with an en-casing decision to record, three judgement calls, and **one trap: `ScopeTenant` must NOT map to `AdminScopeTenant`, whose string is parameterised ("Tenant: {slug}") — a name-similarity pass maps it confidently and ships a literal `{slug}` to a user**. Every candidate must be checked for substitution placeholders before mapping — R2b is 47 keys, not a catalog merge, and stopped being blocked on 2026-09-24. PROPOSED 2026-11-07, awaiting acceptance** (**P3**). The scoping proposal RFC 131's R2b correction owes. **RFC 132 §13 q1 reads ANSWERED (2026-09-24) and says "R3 is no longer blocked"**; RFC 131's R2b paragraph still said *"deferred ... on 2026-09-09"* and the architect cited that stale line **to the owner in conversation** as live evidence of an unanswered dependency. q1's answer is also the input R2b needed: pre-auth is server-rendered, so a reactive locale hook was never a candidate for `auth_shell.rs` and the conflict dissolves. **Measured, the scope is 5× smaller than RFC 131 describes**: the ten i18n-using files reference **47** distinct keys, not 263, and **exact-name overlap with core's catalog is 0**, so nothing collides. **RFC 131's "175" is stale — core has 171** (census reconciled to 247 raw lines, 0 unaccounted; the mockup's 263 reconciled to 363). Core is rich exactly where the shells are not (19 `Sessions*`, 28 `Security*`, 19 `Audit*`) and **empty** where they are (`Config`, `Tokens`, `Operations`, `Scope*`, `Terms`, `Privacy`, `PoweredBy`, `Suspended*`, `PermissionDenied*`: zero each). **`auth_shell.rs` — the file the whole deferral rested on — needs four strings**: `PoweredBy`, `Privacy`, `Status`, `Terms`. Direction: **delete the mechanism rather than import it** — no second `Locale`, no `Msg`, no reactive `LocaleContext` (that second catalog is what ADR-013 declined); the locale is **already in the DOM** since `leptos_html_shell` emits `<html lang>`, so read it once at mount and extend `MessageKey` additively. Noted while measuring: **the CSR app has no locale handling at all** and hardcodes both languages at once — `clients.rs:350` renders `"操作"` while `sessions.rs:96` renders `"Actions"`, in one tree |
| **R3's handoff, as a required section** | — | **Six sidebar destinations in R2b's shells have no registered route.** `/admin/console/investigate`, `/admin/tenancy/users`, `/admin/t/:slug/{roles,groups,oidc-clients,audit}` — verified at review by diffing all 27 comment-stripped path literals in the new components against `lib.rs`. **Harmless now** (dormant, nothing routes them) and correctly out of RFC 180's scope, but **six sidebar links 404 the moment R3 mounts these shells**. Named in inline comments today, which is the wrong home: R3 will be editing those files and needs it in the handoff. **Nothing to build** — this is a note that must reach R3's dispatch |
| after RFC 168's backstop | patch | **Share route constants between backend and frontend — the RFC 108 exclusion now has evidence, not just principle.** `drift-scan.sh`'s RFC 108 check excludes `pages/`, `app.rs` and now `*/components/*` (widened at RFC 180, correctly: same CSR reasoning, latent only because `primitives/` has no `href`). Its comment has promised a follow-up RFC on shared route constants since RFC 108. **RFC 180 is the measured case**: 27 live path literals in the new shells, **three wrong and fixed by hand** (`/admin/console/dashboard`, `/admin/t/{slug}/overview`, `/me/sessions`), **six pointing at routes that do not exist**, and **zero of the nine caught by any gate**. Also one route written two ways in two files — `/admin/t/{s}/roles` and `/admin/t/{tenant_slug}/roles` — two conventions inside one cycle, which is what a shared constant prevents. Sequence after the backstop |
| after RFC 168's backstop | patch | **`for_each_key`'s exhaustiveness pin and its iterated array are not checked against each other** — `crates/core/src/i18n/tests/lookup_completeness.rs`. The `match` arm pins every variant (a compile error if one is missed); a **separate** hand-written `let all = […]` array is what the completeness and dedup tests actually iterate. **Only the pin is enforced**: a key added to it but omitted from the array compiles, passes both tests, and is silently uncovered by the two tests whose entire job is completeness. RFC 180 added 41 keys by hand to both lists and got it right — verified at review, all three sets identical at **212** — but nothing made them. Fix: assert the two agree, or derive the array from the pin with a macro |
| after 0.92.7 | **minor** | **RFC 180 — RETURNED 2026-11-08, implementation report filed at `.git-exclude/review-request/180-r2b-catalog-and-import-report.md`, awaiting review.** All ten files landed under `components/{shells,nav,domain}`, dormant; the mockup's locale mechanism deleted, not imported (`LocaleToggle` included — a live switcher, barred regardless of fixed-vs-reactive). The triage closed at **`47 = 6 mapped + 41 added + 0 unresolved`** — one mapped key beyond the handoff's own six pre-flagged candidates (`TenantAdminInvitations` → `TenantInvitePageTitle`, found only by sweeping the full catalog for exact-string matches, not the named candidates), and the `ScopeTenant`/`AdminScopeTenant` trap avoided (checked, added, not mapped). Host tests **1,677/0/4** (+2, the two `auth_shell` rendered-string tests — the 41 new variants add no test count on their own since the completeness tests are not per-key parameterized). RFC 179 census **96 → 136** (static arithmetic only; live Playwright still blocked by the same `trunk` failure RFC 179 disclosed), with two new computed-class sites and one new non-enumerable site folded into `stylesheet-presence.spec.ts`'s own constants. Worker bundle **889,072 B → 890,352 B, +1,280 B**, attributed entirely to `cesauth-core`'s i18n growth — none of R2b's CSR files reach the Worker build at all (`components` is `csr`-gated like `app`/`pages`). **Two findings along the way, both fixed in-cycle, neither a scope change**: `drift-scan.sh`'s RFC 108 hardcoded-URL check had never excluded `components/` the way it already excludes `pages/`/`app.rs` for the identical stated reason (`components/primitives/` never had an `href` before R2b's shells); and three of the mockup's own hrefs disagree with what the worker actually registers (`/admin/t/{slug}/overview` vs `/admin/t/:slug`, `/admin/console/dashboard` vs `/admin/console`, `/me/sessions` vs `/me/security/sessions`) — corrected rather than carried forward, since nothing requires preserving a mockup bug. Six other links (tenant roles/groups-list/oidc-clients/audit, operator cross-tenant-users-list, console `/investigate`) have no backend route to point at and are left named as placeholders, not routed around |
| ~~0.92.4~~ | patch | ✅ **shipped 2026-11-04, closing RFC 175** (**P2**, downgraded at review by the architect who wrote the P1) — `POST /admin/console/tokens/:id/disable` returns success for an id that does not exist or is already disabled, because the adapter never asks whether the `UPDATE` matched a row, and the handler then writes **`AdminTokenDisabled` into the hash-chained audit log**. Its `Err(PortError::NotFound) => 404` arm is already written and **cannot fire**. **Bounded**: no live token stays valid while the operator believes it was revoked, so this is an integrity defect in the record, not an exposure; reachable only by a script or direct API client — **the architect's "stale list page" claim was wrong**: `GET /admin/console/tokens` renders zero forms, never mentions `/disable`, and the route is bearer-header-only. **Found by RFC 171's census on first use, in a trait that RFC never examined.** Carries the `create` sibling — plain `run_err` against a real `UNIQUE` column, so the *"token hash collision"* arm the architect had built is dead too |
| ~~0.92.6~~ | patch | ✅ **shipped 2026-11-07** — **RFC 176 §6.1 `9b7dadd` + §6.1b `aa113e1` + RFC 177 `be285c8`, all reviewed, CUT READY** — §6.1 first fixed the ADMIN surfaces only: `templates/chrome.rs` carries its own copy of the four semantic tokens with the pre-fix values, so `/`, `/login` and `/me/security` still read success 3.11 and warning 3.76, both failing AA. The architect's own §6.1 handoff said "do not change any template's inline CSS", excluding by name the file carrying the half the owner asked about. §6.1b dispatched 2026-11-04 to bring `chrome.rs` to parity and widen the gate to both files; CUT HELD for it** (**P2**); **§6.2+§6.3 are a minor and not yet dispatched**; the layout/user-flow half stays unsized — measured, not reviewed, answering the owner's question about older users. **Five of nine semantic colour pairs fail WCAG AA for normal text** (`--success` 3.11, `--warning` 3.76 light; `--danger` 3.62, `--info` 4.07 dark; `--scope-tenant` 3.49 on white) and only one reaches AAA — **and the axe `wcag2aa` gate passes because it loads only `/` and `/login`, where these tokens never render.** `design_tokens.rs` has **zero typography tokens**; 13 distinct font sizes across four units, the commonest being **12px/13px/0.8em/0.85em**, and `px` ignores the browser default-font-size preference an older user is most likely to have changed. `min-height` appears nowhere, and the commonest control padding `2px 8px` yields a target **~18px tall against a 44px guideline**. §6 orders the fixes: the contrast arithmetic gate first (no browser, closes a class), then `rem` typography tokens with a 1rem floor, then a control-height floor. **The layout/user-flow half is explicitly not sized** — it needs the real screens driven, which 0.92.2's credentialed job now makes possible |
| ~~0.92.6~~ | patch | ✅ **shipped 2026-11-07** — **RFC 177 §4.1+§4.2 — ACCEPTED and DISPATCHED 2026-11-04** (**P2**); **§4.4 remains OPEN — acceptance did not close it, because the RFC offered two options and picked neither**; §4.3's measurement belongs to RFC 176 §6.3's minor — the half of the owner's frontend question RFC 176 §6 refused to size, now **measured by driving the running screens in Chromium** rather than reading the stylesheet. **`/me/security` leads with its most destructive action**: *"Request account deletion"* is the first `h2` a user reads **and the first control they reach by keyboard**, ahead of two-factor and sessions — on the page people visit to protect an account, at 17 px tall. No stated rationale; it reads like accretion. **`/login`'s first control is *"Sign in with passkey"***, a credential no user can currently create (RFC 172 required a session, RFC 174 confirmed no console affordance, RFC 131's surface is unbuilt) — so the working email path is two tab stops behind an unusable one. Also: **every focusable on all three measured pages is under 44 px, smallest 17 px**, which is the rendered-page evidence RFC 176 §5 inferred from padding. Three things already right and named as such: heading levels well-formed, every input labelled, screens genuinely sparse. **§5 understated its own cost and §5.1 corrects it**: the browser suite is anonymous-only (`PUBLIC_ROUTES = ['/', '/login']`), `/me/security` 302s without a session, and neither frontend page has a single `#[test]` — so the ordering gate needs a credentialed browser context the suite has no path to, and the handoff says report the estimate rather than half-build one. **The open question for the owner: does `/login`'s passkey button move behind the email path until registration exists, or does registration get built?** |
| after 0.92.x | patch | **No gate budgets the artifact that is the user interface.** `bundle-size.yml` explicitly excludes `crates/frontend/dist` as "a build product" and `trunk-release-build.yml` only `test -f`s the filenames, so `cesauth-frontend_bg.wasm` — **317,718 B gzip, a third of the Worker's 889 KB** — has no budget while the Worker's does. Found when RFC 177's reorder moved the frontend wasm by +180 B and left the Worker's unchanged, because those pages are CSR-only: **the architect's handoff predicted the wrong artifact would move.** Third instance of the same shape, with the axe gate's two anonymous pages and the token file that is not the user's |
| ~~0.92.6~~ | patch; **§3 is ANSWERED — the stylesheet was never lost** | ✅ **shipped 2026-11-07** — **RFC 178 — gates `dd64ee2` + §4b `5c08bcd`, both reviewed; the two gates now REPORT instead of blocking and the cut is unblocked.** The Playwright gate carries a dated `KNOWN_NO_STYLESHEET` naming `/` and `/login`, `E6_BEARER_LEGACY_EXEMPT`'s shape, with **three outcomes not two**: exempted-and-unstyled passes *and prints* every run, exempted-and-styled **fails** until the entry is removed — verified by the architect by forcing the branch — so the exemption is self-liquidating and the gate enforces permanently once R3 lands. The trunk step is **reported, not enforced** (RFC 142's precedent) with its `exit 1` commented and a note on when to restore it. Both are in `contributing.md`'s gate table, because a gate whose enforcement status lives only in a spec file is the next thing to be rediscovered. **§0 added at review: the finding was already on record twice** — `rfcs/done/135-wasm-under-csp.md` §4 (*"no stylesheet exists … Presentation wiring is RFC 131 R3"*) and RFC 131 (*"Axe reports zero violations on a page with no CSS, so contrast, focus-visible styling and target size are untested by construction rather than passing"*). Those two paragraphs contain RFC 178 §1's measurement, §2's two-paths explanation, RFC 176 §3's two-page gate scope and RFC 177 §1's sizes; **the architect measured three times instead of reading the record once.** **RFC 178's contribution is the gates, not the finding** — RFC 135 recorded the gap in prose and nothing failed for months — plus `sr-only`, the one consequence neither prior RFC names: with no stylesheet, screen-reader-only text is shown to everyone. **The owner's decision is now narrower and better posed: does RFC 131 R3's position in the queue still hold**, now that the gap is gated and visible? R3 owns `/` and `/login` and their presentation wiring, so the stylesheet is that slice, not a side task |
| after RFC 180 | minor | **RFC 131 §0 slices 1–2** — the audit browser with the export form that already exists, and chain status. The two incident-response surfaces **Re-keyed from `0.93.0` 2026-11-07 (RFC 181 §7): scope is no longer pinned to a predicted version number**, because minors are now the default and advance on every cut — RFC 180 ships before this and would have taken `0.93.0`. Number assigned at the cut |
| after RFC 131 §0 slices 1–2 | minor | **RFC 166 §3 census** — re-scope at dispatch: it was written to count caller-less core services and frontend views, and has since collected the two caller-less `tenant_detail::{suspend,restore}` routes (**a registered route no caller invokes** — neither E4 nor E5 can see that shape), the dead `tenant_admin/invitations.rs` module, `admin::safety_page` and `tokens.rs`'s `list_page`/`created_page` family, and a core doc comment claiming a service hands a report to a view nothing calls. Four shapes, not one. **Distinct from RFC 171 §3 Q1 and not to be merged with it** — this row asks whether a definition has a caller; that one asks whether a matched variant has a producer Re-keyed from `after 0.93.0` 2026-11-07, RFC 181 §7; level is minor by default unless a patch argument is made at dispatch |
| after RFC 131 §0 slices 1–2 | minor | **RFC 163** — the duplicate-route test's needle, plus a non-zero-count assertion Re-keyed from `after 0.93.0` 2026-11-07, RFC 181 §7; level is minor by default unless a patch argument is made at dispatch |
| after RFC 131 §0 slices 1–2 | minor | **RFC 131 §0 slices 3–6** — safety, alerts, cost, config Re-keyed from `0.94.0` 2026-11-07, RFC 181 §7 |

**Scheduling rule, after getting it wrong (2026-11-01):** patch work is listed **against the minor it follows**, never against a reserved patch number. A row reading `0.90.x` carried **RFC 165 §3** into a release that never happened — the sequence went 0.90.0 → 0.91.0 — and the work slipped two releases silently. `contributing.md` already says patch numbers are assigned at each cut, not reserved; the table was contradicting it.

**Not in this sequence, and said rather than omitted:** **RFC 133 half B needs
no decision** — it is parked behind 1.0, which is not declared, not scoped and
not dated, and §15's new datum states in its own words that it changes nothing
in the schedule. Carrying it as *"awaiting an owner decision"* was the
architect's error, corrected 2026-10-31. **RFC 151's open question is answered**
(§6, 2026-10-31): the rule stands, and its back-fill is **eight P0/P1 RFCs in
`done/` with no evidence term** — the architect's own work, not release-bound,
and RFC 151 stays in `accepted/` until they are done. RFC 158 §5.5's two items, RFC 166's census
stage, the `/admin/tenancy/*` half of RFC 161's condition, and RFCs 110a, 112,
119–124 and 144 are likewise unscheduled.


- ✅ **v0.81.1 — RFC 125 (+ condition C1), RFC 127, RFC 126. Shipped
  2026-09-03, one patch release.** Originally planned as three releases
  (0.81.1/0.81.2/0.81.3); reconciled to one because no intermediate commit
  ever set `Cargo.toml` to 0.81.1 or 0.81.2 — retro-tagging would have
  contradicted the project's own "workspace version is the single source of
  truth" invariant. The CHANGELOG entry is sectioned per RFC so the
  boundaries remain legible even though they no longer correspond to
  separate tags.

  **RFC 125 — release-gate integrity restoration.** Repairs the CI gates
  broken by the RFC 114 crate rename: four of nine workflows had been
  failing at invocation or enforcing a rule the tree never satisfied, so the
  "full host suite green" gate every assurance RFC below names as its step
  boundary was not actually running. Adds `cesauth-frontend` (280 tests) to
  the gate set — it had no CI coverage since the rename, making the real
  host suite 1,233 tests rather than the 953 previously reported. Owner
  decision recorded in RFC 125 §13 Q1: `fmt.yml` is dropped and
  hand-alignment is house style; RFC 029's conclusion is amended accordingly.
  Condition C1 (documenting the 23 routes the repaired contract gate found
  undocumented) closed before this release cut. **Blocks:** RFC 117 and the
  rest of the assurance track — now unblocked.

  **RFC 127 — CSR bundle buildability.** The Leptos CSR browser bundle could
  not be built — `cargo check -p cesauth-frontend --features csr --target
  wasm32-unknown-unknown` failed with 79 errors — and no CI gate covered it.
  Not dead code: `leptos_html_shell` is called from `/me/security`,
  `/me/security/sessions`, the TOTP verify/disable gates, invitations and
  deletion requests, with **no server-rendered fallback**, so a deploy from
  this tree served those screens an empty root div. Fixed: the missing
  `wasm-bindgen` dependency, 26 `<Route path="…"/>` calls migrated to
  `path!()`, and Trunk now actually passing `--features csr`. New blocking
  gate `csr-bundle-check.yml`. **Not fixed by this release:** `trunk build
  --release` still fails at `wasm-opt`, and the artifact names Trunk emits
  do not match what the backend expects — RFC 127's acceptance criterion 3
  was formally not met. **RFC 130 (v0.81.2, below) closed this criterion.**

  **RFC 126 — documentation rename sweep + drift-scan rule.** 56 stale
  `crates/worker` / `cesauth-ui` references across 19 non-ADR files fixed,
  including a deployment guide that documented a build path no longer in
  existence. `drift-scan.sh` gains a crate-name rule with a path-exclusion
  mechanism (ADRs and archived changelogs excluded as historical records).
  **Known gap, deliberate:** the exclusion also covers `crates/` itself,
  hiding 25 stale doc-comments in Rust source pending a follow-up RFC. D5
  (adding `ROADMAP.md` to the scan paths) is not included — it would
  surface the then-unresolved Management-GUI scope contradiction and ship
  a knowingly red gate. **Ungated 2026-09-09:** the owner ruled the operator
  console first-class and the contradictory line is gone, so D5 can now land
  green. Scheduled with the console programme.

- ✅ **v0.81.2 — RFC 130 (+ condition C1-130). Shipped 2026-09-05.** Closes
  RFC 127's acceptance criterion 3 (open since v0.81.1): the Leptos CSR
  bundle can now actually be built and deployed, not merely compiled.
  `trunk build --release` was failing at `wasm-opt` (rustc 1.98 emits
  bulk-memory wasm by default; Trunk's pinned Binaryen rejects it and
  exposes no way to pass the enabling flags — measured first against the
  newest available Binaryen release, which fails identically, before
  building the fix), and the artifact names Trunk emits never matched what
  `crates/backend/src/routes/leptos_shell.rs` hardcodes. Both fixed:
  `make build-frontend` disables Trunk's optimize step and runs `wasm-opt`
  itself with the required flags (Binaryen fetched directly from the
  upstream release, **checksum-verified per platform before extraction** —
  condition C1-130, closed same release), and `--filehash false` plus
  corrected constants make the names match. New blocking gate
  `trunk-release-build.yml`. Toolchain pinned for the first time
  (`rust-toolchain.toml`, 1.98.1, measured against the full gate set before
  pinning — not asserted); every CI workflow reconciled to it. First
  recorded bundle measurements in `BUNDLE_SIZE_BUDGET.md`:
  879,980 B → 750,151 B (`-Oz`) → 262,744 B gzipped. **Still not
  delivered:** confirmation that the bundle actually mounts in a browser —
  every check here is build-time; RFC 131's harness adoption closes that.

- ✅ **v0.81.3 — RFC 128 (+ conditions C1-128, C2-128). Shipped
  2026-09-08.** `docs/src/deployment/observability.md` told operators that
  audit events are R2 objects with R2 query patterns and R2-lifecycle-managed
  cost. They have been D1 `audit_events` rows with a SHA-256 hash chain since
  v0.32.0 (ADR-010) — roughly 49 versions. Rewritten against source: the real
  14-column shape, the real query surfaces (console filters — `kind`/`subject`
  substring, `event` exact, silent-drop on invalid `from`/`to` — export,
  chain status/verify, `wrangler d1 execute`), and the real cost mechanism
  (`audit_retention_cron`'s two operator env vars, not an R2 lifecycle rule;
  cesauth's Worker makes no R2 API calls at all — the `ASSETS` binding is
  vestigial, and the frontend bundle is served by Workers Static Assets, a
  different product). New `drift-scan.sh` rules catch the two core stale
  claims should they reappear. Documentation only — no route, schema, or code
  changed. Two review-caught corrections landed before this shipped: the
  first rewrite introduced five new inaccuracies (wrong R2 service named,
  inverted filter-exactness claims, missing export caveats, a masked-IP note
  on the wrong column), and a second pass then found the `admin_*`
  enumeration undercounted (five listed, ten real) and a mislabeled
  reason-string example. **Recorded for v0.82.0:** `ip` and `user_agent` are
  now documented as always NULL — the builder methods that would populate
  them have zero callers — because populating them is a real product
  decision (an unmasked IP in an audit row), not a documentation fix.

- ✅ **v0.82.0 — RFC 134 (+ condition C1-134), RFC 132 (+ conditions
  C1-132, C2-132), RFC 131 R2a. Shipped 2026-09-10.** Every release since
  v0.79.6 (2026-07-07 — eight tags) shipped a Worker whose router panicked
  on construction, on every request, before any handler ran: three route
  patterns put a `.json` suffix on a parameter segment, `matchit` rejected
  the pattern, and `worker` turned the rejection into a Rust panic instead
  of a recoverable error. Found by RFC 131 R5's M1 baseline check on its
  third attempt — the first time in 120 shipped RFCs anything booted the
  runtime and issued a request. **RFC 134** reshapes the three patterns
  (`.../:tid/detail.json` and siblings — the one route-string change this
  project has made outside a minor-version contract, justified because
  none of the three ever served a request), pins `worker` to the version
  a new runtime smoke gate passed on (`=0.8.3`), and adds that gate:
  `scripts/runtime-smoke-check.sh` boots `wrangler dev` and asserts
  content and headers (never status alone) on six requests, blocking in
  CI, no Cloudflare credentials needed. **Condition C1-134** closed a
  second, independent defect the fix surfaced: `leptos_shell.rs` always
  requested its JS/wasm bundle at `/assets/...`, but built output landed
  at `dist/`'s root, so every asset 404'd and Leptos never mounted, on
  every client-rendered surface. Built output now nests under
  `dist/assets/`, and the smoke gate parses every asset URL out of the
  served HTML rather than checking a hardcoded list. **RFC 132**
  establishes cesauth's first working rendering policy — mode derived
  per surface (Q1-Q4: can the user route around a failure, is it
  pre-auth, does it need client interactivity, is it machine-facing) —
  after the prior *stated* policy ("server-side rendering only") was
  silently abandoned by the Leptos CSR migration with no replacement
  written. All 188 routes now declare a `Rendering` value, and a
  `server`-declared route's handler is asserted (by resolving to its
  actual defining function, not a name match — catches re-exports) to
  never call the Leptos shell. Three conformance gaps remain, named and
  exempted rather than hidden: `/`, `/login`, and
  `/me/security/totp/verify` — the last on the only path a no-JS TOTP
  user has to complete sign-in, so RFC 131 R3 must fix it alongside
  `/login`, not separately. **RFC 131 R2a** imports the mockup's
  mechanism-free presentation foundation (`view_models`, `icons`, 17
  i18n-free primitives; ~1,489 LOC) as dormant modules inside
  `crates/frontend/src/` — a merge, not a new crate — pinned at the
  mockup's `df3d9d0` (v0.14.0). **Minor**, not patch: 134 and 132 are
  each fixes on their own, but R2a's new module surface and the new
  blocking smoke gate are added capability. **Not claimed:** that the
  app mounts in a browser (nothing has run JavaScript; RFC 131 R5 owns
  that) or that it works on Cloudflare (observed under Miniflare only).
  RFC 131 itself stays in `accepted/` — R2a shipped, R2b/R3/R4/R5b–e have
  not.

- ✅ **v0.83.0 — RFC 135, RFC 136 (+ conditions C1-136, C2-136), RFC 129
  (+ condition C1-129), RFC 131 R5b–e (+ condition C1-R5). Shipped
  2026-09-13.** **The application could not run.** Every client-rendered
  surface served a blank page: the browser refused to compile the WASM
  bundle, because a `script-src` carrying only a nonce authorises the
  bootstrap *script* and not the *module* it instantiates, and cesauth's
  CSP had never granted `'wasm-unsafe-eval'`. Ten `curl` assertions rated
  that healthy — assets 200, CSP header present, no panic — because curl
  does not execute WebAssembly. **RFC 135** adds the directive to the
  Leptos shell's own CSP and nowhere else (scope follows by construction:
  only routes calling `leptos_html_shell` receive it, and RFC 132's E3
  asserts no `server` route does), amends ADR-007 with the distinction
  between `'wasm-unsafe-eval'` and the still-barred `'unsafe-eval'`, and
  mounts into `#root` via `mount_to(...).forget()` — the shell had claimed
  `#root` since it was written while `mount_to_body` appended to `<body>`.
  Found by RFC 131 R5's M2 probe, the first time anything opened cesauth in
  a browser. **RFC 136:** the deployed crate's 159 tests did not compile —
  36 errors, all ordinary API drift — behind an exclusion whose stated
  reason ("requires the wasm32 target and worker-build toolchain") covered
  two of them; no test in either excluded crate is wasm-only. Both crates
  now run in CI, doc-tests and integration targets included, which also
  restored `cesauth-frontend`'s 4-test acceptance harness. Its C1/C2
  conditions repaired the RFC 008 audit-secret invariant, which had
  **never once executed** since v0.50.2: it searched two directories above
  the repository root, and its fixed eight-line scan window read past each
  `audit::write` call into the next statement. It now holds across 413
  files, and proves its own scanner every run. **RFC 129** closed
  drift-scan's `crates/` blind spot — the gate could not see the largest
  directory in the repository — and added `ROADMAP.md` to the scan.
  **RFC 131 R5b–e** is **the first browser-level verification in this
  project's history**: 20 Playwright tests asserting the layer curl cannot
  reach (WASM instantiation, Leptos mount, thrown errors, axe WCAG A/AA,
  duplicate ids, tab order, 375 px layout, and that no workbench-only
  markup from the mockup reaches served output). Three of the mockup's
  seven specs did not survive contact and were dropped or replaced rather
  than adapted into something vacuous. C1-R5 installed Trunk in the two CI
  jobs that invoked it without it — so RFC 134's deploy-path gate and
  RFC 135's runtime smoke gate had never been able to start — and pinned
  it, `worker-build`'s floating-version failure having already cost a
  release. **Minor**, because R5 is added capability; 135, 136, 129 and
  C1-R5 are fixes. **Not claimed:** that the frontend works (one rendered
  page, one engine, unauthenticated, no interaction beyond Tab), that it is
  styled (no stylesheet exists in the tree, so axe's zero violations say
  nothing about contrast, focus-visible or target size — RFC 131 R3), that
  it works on Cloudflare (**nobody has deployed this tree**), or that
  RFC 134's and RFC 135's CI gates have run — C1-R5 makes their first
  execution possible and it has not happened. `mdbook build docs` is in no
  workflow at all (RFC 138), and the browser suite is non-blocking until
  0.84.0. **RFC 137 is open:** `/token` authenticates no client and binds
  no authorization code to the client it was issued to, both mandated by
  RFC 6749 §4.1.3; PKCE is the only binding left, and it ships next
  release. RFC 131 stays in `accepted/` — R2b/R3/R4 remain.

- ✅ **v0.83.1 — RFC 137 (+ condition C1-137), RFC 138 (+ condition
  C1-138). Shipped 2026-09-15.** **`/token` authenticated no client.** A
  confidential client's secret was never checked, and codes and refresh
  families were bound to their client by PKCE alone. **RFC 137:** both
  grants now authenticate a confidential client before consuming anything;
  a client with no stored secret is public only if registered public; a
  wrong-client redemption consumes the code and is refused, and a
  wrong-client refresh revokes the family. C1-137 closed three standards
  gaps: one authentication method per request, no body `client_id` needed
  under Basic, and `WWW-Authenticate` on `invalid_client`. **RFC 138:** CI
  runs `mdbook build` with `create-missing = false`; wrangler is pinned at
  4.131.2 and called only as `node_modules/.bin/wrangler`, which fails
  loudly without `npm ci` (C1-138 found `npx wrangler` silently falls back
  to a cached or latest copy); tool-installing Actions are pinned;
  drift-scan reads workflows; clippy covers all six crates. **Patch** —
  both are fixes. **Not claimed:** that refresh tokens are safe (they never
  expire — RFC 139, open by the owner's choice), that the registered
  authentication method is enforced (a public client is accepted whatever
  secret it presents), that every rejected authentication is audited, that
  the new or changed CI gates have run in CI (the workflow YAML is
  unvalidated), that every tool is pinned, that the operations docs call
  the pinned wrangler, or that it works on Cloudflare (Miniflare only;
  nobody has deployed this tree).

- ✅ **v0.84.0 — RFC 139 (+ condition C1-139), RFC 140, RFC 131 R5f.
  Shipped 2026-09-22.** **Refresh tokens never expired and login
  challenges outlived their expiry.** **RFC 139:** a refresh family now
  ends at the earlier of an absolute cap (`REFRESH_TOKEN_TTL_SECS`) and a
  new idle window (`REFRESH_TOKEN_IDLE_TIMEOUT_SECS`, 14 days, `0`
  disables), enforced by the store at rotation, revoking and recording
  which deadline ended it; no deadline is stored, so lowering a lifetime
  takes effect immediately; the unsigned expiry has left the token, and
  introspection reports the family's real deadline instead of the
  presenter's number. C1-139 corrected six documents that said an invalid
  pair stops the worker starting — it does not: the deployment succeeds and
  every request that loads configuration then fails with 500. **RFC 140:**
  both challenge stores treat an entry at or past `expires_at` as absent
  against a caller-supplied clock, an expired take deletes, and the
  Durable Object alarm no longer swallows a failed delete. **RFC 131 R5f:**
  the browser suite's one-release non-blocking window is closed in the
  workflow and the documented gate set. **Minor** — RFC 139's idle window
  is a new control; 140 and R5f are fixes. **Not claimed:** that any CI
  gate is enforced (`main` has no branch protection at all, so no check is
  required, including the browser suite), that the new or changed gates
  have run in CI, that the Durable Object's read-time expiry check is
  live-verified, that WebAuthn challenge expiry is tested, that expired
  families are swept or audited distinctly, or that it works on Cloudflare
  — **nobody has deployed this tree**. Refresh tokens issued before this
  release no longer decode.

- ✅ **v0.84.1 — RFC 117 (+ condition C1-117). Shipped 2026-09-22.**
  **Minting a token before its checks is now a compile error.** The
  authorization-code exchange became a typestate pipeline: the client
  authenticates, the code is consumed, it is bound to that client, the
  redirect URI is matched, PKCE verifies — and only then does the value a
  token is minted from exist. Skipping a step, minting early, consuming a
  code before authenticating (C1-117), building the mint input by hand, or
  using it twice all fail to compile rather than failing a test. With it
  came the first property-based tests for PKCE and for the challenge
  store's contract, and a contract clause saying an expired-but-never-taken
  entry still occupies its handle. **Patch** — no wire change, nothing
  added, nothing fixed; every response is what 0.84.0 returned and no
  existing test was edited. **Not claimed:** that the refresh path is
  protected (RFC 118), that one-time use is newly guaranteed (the store
  already guaranteed it; the Durable Object is not host-testable), that the
  types prove the client authenticated against its true stored record, that
  any CI gate is enforced (`main` still has no branch protection), or that
  it works on Cloudflare — **nobody has deployed this tree**.

- ✅ **v0.92.5 — RFC 171 §3 Q1's check (E7): a method's caller-matched `PortError` set must be a subset of what its production adapter can return, asserted on every push. Before this a handler could branch on an error nothing produced and every gate stayed green — which is how six operator messages, three API status codes and an invitation acceptance were lost. 156 methods = 8 resolved + 31 DEFECT + 117 no_caller, the 31 split into 5 `written` and 26 `chokepoint` and exempted by name, so a *new* written defect fails the build. Also the first byte-driven CHANGELOG archive split, which left four minor series against the rule that says five. Shipped 2026-11-04.**
- ✅ **v0.92.4 — RFC 175: disabling an admin token reported success without checking whether the `UPDATE` matched a row, and wrote `AdminTokenDisabled` into the hash-chained audit log for an action that did not happen. Found by RFC 171's producer census on its first use, in a trait that RFC never examined — which is the census earning its cost. Severity corrected during review from P1 to P2: the route is bearer-header-only with no console affordance, so no operator could reach it by clicking. Shipped 2026-11-04.**
- ✅ **v0.92.3 — RFC 174(b): the log-level apply action is gone, and so are the two modules that existed only to serve it. The action wrote to an undeclared KV namespace, nothing would have read the value, and it then wrote an audit row saying the level was applied — but probing it first showed the console renders no such control at all and the route answered 400 before reaching either, so the architect's own P1 became a P2 and the RFC carries the correction. Deleting it left `core::admin::preview` and `frontend::admin::preview` wholly caller-less, and an architect instruction to keep part of the cluster was reversed when its stated future consumer turned out never to have used it: 682 lines and 19 tests deleted, recoverable from a named commit. Routes 194 → 192; the bundle falls below 890 KB for the first time. Shipped 2026-11-03.**
- ✅ **v0.92.2 — RFC 170 both halves + RFC 173: CI can drive a credentialed flow for the first time, which closed RFC 147's deletion sweep at `exercised` and restored RFC 152 half A's admin-cookie witness — and on its very first rehearsal found that `session_index_audit` had never read a row since 2026-05-06, because it bound an `i64` into D1 as a BigInt, and that its error path returned `Ok`, so the operator-facing cron status recorded a successful driftless pass every day for six months. Zero drift is also what a working detector reports, so there was nothing to notice. Nor had any cron pass ever been recorded at all: `record_cron_pass` named a KV binding this project does not declare. Shipped 2026-11-03.**
- ✅ **v0.92.1 — RFC 172 (P0) + RFC 152 half D stage 1 and 1b + RFC 028's archive split: `POST /webauthn/register/start` read the account it was registering a passkey for out of the request body, with no credential of any kind, and `register_finish` then issued a session for it — account takeover in two unauthenticated requests, given a user id. Exposure was none because nobody has deployed this tree. Found by half D stage 1, which recorded *"no ambient credential is ever consulted"* as a correct CSRF justification without noticing the sentence was the whole defect. Half D also found that the control three rows had just documented did not hold — `.contains("application/json")` matches a parameter, and `text/plain; x=application/json` is CORS-safelisted and preflight-free — which had been true of `/me/security/delete-account` since RFC 149 §2. Shipped 2026-11-03.**
- ✅ **v0.92.0 — RFC 141 cycles 2 and 2b: the OIDC clients screen, the CSRF control its four write routes documented and did not have, and a duplicate value that answered 500 everywhere the primary key is the uniqueness constraint. Ten shipped paths branched on a `Conflict` the classifier could not produce — six operator messages that could not be displayed, three API responses answering 500 where they document 409, and an invitation acceptance lost permanently — and one `||` repaired all ten. Nothing caught it because the in-memory test double returned the right error and the D1 adapter did not, which is now RFC 171. Shipped 2026-11-03.**
- ✅ **v0.91.2 — RFC 164 + RFC 168 + RFC 165 §3: three rules written down and never gated now have gates — `rfcs/` cross-reference links, tag-to-CHANGELOG reconciliation both directions, and staleness on four exemption lists. Six links had rotted in during the six days the sweep was being run by hand, one of them swept past by the architect's own grep. And the new checks could not have run in CI at all: no workflow fetched tags. Shipped 2026-11-03.**
- ✅ **v0.91.1 — RFC 169: the book did not contain eleven of its own eighty pages, and one page already in it linked twice to one of the missing ones under the words "Enforced by". Nine are in, two are declared out with reasons, and `drift-scan.sh` now fails when a page leaves the book or an in-book link stops resolving. Shipped 2026-11-01.**
- ✅ **v0.91.0 — RFC 152 half C: the operator console made the same `required` claim, on seven rows. Three forms got the token, five JSON endpoints now reject a cookie outright, and E6 grew from "required implies a verify call" into a census that checks the control each cell names and fails on a cell it does not recognise. Its first run found an eleven-row cell naming a CORS preflight that never happens. Shipped 2026-10-31.**
- ✅ **v0.90.0 — RFC 152 half B: the admin surfaces get the CSRF control their documentation claimed. 34 `POST` routes verify a double-submit token, E6 fails the build if any row claiming `required` stops being true, and `GET /admin/login` no longer sets a session cookie for a token it never validated — it renders a confirmation page naming whose console you are about to hold, and a new `POST` sets the cookie only after the operator submits it. Shipped 2026-10-31.**
- ✅ **v0.89.5 — RFC 167 slice 2 + RFC 028: a reader who wants to deploy now has one ordered path — `first-production-deploy.md`, rehearsed locally end to end through a real OIDC flow, which is what found the seed-key step missing from the README spine and found that `first-oidc-flow.md` cannot be run as written against production. `CHANGELOG.md` 318 KB → 42 KB under RFC 028's long-unenforced budget, with three defects in the split tool recorded. Shipped 2026-10-31.**
- ✅ **v0.89.4 — RFC 161 §9(a) + RFC 167 slice 1: the operator console's documents stop claiming features it does not have — eight contract rows, eight handler docs, the incident-response chapter, six pages' own copy — and the README gains a deploy path and loses two false claims. Shipped 2026-10-31.**
- ✅ **v0.89.3 — RFC 162: a tenant owner's first console page asked for a URL one segment short of the route that serves it, and the system-admin tenant detail page swallowed the same mistake silently; both fixed, and a check added for every URL the frontend fetches. Shipped 2026-10-30.**
- ✅ **v0.89.2 — RFC 159: ten unroutable handlers deleted, and a check that fails the build when a handler is registered nowhere — asserting its own coverage, not just the code's. Shipped 2026-10-30.**
- ✅ **v0.89.1 — RFC 160: a missing reference is classified apart from a duplicate one, so a mistyped owner id no longer reports a taken slug. Shipped 2026-10-29.**
- ✅ **v0.89.0 — RFC 158: a new tenant's owner is assigned that tenant as their home, so `/admin/t/<slug>/*` is reachable by its own administrator for the first time. Shipped 2026-10-29.**
- ✅ **v0.88.1 — RFC 157: 29 unrouted handlers deleted; unused imports/variables now deny in the Worker crate. Shipped 2026-10-29.**
- ✅ **v0.88.0 — RFC 153: an invitation grants the tenant and the role it offers. Shipped 2026-10-29.**
- ✅ **v0.87.1 — RFC 148 §7 + RFC 156: the scrub reports its outcome, and the gate set gets a gate. Shipped 2026-10-28.**
- ✅ **v0.87.0 — RFC 149, RFC 148, RFC 154: self-service deletion, the email scrub, and the second factor's audit trail. Shipped 2026-10-28.**
- ✅ **v0.86.3 — RFC 150, RFC 152 half A, RFC 155: three documented security controls get a failing witness. Shipped 2026-10-28.**
- ✅ **v0.86.2 — RFC 145 cycle 3 + the §4.2 gate; RFC 145 complete (35 routes). Shipped 2026-10-27.**
- ✅ **v0.86.1 — RFC 145 cycle 2: twelve tenant-admin dead pages. Shipped 2026-10-27.**
- ✅ **v0.86.0 — RFC 147 cycle 2, completing RFC 047. Shipped 2026-10-27.**
  **Account deletion works.** Nothing in cesauth had ever executed a deletion by
  any path: 0.85.1 stopped three endpoints claiming otherwise, and this release
  makes them real. A user requests their own deletion and sees it pending in the
  security centre from their own state, not a URL parameter; a tenant admin sees
  the queue server-rendered and can cancel or execute; the daily cron executes
  requests past their 30-day grace. Three defects underneath went with it: the
  self-service route **required an administrator** and so was unreachable by the
  only principal it existed for; `sweep_pending_deletions` was written, correct
  and **called by nothing**; and deletion audit events recorded the admin, or
  nobody, as the subject rather than the affected user. A nonexistent or
  cross-tenant id now 404s and writes **no** event, and no event is written for
  an operation that did not occur. **Removed:** the orphaned
  `deletion-requests.json`, so the route count falls 193 → 192. **Minor** —
  three documented operations begin working and a user gains a capability that
  was never reachable. **Not claimed:** that GDPR compliance is achieved (only
  that the routes do what the contract says), that previously written false
  audit rows are corrected (they remain), that deletion removes everything —
  **`invitation_tokens` is retained and carries a plain-text email**, recorded
  as a separate decision — that the admin console is complete (33 pages still
  answer 200 with Not Found), or that it works on Cloudflare — **nobody has
  deployed this tree**.

- ✅ **v0.85.1 — RFC 146, RFC 145 cycle 1, RFC 147 cycle 1, and an E3 gate fix.
  Shipped 2026-10-27.** **Everything in this release was asserting something it
  could not back.** **Three deletion endpoints stop claiming success**: each
  wrote its audit event, logged, and redirected with a success parameter without
  touching the deletion-request repository, so an admin who "executed" a
  deletion got `DeletionExecuted` in the audit log, `executed=1` in the URL, and
  no deletion — for an id that was never validated. They now emit no audit event
  and return **501**, after their existing auth and CSRF checks, and the operator
  documentation stops promising an irreversible deletion. **This is a withdrawal,
  not a fix, and deliberate** — ending a false claim implements nothing, so it
  ships ahead of the implementation; no flow is lost, because no screen links to
  the three and the self-service route has always required an admin bearer.
  **The admin CSP nonce can match its own document**: the render helper minted it
  after its caller had built the body, so each page named one nonce while its
  header named another and the inline stylesheet was blocked by its own policy —
  measured pre-fix, one request's body carried the previous request's header
  nonce. 77 call sites now render inside a closure. **Two admin pages render
  instead of answering 200 with Not Found**, including the only one of
  thirty-five an operator could reach by following a link. **A gate that could
  not see what it was written to detect** — the server-rendering check missed any
  shell call made through either wrapper, which is all thirty-five routes — now
  follows one level and re-verifies the wrapper every run. **Patch** — every item
  corrects behaviour already specified; nothing gains a capability.
  **Not claimed:** that deletion works (**nothing in cesauth has ever executed a
  deletion** — the sweep is written and called by nothing; next release), that
  the audit log is now correct (entries already written remain), that the admin
  console works without JavaScript (2 of 35 converted), that the gate now guards
  the console (7 `server`-declared rows, one level of indirection by decision),
  that the admin pages are styled (RFC 131 R3 owns that), that any CI gate is
  enforced, or that it works on Cloudflare — **nobody has deployed this tree**.

- ✅ **v0.85.0 — RFC 141 cycle 1 (+ C1-141), RFC 143 (+ C1-143). Shipped
  2026-10-25.** **The product's primary integration action has an API**:
  registering an OIDC client meant hand-writing `INSERT INTO oidc_clients (…)`
  with the columns elided and a secret hash the operator computed themselves.
  Six routes under `/admin/console/clients` replace it; the secret is shown once
  at creation and rotation and is never retrievable; validation runs through the
  code that enforces the record later, not a second copy of the rules.
  `token_auth_method` is **enforced at `/token`**, checked before any secret
  comparison, and editable where `client_type` is not. **A no-JavaScript user is
  no longer stranded at the second factor**: the server-rendered page already
  existed and was already in production, reachable only by submitting a form the
  user could not see — `GET /me/security/totp/verify` now renders it, and the
  client-rendered duplicate is deleted, taking with it a "Use a recovery code"
  link that issued a GET to a POST-only route and returned a bare 404, and a
  screen that used no localized strings where the template uses 29. A **CSRF
  control the route contract claimed and the code lacked** on
  `POST /admin/console/audit/export` now exists. **RUSTSEC-2026-0387** accepted,
  not fixed — cesauth's only path into `p256` is WebAuthn signature
  verification, which holds no secret key material — with a condition that voids
  the acceptance if cesauth ever signs with P-256. **Minor** — RFC 141 adds a
  capability; everything else is a fix. **Not claimed:** that client
  registration has a console screen (that is the RFC's second cycle), that the
  no-JS path has browser-suite coverage (it was driven with `curl` against a
  running worker, which CI does not reproduce), that any CI gate is enforced
  (RFC 142 established that required checks and pushing to `main` are mutually
  exclusive — CI reports, nothing blocks, by design), that the tag format is
  enforced (`tag_name_pattern` is unavailable on this repository, measured), or
  that it works on Cloudflare — **nobody has deployed this tree**.

- ✅ **v0.84.3 — RFC 133 half A (+ condition C1-133), RFC 142 cycle 1, and a
  dependency advisory. Shipped 2026-10-24.** **The build step is a function of
  its input, not its history**: the WebAssembly optimizer no longer reads and
  writes one path, the output directory is cleared first so a failed build
  leaves nothing stale, the scratch output lives outside the deployed asset
  directory, and an empty build fails loudly. `wasm-bindgen` measured
  deterministic. **CI had been running since April — roughly 1,650 times — and
  four of its gates were red**: fuzzing had never built (the crate was never
  excluded from the workspace; it now runs 11.7 M executions), the bundle gate
  had never passed in 149 runs and then measured the loader instead of the
  Worker (**the 2.5 MiB budget is now evaluated for the first time: 30%**), and
  the runtime smoke check and browser suite died at their deadlines during a
  214 s cold compile and now build the Worker first. **RUSTSEC-2026-0386** (an
  unsound `tokio` API cesauth never calls) fixed by upgrading 1.52.3 → 1.54.1
  rather than accepted. Four false documentation statements corrected.
  **Patch** — every item is a fix or a correction. **Not claimed:** that any CI
  gate is enforced (`main` is still unprotected, so nothing is required — the
  fourth release to say so), that the newly fixed checks are proven on pull
  requests, that the build is reproducible (new evidence says the compiler emits
  different bytes for unchanged source), that 60 s of fuzzing is coverage, or
  that it works on Cloudflare — **nobody has deployed this tree**.

- ✅ **v0.84.2 — RFC 118. Shipped 2026-09-24.** **The refresh-family
  lifecycle has an executable specification.** Rotation with reuse detection
  — the response to a stolen refresh token — was pinned only by example
  tests, and rotation bugs are sequence bugs. A reference model written from
  the contract and RFC 9700 §4.14.2, not from any store, is now run in
  lockstep with the real store over generated adversarial sequences
  (replayed retired tokens, rotate-after-revoke, tokens never issued, clock
  jumps past both deadlines, sequences that overflow the 16-entry retired
  ring), comparing every outcome **and the whole resulting state** after
  every operation. With it: 20 named invariant tests, a coverage test that
  fails when the generator stops reaching a category, normative wording on
  `RotateOutcome`, and two previously unwritten rules. **Its first run found
  a real defect:** the in-memory test double dropped the original sign-in
  timestamp that the Durable Object stores — a test-support fidelity defect
  in a `publish = false` crate, **no shipped behaviour affected**, not a
  security fix, and the third instance of that class after RFC 137 and
  RFC 140. **Patch** — a model, tests, docs and one line of a test crate.
  **Not claimed:** that the Durable Object is verified (not host-testable;
  miniflare deferred), that concurrency is proven (sequences, one thread),
  that reuse detection is newly correct (newly pinned), that any CI gate is
  enforced (`main` still has no branch protection), or that it works on
  Cloudflare — **nobody has deployed this tree**.

- **Security-critical assurance track (RFCs 116–124).** RFC 116 shipped in
  v0.81.0 (`rfcs/done/`), with two carve-outs deferred: secret-newtype
  adoption at the remaining credential call sites, and `ports::repo`, which
  RFC 116 never reached — it remains entirely `&str` and un-scoped, and is
  folded into RFC 119. Source:
  architect instruction `security-critical-assurance-strategy-v0.80.2.md`;
  codebase audit at `docs/src/expert/security-assurance-audit-v0.80.2.md`.
  Sequencing (one RFC per release step; full host-side suite is the gate
  between steps):
  1. **RFC 116** — newtypes + secret types baseline (`TenantId`, `UserId`,
     `ClientId`, `SessionId`, `FamilyId`, `Jti`, `ChallengeHandle`,
     `RawSecret`/`HashedSecret`/`RedactedSecret`). Everything below
     consumes these.
  2. **RFC 117** — authorization-code exchange typestate pipeline +
     challenge-store state-machine contract test.
  3. **RFC 118** — refresh-family pure reference model + lockstep
     generated conformance harness (ADR-011 invariants as executable
     spec).
  4. **RFC 119** — tenant-scoped repository APIs + explicit
     `SystemScope` surface + cross-tenant denial matrix.
  5. **RFC 120** — `Permission` sealing + authz deny-by-default /
     monotonicity / lattice property tests (test phase may ship with
     RFC 118).
  6. **RFC 121** — shared state-machine harness extended to sessions,
     all challenge kinds, membership-vs-access sequences.
  7. **RFC 122** — fuzz expansion: 7 targets over redirect-URI, token
     body, magic-link input, JWKS, authorize query, PKCE differential,
     locale negotiation.
  8. **RFC 123** — `Audited<T>` wrapper + route↔EventKind coverage
     test + payload redaction property.
  9. **RFC 124** — time-boxed Kani + TLA+ pilot (Category C; report
     with adopt-narrowly / defer / reject verdict; nothing depends on
     it).
  Category D (recorded, no RFC): broad Verus, Flux-as-default,
  UI typestate, policy-engine migration — per strategy §12.

- ✅ **v0.67.0 — RFC 105 + 106 (UI/UX finishing — design tokens + Security Center i18n).**
  RFC 105: admin / tenant_admin / tenancy_console frame design-token unification —
  `DESIGN_TOKENS_FMT` is now the single source of truth; `SCOPE_TOKENS_FMT` added
  for admin-only scope colors; raw `DESIGN_TOKENS` deleted. RFC 106: Security
  Center i18n closure — 7 new MessageKey variants (EN + JA) close the JA-hardcode
  hole that v0.39.0 deferred for the TOTP enabled badge, the disable link, and
  the N=0 / N=1 / N≥2 recovery banners. Also clears 7 non-deprecated warnings
  that predated v0.66.0 (RFC 098/099 import residue + a duplicate `#[inline]`
  attribute the new Rust 1.91 compiler flagged). 1,219 tests (+15). 0 warnings.
  MessageKey catalogue: 145 → 152.

- ✅ **v0.68.0 — RFC 108 partial (route-catalog correction + end-user migration).**
  Catalog corrected: four WebAuthn paths (`PASSKEY_REGISTER_START`,
  `PASSKEY_REGISTER_FINISH`, `PASSKEY_AUTH_START`, `PASSKEY_AUTH_FINISH`)
  that never matched the worker's registered routes — silently wrong since
  v0.66.0 — now match `/webauthn/register/*` and `/webauthn/authenticate/*`.
  Added `MAGIC_LINK_VERIFY_FORM` and `TOTP_ENROLL_CONFIRM` static paths.
  End-user template migration: 15 hardcoded URLs in
  `templates/{security_center,login,totp}.rs` flow through
  `cesauth_core::routes::{me,auth}::*`. HTML-escape contract for catalog
  builder fns established (caught and fixed a regression where
  `session_revoke(id)` dropped escaping). Admin/tenant_admin/tenancy_console
  migration (~189 URLs across 44 files) + RFC 112 deferred to v0.69.0.
  1,219 tests (no change — pure refactor). 0 warnings.

- ✅ **v0.69.0 — RFC 108 catalog completion + admin/console migration.**
  Second silent v0.66.0 catalog drift caught and fixed: `tenancy_console::*`
  returned `/admin/tenancy/{slug}/...` but the worker has always registered
  `/admin/tenancy/tenants/{tid}/...`. Catalog expanded from ~57 to ~83 entries
  to cover every URL family the production templates need; every const and
  fn now mirrors a worker-registered route. Admin nav migration across all
  three frames (16 URLs). `admin/console/*` templates fully migrated (~22
  URLs across 8 files), including all parameterized routes via builder fns
  with the v0.68.0 escape contract applied. Remaining ~150 URLs in
  `tenant_admin/` and `tenancy_console/` (32 files) pushed to v0.70.0 along
  with the `scripts/drift-scan.sh` URL-hardcode rule. **RFC 112 (worker
  auth macro batch) pushed to v0.70.0** — the development environment used
  for this release cycle cannot install wasm32 or compile-verify worker
  edits; see `rfcs/proposed/112-...md` "Implementation environment". 1,219
  tests (no change — pure refactor). 0 warnings.

- ✅ **v0.70.0 — RFC 108 closure (tenant_admin + tenancy_console + drift-scan).**
  Closes the route-catalog migration begun in v0.68.0. All production
  templates in `crates/ui/src/tenant_admin/` (6 top-level + 8 forms) and
  `crates/ui/src/tenancy_console/` (5 top-level + 11 forms) now construct
  URLs via `cesauth_core::routes::*` builders — ~150 URL literals replaced
  this release; ~190 across the three-release migration. `scripts/drift-scan.sh`
  gains a per-file URL-hardcode rule that stops at `#[cfg(test)]` / `mod tests`
  markers and skips dedicated `tests.rs` files (those exist to fail on
  catalog drift). Two pre-existing orphan UIs surfaced and are intentionally
  left out of scope with module-docstring `# RFC 108 orphan UI exemption`
  notes: `tenant_admin/oidc_clients.rs` (RFC 017 wired the form but never
  the worker handler) and `tenancy_console/forms/membership_add.rs` (form
  actions POST to `.../memberships`, worker only registers `.../memberships/new`).
  **RFC 112 (worker auth macro batch) remains environment-blocked** — the
  sandbox where this release was prepared cannot install rustup / wasm32
  and so cannot verify worker edits. Pushed to v0.71.0+ contingent on
  environment. 1,219 tests (no change — pure refactor). 0 warnings.

- ✅ **v0.71.0 — RFC 109 (Audit log viewer UI surface).** New
  `/admin/console/audit` interactive viewer with actor / event /
  date-range filtering and opaque-cursor pagination. The RFC 080
  export endpoint inherits the same filter state via the viewer's
  export form, closing the "browse → filter → export" flow from PDF
  v0.50.1 page 9. Two scope amendments recorded at implementation
  time: (1) the `tenant_id` filter is deferred — the `audit_events`
  schema has no tenant_id column, adding one needs a separate
  migration RFC; (2) worker handler edits (query-param parsing for
  the new fields) are mechanical but env-blocked for compile
  verification (same posture as RFC 112). The amendments are
  documented in `rfcs/done/109-...md` §"Scope amendments at
  implementation time (v0.71.0)". 1,252 tests (+33 vs v0.70.0
  baseline). 0 warnings.

- ✅ **v0.72.0 — RFC 110 + 113 (Acceptance alignment).** RFC 110 closed as
  **verification + baseline doc + pin tests** per its own §"Open questions"
  Q1 resolution: console nav alignment confirmed a clean superset of PDF
  page 8; the four PDF page 9 "Safety controls" items plus the runbook
  link are documented gaps deferred to RFCs 110a–110e (each touches a
  different worker data source). RFC 113 ships the **UI rendering
  acceptance harness** at `crates/ui/tests/acceptance_harness.rs` —
  five frame fixtures (end-user EN + JA, three admin frames JA-only)
  × five universal invariants (`<html lang>` matches locale, skip-link,
  flash anchor, footer without version, scope badge on admin). Two
  scope amendments recorded against the original RFC 113 draft:
  footer-version invariant inverted (RFC 071 removed version captions;
  draft assumed they were still there) and frame-fixture granularity
  in place of per-route enumeration (same coverage at one-sixth the
  maintenance cost). 1,265 tests (+13 vs v0.71.0 baseline). 0 warnings.

- ✅ **v0.73.0 — RFC 107 + 111 (ADR-013 §Q4 closure).** RFC 107 adds a
  CLDR-minimal `Plural::{One, Other}` enum + `plural_for(locale, n)`
  dispatcher + `lookup_plural(key, locale, n)` parallel catalog branch
  to `cesauth_core::i18n`. First plural-aware key:
  `SecurityRecoveryRemaining` — EN now renders proper plural
  agreement (`5 valid recovery codes`); JA stays plural-invariant.
  No `icu` dependency; WASM size budget preserved. RFC 111 confirms
  UTC ISO-8601 (RFC 3339, Z-form) as cesauth's canonical date
  rendering: `cesauth_core::util::format_unix_as_iso8601` is the
  single formatter, callable from every UI / adapter / service
  layer. Per-file legacy formatters (`format_unix_local` in
  security_center.rs, `format_unix` in audit_chain.rs) removed; 4
  call sites consolidated to the canonical formatter. ADR-013 §Q3
  + §Q4 both marked Resolved with rationale text; new
  `docs/src/expert/i18n.md` digests the i18n contract.
  1,278 tests (+13 vs v0.72.0 baseline: +8 core plural rules,
  +5 ui plural-variants + RFC 111 pins). 0 warnings.

- ✅ **v0.74.0 — RFC 110b/c/d/e (Safety controls panel gap-fills).**
  Four of the five PDF v0.50.1 page 9 gap items identified in v0.72.0
  baseline shipped together. RFC 110b: Turnstile env-var presence
  → boolean indicator badge; never the secret bytes. RFC 110c:
  refresh-token reuse alerts summary — new service helper
  `count_refresh_reuse_since(repo, now - 86400)` reads
  `RefreshTokenReuseDetected` audit events via existing
  `AuditSearch::since` filter (RFC 109). UI renders `0 (clean)` or
  `N in 24h` (critical badge). RFC 110d: TOTP_SECRET_KEY presence
  → same shape as 110b. RFC 110e: `RUNBOOK_URL` env var → anchor
  with `target="_blank" rel="noopener noreferrer"`; missing URL
  surfaces an informational hint, not a broken link. New service
  composition helper `compute_safety_controls(...)` assembles the
  `SafetyControlsReport`. UI signature change:
  `safety_page(principal, report)` →
  `safety_page(principal, report, controls: Option<&SafetyControlsReport>)`
  — backward-compat via None. Pin tests flipped from negative to
  positive (8 new positive pins) and the forward-looking
  secret-leakage pin strengthened to catch env-var names. RFC 110a
  (rate-limit summary, KV-heavy) stays deferred — the
  `Option<RateLimitStatus>` field + "— (RFC 110a deferred)"
  placeholder rendering are wired now, so 110a is a single-PR finish
  when an environment with rustup/wasm32 is available.
  1,290 tests (+12 vs v0.73.0 baseline: +8 core safety_controls,
  +4 ui controls-section rendering). 0 warnings.

- ✅ **v0.78.0 — Test file modularization 100% closure (maintenance release).**
  Four splits closing out every host-buildable oversize test file.
  `tenancy/tests.rs` (664 → 27 + common + 6 siblings) using
  `pub(super) use` re-export pattern for cesauth-core types.
  `authz/tests.rs` (606 → 22 + common + 5 siblings) same pattern.
  `totp/tests.rs` (602 → 27 + 8 siblings) using
  sibling-helper-import pattern for `rfc6238_vectors::rfc_secret`.
  `i18n/tests.rs` (530 → 60 + 3 siblings).
  Total v0.75.0–v0.78.0: 9 test files (8,908 lines) reorganized
  into 63 focused files, every one under 500 ELOC. 1,290 tests
  pass identically across all four releases — zero-behaviour-delta
  refactor track confirmed.
  Only `worker/flash/tests.rs` (560 lines) remains over threshold,
  env-blocked (wasm32-only); ships when rustup/wasm32 is available.

- ✅ **v0.77.0 — Test file modularization closure (maintenance release).**
  Three splits in one release closing out the dev-guideline 500-ELOC
  threshold for the four biggest test files. `migrate/tests.rs`
  (1,154 → 247 + 6 siblings), `tenant_admin/tests.rs`
  (895 → 27 + common + 6 siblings), `migration_chain.rs`
  (881 → 30 + common + 6 siblings). Documented the
  cargo `tests/` directory wrinkle: integration tests need explicit
  `#[path]` attributes for subdirectory submodules.
  Three small overages remain (`tenancy/tests.rs` 664,
  `authz/tests.rs` 606, `totp/tests.rs` 602) — flagged as
  follow-up work. 1,290 tests pass identically across v0.75.0→v0.77.0.

- ✅ **v0.76.0 — Test file modularization continued (maintenance release).**
  Split the second-largest test file
  (`crates/core/src/service/introspect/tests.rs`, 1,519 lines) into
  6 sibling files under `tests/` plus a slim base `tests.rs` (348
  lines). The original file already had clean internal organization
  (each test category in a nested `mod foo` block), so the split is
  the "unwrap-mod-block" pattern — lower-disruption than v0.75.0's
  templates split. Shared `StubFamilyStore` and helpers stay in the
  base `tests.rs`; sibling files reach them via `use super::*`. No
  behaviour changes; 1,290 tests pass identically. Drift-scan
  exemption (`*/tests/*.rs`, added in v0.75.0) covers the new
  layout without script changes.

- ✅ **v0.75.0 — Test file modularization (maintenance release).**
  Split the largest single test file (`crates/ui/src/templates/tests.rs`,
  2,057 lines) into 7 per-feature submodules under
  `templates/tests/`. All submodules now under the 500-ELOC
  "strongly recommended split" threshold from the dev guidelines.
  Cross-module fixtures (`make_state`, `sample_item`) moved to
  `common.rs`. Drift-scan exemption extended from `*/tests.rs` to
  `*/tests/*.rs` to preserve the existing tests-as-drift-detectors
  contract. No behaviour changes; 1,290 tests pass identically.
  Other oversize test files (introspect, migrate, tenant_admin,
  migration_chain) flagged for future maintenance releases.

- 📅 **v0.75.0+ — RFC 110a (Rate limit summary, env-blocked).**
  KV-backed bucket enumeration across the brute-force and
  token-endpoint rate-limit pools. The `RateLimitStatus` struct,
  `Option<RateLimitStatus>` field, and "— (RFC 110a deferred)"
  placeholder are already in place — landing 110a is wiring the
  worker-side KV reads (wasm32-only).

- ⏸ **RFC 112 — Worker auth macro batch (environment-blocked).**
  Mechanical RFC 100 macro adoption across remaining admin handlers
  (~800 LOC reduction). Sandbox where v0.66.0–v0.74.0 were prepared
  cannot install rustup + wasm32 target. Ships once an
  environment with worker compile-verify is available.

- ✅ **v0.66.0 — RFC 096-103 (codebase audit remediation).**
  Zero non-deprecated warnings. Shared util.rs (5 constant_time_eq → 1, 3 ISO-8601 → 1).
  timing.rs (7 TTL constants). routes.rs (165 paths). i18n/mod.rs split (lookup 684 lines → 8 groups).
  templates/ split (1537 lines → 4 files). admin/service/ split. Auth boilerplate macros.
  1,204 tests (+12 util).

- ✅ **v0.65.0 — RFC 092-095 (SaaS acceptance criteria + docs).** ER diagram,
  acceptance report, feature flag verification. 1,192 tests.

- ✅ **v0.64.0 — RFC 085–091 (Core test coverage).** JWT signer 10 tests,
  authz/service 14 tests, i18n inline 6 tests, admin/service 6 tests. Cron pass KV
  record writing (RFC 090). Total: 1,192 tests (+36).

- ✅ **v0.63.0 — RFC 079–084 (P2 operations UX + UI consistency).**
  RFC 079: Magic Link not-configured notice (operator boundary). RFC 080: audit log
  filtered export CSV/JSONL with AuditExported event. RFC 081: cron pass status
  surface (/admin/console/operations, KV-backed). RFC 082: design token unification
  (--success/--warning/--danger aliases). RFC 083: rollback hint (already existed).
  RFC 084: sessions drift note. 1,156 tests. Routes: 165.

- ✅ **v0.66.0 — RFC 096-103 (codebase audit remediation).**
  Zero non-deprecated warnings. Shared util.rs (5 constant_time_eq → 1, 3 ISO-8601 → 1).
  timing.rs (7 TTL constants). routes.rs (165 paths). i18n/mod.rs split (lookup 684 lines → 8 groups).
  templates/ split (1537 lines → 4 files). admin/service/ split. Auth boilerplate macros.
  1,204 tests (+12 util).

- ✅ **v0.65.0 — RFC 092-095 (SaaS acceptance criteria + docs).** ER diagram,
  acceptance report, feature flag verification. 1,192 tests.

- ✅ **v0.64.0 — RFC 085–091 (Core test coverage).** JWT signer 10 tests,
  authz/service 14 tests, i18n inline 6 tests, admin/service 6 tests. Cron pass KV
  record writing (RFC 090). Total: 1,192 tests (+36).

- ✅ **v0.63.0 — RFC 079–084 (P2 operations UX + UI consistency).**
  Magic Link not-configured notice, audit log export CSV/JSONL, cron pass status surface,
  design token unification, sessions drift note. 1,156 tests. Routes: 165.

- ✅ **v0.62.0 — RFC 071–078 (UI/UX alignment from design specification).**
  P0: footer version hygiene, html lang locale binding, scope badge CSS, generic auth
  failure audit + MagicLinkMismatch→400 fix. P1: Security Center mobile summary card
  (8 MessageKey, WCAG 1.4.1), recovery code save-confirmation gate (CSRF form, server
  validation), skip-to-content link (WCAG 2.4.1 all frames), tenant admin UI full i18n
  (35 MessageKey, JA-only rendering tests). 1,138 tests. MessageKey catalog: 145.

- ✅ **v0.61.0 — RFC 059–070 (test coverage completion + §16.7/§16.8 docs + UI pages).**
  RFC 059: admin/policy.rs (13 tests) + oidc/introspect.rs (8 tests).
  RFC 060: jwt/claims.rs (6 tests). RFC 065: oidc/token.rs (13 tests).
  RFC 069: webauthn/cose.rs (7 tests). RFC 061-062: data-model.md,
  admin-operations.md, migration-procedures.md (§16.7 complete).
  RFC 066-067: tenant admin UI — invitation page + deletion requests page.
  RFC 068: POST /admin/tenancy/tenants/:id/suspend and /restore (§16.8).
  RFC 070: versions_mapping.txt update. Total: **1,100+ tests**.

- ✅ **v0.60.0 — RFC 059-064 (coverage + SaaS §16.7 documentation).**
  admin/policy.rs tests (13), oidc/introspect.rs tests (8), jwt/claims.rs
  tests (6). data-model.md ER diagram, admin-operations.md, migration-
  procedures.md. SUMMARY.md updated. 1,089 tests.

- ✅ **v0.59.0 — RFC 054-058 (OIDC/PKCE, tenancy tests, soft-delete, TOTP, E2E).**
  PKCE tests (+9), authorization tests (+4), tenancy/service.rs tests (12),
  soft-delete service (soft_delete_tenant/org/group + suspend/restore), TOTP
  storage.rs tests (6), E2E onboarding scenarios (5 — §16.2/16.4/16.6). 1,062 tests.

- ✅ **v0.58.0 — RFC 049-053 (accept-invite, SQL validation, tenant_id, authz, sessions).**
  /accept-invite full CloudflareInvitationRepository implementation. migrate-test
  SQL queries validated (8 tests). authenticators.tenant_id added (migration 0020,
  SCHEMA_VERSION 20). authz hardening (8 security tests). SessionCreated/Revoked/
  Expired/MfaVerified EventKind. 1,023 tests.

- ✅ **v0.57.0 — RFC 045-048 (audit events, worker layers, D1 adapters, billing).**
  6 new EventKind (Invitation×3 + Deletion×3). Invitation + deletion worker routes.
  CloudflareInvitationRepository + CloudflareDeletionRequestRepository D1 adapters.
  InMemory adapters. sweep_pending_deletions cron. billing change_plan / is_feature_
  enabled / check_quota (9 tests). 1,005 tests.

- ✅ **v0.56.0 — RFC 040-044 (OIDC userinfo, token refactor, invitations, deletions).**
  GET/POST /userinfo endpoint (10 tests). TokenDeps + TokenConfig refactor.
  Preview-and-apply LOG_LEVEL adoption. invitation_tokens table (migration 0018,
  11 tests). deletion_requests table (migration 0019, 8 tests). CoreError::Conflict.
  996 tests, SCHEMA_VERSION 19.

- ✅ **v0.55.0 — RFC 030-039 (P0/P1 review fixes: security, CSP nonces, id_token nonce,
  mailer security, /userinfo discovery, CI hardening).**
  Category::Magic, MagicLinkMailer dyn-free, id_token nonce, auth_time in
  FamilyState, /introspect tenant boundary, request_id audit chain,
  docs cleanup, CI test/clippy/wasm/deny gates. 963 tests.

- ✅ **v0.54.0 — RFC 001 + RFC 013/025/027 + RFC 020-029 (SaaS multi-tenancy core).**
  id_token issuance (OIDC Core §3.1.2.2). schema_meta, 0004 FK repair, COLLATE
  NOCASE fix. Permission catalog sync. ON DELETE CASCADE. Tenant boundary integrity.
  migration 0001-0017. WebAuthn tenant isolation. Batch authz. Admin console
  preview-and-apply. TOTP unconfirmed sweep. Introspect rate limit. 958 tests.

- ✅ **v0.53.0 — RFC 014-018 (audit hash chain, id_token ADR, RFC 018 preview infra).**
  Audit hash chain (DO-serialized). id_token design (ADR-008). Preview-and-apply
  infrastructure (mint_preview_token / verify_preview_token). 888 tests.

- ✅ **v0.52.1 — RFC 012 + RFC 007 (doc/repo hygiene + attack surface review cadence).**
  Patch release. README and intro.md factual errors corrected (admin console
  existence, audit→D1 not R2). `migrate.rs` 2568-line monolith split into
  7 focused submodules (facade re-exports unchanged public API; all 29 tests
  pass). `scripts/drift-scan.sh` + `.github/workflows/drift-scan.yml` added
  for stale-phrase detection on every PR. `wrangler.toml` RATE_LIMIT=DO
  comment added. RFC 007 process doc at
  `docs/src/expert/attack-surface-review-cadence.md`. Both RFCs moved to
  `rfcs/done/`. 888 tests pass.

- ✅ **v0.52.0 — RFC 006 + RFC 019 (CSP nonces + RFC lifecycle policy).**
  Minor bump because RFC 006 changes the observable CSP header for all HTML
  responses. `CspNonce` type + `build_csp_with_nonce` in cesauth-core.
  `set_render_nonce` / `render_nonce` thread-local in cesauth-ui (no public
  API change). Per-request nonce injected into all inline `<style>` and
  `<script defer>` tags via 5 frame functions. Worker HTML handlers generate
  nonce and call `set_render_nonce` before rendering. Per-route CSP strings:
  `'unsafe-inline'` → `'nonce-{n}'`. 15 core + 5 UI nonce tests. 859 tests
  pass. RFC 019: `rfcs/` 4-folder lifecycle structure (proposed/ / done/ /
  archive/), written policy in archive/019-rfc-lifecycle-policy.md.

- ✅ **v0.51.2 — RFC 005 (`cargo fuzz` for JWT parser).**
  Patch release. `fuzz/` crate (NOT workspace member) + one fuzz target
  (`jwt_parse`) exercising `verify` and `verify_for_introspect` under
  libFuzzer. 10-file seed corpus. GH Actions one-shot job (60 s) on PRs
  touching JWT or fuzz code. `.gitignore` and workspace comment updated.
  Zero production code change.

- ✅ **v0.51.1 — RFC 004 + RFC 003 (WebAuthn typed errors + proptest).**
  Patch release. Additive wire change (`kind` field on WebAuthn errors)
  + dev-dep addition only.

  **RFC 004**: `cesauth_core::webauthn::error` — `WebAuthnErrorKind` enum
  with six variants and `classify(detail) -> WebAuthnErrorKind`. Worker
  `oauth_error_response` surfaces `kind` in the JSON body for WebAuthn
  failures only; diagnostic detail stays server-side (audit + logs).
  10 unit tests + 3 worker error-shape pins.
  **RFC 003**: `proptest = "1"` as workspace dev-dep. Two new property-based
  test modules: `jwt/proptests.rs` (5 properties — sign/verify round-trip,
  single-byte tamper, wrong-key rejection, magic-link round-trip, tamper
  rejection) and `oidc/authorization/redirect_uri_proptests.rs` (7 properties
  — exact-match, no-trailing-slash, no-suffix, port-explicit-vs-default,
  http-vs-https, case-sensitive). 481 core tests pass (was 459).

- ✅ **v0.51.0 — RFC 010 + RFC 002 (MagicLinkMailer port + schema drift fix).**
  Minor bump because RFC 010 introduces operator-visible configuration knobs
  (three optional env vars for the HTTPS provider adapter).

  **RFC 010**: `MagicLinkMailer` trait (`cesauth-core::magic_link::mailer`)
  with `MagicLinkPayload`, `MagicLinkReason`, `DeliveryReceipt`, `MailerError`.
  Four reference adapters in `cesauth-adapter-cloudflare::mailer`:
  `DevConsoleMailer` (local dev only, never logs OTP), `UnconfiguredMailer`
  (default fallback, audits misconfig), `ServiceBindingMailer` (CF service
  binding to operator mail worker — preferred), `HttpsProviderMailer`
  (SendGrid v3-compatible POST). Worker factory `crate::adapter::mailer::from_env`
  selects the adapter from env. Both Magic Link issuance routes
  (`routes::magic_link::request`, `routes::api_v1::anonymous` promote path)
  now call the mailer port instead of writing to the audit log. Two new audit
  kinds: `MagicLinkDelivered`, `MagicLinkDeliveryFailed` (keyed on `kind`
  field: `transient` / `permanent` / `not_configured`). ADR-015 Accepted.
  New operator chapter `docs/src/deployment/email-delivery.md`.
  **RFC 002**: `migrations/0001_initial.sql` column comment corrected from
  `argon2id(secret)` to `sha256_hex(secret)`. `service::client_auth` module
  doc updated with RFC 002 resolution rationale. 820 tests pass (was 817).
  No schema migration; new env vars are all optional; existing behavior
  unchanged for deployments that don't configure a provider.

- ✅ **v0.50.3 — RFC 008 + RFC 009 + RFC 011 (security hardening patch).**
  Ships the Tier-0 production-blocker and Tier-1 hardening items from the
  external codebase review that do not require new operator-visible
  configuration knobs.

  **RFC 008 (P0)**: OTP plaintext removed from audit log on every Magic
  Link issuance. `code_plaintext` renamed to `delivery_payload`. Static-
  grep pin test prevents reintroduction. Operator runbook for purging
  already-persisted rows and re-baselining the hash chain added to
  `docs/src/deployment/runbook.md`. **RFC 009 (P0)**: `introspect_token`
  no longer takes `expected_aud` — access tokens carry `aud = client.id`
  not `aud = issuer`; the pre-v0.50.3 verifier rejected every valid
  production access token. New `verify_for_introspect()` in jwt/signer
  is the introspect-only relaxed path. Audience-gate client lookup is now
  fail-closed: `Ok(None)` → HTTP 401 + `IntrospectionRowMissing` audit
  event; `Err(_)` → HTTP 503. Test fixture corrected to `AUD = "client_X"`.
  Three regression tests added. **RFC 011 (P1)**: `csrf::mint()` → `Result`,
  fail HTTP 500 on CSPRNG failure; `var_u32_bounded` helper rejects negative
  rate-limit env values (previously silently disabled limits via `as u32`
  wrap); duplicate session-route block removed from `lib.rs`;
  `no_duplicate_route_registrations` test added; `012-session-hardening.md`
  marked Superseded. 817 tests pass (was 814). No schema/wire/DO changes;
  `/introspect` behavior change: now returns correct `active: true` for
  valid access tokens.

- **v0.50.2 production-blocker sweep — external review remediation.**
  An external Rust + Cloudflare codebase review of v0.50.1
  surfaced three production blockers, three security
  hardening items, and four quality-and-operations items.
  Independently verified against the source tree. Triaged
  into RFCs 008-014 in [`rfcs/`](../rfcs/) for handover to
  implementer.

  **Production blockers (Tier 0, ship in v0.50.2)**:

  - ✅ **RFC 008 — Eliminate plaintext OTP in audit log
    [P0]** — shipped in v0.50.3. `worker/src/routes/magic_link/request.rs:170-178`
    and `worker/src/routes/api_v1/anonymous.rs:254-264`
    write the Magic Link OTP plaintext into
    `EventKind::MagicLinkIssued` audit `reason` on every
    issuance, violating the project's own self-declared
    "No token material ever" invariant from
    `worker/src/audit.rs`. Anyone with audit-read access
    (operator D1 read role, Logpush forwarder, SIEM
    operator, anyone running `cesauth-migrate export`,
    backup restorer) can log in as any user who used Magic
    Link or anonymous-promote during the retention
    window. Fix: drop `code_plaintext` from both audit
    sites; add static-grep pin test to prevent
    reintroduction; rename `code_plaintext` →
    `delivery_payload` to signal intent; ship operator
    runbook for purging already-leaked rows + chain
    re-baseline. RFC 008 details all 6 implementation
    steps.

  - ✅ **RFC 009 — Introspection access-token `aud`
    correctness + audience-gate fail-closed [P0 + P1]** — shipped in v0.50.3.
    Tokens minted with `aud = client.id`
    (`core/src/service/token.rs:115,277`); verifier uses
    `expected_aud = issuer`
    (`worker/src/routes/oidc/introspect.rs:202-208`).
    **Tests pass because fixture sets `ISS == AUD` (line
    78-79 of `service/introspect/tests.rs`)**, masking
    the production bug. Result: `/introspect` returns
    `{"active":false}` for every valid access token in
    production. ADR-014 §Q1's audience gate
    consequently never fires (it gates on active
    responses that never come back). Companion P1: the
    audience-gate's client lookup
    (`introspect.rs:97-117`) silently fails open on D1
    storage error, defeating the security boundary
    operators opted into. Fix: remove `expected_aud`
    from `introspect_token` (audience gate becomes
    canonical aud check); update test fixture to
    `AUD = "client_X"`; harden gate to fail-closed (HTTP
    503 on storage error, HTTP 401 on row missing with
    new audit kind `IntrospectionRowMissing`); amend
    ADR-014 §Q1 with v0.50.2 tightening note. RFC 009
    details all 9 implementation steps.

  - ✅ **RFC 010 — Magic Link real delivery (mailer port +
    provider adapters) [P0]** — shipped in v0.51.0. The development
    directive declares a `MagicLinkMailer` trait that
    operators implement; **workspace-wide grep returns
    zero hits** — no such trait exists. The audit log
    IS the OTP delivery mechanism in cesauth today
    (which is why RFC 008's plaintext-leak exists at
    all). Without a real mailer contract, RFC 008's fix
    will not stay fixed: the next operator under
    deadline pressure reintroduces the audit-as-delivery
    hack. Fix: build the trait the directive claims
    exists (`MagicLinkMailer` in `cesauth-core` with
    audit-disjoint crate boundary); ship 4 reference
    adapters (Cloudflare service binding, HTTPS
    provider, dev console with `WRANGLER_LOCAL=1` gate,
    `UnconfiguredMailer` fallback that surfaces misconfig
    via audit); new audit kinds `MagicLinkDelivered` /
    `MagicLinkDeliveryFailed`; new operator chapter
    `docs/src/deployment/email-delivery.md`; ADR-015
    drafted alongside graduating to Accepted on ship.
    RFC 010 details all 6 implementation PRs.

  - ✅ **RFC 011 — Worker-layer hardening [P1 + P2]** — shipped in v0.50.3. Bundle
    of four mechanical fixes:
    (1) `csrf::mint()` swallows `getrandom` error with
    `let _ =` — RNG failure produces a constant predictable
    token. Fix: `Result`-ize, audit `CsrfRngFailure`
    kind, fail HTTP 500.
    (2) `var_parsed_default(...)? as u32` in `config.rs:126,134`
    silently wraps negative values to huge u32, disabling
    rate limits. Fix: `var_parsed_u32_bounded` with
    explicit non-negative + sane upper bound check.
    (3) `worker/src/lib.rs:161-168` and `:193-200`
    register the same three `/me/security/sessions` routes
    twice (merge-conflict residue from v0.35.0). Fix:
    delete second block; uniqueness pin test.
    (4) `docs/src/expert/adr/012-session-hardening.md`
    (older draft) and `012-sessions.md` (canonical) both
    exist. Fix: header `012-session-hardening.md` as
    Superseded. May ride along v0.50.2 or land in
    v0.50.3 depending on PR review bandwidth.

  **Quality / scaling work (Tier 3, defer behind v0.50.2)**:

  - **RFC 012 — Doc and repo hygiene**. README claims
    "No management GUI" (false — admin console since
    v0.3.0) and "land in R2" (false — R2 audit removed
    v0.32.0); `crates/core/src/migrate.rs` is 2568
    lines (development directive's 800-line cap);
    development directive itself describes rate-limit as
    KV (actually DO); inline comments reference removed
    R2 audit subsystem. Fix: README rewrite, mechanical
    `migrate.rs` split into 9 submodules under 500 lines
    each, dev directive corrections + move into
    `docs/src/expert/development.md`, drift-scan CI
    workflow with stale-phrase pattern list.

  - **RFC 013 — Operational envelope**. Cesauth has
    implicit Cloudflare plan assumptions never
    documented: cron passes walk 1000 rows × DO call
    each (Free plan subrequest cliff at 50);
    `/introspect` hot path issues multiple D1 reads +
    DO calls (Free plan D1 query cliff at 50);
    monolithic worker bundle never measured against
    Free 3 MB / Paid 10 MB ceiling; `nodejs_compat`
    enabled despite no Node API runtime use. Fix:
    ADR-016 declares Paid plan as floor; bundle-size CI
    gate at 7 MB gzipped (70% of Paid ceiling);
    configurable cron batch sizes for each pass;
    `nodejs_compat` removal or in-tree justification;
    new `docs/src/deployment/operational-envelope.md`
    chapter with per-request budget tables; new
    `docs/src/deployment/bundle-history.md` trend
    record.

  - **RFC 014 — Audit append performance**. D1
    contention concern under high-rate audit events
    (`/introspect`-heavy deployments). Path A
    (acceptance + telemetry): instrument
    `audit::append` with latency / retry warnings,
    document ~100/s sustained ceiling, ship operator
    runbook. Path B (DO-serialized append, ADR-017):
    deferred until Path A telemetry triggers — single
    new DO class + adapter + migration; chain integrity
    preserved.

  - **RFC 015 — Request traceability**. Operator
    follow-up question on logging completeness: log
    framework is well-designed (categorized,
    level-gated, sensitivity-gated) but no
    correlation across log lines from the same
    request, no cross-link between log and audit, no
    consistent HTTP request lifecycle log. Adds:
    `cf-ray`-derived `request_id` threaded through
    `LogConfig` and `NewAuditEvent`; one HTTP
    lifecycle log per request as middleware
    (replaces ad-hoc per-handler `Category::Http`
    emissions, net log volume same or fewer); new
    nullable `audit_events.request_id` column
    (SCHEMA_VERSION 10 → 11; non-chained, additive).
    **Deliberately documents the absence of a
    file-writing logger** as ADR-018: Cloudflare
    Workers has no filesystem; persisting per-line
    to KV/R2/D1 contradicts the security posture and
    duplicates audit/log governance — operator
    question on this is answered by ADR-018, not by
    implementation. Coordinates with RFC 013
    (operational envelope) since both touch
    observability.

  **Tier 4 — Admin UX hardening (defer behind P0
  sweep + Tier 3)**: a third source — an external
  UI/UX design update reviewing v0.50.1 — surfaced
  three admin-surface gaps not covered by the
  external code review or operator logging
  follow-up. Triaged into RFCs 016-018:

  - **RFC 016 — Admin scope badge standardization**.
    Currently the three admin frames
    (`/admin/console/*` system, `/admin/tenancy/*`
    tenancy, `/admin/t/<slug>/*` tenant) have
    visually distinct chrome but no semantic "you
    are operating in scope X" badge consistent
    across all three. Adds `ScopeBadge` enum
    (System/Tenancy/Tenant(slug)) + 3 colour tokens
    (purple/blue/green, deliberately distinct from
    semantic success/warning/danger/info) + 3
    MessageKey variants. Single-place chrome change
    that lets operator + screenshot-reviewer read
    scope as a first-class element rather than
    incidental styling.

  - **RFC 017 — OIDC client audience-scoping admin
    editor**. v0.50.0 shipped the audience-scoping
    schema + gate but explicitly deferred the
    admin UI ("Admin console UI for this is out
    of v0.50.0 scope"). Operators currently must
    run `wrangler d1 execute "UPDATE oidc_clients
    SET audience = ? WHERE id = ?"` against
    production. RFC 017 adds the tenant admin
    editor surface with explicit 3-state form
    (Unscoped/Scoped+empty/Scoped+value)
    distinguishing NULL vs `""` vs `"value"`
    semantics, per-tenant uniqueness check with
    `?force=1` override, new audit kind
    `OidcClientAudienceChanged` with before/after
    payload, audit-trail section showing recent
    changes for the client.

  - **RFC 018 — Preview-and-apply pattern for
    destructive admin operations**. The deck's
    "状態 → 影響 → 実行 → 監査" framing; current
    admin console largely lacks the explicit
    impact step (config_edit, token rotation, etc.
    apply directly on submit). Establishes
    reusable infrastructure (`ImpactStatement`,
    HMAC-signed `PreviewToken` with 5-min TTL,
    paired `OperationPreviewed`/
    `OperationApplied` audit events). First
    adopters: LOG_LEVEL change, token rotation,
    audience editor (RFC 017 ideally rides on
    this). ADR-019 establishes the convention.

  All three Tier 4 RFCs ship after Tiers 0-3
  (production blockers + worker hardening +
  quality + operations). Recommended placement:
  v0.52.x or 0.53.0 in the order RFC 016 (chrome,
  ships anywhere) → RFC 018 (pattern infra) → RFC
  017 (rides on the pattern).

- **Security track — phased rollout.** Eleven releases of focused
  security work, ordered by impact-vs-effort. Each is small
  enough to ship cleanly without overlap. Originally framed as
  eight phases; v0.27.0 split into 2a (storage) + 2b (routes)
  mid-implementation, then v0.28.0 split again into 2b
  (presentation) + 2c (routes) + 2d (polish) — adding three
  phases total. Each split keeps releases review-able rather
  than shipping a giant change-set.

  - **0.24.0** ✅ — `SECURITY.md` improvements (severity table,
    known-limitations subsection, see-also cross-links;
    pre-existing policy was already comprehensive) + CSRF
    audit deliverable (`docs/src/expert/csrf-audit.md`,
    per-route inventory with mechanism per route, test
    coverage, re-audit cadence) + CSRF gap fill on
    `/magic-link/verify` (token check, JSON-path exempt) +
    dependency-scan automation review (verified the existing
    `.github/workflows/audit.yml` is comprehensive, documented
    the alert path in `docs/src/expert/security.md`'s new
    "Dependency vulnerability scanning" section). 6 new tests
    pinning the CSRF field contract on `VerifyBody` and
    `RequestBody`. Total 413 passing.
  - **0.25.0** ✅ — Email verification flow audit + gap fill +
    OIDC discovery doc honest reset. Audit deliverable
    (`docs/src/expert/email-verification-audit.md`) documents the
    9-row per-path table, the meaning of `email_verified=true`,
    and the discovered OIDC `id_token` issuance gap. **Concern 2
    fix**: returning-user Magic Link verify now flips
    `email_verified=true` when previously false (best-effort
    UPDATE; skip-write optimization for already-verified rows).
    **Discovery doc honest reset**: `id_token_signing_alg_values_supported`
    and `subject_types_supported` fields removed from wire output,
    `openid` removed from `scopes_supported` (now
    `["profile", "email", "offline_access"]`). Discovery is now
    RFC 8414 (OAuth 2.0 metadata), not OIDC Discovery 1.0 —
    accurate to what the implementation actually delivers.
    **`magic_link_sent_page()` UX bug fix** (folded in from
    v0.24.0 audit): template now takes `handle` and `csrf_token`
    parameters, both rendered as escaped hidden inputs; both
    callers in `/magic-link/request` (rate-limited path with
    placeholder UUID handle, happy path with real handle)
    updated. **ADR-008 drafted**: `id_token` issuance design,
    queued for implementation when scheduling permits (currently
    deferred behind TOTP track per security-track sequencing —
    see below). 14 new tests (8 discovery shape, 6 templates).
    Total 451 passing.
  - **0.26.0** ✅ — TOTP Phase 1: ADR-009 Draft + schema
    migration 0007 + `cesauth_core::totp` library skeleton
    (RFC 6238 generator and verifier with skew tolerance,
    recovery code generator, AES-GCM encryption helpers).
    SCHEMA_VERSION bumped 6 → 7. No HTTP routes, no
    enrollment UI, no verify wire-up — those are Phase 2.
    51 new tests including 5 RFC 6238 reference vectors.
    Total **502 passing**.
  - **0.27.0** ✅ — TOTP Phase 2a: storage layer.
    `cesauth_core::totp::storage` port traits, in-memory
    adapters, D1 adapters, `Challenge::PendingTotp` variant,
    `TOTP_ENCRYPTION_KEY`/`TOTP_ENCRYPTION_KEY_ID` env-var
    parsing in worker config. The original v0.27.0 plan
    bundled storage + routes; mid-implementation the
    storage layer alone proved review-able as its own
    release. 24 new tests. Total **526 passing**.
  - **0.28.0** ✅ — TOTP Phase 2b: presentation layer.
    Three new `cesauth_ui::templates` (enroll page,
    recovery-codes page, verify page) with 18 tests pinning
    CSRF inclusion / escape behavior / `<details>` placement
    of the recovery alternative form / no-email-leak from
    the verify page. New `cesauth_core::totp::qr` module
    with `otpauth_to_svg` using `qrcode` 0.14 at EcLevel::M,
    240 px, deterministic black-on-white. New
    `cesauth_worker::routes::me::auth::resolve_or_redirect`
    centralizing the cookie → session → 302-to-/login
    pipeline for `/me/*` routes. Workspace dep added:
    `qrcode = 0.14`. The original v0.28.0 plan bundled
    presentation + routes; mid-implementation the
    presentation layer alone proved review-able. 25 new
    tests. Total **551 passing**.
  - **0.29.0** ✅ — TOTP Phase 2c: HTTP routes + verify gate.
    Five new routes wired in `worker::lib::main`: `GET` and
    `POST` enroll, `GET` and `POST` verify, `POST` recover.
    Verify gate insertion in `post_auth::complete_auth` —
    for `AuthMethod::MagicLink` after step 1 (AR taken),
    checks `find_active_for_user`, on Some carries AR
    fields inline into `Challenge::PendingTotp` (no chained
    handle) and 302s to verify page. WebAuthn paths bypass.
    `complete_auth_post_gate` extracted from the original
    `complete_auth` body so both no-gate and post-verify
    paths share the same session-start/AuthCode-mint logic.
    Two new short-lived cookies introduced: `__Host-cesauth_totp`
    (5 min, SameSite=Strict, gate handle) and
    `__Host-cesauth_totp_enroll` (15 min, SameSite=Strict,
    enrollment row id). 12 new cookie-shape tests pinning
    Max-Age preservation, prefix integrity, TTL bounds, and
    distinct-cookie-name property. ~800 lines of route
    handlers covering enroll / verify / recover. 12 new
    tests. Total **563 passing**.
  - **0.30.0** ✅ — TOTP Phase 2d: polish + ADR Accepted.
    Disable flow (`GET/POST /me/security/totp/disable`) with
    minimal single-page confirmation. Cron sweep extension —
    drops `confirmed_at IS NULL AND created_at < now - 24h`
    rows after the existing anonymous-trial sweep on the same
    cron tick. `RedactionProfile.drop_tables` field; both
    built-in profiles (`prod-to-staging`, `prod-to-dev`) drop
    both TOTP tables (ADR-009 §Q5/§Q11). New
    `TotpAuthenticatorRepository::delete_all_for_user` trait
    method + adapters. New chapter
    `docs/src/deployment/totp.md` (~270 lines) covering
    encryption key provisioning, key rotation procedure with
    explicit caveat that dual-key resolution is not yet
    implemented (workaround: re-enroll users), admin reset
    path for lockout recovery, cron sweep semantics,
    operational invariants, diagnostic queries. Pre-prod
    release gate updated. **ADR-009 graduates `Draft` →
    `Accepted`** — design validated end-to-end across 5
    releases. 10 new tests (3 redaction + 5 disable template
    + 2 adapter delete_all_for_user). Disable flow is
    intentionally minimal — single-page confirm, silent
    redirect, no flash messages. The UX work (flash
    infrastructure, `/me/security` index, error-slot in
    enroll template, CSS for warning/danger states, handler
    integration tests) consolidates in the next release per
    the user-stated project value. **TOTP track
    feature-complete for the 0.x series.** Total **573
    passing**.

  After this track completes (now 11 phases instead of the
  original 8 — the v0.27.0 split added one and the v0.28.0
  split added two more), the schedule reverts to the
  feature track AFTER one UI/UX-focused release per the
  user-stated project value:

- **UI/UX iteration release.**
  - **0.31.0** ✅ — UI/UX improvements at TOTP-track-completion
    boundary, per user-stated project value "重要な予定が完了
    したタイミングで、UI/UX 改善に取り組みます". Shipped:
    P0-A `/me/security` Security Center index page (primary
    auth method label, TOTP enabled/disabled badge, recovery
    code remaining count with 4-tier rendering N=10/2-9/1/0,
    conditional enroll/disable link, anonymous-suppression
    variant); P0-B flash-message infrastructure
    (`__Host-cesauth_flash` cookie with HMAC + closed token
    table, `flash_block` template, all 4 success/info/warning
    paths wired: TOTP enabled/disabled/recovered + logged-out);
    P0-C `error: Option<&str>` slot on `totp_enroll_page` with
    autofocus on the code input; P0-D 8 design tokens
    (`--success`, `--success-bg`, `--warning`, `--warning-bg`,
    `--danger`, `--danger-bg`, `--info`, `--info-bg`) + dark-mode
    `@media` overrides + `.flash--*` and `.badge--*` modifier
    classes + `button.danger` / `button.warning` rules +
    `.visually-hidden` utility (this fixed a latent bug — the
    class was already referenced but the rule was missing);
    P1-A `validate_next_path` allowlist (`/me/*` + `/`)
    + `__Host-cesauth_login_next` cookie + threading through
    `complete_auth` → `complete_auth_post_gate`; new
    `docs/src/expert/cookies.md` (privacy notice covering all
    7 cookies, EDPB Guidelines 5/2020 rationale for "strictly
    necessary"). 614 → ~680 tests. Plan v2 §6.4 split policy
    invoked: P1-B (TOTP handler integration tests) deferred to
    v0.31.1 — see entry below. The pure-helper extracts
    (`attempts_exhausted`, `DISABLE_SUCCESS_REDIRECT`) shipped
    here as honest minimum coverage at this layer.

  - **0.31.1** ✅ shipped as **v0.32.1** — TOTP handler
    integration tests (P1-B split from v0.31.0) landed via
    Approach 2 (decision-extraction refactor) on top of the
    v0.32.0 audit-log hash-chain release rather than as a
    separate v0.31.x branch. Six handlers were refactored into
    pure-ish `decide_*` functions plus thin Env-touching
    wrappers: `disable::post_handler`, `recover::post_handler`,
    `verify::get_handler`, `verify::post_handler`,
    `enroll::get_handler`, `enroll::post_confirm_handler`.
    Each `decide_X` takes trait-bounded `&impl AuthChallengeStore`
    / `&impl TotpAuthenticatorRepository` /
    `&impl TotpRecoveryCodeRepository` references, returns an
    enum capturing the decision outcome plus any data the
    handler needs to build the response. Tests construct
    in-memory adapters from `cesauth-adapter-test` and exercise
    the full branch table per handler (3-10 tests each, 40
    total). Production wiring unchanged — handler signatures
    are signature-compatible. `unimplemented!()` stub repos
    used to pin port-surface regressions: a passing test
    confirms the decision didn't widen its port contract.
    Released as v0.32.1 because the user explicitly authorized
    "(α) v0.32.0 の上に v0.32.1 として出す" during the
    planning conversation; CHANGELOG entry frames it as
    "deferred from v0.31.0, landing on v0.32.x line". 717 →
    757 tests (+40).

- **Audit log integrity track.**
  - **0.32.0** ✅ — Audit log hash chain Phase 1 (ADR-010 Draft).
    Audit events moved from R2 NDJSON objects to a D1 table
    `audit_events` with SHA-256 hash chain over rows; case C
    (D1 source-of-truth) chosen during planning over case B
    (R2 + parallel D1 chain ledger) because the two-store
    design would have forked the chain under concurrency,
    permanently exposed cross-store consistency hazards, and
    forced N+1 reads on every verifier and admin search. R2
    `AUDIT` binding removed entirely from `wrangler.toml`; no
    backward-compat code left in the repo. New schema
    migration `0008_audit_chain.sql` introduces the table,
    three indexes (`(ts)`, `(kind, ts)`, partial
    `(subject) WHERE NOT NULL`), and a genesis row at `seq=1`.
    `cesauth_core::audit::chain` provides pure hash
    calculation; `cesauth_core::ports::audit::AuditEventRepository`
    is the trait; in-memory adapter and D1 adapter implement
    it. Worker `audit::write` rewritten internally (signature
    unchanged, all 90 call sites work). Admin search rewritten
    to D1 SELECT; `r2_metrics` removed in favor of
    `row_count.audit_events`. `/__dev/audit` rewritten.
    Documentation: ADR-010 Draft, new operator chapter
    `audit-log-hash-chain.md`, R2 audit references purged
    across deployment docs. Project-status framing softened
    across all docs (removed "pre-1.0" / "production-ready"
    claims) per user instruction during planning. 678 → 717
    tests (+39: 25 chain-hash tests in core, 14 in-memory
    repository tests in adapter-test). No verification cron
    yet — that is Phase 2.
  - **0.33.0** ✅ — Audit log hash chain Phase 2 shipped
    (ADR-010 Draft → **Accepted**). Daily cron at 04:00 UTC
    (piggybacked on the existing sweep schedule) walks the
    chain incrementally, resuming from the last checkpoint
    via the new `AuditEventRepository::fetch_after_seq`
    method (page size = 200) and verifying every link's
    payload_hash, chain_hash, and previous_hash linkage.
    New port `AuditChainCheckpointStore` with two records:
    `AuditChainCheckpoint` (resume + cross-check) and
    `AuditVerificationResult` (admin UI surface). KV adapter
    in `cesauth-adapter-cloudflare` stores them under the
    reserved `chain:` prefix in the existing `CACHE`
    namespace — no new wrangler binding, no schema migration.
    The dual-store design is the wholesale-rewrite defense:
    an attacker who compromises D1 still has to compromise
    KV synchronously to evade detection. Pure-ish verifier
    in core (`cesauth_core::audit::verifier::verify_chain`
    incremental + `verify_chain_full` operator-triggered);
    same Approach 2 pattern as v0.32.1 TOTP handlers
    (port-bound IO in scope, Env touching not). Admin UI at
    `/admin/console/audit/chain` renders status badge +
    checkpoint metadata + CSRF-guarded "verify now" button;
    cross-linked from the existing audit search page;
    six rendering tests pin status / tamper / wholesale-
    rewrite / growth-since-checkpoint / CSRF wiring. Tamper
    detection persists the failing result to KV (admin UI
    surfaces the alarm), logs at `console_error!` level, and
    does NOT advance the checkpoint — investigation gate
    before the chain advances past suspect rows. cesauth
    keeps writing audit events on tamper detection (chain is
    forensic, not runtime gating; ADR-010 §Q3). 757 → **777**
    tests (+20: 4 fetch_after_seq + 10 verifier tamper-
    detection scenarios + 6 UI rendering). Open Questions
    Q1 (checkpoint location) and Q3 (in-flight write
    behavior on tamper) closed in this release; Q2/Q4/Q5
    remain open. Rust dev-dep cycle workaround surfaced and
    documented: verifier integration tests live in
    `cesauth-adapter-test::audit_chain::tests` rather than
    `cesauth-core` itself, because dev-depending core on
    adapter-test would produce duplicate trait artifacts.
  - **0.34.0** ✅ — Refresh token reuse hardening shipped
    (ADR-011 Accepted). The structural rotation invariant
    from RFC 9700 §4.14.2 was already implemented and atomic
    since v0.4 (single-writer `RefreshTokenFamily` DO with
    a current_jti + retired_jtis ring; first reuse atomically
    revokes the family). v0.34.0 closes the **observability**
    gaps surfaced by an audit of the v0.33.0 baseline against
    the BCP §4.13 monitoring expectations. **`FamilyState`
    gains** `reused_jti` / `reused_at` / `reuse_was_retired`
    — all `#[serde(default)]` so existing DO storage records
    deserialize unchanged (no migration). **`RotateOutcome::
    ReusedAndRevoked` carries forensic payload** so the
    service layer doesn't need to peek the family again.
    **New `CoreError::RefreshTokenReuse` variant** distinct
    from `InvalidGrant`; service layer `rotate_refresh`
    dispatches by outcome. **Same wire response** for both
    error variants (`error: "invalid_grant"`, HTTP 400) —
    distinguishing externally would let attackers probe
    family state via error-code differentiation, the BCP-
    flagged side channel. The `(code, status)` decision is
    extracted as `oauth_error_code_status` so wire-equivalence
    can be unit-tested without constructing a wasm-backed
    `worker::Response`. **New audit event
    `EventKind::RefreshTokenReuseDetected`** with JSON payload
    `{family_id, client_id, presented_jti, was_retired}`;
    family_id decoded via audit-only lossy decoder so audit
    writes don't fail-close on malformed tokens.
    **`reuse_was_retired`** distinguishes recognized-retired
    jti (= real leaked token, classic case) from unknown jti
    (= forged or shotgun); operators can prioritize alerts on
    the higher-signal subcase. **Schema unchanged** from
    v0.33.0 (still SCHEMA_VERSION 8). **No DO migration.**
    **Wire format unchanged** for OAuth clients. 777 → **783**
    tests (+6: 3 forensic-field tests in adapter-test, 3
    error-mapper wire-equivalence tests in worker). ADR-011
    documents the audit findings + design + 3 deferred items
    (per-family rate limiting at `/token` — **resolved in
    v0.37.0**, user notification on reuse, tenant admin
    aggregate view).
  - **0.35.0** ✅ — Session management hardening shipped
    (ADR-012 Accepted). v0.34.x baseline audited against
    BCP guidance; five gaps closed: idle timeout enforcement
    (default 30 min, `SESSION_IDLE_TIMEOUT_SECS` env, 0
    disables), `me::auth::resolve_or_redirect` switched
    from `status()` to `touch()` (the load-bearing change —
    without it the new gates would be dormant; this also
    fixes a structural bug where `last_seen_at` was never
    advancing past `created_at` in v0.34.x), `SessionStatus`
    gains `IdleExpired` / `AbsoluteExpired` variants
    populated atomically with the DO state mutation,
    `ActiveSessionStore::list_for_user` port method backed
    by a new D1 `user_sessions` index (SCHEMA_VERSION 8 →
    9, migration 0009; per-session DO remains source of
    truth, D1 row is denormalized index for the user-facing
    list page), `/me/security/sessions` page renders one
    card per active session with auth method label /
    timestamps / client_id / shortened session id and a
    "取り消す" button per non-current row, current session
    shows "この端末" badge with disabled button (revoking
    your own session would surprise the user — the explicit
    logout flow is the right path), `POST /me/security/
    sessions/:session_id/revoke` handler with CSRF guard +
    ownership check (refuses revoke of another user's
    session via 403, defense in depth), four new audit
    event kinds: `SessionRevokedByUser`,
    `SessionRevokedByAdmin`, `SessionIdleTimeout`,
    `SessionAbsoluteTimeout`. Legacy `SessionRevoked` kind
    retained for backward-compatibility with v0.4-v0.34.x
    audit chain rows. **Session-id rotation on login** was
    already correct in v0.34.x via `complete_auth_post_gate`
    minting `Uuid::new_v4` per successful auth — preserved
    unchanged. **"New device" notification deferred** —
    requires general transactional email infrastructure
    cesauth doesn't yet have; would entangle two changes;
    documented in ADR-012 §"Considered alternatives". 783 →
    **801** tests (+18: 11 timeout/list tests in adapter-test,
    7 sessions_page rendering tests in ui). **Schema
    migration required**: operators must run `wrangler d1
    migrations apply` before serving v0.35.0 traffic.
    Without the migration `start()` fails on D1 INSERT and
    new sessions can't be created (existing sessions
    continue working through touch/revoke).

  After all of this — security track complete plus the
  UX iteration — the schedule reverts to the feature
  track (RFC 7662 Token Introspection, etc.).

- **Internationalization (i18n) track.** **Status:
  infrastructure shipped in v0.36.0 (ADR-013); migration
  partial.** cesauth's user-facing UI was language-mixed
  without negotiation pre-v0.36.0: the end-user TOTP /
  Security Center / login surfaces carried hardcoded Japanese
  strings (e.g., "TOTP を有効にしました。", "二段階認証 (TOTP)",
  the wrong-code re-render error
  "入力されたコードが一致しませんでした。…"), the admin console
  carried hardcoded English, and machine-emitted error bodies
  were English. There was no `Accept-Language` handling, no
  locale negotiation, no message catalog, no fallback chain.
  The v0.31.0 flash module carried a TODO at
  `crates/worker/src/flash.rs:215` ("Translations are out of
  scope for v0.31.0; future i18n would replace this lookup
  with one keyed by Accept-Language") — this track is the
  payment of that debt.

  Phasing is open; the track may run in parallel with feature
  work because the surface area is small and discrete:

  - **i18n-1** ✅ — message-catalog infrastructure shipped
    in v0.36.0 (ADR-013 Accepted). `cesauth_core::i18n`
    module: closed `Locale` enum (Ja, En), closed
    `MessageKey` enum (22 variants in v0.36.0), `lookup`
    function with compile-time exhaustive coverage of both
    axes (adding a key without a translation in every locale
    is a build error), RFC 7231 §5.3.5 q-value-aware
    `parse_accept_language` parser. `cesauth_worker::i18n::
    resolve_locale(&Request)` is the per-request
    negotiation entrypoint. Migration pattern: each call
    site adds a `_for(..., locale)` variant alongside the
    existing function; the plain function becomes a
    default-locale shorthand so existing callers continue
    to work unchanged. **20 unit tests** in
    `cesauth_core::i18n::tests`: locale parsing
    (case-insensitive, region-stripping, unknown returns
    None), Accept-Language parsing edge cases (empty,
    q-value priority, q=0 dropped per RFC 7231, wildcard,
    malformed q treated as 1.0 lenient, all-unsupported
    falls through, tie-breaking in document order,
    browser-typical headers), catalog completeness (every
    key resolves to nonempty in every locale, no two keys
    share text within a locale).
  - **i18n-2** 🚧 partial through v0.39.0 — surfaces migrated
    to date: flash banners (5 keys, v0.36.0),
    `/me/security/sessions` chrome (16 keys, v0.36.0), TOTP
    enroll wrong-code error (1 key, v0.36.0), **login page**
    (10 keys, v0.39.0), **TOTP enroll page** (11 keys,
    v0.39.0), **TOTP verify page** (12 keys including new
    `TotpVerifyWrongCode`, v0.39.0), **Security Center
    index** (13 keys, v0.39.0). MessageKey total 22 → 70.
    Catalog completeness tests refactored from hardcoded
    `all_keys` arrays to `for_each_key(closure)` — adding a
    new variant without adding it to the iterator is now a
    build error, not a missed-test silent gap. New
    `cesauth_ui::js_string_literal` helper introduced for
    safe interpolation of catalog strings into inline
    `<script>` blocks (login page passkey-failed JS error
    message); 8 dedicated tests for the helper covering
    UTF-8 multi-byte passthrough, `</script>` defense,
    control-char `\uXXXX` fallback. Disabled-state
    Security Center TOTP rendering goes through the
    catalog; **enabled-state + recovery-codes status row
    intentionally still hardcoded JA** pending v0.39.1+
    (recovery messages need pluralization — ADR-013 §Q4).
    `PrimaryAuthMethod::label()` independently localized
    (used by admin console too) — separable thread, not
    in v0.39.0 scope. Remaining for v0.39.1+: TOTP
    recovery codes display, TOTP disable confirm, magic
    link request + sent, error pages,
    `PrimaryAuthMethod::label`, Security Center
    enabled-state recovery-codes row.

  - **i18n-3** — additional locales added on demand. Pull
    requests welcome.

  - **i18n-4** — RFC 5646 / IETF-BCP-47 language tag
    parsing edge cases (script subtags like `zh-Hant`,
    region subtags like `pt-BR`). Defer until i18n-2 ships
    and real demand surfaces.

  Acceptance for i18n-1 + i18n-2 (the MVP): every
  user-visible string in the v0.33.0+ end-user surfaces
  comes through a `MessageKey` lookup; tests pin the table
  shape; both `ja` and `en` resolve every key. No
  template-side hardcoded prose surviving in the
  end-user templates after the migration.

- **Real mail provider for Magic Link delivery.** The current
  `dev-delivery` audit line containing the plaintext OTP must be
  replaced with a transactional mail HTTP call keyed by
  `MAGIC_LINK_MAIL_API_KEY` before any production deployment.
  (Release gate — see [Security → Pre-production release gates](docs/src/expert/security.md).)

  **Implementation choice (chosen 2026-04)**: use `wasm-smtp v0.6`
  with the `wasm-smtp-cloudflare` adapter. Both crates released
  in 2026-04. The integration point is
  `cesauth-worker/src/routes/magic_link/request.rs` (the
  `dev-delivery` line at line ~157 — the audit-write that today
  carries the plaintext OTP must split into (a) an audit-write
  with handle only, and (b) a `wasm-smtp` send call). Operator
  config flows through `wrangler.toml` `[vars]` for the SMTP
  endpoint + `[secrets]` for credentials. Scope: ~1 release,
  most of it operator-doc work in `docs/src/deployment/`.

- **Discoverable-credential (resident-key) WebAuthn flows.**
  Currently cesauth requires the user to start from an identifier;
  resident keys would allow true username-less login.

- **`prompt=consent` with a real consent screen.** Requires a
  consent-record table, consent-screen UI template, and handler
  wiring. Until then the value is rejected with `invalid_request`.

- **Conditional UI for WebAuthn** (`mediation: "conditional"`) —
  autofill-assisted sign-in.

- **Admin Console hot-path counters (0.3.2).** The Cost Dashboard
  reads `counter:workers:requests:YYYY-MM-DD` and
  `counter:turnstile:{verified,rejected}:YYYY-MM-DD` but nothing
  writes them yet, so fresh deployments report zero for Workers and
  Turnstile. The missing piece is a per-request KV increment, and the
  open design question is at what granularity to count:
    - every fetch (including 404s and preflight)?
    - only requests that land on a real handler?
    - by HTTP method / response class?
  The answer shapes what operators see in the dashboard, and the
  spec is silent on it — defer until the counting policy is settled.
  A related open question: how to handle the read-modify-write race
  (KV has no atomic increment; concurrent requests will lose
  increments). Likely acceptable for a "proxy" metric, but worth
  recording explicitly.

- **Tenancy-service HTTP routes (shipped in 0.7.0).** The
  `/api/v1/...` surface ships JSON CRUD for tenants, organizations,
  groups, memberships, role assignments, and subscriptions. Plan-
  quota enforcement (max_users / max_organizations / max_groups)
  runs on org-create and group-create paths. The remaining design
  question — admin bearer vs session cookie for the tenant-scoped
  console — is now scoped to the v0.8.0 admin console, since the
  0.7.0 surface uses the existing 0.3.x admin-bearer model
  exclusively. The `check_permission` integration is also still
  pending: 0.7.0 routes go through `ensure_role_allows` (admin-side
  capability) because admin tokens have no `users` row to feed into
  `check_permission`. The two converge in 0.8.0+ when user-as-bearer
  arrives.

- **Read-only SaaS console (shipped in 0.8.0).** The
  `/admin/saas/*` HTML surface gives cesauth's operator staff a
  navigable view of tenancy state — tenants, organizations,
  members, subscriptions, role assignments — without having to
  curl the JSON API. Five pages, all read-only by design;
  mutations remain on `/api/v1/...`. The footer carries an
  explicit "read-only" marker so operators don't mistake this
  surface for the writable v0.9.0 follow-up.

- **SaaS console mutation forms (shipped in 0.9.0).** Wraps the
  v0.7.0 JSON API in HTML forms following a risk-graded preview/
  confirm pattern: one-click submit for additive operations
  (creates), v0.4.0-style preview/confirm for destructive ones
  (status changes, group deletes, plan changes). Eight forms ship:
  tenant create / set-status, organization create / set-status,
  group create / delete, subscription set-plan / set-status.
  Affordance buttons gate on `Role::can_manage_tenancy()` so
  ReadOnly operators don't see broken-link buttons. Auth caveat:
  forms POST same-origin and the bearer rides on the
  `Authorization` header — operators must use a tool that sets
  the header (curl, browser extension, or the future cookie-auth
  path).

- **Membership / role-assignment forms (shipped in 0.10.0).** The
  HTML console reaches feature parity with the v0.7.0 JSON API:
  three flavors of membership add (one-click submit) and remove
  (one-step confirm), plus role-assignment grant (full Scope
  picker) and revoke (one-step confirm). Reachable from the
  affordance buttons on tenant detail, organization detail, and
  user role-assignments pages. Operations+ only — ReadOnly
  continues to see the read pages with no mutation buttons.

- **Tenant-scoped admin surface — design settled (0.11.0).** The
  three open design questions from the v0.10.0 deferred list have
  been answered as ADRs at `docs/src/expert/adr/`:
  - **ADR-001**: path-based URLs (`/admin/t/<slug>/...`).
    Single cert, single origin, tenant identity visible.
  - **ADR-002**: user-as-bearer extends `admin_tokens` with an
    optional `user_id` column. `Authorization: Bearer` stays as
    the wire format. No new CSRF surface; no new cryptographic
    key.
  - **ADR-003**: complete URL-prefix separation between
    `/admin/saas/*` (system-admin) and `/admin/t/<slug>/*`
    (tenant-admin). No mode switch. Tenant-boundary leakage is
    structurally impossible.

  The 0.11.0 release shipped the foundation reflecting these
  decisions: migration `0005`, the `AdminPrincipal::user_id`
  field, the `is_system_admin()` helper, and Cloudflare D1
  adapters that read the new column. No UI yet — the surface
  implementation lands in 0.13.0.

- **Project-hygiene release with naming-debt cleanup (shipped in
  0.12.0).** Two threads landed together:
  - **Metadata** — author / license / repository now match
    reality (`nabbisen`,
    `https://github.com/nabbisen/cesauth`). Project framing
    language tightened: "Commercial SaaS" / "商用 SaaS" replaced
    with "tenancy service" or equivalent functional
    descriptions across docs and comments. `.github/` gains
    `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1),
    `CONTRIBUTING.md`, and four `ISSUE_TEMPLATE/*` files.
  - **Naming-debt cleanup** — the `saas/` module path under
    both `crates/ui/` and `crates/worker/src/routes/admin/`,
    the `/admin/saas/*` URL prefix, the `SaasTab` public type,
    and the `via=saas-console` audit reason marker have all
    been renamed to `tenancy_console` / `/admin/tenancy/*` /
    `TenancyConsoleTab` / `via=tenancy-console`. Operator-
    visible — bookmarks and scripts targeting the old prefix
    need updating. No compatibility-redirect routes were
    added; the SemVer caveat documented in the policy section
    permits the hard rename.

- **Buffer / follow-up release (shipped in 0.12.1).** Reserved
  as a placeholder slot for any issues the 0.12.0 rename would
  surface in real-world use. The shippable content turned out
  to be two small but worthwhile threads:
  - **Stale-narrative cleanup** — three docstrings carried
    forward-references and historical claims that the 0.12.0
    rename and intervening release-slot reshuffles
    invalidated. Fixed in `crates/ui/src/tenancy_console.rs`
    (the false "URL prefix preserved" claim and the wrong
    "since v0.18.0" marker) and
    `crates/core/src/tenancy/types.rs` (`AccountType::Anonymous`
    forward-ref to 0.18.0 → 0.14.0; `ExternalFederatedUser`
    forward-ref to 0.18.0 → unscheduled).
  - **Dependency audit** — manual review of every direct
    workspace dependency. No bumps. `getrandom 0.2` and
    `rand_core 0.6` are intentionally pinned at the older
    line for wasm32-unknown-unknown + Cloudflare Workers
    integration; bumping is gated on the workers-rs
    ecosystem aligning on the corresponding 0.3 / 0.9 lines.
    Every other direct dep is current.

- **Tenant-scoped admin surface — read pages shipped (0.13.0).**
  The 0.11.0 foundation lands as a working surface. Six read
  pages under `/admin/t/<slug>/...` (overview, organizations,
  organization detail, users, role assignments, subscription),
  a per-route auth gate that enforces ADR-003's three
  invariants (principal is user-bound, slug resolves, user
  belongs to the slug's tenant), and `check_permission`
  integration via a new `gate::check_read` helper that wraps
  the spec §9.2 scope-walk for the worker layer. New port
  methods: `AdminTokenRepository::create_user_bound` (mints
  tokens with `admin_tokens.user_id` populated) and
  `UserRepository::list_by_tenant` (powering the tenant-scoped
  users page). 245 tests passing (+26): 9 in
  `core::tenant_admin::tests` for the gate, 4 in
  `adapter-test` for `create_user_bound`, 13 in
  `ui::tenant_admin::tests` for chrome and per-page rendering.
  Read pages only — mutation forms in 0.14.0 mirror the
  v0.8.0 → v0.9.0 split for the system-admin surface.

- **Tenant-scoped high-risk mutations + token-mint UI
  (shipped in 0.14.0).** Six tenant-scoped form pairs at
  `/admin/t/<slug>/...` (organization create + status,
  group create + delete, role-assignment grant + revoke), plus
  one system-admin form pair at
  `/admin/tenancy/users/:uid/tokens/new` exposing
  `AdminTokenRepository::create_user_bound`. Each handler
  composes the v0.13.0 gate (`auth::resolve_or_respond` →
  `gate::resolve_or_respond` → `gate::check_action`) with the
  appropriate write permission slug; preview/confirm gating on
  the `confirm` form field; audit emission with
  `via=tenant-admin,tenant=<id>` to distinguish from
  `via=tenancy-console`. Defense-in-depth invariants enforced
  per-handler:
  - `organization_set_status`: re-verifies
    `org.tenant_id == ctx_ta.tenant.id`.
  - `group_delete`: walks `GroupParent` to verify either
    `group.tenant_id` or the parent organization's tenant_id.
  - `role_assignment_grant`: rejects `Scope::System` outright
    (per ADR-003), forces tenant scope's scope_id to the
    current tenant, and `verify_scope_in_tenant` walks
    storage to confirm Organization / Group / User scopes
    belong to this tenant before granting.
  - `role_assignment_revoke`: re-verifies the assignment's
    user belongs to this tenant.

  The `gate::check_read` from 0.13.0 is now a thin wrapper
  around a more general `gate::check_action(permission, scope, ctx)`
  that accepts an explicit `ScopeRef` (mutations need narrower
  scopes than reads). 257 tests pass (+12), zero warnings.

- **Tenant-scoped additive mutations + affordance gating
  (shipped in 0.15.0).** Six membership form pairs at
  `/admin/t/<slug>/...` (`memberships/`,
  `organizations/<oid>/memberships/`, `groups/<gid>/memberships/`
  — each with new + delete flavors). Two new permission slugs
  added to fill the symmetry gap: `TENANT_MEMBER_ADD` and
  `TENANT_MEMBER_REMOVE`. Defense-in-depth: target user_id is
  verified to belong to the current tenant before any add
  proceeds.

  Affordance gating: every read page and form page now renders
  mutation links/buttons only when the current user holds the
  relevant permission at tenant scope. Implementation:
  - **`check_permissions_batch`** new in
    `cesauth_core::authz::service` — evaluates N (permission,
    scope) queries with one `list_for_user` call + cached role
    lookups. The scope-walk is in-memory; the cost is one D1
    round-trip total, not N.
  - **`Affordances` struct** in `cesauth_ui::tenant_admin` —
    twelve boolean flags. `Default` is all-false (the safe
    default); `all_allowed()` is provided for tests.
  - **`gate::build_affordances`** in worker — issues the batch
    check and maps results to the struct.
  - Each read/form template now takes `&Affordances` and emits
    HTML conditionally for "+ New organization", "Change
    status", "+ New group", "delete", "+ Add member",
    "+ Grant role", "revoke", etc.

  The route handlers behind each affordance still re-check on
  submit (defense in depth). The affordance gate is the
  operator's first signal — clicking what they can't do already
  returned 403 since v0.13.0, but they shouldn't have to find out
  by clicking. 276 tests pass (+19), zero warnings.

  This release brings the tenant-scoped surface to feature
  parity with what the system-admin tenancy console reached at
  v0.10.0.

- **Anonymous trial → human user promotion — design + foundation
  (shipped in 0.16.0).** ADR-004 settles the five design
  questions (provenance / token issuance / retention / conversion
  ceremony / audit trail). Foundation in this release:
  - **Migration `0006_anonymous.sql`** — `anonymous_sessions`
    table with `token_hash` PK, FK CASCADEs to `users` and
    `tenants`, indexes for the retention sweep and per-user
    revocation paths.
  - **`cesauth_core::anonymous`** — `AnonymousSession` value
    type with `is_expired()` (boundary inclusive — pinned by
    test), `AnonymousSessionRepository` port (4 methods),
    `ANONYMOUS_TOKEN_TTL_SECONDS` (24h) and
    `ANONYMOUS_USER_RETENTION_SECONDS` (7d) constants.
  - **In-memory adapter** in `cesauth-adapter-test`, **D1
    adapter** in `cesauth-adapter-cloudflare` — both behind
    the same trait; the adapter test that runs both will
    catch divergence early in 0.17.0.
  - **`EventKind`** gains `AnonymousCreated`,
    `AnonymousExpired`, `AnonymousPromoted` so v0.17.0's
    emit calls don't force an audit-schema bump on the
    downstream side.

  286 tests pass (+10 over v0.15.1); zero warnings. The
  HTTP surface and existing audit kinds are untouched —
  this is a pure additive release. ADR-004 is in `Draft`
  status until v0.17.0 ships the routes that exercise it.

- **Anonymous trial — HTTP routes (shipped in 0.17.0).**
  ADR-004 graduates from `Draft` to `Accepted`. Two routes
  land:
  - `POST /api/v1/anonymous/begin` — unauthenticated (per-IP
    rate limit only). Mints fresh `users` row +
    `anonymous_sessions` row, returns plaintext bearer once.
    Strict rate limit: 20 over 5 minutes per IP, with
    Turnstile-style escalation at 10. The 7-day daily
    retention sweep (0.6.05) is the second line of defense.
  - `POST /api/v1/anonymous/promote` — anonymous-bearer
    authenticated. Two-step body shape (no `code` =
    issue-OTP step; with `code` = verify-OTP+apply step)
    distinguishes phases under one URL. Magic Link
    infrastructure reused unchanged. UPDATEs the user row
    in place (preserving `User.id`); revokes the anonymous
    bearer at promotion time. Email collisions return a
    distinguishable error (`email_already_registered`) so
    the client can render the right guidance vs OTP-failure.

  Defense-in-depth invariants pinned by adapter-level tests:
  revoke-before-update fail-safe ordering, per-user revoke
  isolation, idempotent double-promote (the racy second
  submit's revoke returns `Ok(0)`, then the route's
  `account_type == Anonymous` re-check refuses with
  `not_anonymous`). 289 tests pass (+3 over v0.16.0);
  zero warnings.

- **Anonymous trial — daily retention sweep (shipped in 0.18.0).**
  ADR-004 Phase 3, the final piece. The flow is now
  feature-complete. New `[triggers]` block in `wrangler.toml`
  (operator-visible config change — first cron trigger in
  cesauth) fires the new `#[event(scheduled)]` handler at
  04:00 UTC daily. The sweep handler runs:
  ```sql
  SELECT id, ... FROM users
   WHERE account_type='anonymous' AND email IS NULL
     AND created_at < ?  -- now - 7d
  ```
  emits one `AnonymousExpired` audit event per row, then
  deletes the row (FK CASCADEs clean up
  `anonymous_sessions`, memberships, role assignments).
  Best-effort failure semantics: per-row failures log `Warn`
  and continue; the next day's sweep retries the survivors.

  **Operator-visible**: cron invocation history in the
  Cloudflare dashboard, `wrangler tail` for live streaming,
  one `Info` summary line per sweep:
  `"anonymous sweep complete: X/Y rows deleted"`. Operator
  runbook gains "Verifying the anonymous-trial retention sweep
  ran" with a residual-count diagnostic query.

  Schema additions: `UserRepository::list_anonymous_expired`
  and `delete_by_id` port methods; in-memory + D1 adapters;
  `EventKind::AnonymousExpired` was pre-added in 0.16.0. 294
  tests pass (+5 over v0.17.0); zero warnings.

- **Data migration tooling (server-to-server moves) — Phase 4:
  polish (shipped in 0.22.0).** All four phases of ADR-005 are
  now shipped; the data-migration tooling is feature-complete
  for the design's scope. Phasing summary:

  - **0.19.0** — design + foundation (ADR-005, library value
    types, CLI skeleton).
  - **0.20.0** — real export + verify, the source side.
  - **0.21.0** — real import, the destination side; ADR-005
    graduated to Accepted.
  - **0.22.0** (this release) — polish: `--tenant <id>`
    filter on `export` (with `TenantScope::Global` vs
    `OwnColumn` per-table classification + manifest scope
    record), `cesauth-migrate refresh-staging` single-command
    combinator (export + redaction + import in one
    invocation, opinionated for single-operator runs, `--yes`
    for unattended use), email-uniqueness-within-tenant
    invariant check (redaction-aware, case-insensitive,
    `users.email` `COLLATE NOCASE`-matching), per-row import
    progress via `ProgressSink` decorator. 379 tests pass
    (+21 over v0.21.0).

  **Deferred to post-1.0 polish** — these were originally on
  the v0.22.0 list but are reclassified because they don't
  change the design and don't have known operator demand:

  - **Resume on interruption** — checkpoint-file format is
    real new design surface. The current Ctrl-C-then-restart-
    from-zero workflow is acceptable for the dump sizes the
    tool targets.
  - **Native Cloudflare HTTP API client** — wrangler shell-out
    works. A native client would avoid subprocess spawn costs
    and the wrangler dependency, but it adds a non-trivial
    HTTP auth surface to the binary.
  - **Custom invariant registration via CLI** — the library
    accepts a slice of `InvariantCheckFn` already; the CLI
    just hardcodes `default_invariant_checks()`. When an
    operator hits a case the defaults miss, the surface to
    expose this is straightforward.

- **OAuth 2.0 Token Introspection (RFC 7662).** `POST /introspect`.
  RFC 7009 (`/revoke`) shipped with the OIDC core; the
  introspection counterpart is the gap. RPs that want to
  validate opaque access tokens stateful-style (instead of
  parsing JWTs themselves) need this. Implementation lifts
  the existing `ActiveSessionStore::status` lookup and wraps
  it in the RFC 7662 response shape (`active`, `client_id`,
  `username`, `exp`, etc.) gated on client authentication.
  The discovery doc gains an `introspection_endpoint`
  declaration. Estimated scope: ~150 lines + tests.

- ✅ **Property-based tests (`proptest`)** — shipped in v0.51.1 (RFC 003). ~~for round-trip and
  matcher invariants.** Two surfaces benefit most:
  1. **Crypto round-trips**: `EncodingKey::from_ed_pem` →
     `DecodingKey::from_ed_der` → JWT sign → JWT verify →
     equal claims; magic-link token gen → verify →
     equal subject. Pure-deterministic, well-defined
     invariants — proptest catches the pathological inputs
     that example-based tests don't reach.
  2. **`redirect_uri` matcher**: OAuth's redirect-URI
     matching is historically the most bug-prone piece of
     a provider (open-redirect via prefix-match, port
     stripping, percent-encoding, IDN). proptest can
     generate adversarial URI pairs and assert the match
     decision matches the spec.

  Modest dep cost (proptest is dev-dep only). Target slot:
  any maintenance window.

- ✅ **`cargo fuzz` for the JWT parser surface** — shipped in v0.51.2 (RFC 005). cesauth
  receives potentially adversarial JWTs on every
  `Authorization: Bearer ...` request. The `jsonwebtoken`
  crate itself is upstream-fuzzed, but cesauth's wrappers
  (`jwt::signer.rs` PEM/DER parsing, claim extraction
  helpers) are independent code paths. Fuzz them for panics,
  OOM, and DoS. Layer-1 setup (single fuzz target,
  GitHub Actions one-shot run) is cheap; long-term continuous
  fuzzing is parked under "Later" for now. Note: CIDR
  parser is **not** a fuzz target — cesauth has no IP
  allowlist code path (Cloudflare dashboard handles
  IP-level controls). Config parser is `Config::from_env`
  reading discrete env vars, surface too small to fuzz
  productively.

- ✅ **WebAuthn error → typed client responses** — shipped in v0.51.1 (RFC 004). ~~The current
  `CoreError::WebAuthn(&'static str)` carries diagnostic
  strings (`"rpIdHash mismatch"`, `"signature invalid"`,
  etc.) that surface only in server-side logs. The HTTP
  response shape collapses them into a generic 400. Client
  UX would benefit from a small `WebAuthnErrorKind` enum
  exposed in the JSON body — distinguishing "wrong
  authenticator", "user cancelled", "credential not
  registered", "RP id mismatch (likely subdomain
  misconfiguration)" so RPs can render specific guidance.
  Server-side strings stay as today (the typed variant is
  the *category*, the string is the *detail*).

- **Domain-metric observability.** Cloudflare Analytics
  already covers HTTP-level metrics (request rate, error
  rate, p50/p95/p99 latency). The gap is **domain-specific**
  counters: `auth_attempts_total{result, method}`,
  `tokens_issued_total{kind}`, `webauthn_ceremony_failures_total{stage}`.
  Architecturally, Prometheus pull is a poor fit for
  Workers (stateless, horizontally scaled — `/metrics` would
  return single-instance values). The native path is to
  emit metric events through the existing `log.rs`
  channel and aggregate downstream via Logpush →
  ClickHouse / BigQuery / Datadog, **or** use the
  Cloudflare `cloudflare:analytics-engine` binding which
  is purpose-built for this. Target slot: any maintenance
  window once the operator-facing dashboarding requirement
  becomes concrete.

- **`cargo audit` integration (shipped in 0.15.1).** Three
  layers landed at once:
  1. **Initial sweep**: ran against the rustsec/advisory-db
     `main` checkout on 2026-04-28. One finding —
     RUSTSEC-2023-0071 in `rsa 0.9.10` (Marvin Attack timing
     side-channel), pulled in transitively by `jsonwebtoken`'s
     `rust_crypto` feature. cesauth never exercised the RSA
     path (EdDSA-only), but the dep would have shipped in the
     workspace lock anyway. Fixed by narrowing `jsonwebtoken`
     features from blanket `rust_crypto` to explicit
     `ed25519-dalek` + `rand`. Post-fix sweep clean; dep count
     186 → 176.
  2. **`.github/workflows/audit.yml`** using
     `rustsec/audit-check@v2.0.0`. Triggers: push, PR,
     weekly cron (Mondays 06:00 UTC), manual dispatch.
     New advisories fail the workflow.
  3. **Operator documentation**: `docs/src/deployment/production.md`
     gains a "Step 7 — Verify dependencies" pre-deploy
     check; the operator runbook in
     `docs/src/expert/tenancy.md` documents the same command
     under "Verifying dependencies before an upgrade".

  Layer 4 (Makefile / xtask wrapper) is **not planned** —
  the cost-vs-value isn't there for a workspace with no
  Makefile today.

- **Login → tenant resolution.** Today `users.email` is globally
  unique. Multi-tenant login flows need either
  tenant-scoped email uniqueness (schema change) or a tenant-picker
  step in the login flow. Spec §6.1 mentions tenant-scoped auth
  policies; the precise UX is open. Tracked here so the change is
  not made silently.

- **External IdP federation.** `AccountType::ExternalFederatedUser`
  is reserved in 0.5.0 but no IdP wiring exists. SAML / OIDC
  federation surface; specific protocols TBD.

### Later

- ✅ **`oidc_clients.client_secret_hash` documentation drift** — resolved in v0.51.0 (RFC 002).
  ~~The schema comment in `migrations/0001_initial.sql` describes
  `client_secret_hash` as "argon2id(secret) or NULL", but no
  Argon2 implementation exists~~ in cesauth as of v0.26.0 — the
  hashing path for client_secret falls back to whatever the
  adapter does, which currently is plaintext comparison or
  unimplemented. (Discovered during the v0.26.0 TOTP work.)
  Two paths to resolve: either implement Argon2id hashing of
  client_secret on write + verify on read (matches the schema
  comment, adds a real password-stretching dependency for the
  one input type that's user-chosen), OR relax the schema
  comment to "SHA-256(secret) or NULL" and route client_secret
  through the same hashing path as admin_tokens (matches what
  cesauth actually does for similar bearer secrets). The
  former is more rigorous; the latter is more honest. Either
  is fine; the current state — schema lying — is not.

- ✅ **OIDC `id_token` issuance** — shipped v0.54.0 (RFC 001, ADR-008).
  cesauth now fully implements OIDC Core §3.1.2.2.
  Discovery doc restored to OIDC posture.
  See `docs/src/expert/adr/008-id-token-issuance.md`.
  Closes the OIDC compliance gap surfaced by the v0.25.0 email
  verification audit: `exchange_code` and `rotate_refresh`
  currently return `id_token: null`, and the discovery doc was
  honestly reset to RFC 8414 OAuth 2.0 metadata until id_token
  ships. Implementation requires:
  - `UserRepository` injected into `cesauth_core::service::token`
    (generic-parameter addition).
  - `auth_time` plumbed through `Challenge::AuthCode` and
    `RefreshTokenFamily` DO state.
  - `build_id_token_claims` pure function with scope-driven
    population (`email`/`email_verified` iff `email` scope;
    `name` iff `profile` scope).
  - Discovery doc restored to OIDC Discovery 1.0 shape with
    `claims_supported` field added.
  - End-to-end test: authorize → token exchange → id_token
    decoded and claims verified.
  - 8 v0.25.0 discovery shape tests inverted/extended to OIDC
    posture.

  **Scheduled when**: TOTP track (v0.26.0 - v0.30.0) is now
  complete. The schedule continues with the UI/UX iteration
  (v0.31.0) and the audit-log-hash-chain track (v0.32.0+)
  before the feature track resumes. Likely v0.36.0 or later.
  Not blocking 1.0 unless a deployment requires OIDC compliance
  for an identity-federation integration. The audit doc and
  ADR-008 keep the design ready for whoever picks it up.

- **`prompt=select_account`.** Requires multi-session / account-picker
  UX. Rejected today.

- **Full FIDO attestation verification** (`packed`, `tpm`,
  `android-key`, `android-safetynet`, `fido-u2f`, `apple`).
  Requires a FIDO Metadata Service (MDS) implementation and a CA
  trust store. Useful if a deployment needs AAGUID-gated access
  control.

- **Device Authorization Grant** (RFC 8628) for CLI / smart-TV
  clients.

- **Dynamic Client Registration** (RFC 7591 / 7592) if multi-tenant
  deployments become a target.

- **Request Objects** (`request` / `request_uri` parameters, JAR).

- **Pushed Authorization Requests** (RFC 9126 PAR).

- **Rate-limit bucket tuning** based on production telemetry.

- **FIDO Alliance conformance certification.** Costs real money and
  assumes full attestation support is already in.

- **OIDC `client_secret` brute-force lockout (per-client).**
  Per-client failure tracking on `oidc_clients` for
  `client_secret_basic` / `client_secret_post` authentication
  failures at `/oauth/token`. **Trigger condition for adoption**:
  production telemetry shows non-trivial volume of failed
  `client_secret` attempts against existing clients. As of
  v0.23.0 (the canonical release), the prior v0.23.0-withdrawn
  attempt assumed user-account lockout, which is inapplicable
  to cesauth's password-less authentication model — Magic Link
  and WebAuthn are the only credential paths and both have
  cryptographic brute-force resistance. Per-client lockout
  would have a different data model (lockout state on
  `oidc_clients`, no per-tenant policy override since clients
  are tenant-scoped, no Magic Link/WebAuthn interaction). A
  future ADR (probably -010) would re-design from the
  per-client angle if the threat materializes. The withdrawn
  artifact (`cesauth-0.23.0-account-lockout-withdrawn.tar.gz`)
  is preserved for reference; ADR-006 number is not reused.

- **CSP without `'unsafe-inline'` (nonces or template
  refactor).** ADR-007 §Q3 documents the v0.23.0 limitation:
  cesauth's HTML templates embed `<style>` and `<script>`
  inline, requiring per-route CSPs to use `'unsafe-inline'`.
  Two paths to remove this: extract inline content to
  same-origin files, or generate per-request nonces and
  attach them to every inline block. The latter is the
  modern best practice. Either path is real refactor work
  (templates module + every render path); track separately
  from the security headers shipped in v0.23.0.

- **Cesauth-specific attack surface review.** A periodic
  audit (ideally before each major milestone, and at minimum
  before any 1.0 release) of cesauth-specific attack
  surfaces. Initial 2026 review identified the following as
  worth examining; this list is not exhaustive and the
  reviewer should look broader:
  - **Open redirect via OAuth `redirect_uri` matcher**: the
    matcher implementation should be exercised with proptest-
    generated adversarial URI pairs. (Already on roadmap as
    "Property-based tests".)
  - **JWT alg confusion attack**: confirm the verifier
    rejects `alg: none`, and never verifies `alg: HS256`
    against a public key.
  - **Confused deputy in tenant scoping**: tenant A's admin
    operating tenant B's resources via global `/api/v1/...`
    routes. (Already on roadmap as "`check_permission`
    integration".)
  - **Subdomain takeover**: if a deployment surfaces
    tenants on `<slug>.example.com`, retired tenants must
    have DNS reclaimed.
  - **PKCE enforcement**: confirm public clients are
    rejected without PKCE.
  - **Cookie security**: SameSite, Secure, HttpOnly attrs
    on every cookie; Path scope; rotation on session id.
  - **Timing side-channels** in token comparison and
    secret verification (constant-time comparison
    everywhere).
  - **Open registration paths**: anonymous trial creation
    rate limit, abuse vectors.

  **Maintainer TODO**: schedule the next review by 2026-Q4
  or before v0.30.0, whichever is sooner. Outcomes either
  feed into the security-track minor releases or become
  individual hardening releases.

---

## Explicitly out of scope

The following are not planned for any future release. If a deployment
needs one of these, cesauth is the wrong choice.

- **Password-based authentication.** No password-hash table, no
  "forgot password" flow, no password reset endpoint. Magic Link
  and passkey cover the equivalent UX without the password's
  problems.

- **SAML 2.0**, **WS-Federation**, **OAuth 1.0**. Out of scope in
  both directions (not as IdP, not as consumer).

- **LDAP directory integration.** Not blocked on LDAP specifically;
  blocked on the entire concept of federating identity from an
  external directory. cesauth is a primary identity source.

<!-- "Management GUI" was removed from this list on 2026-09-09: the owner
     ruled the operator console a FIRST-CLASS product surface. The line had
     said the admin surface is an API and a dashboard was the integrator's
     problem. That was false since v0.3.0, and RFC 012 had already corrected
     the identical claim in the README — leaving this list asserting the
     opposite of a correction the project had already made. The console
     programme is RFC 131 (rfcs/accepted/131-mockup-adoption-strategy.md);
     its four new screen groups are roadmap work, not a side investment. -->

- **Implicit flow** / **hybrid flow**. Deprecated by OAuth 2.1 for
  good reasons.

- **Docker / container-based production deployment.** cesauth
  targets the Cloudflare Workers runtime (V8 isolate, wasm32
  + the `cf::*` API surface, Durable Objects, R2, D1). None of
  these are available inside a generic container. Production
  deployment is `wrangler deploy`; local development is
  `wrangler dev`. A "build environment" container (containing
  `cargo` (pinned by `rust-toolchain.toml`), `wrangler`, `node`) for developer onboarding
  would be a pure ergonomics win, but is not on the roadmap —
  the supported install paths in `docs/src/beginner/prerequisites.md`
  cover the same ground.

- **Prometheus `/metrics` endpoint.** Architecturally a poor
  fit for Workers' stateless / horizontally-scaled execution
  model — a scrape would return single-instance values that
  don't aggregate. See "Domain-metric observability" in
  Planned for the alternative path (Logpush + downstream
  aggregation, or `cloudflare:analytics-engine`).

- **A generic `KeyValueStore` trait.** See [Storage responsibilities](docs/src/expert/storage.md)
  for the reasoning.

- **`mod.rs` module files.** See [Crate layout](docs/src/expert/crate-layout.md).

---

## How to propose changes

Open an issue describing the use case. If it aligns with cesauth's
scope, we'll discuss the design tradeoffs before code. A formal
`CONTRIBUTING.md` is planned but not yet written.
