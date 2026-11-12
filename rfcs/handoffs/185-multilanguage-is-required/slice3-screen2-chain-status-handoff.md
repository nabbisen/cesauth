# Developer Handoff — RFC 185 §5.3, screen 2: the chain-status screen

**Governing RFC.** `rfcs/accepted/185-multilanguage-is-required-and-the-csr-app-has-no-locale-at-all.md` — **§8 first**.
**Prior art to follow.** `rfcs/handoffs/185-multilanguage-is-required/slice3-screen1-audit-viewer-handoff.md`
and its two reviews. Screen 1's pattern applies; the differences are in §3.
**Decisions this cut carries.** `.git-exclude/reviewed/three-decisions-2026-11-12.md` §1 (the `Actor` → `Subject` label fix).
**Target release.** **Minor.** New catalog surface, and a second route begins
negotiating its locale.
**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing.

---

## 1. Purpose

`GET /admin/console/audit/chain` negotiates its locale, its 55 counted literals
move onto the catalog, its two `inner_html` sinks go away, and the dead 281-line
server template it replaced is deleted.

**This screen is why the gate was widened.** Nine of its Japanese strings sit in
raw-string HTML and were invisible to every gate this project had until
`0.101.0` — `r##"<span class="badge">検証未実行</span>"##` and eight more. They
have been rendering unconverted since `0.97.0` shipped, through two reviews of
mine that counted this file's Japanese with the matcher that could not see them.

## 2. Why this matters

This is the screen an operator reads when the audit chain reports tampering. It
is the surface `0.98.0`'s entire security fix exists to feed. Its status badges
— *"⛔ seq={n} で改ざんを検出"*, *"✗ seq の現在行と不一致（書き換えの疑い）"* —
are the words that tell someone their audit log may have been rewritten, and
they exist in one language with no catalog entry.

## 3. How this differs from screen 1 — read this before planning

**D1. There are no existing keys.** Screen 1 re-pointed 18 of its 24 literals at
`AuditViewer*` keys that already existed in both locales. **`grep -cP '^    AuditChain\w+,$'`
returns 0.** Every string here needs a new key *and new English copy*, roughly
50 of them, on a security surface. That makes G1 (§5) much heavier than screen
1's five-key question, and it is the main risk in this cut.

**D2. The nine raw-string badges are restructured into Leptos views, not
wrapped.** `badge_html` (`:97`) and `consistency_badge` (`:131`) build HTML
strings, and the view injects them through **`inner_html=badge` (`:219`)** and
**`inner_html=consistency` (`:258`)**.

Wrapping the text in `lookup()` *inside* the raw strings would be the smaller
change and it is the wrong one: it keeps two `inner_html` sinks on the
audit-tamper screen, and it keeps HTML structure inside string literals where
the gate's HTML mode has to parse it back out. **Return a view, carry the CSS
class in `class=`, and the sinks disappear.** Both functions exist only to pair
a class with a piece of text, which `view!` does natively.

**Today's sinks are not exploitable** — the only interpolation is `{seq}`, an
`i64` — and that is the reason to remove them now rather than urgently: no
pressure, full context, and every line of both functions is being touched
anyway. **State in the report that no exploitable path existed**; do not
describe this as fixing a vulnerability.

**D3. The dead template is deleted in this cut.**
`crates/frontend/src/admin/audit_chain.rs`, **281 lines, 6 tests**, and this
screen's own module doc already records *"no caller since"*. Same clearance as
screen 1's, which is now the standing rule: **zero callers, a host-test delta
equal to the deleted file's own test count, and no route-surface movement.** A
delta *larger* than its own tests means something else depended on it — stop.
Note the delta will not be a clean −6 here, because D2 changes the two tests at
`:312`/`:317` that assert on HTML-string contents; **report the arithmetic
rather than a single number.**

**D4. The `Actor` → `Subject` label fix rides along.** Decision 1, delegated by
the owner and decided: the audit log's `subject` column holds *who the event
concerns*, which is the acting principal for most kinds but **the affected user
for cron-emitted and admin-on-behalf kinds** (`AnonymousExpired`,
`DeletionExecuted`, `DeletionCancelled`). *"Actor"* asserts agency that is false
for those, so the label changes:

| key | `Ja` | `En` |
|---|---|---|
| `AuditViewerActorLabel` | `Subject (部分一致)` | `Subject (substring)` |
| `AuditViewerColActor` | `Subject` | `Subject` |

**Key names do not change** — a rename is churn with no reader. **The `actor`
query parameter and form field name do not change either**: they are
caller-visible and sequenced separately. Changing the `<input id>`/`<label for>`
pair is optional and internal; if you change it, say so.

**D5. Do not try to answer "who did it".** The same decision found that where
actor and subject differ, the actor survives only in free text, so the audit UI
cannot answer *"which admin deleted this user?"*. That is **RFC 187**, proposed,
awaiting the owner. **Out of scope here.** This cut makes a label honest; it does
not add a capability.

## 4. Facts already measured — do not re-derive

**If any of this fails to reproduce, that is a finding — report it.**

- **Ceiling: `pages/operator/audit_chain.rs` = 55 = 50 cjk + 5 en.** Of the 50
  CJK, **41** are quoted Rust literals (clause (a)) and **9** are the
  raw-string-HTML badges (`:100,103,106,109,112,133,134,135,136`) that only the
  `0.101.0` matcher can see.
- **Two `lang` edits, as always** (review finding F-C): the route at
  `crates/backend/src/routes/admin/console/audit_chain.rs:101` passes
  `Locale::Ja`, and `pages/operator/audit_chain.rs:178` is
  `<main lang="ja" aria-label="監査チェーン検証">`. Leaving the second would
  override the first for the whole subtree — **no build-time signal exists for
  getting this wrong.**
- **The title** at the same route line is `"監査チェーン — cesauth"`. Convert it,
  composing the ` — cesauth` suffix at the call site, as screen 1 did.
- **Baseline gates at `0.101.0` (`8644be5`)**: host **1,711 / 0 / 4** across
  **12** `test result:` lines, by **this exact command** —

```sh
cargo test -p cesauth-core -p cesauth-adapter-test -p cesauth-frontend \
           -p cesauth-backend -p cesauth-adapter-cloudflare \
           --features cesauth-frontend/csr
```

  `route-contracts-check.sh` exit 0, **197 routes**, E3 47 · GATE_42 24 ·
  NONCE 13 · E4 219 · E5 19 · E6 95 · E7 156. `drift-scan.sh` clean, **104
  scanned, 68 hit, 70 ceiling entries**. `cargo check` warnings **8** frontend,
  **1** core. Bundle **899,904 B**.

## 5. Report-and-stop gates

**G1 — the key list, before you write it. This is the heavy one.** Report every
new key with its proposed name and **both** locale values, before adding any.
Roughly 50 strings, and the English does not exist anywhere to copy from — unlike
screen 1, where `render_nav` supplied one. These are the words that tell an
operator their audit log may have been tampered with, so the English is
security-surface copy and I want to read it before it is a commit.

Group them in the report by the screen region they serve (status badges,
consistency badges, table labels, nav, error/loading states) rather than listing
50 flat rows — that is how I can review the register for consistency, which is
the thing that went wrong on this very screen at `0.97.0`.

**G2 — parity before deletion.** The template has no catalog keys to compare
against (D1), so screen 1's "18 of 18" check does not apply. Instead report
**region by region**: every status the template's `render_summary` five-arm match
can display, and whether the converted screen can display it. The module doc at
`:11-12` says the badge logic was *"copied verbatim, not re-derived"* from that
match — so a divergence is a real regression, not a cosmetic one. **If any arm
is unreachable on the converted screen, report and stop; do not delete.**

**G3 — the negotiated screen, in the terms `0.100.0` established.** The HTTP
response is `exercised`: drive `wrangler dev --local` with `curl -v` for
`Accept-Language: en`, `ja`, and absent, and **land the redirected log** with the
request headers visible and the bearer token redacted. The mounted DOM stays
`reviewed` — no browser here. That line is standing policy now, not a per-cut
negotiation.

## 6. Change scope

| # | Task | Files |
|---|---|---|
| **T1** | G1's keys, both locales, added to the `match` pin **and** the hand-written array in `lookup_completeness.rs` — the two mechanisms still do not check each other | `crates/core/src/i18n/mod.rs`, `.../tests/lookup_completeness.rs` |
| **T2** | Restructure `badge_html` and `consistency_badge` into views; delete both `inner_html` sinks (D2) | `crates/frontend/src/pages/operator/audit_chain.rs` |
| **T3** | Re-point the remaining literals at the catalog | same |
| **T4** | Both `lang` edits + the title; route calls `resolve_locale` | `crates/backend/src/routes/admin/console/audit_chain.rs`, `pages/operator/audit_chain.rs` |
| **T5** | D4's label values | `crates/core/src/i18n/mod.rs` |
| **T6** | Ceiling `55` → **0** | `scripts/drift-scan.sh` |
| **T7** | G2, then delete `crates/frontend/src/admin/audit_chain.rs` and its `pub use` at `admin.rs:36` **only if** G2 holds; re-point every doc reference by **re-grepping**, not by trusting a cited line list | `crates/frontend/src/admin/audit_chain.rs`, `crates/frontend/src/admin.rs` |

T1 before T2–T3. T6 after them — it will fail until the literals are gone, which
is how you know you are done.

## 7. Explicit non-change scope

- **One screen.** `clients.rs` (60), `console.rs` (44), `tenancy.rs` (27) are
  later. Their ceilings stay.
- **No actor column, no new audit capability** (D5) — that is RFC 187.
- **No `actor` query-parameter or form-field rename** (D4).
- **Do not localise the server-template directories** — ~725 counted literals in
  `admin/`, `tenancy_console/`, `tenant_admin/`, all later work.
- **Do not widen the i18n matcher.** It shipped in `0.101.0`; its residue is
  documented.
- Standing rules: **no `cargo fmt`**, no route-string changes, no `#[allow]`.

## 8. Task detail worth stating explicitly

**T2 — the five-arm match is load-bearing and was copied deliberately.** The
module doc says so. When you restructure to views, the arms must stay in
one-to-one correspondence with `render_summary`'s, because G2 compares them. Do
not "simplify" the match while converting it; if an arm looks redundant, report
it rather than merging it.

**T2 — one badge interpolates.** `:106` is a `format!` carrying `{seq}`. Its key
needs a placeholder, and the substitution happens outside the catalog, as
screen 1's `SessionsCardAriaLabel` does with `{sid}`.

**T4 — the silent-failure risk is `<main lang>`, exactly as on screen 1.** Every
gate passes and `cargo check` is clean whether or not you change it, and a
screen reader reads the whole page in the wrong language if you do not.

**T7 — your own doc edits are in scope for the sweep.** Screen 1's round 2
missed a reference its own round 1 had *added*. Grep after your edits, not only
before.

## 9. Assert machine-checkable things mechanically

```sh
# 1. No Japanese literal left, in either shape (quoted or raw-string HTML).
awk '/^#\[cfg\(test\)\]/{exit} {print}' crates/frontend/src/pages/operator/audit_chain.rs \
  | grep -vP '^\s*//' | grep -P '[\x{3040}-\x{30ff}\x{4e00}-\x{9fff}]'
# 2. No hardcoded lang on the screen.          Expect: no output.
grep -n 'lang="' crates/frontend/src/pages/operator/audit_chain.rs
# 3. Both inner_html sinks gone (D2).          Expect: no output.
grep -n 'inner_html' crates/frontend/src/pages/operator/audit_chain.rs
# 4. The route negotiates.                     Expect: a resolve_locale call.
grep -n "resolve_locale" crates/backend/src/routes/admin/console/audit_chain.rs
# 5. No stale reference to the deleted template anywhere.
grep -rn "admin/audit_chain\.rs\|audit_chain_status_page" --include="*.rs" crates/
# 6. Non-test code changed only where §6 says — hunk headers, not filenames.
git diff -U0 | grep '^@@'
```

## 10. Required tests and evidence

The commands in §4, each redirected to `evidence/`. **Quoted literally there on
purpose** — a cross-reference to a command is an invitation to substitute one,
which is how the last round came to run `cargo test --workspace` and silently
skip every csr-gated test.

Expected: host tests move by **T1's new keys (consumed by existing completeness
tests, so possibly zero new test functions) minus the deleted template's 6, plus
or minus whatever D2's restructure does to the two HTML-string assertions** —
report the arithmetic, not a number. `route-contracts-check.sh` exit 0 with
**route surface 197 pairs, 0 added, 0 removed** — a non-zero delta means the cut
grew; stop. `drift-scan.sh` exit 0 with `audit_chain.rs` at **0** and one fewer
file hit. Warnings: **report the new figure**; T7's deletion may move them.

**Sum test counts programmatically.** **A fires/does-not-fire pair for T6** is
required and free.

## 11. What must NOT be claimed

- **Not that the badge restructure fixed a vulnerability.** No exploitable path
  existed (D2). The honest wording: two `inner_html` sinks removed from a
  security surface while it was being rewritten anyway.
- **Not that anyone saw this screen rendered.** G3's line: the HTTP response is
  `exercised`, the mounted DOM is not.
- **Not that the project is localised.** After this, two screens of eleven
  negotiate.
- **Not that the audit log can say who acted** (D5).

## 12. Prohibited shortcuts

No wrapping `lookup()` inside the raw-string HTML to avoid T2. No raising a
ceiling. No deleting the template on an unmeasured parity claim. No merging a
match arm while converting it. No `cargo fmt`.

## 13. Acceptance criteria

RFC 185 §5.3 for this screen, §5.1's deferred flip for this route, and decision
1's label fix.

**Checked hardest:** (1) G1's English copy, as security-surface wording;
(2) §9 assertions 2 and 3 — `<main lang>` and both sinks — because neither has a
build-time signal; (3) G2's region-by-region parity before any deletion.

## 14. Known risks

- **~50 new English strings on a security screen is the real risk**, not the
  mechanical conversion. If the copy needs more thought than the code, say so
  and send G1 early.
- **The badge restructure touches the one screen whose correctness `0.98.0`
  depends on.** The five arms are the contract.
- **A parity claim about a sibling screen was accepted once and was false**
  (slice 1's export form). G2 exists because of that.
- **If the work turns out materially larger than scoped, stop and report.**

## 15. Review request

Write to `.git-exclude/review-request/`. Include: implementation summary ·
changed files · deviations from §6 · every log from §10 · §9's output · T6's
pair · **G1's grouped key list with both locales** · **G2's region-by-region
parity** · G3's log with the token redacted · gate results against §4 · what
remains unverified (§11) · unresolved issues · requested review focus.

**Report the path only.**
