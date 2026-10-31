# Developer Handoff — RFC 152 half C: the operator console makes the same claim

**Governing RFC.** `rfcs/accepted/152-the-admin-surfaces-documented-csrf-control-is-not-the-real-one.md` §Half C.
**Review that found it.** `.git-exclude/reviewed/152-half-b-stage-2-review.md`
**Builds on.** `7b448c1` on `main` — tag `0.90.0`, 13/13 CI green.

**Target release.** **0.91.0 — minor.** **Trigger hit: a caller obligation
changes.** Class B below makes four routes reject a cookie-derived credential,
so a client authenticating to them by cookie stops working. Class A adds a
token requirement to three more. Scheduled **ahead of RFC 141 cycle 2**: a
documented control that is absent outranks a screen that does not exist yet.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-10-31.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. The measurement is done — start from it, do not redo it

Half B's stages each opened by discovering their own population and each found
my figure wrong. **So this time the measurement came first**, and the answer is
in RFC 152 §Half C. Two things in it you should check rather than trust, because
they are mine:

- **It is seven rows, not the nine the 0.90.0 CHANGELOG entry reports.**
  `…/config/log_level/{preview,apply}` **do** carry a control —
  `cesauth_core::admin::preview::verify_preview_token`, an HMAC'd preview token
  with the submitted CSRF value bound into it, failing closed on *"expired,
  tampered, or CSRF mismatch"*. My scan looked for three function names and
  missed a fourth mechanism. **If you find an eighth mechanism somewhere in the
  seven below, that is a finding and I want it.**
- **The classification rests on "no view fetches or posts to class B".** I
  grepped the frontend for each path and found only
  `pages/operator/console.rs:108`, posting to `/admin/console/tokens/disable` —
  no `:id`, a path no route serves — in a form with no submit button and no id
  field. I read that as a placeholder. **If any class B route turns out to have
  a real browser caller, stop: it belongs in class A and my design for it is
  wrong.**

## 2. Class A — three browser forms get the stage-1 pattern

| Route | Handler | Renders |
|---|---|---|
| `POST /admin/console/tokens` | `console/tokens.rs::create` | `token_new_form` / `token_created_page` |
| `POST /admin/console/config/:bucket/edit` | `console/config.rs::edit_submit` | `config_edit_form` / `config_confirm_page` |
| `POST /admin/console/safety/:bucket/verify` | `console/safety.rs::verify` | content-negotiated; the HTML branch redirects back to its form |

Exactly what stage 1 did, including the parts that were easy to get wrong:

- the `GET` that renders each form mints a token and attaches the cookie;
- the view takes a `csrf: &str` and emits `<input type="hidden" name="csrf" …>`,
  escaped per the RFC 108 contract;
- **every error re-render mints a fresh token and attaches a fresh cookie** —
  `tokens.rs::create` re-renders `token_new_form` on three separate validation
  failures (missing role, bad role, over-long label) and `config.rs::edit_submit`
  re-renders on its own;
- the field name is **`csrf`**, as everywhere else in stage 1;
- reuse `tenancy_console/forms/common.rs`'s `mint_csrf` / `attach_csrf_cookie` /
  `verify_csrf` rather than writing a fourth copy. If their current module path
  makes that awkward from `console/`, **move the three helpers to a neutral
  home and say so** — a shared decision boundary in an odd place is better than
  two of them, and stage 1's review credited that boundary precisely because
  every handler runs the same code.

**`POST /admin/console/tokens` is the one to get right.** It mints an admin
token: the credential every other admin route accepts. It is also the only
class A route whose `csrf_json()` endpoint already exists (`tokens.rs:83`), so
the token is already being served to that surface and simply never checked
coming back.

**`safety.rs::verify` needs care**: it content-negotiates on
`render::prefers_json(&req)`. A JSON caller sends no form body. Decide and state
which you did — my recommendation is to verify the token **only on the HTML
branch** and make the JSON branch header-only per class B's rule, because that
route is both things at once. If that reads wrong to you, say so before
implementing.

## 3. Class B — four JSON endpoints become header-only

`…/tokens/:id/disable`, `…/config/:bucket/preview`, `…/config/:bucket/apply`,
`…/thresholds/:name`.

**Do not add a double-submit token to these.** They return `json_response` only,
`crates/frontend/src/admin/config.rs` documents them as a `curl` API in its own
prose, and a `curl` caller has no cookie jar — the token would be ceremony for a
browser that never calls them and an obstacle for the caller that does.

**The fix is structural.** `auth::bearer` reads the `Authorization` header
first and **falls back to the `__Host-cesauth_admin` cookie** for browser
clients. A browser-attached credential is what makes CSRF possible at all, so:

1. Add a **header-only** resolver beside the existing one — same store lookup,
   same `AdminLoginFailed` audit on failure, same `forbidden_response`, but no
   cookie fallback. Keep it next to `resolve_from_request`/`resolve_or_respond`
   so the pair is visible as a pair.
2. Use it on those four routes.
3. Their `route-contracts.md` CSRF cells become **`N/A (bearer)`** — a value
   the table already carries on 12 other rows. The claim is then true by
   construction, not by a check.

**Disclose the contract change plainly** in your report: a caller that
authenticated to those four by cookie now gets 401. I believe there is no such
caller (§1), which is exactly why I want you to look again before you change it.

## 4. Class C — two cells, no code

`…/config/log_level/{preview,apply}` keep their mechanism. Change only the
CSRF cell so it names the control it actually has, following the table's own
precedent of `required (Origin check)` on another row — e.g.
`required (preview-token binding)`. **No handler change.** If E6 (below) ends up
able to verify this mechanism by name, better; if not, the cell must still say
what is true.

## 5. E6 grows to check the control the cell names

Today E6 asserts `required ⇒ a verify call` on two surfaces. Generalise it to
assert **the cell's own claim**, repo-wide:

- `required` ⇒ a `csrf::verify` / `verify_csrf` in the resolved handler body;
- `required (<mechanism>)` ⇒ that named mechanism is present;
- `N/A (bearer)` ⇒ the handler resolves through the **header-only** resolver.

That absorbs the 12 existing `N/A (bearer)` rows into the gate instead of
trusting them, and it makes the CSRF column self-enforcing in both directions.

**This is not free and the reason is measured**: 10 rows outside E6's current
filter are registered as **multi-line** closures in `lib.rs`, and the
single-line narrow E6 documents for its own two surfaces will not resolve them —
my own single-line matcher missed exactly those 10. **You need E4's multi-line
registration walk.** Two extractors over `lib.rs` already exist with different
blind spots and this would be a third, which is RFC 163's subject. **Do not
write a third.** Either reuse E4's resolution or, if that means extracting it
into one function both call, do that and say so — RFC 163 records
single-extractor as the end state and this is the third caller to ask for it.
**If reuse turns out to need more than a modest refactor, stop and report**: a
scoped E6 that is honest about its scope beats a general one built on a fourth
matcher.

## 6. Tests

- **Class A**: per surface, a host test that the decision boundary rejects a
  missing and a wrong token and accepts a matching one — stage 1's
  `common.rs` tests already cover the shared helpers, so what is new here is
  the **re-render** cases. Assert that each of `tokens.rs::create`'s three
  validation failures re-renders with a fresh token, as a pure-function test on
  the view plus a live capture of the handler.
- **Class B**: a host test that the header-only resolver ignores a cookie —
  construct the request shape if it can be done without `worker::Env`, and if
  it cannot, say so and capture it live instead.
- **Live captures, as captures** (`curl -s -o /dev/null -w "%{http_code}"`):
  for one class A route — no token 400, wrong token 400, matching 303/200, and
  the re-render carrying a fresh token; for one class B route — bearer header
  succeeds, the same credential presented **only** as a cookie gets 401.
- Full gate set. **Baselines at `7b448c1` (tag `0.90.0`)**: host tests
  **1,649 / 0 / 12 lines**, `migration_chain` **35**, **194** routes documented,
  **E4 `216 = 194 + 22 + 0`**, **E5 `16 = 16 + 0 + 0`**, **E6 `36 / 34 / 34 /
  0`, 2 field names**, Playwright **20**, manifest **13 + 1 = 14**, bundle
  **896,327 B gzip** (`885,628` wasm + `10,699` shim) measured with
  `wrangler deploy --dry-run --outdir bundled/` under gzip 1.15. E6's figures
  will move — it is growing a population.

## 7. Stop conditions

- any class B route has a real browser caller (§1);
- generalising E6 needs a third `lib.rs` extractor rather than a modest reuse
  of E4's (§5);
- `safety.rs::verify`'s split treatment reads wrong to you (§2);
- the count of rows needing work is not seven.
