# Developer Handoff — RFC 152 half D stage 1, and a CHANGELOG archive split

**Governing RFCs.** [`rfcs/accepted/152-the-admin-surfaces-documented-csrf-control-is-not-the-real-one.md`](../../accepted/152-the-admin-surfaces-documented-csrf-control-is-not-the-real-one.md)
(half D, §§ "Half D — now 29 rows across two cell values" and "So half D's
measurement stage has two questions"), plus RFC 028's CHANGELOG half for item 2.
**Builds on.** `ecc60d4` on `main` — tag `0.92.0` is `2dd9363`, **13/13 CI
green**.

**Target release.** **Patch — the next cut after 0.92.0.** The number is
assigned at the cut, not reserved here: a reserved patch number is how a row
once carried RFC 165 §3 into a release that never happened. **Trigger: none, and that is an argument
rather than a default.** Item 1 corrects documentation that is false and, where
a control is missing, adds a check that rejects only what no legitimate caller
sends — a fix, not capability. Item 2 moves history between files. **If the
measurement says any route needs a control legitimate callers must newly send,
that part stops and becomes its own minor** — see §4.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-11-03.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. Two unrelated items in one cut, and why

They ride together because item 2 is mechanical and **the next cut crosses the
byte budget** — `CHANGELOG.md` is at 79 KB of 80 and the 0.92.0 entry is what
pushed it there. Precedent: 0.91.2 carried three unrelated RFCs. Keep them in
separate commits.

## 2. Item 1 — RFC 152 half D stage 1

### 2.1 What half D is

29 mutating rows in `docs/src/expert/route-contracts.md` **document a CSRF
control that is not the one protecting them**, across two cell values:

- **18 rows claim `N/A (bearer)` and accept a cookie** — `POST /admin/users`,
  `DELETE /admin/sessions/:id`, and all 16 `/api/v1/*` mutating routes, which
  funnel through `api_v1::auth::require` → `auth::resolve_or_respond`, the
  cookie-accepting resolver. Exempted by name in `E6_BEARER_LEGACY_EXEMPT`.
- **7 rows claim `N/A (JSON)`** — down from 11; cycle 2b gave the four
  `/admin/console/clients` routes a real header token, so they left this set.

**Not exploitable today.** No `Access-Control-Allow-Origin` is set anywhere in
the repo, so `SameSite=Strict` holds. The defect is that the document names the
wrong layer, and the layer that actually holds has no live witness — which is
RFC 170, not yours.

### 2.2 The measurement, which is the stage — and it already has a partial answer

**Question A — the 18 `N/A (bearer)` rows: is there a real cookie-borne
caller?** If none is, making them header-only is mechanical; if one is, it is a
caller-obligation change belonging in its own minor with notice. **Answer the
question. Do not make the change either way in this cycle.** Sizing half D
before this answer exists is what half B and half C each got wrong in their
first draft.

**Question B — the 7 `N/A (JSON)` rows.** I measured these rather than hand you
a question, because it was cheap. **The cell means two different things across
the set, and only one of them is false:**

| row | actor | enforces `Content-Type`? |
|---|---|---|
| `POST /me/security/delete-account` | authenticated user | **yes** |
| `POST /webauthn/register/start` | End user | no |
| `POST /webauthn/register/finish` | End user | no |
| `POST /webauthn/authenticate/start` | Anonymous | no |
| `POST /webauthn/authenticate/finish` | Anonymous | no |
| `POST /api/v1/anonymous/begin` | Anonymous | no |
| `POST /api/v1/anonymous/promote` | Anonymous user | no |

`routes/deletions.rs:90-100` rejects a non-JSON `Content-Type` with a 400 whose
body says *"this header is this route's CSRF control"*, and the doc comment says
the check **is** the control rather than content negotiation. **Requiring
`application/json` is a real CSRF defence** — a cross-site HTML form can only
send `x-www-form-urlencoded`, `multipart/form-data` or `text/plain`, and
`fetch()` with a JSON content type preflights, which this server never grants.
So that row's cell **understates a control it has**; the other six **claim a
control they do not have**, which is half C cycle 2's finding verbatim.

**Correction worth having in front of you:** my first reading had
`/me/security/delete-account` as the *most* exposed of the seven, on the
strength of what it does. It is the one row that is actually defended. I checked
before writing this; the handoff you are reading is the second version.

`grep -n "content-type\|content_type" crates/backend/src/routes/webauthn/*.rs
crates/backend/src/routes/api_v1/anonymous.rs` returns nothing but one
*response* header — that is the whole basis for the "no" column, so verify it
rather than inherit it.

### 2.3 What stage 1 delivers

1. **Question A's answer, as evidence**: for each of the 18, what authenticates
   a real caller today. `reviewed` is the honest term for a code-reading answer
   and is acceptable **for the measurement**; say so plainly where that is what
   it is.
2. **The six false cells made true.** Two shapes are available and the choice is
   per-row, not global:
   - **the control the cell claims** — enforce `Content-Type: application/json`
     the way `deletions.rs` already does, with the same kind of 400 that says
     why. This is the right answer wherever a legitimate caller already sends
     that header, because then the check costs nothing and the cell becomes
     true as written;
   - **an honest cell** naming the layer that holds. `N/A (SameSite=Strict)`
     already exists as a value on 3 rows and
     `N/A (no ambient credential, no state change)` on 1 — reuse the vocabulary,
     do not invent a synonym. E6's census fails on a cell it does not recognise,
     so a new value needs its mechanism taught to the gate.
3. **`/me/security/delete-account`'s cell made accurate** — it has a control and
   the cell hides it. Whatever value you choose must be one E6 can check against
   `deletions.rs`'s actual header check.
4. **E6's arithmetic moves and must still close.** Baseline
   `94 = 80 claims + 14 declared + 0 unclassified`, with `80 = 62 resolved + 0
   unresolved + 18 exempted`. Rows moving from declared to claims change both
   lines; **report the new ones and keep `0 unclassified`.**

### 2.4 Checking, not guessing, before you enforce anything

For each route where you would add the `Content-Type` check, **find the real
caller and confirm it already sends that header.** The frontend's `fetch` calls
are in `crates/frontend/`; a passkey ceremony may be driven by browser code that
does not. **If a legitimate caller does not send it, stop** — adding the check
would break that caller, and that is §4's case.

## 3. Item 2 — the CHANGELOG archive split (RFC 028)

`CHANGELOG.md` says it keeps **the most recent five minor versions** under an
~80 KB budget. It holds **eight** — 0.85 through 0.92 — at **79 KB**, so the
byte guard in `scripts/changelog-archive-split.sh` has never fired and the
five-minor rule is checked by nothing. Both facts are recorded in the file's own
header as of `2dd9363`.

- Archive **0.85, 0.86 and 0.87**, leaving 0.88–0.92 — five series, as the rule
  says. The script takes the newest version to archive as its argument; read its
  usage rather than guessing the form.
- `docs/src/changelog-archive/README.md` (or wherever the archive index lives)
  gains the new file, and **archive files are never edited after creation** —
  check that the split writes a new one rather than appending to an existing
  range.
- **Re-run `drift-scan.sh` and `mdbook build docs` after the split and report
  both**: this moves pages and links, and RFC 169's docs-coverage and
  link-integrity checks plus RFC 164's `rfcs/` sweep are exactly what catches a
  split that breaks a reference. Baseline: docs coverage `80 scanned = 78
  in-book + 2 declared out + 0 unreachable`; docs links `189 seen = 177 checked
  + 6 absolute + 6 outside + 0 unresolvable, 0 broken`; `rfcs/` sweep
  `174 checked, 0 broken`.
- **Report the resulting byte size** of `CHANGELOG.md` and of each archive file.

## 4. Stop conditions

- **Question A's answer is "yes, a real caller uses a cookie"** for any of the
  18 — report it and change nothing. That is a caller-obligation change, its own
  minor, with notice.
- **A legitimate caller does not send `Content-Type: application/json`** for any
  route where you would add the check — report which, and give that row an
  honest cell instead.
- **A cell value you want does not exist in E6's mechanism table** — teach the
  gate or pick an existing value; do not leave an unclassified row.
- **The archive split rewrites an existing archive file** rather than creating a
  new one, or breaks any docs link.
- `E6`'s two arithmetics do not close, or `unclassified` is not 0.

## 5. Baselines at `ecc60d4`, each with its command

- host tests, `cargo test -p cesauth-core -p cesauth-adapter-test -p cesauth-frontend -p cesauth-backend -p cesauth-adapter-cloudflare --features cesauth-frontend/csr` → **1,677 passed, 0 failed, 4 ignored, 12 `test result:` lines**;
- `cargo test -p cesauth-migrate-test --test migration_chain` → **35**;
- `bash scripts/route-contracts-check.sh` → **194 routes**; E3 2 exempted; GATE_42 0 exempted; NONCE 0 violations; E4 `218 = 194 + 24 + 0`; E5 `17 = 17 + 0 + 0`; **E6 `94 = 80 claims + 14 declared + 0 unclassified`**, `80 = 62 + 0 + 18`;
- `bash scripts/drift-scan.sh` → clean, with §3's four counters;
- `npx playwright test` in `e2e/` → **20 passed** — **it needs
  `node_modules/.bin/wrangler dev --port 8787` already serving**; there is no
  `webServer` block, and without it all 20 fail with `ERR_CONNECTION_REFUSED`.
  I tripped over this at the 0.92.0 cut;
- bundle, `./node_modules/.bin/wrangler deploy --dry-run --outdir bundled/`,
  **gzip 1.15 at its default level** → **896,672 B** (885,972 wasm + 10,700
  `shim.js`).

**Name your gzip level with your figure.** `-9` on the same bytes gives
**892,451 B**, and the 4,221-byte gap between those two numbers was mistaken for
a cross-environment difference and written into an RFC before anyone read the
flag. The project's recorded progression is on the **default** level. See
RFC 133 §16.
