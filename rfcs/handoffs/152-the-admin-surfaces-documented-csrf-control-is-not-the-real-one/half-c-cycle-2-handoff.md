# Developer Handoff — RFC 152 half C, cycle 2: E6's cell vocabulary has no census

**Governing RFC.** `rfcs/accepted/152-the-admin-surfaces-documented-csrf-control-is-not-the-real-one.md` §Half C.
**Review.** `.git-exclude/reviewed/152-half-c-review.md`
**Builds on.** `8162b51` on `main`. **Nothing to revert** — half C stands; I
reproduced both classes live.

**Target release.** **0.91.0 — minor, unchanged.** This is a gate change only:
no route, no handler, no caller obligation. **The cut waits on it.**

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-10-31.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. One thing, and it is in the gate you just generalised

E6 closes its **row** arithmetic — `75 claims = 57 resolved + 18 exempted + 0
unresolved` — and that is right. It does **not** account for the rows it
skipped. Its classifier is a `case` with three arms and `*) continue`, so of 94
mutating rows, **19 are dropped without trace**:

```
11  N/A (JSON)
 2  N/A (SameSite=Strict)
 1  N/A (Bearer)          <-- capital B; a bearer claim E6 does not check
 1  N/A (CORS preflight)
 1  N/A (RFC 7009)
 1  N/A (Authorization-only)
 1  N/A (dev only)
 1  N/A                   <-- no reason at all
```

**`POST /userinfo` claims `N/A (Bearer)` and goes unchecked because of one
capital letter.** No live defect — it is an OIDC endpoint authenticated by an
access token, not by the admin resolver — but that is the blind-spot class this
project keeps paying for, now inside the gate built to stop it. And one row's
cell is a bare `N/A`: whatever it meant, nothing records it and nothing checks
it.

**E4 closes its census with `0 unclassified` and fails when that is untrue.**
Give E6 the same property.

## 2. What to build

1. **Every scanned mutating row is either checked or named**, in the shape
   RFC 159 §4.5 established. An unrecognised cell is a **hard failure**, not a
   skip — that is the whole point; a typo, a new value, or a row quietly
   relabelled `N/A` must fail loudly rather than pass silently.
2. **A declared list of cell values that legitimately carry no check**, each
   with its reason — `N/A (JSON)` (no browser form posts it),
   `N/A (RFC 7009)`, `N/A (CORS preflight)`, `N/A (dev only)`, and
   `N/A (SameSite=Strict)` (the two caller-less `tenant_detail` routes, already
   recorded in the table's own prose). **With the stale-entry rule**: a declared
   value matching no row this run is a hard failure, same as
   `NAMED_NON_HANDLERS` and `E6_BEARER_LEGACY_EXEMPT`.
3. **The coverage line reports the split**: scanned, claims checked, exempted,
   declared-no-check, and **unclassified — which must be 0**.
4. **Fix the two rows the census will catch**, which is the cheapest part:
   - `POST /userinfo`'s cell → `N/A (bearer)`, lower-case, so E6 checks it. Then
     **check what it resolves to**: if `userinfo_handler` does not go through the
     header-only resolver, **do not change the handler** — report it. It is an
     OIDC surface, not an admin one, and whether an OIDC access token may arrive
     by cookie is a question for its own cycle, not this one.
   - the bare `N/A` row → either a declared value with a reason, or the right
     claim. **Say which row it is and what you concluded**; I deliberately have
     not named it, because I want your reading of it, not my guess confirmed.

**Do not** make the matcher case-insensitive as the fix. Normalising the one
odd cell is a smaller change than teaching the gate to accept two spellings,
and two spellings is how the `csrf`/`csrf_token` split became folklore — which
E6 now prints a count of precisely so it cannot.

## 3. Tests

- **Negative-test the census**, the same methodology you used twice already:
  introduce a cell value that is neither a claim nor declared, confirm **exit 1**
  naming the row; add a declared value that matches nothing, confirm **exit 1**
  naming it stale; restore from pre-edit copies and byte-diff.
- No host tests are implied — this is a shell gate.
- Full gate set. **Baselines at `8162b51`:** host tests **1,653 / 0 / 12 lines**,
  `migration_chain` **35**, 194 routes documented, **E4 `218 = 194 + 24 + 0`**,
  **E5 `16 = 16 + 0 + 0`**, **E6 `94 scanned / 75 claims / 57 resolved / 0
  unresolved / 18 exempted`**, Playwright **20**, manifest **13 + 1 = 14**.
  E6's line changes shape by design — state the new one in full.

## 4. What to report

- The new coverage line, in full.
- The bare-`N/A` row: which it is, what you concluded, and why.
- What `/userinfo` resolves through, whatever the answer. **If it accepts a
  cookie-derived credential, that is a finding and not a fix** — report it and
  stop.
- Whether any of the other 17 skipped rows turned out to be making a claim
  nobody noticed. That is the question the census exists to answer, and this is
  the first run of it.

## 5. Stop conditions

- the census cannot reach 0 unclassified without a judgement call about a cell's
  meaning that is not yours to make — report the cell and stop;
- `/userinfo` turns out to accept a cookie;
- fixing a cell would require touching a handler.
