# `route-contracts-check.sh` cannot see `PATCH`, and two live routes are undocumented

**Governing RFC.** None. **A defect found by the implementer during RFC 168
§3.2's cycle** and correctly reported rather than fixed there
(`.git-exclude/review-request/168-level-backstop-report.md` §3; reviewed in
`.git-exclude/reviewed/168-level-backstop-review.md` §1).

**Builds on.** `main` at `037cd8d`.

**Target release.** **Minor** — RFC 181's default. **Part of the same cut as
RFC 168 §3.2**, not a release of its own: shipping a new level backstop while
the adjacent gate is known blind would leave a gate asserting something false.

**Tier.** **P2.** Two live API routes are undocumented, and the gate that exists
to prevent exactly that cannot match them.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-11-08.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. The defect

`scripts/route-contracts-check.sh` matches route registrations with
`\.(get|post|put|delete)_async` at **six places** — `:72`, `:77`, `:78`,
`:372`, `:376`, `:1526`. **None include `patch`.**

`crates/backend/src/lib.rs` registers:

```
101 .get_async    87 .post_async    7 .delete_async    2 .patch_async    1 .put_async
```

The two invisible ones, both at `lib.rs:478` and `:483`:

- `PATCH /api/v1/tenants/:tid` → `routes::api_v1::tenants::update`
- `PATCH /api/v1/tenants/:tid/organizations/:oid` → `routes::api_v1::organizations::update`

`grep -c -i PATCH docs/src/expert/route-contracts.md` → **0**. So they are
**live, registered, undocumented, and unreachable by the check that would have
said so.** Its `✅ All 192 routes are documented` is true only of the 192 it can
match; `drift-scan.sh`'s new census says **194**.

**The reachability half of that `✅` is fine** and does not need touching:
`:1074` matches `routes::${name}(` as a substring, which is method-agnostic, so
both handlers are correctly seen as reachable. Only the *method* vocabulary is
wrong.

## 2. Add `patch` at all six sites — and then check for a seventh

`:72` is a comment; `:77`/`:78` are the registration extraction; `:372`/`:376`
are E4's awk; `:1526` is an awk terminator. **Sweep rather than fix the six you
were handed** — a matcher fixed in six places is not the fixed class, and this
defect exists *because* six copies of one vocabulary drifted from the code they
read. Search for every method list in the file, and for any other script that
reads `lib.rs` registrations.

**Prefer one shared constant over six literals** if the script's structure
allows it. If it does not, say why in the report, so the next method this
project adds does not reproduce this.

## 3. Then document the two routes

Add their rows to `docs/src/expert/route-contracts.md`, in the same shape as the
existing `api_v1` rows — the real auth requirement, audit event, response shape,
rendering mode, CSRF/bearer column — **read from the handlers, not inferred from
their neighbours.** Both are `update` handlers on `api_v1`, which is a
bearer-authenticated surface; confirm that against the code rather than assuming
it from the path prefix.

## 4. Two consequences I infer from the code and have NOT verified — check them

Stated as inference so you verify rather than inherit:

- **`:372`/`:376` are E4's awk chunk boundaries.** A `.patch_async` line does
  not start a new chunk today, so the patch routes' lines plausibly fold into
  the **preceding** route's chunk. If so, E4's `216 = 192 + 24 + 0` and
  anything downstream that reads those chunks — **E6's per-route body analysis**
  — are **mis-attributed**, not merely two short. Confirm or refute, and say
  which.
- **`:1526` is a terminator** (`if ($0 ~ /…_async/) { exit }`). Not recognising
  `.patch_async` means a collector **over-runs** past a patch registration
  rather than stopping. Confirm what that function collects and whether the
  over-run changed any reported figure.

## 5. Expect the censuses to move, and report rather than absorb

Adding `patch` will change the numbers. **Every changed figure must be reported
with its before and after**, and reconciled:

| | at `037cd8d` |
|---|---|
| `route-contracts-check.sh` route claim | **192** |
| `drift-scan.sh` route-surface census | **194 pairs** |
| E3 | `47 = 0 unexempted + 2 exempted + 0 unresolved` |
| GATE_42 | `24 = 0 shadowed + 0 absent + 0 exempted` |
| NONCE | `13 = 0 violations + 0 exempted + 0 unresolved` |
| E4 | `216 = 192 handlers (181 + 11) + 24 named non-handlers + 0 unclassified` |
| E5 | `17 = 17 resolved + 0 capture + 0 unresolved` |
| E6 | `92 = 83 claims (65 resolved, 0 unresolved, 18 exempted) + 9 declared + 0 unclassified` |
| E7 | `156 = 8 resolved + 31 DEFECT (5 written + 26 chokepoint) + 117 no_caller` |

**The two should converge on 194** once both scripts share a vocabulary. If they
do not, the remaining difference is a second finding.

**If adding `patch` makes any census report a NEW, REAL violation — an
unclassified row, an undocumented route beyond these two, an E6 claim that no
longer resolves — STOP and report it.** Do not fix it here. That is the most
valuable thing this cycle could surface, and it needs its own record. This is
the same instruction RFC 182 carried, for the same reason: a check that could
not see something may have been hiding more than one thing.

## 6. Do not

- **Do not add, remove or rename a route.** Documentation and matchers only.
- **Do not touch the reachability check at `:1074`** — it is method-agnostic and
  correct.
- **Do not change any exemption list**, or any check's logic beyond the method
  vocabulary.
- **Do not reintroduce a `cmd | grep -q` / `| head` / `| awk '…exit'` pipe**
  (RFC 182). This file was cleaned of them in `0.93.0` and its header states the
  rule.
- **Do not weaken a census to make a number match.** If a figure moves, that is
  the finding.

## 7. Evidence required

1. Every site changed, listed, plus **how you searched for a seventh**.
2. The before/after of **every** figure in §5, reconciled.
3. `grep -c -i PATCH docs/src/expert/route-contracts.md` → **non-zero**, and the
   two routes documented from the handler source.
4. §4's two inferences **confirmed or refuted**, each with the evidence.
5. `route-contracts-check.sh` and `drift-scan.sh` **agreeing on 194** — or the
   remaining difference explained.
6. **20 consecutive runs of `drift-scan.sh`, identical** (~1.8 s/run, measured
   by the previous cycle, so ~36 s). For `route-contracts-check.sh`, which costs
   **~130–150 s/run**, **3 runs with identical output is the ask** — costed
   deliberately this time rather than demanded and then renegotiated.
7. Host tests, `migration_chain`, `mdbook`, Worker bundle (with `sha256sum` and
   the gzip level) — none should move; this is a shell and docs change.

## 8. Stop conditions

- A seventh method-list site exists that cannot be unified without changing a
  check's meaning.
- Any census reports a new real violation (§5).
- The two scripts cannot be made to agree on 194.
- The two PATCH handlers' real auth/audit/CSRF properties cannot be read from
  the code with confidence — **do not guess a documentation row.**
