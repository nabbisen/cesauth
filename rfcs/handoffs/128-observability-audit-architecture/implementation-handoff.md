# Developer Handoff — RFC 128, Observability audit-architecture correction

**Governing RFC.** [`rfcs/accepted/128-observability-audit-architecture-correction.md`](../../accepted/128-observability-audit-architecture-correction.md)
**Target release.** 0.81.3
**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing.

---

## 1. Purpose

`docs/src/deployment/observability.md` tells operators that audit events are
R2 objects and gives them R2 query patterns. Audit events have been rows in the
D1 `audit_events` table with a hash chain since v0.32.0 / ADR-010 — roughly 49
versions. After this, the document describes the system that exists, and a
drift rule stops it drifting back.

## 2. Why this matters

This is the last item from the RFC 126 sweep that can cause operational harm
rather than confusion. Two of the document's three "query patterns" are
unactionable: there is no audit bucket to list. An operator following them
during an incident spends their time discovering that.

And `observability.md:233` tells an operator that audit-log cost is managed by
**R2 lifecycle rules**. It is managed by `audit_retention_cron` under the
tenant's plan-level retention policy. Someone controlling audit spend would
configure a thing that does not exist.

## 3. Facts already measured — do not re-derive

**The schema is the source of truth for the event-shape table.**
`migrations/0008_audit_chain.sql` defines `audit_events` with exactly these
columns:

```
seq (INTEGER PK AUTOINCREMENT), id (TEXT UNIQUE), ts (INTEGER),
kind (TEXT), subject, client_id, ip, user_agent, reason (all TEXT, nullable),
payload (TEXT), payload_hash (TEXT), previous_hash (TEXT),
chain_hash (TEXT), created_at (INTEGER)
```

The document's current table lists `kind / subject / client_id / ip / reason /
ts` and cites `crates/backend/src/audit.rs`. It is wrong in both storage *and*
detail — it omits `seq`, `id`, `user_agent`, `payload`, `payload_hash`,
`previous_hash`, `chain_hash`, `created_at`, which are most of the row and all
of the chain.

**Indexes**, same migration: `idx_audit_events_ts`,
`idx_audit_events_kind_ts`, and a partial `idx_audit_events_subject`. These are
what make the console's filters fast and are worth mentioning where the current
text says "no SQL flexibility."

**The four registered audit routes**, from `crates/backend/src/lib.rs`:

```
/admin/console/audit
/admin/console/audit/export
/admin/console/audit/chain
/admin/console/audit/chain/verify
```

Plus `/__dev/audit`, local-dev only — mention it as such or not at all.

**R2 is still bound**, as `ASSETS` in `wrangler.toml`. That is why three of the
seven R2 references in this file are legitimate and must survive.

## 4. Resolved decisions — do not re-open

**RFC 128 §11 open question 1 — keep an audit section here, or link out?**
**Keep it, and keep it thin.** `docs/src/expert/audit-log-hash-chain.md` is the
reference and stays authoritative; this chapter carries only what an operator
needs *during* an incident — where the data is, how to query it, what a chain
gap means — and links out for the mechanism. Restating the chain here is how
two documents start drifting apart, which is the failure this RFC exists to
correct.

**RFC 128 §11 open question 2 — has the rest of `docs/src/deployment/` ever
been audited?** No, and it is **not** this task's job to find out. Report it if
you notice something; do not go looking.

## 5. Change scope

| # | Task | Where |
|---|---|---|
| D1 | Rewrite "The audit trail" and "Querying the audit trail" | `observability.md` §~108–140 |
| D2 | Disposition all **seven** R2 references per RFC 128 §5 D2's table | `observability.md` lines 5, 99, 115, 128, 133, 180, 233 |
| D3 | Add a drift rule that fires on the old wording | `scripts/drift-scan.sh` |

Order: D1 → D2 → D3. **D3 last**, so it lands green.

## 6. Task detail worth stating explicitly

**D1.** Replace the event-shape table with the real columns (§3) and the query
surfaces with the four real routes. Cover: the console browser and its filters;
the export endpoint, and that **an export is itself an audited event**; chain
verification plus the daily cron, and what a gap means operationally; and
`wrangler d1 execute` against `audit_events` for what the console cannot
express — which is precisely the capability the current text denies exists.

**D2.** Three of the seven are legitimate. Do not sweep on pattern match —
RFC 128 §5 D2 gives a per-line disposition, and for every reference you keep,
say in the review request why. Line 99 in particular needs a judgement, not a
substitution.

**D3.** The reason this survived 49 versions is that nothing checked for it.
`drift-scan.sh` already carries `"all land in R2"` and `"R2_AUDIT"` from
RFC 012 and **neither matches this file's wording** — which is the lesson: a
rule that does not match the text it is meant to catch is not protection.

Use RFC 126 D3's third-field exclude mechanism. Your pattern must not fire on
the legitimate `ASSETS` references, nor on ADRs and `docs/changelog-archive/`,
which legitimately describe the pre-v0.32.0 architecture in the past tense.

## 7. Explicit non-change scope

- No change to the audit implementation, schema, routes, or the chain.
- No rewrite of the log-channel or metrics sections beyond D2's lines.
- Do not touch `docs/src/expert/audit-log-hash-chain.md` — it is already
  correct and is the reference this chapter links to.
- Nothing from RFC 129, 131, 132, or 133.
- Do not audit the rest of `docs/src/deployment/` (see §4).
- **Found while preparing this, deliberately out of scope:**
  `migrations/0008_audit_chain.sql` has a comment citing
  `cesauth_worker::audit::EventKind` — a crate renamed by RFC 114. Migrations
  are historical records and `migrations/` was not in RFC 126's sweep. Leave
  it; it is noted here so it is not rediscovered as new.
- Do not run `cargo fmt`.

## 8. Assert the machine-checkable parts mechanically

Every route and column you name must exist. Do not check by eye:

```sh
# every route named in the audit section resolves in the route table
grep -oP '/admin/console/audit[a-z/]*' docs/src/deployment/observability.md | sort -u | \
  while read -r r; do grep -q "\"$r\"" crates/backend/src/lib.rs \
    && echo "OK      $r" || { echo "MISSING $r"; exit 1; }; done

# every column named in the event-shape table exists in the migration
```

Attach both outputs.

## 9. Required tests and evidence

```sh
mdbook build docs                     > evidence/mdbook.log 2>&1
bash scripts/drift-scan.sh            > evidence/drift-scan.log 2>&1
bash scripts/route-contracts-check.sh > evidence/route-contracts.log 2>&1
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

Expected: `mdbook build` clean; **1,233 passed, 0 failed**; route contracts
188/188; everything else exit 0. `make build-frontend` should reproduce
**751,714 bytes**, sha256 `06009a6f…` — seven builds agree on it, so a
different figure is a finding, per RFC 133.

Plus:

- §8's two assertion outputs.
- **D3 fires:** plant the old wording ("Each audit event is one R2 object") in
  the file, show drift-scan red; remove, show green. Then plant the same string
  inside `docs/src/expert/adr/` and show it does **not** fire. Both halves.
  Sixth time this project has asked for such a pair.

Evidence policy unchanged: redirected output only, never an authored result
line.

## 10. What must NOT be claimed

That the documentation is now correct *generally*. This task corrects one
chapter's audit architecture. RFC 128 §11 q2 records that
`docs/src/deployment/` has never been audited against the code as a whole, and
this work does not change that. Say what you fixed, not what you believe is now
true.

## 11. Prohibited shortcuts

- Do not delete the audit section instead of correcting it. §4 rules on that.
- Do not write a D3 pattern so narrow it only matches the exact string you
  removed, nor so broad it fires on the legitimate `ASSETS` references.
- Do not silence a drift-scan hit with an exclusion where a correction is
  what is needed — that is how the `crates/` blind spot in RFC 126 arose, and
  it is disclosed there rather than hidden.
- No `cargo fmt`.

## 12. Acceptance criteria

RFC 128 §10, items 1–8. Checked hardest: **item 5** (all seven R2 references
dispositioned, with a stated reason for each one kept) and **item 7** (D3's
fires/does-not-fire pair).

## 13. Known risks

| Risk | Mitigation |
|---|---|
| The rewrite introduces a new inaccuracy | §8 asserts routes and columns against source, not against prose |
| A legitimate R2 reference is swept | §5 D2's per-line table; §6 requires a stated reason per reference kept |
| D3 fires on ADRs or archived changelogs | RFC 126 D3's exclude field, as its four crate-name rules already use |
| Duplicating `audit-log-hash-chain.md` | §4 rules: link, do not restate |

If the rewrite turns out to need facts you cannot establish from the schema,
the route table, or `audit-log-hash-chain.md` — **stop and report**. Do not
infer operator guidance.

## 14. Review request

Write the package to `.git-exclude/review-request/`. It must include:

Implementation summary · changed files · any deviation from §5 · every log
from §9 · both §8 assertion outputs · D3's fires/does-not-fire pair (both
halves) · the stated reason for each R2 reference kept · what remains
unverified (§10) · unresolved issues · requested review focus.

Report the path only.
