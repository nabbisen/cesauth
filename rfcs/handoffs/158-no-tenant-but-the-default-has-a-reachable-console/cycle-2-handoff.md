# Developer Handoff — RFC 158, cycle 2

**Governing RFC.** `rfcs/done/158-no-tenant-but-the-default-has-a-reachable-console.md`
— **§5.6** and **§5.7**, both new and both the whole content of this handoff.
**Review.** `.git-exclude/reviewed/158-implementation-review.md`
**Builds on.** `27171b8`, which is accepted and stays.

**Target release.** 0.89.0 — **minor**, unchanged. **Not cut until this
lands**: the gap in §5.6 is inside the feature this release delivers, and
shipping it first would make the first release of owner-home assignment the
one that misleads the operator.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-10-29.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. `27171b8` is accepted — revert nothing

Re-verified, not read: **1,616** host tests passed / 0 failed over 12 `test
result` lines, `migration_chain` **35**, routes **193**, bundle parts
reconcile to 881,882 B, tree clean. Every handoff item matched. Two things
deserve saying:

- **Your `KeptExistingHome` live case and its 403 follow-up were not asked
  for.** They are what found the gap in §3 below — the strongest kind of
  evidence, the kind that argues against the thing it demonstrates.
- **You caught your own probe error** — the first fires attempt used an
  already-homed owner, produced `KeptExistingHome`, exercised nothing, and you
  said so and redid it. Report it that way every time.

## 2. §5.7 — the one defect (small, and yours)

Both callers, on the `Failed` branch only:

    let cfg = Config::from_env(&ctx.env)?;

`Config::from_env` is fallible (`config.rs:90-97`) and this `?` runs **after**
the tenant and membership rows exist. A bad deployment variable therefore turns
a created tenant into a `500` with no body — a failed owner-home assignment
reported as a failed tenant creation, which is the single invariant
`OwnerHomeOutcome` exists to protect. The audit write two lines above uses
`.ok()` for exactly this reason; `deletions.rs:443`, the precedent you
followed, loads config **before** its operation, where failing is harmless.

**Fix:** do not propagate. If the config cannot be loaded, the loud log is
lost, but the response must not change. Make the same change in both callers.

## 3. §5.6 — the gap, and it is mine

My review said *"keep the existing home **and say so**"*; my handoff then
listed the audit event, the audit detail and the log line. **All three are
machine-readable and none reaches the operator.** Your log shows the result:
`303 See Other` to an ordinary success page, and the owner 403s on the console
they were just given.

### 3.1 Console

- **`Assigned`: unchanged.** Same `303`, same location. Do not touch it.
- **`KeptExistingHome` / `Failed`:** render a page instead of redirecting. It
  must say, in the operator's words, three things: the tenant **was** created;
  what happened to the owner's home tenant; and that consequently the owner
  **cannot open this tenant's console** — plus a link on to the tenant detail
  page the redirect would have gone to.
- **Do not invent a flash or notice mechanism.** There is none in this console
  (nothing reads a query parameter or a flash cookie) and this RFC is not where
  one gets designed. A function beside `tenant_create_form` in
  `crates/frontend/src/tenancy_console/forms/tenant_create.rs`, using
  `tenancy_console_frame` as that module already does, is the whole of it.
- The wording for `KeptExistingHome` must explain *why* — the owner already
  administers another tenant and moving them would have taken that away
  (§5.4). An operator who reads it should know what to do next without asking.
- **A rendering test**, beside the existing ones in
  `crates/frontend/src/tenancy_console/tests/`, in the form
  `route-contracts.md`'s "Rendering test" column already uses.

### 3.2 API

The `201` body **keeps every field it has today at the top level** and gains
`owner_home`, carrying the outcome's `as_str()`. A client reading `id` or
`slug` must be unaffected — additive, not a reshape, and not a wrapper object.

- `GET /api/v1/tenants` and `GET /api/v1/tenants/:tid` are **untouched**. The
  home tenant is a property of the user, not of the tenant; this field reports
  what *this call* did, which is the thing the caller cannot otherwise learn.
- **Say this change out loud in your report.** It is a surface-contract change
  on a public route even though it is additive.
- Update `route-contracts.md`'s `POST /api/v1/tenants` row if its columns carry
  anything that is now wrong. The audit-kind cell is already correct.

## 4. Two small ones

- **`rfc_158_owner_home.rs`'s wrong comment.** In
  `owner_already_homed_elsewhere_keeps_that_home`, *"the Beta creation above
  assigned u-beta-owner's home to Beta already (Assigned)"* — it did not;
  `u-beta-owner` is seeded **after** that call, so the outcome was `Failed`.
  The test proves what it claims; the explanation is wrong and `u-beta-owner`
  is then never used. Fix the comment, drop the dead seeding, or make the
  comment true — your call, but the file must not explain itself incorrectly.
- **Pin `Failed` via a failed write.** `StubUsers.fail` gates `find_by_id`
  only, so no host test reaches `Failed` through `assign_tenant` returning
  `Err` — the branch the doc comment calls "must be surfaced loudly". Three
  lines.

## 5. Required evidence

1. **The two console cases, live**, against `wrangler dev` + local D1: create a
   tenant for an already-homed owner and **show the page the operator sees**;
   force the assignment write to fail and show that page too. The rendered
   text is the deliverable here, not a status code.
2. **`Assigned` still redirects** — same `303`, same location. Show it.
3. **The API `201` body** for all three outcomes, showing `owner_home` **and**
   that `id`/`slug` are still top-level.
4. **§5.7 proved**: with the fix in place, a `Failed` outcome returns the
   normal response even when the config load fails. If you cannot make
   `Config::from_env` fail against `wrangler dev` without changing production
   code, **say so in one line and substitute** — do not invent a test that
   cannot exist.
5. **Full gate set with counts.** Host baseline **1,616**; `migration_chain`
   **35**; routes **193**; bundle with sha256 — **all 64 characters, copied
   from the log, not retyped**; 13 workflows against the manifest.
6. **An updated `Status` + `Evidence` back-fill line**, superseding the one in
   your last report.

## 6. Resolved — do not re-open

- Everything in `27171b8`'s design: the assignment inside `create_tenant`, the
  outcome struct, `KeptExistingHome` over a 409, the owner read after both
  inserts.
- **Still out of scope and still open**: the orphan-tenant defect and the API
  path's missing `via=` marker (§5.5); the standalone move-user route; RFC
  159's nine; RFC 152 half B and §6; RFC 141 cycle 2; RFC 123; RFC 120.

## 7. Report-and-stop

- the console notice needs anything beyond one template function and its test;
- adding `owner_home` to the `201` cannot be done without reshaping the body;
- an evidence requirement cannot be constructed.

## 8. Review request

`.git-exclude/review-request/158-cycle-2-report.md`. Give me the commit.
