# Developer Handoff — RFC 158, implementation

**Governing RFC.** `rfcs/done/158-no-tenant-but-the-default-has-a-reachable-console.md`
— **§5 as decided 2026-10-29**, and **§5.1**, which is a trap sitting one
function away from this work.
**Decision review.** `.git-exclude/reviewed/158-decision-review.md`

**Target release.** 0.89.0 — **minor.** One new `EventKind` is additive surface
for anything parsing the audit stream, which is the reasoning that made RFC 154
a minor. Consistency with that precedent decides it, not the fact that this
RFC's primary effect is fixing a defect.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-10-29.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. Build what the decision stage specified

Your own report is the specification; it is not re-derived here. In short:

1. `UserRepository::assign_tenant(user_id, tenant_id, now)` — a dedicated
   single-field port method, **shaped like `tenancy::set_status` and
   `billing::set_plan`**, which the decision stage established as the house
   idiom. Trait addition, so both implementors gain it: the real
   `CloudflareUserRepository` and `adapter-test`'s double.
2. The adapter `UPDATE users SET tenant_id = ?2, updated_at = ?3 WHERE id = ?1`.
3. A core service function wrapping it, with its own identity and test.
4. `create_tenant` gains a `UserRepository` parameter and calls the assignment
   **last**, after the tenant row and the membership row both succeed.
5. One new `EventKind`. Name it as you judged — your reading of the existing
   `TenantCreated`/`MembershipAdded` naming is better placed than mine.
6. The one caller threads the repository through.

**No migration.** `users.tenant_id` exists; this is a new way to write it.

## 2. §5.1 is the trap — do not let it bite the implementation

`UserRepository::update()` **silently ignores `tenant_id`.** No error, no
effect. So:

- **Do not implement `assign_tenant` by fetching, mutating and calling
  `update()`.** It will pass every test you write against the returned
  `Ok(())` and change nothing in the database. **Assert the row.**
- While you are in that file: the omission is deliberate and documented, so
  leave it. **But if a one-line doc note on `update()` would stop the next
  reader assuming it can move tenants, add it** — §5.1 exists because that
  assumption is the one this shape invites.

## 3. Required evidence

**The second half is the one this RFC exists for.** A row is not enough.

1. **Create a tenant through the console** against `wrangler dev` + local D1,
   with an existing user as owner, and **assert by query** that
   `users.tenant_id` equals the new tenant's id and the
   `user_tenant_memberships` row is there.
2. **Then open `/admin/t/<slug>/` as that owner and get a page**, not a 403.
   **That is the only proof the gate now passes for them** — and the symptom
   RFC 158 was written about. A passing database assertion with no page is a
   half-finished demonstration.
3. **The audit row**, queried, with the actor recorded.
4. **Fires/does-not-fire**: remove the assignment call, show the owner still
   gets 403 (the pre-RFC behaviour) and the test fail; restore
   byte-identically; show both pass.
5. **A negative check**: a user who is *not* the owner, in the default tenant,
   still gets 403 on that tenant's console. **The gate must still exclude** —
   this RFC makes one principal pass, not everyone.
6. **Full gate set with counts**: host tests via CI's exact command
   (`test.yml:51-55`, five crates, **no `--lib`**), summed programmatically,
   baseline **1,606**; `migration_chain` **35**; routes **193**; **the Worker
   bundle**, parts checked against the total, sha256 beside each; and the
   workflow count checked against `.github/release-gate-manifest.json`.
7. **A proposed `**Status**` + `**Evidence**` line** in the back-fill's
   normalised format.

## 4. Resolved decisions — do not re-open

- **Option 2**, as decided. Not option 1 in either shape, not option 3.
- **Minor**, for the `EventKind` reason above.
- **`ManageTenancy` is inherited**, not re-litigated.
- **Out of scope**, and you already said so yourself: the standalone "move an
  existing user between tenants" route this method makes possible. **It stays
  undesigned.** My own RFC text named it as a *benefit* of option 2 and you
  correctly declined to treat a benefit as a requirement — that holds here too.
- **Also out of scope:** RFC 159's nine, RFC 152 half B and §6, RFC 141 cycle 2,
  RFC 123, RFC 120.

## 5. Report-and-stop

- the `UserRepository` parameter ripples past `create_tenant`'s one caller;
- the owner still cannot reach the console after the assignment lands, for a
  reason the decision stage did not anticipate — **that would mean a second
  gate exists that nobody has found**, and I want to hear it immediately;
- an evidence requirement in §3 cannot be constructed.

## 6. Review request

Write the package to `.git-exclude/review-request/158-implementation-report.md`
— a **different path from the decision report**, so both survive — and give me
the commit.
