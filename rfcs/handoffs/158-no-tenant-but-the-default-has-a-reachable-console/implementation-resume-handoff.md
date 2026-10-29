# Developer Handoff — RFC 158, implementation resumed

**Governing RFC.** `rfcs/done/158-no-tenant-but-the-default-has-a-reachable-console.md`
— **§5 as decided**, **§5.1** (the trap), and **§5.2-§5.5**, which are new and
are the whole content of this handoff.
**Reviews.** `.git-exclude/reviewed/158-decision-review.md`,
`.git-exclude/reviewed/158-implementation-stop-review.md`

**Target release.** 0.89.0 — **minor**, unchanged.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Resumed 2026-10-29.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. The stop was right, and the error it caught was mine

My §1.6 said *"The one caller threads the repository through."* There are two.
You stopped exactly where the handoff told you to and the condition earned its
place. Keep stopping there.

**Your own count is wrong, though, and it changes the work.** §1 says "three
`adapter-test` call sites, which construct their own stub `UserRepository`
already":

    grep -c "create_tenant(" <the three files>  → 5, 3, 5  = 13 call sites
    grep -c "InMemoryUserRepository" <same>     → 0, 0, 0

Three *files*, **thirteen** call sites, and **none** of them has a user
repository — `common.rs` does not import `UserRepository` at all. The ripple
is **15 sites**, not 2. Reconcile a count against its parts before writing it
down; that rule is not only for my reports.

## 2. Keep everything in the working tree

All eight files are accepted. The adapter is a character-for-character match
of `tenants.rs:131-141`, §5.1's doc note says the useful thing, and the suite
is green at **1,606** (re-run with CI's command, summed programmatically).
Do not revert and re-derive.

## 3. The answer to your question: both — and stop asking "which callers"

**Both callers get it**, because a tenant whose owner can open their console
beside one whose owner cannot — decided by which door it came through — is an
inconsistency the operator cannot see. §5.2.

But do not thread the assignment through two call sites. **Put it inside
`create_tenant`**, where a third caller cannot omit it. You rejected option 3
by quoting ADR-003's *"structurally impossible"*; this is the same argument
applied to your own fix. §5.3.

## 4. What to build

1. **Revert nothing.** Start from the tree as it stands.
2. **`create_tenant` gains a `U: UserRepository` parameter** and returns a
   `#[must_use]` **struct**, not a bare `Tenant`:
   - the struct exists so a future field can join without another signature
     change — `ExecuteOutcome`'s own stated reason (`deletion.rs:194-202`);
   - it carries the tenant and an `OwnerHomeOutcome`.
3. **`OwnerHomeOutcome { Assigned, KeptExistingHome, Failed }`**, `#[must_use]`,
   with `as_str()` — **one-to-one with `ScrubOutcome`** (`deletion.rs:159-180`),
   whose doc comments are the model for yours, including that `Failed` absorbs
   "the owner row could not be found" as a storage inconsistency rather than
   evidence of anything.
4. **Order inside `create_tenant`:** validate slug → insert tenant → insert
   membership → **read the owner** → decide → assign → return the outcome.
   The read goes **after** both inserts, deliberately: §5.5 explains what a
   pre-flight read would fix and why that defect is not this RFC's.
   - owner's `tenant_id == DEFAULT_TENANT_ID` → `assign_tenant`, `Assigned`
     (or `Failed` if the write cannot be confirmed);
   - owner's `tenant_id` is some other tenant → **do not write**,
     `KeptExistingHome`. §5.4: overwriting revokes their admin access to the
     tenant they already administer.
   - owner not found, or the read fails → `Failed`.
5. **Name the small decision step** — the part that takes the owner's current
   home and returns an `OwnerHomeOutcome` — so it is testable without creating
   a tenant. It never returns `Err`; every failure is a variant.
6. **Both callers** use the outcome:
   - emit `user_tenant_assigned` **only** on `Assigned`;
   - put the outcome's `as_str()` in the **`tenant_created` detail** in every
     case, as RFC 148 §7.4 does (`deletions.rs:455`, `sweep.rs:282`);
   - log loudly on `Failed`, as those two sites do.
7. **Extract the detail string into a pure function with a host test.** This is
   a deliberate step *past* RFC 148's own precedent, which inlines `format!`
   inside `worker::Response` handlers that cannot be tested at all. Testing the
   outcome enum is not testing the caller that reports it. Keep each caller's
   existing prefix — the console's `via=tenancy-console,`, the API's absence of
   one (§5.5 records why that absence is a problem and why it is not yours to
   fix here).
8. **Thirteen test call sites** gain the argument. A fixture in
   `tenancy/tests/common.rs` that returns an `InMemoryUserRepository` — empty,
   or seeded with one owner — will keep this to one new helper and thirteen
   one-line changes. Existing assertions must not change meaning; if one does,
   stop and tell me.
9. **Both `route-contracts.md` rows** (`:230` and the console's) gain the
   conditional second event, in the form `:51` already uses for RFC 153.

## 5. Required evidence

§3 of the first handoff stands in full. Three additions, and the first is the
one that exists because of your stop:

1. **The console walkthrough**, unchanged and still mandatory: create a tenant
   with an existing owner against `wrangler dev` + local D1, assert
   `users.tenant_id` and the membership row **by query**, then **open
   `/admin/t/<slug>/` as that owner and get a page, not a 403.**
2. **The same proof through `POST /api/v1/tenants`** — a second tenant, a
   second owner, the same query and the same page. This caller is the reason
   the cycle paused; a design that fixes it unproven is not evidence.
3. **All three `OwnerHomeOutcome` variants exercised as host tests**, plus the
   detail string each one produces — including `KeptExistingHome` against an
   owner already homed in another tenant, asserting the old home **still
   stands** and the old tenant's console still opens for them.
4. **`InMemoryUserRepository::assign_tenant` gets its own test.** It is
   host-testable production code; under RFC 000 §22 what is in the tree today
   is `reviewed`, not `exercised`.
5. **Fires/does-not-fire**, as before, and the **negative check**: a non-owner
   in the default tenant still gets 403.
6. **Full gate set with counts**, host baseline **1,606** before your changes.

## 6. Resolved — do not re-open

- Option 2; `ManageTenancy` inherited; minor.
- **Assignment inside `create_tenant`**, not at the callers.
- **An already-homed owner keeps their home.** The 409 refusal was drafted and
  rejected — §5.4. Do not re-propose it.
- **No pre-flight owner read**, and the orphan-tenant defect stays open — §5.5.
- **The API path's missing `via=` marker stays open** — §5.5.
- Out of scope: the standalone "move an existing user between tenants" route;
  RFC 159's nine; RFC 152 half B and §6; RFC 141 cycle 2; RFC 123; RFC 120.

## 7. Report-and-stop

- an existing test's *assertion* has to change meaning, not just its call;
- the owner still cannot reach the console after the assignment lands;
- a third production caller of `create_tenant` exists that §5.2's grep missed;
- an evidence requirement cannot be constructed.

## 8. Review request

`.git-exclude/review-request/158-implementation-report-2.md` — a new path, so
the first report survives. Give me the commit.
