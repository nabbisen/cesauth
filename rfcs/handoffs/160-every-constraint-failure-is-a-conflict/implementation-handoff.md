# Developer Handoff — RFC 160, implementation

**Governing RFC.** `rfcs/accepted/160-every-constraint-failure-is-a-conflict.md`
— **§4.5 as decided**, plus **§4.6** (the rule that keeps a revived arm
honest) and **§4.7** (the two API paths, decided rather than deferred).
**Decision review.** `.git-exclude/reviewed/160-decision-review.md`

**Target release.** **0.89.1 — patch.** No `core::ports` edit, neither
exhaustive match touched, and the status codes that change are wrong ones being
corrected.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-10-29.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. Your decision stands, and it beat mine on the right ground

`NotFound`, not a new variant. **The argument you led with is not the one that
wins.** The census is a cost comparison, and a cost comparison can always be
answered with "then pay the cost". What cannot be answered is your deliverable
(0): **D1's foreign-key message names neither the column nor the referenced
table**, and `map_insert_err`'s `context` names the statement rather than which
of its two foreign keys failed. The variant I proposed was to *carry which
reference was missing*; that payload does not exist for anyone to put in it.
Lead with that next time — you had the decisive fact and filed it under "one
asymmetry worth recording."

Two corrections, neither changing the decision:

- **Four arms come alive, not seven.** The three in
  `tenant_admin/forms/membership_add.rs` sit behind `verify_user_in_tenant`
  (`:341-350`), which already 404s on an absent user at `:91`/`:196`/`:297`,
  and behind `orgs.get` (`:149`) / `groups.get` (`:255`). Both foreign keys are
  proven present before the statement runs, so those three can fire only on a
  race. A count is a count.
- **`admin/legacy.rs` is not a third exhaustive match** — I briefly thought it
  was. Its wildcard is `Err(_) =>` at `:97`. Your "only two" is right.

Everything else in the census I re-ran and it holds, including both
no-production-caller findings and `groups.rs` as a second live foreign-key
site, which is yours and is not in the governing RFC's evidence.

## 2. Build

1. **Classify UNIQUE and FOREIGN KEY. Nothing else.** §4.5: neither CHECK nor
   NOT NULL is reachable by any caller — which is why you needed a
   sentinel-gated probe in production code to see them at all. Adding branches
   nothing can produce would put untestable code in the very helper whose
   untested assumption caused this RFC. Everything that is not those two keeps
   today's `run_err` path.
2. **The `SQLITE_CONSTRAINT_<CLASS>` suffix is the discriminator.** You found
   it; it is more specific than the human-readable prefix and it is already in
   the string. Case-fold once, not twice inconsistently.
3. **One helper.** `map_insert_err` exists and serves three callers; the other
   five sites inline the same test. Only `memberships.rs` and `groups.rs` need
   FOREIGN KEY recognition — but all eight should stop testing
   `contains("unique")`, which has never changed an outcome.
4. **`groups.rs` gets the classification too**, not only `memberships.rs`. It
   is the site your own census found.
5. **§4.7's two API paths**, as decided:
   - `POST /api/v1/tenants` → a `NotFound` from `create_tenant` can only be the
     owner reference, so **400 naming `owner_user_id`**.
   - `POST /api/v1/tenants/:tid/groups` → resolve the tenant in the handler
     first (one `tenants.get`, as every console handler already does), making
     `:tid` an honest 404; the remaining `NotFound` is then only
     `organization_id`, so **400 naming it**. **Do not** add a
     `TenantRepository` to `create_group` — that is a core signature change
     with a test ripple across its call sites, RFC 158 §5.2's lesson.
6. **Apply §4.6's rule to every arm you touch or revive.** An arm may name a
   subject only where every *other* foreign key on that statement is already
   proven to exist. The four that come alive satisfy it today; say so per arm
   in your report, with the line number of the check that makes it true. Where
   it is not satisfied, the arm names the possibilities or says nothing
   specific.
7. **Census item 3, completed rather than described**: every arm that names a
   cause must be reachable by it, and every reachable cause must have an arm.
   That includes the `group_create.rs`/`organization_create.rs` forms in both
   consoles, which have **no** `NotFound` arm — add one only where a
   `NotFound` can actually reach that handler, and say which and why for each.

## 3. Required evidence

1. **The four strings again is not needed** — you have them, they are in the
   RFC's record. **Do not re-run the production-code probes for CHECK and NOT
   NULL**; nothing in this build depends on those two classes.
2. **Live, through both live sites**: `POST /api/v1/tenants` with an unknown
   `owner_user_id` → **400 naming the field**, not `409`, not `404`; and
   `POST /api/v1/tenants/:tid/groups` with an unknown `organization_id` → 400
   naming it, plus with an unknown `:tid` → 404. Full response bodies.
3. **A UNIQUE collision still answers `409`** at both sites — the fix must
   narrow the classification without losing the case it was right about.
   Duplicate tenant slug and duplicate group slug, both shown.
4. **The console**, live: a mistyped owner id on `/admin/tenancy/tenants/new`
   now renders **"Owner user id not found"** instead of "Slug already taken in
   this deployment", and a genuinely taken slug still renders the slug message.
   **Both halves** — this RFC is as much about not breaking the message that
   was right.
5. **One membership form**, live: a mistyped user id renders "User id not
   found" rather than "Storage error".
6. **Host tests** for the classifier itself, from the recorded strings: a
   UNIQUE string → `Conflict`, a FOREIGN KEY string → `NotFound`, and a string
   that is neither → today's path. These are pure-function tests over the
   message text, so they belong on the host, not in a live walkthrough.
7. **Fires/does-not-fire** on the classification: revert the FOREIGN KEY arm,
   show `409` return and the test fail; restore byte-identically; show both
   pass.
8. **Full gate set with counts.** Host baseline **1,623**; `migration_chain`
   **35**; routes **193**; bundle with full 64-character sha256 copied from the
   log; 13 workflows against the manifest.
9. **A `Status` + `Evidence` back-fill line** in the normalised format.

## 4. Resolved — do not re-open

- `NotFound`, not a new variant, not `PreconditionFailed`.
- CHECK and NOT NULL stay unclassified.
- `create_group`'s signature is unchanged.
- **Patch**, 0.89.1.
- **Still open, still not this RFC's**: the orphan tenant a failed membership
  insert leaves behind, and the API path's missing `via=` audit marker (RFC 158
  §5.5). Also out of scope: RFC 159's nine; RFC 152 half B and §6; RFC 141
  cycle 2; RFC 123; RFC 120.

## 5. Report-and-stop

- a site needs FOREIGN KEY recognition that §4.5's table says cannot produce
  one — that would mean the table is wrong and I want to hear it immediately;
- an arm you revive cannot be made honest under §4.6's rule;
- resolving the tenant in `api_v1/groups.rs::create` turns out to ripple past
  that handler;
- an evidence requirement cannot be constructed.

## 6. Review request

`.git-exclude/review-request/160-implementation-report.md`. Give me the commit.
