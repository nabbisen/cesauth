# Developer Handoff — RFC 157, sixteen unrouted handlers and the gate they block

**Governing RFC.** `rfcs/accepted/157-unrouted-handlers-and-the-warnings-gate.md`

**Target release.** 0.88.1 — **patch.** Deletions and one CI flag. Nothing a
caller can reach changes; if the triage says otherwise for any route, that is a
report-and-stop (§4).

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. RFC 153 shipped in 0.88.0, so the instruction that
cycle carried — *do not delete any of these as a side-effect* — is discharged.
**Dispatched 2026-10-29.**

---

## 1. What this is

RFC 145 §13.2 decided not to enable `-D warnings` because `cargo fix` would
delete unused imports that **were** the compiler's report of a P1 defect. That
defect was fixed in v0.86.1 and v0.86.2. **The prohibition's reason expired and
the rule did not** — RFC 157 §4 lifts it explicitly, and this cycle clears what
remains so the gate can go on.

## 2. Facts already measured — do not re-derive

**Sixteen handler-shaped functions are routed by nothing.** Defined as a
`pub async fn` in `crates/backend/src/routes/` taking `req: Request, ctx:
RouteContext`, whose **name appears nowhere in `lib.rs`** — and `lib.rs` is the
only router:

```
handler-shaped pub async fns in routes/: 218
not referenced in lib.rs at all:          16
```

The sixteen:

```
admin::auth::list_tokens
admin::console::config::edit_form_json
admin::console::tokens::new_form_json
admin::tenancy_console::forms::group_create::form_org_json
admin::tenancy_console::forms::group_delete::confirm_json
admin::tenancy_console::forms::membership_add::form_org_json
admin::tenancy_console::forms::membership_add::form_group_json
admin::tenancy_console::forms::membership_remove::confirm_tenant_json
admin::tenancy_console::forms::membership_remove::confirm_org_json
admin::tenancy_console::forms::membership_remove::confirm_group_json
admin::tenancy_console::forms::role_assignment_delete::confirm_json
admin::tenant_admin::forms::membership_add::form_org_json
admin::tenant_admin::forms::membership_add::form_group_json
admin::tenant_admin::forms::membership_remove::confirm_tenant_json
admin::tenant_admin::forms::membership_remove::confirm_org_json
admin::tenant_admin::forms::membership_remove::confirm_group_json
```

**Three are referenced nowhere in the crate at all** —
`auth::list_tokens`, `console::tokens::new_form_json`,
`console::config::edit_form_json`. The other thirteen are reached **only by
their own tests**.

**Sixteen is a lower bound, and resolving it is deliverable (0).** The name
test under-counts when an unrouted function shares a name with a routed one; a
path-based count gave **18**. The path test over-counts where a re-export
exists, and `admin.rs:32` has one (`pub use legacy::{create_user,
revoke_session}`). **Reconcile the two and report the number with its method.**

**Warning populations are two, not one.**

```
$ cargo build -p cesauth-backend --tests     # rustc lints only
148 warning lines across the lib and lib-test targets
    97  unused import   ·   41  unused variable   ·   10  dead code
```

`cargo clippy` adds a **separate** population (`borrowed expression`,
`doc list item`, `sort_by_key`). **That** is the population a blanket
`-D warnings` would make hostage to a toolchain bump. **Quote the command and
the target** when you re-measure: "143" is the `(lib test)` summary alone, and
I had been quoting it as the crate's total.

## 3. The work

1. **Triage each of the sixteen** (or eighteen): **delete, or wire.** A
   `route-contracts.md` row goes with any deletion that had one. **"Leave it"
   is not available** — that is what produced sixteen.
2. **A test that exists only to exercise a deleted handler goes with it.** But
   **say so per test in the report**: a test whose only subject was an unrouted
   handler was testing dead code, and that is worth one line each, not a silent
   `-N` in the count.
3. **Delete the leftover unused imports** in modules serving legitimately
   `client`-declared routes. §13.2's prohibition is lifted — the defect whose
   evidence it preserved is fixed, and `tenant_admin/organizations.rs` is the
   worked example: it still calls `json_api::shell`, and that route is
   **legitimately** `client` and live in `app.rs`, which the §4.2 gate confirms
   by passing.
4. **Re-measure**, command and target named.
5. **Then add `-D unused_imports -D unused_variables`** to the backend's
   invocation in `.github/workflows/clippy.yml`, beside the existing
   `-D clippy::correctness`.
6. **Blanket `-D warnings` stays rejected.** Not negotiable in this cycle.

## 4. Report-and-stop gates

- a handler turns out to be reachable by something other than `lib.rs`;
- deleting one would remove behaviour a `route-contracts.md` row claims — that
  means the row, not the handler, may be the thing to fix, and I want to decide
  it;
- the new lint flags turn something red that is **not** among the sixteen —
  that is a finding, not a tidy-up, and I would rather hear it than have it
  silently fixed;
- `admin::auth::list_tokens` is the one non-`*_json` entry. **Look before
  deleting**: if it is a would-be API rather than a dead companion, say so.

## 5. Resolved decisions — do not re-open

- **Patch.**
- **Out of scope:** RFC 158 (its decision stage is next and is not yours to
  pre-empt), RFC 152 half B and §6, RFC 141 cycle 2, RFC 123 §1.1/§1.2,
  RFC 120.
- **Do not touch `accept_page` or the invitation flow** beyond anything these
  deletions strictly require — 0.88.0 shipped two days of work there.

## 6. Required evidence

1. **Deliverable (0)**: the reconciled count, with both methods and why they
   differ.
2. **Fires/does-not-fire on the new flags**: reintroduce one unused import,
   show `clippy` fail with the new flags, restore byte-identically, show it
   pass. **A gate nobody has watched fail is not evidence it can.**
3. **Full gate set with counts** — host tests via CI's exact command
   (`test.yml:51-55`, five crates, **no `--lib`**) summed programmatically,
   baseline **1,606**; `migration_chain` **35**; routes **193** before any
   deletions change it.
4. **The Worker bundle**, measured with CI's per-module gzip-sum method, parts
   checked against the total, sha256 beside each. **Naming it here because the
   last cycle's report omitted it and my handoff had not asked** — that was a
   shared miss and this line closes it.
5. **The workflow count checked against `.github/release-gate-manifest.json`**,
   not recalled. The last cycle did this unprompted; it is the manifest's job.
6. **A proposed `**Status**` + `**Evidence**` line** for RFC 157 in the
   back-fill's normalised format.

## 7. What must not be claimed

- Not that the warning count is "zero" — the clippy population is untouched and
  the dead-code lints may remain. Say which population you measured.
- Not that `-D warnings` is enabled. Two named lints are.
- No count in prose without its command **and its target**, no derived total
  unchecked against its parts, and no delta between a local measurement and a
  CI baseline.

## 8. Review request

Write the package to `.git-exclude/review-request/157-report.md` and give me
the commit. I verify independently before anything is tagged.
