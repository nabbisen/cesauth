# RFC 008: Eliminate plaintext OTP in audit log

**Status**: Ready
**ROADMAP**: External codebase review v0.50.1 — Critical finding
**ADR**: N/A (the fix is mechanical; the boundary it enforces is settled by the existing `audit::write_*` invariant)
**Severity**: **P0 — production blocker**
**Estimated scope**: Small — ~30 LOC across two route files + 6 test additions + retention guidance for purging already-leaked rows + chain re-baseline runbook
**Source**: External Rust+Cloudflare codebase review attached to v0.50.1 conversation, Critical finding. Independently verified.

## Background

`crates/worker/src/audit.rs` declares the
project-wide invariant in its module-level
documentation:

> No token material ever.

But two route handlers violate it on every Magic Link
issuance:

```rust
// crates/worker/src/routes/magic_link/request.rs:170-178
audit::write_owned(
    &ctx.env, EventKind::MagicLinkIssued,
    Some(body.email.clone()), None,
    Some(format!("dev-delivery handle={handle} code={}", issued.code_plaintext)),
).await.ok();
```

```rust
// crates/worker/src/routes/api_v1/anonymous.rs:254-264
audit::write_owned(
    &ctx.env, EventKind::MagicLinkIssued,
    Some(session.user_id.clone()),
    None,
    Some(format!("via=anonymous-promote,handle={},code={}",
        handle, issued.code_plaintext)),
).await.ok();
```

The `request.rs` site even self-flags the violation
in its inline comment:

> When production mail is wired in, this line MUST
> change to log only the handle.

The structural reason is the absence of a real mailer
(see RFC 010): the audit log IS the OTP delivery
mechanism in cesauth today, used by operator-side
log-shipper scripts. RFC 010 builds the proper
mailer port; this RFC severs the audit-as-delivery
coupling first so the surface stops bleeding.

Anyone with audit-read access — D1 read role, Logpush
forwarder, SIEM operator, anyone who runs
`cesauth-migrate export` against production, anyone
who restores a backup — can trivially log in as any
user who used Magic Link or anonymous-promote during
the retention window.

This is **P0**: the leak is active, the invariant is
self-declared, the fix is small.

## Requirements

1. The audit log MUST NOT contain the plaintext OTP
   code, anywhere, ever.
2. Existing audit rows containing plaintext OTPs MUST
   be purged from production deployments as part of
   the upgrade procedure.
3. The audit hash chain MUST be re-baselined after
   purge.
4. Reintroducing the leak (a future contributor
   pasting `code=...` into an `audit::write_*` call)
   MUST fail CI.

## Design

### Step 1 — Remove plaintext from the two audit calls

`crates/worker/src/routes/magic_link/request.rs`:

```rust
audit::write_owned(
    &ctx.env, EventKind::MagicLinkIssued,
    Some(body.email.clone()), None,
    Some(format!("handle={handle}")),
).await.ok();
```

`crates/worker/src/routes/api_v1/anonymous.rs`:

```rust
audit::write_owned(
    &ctx.env, EventKind::MagicLinkIssued,
    Some(session.user_id.clone()),
    None,
    Some(format!("via=anonymous-promote,handle={handle}")),
).await.ok();
```

Drop `code_plaintext` from both format strings. The
`handle` is a server-side challenge handle, not user-
facing material — keep it for correlation.

### Step 2 — Static-grep pin test

Reintroduction defense. Test in
`crates/worker/src/audit/tests.rs`:

```rust
/// **Invariant pin (v0.50.2, RFC 008)** — no
/// `audit::write_*` call site shall pass token
/// material through any field, including `reason`.
/// Enforced as a build-time grep over the source
/// tree.
///
/// Denylist tokens that strongly indicate secret
/// material: `code=`, `code_plaintext`, `otp=`,
/// `secret=`, `password=`, `plaintext`, the literal
/// `token=` followed by a non-handle context.
///
/// False positives are rare; if one occurs, refactor
/// the call to use a non-secret-shaped key name
/// rather than weakening this test.
#[test]
fn no_audit_reason_format_string_contains_secret_substring() {
    use std::path::Path;
    let denylist = [
        "code=",            // OTP plaintext
        "code_plaintext",   // bare reference
        "otp=",
        "secret=",
        "password=",
        "plaintext",
    ];
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let crates_dir = Path::new(manifest_dir)
        .parent().unwrap()
        .parent().unwrap()
        .join("crates");
    let mut violations = Vec::new();
    walk_rs_files(&crates_dir, &mut |path, contents| {
        if path.ends_with("tests.rs") || path.contains("/tests/") {
            return;
        }
        // Find every `audit::write` call site and
        // scan the surrounding 8 lines (which span
        // the typical `format!(...)` argument).
        for (line_no, line) in contents.lines().enumerate() {
            if !line.contains("audit::write") { continue; }
            let block = contents.lines()
                .skip(line_no)
                .take(8)
                .collect::<Vec<_>>().join("\n");
            for needle in denylist {
                if block.contains(needle) {
                    violations.push(format!(
                        "{}:{} — `{}` in audit::write context",
                        path, line_no + 1, needle,
                    ));
                }
            }
        }
    });
    assert!(violations.is_empty(),
        "Audit secret-substring denylist matched:\n{}",
        violations.join("\n"));
}
```

The walker function (`walk_rs_files`) is small and
lives alongside the test. The grep operates on the
build tree, not a runtime trace — that's the
correct boundary: every literal site is checked at
test time, including paths never exercised in
runtime tests.

### Step 3 — Rename `code_plaintext` → `delivery_payload`

Currently `MagicLinkIssued` (the in-memory value
returned by `magic_link::issue`) exposes a
`code_plaintext` field. Casual logging of a field
named `code_plaintext` is exactly what the bug was.

Rename to `delivery_payload`:

```rust
pub struct MagicLinkIssued {
    pub handle:           String,
    pub code_hash:        Vec<u8>,
    pub delivery_payload: String,   // ← was: code_plaintext
    pub expires_at:       i64,
}
```

A reader of `delivery_payload` sees a name that says
"this exists to be delivered, not logged". The
denylist grep test in Step 2 still catches the
literal `code_plaintext` if it reappears, AND the
positive-rename signals intent.

This is symbolic but valuable. Engineering hygiene.

Coordinate with RFC 010: the mailer adapter takes
`MagicLinkPayload { code: &str }` — the rename here
makes the audit/mailer field-name divergence
explicit (audit gets `handle` only; mailer gets
`code` from `delivery_payload`).

### Step 4 — Operator data hygiene runbook

Existing audit rows from v0.16 → v0.50.1 contain
plaintext OTPs. Operators upgrading must purge
them as part of the v0.50.1 → v0.50.2 cutover.

Two paths considered:

- **Option A — operator-run SQL**. Release notes
  document a `wrangler d1 execute` script:
  ```sql
  UPDATE audit_events
     SET reason = NULL
   WHERE kind = 'MagicLinkIssued'
     AND reason LIKE '%code=%';
  ```
- **Option B — automated migration `0011_purge_otp_audit_leaks.sql`**
  bumping SCHEMA_VERSION to 11, runs the same
  UPDATE on every deploy.

**Decision: Option A.** Reasoning:

- Option B would force-purge on rollback as well —
  if an operator rolls back v0.50.2 → v0.50.1
  during incident triage, automated purge destroys
  forensic evidence. Option A leaves the operator
  in control of timing.
- Option B adds a SCHEMA_VERSION bump even for
  operators with no leaked rows (fresh deployments
  who never ran v0.50.1 in production), polluting
  the migration history.
- Option A's UPDATE is reversible until the
  operator runs `VACUUM`; Option B is committed in
  migration history.

Document Option A in a new section
`docs/src/deployment/day-2-runbook.md` titled
"Operation: purge plaintext OTP audit leaks
(one-time, v0.50.1 → v0.50.2 upgrade)" with the
SQL, an export-then-purge variant for forensic
preservation, and the chain re-baseline procedure.

### Step 5 — Audit hash-chain re-baseline

The purge UPDATE breaks the chain at every modified
row. The next `audit_chain_cron::run` will fail-
closed at the first purged row, blocking subsequent
verification. Recovery:

```sql
DELETE FROM audit_chain_checkpoints;
```

Then re-run the cron (manual `wrangler dev` or wait
for the daily 04:00 UTC tick); it rewalks from
seq=1 and writes a fresh checkpoint over the
post-purge tail.

The runbook documents this as the third step of the
purge operation. Operators who skip the re-baseline
will see chain-verification alarms on next cron run
— alarming but recoverable.

### Step 6 — Audit module documentation update

`crates/worker/src/audit.rs` module doc gains:

```rust
//! ## Invariant: no token material in audit
//!
//! No call to `write_*` may pass token material —
//! OTP plaintext, refresh-token plaintext, access-
//! token plaintext, magic-link verification code,
//! TOTP secret, recovery code plaintext, session
//! cookie value, CSRF token value, JWT payload — in
//! any field, including `reason`.
//!
//! Enforced by the test
//! `no_audit_reason_format_string_contains_secret_substring`
//! at build time.
//!
//! Violations historically existed in
//! `routes::magic_link::request` and
//! `routes::api_v1::anonymous` (v0.16 → v0.50.1) and
//! were closed in v0.50.2 (RFC 008). Operators
//! upgrading past v0.50.1 must run the
//! audit-purge runbook in
//! `docs/src/deployment/day-2-runbook.md` to
//! sanitize already-persisted rows.
```

## Test plan

1. **Static-grep pin test** (Step 2). Asserts no
   audit-write site references denylist tokens.
2. **Regression test — magic_link/request**:
   construct the request handler with the in-memory
   adapter, drive a Magic Link issue request, fetch
   the persisted audit row, assert `reason` does
   NOT contain the OTP plaintext. The plaintext
   value is captured separately for the assertion.
3. **Regression test — anonymous/promote**: same
   shape against the anonymous promote route.
4. **Field rename compiles**: implicit — the rename
   in Step 3 is enforced by the type system.
5. **Documentation test**: the
   `docs/src/deployment/day-2-runbook.md` section
   exists and references the purge SQL + chain
   re-baseline.
6. **Manual test (operator)**: in staging, populate
   a few `MagicLinkIssued` rows pre-fix, deploy
   v0.50.2, run the runbook, verify no `code=`
   substring remains in any audit row.

## Security considerations

**Forensics impact of the purge**. Rewriting audit
rows loses information. The trade-off is
unavoidable: keep plaintext (active P0 leak) vs lose
audit history of issuance events. The runbook
provides an export-then-purge variant for operators
who need to preserve evidence privately while
removing the live leak.

**Hash-chain rewrite**. The chain's value is
detection-of-tampering. Here the "tampering" is the
operator's deliberate purge — same chain-break
signature as a malicious purge would produce. The
documented re-baseline procedure is correct
recovery; it explicitly accepts the loss of the
"verifiable chain back to genesis" property in
exchange for the post-purge clean state. Future
chain verification works from the new baseline
forward.

**Rollback hazard**. v0.50.2 → v0.50.1 reintroduces
the leak (the bad code paths return). Release notes
explicitly warn: do not roll back v0.50.2 in
production. Stage rollbacks in non-production with
synthetic data only.

**Detection of non-compliance**. If an operator
deploys v0.50.2 without running the purge, live
audit rows still contain leaked OTPs (the rows that
were already there). No automated detection of
this — the runbook is the control. Consider
follow-up RFC for an `audit-leak-scan` admin
diagnostic if non-compliance becomes an observed
issue.

**Defense-in-depth note**. The static-grep test is
*compile-time* defense. A *runtime* defense would
add a tiny check in `audit::write_*` that scans the
`reason` argument for the same denylist before
emitting. This is unnecessary today (compile-time
is stronger), but documented as a fallback if the
grep test ever becomes maintenance-burdensome.

## Open questions

**Are there other secret-bearing audit sites?** The
denylist test catches `code=`, `otp=`, `secret=`,
`password=`, `plaintext`, `code_plaintext`. Run the
grep against the v0.50.1 tree before merging the
fix; any additional hits go in the same PR. As of
the reviewer's analysis, the two cited sites are
the only known instances, but the test must catch
new ones.

**Should `MagicLinkRequested` audit also drop the
email address?** Out of scope. `email` is a
contact identifier, not secret material — keep it
for correlation. Re-evaluate only if a future
privacy-focused operator request surfaces.

## Implementation order

1. **PR 1 — Stop the bleed.** Remove plaintext from
   the two audit sites. ~10 LOC. Mergeable in a
   single sitting; ship as soon as reviewed.
2. **PR 2 — Pin the invariant.** Static-grep test +
   audit module documentation update. ~80 LOC.
3. **PR 3 — Rename `code_plaintext` →
   `delivery_payload`.** Coordinate with RFC 010:
   if RFC 010 is landing the same release, fold the
   rename into RFC 010's mailer-payload work.
4. **PR 4 — Runbook.**
   `docs/src/deployment/day-2-runbook.md` section.
5. **PR 5 — CHANGELOG entry under v0.50.2.**

PRs 1, 2, 4, 5 are the minimum to ship; PR 3 lands
adjacent.

## Notes for the implementer

- **Land PR 1 first**, before any other v0.50.2
  work. Until then, every Magic Link issuance grows
  the leak.
- Coordinate tightly with RFC 009 (introspection
  fixes) and RFC 010 (real mailer): all three are
  the v0.50.2 production-blocker sweep, ship as one
  release.
- The static-grep test needs to traverse `crates/`
  not `crates/worker/src` only (RFC 010's
  `cesauth-core::magic_link::mailer` lives in
  `crates/core/`). Default to walking from the
  workspace root.
- If the grep surfaces a third/fourth site that the
  reviewer didn't list, treat as additional fixes
  in PR 1 — don't gate the test introduction on
  exhaustive prior knowledge.
