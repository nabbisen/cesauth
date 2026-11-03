# RFC 175 — Disabling an admin token reports success without checking, and audits it

**Status.** **Accepted** 2026-11-04, dispatched immediately. Proposed the
same day by the architect, from RFC 171 §3 Q1's census.
**Tier.** **P1.** `POST /admin/console/tokens/:id/disable` returns success for an
id that does not exist or is already disabled, and writes
**`AdminTokenDisabled` to the hash-chained audit log** for an action that did
not happen — on the credential surface. **Bounded**: no live token stays valid
while the operator is told otherwise (§2), so this is an integrity defect in the
record, not an exposure.
**Size.** **Small.** One `meta().changes()` check in the adapter, and the dead
arm that is already written for it starts working.
**Touches.** `crates/adapter-cloudflare/src/admin/tokens.rs`, tests. **No
migration, no schema change, no caller change** — the handler's
`Err(PortError::NotFound) => 404 "unknown token"` arm already exists.
**Found by.** RFC 171 §3 Q1's producer census, 2026-11-04 — **in a trait the
RFC never examined**, which is the census earning its cost on first use.
**Relates to.** [RFC 171](../accepted/171-the-arm-is-written-and-the-error-is-never-produced.md)
(this is its worked shape, reproduced independently),
[RFC 174](../accepted/174-applying-a-log-level-writes-an-audit-event-for-nothing.md)
(the same false-ledger shape, there unreachable, here reachable),
[RFC 160](../done/160-every-constraint-failure-is-a-conflict.md) (§3's sibling
defect is its unadopted classifier again).

**On 1.0:** not declared, not scoped, not dated.

---

## 1. What happens

`crates/adapter-cloudflare/src/admin/tokens.rs:87-97`:

```rust
async fn disable(&self, id: &str, now_unix: i64) -> PortResult<()> {
    db.prepare("UPDATE admin_tokens SET disabled_at = ?2 \
                WHERE id = ?1 AND disabled_at IS NULL")
        .bind(…)? .run().await.map_err(…)?;
    Ok(())                       // <- never asks whether a row matched
}
```

D1's `run()` succeeds on zero rows affected. So `Ok(())` is returned whether or
not anything was disabled, and `routes/admin/console/tokens.rs:248-263` does:

```rust
Ok(()) => { audit::write_owned(… EventKind::AdminTokenDisabled, Some(id), … ) …
            json {"ok": true} / 303 to the token list }
Err(PortError::NotFound) => Response::error("unknown token", 404),   // cannot fire
```

**The `NotFound` arm is already written and cannot be reached**, because the
only implementation never produces it. That is RFC 171 §1 verbatim, in a trait
RFC 171 did not look at.

## 2. Severity, bounded honestly

The `UPDATE` matches zero rows in exactly two cases: **the id does not exist**,
or **it is already disabled**. In neither does a *live* token remain live while
the operator believes it was revoked — so **no credential outlives the
operator's belief about it**, and this is not an exposure.

What is lost is the audit chain's truthfulness on the credential surface: a row
asserting that an admin token was disabled, indistinguishable from the rows
where one actually was.

**Reachability is real but not constant.** `list` filters
`WHERE disabled_at IS NULL`, so the console does not offer disable for an
already-disabled token. The reachable path is a **stale page** — the list opened
before the token was disabled in another tab or by another operator — and a
typo'd or stale id in a direct request. Routine, not constant.

## 3. The sibling the census found with it, and it is smaller

`AdminTokenRepository::create` maps its INSERT failure with plain `run_err`,
never `classify_insert_err`, even though `admin_tokens.token_hash` is
`TEXT NOT NULL UNIQUE` (`migrations/0002_admin_console.sql:40`). So the
handler's `Err(PortError::Conflict)` arm — *"token hash collision — please try
again"* — is also dead.

**Harmless in practice**: the plaintext is 256-bit, so the collision will not
occur, and the cost of the dead arm is a 500 instead of a retry page on an event
that will not happen. **Fix it with §4 anyway**, because it is one call-site
swap and leaving a known-dead arm in place is how the next reader learns the
wrong lesson.

**And the arm is the architect's own.** Its comment reads *"A fourth re-render
path the handoff's own enumeration of three did not name"* — written after the
architect found the fourth path in an earlier cycle and had the arm built. **It
was dead on arrival**: a correct-looking arm added to a producer that cannot
produce it, by the person who later wrote the RFC about exactly that. Recorded
because it is the most direct instance of RFC 171's thesis in the whole census.

## 4. Direction

1. **`disable` asks whether a row matched.** D1's `run()` returns a result whose
   `meta()` carries `changes`; zero changes must become
   `Err(PortError::NotFound)`. The handler's arm then works as written. **Check
   the field's actual name and availability in the pinned `worker` crate before
   building on it** — do not assume `changes` from this text.
2. **`create` uses `classify_insert_err`**, the same one-call-site swap RFC 141
   cycle 2b made for `oidc_clients`. `token_hash`'s `UNIQUE` is real, so
   `SQLITE_CONSTRAINT_UNIQUE` is the class — **not** `PRIMARYKEY`, since
   `admin_tokens.id` is a separate `TEXT PRIMARY KEY` and a duplicate *id* is a
   server-minted UUID collision. Both are `Conflict` after RFC 160 §4.11, so one
   arm covers it.
3. **A witness for `disable`, both halves** (the standing rule): disabling a
   real live token still answers success **and** actually sets `disabled_at`;
   disabling a nonexistent id answers **404 `unknown token`** and writes **no**
   `AdminTokenDisabled` row. The second half is the defect; the first is what a
   fix that rejects everything would fail.
4. **Confirm no `AdminTokenDisabled` row is written on the 404 path** by
   querying `audit_events`, not by reading the handler. The whole finding is
   that the response and the ledger agreed with each other and not with reality.

## 5. What this does not cover

- **The other five classifier-adoption gaps** RFC 171's census found
  (`RoleAssignmentRepository`, `AuthenticatorRepository`,
  `GrantRepository::create`, `SigningKeyRepository::register`, and the three
  ad-hoc `contains("UNIQUE")` sites). **None is a live defect** — nothing
  matches `Conflict` for any of them — but each is a double whose documented
  behaviour production lacks. They belong to RFC 171's own follow-up, not here.
- **The check.** RFC 171 §3 Q1's census sized it; building it is its own
  dispatch, and a P1 whose repair is two call sites should not wait for it.
