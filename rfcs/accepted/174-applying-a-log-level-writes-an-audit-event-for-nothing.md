# RFC 174 — Applying a log level writes an audit event for something that cannot happen

**Status.** **Accepted** 2026-11-03 by the owner (*"RFC 174 is accepted."*).
Proposed the same day by the architect, found reviewing RFC 173 by sweeping the
class that RFC's own fix belonged to.

**Scheduled in two parts, because §3's question is not settled by the
acceptance.** **The false ledger entry is dispatched now** — patch, the next cut
after 0.92.2 — because it is true under both of §3's answers and it is the live
defect. **§3's (a)-or-(b) choice is put to the owner**, because (b) removes an
operator affordance and (a) adds a capability that has never existed, which is a
**minor**: an acceptance cannot be read as picking either one without saying so,
and the architect's recommendation in §3 is a recommendation.

**Said plainly so the record does not quietly assume the larger reading**
(the same note RFC 170's own acceptance carries): if the owner meant the whole
of §3 including its recommendation, that is **(b)** and the route goes — say so
and it goes in the same cut.

**Sibling links.** `rfcs/accepted/173-…` and `rfcs/accepted/161-…` are reached
from here as siblings now that this file has moved.
**Tier.** **P1.** `POST /admin/console/config/log_level/apply` writes nothing,
could not take effect if it did, and then **writes a hash-chained audit event
saying it was applied.** The operator is told it worked, the project's record of
truth says it worked, and the log level cannot be changed at runtime at all.
**Not an exposure.** Nothing is newly reachable and no control is weakened — the
HMAC'd preview-token binding in front of this action is real and was validated
in RFC 152 half C. **The control is real; the action behind it is not.**
**Size.** **Small**, once the question in §3 is answered. The question is the
work.
**Touches.** `crates/backend/src/routes/admin/console/config.rs`, and then
either `wrangler.toml` + `crates/backend/src/log.rs` or the route and its docs —
§3 is the choice. Plus `scripts/` for §4's gate.
**Found by.** The architect, 2026-11-03. The dev team fixed one undeclared KV
binding in RFC 173's cycle; sweeping for the rest of that class found this one.
**One fixed binding is not the fixed class.**
**Relates to.** [RFC 173](173-the-session-index-audit-has-never-read-a-row.md)
(the sibling instance, and the cycle that exposed the family),
[RFC 161](161-six-operator-pages-promise-data-and-render-none.md)
(operator surfaces that promise and do not deliver),
[RFC 171](171-the-arm-is-written-and-the-error-is-never-produced.md)
(a success nothing earns).

**On 1.0:** not declared, not scoped, not dated.

---

## 1. What happens today

`config.rs:459-473`, after the preview token verifies:

```rust
// KV binding: CONFIG_KV (must be declared in wrangler.toml).
if let Ok(kv) = ctx.env.kv("CONFIG_KV") {
    if let Ok(builder) = kv.put("log_level", new_level) { let _ = builder.execute().await; }
}

audit::write_owned(&ctx.env, EventKind::OperationApplied, …,
    Some(format!("log_level applied: {} -> {}", payload.before, payload.after))).await.ok();
```

**Three independent failures, stacked:**

1. **`CONFIG_KV` is not declared.** `wrangler.toml` declares exactly one KV
   namespace, `binding = "CACHE"`. A KV namespace can only come from the config
   file — unlike a secret (`wrangler secret put`) or a var (optional, with a
   default). So `env.kv("CONFIG_KV")` always returns `Err`, and `if let Ok`
   skips in silence. **The comment on the line above states the requirement that
   was never met.**
2. **Nothing would read it.** `LogConfig::from_env` (`log.rs:155-163`) reads
   `env.var("LOG_LEVEL")` and `env.var("LOG_EMIT_SENSITIVE")` — **it never
   touches KV.** The code comment's premise, *"we store a KV value that
   `LogConfig::from_env` will prefer on next request"*, is false independently
   of (1).
3. **The audit event is written anyway**, unconditionally, saying
   `log_level applied: info -> debug`.

So the operator sees a success redirect, the audit log carries an
`OperationApplied` row asserting the change, and **the log level is a
deploy-time variable that nothing at runtime can move.**

## 2. Why (3) is the part that makes this P1

This project's audit chain is hash-linked and treated as the record of truth:
it is what RFC 147's sweep is asserted against, what RFC 170's new job reads,
and what a reviewer used this very week to prove an idempotency arm had fired.
**An `OperationApplied` row that asserts an operation which did not occur is a
false entry in that record**, and it is indistinguishable from a true one.

Nothing else in this family writes an audit event. RFC 173's two instances
reported success to a *status surface*; this one writes it into the *ledger*.

## 3. Direction — the question is what the feature is

**Not decidable from the code, which is why this is an RFC and not a fix.**

- **(a) Make it real.** Declare the KV namespace and make `LogConfig::from_env`
  prefer the stored value. This is what every comment in the file already
  claims, and it gives operators a runtime log-level control — genuinely useful
  during an incident, which is what the `/admin/console/config` page is for.
  **It is also new capability**: a runtime override that has never existed, on a
  per-request KV read in the hot path, which wants a cache and a TTL decision.
  **That makes it a minor, not a patch.**
- **(b) Say what is true.** Remove the apply action (keep the preview, or remove
  both), and document the log level as deploy-time only. Smaller, honest, and it
  deletes an operator affordance someone may be relying on believing in.

**Either way, and before either**: the audit event must not claim an action that
did not happen. If (a), write it only after a confirmed `execute()`. If (b), it
goes with the route. **That part is a patch and should not wait for the rest** —
a false ledger entry is the live defect; the missing feature is a gap.

**The architect's recommendation: (b), then (a) only if an operator asks.** The
page's value is visibility, this project has never had a runtime log-level
override, and inventing one to justify an audit line that should not have been
written is the wrong order. But this is the owner's call, not mine — it removes
something from an operator console.

## 4. The gate, and a census that had to be narrowed before it was worth having

**`env.kv`, `env.d1`, `env.bucket` and `env.durable_object` can only name a
binding declared in `wrangler.toml`.** There is no `wrangler secret put` for a
namespace and no default to fall back on, so a name that is not declared is
always a runtime error — and every call site in this workspace swallows it.

Censused:

| binding | kind | declared |
|---|---|---|
| `DB` | `env.d1` | yes |
| `CACHE` | `env.kv` | yes |
| **`CONFIG_KV`** | `env.kv` | **no** |

Plus `CESAUTH_KV`, the same shape, fixed in RFC 173's cycle. **Two of four
config-only binding names in this codebase have been wrong, and neither failed
anything.**

**The first version of this census was wrong and is worth recording as such.**
Run naively over every `env.*("NAME")` call, it reported **fourteen**
undeclared names — and all but one were correct code: `env.secret(…)`'s five
names come from `wrangler secret put` and must not be in the file, and
`env.var(…)`'s are optional by design, each read as
`.ok().and_then(…).unwrap_or(default)` (checked at
`audit_retention_cron.rs:82-84`, `session_index_repair_cron.rs:93-95`,
`safety_controls.rs:17-18`). **A gate over that set would have been thirteen
false positives and one finding.** The class is narrow or it is noise.

**Not folded into the fix.** The gate belongs with RFC 171's family — *does the
code reach the thing it names?* — and a P1 whose repair is a few lines should
not wait on it.

## 5. The family, named because it is now four

One review surfaced four instances of *a capability that reports success without
doing anything*:

1. `session_index_audit` — dead since 2026-05-06, error path returns `Ok`
   (RFC 173).
2. `cron_status::record_cron_pass` — never persisted for any of six cron passes,
   discarded by `let _ =` (RFC 173's cycle).
3. **This one** — writes nothing, could not take effect, and records that it
   did.
4. `operations_route.rs`'s `CronRecord` — a deserializer for cron records that
   is never constructed, so even now that the records persist, nothing displays
   them (flagged by the dev team, unscoped).

**Whether that is one RFC or four is a scoping question for the owner.** They
share a shape and not a cause: a swallowed `Err`, a wrong string, an unmet
precondition, and an unbuilt reader. §4's gate catches (2) and (3)'s *cause* and
neither of the others.
