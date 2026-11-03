# RFC 171 §3 Q1 — the producer census

**What this is.** The deliverable `q1-census-handoff.md` asked for: for every
`PortError` variant a handler matches, can the adapter behind that call
return it? A stage, not a release — no product code changes, no fixes. This
document is the population, the per-method table, the findings (listed, not
repaired), and the number that sizes the next cycle's check.

**Builds on.** `main` at tag `0.92.3` (`5cff52e`). **Method.** Four parallel
sweeps, one per group of nine port traits, each reading every implementation
body (tracing through helper functions rather than guessing from their
names) and every caller in `cesauth-core` and `cesauth-backend` that matches
a specific named `PortError` variant. Cross-checked by hand afterward for one
interpretive question the sweeps disagreed on (§4), and for the handful of
findings that recurred independently across more than one sweep (strong
corroboration, not coincidence).

---

## 1. The population, derived and stated

**The rule**: a port method is any trait method under `crates/core/src`
whose declared return type is `PortResult<T>` (i.e. `Result<T, PortError>`).
Not "a trait the adapters implement" (the handoff's own suggested rule) —
that phrasing turned out to need a judgement call for `TurnstileVerifier`,
whose one implementation lives in `cesauth-backend` itself, not either
adapter crate, per its own doc comment (*"the worker crate implements this
on top of `worker::Fetch`"*). The `PortResult<T>` rule needs no judgement
call: it is Q1's own vocabulary, checked at the signature level, with zero
ambiguous cases.

**38 `pub trait` definitions exist under `crates/core/src`** (confirmed
by `grep -rn "^pub trait " crates/core/src --include='*.rs' | wc -l`, matching
the handoff's own unverified scale-only figure). Every method of every trait
was checked individually, not just whether the file mentions `PortResult`
anywhere:

- **36 traits — every single method returns `PortResult<T>`.** No trait was
  found with a mix of `PortResult` and non-`PortResult` methods.
- **2 traits use an entirely different error vocabulary and are out of
  scope by definition**: `MagicLinkMailer` (1 method, returns
  `Result<DeliveryReceipt, MailerError>`) and `ImportSink` (3 methods,
  return `Result<_, String>`). Neither speaks `PortError` at all — Q1's
  question does not apply to them.

**Population: 36 port traits, 156 port methods.**

| § | Trait group | Traits | Methods |
|---|---|---|---|
| 3.1 | Admin console + `anonymous.rs` + `turnstile.rs` | 9 | 23 |
| 3.2 | Authorization (`authz/ports.rs`) | 3 | 12 |
| 3.3 | Billing (`billing/ports.rs`) | 3 | 9 |
| 3.4 | `deletion.rs`, `invitation.rs` | 2 | 14 |
| 3.5 | `ports/session_index.rs` | 1 | 3 |
| 3.6 | `ports/audit.rs`, `ports/audit_chain.rs`, `ports/cache.rs` | 3 | 11 |
| 3.7 | `ports/repo.rs` (OIDC-era repositories) | 5 | 27 |
| 3.8 | `ports/store.rs` (DO-shaped stores) | 4 | 15 |
| 3.9 | Tenancy (`tenancy/ports.rs`) | 4 | 29 |
| 3.10 | TOTP (`totp/storage.rs`) | 2 | 13 |
| | **Total** | **36** | **156** |

**Reconciliation — owed by RFC 159 §4.5's own discipline and checked here,
not just asserted.** The review of this document's first version could not
reproduce `156 = resolved + DEFECT + no_caller` from the table rows alone
(102 verdict rows summed, not 156 — the remaining methods were covered only
by prose, and one trait's two methods were missing from §3.8 entirely,
folded back in below). Each of §3.1–§3.10 now ends with an explicit subtotal
line; they sum to:

| | Traits | Methods | resolved | DEFECT | no_caller |
|---|---|---|---|---|---|
| §3.1 | 9 | 23 | 4 | 2 | 17 |
| §3.2 | 3 | 12 | 0 | 0 | 12 |
| §3.3 | 3 | 9 | 2 | 3 | 4 |
| §3.4 | 2 | 14 | 2 | 0 | 12 |
| §3.5 | 1 | 3 | 0 | 0 | 3 |
| §3.6 | 3 | 11 | 0 | 0 | 11 |
| §3.7 | 5 | 27 | 5 | 0 | 22 |
| §3.8 | 4 | 15 | 1 | 0 | 14 |
| §3.9 | 4 | 29 | 12 | 0 | 17 |
| §3.10 | 2 | 13 | 1 | 0 | 12 |
| **Total** | **36** | **156** | **27** | **5** | **124** |

`27 + 5 + 124 = 156`. **`unclassified = 0`**, now checkable by a reader who
did not write this document, not just asserted by one who did.

**Implementations.** 34 of the 36 traits have exactly two: one in
`cesauth-adapter-cloudflare` (the production implementation) and one in
`cesauth-adapter-test` (the in-memory double). Two do not, and both are
findings in their own right (§3.6, §3.9).

**Callers.** Checked in both `cesauth-core` (this project's traits are
consumed by static dispatch — generic service functions take
`fn foo<DR: SomeTrait>(repo: &DR, ...)`, per `ports.rs`'s own doc comment)
and `cesauth-backend` (route handlers, some generic, some constructing a
concrete adapter type directly). A caller "matches a variant" when it names
that specific `PortError` variant in a `match`/`if let`/`matches!` — a bare
`?` or a catch-all `Err(_) =>` matches nothing, which is its own valid
category (`no_caller`), not an omission.

**The handoff's own first question, answered directly rather than left to be
assembled from rows.** §2 of the handoff named the `Serialization`
asymmetry as *"the census's first real question, not a bonus"*:
`adapter-cloudflare` produces `Serialization` at roughly 77 call sites
across the population; `adapter-test` produces it at **zero**. Checked
against every row in §3: **it is inert.** The only place in the entire
codebase that names `Serialization` by a specific match arm — not a
catch-all — is `api_v1::auth::port_error_response`'s own `Serialization`
arm (`auth.rs:80`), and that arm maps to the exact same `server_error()`
response its neighboring `Unavailable` arm produces. So the double's
inability to simulate `Serialization` changes no observable behaviour
anywhere this census found a caller for it. This is also why none of the
`DEFECT` findings in §5 are `Serialization`-shaped: the one variant with a
real production/double asymmetry is also the one variant nobody's response
actually distinguishes.

## 2. Classification scheme

Per method, one of:

- **`resolved`** — every variant any caller matches is genuinely producible
  by the production adapter.
- **`DEFECT`** — a caller matches a variant the production adapter cannot
  produce. Two sub-shapes, kept distinct because their severity differs:
  - **written** — the shape RFC 171 §2.1 itself found: a *specific*,
    *written* consequence (an operator sentence, a documented status code,
    an audit event) is tied to exactly that call, and it is unreachable.
  - **chokepoint** — a shared, generic, exhaustive dispatcher (found three
    of these this cycle: `api_v1::auth::port_error_response`,
    `ClientOpError`'s `From<PortError>` conversion, `AuthFailure`'s) treats
    every `PortError` variant as matched for *every* call routed through
    it, with no domain-specific meaning attached to the unreachable arm for
    that particular call. Real by the letter of the rule — RFC 171 §2.1's
    own worked example (`api_v1/memberships.rs` → `api_v1/auth.rs:74`) *is*
    a chokepoint-shaped citation — but lower-consequence than `written`.
- **`no_caller`** — nothing anywhere matches a specific named variant for
  this method. Covers both "nothing matches anything" and "the producer
  makes a variant nothing happens to use" (not split into a fourth bucket;
  neither is a live risk).

`scanned = resolved + DEFECT + no_caller`, **`unclassified = 0`** — every one
of 156 methods landed in exactly one bucket, with a reason recorded in the
per-trait tables below.

## 3. The table, by trait group

### 3.1 Admin console + `anonymous.rs` + `turnstile.rs` (9 traits, 23 methods)

| Trait::method | CF producer | Test producer | Caller match | Class |
|---|---|---|---|---|
| `AdminPrincipalResolver::resolve` | NotFound, Unavailable, Serialization, PreconditionFailed | NotFound, Unavailable | `admin_login.rs:121,178`, `auth.rs:101` via `AuthFailure::from` (`admin/ports.rs:221-232`): NotFound, PreconditionFailed matched by name | resolved (Unavailable/Serialization fall to the same catch-all arm, inert) |
| `::touch_last_used` | Unavailable | — | `let _ =` at both sites | no_caller |
| `UsageMetricsSource::snapshot` | effectively infallible — every internal error is `.unwrap_or_default()`'d away inside the impl itself | Unavailable (mutex poison only) | `mod.rs:107` bare `?`; `:223` `Err(_)=>{}` | no_caller |
| `CostSnapshotRepository::put` | Serialization, Unavailable | Unavailable | `let _ =` ×2 | no_caller |
| `::latest` | Unavailable, Serialization | Unavailable | `.unwrap_or(None)` | no_caller |
| `::recent` | Unavailable, Serialization | Unavailable | **zero callers anywhere** | no_caller — RFC 166 item, not counted here |
| `BucketSafetyRepository::list` | Unavailable, Serialization | Unavailable | `.unwrap_or_default()` ×4 | no_caller |
| `::get` | Unavailable, Serialization | Unavailable | generic `Err(e)→500`, never named | no_caller |
| `::verify` | NotFound, Unavailable | NotFound, Unavailable | `safety.rs:92`: `NotFound→404` | resolved |
| `::apply_change` | NotFound, Unavailable | NotFound, Unavailable | `config.rs` apply/preview: `NotFound→404` | resolved |
| `ThresholdRepository::list` | Unavailable, Serialization | Unavailable | `.unwrap_or_default()` ×4 | no_caller |
| `::get` | Unavailable, Serialization | Unavailable | **zero callers anywhere** | no_caller — RFC 166 item |
| `::update` | NotFound, Unavailable | NotFound, Unavailable | `actions.rs:58`: NotFound matched | resolved |
| `AuditQuerySource::search` | **Unavailable only** — every internal error collapsed via one `map_err` | Unavailable | `?` / `.unwrap_or_default()` / generic `.map_err` at all 5 sites | no_caller |
| `AdminTokenRepository::list` | Unavailable, Serialization, PreconditionFailed | Unavailable | none named | no_caller |
| **`::create`** | **Unavailable only** — `.run()` error goes through `run_err`, **not** `classify_insert_err`, despite `token_hash TEXT NOT NULL UNIQUE` | Unavailable, **Conflict** (explicit dup-hash check) | **`tokens.rs:177`: `Err(PortError::Conflict) =>` renders a friendly "token hash collision — try again" page** | **DEFECT (written)** — unreachable in production; a real collision falls through to `tokens.rs:191`'s generic `500`. The double producing `Conflict` is why a test is green against behaviour production lacks |
| **`::disable`** | **Unavailable only** — `UPDATE … WHERE id=?1 AND disabled_at IS NULL` affects 0 rows on a missing/already-disabled id and `run()` still returns `Ok(())`; no existence check | Unavailable, **NotFound** | **`tokens.rs:262-263`: `Err(PortError::NotFound) => 404 "unknown token"`** | **DEFECT (written), the more serious of the two** — disabling a nonexistent token always takes the `Ok(())` success branch in production: the operator sees success, and **`AdminTokenDisabled` is written to the hash-chained audit log naming that id** — a record of an action that did not happen, the same shape RFC 174 found for `log_level applied` |
| `::create_user_bound` | Unavailable only (same pattern as `create`) | Unavailable, Conflict | `token_mint.rs:165-168`: generic `Err(e)=>500`, does not name `Conflict` | no_caller (not a defect — nothing names a variant — but the identical collision is handled inconsistently from `create`'s sibling path, worth a sentence) |
| `AnonymousSessionRepository::create` | Conflict, NotFound, Unavailable (ad-hoc `msg.contains("UNIQUE"/"PRIMARY KEY"/"FOREIGN KEY")` — see §5.1) | Conflict, Unavailable | generic `Err(e)=>500` | no_caller — but a parity/matcher finding, §5.1 |
| `::find_by_hash` | Unavailable | Unavailable | `Ok/Ok(None)→401`, `Err(_)→500` | no_caller |
| `::revoke_for_user` | Unavailable | Unavailable | `let _ =` | no_caller |
| `::delete_expired` | Unavailable | Unavailable | **zero callers anywhere** | no_caller — and the method's own doc comment (*"Called by the daily sweep handler"*) is **false**: `sweep.rs`'s real anonymous-trial sweep calls `UserRepository::{list_anonymous_expired, delete_by_id}` directly and relies on cascade, never this method. Documented, ungated, same shape as this whole RFC family |
| `TurnstileVerifier::verify` | Unavailable only (`HttpTurnstileVerifier`, implemented in `cesauth-backend` itself — not either adapter crate) | n/a — no `adapter-test` double exists; a local `CannedVerifier`/`FailingVerifier` lives inside `crates/core/src/turnstile.rs`'s own test module | `core::turnstile::verify()` collapses the result via `.map_err(|_| CoreError::Internal)` immediately — no downstream caller can ever see a `PortError` variant | no_caller |

**§3.1 subtotal: 23 methods = 4 resolved + 2 DEFECT + 17 no_caller.**

### 3.2 Authorization (`authz/ports.rs`, 3 traits, 12 methods)

| Trait::method | CF producer | Test producer | Caller match | Class |
|---|---|---|---|---|
| `PermissionRepository::list_all` | Unavailable, Serialization | never errors | — | no_caller |
| `::exists` | Unavailable, Serialization | never errors | — | no_caller |
| `RoleRepository::create` | NotFound, Conflict, Unavailable (`classify_insert_err`) | Conflict | **zero production callers** — every call site is `#[cfg(test)]` or under `authz/tests/`; the adapter's own comment already says so, confirmed independently | no_caller — RFC 166 item, cross-reference confirmed, not RFC 171's own count |
| `::get` | Unavailable, Serialization | — | `.ok()`/`if let Ok` | no_caller |
| `::find_by_slug` | Unavailable, Serialization | — | **zero production callers** (only a `#[cfg(test)]` stub) | no_caller — RFC 166 item |
| `::list_visible_to_tenant` | Unavailable, Serialization | — | `.unwrap_or_default()` | no_caller |
| `::list_system_roles` | Unavailable, Serialization | — | `.unwrap_or_default()` | no_caller |
| `RoleAssignmentRepository::create` | **Unavailable only** — plain `run_err`, despite `id TEXT PRIMARY KEY` (confirmed, `migrations/0016...:210`) | never errors | none named | no_caller — producer-gap finding, §5.2 |
| `::delete` | Unavailable | never errors | none named | no_caller |
| `::list_for_user` | Unavailable, Serialization | never errors | none named | no_caller |
| `::list_in_scope` | Unavailable, Serialization | never errors | none named | no_caller |
| `::purge_expired` | Unavailable | never errors | **zero production callers** (matches its own *"called by a background sweep (future)"* comment) | no_caller — RFC 166 item |

**§3.2 subtotal: 12 methods = 0 resolved + 0 DEFECT + 12 no_caller.**

### 3.3 Billing (`billing/ports.rs`, 3 traits, 9 methods)

| Trait::method | CF producer | Caller match | Class |
|---|---|---|---|
| `PlanRepository::get` | **Unavailable, Serialization only** | routed through `api_v1::port_error_response`/`unwrap_storage` at `subscriptions.rs:71`, `organizations.rs:40`, `groups.rs:52` — the dispatcher names NotFound/Conflict/PreconditionFailed distinctly for every call through it | **DEFECT (chokepoint)** — §4 |
| `::find_by_slug` | Unavailable, Serialization | no confirmed match through the dispatcher or elsewhere | no_caller |
| `::list_active` | Unavailable, Serialization | no confirmed match | no_caller |
| `SubscriptionRepository::create` | NotFound, Conflict, Unavailable (`classify_insert_err`) | **zero production callers** | no_caller — RFC 166 item |
| `::current_for_tenant` | Unavailable, Serialization | routed through the same dispatcher at least once | **DEFECT (chokepoint)** |
| `::set_plan` | Unavailable, **NotFound** (explicit 0-rows check) | routed through the dispatcher; NotFound genuinely producible | resolved |
| `::set_status` | Unavailable, **NotFound** | same | resolved |
| `SubscriptionHistoryRepository::append` | Unavailable only (plain `run_err` on an INSERT) | `.ok()`-discarded everywhere | no_caller |
| `::list_for_subscription` | Unavailable, Serialization | routed through the dispatcher at least once | **DEFECT (chokepoint)** |

**§3.3 subtotal: 9 methods = 2 resolved + 3 DEFECT + 4 no_caller.**

### 3.4 `deletion.rs` / `invitation.rs` (2 traits, 14 methods)

| Trait::method | CF producer | Test producer | Caller match | Class |
|---|---|---|---|---|
| `DeletionRequestRepository::create` | **Conflict** (ad-hoc `contains("UNIQUE")` — §5.1), Unavailable | **never produces Conflict** — silently overwrites a duplicate id | `crates/core/src/deletion.rs:149` (`schedule_deletion`) matches `Conflict` → `CoreError::Conflict` | resolved in production — **parity gap**: the double cannot simulate this branch at all, so the mapping has zero test coverage (the real defense is the pre-check `find_pending_by_user`, well tested; this is an untested TOCTOU backstop) |
| `::find_by_id` | Unavailable | never errors | `.ok().flatten()` / generic | no_caller |
| `::find_pending_by_user` | Unavailable | never errors | generic `500` | no_caller |
| `::list_due` | Unavailable | never errors | `?`-propagated | no_caller |
| `::list_pending_by_tenant` | Unavailable | never errors | `.unwrap_or_default()` | no_caller |
| `::mark_executed` | Unavailable | always `Ok` (no existence check) | generic | no_caller |
| `::mark_cancelled` | Unavailable | always `Ok` (no existence check) | generic | no_caller |
| `InvitationRepository::create` | **Conflict** (ad-hoc `contains("UNIQUE")`), Unavailable | never produces Conflict | `invitation.rs:177` matches `Conflict` → `CoreError::Conflict` | resolved — same parity gap as deletion requests |
| `::find_by_id` | Unavailable | never errors | `.ok().flatten()` | no_caller |
| `::find_pending_by_tenant_email` | Unavailable | never errors | `if let Ok(Some(_))` | no_caller |
| `::mark_accepted` | Unavailable | always `Ok` | generic | no_caller |
| `::mark_revoked` | Unavailable | always `Ok` | generic | no_caller |
| `::list_pending_by_tenant` | Unavailable | never errors | `.unwrap_or_default()` | no_caller |
| `::scrub_email` | Unavailable | always `Ok` | `Err(_)=>Failed` inside `execute_deletion` | no_caller |

**§3.4 subtotal: 14 methods = 2 resolved + 0 DEFECT + 12 no_caller.**

### 3.5 `ports/session_index.rs` (1 trait, 3 methods)

| Method | CF producer | Test producer | Caller match | Class |
|---|---|---|---|---|
| `list_active` | Unavailable, Serialization | **no implementation exists at all** | `run_repair_pass`: generic `.map_err` | no_caller |
| `delete_row` | Unavailable | none | `Err(_)=>errors+=1` | no_caller |
| `mark_revoked` | Unavailable | none | `Err(_)=>errors+=1` | no_caller |

`SessionIndexRepo` has **no `adapter-test` double at all** — one of two traits in the entire population with this shape (§3.9/§3.6). `run_repair_pass`'s own host tests can only exercise a hand-rolled stub local to that test module, never the real adapter's behaviour. Confirmed the `d1_int()` usage in the real adapter is correct (bind-through-f64-cast, no BigInt bug — read directly, not assumed, distinct from the unrelated `session_index_audit.rs` bug fixed in RFC 173's cycle).

**§3.5 subtotal: 3 methods = 0 resolved + 0 DEFECT + 3 no_caller.**

### 3.6 `ports/audit.rs`, `ports/audit_chain.rs`, `ports/cache.rs` (3 traits, 11 methods)

| Trait::method | CF producer | Test producer | Caller match | Class |
|---|---|---|---|---|
| `AuditEventRepository::append` | Unavailable, Conflict (id-dup, literal `sqlite_constraint_unique` substring, not the shared classifier) | not read (moot — no caller matches anything regardless) | `if let Err(_e)` discarded | no_caller |
| `::tail` | Unavailable | — | generic | no_caller |
| `::search` | Unavailable, Serialization | — | catch-all ×2 | no_caller |
| `::fetch_after_seq` | Unavailable, Serialization | — | bare `?` | no_caller |
| `::delete_below_seq` | Unavailable | — | generic | no_caller |
| `AuditChainCheckpointStore::read_checkpoint` | Unavailable, Serialization | Unavailable only | bare `?` / generic | no_caller |
| `::write_checkpoint` | Unavailable, Serialization | Unavailable only | generic | no_caller |
| `::read_last_result` | Unavailable, Serialization | Unavailable only | generic | no_caller |
| `::write_last_result` | Unavailable, Serialization | Unavailable only | generic | no_caller |
| `CacheStore::get` | Unavailable | Unavailable | `matches!(…, Ok(Some(_)))` — folds every `Err` to `false` | no_caller |
| `::put` | Unavailable | Unavailable | `let _ =` | no_caller |

Every method of all three traits is `no_caller` — nothing in the codebase matches a specific variant from any of them. `AuditChainCheckpointStore`: the double never produces `Serialization` for any of its 4 methods (no JSON round-trip); inert today since nothing matches it, same shape as the rest of this family.

**§3.6 subtotal: 11 methods = 0 resolved + 0 DEFECT + 11 no_caller.**

### 3.7 `ports/repo.rs` (5 traits, 27 methods)

| Trait::method | CF producer | Test producer | Caller match | Class |
|---|---|---|---|---|
| `UserRepository::find_by_id` | Unavailable, Serialization | Unavailable | — | no_caller |
| `::find_by_email` | Unavailable, Serialization | Unavailable | — | no_caller |
| `::create` | Unavailable, **Conflict** (`classify_insert_err`, UNIQUE(tenant_id,email)/id PK), **NotFound** (tenant_id FK) | Conflict only (no FK modeled) | **`admin/legacy.rs:94`: `Conflict => "email already in use", 409`** | resolved (Conflict); NotFound producible, unmatched (inert) |
| `::update` | **Unavailable only** — no rows-changed check, *"optimistically assume success"* per its own comment | Conflict: never; **NotFound**: yes | generic `if let Err(e)` | no_caller today — **parity gap**: the double can report `NotFound` for a missing user, production never can for this method |
| `::assign_tenant` | Unavailable, **NotFound** (rows-changed=0 check) | Unavailable, NotFound | `tenancy/service.rs:97`: catch-all `Err(_)=>Failed` | no_caller (NotFound producible, unmatched) |
| `::list_by_tenant` | Unavailable, Serialization | Unavailable | — | no_caller |
| `::list_anonymous_expired` | Unavailable, Serialization | Unavailable | — | no_caller |
| `::delete_by_id` | Unavailable only | Unavailable | — | no_caller |
| `ClientRepository::find` | Unavailable, Serialization | — | app-level `.ok_or(NotFound)`, not via `PortError` | no_caller (for this method's own `PortError`) |
| `::client_secret_hash` | Unavailable, **NotFound** (explicit) | — | not matched via conversion anywhere found | no_caller |
| `::find_auth_view` | Unavailable, Serialization | — | — | no_caller |
| `::create` | Unavailable, Serialization, **Conflict only** (id PK dup; no FK on this table) | Conflict only | `register_client` → `ClientOpError`'s conversion (maps NotFound→Self::NotFound, Conflict→Self::Conflict, else→Internal) → route renders 404/409 | **resolved** for Conflict. NotFound is named by the shared conversion but **structurally unreachable for this specific call** (the conversion's NotFound arm exists for `update`/`set_secret_hash`/`delete`, not for `create`) — a chokepoint artifact with no written promise attached to *this* call, noted rather than counted as a peer `DEFECT` |
| `::list` | Unavailable, Serialization | — | bare `?` | no_caller |
| `::update` | Unavailable, **NotFound** (rows-changed=0) | NotFound | `update_client` pre-checks via `.find()` first — a real TOCTOU race, not dead code | **resolved** |
| `::set_secret_hash` | Unavailable, **NotFound** (rows-changed=0) | not read | `rotate_secret` pre-checks via `.find()`, same reasoning | **resolved** |
| `::delete` | Unavailable, **NotFound** (rows-changed=0 — the normal case for an already-gone id) | NotFound | `delete_client` → conversion → 404 | **resolved** |
| `AuthenticatorRepository::find_by_credential_id` | Unavailable, Serialization | Unavailable | catch-all | no_caller |
| `::list_by_user` | Unavailable, Serialization | Unavailable | **zero production callers** | no_caller — RFC 166 item |
| `::create` | **Unavailable, Serialization only** — plain `run_err`, despite `credential_id TEXT NOT NULL UNIQUE` | **Conflict** on dup credential_id | catch-all `if let Err(e)` | no_caller today — producer-gap finding, §5.2 |
| `::touch` | Unavailable, **PreconditionFailed** (deliberately conflated per its own comment) | Unavailable, NotFound, PreconditionFailed | catch-all | no_caller (PreconditionFailed producible, unmatched) |
| `::delete` | Unavailable only | Unavailable, NotFound | **zero production callers** | no_caller — RFC 166 item |
| `GrantRepository::create` | **Unavailable, Serialization only** — plain `run_err`, despite `id TEXT PRIMARY KEY` | **Conflict** on dup id | catch-all `.map_err` | no_caller today — producer-gap finding, §5.2 |
| `::list_active_for_user` | Unavailable, Serialization | Unavailable | **zero production callers** (`CloudflareGrantRepository` is only constructed to call `.create()`) | no_caller — RFC 166 item |
| `::mark_revoked` | Unavailable only | Unavailable, NotFound | **zero production callers** | no_caller — RFC 166 item |
| `SigningKeyRepository::list_active` | Unavailable, Serialization | Unavailable | catch-all / generic ×3 | no_caller |
| `::register` | **Unavailable only** — plain `run_err`, despite `kid TEXT PRIMARY KEY` | **Conflict** on dup kid | **zero production callers** (keys seeded another way) | no_caller — RFC 166 item, also a producer-gap finding, §5.2 |
| `::retire` | Unavailable only | Unavailable, NotFound | **zero production callers** | no_caller — RFC 166 item |

**§3.7 subtotal: 27 methods = 5 resolved + 0 DEFECT + 22 no_caller.**

### 3.8 `ports/store.rs` (4 traits, 15 methods)

| Trait::method | CF producer | Test producer | Caller match | Class |
|---|---|---|---|---|
| `AuthChallengeStore::create` / `get` / `consume` / `bump_magic_link_attempts` | Unavailable (±Conflict/NotFound/PreconditionFailed per method; full detail not reproduced per-row here — every method's only matched variant, where one exists, is genuinely producible) | matches CF | 1 of 4 resolved (`bump_magic_link_attempts`), 3 `no_caller` | resolved ×1, no_caller ×3 |
| `RefreshTokenFamilyStore::init` / `rotate` / `revoke` / `peek` | `Conflict` (init, id collision), `NotFound` (rotate/revoke, uninitialized family) both genuinely producible | matches CF | **all four methods' call sites use blanket `.map_err(|_| CoreError::Internal)`** — nothing distinguishes `Conflict`/`NotFound` from anything else | no_caller ×4 (producible variants are inert noise; a different *pattern* than the admin-console routes, which do discriminate — this layer discards detail uniformly) |
| `ActiveSessionStore::start` / … (5 methods) | `Conflict` producible on `start`, rest Unavailable-only | matches CF | none named | no_caller ×5 |
| `RateLimitStore::hit` | Unavailable, Serialization (shared `rpc_call`/`rpc_request` JSON-over-DO-fetch helpers) | Unavailable only | every one of 5 call sites (`introspect.rs:516`, `token.rs:295`, `anonymous.rs:113`, `magic_link/request.rs:181`, `magic_link/verify.rs:211`) is catch-all | no_caller |
| `::reset` | Unavailable, Serialization | Unavailable | **zero callers anywhere, not even catch-all** | no_caller — RFC 166 item |

**Found missing from this section on review** (§3's own reconciliation
check, below): `RateLimitStore` is the fourth trait the section header
already counted (`ports/store.rs:494`, same file as the other three) but
whose two rows were absent from the first version of this table —
corrected here, not re-derived; fork 3's original findings already covered
both methods.

**§3.8 subtotal: 15 methods = 1 resolved + 0 DEFECT + 14 no_caller.**

### 3.9 Tenancy (`tenancy/ports.rs`, 4 traits, 29 methods)

| Trait::method | CF producer | Test producer | Caller match | Class |
|---|---|---|---|---|
| `TenantRepository` (6 methods) | — | — | 1 resolved (`set_status`, via `port_error_response` where NotFound is genuinely producible) | resolved ×1, no_caller ×5 |
| `OrganizationRepository` (6) | — | — | 2 resolved (`set_status`, `update_display_name`, via the dispatcher, both producible) | resolved ×2, no_caller ×4 |
| `GroupRepository` (5) | — | — | 3 resolved (`create` ×3 caller forms, `delete` via `api_v1`) | resolved ×3, no_caller ×2 |
| **`MembershipRepository`** (12 — the largest trait in the census; the one RFC 171 §2.1/§2.2 is centrally about) | — | — | **6 resolved**: the three `add_{tenant,organization,group}_membership` methods, each with 3 real callers (two HTML-form admin surfaces + the shared service wrapper), **now correctly matching both `Conflict` and `NotFound`** — cycle 2b's `classify_insert_err` fix (composite-PK + FK cases) closed RFC 171's own ten-paths finding for this trait. `magic_link/verify.rs:461`'s idempotency arm (`Ok(()) | Err(Conflict) => {}`) is likewise now correctly resolved. | resolved ×6, no_caller ×6 |

**RFC 171 §2.1/§2.2's own findings, reconfirmed as closed in the current tree** — the ten paths and the production/double disagreement over `Conflict` vs `Unavailable` for duplicate memberships are both fixed (RFC 141 cycle 2b). What is **not** closed, and corrects the RFC's own citation: `crates/core/src/tenancy/service.rs`'s three thin wrapper functions (`add_user_to_tenant`/`add_user_to_organization`/`add_user_to_group`, the ones whose doc comment RFC 171 §2.1 quotes as *"the documentation is false"*) have **zero production callers at all** — every route handler calls `CloudflareMembershipRepository` directly, bypassing them. The documentation claim is still false, but the function it's attached to is also simply never run in production — an RFC 166 item layered on top of the RFC 171 one, not previously noted.

**§3.9 subtotal: 29 methods = 1 (Tenant) + 2 (Organization) + 3 (Group) + 6
(Membership) = 12 resolved + 0 DEFECT + 5+4+2+6 = 17 no_caller.**

### 3.10 TOTP (`totp/storage.rs`, 2 traits, 13 methods)

| Trait::method | CF producer | Test producer | Caller match | Class |
|---|---|---|---|---|
| `TotpAuthenticatorRepository::create` | **Unavailable, Serialization only** — plain `run_err`, despite `id TEXT PRIMARY KEY` (`migrations/0007...`). Doc comment at `totp/storage.rs:72-74`: *"Returns `Conflict` if the id is already taken… the adapter must honor the PRIMARY KEY"* — **false of the real adapter today** | **Conflict**, correctly | `enroll.rs:139`: `if totp_repo.create(&row).await.is_err()` — a boolean check, **not** a match on `Conflict` | no_caller today — but the clearest "loaded gun" in the census: anyone who trusts the doc comment and later writes `Err(Conflict) => …` gets RFC 171's own failure mode instantly. `TotpRecoveryCodeRepository::bulk_create`, same table family, does this correctly via `classify_insert_err` — parity holds there |
| `::confirm` | — | — | 1 resolved call site | resolved |
| (5 other methods — `find`, `find_all_for_user`, `delete_all_for_user`, and two more) | — | — | none named | no_caller ×5 |
| `::delete` (single-row) | — | — | **zero production callers** (only `delete_all_for_user` is used) | no_caller — RFC 166 item |
| `TotpRecoveryCodeRepository` (5 methods) | — | — | none named anywhere | no_caller ×5 |

Test-only, one-off failure-injection stubs exist locally inside
`crates/backend/src/routes/me/totp/{disable,verify,enroll,recover}/tests.rs`
(`FailingAuthRepo`, `FailingFindRepo`, `FailingCreateRepo`, `FailingLookupRepo`,
`RaceLossRepo`, `FailingRecoveryRepo`) — scaffolding for specific host tests,
not the real `adapter-test` double, not counted as producers.

**§3.10 subtotal: 13 methods (8 + 5) = 1 resolved + 0 DEFECT + 12 no_caller**
— corrected from an earlier count of 9 rows against an 8-method trait: `::delete`
is one of the "other methods," not an additional one; this version lists 5
others, not 6.

## 4. The interpretive question the sweeps disagreed on, resolved

Two of the four sweeps independently found the same shared dispatcher
(`api_v1::auth::port_error_response`, also reached via `quota.rs`'s
`unwrap_storage`) and drew opposite conclusions: one treated every call
routed through it as "no defect possible, by construction" (since it
matches all five variants); the other treated it as "matches everything,
so an unproducible variant behind it is technically a defect" and declined
to classify it without a ruling.

**Resolved against RFC 171's own text, not by preference.** §2.1's own
worked example cites `api_v1/memberships.rs:49 → Conflict → 409 via
api_v1/auth.rs:74` as the caller-match for one of the RFC's ten canonical
defects — `api_v1/auth.rs:74` *is* this dispatcher. The RFC's own
methodology already treats routing through it as a real caller match. So:
**confirmed as a caller match, but reported as its own sub-category
(`DEFECT (chokepoint)`, §2) distinct from the `written` shape**, because
unlike the ten paths, no specific operator sentence or documented contract
is broken when the unreachable arm here is `Unavailable`/`Serialization`
(both already collapse to the same generic 500 the arm's absence would
produce) and — for `NotFound`/`Conflict`/`PreconditionFailed` specifically
— the three confirmed instances (§3.3) have no domain-specific consequence
tied to *that* call; the dispatcher's wrong-but-silent arm is simply never
reached.

**Not exhaustively traced.** `port_error_response`/`unwrap_storage` appear
at roughly 50 call sites across seven files
(`role_assignments.rs`, `organizations.rs`, `quota.rs`, `subscriptions.rs`,
`memberships.rs`, `tenants.rs`, `groups.rs`). Three concrete instances are
confirmed (§3.3); the rest were not individually traced back to their
specific port method's producible set — named here as a scoping gap with a
reason, not a silent omission, and folded into §6's sizing recommendation
rather than guessed at.

## 5. Findings, separated from the census (RFC 171 §4's own trap, not fallen into)

Nothing below was fixed. Each is its own sizing decision for whoever picks
it up next.

### 5.1 Three "ad-hoc matcher" instances — RFC 171 §2.4's lesson, recurring

`AnonymousSessionRepository::create`, `DeletionRequestRepository::create`,
and `InvitationRepository::create` each classify a duplicate-key failure
with an inline `msg.contains("UNIQUE"/...)` string check instead of the
shared, SQLite-extended-code-based `classify_insert_err`/
`classify_insert_message` (the helper RFC 160/171 themselves built and
enumerated across all 12 SQLite constraint classes). All three happen to
work correctly *today*, because D1's message text reads *"UNIQUE constraint
failed"* for both `SQLITE_CONSTRAINT_UNIQUE` and `SQLITE_CONSTRAINT_PRIMARYKEY`
on these particular tables — but it is exactly the "trust the prose, not the
enumerated vocabulary" shape RFC 171 §2.4 names as the general lesson, and
the in-memory double cannot simulate the branch at all for `deletion.rs`/
`invitation.rs` (silent overwrite instead), so these two call paths have
zero test coverage through their double.

### 5.2 Four "classifier never adopted" instances — the inverse gap

`RoleAssignmentRepository::create`, `AuthenticatorRepository::create`,
`GrantRepository::create`, `SigningKeyRepository::register` each sit behind
a real, verified `UNIQUE`/`PRIMARY KEY` constraint
(`role_assignments.id`, `authenticators.credential_id`, `grants.id`,
`jwt_signing_keys.kid` — schema confirmed, not assumed) and each uses the
plain `run_err` helper, which always reports `Unavailable`. Every one of
their `adapter-test` doubles correctly produces `Conflict` for the same
case. **None is a live defect** — no caller currently matches `Conflict`
for any of the four — but each is the identical "loaded gun" RFC 171 §2.2
describes: a test double whose documented behaviour production does not
have, waiting for the first caller written against the double's contract
rather than the adapter's.

Combined with §5.1, **seven of the thirty-six production `.create()`-shaped
methods this census covers have a real key constraint behind them and do
not route through the shared classifier correctly** — three via a weaker
ad-hoc check, four not routed through any classifier at all. Found
independently by three of the four sweeps without coordination.

### 5.3 The two live `written`-shape defects (§3.1)

`AdminTokenRepository::create` (a dead "token hash collision" friendly
message) and `AdminTokenRepository::disable` (a false success *and* a false
`AdminTokenDisabled` audit-log entry for a disable that never happened) —
both reproduce RFC 171's own headline shape independently, in a trait the
RFC's own text never looked at. `disable` is the more serious: it writes
into the hash-chained ledger, the exact consequence class RFC 174 named for
`log_level applied`.

### 5.4 Three `chokepoint`-shape defects, confirmed (§3.3, §4)

`PlanRepository::get`, `SubscriptionRepository::current_for_tenant`,
`SubscriptionHistoryRepository::list_for_subscription` — each routed
through `port_error_response`/`unwrap_storage`, each only producing
`{Unavailable, Serialization}`. Likely not the full set; see §4's own
scoping note.

### 5.5 Three structural absences, distinct from any DEFECT

- **`SessionIndexRepo` has no `adapter-test` double at all** (§3.5) — not a
  disagreement, an absence. Nothing host-tests this adapter's real D1 error
  paths.
- **`TurnstileVerifier` has no `adapter-test` double either** (§3.1) — its
  one implementation lives in `cesauth-backend`, and its own test double is
  a local `#[cfg(test)]` stub inside `crates/core/src/turnstile.rs`, not
  `cesauth-adapter-test`.
- **`AnonymousSessionRepository::delete_expired`'s doc comment is false**
  (§3.1) — claims to be called by the daily sweep; it is not.

### 5.6 RFC 166 items, cross-referenced and explicitly *not* counted in Q1's own tally

Zero-production-caller methods found incidentally while tracing callers
(this is the opposite question — RFC 166 §3's, not RFC 171's — and §2.3
of the governing RFC says explicitly not to conflate them):
`CostSnapshotRepository::recent`, `ThresholdRepository::get`,
`RoleRepository::{create, find_by_slug}` (the first already named by RFC 171
§5 and reconfirmed here), `RoleAssignmentRepository::purge_expired`,
`SubscriptionRepository::create`, `AuthenticatorRepository::{list_by_user,
delete}`, `GrantRepository::{list_active_for_user, mark_revoked}`,
`SigningKeyRepository::{register, retire}`, `RateLimitStore::reset`,
`PermissionRepository` (both methods — the whole trait), `TotpAuthenticatorRepository::delete`
(single-row form), and `cesauth_core::tenancy::service::{add_user_to_tenant,
add_user_to_organization, add_user_to_group}` (the three functions RFC 171
§2.1 itself quotes — now additionally found to have no production caller at
all, on top of the documentation being false). **Not RFC 171's deliverable**;
recorded here because the same read that found them would otherwise lose
them, for whoever eventually runs RFC 166 §3's actual census.

## 6. The number that sizes the check

**Out of 156 methods: 2 live `written`-shape defects, 3 confirmed
`chokepoint`-shape defects (with an unresolved residual — §4), 7 producer-side
matcher/classifier gaps that are inert only because nothing yet calls them
the way their double would suggest, 2 structural test-double absences, and
roughly 20 RFC 166-shaped zero-caller methods found along the way.
`unclassified = 0`.**

**The check is per method, the same unit this census used — not per variant,
not per crate.** A per-variant check would conflate `AdminTokenRepository::
create`'s dead `Conflict` arm with `SigningKeyRepository::register`'s
(different method, different severity, same variant). A per-crate check
would miss that the defect lives at the intersection of one specific method's
producer and one specific call site's matcher, which is exactly where every
finding above was found. The shape, concretely:

1. **A literal grep for named-variant match arms**, the same as this
   census's manual sweep, but it must also recognize the **dispatcher
   registry** this cycle found by hand — `port_error_response`/
   `unwrap_storage`, `ClientOpError`'s `From<PortError>`, `AuthFailure`'s —
   as "matches every variant it names," the same way E6's
   `e6_mechanism_check` already carries a named table of shared mechanisms
   rather than re-deriving each route's control from scratch. Missing this
   registry is precisely how a name-grep under-reports: two of this
   census's four sweeps initially treated chokepoint-routed calls as having
   "no named match" until the dispatcher itself was recognized.
2. **A producer registry, same shape, the other direction**: `run_err`
   (always `Unavailable`), `classify_insert_err`/`classify_insert_message`
   (the 12-code SQLite census), and the ad-hoc `contains("UNIQUE")` sites
   named in §5.1, each resolved to its actual producible set rather than
   guessed from the call site's own text — exactly how this census avoided
   guessing, by reading every helper's definition.
3. **Fail when a method's caller-matched set is not a subset of its
   production-adapter's producible set.** That is the check; everything
   above is its first, hand-run pass.

**This is RFC 170-shaped, not RFC 166-shaped**: it reads source only, needs
no credential and no migrated D1 — it can run today, on every push, without
waiting on anything. Q2 (parity between the double and the real adapter) is
a separate, later check over the same table, and still needs RFC 170's
credentialed job to assert the D1 side for real — distinct from this one,
as the governing RFC's own §3 already says.
