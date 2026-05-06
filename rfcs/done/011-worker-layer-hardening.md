# RFC 011: Worker-layer hardening — CSRF RNG, env validation, duplicate routes, duplicate ADR file

**Status**: Implemented (v0.50.3)
**ROADMAP**: External codebase review v0.50.1 — P1 + P2 worker hardening
**ADR**: N/A (each item is small enough to settle inline)
**Severity**: **P1 + P2 — ship in the next release after the v0.50.2 production-blocker sweep, or ride along if PR review bandwidth allows**
**Estimated scope**: Small — ~80 LOC across `csrf.rs`, `config.rs`, `lib.rs`; no schema or wire change; ~12 new tests
**Source**: External Rust+Cloudflare codebase review attached to v0.50.1 conversation.

## Background

Four worker-layer / repo defects don't individually
rise to P0 but each represents a real failure mode
worth closing. Bundled because they share the
"worker hardening + repo cleanup" theme and each
fix is mechanical.

1. **CSRF token RNG failure swallowed**
   (`crates/worker/src/csrf.rs:52-55`):

   ```rust
   pub fn mint() -> String {
       let mut buf = [0u8; 24];
       let _ = getrandom(&mut buf);    // ← discards Result
       URL_SAFE_NO_PAD.encode(buf)
   }
   ```

   On `getrandom` failure, `buf` stays zeroed,
   `mint()` returns the constant base64 of 24 zero
   bytes. A predictable token an attacker could
   forge.

2. **Negative env values become huge u32**
   (`crates/worker/src/config.rs:126,134`):

   ```rust
   refresh_rate_limit_threshold:
       var_parsed_default("REFRESH_RATE_LIMIT_THRESHOLD", 5)? as u32,
   ```

   The intermediate parsed value is `i64`. An
   operator setting `REFRESH_RATE_LIMIT_THRESHOLD=-1`
   gets `4_294_967_295` after the `as u32` wrap.
   The rate limit is effectively disabled
   silently. Same pattern affects
   `INTROSPECTION_RATE_LIMIT_THRESHOLD`.

3. **Duplicate route registrations**
   (`crates/worker/src/lib.rs:161-168` and
   `:193-200`):

   ```rust
   // First block (161-168)
   .get_async ("/me/security/sessions",            ...)
   .post_async("/me/security/sessions/revoke-others", ...)
   .post_async("/me/security/sessions/:session_id/revoke", ...)
   // ... TOTP routes between ...
   // Second block (193-200) — DUPLICATES of first
   .get_async ("/me/security/sessions",            ...)
   .post_async("/me/security/sessions/revoke-others", ...)
   .post_async("/me/security/sessions/:session_id/revoke", ...)
   ```

   The second block is merge-conflict residue from
   v0.35.0; the first block was added in a later
   edit and the older one was never deleted.
   workers-rs router behavior on duplicate
   `(method, path)` tuples is "last wins" — the
   handlers are identical so production behavior is
   correct today, but a future "fix" applied to one
   block leaves the other block to be served. Real
   regression hazard.

4. **Duplicate ADR-012 file**:
   `docs/src/expert/adr/012-session-hardening.md`
   (older v0.35.0 draft) and
   `docs/src/expert/adr/012-sessions.md` (canonical,
   referenced by all v0.40+ resolutions §Q1 / §Q1.5
   / §Q4) both exist with overlapping content and
   slightly different §Q numbering. Future
   "ADR-012 §Q3" references are ambiguous.

## Requirements

1. `csrf::mint()` MUST return `Result<String, _>`
   surfacing RNG failure. Callers MUST fail-closed
   on `Err` (HTTP 500 with generic error page;
   audited).
2. Configuration parsing of bounded integer fields
   MUST reject negative values and out-of-range
   values at startup with a clear error message.
3. Route registration MUST be deduplicated; a
   uniqueness check MUST run in CI.
4. `docs/src/expert/adr/012-session-hardening.md`
   MUST be marked **Superseded by 012-sessions.md**
   with body preserved for history.

## Design

### Issue 1 — CSRF RNG failure handling

**Replacement** (`crates/worker/src/csrf.rs`):

```rust
/// Mint a fresh CSRF token. 24 bytes of CSPRNG
/// base64url-encoded. Returns `Err` if the
/// platform CSPRNG fails.
pub fn mint() -> Result<String, getrandom::Error> {
    let mut buf = [0u8; 24];
    getrandom(&mut buf)?;
    Ok(URL_SAFE_NO_PAD.encode(buf))
}
```

**Caller updates**: every `csrf::mint()` site
becomes `csrf::mint()?` with a graceful 500
fallback. Callers in form-render paths render a
generic "service temporarily unavailable" page
(no CSRF token in the response means no
state-changing form would work anyway). Audit the
event for operator visibility.

**New audit kind**:

```rust
EventKind::CsrfRngFailure
```

Snake-case: `csrf_rng_failure`. Payload fields:
the route path that triggered it (operator can
correlate against worker version, CF colo, time
of day).

**Why HTTP 500, not graceful "form without CSRF"**:
silently rendering a form with `[0; 24]` CSRF
token would let submitted forms bypass CSRF (since
the cookie is also `[0; 24]`, the double-submit
check passes trivially). Failing loudly is the
only safe option.

In practice `getrandom` on Cloudflare Workers'
WASM target reliably succeeds via
`crypto.getRandomValues` — this fix is
defense-in-depth against a runtime regression that
would otherwise be silent.

### Issue 2 — Config integer validation

**New helper** in `crates/worker/src/config.rs`:

```rust
/// Parse a `u32` env var with bounds. Rejects
/// negative inputs (which would silently wrap to
/// huge values via `as u32`) and out-of-range
/// inputs. Empty / missing returns `default`.
fn var_parsed_u32_bounded(
    env: &Env,
    name: &str,
    default: u32,
    max:    u32,
) -> Result<u32, worker::Error> {
    let raw_str = match env.var(name) {
        Ok(v) => v.to_string(),
        Err(_) => return Ok(default),
    };
    if raw_str.is_empty() {
        return Ok(default);
    }
    let raw: i64 = raw_str.parse().map_err(|_| {
        worker::Error::RustError(format!(
            "{name} must be an integer (got {raw_str:?})"
        ))
    })?;
    if raw < 0 {
        return Err(worker::Error::RustError(format!(
            "{name} must be non-negative (got {raw})"
        )));
    }
    if raw > max as i64 {
        return Err(worker::Error::RustError(format!(
            "{name} exceeds bound {max} (got {raw})"
        )));
    }
    Ok(raw as u32)
}
```

**Bounded fields**:

| Env var | Default | Bound | Reasoning |
|---|---|---|---|
| `REFRESH_RATE_LIMIT_THRESHOLD` | 5 | 1_000_000 | Beyond → operator typo |
| `REFRESH_RATE_LIMIT_WINDOW_SECS` | 60 | 86_400 (1 day) | Longer window → unbounded family bookkeeping |
| `INTROSPECTION_RATE_LIMIT_THRESHOLD` | 600 | 1_000_000 | Same |
| `INTROSPECTION_RATE_LIMIT_WINDOW_SECS` | 60 | 86_400 | Same |
| `AUDIT_RETENTION_DAYS` | 365 | 36_500 (100y) | Operator clarity |
| `AUDIT_RETENTION_TOKEN_INTROSPECTED_DAYS` | 30 | 36_500 | Same |
| `SESSION_INDEX_REPAIR_BATCH_LIMIT` | 1000 | 100_000 | Cron budget cap |

A startup validation failure MUST result in
cesauth refusing to serve. Pattern: log to
`console_error!` and propagate the worker::Error
out of `Config::from_env`. No silent
"continue with default" — the operator's intent
is unrecoverable.

**`0` is preserved as "disabled"** for fields
where downstream code already treats 0 specially
(rate-limit thresholds use `if threshold > 0`
guards). The helper accepts `0`; downstream
`if threshold > 0` is unchanged.

**Symmetric helper for `i64` durations**: add
`var_parsed_i64_bounded` for `*_secs` fields. Same
shape; type differs.

### Issue 3 — Duplicate route deletion

Delete lines 193-200 of
`crates/worker/src/lib.rs` (the second block of
`/me/security/sessions` registrations). Keep the
first block (161-168).

**Uniqueness test**:

```rust
#[test]
fn no_duplicate_route_registrations() {
    // Greps lib.rs for `(get|post|put|delete)_async("..."`
    // and asserts no (method, path) tuple appears
    // more than once.
    let lib_rs = include_str!("../lib.rs");
    let re = regex::Regex::new(
        r#"\.(\w+)_async\s*\(\s*"([^"]+)""#
    ).unwrap();
    let mut seen: std::collections::HashSet<(String, String)> = Default::default();
    let mut dupes = Vec::new();
    for cap in re.captures_iter(lib_rs) {
        let method = cap[1].to_string();
        let path   = cap[2].to_string();
        if !seen.insert((method.clone(), path.clone())) {
            dupes.push(format!("{method} {path}"));
        }
    }
    assert!(dupes.is_empty(),
        "Duplicate route registrations:\n{}", dupes.join("\n"));
}
```

If `regex` isn't already a dev-dep, prefer a
hand-rolled scan over the file's lines for
`_async(` substrings to keep dev-deps small.

### Issue 4 — Duplicate ADR-012 file

Add a header to
`docs/src/expert/adr/012-session-hardening.md`:

```markdown
# ADR-012: Session hardening + user-facing session list (older draft)

**Status**: **Superseded by [ADR-012 (sessions)](012-sessions.md)** as of 2026-05.

The §Q numbering and decisions in this draft were
refined and consolidated into `012-sessions.md`,
which is the canonical ADR-012. The text below is
preserved for historical reference but is not the
authoritative record.

For active decisions and open questions on
sessions, refer to `012-sessions.md`.

---

[original body unchanged]
```

Update `docs/src/expert/adr/README.md` index entry
to link to `012-sessions.md` only and mark
`012-session-hardening.md` as Superseded. Same in
`SUMMARY.md`.

No file rename or delete — preserves history,
costs nothing, eliminates ambiguity.

## Test plan

### Issue 1 (CSRF RNG)

1. **`mint_returns_err_on_rng_failure`** — inject
   a stub RNG that errors. Pin: `mint()` returns
   `Err`, not a fallback string.
2. **`mint_returns_24_byte_url_safe_no_pad_on_success`**
   — pin format.
3. **`csrf_rng_failure_renders_500_at_login_route`**
   — handler-level integration test.
4. **`csrf_rng_failure_emits_audit_event`** — pin
   the new audit kind fires.

### Issue 2 (config validation)

5. **`config_rejects_negative_rate_limit_threshold`**
   — `REFRESH_RATE_LIMIT_THRESHOLD=-1` → `Err`.
6. **`config_rejects_above_bound_rate_limit_threshold`**
   — `=2_000_000` → `Err`.
7. **`config_accepts_zero_as_disabled`** — `=0` →
   `Ok(0)`.
8. **`config_rejects_non_numeric`** — `=abc` →
   `Err`.
9. **`config_uses_default_when_var_unset`** — Ok
   with default value.
10. Parametric versions covering remaining bounded
    fields (introspection threshold, retention
    days, etc.).

### Issue 3 (duplicate routes)

11. **`no_duplicate_route_registrations`** — see
    Design.

### Issue 4 (duplicate ADR file)

No code test. Documentation review confirms the
Superseded notice is in place and the index links
correctly.

## Security considerations

**CSRF RNG fix**. Today's `getrandom` reliably
succeeds on Cloudflare Workers' WASM target — this
is defense-in-depth, not a known active exploit.
Still: ship the fix. The cost is one extra `?` per
caller; the benefit is robustness against any
future runtime regression.

**Config validation**. The negative-→-huge-u32 bug
is exploitable only by an operator with
mis-config authority. The threat is "operator
typo silently disables rate limit" — a foot-gun,
not external attack surface. Validation is
defense-in-depth.

**Duplicate routes**. Today's identical handlers
mean no production behavior change; tomorrow's
"fix" applied to only one block is the regression
hazard. Cleanup eliminates the trap.

**Duplicate ADR file**. No security implication.
Doc hygiene only.

## Open questions

**Should `var_parsed_u32_bounded` move to
`cesauth-core`?** The validation logic is
reusable; the `Env` wrapper is worker glue. Keep
in worker for v0.50.x. Promote to core if a
second consumer (e.g., `cesauth-migrate` reading
bounded knobs from env) emerges.

**Should rate-limit field bounds be configurable?**
No — meta-config rabbit-hole. Bounds are documented
and fixed; an operator who legitimately needs
higher tunes downstream code or files an issue.

## Implementation order

1. **PR 1 — Issue 4** (duplicate ADR file
   header). 2-line doc edit + index update.
   Trivial, ride in any release.
2. **PR 2 — Issue 3** (duplicate route deletion +
   uniqueness test). ~10 LOC + 1 test. Quick win.
3. **PR 3 — Issue 1** (CSRF RNG `Result`). ~30
   LOC + 4 tests + new audit kind.
4. **PR 4 — Issue 2** (config validation). ~50
   LOC + 8 tests.
5. **PR 5 — CHANGELOG + release.**

## Notes for the implementer

- Issue 4 is so trivial it should land first
  regardless of branch.
- Issue 3's uniqueness test: if `regex` isn't
  already a dev-dep, a hand-rolled scan over
  lines for `_async(` substrings is fine. The
  goal is "merging a duplicate fails CI", not
  perfect AST parsing.
- Issue 2's bounds are operator-tunable in
  principle. Document in the deployment chapter
  alongside RFC 013's operational envelope work.
- The new `CsrfRngFailure` audit kind goes in the
  same audit-kinds catalog edit as RFC 008's
  invariant-pin work and RFC 009's
  `IntrospectionRowMissing`. Coordinate to
  minimize merge conflicts.
- This RFC is the ideal candidate for a
  v0.50.3 release if v0.50.2 ships RFCs 008+009+010
  alone. The four items here are entirely
  mechanical.
