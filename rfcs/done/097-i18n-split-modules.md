# RFC 097 — Split i18n.rs into surface-grouped sub-modules

**Status**: Implemented | **Tier**: Refactoring | **Size**: Medium | **Target**: v0.66.0

## Problem

`crates/core/src/i18n.rs` is **1,145 lines** containing:

- `Locale` enum (~30 lines)
- `MessageKey` enum (~150 lines) — 147 variants
- `lookup()` function — **684 lines, 145 match arms in one function**

Adding a new translatable string requires editing two places in a 1,145-line file
and the test in `i18n/tests.rs`. Reviewers must scroll past unrelated translations
to confirm a single key was added correctly. The build cost is real: every
change to a translation invalidates compile cache for the entire file.

The keys themselves are well-organized into RFC sections via `// ----` comments,
but they all share a single match-arm block.

## Existing structure observed

| Section header | Approx. keys |
|---|---|
| `// ---- v0.39.0: login page` | 8 |
| `// ---- v0.39.0: TOTP enroll page` | 12 |
| `// ---- v0.39.0: TOTP verify gate page` | 6 |
| `// ---- v0.39.0: Security Center index` | 12 |
| `// ---- RFC 075: Security Center summary card` | 8 |
| `// ---- v0.45.0: bulk "revoke all other sessions"` | 4 |
| `// ---- v0.47.0: i18n-2 continuation` | 25 |
| `// ---- RFC 016: admin scope badge` | 3 |
| `// ---- RFC 077: skip-to-content` | 1 |
| `// ---- RFC 078: tenant admin invitation/deletion` | 35 |

10 distinct surface groups, each cohesive within itself.

## Proposed split

```
crates/core/src/i18n/
├── mod.rs               # Locale, MessageKey, public `lookup()` dispatcher (~80 lines)
├── login.rs             # login + magic-link keys
├── totp.rs              # TOTP enroll/verify/disable/recovery keys
├── security_center.rs   # /me/security + sessions keys
├── flash.rs             # FlashTotpEnabled, FlashLoggedOut, etc.
├── admin_scope.rs       # AdminScopeSystem/Tenancy/Tenant
├── tenant_admin.rs      # RFC 078 invitation + deletion keys
├── chrome.rs            # SkipToMainContent, generic page titles
└── tests.rs             # existing exhaustive-match test (already separate)
```

Each sub-module exposes `pub(super) fn lookup(key, locale) -> Option<&'static str>`
returning `Some(text)` for keys it handles, `None` otherwise. The root `lookup()`
walks each submodule until one returns `Some`. With 10 sub-modules and 147 keys,
that's ~15 lookups per sub-module — still O(1) at runtime thanks to match-arm
jump tables in each sub-module.

Alternative: keep `MessageKey` and `lookup()` in one file, but break `lookup()`
into 10 nested calls (`lookup_login`, `lookup_totp`, …) inside the same file.
Less clean for diff review but minimizes structural change.

## Trade-offs

| Approach | Pros | Cons |
|---|---|---|
| Sub-modules (preferred) | Small files, clear ownership, fast incremental builds | More files; each sub-module has its own `MessageKey::*` pattern matches |
| Nested helpers | Single file, no module structure change | 684-line `lookup()` still exists, just delegated |

## Acceptance

- `crates/core/src/i18n.rs` no longer exists; replaced by `crates/core/src/i18n/mod.rs`.
- Each sub-module ≤ 200 lines.
- `MessageKey::*` pattern in `lookup()` dispatcher is exhaustive (compiler error if a sub-module forgets one).
- All 1,192 tests still pass.
- No public API change — `cesauth_core::i18n::{Locale, MessageKey, lookup}` still works.

## Risks

- The exhaustive match in `i18n/tests.rs` becomes the single source of "every key is mapped";
  adding a key requires both adding to the sub-module's match and the global test.
  This is the same constraint as today — just enforced by a different layout.
