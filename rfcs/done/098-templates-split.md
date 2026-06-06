# RFC 098 — Split templates.rs by surface

**Status**: Implemented | **Tier**: Refactoring | **Size**: Medium | **Target**: v0.66.0

## Problem

`crates/ui/src/templates.rs` is **1,537 lines** containing rendering for:

| Lines | Surface |
|---|---|
| 1–250 | shared scaffolding (BASE_CSS, frame, flash, escape, render_nonce) |
| 250–650 | login page (`/login`, magic-link form, magic-link sent) |
| 650–990 | TOTP pages (enroll, verify, recovery codes, disable confirm) |
| 990–1310 | Security Center + summary card |
| 1310–1537 | Sessions list page |

Five distinct surfaces, no internal sharing beyond `frame()` and `escape()`.
Edits to one surface (e.g. RFC 075's summary card) require holding the entire
file in working memory; the file does not fit on a screen.

Test file is also bloated: `crates/ui/src/templates/tests.rs` is **1,912 lines**.

## Proposed split

```
crates/ui/src/templates/
├── mod.rs                  # re-export everything for backward compat (small)
├── chrome.rs               # BASE_CSS, frame(), frame_with_flash(), escape(), render_nonce() (~250 lines)
├── login.rs                # login_page, login_page_for, magic_link_sent_page (~400 lines)
├── totp.rs                 # totp_enroll/verify/recovery/disable pages (~350 lines)
├── security_center.rs      # security_center_page, SecurityCenterState, summary card (~350 lines)
├── sessions.rs             # sessions_page, SessionListItem (~200 lines)
└── error_page.rs           # error_page, error_page_for (~50 lines)
```

Test file should be split correspondingly:

```
crates/ui/src/templates/tests/
├── mod.rs                  # shared test fixtures (PrimaryAuthMethod construction, etc.)
├── chrome_tests.rs
├── login_tests.rs
├── totp_tests.rs
├── security_center_tests.rs
└── sessions_tests.rs
```

## Public API preservation

The current call sites import `cesauth_ui::templates::*`. To preserve compatibility:

```rust
// templates/mod.rs
mod chrome;
mod login;
mod totp;
mod security_center;
mod sessions;
mod error_page;

pub use chrome::{escape, frame, frame_with_flash, render_nonce, BASE_CSS};
pub use login::{login_page, login_page_for, magic_link_sent_page, ...};
pub use totp::{totp_enroll_page, totp_verify_page, ...};
// etc.
```

Worker route handlers continue using `templates::login_page_for(...)` etc.
unchanged.

## Acceptance

- `templates.rs` (file) removed; replaced by `templates/` (directory).
- Each module ≤ 400 lines.
- All 310 UI tests still pass.
- No worker route handler requires modification (only `use templates;` paths).

## Out of scope

- Admin frame files (`admin/frame.rs`, `tenant_admin/frame.rs`,
  `tenancy_console/frame.rs`) are already at ~400 lines each and don't need splitting.
- The `Affordances` struct in `tenant_admin/` is fine where it is.
