# RFC 099 — Split admin/service.rs by responsibility

**Status**: Implemented | **Tier**: Refactoring | **Size**: Small | **Target**: v0.66.0

## Problem

`crates/core/src/admin/service.rs` is **706 lines** containing 11 unrelated
public service functions:

| Function | Lines | Responsibility |
|---|---|---|
| `build_overview` | ~50 | Admin home page assembly |
| `build_cost_trend`, `build_cost_dashboard` | ~50 | Cost analytics |
| `build_safety_report` | ~35 | Bucket safety |
| `search_audit` | ~10 | Audit search |
| `generate_alerts` | ~55 | Threshold alerts |
| `verify_bucket_safety`, `apply_bucket_safety_change`, `preview_bucket_safety_change` | ~60 | Safety mutation |
| `update_threshold` | ~15 | Threshold mutation |
| `export_audit` + `render_csv` + `render_jsonl` + helpers | ~150 | Audit export (RFC 080) |

Plus two test submodules (`export_tests`, `service_tests`) totaling another ~200 lines.

Each function reads at least one repository port. There's no shared state and no
inter-function calls — they're 11 independent operations colocated by accident
of being "the admin service layer."

## Proposed split

```
crates/core/src/admin/services/
├── mod.rs              # re-exports
├── overview.rs         # build_overview
├── cost.rs             # build_cost_trend, build_cost_dashboard
├── safety.rs           # build_safety_report, verify/apply/preview_bucket_safety
├── audit.rs            # search_audit (+ AuditQuery types re-exported)
├── audit_export.rs     # export_audit, ExportFormat, ExportResult, render_csv, render_jsonl
├── alerts.rs           # generate_alerts
└── thresholds.rs       # update_threshold
```

Then `crates/core/src/admin/service.rs` becomes a flat re-export shim:

```rust
// admin/service.rs — backward-compat shim
mod services;
pub use services::overview::*;
pub use services::cost::*;
pub use services::safety::*;
pub use services::audit::*;
pub use services::audit_export::*;
pub use services::alerts::*;
pub use services::thresholds::*;
```

## Test relocation

Each services/X.rs file gets its own `#[cfg(test)] mod tests;` block. The current
`export_tests` and `service_tests` submodules in `service.rs` move into
`services/audit_export.rs` and `services/audit.rs` respectively.

## Acceptance

- Each `services/X.rs` ≤ 200 lines.
- Public API unchanged — call sites that import from
  `cesauth_core::admin::service::*` continue to work.
- All `admin` tests still pass.

## Order of work

Implement in one commit; small enough that partial implementation provides
no benefit. ~706 lines moved into 7 files of ~100 lines each.
