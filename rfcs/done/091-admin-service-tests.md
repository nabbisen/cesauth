# RFC 091 — admin/service.rs unit tests

**Status**: Implemented | **Tier**: Quality | **Size**: Small

`admin/service.rs` has 10 public async functions (build_overview, build_cost_trend,
build_safety_report, search_audit, export_audit, etc.) with only the export_tests
submodule. Add tests for pure-logic helpers: `build_trend`, `evaluate_cost_thresholds`
(already in policy.rs), `render_csv` / `render_jsonl` coverage completion.
