# RFC 088 — i18n.rs locale resolution tests

**Status**: Implemented | **Tier**: Quality | **Size**: Small

`i18n.rs` contains `Locale::bcp47()`, `Locale::default()`, and the `lookup` function.
The exhaustive match test is in `i18n/tests.rs` but `i18n.rs` itself has zero inline tests.
Add tests for bcp47(), default(), and the lookup() dispatch function.
