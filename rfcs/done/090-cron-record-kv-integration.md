# RFC 090 — Cron pass KV record writing

**Status**: Implemented | **Tier**: Feature | **Size**: Small

RFC 081 added the operations page UI that reads KV records. But no cron pass currently
*writes* `cron:last-run:{name}` to KV. Add `record_cron_pass()` calls to all 5 cron
passes in `crates/worker/src/`.
