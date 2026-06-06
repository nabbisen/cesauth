# RFC 081 — Cron pass status surface

**Status**: Proposed  
**Tier**: P2  
**Size**: Medium  
**Target**: v0.62.x  
**Phase**: Operations UX  
**Refs**: G11 (gap analysis), PDF "5 daily cron passes: sweep audit_chain session_index_audit audit_retention session_index_repair"

## Problem

cesauth は 5 つの daily cron pass を持つ (04:00 UTC):

1. `sweep` — anonymous session 整理、TOTP unconfirmed 整理、deletion executions
2. `audit_chain_cron` — audit hash chain verification + KV checkpoint update
3. `session_index_audit` — D1-DO session index drift detection (audit only)
4. `audit_retention_cron` — 古い audit rows の prune (365日 default)
5. `session_index_repair_cron` — drift repair (opt-in, default dry-run)

これらは動作しているが、**admin console から「最後の実行はいつ、結果はどうか」が
見えない**。問題発生時に audit_events を SQL で grep するしかない。

PDF Operations UX panel が示すように、`[Safety controls]` / `5 daily cron passes`
の状態は admin 向けに**画面化されているべき**。

## Goal

新規ページ `/admin/console/operations` で:

1. 5 cron pass の **最終実行日時 / 成功 or 失敗 / 処理件数**を一覧表示。
2. 各 pass について次回実行予定 (04:00 UTC の next occurrence) を表示。
3. **destructive operation** (audit retention prune, session index repair) は
   "dry-run / opt-in" バッジで区別表示。
4. 読み取り専用 (操作は wrangler / cron schedule から)。

## Design

### Data model (KV-backed)

各 cron pass は KV に最終実行状態を保存する。**Key naming convention**:

```
cron:last-run:sweep             → JSON
cron:last-run:audit_chain       → JSON
cron:last-run:session_index_audit
cron:last-run:audit_retention
cron:last-run:session_index_repair
```

JSON shape:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronPassRecord {
    pub pass_name:        String,            // "sweep"
    pub started_at:       i64,               // unix seconds
    pub finished_at:      i64,               // unix seconds
    pub success:          bool,
    pub processed_count:  u64,               // pass-specific counter
    pub error_message:    Option<String>,    // truncated to 200 chars; no secrets
    pub mode:             CronPassMode,      // Dryrun / Apply
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CronPassMode {
    Dryrun,   // session_index_repair when AUTO_REPAIR != true; audit retention preview
    Apply,    // actual mutation performed
}
```

### KV TTL

これらの key は **TTL 8 days** (1 week + grace) で保存。失敗したり cron が
止まったりすれば自動的に key が消え、UI は "No recent run" と表示できる。

### KV namespace

既存の `CESAUTH_KV` を再利用する (RATE_LIMIT 含む)。新規 namespace は作らない。

### Cron pass 側の修正

各 cron pass の finalize handler に `record_cron_pass(env, record)` を呼ぶ。
これは KV write のみで、失敗してもメイン処理を巻き戻さない (best-effort).

例:

```rust
// crates/worker/src/sweep.rs

pub async fn run(env: &Env) -> Result<()> {
    let started_at = now();
    let mut processed = 0u64;
    let success = run_sweep_inner(env, &mut processed).await.is_ok();
    let finished_at = now();

    let _ = record_cron_pass(env, CronPassRecord {
        pass_name:       "sweep".into(),
        started_at,
        finished_at,
        success,
        processed_count: processed,
        error_message:   None, // (or capture if Err)
        mode:            CronPassMode::Apply,
    }).await;

    Ok(())
}
```

`record_cron_pass` は `crates/worker/src/cron_status.rs` (新規) に住む:

```rust
pub async fn record_cron_pass(env: &Env, record: CronPassRecord) -> Result<()> {
    let kv = env.kv("CESAUTH_KV")?;
    let key = format!("cron:last-run:{}", record.pass_name);
    let body = serde_json::to_string(&record)?;
    kv.put(&key, body)?.expiration_ttl(7 * 86400).execute().await?;
    Ok(())
}

pub async fn load_all_pass_records(env: &Env) -> Result<Vec<CronPassRecord>> {
    let kv = env.kv("CESAUTH_KV")?;
    let names = ["sweep", "audit_chain", "session_index_audit",
                 "audit_retention", "session_index_repair"];
    let mut out = Vec::new();
    for name in names {
        let key = format!("cron:last-run:{}", name);
        if let Ok(Some(s)) = kv.get(&key).text().await {
            if let Ok(r) = serde_json::from_str::<CronPassRecord>(&s) {
                out.push(r);
            }
        }
    }
    Ok(out)
}
```

### UI page

`crates/ui/src/admin/operations.rs` (新規):

```rust
pub fn operations_page(
    principal: &AdminPrincipal,
    records:   &[CronPassRecord],
    now_unix:  i64,
) -> String {
    // ... admin_frame_for(...,
    //   body = <table> rendering records,
    //   with badge--success / badge--danger for success bool,
    //   and "Dry-run" / "Apply" subtle badge per mode).
}
```

table 列:

| Pass | Last run | Status | Mode | Processed | Next 04:00 UTC |
|---|---|---|---|---|---|
| sweep | 2026-05-12 04:00 | ✓ Success | Apply | 123 | tomorrow |
| audit_chain | 2026-05-12 04:01 | ✓ Success | Apply | 45000 | tomorrow |
| audit_retention | 2026-05-12 04:02 | △ Dry-run | Dryrun | 0 | tomorrow |

### Route

```
GET /admin/console/operations
```

Auth: `AdminAction::ViewConsole` (ReadOnly+ 以上).

### Navigation

`AdminTab::Operations` を追加 (`crates/core/src/admin/types.rs`):

```rust
pub enum AdminTab {
    Overview,
    Audit,
    Safety,
    Operations, // NEW (RFC 081)
    Tokens,
    Config,
}
```

`admin/frame.rs` の nav に "Operations" 項目を追加。

## Implementation steps

1. **Core**: `CronPassRecord` / `CronPassMode` を `crates/core/src/admin/types.rs`
   または新規 `crates/core/src/cron/types.rs` に定義。
2. **Worker**: `crates/worker/src/cron_status.rs` 新規。`record_cron_pass` /
   `load_all_pass_records` 実装。
3. **Worker**: 各 cron pass (`sweep.rs`, `audit_chain_cron.rs`, etc.) の最後で
   `record_cron_pass` を呼ぶ修正。
4. **UI**: `crates/ui/src/admin/operations.rs` 新規。table render。
5. **UI**: `AdminTab::Operations` を `frame.rs` の nav に追加。
6. **Worker**: `GET /admin/console/operations` route 登録。
7. **Tests**:
   - `cron_pass_record_round_trip_serde`
   - `operations_page_renders_all_5_passes`
   - `operations_page_shows_dryrun_badge_for_repair_pass`
   - `operations_page_handles_missing_record` (1 pass の record 欠落でも崩れない)

## Acceptance

- [ ] `GET /admin/console/operations` が ReadOnly+ で 200
- [ ] 5 cron pass それぞれの最終実行情報が表示される
- [ ] dry-run pass に対して "Dry-run" バッジが出る
- [ ] 1 つの KV key が欠落 (recent run なし) でも表示できる
- [ ] route-contracts に新ルート登録済み
- [ ] 全テストスイート green

## Test plan

- `cron_pass_record_serde_round_trip`
- `cron_pass_record_size_under_2kb` (KV size sanity)
- `operations_page_renders_5_passes`
- `operations_page_no_record_shows_no_recent_run`
- `operations_page_dryrun_mode_badge`
- worker `cron_status::record_cron_pass_writes_to_kv`

## Risks / Notes

- **KV eventual consistency**: 別 region から read すると最新値が見えないことがある。
  本 RFC では許容 (UI は 30 秒前の値を表示しても困らない)。
- **error_message のサニタイズ**: cron pass error は token material や DB 接続
  情報を含む可能性があるため、最大 200 char で truncate + redaction list を適用。
  既存の audit redaction を流用。
- **destructive operation の表示**: PDF が要求する "default-off / dry-run / opt-in"
  の視覚化はこの table で `Mode = Dryrun` 列として実装される。
