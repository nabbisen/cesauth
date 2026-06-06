# RFC 080 — Audit log filtered export (CSV/JSONL)

**Status**: Implemented  
**Tier**: P2  
**Size**: Medium  
**Target**: v0.62.x  
**Phase**: Operations UX  
**Refs**: G10 (gap analysis), PDF "Audit log viewer ... [ Export filtered ]"

## Problem

PDF Operations UX panel:
```
Audit log viewer
Search actor / event / tenant
2026-05-05 Login success
...
[ Export filtered ]
```

`[ Export filtered ]` ボタンは現状実装されていない。

オペレーターが監査ログを外部システムに取り込む (SIEM、Excel 分析、コンプライ
アンス報告) には、現状 D1 から直接 SQL で取り出すしかない。これは **operator
console から実行できる** べき機能。

## Goal

`/admin/console/audit` 上の検索結果について、以下を実現:

1. **Export filtered** ボタンが検索 form の下部に表示される。
2. 押下すると **CSV** または **JSONL** 形式でダウンロードできる。
3. ダウンロード時、 `AuditExported` 監査イベントが書き込まれる。
4. 1 リクエストあたり最大行数 (`AUDIT_EXPORT_MAX_ROWS`、デフォルト 10000) で
   capped。超える場合は 「最初の N 行のみ」と response に明示。
5. CSV/JSONL ともに **token material、code_plaintext、secret 系を含まない**
   (現状の denylist と整合)。

## Design

### Route

新規ルート:

```
POST /admin/console/audit/export?format=csv
POST /admin/console/audit/export?format=jsonl
```

POST にする理由: 
- CSRF token 必須 (export は副作用としての監査書き込みあり)
- query params + form body で複合フィルタを受ける

### Form

`/admin/console/audit` の search form を拡張:

```html
<form method="POST" action="/admin/console/audit/export">
  <input type="hidden" name="csrf_token" value="{csrf}">
  <!-- existing filter fields (actor, event, tenant, since, until) -->
  <button type="submit" name="format" value="csv">Export CSV</button>
  <button type="submit" name="format" value="jsonl">Export JSONL</button>
</form>
```

### CSV schema

列順序を固定 (drift 検出のため):

```
seq,timestamp,kind,actor,subject,scope,detail_redacted,chain_hash
1,2026-05-05T12:34:56Z,LoginSuccess,u-001,/,system,,abc123...
```

- `detail_redacted` は `audit::detail_for_export(event)` を通った後の文字列。
  既存 denylist (`code_plaintext` 等) は core 層の `audit::redaction` で扱う。
- `chain_hash` を含めて出力することで、外部ツールで chain integrity を再検証
  可能にする。

### JSONL schema

1 行 1 JSON オブジェクト:

```json
{"seq":1,"timestamp":"2026-05-05T12:34:56Z","kind":"LoginSuccess","actor":"u-001","subject":"/","scope":"system","detail":null,"chain_hash":"abc123..."}
```

### Service layer

`crates/core/src/admin/service.rs` に新規関数:

```rust
pub async fn export_audit<A>(
    audit:  &A,
    query:  &AuditQuery,
    format: ExportFormat,
    max_rows: usize,
) -> PortResult<ExportResult>
where A: AuditRepository
{
    let rows = audit.search(query).await?;
    let truncated = rows.len() > max_rows;
    let rows = rows.into_iter().take(max_rows).collect::<Vec<_>>();

    let body = match format {
        ExportFormat::Csv   => render_csv(&rows),
        ExportFormat::Jsonl => render_jsonl(&rows),
    };

    Ok(ExportResult {
        body,
        row_count:   rows.len(),
        truncated,
        content_type: format.content_type(),
        filename:    build_filename(query, format),
    })
}

#[derive(Debug, Clone, Copy)]
pub enum ExportFormat { Csv, Jsonl }

impl ExportFormat {
    pub fn content_type(self) -> &'static str {
        match self {
            ExportFormat::Csv   => "text/csv; charset=utf-8",
            ExportFormat::Jsonl => "application/x-ndjson; charset=utf-8",
        }
    }
}

pub struct ExportResult {
    pub body:         String,
    pub row_count:    usize,
    pub truncated:    bool,
    pub content_type: &'static str,
    pub filename:     String,
}
```

### Audit event for the export operation itself

```rust
EventKind::AuditExported,  // new
```

emit すべきフィールド:
- `actor`: 操作した admin user id
- `subject`: query string (フィルタ条件のサマリ)
- `detail`: `format=csv rows=1234 truncated=false`

### Worker handler

```rust
// crates/worker/src/routes/admin/audit_export.rs (新規)

pub async fn export<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = auth::resolve_or_respond(&req, &ctx.env).await?;
    auth::ensure_role_allows(&principal, AdminAction::ViewConsole)?;

    let query = parse_audit_query_from_form(&req).await?;
    let format = parse_format(&req)?;
    let max_rows = env_var_or(&ctx.env, "AUDIT_EXPORT_MAX_ROWS", 10000);

    let audit_repo = CloudflareAuditRepository::new(&ctx.env);
    let result = export_audit(&audit_repo, &query, format, max_rows).await?;

    audit::write(&ctx.env, EventKind::AuditExported, ...).await?;

    let mut headers = Headers::new();
    headers.set("content-type", result.content_type)?;
    headers.set("content-disposition",
        &format!("attachment; filename=\"{}\"", result.filename))?;
    if result.truncated {
        headers.set("x-cesauth-export-truncated", "true")?;
    }

    Response::ok(result.body).map(|r| r.with_headers(headers))
}
```

### Filename convention

```
cesauth-audit-{from}_{to}_{filter}.{ext}
e.g. cesauth-audit-2026-04-01_2026-04-30_LoginSuccess.csv
```

タイムスタンプは UTC、フィルタはアンダースコア区切り。

### Redaction unification

既存の `crates/core/src/audit/redaction.rs` (RFC 030) は `detail` フィールドから
secret 系を除去する。export 時も同じ redaction を適用 (新規 path で redaction
を回避しない)。これは設計上の必須項目。

## Implementation steps

1. **Core**: `ExportFormat` enum + `ExportResult` struct + `export_audit` 関数を追加。
2. **Core**: `EventKind::AuditExported` を追加。
3. **Core**: `render_csv` / `render_jsonl` 純粋関数 + tests。
4. **Worker**: `routes/admin/audit_export.rs` 新規。route 登録 (`POST /admin/console/audit/export`)。
5. **UI**: `admin/audit.rs` の search form に Export buttons を追加。MessageKey 追加。
6. **adapter-cloudflare**: `AuditRepository::search` が既に存在することを確認。
7. **Tests**: CSV/JSONL format tests、redaction tests、route-contracts 更新。

## Acceptance

- [ ] `POST /admin/console/audit/export?format=csv` が CSV を返す
- [ ] `POST /admin/console/audit/export?format=jsonl` が JSONL を返す
- [ ] `content-disposition: attachment; filename=...` ヘッダが付く
- [ ] 出力に token material / code_plaintext が含まれない (denylist 経由)
- [ ] 超過時 `x-cesauth-export-truncated: true` ヘッダが付く
- [ ] `AuditExported` イベントが書き込まれる
- [ ] route-contracts.md に新ルートが追加されている
- [ ] 全テストスイート green

## Test plan

- `export_audit_csv_format` (純粋関数)
- `export_audit_jsonl_format` (純粋関数)
- `export_audit_respects_max_rows`
- `export_audit_truncated_flag_set_correctly`
- `export_audit_redacts_secret_fields`
- `export_filename_format`
- CSP / CSRF integration

## Risks / Notes

- **メモリ**: 10000 行を一気に文字列にバッファすると数 MB。Cloudflare worker
  の 128 MB limit 内ではあるが、将来的に streaming response にする選択肢を残す。
  本 RFC では同期生成。
- **rate limit**: export は重い operation。`admin_action` rate-limit に
  カウント (新規 envelope or 既存)。
- **chain_hash の意味**: 外部ツールで chain verification ができるのは便利だが、
  hash chain の完全検証は内部 cron が担当。外部での再検証はベストエフォート。
