# RFC 109 — Audit log viewer UI surface

**Status**: Proposed  
**Tier**: P2  
**Size**: Large  
**Target**: v0.69.0  
**Phase**: New surface (finishing track)  
**Refs**: PDF v0.50.1 page 9 "Operations UX: Audit log viewer" / RFC 080 (audit log export) / ADR-010 (hash chain) / ADR-013 (admin JA-only)

## Problem

PDF v0.50.1 page 9 ("Operations UX") の左パネルは:

```
Audit log viewer
Search actor / event / tenant
2026-05-05 Login success
2026-05-05 Token introspected
2026-05-05 Session repaired
[ Export filtered ]
```

を **interactive** な UI surface として要求する。
現状 v0.66.0 では:

- **RFC 080 (v0.63.0)** で audit log の **filtered export** (CSV / JSONL) は実装済。
  endpoint: `POST /admin/console/audit/export`、`AuditExported` イベント記録。
- しかし **ブラウザ上で audit log を逐次閲覧する画面が存在しない**。
  operator は `wrangler d1 execute` あるいは export → 外部ツールでの閲覧に
  依存する。

これは PDF page 9 の "状態確認 → 影響範囲 → 実行 → 監査" の最初の段
(状態確認) を UI で扱えないことを意味する。export ボタンは「閲覧→絞り込み→
export」の絞り込み段が欠落したまま使うことになる。

## Goal

1. `/admin/console/audit` (system admin scope) に audit log viewer ページを追加する。
2. 絞り込みフィルタ (actor / event_kind / tenant_id / 日付範囲) を form contract で提供する。
3. 既存の `POST /admin/console/audit/export` (RFC 080) に対する **絞り込み済みの
   query を継承** したまま export できる導線を整える。
4. ADR-013 (admin JA-only) に従い、UI は JA のみ。

明示的に out of scope:
- end-user 向け audit 閲覧 (`/me/audit` 等の新規 surface) — 本 RFC は admin のみ。
- 自然言語検索 / full-text — 構造化フィルタのみ。
- リアルタイム push (WebSocket) — paginated polling のみ。
- 個別行の "詳細" モーダル — 行情報は表内に出し、必要なら export で取得。
- chain hash の可視化 — ADR-010 範囲。本 RFC は通常閲覧 UI のみ。
- hash chain repair / retention 操作 — RFC 080 / RFC 081 範囲。

## Design

### Surface

ルート: `GET /admin/console/audit` (新規)
scope: System admin (RFC 016 scope badge は `System scope`)。
i18n: JA-only。
auth: 既存の `require_system_admin!` macro (RFC 100)。

### Form contract (PDF page 13 整合)

| 項目 | 値 |
|---|---|
| Route | `GET /admin/console/audit` |
| Actor | System admin |
| Main task | filter / list audit events |
| UX guardrail | scope badge required, no destructive op |
| Audit kind | `AuditViewed` (新規 EventKind) は不要 — read-only 操作は audit 自体に
              含めない (PDF page 10 "Secret in audit" との対称: 表示行為は不記録)。

filter parameters (query string):
- `actor` (string, optional) — actor_id 部分一致
- `event` (`EventKind`, optional) — event_kind 完全一致
- `tenant` (string, optional) — tenant_id 完全一致
- `from` (RFC 3339 timestamp, optional) — 開始日時 (UTC)
- `to` (RFC 3339 timestamp, optional) — 終了日時 (UTC)
- `cursor` (opaque, optional) — pagination cursor (server-issued)

すべて URL query。POST/Redirect/GET の G 段相当 (form submission は GET)。
CSRF は不要 (read-only)。

### Pagination

ADR-010 hash chain に依存しない開始位置を許す:
- 既定: 最新 100 行 (descending by `seq`)
- `cursor` は `seq` のエンコード値 (opaque base64) — 内部実装の詳細を漏らさず、
  かつ KV/D1 page-by-page で逐次取得できるシグネチャ。

> 留意: hash chain 検証ではないので、`cursor` を別経路で改竄されても
> ハッシュ整合性には影響しない。表示が飛ぶだけ。

### UI layout (JA, 1 column / 768px 以下は table → card 切替)

```
[scope badge: System scope]
監査ログ

[form]
  Actor          [_________________]
  Event          [Select ▼ — Login success / Token introspected / ...]
  Tenant         [_________________]
  期間           [from] — [to]
  [絞り込む]  [絞り込み条件で export]

[table]
  seq | 時刻 (UTC) | actor | event | tenant | 詳細
  ----+-----------+-------+-------+--------+-----
  ... 100 行 ...

[pagination] ← より新しい | より古い →
```

`絞り込み条件で export` は同じ query を持って `POST /admin/console/audit/export`
(既存 RFC 080) に転送する form (CSRF 付き)。export 列は現状と同じ
(CSV / JSONL 選択 modal は不要 — 既存 endpoint の format フィールドで決める)。

### Server-side rendering

`crates/ui/src/admin/audit.rs` (既存) に viewer 関数追加。現状の
`audit_export.rs` (RFC 099 で分割済) と区別:

- `admin/service/audit_export.rs` — export 関数 (RFC 099)
- `admin/audit.rs` (UI 側) — 既存。viewer template を追加。
- 新規 `admin/service/audit_view.rs` (or `audit_query.rs`) — query 実行 service。
  `AuditEventRepository::list_paginated(filter, cursor, limit)` 経由。

### Repository extension

`crates/core/src/ports/audit.rs::AuditEventRepository` に
`list_paginated(filter: AuditFilter, cursor: Option<Cursor>, limit: u32) -> (Vec<AuditEvent>, Option<Cursor>)`
を追加。

`adapter-cloudflare` (D1) と `adapter-test` (in-memory) に実装。
WHERE clause は `actor` LIKE + `event_kind = ?` + `tenant_id = ?` +
`created_at BETWEEN ?, ?`、ORDER BY `seq DESC`、LIMIT 100。

## Implementation steps

1. `AuditFilter` 構造体 + `AuditEventRepository::list_paginated` 追加。
2. `adapter-cloudflare` / `adapter-test` に実装。
3. `cesauth_core::service::audit_query::query_audit_log` 純粋 service。
4. `worker/src/routes/admin/console/audit_view.rs` ハンドラ追加。
   `require_system_admin!` macro 適用。
5. `cesauth_ui::admin::audit::viewer_page_for` template を追加。RFC 100 macro
   と RFC 016 scope badge 経由。
6. `MessageKey` 追加: filter labels (JA-only) は `i18n/admin.rs` (RFC 097
   分割済 sub-module) に。
7. `crates/core/src/routes.rs` の admin sub-mod に AUDIT_VIEWER パス定数追加。
8. `docs/src/expert/route-contracts.md` (RFC 027) に行追加。
9. テスト追加 (詳細は test strategy)。
10. CHANGELOG / ROADMAP 更新。

## Acceptance

- [ ] `GET /admin/console/audit` が 200 OK で table を返す (system admin)
- [ ] tenant admin / 未認証 access は 403 / 302 (`require_system_admin!`)
- [ ] filter 適用後の URL に query string が反映
- [ ] export ボタンが同じ filter を継承して `POST /admin/console/audit/export`
      にチェーンする
- [ ] pagination cursor が opaque base64 形式
- [ ] EN locale でアクセスしても admin console は JA で render (ADR-013)
- [ ] `cargo-1.91 test --workspace --lib` が green
- [ ] `cargo-1.91 build --workspace --target wasm32-unknown-unknown --release` が成功
- [ ] 非 deprecated warnings = 0
- [ ] `route-contracts.md` に新規行
- [ ] テスト合計: 1,204 → ~1,230 (+~25)

## Test strategy

### Unit tests (core service)

```rust
#[test]
fn query_returns_descending_by_seq() { ... }

#[test]
fn query_filters_by_event_kind() { ... }

#[test]
fn query_pagination_cursor_round_trips() { ... }

#[test]
fn query_filters_by_date_range_utc() { ... }

#[test]
fn query_returns_empty_when_no_match() { ... }
```

### Integration tests (adapter-test)

`AuditEventRepository::list_paginated` を 100+ 行のフィクスチャで実行し、
cursor を辿って全件取得できることを確認。

### Worker route tests

`crates/adapter-test` から疑似 admin token で `GET /admin/console/audit` を
呼ぶ。filter query × scope badge × table 構造の HTML を確認。

### Rendering tests

`crates/ui/src/admin/tests.rs` に JA レンダリングテストを追加。
scope badge (`System scope`) と filter form labels が含まれることを確認。

## Migration / compatibility

- 後方互換性: 不要。
- スキーマ変更: 無し (`audit_events` テーブルは既存。WHERE 用 index は
  必要に応じて RFC 024 と協調)。
- wire / DO: 無し (D1 のみ; ADR-010 hash chain は触らない)。
- 運用者向け: 新規 surface。RFC 027 route-contracts.md と
  `docs/src/deployment/...` に operator runbook 追加。
- env 変数追加: 無し。

## Open questions

なし。
