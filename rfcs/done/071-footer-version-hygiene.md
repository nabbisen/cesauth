# RFC 071 — Footer version hygiene + drift-scan reinforcement

**Status**: Implemented  
**Tier**: P0  
**Size**: Small  
**Target**: v0.62.0  
**Phase**: Hygiene  
**Refs**: G5 (gap analysis)

## Problem

PDF acceptance criterion: "version / README / docs drift を release checklist で
検知する" は drift-scan で実現する建付けだが、現状以下の **古いバージョン文字列**
がコード内に残存しており、drift-scan が拾っていない:

- `crates/ui/src/admin/frame.rs:233` — `cesauth Cost & Data Safety Admin Console — v0.4.0`
- `crates/ui/src/tenant_admin/frame.rs:205` — `cesauth tenant admin — v0.50.2 (mutations + affordance gating)`
- `crates/ui/src/tenancy_console/frame.rs:158` — `cesauth tenancy console — v0.50.2 (full mutation surface for Operations+)`

これらは UI フッターでユーザーに見える文字列であり、リリースのたびに更新する
運用負荷がかかる一方で、整合性が崩れるとユーザーに誤った印象を与える。

加えて、現在の `drift-scan.sh` には**「フッター内の固定バージョン文字列」を検出する
パターンが存在しない**。

## Goal

1. フッターから固定バージョン文字列を駆逐し、**「製品名のみ」or「動的に CARGO_PKG_VERSION
   を埋める」** のいずれかに統一する。
2. drift-scan に「`v0\.[0-9]+\.[0-9]+` フォーマットの固定バージョン文字列が
   `crates/ui/` に残っていないか」を検出するパターンを追加する。

## Design

### Decision: 静的フッター文字列

動的埋込 (`env!("CARGO_PKG_VERSION")`) も検討したが、**フッターは UI から削除する**
方針を採る。理由:

- ユーザーは「自分が使っているバージョン」を知りたいわけではない (内部ツールではない)。
- 操作内容や監査表示に対し、バージョン番号は意思決定の助けにならない。
- リリースごとの footer 更新作業を不要にできる (drift の根を断つ)。
- 内部識別子は HTTP response header `X-Cesauth-Build` で出力可能 (operator 向け)。

ただし、**製品名 + 短いタグライン**は維持する。

### After

```
crates/ui/src/admin/frame.rs:233:
  <footer>cesauth Cost & Data Safety Admin Console</footer>

crates/ui/src/tenant_admin/frame.rs:205:
  <footer>cesauth tenant admin</footer>

crates/ui/src/tenancy_console/frame.rs:158:
  <footer>cesauth tenancy console</footer>
```

### drift-scan pattern 追加

```bash
# scripts/drift-scan.sh の PATTERNS 配列に追加
"v0\\.[0-9]+\\.[0-9]+ \\(.*\\)\tHardcoded version with phase descriptor — should be removed (RFC 071)"
```

このパターンは「`v0.X.Y (text...)`」形式 (`v0.50.2 (mutations + ...)` のような
歴史的キャプション付きフッター) を拾う。生のバージョン番号自体は CHANGELOG や
ROADMAP で正当な引用が多いので狭く絞る。

### スコープ外

- ROADMAP.md / CHANGELOG.md / docs/src の歴史的記述: 過去バージョンの言及は
  そのまま残す (歴史記録)。drift-scan のパターンも `crates/ui/` のみを対象にする。
- `crates/ui/src/admin/audit.rs:57` の "Audit events live in the D1 audit_events
  table (v0.32.0+, ADR-010)" — これは「設計上の起点バージョン」言及であり drift
  ではない (永続的に正しい)。touch しない。

## Implementation steps

1. 3 ファイルの footer 行を編集 (固定 caption を削除)。
2. `scripts/drift-scan.sh` の `PATTERNS` に新ルールを追加。
3. `bash scripts/drift-scan.sh` を実行し、新パターンが既存コードに対して
   green であることを確認 (誤検知ゼロ)。
4. UI rendering test (`crates/ui/src/admin/tests.rs` 等) で footer 内に
   固定 caption が出ないことを assertion 追加。

## Acceptance

- [ ] `grep "v0\\.50\\.2 (" crates/ui/` がゼロヒット
- [ ] `grep "v0\\.4\\.0" crates/ui/src/admin/frame.rs` がゼロヒット
- [ ] `bash scripts/drift-scan.sh` green
- [ ] UI rendering tests green
- [ ] 全テストスイート green (1,107+)

## Test plan

- `admin_frame_footer_has_no_version_caption` (new): admin frame の HTML 出力に
  `v0.` 文字列が含まれないことを assertion
- `tenant_admin_frame_footer_has_no_version_caption` (new): tenant admin frame
- `tenancy_console_frame_footer_has_no_version_caption` (new): tenancy console
- drift-scan pattern test を `scripts/drift-scan-self-test.sh` に追加 (新規)
