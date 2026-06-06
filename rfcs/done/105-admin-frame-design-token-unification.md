# RFC 105 — Admin / tenant_admin / tenancy_console frame design-token unification

**Status**: Implemented (v0.67.0)  
**Tier**: P1  
**Size**: Medium  
**Target**: v0.67.0  
**Phase**: UI consistency (finishing track)  
**Refs**: HANDOFF v0.66.0 残課題 §3 ("`design_tokens.rs` の admin frame 統合") / 懸念事項 §4 ("`design_tokens.rs` のダブル定義") / PDF v0.50.1 page 12 "色だけに依存しない状態表示" / RFC 082

## Problem

v0.66.0 時点で UI の color/state token は二重定義のまま残っている。

1. **`crates/ui/src/design_tokens.rs`** に二つの定数が並存している:
   - `DESIGN_TOKENS` (raw `:root { ... }`) — 誰も参照していない。
   - `DESIGN_TOKENS_FMT` (escaped `{{ ... }}`、`format!()` 用) — 追加されたが
     consumer が居ない。
2. **`crates/ui/src/templates/chrome.rs`** の `BASE_CSS` は state token (`--success`,
   `--warning`, `--danger`, `--info` ほか) を独自に定義し、end-user UI のみで
   使われている (1,538 行 → 343 行に分割済 / RFC 098)。
3. **`crates/ui/src/admin/frame.rs`** (262 行),
   **`crates/ui/src/tenant_admin/frame.rs`** (231 行),
   **`crates/ui/src/tenancy_console/frame.rs`** (180 行) は依然として
   独自の inline CSS を持っている。RFC 082 で alias (`--success` etc.) を
   admin frame に部分導入したが、tenant_admin / tenancy_console は触っていない
   ため、admin console / tenancy console / tenant admin で色値の出どころが
   分散している。

これは PDF v0.50.1 page 12 の「色だけに依存しない状態表示」の前提条件
(同じ state token が画面横断で意味を保つ) を弱め、また dark mode override の
適用漏れを生む。

## Goal

1. CSS の color/state token を一箇所 (`design_tokens.rs::DESIGN_TOKENS_FMT`)
   に集約する。
2. admin / tenant_admin / tenancy_console の 3 frame は inline ハードコード値で
   はなく `DESIGN_TOKENS_FMT` を `format!()` 経由で展開して同じ tokens を共有する。
3. 未使用の raw `DESIGN_TOKENS` (escape 無しの方) を削除する。重複の出元を断つ。
4. admin console は ADR-013 上 JA-only のまま変更しない (色値だけの統合)。

明示的に out of scope:
- `BASE_CSS` の token 部分を `DESIGN_TOKENS_FMT` 由来に置き換える (end-user
  UI 側) — 別 RFC に切る価値がない場合は将来の cleanup として残す。本 RFC は
  3 admin frame の inline 重複の解消のみ。

## Design

### Token source

`crates/ui/src/design_tokens.rs::DESIGN_TOKENS_FMT` を **唯一の source of
truth** とする。中身は `:root {{ --success: …; --warning: …; --danger: …;
--info: …; --bg: …; --fg: …; --muted: …; --accent: …; }}` の escape 済み
バリアント。dark mode override (`@media (prefers-color-scheme: dark) {{ … }}`)
を同じ定数に含める。

`scope-system` / `scope-tenant` / `scope-tenancy` も同じ定数の中に置く
(RFC 016 / 073 で導入された scope badge 色)。これら 3 frame で意味の同じ
色を別 hex に取らないため。

### Frame integration

各 frame の inline `<style>` 内の token 定義 (現在 `:root { ... }` ハードコード)
を、`format!()` 内で `tokens = cesauth_ui::design_tokens::DESIGN_TOKENS_FMT`
として展開する。

例 (admin/frame.rs):

```rust
let html = format!(
    r##"<!doctype html>
<html lang="ja">
<head>
  <style nonce="{nonce}">
{tokens}
{rest_of_css}
  </style>
  ...
</head>
..."##,
    nonce  = render_nonce(),
    tokens = cesauth_ui::design_tokens::DESIGN_TOKENS_FMT,
    rest_of_css = ADMIN_CHROME_CSS,
);
```

`ADMIN_CHROME_CSS` は token を持たない (layout / typography / 個別要素の
スタイルのみ) ので、CSS 変数を参照するだけ。

### `DESIGN_TOKENS` 削除

`design_tokens.rs` から raw `DESIGN_TOKENS` 定数 (escape 無し) を物理削除。
`DESIGN_TOKENS_FMT` だけを残す。dead-code warning は RFC 101 で 0 を維持して
いるので、削除しないと再び warning が立つ。

## Implementation steps

1. `crates/ui/src/design_tokens.rs` を見直し:
   - `DESIGN_TOKENS_FMT` に scope token (`--scope-system`, `--scope-tenant`,
     `--scope-tenancy`) と dark mode override を含める。
   - raw `DESIGN_TOKENS` を削除。
2. `crates/ui/src/admin/frame.rs`: inline token block (`:root { ... }`) を
   削除し、`format!()` で `DESIGN_TOKENS_FMT` を埋め込む。エスケープ罠
   (HANDOFF §6) に注意: `{` は `{{` 必須。
3. `crates/ui/src/tenant_admin/frame.rs`: 同上。
4. `crates/ui/src/tenancy_console/frame.rs`: 同上。
5. 各 frame に rendering test を追加: `--success` / `--scope-system` などの
   token 文字列が HTML に含まれることを確認 (1 行アサーション × 3 frame)。
6. `cesauth_ui::tests` の visual regression テストで色値が以前と一致することを
   確認 (現在のテストが green を維持していれば十分)。

## Acceptance

- [ ] `cargo-1.91 test -p cesauth-ui` が green
- [ ] `cargo-1.91 test --workspace --lib` が green
- [ ] `cargo-1.91 build --workspace --target wasm32-unknown-unknown --release` が成功
- [ ] `grep -rn "color: #[0-9a-fA-F]" crates/ui/src/admin/ crates/ui/src/tenant_admin/ crates/ui/src/tenancy_console/` が空 (token 経由のみ)
- [ ] `grep -rn "DESIGN_TOKENS\b" crates/` が `DESIGN_TOKENS_FMT` のみマッチ
- [ ] 非 deprecated warnings = 0 (RFC 101 維持)
- [ ] EN + JA rendering で frame の HTML に `--success`, `--warning`, `--danger`,
      `--info`, `--scope-system`, `--scope-tenant`, `--scope-tenancy` token が
      存在する
- [ ] dark mode override (`@media (prefers-color-scheme: dark)`) が 3 frame の
      output に含まれる

## Test strategy

新規ユニットテスト (`crates/ui/src/admin/tests.rs`,
`crates/ui/src/tenant_admin/tests.rs`,
`crates/ui/src/tenancy_console/tests.rs`):

```rust
#[test]
fn admin_frame_uses_shared_design_tokens() {
    let html = admin::frame::frame("title", "<p>body</p>", /* ... */);
    assert!(html.contains("--success:"));
    assert!(html.contains("--scope-system:"));
    assert!(html.contains("@media (prefers-color-scheme: dark)"));
}
```

同型を 3 frame で並べる。これにより将来の inline 化逆戻りを invariant として
固定する (固定方針は RFC 開発指示書 v2-0.50.1 §テスト指針)。

## Migration / compatibility

- 後方互換性: 不要 (HANDOFF §制約事項 3)。
- スキーマ変更: 無し。
- wire / DO: 無し。
- 運用者向け: 視覚出力に微小な差分 (色値統一による) が出る可能性。CHANGELOG に
  「admin / tenant_admin / tenancy_console の色値が end-user UI と一致しました」
  と明記。

## Open questions

なし。
