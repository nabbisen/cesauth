# RFC 077 — Skip-to-content link (WCAG 2.4.1)

**Status**: Implemented  
**Tier**: P1  
**Size**: Small  
**Target**: v0.62.0  
**Phase**: Accessibility  
**Refs**: G6 (gap analysis), WCAG 2.4.1 (Bypass Blocks, Level A)

## Problem

WCAG 2.4.1 (Bypass Blocks, Level A) は、複数のページにまたがる繰り返しコンテンツ
(header, navigation) を**バイパスする手段**をキーボードユーザーに提供することを
要求する。

最も一般的な実装は **"Skip to main content" リンク** で、Tab キー押下時に最初に
focus を受け取り、そのリンクから `<main>` 要素に直接ジャンプできる。

現状の cesauth UI には skip link が存在しない。PDF "Accessible by default" /
ABDD criteria の核心であり、対応が必要。

## Goal

すべての end-user UI フレームと admin フレームに **"Skip to main content"
リンク**を追加する:

- 視覚的には**非表示** (`.visually-hidden`)
- **focus を受けたとき** (Tab で到達) は可視化される
- リンク先は `#main`
- locale 対応 (JA: "メインコンテンツへスキップ" / EN: "Skip to main content")

## Design

### HTML 構造

`<body>` の直後、`<header>` の前に:

```html
<body>
  <a href="#main" class="skip-link">{skip_to_main_text}</a>
  <header>...</header>
  <main id="main">...</main>
</body>
```

`<main>` 要素には `id="main"` 属性を追加する (アンカーターゲット)。

### CSS

`.skip-link` rule:

```css
.skip-link {
  position: absolute;
  top: -100px;
  left: 0;
  padding: 0.5rem 1rem;
  background: var(--bg);
  color: var(--accent);
  text-decoration: underline;
  z-index: 1000;
  transition: top 0.2s ease-in-out;
}
.skip-link:focus {
  top: 0;
  outline: 2px solid var(--accent);
  outline-offset: 2px;
}
```

通常は画面外 (`top: -100px`)、focus 時に画面内 (`top: 0`) にスライドイン。

### MessageKey 追加

```rust
SkipToMainContent, // "メインコンテンツへスキップ" / "Skip to main content"
```

### admin frame の対応

admin frame (`admin/frame.rs`) と `tenant_admin/frame.rs`、
`tenancy_console/frame.rs` も同様に skip link を追加する。

admin は JA-only policy なので、admin 系では JA テキストを直接埋め込む
(MessageKey lookup は使うが locale 引数は `Locale::Ja` 固定):

```rust
let skip_text = lookup(MessageKey::SkipToMainContent, Locale::Ja);
```

### End-user templates

`templates.rs::frame_with_flash` を修正:

```rust
let skip_text = escape(lookup(MessageKey::SkipToMainContent, locale));
// ...
<body>
  <a href="#main" class="skip-link">{skip_text}</a>
  <main id="main">
    {flash}
    {body}
  </main>
  ...
```

`<main>` に `id="main"` を追加することを忘れない。

## Implementation steps

1. `MessageKey::SkipToMainContent` を追加 + JA/EN 翻訳。
2. End-user `frame_with_flash` に skip-link 挿入 + `<main id="main">` に変更。
3. End-user `BASE_CSS` に `.skip-link` rule 追加。
4. Admin (`admin/frame.rs`, `tenant_admin/frame.rs`, `tenancy_console/frame.rs`)
   に skip-link 挿入 + `<main id="main">` に変更。
5. Admin CSS にも `.skip-link` rule を追加 (重複だが locale 分離の都合)。
6. テスト追加。

## Acceptance

- [ ] 全 frame の HTML に `<a href="#main" class="skip-link">` が含まれる
- [ ] 全 frame の `<main>` に `id="main"` 属性がある
- [ ] CSS で `.skip-link:focus` が可視化される
- [ ] JA locale で "メインコンテンツへスキップ" が出る
- [ ] EN locale で "Skip to main content" が出る (end-user のみ; admin は JA only)
- [ ] 全テストスイート green

## Test plan

- `end_user_frame_has_skip_link` (JA + EN)
- `end_user_frame_main_has_id_main`
- `admin_frame_has_skip_link` (JA only)
- `tenant_admin_frame_has_skip_link`
- `tenancy_console_frame_has_skip_link`
- CSS: `.skip-link:focus` rule の存在テスト

## Risks / Notes

- スタイル衝突: `position: absolute` で他要素の position に依存しないため、
  既存 layout への影響は無いはず。
- `id="main"` の重複: 1 ページに 1 つの `<main>` のみなので問題なし。
  template engine が `<main>` を複数 emit しないか確認が必要 (検査)。
