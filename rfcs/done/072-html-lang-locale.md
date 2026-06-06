# RFC 072 — `<html lang>` attribute locale binding

**Status**: Implemented  
**Tier**: P0  
**Size**: Small  
**Target**: v0.62.0  
**Phase**: Accessibility correctness  
**Refs**: G7 (gap analysis)

## Problem

すべての end-user UI ページが `<html lang="en">` をハードコードしている。
Locale が `Locale::Ja` のときも `lang="en"` のままで、これは:

1. **スクリーンリーダーの言語切替が誤動作する** — 日本語コンテンツを英語の音素で
   読み上げる。WCAG 3.1.1 (Language of Page) 違反。
2. ブラウザの自動翻訳挙動が誤検出する可能性。
3. PDF i18n contract "End-user UI は JA / EN" の実装責任を半分しか果たしていない
   (テキストは i18n、属性はハードコード)。

## Goal

`Locale` → `lang` 属性 BCP 47 タグへのマッピングを定義し、全 end-user
テンプレートで適用する。

| Locale | lang attribute |
|---|---|
| `Locale::Ja` | `ja` |
| `Locale::En` | `en` |

## Design

### API 追加

`cesauth_core::i18n::Locale` に `bcp47()` メソッドを追加:

```rust
impl Locale {
    /// BCP 47 language tag for this locale.
    /// Used for `<html lang>` and `lang=` attributes.
    pub const fn bcp47(self) -> &'static str {
        match self {
            Locale::Ja => "ja",
            Locale::En => "en",
        }
    }
}
```

### テンプレート側の修正

`crates/ui/src/templates.rs` の `frame_with_flash()` 内で:

```rust
<html lang="{lang}">
// →
lang = locale.bcp47(),
```

`frame_with_flash` の signature を `(title, flash_html, body)` から
`(title, flash_html, body, locale)` に拡張。

すべての end-user テンプレート (`login_page_for`, `security_center_page_for`,
`sessions_page_for`, `totp_*_page_for`, `magic_link_sent_page_for`,
`totp_recovery_codes_page_for`, `totp_verify_page_for`, `totp_disable_confirm_page_for`,
`error_page_for`) は既に `locale` を受け取っているので、`frame_with_flash` への
pass-through を追加するだけで対応できる。

shorthand 版 (`login_page`, `security_center_page` 等) は内部で `_for` を
`Locale::default()` で呼ぶので変更不要。

### Admin console

PDF の i18n contract: **"admin console は当面 JA-only"**

したがって `admin/frame.rs` と `tenant_admin/frame.rs`、`tenancy_console/frame.rs`
は `<html lang="ja">` で固定。これは構造的なポリシーであり、Locale パラメータを
ここに流す必要はない (今後変更されるなら別 RFC で扱う)。

## Implementation steps

1. `crates/core/src/i18n.rs` に `Locale::bcp47()` を追加。
2. `crates/ui/src/templates.rs` の `frame_with_flash` に `locale` 引数を追加し、
   `<html lang="{locale.bcp47()}">` に。
3. 各 `*_page_for` 関数で `frame_with_flash(..., locale)` を呼ぶように更新。
4. admin 系の 3 frame は `<html lang="en">` → `<html lang="ja">` に変更
   (admin は JA-only という constitution を遵守)。
5. テスト追加。

## Acceptance

- [ ] `Locale::Ja.bcp47() == "ja"` / `Locale::En.bcp47() == "en"`
- [ ] `login_page_for(.., Locale::Ja)` の HTML が `<html lang="ja">` を含む
- [ ] `login_page_for(.., Locale::En)` の HTML が `<html lang="en">` を含む
- [ ] admin 系 frame は常に `<html lang="ja">` (JA-only ポリシー反映)
- [ ] 全テストスイート green

## Test plan

- `bcp47_returns_correct_tag` (unit, in i18n.rs)
- `frame_with_flash_html_lang_attribute_follows_locale` (template tests)
- `login_page_ja_uses_lang_ja` / `login_page_en_uses_lang_en`
- `admin_frame_uses_lang_ja_unconditionally` (admin always JA)

## Backward compatibility

`frame_with_flash` は private なので外部 API breakage なし。
shorthand `*_page` 関数は signature 変更なし。
