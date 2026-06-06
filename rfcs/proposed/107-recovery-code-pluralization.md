# RFC 107 — Recovery code pluralization (ADR-013 §Q4 closure)

**Status**: Proposed  
**Tier**: P2  
**Size**: Small  
**Target**: v0.71.0  
**Phase**: i18n completeness (finishing track)  
**Refs**: ADR-013 §Q4 ("pluralization deferred until a real string demands it") / PDF v0.50.1 page 12 "i18n contract: date / plural は未解決として扱う" / RFC 106

## Problem

ADR-013 §Q4 は cesauth の i18n 設計から **複数形 (plural)** を意図的に
deferred としていた:

> Pluralization is deferred until a real string demands it.

v0.66.0 時点で plural を実際に要求している唯一の visible string は
recovery code 残数表示:

- EN: `Recovery codes: 0 valid` / `Recovery codes: 1 valid` / `Recovery codes: 5 valid`
- JA: `リカバリーコード: 0 個有効` / `リカバリーコード: 1 個有効` / `リカバリーコード: 5 個有効`

JA は助数詞 (`個`) と数字の語順が plural-invariant なので問題が見えにくいが、
EN は文法上 N=1 のとき `1 valid recovery code` のような単数形を期待する
読み手が存在する。CLDR plural rules では EN は `one` / `other` の 2 カテゴリ。

RFC 106 は template literal (`{n}`) 置換で catalog 化したが、これは
plural の問題を **回避しただけ** で解いていない。本 RFC で正式な決着を付ける。

## Goal

1. ADR-013 §Q4 を `Resolved in v0.71.0` でクローズする。
2. recovery code 残数表示について plural-aware なレンダリングを提供する。
3. cesauth 全体で再利用可能な plural-form 関数のシグネチャを `cesauth-core::i18n`
   に置く (将来 sessions count 等で再利用できる土台)。
4. `icu` / `unic-langid` などの大型 crate を **導入しない** (WASM size budget
   と既存の closed-enum 設計方針に反する)。

明示的に out of scope:
- ICU MessageFormat の完全実装 (`{count, plural, one {…} other {…}}`)。
- ロケール横断の date/time formatting (RFC 111)。
- 数字フォーマット (1,000 / 1.000 などの区切り) — 該当ケース無し。

## Design

### Plural function

`cesauth_core::i18n` に最小 plural ヘルパを追加:

```rust
/// Pick a plural variant for an integer count. Returns the catalog
/// category that the catalog lookup should use for this locale.
///
/// This is a deliberately small implementation matching CLDR cardinal
/// rules for cesauth's currently-supported locales:
///
/// - JA: every count maps to `Other` (Japanese has no morphological
///   plural; CLDR pluralRules calls this "no plural form").
/// - EN: `1` → `One`; everything else → `Other` (CLDR EN rules).
pub enum Plural { One, Other }

pub fn plural_for(locale: Locale, n: u64) -> Plural { ... }
```

このアプローチは:
- closed enum (新規 plural category 追加時はコンパイル時に網羅性が要求される)。
- runtime parsing 無し (open string rule 不採用)。
- 将来 `Few` / `Many` 等が必要な locale (PL, RU など) を追加するときは
  variant 追加 + match 強制 + テストで全 locale カバレッジ確認。

### Catalog 設計

`MessageKey` を **plural variant ごとに別 key にしない**。代わりに既存の
`SecurityRecoveryRemaining` を保ち、それに対する EN の翻訳を 1 個用 / 複数用 で
別 key として持つことも避ける。代案: catalog entry の値型を拡張し、
plural-aware lookup を提供する。

二つの選択肢を検討し、本 RFC は (B) を採る:

(A) **MessageKey を pluralized variant に分ける** — 例:
  `SecurityRecoveryRemainingOne`, `SecurityRecoveryRemainingOther`。
  メリット: 既存の `lookup() -> &'static str` シグネチャを保つ。
  デメリット: key 数が `N × (plural form 数)` で増える。

(B) **plural-aware lookup 関数を追加** — 例:
  ```rust
  pub fn lookup_plural(key: MessageKey, locale: Locale, n: u64) -> &'static str
  ```
  と、catalog の対応 entry を 1-tuple ではなく `&[(Plural, &'static str)]`
  で持つ。`lookup()` は default plural (`Other`) を返す。
  メリット: key 数を増やさない。 既存呼び出しを壊さない。
  デメリット: catalog entry の値型が一段複雑化する。

(B) は cesauth の closed-enum 設計と整合し、plural を「メッセージのデータ次元」
として扱える。i18n module は RFC 097 で sub-module 分割済なので、plural-aware
entry はその中の対応 sub-module 内に閉じる。

### Template 修正

`security_center.rs::recovery_status_html_for`:

```rust
let plural = cesauth_core::i18n::plural_for(locale, n as u64);
let template = lookup_plural(MessageKey::SecurityRecoveryRemaining, locale, n as u64);
let label = template.replace("{n}", &n.to_string());
```

## Implementation steps

1. `cesauth_core::i18n` に `Plural` enum + `plural_for` を実装。
2. `crates/core/src/i18n/mod.rs` (またはサブモジュール) に `lookup_plural`
   を追加。実装は `lookup_*` 系と同じ exhaustive-match パターン。
3. `MessageKey::SecurityRecoveryRemaining` の catalog entry を plural variant
   2 個 (`One`, `Other`) に拡張:
   - EN One: `1 valid recovery code`
   - EN Other: `{n} valid recovery codes`
   - JA One: `リカバリーコード: {n} 個有効` (JA は plural 不変)
   - JA Other: `リカバリーコード: {n} 個有効`
4. `security_center.rs` の N≥2 path を `lookup_plural` 経由に変更。
   (N=0, N=1 は固定文の banner なので RFC 106 のまま影響無し。)
5. `crates/core/src/i18n/tests.rs` に plural exhaustiveness テスト追加:
   全 `MessageKey` が plural-aware か否かをコンパイル時に判定する仕組み
   (例: `enum MessageEntry { Single(LocaleMap), Plural(LocaleMap × Plural)}` で
   match 強制)。
6. ADR-013 §Q4 を `~~取消線~~` + `**Resolved in v0.71.0.**` で更新。

## Acceptance

- [ ] `cargo-1.91 test --workspace --lib` が green
- [ ] `plural_for(Locale::En, 1)` が `Plural::One` を返す
- [ ] `plural_for(Locale::En, 0)` が `Plural::Other` (EN は zero も other)
- [ ] `plural_for(Locale::En, 5)` が `Plural::Other`
- [ ] `plural_for(Locale::Ja, _)` が常に `Plural::Other`
- [ ] EN locale で N=1 の recovery 表示が `Recovery codes: 1 remaining.` 形式
  (現状の N=1 専用 banner と本 RFC 範囲外 — N=1 は RFC 106 の固定文 banner)。
  本 RFC は N≥2 範囲を改良する。
- [ ] EN locale で N=5 の recovery 表示が `5 valid recovery codes` 形式
- [ ] JA は前後で文字列が変わらない (回帰しない)
- [ ] ADR-013 §Q4 が `Resolved` でマーク済
- [ ] 非 deprecated warnings = 0

## Test strategy

```rust
#[test]
fn plural_for_en_handles_one_and_other() {
    assert_eq!(plural_for(Locale::En, 0), Plural::Other);
    assert_eq!(plural_for(Locale::En, 1), Plural::One);
    assert_eq!(plural_for(Locale::En, 2), Plural::Other);
    assert_eq!(plural_for(Locale::En, 100), Plural::Other);
}

#[test]
fn plural_for_ja_is_always_other() {
    for n in [0u64, 1, 2, 5, 100] {
        assert_eq!(plural_for(Locale::Ja, n), Plural::Other);
    }
}

#[test]
fn recovery_remaining_uses_plural_en() {
    let state = SecurityCenterState { recovery_codes_remaining: 5, totp_enabled: true, .. };
    let html = security_center_page_for(&state, "", Locale::En);
    assert!(html.contains("5 valid recovery codes"));
}
```

## Migration / compatibility

- 後方互換性: 不要。
- スキーマ変更: 無し。
- wire / DO: 無し。
- 運用者向け: EN ユーザー視点で recovery 残数表示が grammar-correct になる。
  JA は不変。CHANGELOG に ADR-013 §Q4 closure を明記。

## Open questions

なし。
