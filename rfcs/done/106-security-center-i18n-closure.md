# RFC 106 — Security Center i18n closure (TOTP enabled / disable / recovery banners)

**Status**: Implemented (v0.67.0)  
**Tier**: P1  
**Size**: Small  
**Target**: v0.67.0  
**Phase**: i18n completeness (finishing track)  
**Refs**: PDF v0.50.1 page 6 "Self-service" / page 12 "i18n contract" / 開発指示書 v2-0.50.1 §多言語対応 "多言語化していないテンプレートを残さない" / RFC 097 (i18n module split)

## Problem

`crates/ui/src/templates/security_center.rs` には依然として **JA ハードコード文字列**
が残っている。具体的には以下:

| 位置 | 文字列 | 状態 |
|---|---|---|
| L274–289 (enabled-state TOTP section) | `有効` (badge), `TOTP を無効化する` (link) | hardcoded JA |
| L304–310 (recovery N=0 banner) | `リカバリーコード残なし。authenticator を失うと管理者連絡が必要です。` | hardcoded JA |
| L312–319 (recovery N=1 banner) | `リカバリーコード: 残り 1 個。…TOTP を一度無効化して再 enroll すると 10 個に戻せます。` | hardcoded JA |
| L322–327 (recovery N≥2 badge) | `リカバリーコード: {n} 個有効` | hardcoded JA template |

これは PDF v0.50.1 page 12 の i18n contract:

> End-user UI は JA / EN

および 開発指示書 v2-0.50.1:

> 多言語化していないテンプレートを残さない。新しい end-user テンプレートは
> 最初から `_for(.., locale)` 版で書き、shorthand を `Locale::default()` 経由
> にする

の両方に違反している。

`security_center.rs` 上部 (`security_center_page_for`) と
`totp_section_html_for` の disabled-state は v0.39.0 以降 i18n 化されているが、
enabled-state は当時「`有効`/recovery 文言は plural-form 議論があるため deferred」
として残された (ADR-013 §Q4 と source code comment 参照)。

本 RFC は plural form の議論を切り離し、**現状の単数固定文を catalog 化** することで
i18n hole を閉じる。N=2..9 の `{n} 個有効` のような可算文字列の
複数形ルールは RFC 107 (recovery pluralization closure) に分離する。

## Goal

1. `security_center.rs` の hardcoded JA を `MessageKey` カタログ経由に置き換える。
2. EN ロケールの文字列を i18n catalog に追加する。
3. 「N=1 と N=0 の banner」「`有効` バッジ」「`TOTP を無効化する` link」
   の 4 種は plural の問題が無い (固定文 / 数値置換のみ) ので、本 RFC で完結。
4. N≥2 の `{n} 個有効` 表示は本 RFC では template literal (`{n}` 置換) のまま
   catalog 化する。本格的な複数形対応は RFC 107 に任せる。

明示的に out of scope:
- 複数形 (1 個 vs 2 個 vs many) の言語学的に正しい複数化ルール → RFC 107。
- 日付・時刻のロケール対応 → RFC 111。
- admin console の i18n → ADR-013 (JA-only 継続)。

## Design

### 新規 MessageKey

`crates/core/src/i18n/mod.rs` の `MessageKey` enum に以下を追加し、
`crates/core/src/i18n/end_user.rs` (or sub-module per RFC 097 split) に
JA / EN を実装:

| MessageKey | JA | EN |
|---|---|---|
| `SecurityTotpEnabledBadge` | `有効` | `Enabled` |
| `SecurityTotpDisableLink` | `TOTP を無効化する` | `Disable TOTP` |
| `SecurityRecoveryZeroTitle` | `リカバリーコード残なし。` | `No recovery codes remaining.` |
| `SecurityRecoveryZeroDetail` | `authenticator を失うと管理者連絡が必要です。` | `Losing your authenticator will require operator contact.` |
| `SecurityRecoveryOneTitle` | `リカバリーコード: 残り 1 個。` | `Recovery codes: 1 remaining.` |
| `SecurityRecoveryOneDetail` | `次に authenticator を失うと管理者連絡が必要になります。TOTP を一度無効化して再 enroll すると 10 個に戻せます。` | `If you lose your authenticator next, operator contact is required. Disable TOTP and re-enroll to refresh to 10 codes.` |
| `SecurityRecoveryRemaining` | `リカバリーコード: {n} 個有効` | `Recovery codes: {n} valid` |

### Template 移行

`recovery_status_html(n: u32, locale: Locale) -> String` にシグネチャを変更し、
`render_session_row_for` 等と同じパターンで catalog 経由にする。
3-tier (N=0 / N=1 / N≥2) のロジックはそのまま。

`totp_section_html_for(enabled, recovery_remaining, locale)` の enabled-state
path で `SecurityTotpEnabledBadge` と `SecurityTotpDisableLink` を参照する。

`anchor` (link href: `/me/security/totp/disable`) は触らない (URL は本 RFC 外)。
RFC 108 で `routes::*` 経由に統一する。

### MessageKey 追加時の注意

HANDOFF §6 の "i18n の legitimate_duplicate whitelist" を要確認:
`Enabled` (EN) と RFC 075 で追加した `SecuritySummaryTotpEnabled` (EN: `TOTP enabled`) は
**文字列が重複していない** (`Enabled` vs `TOTP enabled`) ので whitelist 追加不要。
JA `有効` は短すぎる単独語で、おそらく既存の `Enabled` 系 key (admin の OIDC client
status `enabled` など) と衝突する可能性がある。実装時に
`i18n/tests.rs::no_two_keys_share_text_within_a_locale` が落ちたら、`is_legitimate_duplicate()` に
`("有効", &["SecurityTotpEnabledBadge", "...別 key 名..."])` を追加する。

## Implementation steps

1. `crates/core/src/i18n/mod.rs` に `MessageKey` の 7 つの variant 追加。
2. `crates/core/src/i18n/end_user.rs` (RFC 097 で sub-module 化済) に
   JA / EN 各 7 文字列を実装。
3. `crates/core/src/i18n/tests.rs` の exhaustiveness テストが新規 key を要求するので、
   `for_each_key` に分岐追加。
4. `crates/ui/src/templates/security_center.rs::recovery_status_html` を
   `recovery_status_html_for(n, locale)` に書き換え、JA hardcode を catalog 経由に。
5. `totp_section_html_for` enabled-state の hardcoded 部を catalog 経由に。
6. `crates/ui/src/templates/tests.rs` (1,913 行) に EN / JA レンダリングテストを追加。
   各 N=0, 1, 5 で各 locale の出力が正しい catalog 文字列を含むことを確認。
7. `i18n/tests.rs::no_two_keys_share_text_within_a_locale` が落ちた場合、
   `is_legitimate_duplicate()` whitelist を更新。

## Acceptance

- [ ] `cargo-1.91 test --workspace --lib` が green
- [ ] `cargo-1.91 build --workspace --target wasm32-unknown-unknown --release` が成功
- [ ] `grep -n "有効\|TOTP を無効化\|リカバリーコード" crates/ui/src/templates/security_center.rs` が
      空 (catalog 経由のみ)
- [ ] EN locale で `/me/security` を render すると上記 7 文字列の EN 翻訳が出る
- [ ] JA locale で render すると以前と同じ JA 文字列が出る
- [ ] MessageKey 数: 145 → 152 (+7)
- [ ] 非 deprecated warnings = 0

## Test strategy

`crates/ui/src/templates/tests.rs` に以下を追加:

```rust
#[test]
fn security_center_recovery_zero_uses_catalog_ja() {
    let state = SecurityCenterState { recovery_codes_remaining: 0, totp_enabled: true, .. };
    let html = security_center_page_for(&state, "", Locale::Ja);
    assert!(html.contains("リカバリーコード残なし。"));
    assert!(html.contains("flash--danger"));
}

#[test]
fn security_center_recovery_zero_uses_catalog_en() {
    let state = SecurityCenterState { recovery_codes_remaining: 0, totp_enabled: true, .. };
    let html = security_center_page_for(&state, "", Locale::En);
    assert!(html.contains("No recovery codes remaining."));
    assert!(!html.contains("リカバリーコード"));   // no JA leakage
}
```

各 N=0, 1, 5 × 2 locale = 6 ケース。enabled badge と disable link で 2 × 2 = 4 ケース。
合計 +10 テスト。

## Migration / compatibility

- 後方互換性: 不要。
- スキーマ変更: 無し。
- wire / DO: 無し。
- 運用者向け: EN ユーザーは初めて Security Center の TOTP/Recovery 周りで
  自国語表示を見ることになる。CHANGELOG にその旨記載。

## Open questions

なし (plural form は本 RFC では template literal のままにする方針で確定。
複数形対応は RFC 107)。
