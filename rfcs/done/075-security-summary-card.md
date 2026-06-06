# RFC 075 — Security Center mobile state summary card

**Status**: Implemented  
**Tier**: P1  
**Size**: Medium  
**Target**: v0.62.0  
**Phase**: UX completeness  
**Refs**: G1 (gap analysis), PDF "Mobile-first state model" / "Security Center: Status summary"

## Problem

PDF design (overview onepage, mobile-first state model panel) は、
`/me/security` 上部に**4 つの状態を一覧できる summary card** を配置することを
要求している:

```
9:41
cesauth
[Passkey OK]
[TOTP enabled]
[Recovery: 8]
[Sessions: 2]
```

現状の `security_center_page_for(state, flash_html, locale)` が受け取る
`SecurityCenterState` は:

```rust
pub struct SecurityCenterState {
    pub primary_method:           PrimaryAuthMethod,
    pub totp_enabled:             bool,
    pub recovery_codes_remaining: u32,
}
```

**`active_sessions_count` が無い**。Sessions 状態は別ページに行かないと見えない。
PDF mobile-first state model の意図は「重要状態を一画面で把握させる」ことなので、
この欠落は acceptance gap である。

加えて、現状の Security Center HTML はバッジ群ではなく**節 (section) 構造**で
状態を提示しており、モバイルの視覚パッと見の優先度が低い。

## Goal

1. `SecurityCenterState` に `active_sessions_count: u32` を追加する。
2. ページ上部に **summary card** (バッジ + ラベル + 数値の集合) を配置する。
3. summary card は色だけに依存せず、テキスト・アイコン併用 (WCAG 1.4.1 遵守)。
4. summary card は既存の細分セクション (Primary / TOTP / Sessions) と
   重複しない (バッジは「指標」、節は「操作入口」)。

## Design

### Data model 変更

```rust
// crates/ui/src/templates.rs

pub struct SecurityCenterState {
    pub primary_method:           PrimaryAuthMethod,
    pub totp_enabled:             bool,
    pub recovery_codes_remaining: u32,
    /// **v0.62.0 (RFC 075)** — active sessions count for the
    /// current user. Computed by the worker handler via
    /// `SessionStore::list_for_user(user_id).await?.len()`.
    /// 0 is a valid value (current session may not yet appear
    /// in the index, depending on session-index drift state).
    pub active_sessions_count:    u32,
}
```

### Worker handler 変更

`crates/worker/src/routes/me_security/index.rs` (またはあるべき場所) で:

```rust
let session_index_repo = ... // existing session store
let active_sessions = session_index_repo.list_for_user(&user.id).await.unwrap_or_default();
let state = SecurityCenterState {
    primary_method:           ...,
    totp_enabled:             ...,
    recovery_codes_remaining: ...,
    active_sessions_count:    active_sessions.len() as u32,
};
```

### MessageKey 追加

```rust
// crates/core/src/i18n.rs

// --- v0.62.0 (RFC 075): mobile state summary card ---
SecuritySummaryHeading,            // "状態サマリ" / "At a glance"
SecuritySummaryPasskeyOk,          // "パスキー設定済み" / "Passkey OK"
SecuritySummaryPasskeyAnonymous,   // "ログイン未完了" / "Not signed in"
SecuritySummaryPasskeyMagicLink,   // "メールリンク認証" / "Magic Link"
SecuritySummaryTotpEnabled,        // "TOTP 有効" / "TOTP enabled"
SecuritySummaryTotpDisabled,       // "TOTP 未設定" / "TOTP off"
SecuritySummaryRecoveryRemaining,  // "リカバリーコード {n} 残" / "Recovery: {n}"
SecuritySummarySessions,           // "セッション {n}" / "Sessions: {n}"
```

PDF i18n contract: closed enum なので JA/EN すべて埋める。

注: pluralization は ADR-013 §Q4 で未解決のため、`recovery_codes_remaining = 0`
の場合だけ別キー (`SecuritySummaryRecoveryNone`) を用意するか、`{n} 残` で
0 を許容する。本 RFC では後者を採る (`0 残` でも文法的に成立する JA、
"Recovery: 0" で成立する EN)。

### HTML 構造

```html
<section class="security-summary" aria-labelledby="summary-heading">
  <h2 id="summary-heading" class="visually-hidden">{summary_heading}</h2>
  <ul class="badges">
    <li>
      <span class="badge badge--{passkey_token}">
        <span class="badge__icon" aria-hidden="true">{passkey_icon}</span>
        <span class="badge__text">{passkey_label}</span>
      </span>
    </li>
    <li>
      <span class="badge badge--{totp_token}">
        <span class="badge__icon" aria-hidden="true">{totp_icon}</span>
        <span class="badge__text">{totp_label}</span>
      </span>
    </li>
    <li>
      <span class="badge badge--{recovery_token}">
        <span class="badge__icon" aria-hidden="true">{recovery_icon}</span>
        <span class="badge__text">{recovery_label}</span>
      </span>
    </li>
    <li>
      <span class="badge badge--info">
        <span class="badge__icon" aria-hidden="true">▣</span>
        <span class="badge__text">{sessions_label}</span>
      </span>
    </li>
  </ul>
</section>
```

### Token mapping (色 + アイコン)

| State | Token | Icon | Label |
|---|---|---|---|
| Passkey set | success | ✓ | パスキー設定済み |
| Anonymous | info | · | ログイン未完了 |
| Magic Link only | warning | ◇ | メールリンク認証 |
| TOTP enabled | success | ✓ | TOTP 有効 |
| TOTP disabled | warning | △ | TOTP 未設定 |
| Recovery ≥ 3 | success | ✓ | リカバリーコード N 残 |
| Recovery 1-2 | warning | △ | リカバリーコード N 残 |
| Recovery 0 | danger | ✗ | リカバリーコード 0 残 |
| Sessions | info | ▣ | セッション N |

**色のみで意味伝達しない**: 各バッジは「アイコン + テキスト」を必ず持つ。
WCAG 1.4.1 (Use of Color)、SC 1.3.1 (Info and Relationships) 遵守。

### CSS

既存 `.badge--success/--warning/--danger/--info` を流用。新規追加は不要。
`.security-summary .badges` のレイアウト rule のみ追加 (flex-wrap で
モバイル時は折返し):

```css
.security-summary .badges {
  list-style: none;
  padding: 0;
  margin: 0 0 1.5rem;
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}
```

## Implementation steps

1. **Core**: `MessageKey` に 8 個追加。`i18n.rs` の JA/EN 翻訳 enum match を更新。
2. **UI**: `SecurityCenterState` に `active_sessions_count` を追加。
   既存の利用箇所はデフォルト値 0 で update。
3. **UI**: `security_center_page_for()` の冒頭に summary card HTML を組み立てて挿入。
4. **CSS**: `.security-summary .badges` rule を追加。
5. **Worker**: `/me/security` handler でセッション数を取得し state に含める。
6. **テスト**:
   - `security_center_summary_has_four_badges` (JA, EN 両方)
   - `security_center_recovery_zero_uses_danger_badge`
   - `security_center_recovery_high_uses_success_badge`
   - `security_center_summary_each_badge_has_icon_and_text` (no color-only check)

## Acceptance

- [ ] `/me/security` HTML に `.security-summary` セクションが存在
- [ ] 4 バッジ (Passkey / TOTP / Recovery / Sessions) が表示される
- [ ] 各バッジに icon + text の両方が含まれる
- [ ] Recovery 残数 0 のとき `badge--danger` クラスが付く
- [ ] JA / EN 両方の rendering test が pass
- [ ] WCAG 1.4.1 を violate しない (color-only にしない) ことの assertion
- [ ] 全テストスイート green

## Data flow

```
SessionIndexRepository::list_for_user(user_id)
  → Vec<SessionIndexRow>
    .len() as u32
      → SecurityCenterState::active_sessions_count
        → security_center_page_for()
          → HTML <span class="badge badge--info">セッション {n}</span>
```

## Risks / Open questions

- セッション数取得が失敗した場合 (DO 不通など): summary card は **0** を表示せず、
  バッジ自体を non-render (skip) する。詳細表示は `/me/security/sessions` で。
- recovery_codes_remaining の境界値 (3 を success/warning の境にする) は
  ADR-009 とは独立に決められる。3 は経験則。将来調整可。
