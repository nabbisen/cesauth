# RFC 073 — Tenant admin scope badge 標準化

**Status**: Implemented  
**Tier**: P0  
**Size**: Small  
**Target**: v0.62.0  
**Phase**: Consistency  
**Refs**: G8 (gap analysis), RFC 016 (system admin scope badge)

## Problem

PDF: "admin scope badge の標準化"

System admin の scope badge は RFC 016 で標準化済み:
- CSS class: `scope-badge scope-system`
- 配置: header 右上
- ARIA: `aria-label` で操作範囲を読み上げ
- 4 ロケールラベル: `lookup(SystemScopeBadge, locale)`

一方 tenant admin の `crates/ui/src/tenant_admin/frame.rs` には:
- `.scope-badge` CSS は定義済み (`scope-badge { font-size: 0.75em; padding: 2px 8px; ... }`)
- しかし HTML に `class="{scope_class}"` を埋めているだけで、`scope-tenant` クラスが
  独立した CSS rule を持っていない
- `scope.css_class()` の返却値が `scope-system` と `scope-tenant` を整合的に出して
  いるかの検証テストが System admin 側にしかない

PDF が要求するのは **"システム / テナント / オペレーターを画面で混ぜない"** こと。
スコープバッジは tenant 越境操作を視覚的に防ぐ最後の安全装置であり、両者で
スタイル・命名規則・テストを揃える必要がある。

## Goal

1. System admin と tenant admin の scope-badge について、**class 命名規則、HTML 構造、
   ARIA label、locale 別ラベルを完全に一致させる**。
2. 両 frame について、scope-badge が描画されることを assertion するテストを追加する。
3. CSS 色は system (赤系) ≠ tenant (青系) で視覚的に区別し続ける (誤認防止)。

## Design

### 標準化された scope-badge 仕様

```html
<!-- System admin -->
<span class="scope-badge scope-system"
      role="status"
      aria-label="システム管理スコープ">SYSTEM</span>

<!-- Tenant admin -->
<span class="scope-badge scope-tenant"
      role="status"
      aria-label="テナント管理スコープ">TENANT</span>
```

### CSS

両 frame の `<style>` に同じ rule set:

```css
.scope-badge {
  font-size: 0.75em;
  padding: 2px 8px;
  border-radius: 10px;
  font-weight: 500;
  border: 1px solid rgba(255,255,255,0.5);
  color: #fff;
  letter-spacing: 0.05em;
}
.scope-system { background: #c0392b; }  /* red — system */
.scope-tenant { background: #2980b9; }  /* blue — tenant */
```

(現状の system frame に `.scope-system` 色が CSS variable で定義されているなら
そちらに合わせる。RFC 016 の選定を尊重する。)

### Locale ラベル

`MessageKey::ScopeSystemLabel` / `ScopeTenantLabel` を用意済み (RFC 016)。
tenant admin frame も `lookup()` 経由で同じ catalog を引く。

### admin scope module の re-use

`crates/core/src/admin/scope.rs` の `Scope` enum を tenant admin frame でも
利用するか、tenant 専用 enum を作るか。**前者を採る** — 統合された scope
表現で `Scope::System` と `Scope::Tenant { slug }` を共通的に扱う。

## Implementation steps

1. `crates/core/src/admin/scope.rs` の `Scope` enum に `Tenant { slug }` バリアントが
   既に存在することを確認 (RFC 016 で予定済み)。なければ追加。
2. `tenant_admin/frame.rs` の header HTML を上記の標準形に変更。`scope-tenant`
   class を明示的に発行する。
3. `tenant_admin/frame.rs` の CSS に `.scope-system` / `.scope-tenant` の色 rule
   を `admin/frame.rs` から複写 (今後の集約は別 RFC で扱う)。
4. テスト追加: `tenant_admin_frame_renders_scope_badge_with_correct_class`,
   `tenant_admin_scope_badge_label_ja_default`, `tenant_admin_scope_badge_aria_label`

## Acceptance

- [ ] tenant admin frame の HTML 出力に `<span class="scope-badge scope-tenant" ...>` が含まれる
- [ ] tenant admin frame の `aria-label` に「テナント管理スコープ」が出る (JA)
- [ ] tenant admin frame の `aria-label` に「Tenant admin scope」が出る (EN)
  — ただし admin は JA-only ポリシーなので**当面 JA のみ**
- [ ] 全テストスイート green

## Test plan

- `tenant_admin_frame_renders_scope_badge_with_correct_class` (new)
- `tenant_admin_scope_badge_label_matches_system_pattern` (new — pattern parity)
- 既存の system admin scope badge テストはそのまま維持
