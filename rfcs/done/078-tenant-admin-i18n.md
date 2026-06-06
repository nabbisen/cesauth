# RFC 078 — Tenant admin UI ページの i18n 化と JA/EN rendering test

**Status**: Implemented  
**Tier**: P1  
**Size**: Medium  
**Target**: v0.62.0  
**Phase**: i18n completion  
**Refs**: G12 (gap analysis), PDF "EN + JA rendering test を追加"

## Problem

PDF i18n contract:
- **End-user UI は JA / EN 多言語**
- **admin console は当面 JA-only**

RFC 066 / RFC 067 で追加した:
- `crates/ui/src/tenant_admin/invitations.rs` (`invitations_page`)
- `crates/ui/src/tenant_admin/deletions.rs` (`deletion_requests_page`)

は **すべての visible string がハードコード英語** ("Invite a user", "Pending invitations",
"Send invitation", "Revoke", "Execute now" 等)。

これは admin console の i18n contract 「**JA-only**」にも違反する (英語が出ている)。
正しくは:

- admin console は **JA-only** ポリシーなので、これらは **日本語に統一**するべき
- ただし visible strings は `MessageKey` 経由で翻訳テーブルから引く (drift 防止)

PDF acceptance: "EN + JA rendering test を追加" は **end-user UI** に対しての要求。
admin の場合は **JA rendering test** の追加が該当する。

## Goal

1. `tenant_admin/invitations.rs` の全 visible string を `MessageKey` 化。
2. `tenant_admin/deletions.rs` の全 visible string を `MessageKey` 化。
3. JA 翻訳を整備 (admin JA-only policy)。
4. JA rendering test を追加 (頁内に期待 JA 文字列が含まれることを assertion)。

## Design

### MessageKey 追加

```rust
// crates/core/src/i18n.rs

// --- RFC 078: tenant admin invitation page ---
TenantInvitePageTitle,            // 招待
TenantInviteSectionTitle,         // ユーザーを招待する
TenantInviteEmailLabel,           // メールアドレス
TenantInviteRoleLabel,            // 初期ロール
TenantInviteRoleMember,           // テナントメンバー
TenantInviteRoleAdmin,            // テナント管理者
TenantInviteSubmitButton,         // 招待を送信
TenantInvitePendingHeading,       // 保留中の招待
TenantInviteEmpty,                // 保留中の招待はありません
TenantInviteColEmail,             // メールアドレス
TenantInviteColRole,              // ロール
TenantInviteColStatus,            // 状態
TenantInviteColExpires,           // 有効期限
TenantInviteStatusPending,        // 保留中
TenantInviteStatusExpired,        // 期限切れ
TenantInviteStatusRevoked,        // 取り消し済み
TenantInviteExpiresInHours,       // {n}時間後に期限切れ
TenantInviteRevokeButton,         // 取り消す
TenantInviteRevokeConfirm,        // この招待を取り消しますか?

// --- RFC 078: tenant admin deletion request page ---
TenantDeletionPageTitle,          // 削除リクエスト
TenantDeletionGracePeriodWarning, // 削除リクエストは指定日以降に実行されます (デフォルト30日)
TenantDeletionIrreversibleNotice, // 実行された削除は復元できません
TenantDeletionTableHeading,       // 削除リクエスト
TenantDeletionEmpty,              // 保留中の削除リクエストはありません
TenantDeletionColUserId,          // ユーザー ID
TenantDeletionColStatus,          // 状態
TenantDeletionColScheduled,       // 予定日
TenantDeletionColActions,         // 操作
TenantDeletionStatusPending,      // 保留中
TenantDeletionStatusExecuted,     // 実行済み
TenantDeletionStatusCancelled,    // キャンセル済み
TenantDeletionScheduledInDays,    // {n}日後
TenantDeletionCancelButton,       // キャンセル
TenantDeletionExecuteButton,      // すぐに実行
TenantDeletionExecuteConfirm,     // この削除を即時実行しますか? 取り消せません
```

合計 28 個の新 MessageKey。**admin console は JA-only** なので、`i18n.rs` の
match arm では英語訳も入れるが、tenant_admin UI 側は `Locale::Ja` で固定。

(将来 admin console を多言語化する場合に備えて EN 訳も書いておく — drift を生まない)

### MessageKey にプレースホルダ展開

`{n}時間後に期限切れ` の `{n}` 展開は `cesauth_core::i18n::lookup` だけでは
できない。現状 i18n catalog は plain string lookup のみ。

対応案 (2 つ):

**A. format!() で動的構築 (採用)**:
```rust
let expires_in_h = (inv.expires_at - now_unix).max(0) / 3600;
let template = lookup(MessageKey::TenantInviteExpiresInHours, Locale::Ja);
let display = template.replace("{n}", &expires_in_h.to_string());
```

**B. format-aware lookup (将来課題)**:
将来 RFC で `lookup_with_args` を追加する。本 RFC では A を採る。

### UI 側の修正

```rust
// crates/ui/src/tenant_admin/invitations.rs (抜粋)

use cesauth_core::i18n::{lookup, MessageKey, Locale};

pub fn invitations_page(
    principal:   &AdminPrincipal,
    tenant:      &Tenant,
    invitations: &[Invitation],
    now_unix:    i64,
) -> String {
    let l = Locale::Ja; // admin is JA-only

    let issue_form = format!(
        r#"<section class="card mb-4">
  <h2 class="card-title">{title}</h2>
  <form method="POST" action="/admin/t/{slug}/invitations">
    <input type="hidden" name="csrf_token" value="{csrf}">
    <div class="form-row">
      <label for="email">{email_label}</label>
      <input type="email" id="email" name="email" required placeholder="user@example.com">
    </div>
    <div class="form-row">
      <label for="role">{role_label}</label>
      <select id="role" name="role">
        <option value="tenant_member">{role_member}</option>
        <option value="tenant_admin">{role_admin}</option>
      </select>
    </div>
    <button type="submit" class="btn-primary">{submit_button}</button>
  </form>
</section>"#,
        slug          = escape(&tenant.slug),
        csrf          = escape(""),
        title         = escape(lookup(MessageKey::TenantInviteSectionTitle, l)),
        email_label   = escape(lookup(MessageKey::TenantInviteEmailLabel, l)),
        role_label    = escape(lookup(MessageKey::TenantInviteRoleLabel, l)),
        role_member   = escape(lookup(MessageKey::TenantInviteRoleMember, l)),
        role_admin    = escape(lookup(MessageKey::TenantInviteRoleAdmin, l)),
        submit_button = escape(lookup(MessageKey::TenantInviteSubmitButton, l)),
    );
    // ... (continue refactoring)
}
```

同様に `deletions.rs` も MessageKey 経由に変更。

### Rendering test

`crates/ui/src/tenant_admin/tests.rs` (既存) に追加:

```rust
#[test]
fn invitations_page_renders_ja_strings() {
    let principal = test_principal();
    let tenant = test_tenant();
    let invitations: Vec<Invitation> = vec![];
    let html = invitations_page(&principal, &tenant, &invitations, 1_700_000_000);
    assert!(html.contains("ユーザーを招待する"));
    assert!(html.contains("招待を送信"));
    assert!(html.contains("保留中の招待はありません"));
}

#[test]
fn invitations_page_renders_pending_invitation_row() {
    let inv = Invitation {
        id: "inv-1".into(),
        tenant_id: "t-1".into(),
        email: "alice@example.com".into(),
        role: "tenant_member".into(),
        expires_at: 1_700_010_000,
        // ...
    };
    let html = invitations_page(&principal, &tenant, &[inv], 1_700_000_000);
    assert!(html.contains("alice@example.com"));
    assert!(html.contains("保留中"));
    assert!(html.contains("取り消す"));
}

// (同様に deletions のテスト)
```

## Implementation steps

1. `MessageKey` に 28 個追加 (上記リスト)、JA/EN 訳を `i18n.rs` のマッチアームに追加。
2. `crates/ui/src/tenant_admin/invitations.rs` を MessageKey lookup ベースに refactor。
3. `crates/ui/src/tenant_admin/deletions.rs` を同様に refactor。
4. Plurals/動的値プレースホルダは `.replace("{n}", &n.to_string())` で対応。
5. テスト追加 (`tenant_admin/tests.rs`)。

## Acceptance

- [ ] invitations_page / deletion_requests_page の visible strings がすべて
      MessageKey 経由 (ハードコード英語ゼロ)
- [ ] JA rendering test が 4 本以上 pass (各ページ × 「空」「データあり」)
- [ ] 既存の 270 UI テスト全 pass
- [ ] 全テストスイート green

## Risks / Notes

- 翻訳の長さ違いで HTML 崩れがありえる: 表示テストで widget 内に文字列が
  「含まれる」のみを assertion し、layout は CSS が担保。
- 動的展開 (`{n}` replace) は escape を**忘れない**こと。数値だけなので
  XSS リスクは無いが、慣習として escape 経由を推奨。
