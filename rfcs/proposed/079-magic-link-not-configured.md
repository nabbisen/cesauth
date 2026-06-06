# RFC 079 — Magic Link "not configured" UI 通知

**Status**: Proposed  
**Tier**: P2  
**Size**: Medium  
**Target**: v0.62.x  
**Phase**: Operator boundary clarity  
**Refs**: G4 (gap analysis), PDF "MagicLinkMailer は operator 実装. cesauth UI は 'sent' と 'not configured' を正しく伝える"

## Problem

PDF design stance:
> "MagicLinkMailer は operator 実装。cesauth UI は 'sent' と 'not configured' を
> 正しく伝えるが、配送 secret は持たない"

現状実装:
- `adapter-cloudflare/src/mailer/https_provider.rs` で `MailerError::NotConfigured` を
  返すことはある。
- しかし `/login` ページに「Magic Link は現在利用できません」と表示する経路がない。
- ユーザーは Magic Link form に email を入れ、送信ボタンを押し、エラーで戻り、
  「何が起きたのか分からない」状態になる。

正しい UX:
- **operator が MagicLinkMailer を未設定**の場合、`/login` の Magic Link section
  を**初期表示時点で非活性化** or **明示的に "現在無効です" 通知**を出す。
- ユーザーは Passkey で進む (それしか道がない) ことが明示的に分かる。
- 配送 secret の存在 / 不在は **operator boundary** であり、画面コピーで
  詳細を出さない。

## Goal

`/login` ページで以下を実現:
1. MagicLinkMailer が configured かどうかを worker が認識する。
2. configured **でない**場合: Magic Link section をフォームではなく
   "現在無効です" notice として表示。
3. configured な場合: 従来通り form を表示。
4. 配送詳細 (provider 名、API key の有無等) は**画面に出さない**。

## Design

### Data model

`AdapterCloudflareMailer` または `MailerPort` trait に `is_configured()` を追加:

```rust
// crates/core/src/mailer/ports.rs (or wherever the trait lives)

pub trait MagicLinkMailer {
    /// Returns true if this mailer is operationally configured.
    /// When false, the worker should not call `send_*` and the UI
    /// should mark Magic Link as unavailable.
    fn is_configured(&self) -> bool;

    async fn send(...) -> Result<(), MailerError>;
}
```

Default implementation: `true` (backward compat — existing implementations
opt-in to honest reporting).

### CloudflareMailer 実装

```rust
// adapter-cloudflare/src/mailer/https_provider.rs

impl MagicLinkMailer for HttpsProviderMailer {
    fn is_configured(&self) -> bool {
        !self.api_key.is_empty() && !self.from_addr.is_empty()
    }
    // ...
}
```

`HttpsProviderMailer::from_env(env)` が `Err(NotConfigured)` を返したとき、
worker はこの mailer を持たず、UI 状態フラグだけ持つ:

```rust
pub struct LoginPageState {
    pub csrf_token: String,
    pub error: Option<String>,
    pub turnstile_sitekey: Option<String>,
    pub magic_link_available: bool,   // NEW
}
```

### MessageKey 追加

```rust
LoginMagicLinkUnavailableNotice,  // "Magic Link は現在利用できません。パスキーでサインインしてください。" / "Magic Link is currently unavailable. Please sign in with a passkey."
```

### login_page_for 修正

```rust
pub fn login_page_for(
    state: &LoginPageState,    // or accept extra arg
    locale: Locale,
) -> String {
    // ...
    let magic_link_block = if state.magic_link_available {
        // existing form
        render_magic_link_form(...)
    } else {
        format!(
            r#"<section aria-labelledby="mail-heading">
  <h2 id="mail-heading" class="muted">{email_heading}</h2>
  <p class="flash flash--info" role="status">
    <span class="flash__icon" aria-hidden="true">·</span>
    <span class="flash__text">{notice}</span>
  </p>
</section>"#,
            email_heading = escape(lookup(MessageKey::LoginEmailHeading, locale)),
            notice = escape(lookup(MessageKey::LoginMagicLinkUnavailableNotice, locale)),
        )
    };
    // ...
}
```

### Worker handler

`crates/worker/src/routes/login.rs` (またはあるべき場所):

```rust
pub async fn show(req: Request, ctx: RouteContext<...>) -> Result<Response> {
    let mailer = HttpsProviderMailer::from_env(&ctx.env);
    let magic_link_available = match &mailer {
        Ok(m) => m.is_configured(),
        Err(_) => false,
    };
    let csrf = ...;
    let html = login_page_for(&LoginPageState {
        csrf_token: csrf,
        error: None,
        turnstile_sitekey: get_turnstile_sitekey(&ctx.env),
        magic_link_available,
    }, locale);
    render::html_response(html)
}
```

### Backward compatibility

既存 call sites:

```rust
login_page_for(csrf, error, turnstile_sitekey, locale)
```

これは positional arg signature を変更するので **breaking change**。

選択肢:
- **A**: signature を `(state: &LoginPageState, locale: Locale)` に統合 (破壊的)
- **B**: 既存 signature を保ち、`magic_link_available: bool` を追加 (破壊的 + arg 増)
- **C**: 既存 signature を `_legacy` にし、新 signature を別関数として追加

開発方針「後方互換性への考慮は不要」に基づき **A を採用**。`LoginPageState`
struct を導入してまとめる。

### POST /magic-link/request の防御

UI が無効化されていても、攻撃者は POST を直接打てる。worker handler 側でも
`if !mailer.is_configured() { return 503; }` を加える。これは UI 通知と
**サーバ側 fail-closed** の二重防御。

## Implementation steps

1. `MagicLinkMailer` trait に `is_configured()` を追加 (default true)。
2. `CloudflareMailer` (etc.) 実装で正しい返却値を設定。
3. `LoginPageState` struct を `templates.rs` に追加。
4. `login_page_for` の signature を `(state, locale)` に変更。call sites を更新。
5. `MessageKey::LoginMagicLinkUnavailableNotice` 追加 + JA/EN 翻訳。
6. `POST /magic-link/request` の handler に `is_configured()` チェック追加。
7. テスト追加。

## Acceptance

- [ ] `magic_link_available: false` のとき、login page に form が出ない
- [ ] 代わりに "現在利用できません" notice が出る (JA / EN)
- [ ] `POST /magic-link/request` は configured でないとき 503 を返す
- [ ] 配送詳細 (provider 名等) は HTML に出ない
- [ ] 全テストスイート green

## Test plan

- `login_page_with_magic_link_disabled_renders_unavailable_notice` (JA + EN)
- `login_page_with_magic_link_disabled_has_no_form_action`
- `login_page_with_magic_link_enabled_still_renders_form`
- `magic_link_request_returns_503_when_mailer_not_configured`
- HTML lint: configured/non-configured 状態で provider 名が漏れない

## Risks / Notes

- **breaking change**: `login_page_for` の signature 変更は影響範囲広い。worker
  の call sites を全て更新する必要あり。
- レンダリング時に毎回 `MagicLinkMailer::from_env` を呼ぶのは無駄。
  worker 起動時に static フラグとして cache する選択肢もあるが、本 RFC では
  単純な hot path 内チェックで OK (Cloudflare worker は per-request cold-ish)。
