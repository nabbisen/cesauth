# RFC 076 — Recovery code 保存確認ゲート

**Status**: Implemented  
**Tier**: P1  
**Size**: Small  
**Target**: v0.62.0  
**Phase**: Danger UX  
**Refs**: G3 (gap analysis), PDF "Recovery code は再表示不可。保存確認を必須化"

## Problem

PDF self-service contract:
> "Recovery code は再表示不可。保存確認を必須化"

現状 `totp_recovery_codes_page_for(codes)` は:

- 10 個のコードを表示する
- 「もう一度表示することはできません」と inline で警告する
- しかし「保存しましたボタン」が表示と同じページに**即時押下可能**な状態にある

ユーザーが**コードを保存せずに**確認ボタンを押してしまうリスクが残る。
PDF が要求する「保存確認を必須化」は満たしていない。

## Goal

Recovery code 表示ページに**チェックボックス保存確認ゲート**を追加する:

1. ページ初期表示時、"続ける" ボタンは **disabled**。
2. "I have saved my recovery codes" (JA: "リカバリーコードを安全に保管しました")
   チェックボックスにチェックを入れたときのみボタンを有効化。
3. JS 無効環境でもページが機能する (progressive enhancement):
   - `<noscript>` 環境ではボタンは初期表示で有効。代わりに警告コピーを強調。

## Design

### HTML 構造

```html
<form method="POST" action="/me/security/totp/recover/confirm">
  <input type="hidden" name="csrf" value="{csrf}">

  <ol class="recovery-codes" aria-label="リカバリーコード一覧">
    <li><code>{code1}</code></li>
    <li><code>{code2}</code></li>
    <!-- ... -->
  </ol>

  <div class="warning-block">
    <p><strong>{warning_no_show_again}</strong></p>
    <p>{warning_storage_advice}</p>
  </div>

  <noscript>
    <p class="muted">{noscript_advice}</p>
  </noscript>

  <fieldset class="save-gate">
    <legend class="visually-hidden">{save_gate_legend}</legend>
    <label>
      <input type="checkbox"
             id="saved-confirm"
             name="saved_confirm"
             required>
      <span>{saved_confirm_label}</span>
    </label>
  </fieldset>

  <button id="proceed-btn" type="submit" class="secondary" disabled>
    {proceed_button}
  </button>

  <script defer nonce="{nonce}">
    const cb = document.getElementById('saved-confirm');
    const btn = document.getElementById('proceed-btn');
    if (cb && btn) {
      cb.addEventListener('change', () => {
        btn.disabled = !cb.checked;
      });
    }
  </script>
</form>
```

注意点:

- `<button disabled>` を初期 HTML に出すので、JS が読み込まれなくてもブラウザの
  Enter キー押下では送信されない (HTML 仕様)。**ただし** `<noscript>` 環境では
  チェックボックスのチェック状態を JS なしで監視できない。この場合は:
  - サーバ側で `saved_confirm` checkbox の存在を検証 (送信時の post body check)。
  - `<input type="checkbox" required>` 属性によりブラウザネイティブ validation
    が動く。
- **サーバ側 validation 必須**: `saved_confirm=on` がない POST は 400 で reject。
  これにより JS 無効ブラウザでも保存確認を強制できる。

### MessageKey 追加

```rust
TotpRecoveryWarningNoShowAgain,   // "このコードは再表示できません" / "These codes cannot be shown again"
TotpRecoveryWarningStorageAdvice, // "パスワードマネージャーや印刷で安全に保管してください" / "Store these in a password manager or print them"
TotpRecoveryNoscriptAdvice,       // "JavaScript 無効環境では..." / "If JavaScript is disabled..."
TotpRecoverySavedConfirmLabel,    // "リカバリーコードを安全に保管しました" / "I have saved my recovery codes"
TotpRecoverySaveGateLegend,       // "保存確認" / "Save confirmation"
TotpRecoveryProceedButton,        // "続ける" / "Proceed"
```

### Worker handler (server-side validation)

`POST /me/security/totp/recover/confirm` (新規 route or 既存 reuse) で:

```rust
let form = parse_form_body(req).await?;
let saved_confirm = form.get("saved_confirm").is_some_and(|v| v == "on");
if !saved_confirm {
    return Response::error("Recovery code save confirmation required", 400);
}
// proceed to next step (redirect to /me/security or login completion)
```

実際にはこのフォーム送信は単に「ユーザーが保存したことを記録」してリダイレクト
するだけで、コード自体はサーバ側で既に DB に保存済み (TOTP 登録時に生成済み)。
このフォームはあくまで **UI flow gate**。

### 既存ルートとの関係

現状の `/me/security/totp/recover` がどの段階で recovery codes を表示するか:

- **新規ユーザー TOTP 登録時**: codes は登録 confirm 時に表示される (1 度きり)
- **TOTP 紛失 → recovery flow**: 既存コードを使って認証する page

本 RFC は **コード表示時** に適用される。新規登録 confirm のレスポンスとして
recovery codes を出すページに save gate を追加する。

## Implementation steps

1. `MessageKey` に 6 個追加 + JA/EN 翻訳。
2. `crates/ui/src/templates.rs::totp_recovery_codes_page_for` を書き換え:
   - form タグで wrap
   - チェックボックス + disabled button 追加
   - noscript 警告
   - JS による button.disabled の toggle (CSP nonce 利用)
3. Worker handler 側で `saved_confirm` の post-body validation を追加。
4. テスト追加:
   - `recovery_codes_page_button_starts_disabled`
   - `recovery_codes_page_has_saved_confirm_checkbox`
   - `recovery_codes_page_noscript_section_present`
   - JA/EN 両方で rendering test

## Acceptance

- [ ] Recovery codes ページ HTML に `<button id="proceed-btn" ... disabled>` が含まれる
- [ ] Recovery codes ページ HTML に `<input type="checkbox" required name="saved_confirm">` が含まれる
- [ ] サーバ側で `saved_confirm` 無し POST は 400 を返す
- [ ] CSP nonce が JS block に正しく適用される (既存パターン踏襲)
- [ ] 全テストスイート green

## Test plan

- `recovery_codes_page_button_starts_disabled` — HTML に `disabled` 属性
- `recovery_codes_page_checkbox_is_required` — `required` 属性
- `recovery_codes_page_warning_block_present` — warning copy
- `recovery_codes_page_ja_localized` / `recovery_codes_page_en_localized`
- worker test: `recover_confirm_without_saved_confirm_returns_400`

## Risks / Open questions

- **UX 摩擦**: 余計なチェックボックスは TOTP 登録の最終段階で 1 秒の遅延を生む。
  これは設計上の意図的なコストであり、再表示不可な情報を扱う代償として受け入れる。
- **誤チェック**: ユーザーが内容を読まずにチェックする可能性。これは UI 設計の
  限界で、技術的には防げない。warning copy を強調することで mitigate。
