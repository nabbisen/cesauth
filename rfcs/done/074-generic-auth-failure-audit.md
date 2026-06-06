# RFC 074 — Generic auth failure copy audit

**Status**: Implemented  
**Tier**: P0  
**Size**: Small (audit) / Medium (if fixes needed)  
**Target**: v0.62.0  
**Phase**: Security UX  
**Refs**: G13 (gap analysis), PDF "Generic auth failures" acceptance

## Problem

PDF acceptance criterion: "security-sensitive な失敗は詳細を漏らさない。ただし
操作可能な次手だけは明確に示す"

これは UI 上で**認証経路の失敗が、どの段階で失敗したかを推測可能にしない**ことを
要求する。具体的には:

| 経路 | NG (情報漏洩) | OK (汎用) |
|---|---|---|
| `/login` (Passkey) | "No passkey registered for this user" | "認証に失敗しました" |
| `/login` (Magic Link) | "Email not found" | "メールアドレスが正しければリンクを送信しました" |
| `/magic-link/verify` | "Code expired" vs "Code wrong" を区別 | "コードが正しくないか期限切れです" |
| `/me/security/totp/verify` | "User has no TOTP enrolled" | "コードが正しくないか TOTP 未設定です" |

現状コードを監査して、これらの**情報漏洩パターンが残っていないか網羅的に
チェックする RFC**。

## Goal

1. 全認証/2FA エンドポイントの失敗パスについて、エラーメッセージを監査する。
2. 「ユーザー固有状態が推測可能」なエラーメッセージを特定し、汎用化する。
3. 監査結果を `docs/src/expert/generic-error-policy.md` として固定。
4. 退行検知用のテストを追加。

## Design

### Phase 1: 監査 (audit)

以下の関数 / ルートのエラー応答を列挙し、表にまとめる:

| 関数/ルート | 現状 errorMessageKey | 漏洩リスク | 修正案 |
|---|---|---|---|
| `routes/login.rs::passkey_finish` | `LoginPasskeyFailed` | OK (汎用) | — |
| `routes/login.rs::magic_link_request` | `MagicLinkSent` | OK (常に "sent") | — |
| `routes/magic_link.rs::verify_get/post` | ? | 要調査 | — |
| `routes/me_security/totp.rs::verify_post` | ? | 要調査 | — |
| `routes/oidc/authorize.rs::error_response` | (RFC 6749 standard) | 範囲外 | — |
| `routes/admin/auth.rs::resolve_or_respond` | (admin tokens) | 限定 actor | — |

### Phase 2: 修正

監査で見つけた漏洩を修正:

1. **エラーメッセージの汎用化** — `MessageKey` を新規追加 (例: `MagicLinkVerifyGenericFailure`)
   既存の細分化キーを置き換え。
2. **rate limit との関係**: rate limit に達した場合も "認証に失敗しました" 系の
   汎用メッセージで応答する (rate-limit hit を漏らさない)。Retry-After ヘッダで
   ヒントは出す。
3. **timing attack 対策**: 細分化されたメッセージは表面上消えても、応答時間で
   推測可能な経路がないか確認。MagicLink verify の場合は、user 存在/非存在で
   同じ処理時間になるよう constant-time pattern を確認。

### Phase 3: ポリシー文書化

新規ドキュメント `docs/src/expert/generic-error-policy.md`:

- 認証経路の失敗メッセージは原則 1 つの汎用文言
- 例外 (操作可能な次手を示すべきケース) を列挙
- 退行検知の仕組み (テスト, lint, CR ガイド)

### Phase 4: 退行検知テスト

新規テストモジュール `crates/worker/src/routes/tests/generic_error_test.rs`
(または整合する場所):

- `magic_link_verify_unknown_email_and_wrong_code_have_same_response`
- `totp_verify_unenrolled_user_and_wrong_code_have_same_response`
- `login_passkey_fail_message_contains_no_internal_state`

これらは worker をホストビルドできない制約 (WASM-only) のため、**core 層に
"render error response from CoreError" 関数を切り出し**、その関数に対してテストを
書く設計に変更する可能性あり。実装時に判断。

## Implementation steps

1. **監査フェーズ**: `crates/worker/src/routes/` 下の全ファイルを走査し、
   error response 出力箇所をリスト化。
2. **修正フェーズ**: 漏洩が見つかれば該当箇所の `MessageKey` を汎用化。
   新規 `MessageKey` を追加し、JA/EN 翻訳を整備。
3. **テストフェーズ**: core 層 (テスト可能な場所) でテストを書く。
4. **ドキュメントフェーズ**: ポリシー文書を作成し、`SUMMARY.md` から参照。

## Acceptance

- [ ] 監査表が `docs/src/expert/generic-error-policy.md` に存在
- [ ] 監査で見つかった漏洩がすべて修正済み
- [ ] 退行検知テストが pass
- [ ] 全テストスイート green

## Risks / Notes

- 過度な汎用化は UX を悪化させる (「何が悪いかわからない」)。**操作可能な次手**
  (例: "もう一度試してください" / "サポートに連絡してください") は明示する。
- レート制限へのヒット応答は汎用にすべきだが、`Retry-After` HTTP header は出して
  良い (RFC 6585)。
