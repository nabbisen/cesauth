# cesauth v0.52.1 → v0.54.0 開発サマリー

**対象バージョン**: v0.52.1 (起点) → v0.53.0 → v0.54.0  
**実施 RFC**: 020–029、013–018、001 (計 18 RFC)  
**Rust バージョン**: 1.91 (apt `rustc-1.91` / `cargo-1.91`)  
**最終テスト数**: 958 (起点 859 比 +99)  
**未完了 proposed RFC**: 0 件 (`rfcs/proposed/` 空)

---

## 目次

1. [テスト数の推移](#テスト数の推移)
2. [RFC 別対応内容](#rfc-別対応内容)
3. [検討が必要だった課題と対応方針](#検討が必要だった課題と対応方針)
4. [現時点での制約事項](#現時点での制約事項)
5. [リスク分析](#リスク分析)
6. [次のテーマ候補](#次のテーマ候補)

---

## テスト数の推移

| バージョン | cesauth-core | adapter-test | cesauth-ui | migrate-test | 合計 |
|---|---:|---:|---:|---:|---:|
| v0.52.1 (起点) | 493 | 117 | 249 | — | 859 |
| v0.53.0 (RFC 020–029 + 013–018) | 532 | 117 | 270 | 14 (新規) | 933 |
| **v0.54.0 (RFC 001)** | **557** | **117** | **270** | **14** | **958** |

SCHEMA_VERSION: 10 → **15** (新規マイグレーション 5 本)

---

## RFC 別対応内容

### RFC 020 — Migration chain hygiene (P0)

**目的**: マイグレーションチェーンの健全性確保。

**主な変更**:
- `schema_meta` テーブルを `0001_initial.sql` に追加し、全マイグレーション (0001–0010) の末尾に `schema_version` 書き込みを追加
- `0004_user_tenancy_backfill.sql` を完全書き直し:
  - `PRAGMA foreign_keys = OFF` ブロック内で users テーブルを再構築
  - 子テーブル 3 本 (`authenticators`, `consent`, `grants`) も同ブロック内で再構築し、FK が `users_pre_0004` ではなく `users` を指すよう修正
  - `COLLATE NOCASE` を users.email に復元 (0001 定義にはあったが 0004 で消失していた)
  - `PRAGMA foreign_key_check` を防衛的に追記
- `0009_user_session_index.sql` の壊れた `schema_meta` INSERT を修正
- `cesauth-migrate-test` 統合テストクレートを新規作成 (ワークスペースに追加)
  - 8 本の統合テストで FK 整合性・COLLATE NOCASE・schema_version 一致をアサート

**起動ポイント**: RFC 020 は production-blocker。本クレートを先に作り赤い状態を確認してからマイグレーション修正に入るアーキテクト推奨の手順を採用した。

---

### RFC 022 — Permission catalog seed sync (P1)

**目的**: `tenant:member:add` / `tenant:member:remove` がコードには宣言されているが DB シードに存在せず、tenant admin が 403 を受け続ける問題の修正。

**主な変更**:
- `0011_permission_catalog_sync.sql` を新規作成
  - `permissions` テーブルに 2 権限を INSERT
  - `system_admin` / `tenant_admin` ロールの `permissions` TEXT カラムに末尾追記 (`instr()` で二重追記防止)
- migrate-test にカタログ全数チェックテストを追加 (RFC 020 の赤いテストが緑になる)

---

### RFC 021 — User FK cascade alignment (P1)

**目的**: DELETE users 時に関連データが残留するプライバシー / GDPR リスクの解消。

**主な変更**:
- `0012_user_fk_cascades.sql` で 7 テーブルを `PRAGMA foreign_keys = OFF` ブロック内で再構築:
  - `user_tenant_memberships`, `user_organization_memberships`, `user_group_memberships`
  - `role_assignments`, `totp_authenticators`, `totp_recovery_codes`, `user_sessions`
  - 各テーブルの `user_id` FK に `ON DELETE CASCADE` を付与
- 各テーブルの元のスキーマ (CHECK 制約、列数) を正確に再現する必要があり、`0007_totp.sql` の totp_authenticators が 10 列であることを確認してから作業

---

### RFC 023 — Tenant boundary integrity (P1)

**目的**: クロステナント参照をスキーマ層とサービス層の両方で遮断する。

**主な変更**:
- `0013_tenant_composite_keys.sql`:
  - `organizations(tenant_id, id)` に複合 UNIQUE インデックスを追加
  - `groups` テーブルを再構築し、`(tenant_id, organization_id) → organizations(tenant_id, id)` の複合 FK を付与
  - `(tenant_id, parent_group_id) → groups(tenant_id, id)` の自己参照複合 FK も付与
- `CoreError::CrossTenantReference { kind, expected_tenant_id, actual_tenant_id }` バリアントを追加
- `NewGroupInput<'a>` に `organization_tenant_id: Option<&'a str>` フィールドを追加
- `service::validate_group_tenant_boundary()` 純粋関数を追加 (I/O なし、`PortError::PreconditionFailed` を返す)
- `cross_tenant_error_for_group()` 関数 — worker 層が構造化エラーボディと監査イベントを生成するために使用
- migrate-test にクロステナント参照の rejection / 同テナント参照の acceptance をアサートするテストを追加

---

### RFC 024 — D1 index restoration (P2)

**目的**: 0004 再構築で消失したインデックスの復元と、cron スキャン用 partial index の追加。

**主な変更**:
- `0014_index_restoration.sql`:
  - `idx_users_tenant_status` (tenant admin ユーザー一覧クエリ)
  - `idx_users_created_at` (管理者検索)
  - `idx_users_anonymous_expired` (partial: `account_type = 'anonymous' AND email IS NULL`) — 匿名ユーザー retention sweep 用
  - `idx_user_sessions_active_created` (partial: `revoked_at IS NULL`) — session-index cron 用
- migrate-test に `EXPLAIN QUERY PLAN` ベースの 4 本のインデックス使用確認テストを追加

---

### RFC 028 — CHANGELOG/ROADMAP volume policy (P2)

**目的**: ファイルサイズ超過によるツール障害防止と閲覧性向上。

**主な変更**:
- `CHANGELOG.md`: 511 KB → 62 KB
  - v0.49.0 以前を `docs/changelog-archive/` に 3 ファイルに分割 (0.1–0.30 / 0.31–0.40 / 0.41–0.49)
- `ROADMAP.md`: 211 KB → 79 KB
  - Shipped テーブルの narrative を condensed summary + アーカイブリンクに置換
- `docs/changelog-archive/README.md` — アーカイブインデックス + ポリシー記述
- `scripts/changelog-archive-split.sh` — 次回分割時の自動化スクリプト
- CI 目標サイズ: CHANGELOG ≤ 80 KB、ROADMAP ≤ 40 KB

---

### RFC 026 — `/introspect` hot path consolidation (P2)

**目的**: `/introspect` リクエストあたり D1 を 2 回読んでいた TOCTOU ウィンドウの解消。

**主な変更**:
- `ports::repo::ClientAuthView` 型を新規追加:
  ```rust
  pub struct ClientAuthView {
      pub client_id:          String,
      pub client_secret_hash: Option<String>,
      pub audience:           Option<String>,
      pub token_auth_method:  TokenAuthMethod,
  }
  ```
- `ClientRepository` トレイトに `find_auth_view(&str) -> PortResult<Option<ClientAuthView>>` を追加
- `service::client_auth::check_client_credentials_from_view()` 純粋関数を追加 — 既読の View に対してゼロ I/O でシークレット検証
- in-memory adapter (adapter-test) と Cloudflare D1 adapter の両方に実装
  - D1 実装: `SELECT id, client_secret_hash, audience, token_auth_method FROM oidc_clients WHERE id = ?` の単一クエリ
- 既存の `verify_client_credentials_optional` を使う呼び出し側 (`revoke/tests.rs`) にも `find_auth_view` stub を追加
- 新 5 本テスト: `check_client_credentials_from_view` の正常/誤秘密/hash なし/audience フィールド保持/空秘密

---

### RFC 025 — Workers operational readiness (P2)

**目的**: Cloudflare プラン対応基準の明文化と CI gate の整備。

**主な変更**:
- `.github/workflows/bundle-size.yml` — gzip 2.5 MiB 上限チェック
- `BUNDLE_SIZE_BUDGET.md` — 予算根拠・調査ガイド・サイズ履歴表
- `scripts/bundle-bloat.sh` — `cargo bloat` で top-N contributing crates を出力
- `docs/src/deployment/preflight.md` に **Paid plan 必須の根拠表を追加** (cron subrequest / D1 query / bundle サイズ比較)
  - Free plan 向け環境変数 (`SESSION_INDEX_AUDIT_BATCH_LIMIT` 等) のチューニング案も記載
- `docs/src/expert/nodejs-compat-investigation.md` — `nodejs_compat` フラグの測定プロトコルと結果 placeholder

---

### RFC 027 — Accessibility & route contracts (P2)

**目的**: アクセシビリティの機械的検証と、ルート追加時の文書化チェックの強制。

**主な変更**:
- アクセシビリティテスト 3 本を `cesauth-ui` に追加:
  - `every_flash_level_pairs_css_class_icon_and_text` — 4 レベル × (CSS class + aria-hidden icon + text span) を検証 (WCAG 1.4.1)
  - `flash_block_icon_is_aria_hidden_not_in_text_span` — スクリーンリーダーへのアイコン重複読み上げ防止を固定
  - `flash_block_polite_uses_role_status_assertive_uses_role_alert` — WAI-ARIA best practice を固定
- `docs/src/expert/route-contracts.md` — **149 ルート全て**を 7 セクションに分けて文書化
  - actor / audit kind / view / rendering test / CSRF の 5 フィールドをルート毎に記載
- `scripts/route-contracts-check.sh` — `lib.rs` 登録ルートと `route-contracts.md` の差分を検出するシェルスクリプト
- `.github/workflows/route-contracts.yml` — PR ごとに上記スクリプトを実行

---

### RFC 029 — rustfmt.toml review (P3)

**目的**: `rustfmt.toml` の必要性を実測で評価し、不要なら削除する。

**測定結果**: `rustfmt.toml` を削除した状態でも `cargo fmt --all` による diff は **0 行** (手動アライメントを含む全ファイルで変化なし)。

**主な変更**:
- `rustfmt.toml` を削除 (ファイルなし = 1.91 edition デフォルトを使用)
- `.github/workflows/fmt.yml` を追加 (`cargo fmt --all -- --check` を PR / main push で実行)
- `docs/src/expert/contributing.md` に「なぜ rustfmt.toml がないか」を記述

---

### RFC 013 — Operational envelope / ADR-016 (P2)

**目的**: Cloudflare プラン基準と各種リソース予算の ADR 化。

**主な変更**:
- `docs/src/expert/adr/016-operational-baseline.md` を新規作成:
  - Paid plan を supported baseline と宣言した根拠 (cron subrequest 試算表)
  - bundle size 2.5 MiB 予算の根拠
  - `nodejs_compat` 保留の経緯 (測定したが 0 diff → v0.54.x での削除候補)
  - cron batch size 環境変数の Free/Paid 推奨値

---

### RFC 014 — Audit append performance / ADR-017 (P2)

**目的**: audit_events のシリアライズ競合問題を計測・文書化し、Path A (accept + telemetry) を採択する。

**主な変更**:
- `CloudflareAuditEventRepository::append` に latency telemetry を追加:
  - 100ms 超または retries > 0 の場合 `console_warn!` で `latency_ms` / `retries` / `kind` を出力
  - `retries` カウンターを追加 (以前は再試行を count していなかった)
- `docs/src/deployment/runbook.md` に「audit-append contention 検出・対応」エントリを追加
- `docs/src/expert/adr/017-audit-append-performance.md` を新規作成:
  - Path B (DO シリアライズ) の設計仕様を deferred として記述

---

### RFC 015 — Request traceability (P2)

**目的**: `cf-ray` を correlation ID として全ログ行と audit 行に紐付ける。

**主な変更**:
- `crates/worker/src/request_id.rs` — `RequestId` newtype:
  - `cf-ray` ヘッダから生成 (ない場合 `local-<uuid>` フォールバック)
  - 64 文字超の値をフォールバック扱い (malformed 入力対策)
  - 8 本のユニットテスト
- `LogConfig` に `request_id: Option<String>` フィールドを追加
- `LogRecord` に `request_id` フィールドを追加 (`skip_serializing_if = "Option::is_none"`)
- `LogConfig::with_request_id(String) -> Self` メソッドを追加
- `0015_audit_request_id.sql` — `audit_events` テーブルに `request_id TEXT` カラムを追加 (nullable)
- `docs/src/expert/adr/018-request-traceability.md` — cf-ray 採用根拠 + ファイル書き込みロガー非採用の判断記録

---

### RFC 016 — Admin scope badge (P2)

**目的**: 管理画面の全フレームにスコープバッジを表示し、「どのスコープで操作しているか」を視覚的に明示する (スクリーンショット・バグレポートの文脈確認を容易にする)。

**主な変更**:
- `cesauth_core::admin::scope::ScopeBadge<'a>` enum — `System` / `Tenancy` / `Tenant(&str)` の 3 バリアント
  - `label_for(locale)`, `css_class()`, `aria_label_for(locale)` メソッド
  - JA/EN 両対応の i18n カタログ (`AdminScopeSystem`, `AdminScopeTenancy`, `AdminScopeTenant`)
  - 12 本のユニットテスト
- i18n `MessageKey` に 3 variants 追加、`for_each_key` exhaustive match を更新
- `admin_frame` シグネチャに `scope: &ScopeBadge` を追加 (旧シグネチャからの破壊的変更)
  - `admin_frame_for(locale-aware variant)` も追加
- `tenancy_console_frame` / `tenant_admin_frame` をラッパー方式で後方互換を保ちつつ scope badge を組み込み
- admin/ 以下 9 ファイルの呼び出し側を一括更新
- CSS scope トークン (`--scope-system`, `--scope-tenancy`, `--scope-tenant`) を各フレームに追加
- ui テストに 3 本追加 (badge クラス・JA ラベル・aria-label)

---

### RFC 017 — OIDC audience admin editor (P2)

**目的**: `oidc_clients.audience` を管理 UI から設定できるようにする (従来は D1 SQL 直打ちが必要)。

**主な変更**:
- `cesauth_core::oidc::audience::AudienceTarget` enum — `Unscoped` (NULL) / `ExplicitEmpty` ("") / `Scoped(String)` の 3 状態を明示的に区別
  - `NULL` と `""` は意味論的に異なるため別バリアント設計 (DB 値 ↔ enum の round-trip は完全双射)
  - `resolve_audience_target(mode, value)` — フォーム送信値を enum に変換、改行・NUL バイト拒否
  - 11 本のユニットテスト
- `cesauth_ui::tenant_admin::oidc_clients::audience_edit_page()` — audience 編集フォーム HTML
  - unscoped / scoped の radio + テキスト入力、uniqueness warning セクション
  - 8 本のレンダリングテスト
- `worker::audit::EventKind` に 3 variants 追加:
  - `OidcClientAudienceChanged` — 変更イベント (payload: client_id, before, after, tenant_slug)
  - `OperationPreviewed` / `OperationApplied` — RFC 018 preview-and-apply パターンと連動

---

### RFC 018 — Preview-and-apply pattern (P2)

**目的**: 破壊的な管理操作に preview → apply の 2 ステップを強制する汎用 infrastructure。

**主な変更**:
- `cesauth_core::admin::preview` モジュール:
  - `ImpactSeverity` enum — `Low` / `Medium` / `High` (banner 色制御)
  - `ImpactStatement { title, bullets, rollback, severity }` — 操作別純粋関数が生成
  - `DiffEntry { field, before, after }` + `is_unchanged()` helper
  - `PreviewTokenPayload { operation_id, before, after, preview_ts, csrf }`
  - `mint_preview_token(payload, hmac_key)` — HMAC-SHA256 署名 + base64url wire form
  - `verify_preview_token(token, hmac_key, now, expected_csrf)` — TTL 5 分 + CSRF バインディング検証
  - 操作別 impact 関数: `log_level_impact()`, `admin_token_rotation_impact()`
  - 19 本のユニットテスト (tamper detection, TTL, CSRF mismatch, round-trip 等)
- `cesauth_ui::admin::preview` モジュール:
  - `preview_body(diff, impact, apply_action, cancel_url, preview_token, csrf, can_apply)` — preview ページ HTML
  - `preview_body_noop()` — 変更なし状態の HTML
  - 8 本のレンダリングテスト (severity 別 banner、destructive notice、rollback hint 等)

---

### RFC 001 — OIDC `id_token` issuance (v0.25.0 以来の懸案)

**目的**: OIDC Core §3.1.2.2 準拠の id_token を `authorization_code` exchange と `refresh_token` rotation で発行し、discovery doc を OIDC posture に戻す。

**主な変更**:
- `cesauth_core::oidc::id_token` モジュール:
  - `IdTokenClaims` struct (required claims + optional claims with skip_serializing_if)
  - `build_id_token_claims(iss, user, client_id, scopes, nonce, auth_time, iat, ttl)` — scope 駆動クレーム構築 (ADR-008 §Q2)
  - `sign_id_token(claims, signer)` — 既存 `JwtSigner::sign()` への薄いラッパー
  - 12 本のユニットテスト (scope 別クレーム / auth_time fallback / alg header / kid header 等)
- `Challenge::AuthCode` に `auth_time: i64` 追加 (`#[serde(default)]`)
- `FamilyState.auth_time` + `FamilyInit.auth_time` を追加 (`#[serde(default)]`)
- `service::token::exchange_code<..., UR: UserRepository>` — `users` / `iss` 引数を追加、`openid` scope 時に id_token を発行
- `service::token::rotate_refresh<..., UR: UserRepository>` — 同様 (`auth_time = family.auth_time` で original auth time を保持)
- `post_auth::complete_auth_post_gate` で `Challenge::AuthCode.auth_time = now` を設定
- Worker `/token` handler に `CloudflareUserRepository` を追加し `iss = cfg.issuer` を渡す
- `DiscoveryDocument` に OIDC fields を追加:
  - `id_token_signing_alg_values_supported: ["EdDSA"]`
  - `subject_types_supported: ["public"]`
  - `claims_supported: ["iss","sub","aud","exp","iat","auth_time","nonce","email","email_verified","name"]`
  - `scopes_supported` に `"openid"` を復活
- v0.25.0 の "honest-reset" discovery テスト 8 本を OIDC posture に invert
- service integration テスト 8 本 (inline stubs、exchange_code + rotate_refresh の id_token 発行・auth_time 保持・no-openid 抑制を検証)

---

## 検討が必要だった課題と対応方針

### 1. 0004 マイグレーションの子テーブル FK 破損問題

**課題**: SQLite の "rename → recreate → copy" パターンで `users` テーブルを再構築した場合、同一 `PRAGMA foreign_keys = OFF` ブロック内で子テーブル (`authenticators`, `consent`, `grants`) も再構築しないと、子テーブルの FK が削除済みの `users_pre_0004` を指したままになる。元の `0004` にはこの処理が欠落していた。

**対応**: `PRAGMA foreign_keys = OFF` の単一トランザクション内で users + 子テーブル 3 本を全て再構築。末尾に `PRAGMA foreign_key_check` を追加してデプロイ時に壊れた FK を検出できるようにした。

### 2. COLLATE NOCASE の消失

**課題**: `users.email` の `COLLATE NOCASE` が 0001 では付いていたが 0004 の再構築で消失。大文字/小文字の違いで同一メールアドレスを持つ複数ユーザーが作成できてしまう状態だった。

**対応**: 0004 の再構築 CREATE TABLE に `COLLATE NOCASE` を復元し、migrate-test に case-insensitive uniqueness テストを追加。

### 3. `FamilyInit` の破壊的変更 vs 後方互換

**課題**: RFC 001 で `FamilyInit.auth_time` を追加すると、全構築箇所がコンパイルエラーになる。7 箇所 (crates 横断) の修正が必要。

**対応**: `#[serde(default)]` を `FamilyState.auth_time` / `Challenge::AuthCode.auth_time` に付与してシリアライズ互換を確保。コンパイル箇所は全て `auth_time: 0` を明示 (pre-RFC 001 データと同等)。id_token builder 側で `auth_time == 0` の場合に `issued_at` へフォールバックする処理を実装 (ADR-008 §Q4 migration compatibility)。

### 4. `exchange_code` / `rotate_refresh` の signature 変更

**課題**: `UserRepository` 追加は全ての呼び出し側 (worker route handler) に波及する破壊的変更。また、型パラメータが増える (5 型 → 6 型) ため可読性が下がる。

**対応**: 変更をシグネチャに反映し worker 側 1 箇所 (routes/oidc/token.rs) のみ修正。型エイリアスや trait object への変換は依存関係を複雑にするため見送り。将来的に service 設計を builder pattern に移行する際に型パラメータ増加問題を解消できる。

### 5. `admin_frame` シグネチャの破壊的変更 (RFC 016)

**課題**: `scope: &ScopeBadge` 引数を追加すると、admin/ 以下の 9 ファイルが全てコンパイルエラーになる。

**対応**: Python スクリプトによる一括正規表現置換 (Tab→`ScopeBadge::System` の挿入) で対応。tenancy_console / tenant_admin のフレームについてはラッパー関数を維持して既存呼び出し側の変更を不要にした (後方互換)。

### 6. PKCE 検証の最小長要件 (RFC 001 テスト)

**課題**: integration テストで `"test-verifier"` (13 文字) を使ったところ、RFC 7636 §4.1 の「verifier は 43〜128 文字」チェックに引っかかり `PkceMismatch` エラーになった。テストは `.unwrap()` でパニックしていたため、エラーメッセージが出力されず原因特定に時間がかかった。

**対応**: verifier を 43 文字の固定文字列に変更。テストの `.unwrap()` を残しつつも、将来は `expect("exchange_code should succeed")` 形式にすることで問題の局所化を推奨。

### 7. `AudienceTarget` の `NULL` vs `""` 区別

**課題**: `oidc_clients.audience = NULL` (スコープなし・旧挙動) と `audience = ""` (空文字列へのスコープ) は意味論的に異なるが、`Option<String>` では `None` vs `Some("")` を UI 側で表現するのが難しい。

**対応**: `AudienceTarget::Unscoped` / `ExplicitEmpty` / `Scoped(String)` の 3 バリアント enum を設計。DB 値との round-trip も完全双射。フォームの radio は `"unscoped"` / `"scoped"` の 2 択とし、テキスト入力が空の場合に `ExplicitEmpty` として扱う。

### 8. Migration テスト `for_each_key` の exhaustive match

**課題**: RFC 016 で i18n `MessageKey` に `AdminScope*` variants を追加した際、`i18n/tests.rs` の exhaustive match が更新されておらずコンパイルエラーが発生。match と `all = [...]` 配列の両方を更新する必要があった。また、誤ったコードを挿入したことで重複コードが発生。

**対応**: match の exhaustiveness pin と runtime walker 配列を一緒に更新するルールをコード内コメントで明文化。重複は str_replace で修正。

---

## 現時点での制約事項

### ビルド環境

| 制約 | 詳細 |
|---|---|
| WASM ターゲット不可 | `cesauth-adapter-cloudflare` / `cesauth-worker` は `worker` クレートの WASM-only API (`wasm_bindgen`, `JsValue`, `worker::Env`) に依存するためホスト環境ではコンパイル不可 |
| `MagicLinkMailer` dyn 非互換 | `async fn` を含むトレイトは Rust 1.91 の dyn compatibility 要件を満たさない。現在の adapter-cloudflare はこのエラーを抱えたままで、WASM ターゲット専用のコンパイルパスが必要 |
| ホストテスト対象外 | worker / adapter-cloudflare の 29 本程度のテストはホスト環境では実行できない |

### スキーマ・マイグレーション

| 制約 | 詳細 |
|---|---|
| `schema_meta` 統合 | RFC 020 §"Open questions" に記載: `schema_meta` と `cesauth-migrate` マニフェストの統合は別 RFC が必要 |
| `0004` の冪等性 | 修正済み 0004 はまだ「リネーム → 再作成 → コピー」パターンを使用するため、同一 DB に 2 回適用するとエラー。D1 の wrangler-driven single-session 前提は変わらない |

### RFC 015 (request traceability) の部分実装

| 制約 | 詳細 |
|---|---|
| worker ハンドラー未配線 | `RequestId::from_header_lookup()` と `LogConfig::with_request_id()` は実装済みだが、各 HTTP ハンドラーで `cf-ray` を読んで `LogConfig` に設定する配線は未実施 |
| audit 書き込み未配線 | `audit_events.request_id` カラムは追加済みだが、`NewAuditEvent` 構造体への `request_id` フィールド追加と書き込みパスへの伝播は未実施 |

### RFC 017 (OIDC audience admin editor) の部分実装

| 制約 | 詳細 |
|---|---|
| worker route 未作成 | `audience_edit_page()` HTML テンプレートは完成しているが、`GET /admin/t/:slug/oidc-clients/:id/audience` および `POST` ハンドラーは worker crate 側に存在しない |
| route-contracts.md 未記載 | 上記 routes を追加した際は route-contracts.md の更新が必要 |

### RFC 018 (Preview-and-apply) の部分実装

| 制約 | 詳細 |
|---|---|
| adopter なし | infrastructure は完成しているが、既存の config_edit / 管理操作ハンドラーへの adoption は 0 件 |
| `OperationPreviewed` / `OperationApplied` EventKind | audit.rs に追加済みだが、実際に emit するハンドラーがない |

### RFC 016 (scope badge) の部分実装

| 制約 | 詳細 |
|---|---|
| 日本語デフォルト | `admin_frame` / `tenancy_console_frame` は `Locale::default()` (JA) でバッジを描画する。locale を呼び出し側から渡す `_for` variant は実装済みだが、worker handler 側での locale 解決と連携していない |

---

## リスク分析

### 高リスク

| リスク | 影響 | 可能性 | 対応状況 |
|---|---|---|---|
| **0004 修正の本番 D1 適用失敗** | ユーザーデータ消失 / 復元不可 | 低 (ただし新規 DB では 0 件のため再現困難) | migrate-test 14 本でカバー。`PRAGMA foreign_key_check` が末尾で失敗すれば migration を中断する。**本番適用前に staging DB で必ず検証**すること。本番 DB には 0004 適用済みデータが存在するため、修正版 0004 は新規 DB にのみ適用される。**既存本番 DB は影響受けない。** |
| **RFC 015 の未完成配線** | request_id が常に NULL のまま出荷 | 高 (配線コードが存在しない) | `request_id.rs` は完成済みで 8 本テスト付き。worker 側の配線が次の作業。未配線で出荷してもリグレッションはないが、feature が機能しない。 |
| **MagicLinkMailer dyn 非互換** | adapter-cloudflare が WASM ビルドでも失敗する可能性 | 中 | Rust 1.91 の dyn-compatible 要件は `async fn` in trait を除外する。`impl Future` を使うか `async_trait` crate を導入する必要がある。worker テストへの影響要確認。 |

### 中リスク

| リスク | 影響 | 可能性 | 対応状況 |
|---|---|---|---|
| **RFC 001 の id_token `auth_time = 0` 漏洩** | id_token の `auth_time` クレームが 0 になる可能性 (pre-RFC 001 in-flight challenges) | 低 (AuthCode TTL が短い) | `#[serde(default)]` + `issued_at` へのフォールバックで対処済み。テスト 8 本でカバー。 |
| **audit append latency telemetry のノイズ** | false positive `console_warn` が Logpush を汚染する | 低 | 100ms 閾値は保守的。D1 が健全なデプロイでは通常 10–30ms。閾値は hardcode されており環境変数でのオーバーライドができない (ADR-017 の改善項目)。 |
| **`nodejs_compat` 削除の延期** | 削除せず bundle 予算を無駄に消費し続ける | 低 | RFC 029 で 0 diff を確認済み。v0.54.x で削除 PR を出すことを ROADMAP に記載。 |
| **route-contracts.md の鮮度** | スクリプトが lib.rs の `.get_async` / `.post_async` に依存するため、router API 変更で false negative になりうる | 低 | `scripts/route-contracts-check.sh` はパターンマッチベースのため router フレームワーク変更時に更新が必要。 |

### 低リスク

| リスク | 影響 | 対応状況 |
|---|---|---|
| **bundle サイズ未測定** | CI gate が初回実行まで機能しない | WASM ビルド環境で初回実測して `BUNDLE_SIZE_BUDGET.md` に記入が必要。CI は wrangler-dependent のため本環境では実行不可。 |
| **AudienceTarget ExplicitEmpty の誤用** | `audience = ""` に設定するオペレーターが意図を理解していない | `audience_edit_page()` の fieldset legend に説明文を追加済み。ExplicitEmpty は通常の運用では使用しないことを docs に記載推奨。 |

---

## 次のテーマ候補

### 最優先 (制約解消)

| テーマ | 根拠 |
|---|---|
| **RFC 015 完成: request_id の worker 配線** | カラムと型は存在するが配線が未実施。各 HTTP ハンドラーで `cf-ray` 読み取り → `LogConfig.with_request_id()` → audit `request_id` 書き込みの 3 ステップ。30分〜1時間の作業。 |
| **RFC 017 完成: worker route 追加** | `GET / POST /admin/t/:slug/oidc-clients/:id/audience` の 2 ルートを追加。`AudienceTarget` 型と `audience_edit_page()` テンプレートは実装済みのため接続のみ。route-contracts.md 更新も忘れずに。 |
| **RFC 018 採用: 最初の adopter** | config_edit ハンドラー (LOG_LEVEL 変更) が最適な first adopter。`log_level_impact()` 関数が既に RFC 018 infrastructure に含まれているため、preview/apply フローの接続が主作業。 |
| **MagicLinkMailer dyn 非互換の修正** | `async fn` を `fn ... -> impl Future` に変更するか `#[async_trait]` crate を導入。adapter-cloudflare が WASM ビルドで通らない状態を解消し、worker テストを復活させる。 |

### 中期

| テーマ | 根拠 |
|---|---|
| **`nodejs_compat` 実測と削除 PR** | RFC 029 で 0 diff を確認済み。wrangler deploy --dry-run でサイズ測定後に削除 PR。ADR-016 §"nodejs_compat" に記録。 |
| **scope_meta + cesauth-migrate 統合 RFC (030)** | RFC 020 §"Open questions" に記載。`schema_meta` の最終 version が migrate CLI の manifest と一致するかを CI で検証する仕組みが必要。 |
| **role_assignments の scope-typed table 分離 RFC (031)** | RFC 023 §"Open questions" に記載。現在 `scope_type` / `scope_id` はポリモーフィック設計でスキーマ FK 未強制。テナント/組織/グループ別の typed table に分離することで FK 整合性を強化。 |
| **RFC 013 §"Step 2" nodejs_compat 計測完遂** | `docs/src/expert/nodejs-compat-investigation.md` の Results 表に測定値を記入し、削除 or 保留の結論を出す。 |
| **audit_events rate optimization** | ADR-017 に Path B (DO シリアライズ) の設計仕様を記述済み。telemetry で `latency_ms > 100` の警告が出始めた段階で RFC 化する。 |

### 長期 / 機能拡張

| テーマ | 根拠 |
|---|---|
| **`prompt=select_account`** | ROADMAP 記載。マルチセッション / アカウントピッカー UX が必要。複雑度が高く単独 RFC サイクル。 |
| **FIDO 完全 attestation 検証** | MDS + CA trust store が必要。AAGUID ゲーテッドアクセス制御が要件になった時点で着手。 |
| **Device Authorization Grant (RFC 8628)** | CLI / smart-TV クライアント向け。ROADMAP 記載。 |
| **Dynamic Client Registration (RFC 7591/7592)** | マルチテナント SaaS 化を本格的に進める場合に必要。 |
| **商用 SaaS 化構成** | `cesauth-商用_SaaS_化可能な構成への拡張開発指示書.md` (プロジェクト Files) が既にあり、テナント課金・セルフサービスプロビジョニングの設計を扱う。RFC 020–024 のテナント境界強化が先行条件として完了した。 |

---

## 付録: ファイル変更一覧 (主要)

```
migrations/
  0011_permission_catalog_sync.sql   (RFC 022)
  0012_user_fk_cascades.sql          (RFC 021)
  0013_tenant_composite_keys.sql     (RFC 023)
  0014_index_restoration.sql         (RFC 024)
  0015_audit_request_id.sql          (RFC 015)
  [0001–0010 に schema_version 追記]  (RFC 020)

crates/core/src/
  admin/preview.rs                    (RFC 018, 新規)
  admin/scope.rs                      (RFC 016, 新規)
  migrate/types.rs                    SCHEMA_VERSION 10→15
  error.rs                            CrossTenantReference variant
  i18n.rs                             AdminScope* variants
  oidc/audience.rs                    (RFC 017, 新規)
  oidc/id_token.rs                    (RFC 001, 新規)
  oidc/discovery.rs                   OIDC posture 復元
  ports/repo.rs                       ClientAuthView, find_auth_view
  ports/store.rs                      auth_time fields
  service/token.rs                    exchange_code/rotate_refresh 拡張
  tenancy/service.rs                  validate_group_tenant_boundary
  tenancy/ports.rs                    organization_tenant_id field

crates/adapter-test/src/
  repo/clients.rs                     find_auth_view 実装
  store/refresh_token_family.rs       auth_time 追加

crates/worker/src/
  audit.rs                            3 EventKind 追加
  log.rs                              request_id フィールド
  post_auth.rs                        auth_time 設定
  request_id.rs                       (RFC 015, 新規)
  routes/oidc/token.rs                users/iss 引数追加

crates/ui/src/
  admin/frame.rs                      scope badge
  admin/preview.rs                    (RFC 018, 新規)
  tenant_admin/oidc_clients.rs        (RFC 017, 新規)
  [10+ frame files]                   scope badge 組み込み

crates/migrate-test/                  (新規クレート, 14 tests)

.github/workflows/
  bundle-size.yml                     (RFC 025)
  fmt.yml                             (RFC 029)
  route-contracts.yml                 (RFC 027)

docs/src/expert/adr/
  016-operational-baseline.md         (RFC 013)
  017-audit-append-performance.md     (RFC 014)
  018-request-traceability.md         (RFC 015)

docs/src/expert/
  contributing.md                     (RFC 029, 新規)
  nodejs-compat-investigation.md      (RFC 025, 新規)
  route-contracts.md                  (RFC 027, 新規, 149 routes)

docs/changelog-archive/               (RFC 028, 新規ディレクトリ)
CHANGELOG.md                          511KB → 70KB
ROADMAP.md                            211KB → 79KB
BUNDLE_SIZE_BUDGET.md                 (RFC 025, 新規)
scripts/bundle-bloat.sh               (RFC 025)
scripts/changelog-archive-split.sh   (RFC 028)
```
