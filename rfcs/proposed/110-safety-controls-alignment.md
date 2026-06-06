# RFC 110 — Safety controls dashboard alignment audit

**Status**: Proposed  
**Tier**: P2  
**Size**: Small-Medium  
**Target**: v0.70.0  
**Phase**: Surface alignment audit (finishing track)  
**Refs**: PDF v0.50.1 page 9 "Operations UX: Safety controls" / `crates/ui/src/admin/safety.rs` / RFC 081 (cron pass status)

## Problem

PDF v0.50.1 page 9 中央パネルは **Safety controls** として以下 4 項目の
状態確認 + "Open runbook" 導線を要求している:

```
Safety controls
- Rate limit status
- Turnstile configured
- Refresh reuse alerts
- TOTP key status
[ Open runbook ]
```

v0.66.0 時点で `crates/ui/src/admin/safety.rs` および
`crates/worker/src/routes/admin/console/safety.rs` (相当のルート) は存在するが、
4 項目が PDF と完全に揃っているか **検証されていない**。具体的には:

| PDF 要求 | 現状 (推定) |
|---|---|
| Rate limit status | 不明 — `/admin/console/safety` に rate-limit metrics 表示が
                     あるか確認が必要 |
| Turnstile configured | `crates/worker/src/turnstile.rs` あり、admin console
                       で env 設定状態が表示されているか不明 |
| Refresh reuse alerts | `RefreshTokenReuseDetected` audit event は記録されるが、
                       safety パネルに最近の検知件数が summary として出ているか不明 |
| TOTP key status | `totp.rs` の encryption key (`TOTP_SECRET_KEY` env)
                  の存在/欠落表示があるか不明 |
| Open runbook link | `docs/src/deployment/day-2-runbook.md` 等への hyperlink
                   が存在するか不明 |

加えて PDF page 8 "Admin / Tenancy Console" は
"Safety controls / Audit / Config / Alerts / Tokens" を console shell の
nav として並べる。これらの sub-route の存在と alignment を verify する。

## Goal

1. PDF page 9 の Safety controls 4 項目すべてが `/admin/console/safety` に
   surface していることを確認/実装する。
2. "Open runbook" hyperlink が deployment docs の day-2 runbook を指している
   ことを確認する。
3. PDF page 8 の console shell nav (`Overview / Safety / Audit / Config /
   Alerts / Tokens`) が実装と整合していることを確認する。
4. **gap がなければ verification + テスト追加のみで closure** とする。
   gap があれば追加実装。

明示的に out of scope:
- 新規 metric 収集 (rate-limit カウンタの telemetry export 等) — 既存の
  data source のみで surface する。新規収集は別 RFC。
- runbook 自体の更新 — `docs/src/deployment/day-2-runbook.md` の中身は本 RFC
  範囲外。link が正しいことだけ確認。
- Alerts surface の機能追加 — Alerts は別 RFC で扱う場合があれば別建て。

## Design

### Verification step (実装前にまず audit)

実装者は以下を確認する:

1. `crates/ui/src/admin/safety.rs` の現状 rendering をローカル / staging で確認
   (admin token 経由)。
2. 上記 4 項目の有無を `safety_page` 出力の HTML 文字列で grep して
   ベースライン取得。
3. console shell nav の menu items を確認 (PDF page 8 と 1:1 対応)。

### Gap fill (verification 結果次第)

不足項目があれば追加する:

#### Rate limit status

KV-backed rate-limit buckets (per-family on /token, per-client on /introspect)
の **直近 24h ヒット数 + threshold 設定値** を summary として表示。
data source は `crates/worker/src/routes/admin/console/operations*.rs` 経由で
集計 (RFC 081 で cron pass status と同じ KV-record パターンを再利用)。

#### Turnstile configured

`crates/worker/src/turnstile.rs` の `TurnstileConfig::is_configured()`
真偽値を表示。secret は表示しない (PDF page 10 "Secret in audit" 原則)。

#### Refresh reuse alerts

`audit_events` table に対し、直近 7d の `RefreshTokenReuseDetected` 件数を
summary 表示。0 件なら "監視中" 表示、>0 なら数値と viewer (RFC 109) への
hyperlink。

#### TOTP key status

`TOTP_SECRET_KEY` env 変数の **存在/欠落** のみ表示。
keymaterial そのものは表示しない。

#### Open runbook link

`/safety` ページ末尾に
`<a href="/docs/deployment/day-2-runbook">[ ランブックを開く ]</a>` を追加。
hyperlink 先は文書化 (route-contracts.md 更新)。

### Console shell nav (PDF page 8)

`Overview / Safety / Audit / Config / Alerts / Tokens` を `admin/frame.rs` の
nav に並べる。現状の admin frame で既に存在するかを RFC 110 の verification step
で確認。Audit nav は RFC 109 の `/admin/console/audit` (v0.69.0) と紐付け。

## Implementation steps

1. **Verification PR (no code change)**:
   - `crates/ui/src/admin/safety.rs` の現状 rendering をベースライン化。
   - PDF page 9 / page 8 と diff を取り、gap list を作成。
   - gap list を `docs/src/expert/rfc-110-baseline.md` として記録。
2. **Implementation PRs (gap 別に分割)**:
   - PR-A: Rate limit summary
   - PR-B: Turnstile configured indicator
   - PR-C: Refresh reuse alerts summary
   - PR-D: TOTP key status indicator
   - PR-E: "Open runbook" hyperlink + console shell nav 整合
3. 各 PR で `admin/tests.rs` に rendering test を追加。

## Acceptance

- [ ] `/admin/console/safety` の出力に 4 項目すべてが存在
- [ ] secret material が一切表示されていない (Turnstile secret, TOTP key bytes)
- [ ] "Open runbook" link が `/docs/src/deployment/day-2-runbook.md` 相当に
      解決する
- [ ] console shell nav に PDF page 8 の 6 項目が並ぶ (Overview / Safety /
      Audit / Config / Alerts / Tokens)
- [ ] `cargo-1.91 test --workspace --lib` が green
- [ ] `cargo-1.91 build --workspace --target wasm32-unknown-unknown --release` が成功
- [ ] 非 deprecated warnings = 0

## Test strategy

`crates/ui/src/admin/tests.rs` に rendering test 追加 (各 gap fill 単位):

```rust
#[test]
fn safety_page_lists_rate_limit_status() {
    let html = safety_page_for(/* fixture state */);
    assert!(html.contains("レート制限"));
    assert!(html.contains("直近 24h"));
}

#[test]
fn safety_page_lists_turnstile_configured_indicator() {
    let html_configured     = safety_page_for(SafetyState { turnstile_configured: true, .. });
    let html_not_configured = safety_page_for(SafetyState { turnstile_configured: false, .. });
    assert!(html_configured.contains("構成済"));
    assert!(html_not_configured.contains("未構成"));
}

#[test]
fn safety_page_does_not_expose_totp_secret_bytes() {
    let html = safety_page_for(/* state with key present */);
    // secret bytes must never appear; only presence indicator
    assert!(!html.contains("BEGIN ") /* PEM-like leaks */);
}
```

## Migration / compatibility

- 後方互換性: 不要。
- スキーマ変更: 無し。
- wire / DO: 無し。
- 運用者向け: surface 強化のみ。CHANGELOG に PDF page 9 alignment と記載。

## Open questions

Q1. Verification 結果として **全項目すでに揃っている** 場合、本 RFC は
"verification + test pin only" として close するか、それとも minor fill だけ
追加するか?

→ 提案: verification step を本 RFC の唯一 deliverable とし、gap が有る場合は
follow-up RFC (e.g., 110a-rate-limit-summary 等) を別建てする。RFC 110 の
本体は "rendering test pinning" + baseline 文書のみ。
