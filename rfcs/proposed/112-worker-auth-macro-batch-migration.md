# RFC 112 — Worker auth macro batch migration

**Status**: Proposed  
**Tier**: P2  
**Size**: Medium  
**Target**: v0.68.0  
**Phase**: Drift prevention (finishing track)  
**Refs**: HANDOFF v0.66.0 残課題 §1 ("RFC 100 macro の他ルートへの適用") / 懸念事項 §2 / RFC 100

## Problem

RFC 100 (v0.66.0) で `require_system_admin!` / `require_tenant_admin_read!`
の auth preamble macro を導入したが、`audit_export.rs` と `operations_route.rs`
の **2 箇所のみ** 適用済。HANDOFF §1 が指摘:

> RFC 100 macro の他ルートへの適用: 57 残ハンドラ (system-admin macro) +
> 67 ハンドラ (tenant-admin macro) は依然として旧 5-12行 preamble。今回は
> `audit_export.rs` と `operations_route.rs` の 2 箇所のみ移行。

問題:

1. **混在状態の固定**: macro 適用済 / 未適用が混ざると、新規ハンドラの
   レビュー時に「どちらが正しいパターンか」が曖昧になる。HANDOFF 懸念事項 §2 で:
   > 完全に移行する前に新規ハンドラが追加されると、旧パターンと新パターンが
   > 混在し続ける。次フェーズで一括移行を推奨。
2. **コード行数**: 各ハンドラ 5-12 行 preamble が残ったまま。`audit_export.rs`
   での実測で 1 ハンドラ平均 7 行削減。57 + 67 = 124 ハンドラ × ~7 行 =
   ~860 行のボイラープレート削減が可能。
3. **macro signature の安定確認**: 2 箇所だけの適用では macro signature が
   実用上十分か (全 124 箇所の edge case をカバーするか) が未検証。

## Goal

1. `require_system_admin!` を適用可能な 57 ハンドラ全てに適用する。
2. `require_tenant_admin_read!` (および write variant が必要であれば追加) を
   67 ハンドラ全てに適用する。
3. 適用前後で全 1,204 テストが green を維持する (リグレッション無し)。
4. macro signature が edge case をカバーしないハンドラがあれば、macro 自体を
   拡張するか、当該ハンドラを明示的に "macro 非適用" として理由を inline コメント
   で残す。

明示的に out of scope:
- 新規 macro (e.g., `require_operator!` 等) の追加 — 既存 2 macro の適用範囲のみ。
- end-user route (e.g., `/me/security/*`) の preamble — admin route のみ対象。
- worker route table (`crates/worker/src/lib.rs`) の構造変更 — HANDOFF §既存課題で
  「分割は登録漏れリスク」として見送り。本 RFC も触らない。

## Design

### Inventory step

実装者はまず inventory:

```bash
# system admin route candidates
rg -l "require_admin\|RequireSystemAdmin\|hash_admin_token" crates/worker/src/routes/admin/console/
# tenant admin route candidates
rg -l "require_admin\|RequireTenantAdmin\|hash_admin_token" crates/worker/src/routes/admin/t/
```

各 file に対し、macro 適用候補ハンドラの一覧を取得する。124 ハンドラを
file 単位でグルーピング (typically 6-10 file)。

### Migration step (per-file basis)

各 file を一つの PR (or commit) として扱う。差分は機械的:

```rust
// Before
pub async fn handler(req: Request, ctx: RouteContext) -> Result<Response> {
    let auth = req.headers().get("authorization")?;
    let Some(token) = auth.and_then(|v| v.strip_prefix("Bearer ")) else {
        return cesauth_worker::error::admin_unauthorized();
    };
    let hashed = cesauth_core::admin::hash_admin_token(token);
    let admin = ctx.env.d1("DB")?.prepare("SELECT ...").bind(&[hashed.into()])?
        .first::<Admin>(None).await?;
    let Some(admin) = admin else {
        return cesauth_worker::error::admin_unauthorized();
    };
    if !matches!(admin.role, Role::SystemAdmin) {
        return cesauth_worker::error::admin_forbidden();
    }
    // ... actual handler ...
}

// After
pub async fn handler(req: Request, ctx: RouteContext) -> Result<Response> {
    let admin = require_system_admin!(req, ctx);
    // ... actual handler ...
}
```

### Macro non-applicability cases

以下の場合は macro を適用せず、inline コメントで理由を残す:

1. **複数の認可レベル** を一つのハンドラで分岐する必要がある場合
   (現状では存在しないが、見つかった場合)。
2. **public read 部分** を持つ admin route (現状では存在しないが、念のため)。
3. **macro 拡張で対処可能** な場合は、macro を拡張する PR を別建てして
   先行マージする。

## Implementation steps

### PR 1 — Inventory & analysis

`rfcs/proposed/112-rfc-100-batch-migration-inventory.md` (or scratchpad) に
124 ハンドラのリストと macro signature 互換性メモを記録する。

### PR 2-7 — File-by-file migration (system admin)

`crates/worker/src/routes/admin/console/*.rs` (57 ハンドラ程度) の各 file を
順次移行。1 PR / 1 file が目安。

### PR 8-15 — File-by-file migration (tenant admin)

`crates/worker/src/routes/admin/t/*.rs` (67 ハンドラ程度) の各 file を順次移行。

### PR 16 — drift-scan rule

`scripts/drift-scan.sh` に「`hash_admin_token` 直接呼び出しが
`crates/worker/src/routes/admin/` 配下の `*.rs` に出現すべきでない (macro 経由のみ)」
チェックを追加。

## Acceptance

- [ ] `cargo-1.91 test --workspace --lib` が green (1,204 → 1,204、件数変化無し)
- [ ] `cargo-1.91 build --workspace --target wasm32-unknown-unknown --release` が成功
- [ ] `rg -n "hash_admin_token" crates/worker/src/routes/admin/` が 0 件
      (macro 内部以外)、または non-applicability comment 付きの exception のみ
- [ ] 全 admin ハンドラが macro 経由か、明示的な exception コメント付き
- [ ] `drift-scan.sh` rule で macro 非経由の admin auth preamble を検知
- [ ] 非 deprecated warnings = 0
- [ ] LOC 削減 ~800-900 (推計)

## Test strategy

新規テスト追加は不要 (refactor のみ、観測挙動は不変)。既存の auth route テストが
green を維持することで担保。Adapter-test 側で各 admin route の auth ガード
(403/401 paths) が変わっていないことを確認。

## Migration / compatibility

- 後方互換性: 不要。
- スキーマ変更: 無し。
- wire / DO: 無し。
- 運用者向け: 視覚的変更も挙動変更も無し。CHANGELOG に "RFC 100 macro 全面適用、
  LOC ~800 削減" と簡潔に記載。

## Open questions

なし。
