# RFC 111 — Date rendering policy (ADR-013 §Q4 closure / date side)

**Status**: Implemented (v0.73.0 — UTC ISO-8601 confirmed as canonical policy, `cesauth_core::util::format_unix_as_iso8601` is the single formatter, per-file legacy formatters removed)  
**Tier**: P2  
**Size**: Small  
**Target**: v0.71.0 (originally) → shipped v0.73.0  
**Phase**: i18n completeness (finishing track)  
**Refs**: ADR-013 §Q3 + §Q4 (both closed v0.73.0) / PDF v0.50.1 page 12 "i18n contract: date / plural は未解決として扱う" / RFC 096 (canonical formatter introduced) / `docs/src/expert/i18n.md` §"Date / time rendering"

## Problem

ADR-013 §Q4 は cesauth の i18n 設計から **date / plural** を deferred と
していた。RFC 107 が plural side を閉じる。本 RFC は date side を閉じる。

現状 v0.66.0 の date 表示は:

- `security_center.rs::format_unix_local(unix: i64) -> String` は
  `time::OffsetDateTime::from_unix_timestamp(unix)` で **UTC ISO-8601** を
  返す (e.g., `2026-05-13T14:23:45+00:00`)。
- security_center.rs L535-545 のコメント:
  > The user page is otherwise localized JA, but timestamp formatting
  > stays UTC because cesauth has no per-user timezone yet — see ROADMAP
  > i18n track for that future work.
- admin / tenant_admin / tenancy_console 系の audit / session 表示も同様に UTC
  ISO-8601 が散在 (`util::format_unix_as_iso8601`, RFC 096 で統一済)。

PDF v0.50.1 page 12 は明示的に「date / plural は未解決として扱う」と書いており、
**特定の locale rendering を要求していない**。すなわち PDF の acceptance は
「未解決でも一貫していること」。本 RFC はその **一貫性** を invariant として
固定する。

## Goal

1. cesauth における date / time 表示の方針を **明示的に文書化** する。
2. ADR-013 §Q4 (date side) を `Resolved in v0.71.0` でクローズする。
3. 既存の `util::format_unix_as_iso8601` を canonical 化し、`security_center.rs`
   の locale-unaware な `format_unix_local` を統一する。
4. 将来 per-user timezone を追加する場合の **拡張点** を残しつつ、現時点では
   UTC ISO-8601 で確定する。

明示的に out of scope:
- per-user timezone preference (`Asia/Tokyo` / `America/Los_Angeles` 等の
  個人設定) — 別 ROADMAP item として残す。
- 相対時刻表示 (`3 hours ago` 等) — 別 RFC で検討。
- locale-aware date 区切り (`2026/05/13` JA vs `2026-05-13` ISO) — UTC ISO-8601
  で統一する方針なので不要。

## Design

### 方針確定

cesauth は **UTC ISO-8601 (RFC 3339) を全 surface で使用する** と確定する。
理由 (二点):

1. **ambiguity の排除**: UTC ISO-8601 は誰が読んでも同じ瞬間を指す。
   audit log / session list / token expiration 等 security-sensitive な表示で
   timezone ambiguity を作らない。
2. **operator-friendly**: log aggregation (Workers Logs, R2 audit dump,
   migrate export) は全て UTC ISO-8601。UI 表示と一致させると trace 時の
   照合コストがゼロ。

per-user timezone は **将来の拡張**。本 RFC では cesauth-core に preference
schema を持たない。

### 実装統合

1. `cesauth_core::util::format_unix_as_iso8601` (RFC 096 で導入) を **唯一の
   date formatter** とする。
2. `security_center.rs::format_unix_local` を削除し、`util::format_unix_as_iso8601`
   呼び出しに置き換える。同じ I/O のため挙動変更無し。
3. `crates/ui/src/admin/*.rs` 内の他の date formatting 箇所も同一関数経由に
   統一する (RFC 096 の継続)。

### Documentation

`docs/src/expert/i18n.md` (新規 or 既存 i18n doc に追記) に明記:

> **Date / time rendering**. cesauth uses UTC ISO-8601 (RFC 3339) for every
> visible timestamp. Locale does not change date formatting. Per-user
> timezone preferences are future work.

`docs/src/expert/adr/013-i18n-locale-negotiation.md` の §Q4 を closure 形式で
更新:

```markdown
**Q4 (date / plural)**: ~~Pluralization and date rendering deferred...~~
**Resolved in v0.71.0** (RFC 107 / RFC 111):
- Plural: see RFC 107.
- Date: UTC ISO-8601 (RFC 3339) for all surfaces. Per-user timezone is
  separate future work.
```

## Implementation steps

1. `crates/ui/src/templates/security_center.rs::format_unix_local` を削除。
2. 呼び出し箇所 (`render_session_row_for` L472-473) を
   `cesauth_core::util::format_unix_as_iso8601` に置換。
3. `crates/ui/src/admin/`, `crates/ui/src/tenant_admin/`,
   `crates/ui/src/tenancy_console/` で date formatting 箇所を全て同関数経由に統一
   (RFC 096 の継続作業)。
4. `docs/src/expert/i18n.md` に "Date / time rendering" セクション追加。
5. `docs/src/expert/adr/013-i18n-locale-negotiation.md` §Q4 を closure 形式に更新。
6. CHANGELOG / ROADMAP 更新 (ADR-013 §Q4 marked **Resolved**)。

## Acceptance

- [ ] `cargo-1.91 test --workspace --lib` が green
- [ ] `cargo-1.91 build --workspace --target wasm32-unknown-unknown --release` が成功
- [ ] `grep -rn "OffsetDateTime::from_unix_timestamp" crates/ui/` が空
      (util 経由のみ)
- [ ] `grep -rn "fn format_unix_local" crates/ui/` が空
- [ ] EN / JA 両 locale で同じ date 表記 (UTC ISO-8601) が出る — pin テスト
- [ ] ADR-013 §Q4 (date side) が `Resolved` 化済
- [ ] 非 deprecated warnings = 0

## Test strategy

```rust
#[test]
fn date_format_is_iso8601_in_both_locales() {
    let item = SessionListItem { created_at: 1715000000, .. };
    let ja = render_session_row_for(&item, "csrf", Locale::Ja);
    let en = render_session_row_for(&item, "csrf", Locale::En);
    // Same date appears in both locales' output
    let expected = "2024-05-06T15:33:20+00:00"; // example
    assert!(ja.contains(expected));
    assert!(en.contains(expected));
}

#[test]
fn date_format_uses_util_function_consistently() {
    // Pin that util::format_unix_as_iso8601 is the formatter used.
    // (Compile-time check: removing format_unix_local from security_center.rs
    //  is structural enforcement.)
}
```

## Migration / compatibility

- 後方互換性: 不要。
- スキーマ変更: 無し。
- wire / DO: 無し。
- 運用者向け: 表示は実質変わらない (両方とも UTC ISO-8601)。コード重複の解消のみ。
  CHANGELOG に ADR-013 §Q4 closure を明記。

## Open questions

なし (per-user timezone は明示的に future work として ROADMAP に残す)。
